# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C9 native streaming state Guard for the Python SDK (design.md §10 state table; § Timers;
naalp-error code 49). Mirrors impl/go/streaming/state_guard_test.go's 7 mutation-surviving guard
tests, translated to the Python Guard/StreamOpen/StreamCommit/Chunk port in
impl/python/naalp/streaming.py.

Mutation target: flipping the state check in Guard.open (or any of chunk/checkpoint/commit/expire)
so a forbidden transition is admitted flips test_guard_rejects_forbidden_transitions (and several
siblings) RED; flipping Guard.expire to leave the state OPEN instead of ABANDONED flips
test_guard_expire_abandons_open_stream RED.

Run:  python -m unittest tests.test_streaming_guard      (from impl/python/)
"""
import unittest

from naalp import policy, streaming


def _open(sid, effect=policy.IDEMPOTENT_WRITE):
    return streaming.StreamOpen(sid, effect, None, 0)


class StreamGuardTests(unittest.TestCase):

    def test_guard_rejects_forbidden_transitions(self):
        """(a) forbidden transitions -- chunk/checkpoint/commit before open, double-open, and
        events after commit -- each raise StreamStateError and leave the state unchanged."""
        # idle + chunk / checkpoint / commit -> unlisted pair, default StreamStateError.
        cases = [
            ("chunk_before_open", lambda g, sid: g.chunk(sid)),
            ("checkpoint_before_open", lambda g, sid: g.checkpoint(sid)),
            ("commit_before_open", lambda g, sid: g.commit(streaming.StreamCommit(sid, b""), [])),
        ]
        for name, run in cases:
            with self.subTest(name):
                g = streaming.Guard()
                sid = b"stream-forbidden"
                with self.assertRaises(streaming.StreamError) as cm:
                    run(g, sid)
                self.assertEqual(cm.exception.kind, "StreamStateError")
                self.assertEqual(g.state(sid), streaming.STATE_IDLE,
                                  "a rejected event must not change state")

        # open + StreamOpen -> reject (StreamStateError) -- explicit table row.
        sid = b"stream-double-open"
        g = streaming.Guard()
        o = _open(sid)
        g.open(o, policy.IDEMPOTENT_WRITE)  # first open should succeed
        with self.assertRaises(streaming.StreamError) as cm:
            g.open(o, policy.IDEMPOTENT_WRITE)
        self.assertEqual(cm.exception.kind, "StreamStateError")
        self.assertEqual(g.state(sid), streaming.STATE_OPEN,
                          "a rejected re-open must not change state")

        # committed + {chunk, StreamCheckpoint, StreamCommit, StreamOpen} -- the first three are
        # explicit table rows; StreamOpen-after-committed is the unlisted-pair default.
        sid = b"stream-after-commit"
        g = streaming.Guard()
        o = _open(sid)
        g.open(o, policy.IDEMPOTENT_WRITE)
        chunks = [streaming.Chunk(0, b"payload")]
        commit = streaming.StreamCommit(sid, streaming.commit_digest(chunks))
        g.commit(commit, chunks)
        self.assertEqual(g.state(sid), streaming.STATE_COMMITTED)

        for run in (lambda: g.chunk(sid), lambda: g.checkpoint(sid),
                    lambda: g.commit(commit, chunks), lambda: g.open(o, policy.IDEMPOTENT_WRITE)):
            with self.assertRaises(streaming.StreamError) as cm:
                run()
            self.assertEqual(cm.exception.kind, "StreamStateError")
        self.assertEqual(g.state(sid), streaming.STATE_COMMITTED,
                          "rejected post-commit events must not change state")

    def test_guard_valid_sequence_succeeds(self):
        """(b) the false-positive check: an ordered open -> chunk -> checkpoint -> commit sequence
        must succeed and drive the state idle -> open -> committed -- the guard must not reject
        events the stream state table actually admits."""
        sid = b"stream-valid"
        g = streaming.Guard()
        self.assertEqual(g.state(sid), streaming.STATE_IDLE, "an unopened stream should be idle")

        o = _open(sid)
        g.open(o, policy.IDEMPOTENT_WRITE)
        self.assertEqual(g.state(sid), streaming.STATE_OPEN, "after open, state should be open")

        chunks = [streaming.Chunk(0, b"hello "), streaming.Chunk(6, b"world")]
        for _ in chunks:
            g.chunk(sid)
        g.checkpoint(sid)
        self.assertEqual(g.state(sid), streaming.STATE_OPEN,
                          "chunks/checkpoint must keep the stream open")

        commit = streaming.StreamCommit(sid, streaming.commit_digest(chunks))
        g.commit(commit, chunks)
        self.assertEqual(g.state(sid), streaming.STATE_COMMITTED, "after commit, state should be committed")

    def test_guard_digest_mismatch_is_not_state_error(self):
        """(c) distinguishes the guard's ordering check from the existing digest check: "open |
        StreamCommit (digest mismatch) | reject (StreamDigestMismatch)" must surface
        StreamDigestMismatch, not StreamStateError, and must leave the stream open (the row rejects
        without advancing) so a corrected commit still lands."""
        sid = b"stream-bad-digest"
        g = streaming.Guard()
        g.open(_open(sid), policy.IDEMPOTENT_WRITE)
        chunks = [streaming.Chunk(0, b"payload")]

        bad = streaming.StreamCommit(sid, b"not-the-real-digest-not-the-real-digest")
        with self.assertRaises(streaming.StreamError) as cm:
            g.commit(bad, chunks)
        self.assertEqual(cm.exception.kind, "StreamDigestMismatch")
        self.assertEqual(g.state(sid), streaming.STATE_OPEN,
                          "a digest-mismatched commit must leave the stream open")

        good = streaming.StreamCommit(sid, streaming.commit_digest(chunks))
        g.commit(good, chunks)  # the corrected commit should still succeed
        self.assertEqual(g.state(sid), streaming.STATE_COMMITTED,
                          "after the corrected commit, state should be committed")

    def test_guard_effect_not_authorized_leaves_idle(self):
        """(d) "idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)" must
        surface EffectNotAuthorized, not StreamStateError, and must leave the stream idle so a
        properly authorized open on the same stream id still succeeds (R-10.3)."""
        sid = b"stream-unauthorized"
        g = streaming.Guard()

        destructive = streaming.StreamOpen(sid, policy.DESTRUCTIVE, None, 0)
        with self.assertRaises(streaming.StreamError) as cm:
            g.open(destructive, policy.READ_ONLY)
        self.assertEqual(cm.exception.kind, "EffectNotAuthorized")
        self.assertEqual(g.state(sid), streaming.STATE_IDLE,
                          "an unauthorized open must leave the stream idle")

        authorized = _open(sid)
        g.open(authorized, policy.IDEMPOTENT_WRITE)  # the authorized open should still succeed
        self.assertEqual(g.state(sid), streaming.STATE_OPEN,
                          "after the authorized open, state should be open")

    def test_guard_independent_streams_do_not_interfere(self):
        """(e) the guard is keyed by stream id, so one stream's state never leaks into another's."""
        g = streaming.Guard()
        a, b = b"stream-a", b"stream-b"

        g.open(_open(a), policy.IDEMPOTENT_WRITE)
        # b was never opened; any event on b is still rejected StreamStateError even though a is open.
        with self.assertRaises(streaming.StreamError) as cm:
            g.chunk(b)
        self.assertEqual(cm.exception.kind, "StreamStateError")
        g.chunk(a)  # chunk on the open stream a should succeed

    def test_guard_expire_abandons_open_stream(self):
        """(f) drives the idle/commit timer's expiry (§ Timers): expire() on an open stream
        transitions it "open -> abandoned", a terminal state that then rejects every event with
        StreamStateError -- including a StreamOpen reusing the id, so an abandoned stream is never
        re-admitted. This is the fail-closed retention that stops a replayed signed StreamOpen from
        re-opening an abandoned id."""
        sid = b"stream-abandoned"
        g = streaming.Guard()
        o = _open(sid)
        g.open(o, policy.IDEMPOTENT_WRITE)

        g.expire(sid)  # expiring an open stream should succeed
        self.assertEqual(g.state(sid), streaming.STATE_ABANDONED, "after expiry, state should be abandoned")

        # An abandoned stream admits nothing -- chunk, checkpoint, commit, and a StreamOpen reusing
        # the id are all rejected StreamStateError (the id is never re-admitted).
        chunks = [streaming.Chunk(0, b"payload")]
        commit = streaming.StreamCommit(sid, streaming.commit_digest(chunks))
        for run in (lambda: g.chunk(sid), lambda: g.checkpoint(sid),
                    lambda: g.commit(commit, chunks), lambda: g.open(o, policy.IDEMPOTENT_WRITE)):
            with self.assertRaises(streaming.StreamError) as cm:
                run()
            self.assertEqual(cm.exception.kind, "StreamStateError")
        self.assertEqual(g.state(sid), streaming.STATE_ABANDONED,
                          "rejected post-abandon events must not change state")

    def test_guard_expire_on_non_open_is_state_error(self):
        """(g) the idle/commit timer clears when a StreamCommit transitions the stream to committed
        (§ Timers), so a correct caller fires expire() only while the stream is open. Expire on an
        idle, committed, or already-abandoned stream is therefore rejected StreamStateError and
        leaves the state unchanged (fail-closed)."""
        # idle: nothing has been opened.
        sid = b"stream-expire-idle"
        g = streaming.Guard()
        with self.assertRaises(streaming.StreamError) as cm:
            g.expire(sid)
        self.assertEqual(cm.exception.kind, "StreamStateError")
        self.assertEqual(g.state(sid), streaming.STATE_IDLE,
                          "expiring an idle stream must not change state")

        # committed: the timer should have cleared on commit; a spurious expire is a state error and
        # must not turn a committed (non-repudiable) stream into an abandoned one.
        sid = b"stream-expire-committed"
        g = streaming.Guard()
        g.open(_open(sid), policy.IDEMPOTENT_WRITE)
        chunks = [streaming.Chunk(0, b"payload")]
        commit = streaming.StreamCommit(sid, streaming.commit_digest(chunks))
        g.commit(commit, chunks)
        with self.assertRaises(streaming.StreamError) as cm:
            g.expire(sid)
        self.assertEqual(cm.exception.kind, "StreamStateError")
        self.assertEqual(g.state(sid), streaming.STATE_COMMITTED,
                          "expiring a committed stream must not change state")

        # already abandoned: a second expire is a state error and a no-op.
        sid = b"stream-expire-twice"
        g = streaming.Guard()
        g.open(_open(sid), policy.IDEMPOTENT_WRITE)
        g.expire(sid)  # first expire
        with self.assertRaises(streaming.StreamError) as cm:
            g.expire(sid)
        self.assertEqual(cm.exception.kind, "StreamStateError")
        self.assertEqual(g.state(sid), streaming.STATE_ABANDONED,
                          "a second expire must not change state")


if __name__ == "__main__":
    unittest.main()
