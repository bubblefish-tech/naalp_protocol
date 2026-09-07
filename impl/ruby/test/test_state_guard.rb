# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C9 streaming state-machine Guard conformance for the Ruby SDK (design.md §10, § Timers), mirroring
# impl/go/streaming/state_guard_test.go's 7 mutation-surviving tests. These are unit tests over
# Naalp::Streaming::Guard's state machine (idle -> open -> committed, with abandoned as the terminal
# state a stream enters on the idle/commit timer's expiry) -- NOT graded against the shared corpus (the
# corpus's `stream.state` op drives the Guard through the harness adapter instead; see
# tools/streamstate_oracle.py).
#
# THE MUTATION TARGET: any of the state-check conditionals in Naalp::Streaming::Guard (e.g. #open
# admitting a non-idle stream, or #expire not transitioning to abandoned) flips one or more of these
# tests RED.
#
# Run:  ruby -Ilib -Itest test/test_state_guard.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'naalp'

def new_guard
  Naalp::Streaming::Guard.new
end

def open_of(id, effect)
  Naalp::Streaming::StreamOpen.new(id, effect, nil, 0)
end

class StateGuardTest < Minitest::Test
  # test_guard_rejects_forbidden_transitions drives forbidden (state, event) pairs from the stream
  # state table (design.md §10) and asserts each is rejected StreamStateError. Every case is either a
  # table row whose reaction is "reject (StreamStateError)" or falls under the table's "any (state,
  # event) pair not listed above is rejected with StreamStateError" default.
  def test_guard_rejects_forbidden_transitions
    sid = "stream-forbidden".b

    # idle + chunk -> unlisted pair, default StreamStateError.
    g = new_guard
    err = assert_raises(Naalp::Streaming::StreamError) { g.chunk(sid) }
    assert_equal "StreamStateError", err.kind
    assert_equal Naalp::Streaming::STATE_IDLE, g.state(sid), "a rejected event must not change state"

    # idle + StreamCheckpoint -> unlisted pair, default StreamStateError.
    g = new_guard
    err = assert_raises(Naalp::Streaming::StreamError) { g.checkpoint(sid) }
    assert_equal "StreamStateError", err.kind
    assert_equal Naalp::Streaming::STATE_IDLE, g.state(sid), "a rejected event must not change state"

    # idle + StreamCommit -> unlisted pair, default StreamStateError.
    g = new_guard
    err = assert_raises(Naalp::Streaming::StreamError) { g.commit(Naalp::Streaming::StreamCommit.new(sid, nil), []) }
    assert_equal "StreamStateError", err.kind
    assert_equal Naalp::Streaming::STATE_IDLE, g.state(sid), "a rejected event must not change state"

    # open + StreamOpen -> reject (StreamStateError) -- explicit table row.
    id = "stream-double-open".b
    g = new_guard
    open = open_of(id, Naalp::Policy::IDEMPOTENT_WRITE)
    g.open(open, Naalp::Policy::IDEMPOTENT_WRITE)
    err = assert_raises(Naalp::Streaming::StreamError) { g.open(open, Naalp::Policy::IDEMPOTENT_WRITE) }
    assert_equal "StreamStateError", err.kind
    assert_equal Naalp::Streaming::STATE_OPEN, g.state(id), "a rejected re-open must not change state"

    # committed + {chunk, StreamCheckpoint, StreamCommit, StreamOpen} -- the first three are explicit
    # table rows ("reject (StreamStateError)"); StreamOpen-after-committed is the unlisted-pair
    # default.
    id2 = "stream-after-commit".b
    g2 = new_guard
    open2 = open_of(id2, Naalp::Policy::IDEMPOTENT_WRITE)
    g2.open(open2, Naalp::Policy::IDEMPOTENT_WRITE)
    chunks = [Naalp::Streaming::Chunk.new(0, "payload".b)]
    commit = Naalp::Streaming::StreamCommit.new(id2, Naalp::Streaming.commit_digest(chunks))
    g2.commit(commit, chunks)
    assert_equal Naalp::Streaming::STATE_COMMITTED, g2.state(id2), "stream should be committed"

    e1 = assert_raises(Naalp::Streaming::StreamError) { g2.chunk(id2) }
    assert_equal "StreamStateError", e1.kind
    e2 = assert_raises(Naalp::Streaming::StreamError) { g2.checkpoint(id2) }
    assert_equal "StreamStateError", e2.kind
    e3 = assert_raises(Naalp::Streaming::StreamError) { g2.commit(commit, chunks) }
    assert_equal "StreamStateError", e3.kind
    e4 = assert_raises(Naalp::Streaming::StreamError) { g2.open(open2, Naalp::Policy::IDEMPOTENT_WRITE) }
    assert_equal "StreamStateError", e4.kind

    assert_equal Naalp::Streaming::STATE_COMMITTED, g2.state(id2), "rejected post-commit events must not change state"
  end

  # test_guard_valid_sequence_succeeds is the false-positive check: an ordered open -> chunk ->
  # checkpoint -> commit sequence must succeed and drive the state idle -> open -> committed -- the
  # guard must not reject events the stream state table actually admits.
  def test_guard_valid_sequence_succeeds
    id = "stream-valid".b
    g = new_guard

    assert_equal Naalp::Streaming::STATE_IDLE, g.state(id), "an unopened stream should be idle"

    open = open_of(id, Naalp::Policy::IDEMPOTENT_WRITE)
    g.open(open, Naalp::Policy::IDEMPOTENT_WRITE)
    assert_equal Naalp::Streaming::STATE_OPEN, g.state(id), "after open, state should be open"

    chunks = [
      Naalp::Streaming::Chunk.new(0, "hello ".b),
      Naalp::Streaming::Chunk.new(6, "world".b),
    ]
    chunks.each { g.chunk(id) }
    g.checkpoint(id)
    assert_equal Naalp::Streaming::STATE_OPEN, g.state(id), "chunks/checkpoint must keep the stream open"

    commit = Naalp::Streaming::StreamCommit.new(id, Naalp::Streaming.commit_digest(chunks))
    g.commit(commit, chunks)
    assert_equal Naalp::Streaming::STATE_COMMITTED, g.state(id), "after commit, state should be committed"
  end

  # test_guard_digest_mismatch_is_not_state_error distinguishes the guard's ordering check from the
  # existing digest check: "open | StreamCommit (digest mismatch) | reject (StreamDigestMismatch)"
  # must surface StreamDigestMismatch, not StreamStateError, and must leave the stream open (the row
  # rejects without advancing) so a corrected commit still lands.
  def test_guard_digest_mismatch_is_not_state_error
    id = "stream-bad-digest".b
    g = new_guard
    open = open_of(id, Naalp::Policy::IDEMPOTENT_WRITE)
    g.open(open, Naalp::Policy::IDEMPOTENT_WRITE)
    chunks = [Naalp::Streaming::Chunk.new(0, "payload".b)]

    bad = Naalp::Streaming::StreamCommit.new(id, "not-the-real-digest-not-the-real-digest".b)
    err = assert_raises(Naalp::Streaming::StreamError) { g.commit(bad, chunks) }
    assert_equal "StreamDigestMismatch", err.kind
    assert_equal Naalp::Streaming::STATE_OPEN, g.state(id), "a digest-mismatched commit must leave the stream open"

    good = Naalp::Streaming::StreamCommit.new(id, Naalp::Streaming.commit_digest(chunks))
    g.commit(good, chunks)
    assert_equal Naalp::Streaming::STATE_COMMITTED, g.state(id), "after the corrected commit, state should be committed"
  end

  # test_guard_effect_not_authorized_leaves_idle: "idle | StreamOpen (effect not authorized) | reject
  # (EffectNotAuthorized)" must surface EffectNotAuthorized, not StreamStateError, and must leave the
  # stream idle so a properly authorized open on the same stream id still succeeds (R-10.3).
  def test_guard_effect_not_authorized_leaves_idle
    id = "stream-unauthorized".b
    g = new_guard

    destructive = open_of(id, Naalp::Policy::DESTRUCTIVE)
    err = assert_raises(Naalp::Streaming::StreamError) { g.open(destructive, Naalp::Policy::READ_ONLY) }
    assert_equal "EffectNotAuthorized", err.kind
    assert_equal Naalp::Streaming::STATE_IDLE, g.state(id), "an unauthorized open must leave the stream idle"

    authorized = open_of(id, Naalp::Policy::IDEMPOTENT_WRITE)
    g.open(authorized, Naalp::Policy::IDEMPOTENT_WRITE)
    assert_equal Naalp::Streaming::STATE_OPEN, g.state(id), "after the authorized open, state should be open"
  end

  # test_guard_independent_streams_do_not_interfere: the guard is keyed by stream id, so one stream's
  # state never leaks into another's.
  def test_guard_independent_streams_do_not_interfere
    g = new_guard
    a = "stream-a".b
    b = "stream-b".b

    open_a = open_of(a, Naalp::Policy::IDEMPOTENT_WRITE)
    g.open(open_a, Naalp::Policy::IDEMPOTENT_WRITE)
    # b was never opened; any event on b is still rejected StreamStateError even though a is open.
    err = assert_raises(Naalp::Streaming::StreamError) { g.chunk(b) }
    assert_equal "StreamStateError", err.kind
    g.chunk(a) # chunk on the open stream a should succeed (no raise)
  end

  # test_guard_expire_abandons_open_stream drives the idle/commit timer's expiry (§ Timers): expire on
  # an open stream transitions it "open -> abandoned", a terminal state that then rejects every event
  # with StreamStateError -- including a StreamOpen reusing the id, so an abandoned stream is never
  # re-admitted. This is the fail-closed retention that stops a replayed signed StreamOpen from
  # re-opening an abandoned id.
  def test_guard_expire_abandons_open_stream
    id = "stream-abandoned".b
    g = new_guard
    open = open_of(id, Naalp::Policy::IDEMPOTENT_WRITE)
    g.open(open, Naalp::Policy::IDEMPOTENT_WRITE)

    g.expire(id)
    assert_equal Naalp::Streaming::STATE_ABANDONED, g.state(id), "after expiry, state should be abandoned"

    # An abandoned stream admits nothing -- chunk, checkpoint, commit, and a StreamOpen reusing the id
    # are all rejected StreamStateError (the id is never re-admitted).
    chunks = [Naalp::Streaming::Chunk.new(0, "payload".b)]
    commit = Naalp::Streaming::StreamCommit.new(id, Naalp::Streaming.commit_digest(chunks))
    e1 = assert_raises(Naalp::Streaming::StreamError) { g.chunk(id) }
    assert_equal "StreamStateError", e1.kind
    e2 = assert_raises(Naalp::Streaming::StreamError) { g.checkpoint(id) }
    assert_equal "StreamStateError", e2.kind
    e3 = assert_raises(Naalp::Streaming::StreamError) { g.commit(commit, chunks) }
    assert_equal "StreamStateError", e3.kind
    e4 = assert_raises(Naalp::Streaming::StreamError) { g.open(open, Naalp::Policy::IDEMPOTENT_WRITE) }
    assert_equal "StreamStateError", e4.kind

    assert_equal Naalp::Streaming::STATE_ABANDONED, g.state(id), "rejected post-abandon events must not change state"
  end

  # test_guard_expire_on_non_open_is_state_error: the idle/commit timer clears when a StreamCommit
  # transitions the stream to committed (§ Timers), so a correct caller fires expire only while the
  # stream is open. Expire on an idle, committed, or already-abandoned stream is therefore rejected
  # StreamStateError and leaves the state unchanged (fail-closed).
  def test_guard_expire_on_non_open_is_state_error
    # idle: nothing has been opened.
    id_idle = "stream-expire-idle".b
    g_idle = new_guard
    err = assert_raises(Naalp::Streaming::StreamError) { g_idle.expire(id_idle) }
    assert_equal "StreamStateError", err.kind
    assert_equal Naalp::Streaming::STATE_IDLE, g_idle.state(id_idle), "expiring an idle stream must not change state"

    # committed: the timer should have cleared on commit; a spurious expire is a state error and must
    # not turn a committed (non-repudiable) stream into an abandoned one.
    id_committed = "stream-expire-committed".b
    g_committed = new_guard
    open_c = open_of(id_committed, Naalp::Policy::IDEMPOTENT_WRITE)
    g_committed.open(open_c, Naalp::Policy::IDEMPOTENT_WRITE)
    chunks = [Naalp::Streaming::Chunk.new(0, "payload".b)]
    commit = Naalp::Streaming::StreamCommit.new(id_committed, Naalp::Streaming.commit_digest(chunks))
    g_committed.commit(commit, chunks)
    err2 = assert_raises(Naalp::Streaming::StreamError) { g_committed.expire(id_committed) }
    assert_equal "StreamStateError", err2.kind
    assert_equal Naalp::Streaming::STATE_COMMITTED, g_committed.state(id_committed), "expiring a committed stream must not change state"

    # already abandoned: a second expire is a state error and a no-op.
    id_twice = "stream-expire-twice".b
    g_twice = new_guard
    open_t = open_of(id_twice, Naalp::Policy::IDEMPOTENT_WRITE)
    g_twice.open(open_t, Naalp::Policy::IDEMPOTENT_WRITE)
    g_twice.expire(id_twice)
    err3 = assert_raises(Naalp::Streaming::StreamError) { g_twice.expire(id_twice) }
    assert_equal "StreamStateError", err3.kind
    assert_equal Naalp::Streaming::STATE_ABANDONED, g_twice.state(id_twice), "a second expire must not change state"
  end
end
