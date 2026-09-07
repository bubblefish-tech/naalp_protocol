// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// The stream state machine Guard (design.md §10 state table; § Timers), ported from
    /// impl/go/streaming/state_guard_test.go. Every case is either an explicit state-table row or falls
    /// under the table's "any (state, event) pair not listed above is rejected with StreamStateError"
    /// default. Graded structurally here (unit tests); the adapter's <c>stream.state</c> op is graded
    /// against the independent, non-circular tools/streamstate_oracle.py corpus (F3).
    /// </summary>
    public sealed class StreamingStateGuardTests
    {
        private static void WantKind(Action action, string kind)
        {
            NaalpException ex = Assert.Throws<NaalpException>(() => action());
            Assert.Equal(kind, ex.Kind);
        }

        private static Streaming.StreamOpen OpenFor(byte[] id, long effect = Policy.IDEMPOTENT_WRITE)
            => new Streaming.StreamOpen(id, effect, null, 0);

        // ---- (a) forbidden transitions -------------------------------------------------------------

        /// <summary>Drives forbidden (state, event) pairs from the stream state table and asserts each
        /// is rejected StreamStateError, with the state left exactly as it was.</summary>
        [Fact]
        public void GuardRejectsForbiddenTransitions()
        {
            byte[] sid = System.Text.Encoding.ASCII.GetBytes("stream-forbidden");

            // idle + chunk -> unlisted pair, default StreamStateError.
            {
                var g = new Streaming.Guard();
                WantKind(() => g.Chunk(sid), "StreamStateError");
                Assert.Equal(Streaming.State.Idle, g.GetState(sid));
            }
            // idle + StreamCheckpoint -> unlisted pair, default StreamStateError.
            {
                var g = new Streaming.Guard();
                WantKind(() => g.Checkpoint(sid), "StreamStateError");
                Assert.Equal(Streaming.State.Idle, g.GetState(sid));
            }
            // idle + StreamCommit -> unlisted pair, default StreamStateError.
            {
                var g = new Streaming.Guard();
                WantKind(() => g.Commit(new Streaming.StreamCommit(sid, Array.Empty<byte>()), new List<Streaming.Chunk>()), "StreamStateError");
                Assert.Equal(Streaming.State.Idle, g.GetState(sid));
            }

            // open + StreamOpen -> reject (StreamStateError) — explicit table row.
            {
                byte[] id = System.Text.Encoding.ASCII.GetBytes("stream-double-open");
                var g = new Streaming.Guard();
                Streaming.StreamOpen open = OpenFor(id);
                g.Open(open, Policy.IDEMPOTENT_WRITE); // first open should succeed
                WantKind(() => g.Open(open, Policy.IDEMPOTENT_WRITE), "StreamStateError");
                Assert.Equal(Streaming.State.Open, g.GetState(id));
            }

            // committed + {chunk, StreamCheckpoint, StreamCommit, StreamOpen} — the first three are
            // explicit table rows ("reject (StreamStateError)"); StreamOpen-after-committed is the
            // unlisted-pair default.
            {
                byte[] id = System.Text.Encoding.ASCII.GetBytes("stream-after-commit");
                var g = new Streaming.Guard();
                Streaming.StreamOpen open = OpenFor(id);
                g.Open(open, Policy.IDEMPOTENT_WRITE);
                var chunks = new List<Streaming.Chunk> { new Streaming.Chunk(0, System.Text.Encoding.ASCII.GetBytes("payload")) };
                var commit = new Streaming.StreamCommit(id, Streaming.CommitDigest(chunks));
                g.Commit(commit, chunks);
                Assert.Equal(Streaming.State.Committed, g.GetState(id));

                WantKind(() => g.Chunk(id), "StreamStateError");
                WantKind(() => g.Checkpoint(id), "StreamStateError");
                WantKind(() => g.Commit(commit, chunks), "StreamStateError");
                WantKind(() => g.Open(open, Policy.IDEMPOTENT_WRITE), "StreamStateError");

                Assert.Equal(Streaming.State.Committed, g.GetState(id));
            }
        }

        // ---- (b) valid sequence ----------------------------------------------------------------------

        /// <summary>The false-positive check: an ordered open -&gt; chunk -&gt; checkpoint -&gt; commit
        /// sequence must succeed and drive the state idle -&gt; open -&gt; committed — the guard must not
        /// reject events the stream state table actually admits.</summary>
        [Fact]
        public void GuardValidSequenceSucceeds()
        {
            byte[] id = System.Text.Encoding.ASCII.GetBytes("stream-valid");
            var g = new Streaming.Guard();

            Assert.Equal(Streaming.State.Idle, g.GetState(id));

            Streaming.StreamOpen open = OpenFor(id);
            g.Open(open, Policy.IDEMPOTENT_WRITE);
            Assert.Equal(Streaming.State.Open, g.GetState(id));

            var chunks = new List<Streaming.Chunk>
            {
                new Streaming.Chunk(0, System.Text.Encoding.ASCII.GetBytes("hello ")),
                new Streaming.Chunk(6, System.Text.Encoding.ASCII.GetBytes("world")),
            };
            foreach (Streaming.Chunk _ in chunks)
            {
                g.Chunk(id);
            }
            g.Checkpoint(id);
            Assert.Equal(Streaming.State.Open, g.GetState(id));

            var commit = new Streaming.StreamCommit(id, Streaming.CommitDigest(chunks));
            g.Commit(commit, chunks);
            Assert.Equal(Streaming.State.Committed, g.GetState(id));
        }

        // ---- (c) digest mismatch is not a state error ------------------------------------------------

        /// <summary>Distinguishes the guard's ordering check from the existing digest check: "open |
        /// StreamCommit (digest mismatch) | reject (StreamDigestMismatch)" must surface
        /// StreamDigestMismatch, not StreamStateError, and must leave the stream open so a corrected
        /// commit still lands.</summary>
        [Fact]
        public void GuardDigestMismatchIsNotStateError()
        {
            byte[] id = System.Text.Encoding.ASCII.GetBytes("stream-bad-digest");
            var g = new Streaming.Guard();
            Streaming.StreamOpen open = OpenFor(id);
            g.Open(open, Policy.IDEMPOTENT_WRITE);
            var chunks = new List<Streaming.Chunk> { new Streaming.Chunk(0, System.Text.Encoding.ASCII.GetBytes("payload")) };

            var bad = new Streaming.StreamCommit(id, System.Text.Encoding.ASCII.GetBytes("not-the-real-digest-not-the-real-digest"));
            WantKind(() => g.Commit(bad, chunks), "StreamDigestMismatch");
            Assert.Equal(Streaming.State.Open, g.GetState(id));

            var good = new Streaming.StreamCommit(id, Streaming.CommitDigest(chunks));
            g.Commit(good, chunks); // the corrected commit should still succeed
            Assert.Equal(Streaming.State.Committed, g.GetState(id));
        }

        // ---- (d) effect-not-authorized leaves idle ----------------------------------------------------

        /// <summary>"idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)" must
        /// surface EffectNotAuthorized, not StreamStateError, and must leave the stream idle so a
        /// properly authorized open on the same stream id still succeeds (R-10.3).</summary>
        [Fact]
        public void GuardEffectNotAuthorizedLeavesIdle()
        {
            byte[] id = System.Text.Encoding.ASCII.GetBytes("stream-unauthorized");
            var g = new Streaming.Guard();

            Streaming.StreamOpen destructive = OpenFor(id, Policy.DESTRUCTIVE);
            WantKind(() => g.Open(destructive, Policy.READ_ONLY), "EffectNotAuthorized");
            Assert.Equal(Streaming.State.Idle, g.GetState(id));

            Streaming.StreamOpen authorized = OpenFor(id, Policy.IDEMPOTENT_WRITE);
            g.Open(authorized, Policy.IDEMPOTENT_WRITE); // the authorized open should still succeed
            Assert.Equal(Streaming.State.Open, g.GetState(id));
        }

        // ---- (e) independent streams don't interfere --------------------------------------------------

        /// <summary>The guard is keyed by stream id, so one stream's state never leaks into another's.</summary>
        [Fact]
        public void GuardIndependentStreamsDoNotInterfere()
        {
            var g = new Streaming.Guard();
            byte[] a = System.Text.Encoding.ASCII.GetBytes("stream-a");
            byte[] b = System.Text.Encoding.ASCII.GetBytes("stream-b");

            Streaming.StreamOpen openA = OpenFor(a);
            g.Open(openA, Policy.IDEMPOTENT_WRITE);
            // b was never opened; any event on b is still rejected StreamStateError even though a is open.
            WantKind(() => g.Chunk(b), "StreamStateError");
            g.Chunk(a); // chunk on the open stream a should succeed
        }

        // ---- (f) expire abandons an open stream ---------------------------------------------------------

        /// <summary>Drives the idle/commit timer's expiry (§ Timers): Expire on an open stream
        /// transitions it "open -&gt; abandoned", a terminal state that then rejects every event with
        /// StreamStateError — including a StreamOpen reusing the id, so an abandoned stream is never
        /// re-admitted.</summary>
        [Fact]
        public void GuardExpireAbandonsOpenStream()
        {
            byte[] id = System.Text.Encoding.ASCII.GetBytes("stream-abandoned");
            var g = new Streaming.Guard();
            Streaming.StreamOpen open = OpenFor(id);
            g.Open(open, Policy.IDEMPOTENT_WRITE);

            g.Expire(id); // expiring an open stream should succeed
            Assert.Equal(Streaming.State.Abandoned, g.GetState(id));

            // An abandoned stream admits nothing — chunk, checkpoint, commit, and a StreamOpen reusing
            // the id are all rejected StreamStateError (the id is never re-admitted).
            var chunks = new List<Streaming.Chunk> { new Streaming.Chunk(0, System.Text.Encoding.ASCII.GetBytes("payload")) };
            var commit = new Streaming.StreamCommit(id, Streaming.CommitDigest(chunks));
            WantKind(() => g.Chunk(id), "StreamStateError");
            WantKind(() => g.Checkpoint(id), "StreamStateError");
            WantKind(() => g.Commit(commit, chunks), "StreamStateError");
            WantKind(() => g.Open(open, Policy.IDEMPOTENT_WRITE), "StreamStateError");

            Assert.Equal(Streaming.State.Abandoned, g.GetState(id));
        }

        // ---- (g) expire on a non-open stream is a state error --------------------------------------------

        /// <summary>The idle/commit timer clears when a StreamCommit transitions the stream to committed
        /// (§ Timers), so a correct caller fires Expire only while the stream is open. Expire on an idle,
        /// committed, or already-abandoned stream is therefore rejected StreamStateError and leaves the
        /// state unchanged (fail-closed).</summary>
        [Fact]
        public void GuardExpireOnNonOpenIsStateError()
        {
            // idle: nothing has been opened.
            {
                byte[] id = System.Text.Encoding.ASCII.GetBytes("stream-expire-idle");
                var g = new Streaming.Guard();
                WantKind(() => g.Expire(id), "StreamStateError");
                Assert.Equal(Streaming.State.Idle, g.GetState(id));
            }

            // committed: the timer should have cleared on commit; a spurious Expire is a state error and
            // must not turn a committed (non-repudiable) stream into an abandoned one.
            {
                byte[] id = System.Text.Encoding.ASCII.GetBytes("stream-expire-committed");
                var g = new Streaming.Guard();
                Streaming.StreamOpen open = OpenFor(id);
                g.Open(open, Policy.IDEMPOTENT_WRITE);
                var chunks = new List<Streaming.Chunk> { new Streaming.Chunk(0, System.Text.Encoding.ASCII.GetBytes("payload")) };
                var commit = new Streaming.StreamCommit(id, Streaming.CommitDigest(chunks));
                g.Commit(commit, chunks);
                WantKind(() => g.Expire(id), "StreamStateError");
                Assert.Equal(Streaming.State.Committed, g.GetState(id));
            }

            // already abandoned: a second Expire is a state error and a no-op.
            {
                byte[] id = System.Text.Encoding.ASCII.GetBytes("stream-expire-twice");
                var g = new Streaming.Guard();
                Streaming.StreamOpen open = OpenFor(id);
                g.Open(open, Policy.IDEMPOTENT_WRITE);
                g.Expire(id); // first expire
                WantKind(() => g.Expire(id), "StreamStateError");
                Assert.Equal(Streaming.State.Abandoned, g.GetState(id));
            }
        }
    }
}
