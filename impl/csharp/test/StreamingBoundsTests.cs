// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System.Collections.Generic;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// The stream chunk-count bound (design.md §3.4, R7), ported from
    /// impl/go/streaming/bounds_test.go. A commit over exactly MaxStreamChunks chunks verifies, and
    /// one over MaxStreamChunks+1 is rejected TooManyChunks. Both carry a MATCHING rolling digest, so
    /// the count is the only reason to reject — deleting the count check makes the +1 case verify
    /// (the mutation is caught). The chunks share one backing array to bound test memory.
    /// </summary>
    public sealed class StreamingBoundsTests
    {
        [Fact]
        public void BoundTooManyChunks()
        {
            var over = new List<Streaming.Chunk>((int)Envelope.MaxStreamChunks + 1);
            for (int i = 0; i <= Envelope.MaxStreamChunks; i++)
            {
                over.Add(new Streaming.Chunk(0, new byte[0]));
            }
            var atLimit = over.GetRange(0, (int)Envelope.MaxStreamChunks);

            var okCommit = new Streaming.StreamCommit(new byte[0], Streaming.CommitDigest(atLimit));
            Streaming.VerifyCommit(okCommit, atLimit); // must not throw

            var overCommit = new Streaming.StreamCommit(new byte[0], Streaming.CommitDigest(over));
            var ex = Assert.Throws<NaalpException>(() => Streaming.VerifyCommit(overCommit, over));
            Assert.Equal("TooManyChunks", ex.Kind);

            // VerifyCheckpoint enforces the same bound, and the count check fires before the
            // contiguity/digest checks, so the diagnosis is TooManyChunks (not a digest error).
            var cpEx = Assert.Throws<NaalpException>(() =>
                Streaming.VerifyCheckpoint(new Streaming.StreamCheckpoint(new byte[0], 0, new byte[0]), over));
            Assert.Equal("TooManyChunks", cpEx.Kind);
        }
    }
}
