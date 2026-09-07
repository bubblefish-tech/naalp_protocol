// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// C9 — native streaming with a single signed per-stream commitment for the C# SDK (design.md §10;
    /// R-10.1..10.6), ported from impl/go/streaming and cross-checked against
    /// impl/python/naalp/streaming.py. Graded against the shared independent corpus
    /// <c>vectors/stream/cases.json</c> (the oracle directory is <c>stream</c>, NOT <c>streaming</c>),
    /// which is NOT produced by this code.
    ///
    /// <para>BYTE surface (⟹ csharp == Go == Rust == Python == oracle): the StreamOpen / StreamCommit /
    /// StreamCheckpoint body hexes, the final rolling-SHA-384 commitment, each checkpoint digest_so_far,
    /// and the oracle-pinned tampered digest. Behaviour: order-independence of the commitment
    /// (reversed-input-same-digest) versus offset-sensitivity (swapped-offset-different-digest), prefix
    /// checkpoints, and tamper → StreamDigestMismatch. FULL-SIG (real deterministic ML-DSA-65, rnd=0):
    /// the raw StreamOpen/Commit/Checkpoint signatures round-trip (a raw ML-DSA signature over the body,
    /// matching impl/go/streaming; not corpus-graded).</para>
    /// </summary>
    public sealed class StreamingTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "stream", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/stream/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        private static List<Streaming.Chunk> Chunks(JsonElement v)
        {
            var outp = new List<Streaming.Chunk>();
            foreach (JsonElement c in v.GetProperty("chunks").EnumerateArray())
            {
                outp.Add(new Streaming.Chunk(c.GetProperty("offset").GetInt64(), Hb(c.GetProperty("data_hex").GetString()!)));
            }
            return outp;
        }

        // ---- StreamOpen / StreamCommit / StreamCheckpoint body parity + the rolling commitment ------

        [Fact]
        public void BodyParityAndCommitment()
        {
            JsonElement v = Vector();
            byte[] streamId = Hb(v.GetProperty("stream_id_hex").GetString()!);
            long substream = v.GetProperty("substream").GetInt64();
            long effect = v.GetProperty("effect").GetInt64();
            byte[] approval = Hb(v.GetProperty("approval_hex").GetString()!);

            var open = new Streaming.StreamOpen(streamId, effect, approval, substream);
            Assert.Equal(v.GetProperty("open_body_hex").GetString(), Hex(open.Bytes()));

            List<Streaming.Chunk> chunks = Chunks(v);
            byte[] digest = Streaming.CommitDigest(chunks);
            Assert.Equal(v.GetProperty("final_digest_hex").GetString(), Hex(digest));

            var commit = new Streaming.StreamCommit(streamId, digest);
            Assert.Equal(v.GetProperty("commit_body_hex").GetString(), Hex(commit.Bytes()));

            // The first checkpoint's body encodes byte-identically (through_offset 6, digest_so_far).
            JsonElement cp0 = v.GetProperty("checkpoints")[0];
            var checkpoint = new Streaming.StreamCheckpoint(streamId, cp0.GetProperty("through_offset").GetInt64(),
                Hb(cp0.GetProperty("digest_so_far_hex").GetString()!));
            Assert.Equal(v.GetProperty("checkpoint_body_hex").GetString(), Hex(checkpoint.Bytes()));

            // Every checkpoint's digest_so_far is the rolling digest of the prefix through its offset.
            foreach (JsonElement cp in v.GetProperty("checkpoints").EnumerateArray())
            {
                long through = cp.GetProperty("through_offset").GetInt64();
                var prefix = new List<Streaming.Chunk>();
                foreach (Streaming.Chunk c in chunks) if (c.Offset < through) prefix.Add(c);
                Assert.Equal(cp.GetProperty("digest_so_far_hex").GetString(), Hex(Streaming.CommitDigest(prefix)));
                // VerifyCheckpoint confirms the prefix.
                var checkpointObj = new Streaming.StreamCheckpoint(streamId, through, Streaming.CommitDigest(prefix));
                Streaming.VerifyCheckpoint(checkpointObj, prefix); // must not throw
            }

            // VerifyCommit confirms the completed commitment.
            Streaming.VerifyCommit(commit, chunks); // must not throw
        }

        // ---- order-independence of the commitment (MUTATION ANCHOR) --------------------------------
        // MUTATION ANCHOR: dropping the absolute-offset sort in CommitDigest makes a reversed delivery
        // of the SAME frames fold in a different order, flipping the reversed-input-same-digest
        // Assert.Equal below.

        [Fact]
        public void CommitmentIsOrderIndependentButOffsetSensitive()
        {
            JsonElement v = Vector();
            List<Streaming.Chunk> chunks = Chunks(v);
            byte[] forward = Streaming.CommitDigest(chunks);

            // A reversed delivery of the SAME frames (same offset->data pairing) yields the SAME digest:
            // CommitDigest folds in absolute-offset order regardless of delivery order.
            var reversed = new List<Streaming.Chunk>(chunks);
            reversed.Reverse();
            Assert.Equal(Hex(forward), Hex(Streaming.CommitDigest(reversed)));
            Assert.Equal(v.GetProperty("final_digest_hex").GetString(), Hex(Streaming.CommitDigest(reversed)));

            // But SWAPPING which bytes sit at which offset changes the digest (offset-sensitive): the
            // commitment is over data-in-offset-order, not a set of frames.
            var swapped = new List<Streaming.Chunk>
            {
                new Streaming.Chunk(chunks[0].Offset, chunks[1].Data),
                new Streaming.Chunk(chunks[1].Offset, chunks[0].Data),
                chunks[2],
            };
            Assert.NotEqual(Hex(forward), Hex(Streaming.CommitDigest(swapped)));
        }

        // ---- tamper: a flipped delivered byte breaks the commitment (oracle-pinned tamper digest) ---

        [Fact]
        public void TamperBreaksCommitment()
        {
            JsonElement v = Vector();
            byte[] streamId = Hb(v.GetProperty("stream_id_hex").GetString()!);
            List<Streaming.Chunk> chunks = Chunks(v);
            byte[] goodDigest = Streaming.CommitDigest(chunks);
            var commit = new Streaming.StreamCommit(streamId, goodDigest);

            JsonElement tamper = v.GetProperty("tamper");
            int idx = tamper.GetProperty("chunk_index").GetInt32();
            var tampered = new List<Streaming.Chunk>(chunks);
            tampered[idx] = new Streaming.Chunk(chunks[idx].Offset, Hb(tamper.GetProperty("flipped_data_hex").GetString()!));

            // The tampered stream's recomputed digest equals the oracle-pinned tampered digest (a
            // non-circular check: the expected value is in the corpus, not from this code).
            Assert.Equal(tamper.GetProperty("digest_hex").GetString(), Hex(Streaming.CommitDigest(tampered)));

            // Verifying the tampered delivery against the honest commitment fails closed.
            var ex = Assert.Throws<NaalpException>(() => Streaming.VerifyCommit(commit, tampered));
            Assert.Equal("StreamDigestMismatch", ex.Kind);

            // A non-contiguous prefix, or a wrong through_offset, is StreamDigestMismatch too.
            var badPrefix = new List<Streaming.Chunk> { chunks[0], chunks[2] }; // gap: offset 6..16 missing
            var cp = new Streaming.StreamCheckpoint(streamId, 6, Streaming.CommitDigest(new List<Streaming.Chunk> { chunks[0] }));
            var exCp = Assert.Throws<NaalpException>(() => Streaming.VerifyCheckpoint(cp, badPrefix));
            Assert.Equal("StreamDigestMismatch", exCp.Kind);
        }

        // ---- effect authorization + full-signature round-trip (real ML-DSA, demonstrated isolation) --

        [Fact]
        public void OpenAuthorizationAndSignatures()
        {
            JsonElement v = Vector();
            byte[] streamId = Hb(v.GetProperty("stream_id_hex").GetString()!);
            long substream = v.GetProperty("substream").GetInt64();
            long effect = v.GetProperty("effect").GetInt64(); // idempotent_write (1)
            byte[] approval = Hb(v.GetProperty("approval_hex").GetString()!);
            var open = new Streaming.StreamOpen(streamId, effect, approval, substream);

            // A ceiling that authorizes idempotent_write admits the stream; a read-only ceiling refuses.
            Streaming.OpenStream(open, Policy.IDEMPOTENT_WRITE); // must not throw
            var ex = Assert.Throws<NaalpException>(() => Streaming.OpenStream(open, Policy.READ_ONLY));
            Assert.Equal("EffectNotAuthorized", ex.Kind);

            byte[] seed = new byte[32];
            for (int i = 0; i < 32; i++) seed[i] = 0x11;
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);
            byte[] foreignSeed = new byte[32];
            for (int i = 0; i < 32; i++) foreignSeed[i] = 0x22;
            byte[] foreignPk = Cose.MldsaKeygen("ML-DSA-65", foreignSeed);

            List<Streaming.Chunk> chunks = Chunks(v);
            var commit = new Streaming.StreamCommit(streamId, Streaming.CommitDigest(chunks));
            var checkpoint = new Streaming.StreamCheckpoint(streamId,
                v.GetProperty("checkpoints")[0].GetProperty("through_offset").GetInt64(),
                Hb(v.GetProperty("checkpoints")[0].GetProperty("digest_so_far_hex").GetString()!));

            // The three signed objects verify under the owner's key and NOT under a foreign key.
            byte[] openSig = Streaming.SignOpen(open, Alg, seed);
            Assert.True(Streaming.VerifyOpenSig(open, Alg, pk, openSig));
            Assert.False(Streaming.VerifyOpenSig(open, Alg, foreignPk, openSig));

            byte[] commitSig = Streaming.SignCommit(commit, Alg, seed);
            Assert.True(Streaming.VerifyCommitSig(commit, Alg, pk, commitSig));

            byte[] cpSig = Streaming.SignCheckpoint(checkpoint, Alg, seed);
            Assert.True(Streaming.VerifyCheckpointSig(checkpoint, Alg, pk, cpSig));
        }
    }
}
