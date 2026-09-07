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
    /// C17 N-AALP-CONT conformance for the C# SDK, graded against the shared independent corpus
    /// <c>vectors/continuation/cases.json</c> (NOT produced by this code): the one signed FlowOpen's
    /// body/head/id, the cheap Continuation hash-chain links, the VerifyChain final head, the Checkpoint
    /// prefix confirmation and gap detection, the 2-field FlowCommit, the big-seq (&gt;2^53) round-trip,
    /// the u64::MAX overflow, and the closed-lattice / wrong-flow / non-canonical / look-alike rejections.
    ///
    /// <para>CORPUS-GRADED (pure bytes / verdicts): every FlowOpen/Continuation/Checkpoint/FlowCommit
    /// body and head, the final chain head, the big-seq round-trip, and the AboveCeiling / RangeError /
    /// WrongFlow / GapDetected / NonCanonical / ContMalformed rejections. The u64::MAX overflow checkpoint
    /// is DECODE-graded — the shared shortest-form encoder refuses a &gt;=2^63 uint (as in the Go/Java/
    /// Kotlin ports), so the overflow body is only ever received and rejected: ParseCheckpoint recovers
    /// through_seq == u64::MAX and VerifyCheckpoint reports GapDetected. WIRING DEMONSTRATED IN ISOLATION:
    /// the FlowOpen / FlowCommit full signatures are real deterministic ML-DSA-65 (COSE_Sign1), verified
    /// here with a local seed (the corpus carries no signature vector) — stated honestly. Ported from
    /// impl/go/continuation; mirrors the Java/Kotlin ports.</para>
    /// </summary>
    public sealed class ContinuationTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "continuation", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/continuation/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        private static Continuation.FlowOpen OpenFrom(JsonElement v)
        {
            JsonElement fo = v.GetProperty("flow_open");
            var apps = new List<byte[]>();
            foreach (JsonElement a in fo.GetProperty("approvals_hex").EnumerateArray())
            {
                apps.Add(Hb(a.GetString()!));
            }
            return new Continuation.FlowOpen(Hb(fo.GetProperty("flow_id_hex").GetString()!), fo.GetProperty("effect_ceiling").GetInt64(), apps);
        }

        private static List<Continuation> ContsFrom(JsonElement v)
        {
            byte[] id = Hb(v.GetProperty("flow_open").GetProperty("id_hex").GetString()!);
            var outp = new List<Continuation>();
            foreach (JsonElement c in v.GetProperty("continuations").EnumerateArray())
            {
                outp.Add(new Continuation(id, c.GetProperty("seq").GetInt64(), c.GetProperty("effect").GetInt64(),
                    Hb(c.GetProperty("payload_id_hex").GetString()!), Hb(c.GetProperty("prev_hex").GetString()!)));
            }
            return outp;
        }

        // ---- byte parity (the mutation-target byte surface) -----------------------------------

        [Fact]
        public void ByteParityAgainstOracle()
        {
            JsonElement v = Vector();
            Continuation.FlowOpen open = OpenFrom(v);
            JsonElement fo = v.GetProperty("flow_open");
            Assert.Equal(fo.GetProperty("body_hex").GetString(), Hex(open.Bytes()));
            Assert.Equal(fo.GetProperty("head_hex").GetString(), Hex(open.Head()));
            Assert.Equal(fo.GetProperty("id_hex").GetString(), Hex(open.Id()));

            List<Continuation> conts = ContsFrom(v);
            int i = 0;
            foreach (JsonElement c in v.GetProperty("continuations").EnumerateArray())
            {
                Assert.Equal(c.GetProperty("body_hex").GetString(), Hex(conts[i].Bytes()));
                Assert.Equal(c.GetProperty("head_hex").GetString(), Hex(conts[i].Head()));
                i++;
            }

            var cp = new Continuation.Checkpoint(open.Id(), v.GetProperty("checkpoint").GetProperty("through_seq").GetInt64(),
                Hb(v.GetProperty("checkpoint").GetProperty("head_hex").GetString()!));
            Assert.Equal(v.GetProperty("checkpoint").GetProperty("body_hex").GetString(), Hex(cp.Bytes()));

            var fc = new Continuation.FlowCommit(open.Id(), Hb(v.GetProperty("flow_commit").GetProperty("final_head_hex").GetString()!));
            Assert.Equal(v.GetProperty("flow_commit").GetProperty("body_hex").GetString(), Hex(fc.Bytes()));
        }

        [Fact]
        public void VerifyChainReachesFinalHead()
        {
            JsonElement v = Vector();
            byte[] final = Continuation.VerifyChain(OpenFrom(v), ContsFrom(v));
            Assert.Equal(v.GetProperty("final_head_hex").GetString(), Hex(final));
        }

        [Fact]
        public void ReconstructFromBytesAlone()
        {
            JsonElement v = Vector();
            Continuation.FlowOpen open = OpenFrom(v);
            Continuation.FlowOpen got = Continuation.ParseFlowOpen(open.Bytes());
            Assert.Equal(open.EffectCeiling, got.EffectCeiling);
            Assert.Equal(Hex(open.FlowId), Hex(got.FlowId));
            Assert.Equal(open.Approvals.Count, got.Approvals.Count);
            Assert.Equal(Hex(open.Id()), Hex(got.Id())); // round-trips to the same id
        }

        [Fact]
        public void ReplayUnderDifferentFlowFails()
        {
            JsonElement v = Vector();
            Continuation.FlowOpen openA = OpenFrom(v);
            List<Continuation> conts = ContsFrom(v);
            long ceiling = openA.EffectCeiling;
            byte[] openBId = Hb(v.GetProperty("replay").GetProperty("flow_open_b_id_hex").GetString()!);
            byte[] openBHead = Hb(v.GetProperty("replay").GetProperty("flow_open_b_head_hex").GetString()!);

            // (a) As delivered: the continuation still names flow A -> WrongFlow under B.
            var wf = Assert.Throws<NaalpException>(() => Continuation.VerifyContinuation(conts[0], openBId, openBHead, 0, ceiling));
            Assert.Equal("WrongFlow", wf.Kind);
            // (b) Attacker rewrites the id to B's: now prev (head of A) no longer chains to B's head.
            var forged = new Continuation(openBId, conts[0].Seq, conts[0].Effect, conts[0].PayloadId, conts[0].Prev);
            var cb = Assert.Throws<NaalpException>(() => Continuation.VerifyContinuation(forged, openBId, openBHead, 0, ceiling));
            Assert.Equal("ChainBroken", cb.Kind);
            // Sanity: the same continuation DOES verify under its own FlowOpen A (positive control).
            Continuation.VerifyContinuation(conts[0], openA.Id(), openA.Head(), 0, ceiling);
        }

        [Fact]
        public void AboveCeilingRejected()
        {
            // A continuation whose effect exceeds the ceiling is refused AboveCeiling — the cheap path can
            // never escalate past the one full signature. THIS is the mutation-target assertion: removing
            // the ceiling.Authorizes check in VerifyContinuation lets the destructive step pass.
            JsonElement v = Vector();
            Continuation.FlowOpen open = OpenFrom(v);
            long ceiling = open.EffectCeiling;
            JsonElement ac = v.GetProperty("above_ceiling");
            var above = new Continuation(open.Id(), ac.GetProperty("seq").GetInt64(), ac.GetProperty("effect").GetInt64(),
                Hb(ac.GetProperty("payload_id_hex").GetString()!), Hb(ac.GetProperty("prev_hex").GetString()!));
            Assert.Equal(ac.GetProperty("body_hex").GetString(), Hex(above.Bytes())); // byte parity of the forbidden body
            var ex = Assert.Throws<NaalpException>(
                () => Continuation.VerifyContinuation(above, open.Id(), Hb(ac.GetProperty("prev_hex").GetString()!), ac.GetProperty("seq").GetInt64(), ceiling));
            Assert.Equal(ac.GetProperty("reject").GetString(), ex.Kind); // AboveCeiling
            // A within-ceiling effect at the same position is accepted (positive control).
            var ok = new Continuation(open.Id(), ac.GetProperty("seq").GetInt64(), Policy.NON_IDEMPOTENT_WRITE,
                above.PayloadId, above.Prev);
            Continuation.VerifyContinuation(ok, open.Id(), above.Prev, ac.GetProperty("seq").GetInt64(), ceiling);
        }

        [Fact]
        public void CheckpointDetectsGap()
        {
            JsonElement v = Vector();
            Continuation.FlowOpen open = OpenFrom(v);
            List<Continuation> conts = ContsFrom(v);
            long through = v.GetProperty("checkpoint").GetProperty("through_seq").GetInt64();
            byte[] cpHead = Hb(v.GetProperty("checkpoint").GetProperty("head_hex").GetString()!);

            // Honest checkpoint over seq 0..1 verifies.
            var cp = new Continuation.Checkpoint(open.Id(), through, cpHead);
            Continuation.VerifyCheckpoint(cp, open, conts.GetRange(0, (int)through + 1));

            // Gap: claim through_seq 2 but deliver only [seq0, seq2] (seq1 dropped).
            var gapPrefix = new List<Continuation> { conts[0], conts[2] };
            var gapCp = new Continuation.Checkpoint(open.Id(), v.GetProperty("gap").GetProperty("through_seq").GetInt64(),
                Hb(v.GetProperty("final_head_hex").GetString()!));
            var g1 = Assert.Throws<NaalpException>(() => Continuation.VerifyCheckpoint(gapCp, open, gapPrefix));
            Assert.Equal("GapDetected", g1.Kind);

            // Reorder: [seq1, seq0] with the right count is still a gap (seq mismatch at index 0).
            var reordered = new List<Continuation> { conts[1], conts[0] };
            var rcp = new Continuation.Checkpoint(open.Id(), 1, cpHead);
            var g2 = Assert.Throws<NaalpException>(() => Continuation.VerifyCheckpoint(rcp, open, reordered));
            Assert.Equal("GapDetected", g2.Kind);

            // Tampered head with the right prefix is also GapDetected.
            byte[] badHead = (byte[])cpHead.Clone();
            badHead[0] ^= 0x01;
            var badCp = new Continuation.Checkpoint(open.Id(), through, badHead);
            var g3 = Assert.Throws<NaalpException>(() => Continuation.VerifyCheckpoint(badCp, open, conts.GetRange(0, (int)through + 1)));
            Assert.Equal("GapDetected", g3.Kind);
        }

        [Fact]
        public void RangeRejectClosedLattice()
        {
            JsonElement v = Vector();
            JsonElement rr = v.GetProperty("range_reject");
            long bad = rr.GetProperty("out_of_lattice_value").GetInt64(); // 4
            Assert.True(bad > Policy.DESTRUCTIVE, "fixture out_of_lattice_value must be outside the lattice");
            Continuation.FlowOpen open = OpenFrom(v);

            // (a) ceiling = 4: byte parity, ParseFlowOpen and VerifyChain both reject RangeError.
            var badOpen = new Continuation.FlowOpen(open.FlowId, bad, open.Approvals);
            Assert.Equal(rr.GetProperty("flow_open_ceiling_body_hex").GetString(), Hex(badOpen.Bytes()));
            Assert.Equal("RangeError", Assert.Throws<NaalpException>(() => Continuation.ParseFlowOpen(Hb(rr.GetProperty("flow_open_ceiling_body_hex").GetString()!))).Kind);
            Assert.Equal("RangeError", Assert.Throws<NaalpException>(() => Continuation.VerifyChain(badOpen, new List<Continuation>())).Kind);

            // (b) effect = 4: byte parity, ParseContinuation and VerifyContinuation both reject RangeError.
            byte[] payload0 = Hb(v.GetProperty("continuations")[0].GetProperty("payload_id_hex").GetString()!);
            var badCont = new Continuation(open.Id(), 0, bad, payload0, open.Head());
            Assert.Equal(rr.GetProperty("continuation_effect_body_hex").GetString(), Hex(badCont.Bytes()));
            Assert.Equal("RangeError", Assert.Throws<NaalpException>(() => Continuation.ParseContinuation(Hb(rr.GetProperty("continuation_effect_body_hex").GetString()!))).Kind);
            Assert.Equal("RangeError", Assert.Throws<NaalpException>(() => Continuation.VerifyContinuation(badCont, open.Id(), open.Head(), 0, Policy.DESTRUCTIVE)).Kind);

            // An out-of-lattice CEILING passed to VerifyContinuation is also RangeError (never top-of-lattice).
            var okCont = new Continuation(open.Id(), 0, 0, payload0, open.Head());
            Assert.Equal("RangeError", Assert.Throws<NaalpException>(() => Continuation.VerifyContinuation(okCont, open.Id(), open.Head(), 0, bad)).Kind);
        }

        [Fact]
        public void CheckpointOverflowDecodeAndReject()
        {
            // through_seq = u64::MAX: the shared shortest-form encoder refuses a >=2^63 uint (as in the
            // Go/Java/Kotlin ports), so the overflow checkpoint is DECODE-graded — ParseCheckpoint recovers
            // through_seq == u64::MAX from the oracle's own bytes, then VerifyCheckpoint reports GapDetected
            // (no MAX+1 contiguous links). Mutation: removing the u64::MAX guard false-verifies an empty
            // prefix.
            JsonElement v = Vector();
            JsonElement ov = v.GetProperty("checkpoint_overflow");
            Continuation.FlowOpen open = OpenFrom(v);
            Continuation.Checkpoint cp = Continuation.ParseCheckpoint(Hb(ov.GetProperty("body_hex").GetString()!));
            Assert.Equal(ov.GetProperty("through_seq_str").GetString(), ((ulong)cp.ThroughSeq).ToString()); // round-trips u64::MAX
            var ex = Assert.Throws<NaalpException>(() => Continuation.VerifyCheckpoint(cp, open, new List<Continuation>()));
            Assert.Equal(ov.GetProperty("reject").GetString(), ex.Kind); // GapDetected
        }

        [Fact]
        public void BigSeqRoundTrip()
        {
            // A seq above 2^53 (0x0102030405060708 = 72623859790382856, < 2^63) round-trips byte-exact —
            // uint64 all the way, no float64. The oracle carries it as a JSON string; parse with a 64-bit
            // integer parser so the low octets are never rounded.
            JsonElement v = Vector();
            JsonElement bs = v.GetProperty("big_seq");
            long seq = long.Parse(bs.GetProperty("seq_str").GetString()!);
            Assert.True(seq > (1L << 53), "fixture big seq must be > 2^53");
            Continuation.FlowOpen open = OpenFrom(v);
            var c = new Continuation(open.Id(), seq, bs.GetProperty("effect").GetInt64(),
                Hb(bs.GetProperty("payload_id_hex").GetString()!), Hb(bs.GetProperty("prev_hex").GetString()!));
            Assert.Equal(bs.GetProperty("body_hex").GetString(), Hex(c.Bytes()));
            Assert.Equal(bs.GetProperty("head_hex").GetString(), Hex(c.Head()));
            Continuation got = Continuation.ParseContinuation(c.Bytes());
            Assert.Equal(seq, got.Seq); // survives byte-exact through decode
        }

        [Fact]
        public void MinimalFlowOpen()
        {
            JsonElement v = Vector();
            JsonElement mn = v.GetProperty("minimal");
            var apps = new List<byte[]>();
            foreach (JsonElement a in mn.GetProperty("approvals_hex").EnumerateArray())
            {
                apps.Add(Hb(a.GetString()!));
            }
            var m = new Continuation.FlowOpen(Hb(mn.GetProperty("flow_id_hex").GetString()!), mn.GetProperty("effect_ceiling").GetInt64(), apps);
            Assert.Equal(mn.GetProperty("body_hex").GetString(), Hex(m.Bytes()));
            Assert.Equal(mn.GetProperty("head_hex").GetString(), Hex(m.Head()));
            Assert.Equal(mn.GetProperty("id_hex").GetString(), Hex(m.Id()));
            Assert.Equal(Hex(m.Id()), Hex(Continuation.ParseFlowOpen(m.Bytes()).Id()));
        }

        [Fact]
        public void EmptyVsNonemptyApprovals()
        {
            JsonElement v = Vector();
            JsonElement fo = v.GetProperty("flow_open");
            JsonElement evn = v.GetProperty("empty_vs_nonempty");
            var empty = new Continuation.FlowOpen(Hb(fo.GetProperty("flow_id_hex").GetString()!), fo.GetProperty("effect_ceiling").GetInt64(), new List<byte[]>());
            var one = new Continuation.FlowOpen(Hb(fo.GetProperty("flow_id_hex").GetString()!), fo.GetProperty("effect_ceiling").GetInt64(),
                new List<byte[]> { Hb(fo.GetProperty("approvals_hex")[0].GetString()!) });
            Assert.Equal(evn.GetProperty("empty_approvals").GetProperty("body_hex").GetString(), Hex(empty.Bytes()));
            Assert.Equal(evn.GetProperty("one_approval").GetProperty("body_hex").GetString(), Hex(one.Bytes()));
            Assert.Equal(evn.GetProperty("empty_approvals").GetProperty("id_hex").GetString(), Hex(empty.Id()));
            Assert.NotEqual(Hex(empty.Id()), Hex(one.Id())); // empty != populated on the wire and by id
        }

        [Fact]
        public void KeysOutOfOrderRejected()
        {
            JsonElement v = Vector();
            JsonElement koo = v.GetProperty("keys_out_of_order");
            Continuation.FlowOpen open = OpenFrom(v);
            var fc = new Continuation.FlowCommit(open.Id(), Hb(v.GetProperty("final_head_hex").GetString()!));
            Assert.Equal(koo.GetProperty("canonical_commit_body_hex").GetString(), Hex(fc.Bytes())); // canonical == ascending keys
            Cbor.Decode(Hb(koo.GetProperty("canonical_commit_body_hex").GetString()!)); // canonical decodes
            var ex = Assert.Throws<NaalpException>(() => Cbor.Decode(Hb(koo.GetProperty("noncanonical_commit_body_hex").GetString()!)));
            Assert.Equal("NonCanonical", ex.Kind); // descending keys rejected by the strict decoder
        }

        [Fact]
        public void LookAlikeRejectedBySibling()
        {
            JsonElement v = Vector();
            byte[] commitBody = Hb(v.GetProperty("look_alike").GetProperty("flow_commit_body_hex").GetString()!);
            Assert.Equal("ContMalformed", Assert.Throws<NaalpException>(() => Continuation.ParseCheckpoint(commitBody)).Kind);
            Assert.Equal("ContMalformed", Assert.Throws<NaalpException>(() => Continuation.ParseContinuation(commitBody)).Kind);
        }

        // ---- full-signature demonstrated in isolation (real ML-DSA-65, NOT corpus-graded) -----

        [Fact]
        public void FlowOpenFullSignatureIsolation()
        {
            JsonElement v = Vector();
            Continuation.FlowOpen open = OpenFrom(v);
            byte[] seed = Seed(0x11);
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);
            byte[] foreignPk = Cose.MldsaKeygen("ML-DSA-65", Seed(0x22));

            byte[] obj1 = Continuation.SignFlowOpen(open, Alg, seed);
            byte[] obj2 = Continuation.SignFlowOpen(open, Alg, seed);
            Assert.Equal(Hex(obj1), Hex(obj2)); // deterministic ML-DSA (rnd=0)
            Continuation.FlowOpen got = Continuation.VerifyFlowOpen(obj1, Alg, pk);
            Assert.Equal(open.EffectCeiling, got.EffectCeiling);
            Assert.Equal(Hex(open.Id()), Hex(got.Id())); // reconstructs the authority
            Assert.Equal("BadSignature", Assert.Throws<NaalpException>(() => Continuation.VerifyFlowOpen(obj1, Alg, foreignPk)).Kind);
        }

        [Fact]
        public void FlowCommitFullSignatureIsolation()
        {
            JsonElement v = Vector();
            Continuation.FlowOpen open = OpenFrom(v);
            List<Continuation> conts = ContsFrom(v);
            byte[] seed = Seed(0x11);
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);
            byte[] foreignPk = Cose.MldsaKeygen("ML-DSA-65", Seed(0x22));

            var fc = new Continuation.FlowCommit(open.Id(), Hb(v.GetProperty("final_head_hex").GetString()!));
            byte[] obj = Continuation.SignFlowCommit(fc, Alg, seed);
            Continuation.VerifyFlowCommit(obj, Alg, pk, open, conts); // honest (no throw)
            Assert.Equal("BadSignature", Assert.Throws<NaalpException>(() => Continuation.VerifyFlowCommit(obj, Alg, foreignPk, open, conts)).Kind);
            // Missing the last continuation -> recomputed final head differs -> CommitMismatch.
            Assert.Equal("CommitMismatch", Assert.Throws<NaalpException>(() => Continuation.VerifyFlowCommit(obj, Alg, pk, open, conts.GetRange(0, 2))).Kind);
            // Tampered final_head in the signed body -> the signature no longer matches the tampered bytes.
            byte[] badFinal = (byte[])fc.FinalHead.Clone();
            badFinal[0] ^= 0x01;
            byte[] badObj = Continuation.SignFlowCommit(new Continuation.FlowCommit(open.Id(), badFinal), Alg, seed);
            Assert.Equal("CommitMismatch", Assert.Throws<NaalpException>(() => Continuation.VerifyFlowCommit(badObj, Alg, pk, open, conts)).Kind);
        }

        private static byte[] Seed(byte b)
        {
            var s = new byte[32];
            for (int i = 0; i < 32; i++) s[i] = b;
            return s;
        }
    }
}
