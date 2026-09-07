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
    /// C7 audit conformance for the C# SDK, graded against the shared independent corpus
    /// <c>vectors/audit/cases.json</c> (NOT produced by this code): the hash-chained signed receipt
    /// body + head, offline chain verification (ChainBroken / ReceiptUnsigned), equivocation
    /// detection, the draft-01 fork-proof preimage (signatures elided), and the offline causal graph
    /// (valid topo order, cycle rejection, future-cause rejection).
    ///
    /// <para>The receipt/fork-proof SIGNATURES are real deterministic ML-DSA-65 (BouncyCastle, rnd=0),
    /// but the corpus carries no signature vector for this channel (signatures are graded by the shared
    /// cose byte-parity — the worked-example / gateway pins), so the sign/verify round-trips here are
    /// demonstrated in isolation with a fixed local seed — stated honestly, not corpus-graded. Every
    /// byte-exact assertion (body/head/preimage/topo) IS corpus-graded. Ported from impl/go/audit;
    /// mirrors impl/python/tests/test_audit.py.</para>
    /// </summary>
    public sealed class AuditTests
    {
        private const int Alg = Cose.ALG_MLDSA65;
        private static readonly byte[] Seed = new byte[32];
        private static readonly byte[] Pk = Cose.MldsaKeygen("ML-DSA-65", Seed);

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "audit", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/audit/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        // ---- signed hash-chained receipt (design §8.1) ----------------------------------------

        [Fact]
        public void ChainReceiptsMatchOracle()
        {
            JsonElement v = Vector();
            JsonElement chain = v.GetProperty("chain");
            byte[] head = Hb(chain.GetProperty("genesis_prev_hex").GetString()!);
            Assert.Equal(Audit.HeadSize, head.Length);
            foreach (JsonElement rv in chain.GetProperty("receipts").EnumerateArray())
            {
                var r = new Audit.Receipt(
                    Hb(rv.GetProperty("prev_hex").GetString()!),
                    Hb(rv.GetProperty("obj_hex").GetString()!),
                    rv.GetProperty("seq").GetInt64(),
                    rv.GetProperty("at").GetInt64());
                Assert.Equal(rv.GetProperty("body_hex").GetString(), Hex(r.Bytes()));
                Assert.Equal(rv.GetProperty("head_after_hex").GetString(), Hex(r.Head()));
                Assert.Equal(Hex(head), Hex(r.Prev));
                head = r.Head();
            }
            Assert.Equal(chain.GetProperty("final_head_hex").GetString(), Hex(head));
        }

        [Fact]
        public void AuthorityReproducesChainAndVerifies()
        {
            JsonElement v = Vector();
            var authority = new Audit.Authority(Alg, Seed);
            var receipts = new List<Audit.Receipt>();
            var sigs = new List<byte[]>();
            foreach (JsonElement rv in v.GetProperty("chain").GetProperty("receipts").EnumerateArray())
            {
                (Audit.Receipt r, byte[] sig) = authority.Append(
                    Hb(rv.GetProperty("obj_hex").GetString()!), rv.GetProperty("at").GetInt64());
                Assert.Equal(rv.GetProperty("body_hex").GetString(), Hex(r.Bytes()));
                receipts.Add(r);
                sigs.Add(sig);
            }
            Audit.VerifyChain(receipts, sigs, Alg, Pk); // real-ML-DSA chain verifies offline
        }

        [Fact]
        public void VerifyChainDetectsBrokenPrevLink()
        {
            JsonElement v = Vector();
            JsonElement cb = v.GetProperty("chain_broken");
            var receipts = new List<Audit.Receipt>();
            var sigs = new List<byte[]>();
            foreach (JsonElement rv in cb.GetProperty("receipts").EnumerateArray())
            {
                var r = new Audit.Receipt(
                    Hb(rv.GetProperty("prev_hex").GetString()!),
                    Hb(rv.GetProperty("obj_hex").GetString()!),
                    rv.GetProperty("seq").GetInt64(),
                    rv.GetProperty("at").GetInt64());
                Assert.Equal(rv.GetProperty("body_hex").GetString(), Hex(r.Bytes()));
                receipts.Add(r);
                sigs.Add(Cose.MldsaSign(Alg, Seed, r.Bytes())); // a real sig, so the BREAK is what fires
            }
            var ex = Assert.Throws<NaalpException>(() => Audit.VerifyChain(receipts, sigs, Alg, Pk));
            Assert.Equal(cb.GetProperty("expect").GetString(), ex.Kind); // ChainBroken
        }

        [Fact]
        public void VerifyChainDetectsTamperedSignature()
        {
            JsonElement v = Vector();
            JsonElement chain = v.GetProperty("chain");
            JsonElement rv0 = chain.GetProperty("receipts")[0];
            var r = new Audit.Receipt(
                Hb(chain.GetProperty("genesis_prev_hex").GetString()!),
                Hb(rv0.GetProperty("obj_hex").GetString()!),
                0, rv0.GetProperty("at").GetInt64());
            byte[] good = Cose.MldsaSign(Alg, Seed, r.Bytes());
            byte[] bad = (byte[])good.Clone();
            bad[bad.Length - 1] ^= 1;
            var ex = Assert.Throws<NaalpException>(
                () => Audit.VerifyChain(new List<Audit.Receipt> { r }, new List<byte[]> { bad }, Alg, Pk));
            Assert.Equal("ReceiptUnsigned", ex.Kind);
        }

        [Fact]
        public void ConsistentWithAnchor()
        {
            Assert.True(Audit.ConsistentWithAnchor(100, 100));
            Assert.True(Audit.ConsistentWithAnchor(99, 100));
            Assert.False(Audit.ConsistentWithAnchor(101, 100)); // created after ordered
        }

        // ---- equivocation detection (design §8.5) ---------------------------------------------

        private static (JsonElement F, Audit.Receipt A, Audit.Receipt B) ForkReceipts()
        {
            JsonElement v = Vector();
            JsonElement f = v.GetProperty("fork_proof");
            var ra = new Audit.Receipt(
                Hb(f.GetProperty("prev_hex").GetString()!), Hb(f.GetProperty("obj_a_hex").GetString()!),
                f.GetProperty("seq").GetInt64(), f.GetProperty("at").GetInt64());
            var rb = new Audit.Receipt(
                Hb(f.GetProperty("prev_hex").GetString()!), Hb(f.GetProperty("obj_b_hex").GetString()!),
                f.GetProperty("seq").GetInt64(), f.GetProperty("at").GetInt64());
            return (f, ra, rb);
        }

        [Fact]
        public void EquivocationReceiptsMatchOracle()
        {
            (JsonElement f, Audit.Receipt ra, Audit.Receipt rb) = ForkReceipts();
            Assert.Equal(f.GetProperty("body_a_hex").GetString(), Hex(ra.Bytes()));
            Assert.Equal(f.GetProperty("body_b_hex").GetString(), Hex(rb.Bytes()));
            JsonElement eq = Vector().GetProperty("equivocation");
            Assert.Equal(eq.GetProperty("receipt_a").GetProperty("body_hex").GetString(), Hex(ra.Bytes()));
            Assert.Equal(eq.GetProperty("receipt_b").GetProperty("body_hex").GetString(), Hex(rb.Bytes()));
        }

        [Fact]
        public void EquivocationDetected()
        {
            // Two validly-signed receipts by ONE authority at one seq naming DIFFERENT objects: the
            // auditor mints a fork proof (corpus expect == "Equivocation"). A benign first observe
            // returns null. THIS is the mutation-target assertion.
            (JsonElement f, Audit.Receipt ra, Audit.Receipt rb) = ForkReceipts();
            byte[] sigA = Cose.MldsaSign(Alg, Seed, ra.Bytes());
            byte[] sigB = Cose.MldsaSign(Alg, Seed, rb.Bytes());
            var auditor = new Audit.Auditor(Alg, Pk, Hb(f.GetProperty("signer_hex").GetString()!), f.GetProperty("ext_counter").GetInt64());
            Assert.Null(auditor.Observe(ra, sigA)); // first observe is benign
            Audit.ForkProof? fp = auditor.Observe(rb, sigB);
            Assert.NotNull(fp); // a genuine fork at one seq must be detected
            fp!.Verify(Alg, Pk); // the minted proof verifies against the accused key (no throw)
            Assert.Equal("Equivocation", Vector().GetProperty("equivocation").GetProperty("expect").GetString());
        }

        [Fact]
        public void BenignDuplicateIsNotEquivocation()
        {
            (JsonElement f, Audit.Receipt ra, _) = ForkReceipts();
            byte[] sigA = Cose.MldsaSign(Alg, Seed, ra.Bytes());
            var auditor = new Audit.Auditor(Alg, Pk, Hb(f.GetProperty("signer_hex").GetString()!), f.GetProperty("ext_counter").GetInt64());
            Assert.Null(auditor.Observe(ra, sigA));
            Assert.Null(auditor.Observe(ra, sigA)); // an exact duplicate is not a fork
        }

        [Fact]
        public void ObserveRejectsUnsigned()
        {
            (JsonElement f, Audit.Receipt ra, _) = ForkReceipts();
            var auditor = new Audit.Auditor(Alg, Pk, Hb(f.GetProperty("signer_hex").GetString()!), f.GetProperty("ext_counter").GetInt64());
            var ex = Assert.Throws<NaalpException>(() => auditor.Observe(ra, new byte[8]));
            Assert.Equal("ReceiptUnsigned", ex.Kind);
        }

        // ---- fork proof (draft-01 §8.5) -------------------------------------------------------

        [Fact]
        public void ForkProofPreimageMatchesOracle()
        {
            (JsonElement f, Audit.Receipt ra, Audit.Receipt rb) = ForkReceipts();
            Audit.ForkProof fp = Audit.NewForkProof(
                Hb(f.GetProperty("signer_hex").GetString()!), ra, Array.Empty<byte>(), rb, Array.Empty<byte>(),
                f.GetProperty("ext_counter").GetInt64());
            Assert.Equal(f.GetProperty("preimage_hex").GetString(), Hex(fp.Preimage()));
        }

        [Fact]
        public void ForkProofVerifyAcceptsAndFailsClosed()
        {
            (JsonElement f, Audit.Receipt ra, Audit.Receipt rb) = ForkReceipts();
            byte[] sigA = Cose.MldsaSign(Alg, Seed, ra.Bytes());
            byte[] sigB = Cose.MldsaSign(Alg, Seed, rb.Bytes());
            byte[] signer = Hb(f.GetProperty("signer_hex").GetString()!);
            long ext = f.GetProperty("ext_counter").GetInt64();

            Audit.NewForkProof(signer, ra, sigA, rb, sigB, ext).Verify(Alg, Pk); // a valid proof (no throw)

            var same = Assert.Throws<NaalpException>(
                () => Audit.NewForkProof(signer, ra, sigA, ra, sigA, ext).Verify(Alg, Pk));
            Assert.Equal("ForkProofInvalid", same.Kind); // same object named twice

            var unnamed = Assert.Throws<NaalpException>(
                () => Audit.NewForkProof(Array.Empty<byte>(), ra, sigA, rb, sigB, ext).Verify(Alg, Pk));
            Assert.Equal("ForkProofInvalid", unnamed.Kind); // unnamed accused

            var rbSeq = new Audit.Receipt(rb.Prev, rb.Obj, rb.Seq + 1, rb.At);
            byte[] sigB2 = Cose.MldsaSign(Alg, Seed, rbSeq.Bytes());
            var mism = Assert.Throws<NaalpException>(
                () => Audit.NewForkProof(signer, ra, sigA, rbSeq, sigB2, ext).Verify(Alg, Pk));
            Assert.Equal("ForkProofInvalid", mism.Kind); // seq mismatch

            byte[] badB = (byte[])sigB.Clone();
            badB[badB.Length - 1] ^= 1;
            var tampered = Assert.Throws<NaalpException>(
                () => Audit.NewForkProof(signer, ra, sigA, rb, badB, ext).Verify(Alg, Pk));
            Assert.Equal("ReceiptUnsigned", tampered.Kind); // a signature that does not verify
        }

        // ---- offline causal graph (design §8.2-§8.3) ------------------------------------------

        private static List<Audit.CausalNode> Nodes(string key)
        {
            var nodes = new List<Audit.CausalNode>();
            foreach (JsonElement n in Vector().GetProperty(key).GetProperty("nodes").EnumerateArray())
            {
                var causes = new List<byte[]>();
                foreach (JsonElement c in n.GetProperty("causes_hex").EnumerateArray())
                {
                    causes.Add(Hb(c.GetString()!));
                }
                nodes.Add(new Audit.CausalNode(Hb(n.GetProperty("id_hex").GetString()!), causes, n.GetProperty("position").GetInt64()));
            }
            return nodes;
        }

        [Fact]
        public void CausalValidTopoOrderMatchesOracle()
        {
            List<Audit.CausalNode> nodes = Nodes("causal_valid");
            Audit.VerifyCausal(nodes); // no throw
            List<byte[]> order = Audit.TopoOrder(nodes);
            var want = new List<string>();
            foreach (JsonElement e in Vector().GetProperty("causal_valid").GetProperty("topo_order_hex").EnumerateArray())
            {
                want.Add(e.GetString()!);
            }
            var got = new List<string>();
            foreach (byte[] o in order)
            {
                got.Add(Hex(o));
            }
            Assert.Equal(want, got);
        }

        [Fact]
        public void CausalCycleRejected()
        {
            JsonElement v = Vector();
            var ex = Assert.Throws<NaalpException>(() => Audit.VerifyCausal(Nodes("causal_cycle")));
            Assert.Equal(v.GetProperty("causal_cycle").GetProperty("expect").GetString(), ex.Kind);
        }

        [Fact]
        public void CausalFutureCauseRejected()
        {
            JsonElement v = Vector();
            var ex = Assert.Throws<NaalpException>(() => Audit.VerifyCausal(Nodes("causal_future")));
            Assert.Equal(v.GetProperty("causal_future").GetProperty("expect").GetString(), ex.Kind);
        }
    }
}
