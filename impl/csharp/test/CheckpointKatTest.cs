// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// S3 naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof known-answer test for
    /// the C# SDK (design.md §26.5, RFC 9162 §2.1), graded against the independent, non-circular
    /// corpus <c>vectors/checkpoint/cases.json</c> — mirroring impl/go/gateway/checkpoint_test.go and
    /// impl/python/tests/test_checkpoint.py.
    /// </summary>
    public sealed class CheckpointKatTest
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "checkpoint", "cases.json");
                if (File.Exists(p))
                {
                    var doc = JsonDocument.Parse(File.ReadAllText(p));
                    return doc.RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/checkpoint/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        private static byte[] Seed(int b)
        {
            var s = new byte[32];
            for (int i = 0; i < s.Length; i++) s[i] = (byte)b;
            return s;
        }

        private static string ErrKind(Action a)
        {
            try
            {
                a();
                return "no-error";
            }
            catch (NaalpException e)
            {
                return e.Kind;
            }
        }

        /// <summary>An unsigned-64-bit integer field carried as a decimal STRING so no float64 decoder
        /// anywhere can round it (at_str ranges up to 2^64-1).</summary>
        private static long LongField(JsonElement scope, string key)
        {
            string s = scope.GetProperty(key).GetString()!;
            return unchecked((long)ulong.Parse(s));
        }

        private static List<byte[]> HexArray(JsonElement arr)
        {
            var outp = new List<byte[]>();
            foreach (JsonElement e in arr.EnumerateArray())
            {
                outp.Add(Hb(e.GetString()!));
            }
            return outp;
        }

        private static Gateway.CheckpointRoot CpFrom(JsonElement cv)
        {
            return new Gateway.CheckpointRoot(
                Hb(cv.GetProperty("log_hex").GetString()!), cv.GetProperty("size").GetInt64(),
                Hb(cv.GetProperty("root_hex").GetString()!), Hb(cv.GetProperty("prev_hex").GetString()!),
                LongField(cv, "at_str"));
        }

        private static Gateway.WitnessCosign WcFrom(JsonElement wv)
        {
            return new Gateway.WitnessCosign(
                Hb(wv.GetProperty("witness_hex").GetString()!), Hb(wv.GetProperty("root_hex").GetString()!), LongField(wv, "at_str"));
        }

        private static string CpRejectKind(byte[] body)
        {
            try
            {
                Gateway.ParseCheckpointRoot(body);
                return "no-error";
            }
            catch (NaalpException e)
            {
                return e.Kind;
            }
        }

        [Fact]
        public void GenesisPrevMatchesOracle()
        {
            JsonElement json = Vector();
            Assert.Equal(json.GetProperty("genesis").GetProperty("prev_hex").GetString(), Hex(Gateway.GenesisPrev()));
        }

        [Fact]
        public void CheckpointsByteParity()
        {
            JsonElement json = Vector();
            foreach (JsonProperty p in json.GetProperty("checkpoints").EnumerateObject())
            {
                JsonElement cv = p.Value;
                Gateway.CheckpointRoot c = CpFrom(cv);
                Assert.Equal(cv.GetProperty("body_hex").GetString(), Hex(c.Bytes()));
                Assert.Equal(cv.GetProperty("head_hex").GetString(), Hex(c.Head()));
                Assert.Equal(cv.GetProperty("id_hex").GetString(), Hex(c.Id()));
                Assert.Equal(cv.GetProperty("body_hex").GetString(), Hex(Gateway.ParseCheckpointRoot(c.Bytes()).Bytes()));
            }
        }

        [Fact]
        public void WitnessCosignsByteParity()
        {
            JsonElement json = Vector();
            foreach (JsonProperty p in json.GetProperty("witness_cosigns").EnumerateObject())
            {
                JsonElement wv = p.Value;
                Gateway.WitnessCosign w = WcFrom(wv);
                Assert.Equal(wv.GetProperty("body_hex").GetString(), Hex(w.Bytes()));
                Assert.Equal(wv.GetProperty("head_hex").GetString(), Hex(w.Head()));
                Assert.Equal(wv.GetProperty("id_hex").GetString(), Hex(w.Id()));
            }
        }

        [Fact]
        public void ForkEvidence()
        {
            JsonElement json = Vector();
            JsonElement fe = json.GetProperty("fork_evidence");
            JsonElement cpA = fe.GetProperty("checkpoint_a");
            JsonElement cpB = fe.GetProperty("checkpoint_b");
            Assert.NotEqual(cpA.GetProperty("root_hex").GetString(), cpB.GetProperty("root_hex").GetString());
            Assert.NotEqual(cpA.GetProperty("id_hex").GetString(), cpB.GetProperty("id_hex").GetString());

            JsonElement wcABlock = cpA.GetProperty("witness_cosign");
            JsonElement wcBBlock = cpB.GetProperty("witness_cosign");
            Gateway.WitnessCosign wcA = WcFrom(wcABlock);
            Gateway.WitnessCosign wcB = WcFrom(wcBBlock);
            Assert.Equal(wcABlock.GetProperty("body_hex").GetString(), Hex(wcA.Bytes()));
            Assert.Equal(wcBBlock.GetProperty("body_hex").GetString(), Hex(wcB.Bytes()));
            byte[] idA = Hb(cpA.GetProperty("id_hex").GetString()!);
            byte[] idB = Hb(cpB.GetProperty("id_hex").GetString()!);
            Assert.Equal("no-error", ErrKind(() => Gateway.ValidateWitnessCosign(wcA, idA)));
            Assert.Equal("no-error", ErrKind(() => Gateway.ValidateWitnessCosign(wcB, idB)));
            Assert.Equal("WitnessRootMismatch", ErrKind(() => Gateway.ValidateWitnessCosign(wcA, idB)));
            Assert.Equal("WitnessRootMismatch", ErrKind(() => Gateway.ValidateWitnessCosign(wcB, idA)));
        }

        [Fact]
        public void InclusionProofsVerify()
        {
            JsonElement json = Vector();
            JsonElement checkpoints = json.GetProperty("checkpoints");
            var checkpointFor = new Dictionary<string, string>
            {
                { "leaf3_of7", "checkpoint0_size7" },
                { "leaf7_of8_newly_appended", "checkpoint1_size8" },
                { "single_leaf_tree_empty_path", "checkpoint_single_leaf" },
            };
            foreach (JsonProperty p in json.GetProperty("inclusion_proofs").EnumerateObject())
            {
                string name = p.Name;
                JsonElement iv = p.Value;
                JsonElement cp = checkpoints.GetProperty(checkpointFor[name]);
                Assert.Equal(iv.GetProperty("root_hex").GetString(), Hex(CpFrom(cp).Id()));

                var proof = new Gateway.InclusionProof(
                    Hb(iv.GetProperty("root_hex").GetString()!), Hb(iv.GetProperty("leaf_hex").GetString()!),
                    iv.GetProperty("index").GetInt64(), HexArray(iv.GetProperty("path_hex")));
                Assert.Equal(iv.GetProperty("body_hex").GetString(), Hex(proof.Bytes()));
                Assert.Equal(iv.GetProperty("head_hex").GetString(), Hex(proof.Head()));
                Assert.Equal(iv.GetProperty("id_hex").GetString(), Hex(proof.Id()));
                Gateway.InclusionProof parsed = Gateway.ParseInclusionProof(proof.Bytes());
                long cpSize = cp.GetProperty("size").GetInt64();
                byte[] cpRoot = Hb(cp.GetProperty("root_hex").GetString()!);
                Assert.Equal("no-error", ErrKind(() => Gateway.VerifyInclusionProof(parsed.Leaf, parsed.Index, cpSize, parsed.Path, cpRoot)));
            }
        }

        [Fact]
        public void NegativeCases()
        {
            JsonElement json = Vector();
            JsonElement neg = json.GetProperty("negative");
            JsonElement cp0 = json.GetProperty("checkpoints").GetProperty("checkpoint0_size7");
            byte[] root0 = Hb(cp0.GetProperty("root_hex").GetString()!);
            long size0 = cp0.GetProperty("size").GetInt64();

            JsonElement wi = neg.GetProperty("inclusion_wrong_index");
            List<byte[]> wiPath = HexArray(wi.GetProperty("path_hex"));
            byte[] wiLeaf = Hb(wi.GetProperty("leaf_hex").GetString()!);
            long wiIndex = wi.GetProperty("claimed_index").GetInt64();
            Assert.Equal("InclusionProofInvalid", ErrKind(() => Gateway.VerifyInclusionProof(wiLeaf, wiIndex, size0, wiPath, root0)));

            JsonElement wp = neg.GetProperty("inclusion_wrong_path");
            List<byte[]> wpPath = HexArray(wp.GetProperty("path_hex"));
            byte[] wpLeaf = Hb(wp.GetProperty("leaf_hex").GetString()!);
            long wpIndex = wp.GetProperty("index").GetInt64();
            Assert.Equal("InclusionProofInvalid", ErrKind(() => Gateway.VerifyInclusionProof(wpLeaf, wpIndex, size0, wpPath, root0)));

            JsonElement wm = neg.GetProperty("witness_root_mismatch");
            Gateway.WitnessCosign wParsed = Gateway.ParseWitnessCosign(Hb(wm.GetProperty("cosign_body_hex").GetString()!));
            Assert.Equal(wm.GetProperty("cosign_names_root_hex").GetString(), Hex(wParsed.Root));
            byte[] wmAccompaniedId = Hb(wm.GetProperty("checkpoint_accompanied_id_hex").GetString()!);
            Assert.Equal(wm.GetProperty("reject").GetString(), ErrKind(() => Gateway.ValidateWitnessCosign(wParsed, wmAccompaniedId)));

            JsonElement ckoo = neg.GetProperty("checkpoint_keys_out_of_order");
            Gateway.ParseCheckpointRoot(Hb(ckoo.GetProperty("canonical_body_hex").GetString()!)); // should parse
            var ce = Assert.Throws<NaalpException>(() => Cbor.Decode(Hb(ckoo.GetProperty("noncanonical_body_hex").GetString()!)));
            Assert.Equal("NonCanonical", ce.Kind);
            Assert.Equal("CheckpointMalformed", CpRejectKind(Hb(ckoo.GetProperty("noncanonical_body_hex").GetString()!)));

            JsonElement cmf = neg.GetProperty("checkpoint_missing_field");
            Assert.Equal(cmf.GetProperty("reject").GetString(), CpRejectKind(Hb(cmf.GetProperty("body_hex").GetString()!)));
        }

        [Fact]
        public void EmptyTreeKat()
        {
            JsonElement json = Vector();
            JsonElement etk = json.GetProperty("empty_tree_kat");
            Assert.Equal(etk.GetProperty("root_hex").GetString(), Hex(Gateway.MerkleRoot(null)));
            Assert.Equal(etk.GetProperty("root_hex").GetString(), Hex(Gateway.MerkleRoot(new List<byte[]>())));
        }

        /// <summary>RFC 9162 self-fidelity: independently re-derives PATH()/recompute over SYNTHETIC
        /// leaves (never the oracle's own numbers), catching an algorithmic defect the n in {1,7,8}
        /// byte-parity vectors above do not reach.</summary>
        [Fact]
        public void Rfc9162SelfFidelity()
        {
            int total = 0;
            for (int n = 1; n <= 12; n++)
            {
                var leaves = new List<byte[]>();
                for (int i = 0; i < n; i++)
                {
                    leaves.Add(Encoding.UTF8.GetBytes("synthetic-leaf-" + i));
                }
                byte[] root = Gateway.MerkleRoot(leaves);
                for (int m = 0; m < n; m++)
                {
                    List<byte[]> path = Gateway.GenerateInclusionProofPath(leaves, m);
                    Gateway.VerifyInclusionProof(leaves[m], m, n, path, root); // no throw
                    total++;
                }
            }
            Assert.Equal(78, total); // sum 1..12

            var leaves5 = new List<byte[]>();
            for (int i = 0; i < 5; i++)
            {
                leaves5.Add(Encoding.UTF8.GetBytes("synthetic-leaf-" + i));
            }
            byte[] root5 = Gateway.MerkleRoot(leaves5);
            List<byte[]> path2 = Gateway.GenerateInclusionProofPath(leaves5, 2);
            Assert.Equal("InclusionProofInvalid", ErrKind(() =>
                Gateway.VerifyInclusionProof(Encoding.UTF8.GetBytes("tampered-leaf"), 2, 5, path2, root5)));
        }

        [Fact]
        public void SignVerifyInIsolation()
        {
            JsonElement json = Vector();
            JsonElement cp0 = json.GetProperty("checkpoints").GetProperty("checkpoint0_size7");
            Gateway.CheckpointRoot cp0Obj = CpFrom(cp0);
            byte[] cpSeed = Seed(0x11);
            byte[] cpPk = Cose.MldsaKeygen("ML-DSA-65", cpSeed);
            byte[] cpObj = Gateway.SignCheckpointRoot(cp0Obj, Alg, cpSeed);
            byte[][] cpParts = Cose.ParseSign1Raw(cpObj);
            Assert.True(Cose.CoseVerify1Raw(Alg, cpPk, Cose.ToBeSignedRaw(cpParts[0], cpParts[1]), cpParts[2]));
            Assert.Equal(Hex(cp0Obj.Bytes()), Hex(cpParts[1]));
        }
    }
}
