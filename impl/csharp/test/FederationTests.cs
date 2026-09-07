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
    /// Federation (tier 1) federated ordering graded against the non-circular oracle
    /// <c>vectors/federation/cases.json</c>: reconcile is a deterministic topological sort of the
    /// union causal DAG, tie-broken by content id (bytewise ascending); it is scope-independent (any
    /// input permutation reconciles identically, R-8.6); a naive content-id sort that ignores the
    /// causal graph is NOT causally valid; the Reconcile record encodes to the oracle bytes; and the
    /// record signs/verifies under real deterministic ML-DSA-65. Expected values come from the
    /// committed corpus, not from the module under test.
    /// </summary>
    public sealed class FederationTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "federation", "cases.json");
                if (File.Exists(p))
                {
                    var doc = JsonDocument.Parse(File.ReadAllText(p));
                    return doc.RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/federation/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

        private static List<Federation.CausalNode> Nodes(JsonElement v)
        {
            var nodes = new List<Federation.CausalNode>();
            foreach (JsonElement n in v.GetProperty("nodes").EnumerateArray())
            {
                byte[] id = Convert.FromHexString(n.GetProperty("id_hex").GetString()!);
                var causes = new List<byte[]>();
                foreach (JsonElement c in n.GetProperty("causes_hex").EnumerateArray())
                {
                    causes.Add(Convert.FromHexString(c.GetString()!));
                }
                nodes.Add(new Federation.CausalNode(id, causes));
            }
            return nodes;
        }

        [Fact]
        public void ReconcileMatchesOracle()
        {
            JsonElement v = Vector();
            List<Federation.CausalNode> nodes = Nodes(v);
            List<byte[]> order = Federation.Reconcile(nodes);

            var want = new List<string>();
            foreach (JsonElement e in v.GetProperty("reconcile_order_hex").EnumerateArray())
            {
                want.Add(e.GetString()!);
            }
            Assert.Equal(want.Count, order.Count);
            for (int i = 0; i < order.Count; i++)
            {
                Assert.Equal(want[i], Hex(order[i]));
            }
            Assert.True(Federation.CausallyValid(order, nodes), "reconcile order is not causally valid");

            var authorities = new List<string>();
            foreach (JsonElement a in v.GetProperty("authorities").EnumerateArray())
            {
                authorities.Add(a.GetString()!);
            }
            var rec = new Federation.ReconcileRecord(authorities, order);
            Assert.Equal(v.GetProperty("record_hex").GetString(), Hex(rec.Bytes()));
        }

        [Fact]
        public void NaiveMergeFailsCausality()
        {
            JsonElement v = Vector();
            List<Federation.CausalNode> nodes = Nodes(v);
            var naive = new List<byte[]>();
            foreach (JsonElement e in v.GetProperty("naive_content_id_sort_hex").EnumerateArray())
            {
                naive.Add(Convert.FromHexString(e.GetString()!));
            }
            bool oracleValid = v.GetProperty("naive_causally_valid").GetBoolean();
            Assert.Equal(oracleValid, Federation.CausallyValid(naive, nodes));
            Assert.False(oracleValid, "this graph's naive sort should violate causality");
        }

        [Fact]
        public void ScopeIndependence()
        {
            JsonElement v = Vector();
            List<byte[]> baseOrder = Federation.Reconcile(Nodes(v));

            List<Federation.CausalNode> nodes = Nodes(v);
            var rev = new List<Federation.CausalNode>(nodes);
            rev.Reverse();
            List<byte[]> other = Federation.Reconcile(rev);

            Assert.Equal(baseOrder.Count, other.Count);
            for (int i = 0; i < baseOrder.Count; i++)
            {
                Assert.Equal(Hex(baseOrder[i]), Hex(other[i]));
            }
        }

        [Fact]
        public void ReconcileRecordSignVerifyRoundtrip()
        {
            JsonElement v = Vector();
            List<byte[]> order = Federation.Reconcile(Nodes(v));
            var authorities = new List<string>();
            foreach (JsonElement a in v.GetProperty("authorities").EnumerateArray())
            {
                authorities.Add(a.GetString()!);
            }
            var rec = new Federation.ReconcileRecord(authorities, order);

            byte[] seed = new byte[32];
            for (int i = 0; i < seed.Length; i++) seed[i] = 0x2b;
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);

            byte[] sig = Federation.SignReconcile(rec, Alg, seed);
            Assert.True(Federation.VerifyReconcile(rec, Alg, pk, sig), "reconcile record must verify");

            // Tamper: the record bytes changed => the signature must no longer verify.
            byte[] tampered = (byte[])rec.Bytes().Clone();
            tampered[tampered.Length - 1] ^= 0x01;
            Assert.False(Cose.MldsaVerify(Alg, pk, tampered, sig), "a tampered record must not verify");
        }

        // ---- VerifyReconcileOrder: the verify-event choke point of the Reconcile state machine -----
        //
        // Mirrors impl/go/federation/verify_reconcile_test.go TestVerifyReconcileOrder. Two
        // causally-INDEPENDENT byte-id nodes idA=[0x01], idB=[0x02]: Reconcile orders concurrent
        // objects by content id bytewise-ascending, so the one deterministic order is [idA, idB]. The
        // mutation that neuters the order comparison (making VerifyReconcileOrder always accept) flips
        // the "mismatch" and "mismatch-length" cases from ReconcileMismatch to no-throw.

        private static readonly byte[] IdA = new byte[] { 0x01 };
        private static readonly byte[] IdB = new byte[] { 0x02 };

        private static List<Federation.CausalNode> ConcurrentAB() => new List<Federation.CausalNode>
        {
            new Federation.CausalNode(IdA, new List<byte[]>(), 0),
            new Federation.CausalNode(IdB, new List<byte[]>(), 0),
        };

        [Fact]
        public void VerifyReconcileOrderAgrees()
        {
            // The claimed order IS the deterministic order -> verified (no throw).
            var rec = new Federation.ReconcileRecord(new List<string> { "auth-1" }, new List<byte[]> { IdA, IdB });
            Federation.VerifyReconcileOrder(rec, ConcurrentAB()); // must not throw
        }

        [Fact]
        public void VerifyReconcileOrderMismatch()
        {
            // A causally-VALID-but-different order (idA/idB are concurrent, so [idB, idA] is causally
            // valid) is not the deterministic order -> ReconcileMismatch. THIS is the mutation-target
            // assertion: neutering the order comparison in VerifyReconcileOrder flips this to no-throw.
            var rec = new Federation.ReconcileRecord(new List<string> { "auth-1" }, new List<byte[]> { IdB, IdA });
            var ex = Assert.Throws<NaalpException>(() => Federation.VerifyReconcileOrder(rec, ConcurrentAB()));
            Assert.Equal("ReconcileMismatch", ex.Kind);
        }

        [Fact]
        public void VerifyReconcileOrderMismatchLength()
        {
            // A claim that drops an element -> ReconcileMismatch.
            var rec = new Federation.ReconcileRecord(new List<string> { "auth-1" }, new List<byte[]> { IdA });
            var ex = Assert.Throws<NaalpException>(() => Federation.VerifyReconcileOrder(rec, ConcurrentAB()));
            Assert.Equal("ReconcileMismatch", ex.Kind);
        }

        [Fact]
        public void VerifyReconcileOrderCausalViolation()
        {
            // A cyclic node set is not a valid partial order; the recomputation rejects it before any
            // order comparison, so the record is rejected under the graph fault, fail-closed.
            byte[] idC = new byte[] { 0x03 };
            byte[] idD = new byte[] { 0x04 };
            var cyclic = new List<Federation.CausalNode>
            {
                new Federation.CausalNode(idC, new List<byte[]> { idD }, 1),
                new Federation.CausalNode(idD, new List<byte[]> { idC }, 1),
            };
            var rec = new Federation.ReconcileRecord(new List<string> { "auth-1" }, new List<byte[]> { idC, idD });
            var ex = Assert.Throws<NaalpException>(() => Federation.VerifyReconcileOrder(rec, cyclic));
            Assert.Equal("CausalViolation", ex.Kind);
        }
    }
}
