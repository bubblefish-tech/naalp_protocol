// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

namespace Naalp
{
    /// <summary>
    /// Federation (tier 1) for the C# SDK — federated ordering by a deterministic reconcile-merge over
    /// the shared causal graph (design.md §8.4; design-channels.md §7; requirements R-8.6, R-15A.2,
    /// R-15A.3), ported from impl/go/federation.
    ///
    /// <para>The baseline tier is a single ordering authority's monotonic receipt chain. The higher
    /// tier lets multiple independent authorities each order their own scope and reconcile over the
    /// shared causal graph — the partial order every authority already signs over (§8.2). Reconcile is
    /// a DETERMINISTIC linearization of the union causal DAG: a topological sort whose tie-break among
    /// causally-concurrent objects is the object content id (bytewise ascending). Because it depends
    /// only on the causal graph (not on how scopes are split), any split of the same objects
    /// reconciles to the same order — so moving from single-authority to federated ordering requires
    /// no envelope or object change (R-8.6).</para>
    /// </summary>
    public static class Federation
    {
        /// <summary>
        /// An object's place in the causal graph: its content id, the content ids of its causes
        /// (envelope field 8), and its ordering position (authority seq, or `created` absent a
        /// receipt). Mirrors impl/go/audit.CausalNode.
        /// </summary>
        public sealed class CausalNode
        {
            public readonly byte[] Id;
            public readonly List<byte[]> Causes;
            public readonly long Position;

            public CausalNode(byte[] id, List<byte[]> causes, long position = 0)
            {
                Id = id;
                Causes = causes ?? new List<byte[]>();
                Position = position;
            }
        }

        private static string Key(byte[] b) => Convert.ToHexString(b);

        /// <summary>
        /// Checks the signed partial order (§8.2, §8.3): no object names a present cause whose position
        /// exceeds its own (a future cause it could not have seen), and the graph is acyclic. Either
        /// fault throws CausalViolation. Edges to causes not present in the set are ignored (external
        /// references). Ported from impl/go/audit.VerifyCausal.
        /// </summary>
        public static void VerifyCausal(List<CausalNode> nodes)
        {
            var idx = new Dictionary<string, int>(nodes.Count);
            for (int i = 0; i < nodes.Count; i++)
            {
                idx[Key(nodes[i].Id)] = i;
            }
            // No future cause: a present cause must not sit at a later position than its effect.
            foreach (CausalNode n in nodes)
            {
                foreach (byte[] c in n.Causes)
                {
                    if (idx.TryGetValue(Key(c), out int j) && nodes[j].Position > n.Position)
                    {
                        throw new NaalpException("CausalViolation", "causal graph has a future cause");
                    }
                }
            }
            // Acyclic: 3-colour DFS over depends-on edges (effect -> cause).
            const int white = 0, gray = 1, black = 2;
            int[] color = new int[nodes.Count];

            bool HasCycle(int i)
            {
                color[i] = gray;
                foreach (byte[] c in nodes[i].Causes)
                {
                    if (!idx.TryGetValue(Key(c), out int j))
                    {
                        continue;
                    }
                    if (color[j] == gray)
                    {
                        return true;
                    }
                    if (color[j] == white && HasCycle(j))
                    {
                        return true;
                    }
                }
                color[i] = black;
                return false;
            }

            for (int i = 0; i < nodes.Count; i++)
            {
                if (color[i] == white && HasCycle(i))
                {
                    throw new NaalpException("CausalViolation", "causal graph has a cycle");
                }
            }
        }

        /// <summary>
        /// Deterministically merges the objects of a shared causal graph into one total order
        /// (design.md §8.4). It first verifies the graph is a valid partial order (VerifyCausal), then
        /// linearizes it with Kahn's algorithm, breaking ties among ready nodes by content id (bytewise
        /// ascending). The result is causally consistent and deterministic. A duplicate object id
        /// (scope overlap) is ordered once (resolved). Ported from impl/go/federation.Reconcile.
        /// </summary>
        public static List<byte[]> Reconcile(List<CausalNode> nodes)
        {
            VerifyCausal(nodes);

            var present = new HashSet<string>();
            foreach (CausalNode n in nodes)
            {
                present.Add(Key(n.Id));
            }
            int count = nodes.Count;
            int[] indeg = new int[count];
            for (int i = 0; i < count; i++)
            {
                foreach (byte[] c in nodes[i].Causes)
                {
                    if (present.Contains(Key(c)))
                    {
                        indeg[i]++;
                    }
                }
            }
            bool[] done = new bool[count];
            var order = new List<byte[]>(count);
            while (order.Count < count)
            {
                int pick = -1;
                for (int i = 0; i < count; i++)
                {
                    if (done[i] || indeg[i] != 0)
                    {
                        continue;
                    }
                    if (pick == -1 || Cbor.CompareBytes(nodes[i].Id, nodes[pick].Id) < 0)
                    {
                        pick = i;
                    }
                }
                if (pick == -1)
                {
                    // Unreachable after VerifyCausal; fail-closed.
                    throw new NaalpException("CausalViolation", "graph did not linearize");
                }
                done[pick] = true;
                order.Add(nodes[pick].Id);
                for (int j = 0; j < count; j++)
                {
                    if (done[j])
                    {
                        continue;
                    }
                    foreach (byte[] c in nodes[j].Causes)
                    {
                        if (Cbor.CompareBytes(c, nodes[pick].Id) == 0)
                        {
                            indeg[j]--;
                        }
                    }
                }
            }
            return order;
        }

        /// <summary>Reports whether an order places every object's (present) causes before it.</summary>
        public static bool CausallyValid(List<byte[]> order, List<CausalNode> nodes)
        {
            var pos = new Dictionary<string, int>(order.Count);
            for (int k = 0; k < order.Count; k++)
            {
                pos[Key(order[k])] = k;
            }
            foreach (CausalNode n in nodes)
            {
                if (!pos.TryGetValue(Key(n.Id), out int np))
                {
                    continue;
                }
                foreach (byte[] c in n.Causes)
                {
                    if (pos.TryGetValue(Key(c), out int cp) && cp > np)
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        /// <summary>
        /// The tier-1 Federation Reconcile object body (design-channels.md §7): the authorities
        /// reconciled and the resulting deterministic total order (object content ids). It is signed
        /// with the C2 crypto over its deterministic-CBOR bytes; it orders the identical signed objects
        /// the baseline already produced (no envelope change).
        /// </summary>
        public sealed class ReconcileRecord
        {
            public readonly List<string> Authorities;
            public readonly List<byte[]> Order;

            public ReconcileRecord(List<string> authorities, List<byte[]> order)
            {
                Authorities = authorities;
                Order = order;
            }

            /// <summary>The deterministic-CBOR encoding {1: [authorities], 2: [order content-ids]}.</summary>
            public byte[] Bytes()
            {
                var auth = new List<Cbor.Value>(Authorities.Count);
                foreach (string a in Authorities)
                {
                    auth.Add(new Cbor.T(a));
                }
                var order = new List<Cbor.Value>(Order.Count);
                foreach (byte[] o in Order)
                {
                    order.Add(new Cbor.B(o));
                }
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.A(auth)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.A(order)),
                }));
            }
        }

        /// <summary>
        /// Signs a Reconcile record with a tier-1 ordering authority's ML-DSA key derived from seed —
        /// a raw deterministic ML-DSA signature over the record bytes (matches impl/go
        /// federation.SignReconcile = signer.Sign(r.Bytes())).
        /// </summary>
        public static byte[] SignReconcile(ReconcileRecord r, int alg, byte[] seed)
        {
            return Cose.MldsaSign(alg, seed, r.Bytes());
        }

        /// <summary>Verifies a Reconcile record's raw ML-DSA signature under the authority's key.</summary>
        public static bool VerifyReconcile(ReconcileRecord r, int alg, byte[] pubkey, byte[] sig)
        {
            return Cose.MldsaVerify(alg, pubkey, r.Bytes(), sig);
        }

        /// <summary>
        /// The verify-event choke point of the Reconcile state machine (draft-01 "## Reconcile state
        /// machine", error code 61). A verifier independently re-runs the deterministic linearization
        /// over the identical causal graph and rejects the record whole (ReconcileMismatch) if the
        /// recomputed total order differs from the one the record claims. It recomputes via
        /// <see cref="Reconcile"/> — the content-id tie-break — and NEVER a position/index tie-break
        /// topological sort, whose tie-break would spuriously disagree on causally-concurrent objects. A
        /// node set that is not a valid partial order is rejected under that fault (CausalViolation),
        /// propagated fail-closed from Reconcile. Returns only when the record's claimed order is
        /// byte-for-byte the deterministic order (verified); throws ReconcileMismatch otherwise.
        ///
        /// <para>This is distinct from the per-port signature-verify <see cref="VerifyReconcile"/>, which
        /// checks the raw ML-DSA signature over the record bytes; VerifyReconcileOrder verifies the
        /// ORDER, not the signature. Ported from impl/go/federation.VerifyReconcileOrder.</para>
        /// </summary>
        public static void VerifyReconcileOrder(ReconcileRecord r, List<CausalNode> nodes)
        {
            List<byte[]> recomputed = Reconcile(nodes); // CausalViolation propagates fail-closed
            if (recomputed.Count != r.Order.Count)
            {
                throw new NaalpException("ReconcileMismatch",
                    "independent linearization disagrees with the reconcile record's claimed order");
            }
            for (int i = 0; i < recomputed.Count; i++)
            {
                if (Cbor.CompareBytes(recomputed[i], r.Order[i]) != 0)
                {
                    throw new NaalpException("ReconcileMismatch",
                        "independent linearization disagrees with the reconcile record's claimed order");
                }
            }
        }
    }
}
