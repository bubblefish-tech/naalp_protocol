// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System.Collections.Generic;

namespace Naalp
{
    /// <summary>
    /// N-AALP causal graph (C7, §8.2-§8.3) and federation reconcile (T13, §8.6) for the C# SDK.
    ///
    /// <para>VerifyCausal enforces no-future-cause (a present cause may not sit at a later position than
    /// its effect) and acyclicity. Reconcile is the deterministic merge: a topological linearization of
    /// the union causal DAG, ties broken by content id (bytewise), scope-independent (R-8.6).</para>
    /// </summary>
    public static class Graph
    {
        /// <summary>A causal graph node: id bytes, its cause ids, and its position.</summary>
        public sealed class Node
        {
            public readonly byte[] Id;
            public readonly List<byte[]> Causes;
            public readonly long Position;
            public Node(byte[] id, List<byte[]> causes, long position)
            {
                Id = id;
                Causes = causes;
                Position = position;
            }
        }

        private static string Key(byte[] b) => Hex.Encode(b);

        public static void VerifyCausal(List<Node> nodes)
        {
            var idx = new Dictionary<string, int>();
            for (int i = 0; i < nodes.Count; i++)
            {
                idx[Key(nodes[i].Id)] = i;
            }

            // no future cause
            foreach (Node node in nodes)
            {
                foreach (byte[] c in node.Causes)
                {
                    if (idx.TryGetValue(Key(c), out int j) && nodes[j].Position > node.Position)
                    {
                        throw new NaalpException("CausalViolation", "cause at a later position than its effect");
                    }
                }
            }

            // acyclic (3-colour DFS over effect -> cause edges)
            const int White = 0, Gray = 1, Black = 2;
            var color = new int[nodes.Count];

            bool HasCycle(int i)
            {
                color[i] = Gray;
                foreach (byte[] c in nodes[i].Causes)
                {
                    if (!idx.TryGetValue(Key(c), out int j))
                    {
                        continue;
                    }
                    if (color[j] == Gray)
                    {
                        return true;
                    }
                    if (color[j] == White && HasCycle(j))
                    {
                        return true;
                    }
                }
                color[i] = Black;
                return false;
            }

            for (int i = 0; i < nodes.Count; i++)
            {
                if (color[i] == White && HasCycle(i))
                {
                    throw new NaalpException("CausalViolation", "causal graph contains a cycle");
                }
            }
        }

        /// <summary>Deterministic topological merge over the union causal DAG; ties break by content id.</summary>
        public static List<byte[]> Reconcile(List<Node> nodes)
        {
            VerifyCausal(nodes);
            int n = nodes.Count;
            var ids = new byte[n][];
            var present = new HashSet<string>();
            for (int i = 0; i < n; i++)
            {
                ids[i] = nodes[i].Id;
                present.Add(Key(nodes[i].Id));
            }

            // causes filtered to present nodes, as membership sets
            var causes = new List<HashSet<string>>(n);
            var indeg = new int[n];
            for (int i = 0; i < n; i++)
            {
                var set = new HashSet<string>();
                foreach (byte[] c in nodes[i].Causes)
                {
                    string ck = Key(c);
                    if (present.Contains(ck))
                    {
                        set.Add(ck);
                    }
                }
                causes.Add(set);
                indeg[i] = set.Count;
            }

            var done = new bool[n];
            var order = new List<byte[]>(n);
            while (order.Count < n)
            {
                int pick = -1;
                for (int i = 0; i < n; i++)
                {
                    if (done[i] || indeg[i] != 0)
                    {
                        continue;
                    }
                    if (pick == -1 || Cbor.CompareBytes(ids[i], ids[pick]) < 0)
                    {
                        pick = i;
                    }
                }
                if (pick == -1)
                {
                    throw new NaalpException("CausalViolation", "no ready node (unreachable after verify_causal)");
                }
                done[pick] = true;
                order.Add(ids[pick]);
                string pickKey = Key(ids[pick]);
                for (int j = 0; j < n; j++)
                {
                    if (!done[j] && causes[j].Contains(pickKey))
                    {
                        indeg[j] -= 1;
                    }
                }
            }
            return order;
        }

        /// <summary>The tier-1 Reconcile body {1: [authorities], 2: [order content-ids]}.</summary>
        public static byte[] ReconcileRecord(List<string> authorities, List<byte[]> order)
        {
            var auth = new List<Cbor.Value>(authorities.Count);
            foreach (string a in authorities)
            {
                auth.Add(new Cbor.T(a));
            }
            var ordr = new List<Cbor.Value>(order.Count);
            foreach (byte[] o in order)
            {
                ordr.Add(new Cbor.B(o));
            }
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.A(auth)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.A(ordr)),
            }));
        }
    }
}
