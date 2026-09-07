// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

namespace Naalp
{
    /// <summary>
    /// C7 — the signed hash-chained receipt (the baseline single-authority ordering tier), the
    /// equivocation auditor and its non-repudiable fork proof, and the offline-checkable causal graph
    /// (design.md §8; requirements R-8.1..8.6, R-12.2, R-12.3) — the C# SDK, ported from
    /// impl/go/audit.
    ///
    /// <para>An ordering authority records each accepted object by appending a signed Receipt
    /// {1: prev, 2: obj, 3: seq, 4: at}; the chain is tamper-evident because reordering, omission, or
    /// substitution breaks a <c>prev</c> link or a <c>seq</c> (§8.1). The authority never mutates the
    /// origin object to order it — ordering is an outer signed layer (§8.2). The causal graph is the
    /// authority-independent foundation: an edge "A causes B" is proven by B's signature over A's
    /// content id and is checkable offline; a total order is a policy layered over this partial order
    /// (§8.2). A cause an effect could not have seen (later position, or a cycle) is rejected
    /// (CausalViolation, §8.3). An auditor detects equivocation — two receipts by one authority at one
    /// seq naming different objects — from the signed receipts alone (§8.5).</para>
    ///
    /// <para>The receipt/fork-proof body is deterministic CBOR built by the shared spine
    /// (<see cref="Records.ReceiptBody"/>); the causal partial order is checked by the shared
    /// <see cref="Graph.VerifyCausal"/>. Receipt/fork-proof signatures are a RAW deterministic ML-DSA
    /// signature over the record body (<see cref="Cose.MldsaSign"/> / <see cref="Cose.MldsaVerify"/>),
    /// exactly as the Go/Python/Rust reference implementations sign the receipt body directly — NOT a
    /// COSE_Sign1 wrap. Every check is fail-closed (§15): a failing object is rejected whole, throws
    /// its named error, and causes no state change.</para>
    /// </summary>
    public static class Audit
    {
        /// <summary>The width of a chain head / prev link (SHA-384 = 48 bytes). Genesis is zero.</summary>
        public const int HeadSize = 48;

        /// <summary>One signed append to an ordering authority's chain (design.md §8.1).</summary>
        public sealed class Receipt
        {
            public readonly byte[] Prev; // hash of the previous receipt body (HeadSize bytes; genesis is zero)
            public readonly byte[] Obj;  // content id of the accepted object (never the object itself — §8.2)
            public readonly long Seq;    // monotonic sequence position within this authority's chain
            public readonly long At;     // the authority's time anchor, epoch ms (independent of the signer's clock)

            public Receipt(byte[] prev, byte[] obj, long seq, long at)
            {
                Prev = prev;
                Obj = obj;
                Seq = seq;
                At = at;
            }

            /// <summary>The deterministic-CBOR encoding {1: prev, 2: obj, 3: seq, 4: at} (shared spine).</summary>
            public byte[] Bytes() => Records.ReceiptBody(Prev, Obj, Seq, At);

            /// <summary>The chain head after this receipt: SHA-384 of the receipt body. Because the body
            /// carries Prev, editing any receipt breaks the next receipt's linkage.</summary>
            public byte[] Head() => Records.ReceiptHead(Bytes());
        }

        /// <summary>
        /// A baseline single ordering authority (§8.4). It appends monotonic signed receipts over
        /// object content ids; it holds no object bodies and mutates none. Signs with a real
        /// deterministic ML-DSA key derived from a 32-byte seed (a RAW signature over each receipt body).
        /// </summary>
        public sealed class Authority
        {
            private readonly int _alg;
            private readonly byte[] _seed;
            private byte[] _head;
            private long _seq;

            public Authority(int alg, byte[] seed)
            {
                _alg = alg;
                _seed = (byte[])seed.Clone();
                _head = new byte[HeadSize];
                _seq = 0;
            }

            /// <summary>Record acceptance of the object named by content id obj at time at, returning the
            /// signed receipt and its signature. Seq increases by one per append (monotonic).</summary>
            public (Receipt Receipt, byte[] Sig) Append(byte[] obj, long at)
            {
                var r = new Receipt((byte[])_head.Clone(), (byte[])obj.Clone(), _seq, at);
                byte[] sig = Cose.MldsaSign(_alg, _seed, r.Bytes());
                _head = r.Head();
                _seq++;
                return (r, sig);
            }
        }

        /// <summary>
        /// Check a receipt chain offline against the authority's key: each receipt's Seq is the next
        /// expected value, its Prev links to the previous receipt's Head (genesis is zero), and its raw
        /// signature verifies. A broken link or a seq gap is ChainBroken; a bad signature is
        /// ReceiptUnsigned. This detects any reorder, omission, or substitution (§8.1). Returns on
        /// success; throws a named NaalpException on any fault (fail-closed).
        /// </summary>
        public static void VerifyChain(IReadOnlyList<Receipt> receipts, IReadOnlyList<byte[]> sigs, int alg, byte[] pubkey)
        {
            if (receipts.Count != sigs.Count)
            {
                throw new NaalpException("ChainBroken", "receipt/signature count mismatch");
            }
            byte[] head = new byte[HeadSize];
            for (int i = 0; i < receipts.Count; i++)
            {
                Receipt r = receipts[i];
                if (r.Seq != i || !BytesEqual(r.Prev, head))
                {
                    throw new NaalpException("ChainBroken", "receipt prev/seq does not chain to the previous receipt");
                }
                if (!Cose.MldsaVerify(alg, pubkey, r.Bytes(), sigs[i]))
                {
                    throw new NaalpException("ReceiptUnsigned", "receipt signature does not verify");
                }
                head = r.Head();
            }
        }

        /// <summary>
        /// An object cannot be created after the authority ordered it, so created MUST NOT exceed at
        /// (R-8.4). The receipt's `at` is signed and chained, so it is evidence a verifier checks
        /// independently of the signer's clock.
        /// </summary>
        public static bool ConsistentWithAnchor(long created, long at) => created <= at;

        /// <summary>
        /// Non-repudiable evidence of equivocation (design.md §8.5, R-8.3): two validly-signed receipts
        /// by ONE authority at the SAME seq naming DIFFERENT objects, with the accused's OWN two
        /// signatures and an external monotonic counter — self-contained, so any third party verifies
        /// both signatures against the accused key with no further evidence and no repudiation.
        /// </summary>
        public sealed class ForkProof
        {
            public readonly byte[] Signer;  // accused authority signer id; both sigs verify under its key
            public readonly long ExtCounter; // external monotonic counter bound into the proof (fixes replay/reorder)
            public readonly Receipt A;      // first receipt (A.Bytes() is the signed input for SigA)
            public readonly byte[] SigA;    // the accused authority's signature over A.Bytes()
            public readonly Receipt B;      // second receipt at the same seq naming a different object
            public readonly byte[] SigB;    // the accused authority's signature over B.Bytes()

            public ForkProof(byte[] signer, long extCounter, Receipt a, byte[] sigA, Receipt b, byte[] sigB)
            {
                Signer = signer;
                ExtCounter = extCounter;
                A = a;
                SigA = sigA;
                B = b;
                SigB = sigB;
            }

            // The fork-proof body {1: signer, 2: ext_counter, 3: body_a, 4: sig_a, 5: body_b, 6: sig_b}
            // — sigA/sigB carried verbatim in the body, elided to empty for the preimage witness.
            private byte[] Encode(byte[] sigA, byte[] sigB)
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Signer)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(ExtCounter)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(A.Bytes())),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(sigA)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.B(B.Bytes())),
                    new Cbor.Pair(new Cbor.U(6), new Cbor.B(sigB)),
                }));
            }

            /// <summary>The deterministic-CBOR fork-proof body (draft-01 naalp-fork-proof).</summary>
            public byte[] Bytes() => Encode(SigA, SigB);

            /// <summary>The deterministic-CBOR framing witness: the fork-proof body with the two signature
            /// byte-strings elided to empty. It is the structural authority the independent oracle
            /// reproduces byte-for-byte; the two ML-DSA signatures are graded by cross-implementation
            /// byte-parity elsewhere. This is not a wire object; it exists only to grade the framing.</summary>
            public byte[] Preimage() => Encode(Array.Empty<byte>(), Array.Empty<byte>());

            /// <summary>
            /// Accept iff ALL hold: (1) the signer id is present; (2) the two receipts share one seq;
            /// (3) they name DIFFERENT objects; and (4) BOTH signatures verify under the accused key.
            /// Any failure rejects the whole proof (fail-closed): a same-object / seq-mismatch /
            /// unnamed-signer proof is ForkProofInvalid, and a signature that does not verify is
            /// ReceiptUnsigned. Returns on a valid, non-repudiable proof of Equivocation.
            /// </summary>
            public void Verify(int alg, byte[] pubkey)
            {
                if (Signer.Length == 0)
                {
                    throw new NaalpException("ForkProofInvalid", "an unnamed accused is not evidence");
                }
                if (A.Seq != B.Seq)
                {
                    throw new NaalpException("ForkProofInvalid", "receipts at different sequence positions");
                }
                if (BytesEqual(A.Obj, B.Obj))
                {
                    throw new NaalpException("ForkProofInvalid", "same object named twice — no equivocation");
                }
                if (!Cose.MldsaVerify(alg, pubkey, A.Bytes(), SigA) || !Cose.MldsaVerify(alg, pubkey, B.Bytes(), SigB))
                {
                    throw new NaalpException("ReceiptUnsigned", "a signature does not verify under the accused key");
                }
            }
        }

        /// <summary>Assemble a fork proof from two conflicting signed receipts, the accused signer id,
        /// and an external monotonic counter. Performs no checks — Verify is the fail-closed gate; this
        /// is the pure constructor (A9). Copies the byte slices so the proof owns its evidence.</summary>
        public static ForkProof NewForkProof(byte[] signer, Receipt a, byte[] sigA, Receipt b, byte[] sigB, long extCounter)
        {
            return new ForkProof((byte[])signer.Clone(), extCounter, a, (byte[])sigA.Clone(), b, (byte[])sigB.Clone());
        }

        /// <summary>
        /// Observes an authority's receipts and detects equivocation from the signed receipts alone
        /// (§8.5). On a conflict it mints a non-repudiable ForkProof carrying the accused signer id,
        /// both conflicting signatures, and an external monotonic counter (T2.1).
        /// </summary>
        public sealed class Auditor
        {
            private readonly int _alg;
            private readonly byte[] _pk;
            private readonly byte[] _signer;
            private long _ext;
            private readonly Dictionary<long, (Receipt R, byte[] Sig)> _seen = new Dictionary<long, (Receipt, byte[])>();

            public Auditor(int alg, byte[] pubkey, byte[] signer, long extBase = 0)
            {
                _alg = alg;
                _pk = (byte[])pubkey.Clone();
                _signer = (byte[])signer.Clone();
                _ext = extBase;
            }

            /// <summary>
            /// Record a signed receipt. Throws ReceiptUnsigned on a bad signature. Returns a ForkProof
            /// (Equivocation) if a previously-seen receipt at the same seq named a different object — the
            /// proof carries the accused signer id, both signatures, and the auditor's current external
            /// counter, which then advances. Returns null otherwise (including a benign exact duplicate).
            /// </summary>
            public ForkProof? Observe(Receipt r, byte[] sig)
            {
                if (!Cose.MldsaVerify(_alg, _pk, r.Bytes(), sig))
                {
                    throw new NaalpException("ReceiptUnsigned", "receipt signature does not verify");
                }
                if (_seen.TryGetValue(r.Seq, out (Receipt R, byte[] Sig) prev))
                {
                    if (!BytesEqual(prev.R.Obj, r.Obj))
                    {
                        ForkProof fp = NewForkProof(_signer, prev.R, prev.Sig, r, sig, _ext);
                        _ext++;
                        return fp;
                    }
                    return null;
                }
                _seen[r.Seq] = (r, (byte[])sig.Clone());
                return null;
            }
        }

        /// <summary>An object's place in the causal graph: its content id, the content ids of its causes
        /// (envelope field 8), and its ordering position (authority seq, or `created` absent a receipt).</summary>
        public sealed class CausalNode
        {
            public readonly byte[] Id;
            public readonly List<byte[]> Causes;
            public readonly long Position;

            public CausalNode(byte[] id, List<byte[]> causes, long position)
            {
                Id = id;
                Causes = causes;
                Position = position;
            }
        }

        /// <summary>
        /// Check the signed partial order (§8.2, §8.3): no object names a present cause whose position
        /// exceeds its own (a future cause it could not have seen), and the graph is acyclic. Either
        /// fault is CausalViolation. Edges to causes not present in the set are ignored (external
        /// references). Runs with no ordering authority present (R-8.5). Delegates to the shared
        /// <see cref="Graph.VerifyCausal"/>, which implements exactly this partial order.
        /// </summary>
        public static void VerifyCausal(IReadOnlyList<CausalNode> nodes)
        {
            Graph.VerifyCausal(ToGraphNodes(nodes));
        }

        /// <summary>
        /// Return the causal nodes' content ids in a deterministic topological order (a cause before its
        /// effects). Ties among ready nodes break by (position, input index), so the order is
        /// reproducible. Throws CausalViolation if the graph does not verify. NOTE: the audit tie-break
        /// is by POSITION — distinct from the federation reconcile, whose tie-break is the content id
        /// (<see cref="Graph.Reconcile"/>).
        /// </summary>
        public static List<byte[]> TopoOrder(IReadOnlyList<CausalNode> nodes)
        {
            VerifyCausal(nodes);
            int n = nodes.Count;
            var idx = new Dictionary<string, int>();
            for (int i = 0; i < n; i++)
            {
                idx[Hex.Encode(nodes[i].Id)] = i;
            }
            var indeg = new int[n];
            var effects = new List<int>[n]; // cause index -> effect indices
            for (int i = 0; i < n; i++)
            {
                effects[i] = new List<int>();
            }
            for (int i = 0; i < n; i++)
            {
                foreach (byte[] c in nodes[i].Causes)
                {
                    if (idx.TryGetValue(Hex.Encode(c), out int j))
                    {
                        effects[j].Add(i);
                        indeg[i]++;
                    }
                }
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
                    if (pick == -1 || nodes[i].Position < nodes[pick].Position)
                    {
                        pick = i; // lowest position wins; equal positions keep the lower index (first seen)
                    }
                }
                if (pick == -1)
                {
                    throw new NaalpException("CausalViolation", "no ready node (unreachable after VerifyCausal)");
                }
                done[pick] = true;
                order.Add(nodes[pick].Id);
                foreach (int e in effects[pick])
                {
                    indeg[e]--;
                }
            }
            return order;
        }

        private static List<Graph.Node> ToGraphNodes(IReadOnlyList<CausalNode> nodes)
        {
            var gn = new List<Graph.Node>(nodes.Count);
            foreach (CausalNode n in nodes)
            {
                gn.Add(new Graph.Node(n.Id, n.Causes, n.Position));
            }
            return gn;
        }

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
