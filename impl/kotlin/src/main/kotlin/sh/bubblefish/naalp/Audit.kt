// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

/**
 * C7 audit for the Kotlin SDK — the signed hash-chained receipt (the baseline single-authority
 * ordering tier), the equivocation auditor and its non-repudiable fork proof, and the
 * offline-checkable causal graph (design.md §8; R-8.1..8.6, R-12.2, R-12.3).
 *
 * An ordering authority records each accepted object by appending a signed Receipt
 * {1: prev, 2: obj, 3: seq, 4: at}; the chain is tamper-evident because reordering, omission, or
 * substitution breaks a `prev` link or a `seq`. The authority never mutates the origin object to
 * order it — ordering is an outer signed layer. The causal graph is the authority-independent
 * foundation: an edge "A causes B" is proven by B's signature over A's content id and is checkable
 * offline; a total order is a policy layered over this partial order. An auditor detects
 * equivocation — two receipts by one authority at one seq naming different objects — from the signed
 * receipts alone, and mints a non-repudiable ForkProof carrying BOTH of the accused's signatures and
 * an external monotonic counter (draft-01 finding #70).
 *
 * Ported from impl/go/audit (cross-read against impl/python/naalp/audit.py). Receipt/fork-proof
 * signatures are a RAW deterministic ML-DSA signature over the record body (Cose.mldsaSign /
 * Cose.mldsaVerify), exactly as the reference's cose.Signer/Verifier sign the receipt body directly.
 * Graded against the shared vectors/audit/cases.json.
 */
object Audit {

    /** The width of a chain head / prev link (SHA-384 = 48 bytes); genesis is zero. */
    const val HEAD_SIZE = 48

    private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

    /** One signed append to an ordering authority's chain (design §8.1). */
    class Receipt(prev: ByteArray, obj: ByteArray, val seq: Long, val at: Long) {
        /** hash of the previous receipt body (HEAD_SIZE bytes; genesis is zero). */
        val prev: ByteArray = prev.copyOf()

        /** content id of the accepted object (never the object itself — §8.2). */
        val obj: ByteArray = obj.copyOf()

        /** Deterministic-CBOR encoding of the receipt body {1: prev, 2: obj, 3: seq, 4: at}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(prev)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(obj)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(seq)),
                    Cbor.Pair(Cbor.U(4), Cbor.U(at)),
                )
            )
        )

        /**
         * The chain head after this receipt: SHA-384 of the receipt body. Because the body carries
         * prev, editing any receipt breaks the next receipt's linkage.
         */
        fun head(): ByteArray = sha384(bytes())
    }

    /**
     * A baseline single ordering authority (§8.4). It appends monotonic signed receipts over object
     * content ids; it holds no object bodies and mutates none. Signs with a real deterministic ML-DSA
     * key derived from `seed` (a RAW signature over each receipt body).
     */
    class Authority(private val alg: Int, seed: ByteArray) {
        private val seed: ByteArray = seed.copyOf()
        private var headState: ByteArray = ByteArray(HEAD_SIZE)
        private var seqState: Long = 0

        /**
         * Record acceptance of the object named by content id obj at time at, returning
         * (receipt, signature). Seq increases by one per append (monotonic).
         */
        fun append(obj: ByteArray, at: Long): Pair<Receipt, ByteArray> {
            val r = Receipt(headState, obj, seqState, at)
            val sig = Cose.mldsaSign(alg, seed, r.bytes())
            headState = r.head()
            seqState++
            return Pair(r, sig)
        }
    }

    /**
     * Check a receipt chain offline against the authority's key: each receipt's seq is the next
     * expected value, its prev links to the previous receipt's head (genesis is zero), and its raw
     * signature verifies. A broken link or a seq gap is ChainBroken; a bad signature is
     * ReceiptUnsigned. Detects any reorder, omission, or substitution (§8.1). Fail-closed: throws on
     * the first fault and returns normally on success.
     */
    fun verifyChain(receipts: List<Receipt>, sigs: List<ByteArray>, alg: Int, pubkey: ByteArray) {
        if (receipts.size != sigs.size) {
            throw NaalpException("ChainBroken", "receipt/signature count mismatch")
        }
        var head = ByteArray(HEAD_SIZE)
        for (i in receipts.indices) {
            val r = receipts[i]
            if (r.seq != i.toLong() || !r.prev.contentEquals(head)) {
                throw NaalpException("ChainBroken", "receipt prev/seq does not chain to the previous receipt")
            }
            if (!Cose.mldsaVerify(alg, pubkey, r.bytes(), sigs[i])) {
                throw NaalpException("ReceiptUnsigned", "receipt signature does not verify")
            }
            head = r.head()
        }
    }

    /**
     * An object cannot be created after the authority ordered it, so created MUST NOT exceed at
     * (R-8.4). The receipt's `at` is signed and chained, so it is evidence a verifier checks
     * independently of the signer's clock.
     */
    fun consistentWithAnchor(created: Long, at: Long): Boolean = created <= at

    /**
     * Non-repudiable evidence of equivocation (draft-01 §8.5, R-8.3): two validly-signed receipts by
     * ONE authority at the SAME seq naming DIFFERENT objects, with the accused's OWN two signatures
     * and an external monotonic counter — self-contained, so any third party verifies both signatures
     * against the accused key with no further evidence and no repudiation.
     */
    class ForkProof(
        signer: ByteArray,
        val extCounter: Long,
        val a: Receipt,
        sigA: ByteArray,
        val b: Receipt,
        sigB: ByteArray,
    ) {
        /** accused authority signer id; both sigs verify under its key. */
        val signer: ByteArray = signer.copyOf()

        /** the accused authority's signature over a.bytes(). */
        val sigA: ByteArray = sigA.copyOf()

        /** the accused authority's signature over b.bytes(). */
        val sigB: ByteArray = sigB.copyOf()

        /**
         * Deterministic-CBOR fork-proof body {1: signer, 2: ext_counter, 3: body_a, 4: sig_a,
         * 5: body_b, 6: sig_b}. The two receipt bodies are embedded as the exact bytes each signature
         * covers.
         */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(signer)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(extCounter)),
                    Cbor.Pair(Cbor.U(3), Cbor.B(a.bytes())),
                    Cbor.Pair(Cbor.U(4), Cbor.B(sigA)),
                    Cbor.Pair(Cbor.U(5), Cbor.B(b.bytes())),
                    Cbor.Pair(Cbor.U(6), Cbor.B(sigB)),
                )
            )
        )

        /**
         * The deterministic-CBOR framing witness: the fork-proof body with the two signature
         * byte-strings elided to empty. It is the structural authority the independent oracle
         * reproduces byte-for-byte; the two ML-DSA signatures are graded by cross-implementation
         * byte-parity elsewhere. This is not a wire object; it exists only to grade the framing.
         */
        fun preimage(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(signer)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(extCounter)),
                    Cbor.Pair(Cbor.U(3), Cbor.B(a.bytes())),
                    Cbor.Pair(Cbor.U(4), Cbor.B(ByteArray(0))),
                    Cbor.Pair(Cbor.U(5), Cbor.B(b.bytes())),
                    Cbor.Pair(Cbor.U(6), Cbor.B(ByteArray(0))),
                )
            )
        )

        /**
         * Accept iff ALL hold: (1) the signer id is present; (2) the two receipts share one seq;
         * (3) they name DIFFERENT objects; and (4) BOTH signatures verify under the accused key. Any
         * failure rejects the whole proof (fail-closed): a same-object / seq-mismatch / unnamed-signer
         * proof is ForkProofInvalid, and a signature that does not verify is ReceiptUnsigned. Returns
         * normally on a valid, non-repudiable proof of Equivocation.
         */
        fun verify(alg: Int, pubkey: ByteArray) {
            if (signer.isEmpty()) {
                throw NaalpException("ForkProofInvalid", "an unnamed accused is not evidence")
            }
            if (a.seq != b.seq) {
                throw NaalpException("ForkProofInvalid", "receipts at different sequence positions")
            }
            if (a.obj.contentEquals(b.obj)) {
                throw NaalpException("ForkProofInvalid", "same object named twice — no equivocation")
            }
            if (!Cose.mldsaVerify(alg, pubkey, a.bytes(), sigA) || !Cose.mldsaVerify(alg, pubkey, b.bytes(), sigB)) {
                throw NaalpException("ReceiptUnsigned", "a signature does not verify under the accused key")
            }
        }
    }

    /**
     * Assemble a fork proof from two conflicting signed receipts, the accused signer id, and an
     * external monotonic counter. Performs no checks — verify is the fail-closed gate; this is the
     * pure constructor (A9). Copies the byte slices so the proof owns its evidence.
     */
    fun newForkProof(signer: ByteArray, a: Receipt, sigA: ByteArray, b: Receipt, sigB: ByteArray, extCounter: Long): ForkProof =
        ForkProof(signer, extCounter, a, sigA, b, sigB)

    /**
     * Observes an authority's receipts and detects equivocation from the signed receipts alone
     * (§8.5). On a conflict it mints a non-repudiable ForkProof carrying the accused signer id, both
     * conflicting signatures, and an external monotonic counter.
     */
    class Auditor(private val alg: Int, pubkey: ByteArray, signer: ByteArray, extBase: Long = 0) {
        private val pk: ByteArray = pubkey.copyOf()
        private val signer: ByteArray = signer.copyOf()
        private var ext: Long = extBase
        private val seen = HashMap<Long, Pair<Receipt, ByteArray>>()

        /**
         * Record a signed receipt. Throws ReceiptUnsigned on a bad signature. Returns a ForkProof
         * (Equivocation) if a previously-seen receipt at the same seq named a different object — the
         * proof carries the accused signer id, both signatures, and the auditor's current external
         * counter, which then advances. Returns null otherwise (including a benign exact duplicate).
         */
        fun observe(r: Receipt, sig: ByteArray): ForkProof? {
            if (!Cose.mldsaVerify(alg, pk, r.bytes(), sig)) {
                throw NaalpException("ReceiptUnsigned", "receipt signature does not verify")
            }
            val prev = seen[r.seq]
            if (prev != null) {
                if (!prev.first.obj.contentEquals(r.obj)) {
                    val fp = newForkProof(signer, prev.first, prev.second, r, sig, ext)
                    ext++
                    return fp
                }
                return null
            }
            seen[r.seq] = Pair(r, sig.copyOf())
            return null
        }
    }

    /**
     * An object's place in the causal graph: its content id, the content ids of its causes (envelope
     * field 8), and its ordering position (authority seq, or `created` absent a receipt).
     */
    class CausalNode(id: ByteArray, causes: List<ByteArray>, val position: Long) {
        val id: ByteArray = id.copyOf()
        val causes: List<ByteArray> = causes.map { it.copyOf() }
    }

    /**
     * Check the signed partial order (§8.2, §8.3): no object names a present cause whose position
     * exceeds its own (a future cause it could not have seen), and the graph is acyclic. Either fault
     * is CausalViolation. Edges to causes not present in the set are ignored (external references).
     * Runs with no ordering authority present (R-8.5). Fail-closed: throws on a fault.
     */
    fun verifyCausal(nodes: List<CausalNode>) {
        val idx = HashMap<String, Int>(nodes.size)
        for (i in nodes.indices) idx[keyOf(nodes[i].id)] = i
        // No future cause: a present cause must not sit at a later position than its effect.
        for (n in nodes) {
            for (c in n.causes) {
                val j = idx[keyOf(c)]
                if (j != null && nodes[j].position > n.position) {
                    throw NaalpException("CausalViolation", "a present cause sits at a later position than its effect")
                }
            }
        }
        // Acyclic: 3-colour DFS over depends-on edges (effect -> cause).
        val white = 0; val gray = 1; val black = 2
        val color = IntArray(nodes.size)
        fun hasCycle(start: Int): Boolean {
            val stack = ArrayDeque<Pair<Int, Int>>() // (node, next-cause-index)
            color[start] = gray
            stack.addLast(Pair(start, 0))
            while (stack.isNotEmpty()) {
                val (i, ci) = stack.removeLast()
                val causes = nodes[i].causes
                if (ci < causes.size) {
                    stack.addLast(Pair(i, ci + 1))
                    val j = idx[keyOf(causes[ci])] ?: continue
                    if (color[j] == gray) return true
                    if (color[j] == white) {
                        color[j] = gray
                        stack.addLast(Pair(j, 0))
                    }
                } else {
                    color[i] = black
                }
            }
            return false
        }
        for (i in nodes.indices) {
            if (color[i] == white && hasCycle(i)) {
                throw NaalpException("CausalViolation", "causal graph has a cycle")
            }
        }
    }

    /**
     * Return the causal nodes' content ids in a deterministic topological order (a cause before its
     * effects). Ties among ready nodes break by (position, input index), so the order is reproducible.
     * Throws CausalViolation if the graph does not verify. NOTE: the audit tie-break is by POSITION —
     * distinct from the federation reconcile, whose tie-break is the content id.
     */
    fun topoOrder(nodes: List<CausalNode>): List<ByteArray> {
        verifyCausal(nodes)
        val idx = HashMap<String, Int>(nodes.size)
        for (i in nodes.indices) idx[keyOf(nodes[i].id)] = i
        val indeg = IntArray(nodes.size)
        val effects = Array(nodes.size) { ArrayList<Int>() } // cause index -> effect indices
        for (i in nodes.indices) {
            for (c in nodes[i].causes) {
                val j = idx[keyOf(c)]
                if (j != null) {
                    effects[j].add(i)
                    indeg[i]++
                }
            }
        }
        val done = BooleanArray(nodes.size)
        val order = ArrayList<ByteArray>(nodes.size)
        while (order.size < nodes.size) {
            var pick = -1
            for (i in nodes.indices) {
                if (done[i] || indeg[i] != 0) continue
                if (pick == -1 || nodes[i].position < nodes[pick].position) {
                    pick = i // lowest position wins; equal positions keep the lower index (first seen)
                }
            }
            if (pick == -1) {
                throw NaalpException("CausalViolation", "no ready node (unreachable after verifyCausal)")
            }
            done[pick] = true
            order.add(nodes[pick].id)
            for (e in effects[pick]) indeg[e]--
        }
        return order
    }

    private fun keyOf(b: ByteArray): String = Hex.encode(b)
}
