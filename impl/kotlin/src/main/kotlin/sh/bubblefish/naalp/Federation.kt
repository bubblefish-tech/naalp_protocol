// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * N-AALP Federation higher tier (tier 1) for the Kotlin SDK — federated ordering by a deterministic
 * reconcile-merge over the shared causal graph (design.md §8.4; design-channels.md §7; R-8.6, R-15A.2,
 * R-15A.3).
 *
 * The baseline tier is a single ordering authority's monotonic receipt chain (C7). The higher tier
 * lets multiple independent authorities each order their own scope and reconcile over the shared causal
 * graph — the partial order every authority already signs over (§8.2). Reconcile is a DETERMINISTIC
 * linearization of the union causal DAG: a topological sort whose tie-break among causally-concurrent
 * objects is the object content id (bytewise ascending). Because it depends only on the causal graph
 * (not on how scopes are split), any split of the same objects reconciles to the same order — so moving
 * from single-authority to federated ordering requires no envelope or object change (R-8.6). An
 * independent transcription of impl/go/federation, graded against the shared vectors/federation/cases.json.
 * The causal partial order is checked by the shared [Graph] (the C7/audit foundation), exactly as the
 * reference federation package reuses the audit layer.
 */
object Federation {

    /**
     * A node's place in the shared causal graph: its content id and the content ids of its causes
     * (envelope field 8). The federated tier reconciles by these causal edges and the content-id
     * tie-break; the single-authority future-cause position check lives in the baseline tier.
     */
    class CausalNode(id: ByteArray, causes: List<ByteArray>) {
        val id: ByteArray = id.copyOf()
        val causes: List<ByteArray> = causes.map { it.copyOf() }
    }

    /**
     * The tier-1 Reconcile object body (design-channels.md §7): the authorities reconciled and the
     * resulting deterministic total order (object content ids). Signed with the C2 crypto over its
     * deterministic-CBOR bytes; it orders the identical signed objects the baseline already produced (no
     * envelope change).
     */
    class ReconcileRecord(authorities: List<String>, order: List<ByteArray>) {
        val authorities: List<String> = ArrayList(authorities)
        val order: List<ByteArray> = order.map { it.copyOf() }

        /** Deterministic-CBOR encoding {1: [authorities], 2: [order content-ids]}. */
        fun bytes(): ByteArray {
            val auth = authorities.map { Cbor.T(it) as Cbor.Value }
            val ordr = order.map { Cbor.B(it) as Cbor.Value }
            return Cbor.encode(
                Cbor.M(
                    listOf(
                        Cbor.Pair(Cbor.U(1), Cbor.A(auth)),
                        Cbor.Pair(Cbor.U(2), Cbor.A(ordr))
                    )
                )
            )
        }
    }

    /**
     * Reconcile deterministically merges the objects of a shared causal graph into one total order
     * (design.md §8.4). It first verifies the graph is a valid partial order (acyclic, no future-cause)
     * via the shared [Graph], then linearizes it with Kahn's algorithm, breaking ties among ready nodes
     * by content id (bytewise ascending). The result is causally consistent and deterministic. A
     * duplicate object id (scope overlap) is ordered once (resolved).
     */
    fun reconcile(nodes: List<CausalNode>): List<ByteArray> {
        val gnodes = nodes.map { Graph.Node(it.id, it.causes, 0L) }
        Graph.verifyCausal(gnodes) // acyclic + no-future-cause, fail-closed (CausalViolation)

        val n = nodes.size
        val ids = nodes.map { it.id }
        val present = HashSet<String>()
        for (id in ids) present.add(Hex.encode(id))
        val causes = nodes.map { node ->
            node.causes.filter { present.contains(Hex.encode(it)) }
        }
        val indeg = IntArray(n) { causes[it].size }
        val done = BooleanArray(n)
        val order = ArrayList<ByteArray>(n)
        while (order.size < n) {
            var pick = -1
            for (i in 0 until n) {
                if (done[i] || indeg[i] != 0) continue
                if (pick == -1 || Cbor.compareBytes(ids[i], ids[pick]) < 0) pick = i
            }
            if (pick == -1) {
                // unreachable after verifyCausal, but fail-closed rather than loop forever
                throw NaalpException("CausalViolation", "no ready node")
            }
            done[pick] = true
            order.add(ids[pick])
            for (j in 0 until n) {
                if (!done[j]) {
                    for (c in causes[j]) {
                        if (Cbor.compareBytes(c, ids[pick]) == 0) {
                            indeg[j]--
                            break
                        }
                    }
                }
            }
        }
        return order
    }

    /** Reports whether an order places every object's (present) causes before it. */
    fun causallyValid(order: List<ByteArray>, nodes: List<CausalNode>): Boolean {
        val pos = HashMap<String, Int>()
        for (k in order.indices) pos[Hex.encode(order[k])] = k
        for (node in nodes) {
            val np = pos[Hex.encode(node.id)] ?: continue
            for (c in node.causes) {
                val cp = pos[Hex.encode(c)]
                if (cp != null && cp > np) return false
            }
        }
        return true
    }

    /**
     * Sign a Reconcile record with a tier-1 ordering authority's ML-DSA key: a deterministic FIPS-204
     * signature over the record's deterministic-CBOR bytes.
     */
    fun signReconcile(record: ReconcileRecord, alg: Int, seed: ByteArray): ByteArray =
        Cose.mldsaSign(alg, seed, record.bytes())

    /** Verify a raw Reconcile-record signature under the authority's public key. */
    fun verifyReconcile(record: ReconcileRecord, alg: Int, pubkey: ByteArray, sig: ByteArray): Boolean =
        Cose.mldsaVerify(alg, pubkey, record.bytes(), sig)

    /**
     * The verify-event choke point of the Reconcile state machine (ietf draft "## Reconcile state
     * machine", error code 61). A verifier independently re-runs the deterministic linearization over
     * the identical causal graph and rejects the record whole (ReconcileMismatch) if the recomputed
     * total order differs from the one the record claims. It recomputes via [reconcile] — the
     * content-id tie-break — and NEVER a position tie-break, which would spuriously disagree on
     * causally-concurrent objects. A node set that is not a valid partial order is rejected under that
     * fault (CausalViolation), propagated fail-closed from [reconcile]. Returns normally only when the
     * record's claimed order is byte-for-byte the deterministic order (verified).
     *
     * Distinct from [verifyReconcile], which checks the COSE signature over the record bytes;
     * verifyReconcileOrder verifies the ORDER, not the signature.
     */
    fun verifyReconcileOrder(record: ReconcileRecord, nodes: List<CausalNode>) {
        val recomputed = reconcile(nodes) // CausalViolation propagates fail-closed
        if (recomputed.size != record.order.size) {
            throw NaalpException(
                "ReconcileMismatch",
                "independent linearization disagrees with the reconcile record's claimed order"
            )
        }
        for (i in recomputed.indices) {
            if (!recomputed[i].contentEquals(record.order[i])) {
                throw NaalpException(
                    "ReconcileMismatch",
                    "independent linearization disagrees with the reconcile record's claimed order"
                )
            }
        }
    }
}
