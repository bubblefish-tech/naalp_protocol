// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * N-AALP causal graph (C7, §8.2-§8.3) and federation reconcile (T13, §8.6) for the Kotlin SDK.
 *
 * verifyCausal enforces no-future-cause (a present cause may not sit at a later position than its
 * effect) and acyclicity. reconcile is the deterministic merge: a topological linearization of the
 * union causal DAG, ties broken by content id (bytewise), scope-independent (R-8.6).
 */
object Graph {

    /** A causal node: content id, the ids it directly depends on, and its ordering position. */
    class Node(val id: ByteArray, val causes: List<ByteArray>, val position: Long)

    private fun key(b: ByteArray): String = Hex.encode(b)

    fun verifyCausal(nodes: List<Node>) {
        val idx = HashMap<String, Int>()
        for (i in nodes.indices) idx[key(nodes[i].id)] = i
        // no future cause
        for (n in nodes) {
            for (c in n.causes) {
                val j = idx[key(c)]
                if (j != null && nodes[j].position > n.position) {
                    throw NaalpException("CausalViolation", "cause at a later position than its effect")
                }
            }
        }
        // acyclic (3-colour DFS over effect -> cause edges)
        val color = IntArray(nodes.size) // 0 white, 1 gray, 2 black
        for (i in nodes.indices) {
            if (color[i] == 0 && hasCycle(i, nodes, idx, color)) {
                throw NaalpException("CausalViolation", "causal graph contains a cycle")
            }
        }
    }

    private fun hasCycle(i: Int, nodes: List<Node>, idx: Map<String, Int>, color: IntArray): Boolean {
        color[i] = 1
        for (c in nodes[i].causes) {
            val j = idx[key(c)] ?: continue
            if (color[j] == 1) return true
            if (color[j] == 0 && hasCycle(j, nodes, idx, color)) return true
        }
        color[i] = 2
        return false
    }

    /** Deterministic topological merge over the union causal DAG; ties break by content id. */
    fun reconcile(nodes: List<Node>): List<ByteArray> {
        verifyCausal(nodes)
        val n = nodes.size
        val ids = ArrayList<ByteArray>(n)
        for (node in nodes) ids.add(node.id)
        val present = HashSet<String>()
        for (id in ids) present.add(key(id))
        val causes = ArrayList<List<ByteArray>>(n)
        for (node in nodes) {
            val filtered = ArrayList<ByteArray>()
            for (c in node.causes) if (present.contains(key(c))) filtered.add(c)
            causes.add(filtered)
        }
        val indeg = IntArray(n)
        for (i in 0 until n) indeg[i] = causes[i].size
        val done = BooleanArray(n)
        val order = ArrayList<ByteArray>(n)
        while (order.size < n) {
            var pick = -1
            for (i in 0 until n) {
                if (done[i] || indeg[i] != 0) continue
                if (pick == -1 || Cbor.compareBytes(ids[i], ids[pick]) < 0) pick = i
            }
            if (pick == -1) {
                throw NaalpException("CausalViolation", "no ready node (unreachable after verifyCausal)")
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

    /** The tier-1 Reconcile body {1: [authorities], 2: [order content-ids]}. */
    fun reconcileRecord(authorities: List<String>, order: List<ByteArray>): ByteArray {
        val auth = ArrayList<Cbor.Value>()
        for (a in authorities) auth.add(Cbor.T(a))
        val ordr = ArrayList<Cbor.Value>()
        for (o in order) ordr.add(Cbor.B(o))
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
