// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

/**
 * Federation higher-tier (tier 1) known-answer test for the Kotlin SDK (design.md §8.4;
 * design-channels.md §7; R-8.6), graded against the shared independent corpus
 * vectors/federation/cases.json (NOT produced by this code). Reconcile is the deterministic
 * linearization of the union causal DAG, tie-broken among causally-concurrent objects by content id
 * (bytewise ascending): it MUST equal the oracle order, be causally valid, and beat the naive
 * content-id sort (which is NOT causally valid here). The tier-1 Reconcile record MUST encode to the
 * oracle bytes, and reconcile MUST be scope-independent (R-8.6).
 *
 * CORPUS-GRADED (pure): reconcile order, causal validity, naive-sort baseline, record bytes, scope
 * independence, cycle rejection. ML-DSA-DEMONSTRATED (isolation, real FIPS-204 via BouncyCastle, NOT
 * corpus-graded — the corpus carries no federation signature): the tier-1 authority's deterministic
 * ML-DSA signature over the record, and rejection of a tampered record.
 *
 * KAT convention (a standalone main() that exits non-zero on any failure); the filename carries the
 * "Tests" token the ten-language-parity gate indexes. Written test-first: [Federation] is absent until
 * Federation.kt lands, so this fails RED with a kotlinc "unresolved reference: Federation"; a mutation
 * that inverts the reconcile tie-break flips "reconcile order == oracle" and "record bytes == oracle".
 */

private var fedFails = 0

private fun fCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        fedFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- minimal regex JSON access (no JSON library on the Kotlin port) ----

private fun fFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/federation/cases.json not found")
        val p = File(File(cur, "vectors"), "federation/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/federation/cases.json not found from ${File(".").absolutePath}")
}

private fun fStr(scope: String, key: String): String {
    val m = Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun fBool(scope: String, key: String): Boolean {
    val m = Regex("\"$key\"\\s*:\\s*(true|false)").find(scope)
        ?: throw AssertionError("boolean key not found: $key")
    return m.groupValues[1] == "true"
}

/** Every lowercase-hex token quoted inside a JSON segment, decoded to bytes, in document order. */
private fun fHexTokens(segment: String): List<ByteArray> =
    Regex("\"([0-9a-f]+)\"").findAll(segment).map { Hex.decode(it.groupValues[1]) }.toList()

/** The decoded hex strings of the array named [key] (no nested arrays inside). */
private fun fHexArray(json: String, key: String): List<ByteArray> {
    val a = Regex("\"$key\"\\s*:\\s*\\[(.*?)\\]", RegexOption.DOT_MATCHES_ALL).find(json)
        ?: throw AssertionError("array key not found: $key")
    return fHexTokens(a.groupValues[1])
}

/** The string elements of the array named [key]. */
private fun fStringArray(json: String, key: String): List<String> {
    val a = Regex("\"$key\"\\s*:\\s*\\[(.*?)\\]", RegexOption.DOT_MATCHES_ALL).find(json)
        ?: throw AssertionError("array key not found: $key")
    return Regex("\"([^\"]*)\"").findAll(a.groupValues[1]).map { it.groupValues[1] }.toList()
}

/**
 * The corpus nodes as CausalNode list. The federation corpus's only brace-pairs are the node objects
 * (each flat: name, id_hex, a causes_hex array of hex strings, no nested object), so matching every
 * innermost {...} yields exactly the nodes in document order.
 */
private fun fCorpusNodes(json: String): List<Federation.CausalNode> =
    Regex("\\{([^{}]*)\\}", RegexOption.DOT_MATCHES_ALL).findAll(json).map { m ->
        val block = m.groupValues[1]
        val id = Hex.decode(fStr(block, "id_hex"))
        val ce = Regex("\"causes_hex\"\\s*:\\s*\\[([^\\]]*)\\]", RegexOption.DOT_MATCHES_ALL).find(block)
        val causes = if (ce != null) fHexTokens(ce.groupValues[1]) else emptyList()
        Federation.CausalNode(id, causes)
    }.toList()

private fun fHexJoin(bins: List<ByteArray>): String = bins.joinToString(",") { Hex.encode(it) }

private fun fedRun() {
    val json = fFindVector().readText(Charsets.UTF_8)
    val nodes = fCorpusNodes(json)
    fCheck("node count", nodes.size.toString(), fHexArray(json, "reconcile_order_hex").size.toString())

    // 1. reconcile == the independent oracle order (the load-bearing property; the mutation target).
    val order = Federation.reconcile(nodes)
    fCheck("reconcile order == oracle", fHexJoin(order), fHexJoin(fHexArray(json, "reconcile_order_hex")))

    // 2. the reconcile order is causally valid (every present cause precedes its effect).
    fCheck(
        "reconcile order causally valid",
        Federation.causallyValid(order, nodes).toString(),
        fBool(json, "reconcile_order_causally_valid").toString()
    )

    // 3. the naive content-id sort's causal validity matches the oracle — and here it is NOT valid, so
    //    it is the mutation baseline: a reconcile that degrades to the naive sort is caught.
    val naive = fHexArray(json, "naive_content_id_sort_hex")
    fCheck(
        "naive content-id sort causally valid == oracle",
        Federation.causallyValid(naive, nodes).toString(),
        fBool(json, "naive_causally_valid").toString()
    )

    // 4. the tier-1 Reconcile record encodes to the oracle bytes {1:[authorities], 2:[order]}.
    val authorities = fStringArray(json, "authorities")
    val rec = Federation.ReconcileRecord(authorities, order)
    fCheck("reconcile record bytes == oracle", Hex.encode(rec.bytes()), fStr(json, "record_hex"))

    // 5. R-8.6: reconcile depends only on the causal graph, not on input (scope) order — reversing the
    //    input reconciles identically.
    fCheck("scope independence (reversed input)", fHexJoin(Federation.reconcile(nodes.reversed())), fHexJoin(order))

    // 6. an out-of-lattice cycle is rejected fail-closed (CausalViolation).
    val a = Hex.decode("2030" + "aa".repeat(48))
    val b = Hex.decode("2030" + "bb".repeat(48))
    val cyclic = listOf(
        Federation.CausalNode(a, listOf(b)),
        Federation.CausalNode(b, listOf(a))
    )
    var cycleKind = "no-error"
    try {
        Federation.reconcile(cyclic)
    } catch (e: NaalpException) {
        cycleKind = e.kind
    }
    fCheck("cycle rejected", cycleKind, "CausalViolation")

    // 7. ML-DSA-DEMONSTRATED (isolation, real FIPS-204): a tier-1 authority signs the Reconcile record
    //    deterministically; the raw signature verifies under its key, and a tampered record does NOT
    //    verify. This exercises the signing binding in isolation (NOT corpus-graded).
    val seed = ByteArray(32) { 0x2a }
    val pk = Cose.mldsaKeygen("ML-DSA-65", seed)
    val sig = Federation.signReconcile(rec, Cose.ALG_MLDSA65, seed)
    fCheck(
        "ml-dsa reconcile-record sign/verify",
        Federation.verifyReconcile(rec, Cose.ALG_MLDSA65, pk, sig).toString(), "true"
    )
    val tampered = Federation.ReconcileRecord(listOf("bauthority-z"), rec.order)
    fCheck(
        "ml-dsa tampered record rejected",
        Federation.verifyReconcile(tampered, Cose.ALG_MLDSA65, pk, sig).toString(), "false"
    )
}

fun main() {
    println("federation conformance (Kotlin) — graded vs vectors/federation/cases.json")
    fedRun()
    println(if (fedFails == 0) "FederationTests: PASS" else "FederationTests: FAIL ($fedFails)")
    exitProcess(if (fedFails == 0) 0 else 1)
}
