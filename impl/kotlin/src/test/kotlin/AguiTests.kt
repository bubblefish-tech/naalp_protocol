// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

//
// C21 NAALP-AGUI UI-consent-binding known-answer test for the Kotlin SDK (design.md §24; R-AGUI-1..6),
// graded against the shared independent corpus vectors/agui/cases.json (NOT produced by this code).
//
// CORPUS-GRADED (pure, no signature): each shown tool-lifecycle event body + head + content id; the
// receipt-chained shown-chain walk (each running head + the final head); an oversized seq (0x0102030405060708
// > 2^53) round-tripping byte-exact (carried as a 64-bit integer, no float rounding); the minimal event;
// the edge cases (non-canonical key order rejected, empty-vs-absent action, a body missing its field-5
// chain back-pointer rejected); a removed shown-event detected as a HOLE with its position; and an unknown
// event kind rejected. ISOLATION (real FIPS-204 ML-DSA-65 via BouncyCastle — Kotlin is a full-signature
// port; the corpus carries NO signed vector, so these are demonstrated with a fixed local seed, stated
// honestly, NOT corpus-graded): the signed shown-chain verifies; and the consent binding — a human §7
// approval binds the EXACT action shown-and-approved, so executing a SUBSTITUTED action (different content
// id) is ActionSubstituted, and a chain with no approved event is UINoConsent — reusing the §7 Approval
// UNCHANGED.
//
// KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the "Tests"
// token the ten-language-parity gate indexes. Written test-first: [Agui] is absent until Agui.kt lands, so
// this fails RED with a kotlinc "unresolved reference: Agui". The load-bearing mutation — the detectHole
// hole return made a no-hole constant (return (i, true) -> return (0, false)) — flips "agui hole detected
// at position 1" on its assertion.
//

private var agFails = 0

private fun agCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        agFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- balanced-brace / regex JSON access (no JSON library on the Kotlin port) ----

private fun agFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/agui/cases.json not found")
        val p = File(File(cur, "vectors"), "agui/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/agui/cases.json not found from ${File(".").absolutePath}")
}

private fun agSection(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*").find(scope)
        ?: throw AssertionError("key not found: $key")
    var i = m.range.last + 1
    while (i < scope.length && scope[i].isWhitespace()) i++
    val open = scope[i]
    val close = when (open) { '{' -> '}'; '[' -> ']'; else -> throw AssertionError("not object/array at $key") }
    var depth = 0
    var inStr = false
    var esc = false
    val start = i
    while (i < scope.length) {
        val c = scope[i]
        if (inStr) {
            when {
                esc -> esc = false
                c == '\\' -> esc = true
                c == '"' -> inStr = false
            }
        } else {
            when (c) {
                '"' -> inStr = true
                open -> depth++
                close -> { depth--; if (depth == 0) return scope.substring(start, i + 1) }
            }
        }
        i++
    }
    throw AssertionError("unbalanced value at key: $key")
}

private fun agElements(arraySection: String): List<String> {
    val out = ArrayList<String>()
    var i = 1
    var inStr = false
    var esc = false
    var depth = 0
    var start = -1
    while (i < arraySection.length - 1) {
        val c = arraySection[i]
        if (inStr) {
            when {
                esc -> esc = false
                c == '\\' -> esc = true
                c == '"' -> inStr = false
            }
        } else {
            when (c) {
                '"' -> inStr = true
                '{' -> { if (depth == 0) start = i; depth++ }
                '}' -> { depth--; if (depth == 0 && start >= 0) { out.add(arraySection.substring(start, i + 1)); start = -1 } }
            }
        }
        i++
    }
    return out
}

private fun agStr(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun agInt(scope: String, key: String): Long {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun agHex(s: String): ByteArray = Hex.decode(s)

private const val AG_ALG = Cose.ALG_MLDSA65
private val AG_SEED = ByteArray(32) { 4 }
private val AG_PK = Cose.mldsaKeygen("ML-DSA-65", AG_SEED)
private val AG_APPR_SEED = ByteArray(32) { 8 }
private val AG_APPR_PK = Cose.mldsaKeygen("ML-DSA-65", AG_APPR_SEED)

private inline fun agKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

private fun aguiRun() {
    val json = agFindVector().readText(Charsets.UTF_8)
    val session = agHex(agStr(json, "session_hex"))

    // 1. the receipt-chained shown chain: each event body/head/id, the running heads, the final head.
    val chainSec = agSection(json, "chain")
    val evElems = agElements(agSection(chainSec, "events"))
    val events = ArrayList<Agui.UIEvent>()
    for (eb in evElems) {
        val e = Agui.UIEvent(session, agInt(eb, "kind"), agHex(agStr(eb, "action_hex")), agInt(eb, "seq"), agHex(agStr(eb, "prev_hex")))
        agCheck("chain event seq=${agInt(eb, "seq")} body == oracle", Hex.encode(e.bytes()), agStr(eb, "body_hex"))
        agCheck("chain event seq=${agInt(eb, "seq")} head == oracle", Hex.encode(e.head()), agStr(eb, "head_hex"))
        agCheck("chain event seq=${agInt(eb, "seq")} id == oracle", Hex.encode(e.id()), agStr(eb, "id_hex"))
        events.add(e)
    }
    val shown = Agui.walkShown(events)
    for (i in evElems.indices) {
        agCheck("walkShown running head [$i] == oracle", Hex.encode(shown[i].head), agStr(evElems[i], "head_hex"))
    }
    agCheck("walkShown final head == oracle", Hex.encode(shown[shown.size - 1].head), agStr(chainSec, "final_head_hex"))

    // 2. an oversized seq (>2^53) round-trips byte-exact — carried as a 64-bit integer, no float rounding.
    val bigSec = agSection(json, "big_seq")
    val bigSeq = agStr(bigSec, "seq_str").toLong()
    val bigEv = Agui.UIEvent(session, agInt(bigSec, "kind"), agHex(agStr(bigSec, "action_hex")), bigSeq, agHex(agStr(bigSec, "prev_hex")))
    agCheck("big_seq body == oracle", Hex.encode(bigEv.bytes()), agStr(bigSec, "body_hex"))
    agCheck("big_seq head == oracle", Hex.encode(bigEv.head()), agStr(bigSec, "head_hex"))
    agCheck("big_seq id == oracle", Hex.encode(bigEv.id()), agStr(bigSec, "id_hex"))

    // 3. the minimal event.
    val minSec = agSection(json, "minimal")
    val minEv = Agui.UIEvent(agHex(agStr(minSec, "session_hex")), agInt(minSec, "kind"), agHex(agStr(minSec, "action_hex")), agInt(minSec, "seq"), agHex(agStr(minSec, "prev_hex")))
    agCheck("minimal body == oracle", Hex.encode(minEv.bytes()), agStr(minSec, "body_hex"))
    agCheck("minimal head == oracle", Hex.encode(minEv.head()), agStr(minSec, "head_hex"))
    agCheck("minimal id == oracle", Hex.encode(minEv.id()), agStr(minSec, "id_hex"))

    // 4. edge cases.
    val edge = agSection(json, "edge_cases")
    val koo = agSection(edge, "keys_out_of_order")
    agCheck("edge keys_out_of_order noncanonical rejected", agKind { Cbor.decode(agHex(agStr(koo, "noncanonical_body_hex"))) }, agStr(koo, "reject"))
    agCheck("edge keys_out_of_order canonical parses", agKind { Agui.parseUIEvent(agHex(agStr(koo, "canonical_body_hex"))) }, "no-error")

    val eva = agSection(edge, "empty_vs_absent")
    val emptyAct = agSection(eva, "empty_action")
    agCheck("edge empty_action id == oracle", Hex.encode(Agui.parseUIEvent(agHex(agStr(emptyAct, "body_hex"))).id()), agStr(emptyAct, "id_hex"))
    val popAct = agSection(eva, "populated_action")
    agCheck("edge populated_action id == oracle", Hex.encode(Agui.parseUIEvent(agHex(agStr(popAct, "body_hex"))).id()), agStr(popAct, "id_hex"))
    val absentF = agSection(eva, "absent_field")
    agCheck("edge absent_field rejected", agKind { Agui.parseUIEvent(agHex(agStr(absentF, "body_hex"))) }, agStr(absentF, "reject"))

    val look = agSection(edge, "look_alike")
    agCheck("edge look_alike (missing prev) rejected", agKind { Agui.parseUIEvent(agHex(agStr(look, "body_hex"))) }, agStr(look, "reject"))

    // 5. a removed shown-event is a detectable HOLE with its position: present indices ev0, ev2 (ev1 omitted)
    //    break contiguity at position 1. THIS is the mutation's target assertion.
    val holeSec = agSection(json, "hole")
    val (holePos, holeFound) = Agui.detectHole(listOf(events[0], events[2]))
    agCheck("agui hole found", holeFound.toString(), "true")
    agCheck("agui hole detected at position 1", holePos.toString(), agInt(holeSec, "position").toString())

    // 6. an unknown event kind is rejected.
    val unknownKind = agInt(json, "unknown_kind")
    val unkEv = Agui.UIEvent(session, unknownKind, agHex(agStr(json, "action_cid_hex")), 0L, Agui.genesis())
    agCheck("agui unknown kind rejected", agKind { Agui.walkShown(listOf(unkEv)) }, "UnknownUIEventKind")

    // 7. ISOLATION (real ML-DSA): the signed shown-chain and the consent binding.
    val now = 1000L
    val actionCid = agHex(agStr(json, "action_cid_hex"))
    val actionBytes = agHex(agStr(json, "action_bytes_hex"))
    val substitutedBytes = agHex(agStr(json, "substituted_bytes_hex"))
    // exported action content id matches the oracle (a relying party computes it over the exact bytes).
    agCheck("iso action content id == oracle", Hex.encode(Agui.contentId(actionBytes)), agStr(json, "action_cid_hex"))

    // 7a. the signed shown-chain verifies under the UI authority's key.
    val signedObjs = events.map { Agui.signUIEvent(it, AG_ALG, AG_SEED) }
    agCheck("iso signed shown-chain verifies", agKind { Agui.verifyShownChain(signedObjs, Cose.PROFILE_PUBLIC, AG_ALG, AG_PK) }, "no-error")
    val tampered = signedObjs[1].copyOf(); tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte()
    agCheck("iso tampered shown-chain rejected BadSignature", agKind { Agui.verifyShownChain(listOf(signedObjs[0], tampered, signedObjs[2]), Cose.PROFILE_PUBLIC, AG_ALG, AG_PK) }, "BadSignature")

    // 7b. consent binding: a chain that shows + approves actionCid; the human approval binds actionCid.
    val e0 = Agui.UIEvent(session, Agui.KIND_SHOWN, actionCid, 0L, Agui.genesis())
    val e1 = Agui.UIEvent(session, Agui.KIND_ARGS_SHOWN, actionCid, 1L, e0.head())
    val e2 = Agui.UIEvent(session, Agui.KIND_APPROVED, actionCid, 2L, e1.head())
    val consentChain = listOf(e0, e1, e2)
    val appr = Approval.ApprovalRecord(actionCid, "human", Policy.DESTRUCTIVE, ByteArray(16) { 2 }, 2_000_000_000_000L)
    val apprSig = Approval.signApproval(appr, AG_ALG, AG_APPR_SEED)
    agCheck("iso consent binds the exact action shown+approved", agKind { Agui.verifyConsent(consentChain, actionBytes, appr, AG_ALG, AG_APPR_PK, apprSig, now) }, "no-error")
    // a substituted action (different content id) is rejected.
    agCheck("iso substituted action rejected ActionSubstituted", agKind { Agui.verifyConsent(consentChain, substitutedBytes, appr, AG_ALG, AG_APPR_PK, apprSig, now) }, "ActionSubstituted")
    // a chain with no approved event has no consent to bind.
    val noApprove = listOf(e0, e1)
    agCheck("iso no approved event rejected UINoConsent", agKind { Agui.verifyConsent(noApprove, actionBytes, appr, AG_ALG, AG_APPR_PK, apprSig, now) }, "UINoConsent")
}

fun main() {
    println("agui conformance (Kotlin) — graded vs vectors/agui/cases.json")
    aguiRun()
    println(if (agFails == 0) "AguiTests: PASS" else "AguiTests: FAIL ($agFails)")
    exitProcess(if (agFails == 0) 0 else 1)
}
