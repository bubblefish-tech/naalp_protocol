// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

//
// C17 N-AALP-CONT flow-continuation known-answer test for the Kotlin SDK (design.md §20;
// R-CONT-1..7), graded against the shared independent corpus vectors/continuation/cases.json (NOT
// produced by this code).
//
// CORPUS-GRADED (pure): the FlowOpen body + head + content id; each cheap Continuation link body +
// head and the whole recomputed chain's final head; the Checkpoint body and a clean prefix
// confirmation; the FlowCommit body; the AboveCeiling refusal of an over-ceiling link; the
// GapDetected on a non-contiguous prefix; the WrongFlow on a cross-flow replay; the RangeError on an
// out-of-lattice ceiling/effect; the GapDetected on a u64::MAX through_seq overflow; a > 2^53 seq
// that round-trips byte-exact; the minimal FlowOpen; the empty-vs-nonempty approvals distinction;
// the NonCanonical rejection of descending map keys; and the ContMalformed rejection of a 2-field
// FlowCommit fed to ParseCheckpoint. ISOLATION (real FIPS-204 ML-DSA-65 via BouncyCastle — Kotlin is
// a full-signature port; the corpus carries no signature vector, so these are demonstrated with a
// fixed local seed, stated honestly, NOT corpus-graded): the one full FlowOpen signature verifies
// and reconstructs the authority; a tampered FlowOpen is BadSignature; the second full FlowCommit
// signature binds the whole ordered sequence and a dropped link makes it CommitMismatch.
//
// KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
// "Tests" token the ten-language-parity gate indexes. Written test-first: [Cont] is absent until
// Continuation.kt lands, so this fails RED with a kotlinc "unresolved reference: Cont". The
// load-bearing mutation — the AboveCeiling ceiling check made a no-op — flips "above_ceiling link
// rejected AboveCeiling" on its assertion.
//

private var coFails = 0

private fun coCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        coFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- balanced-brace / regex JSON access (no JSON library on the Kotlin port) ----

private fun coFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/continuation/cases.json not found")
        val p = File(File(cur, "vectors"), "continuation/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/continuation/cases.json not found from ${File(".").absolutePath}")
}

private fun coSection(scope: String, key: String): String {
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

private fun coElements(arraySection: String): List<String> {
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

private fun coStr(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun coInt(scope: String, key: String): Long {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun coHex(s: String): ByteArray = Hex.decode(s)

private const val CO_ALG = Cose.ALG_MLDSA65
private val CO_SEED = ByteArray(32) { 0x11 }
private val CO_PK = Cose.mldsaKeygen("ML-DSA-65", ByteArray(32) { 0x11 })

private inline fun coKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

private fun coProtectedHeader(alg: Int): ByteArray =
    Cbor.encode(Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.N(alg.toLong())))))

private fun continuationRun() {
    val json = coFindVector().readText(Charsets.UTF_8)

    // 1. FlowOpen body + head + content id == the oracle.
    val fo = coSection(json, "flow_open")
    val open = Cont.FlowOpen(coHex(coStr(fo, "flow_id_hex")), coInt(fo, "effect_ceiling"), coApprovals(fo).map { coHex(it) })
    coCheck("flow_open body == oracle", Hex.encode(open.bytes()), coStr(fo, "body_hex"))
    coCheck("flow_open head == oracle", Hex.encode(open.head()), coStr(fo, "head_hex"))
    coCheck("flow_open id == oracle", Hex.encode(open.id()), coStr(fo, "id_hex"))

    // 2. each cheap Continuation link body + head == the oracle, and the recomputed chain's final head.
    val conts = ArrayList<Cont.Continuation>()
    for (cb in coElements(coSection(json, "continuations"))) {
        val c = Cont.Continuation(open.id(), coInt(cb, "seq"), coInt(cb, "effect"), coHex(coStr(cb, "payload_id_hex")), coHex(coStr(cb, "prev_hex")))
        coCheck("continuation seq=${coInt(cb, "seq")} body == oracle", Hex.encode(c.bytes()), coStr(cb, "body_hex"))
        coCheck("continuation seq=${coInt(cb, "seq")} head == oracle", Hex.encode(c.head()), coStr(cb, "head_hex"))
        conts.add(c)
    }
    coCheck("verify_chain final head == oracle", Hex.encode(Cont.verifyChain(open, conts)), coStr(json, "final_head_hex"))

    // 3. Checkpoint body == oracle, and a clean contiguous prefix confirms.
    val cp = coSection(json, "checkpoint")
    val checkpoint = Cont.Checkpoint(open.id(), coInt(cp, "through_seq"), coHex(coStr(cp, "head_hex")))
    coCheck("checkpoint body == oracle", Hex.encode(checkpoint.bytes()), coStr(cp, "body_hex"))
    val prefix = conts.subList(0, (coInt(cp, "through_seq") + 1).toInt()).toList()
    coCheck("checkpoint confirms a clean prefix", coKind { Cont.verifyCheckpoint(checkpoint, open, prefix) }, "no-error")

    // 4. FlowCommit body == oracle.
    val fc = coSection(json, "flow_commit")
    val commit = Cont.FlowCommit(open.id(), coHex(coStr(fc, "final_head_hex")))
    coCheck("flow_commit body == oracle", Hex.encode(commit.bytes()), coStr(fc, "body_hex"))

    // 5. an over-ceiling link is refused AboveCeiling (the cheap path can never escalate).
    val ac = coSection(json, "above_ceiling")
    val acCont = Cont.Continuation(open.id(), coInt(ac, "seq"), coInt(ac, "effect"), coHex(coStr(ac, "payload_id_hex")), coHex(coStr(ac, "prev_hex")))
    coCheck("above_ceiling link body == oracle", Hex.encode(acCont.bytes()), coStr(ac, "body_hex"))
    coCheck("above_ceiling link head == oracle", Hex.encode(acCont.head()), coStr(ac, "head_hex"))
    coCheck("above_ceiling link rejected AboveCeiling", coKind { Cont.verifyContinuation(acCont, open.id(), coHex(coStr(ac, "prev_hex")), coInt(ac, "seq"), coInt(ac, "ceiling")) }, coStr(ac, "reject"))

    // 6. a non-contiguous prefix (seq 0 then seq 2, missing seq 1) is GapDetected.
    val gap = coSection(json, "gap")
    val gapPrefix = listOf(conts[0], conts[2])
    val gapCp = Cont.Checkpoint(open.id(), coInt(gap, "through_seq"), coHex(coStr(gap, "claimed_head_hex")))
    coCheck("gap prefix rejected GapDetected", coKind { Cont.verifyCheckpoint(gapCp, open, gapPrefix) }, coStr(gap, "detect"))

    // 7. cross-flow replay: seq-0 link (flow A) verified under FlowOpen B is WrongFlow. FlowOpen B is
    //    reconstructed from its bytes (ParseFlowOpen) and its body/head/id round-trip byte-exact.
    val rp = coSection(json, "replay")
    val openB = Cont.parseFlowOpen(coHex(coStr(rp, "flow_open_b_body_hex")))
    coCheck("flow_open B round-trip body == oracle", Hex.encode(openB.bytes()), coStr(rp, "flow_open_b_body_hex"))
    coCheck("flow_open B head == oracle", Hex.encode(openB.head()), coStr(rp, "flow_open_b_head_hex"))
    coCheck("flow_open B id == oracle", Hex.encode(openB.id()), coStr(rp, "flow_open_b_id_hex"))
    coCheck("cross-flow replay rejected WrongFlow", coKind { Cont.verifyContinuation(conts[0], openB.id(), openB.head(), 0, openB.effectCeiling) }, coStr(rp, "detect"))

    // 8. an out-of-lattice ceiling (flow-open field 2) and effect (continuation field 3) are RangeError,
    //    never normalized to destructive.
    val rr = coSection(json, "range_reject")
    coCheck("out-of-lattice ceiling rejected RangeError", coKind { Cont.parseFlowOpen(coHex(coStr(rr, "flow_open_ceiling_body_hex"))) }, coStr(rr, "reject"))
    coCheck("out-of-lattice effect rejected RangeError", coKind { Cont.parseContinuation(coHex(coStr(rr, "continuation_effect_body_hex"))) }, coStr(rr, "reject"))

    // 9. a checkpoint with through_seq == u64::MAX admits no contiguous prefix -> GapDetected (no MAX+1
    //    links; the through_seq+1 overflow guard).
    val ov = coSection(json, "checkpoint_overflow")
    val ovCp = Cont.parseCheckpoint(coHex(coStr(ov, "body_hex")))
    coCheck("u64::MAX through_seq overflow rejected GapDetected", coKind { Cont.verifyCheckpoint(ovCp, open, emptyList()) }, coStr(ov, "reject"))

    // 10. a seq > 2^53 round-trips byte-exact (carried as a JSON string; Kotlin Long is 64-bit).
    val bs = coSection(json, "big_seq")
    val bigCont = Cont.Continuation(open.id(), coStr(bs, "seq_str").toLong(), coInt(bs, "effect"), coHex(coStr(bs, "payload_id_hex")), coHex(coStr(bs, "prev_hex")))
    coCheck("big_seq (>2^53) body == oracle", Hex.encode(bigCont.bytes()), coStr(bs, "body_hex"))
    coCheck("big_seq (>2^53) head == oracle", Hex.encode(bigCont.head()), coStr(bs, "head_hex"))

    // 11. the smallest valid FlowOpen (empty flow_id, ceiling read_only, no approvals).
    val mn = coSection(json, "minimal")
    val minOpen = Cont.FlowOpen(coHex(coStr(mn, "flow_id_hex")), coInt(mn, "effect_ceiling"), coApprovals(mn).map { coHex(it) })
    coCheck("minimal flow_open body == oracle", Hex.encode(minOpen.bytes()), coStr(mn, "body_hex"))
    coCheck("minimal flow_open head == oracle", Hex.encode(minOpen.head()), coStr(mn, "head_hex"))
    coCheck("minimal flow_open id == oracle", Hex.encode(minOpen.id()), coStr(mn, "id_hex"))

    // 12. an empty approvals[] is distinct on the wire and by content id from a populated one.
    val ev = coSection(json, "empty_vs_nonempty")
    val flowId = coHex(coStr(fo, "flow_id_hex"))
    val emptyOpen = Cont.FlowOpen(flowId, 2, emptyList())
    val oneOpen = Cont.FlowOpen(flowId, 2, listOf(coHex(coApprovals(fo)[0])))
    coCheck("empty approvals body == oracle", Hex.encode(emptyOpen.bytes()), coStr(coSection(ev, "empty_approvals"), "body_hex"))
    coCheck("empty approvals id == oracle", Hex.encode(emptyOpen.id()), coStr(coSection(ev, "empty_approvals"), "id_hex"))
    coCheck("one approval body == oracle", Hex.encode(oneOpen.bytes()), coStr(coSection(ev, "one_approval"), "body_hex"))
    coCheck("one approval id == oracle", Hex.encode(oneOpen.id()), coStr(coSection(ev, "one_approval"), "id_hex"))
    coCheck("empty != one approval by id", (Hex.encode(emptyOpen.id()) != Hex.encode(oneOpen.id())).toString(), "true")

    // 13. descending map keys (2 then 1) are rejected NonCanonical by the strict decoder.
    val ko = coSection(json, "keys_out_of_order")
    coCheck("noncanonical commit body rejected NonCanonical", coKind { Cbor.decode(coHex(coStr(ko, "noncanonical_commit_body_hex"))) }, coStr(ko, "reject"))
    coCheck("canonical commit body decodes cleanly", coKind { Cbor.decode(coHex(coStr(ko, "canonical_commit_body_hex"))) }, "no-error")

    // 14. a 2-field FlowCommit body fed to ParseCheckpoint is rejected ContMalformed (Checkpoint is 3 fields).
    val la = coSection(json, "look_alike")
    coCheck("FlowCommit look-alike rejected by ParseCheckpoint", coKind { Cont.parseCheckpoint(coHex(coStr(la, "flow_commit_body_hex"))) }, "ContMalformed")

    // 15. ISOLATION (real ML-DSA): the one full FlowOpen signature verifies + reconstructs the authority;
    //     a tampered FlowOpen is BadSignature; the FlowCommit binds the ordered chain (CommitMismatch on a drop).
    run {
        val prot = coProtectedHeader(CO_ALG)
        val signedOpen = Cose.coseSign1(CO_ALG, CO_SEED, prot, open.bytes())
        val recovered = Cont.verifyFlowOpen(signedOpen, CO_ALG, CO_PK)
        coCheck("signed FlowOpen verifies + reconstructs ceiling", recovered.effectCeiling.toString(), coInt(fo, "effect_ceiling").toString())
        val tampered = signedOpen.copyOf(); tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte()
        coCheck("tampered FlowOpen rejected BadSignature", coKind { Cont.verifyFlowOpen(tampered, CO_ALG, CO_PK) }, "BadSignature")
        val signedCommit = Cose.coseSign1(CO_ALG, CO_SEED, prot, commit.bytes())
        coCheck("signed FlowCommit binds the ordered chain", coKind { Cont.verifyFlowCommit(signedCommit, CO_ALG, CO_PK, open, conts) }, "no-error")
        coCheck("FlowCommit over a dropped link is CommitMismatch", coKind { Cont.verifyFlowCommit(signedCommit, CO_ALG, CO_PK, open, conts.subList(0, 2).toList()) }, "CommitMismatch")
    }
}

// The approvals_hex list of a FlowOpen-like section (empty for a no-approvals FlowOpen).
private fun coApprovals(scope: String): List<String> {
    val arr = coSection(scope, "approvals_hex")
    return Regex("\"([0-9a-fA-F]+)\"").findAll(arr).map { it.groupValues[1] }.toList()
}

fun main() {
    println("continuation conformance (Kotlin) — graded vs vectors/continuation/cases.json")
    continuationRun()
    println(if (coFails == 0) "ContinuationTests: PASS" else "ContinuationTests: FAIL ($coFails)")
    exitProcess(if (coFails == 0) 0 else 1)
}
