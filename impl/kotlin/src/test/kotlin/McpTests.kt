// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

//
// NAALP-MCP binding-profile known-answer test for the Kotlin SDK (design.md §19; Companion-Spec
// Requirement 6.1), graded against the shared independent corpus vectors/mcp/cases.json (NOT produced
// by this code).
//
// CORPUS-GRADED (pure, no signature): the transcribed annotation set (encode + parse round-trip) and
// its mapping to the closed four-effect lattice; every malformed annotation set rejected
// MalformedAnnotation; each tool-call body + content id, its (tool_id, args_id) call binding, the call
// binding body + call content id; the more-severe resolution verdicts (accept with enforced+mismatch,
// or EffectUnderDeclared); the approval-binding cases (changed args OR changed tool description yields a
// different call content id); the edge cases (non-canonical key order rejected, empty-vs-absent
// annotations, minimal call, a 2-field call-binding fed to the 3-field tool-call parser rejected).
// ISOLATION (real FIPS-204 ML-DSA-65 via BouncyCastle — Kotlin is a full-signature port; the corpus
// carries NO signed vector, so these are demonstrated with a fixed local seed, stated honestly, NOT
// corpus-graded): a signed McpToolCall verifies and resolves; a lying benign annotation with a severe
// declared effect enforces the more-severe (mismatch attributable to the signer); an under-declared
// signer is rejected EffectUnderDeclared; a garbage signature is BadSignature; and the per-call
// approval gate authorizes exactly once, replays AlreadyConsumed, and denies a different call
// ApprovalRequired — reusing the just-landed §7 Approval single-use consume ledger UNCHANGED.
//
// KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the "Tests"
// token the ten-language-parity gate indexes. Written test-first: [Mcp] is absent until Mcp.kt lands, so
// this fails RED with a kotlinc "unresolved reference: Mcp". The load-bearing mutation — the
// resolveEnforcedEffect under-declaration guard made unreachable (if (declared < annotationMapped) ->
// if (false)) — flips "resolution under_declare_severe_annotation_benign_signer verdict ==
// EffectUnderDeclared" on its assertion.
//

private var mcFails = 0

private fun mcCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        mcFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- balanced-brace / regex JSON access (no JSON library on the Kotlin port) ----

private fun mcFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/mcp/cases.json not found")
        val p = File(File(cur, "vectors"), "mcp/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/mcp/cases.json not found from ${File(".").absolutePath}")
}

private fun mcSection(scope: String, key: String): String {
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

private fun mcElements(arraySection: String): List<String> {
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

private fun mcStr(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun mcInt(scope: String, key: String): Long {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun mcBool(scope: String, key: String): Boolean {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(true|false)").find(scope)
        ?: throw AssertionError("bool key not found: $key")
    return m.groupValues[1] == "true"
}

private fun mcHex(s: String): ByteArray = Hex.decode(s)

private const val MC_ALG = Cose.ALG_MLDSA65
private val MC_SEED = ByteArray(32) { 7 }
private val MC_PK = Cose.mldsaKeygen("ML-DSA-65", MC_SEED)
private val MC_SIGNER = Identity.signerId(MC_ALG, MC_PK).toByteArray(Charsets.UTF_8)
private val MC_APPR_SEED = ByteArray(32) { 9 }
private val MC_APPR_PK = Cose.mldsaKeygen("ML-DSA-65", MC_APPR_SEED)

private inline fun mcKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

// Build an Annotations from a naalp-mcp-annotations hex map (the corpus wire form), through the parser
// under test.
private fun mcAnn(hex: String): Mcp.Annotations = Mcp.annotationsFromValue(Cbor.decode(mcHex(hex)))

private fun mcpRun() {
    val json = mcFindVector().readText(Charsets.UTF_8)

    // 1. the transcribed annotation set: encode round-trip + mapping to the closed effect lattice.
    for (ab in mcElements(mcSection(json, "annotations"))) {
        val name = mcStr(ab, "name")
        val hex = mcStr(ab, "annotations_hex")
        val a = mcAnn(hex)
        mcCheck("annotation $name encode round-trip == oracle", Hex.encode(a.encode()), hex)
        mcCheck("annotation $name mapped effect == oracle", Mcp.mapAnnotationsToEffect(a).toString(), mcInt(ab, "mapped_effect").toString())
    }

    // 2. every malformed annotation set is rejected MalformedAnnotation (fail-closed, never defaulted).
    for (mb in mcElements(mcSection(json, "malformed_annotations"))) {
        val name = mcStr(mb, "name")
        val hex = mcStr(mb, "annotations_hex")
        mcCheck("malformed annotation $name rejected", mcKind { Mcp.annotationsFromValue(Cbor.decode(mcHex(hex))) }, mcStr(mb, "expect"))
    }

    // 3. each tool call: body + content id, (tool_id,args_id) binding, call-binding body + call content
    //    id, the annotation-mapped effect, and a body round-trip through the parser.
    for (tb in mcElements(mcSection(json, "tool_calls"))) {
        val name = mcStr(tb, "name")
        val tool = mcHex(mcStr(tb, "tool_hex"))
        val args = mcHex(mcStr(tb, "args_hex"))
        val ann = mcAnn(mcStr(tb, "annotations_hex"))
        val tc = Mcp.ToolCall(tool, args, ann)
        mcCheck("tool_call $name body == oracle", Hex.encode(tc.bytes()), mcStr(tb, "body_hex"))
        mcCheck("tool_call $name content id == oracle", Hex.encode(tc.contentId()), mcStr(tb, "content_id_hex"))
        val cb = tc.callBinding()
        mcCheck("tool_call $name tool_id == oracle", Hex.encode(cb.toolId), mcStr(tb, "tool_id_hex"))
        mcCheck("tool_call $name args_id == oracle", Hex.encode(cb.argsId), mcStr(tb, "args_id_hex"))
        mcCheck("tool_call $name call binding == oracle", Hex.encode(cb.bytes()), mcStr(tb, "call_binding_hex"))
        mcCheck("tool_call $name call content id == oracle", Hex.encode(cb.contentId()), mcStr(tb, "call_content_id_hex"))
        mcCheck("tool_call $name annotation-mapped effect == oracle", Mcp.mapAnnotationsToEffect(ann).toString(), mcInt(tb, "annotation_mapped_effect").toString())
        val parsed = Mcp.toolCallFromBody(Cbor.decode(mcHex(mcStr(tb, "body_hex"))))
        mcCheck("tool_call $name parse round-trip == oracle", Hex.encode(parsed.bytes()), mcStr(tb, "body_hex"))
    }

    // 4. the more-severe resolution (good-regulator attenuator): accept -> (enforced, mismatch);
    //    under-declaration -> EffectUnderDeclared. THIS is the mutation's target assertion.
    for (rb in mcElements(mcSection(json, "resolution"))) {
        val name = mcStr(rb, "name")
        val mapped = mcInt(rb, "annotation_mapped")
        val declared = mcInt(rb, "declared")
        val verdict = mcStr(rb, "verdict")
        if (verdict == "accept") {
            val (enforced, mismatch) = Mcp.resolveEnforcedEffect(mapped, declared)
            mcCheck("resolution $name enforced == oracle", enforced.toString(), mcInt(rb, "enforced").toString())
            mcCheck("resolution $name mismatch == oracle", mismatch.toString(), mcBool(rb, "mismatch").toString())
        } else {
            mcCheck("resolution $name verdict == $verdict", mcKind { Mcp.resolveEnforcedEffect(mapped, declared) }, verdict)
        }
    }

    // 5. the approval binding: changed args OR changed tool description yields a DIFFERENT call content
    //    id, so a prior approval no longer matches (AC-6.1.2 / AC-6.1.3).
    for (ab in mcElements(mcSection(json, "approval_binding"))) {
        val name = mcStr(ab, "name")
        val cb = Mcp.newCallBinding(mcHex(mcStr(ab, "tool_hex")), mcHex(mcStr(ab, "args_hex")))
        mcCheck("approval_binding $name tool_id == oracle", Hex.encode(cb.toolId), mcStr(ab, "tool_id_hex"))
        mcCheck("approval_binding $name args_id == oracle", Hex.encode(cb.argsId), mcStr(ab, "args_id_hex"))
        mcCheck("approval_binding $name call binding == oracle", Hex.encode(cb.bytes()), mcStr(ab, "call_binding_hex"))
        mcCheck("approval_binding $name call content id == oracle", Hex.encode(cb.contentId()), mcStr(ab, "call_content_id_hex"))
    }

    // 6. edge cases.
    val edge = mcSection(json, "edge_cases")
    val koo = mcSection(edge, "keys_out_of_order")
    mcCheck("edge keys_out_of_order noncanonical rejected", mcKind { Cbor.decode(mcHex(mcStr(koo, "noncanonical_body_hex"))) }, mcStr(koo, "reject"))
    mcCheck("edge keys_out_of_order canonical parses", mcKind { Mcp.toolCallFromBody(Cbor.decode(mcHex(mcStr(koo, "canonical_body_hex")))) }, "no-error")

    val eva = mcSection(edge, "empty_vs_absent")
    val empt = mcSection(eva, "empty_annotations")
    val emptTc = Mcp.toolCallFromBody(Cbor.decode(mcHex(mcStr(empt, "body_hex"))))
    mcCheck("edge empty_annotations body round-trip == oracle", Hex.encode(emptTc.bytes()), mcStr(empt, "body_hex"))
    mcCheck("edge empty_annotations mapped effect == oracle", Mcp.mapAnnotationsToEffect(emptTc.annotations).toString(), mcInt(empt, "mapped_effect").toString())
    val absent = mcSection(eva, "absent_annotations")
    mcCheck("edge absent_annotations rejected", mcKind { Mcp.toolCallFromBody(Cbor.decode(mcHex(mcStr(absent, "body_hex")))) }, mcStr(absent, "reject"))

    val minimal = mcSection(edge, "minimal")
    val minTc = Mcp.ToolCall(mcHex(mcStr(minimal, "tool_hex")), mcHex(mcStr(minimal, "args_hex")), Mcp.Annotations(null, null, null, null))
    mcCheck("edge minimal body == oracle", Hex.encode(minTc.bytes()), mcStr(minimal, "body_hex"))
    mcCheck("edge minimal content id == oracle", Hex.encode(minTc.contentId()), mcStr(minimal, "content_id_hex"))
    mcCheck("edge minimal mapped effect == oracle", Mcp.mapAnnotationsToEffect(minTc.annotations).toString(), mcInt(minimal, "mapped_effect").toString())

    val look = mcSection(edge, "look_alike")
    mcCheck("edge look_alike (2-field binding) rejected", mcKind { Mcp.toolCallFromBody(Cbor.decode(mcHex(mcStr(look, "call_binding_body_hex")))) }, mcStr(look, "reject"))

    // 7. ISOLATION (real ML-DSA): the signed governance path. A signed McpToolCall verifies and resolves;
    //    a lying benign annotation with a severe declared effect enforces the more severe; an
    //    under-declared signer is rejected; a garbage signature is BadSignature.
    val now = 1000L
    // 7a. agree read_only: annotations {ro=1} -> mapped 0, declared 0 -> enforced 0, no mismatch.
    val roTc = Mcp.ToolCall("tool-ro".toByteArray(), "args-ro".toByteArray(), Mcp.Annotations(true, null, null, null))
    val roObj = roTc.envelopeObject(MC_SIGNER, now, Cose.PROFILE_PUBLIC, 0L, emptyList())
    val roSigned = Envelope.sign(roObj, MC_ALG, MC_SEED)
    val roRes = Mcp.verifyToolCall(Cose.PROFILE_PUBLIC, MC_ALG, MC_PK, roSigned)
    mcCheck("iso verify read_only enforced == 0", roRes.enforced.toString(), "0")
    mcCheck("iso verify read_only no mismatch", roRes.mismatch.toString(), "false")

    // 7b. lying tool (ro=1 -> mapped read_only) but the signer, accountable, declares destructive:
    //     enforced = destructive (the more severe), mismatch attributable to the signer.
    val lieObj = roTc.envelopeObject(MC_SIGNER, now, Cose.PROFILE_PUBLIC, Policy.DESTRUCTIVE, emptyList())
    val lieSigned = Envelope.sign(lieObj, MC_ALG, MC_SEED)
    val lieRes = Mcp.verifyToolCall(Cose.PROFILE_PUBLIC, MC_ALG, MC_PK, lieSigned)
    mcCheck("iso lying-benign-severe-declared enforced == destructive", lieRes.enforced.toString(), Policy.DESTRUCTIVE.toString())
    mcCheck("iso lying-benign-severe-declared mismatch attributable to signer", lieRes.mismatch.toString(), "true")

    // 7c. under-declare: annotations {ro=0,de=1} -> mapped destructive, declared read_only -> rejected.
    val destTc = Mcp.ToolCall("tool-x".toByteArray(), "args-x".toByteArray(), Mcp.Annotations(false, true, null, null))
    val underObj = destTc.envelopeObject(MC_SIGNER, now, Cose.PROFILE_PUBLIC, 0L, emptyList())
    val underSigned = Envelope.sign(underObj, MC_ALG, MC_SEED)
    mcCheck("iso under-declared signer rejected EffectUnderDeclared", mcKind { Mcp.verifyToolCall(Cose.PROFILE_PUBLIC, MC_ALG, MC_PK, underSigned) }, "EffectUnderDeclared")

    // 7d. a tampered signature is BadSignature (fail-closed), never a crash or silent pass.
    val tampered = roSigned.copyOf(); tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte()
    mcCheck("iso tampered signature rejected BadSignature", mcKind { Mcp.verifyToolCall(Cose.PROFILE_PUBLIC, MC_ALG, MC_PK, tampered) }, "BadSignature")

    // 8. ISOLATION: the per-call approval gate (reuses the §7 Approval single-use consume ledger). The
    //    approval binds the EXACT call binding content id; authorize once, replay AlreadyConsumed, deny a
    //    different call ApprovalRequired.
    val callCID = destTc.callBinding().contentId()
    val appr = Approval.ApprovalRecord(callCID, "approver", Policy.DESTRUCTIVE, ByteArray(16) { 3 }, 2_000_000_000_000L)
    val apprSig = Approval.signApproval(appr, MC_ALG, MC_APPR_SEED)
    // A verified Resolved for destTc, declaring destructive to match its annotations.
    val destObj = destTc.envelopeObject(MC_SIGNER, now, Cose.PROFILE_PUBLIC, Policy.DESTRUCTIVE, emptyList())
    val destRes = Mcp.verifyToolCall(Cose.PROFILE_PUBLIC, MC_ALG, MC_PK, Envelope.sign(destObj, MC_ALG, MC_SEED))
    val wal = File.createTempFile("naalp-mcp-kat", ".wal").also { it.deleteOnExit() }; wal.delete()
    val ledger = Approval.openLedger(wal.absolutePath)
    mcCheck("iso authorize matching call succeeds", mcKind { Mcp.authorizeCall(destRes, appr, MC_ALG, MC_APPR_PK, apprSig, "caller", now, ledger) }, "no-error")
    mcCheck("iso authorize replay rejected AlreadyConsumed", mcKind { Mcp.authorizeCall(destRes, appr, MC_ALG, MC_APPR_PK, apprSig, "caller", now, ledger) }, "AlreadyConsumed")
    ledger.close()
    // A different call (different args -> different call binding cid): the approval no longer matches.
    val otherTc = Mcp.ToolCall("tool-x".toByteArray(), "args-DIFFERENT".toByteArray(), Mcp.Annotations(false, true, null, null))
    val otherObj = otherTc.envelopeObject(MC_SIGNER, now, Cose.PROFILE_PUBLIC, Policy.DESTRUCTIVE, emptyList())
    val otherRes = Mcp.verifyToolCall(Cose.PROFILE_PUBLIC, MC_ALG, MC_PK, Envelope.sign(otherObj, MC_ALG, MC_SEED))
    val wal2 = File.createTempFile("naalp-mcp-kat2", ".wal").also { it.deleteOnExit() }; wal2.delete()
    val ledger2 = Approval.openLedger(wal2.absolutePath)
    mcCheck("iso authorize different call denied ApprovalRequired", mcKind { Mcp.authorizeCall(otherRes, appr, MC_ALG, MC_APPR_PK, apprSig, "caller", now, ledger2) }, "ApprovalRequired")
    ledger2.close()
}

fun main() {
    println("mcp conformance (Kotlin) — graded vs vectors/mcp/cases.json")
    mcpRun()
    println(if (mcFails == 0) "McpTests: PASS" else "McpTests: FAIL ($mcFails)")
    exitProcess(if (mcFails == 0) 0 else 1)
}
