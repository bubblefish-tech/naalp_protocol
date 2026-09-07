// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

//
// C15 multi-hop agent-delegation known-answer test for the Kotlin SDK (design.md §18; R-DEL-1..8),
// graded against the shared independent corpus vectors/delegation/cases.json (NOT produced by this
// code).
//
// CORPUS-GRADED (pure): (1) each DelegationGrant wire body + content id (byte-exact, incl. the
// optional-scope omission and a Unicode subject/scope); (2) the D2 path-prefix scope-containment
// truth table; (3) the D3 12-step leaf->root chain verifier's verdict for every scenario — the
// independent from-scratch oracle model's verdict, reproduced by the pure chain walk over directly
// built verified grants (the abstract issuer/subject/anchor labels are exactly the oracle's model).
// ISOLATION (real FIPS-204 ML-DSA-65 via BouncyCastle — Kotlin is a full-signature port; the corpus
// scenario verdicts are signature-independent, so the real-crypto path is demonstrated separately,
// stated honestly, NOT corpus-graded): a real signed DelegationGrant round-trips through
// verifyGrantObject with the R-DEL-3 issuer binding (the envelope signer id derives from the key),
// authorizes a 1-hop action, and rejects a tampered signature (BadSignature) and a forged signer
// (SignerMismatch); and the D4 two-gate composition (authorizeDestructive) really consumes a §7
// approval through the Approval ledger — authorized once, AlreadyConsumed on replay, ApprovalRequired
// with none — a real wiring of delegation onto approval, not a stub.
//
// KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
// "Tests" token the ten-language-parity gate indexes. Written test-first: [Delegation] is absent
// until Delegation.kt lands, so this fails RED with a kotlinc "unresolved reference: Delegation". The
// load-bearing mutation — the step-6 effect-ceiling attenuation check made a no-op — flips "scenario
// effect_exceeds_leaf verdict == oracle" on its assertion.
//

private var deFails = 0

private fun deCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        deFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- balanced-brace / regex JSON access (no JSON library on the Kotlin port) ----

private fun deFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/delegation/cases.json not found")
        val p = File(File(cur, "vectors"), "delegation/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/delegation/cases.json not found from ${File(".").absolutePath}")
}

private fun deSection(scope: String, key: String): String {
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

private fun deElements(arraySection: String): List<String> {
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

// The string value of a "key": "value" pair (value may be empty; captures a leading balanced quote).
private fun deStr(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun deInt(scope: String, key: String): Long {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun deBool(scope: String, key: String): Boolean {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(true|false)").find(scope)
        ?: throw AssertionError("bool key not found: $key")
    return m.groupValues[1] == "true"
}

private fun deIntList(scope: String, key: String): List<Long> {
    val arr = deSection(scope, key)
    return Regex("\\d+").findAll(arr).map { it.value.toLong() }.toList()
}

private fun deStrList(scope: String, key: String): List<String> {
    val arr = deSection(scope, key)
    return Regex("\"([^\"]*)\"").findAll(arr).map { it.groupValues[1] }.toList()
}

private fun deHex(s: String): ByteArray = Hex.decode(s)

private inline fun deKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

// A distinct synthetic content id per scenario-grant index (the scenario `causes` are indices; this
// makes each grant a distinct object exactly as the oracle model treats them).
private fun deGrantId(i: Long): ByteArray = Cbor.contentId(("del-grant-" + i).toByteArray())

private fun deGrantFromBlock(block: String): Delegation.Grant {
    val scope = if (Regex("\"scope\"\\s*:").containsMatchIn(block)) deStr(block, "scope") else ""
    return Delegation.Grant(
        deStr(block, "subject"),
        deInt(block, "effect_cap"),
        deInt(block, "max_depth"),
        deInt(block, "not_before"),
        deInt(block, "not_after"),
        scope,
    )
}

private fun delegationRun() {
    val json = deFindVector().readText(Charsets.UTF_8)

    // 1. each DelegationGrant wire body + content id == the oracle (incl. optional-scope omission and
    //    a Unicode subject/scope).
    for (gb in deElements(deSection(json, "grants"))) {
        val name = deStr(gb, "name")
        val g = deGrantFromBlock(gb)
        deCheck("grant $name body == oracle", Hex.encode(g.bytes()), deStr(gb, "body_hex"))
        deCheck("grant $name content id == oracle", Hex.encode(g.contentId()), deStr(gb, "content_id_hex"))
    }

    // 2. the D2 path-prefix scope-containment truth table.
    var scIdx = 0
    for (sb in deElements(deSection(json, "scope_containment"))) {
        val child = deStr(sb, "child")
        val parent = deStr(sb, "parent")
        deCheck("scope_containment[$scIdx] '$child' in '$parent'", Delegation.scopeContained(child, parent).toString(), deBool(sb, "contained").toString())
        scIdx++
    }

    // 3. the D3 12-step chain verifier's verdict for every scenario (pure model == oracle).
    for (sc in deElements(deSection(json, "scenarios"))) {
        val name = deStr(sc, "name")
        val expect = deStr(sc, "expect")
        val now = deInt(sc, "now")
        val grantBlocks = deElements(deSection(sc, "grants"))
        val resolved = ArrayList<Delegation.Resolved>()
        for ((idx, gb) in grantBlocks.withIndex()) {
            val issuer = deStr(gb, "issuer")
            val g = deGrantFromBlock(gb)
            val causes = deIntList(gb, "causes").map { deGrantId(it) }
            resolved.add(Delegation.Resolved(deGrantId(idx.toLong()), issuer, g, causes))
        }
        val grants = Delegation.newGrantSet(resolved)
        val action = deSection(sc, "action")
        val act = Delegation.Action(
            deStr(action, "signer"),
            deInt(action, "effect"),
            deStr(action, "scope"),
            deIntList(action, "causes").map { deGrantId(it) },
        )
        val anchors = deStrList(sc, "anchors").toHashSet()
        val revoked = HashMap<String, Long>()
        for (rb in deElements(deSection(sc, "revoked"))) {
            revoked[Hex.encode(deGrantId(deInt(rb, "grant")))] = deInt(rb, "pos")
        }
        val verdict = deKind { Delegation.verifyChain(act, grants, anchors, revoked, now) }
        val got = if (verdict == "no-error") "authorized" else verdict
        deCheck("scenario $name verdict == oracle", got, expect)
    }

    // 4. ISOLATION (real ML-DSA): a real signed DelegationGrant round-trips through verifyGrantObject
    //    with the R-DEL-3 issuer binding, authorizes a 1-hop action, and rejects tamper / forged signer.
    run {
        val seed = ByteArray(32) { 0x33 }
        val pk = Cose.mldsaKeygen("ML-DSA-65", seed)
        val issuerId = Identity.signerId(Cose.ALG_MLDSA65, pk)
        val subjectSeed = ByteArray(32) { 0x44 }
        val subjectPk = Cose.mldsaKeygen("ML-DSA-65", subjectSeed)
        val subjectId = Identity.signerId(Cose.ALG_MLDSA65, subjectPk)
        val grant = Delegation.Grant(subjectId, Policy.NON_IDEMPOTENT_WRITE, 0, 100, 900, "")
        val obj = grant.envelopeObject(issuerId.toByteArray(), 500, Cose.PROFILE_PUBLIC, emptyList())
        val signed = Envelope.sign(obj, Cose.ALG_MLDSA65, seed)
        val resolved = Delegation.verifyGrantObject(Cose.PROFILE_PUBLIC.toInt(), Cose.ALG_MLDSA65, pk, signed)
        deCheck("real grant: issuer binds to the verifying key (R-DEL-3)", resolved.issuer, issuerId)
        deCheck("real grant: parsed subject == the delegatee", resolved.grant.subject, subjectId)
        val grants = Delegation.newGrantSet(listOf(resolved))
        val act = Delegation.Action(subjectId, Policy.NON_IDEMPOTENT_WRITE, "", listOf(resolved.contentId))
        deCheck("real 1-hop chain authorized", deKind { Delegation.verifyChain(act, grants, hashSetOf(issuerId), HashMap(), 500) }, "no-error")
        val tampered = signed.copyOf(); tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte()
        deCheck("real grant: tampered signature rejected BadSignature", deKind { Delegation.verifyGrantObject(Cose.PROFILE_PUBLIC.toInt(), Cose.ALG_MLDSA65, pk, tampered) }, "BadSignature")
        // forged signer: the envelope signer field names an id that does not derive from the key.
        val forged = grant.envelopeObject(subjectId.toByteArray(), 500, Cose.PROFILE_PUBLIC, emptyList())
        val forgedSigned = Envelope.sign(forged, Cose.ALG_MLDSA65, seed)
        deCheck("real grant: forged signer rejected SignerMismatch", deKind { Delegation.verifyGrantObject(Cose.PROFILE_PUBLIC.toInt(), Cose.ALG_MLDSA65, pk, forgedSigned) }, "SignerMismatch")
    }

    // 5. ISOLATION (real wiring): the D4 two-gate composition really consumes a §7 approval through
    //    the Approval ledger — authorized once, AlreadyConsumed on replay, ApprovalRequired with none.
    run {
        val rootId = "anchor-root"
        val actorId = "actor-b"
        val leaf = Delegation.Resolved(deGrantId(900), rootId, Delegation.Grant(actorId, Policy.DESTRUCTIVE, 0, 0, 10000, ""), emptyList())
        val grants = Delegation.newGrantSet(listOf(leaf))
        val act = Delegation.Action(actorId, Policy.DESTRUCTIVE, "", listOf(leaf.contentId))
        val anchors = hashSetOf(rootId)
        val argsId = Cbor.contentId("d4-args".toByteArray())
        val apprSeed = ByteArray(32) { 0x55 }
        val apprPk = Cose.mldsaKeygen("ML-DSA-65", apprSeed)
        val appr = Approval.ApprovalRecord(argsId, "approver", Policy.DESTRUCTIVE, ByteArray(16) { 0x01 }, 10000)
        val apprSig = Approval.signApproval(appr, Cose.ALG_MLDSA65, apprSeed)
        val wal = File.createTempFile("naalp-d4-kat", ".wal").also { it.deleteOnExit() }; wal.delete()
        val ledger = Approval.openLedger(wal.absolutePath)
        deCheck("D4: destructive action authorized (chain + fresh approval)", deKind { Delegation.authorizeDestructive(act, grants, anchors, HashMap(), 500, appr, Cose.ALG_MLDSA65, apprPk, apprSig, argsId, ledger) }, "no-error")
        deCheck("D4: the approval was consumed single-use", ledger.isConsumed(appr.id()).toString(), "true")
        deCheck("D4: replay denies AlreadyConsumed (spent approval)", deKind { Delegation.authorizeDestructive(act, grants, anchors, HashMap(), 500, appr, Cose.ALG_MLDSA65, apprPk, apprSig, argsId, ledger) }, "AlreadyConsumed")
        // a broken chain (untrusted root) denies with the D3 error even though the approval is present.
        val wal2 = File.createTempFile("naalp-d4b-kat", ".wal").also { it.deleteOnExit() }; wal2.delete()
        val ledger2 = Approval.openLedger(wal2.absolutePath)
        val appr2Sig = Approval.signApproval(appr, Cose.ALG_MLDSA65, apprSeed)
        deCheck("D4: untrusted root denies with the D3 error (chain checked first)", deKind { Delegation.authorizeDestructive(act, grants, hashSetOf("someone-untrusted"), HashMap(), 500, appr, Cose.ALG_MLDSA65, apprPk, appr2Sig, argsId, ledger2) }, "UntrustedChainRoot")
        deCheck("D4: no approval consumed on a denied action", ledger2.isConsumed(appr.id()).toString(), "false")
        ledger.close(); ledger2.close()
    }
}

fun main() {
    println("delegation conformance (Kotlin) — graded vs vectors/delegation/cases.json")
    delegationRun()
    println(if (deFails == 0) "DelegationTests: PASS" else "DelegationTests: FAIL ($deFails)")
    exitProcess(if (deFails == 0) 0 else 1)
}
