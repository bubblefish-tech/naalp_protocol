// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import java.security.MessageDigest
import kotlin.system.exitProcess

/**
 * C7 audit known-answer test for the Kotlin SDK (design.md §8; R-8.1..8.6, R-12.2, R-12.3), graded
 * against the shared independent corpus vectors/audit/cases.json (NOT produced by this code).
 *
 * CORPUS-GRADED (pure): the hash-chained signed-receipt body + head for each receipt, the running
 * prev-link and final head, the draft-01 fork-proof preimage (both signatures elided to empty), the
 * equivocation receipt bodies, and the offline causal graph (valid topo order, cycle rejection,
 * future-cause rejection). ISOLATION (real FIPS-204 ML-DSA-65 via BouncyCastle — Kotlin is a full-
 * signature port; the corpus carries no signature vector for this channel, so these are demonstrated
 * with a fixed local seed, stated honestly, NOT corpus-graded): a fresh Authority reproduces the
 * byte-exact chain and its real-ML-DSA-signed receipts verify offline; a broken prev-link is
 * ChainBroken; a tampered signature is ReceiptUnsigned; the auditor mints a verifying fork proof on a
 * genuine one-seq conflict and rejects a benign duplicate / an unsigned receipt; the fork proof
 * fails closed (ForkProofInvalid / ReceiptUnsigned).
 *
 * KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
 * "Tests" token the ten-language-parity gate indexes. Written test-first: [Audit] is absent until
 * Audit.kt lands, so this fails RED with a kotlinc "unresolved reference: Audit". A mutation that
 * forces the encoded receipt seq field to a constant flips "chain receipt body seq=1 == oracle".
 */

private var auFails = 0

private fun auCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        auFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- balanced-brace / regex JSON access (no JSON library on the Kotlin port) ----

private fun auFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/audit/cases.json not found")
        val p = File(File(cur, "vectors"), "audit/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/audit/cases.json not found from ${File(".").absolutePath}")
}

/**
 * The balanced { ... } or [ ... ] value text (delimiters included) that follows "key":, scanning
 * with brace/bracket depth while skipping string contents. Robust to nesting (arrays inside objects).
 */
private fun auSection(scope: String, key: String): String {
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

/** Top-level { ... } object element substrings of an already-extracted [ ... ] array section. */
private fun auElements(arraySection: String): List<String> {
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

/** The string value of a "key": "value" pair inside [scope] (value may be empty). */
private fun auStr(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

/** The integer value of a "key": <number> pair inside [scope]. */
private fun auInt(scope: String, key: String): Long {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

/** The list of quoted hex strings of the array-valued field named [key] inside [scope]. */
private fun auHexList(scope: String, key: String): List<String> {
    val arr = auSection(scope, key)
    return Regex("\"([0-9a-fA-F]*)\"").findAll(arr).map { it.groupValues[1] }.toList()
}

private fun auHex(s: String): ByteArray = Hex.decode(s)
private fun auSha384Hex(b: ByteArray): String = Hex.encode(MessageDigest.getInstance("SHA-384").digest(b))

private const val AU_ALG = Cose.ALG_MLDSA65
private val AU_SEED = ByteArray(32)
private val AU_PK = Cose.mldsaKeygen("ML-DSA-65", ByteArray(32))

/** The named kind thrown by [block], or "no-error". */
private inline fun auKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

private fun auReceipt(block: String): Audit.Receipt =
    Audit.Receipt(auHex(auStr(block, "prev_hex")), auHex(auStr(block, "obj_hex")), auInt(block, "seq"), auInt(block, "at"))

private fun auCausalNodes(scope: String): List<Audit.CausalNode> =
    auElements(auSection(scope, "nodes")).map { nb ->
        Audit.CausalNode(auHex(auStr(nb, "id_hex")), auHexList(nb, "causes_hex").map { auHex(it) }, auInt(nb, "position"))
    }

private fun auditRun() {
    val json = auFindVector().readText(Charsets.UTF_8)

    // 1. signed hash-chained receipt: each receipt body/head == the oracle, and prev links the chain.
    val chain = auSection(json, "chain")
    var head = auHex(auStr(chain, "genesis_prev_hex"))
    auCheck("genesis prev is HEAD_SIZE zeros", head.size.toString() + "/" + Hex.encode(head), "48/" + "00".repeat(48))
    auCheck("HEAD_SIZE", Audit.HEAD_SIZE.toString(), "48")
    for (rb in auElements(auSection(chain, "receipts"))) {
        val r = auReceipt(rb)
        auCheck("chain receipt body seq=${r.seq} == oracle", Hex.encode(r.bytes()), auStr(rb, "body_hex"))
        auCheck("chain receipt head seq=${r.seq} == oracle", Hex.encode(r.head()), auStr(rb, "head_after_hex"))
        auCheck("chain prev links seq=${r.seq}", Hex.encode(r.prev), Hex.encode(head))
        head = r.head()
    }
    auCheck("chain final head == oracle", Hex.encode(head), auStr(chain, "final_head_hex"))

    // 2. a fresh authority reproduces the byte-exact chain; its real-ML-DSA-signed receipts verify
    //    offline (ISOLATION — corpus has no signature vector).
    run {
        val auth = Audit.Authority(AU_ALG, AU_SEED)
        val receipts = ArrayList<Audit.Receipt>()
        val sigs = ArrayList<ByteArray>()
        for (rb in auElements(auSection(chain, "receipts"))) {
            val (r, sig) = auth.append(auHex(auStr(rb, "obj_hex")), auInt(rb, "at"))
            auCheck("authority append body seq=${r.seq} == oracle", Hex.encode(r.bytes()), auStr(rb, "body_hex"))
            receipts.add(r); sigs.add(sig)
        }
        auCheck("authority chain verifies offline", auKind { Audit.verifyChain(receipts, sigs, AU_ALG, AU_PK) }, "no-error")
    }

    // 3. a broken prev-link is ChainBroken (each body signed with a real key so the break, not a bad
    //    signature, is what fires).
    run {
        val cb = auSection(json, "chain_broken")
        val receipts = ArrayList<Audit.Receipt>()
        val sigs = ArrayList<ByteArray>()
        for (rb in auElements(auSection(cb, "receipts"))) {
            val r = auReceipt(rb)
            auCheck("chain_broken body seq=${r.seq} == oracle", Hex.encode(r.bytes()), auStr(rb, "body_hex"))
            receipts.add(r); sigs.add(Cose.mldsaSign(AU_ALG, AU_SEED, r.bytes()))
        }
        auCheck("broken prev-link rejected", auKind { Audit.verifyChain(receipts, sigs, AU_ALG, AU_PK) }, auStr(cb, "expect"))
    }

    // 4. a tampered signature is ReceiptUnsigned (ISOLATION).
    run {
        val rb = auElements(auSection(chain, "receipts"))[0]
        val r = Audit.Receipt(auHex(auStr(chain, "genesis_prev_hex")), auHex(auStr(rb, "obj_hex")), 0, auInt(rb, "at"))
        val bad = Cose.mldsaSign(AU_ALG, AU_SEED, r.bytes()).copyOf()
        bad[bad.size - 1] = (bad[bad.size - 1].toInt() xor 1).toByte()
        auCheck("tampered signature rejected", auKind { Audit.verifyChain(listOf(r), listOf(bad), AU_ALG, AU_PK) }, "ReceiptUnsigned")
    }

    // 5. consistent-with-anchor: an object cannot be created after the authority ordered it.
    auCheck("anchor created==at ok", Audit.consistentWithAnchor(100, 100).toString(), "true")
    auCheck("anchor created<at ok", Audit.consistentWithAnchor(99, 100).toString(), "true")
    auCheck("anchor created>at rejected", Audit.consistentWithAnchor(101, 100).toString(), "false")

    // 6. equivocation receipts (two receipts at one seq naming different objects) match the oracle.
    val fp = auSection(json, "fork_proof")
    val ra = Audit.Receipt(auHex(auStr(fp, "prev_hex")), auHex(auStr(fp, "obj_a_hex")), auInt(fp, "seq"), auInt(fp, "at"))
    val rb = Audit.Receipt(auHex(auStr(fp, "prev_hex")), auHex(auStr(fp, "obj_b_hex")), auInt(fp, "seq"), auInt(fp, "at"))
    auCheck("fork receipt A body == oracle", Hex.encode(ra.bytes()), auStr(fp, "body_a_hex"))
    auCheck("fork receipt B body == oracle", Hex.encode(rb.bytes()), auStr(fp, "body_b_hex"))
    val eq = auSection(json, "equivocation")
    auCheck("equivocation receipt_a body == oracle", Hex.encode(ra.bytes()), auStr(auSection(eq, "receipt_a"), "body_hex"))
    auCheck("equivocation receipt_b body == oracle", Hex.encode(rb.bytes()), auStr(auSection(eq, "receipt_b"), "body_hex"))

    // 7. the auditor detects a genuine one-seq fork and mints a verifying proof; a benign duplicate
    //    and an unsigned receipt do not (ISOLATION).
    run {
        val signer = auHex(auStr(fp, "signer_hex"))
        val ext = auInt(fp, "ext_counter")
        val sigA = Cose.mldsaSign(AU_ALG, AU_SEED, ra.bytes())
        val sigB = Cose.mldsaSign(AU_ALG, AU_SEED, rb.bytes())
        val auditor = Audit.Auditor(AU_ALG, AU_PK, signer, ext)
        auCheck("first observe benign", (auditor.observe(ra, sigA) == null).toString(), "true")
        val proof = auditor.observe(rb, sigB)
        auCheck("second observe mints proof", (proof != null).toString(), "true")
        auCheck("minted proof verifies", auKind { proof!!.verify(AU_ALG, AU_PK) }, "no-error")
        auCheck("corpus equivocation expect", auStr(eq, "expect"), "Equivocation")

        val dupAuditor = Audit.Auditor(AU_ALG, AU_PK, signer, ext)
        auCheck("duplicate observe 1 benign", (dupAuditor.observe(ra, sigA) == null).toString(), "true")
        auCheck("exact duplicate is not a fork", (dupAuditor.observe(ra, sigA) == null).toString(), "true")

        val foreignSig = Cose.mldsaSign(AU_ALG, ByteArray(32) { 0x77 }, ra.bytes()) // valid-length, verifies false
        auCheck("unsigned receipt rejected", auKind { Audit.Auditor(AU_ALG, AU_PK, signer, ext).observe(ra, foreignSig) }, "ReceiptUnsigned")
    }

    // 8. the fork-proof framing witness (both signatures elided to empty) == the oracle preimage.
    run {
        val signer = auHex(auStr(fp, "signer_hex"))
        val ext = auInt(fp, "ext_counter")
        val proof = Audit.newForkProof(signer, ra, ByteArray(0), rb, ByteArray(0), ext)
        auCheck("fork-proof preimage == oracle", Hex.encode(proof.preimage()), auStr(fp, "preimage_hex"))
    }

    // 9. the fork proof accepts a valid proof and fails closed on every degenerate shape (ISOLATION).
    run {
        val signer = auHex(auStr(fp, "signer_hex"))
        val ext = auInt(fp, "ext_counter")
        val sigA = Cose.mldsaSign(AU_ALG, AU_SEED, ra.bytes())
        val sigB = Cose.mldsaSign(AU_ALG, AU_SEED, rb.bytes())
        auCheck("valid fork proof accepts", auKind { Audit.newForkProof(signer, ra, sigA, rb, sigB, ext).verify(AU_ALG, AU_PK) }, "no-error")
        auCheck("same-object proof rejected", auKind { Audit.newForkProof(signer, ra, sigA, ra, sigA, ext).verify(AU_ALG, AU_PK) }, "ForkProofInvalid")
        auCheck("unnamed-signer proof rejected", auKind { Audit.newForkProof(ByteArray(0), ra, sigA, rb, sigB, ext).verify(AU_ALG, AU_PK) }, "ForkProofInvalid")
        val rbSeq = Audit.Receipt(rb.prev, rb.obj, rb.seq + 1, rb.at)
        val sigB2 = Cose.mldsaSign(AU_ALG, AU_SEED, rbSeq.bytes())
        auCheck("seq-mismatch proof rejected", auKind { Audit.newForkProof(signer, ra, sigA, rbSeq, sigB2, ext).verify(AU_ALG, AU_PK) }, "ForkProofInvalid")
        val badSig = sigB.copyOf(); badSig[badSig.size - 1] = (badSig[badSig.size - 1].toInt() xor 1).toByte()
        auCheck("tampered-signature proof rejected", auKind { Audit.newForkProof(signer, ra, sigA, rb, badSig, ext).verify(AU_ALG, AU_PK) }, "ReceiptUnsigned")
    }

    // 10. offline causal graph: valid topo order == oracle; cycle and future-cause are CausalViolation.
    run {
        val cv = auSection(json, "causal_valid")
        val nodes = auCausalNodes(cv)
        auCheck("causal valid verifies", auKind { Audit.verifyCausal(nodes) }, "no-error")
        auCheck("causal topo order == oracle", Audit.topoOrder(nodes).joinToString(",") { Hex.encode(it) }, auHexList(cv, "topo_order_hex").joinToString(","))
        val cc = auSection(json, "causal_cycle")
        auCheck("causal cycle rejected", auKind { Audit.verifyCausal(auCausalNodes(cc)) }, auStr(cc, "expect"))
        val cf = auSection(json, "causal_future")
        auCheck("causal future-cause rejected", auKind { Audit.verifyCausal(auCausalNodes(cf)) }, auStr(cf, "expect"))
    }
}

fun main() {
    println("audit conformance (Kotlin) — graded vs vectors/audit/cases.json")
    auditRun()
    println(if (auFails == 0) "AuditTests: PASS" else "AuditTests: FAIL ($auFails)")
    exitProcess(if (auFails == 0) 0 else 1)
}
