// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.concurrent.thread

/**
 * T1.5 (NAALP-REQ-121, design.md §7.5) ledger-signed consume-receipt / fork-evidence / receipt-set
 * surface, plus design §25 (C22, R-TDCS) trust-decision closure-sovereignty surfaces (R-TDCS-3
 * refusal, R-TDCS-4 freshness independence, R-TDCS-5 audience), known-answer + fail-closed tests for
 * the Kotlin SDK.
 *
 * CORPUS-GRADED (pure, non-circular per F3): every consume-receipt body against
 * vectors/consume_receipt/cases.json (base + sequence + fork legs); the fork/benign verdicts (same-
 * ledger different position, cross-ledger same/different position, benign byte-identical duplicate,
 * distinct approvals); the wire cases (non-canonical key order rejected before any receipt rule,
 * position round-tripping up to 2^64-1, empty-vs-absent ledger id); the audience byte-parity + id
 * against vectors/trust_decision/cases.json; and the refusal byte-parity + no-leak + reject family
 * against the same corpus.
 *
 * ISOLATION (real FIPS-204 ML-DSA-65 via BouncyCastle; the corpora carry no signature vector, so
 * these are demonstrated with fixed local seeds, stated honestly, NOT corpus-graded): consume-receipt
 * sign/verify (valid / unnamed / tampered / wrong-key); first-append-wins CAS on ONE signed ledger
 * (the mutation anchor -- see below); exactly-once under a concurrent race with consumeWithReceipt;
 * cross-ledger fork detection under two independently-racing ledgers; R-TDCS-4 freshness independence
 * (distinct ordering authority verifies, self-asserted freshness rejected, expiry still enforced,
 * unnamed ordering authority rejected).
 *
 * KAT convention: a standalone main() exiting non-zero on any failure (mirrors ApprovalTests.kt /
 * ProducingBoundaryKatTest.kt / RotationKatTest.kt); the filename carries the "KatTest" token the
 * ten-language-parity gate indexes. Written test-first: the T1.5/R-TDCS symbols referenced below are
 * absent until Approval.kt lands them, so this fails RED with kotlinc "unresolved reference" errors.
 *
 * The load-bearing MUTATION ANCHOR (matches the Go/Java/Kotlin family's existing approval red-evidence
 * shape): disabling the first-append-wins compare-and-set guard in Ledger.consumeWithReceipt (the
 * `if (consumed.containsKey(key))` check) makes a second consumeWithReceipt of the same approval id
 * succeed and mint a SECOND receipt at position 1 instead of throwing AlreadyConsumed -- flipping the
 * "second consumeWithReceipt of the same approval id is rejected AlreadyConsumed (first-append-wins)"
 * assertion in step 5 of consumeReceiptRun() below.
 *
 * NOT GRADED here (honest status F2/F4): vectors/partition/consume_partition_cases.json is UNRELATED
 * to any Approval API surface -- it is a REQ-103 policy-conformance behavioral-transcript corpus
 * graded by scripts/partition_case.py (a classifier over {tier, ledger_reachable, consumer_action}
 * transcripts), not a ConsumeForkEvidence byte-format vector. There is no ConsumeForkEvidence content
 * anywhere in that file; treating it as fork-evidence vectors (as an early reading of the launch spec
 * suggested) would be building a test against a corpus that names no surface this port implements.
 */

// ---- balanced-brace / regex JSON access (string-aware; mirrors ProducingBoundaryKatTest.kt) --------

private class KatFailure(msg: String) : RuntimeException(msg)

private var katFails = 0

private fun katOk(name: String) = println("  ok   $name")

private fun katFail(name: String, detail: String) {
    katFails++
    println("  FAIL $name\n       $detail")
}

private fun katCheck(name: String, got: String, want: String) {
    if (got == want) katOk(name) else katFail(name, "got  $got\n       want $want")
}

private fun katCheckBool(name: String, got: Boolean, want: Boolean) {
    if (got == want) katOk(name) else katFail(name, "got $got want $want")
}

/** Run [block]; require it throws a [NaalpException] whose kind == [wantKind]. */
private fun katExpectThrows(name: String, wantKind: String, block: () -> Unit) {
    try {
        block()
        katFail(name, "expected $wantKind, no exception thrown")
    } catch (e: NaalpException) {
        katCheck(name, e.kind, wantKind)
    }
}

/** Run [block]; require it does NOT throw. */
private fun katExpectOk(name: String, block: () -> Unit) {
    try {
        block()
        katOk(name)
    } catch (e: NaalpException) {
        katFail(name, "expected no error, got ${e.kind}: ${e.message}")
    }
}

private fun objectField(s: String, key: String): String? {
    val idx = s.indexOf("\"$key\"")
    if (idx < 0) return null
    val after = s.substring(idx)
    val colon = after.indexOf(':')
    if (colon < 0) return null
    val rest = after.substring(colon + 1).trimStart()
    if (rest.startsWith("null")) return null
    if (!rest.startsWith("{")) return null
    var depth = 0
    var inString = false
    var escape = false
    for (i in rest.indices) {
        val c = rest[i]
        if (inString) {
            when {
                escape -> escape = false
                c == '\\' -> escape = true
                c == '"' -> inString = false
            }
            continue
        }
        when (c) {
            '"' -> inString = true
            '{' -> depth++
            '}' -> {
                depth--
                if (depth == 0) return rest.substring(0, i + 1)
            }
        }
    }
    return null
}

private fun arrayField(s: String, key: String): List<String> {
    val idx = s.indexOf("\"$key\"")
    if (idx < 0) return emptyList()
    val after = s.substring(idx)
    val colon = after.indexOf(':')
    if (colon < 0) return emptyList()
    val rest = after.substring(colon + 1).trimStart()
    if (!rest.startsWith("[")) return emptyList()
    var depth = 0
    var inString = false
    var escape = false
    var end = -1
    for (i in rest.indices) {
        val c = rest[i]
        if (inString) {
            when {
                escape -> escape = false
                c == '\\' -> escape = true
                c == '"' -> inString = false
            }
            continue
        }
        when (c) {
            '"' -> inString = true
            '[' -> depth++
            ']' -> {
                depth--
                if (depth == 0) end = i
            }
        }
        if (end >= 0) break
    }
    if (end < 0) return emptyList()
    return splitJsonObjects(rest.substring(1, end))
}

private fun splitJsonObjects(body: String): List<String> {
    val out = ArrayList<String>()
    var depth = 0
    var start = -1
    var inString = false
    var escape = false
    for (i in body.indices) {
        val c = body[i]
        if (inString) {
            when {
                escape -> escape = false
                c == '\\' -> escape = true
                c == '"' -> inString = false
            }
            continue
        }
        when (c) {
            '"' -> inString = true
            '{' -> {
                if (depth == 0) start = i
                depth++
            }
            '}' -> {
                depth--
                if (depth == 0 && start >= 0) {
                    out.add(body.substring(start, i + 1))
                    start = -1
                }
            }
        }
    }
    return out
}

private fun nullableField(s: String, key: String): String? {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(null|\"[^\"]*\"|-?[0-9]+)").find(s) ?: return null
    val raw = m.groupValues[1]
    if (raw == "null") return null
    return if (raw.startsWith("\"")) raw.substring(1, raw.length - 1) else raw
}

private fun strField(s: String, key: String): String =
    nullableField(s, key) ?: throw KatFailure("string key not found: $key")

private fun hexField(s: String, key: String): ByteArray = Hex.decode(strField(s, key))

/** Parses the FULL uint64 range (0..2^64-1) into the identical bit pattern Cbor.U carries. */
private fun u64Field(s: String, key: String): Long =
    java.lang.Long.parseUnsignedLong(nullableField(s, key) ?: throw KatFailure("uint key not found: $key"))

private fun findVector(rel: String): File {
    var d: File? = File(".").absoluteFile
    repeat(8) {
        val cur = d ?: throw KatFailure("$rel not found")
        val p = File(cur, rel)
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw KatFailure("$rel not found from ${File(".").absolutePath}")
}

// ---- shared crypto fixtures ---------------------------------------------------------------------

private const val ALG = Cose.ALG_MLDSA65

private fun seedOf(b: Int): ByteArray = ByteArray(32) { b.toByte() }
private fun pubOf(seed: ByteArray): ByteArray = Cose.mldsaKeygen("ML-DSA-65", seed)

/** Builds a ledger-id-hex -> (alg, pubkey) resolver, matching the Go test helper resolverFor. */
private fun resolverFor(pairs: Map<String, kotlin.Pair<Int, ByteArray>>): (ByteArray) -> kotlin.Pair<Int, ByteArray>? =
    { id -> pairs[Hex.encode(id)] }

private fun receiptFromJson(rj: String): Approval.ConsumeReceipt =
    Approval.ConsumeReceipt(hexField(rj, "ledger_hex"), hexField(rj, "approval_id_hex"), u64Field(rj, "position"))

/** True IFF [needle] occurs as a contiguous byte subsequence of [haystack] (mirrors Go bytes.Contains
 *  exactly -- a hex-string substring check is NOT reliable at odd byte offsets). */
private fun bytesContains(haystack: ByteArray, needle: ByteArray): Boolean {
    if (needle.isEmpty()) return true
    outer@ for (i in 0..haystack.size - needle.size) {
        for (j in needle.indices) {
            if (haystack[i + j] != needle[j]) continue@outer
        }
        return true
    }
    return false
}

// ==== consume_receipt corpus ========================================================================

private fun consumeReceiptRun() {
    val json = findVector("vectors/consume_receipt/cases.json").readText(Charsets.UTF_8)
    val ledgersSec = objectField(json, "ledgers") ?: throw KatFailure("ledgers section missing")
    val approvalsSec = objectField(json, "approvals") ?: throw KatFailure("approvals section missing")
    val ledgerAId = hexField(ledgersSec, "a_hex")
    val ledgerBId = hexField(ledgersSec, "b_hex")
    val approvalX = hexField(approvalsSec, "x_hex")

    val base = objectField(json, "base") ?: throw KatFailure("base missing")
    val sequence = arrayField(json, "sequence")
    val forks = arrayField(json, "forks")

    // 1. TestConsumeReceiptBytesMatchOracle -- every receipt body (base + sequence + fork legs) ==
    //    the independent oracle.
    val all = ArrayList<String>()
    all.add(base)
    all.addAll(sequence)
    for (f in forks) {
        objectField(f, "a")?.let { all.add(it) }
        objectField(f, "b")?.let { all.add(it) }
    }
    for (rj in all) {
        val got = Hex.encode(receiptFromJson(rj).bytes())
        katCheck("receipt body == oracle (${strField(rj, "ledger_hex").take(8)}..)", got, strField(rj, "body_hex"))
    }

    // 2. TestConsumeReceiptSignVerify -- a ledger-signed receipt verifies under the ledger key; an
    //    unnamed ordering authority, a tampered signature, and the wrong ledger key are each rejected
    //    fail-closed.
    run {
        val signerSeed = seedOf(0x51)
        val signerPk = pubOf(signerSeed)
        val r = receiptFromJson(base)
        val sig = Approval.signConsumeReceipt(r, ALG, signerSeed)
        katExpectOk("valid ledger-signed receipt verifies") { Approval.verifyConsumeReceipt(r, ALG, signerPk, sig) }
        val unnamed = Approval.ConsumeReceipt(ByteArray(0), r.approvalId, r.position)
        katExpectThrows("unnamed-ledger receipt rejected", "ConsumeReceiptUnsigned") {
            Approval.verifyConsumeReceipt(unnamed, ALG, signerPk, sig)
        }
        val bad = sig.copyOf(); bad[bad.size - 1] = (bad[bad.size - 1].toInt() xor 1).toByte()
        katExpectThrows("tampered signature rejected", "ConsumeReceiptUnsigned") {
            Approval.verifyConsumeReceipt(r, ALG, signerPk, bad)
        }
        val otherPk = pubOf(seedOf(0x52))
        katExpectThrows("wrong ledger key rejected", "ConsumeReceiptUnsigned") {
            Approval.verifyConsumeReceipt(r, ALG, otherPk, sig)
        }
    }

    // 3. TestConsumeForkDetected (case a) -- two ledger-signed receipts for the SAME approval id with
    //    DIFFERENT positions are detected as a fork; the surfaced evidence carries BOTH positions and
    //    verifies as a non-repudiable double-spend proof; a byte-identical re-emission is benign.
    run {
        val fk = forks.firstOrNull { strField(it, "name") == "same_ledger_diff_position" }
            ?: throw KatFailure("same_ledger_diff_position case missing from oracle")
        katCheck("oracle marks same_ledger_diff_position as fork", strField(fk, "expect"), "fork")
        val seed = seedOf(0x41); val pk = pubOf(seed) // one ledger signs both conflicting positions
        val aj = objectField(fk, "a")!!; val bj = objectField(fk, "b")!!
        val rA = receiptFromJson(aj); val rB = receiptFromJson(bj)
        val sigA = Approval.signConsumeReceipt(rA, ALG, seed)
        val sigB = Approval.signConsumeReceipt(rB, ALG, seed)
        val resolve = resolverFor(mapOf(Hex.encode(rA.ledger) to (ALG to pk)))
        val rs = Approval.newReceiptSet(resolve)
        val fe0 = rs.observe(rA, sigA)
        if (fe0 != null) katFail("first receipt not flagged", "got fork evidence on first sighting")
        else katOk("first receipt not flagged")
        val fe = rs.observe(rB, sigB)
        if (fe == null) katFail("fork detected on same id/different positions", "observe returned null (no fork)")
        else katOk("fork detected on same id/different positions")
        if (fe != null) {
            katCheckBool("fork evidence surfaces the position conflict", fe.a.position != fe.b.position, true)
            katExpectOk("fork evidence verifies as non-repudiable") { fe.verify(resolve) }
        }
        // benign byte-identical re-emission is never flagged.
        val rs2 = Approval.newReceiptSet(resolve)
        rs2.observe(rA, sigA)
        val fe2 = rs2.observe(rA, sigA)
        if (fe2 != null) katFail("benign duplicate not flagged", "got fork evidence on identical re-emission")
        else katOk("benign duplicate not flagged")
    }

    // 4. TestConsumeForkCrossLedger (case b) -- two INDEPENDENT ledgers, run concurrently, each
    //    consume approval X on its own signed ledger; each succeeds locally, and comparing the two
    //    signed receipts surfaces a provable contradiction.
    run {
        val seedA = seedOf(0x41); val pkA = pubOf(seedA)
        val seedB = seedOf(0x42); val pkB = pubOf(seedB)
        val walA = File.createTempFile("naalp-cr-a", ".wal").also { it.deleteOnExit() }; walA.delete()
        val walB = File.createTempFile("naalp-cr-b", ".wal").also { it.deleteOnExit() }; walB.delete()
        val lA = Approval.openLedgerSigned(walA.absolutePath, ledgerAId, ALG, seedA)
        val lB = Approval.openLedgerSigned(walB.absolutePath, ledgerBId, ALG, seedB)
        val results = java.util.concurrent.ConcurrentLinkedQueue<kotlin.Pair<Approval.ConsumeReceipt, ByteArray>>()
        val errors = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
        val threads = listOf(lA, lB).map { l ->
            thread(start = false) {
                try {
                    val (_, r, sig) = l.consumeWithReceipt(approvalX, "requester")
                    results.add(kotlin.Pair(r, sig))
                } catch (e: Throwable) {
                    errors.add(e)
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        lA.close(); lB.close()
        if (errors.isNotEmpty()) katFail("independent ledger consume", "unexpected error: ${errors.first()}")
        else katOk("independent ledger consume (both succeeded)")
        val resolve = resolverFor(mapOf(Hex.encode(ledgerAId) to (ALG to pkA), Hex.encode(ledgerBId) to (ALG to pkB)))
        val rs = Approval.newReceiptSet(resolve)
        var forkEvidence: Approval.ConsumeForkEvidence? = null
        for ((r, sig) in results) {
            val fe = rs.observe(r, sig)
            if (fe != null) forkEvidence = fe
        }
        if (forkEvidence == null) katFail("cross-ledger double spend detected", "no fork surfaced")
        else {
            katOk("cross-ledger double spend detected")
            katCheckBool("cross-ledger fork names two distinct ledgers", forkEvidence.a.ledger.contentEquals(forkEvidence.b.ledger), false)
            katExpectOk("cross-ledger fork evidence verifies") { forkEvidence.verify(resolve) }
        }
    }

    // 5. TestConsumeFirstAppendWinsCAS -- the compare-and-set MUTATION ANCHOR. On ONE honest signed
    //    ledger, consuming the same approval id twice must yield exactly ONE ledger-signed receipt: the
    //    first consume returns a receipt at position 0, the second returns AlreadyConsumed and signs
    //    nothing. Feeding the emitted receipt into a fork detector finds NO fork.
    run {
        val seed = seedOf(0x41); val pk = pubOf(seed)
        val wal = File.createTempFile("naalp-cr-cas", ".wal").also { it.deleteOnExit() }; wal.delete()
        val l = Approval.openLedgerSigned(wal.absolutePath, ledgerAId, ALG, seed)
        val resolve = resolverFor(mapOf(Hex.encode(ledgerAId) to (ALG to pk)))
        val rs = Approval.newReceiptSet(resolve)

        val (e, r1, sig1) = l.consumeWithReceipt(approvalX, "requester")
        katCheck("first receipt position", "${e.seq}/${r1.position}", "0/0")
        val fe0 = rs.observe(r1, sig1)
        if (fe0 != null) katFail("first receipt not flagged", "got fork evidence") else katOk("first receipt not flagged")

        // *** mutation anchor: the assertion below flips if the CAS in consumeWithReceipt is
        // *** disabled (a second consume would succeed and mint a second receipt at position 1).
        katExpectThrows(
            "second consumeWithReceipt of the same approval id is rejected AlreadyConsumed (first-append-wins)",
            "AlreadyConsumed",
        ) { l.consumeWithReceipt(approvalX, "requester") }
        katCheck("ledger has exactly one entry after the rejected second consume", l.len().toString(), "1")
        l.close()
    }

    // 6. TestConsumeReceiptExactlyOnceUnderRace -- N goroutines/threads call consumeWithReceipt for the
    //    same approval id concurrently on ONE signed ledger; exactly one wins and mints exactly one
    //    receipt, the rest get AlreadyConsumed, and the fork detector sees no fork from the winner.
    run {
        val seed = seedOf(0x41); val pk = pubOf(seed)
        val wal = File.createTempFile("naalp-cr-race", ".wal").also { it.deleteOnExit() }; wal.delete()
        val l = Approval.openLedgerSigned(wal.absolutePath, ledgerAId, ALG, seed)
        val n = 64
        val wins = java.util.concurrent.atomic.AtomicInteger(0)
        val already = java.util.concurrent.atomic.AtomicInteger(0)
        val winner = java.util.concurrent.ConcurrentLinkedQueue<kotlin.Pair<Approval.ConsumeReceipt, ByteArray>>()
        val start = java.util.concurrent.CountDownLatch(1)
        val threads = (0 until n).map {
            thread(start = false) {
                start.await()
                try {
                    val (_, r, sig) = l.consumeWithReceipt(approvalX, "requester")
                    wins.incrementAndGet()
                    winner.add(kotlin.Pair(r, sig))
                } catch (e: NaalpException) {
                    if (e.kind == "AlreadyConsumed") already.incrementAndGet() else throw e
                }
            }
        }
        threads.forEach { it.start() }
        start.countDown()
        threads.forEach { it.join() }
        katCheck("race: exactly one consumer wins", wins.get().toString(), "1")
        katCheck("race: every other consumer got AlreadyConsumed", already.get().toString(), (n - 1).toString())
        val resolve = resolverFor(mapOf(Hex.encode(ledgerAId) to (ALG to pk)))
        val rs = Approval.newReceiptSet(resolve)
        val (wr, wsig) = winner.first()
        val fe = rs.observe(wr, wsig)
        if (fe != null) katFail("sole winning receipt not flagged", "got fork evidence") else katOk("sole winning receipt not flagged")
        l.close()
    }

    // 7. TestConsumeReceiptWireCases -- keys out of order (rejected NonCanonical before any receipt
    //    rule), position too large for a normal int (64-bit uint round-trip), and empty-value vs
    //    absent-value (empty != absent; empty ledger id is verify-rejected fail-closed).
    run {
        val wire = objectField(json, "wire") ?: throw KatFailure("wire section missing")
        val koo = objectField(wire, "keys_out_of_order") ?: throw KatFailure("keys_out_of_order missing")
        val noncanon = hexField(koo, "payload_hex")
        try {
            Cbor.decode(noncanon)
            katFail("non-canonical (keys 3,2,1) receipt body rejected", "decoded without error")
        } catch (e: NaalpException) {
            katCheck("non-canonical (keys 3,2,1) receipt body rejected", e.kind, "NonCanonical")
        }
        katExpectOk("canonical variant of the same receipt decodes cleanly") { Cbor.decode(hexField(koo, "canonical_payload_hex")) }

        val ledgerX = hexField(base, "ledger_hex")
        val approvalXHex = hexField(base, "approval_id_hex")
        for (big in arrayField(wire, "position_too_large")) {
            val pos = u64Field(big, "position")
            val r = Approval.ConsumeReceipt(ledgerX, approvalXHex, pos)
            katCheck("${strField(big, "name")} encode == oracle", Hex.encode(r.bytes()), strField(big, "body_hex"))
            val v = Cbor.decode(hexField(big, "body_hex"))
            if (v !is Cbor.M) throw KatFailure("${strField(big, "name")}: decoded value is not a map")
            var found = false
            var decodedPos = 0L
            for (p in v.pairs) {
                val k = p.k
                if (k is Cbor.U && k.v == 3L) {
                    val u = p.v as? Cbor.U ?: throw KatFailure("${strField(big, "name")}: position not a uint")
                    decodedPos = u.v
                    found = true
                }
            }
            katCheckBool("${strField(big, "name")} decode found position field", found, true)
            katCheck("${strField(big, "name")} position round-trip", decodedPos.toString(), pos.toString())
        }

        val emptyLedger = objectField(wire, "empty_ledger") ?: throw KatFailure("empty_ledger missing")
        val emptyR = Approval.ConsumeReceipt(ByteArray(0), hexField(emptyLedger, "approval_id_hex"), u64Field(emptyLedger, "position"))
        katCheck("empty-ledger body == oracle", Hex.encode(emptyR.bytes()), strField(emptyLedger, "body_hex"))
        katExpectThrows("empty-ledger receipt verify-rejected", strField(emptyLedger, "expect_verify")) {
            // a zero-filled dummy sig -- the empty ledger id is rejected BEFORE any signature check runs
            Approval.verifyConsumeReceipt(emptyR, ALG, pubOf(seedOf(0x41)), ByteArray(64))
        }
        val absentLedger = objectField(wire, "absent_ledger") ?: throw KatFailure("absent_ledger missing")
        katCheckBool(
            "empty-ledger and absent-ledger receipts encode to distinct bytes",
            strField(emptyLedger, "body_hex") == strField(absentLedger, "body_hex"),
            false,
        )
    }
}

// ==== trust_decision corpus (audience + refusal) ====================================================

private fun trustDecisionRun() {
    val json = findVector("vectors/trust_decision/cases.json").readText(Charsets.UTF_8)

    // ---- R-TDCS-5 audience ----
    run {
        val aSec = objectField(json, "audience") ?: throw KatFailure("audience section missing")
        val approvesHex = strField(aSec, "approves_hex")
        val approver = strField(aSec, "approver")
        val grant = u64Field(aSec, "grant")
        val nonceHex = strField(aSec, "nonce_hex")
        val notAfter = u64Field(aSec, "not_after")
        val useMatch = strField(aSec, "use_context_match")
        val useMismatch = strField(aSec, "use_context_mismatch")

        for (tc in arrayField(aSec, "cases")) {
            val name = strField(tc, "name")
            val audience = nullableField(tc, "audience") ?: ""
            val rec = Approval.ApprovalRecord(Hex.decode(approvesHex), approver, grant, Hex.decode(nonceHex), notAfter, audience)
            katCheck("$name approval bytes == oracle", Hex.encode(rec.bytes()), strField(tc, "record_hex"))
            katCheck("$name approval id == oracle", Hex.encode(rec.id()), strField(tc, "approval_id_hex"))
        }

        val present = Approval.ApprovalRecord(Hex.decode(approvesHex), approver, grant, Hex.decode(nonceHex), notAfter, useMatch)
        val absent = Approval.ApprovalRecord(Hex.decode(approvesHex), approver, grant, Hex.decode(nonceHex), notAfter)
        katCheckBool("naming an audience changes the approval bytes", present.bytes().contentEquals(absent.bytes()), false)

        katExpectOk("matching audience verifies") { Approval.verifyAudience(present, useMatch) }
        katExpectThrows("mismatched audience rejected", "AudienceMismatch") { Approval.verifyAudience(present, useMismatch) }
        katExpectOk("absent audience passes any context") { Approval.verifyAudience(absent, useMismatch) }
    }

    // ---- R-TDCS-3 refusal ----
    run {
        val rSec = objectField(json, "refusal") ?: throw KatFailure("refusal section missing")
        val fullRecord = hexField(rSec, "full_record_hex")
        val recordId = hexField(rSec, "full_record_id_hex")
        val reason = strField(rSec, "leaked_reason").toByteArray(Charsets.UTF_8)

        for (tc in arrayField(rSec, "cases")) {
            val name = strField(tc, "name")
            val outcome = u64Field(tc, "outcome")
            val ref = Approval.refusalFromRecord(outcome, fullRecord)
            val b = ref.bytes()
            katCheck("$name refusal bytes == oracle", Hex.encode(b), strField(tc, "record_hex"))
            katCheckBool("$name refusal does not leak the reason", bytesContains(b, reason), false)
            katCheckBool("$name refusal carries the full-record content id", bytesContains(b, recordId), true)
            val got = Approval.parseRefusal(b)
            katCheck("$name round-trip outcome", got.outcome.toString(), outcome.toString())
            katCheckBool("$name round-trip record id", got.record.contentEquals(recordId), true)
        }

        val reject = objectField(rSec, "reject") ?: throw KatFailure("refusal.reject missing")
        katExpectThrows("unknown refusal outcome rejected", "UnknownRefusalOutcome") {
            Approval.parseRefusal(hexField(reject, "unknown_outcome_hex"))
        }
        katExpectThrows("extra field (leaked detail) rejected", "RefusalDetailLeak") {
            Approval.parseRefusal(hexField(reject, "detail_leak_extra_field_hex"))
        }
        katExpectThrows("missing record id rejected", "RefusalDetailLeak") {
            Approval.parseRefusal(hexField(reject, "missing_record_hex"))
        }
        katExpectThrows("empty record id rejected", "RefusalDetailLeak") {
            Approval.parseRefusal(hexField(reject, "empty_record_hex"))
        }

        // sanity: the closed set is exactly {0,1,2}; nothing else.
        katCheckBool("isKnownRefusalOutcome(0) denied", Approval.isKnownRefusalOutcome(0), true)
        katCheckBool("isKnownRefusalOutcome(1) held", Approval.isKnownRefusalOutcome(1), true)
        katCheckBool("isKnownRefusalOutcome(2) unverifiable", Approval.isKnownRefusalOutcome(2), true)
        katCheckBool("isKnownRefusalOutcome(3) outside closed set", Approval.isKnownRefusalOutcome(3), false)
    }
}

// ==== R-TDCS-4 freshness independence (ISOLATION, self-contained -- no vector, mirrors Go tdcs_test.go) ==

private fun freshnessIndependenceRun() {
    val approverSeed = seedOf(0x11); val approverPk = pubOf(approverSeed) // the approver's key (the authenticated party)
    val ledgerSeed = seedOf(0x22); val ledgerPk = pubOf(ledgerSeed) // the ordering authority (ledger) -- a DISTINCT key
    val argsId = "the-exact-canonical-args-content-id".toByteArray(Charsets.UTF_8)
    val approverId = "approver-authenticated-party-id".toByteArray(Charsets.UTF_8)
    val ledgerId = "ordering-authority-ledger-id".toByteArray(Charsets.UTF_8)

    val a = Approval.ApprovalRecord(argsId, "approver-authenticated-party-id", 1, "anti-replay-nonce".toByteArray(Charsets.UTF_8), 1000)
    val aSig = Approval.signApproval(a, ALG, approverSeed)
    val r = Approval.ConsumeReceipt(ledgerId, a.id(), 7)
    val rSig = Approval.signConsumeReceipt(r, ALG, ledgerSeed)
    val posTime = 1000L

    // distinct ordering authority (party != ledger): verifies.
    katExpectOk("distinct ordering authority verifies") {
        Approval.verifyFreshIndependent(a, ALG, approverPk, aSig, argsId, posTime, r, ALG, ledgerPk, rSig, approverId)
    }
    // self-asserted freshness (party == ledger): rejected.
    katExpectThrows("self-asserted freshness (party == ordering authority) rejected", "FreshnessSelfAsserted") {
        Approval.verifyFreshIndependent(a, ALG, approverPk, aSig, argsId, posTime, r, ALG, ledgerPk, rSig, ledgerId)
    }
    // the distinctness check does not weaken the underlying checks: expiry still enforced.
    katExpectThrows("expired approval still rejected under a distinct authority", "ApprovalExpired") {
        Approval.verifyFreshIndependent(a, ALG, approverPk, aSig, argsId, a.notAfter + 1, r, ALG, ledgerPk, rSig, approverId)
    }
    // a receipt with no named ordering authority is not evidence, even with a distinct party id.
    val throwawaySeed = seedOf(0x33)
    val emptyReceipt = Approval.ConsumeReceipt(ByteArray(0), a.id(), 7)
    val emptySig = Approval.signConsumeReceipt(emptyReceipt, ALG, throwawaySeed)
    katExpectThrows("unnamed ordering authority not accepted as freshness evidence", "ConsumeReceiptUnsigned") {
        Approval.verifyFreshIndependent(a, ALG, approverPk, aSig, argsId, posTime, emptyReceipt, ALG, ledgerPk, emptySig, approverId)
    }
}

// ==== Ledger.len() alias (port extra) ================================================================

private fun ledgerLenAliasRun() {
    val wal = File.createTempFile("naalp-cr-len", ".wal").also { it.deleteOnExit() }; wal.delete()
    val l = Approval.openLedger(wal.absolutePath)
    katCheck("len() alias matches size() (empty)", l.len().toString(), l.size().toString())
    l.consume(byteArrayOf(1, 2, 3), "someone")
    katCheck("len() alias matches size() (after one consume)", l.len().toString(), l.size().toString())
    katCheck("len() alias returns 1", l.len().toString(), "1")
    l.close()
}

fun main() {
    println("ApprovalKatTest (Kotlin) — T1.5 consume receipt + fork evidence + R-TDCS audience/refusal/freshness")
    consumeReceiptRun()
    trustDecisionRun()
    freshnessIndependenceRun()
    ledgerLenAliasRun()
    println(if (katFails == 0) "ApprovalKatTest: PASS" else "ApprovalKatTest: FAIL ($katFails)")
    if (katFails != 0) kotlin.system.exitProcess(1)
}
