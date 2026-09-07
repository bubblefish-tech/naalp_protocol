// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import java.security.MessageDigest
import kotlin.concurrent.thread
import kotlin.system.exitProcess

//
// C6 approval known-answer test for the Kotlin SDK (design.md §7; R-7.1..7.4), graded against the
// shared independent corpus vectors/approval/cases.json (NOT produced by this code).
//
// CORPUS-GRADED (pure): the approval record body + content id for each approval; the durable
// hash-chained consume ledger — the genesis head, each winning entry body, its head_after and the
// running chain head, the final head — and the single-use compare-and-set (the third consume of an
// already-consumed id is rejected AlreadyConsumed with no append). ISOLATION (real FIPS-204
// ML-DSA-65 via BouncyCastle — Kotlin is a full-signature port; the corpus carries no signature
// vector, so these are demonstrated with a fixed local seed, stated honestly, NOT corpus-graded): a
// signed approval verifies; a wrong args-content-id is ApprovalMismatch; an expired posTime is
// ApprovalExpired; a garbage/empty signature is BadSignature (fail-closed); the WAL replays across a
// close/reopen so the consumed set and head survive (durability); and, under a concurrent race on
// one id, exactly one consumer wins and every other gets AlreadyConsumed (the single-use guarantee).
//
// KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
// "Tests" token the ten-language-parity gate indexes. Written test-first: [Approval] is absent until
// Approval.kt lands, so this fails RED with a kotlinc "unresolved reference: Approval". The
// load-bearing mutation — the consume membership check made to always-miss (consume always succeeds)
// — flips "ledger third consume rejected AlreadyConsumed (single-use)" on its assertion.
//

private var apFails = 0

private fun apCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        apFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- balanced-brace / regex JSON access (no JSON library on the Kotlin port) ----

private fun apFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/approval/cases.json not found")
        val p = File(File(cur, "vectors"), "approval/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/approval/cases.json not found from ${File(".").absolutePath}")
}

private fun apSection(scope: String, key: String): String {
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

private fun apElements(arraySection: String): List<String> {
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

private fun apStr(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun apInt(scope: String, key: String): Long {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun apHex(s: String): ByteArray = Hex.decode(s)

private const val AP_ALG = Cose.ALG_MLDSA65
private val AP_SEED = ByteArray(32)
private val AP_PK = Cose.mldsaKeygen("ML-DSA-65", ByteArray(32))

private inline fun apKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

private fun apRecord(block: String): Approval.ApprovalRecord =
    Approval.ApprovalRecord(
        apHex(apStr(block, "approves_hex")),
        apStr(block, "approver"),
        apInt(block, "grant"),
        apHex(apStr(block, "nonce_hex")),
        apInt(block, "not_after"),
    )

private fun approvalRun() {
    val json = apFindVector().readText(Charsets.UTF_8)

    // 1. each approval's record body + content id == the oracle.
    val approvals = apElements(apSection(json, "approvals"))
    for (ab in approvals) {
        val name = apStr(ab, "name")
        val r = apRecord(ab)
        apCheck("approval $name record body == oracle", Hex.encode(r.bytes()), apStr(ab, "record_hex"))
        apCheck("approval $name content id == oracle", Hex.encode(r.id()), apStr(ab, "approval_id_hex"))
    }

    // 2. the durable hash-chained single-use consume ledger: genesis head, each winning entry body +
    //    head_after + running head, the third consume rejected AlreadyConsumed, and the final head.
    val ledgerSec = apSection(json, "ledger")
    val wal = File.createTempFile("naalp-approval-kat", ".wal").also { it.deleteOnExit() }
    wal.delete() // openLedger creates it; start from an empty log
    val ledger = Approval.openLedger(wal.absolutePath)
    apCheck("genesis head is 48 zeros == oracle", Hex.encode(ledger.head()), apStr(ledgerSec, "genesis_head_hex"))
    for (cb in apElements(apSection(ledgerSec, "consumes"))) {
        val aid = apHex(apStr(cb, "approval_id_hex"))
        val by = apStr(cb, "by")
        val expect = apStr(cb, "expect")
        if (expect == "ok") {
            val e = ledger.consume(aid, by)
            apCheck("ledger consume seq=${apInt(cb, "seq")} entry body == oracle", Hex.encode(e.bytes()), apStr(cb, "entry_hex"))
            apCheck("ledger consume seq=${apInt(cb, "seq")} seq == oracle", e.seq.toString(), apInt(cb, "seq").toString())
            apCheck("ledger head after seq=${apInt(cb, "seq")} == oracle", Hex.encode(ledger.head()), apStr(cb, "head_after_hex"))
        } else {
            // the third consume names an already-consumed id; single-use rejects it, appends nothing.
            val before = ledger.size()
            apCheck("ledger third consume rejected AlreadyConsumed (single-use)", apKind { ledger.consume(aid, by) }, expect)
            apCheck("rejected consume made no append", ledger.size().toString(), before.toString())
        }
    }
    apCheck("ledger final head == oracle", Hex.encode(ledger.head()), apStr(ledgerSec, "final_head_hex"))

    // 3. durability (ISOLATION): close + reopen replays the WAL; the consumed set and head survive,
    //    and a re-consume of a spent id is still AlreadyConsumed.
    val firstId = apHex(apStr(approvals[0], "approval_id_hex"))
    val secondId = apHex(apStr(approvals[1], "approval_id_hex"))
    ledger.close()
    val reopened = Approval.openLedger(wal.absolutePath)
    apCheck("replay: consumed set survives (2 ids)", reopened.size().toString(), "2")
    apCheck("replay: id A still consumed", reopened.isConsumed(firstId).toString(), "true")
    apCheck("replay: id B still consumed", reopened.isConsumed(secondId).toString(), "true")
    apCheck("replay: head survives == final head", Hex.encode(reopened.head()), apStr(ledgerSec, "final_head_hex"))
    apCheck("replay: re-consume spent id A is AlreadyConsumed", apKind { reopened.consume(firstId, "someone") }, "AlreadyConsumed")
    reopened.close()

    // 4. verifyApproval (ISOLATION, real ML-DSA): a signed approval verifies; a wrong args-content-id
    //    is ApprovalMismatch; an expired posTime is ApprovalExpired; a garbage signature is BadSignature.
    val a0 = apRecord(approvals[0])
    val argsId = apHex(apStr(apSection(json, "args"), "content_id_hex"))
    val expiry = apSection(json, "expiry")
    val validAt = apInt(expiry, "valid_at")
    val expiredAt = apInt(expiry, "expired_at")
    val sig = Approval.signApproval(a0, AP_ALG, AP_SEED)
    apCheck("valid approval verifies at valid_at", apKind { Approval.verifyApproval(a0, AP_ALG, AP_PK, sig, argsId, validAt) }, "no-error")
    val wrongArgs = apHex(apStr(apSection(json, "mismatch"), "wrong_args_id_hex"))
    apCheck("wrong args id rejected ApprovalMismatch", apKind { Approval.verifyApproval(a0, AP_ALG, AP_PK, sig, wrongArgs, validAt) }, "ApprovalMismatch")
    apCheck("expired posTime rejected ApprovalExpired", apKind { Approval.verifyApproval(a0, AP_ALG, AP_PK, sig, argsId, expiredAt) }, "ApprovalExpired")
    // fail-closed on an empty/garbage signature: BadSignature, never a crash or a silent pass.
    apCheck("empty signature rejected BadSignature (fail-closed)", apKind { Approval.verifyApproval(a0, AP_ALG, AP_PK, ByteArray(0), argsId, validAt) }, "BadSignature")
    val tampered = sig.copyOf(); tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte()
    apCheck("tampered signature rejected BadSignature", apKind { Approval.verifyApproval(a0, AP_ALG, AP_PK, tampered, argsId, validAt) }, "BadSignature")

    // 5. a held (not-yet-granted) outcome is itself a distinct, signed, attributable result (ISOLATION).
    val held = Approval.HeldResult(argsId, "awaiting approver")
    val heldSig = Approval.signHeld(held, AP_ALG, AP_SEED)
    apCheck("held result signature verifies", Cose.mldsaVerify(AP_ALG, AP_PK, held.bytes(), heldSig).toString(), "true")

    // 6. single-use under a concurrent race (ISOLATION): many threads consume ONE fresh id; exactly
    //    one wins, every other gets AlreadyConsumed, and exactly one append lands. Proves the atomic
    //    compare-and-set (one lock-held critical section, no read-then-write TOCTOU).
    run {
        val raceWal = File.createTempFile("naalp-approval-race", ".wal").also { it.deleteOnExit() }
        raceWal.delete()
        val rl = Approval.openLedger(raceWal.absolutePath)
        val raceId = MessageDigest.getInstance("SHA-384").digest("race".toByteArray())
        val n = 64
        val wins = java.util.concurrent.atomic.AtomicInteger(0)
        val already = java.util.concurrent.atomic.AtomicInteger(0)
        val threads = (0 until n).map { i ->
            thread(start = false) {
                try {
                    rl.consume(raceId, "racer-$i")
                    wins.incrementAndGet()
                } catch (e: NaalpException) {
                    if (e.kind == "AlreadyConsumed") already.incrementAndGet()
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        apCheck("race: exactly one consumer wins", wins.get().toString(), "1")
        apCheck("race: every other consumer got AlreadyConsumed", already.get().toString(), (n - 1).toString())
        apCheck("race: exactly one append landed", rl.size().toString(), "1")
        rl.close()
    }
}

// consumeApprovalPrecedenceRun (T20.1, mirrors Go TestConsumeApprovalPrecedence / Rust
// consume_approval_precedence): exercises the composed choke point Approval.consumeApproval's
// precedence -- mismatch over every cell, expiry-over-consume, the effect-ceiling and grant-range
// guards, and bad-signature -- asserting BOTH the returned Kind and the ledger length, so a mutant
// that returns the right Kind but still appends, or one that drops the effect-ceiling check, is
// caught. ISOLATION (real ML-DSA-65, reusing the AP_ALG/AP_SEED/AP_PK keypair above): consumeApproval
// has no dedicated corpus, mirroring the reference tests.
private fun consumeApprovalPrecedenceRun() {
    val argsCid = "args-content-id-A".toByteArray(Charsets.US_ASCII)
    val wrongCid = "args-content-id-B".toByteArray(Charsets.US_ASCII)
    fun mk(grant: Long, notAfter: Long): kotlin.Pair<Approval.ApprovalRecord, ByteArray> {
        val a = Approval.ApprovalRecord(argsCid, "approver-1", grant, byteArrayOf(0x01, 0x02), notAfter)
        return kotlin.Pair(a, Approval.signApproval(a, AP_ALG, AP_SEED))
    }
    fun freshLedger(tag: String): Approval.Ledger {
        val wal = File.createTempFile("naalp-consume-approval-$tag", ".wal").also { it.deleteOnExit() }
        wal.delete()
        return Approval.openLedger(wal.absolutePath)
    }

    // approved + consume -> consumed (len 1); a second consume -> AlreadyConsumed (len stays 1).
    run {
        val (a, sig) = mk(Policy.DESTRUCTIVE, 1000)
        val l = freshLedger("consumed")
        apCheck("consumeApproval: valid consume", apKind { Approval.consumeApproval(a, AP_ALG, AP_PK, sig, argsCid, 500, Policy.READ_ONLY, l, "by") }, "no-error")
        apCheck("consumeApproval: valid consume ledger len", l.size().toString(), "1")
        apCheck("consumeApproval: second consume rejected AlreadyConsumed", apKind { Approval.consumeApproval(a, AP_ALG, AP_PK, sig, argsCid, 500, Policy.READ_ONLY, l, "by") }, "AlreadyConsumed")
        apCheck("consumeApproval: second consume made no append", l.size().toString(), "1")
        l.close()
    }
    // expired + consume -> ApprovalExpired; nothing appended.
    run {
        val (a, sig) = mk(Policy.DESTRUCTIVE, 1000)
        val l = freshLedger("expired")
        apCheck("consumeApproval: expired consume rejected ApprovalExpired", apKind { Approval.consumeApproval(a, AP_ALG, AP_PK, sig, argsCid, 2000, Policy.READ_ONLY, l, "by") }, "ApprovalExpired")
        apCheck("consumeApproval: expired consume made no append", l.size().toString(), "0")
        l.close()
    }
    // expiry over consume: success, then a second past not_after -> ApprovalExpired (never
    // AlreadyConsumed), ledger untouched (len stays 1).
    run {
        val (a, sig) = mk(Policy.DESTRUCTIVE, 1000)
        val l = freshLedger("eoc")
        Approval.consumeApproval(a, AP_ALG, AP_PK, sig, argsCid, 500, Policy.READ_ONLY, l, "by")
        apCheck("consumeApproval: expiry-over-consume rejected ApprovalExpired (not AlreadyConsumed)", apKind { Approval.consumeApproval(a, AP_ALG, AP_PK, sig, argsCid, 2000, Policy.READ_ONLY, l, "by") }, "ApprovalExpired")
        apCheck("consumeApproval: expiry-over-consume ledger len stays 1", l.size().toString(), "1")
        l.close()
    }
    // mismatch over every cell (fresh, and over an also-expired approval); no append.
    run {
        val (a, sig) = mk(Policy.DESTRUCTIVE, 1000)
        val l = freshLedger("mismatch")
        apCheck("consumeApproval: fresh mismatch rejected ApprovalMismatch", apKind { Approval.consumeApproval(a, AP_ALG, AP_PK, sig, wrongCid, 500, Policy.READ_ONLY, l, "by") }, "ApprovalMismatch")
        apCheck("consumeApproval: mismatch precedence over expiry", apKind { Approval.consumeApproval(a, AP_ALG, AP_PK, sig, wrongCid, 2000, Policy.READ_ONLY, l, "by") }, "ApprovalMismatch")
        apCheck("consumeApproval: mismatch made no append", l.size().toString(), "0")
        l.close()
    }
    // a rejected mismatch leaves the ledger clean, so a later valid consume still succeeds.
    run {
        val (a, sig) = mk(Policy.DESTRUCTIVE, 1000)
        val l = freshLedger("reject-then-valid")
        apCheck("consumeApproval: reject-then-valid rejected mismatch", apKind { Approval.consumeApproval(a, AP_ALG, AP_PK, sig, wrongCid, 500, Policy.READ_ONLY, l, "by") }, "ApprovalMismatch")
        apCheck("consumeApproval: reject-then-valid no append after reject", l.size().toString(), "0")
        apCheck("consumeApproval: reject-then-valid later valid consume succeeds", apKind { Approval.consumeApproval(a, AP_ALG, AP_PK, sig, argsCid, 500, Policy.READ_ONLY, l, "by") }, "no-error")
        apCheck("consumeApproval: reject-then-valid len 1", l.size().toString(), "1")
        l.close()
    }
    // effect ceiling: granted effect below the action's required effect -> ApprovalRequired.
    run {
        val (a, sig) = mk(Policy.READ_ONLY, 1000)
        val l = freshLedger("under-grant")
        apCheck("consumeApproval: insufficient grant rejected ApprovalRequired", apKind { Approval.consumeApproval(a, AP_ALG, AP_PK, sig, argsCid, 500, Policy.DESTRUCTIVE, l, "by") }, "ApprovalRequired")
        apCheck("consumeApproval: insufficient grant made no append", l.size().toString(), "0")
        l.close()
    }
    // grant-range guard: a grant outside the closed 0..3 vocabulary authorizes nothing.
    run {
        val (a, sig) = mk(7L, 1000)
        val l = freshLedger("malformed-grant")
        apCheck("consumeApproval: malformed grant rejected ApprovalRequired", apKind { Approval.consumeApproval(a, AP_ALG, AP_PK, sig, argsCid, 500, Policy.READ_ONLY, l, "by") }, "ApprovalRequired")
        apCheck("consumeApproval: malformed grant made no append", l.size().toString(), "0")
        l.close()
    }
    // bad signature (checked first) -> BadSignature.
    run {
        val (a, sig) = mk(Policy.DESTRUCTIVE, 1000)
        val bad = sig.copyOf()
        bad[bad.size - 1] = (bad[bad.size - 1].toInt() xor 1).toByte()
        val l = freshLedger("bad-sig")
        apCheck("consumeApproval: bad signature rejected BadSignature", apKind { Approval.consumeApproval(a, AP_ALG, AP_PK, bad, argsCid, 500, Policy.READ_ONLY, l, "by") }, "BadSignature")
        apCheck("consumeApproval: bad signature made no append", l.size().toString(), "0")
        l.close()
    }
}

fun main() {
    println("approval conformance (Kotlin) — graded vs vectors/approval/cases.json")
    approvalRun()
    consumeApprovalPrecedenceRun()
    println(if (apFails == 0) "ApprovalTests: PASS" else "ApprovalTests: FAIL ($apFails)")
    exitProcess(if (apFails == 0) 0 else 1)
}
