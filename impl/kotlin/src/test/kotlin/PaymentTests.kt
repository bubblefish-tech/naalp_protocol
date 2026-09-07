// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

/**
 * C21 (5B.1) NAALP-PAY payment-import known-answer test for the Kotlin SDK (design.md §24;
 * R-PAY-1..6), graded against the shared independent corpus vectors/payment/cases.json (NOT produced
 * by this code): the closed payment-format registry, the byte-exact PaymentImport body/head/content-id
 * (incl. the oversized >2^53 amount and the minimal import), the foreign-payload content id (carriage
 * binding), the byte-exact ChargeBinding body/head/content-id, the parse round-trip, the fail-closed
 * edge cases (non-canonical -> NonCanonical / PayMalformed, absent mandatory field -> PayMalformed, a
 * bstr-currency look-alike -> PayMalformed, empty vs populated foreign distinct by content-id), and
 * the mismatch content-ids (a wrong amount, wrong payee, or substituted foreign payload yields a
 * DIFFERENT charge content-id, so a §7 approval bound to the original no longer matches).
 *
 * The PaymentImport SIGNATURE is real deterministic ML-DSA-65 via a bare-{1:alg} COSE_Sign1 (Kotlin is
 * a full-signature port); the corpus carries no signed vector for this channel, so sign/verify is
 * demonstrated in isolation only — stated honestly, NOT corpus-graded.
 *
 * STEP-2 parity (section 13, ISOLATION, real ML-DSA): AuthorizeCharge — the per-charge approval gate
 * that composes approval.verifyApproval + policy.authorizes + the §7 single-use consume ledger, ported
 * from impl/go/payment/payment.go:241 — is now built and tested against real keys/ledgers, exactly as
 * the go/rust/python/typescript/ruby/php/csharp/java/swift ports. The payment corpus itself carries no
 * authorize/consume vector, so this surface is demonstrated in isolation (not corpus-graded); the
 * value-bearing binding property it depends on (a wrong amount/payee/currency/substituted-foreign
 * charge yields a DIFFERENT charge content-id) IS corpus-graded in section 11 above and reused here.
 *
 * KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
 * "Tests" token the ten-language-parity gate indexes. Written test-first: [Payment] is absent until
 * Payment.kt lands, so this fails RED with a kotlinc "unresolved reference: Payment". A mutation
 * forcing the ChargeBinding amount field to a constant flips "charge-binding id ap2 == oracle".
 */

private var pyFails = 0

private fun pyCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        pyFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- balanced-brace / regex JSON access (no JSON library on the Kotlin port) ----

private fun pyFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/payment/cases.json not found")
        val p = File(File(cur, "vectors"), "payment/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/payment/cases.json not found from ${File(".").absolutePath}")
}

private fun pySection(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*").find(scope)
        ?: throw AssertionError("key not found: $key")
    var i = m.range.last + 1
    while (i < scope.length && scope[i].isWhitespace()) i++
    val open = scope[i]
    val close = when (open) { '{' -> '}'; '[' -> ']'; else -> throw AssertionError("not object/array at $key") }
    var depth = 0; var inStr = false; var esc = false; val start = i
    while (i < scope.length) {
        val c = scope[i]
        if (inStr) {
            when { esc -> esc = false; c == '\\' -> esc = true; c == '"' -> inStr = false }
        } else {
            when (c) { '"' -> inStr = true; open -> depth++; close -> { depth--; if (depth == 0) return scope.substring(start, i + 1) } }
        }
        i++
    }
    throw AssertionError("unbalanced value at key: $key")
}

private fun pyElements(arraySection: String): List<String> {
    val out = ArrayList<String>(); var i = 1; var inStr = false; var esc = false; var depth = 0; var start = -1
    while (i < arraySection.length - 1) {
        val c = arraySection[i]
        if (inStr) {
            when { esc -> esc = false; c == '\\' -> esc = true; c == '"' -> inStr = false }
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

private fun pyStr(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun pyInt(scope: String, key: String): Long {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun pyHex(s: String): ByteArray = Hex.decode(s)

private const val PY_ALG = Cose.ALG_MLDSA65
private val PY_SEED = ByteArray(32)
private val PY_PK = Cose.mldsaKeygen("ML-DSA-65", ByteArray(32))

// ---- AuthorizeCharge (STEP-2 parity): the approver + a distinct foreign key, seeded exactly as the
// Go authority's key(t, 0x11) / key(t, 0x22) (a 32-byte seed filled with the one byte). ----
private val PAY_APPROVER_SEED = ByteArray(32) { 0x11.toByte() }
private val PAY_APPROVER_PK = Cose.mldsaKeygen("ML-DSA-65", PAY_APPROVER_SEED)
private val PAY_FOREIGN_SEED = ByteArray(32) { 0x22.toByte() }
private val PAY_FOREIGN_PK = Cose.mldsaKeygen("ML-DSA-65", PAY_FOREIGN_SEED)

private inline fun pyKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

/** A PaymentImport from a corpus import block carrying format/amount/currency/payee_hex/not_after/foreign_hex. */
private fun pyImportFrom(iv: String): Payment.PaymentImport = Payment.PaymentImport(
    pyInt(iv, "format"), pyInt(iv, "amount"), pyStr(iv, "currency"),
    pyHex(pyStr(iv, "payee_hex")), pyInt(iv, "not_after"), pyHex(pyStr(iv, "foreign_hex")),
)

/** Build and sign a §7 approval binding a charge content-id at grant [grant] (mirrors Go mkApproval). */
private fun pyMkApproval(chargeCid: ByteArray, approver: String, grant: Long, nonceByte: Byte, notAfter: Long, seed: ByteArray): kotlin.Pair<Approval.ApprovalRecord, ByteArray> {
    val nonce = ByteArray(16) { nonceByte }
    val a = Approval.ApprovalRecord(chargeCid, approver, grant, nonce, notAfter)
    val sig = Approval.signApproval(a, PY_ALG, seed)
    return kotlin.Pair(a, sig)
}

/** A fresh, empty, temp-file-backed consume ledger (mirrors Go freshLedger). */
private fun pyFreshLedger(): Approval.Ledger {
    val wal = File.createTempFile("naalp-payment-kat", ".wal").also { it.deleteOnExit() }
    wal.delete() // openLedger creates it; start from an empty log
    return Approval.openLedger(wal.absolutePath)
}

private fun paymentRun() {
    val json = pyFindVector().readText(Charsets.UTF_8)

    // 1. the closed payment-format registry (design §24).
    for (fv in pyElements(pySection(json, "format_vocabulary"))) {
        val name = pyStr(fv, "name")
        val code = pyInt(fv, "code")
        pyCheck("format $name registered", Payment.isRegisteredFormat(code).toString(), "true")
        pyCheck("format $name name", Payment.formatName(code), name)
    }
    val unknownFormat = pyInt(json, "unknown_format")
    pyCheck("unknown format not registered", Payment.isRegisteredFormat(unknownFormat).toString(), "false")
    pyCheck("unknown format name", Payment.formatName(unknownFormat), "unknown")

    // 2. a payment spend is a non_idempotent_write (the value-bearing rule).
    pyCheck("charge effect == corpus", Payment.CHARGE_EFFECT.toString(), pyInt(json, "charge_effect").toString())
    pyCheck("charge effect == policy NON_IDEMPOTENT_WRITE", Payment.CHARGE_EFFECT.toString(), Policy.NON_IDEMPOTENT_WRITE.toString())

    val imports = pySection(json, "imports")

    // 3. PaymentImport body/head/content-id + foreign-payload content-id == the oracle, byte-for-byte.
    for (name in listOf("ap2", "acp", "x402")) {
        val iv = pySection(imports, name)
        val p = pyImportFrom(iv)
        pyCheck("import body $name == oracle", Hex.encode(p.bytes()), pyStr(iv, "body_hex"))
        pyCheck("import head $name == oracle", Hex.encode(p.head()), pyStr(iv, "head_hex"))
        pyCheck("import id $name == oracle", Hex.encode(p.id()), pyStr(iv, "id_hex"))
        pyCheck("import foreign_id $name == oracle", Hex.encode(p.foreignId()), pyStr(iv, "foreign_id_hex"))
    }

    // 4. the exact charge value a §7 approval binds (the mutation-target assertion).
    for (name in listOf("ap2", "acp", "x402")) {
        val iv = pySection(imports, name)
        val cbv = pySection(iv, "charge_binding")
        val cb = pyImportFrom(iv).chargeBinding()
        pyCheck("charge-binding body $name == oracle", Hex.encode(cb.bytes()), pyStr(cbv, "body_hex"))
        pyCheck("charge-binding head $name == oracle", Hex.encode(cb.head()), pyStr(cbv, "head_hex"))
        pyCheck("charge-binding id $name == oracle", Hex.encode(cb.contentId()), pyStr(cbv, "id_hex"))
    }

    // 5. an oversized amount (>2^53) round-trips byte-exact through the strict decoder.
    run {
        val bv = pySection(json, "big_amount")
        val amount = pyStr(bv, "amount_str").toLong() // 72623859790382856 > 2^53, exact (Long)
        pyCheck("big amount > 2^53", (amount > (1L shl 53)).toString(), "true")
        val p = Payment.PaymentImport(pyInt(bv, "format"), amount, pyStr(bv, "currency"),
            pyHex(pyStr(bv, "payee_hex")), pyInt(bv, "not_after"), pyHex(pyStr(bv, "foreign_hex")))
        pyCheck("big amount body == oracle", Hex.encode(p.bytes()), pyStr(bv, "body_hex"))
        pyCheck("big amount head == oracle", Hex.encode(p.head()), pyStr(bv, "head_hex"))
        pyCheck("big amount id == oracle", Hex.encode(p.id()), pyStr(bv, "id_hex"))
        pyCheck("big amount charge-binding id == oracle", Hex.encode(p.chargeBinding().contentId()), pyStr(pySection(bv, "charge_binding"), "id_hex"))
        val rp = Payment.parsePaymentImport(pyHex(pyStr(bv, "body_hex")))
        pyCheck("big amount parses byte-exact", rp.amount.toString(), amount.toString())
    }

    // 6. the minimal import encodes to the oracle bytes.
    run {
        val m = pySection(json, "minimal")
        val p = pyImportFrom(m)
        pyCheck("minimal body == oracle", Hex.encode(p.bytes()), pyStr(m, "body_hex"))
        pyCheck("minimal head == oracle", Hex.encode(p.head()), pyStr(m, "head_hex"))
        pyCheck("minimal id == oracle", Hex.encode(p.id()), pyStr(m, "id_hex"))
    }

    // 7. parse round-trips each import from its body bytes alone.
    for (name in listOf("ap2", "acp", "x402")) {
        val iv = pySection(imports, name)
        val p = Payment.parsePaymentImport(pyHex(pyStr(iv, "body_hex")))
        pyCheck("parse $name format", p.format.toString(), pyInt(iv, "format").toString())
        pyCheck("parse $name amount", p.amount.toString(), pyInt(iv, "amount").toString())
        pyCheck("parse $name currency", p.currency, pyStr(iv, "currency"))
        pyCheck("parse $name payee", Hex.encode(p.payee), pyStr(iv, "payee_hex"))
        pyCheck("parse $name not_after", p.notAfter.toString(), pyInt(iv, "not_after").toString())
        pyCheck("parse $name foreign", Hex.encode(p.foreign), pyStr(iv, "foreign_hex"))
    }

    val edges = pySection(json, "edge_cases")

    // 8. a non-canonical body is rejected NonCanonical by the decoder and PayMalformed by the parser;
    //    the canonical form of the same content parses.
    run {
        val koo = pySection(edges, "keys_out_of_order")
        // the corpus keys_out_of_order.reject ("NonCanonical") names the STRICT-DECODER verdict; the
        // parser wraps it to its fail-closed PayMalformed (as the go/python/typescript/ruby ports do).
        pyCheck("non-canonical decoder-rejected", pyKind { Cbor.decode(pyHex(pyStr(koo, "noncanonical_body_hex"))) }, pyStr(koo, "reject"))
        pyCheck("non-canonical parser-rejected", pyKind { Payment.parsePaymentImport(pyHex(pyStr(koo, "noncanonical_body_hex"))) }, "PayMalformed")
        val cp = Payment.parsePaymentImport(pyHex(pyStr(koo, "canonical_body_hex")))
        pyCheck("canonical form parses", cp.format.toString(), pyInt(koo, "format").toString())
    }

    // 9. an empty foreign payload is present and valid, distinct by content-id from a populated one;
    //    both differ from a body whose foreign field is ABSENT (rejected — field 6 is mandatory).
    run {
        val ev = pySection(edges, "empty_vs_absent")
        val emptyB = pySection(ev, "empty_foreign")
        val popB = pySection(ev, "populated_foreign")
        val absB = pySection(ev, "absent_field")
        val empty = Payment.parsePaymentImport(pyHex(pyStr(emptyB, "body_hex")))
        pyCheck("empty foreign is empty", Hex.encode(empty.foreign), "")
        pyCheck("empty foreign id == oracle", Hex.encode(empty.id()), pyStr(emptyB, "id_hex"))
        pyCheck("empty foreign_id == oracle", Hex.encode(empty.foreignId()), pyStr(emptyB, "foreign_id_hex"))
        val populated = Payment.parsePaymentImport(pyHex(pyStr(popB, "body_hex")))
        pyCheck("populated foreign id == oracle", Hex.encode(populated.id()), pyStr(popB, "id_hex"))
        pyCheck("populated foreign_id == oracle", Hex.encode(populated.foreignId()), pyStr(popB, "foreign_id_hex"))
        pyCheck("empty vs populated ids distinct", (Hex.encode(empty.id()) != Hex.encode(populated.id())).toString(), "true")
        pyCheck("empty vs populated foreign_ids distinct", (Hex.encode(empty.foreignId()) != Hex.encode(populated.foreignId())).toString(), "true")
        pyCheck("absent foreign field rejected", pyKind { Payment.parsePaymentImport(pyHex(pyStr(absB, "body_hex"))) }, pyStr(absB, "reject"))
    }

    // 10. a bstr-currency look-alike is rejected PayMalformed.
    run {
        val la = pySection(edges, "look_alike")
        pyCheck("look-alike rejected", pyKind { Payment.parsePaymentImport(pyHex(pyStr(la, "body_hex"))) }, pyStr(la, "reject"))
    }

    // 11. the binding property: a wrong amount / payee / substituted foreign yields a DIFFERENT charge
    //     content-id (ApprovalMismatch at the §7 layer — expressed structurally, corpus-graded).
    run {
        val baseIv = pySection(imports, "ap2")
        val base = pyImportFrom(baseIv)
        val baseId = Hex.encode(base.chargeBinding().contentId())
        pyCheck("base charge id == oracle", baseId, pyStr(pySection(baseIv, "charge_binding"), "id_hex"))
        val mm = pySection(json, "mismatch")

        val wrongAmount = Payment.PaymentImport(base.format, base.amount + 8000, base.currency, base.payee, base.notAfter, base.foreign)
        pyCheck("wrong-amount charge id == oracle", Hex.encode(wrongAmount.chargeBinding().contentId()), pyStr(mm, "wrong_amount_charge_id_hex"))

        val wrongPayee = Payment.PaymentImport(base.format, base.amount, base.currency, "merchant:evil-store".toByteArray(Charsets.UTF_8), base.notAfter, base.foreign)
        pyCheck("wrong-payee charge id == oracle", Hex.encode(wrongPayee.chargeBinding().contentId()), pyStr(mm, "wrong_payee_charge_id_hex"))

        val substituted = Payment.PaymentImport(base.format, base.amount, base.currency, base.payee, base.notAfter, pyHex(pyStr(mm, "substituted_foreign_hex")))
        pyCheck("substituted foreign_id == oracle", Hex.encode(substituted.foreignId()), pyStr(mm, "substituted_foreign_id_hex"))
        pyCheck("substituted charge id == oracle", Hex.encode(substituted.chargeBinding().contentId()), pyStr(mm, "substituted_charge_id_hex"))

        for (other in listOf(pyStr(mm, "wrong_amount_charge_id_hex"), pyStr(mm, "wrong_payee_charge_id_hex"), pyStr(mm, "substituted_charge_id_hex"))) {
            pyCheck("changed charge != bound charge ($other)", (baseId != other).toString(), "true")
        }
    }

    // 12. signed import round-trip in isolation (design §24) — NOT corpus-graded.
    run {
        val iv = pySection(imports, "ap2")
        val p = pyImportFrom(iv)
        val obj = Payment.signPaymentImport(p, PY_ALG, PY_SEED)
        val got = Payment.verifyPaymentImport(obj, Cose.PROFILE_PUBLIC, PY_ALG, PY_PK)
        val same = got.format == p.format && got.amount == p.amount && got.currency == p.currency &&
            got.payee.contentEquals(p.payee) && got.notAfter == p.notAfter && got.foreign.contentEquals(p.foreign)
        pyCheck("signed import verifies + round-trips", same.toString(), "true")
        val bad = obj.copyOf(); bad[bad.size - 1] = (bad[bad.size - 1].toInt() xor 1).toByte()
        pyCheck("tampered signature rejected", pyKind { Payment.verifyPaymentImport(bad, Cose.PROFILE_PUBLIC, PY_ALG, PY_PK) }, "BadSignature")
        val badFmt = Payment.PaymentImport(unknownFormat, 1, "USD", "x".toByteArray(Charsets.UTF_8), 1, ByteArray(0))
        val badObj = Payment.signPaymentImport(badFmt, PY_ALG, PY_SEED)
        pyCheck("unknown-format import rejected", pyKind { Payment.verifyPaymentImport(badObj, Cose.PROFILE_PUBLIC, PY_ALG, PY_PK) }, "UnknownPaymentFormat")
    }

    // 13. AuthorizeCharge (STEP-2 parity; ISOLATION, real ML-DSA) — the per-charge approval gate that
    //     composes approval.verifyApproval + policy.authorizes + approval.Ledger.consume, exactly as
    //     impl/go/payment/payment.go:241 AuthorizeCharge (mirrors TestChargeSingleUseAndBinding +
    //     TestPaymentImportMultiUseMutation). A §7 approval bound to the EXACT charge-binding content
    //     id is spent SINGLE-USE through the ledger (a replay is AlreadyConsumed, no double-spend, no
    //     second append); a wrong-amount/wrong-payee/substituted-foreign charge fails its binding
    //     (ApprovalMismatch, using the SAME oracle-graded mismatch content-ids as section 11); a
    //     foreign key never authenticates (BadSignature); an expired charge is rejected
    //     (ApprovalExpired); an under-granting approval (read_only cannot authorize a
    //     non_idempotent_write charge) is denied (ApprovalRequired); and an unknown imported format is
    //     not chargeable (UnknownPaymentFormat) with no ledger append.
    run {
        val ap = pyImportFrom(pySection(imports, "ap2"))
        val chargeCid = ap.chargeBinding().contentId()
        val (appr, apprSig) = pyMkApproval(chargeCid, "approver-A", Payment.CHARGE_EFFECT, 0x01, ap.notAfter, PAY_APPROVER_SEED)

        // First charge: authorized and consumed exactly once (seq 0); a replay is rejected
        // AlreadyConsumed with no second spend (no state change beyond the one consume).
        val ledger = pyFreshLedger()
        val entry = Payment.authorizeCharge(ap, appr, PY_ALG, PAY_APPROVER_PK, apprSig, "payer-1", ap.notAfter, ledger)
        pyCheck("authorize-charge honest first charge consumes at seq 0", entry.seq.toString(), "0")
        pyCheck("authorize-charge replay rejected AlreadyConsumed", pyKind { Payment.authorizeCharge(ap, appr, PY_ALG, PAY_APPROVER_PK, apprSig, "payer-1", ap.notAfter, ledger) }, "AlreadyConsumed")
        pyCheck("authorize-charge replay made no second spend", ledger.size().toString(), "1")
        ledger.close()

        // A wrong-amount charge yields a different charge content-id (section 11's oracle-graded
        // wrong_amount_charge_id_hex), so the bound approval no longer matches.
        val wrongAmount = Payment.PaymentImport(ap.format, ap.amount + 8000, ap.currency, ap.payee, ap.notAfter, ap.foreign)
        pyCheck("authorize-charge wrong-amount denied ApprovalMismatch", pyKind { Payment.authorizeCharge(wrongAmount, appr, PY_ALG, PAY_APPROVER_PK, apprSig, "payer-1", ap.notAfter, pyFreshLedger()) }, "ApprovalMismatch")

        // A wrong-payee charge likewise fails the binding (section 11's wrong_payee_charge_id_hex).
        val wrongPayee = Payment.PaymentImport(ap.format, ap.amount, ap.currency, "merchant:evil-store".toByteArray(Charsets.UTF_8), ap.notAfter, ap.foreign)
        pyCheck("authorize-charge wrong-payee denied ApprovalMismatch", pyKind { Payment.authorizeCharge(wrongPayee, appr, PY_ALG, PAY_APPROVER_PK, apprSig, "payer-1", ap.notAfter, pyFreshLedger()) }, "ApprovalMismatch")

        // A substituted foreign payload changes the foreign content-id, hence the charge binding
        // (section 11's substituted_foreign_hex / substituted_charge_id_hex).
        val mm = pySection(json, "mismatch")
        val substituted = Payment.PaymentImport(ap.format, ap.amount, ap.currency, ap.payee, ap.notAfter, pyHex(pyStr(mm, "substituted_foreign_hex")))
        pyCheck("authorize-charge substituted-foreign denied ApprovalMismatch", pyKind { Payment.authorizeCharge(substituted, appr, PY_ALG, PAY_APPROVER_PK, apprSig, "payer-1", ap.notAfter, pyFreshLedger()) }, "ApprovalMismatch")

        // A foreign key never authenticates the approval.
        pyCheck("authorize-charge foreign-key denied BadSignature", pyKind { Payment.authorizeCharge(ap, appr, PY_ALG, PAY_FOREIGN_PK, apprSig, "payer-1", ap.notAfter, pyFreshLedger()) }, "BadSignature")

        // An expired charge (now > approval.notAfter) is rejected.
        pyCheck("authorize-charge expired denied ApprovalExpired", pyKind { Payment.authorizeCharge(ap, appr, PY_ALG, PAY_APPROVER_PK, apprSig, "payer-1", ap.notAfter + 1, pyFreshLedger()) }, "ApprovalExpired")

        // An under-granting approval (read_only cannot authorize a non_idempotent_write charge) is denied.
        val (underAppr, underSig) = pyMkApproval(chargeCid, "approver-A", Policy.READ_ONLY, 0x03, ap.notAfter, PAY_APPROVER_SEED)
        pyCheck("authorize-charge under-granting denied ApprovalRequired", pyKind { Payment.authorizeCharge(ap, underAppr, PY_ALG, PAY_APPROVER_PK, underSig, "payer-1", ap.notAfter, pyFreshLedger()) }, "ApprovalRequired")

        // An unknown imported format is not chargeable, checked BEFORE any approval/ledger work.
        val unk = Payment.PaymentImport(unknownFormat, ap.amount, ap.currency, ap.payee, ap.notAfter, ap.foreign)
        pyCheck("authorize-charge unknown-format denied UnknownPaymentFormat", pyKind { Payment.authorizeCharge(unk, appr, PY_ALG, PAY_APPROVER_PK, apprSig, "payer-1", ap.notAfter, pyFreshLedger()) }, "UnknownPaymentFormat")
    }
}

fun main() {
    println("payment conformance (Kotlin) — graded vs vectors/payment/cases.json")
    paymentRun()
    println(if (pyFails == 0) "PaymentTests: PASS" else "PaymentTests: FAIL ($pyFails)")
    exitProcess(if (pyFails == 0) 0 else 1)
}
