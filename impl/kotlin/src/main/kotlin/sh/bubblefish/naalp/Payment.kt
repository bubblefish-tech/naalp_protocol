// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

/**
 * C21 (task 5B.1) NAALP-PAY payment import for the Kotlin SDK (design.md §24; R-PAY-1..6).
 *
 * NAALP-PAY imports a foreign payment payload — an AP2 mandate, an Agentic Commerce Protocol
 * delegated token, an x402 payload — octet-for-octet as OPAQUE foreign bytes (carriage, not
 * adoption): the foreign bytes are never re-serialized, canonicalized, or rewritten, and a foreign
 * identity inside them never becomes an N-AALP authorization identity. It introduces NO new envelope,
 * encoding, signature, identity, effect, or ledger mechanism: the imported payload becomes a
 * value-bearing charge that N-AALP governs with its OWN added guarantees, reusing the closed C5 effect
 * lattice (Policy). There is NO fifth effect and NO payment-specific ledger.
 *
 * The added guarantees over the imported formats:
 *
 *   - PaymentImport {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign} is the
 *     wrapper body. `format` selects the imported FORMAT from the closed payment-format registry;
 *     `foreign` carries the imported payload octet-for-octet. An unknown format is rejected
 *     (UnknownPaymentFormat).
 *   - THE CHARGE IS BOUND. ChargeBinding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
 *     6: foreign_id} names the exact value a §7 approval binds by content id — including the foreign
 *     payload's content id (the carriage binding). A wrong-amount, wrong-payee, wrong-currency, or
 *     substituted-payload charge yields a different content id and no longer matches the approval.
 *
 * Every check is fail-closed (§15): a failing charge is rejected whole and returns its named error.
 *
 * Ported from impl/go/payment (cross-read against impl/python/naalp/payment.py). The PaymentImport
 * signature is a bare-{1:alg} COSE_Sign1 (as the reference's cose.Sign1) with real deterministic
 * ML-DSA. Graded against vectors/payment/cases.json.
 *
 * STEP-2 parity: [authorizeCharge] is the per-charge approval gate (ported from
 * impl/go/payment/payment.go:241 AuthorizeCharge), reusing the §7 approval object (Approval), its
 * VerifyApproval binding check, and the §7 single-use consume ledger UNCHANGED, plus the closed C5
 * effect lattice (Policy.authorizes) — exactly as the Go/Rust reference. It introduces no new approval
 * or ledger mechanism of its own. The payment corpus carries no authorize/consume vector, so this
 * surface is demonstrated in isolation (real ML-DSA keys + a real WAL ledger), not corpus-graded; the
 * value-bearing binding property it depends on (a wrong amount/payee/currency/substituted-foreign
 * charge yields a DIFFERENT ChargeBinding content id) IS corpus-graded above. Mirrors the
 * go/rust/python/typescript/ruby/php/csharp/java/swift ports.
 */
object Payment {

    /** The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain. */
    const val HEAD_SIZE = 48

    /**
     * The C5 effect a payment spend carries: a non_idempotent_write. A charge is value-bearing and not
     * safely repeatable, which is why it is spent single-use through the §7 ledger.
     */
    const val CHARGE_EFFECT = Policy.NON_IDEMPOTENT_WRITE

    // Payment format codes (design §24; the closed payment-format registry). A code outside the closed
    // set is rejected (UnknownPaymentFormat).
    const val FORMAT_AP2_MANDATE = 1L // AP2 mandate
    const val FORMAT_ACP_TOKEN = 2L   // Agentic Commerce Protocol delegated token
    const val FORMAT_X402 = 3L        // x402 payload

    private val FORMAT_NAMES = mapOf(
        FORMAT_AP2_MANDATE to "ap2-mandate",
        FORMAT_ACP_TOKEN to "acp-delegated-token",
        FORMAT_X402 to "x402-payload",
    )

    /** Whether code is one of the closed payment formats. */
    fun isRegisteredFormat(code: Long): Boolean = FORMAT_NAMES.containsKey(code)

    /** The registry name of a format code, or "unknown". */
    fun formatName(code: Long): String = FORMAT_NAMES[code] ?: "unknown"

    private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

    /**
     * Wraps a foreign payment payload as a value-bearing charge. Format selects the imported format
     * (closed registry); amount/currency/payee/notAfter are the bound charge terms; foreign is the
     * imported payload carried octet-for-octet (carriage, not adoption).
     */
    class PaymentImport(
        val format: Long,
        val amount: Long,
        val currency: String,
        payee: ByteArray,
        val notAfter: Long,
        foreign: ByteArray,
    ) {
        val payee: ByteArray = payee.copyOf()
        val foreign: ByteArray = foreign.copyOf()

        /** Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.U(format)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(amount)),
                    Cbor.Pair(Cbor.U(3), Cbor.T(currency)),
                    Cbor.Pair(Cbor.U(4), Cbor.B(payee)),
                    Cbor.Pair(Cbor.U(5), Cbor.U(notAfter)),
                    Cbor.Pair(Cbor.U(6), Cbor.B(foreign)),
                )
            )
        )

        /** The SHA-384 head (48 octets). */
        fun head(): ByteArray = sha384(bytes())

        /** The T1 content-id (50 octets): multihash(0x20, SHA-384(body)). */
        fun id(): ByteArray = Cbor.contentId(bytes())

        /**
         * The T1 content-id of the carried foreign payload — the hash the charge binding binds (the
         * carriage binding). A substituted payload yields a different foreign_id.
         */
        fun foreignId(): ByteArray = Cbor.contentId(foreign)

        /**
         * The exact charge value an approval binds for this import (amount + currency + payee + expiry
         * + the foreign payload's content id). A change to any bound term — including the foreign
         * payload — changes the binding's content id.
         */
        fun chargeBinding(): ChargeBinding =
            ChargeBinding(format, amount, currency, payee, notAfter, foreignId())
    }

    /**
     * Names the exact charge by value: format, amount, currency, payee, expiry, and the foreign
     * payload's content id. A §7 approval binds THIS binding's content id, so a change to any bound
     * term invalidates a prior approval (ApprovalMismatch).
     */
    class ChargeBinding(
        val format: Long,
        val amount: Long,
        val currency: String,
        payee: ByteArray,
        val notAfter: Long,
        foreignId: ByteArray,
    ) {
        val payee: ByteArray = payee.copyOf()

        /** content-id of the foreign payload: multihash(0x20, SHA-384(foreign)). */
        val foreignId: ByteArray = foreignId.copyOf()

        /** Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign_id}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.U(format)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(amount)),
                    Cbor.Pair(Cbor.U(3), Cbor.T(currency)),
                    Cbor.Pair(Cbor.U(4), Cbor.B(payee)),
                    Cbor.Pair(Cbor.U(5), Cbor.U(notAfter)),
                    Cbor.Pair(Cbor.U(6), Cbor.B(foreignId)),
                )
            )
        )

        /** The SHA-384 head (48 octets). */
        fun head(): ByteArray = sha384(bytes())

        /** The charge content id an approval binds: multihash(0x20, SHA-384(binding)). */
        fun contentId(): ByteArray = Cbor.contentId(bytes())
    }

    /** Return the value of map key k if present with type [U]/[N]/[B]/[T] matching [typ], else null. */
    private fun field(m: Cbor.M, k: Long): Cbor.Value? {
        for (p in m.pairs) {
            val key = p.k
            if (key is Cbor.U && key.v == k) return p.v
        }
        return null
    }

    /**
     * Reconstruct a PaymentImport from its body bytes alone. Does NOT validate the format against the
     * closed set (that is verifyPaymentImport's job), so an import carrying an unknown format can be
     * represented (then rejected). Fail-closed on a malformed shape or a non-canonical encoding
     * (PayMalformed).
     */
    fun parsePaymentImport(b: ByteArray): PaymentImport {
        val v = try {
            Cbor.decode(b) // the strict decoder rejects a non-canonical body (NonCanonical)
        } catch (e: NaalpException) {
            throw NaalpException("PayMalformed", "non-canonical payment-import body: ${e.kind}")
        }
        if (v !is Cbor.M) throw NaalpException("PayMalformed", "payment import is not a map")
        val fmt = field(v, 1) as? Cbor.U
        val amt = field(v, 2) as? Cbor.U
        val cur = field(v, 3) as? Cbor.T
        val payee = field(v, 4) as? Cbor.B
        val na = field(v, 5) as? Cbor.U
        val foreign = field(v, 6) as? Cbor.B
        if (fmt == null || amt == null || cur == null || payee == null || na == null || foreign == null) {
            throw NaalpException("PayMalformed", "object is not a well-formed N-AALP payment-import body")
        }
        return PaymentImport(fmt.v, amt.v, cur.v, payee.v, na.v, foreign.v)
    }

    // ---- signed import (bare {1:alg} COSE_Sign1, as the reference's cose.Sign1) ----

    /** The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int). */
    private fun protectedHeader(alg: Int): ByteArray =
        Cbor.encode(Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.N(alg.toLong())))))

    private fun algFromProtected(prot: ByteArray): Int {
        val v = Cbor.decode(prot)
        if (v !is Cbor.M) throw NaalpException("PayMalformed", "protected header is not a map")
        for (p in v.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == 1L) {
                val vv = p.v
                if (vv is Cbor.N) return vv.v.toInt()
                if (vv is Cbor.U) return vv.v.toInt()
            }
        }
        throw NaalpException("PayMalformed", "protected header has no alg")
    }

    /**
     * Produce the tagged COSE_Sign1 object over the PaymentImport body with a real deterministic ML-DSA
     * key derived from seed.
     */
    fun signPaymentImport(p: PaymentImport, alg: Int, seed: ByteArray): ByteArray {
        val prot = protectedHeader(alg)
        val payload = p.bytes()
        val tbs = Cose.toBeSignedRaw(prot, payload)
        val sig = Cose.mldsaSign(alg, seed, tbs)
        return Cose.assembleSign1Raw(prot, payload, sig)
    }

    /**
     * Verify the import's full signature under the profile, reconstruct it from the signed body bytes,
     * and validate the format against the closed registry. Check order (fail-closed): PayMalformed ->
     * UnknownAlg -> ProfileDowngrade -> KeyAlgMismatch -> BadSignature -> parse -> UnknownPaymentFormat.
     * Returns the PaymentImport on success.
     */
    fun verifyPaymentImport(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): PaymentImport {
        val parts = try {
            Cose.parseSign1Raw(obj)
        } catch (e: NaalpException) {
            throw NaalpException("PayMalformed", "not a tagged COSE_Sign1: ${e.kind}")
        }
        val prot = parts[0]
        val payload = parts[1]
        val sig = parts[2]
        val halg = algFromProtected(prot)
        val (level, known) = Cose.algLevel(halg)
        if (!known) throw NaalpException("UnknownAlg", "algorithm id not in the N-AALP registry")
        if (level < Cose.profileMinLevel(profile)) throw NaalpException("ProfileDowngrade", "signature level below the profile minimum")
        if (halg != alg) throw NaalpException("KeyAlgMismatch", "key algorithm does not match object header")
        val tbs = Cose.toBeSignedRaw(prot, payload)
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, sig)) throw NaalpException("BadSignature", "signature verification failed")
        val p = parsePaymentImport(payload)
        if (!isRegisteredFormat(p.format)) {
            throw NaalpException("UnknownPaymentFormat", "payment import selects a format outside the closed payment-format registry")
        }
        return p
    }

    // ---- the per-charge approval gate (reuses §7 approval + consume ledger) ----

    /**
     * Enforce the value-bearing rule for an imported payment, reusing the §7 approval and single-use
     * consume ledger UNCHANGED (ported from impl/go/payment/payment.go:241 AuthorizeCharge). The
     * approval MUST bind the EXACT charge binding content id (format + amount + currency + payee +
     * expiry + foreign_id) — so it satisfies neither a different amount/payee/currency nor a
     * substituted foreign payload ([NaalpException] "ApprovalMismatch", from [Approval.verifyApproval])
     * — its granted effect must cover [CHARGE_EFFECT] (a non_idempotent_write), it must be unexpired
     * at [now], and it is consumed single-use by [by] through the §7 ledger. Precedence and
     * fail-closed behaviour mirror the spine: an unknown/unregistered format denies before any
     * approval work (no ledger append); a non-matching or under-granting approval denies with no
     * ledger append; an already-spent approval denies AlreadyConsumed; the consume (the single state
     * change) happens only when every check holds. Returns the ledger entry on success.
     *
     * [approverAlg]/[approverPk] are the approver's key (the reference's `cose.Verifier`, represented
     * here as an explicit alg + public-key pair, matching [Approval.verifyApproval]'s convention).
     */
    fun authorizeCharge(
        p: PaymentImport,
        appr: Approval.ApprovalRecord,
        approverAlg: Int,
        approverPk: ByteArray,
        apprSig: ByteArray,
        by: String,
        now: Long,
        ledger: Approval.Ledger,
    ): Approval.LedgerEntry {
        if (!isRegisteredFormat(p.format)) {
            // an unknown imported format is not chargeable, fail-closed, before any approval work
            throw NaalpException("UnknownPaymentFormat", "payment import selects a format outside the closed payment-format registry")
        }
        val chargeCid = p.chargeBinding().contentId()
        // throws BadSignature / ApprovalMismatch (wrong amount/payee/currency/payload) / ApprovalExpired
        Approval.verifyApproval(appr, approverAlg, approverPk, apprSig, chargeCid, now)
        if (!Policy.authorizes(appr.grant, CHARGE_EFFECT)) {
            // the approval's granted effect does not cover the charge
            throw NaalpException("ApprovalRequired", "the approval's granted effect does not cover the charge")
        }
        // AlreadyConsumed on replay — single-use, no double-spend; the only state change on success
        return ledger.consume(appr.id(), by)
    }
}
