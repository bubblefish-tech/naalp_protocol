// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.security.MessageDigest;
import java.util.List;

/**
 * N-AALP C21 (task 5B.1) NAALP-PAY payment import for the Java SDK (design.md §24; R-PAY-1..6).
 *
 * <p>NAALP-PAY imports a foreign payment payload — an AP2 mandate, an Agentic Commerce Protocol
 * delegated token, an x402 payload — octet-for-octet as OPAQUE foreign bytes (carriage, not adoption):
 * the foreign bytes are never re-serialized, canonicalized, or rewritten (R-14.4), and a foreign
 * identity inside them never becomes an N-AALP authorization identity (R-14.6). It introduces NO new
 * envelope, encoding, signature, identity, effect, or ledger mechanism (R-11.3): the imported payload
 * becomes a value-bearing charge that N-AALP governs with its OWN added guarantees, reusing the closed
 * C5 effect lattice ({@link Policy}) UNCHANGED. There is NO fifth effect and NO payment-specific ledger.
 *
 * <p>The added guarantees over the imported formats:
 * <ul>
 *   <li>PaymentImport {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign} is the
 *       wrapper body. {@code format} selects the imported FORMAT from the closed payment-format
 *       registry; {@code foreign} carries the imported payload octet-for-octet. An unknown format code
 *       is rejected (UnknownPaymentFormat).
 *   <li>THE CHARGE IS BOUND. ChargeBinding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
 *       6: foreign_id} names the exact value a §7 approval binds by content id — including the foreign
 *       payload's content id (the carriage binding). A wrong-amount, wrong-payee, wrong-currency, or
 *       substituted-payload charge yields a different content id and no longer matches the approval.
 * </ul>
 *
 * <p>Every check is fail-closed (§15): a failing charge is rejected whole and returns its named error.
 * An independent transcription of impl/go/payment (cross-checked against impl/python/naalp/payment);
 * byte surfaces graded against vectors/payment/cases.json; the bare-{1:alg} COSE_Sign1 signature is
 * real deterministic ML-DSA-65, demonstrated in isolation.
 *
 * <p>ALSO PORTED (STEP-2 ten-port parity wave): {@link #authorizeCharge}, the per-charge approval gate
 * reusing the §7 {@link Approval} object and single-use consume {@link Approval.Ledger} UNCHANGED (the
 * same composition as {@code impl/go/payment.AuthorizeCharge}). It binds the exact charge (via {@link
 * ChargeBinding#contentId}), requires the approval's granted effect to cover {@link #CHARGE_EFFECT}
 * (the §6.1 lattice, {@link Policy#authorizes}), and consumes the approval single-use through the
 * ledger — a replay is rejected AlreadyConsumed with no double-spend. Demonstrated in isolation against
 * real deterministic ML-DSA-65 approvals and a real WAL-backed ledger (not corpus-graded — the payment
 * corpus carries no approval/consume vector — but every deny path and the single-use success are
 * exercised directly, matching the Go reference's TestChargeSingleUseAndBinding).
 */
public final class Payment {
    /** The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain. */
    public static final int HEAD_SIZE = 48;

    /** The C5 effect a payment spend carries: a non_idempotent_write. A charge is value-bearing and not
     * safely repeatable, which is why it is spent single-use through the §7 ledger (the value-bearing
     * rule). */
    public static final long CHARGE_EFFECT = Policy.NON_IDEMPOTENT_WRITE;

    /** Payment format codes (design §24; the closed payment-format registry). A code outside the closed
     * set is rejected (UnknownPaymentFormat). */
    public static final long FORMAT_AP2_MANDATE = 1; // AP2 mandate
    public static final long FORMAT_ACP_TOKEN = 2;   // Agentic Commerce Protocol delegated token
    public static final long FORMAT_X402 = 3;        // x402 payload

    private Payment() {}

    /** Whether {@code code} is one of the closed payment formats. */
    public static boolean isRegisteredFormat(long code) {
        return code == FORMAT_AP2_MANDATE || code == FORMAT_ACP_TOKEN || code == FORMAT_X402;
    }

    /** The registry name of a format code, or "unknown". */
    public static String formatName(long code) {
        if (code == FORMAT_AP2_MANDATE) {
            return "ap2-mandate";
        }
        if (code == FORMAT_ACP_TOKEN) {
            return "acp-delegated-token";
        }
        if (code == FORMAT_X402) {
            return "x402-payload";
        }
        return "unknown";
    }

    private static NaalpException malformed() {
        return new NaalpException("PayMalformed", "object is not a well-formed N-AALP payment-import body");
    }

    private static NaalpException unknownFormat() {
        return new NaalpException("UnknownPaymentFormat",
                "payment import selects a format outside the closed payment-format registry");
    }

    private static byte[] sha384(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    // ---- PaymentImport: the imported payload wrapper (design §24) --------------------------------

    /** Wraps a foreign payment payload as a value-bearing charge. Format selects the imported format
     * (closed registry); Amount/Currency/Payee/NotAfter are the bound charge terms; Foreign is the
     * imported payload carried octet-for-octet (carriage, not adoption). */
    public static final class PaymentImport {
        public final long format;
        public final long amount;
        public final String currency;
        public final byte[] payee;
        public final long notAfter;
        public final byte[] foreign;

        public PaymentImport(long format, long amount, String currency, byte[] payee, long notAfter, byte[] foreign) {
            this.format = format;
            this.amount = amount;
            this.currency = currency;
            this.payee = payee.clone();
            this.notAfter = notAfter;
            this.foreign = foreign.clone();
        }

        /** Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
         * 6: foreign}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(format)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(amount)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.T(currency)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(payee)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(notAfter)),
                    new Cbor.Pair(new Cbor.U(6), new Cbor.B(foreign)))));
        }

        /** The SHA-384 head (48 octets). */
        public byte[] head() {
            return sha384(bytes());
        }

        /** The T1 content-id (50 octets): multihash(0x20, SHA-384(body)). */
        public byte[] id() {
            return Cbor.contentId(bytes());
        }

        /** The T1 content-id of the carried foreign payload — the hash the charge binding binds (the
         * carriage binding). A substituted payload yields a different foreign_id. */
        public byte[] foreignId() {
            return Cbor.contentId(foreign);
        }

        /** The exact charge value an approval binds for this import (amount + currency + payee + expiry
         * + the foreign payload's content id). A change to any bound term — including the foreign payload
         * — changes the binding's content id. */
        public ChargeBinding chargeBinding() {
            return new ChargeBinding(format, amount, currency, payee, notAfter, foreignId());
        }
    }

    /** Reconstruct a PaymentImport from its body bytes alone. Does NOT validate the format against the
     * closed set (that is {@link #verifyPaymentImport}'s job), so an import carrying an unknown format
     * can be represented (then rejected). Fail-closed on a malformed shape or a non-canonical encoding. */
    public static PaymentImport parsePaymentImport(byte[] b) {
        Cbor.Value v;
        try {
            v = Cbor.decode(b); // the strict decoder rejects a non-canonical body (NonCanonical)
        } catch (NaalpException e) {
            throw malformed();
        }
        if (!(v instanceof Cbor.M m)) {
            throw malformed();
        }
        Long format = uintField(m, 1);
        Long amount = uintField(m, 2);
        String currency = tstrField(m, 3);
        byte[] payee = bstrField(m, 4);
        Long notAfter = uintField(m, 5);
        byte[] foreign = bstrField(m, 6);
        if (format == null || amount == null || currency == null || payee == null || notAfter == null || foreign == null) {
            throw malformed();
        }
        return new PaymentImport(format, amount, currency, payee, notAfter, foreign);
    }

    // ---- ChargeBinding: the value an approval binds (design §24) ---------------------------------

    /** Names the exact charge by value: format, amount, currency, payee, expiry, and the foreign
     * payload's content id. A §7 approval binds THIS binding's content id, so a change to any bound term
     * invalidates a prior approval (ApprovalMismatch). */
    public static final class ChargeBinding {
        public final long format;
        public final long amount;
        public final String currency;
        public final byte[] payee;
        public final long notAfter;
        public final byte[] foreignId; // content-id of the foreign payload: multihash(0x20, SHA-384(foreign))

        public ChargeBinding(long format, long amount, String currency, byte[] payee, long notAfter, byte[] foreignId) {
            this.format = format;
            this.amount = amount;
            this.currency = currency;
            this.payee = payee.clone();
            this.notAfter = notAfter;
            this.foreignId = foreignId.clone();
        }

        /** Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
         * 6: foreign_id}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(format)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(amount)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.T(currency)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(payee)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(notAfter)),
                    new Cbor.Pair(new Cbor.U(6), new Cbor.B(foreignId)))));
        }

        /** The SHA-384 head (48 octets). */
        public byte[] head() {
            return sha384(bytes());
        }

        /** The charge content id an approval binds: multihash(0x20, SHA-384(binding)). */
        public byte[] contentId() {
            return Cbor.contentId(bytes());
        }
    }

    // ---- the per-charge approval gate (reuses §7 approval + consume ledger) -----------------------

    /** Enforces the value-bearing rule for an imported payment, reusing the §7 approval and single-use
     * consume ledger UNCHANGED. The approval MUST bind the EXACT charge binding content id (format +
     * amount + currency + payee + expiry + foreign_id) — so it satisfies neither a different
     * amount/payee/currency nor a substituted foreign payload (ApprovalMismatch, from {@link Approval}) —
     * its granted effect must cover the charge's {@link #CHARGE_EFFECT} (a non_idempotent_write), it must
     * be unexpired at {@code now}, and it is consumed single-use by {@code by} through the §7 ledger.
     * Precedence and fail-closed behaviour mirror the spine: a non-matching or under-granting approval
     * denies with no ledger append; an already-spent approval denies AlreadyConsumed; the consume (the
     * single state change) happens only when every check holds. Returns the ledger entry on success. */
    public static Approval.LedgerEntry authorizeCharge(PaymentImport p, Approval.ApprovalRecord appr,
            int approverAlg, byte[] approverPk, byte[] apprSig, String by, long now, Approval.Ledger ledger) {
        if (!isRegisteredFormat(p.format)) {
            throw unknownFormat(); // an unknown imported format is not chargeable, fail-closed
        }
        byte[] chargeCid = p.chargeBinding().contentId();
        // ApprovalMismatch (wrong amount/payee/currency/payload) / ApprovalExpired / BadSignature:
        Approval.verifyApproval(appr, approverAlg, approverPk, apprSig, chargeCid, now);
        if (!Policy.authorizes(appr.grant, CHARGE_EFFECT)) {
            throw new NaalpException("ApprovalRequired", "the approval's granted effect does not cover the charge");
        }
        // AlreadyConsumed on replay (or LedgerIO) — single-use, no double-spend. The single state change.
        return ledger.consume(appr.id(), by);
    }

    // ---- signed import (bare {1:alg} COSE_Sign1, as the reference's cose.Sign1) ------------------

    /** The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int). */
    private static byte[] protectedHeader(int alg) {
        return Cbor.encode(new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)))));
    }

    private static int algFromProtected(byte[] prot) {
        Cbor.Value v;
        try {
            v = Cbor.decode(prot);
        } catch (NaalpException e) {
            throw new NaalpException("PayMalformed", "protected header is not canonical");
        }
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("PayMalformed", "protected header is not a map");
        }
        for (Cbor.Pair p : m.pairs) {
            if (p.k instanceof Cbor.U u && u.v == 1) {
                if (p.val instanceof Cbor.N n) {
                    return (int) n.v;
                }
                if (p.val instanceof Cbor.U pu) {
                    return (int) pu.v;
                }
            }
        }
        throw new NaalpException("PayMalformed", "protected header has no alg");
    }

    /** Produce the tagged COSE_Sign1 object over the PaymentImport body with a real deterministic
     * ML-DSA key derived from seed. */
    public static byte[] signPaymentImport(PaymentImport p, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), p.bytes());
    }

    /** Verify the import's full signature under the profile, reconstruct it from the signed body bytes,
     * and validate the format against the closed registry. Check order (fail-closed): PayMalformed ->
     * UnknownAlg -> ProfileDowngrade -> KeyAlgMismatch -> BadSignature -> parse -> UnknownPaymentFormat.
     * Returns the PaymentImport on success. */
    public static PaymentImport verifyPaymentImport(byte[] obj, int profile, int alg, byte[] pk) {
        byte[][] parts;
        try {
            parts = Cose.parseSign1Raw(obj); // [protected, payload, signature]
        } catch (NaalpException e) {
            throw new NaalpException("PayMalformed", "not a tagged COSE_Sign1");
        }
        int halg = algFromProtected(parts[0]);
        Cose.AlgLevel al = Cose.algLevel(halg);
        if (!al.known) {
            throw new NaalpException("UnknownAlg", "algorithm id not in the N-AALP registry");
        }
        if (al.level < Cose.profileMinLevel(profile)) {
            throw new NaalpException("ProfileDowngrade", "signature level below the profile minimum");
        }
        if (halg != alg) {
            throw new NaalpException("KeyAlgMismatch", "key algorithm does not match object header");
        }
        byte[] tbs = Cose.toBeSignedRaw(parts[0], parts[1]);
        if (!Cose.coseVerify1Raw(halg, pk, tbs, parts[2])) {
            throw new NaalpException("BadSignature", "signature verification failed");
        }
        PaymentImport p = parsePaymentImport(parts[1]);
        if (!isRegisteredFormat(p.format)) {
            throw unknownFormat();
        }
        return p;
    }

    // ---- small deterministic-CBOR field accessors (present + correct type, else null) ------------

    private static Cbor.Value field(Cbor.M m, long k) {
        for (Cbor.Pair p : m.pairs) {
            if (p.k instanceof Cbor.U u && u.v == k) {
                return p.val;
            }
        }
        return null;
    }

    private static Long uintField(Cbor.M m, long k) {
        Cbor.Value v = field(m, k);
        return v instanceof Cbor.U u ? u.v : null;
    }

    private static String tstrField(Cbor.M m, long k) {
        Cbor.Value v = field(m, k);
        return v instanceof Cbor.T t ? t.v : null;
    }

    private static byte[] bstrField(Cbor.M m, long k) {
        Cbor.Value v = field(m, k);
        return v instanceof Cbor.B b ? b.v : null;
    }
}
