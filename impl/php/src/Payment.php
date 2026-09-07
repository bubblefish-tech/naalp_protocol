<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C21 (task 5B.1) NAALP-PAY payment import for the PHP SDK (design.md §24; R-PAY-1..6).
 *
 * NAALP-PAY imports a foreign payment payload — an AP2 mandate, an Agentic Commerce Protocol delegated
 * token, an x402 payload — octet-for-octet as OPAQUE foreign bytes (carriage, not adoption): the
 * foreign bytes are never re-serialized, canonicalized, or rewritten, and a foreign identity inside
 * them never becomes an N-AALP authorization identity. It introduces NO new envelope, encoding,
 * signature, identity, effect, or ledger mechanism: the imported payload becomes a value-bearing charge
 * that N-AALP governs with its OWN added guarantees, reusing the closed C5 effect lattice (Naalp\Policy).
 * There is NO fifth effect and NO payment-specific ledger.
 *
 * The added guarantees over the imported formats:
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
 * An independent transcription of impl/go/payment (cross-read against impl/python/naalp/payment.py),
 * graded against the shared vectors/payment/cases.json.
 *
 * CRYPTO SCOPE (PURE-ONLY): the corpus-graded surfaces — the closed format registry, the
 * PaymentImport and ChargeBinding body/head/content-id (incl. the >2^53 amount), the parse round-trip,
 * the fail-closed edges, and the mismatch content-ids — are pure and signature-independent. PHP has no
 * deterministic ML-DSA (FIPS 204), so the reference's ML-DSA PaymentImport signature is demonstrated
 * with a real Ed25519 (RFC 8032) signature; the profile floor is level 3, so verifyPaymentImport
 * correctly floors a pure-Ed25519 (level-0) object (ProfileDowngrade) and refuses an ML-DSA object at
 * the signature step rather than fake a result.
 *
 * AUTHORIZE-CHARGE (Go impl/go/payment/payment.go:241): AuthorizeCharge enforces the value-bearing rule
 * for an imported payment by composing the §7 approval + single-use consume ledger UNCHANGED
 * (Naalp\Approval, Naalp\ApprovalRecord, Naalp\Ledger, landed in the approval cluster) with the C5
 * effect lattice (Naalp\Policy::authorizes). The approval MUST bind the EXACT ChargeBinding content id
 * (format + amount + currency + payee + expiry + foreign_id) — so it satisfies neither a different
 * amount/payee/currency nor a substituted foreign payload (ApprovalMismatch) — its granted effect must
 * cover CHARGE_EFFECT (a non_idempotent_write, ApprovalRequired otherwise), it must be unexpired
 * (ApprovalExpired) and correctly signed (BadSignature), the format must be registered
 * (UnknownPaymentFormat, checked FIRST, before the binding, so an unknown format never touches the
 * ledger), and the single state change — the ledger consume — happens only when every check holds
 * (AlreadyConsumed on replay, no double-spend). Ed25519-demonstrated (isolation, NOT corpus-graded: the
 * payment corpus carries no approval/ledger vectors), mirroring
 * impl/go/payment/payment_test.go's TestChargeSingleUseAndBinding.
 */

declare(strict_types=1);

namespace Naalp;

/** A named, fail-closed payment error; $kind is a stable string mirroring the reference error kinds. */
class PayError extends \RuntimeException
{
    public string $kind;

    public function __construct(string $kind, string $msg = "")
    {
        $this->kind = $kind;
        parent::__construct($msg === "" ? $kind : "$kind: $msg");
    }
}

/**
 * Wraps a foreign payment payload as a value-bearing charge. `format` selects the imported format
 * (closed registry); `amount`/`currency`/`payee`/`notAfter` are the bound charge terms; `foreign` is
 * the imported payload carried octet-for-octet (carriage, not adoption).
 */
final class PaymentImport
{
    public int $format;
    public int $amount;
    public string $currency;
    public string $payee;
    public int $notAfter;
    public string $foreign;

    public function __construct(int $format, int $amount, string $currency, string $payee, int $notAfter, string $foreign)
    {
        $this->format = $format;
        $this->amount = $amount;
        $this->currency = $currency;
        $this->payee = $payee;
        $this->notAfter = $notAfter;
        $this->foreign = $foreign;
    }

    /** Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new U($this->format)],
            [new U(2), new U($this->amount)],
            [new U(3), new T($this->currency)],
            [new U(4), new B($this->payee)],
            [new U(5), new U($this->notAfter)],
            [new U(6), new B($this->foreign)],
        ]));
    }

    /** The SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The T1 content-id (50 octets): multihash(0x20, SHA-384(body)). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }

    /**
     * The T1 content-id of the carried foreign payload — the hash the charge binding binds (the
     * carriage binding). A substituted payload yields a different foreign-id.
     */
    public function foreignId(): string
    {
        return Cbor::contentId($this->foreign);
    }

    /**
     * The exact charge value an approval binds for this import (amount + currency + payee + expiry +
     * the foreign payload's content id). A change to any bound term — including the foreign payload —
     * changes the binding's content id.
     */
    public function chargeBinding(): ChargeBinding
    {
        return new ChargeBinding($this->format, $this->amount, $this->currency, $this->payee, $this->notAfter, $this->foreignId());
    }
}

/**
 * Names the exact charge by value: format, amount, currency, payee, expiry, and the foreign payload's
 * content id. A §7 approval binds THIS binding's content id, so a change to any bound term invalidates
 * a prior approval (ApprovalMismatch).
 */
final class ChargeBinding
{
    public int $format;
    public int $amount;
    public string $currency;
    public string $payee;
    public int $notAfter;
    public string $foreignId;

    public function __construct(int $format, int $amount, string $currency, string $payee, int $notAfter, string $foreignId)
    {
        $this->format = $format;
        $this->amount = $amount;
        $this->currency = $currency;
        $this->payee = $payee;
        $this->notAfter = $notAfter;
        $this->foreignId = $foreignId;
    }

    /** Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign_id}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new U($this->format)],
            [new U(2), new U($this->amount)],
            [new U(3), new T($this->currency)],
            [new U(4), new B($this->payee)],
            [new U(5), new U($this->notAfter)],
            [new U(6), new B($this->foreignId)],
        ]));
    }

    /** The SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The charge content id an approval binds: multihash(0x20, SHA-384(binding)). */
    public function contentId(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

final class Payment
{
    /** The C5 effect a payment spend carries: a non_idempotent_write (no fifth effect). */
    public const CHARGE_EFFECT = Policy::NON_IDEMPOTENT_WRITE;

    // Payment format codes (design §24; the closed payment-format registry).
    public const FORMAT_AP2_MANDATE = 1; // AP2 mandate
    public const FORMAT_ACP_TOKEN = 2;   // Agentic Commerce Protocol delegated token
    public const FORMAT_X402 = 3;        // x402 payload

    /** format code => registry name; an unknown code has no entry. */
    private const FORMAT_NAMES = [
        self::FORMAT_AP2_MANDATE => "ap2-mandate",
        self::FORMAT_ACP_TOKEN => "acp-delegated-token",
        self::FORMAT_X402 => "x402-payload",
    ];

    /** Whether code is one of the closed payment formats. */
    public static function isRegisteredFormat(int $code): bool
    {
        return \array_key_exists($code, self::FORMAT_NAMES);
    }

    /** The registry name of a format code, or "unknown". */
    public static function formatName(int $code): string
    {
        return self::FORMAT_NAMES[$code] ?? "unknown";
    }

    /**
     * Reconstruct a PaymentImport from its body bytes alone. Does NOT validate the format against the
     * closed set (that is verifyPaymentImport's job), so an import carrying an unknown format can be
     * represented (and then rejected). Fail-closed (PayMalformed) on a non-canonical encoding, a
     * non-map, or a missing/mistyped field 1-6.
     */
    public static function parsePaymentImport(string $b): PaymentImport
    {
        try {
            $v = Cbor::decode($b); // the strict decoder rejects a non-canonical body (NonCanonical)
        } catch (NonCanonical $e) {
            throw new PayError("PayMalformed", "non-canonical payment-import body");
        }
        if (!($v instanceof M)) {
            throw new PayError("PayMalformed", "payment import is not a map");
        }
        $fmt = self::field($v, 1, U::class);
        $amt = self::field($v, 2, U::class);
        $cur = self::field($v, 3, T::class);
        $payee = self::field($v, 4, B::class);
        $na = self::field($v, 5, U::class);
        $foreign = self::field($v, 6, B::class);
        if ($fmt === null || $amt === null || $cur === null || $payee === null || $na === null || $foreign === null) {
            throw new PayError("PayMalformed", "object is not a well-formed N-AALP payment-import body");
        }
        return new PaymentImport($fmt->v, $amt->v, $cur->v, $payee->v, $na->v, $foreign->v);
    }

    /** The bare {1: alg} COSE_Sign1 protected header (§4); alg is a negative int. */
    public static function protectedHeader(int $alg): string
    {
        return Cbor::encode(new M([[new U(1), new N($alg)]]));
    }

    /** Read the alg (label 1) value from an encoded protected header. */
    public static function algFromProtected(string $prot): int
    {
        $v = Cbor::decode($prot);
        if (!($v instanceof M)) {
            throw new PayError("PayMalformed", "protected header is not a map");
        }
        foreach ($v->pairs as $pair) {
            [$k, $val] = $pair;
            if ($k instanceof U && $k->v === 1 && ($val instanceof N || $val instanceof U)) {
                return $val->v;
            }
        }
        throw new PayError("PayMalformed", "protected header has no alg");
    }

    /**
     * Produce the tagged COSE_Sign1 object over the PaymentImport body. PURE-ONLY PHP: the signature is
     * a real Ed25519 (RFC 8032) signature over the ToBeSigned bytes, standing in for the reference's
     * ML-DSA signature.
     */
    public static function signPaymentImport(PaymentImport $p, int $alg, string $seed): string
    {
        $prot = self::protectedHeader($alg);
        $payload = $p->bytes();
        $sig = Cose::ed25519Sign($seed, Cose::toBeSignedRaw($prot, $payload));
        return Cose::assembleSign1Raw($prot, $payload, $sig);
    }

    /**
     * Verify the import's full signature under the profile, reconstruct it from the signed body bytes,
     * and validate the format against the closed registry. Check order (fail-closed): PayMalformed ->
     * UnknownAlg -> ProfileDowngrade -> KeyAlgMismatch -> BadSignature -> parse -> UnknownPaymentFormat.
     *
     * PURE-ONLY PHP: the profile floor is level 3 (ML-DSA), so a pure-Ed25519 (level-0) object is
     * correctly floored (ProfileDowngrade); an ML-DSA object is refused at the signature step (the pure
     * port cannot verify ML-DSA) rather than passed silently.
     */
    public static function verifyPaymentImport(string $obj, int $profile, int $alg, string $pubkey): PaymentImport
    {
        try {
            [$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
        } catch (\Throwable $e) {
            throw new PayError("PayMalformed", "not a tagged COSE_Sign1");
        }
        $halg = self::algFromProtected($prot);
        [$level, $known] = Cose::algLevel($halg);
        if (!$known) {
            throw new PayError("UnknownAlg", "algorithm id not in the N-AALP registry");
        }
        if ($level < Cose::profileMinLevel($profile)) {
            throw new PayError("ProfileDowngrade", "signature level below the profile minimum");
        }
        if ($halg !== $alg) {
            throw new PayError("KeyAlgMismatch", "key algorithm does not match object header");
        }
        if (!self::verifySignature($halg, $pubkey, Cose::toBeSignedRaw($prot, $payload), $sig)) {
            throw new PayError("BadSignature", "signature verification failed");
        }
        $p = self::parsePaymentImport($payload);
        if (!self::isRegisteredFormat($p->format)) {
            throw new PayError("UnknownPaymentFormat", "payment import selects a format outside the closed payment-format registry");
        }
        return $p;
    }

    /**
     * Verify the signature over the ToBeSigned bytes. Ed25519 is verified with real crypto; ML-DSA
     * verification is unavailable on the pure PHP port, so it is refused (fail-closed) rather than
     * assumed valid. This branch is reachable only for a level-3+ object, which passes the floor.
     */
    private static function verifySignature(int $alg, string $pubkey, string $tbs, string $sig): bool
    {
        if ($alg === Cose::ALG_ED25519) {
            return Cose::ed25519Verify($pubkey, $tbs, $sig);
        }
        throw new \RuntimeException("ML-DSA signature verification is unavailable on the pure PHP port");
    }

    /**
     * AuthorizeCharge (Go impl/go/payment/payment.go:241) enforces the value-bearing rule for an
     * imported payment, reusing the §7 approval and single-use consume ledger UNCHANGED
     * (Naalp\Approval, Naalp\Ledger). The approval MUST bind the EXACT charge binding content id
     * (format + amount + currency + payee + expiry + foreign_id) — so it satisfies neither a different
     * amount/payee/currency nor a substituted foreign payload (ApprovalMismatch, thrown by
     * Approval::verifyApproval) — its granted effect must cover the charge's CHARGE_EFFECT (a
     * non_idempotent_write; ApprovalRequired if under-granting), it must be unexpired at $now
     * (ApprovalExpired) and correctly signed (BadSignature), and it is consumed single-use by $by
     * through the §7 ledger. Precedence and fail-closed behaviour mirror the spine: the format
     * registration is checked FIRST (UnknownPaymentFormat, no ledger append) — an unknown imported
     * format is not chargeable regardless of what approval is presented; a non-matching or
     * under-granting approval denies with no ledger append; an already-spent approval denies
     * AlreadyConsumed; the consume (the single state change) happens only when every check holds.
     * $approverVerify is `fn(string $msg, string $sig): bool` — the injected signature verifier
     * (Ed25519 on the pure PHP port), matching Approval::verifyApproval's convention. Returns the
     * ledger entry on success.
     */
    public static function authorizeCharge(PaymentImport $p, ApprovalRecord $appr, callable $approverVerify, string $apprSig, string $by, int $now, Ledger $ledger): LedgerEntry
    {
        if (!self::isRegisteredFormat($p->format)) {
            throw new PayError("UnknownPaymentFormat", "payment import selects a format outside the closed payment-format registry");
        }
        $chargeCid = $p->chargeBinding()->contentId();
        // ApprovalMismatch (wrong amount/payee/currency/payload) / ApprovalExpired / BadSignature:
        Approval::verifyApproval($appr, $approverVerify, $apprSig, $chargeCid, $now);
        if (!Policy::authorizes($appr->grant, self::CHARGE_EFFECT)) {
            throw new ApprovalRequired("the approval's granted effect does not cover the charge");
        }
        return $ledger->consume($appr->id(), $by); // AlreadyConsumed on replay — single-use, no double-spend
    }

    /** Return the map value for key $k if present with type $class, else null. */
    private static function field(M $m, int $k, string $class): mixed
    {
        foreach ($m->pairs as $pair) {
            [$key, $val] = $pair;
            if ($key instanceof U && $key->v === $k) {
                return $val instanceof $class ? $val : null;
            }
        }
        return null;
    }
}
