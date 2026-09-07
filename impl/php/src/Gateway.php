<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C21 portable gateway-decision object for the PHP SDK (design.md §24; R-GW-1..6).
 *
 * A GatewayDecision is a SIGNED decision object an enforcement gateway of ANY vendor emits as
 * PORTABLE EVIDENCE that it decided about an action. Its load-bearing property, exactly as the C18
 * signed description, is that authority lives in the SIGNED BYTES, never in the connection or the
 * host that served them: verifyDecision takes NO serving-party/connection identity, so the same
 * signed decision RE-VERIFIES IDENTICALLY when a party OTHER than the gateway serves it (the
 * third-party re-serve property). It introduces NO new envelope, encoding, signature, identity, or
 * audit mechanism: the object is an ordinary signed N-AALP body (COSE_Sign1), reusing the closed C5
 * effect lattice and the T1 content-id framing unchanged. This is the EVIDENCE FORMAT ONLY — never a
 * policy language. Every check is fail-closed: a failing object is rejected whole, returns its named
 * error, and causes no state change.
 *
 * An independent transcription of impl/go/gateway, graded against the shared vectors/gateway/cases.json.
 *
 * CRYPTO SCOPE (PURE-ONLY): the corpus-graded deliverable — the deterministic body/head/content-id,
 * the closed decision set, and the strict-decoder rejections — is pure and complete here. PHP cannot
 * deterministically sign or verify ML-DSA (FIPS 204); signDecision therefore uses a real Ed25519
 * (RFC 8032) signature to demonstrate the signing binding in isolation. verifyDecision is the full
 * faithful transcription (alg registry + profile floor + signature + closed set); on the pure port
 * its reachable branches are UnknownAlg and ProfileDowngrade (a level-0 Ed25519 object is below the
 * level-3 floor), and it refuses an ML-DSA object rather than fake a verification result.
 */

declare(strict_types=1);

namespace Naalp;

// Named, fail-closed errors; $kind is a stable string mirroring the Go/Rust/Python/Ruby error kinds.
class GwMalformed extends \RuntimeException
{
    public string $kind = "GwMalformed";
}
class UnknownGatewayDecision extends \RuntimeException
{
    public string $kind = "UnknownGatewayDecision";
}
class BadSignature extends \RuntimeException
{
    public string $kind = "BadSignature";
}
// UnknownAlg (an unregistered signature algorithm) is the existing Naalp\UnknownAlg from Identity.php,
// reused unchanged — same kind, same meaning — rather than redeclared.
class ProfileDowngrade extends \RuntimeException
{
    public string $kind = "ProfileDowngrade";
}
class KeyAlgMismatch extends \RuntimeException
{
    public string $kind = "KeyAlgMismatch";
}

// ---- Evidence-record family errors (E6.3 egress + S1 decision-record + S3 checkpoint + R1/R8),
// naalp-error codes 120-129 (NaalpError.php). Named, fail-closed: a failing object is rejected
// whole, returns its named error, and causes no state change.
class UnknownOrderingBasis extends \RuntimeException
{
    public string $kind = "UnknownOrderingBasis";
}
class OrderingDisclosureMalformed extends \RuntimeException
{
    public string $kind = "OrderingDisclosureMalformed";
}
class DecisionMalformed extends \RuntimeException
{
    public string $kind = "DecisionMalformed";
}
class TermDispositionMalformed extends \RuntimeException
{
    public string $kind = "TermDispositionMalformed";
}
// CheckpointMalformed is shared across all THREE checkpoint-family bodies (naalp-checkpoint-root,
// naalp-witness-cosign, naalp-inclusion-proof) -- only the message differs, mirroring the
// Go/Python/Rust reference exactly.
class CheckpointMalformed extends \RuntimeException
{
    public string $kind = "CheckpointMalformed";
}
class WitnessRootMismatch extends \RuntimeException
{
    public string $kind = "WitnessRootMismatch";
}
class InclusionProofInvalid extends \RuntimeException
{
    public string $kind = "InclusionProofInvalid";
}
class ForeignProfileMalformed extends \RuntimeException
{
    public string $kind = "ForeignProfileMalformed";
}
class EgMalformed extends \RuntimeException
{
    public string $kind = "EgMalformed";
}
class UnknownEgressBinding extends \RuntimeException
{
    public string $kind = "UnknownEgressBinding";
}

/**
 * A signed decision an enforcement gateway emits as portable evidence. `decision` is the closed-set
 * outcome; `action` is the content id of the action decided about; `policy` is the opaque
 * deciding-policy identity (a name, not a program); `effect` is the action's C5 class. `ordering`
 * (field 5, R1) and `foreignProfile` (field 6, R8) are OPTIONAL: null reads exactly as an absent
 * field (correspondence-only ordering / no foreign-profile pin) -- never a stronger claim inferred
 * from silence.
 */
final class GatewayDecision
{
    public int $decision;
    public string $action;
    public string $policy;
    public int $effect;
    public ?OrderingDisclosure $ordering;
    public ?ForeignProfilePin $foreignProfile;

    public function __construct(
        int $decision,
        string $action,
        string $policy,
        int $effect,
        ?OrderingDisclosure $ordering = null,
        ?ForeignProfilePin $foreignProfile = null
    ) {
        $this->decision = $decision;
        $this->action = $action;
        $this->policy = $policy;
        $this->effect = $effect;
        $this->ordering = $ordering;
        $this->foreignProfile = $foreignProfile;
    }

    /** Deterministic-CBOR encoding {1: decision, 2: action, 3: policy, 4: effect, ?5: ordering,
     * ?6: foreign-profile}. Fields 5/6 are OMITTED entirely when null (the same omit-when-absent
     * precedent as naalp-decision-record's optional fields 3/6/7). */
    public function bytes(): string
    {
        $pairs = [
            [new U(1), new U($this->decision)],
            [new U(2), new B($this->action)],
            [new U(3), new B($this->policy)],
            [new U(4), new U($this->effect)],
        ];
        if ($this->ordering !== null) {
            $pairs[] = [new U(5), $this->ordering->toCbor()];
        }
        if ($this->foreignProfile !== null) {
            $pairs[] = [new U(6), $this->foreignProfile->toCbor()];
        }
        return Cbor::encode(new M($pairs));
    }

    /** The decision's SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The decision's T1 content-id: multihash(0x20, 0x30 [48]) || SHA-384(body) (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }

    /** The C5 effect class, normalized fail-closed: an unrecognized value is destructive (R-6.2). */
    public function effectClass(): int
    {
        return Policy::normalizeEffect($this->effect);
    }
}

/**
 * A GatewayDecision that has passed signature verification. It carries NOTHING about who served the
 * bytes — the authority is the signature, so the resolved evidence is identical regardless of the
 * serving party (the third-party re-serve property).
 */
final class ResolvedDecision
{
    public int $decision;
    public string $action;
    public string $policy;
    public int $effect;

    public function __construct(int $decision, string $action, string $policy, int $effect)
    {
        $this->decision = $decision;
        $this->action = $action;
        $this->policy = $policy;
        $this->effect = $effect;
    }
}

final class Gateway
{
    /** The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain. */
    public const HEAD_SIZE = 48;

    // The closed set a gateway may emit; a code outside the set is rejected (UnknownGatewayDecision).
    public const DECISION_ALLOW = 0; // the gateway allows the action
    public const DECISION_DENY = 1;  // the gateway denies the action
    public const DECISION_HOLD = 2;  // the gateway holds the action pending a further step

    /** decision code => name (diagnostics); an unknown code has no entry. */
    private const DECISION_NAMES = [
        self::DECISION_ALLOW => "allow",
        self::DECISION_DENY => "deny",
        self::DECISION_HOLD => "hold",
    ];

    /** Reports whether code is one of the closed decision codes. */
    public static function isKnownDecision(int $code): bool
    {
        return \array_key_exists($code, self::DECISION_NAMES);
    }

    /** The decision name, or "unknown". */
    public static function decisionName(int $code): string
    {
        return self::DECISION_NAMES[$code] ?? "unknown";
    }

    // ---- Evidence-record family shared vocabularies (design.md §26.3/§26.4) -----------------------

    // Ordering-basis codes -- the closed set (design.md §26.3).
    public const ORDERING_CORRESPONDENCE_ONLY = 0; // the record orders only its own two-party construction (the weakest claim)
    public const ORDERING_SINGLE_BOUNDARY = 1;     // one boundary observed both terms and is named
    public const ORDERING_EXTERNAL_MECHANISM = 2;  // an external sequencing mechanism is named

    /** ordering-basis code => name (diagnostics); an unknown code has no entry. */
    private const ORDERING_BASIS_NAMES = [
        self::ORDERING_CORRESPONDENCE_ONLY => "correspondence-only",
        self::ORDERING_SINGLE_BOUNDARY => "single-boundary",
        self::ORDERING_EXTERNAL_MECHANISM => "external-mechanism",
    ];

    /** Reports whether code is one of the closed ordering-basis codes. */
    public static function isKnownOrderingBasis(int $code): bool
    {
        return \array_key_exists($code, self::ORDERING_BASIS_NAMES);
    }

    /** The ordering-basis name, or "unknown". */
    public static function orderingBasisName(int $code): string
    {
        return self::ORDERING_BASIS_NAMES[$code] ?? "unknown";
    }

    /** The weakest ordering-disclosure claim, exactly what a verifier reads for an absent optional
     * ordering-disclosure field. */
    public static function correspondenceOnly(): OrderingDisclosure
    {
        return new OrderingDisclosure(self::ORDERING_CORRESPONDENCE_ONLY);
    }

    // Enforcement-disposition codes -- the closed set (design.md §26.4).
    public const ENFORCEMENT_ENFORCED = 1; // the producer states it actually enforces this outcome
    public const ENFORCEMENT_ADVISED = 2;  // the producer's own unverifiable self-account that it only advises

    // Term-disposition kind codes -- reused unchanged from the §2.5.4 producing-boundary kind vocabulary.
    public const TERM_OBSERVED = 1; // the term was observed first-hand
    public const TERM_REPORTED = 2; // the term was reported, relayed from a named source

    // Binding codes -- the closed set an egress attestation may declare (E6.3).
    public const BINDING_CONTENT_BOUND = 0; // digest is the crossed object's T1 content-id
    public const BINDING_CONTENT_FREE = 1;  // digest is a hiding commitment SHA-384(content_id||salt)

    /** binding code => name (diagnostics); an unknown code has no entry. */
    private const BINDING_NAMES = [
        self::BINDING_CONTENT_BOUND => "content_bound",
        self::BINDING_CONTENT_FREE => "content_free",
    ];

    /** Reports whether code is one of the closed binding codes. */
    public static function isKnownBinding(int $code): bool
    {
        return \array_key_exists($code, self::BINDING_NAMES);
    }

    /** The binding name, or "unknown". */
    public static function bindingName(int $code): string
    {
        return self::BINDING_NAMES[$code] ?? "unknown";
    }

    /**
     * Return the CBOR value paired with U($k) in a decoded map's pairs list, or null if absent.
     * Mirrors the Go embedded-field accessor field(m, k) / Python's _mfield: a key that is not the
     * matching cbor.U simply does not match -- it never causes the whole map to be rejected (and
     * the strict decoder already forbids a duplicate key at every nesting level, so "first match"
     * and "last match" coincide in practice).
     */
    private static function mfield(array $pairs, int $k): mixed
    {
        foreach ($pairs as $pair) {
            [$key, $val] = $pair;
            if ($key instanceof U && $key->v === $k) {
                return $val;
            }
        }
        return null;
    }

    /** Decode a nested ordering-disclosure map value. Returns null on any wrong shape, including
     * an optional key present under the WRONG CBOR type (never silently treated as absent). */
    private static function orderingFromCbor(mixed $v): ?OrderingDisclosure
    {
        if (!($v instanceof M)) {
            return null;
        }
        $basisV = self::mfield($v->pairs, 1);
        if (!($basisV instanceof U)) {
            return null;
        }
        $boundary = $mechanism = $relation = "";
        $v2 = self::mfield($v->pairs, 2);
        if ($v2 !== null) {
            if (!($v2 instanceof B)) {
                return null;
            }
            $boundary = $v2->v;
        }
        $v3 = self::mfield($v->pairs, 3);
        if ($v3 !== null) {
            if (!($v3 instanceof B)) {
                return null;
            }
            $mechanism = $v3->v;
        }
        $v4 = self::mfield($v->pairs, 4);
        if ($v4 !== null) {
            if (!($v4 instanceof B)) {
                return null;
            }
            $relation = $v4->v;
        }
        return new OrderingDisclosure($basisV->v, $boundary, $mechanism, $relation);
    }

    /** Decode a nested term-disposition map value. Returns null on any wrong shape. */
    private static function termDispositionFromCbor(mixed $v): ?TermDisposition
    {
        if (!($v instanceof M)) {
            return null;
        }
        $kindV = self::mfield($v->pairs, 1);
        if (!($kindV instanceof U)) {
            return null;
        }
        $source = "";
        $v2 = self::mfield($v->pairs, 2);
        if ($v2 !== null) {
            if (!($v2 instanceof B)) {
                return null;
            }
            $source = $v2->v;
        }
        return new TermDisposition($kindV->v, $source);
    }

    /** Decode a nested foreign-profile-pin map value. Decode is STRUCTURAL only, mirroring
     * orderingFromCbor: a key present under the WRONG CBOR type fails decode (returns null, never
     * silently treated as absent); a key that is simply ABSENT decodes to the empty string, leaving
     * the mandatory-presence check to validate() (mirroring OrderingDisclosure's own decode/validate
     * split). A key besides 1/2 marks the group's unknownField flag, also caught by validate() —
     * the closed 2-key set is enforced semantically, not by refusing to decode a map that merely
     * carries an extra key. */
    private static function foreignProfileFromCbor(mixed $v): ?ForeignProfilePin
    {
        if (!($v instanceof M)) {
            return null;
        }
        $id = "";
        $v1 = self::mfield($v->pairs, 1);
        if ($v1 !== null) {
            if (!($v1 instanceof T)) {
                return null;
            }
            $id = $v1->v;
        }
        $revision = "";
        $v2 = self::mfield($v->pairs, 2);
        if ($v2 !== null) {
            if (!($v2 instanceof T)) {
                return null;
            }
            $revision = $v2->v;
        }
        $unknown = false;
        foreach ($v->pairs as $pair) {
            [$k, ] = $pair;
            if (!($k instanceof U && ($k->v === 1 || $k->v === 2))) {
                $unknown = true;
                break;
            }
        }
        return new ForeignProfilePin($id, $revision, $unknown);
    }

    /**
     * Reconstruct a GatewayDecision from its body bytes alone. It does NOT validate the decision
     * code against the closed set, the ordering-disclosure's basis-conditioned well-formedness, or
     * the foreign-profile-pin's field well-formedness — those are verifyDecision's job (mirroring
     * the decision-record parse/validate split), so a decision carrying an unknown code, or an
     * ordering/foreign-profile that is structurally decodable but semantically malformed, can be
     * represented (and then rejected). It DOES enforce field-1-4 presence/type and, when field 5/6
     * is PRESENT, that it decodes to the expected CBOR shape: present-with-wrong-type fails here
     * (GwMalformed), never silently treated as absent. Fail-closed on any malformed shape: a
     * non-canonical body, a non-map, or an absent/wrong-typed field 1-4 is GwMalformed.
     */
    public static function parseDecision(string $b): GatewayDecision
    {
        try {
            $v = Cbor::decode($b);
        } catch (NonCanonical $e) {
            throw new GwMalformed("decision body is not well-formed deterministic CBOR");
        }
        if (!($v instanceof M)) {
            throw new GwMalformed("decision body is not a map");
        }
        $dec = self::mfield($v->pairs, 1);
        $action = self::mfield($v->pairs, 2);
        $pol = self::mfield($v->pairs, 3);
        $eff = self::mfield($v->pairs, 4);
        if (!($dec instanceof U) || !($action instanceof B) || !($pol instanceof B) || !($eff instanceof U)) {
            throw new GwMalformed("decision body missing or wrong-typed field 1-4");
        }
        $gd = new GatewayDecision($dec->v, $action->v, $pol->v, $eff->v);
        $ordV = self::mfield($v->pairs, 5);
        if ($ordV !== null) {
            $ordering = self::orderingFromCbor($ordV);
            if ($ordering === null) {
                throw new GwMalformed("field 5 (ordering) is present but malformed");
            }
            $gd->ordering = $ordering;
        }
        $fpV = self::mfield($v->pairs, 6);
        if ($fpV !== null) {
            $fp = self::foreignProfileFromCbor($fpV);
            if ($fp === null) {
                throw new GwMalformed("field 6 (foreign-profile) is present but malformed");
            }
            $gd->foreignProfile = $fp;
        }
        return $gd;
    }

    /** The bare {1: alg} COSE_Sign1 protected header (§4). */
    public static function gatewayProtectedHeader(int $alg): string
    {
        return Cbor::encode(new M([[new U(1), new N($alg)]]));
    }

    /**
     * Produce the tagged COSE_Sign1 object over the decision body, signed by the gateway. PURE-ONLY
     * PHP: the signature is a real Ed25519 (RFC 8032) signature demonstrating the signing binding —
     * the reference signs with ML-DSA, which the pure port cannot reproduce.
     */
    public static function signDecision(GatewayDecision $d, int $alg, string $seed): string
    {
        $prot = self::gatewayProtectedHeader($alg);
        $payload = $d->bytes();
        $sig = Cose::ed25519Sign($seed, Cose::toBeSignedRaw($prot, $payload));
        return Cose::assembleSign1Raw($prot, $payload, $sig);
    }

    /** Read the alg (label 1) value from an encoded protected header. */
    public static function algFromProtected(string $prot): int
    {
        $v = Cbor::decode($prot);
        if (!($v instanceof M)) {
            throw new GwMalformed("protected header is not a map");
        }
        foreach ($v->pairs as $pair) {
            [$k, $val] = $pair;
            if ($k instanceof U && $k->v === 1 && ($val instanceof N || $val instanceof U)) {
                return $val->v;
            }
        }
        throw new GwMalformed("protected header has no alg");
    }

    /**
     * Verify a gateway decision end-to-end and return the resolved evidence. It (1) verifies the
     * signed object under the profile (signature, alg registry, profile floor) against the gateway's
     * key; (2) reconstructs it from the signed bytes; and (3) validates the decision code against the
     * closed set (UnknownGatewayDecision). It takes NO serving-party or connection identity: the
     * authority is the signature over the bytes, so the same obj yields an identical ResolvedDecision
     * whether the gateway or an unrelated third party served it. Any failure returns its named error
     * and resolves nothing (fail-closed).
     *
     * PURE-ONLY PHP: the profile floor is level 3 (ML-DSA), so a pure-Ed25519 (level-0) object is
     * correctly rejected ProfileDowngrade here; an ML-DSA object is refused at the signature step
     * (the pure port cannot verify ML-DSA) rather than passed silently.
     */
    public static function verifyDecision(string $obj, int $profile, int $alg, string $pubkey): ResolvedDecision
    {
        [$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
        $halg = self::algFromProtected($prot);
        [$level, $known] = Cose::algLevel($halg);
        if (!$known) {
            throw new UnknownAlg("unregistered alg $halg");
        }
        if ($level < Cose::profileMinLevel($profile)) {
            throw new ProfileDowngrade("signature level below the profile minimum");
        }
        if ($halg !== $alg) {
            throw new KeyAlgMismatch("alg $halg does not match the verifier key alg $alg");
        }
        if (!self::verifySignature($halg, $pubkey, Cose::toBeSignedRaw($prot, $payload), $sig)) {
            throw new BadSignature("signature does not verify");
        }
        $d = self::parseDecision($payload);
        if (!self::isKnownDecision($d->decision)) {
            throw new UnknownGatewayDecision("decision code {$d->decision} outside the closed set");
        }
        if ($d->ordering !== null) {
            $d->ordering->validate();
        }
        if ($d->foreignProfile !== null) {
            $d->foreignProfile->validate();
        }
        return new ResolvedDecision($d->decision, $d->action, $d->policy, Policy::normalizeEffect($d->effect));
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

    // =============================================================================================
    // Evidence-record family (E6.3 egress-attestation + S1 decision-record + S3 checkpoint +
    // R1/R8 ordering-disclosure / foreign-profile-pin), ported from
    // impl/go/gateway/{ordering,decision_record,checkpoint,egress_attestation}.go; graded against
    // the shared vectors/{decision_record,checkpoint,egress_attestation}/cases.json plus
    // gateway/cases.json's optional_fields{} block.
    //
    // UNLIKE GatewayDecision::signDecision/verifyDecision above (written PURE-ONLY, before MlDsa.php
    // landed), this family signs/verifies with REAL deterministic ML-DSA-65/87 via MlDsa.php
    // (PHP-FFI to OpenSSL >= 3.5), exactly as the Go/Rust/Python reference. signEvidence/
    // verifyEvidenceSignature below are ADDITIVE: they do not alter GatewayDecision's own
    // signDecision/verifyDecision/verifySignature, which keep their pre-existing Ed25519-pure-only
    // wire behaviour unchanged.
    // =============================================================================================

    /** Sign $tbs for $alg with real crypto: ML-DSA-65/87 via MlDsa::sign; Ed25519 via
     * Cose::ed25519Sign. Used by the evidence-record family's sign* functions below. */
    private static function signEvidence(int $alg, string $seed, string $tbs): string
    {
        if ($alg === Cose::ALG_MLDSA65 || $alg === Cose::ALG_MLDSA87) {
            return MlDsa::sign($seed, $tbs, $alg);
        }
        if ($alg === Cose::ALG_ED25519) {
            return Cose::ed25519Sign($seed, $tbs);
        }
        throw new \RuntimeException("unsupported signature alg $alg for the evidence-record family");
    }

    /** Verify $sig over $tbs for $alg with real crypto: ML-DSA-65/87 via MlDsa::verify; Ed25519 via
     * Cose::ed25519Verify. Mirrors signEvidence's alg dispatch. */
    private static function verifyEvidenceSignature(int $alg, string $pubkey, string $tbs, string $sig): bool
    {
        if ($alg === Cose::ALG_MLDSA65 || $alg === Cose::ALG_MLDSA87) {
            return MlDsa::verify($pubkey, $tbs, $sig, $alg);
        }
        if ($alg === Cose::ALG_ED25519) {
            return Cose::ed25519Verify($pubkey, $tbs, $sig);
        }
        throw new \RuntimeException("unsupported signature alg $alg for the evidence-record family");
    }

    // ---- naalp-decision-record: S1, the full governed-decision accountability record ------------
    //
    // A DecisionRecord is the SIGNED record a governed decision point emits that it decided about an
    // action under a CLOSED, uniquely-selected condition set. It carries the T/T+n accountability
    // triple (§26.1): UNIQUE SELECTION (field 2, the governing set in the clear as content ids);
    // GOVERNED-AT-T (field 3, the naalp-consume-receipt spent at decision time); BINDING-FIXED-BY-T
    // (established off-record by inclusion under a witnessed naalp-checkpoint-root). The record is
    // deliberately CLOCK-FREE: it carries no claimed timestamp anywhere in its own body; both time
    // properties are POSITIONAL, never a self-asserted timestamp.
    //
    // Following parseDecision/verifyDecision's split: parseDecisionRecord reconstructs the record
    // from its body bytes ALONE and performs only STRUCTURAL checks (field presence and CBOR type);
    // it does NOT validate the outcome against the closed gw-decision set, the ordering disclosure's
    // well-formedness, the deny/hold-with-consume rule, or the terms key set -- those are
    // validateDecisionRecord's job.

    /**
     * Reconstruct a DecisionRecord from its body bytes alone. It performs ONLY structural checks
     * (mandatory-field presence and CBOR type); it does NOT validate the outcome against the closed
     * gw-decision set, the ordering disclosure's basis-conditioned well-formedness, the
     * deny/hold-with-consume rule, or the terms key set -- see validateDecisionRecord. Fail-closed
     * on any malformed shape (DecisionMalformed).
     */
    public static function parseDecisionRecord(string $b): DecisionRecord
    {
        try {
            $v = Cbor::decode($b);
        } catch (NonCanonical $e) {
            throw new DecisionMalformed("decision-record body is not well-formed deterministic CBOR");
        }
        if (!($v instanceof M)) {
            throw new DecisionMalformed("decision-record body is not a map");
        }
        $action = self::mfield($v->pairs, 1);
        $govV = self::mfield($v->pairs, 2);
        if (!($action instanceof B) || !($govV instanceof A)) {
            throw new DecisionMalformed("missing or wrong-typed field 1/2");
        }
        $governing = [];
        foreach ($govV->items as $e) {
            if (!($e instanceof B)) {
                throw new DecisionMalformed("governing array element not a bstr");
            }
            $governing[] = $e->v;
        }
        $consume = "";
        $consumeV = self::mfield($v->pairs, 3);
        if ($consumeV !== null) {
            if (!($consumeV instanceof B)) {
                throw new DecisionMalformed("field 3 (consume) wrong type");
            }
            $consume = $consumeV->v;
        }
        $outcomeV = self::mfield($v->pairs, 4);
        if (!($outcomeV instanceof U)) {
            throw new DecisionMalformed("missing or wrong-typed field 4 (outcome)");
        }
        $ordV = self::mfield($v->pairs, 5);
        if ($ordV === null) {
            throw new DecisionMalformed("missing mandatory field 5 (ordering)");
        }
        $ordering = self::orderingFromCbor($ordV);
        if ($ordering === null) {
            throw new DecisionMalformed("field 5 (ordering) malformed");
        }
        $terms = [];
        $termsV = self::mfield($v->pairs, 6);
        if ($termsV !== null) {
            if (!($termsV instanceof M)) {
                throw new DecisionMalformed("field 6 (terms) wrong type");
            }
            foreach ($termsV->pairs as $pair) {
                [$k, $val] = $pair;
                if (!($k instanceof U)) {
                    throw new DecisionMalformed("terms map key not a uint");
                }
                $td = self::termDispositionFromCbor($val);
                if ($td === null) {
                    throw new DecisionMalformed("terms map value malformed");
                }
                $terms[$k->v] = $td;
            }
        }
        $enforcement = 0;
        $enfV = self::mfield($v->pairs, 7);
        if ($enfV !== null) {
            if (!($enfV instanceof U)) {
                throw new DecisionMalformed("field 7 (enforcement) wrong type");
            }
            $enforcement = $enfV->v;
        }
        return new DecisionRecord($action->v, $governing, $outcomeV->v, $ordering, $consume, $terms, $enforcement);
    }

    /** Reports whether k is one of the record's own field numbers 1..5 -- the only valid keys for
     * the field-6 terms map (design.md §26.4; TermDispositionMalformed otherwise). */
    private static function validDecisionRecordTermKey(int $k): bool
    {
        return $k >= 1 && $k <= 5;
    }

    /**
     * Performs the semantic, closed-set, and native well-formedness checks parseDecisionRecord
     * deliberately does not (mirroring verifyDecision's parse/validate split):
     *
     * 1. Outcome must be in the closed gw-decision set (UnknownGatewayDecision).
     * 2. Ordering must satisfy its basis-conditioned well-formedness rule (UnknownOrderingBasis /
     *    OrderingDisclosureMalformed) -- checked BEFORE the deny/hold-consume rule so a record
     *    whose ordering is itself malformed is never additionally reported as a consume violation.
     * 3. A deny/hold outcome carrying a field-3 consume reference is rejected in full
     *    (DecisionMalformed) -- nothing was consumed, so a value here would assert authority spent
     *    for an action the record's own outcome says was not taken.
     * 4. Every terms map key must be one of the record's own field numbers 1..5
     *    (TermDispositionMalformed).
     */
    public static function validateDecisionRecord(DecisionRecord $d): void
    {
        if (!self::isKnownDecision($d->outcome)) {
            throw new UnknownGatewayDecision("decision-record outcome {$d->outcome} outside the closed set");
        }
        $d->ordering->validate();
        if ($d->outcome !== self::DECISION_ALLOW && $d->consume !== "") {
            throw new DecisionMalformed("a deny/hold outcome must not carry a field-3 consume reference");
        }
        foreach (\array_keys($d->terms) as $k) {
            if (!self::validDecisionRecordTermKey($k)) {
                throw new TermDispositionMalformed("a terms map key is outside the record's own field set 1..5");
            }
        }
    }

    /** Produce the tagged COSE_Sign1 object over the record body, signed by the governed decision
     * point. */
    public static function signDecisionRecord(DecisionRecord $d, int $alg, string $seed): string
    {
        $prot = self::gatewayProtectedHeader($alg);
        $payload = $d->bytes();
        $sig = self::signEvidence($alg, $seed, Cose::toBeSignedRaw($prot, $payload));
        return Cose::assembleSign1Raw($prot, $payload, $sig);
    }

    /**
     * Verify a decision record end-to-end: (1) the signed object under the profile with real
     * crypto; (2) structural reconstruction (parseDecisionRecord); and (3) full semantic
     * validation (validateDecisionRecord). It takes no serving-party or connection identity -- the
     * authority is the signature over the bytes, mirroring verifyDecision. Any failure throws its
     * named error and resolves nothing (fail-closed).
     */
    public static function verifyDecisionRecord(string $obj, int $profile, int $alg, string $pubkey): ResolvedDecisionRecord
    {
        [$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
        $halg = self::algFromProtected($prot);
        [$level, $known] = Cose::algLevel($halg);
        if (!$known) {
            throw new UnknownAlg("unregistered alg $halg");
        }
        if ($level < Cose::profileMinLevel($profile)) {
            throw new ProfileDowngrade("signature level below the profile minimum");
        }
        if ($halg !== $alg) {
            throw new KeyAlgMismatch("alg $halg does not match the verifier key alg $alg");
        }
        if (!self::verifyEvidenceSignature($halg, $pubkey, Cose::toBeSignedRaw($prot, $payload), $sig)) {
            throw new BadSignature("signature does not verify");
        }
        $d = self::parseDecisionRecord($payload);
        self::validateDecisionRecord($d);
        return new ResolvedDecisionRecord(
            $d->action,
            $d->governing,
            $d->consume,
            $d->outcome,
            $d->ordering,
            $d->terms,
            $d->enforcement
        );
    }

    // ---- naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof: S3 -------------------
    //
    // S3 is the neither-party anchor for the BINDING-FIXED-BY-T leg of the accountability triple
    // (design.md §26.5). Tree construction follows RFC 9162
    // (https://www.rfc-editor.org/rfc/rfc9162.html) §2.1 EXACTLY, SHA-384-profiled: leaf hash =
    // HASH(0x00 || leaf); interior node hash = HASH(0x01 || left || right); MTH({}) = HASH() (the
    // empty hash); MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for
    // the largest power of two k < n. §2.1.2's PATH(m, D[n]) recursion (leaf-to-root sibling order)
    // generates the audit path; §2.1.3.1's inverse recursion recomputes the root from
    // (leaf, index, size, path) and compares against the named root (InclusionProofInvalid on
    // mismatch, fail-closed).

    /** The HEAD_SIZE all-zero prev value a log's first checkpoint chains from. */
    public static function genesisPrev(): string
    {
        return \str_repeat("\x00", self::HEAD_SIZE);
    }

    /** Reconstruct a CheckpointRoot from its body bytes alone. Fail-closed on any malformed shape
     * (CheckpointMalformed): every one of the five fields is mandatory. */
    public static function parseCheckpointRoot(string $b): CheckpointRoot
    {
        try {
            $v = Cbor::decode($b);
        } catch (NonCanonical $e) {
            throw new CheckpointMalformed("checkpoint-root body is not well-formed deterministic CBOR");
        }
        if (!($v instanceof M)) {
            throw new CheckpointMalformed("checkpoint-root body is not a map");
        }
        $log = self::mfield($v->pairs, 1);
        $size = self::mfield($v->pairs, 2);
        $root = self::mfield($v->pairs, 3);
        $prev = self::mfield($v->pairs, 4);
        $at = self::mfield($v->pairs, 5);
        if (!($log instanceof B) || !($size instanceof U) || !($root instanceof B)
            || !($prev instanceof B) || !($at instanceof U)) {
            throw new CheckpointMalformed("missing or wrong-typed field 1-5");
        }
        return new CheckpointRoot($log->v, $size->v, $root->v, $prev->v, $at->v);
    }

    /** Produce the tagged COSE_Sign1 object over the checkpoint body, signed by the log operator. */
    public static function signCheckpointRoot(CheckpointRoot $c, int $alg, string $seed): string
    {
        $prot = self::gatewayProtectedHeader($alg);
        $payload = $c->bytes();
        $sig = self::signEvidence($alg, $seed, Cose::toBeSignedRaw($prot, $payload));
        return Cose::assembleSign1Raw($prot, $payload, $sig);
    }

    /** Reconstruct a WitnessCosign from its body bytes alone. Fail-closed on any malformed shape:
     * every one of the three fields is mandatory. */
    public static function parseWitnessCosign(string $b): WitnessCosign
    {
        try {
            $v = Cbor::decode($b);
        } catch (NonCanonical $e) {
            throw new CheckpointMalformed("witness-cosign body is not well-formed deterministic CBOR");
        }
        if (!($v instanceof M)) {
            throw new CheckpointMalformed("witness-cosign body is not a map");
        }
        $witness = self::mfield($v->pairs, 1);
        $root = self::mfield($v->pairs, 2);
        $at = self::mfield($v->pairs, 3);
        if (!($witness instanceof B) || !($root instanceof B) || !($at instanceof U)) {
            throw new CheckpointMalformed("missing or wrong-typed field 1-3");
        }
        return new WitnessCosign($witness->v, $root->v, $at->v);
    }

    /** Produce the tagged COSE_Sign1 object over the cosign body, signed by the witness. */
    public static function signWitnessCosign(WitnessCosign $w, int $alg, string $seed): string
    {
        $prot = self::gatewayProtectedHeader($alg);
        $payload = $w->bytes();
        $sig = self::signEvidence($alg, $seed, Cose::toBeSignedRaw($prot, $payload));
        return Cose::assembleSign1Raw($prot, $payload, $sig);
    }

    /** Checks that w names the EXACT checkpoint it accompanies (WitnessRootMismatch, design.md
     * §26.5): w->root must equal $accompaniedCheckpointId, the content id of the
     * naalp-checkpoint-root object w claims to cosign. Fail-closed. */
    public static function validateWitnessCosign(WitnessCosign $w, string $accompaniedCheckpointId): void
    {
        if ($w->root !== $accompaniedCheckpointId) {
            throw new WitnessRootMismatch(
                "witness-cosign names a root content id that does not match the checkpoint it accompanies"
            );
        }
    }

    /** Reconstruct an InclusionProof from its body bytes alone. Fail-closed on any malformed shape:
     * every one of the four fields is mandatory. */
    public static function parseInclusionProof(string $b): InclusionProof
    {
        try {
            $v = Cbor::decode($b);
        } catch (NonCanonical $e) {
            throw new CheckpointMalformed("inclusion-proof body is not well-formed deterministic CBOR");
        }
        if (!($v instanceof M)) {
            throw new CheckpointMalformed("inclusion-proof body is not a map");
        }
        $root = self::mfield($v->pairs, 1);
        $leaf = self::mfield($v->pairs, 2);
        $index = self::mfield($v->pairs, 3);
        $pathV = self::mfield($v->pairs, 4);
        if (!($root instanceof B) || !($leaf instanceof B) || !($index instanceof U) || !($pathV instanceof A)) {
            throw new CheckpointMalformed("missing or wrong-typed field 1-4");
        }
        $path = [];
        foreach ($pathV->items as $e) {
            if (!($e instanceof B)) {
                throw new CheckpointMalformed("path array element not a bstr");
            }
            $path[] = $e->v;
        }
        return new InclusionProof($root->v, $leaf->v, $index->v, $path);
    }

    // ---- RFC 9162 §2.1 Merkle tree math (SHA-384-profiled) -----------------------------------------

    /** leaf_hash = HASH(0x00 || leaf) (RFC 9162 §2.1's LEAF_HASH, leaf/interior domain separation). */
    private static function leafHash(string $leaf): string
    {
        return \hash('sha384', "\x00" . $leaf, true);
    }

    /** node_hash = HASH(0x01 || left || right) (RFC 9162 §2.1's NODE_HASH). */
    private static function nodeHash(string $l, string $r): string
    {
        return \hash('sha384', "\x01" . $l . $r, true);
    }

    /** The largest power of two strictly less than n (n > 1), per RFC 9162 §2.1's
     * k = "the largest power of two smaller than n". */
    private static function largestPowerOfTwoLessThan(int $n): int
    {
        $k = 1;
        while (2 * $k < $n) {
            $k *= 2;
        }
        return $k;
    }

    /**
     * Computes MTH(leaves) per RFC 9162 §2.1: MTH({}) = HASH() (SHA-384 of the empty string);
     * MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the largest
     * power of two k < n. $leaves are raw leaf VALUES (record content ids); LEAF_HASH is applied
     * internally -- callers never hash a leaf before calling merkleRoot. `$leaves = null` is
     * accepted as the empty list (mirroring Go's nil-slice-len-0 / Python's None semantics).
     *
     * @param array<int,string>|null $leaves
     */
    public static function merkleRoot(?array $leaves): string
    {
        $n = $leaves === null ? 0 : \count($leaves);
        if ($n === 0) {
            return \hash('sha384', '', true); // MTH({}) = HASH(""), the empty-list base case
        }
        if ($n === 1) {
            return self::leafHash($leaves[0]);
        }
        $k = self::largestPowerOfTwoLessThan($n);
        return self::nodeHash(
            self::merkleRoot(\array_slice($leaves, 0, $k)),
            self::merkleRoot(\array_slice($leaves, $k))
        );
    }

    /**
     * Computes the RFC 9162 §2.1.2 PATH(index, leaves) audit path (leaf-to-root sibling order --
     * the array's FIRST entry is the leaf's immediate sibling, the LAST is closest to the root,
     * exactly the order naalp-inclusion-proof's `path` field carries).
     *
     * @param array<int,string> $leaves
     * @return array<int,string>
     */
    public static function generateInclusionProofPath(array $leaves, int $index): array
    {
        if ($index < 0 || $index >= \count($leaves)) {
            throw new InclusionProofInvalid("leaf index out of range");
        }
        return self::genPath($leaves, $index);
    }

    /** @param array<int,string> $leaves
     * @return array<int,string> */
    private static function genPath(array $leaves, int $index): array
    {
        $n = \count($leaves);
        if ($n <= 1) {
            return []; // PATH(0, {d0}) = {} -- the single-leaf base case
        }
        $k = self::largestPowerOfTwoLessThan($n);
        if ($index < $k) {
            $sub = self::genPath(\array_slice($leaves, 0, $k), $index);
            $sub[] = self::merkleRoot(\array_slice($leaves, $k));
            return $sub;
        }
        $sub = self::genPath(\array_slice($leaves, $k), $index - $k);
        $sub[] = self::merkleRoot(\array_slice($leaves, 0, $k));
        return $sub;
    }

    /** The exact structural inverse of genPath: at each level it consumes the LAST remaining path
     * entry (closest to the root) as this level's sibling and recurses into the appropriate half
     * with the entries that remain. Throws InclusionProofInvalid on any path-length mismatch.
     *
     * @param array<int,string> $path
     */
    private static function recomputeRoot(string $leafH, int $index, int $size, array $path): string
    {
        if ($size === 1) {
            if (\count($path) !== 0) {
                throw new InclusionProofInvalid("inclusion path length does not match the claimed tree size");
            }
            return $leafH;
        }
        if (\count($path) === 0) {
            throw new InclusionProofInvalid("inclusion path length does not match the claimed tree size");
        }
        $k = self::largestPowerOfTwoLessThan($size);
        $last = $path[\count($path) - 1];
        $rest = \array_slice($path, 0, \count($path) - 1);
        if ($index < $k) {
            $left = self::recomputeRoot($leafH, $index, $k, $rest);
            return self::nodeHash($left, $last);
        }
        $right = self::recomputeRoot($leafH, $index - $k, $size - $k, $rest);
        return self::nodeHash($last, $right);
    }

    /**
     * Recomputes the audit path bottom-up (RFC 9162 §2.1.3.1, the inverse of PATH()) from
     * (leaf, index, size, path) and compares the result against root. `$size` is the tree size the
     * proof is checked against -- the resolved naalp-checkpoint-root's own `size` field, NOT
     * carried inside naalp-inclusion-proof itself. Fail-closed: any mismatch, out-of-range index,
     * or path-length mismatch is InclusionProofInvalid.
     *
     * @param array<int,string> $path
     */
    public static function verifyInclusionProof(string $leaf, int $index, int $size, array $path, string $root): void
    {
        if ($size === 0 || $index >= $size) {
            throw new InclusionProofInvalid("index out of range for the claimed tree size");
        }
        $got = self::recomputeRoot(self::leafHash($leaf), $index, $size, $path);
        if ($got !== $root) {
            throw new InclusionProofInvalid("inclusion audit path does not recompute to the named root");
        }
    }

    // ---- naalp-egress-attestation: E6.3 --------------------------------------------------------------
    //
    // A naalp-egress-attestation is a SIGNED attestation a gateway/sidecar emits that an object of a
    // given effect class, bound to a given audience, crossed an egress boundary at a given time --
    // third-party verifiable WITHOUT the payload. `binding` is a closed set (content_bound/
    // content_free); `digest` is either the T1 content-id of the crossed object (content_bound) or
    // a hiding commitment SHA-384(content_id||salt) (content_free) -- never both; `effect` is the
    // C5 effect class of the crossed object; `audience` is the bound destination (empty-permitted);
    // `at` is the crossing time in epoch milliseconds. Field 6 (`ordering`) is OPTIONAL: ABSENT
    // reads correspondence-only, never a stronger claim inferred from silence.

    /** Reconstruct an EgressAttestation from its body bytes alone. It does NOT validate the binding
     * code against the closed set -- that is verifyEgressAttestation's job -- so an attestation
     * carrying an unknown binding can be represented (and then rejected). Fail-closed on a
     * malformed shape: every one of the five mandatory fields is required, and a present-but-
     * wrong-typed field 6 fails here too. */
    public static function parseEgressAttestation(string $b): EgressAttestation
    {
        try {
            $v = Cbor::decode($b);
        } catch (NonCanonical $e) {
            throw new EgMalformed("egress-attestation body is not well-formed deterministic CBOR");
        }
        if (!($v instanceof M)) {
            throw new EgMalformed("egress-attestation body is not a map");
        }
        $binding = self::mfield($v->pairs, 1);
        $digest = self::mfield($v->pairs, 2);
        $effect = self::mfield($v->pairs, 3);
        $audience = self::mfield($v->pairs, 4);
        $at = self::mfield($v->pairs, 5);
        if (!($binding instanceof U) || !($digest instanceof B) || !($effect instanceof U)
            || !($audience instanceof B) || !($at instanceof U)) {
            throw new EgMalformed("missing or wrong-typed field 1-5");
        }
        $ordering = null;
        $ordV = self::mfield($v->pairs, 6);
        if ($ordV !== null) {
            $ordering = self::orderingFromCbor($ordV);
            if ($ordering === null) {
                throw new EgMalformed("field 6 (ordering) is present but malformed");
            }
        }
        return new EgressAttestation($binding->v, $digest->v, $effect->v, $audience->v, $at->v, $ordering);
    }

    /** Produce the tagged COSE_Sign1 object over the attestation body, signed by the gateway. */
    public static function signEgressAttestation(EgressAttestation $a, int $alg, string $seed): string
    {
        $prot = self::gatewayProtectedHeader($alg);
        $payload = $a->bytes();
        $sig = self::signEvidence($alg, $seed, Cose::toBeSignedRaw($prot, $payload));
        return Cose::assembleSign1Raw($prot, $payload, $sig);
    }

    /** Performs the semantic, closed-set checks parseEgressAttestation deliberately does not: the
     * binding must be in the closed set (UnknownEgressBinding), and -- if present -- the field-6
     * ordering disclosure must satisfy its basis-conditioned well-formedness rule. */
    public static function validateEgressAttestation(EgressAttestation $a): void
    {
        if (!self::isKnownBinding($a->binding)) {
            throw new UnknownEgressBinding(
                "egress attestation binding code is outside the closed set content_bound/content_free"
            );
        }
        if ($a->ordering !== null) {
            $a->ordering->validate();
        }
    }

    /**
     * Verifies an egress attestation end-to-end and returns the resolved evidence. It (1) verifies
     * the signed object under the profile with real crypto against the GATEWAY's key; (2)
     * reconstructs it from the signed bytes; and (3) validates the binding code against the closed
     * set (UnknownEgressBinding), and the ordering disclosure if present. It takes NO serving-party
     * or connection identity: the authority is the signature over the bytes, so the same `$obj`
     * yields an identical ResolvedEgressAttestation whether the gateway or an unrelated third party
     * served it (the third-party re-serve property). Any failure throws its named error and
     * resolves nothing (fail-closed).
     */
    public static function verifyEgressAttestation(string $obj, int $profile, int $alg, string $pubkey): ResolvedEgressAttestation
    {
        [$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
        $halg = self::algFromProtected($prot);
        [$level, $known] = Cose::algLevel($halg);
        if (!$known) {
            throw new UnknownAlg("unregistered alg $halg");
        }
        if ($level < Cose::profileMinLevel($profile)) {
            throw new ProfileDowngrade("signature level below the profile minimum");
        }
        if ($halg !== $alg) {
            throw new KeyAlgMismatch("alg $halg does not match the verifier key alg $alg");
        }
        if (!self::verifyEvidenceSignature($halg, $pubkey, Cose::toBeSignedRaw($prot, $payload), $sig)) {
            throw new BadSignature("signature does not verify");
        }
        $a = self::parseEgressAttestation($payload);
        self::validateEgressAttestation($a);
        return new ResolvedEgressAttestation(
            $a->binding,
            $a->digest,
            Policy::normalizeEffect($a->effect),
            $a->audience,
            $a->at,
            $a->ordering
        );
    }

    // ---- content_free commitment open/verify pair --------------------------------------------------

    /** The content_free hiding commitment over an object's T1 content-id and a salt:
     * SHA-384(objectCid || salt) (48 octets). */
    public static function egressCommit(string $objectCid, string $salt): string
    {
        return \hash('sha384', $objectCid . $salt, true);
    }

    /** Proves which object crossed under a content_free attestation. Recomputes
     * egressCommit(objectCid, salt) and compares it, in constant time, against $a->digest. Returns
     * true iff $a is a content_free attestation AND the recomputed commitment matches: a wrong salt
     * or a wrong objectCid both fail to open (return false), and a content_bound attestation never
     * opens (its digest is not a commitment). */
    public static function openEgressCommitment(EgressAttestation $a, string $objectCid, string $salt): bool
    {
        if ($a->binding !== self::BINDING_CONTENT_FREE) {
            return false;
        }
        $want = self::egressCommit($objectCid, $salt);
        if (\strlen($want) !== \strlen($a->digest)) {
            return false;
        }
        return \hash_equals($want, $a->digest);
    }
}

// =================================================================================================
// Evidence-record family value types (design.md §26.3-§26.6), ported from
// impl/go/gateway/{ordering,decision_record,checkpoint,egress_attestation}.go.
// =================================================================================================

/**
 * The embeddable group {1: basis, ?2: boundary, ?3: mechanism, ?4: relation} (design.md §26.3). It
 * is never a top-level signed object; it is always a field inside another record, so it has no
 * head()/id() of its own. The zero value (basis=correspondence-only, no boundary/mechanism/
 * relation) is the weakest claim and is exactly what an ABSENT optional ordering-disclosure field
 * reads as.
 */
final class OrderingDisclosure
{
    public int $basis;
    public string $boundary;
    public string $mechanism;
    public string $relation;

    public function __construct(int $basis, string $boundary = "", string $mechanism = "", string $relation = "")
    {
        $this->basis = $basis;
        $this->boundary = $boundary;
        $this->mechanism = $mechanism;
        $this->relation = $relation;
    }

    /** Return self as a nested CBOR map VALUE (never top-level bytes -- self is always embedded as
     * a field inside its carrying record). */
    public function toCbor(): M
    {
        $pairs = [[new U(1), new U($this->basis)]];
        if ($this->boundary !== "") {
            $pairs[] = [new U(2), new B($this->boundary)];
        }
        if ($this->mechanism !== "") {
            $pairs[] = [new U(3), new B($this->mechanism)];
        }
        if ($this->relation !== "") {
            $pairs[] = [new U(4), new B($this->relation)];
        }
        return new M($pairs);
    }

    /**
     * Checks (a) basis is in the closed set (UnknownOrderingBasis) and (b) the basis-conditioned
     * field well-formedness rule (design.md §26.3, native and fail-closed -- any violation rejects
     * the whole carrying record, OrderingDisclosureMalformed). UnknownOrderingBasis is checked and
     * thrown FIRST: an out-of-set basis is never additionally reported as malformed.
     */
    public function validate(): void
    {
        if (!Gateway::isKnownOrderingBasis($this->basis)) {
            throw new UnknownOrderingBasis(
                "ordering-disclosure basis is outside the closed set "
                . "correspondence-only/single-boundary/external-mechanism"
            );
        }
        if ($this->basis === Gateway::ORDERING_CORRESPONDENCE_ONLY) {
            if ($this->boundary !== "" || $this->mechanism !== "" || $this->relation !== "") {
                throw new OrderingDisclosureMalformed("correspondence-only requires keys 2/3/4 absent");
            }
        } elseif ($this->basis === Gateway::ORDERING_SINGLE_BOUNDARY) {
            if ($this->boundary === "" || $this->mechanism !== "" || $this->relation !== "") {
                throw new OrderingDisclosureMalformed("single-boundary requires key 2 present, keys 3/4 absent");
            }
        } elseif ($this->basis === Gateway::ORDERING_EXTERNAL_MECHANISM) {
            if ($this->boundary !== "" || $this->mechanism === "") {
                throw new OrderingDisclosureMalformed("external-mechanism requires key 2 absent, key 3 present");
            }
        }
    }
}

/**
 * The embeddable group {1: kind, ?2: source} (design.md §26.4). `kind` is carried as a plain uint
 * on the wire (the CDDL does not close its value set the way ordering-basis does), so
 * TermDisposition itself validates no closed set -- only naalp-decision-record's own field-6 key
 * set (the record's own field numbers) is fail-closed (TermDispositionMalformed).
 */
final class TermDisposition
{
    public int $kind;
    public string $source;

    public function __construct(int $kind, string $source = "")
    {
        $this->kind = $kind;
        $this->source = $source;
    }

    public function toCbor(): M
    {
        $pairs = [[new U(1), new U($this->kind)]];
        if ($this->source !== "") {
            $pairs[] = [new U(2), new B($this->source)];
        }
        return new M($pairs);
    }
}

/**
 * The embeddable group {1: id, 2: revision} (naalp-foreign-profile-pin, R8). Present on
 * GatewayDecision field 6 iff the decision was over foreign-protocol evidence: it pins the
 * foreign evidence profile's identifier (an absolute URI) AND the revision pinned at decision
 * time -- binding the reference, not just the class. Both fields are mandatory tstr; the group
 * carries no other keys. It is never a top-level signed object -- always embedded as field 6 of
 * its carrying naalp-gateway-decision, so it has no head()/id() of its own (mirroring
 * OrderingDisclosure).
 */
final class ForeignProfilePin
{
    public string $id;
    public string $revision;
    /** An unrecognized key besides 1/2 was present in the decoded CBOR map. */
    public bool $unknownField;

    public function __construct(string $id = "", string $revision = "", bool $unknownField = false)
    {
        $this->id = $id;
        $this->revision = $revision;
        $this->unknownField = $unknownField;
    }

    /** Return self as a nested CBOR map VALUE {1: tstr(id), 2: tstr(revision)}. */
    public function toCbor(): M
    {
        return new M([
            [new U(1), new T($this->id)],
            [new U(2), new T($this->revision)],
        ]);
    }

    /**
     * Checks the foreign-profile-pin's own well-formedness (R8): both id and revision are
     * mandatory non-empty tstr, and no key besides 1/2 may be present. A missing, empty, or extra
     * field rejects the WHOLE carrying naalp-gateway-decision (ForeignProfileMalformed).
     */
    public function validate(): void
    {
        if ($this->id === "" || $this->revision === "" || $this->unknownField) {
            throw new ForeignProfileMalformed(
                "foreign-profile-pin is not well-formed (id and revision are mandatory tstr, no other keys)"
            );
        }
    }
}

/**
 * The governed-decision accountability record (design.md §26.4, S1). `action` is the content id of
 * the action decided about; `governing` is the closed governing condition set, content ids, in the
 * clear (may be empty); `consume` is OPTIONAL field 3 (content id of the consume-receipt spent at
 * decision time; "" == absent); `outcome` is field 4 (allow/deny/hold, reuses the closed
 * gw-decision set); `ordering` is field 5, MANDATORY (no silent default -- every record states its
 * ordering basis); `terms` is OPTIONAL field 6 (per-term observed/reported, keyed by this record's
 * OWN field numbers 1..5; empty == absent); `enforcement` is OPTIONAL field 7
 * (enforced(1)/advised(2); 0 == absent).
 */
final class DecisionRecord
{
    public string $action;
    /** @var array<int,string> */
    public array $governing;
    public string $consume;
    public int $outcome;
    public OrderingDisclosure $ordering;
    /** @var array<int,TermDisposition> */
    public array $terms;
    public int $enforcement;

    /**
     * @param array<int,string> $governing
     * @param array<int,TermDisposition> $terms
     */
    public function __construct(
        string $action,
        array $governing,
        int $outcome,
        OrderingDisclosure $ordering,
        string $consume = "",
        array $terms = [],
        int $enforcement = 0
    ) {
        $this->action = $action;
        $this->governing = $governing;
        $this->consume = $consume;
        $this->outcome = $outcome;
        $this->ordering = $ordering;
        $this->terms = $terms;
        $this->enforcement = $enforcement;
    }

    /** Deterministic-CBOR encoding {1:action, 2:governing[], ?3:consume, 4:outcome, 5:ordering,
     * ?6:terms, ?7:enforcement}. Fields 3/6/7 are OMITTED when absent (consume empty, terms empty,
     * enforcement zero) -- the omit-when-absent precedent (naalp-approval ?6:audience). */
    public function bytes(): string
    {
        $pairs = [
            [new U(1), new B($this->action)],
            [new U(2), new A(\array_map(static fn(string $g) => new B($g), $this->governing))],
        ];
        if ($this->consume !== "") {
            $pairs[] = [new U(3), new B($this->consume)];
        }
        $pairs[] = [new U(4), new U($this->outcome)];
        $pairs[] = [new U(5), $this->ordering->toCbor()];
        if (\count($this->terms) > 0) {
            $tpairs = [];
            foreach ($this->terms as $k => $td) {
                $tpairs[] = [new U($k), $td->toCbor()];
            }
            $pairs[] = [new U(6), new M($tpairs)];
        }
        if ($this->enforcement !== 0) {
            $pairs[] = [new U(7), new U($this->enforcement)];
        }
        return Cbor::encode(new M($pairs));
    }

    /** The record's SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The record's T1 content-id (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/** A DecisionRecord that has passed signature verification and full semantic validation. */
final class ResolvedDecisionRecord
{
    public string $action;
    /** @var array<int,string> */
    public array $governing;
    public string $consume;
    public int $outcome;
    public OrderingDisclosure $ordering;
    /** @var array<int,TermDisposition> */
    public array $terms;
    public int $enforcement;

    /**
     * @param array<int,string> $governing
     * @param array<int,TermDisposition> $terms
     */
    public function __construct(
        string $action,
        array $governing,
        string $consume,
        int $outcome,
        OrderingDisclosure $ordering,
        array $terms,
        int $enforcement
    ) {
        $this->action = $action;
        $this->governing = $governing;
        $this->consume = $consume;
        $this->outcome = $outcome;
        $this->ordering = $ordering;
        $this->terms = $terms;
        $this->enforcement = $enforcement;
    }
}

/** A log operator's signed Merkle tree head over a leaf set of record content ids (design.md
 * §26.5, S3). */
final class CheckpointRoot
{
    public string $log;
    public int $size;
    public string $root;
    public string $prev;
    public int $at;

    public function __construct(string $log, int $size, string $root, string $prev, int $at)
    {
        $this->log = $log;
        $this->size = $size;
        $this->root = $root;
        $this->prev = $prev;
        $this->at = $at;
    }

    /** Deterministic-CBOR encoding {1:log, 2:size, 3:root, 4:prev, 5:at}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->log)],
            [new U(2), new U($this->size)],
            [new U(3), new B($this->root)],
            [new U(4), new B($this->prev)],
            [new U(5), new U($this->at)],
        ]));
    }

    /** The checkpoint's SHA-384 head (48 octets) -- the `prev` the NEXT checkpoint chains from. */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The checkpoint's T1 content-id (50 octets) -- what an inclusion proof's `root` field and a
     * witness-cosign's `root` field both name. */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/** A witness's countersignature over one exact checkpoint by content id (design.md §26.5). */
final class WitnessCosign
{
    public string $witness;
    public string $root;
    public int $at;

    public function __construct(string $witness, string $root, int $at)
    {
        $this->witness = $witness;
        $this->root = $root;
        $this->at = $at;
    }

    /** Deterministic-CBOR encoding {1:witness, 2:root, 3:at}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->witness)],
            [new U(2), new B($this->root)],
            [new U(3), new U($this->at)],
        ]));
    }

    /** The cosign's SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The cosign's T1 content-id (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/** Proves one record's content id existed as a leaf under a named checkpoint (design.md §26.5,
 * RFC 9162 §2.1.3.1). */
final class InclusionProof
{
    public string $root;
    public string $leaf;
    public int $index;
    /** @var array<int,string> */
    public array $path;

    /** @param array<int,string> $path */
    public function __construct(string $root, string $leaf, int $index, array $path)
    {
        $this->root = $root;
        $this->leaf = $leaf;
        $this->index = $index;
        $this->path = $path;
    }

    /** Deterministic-CBOR encoding {1:root, 2:leaf, 3:index, 4:path[]}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->root)],
            [new U(2), new B($this->leaf)],
            [new U(3), new U($this->index)],
            [new U(4), new A(\array_map(static fn(string $p) => new B($p), $this->path))],
        ]));
    }

    /** The proof's SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The proof's T1 content-id (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/**
 * A signed attestation a gateway/sidecar emits that an object crossed an egress boundary (E6.3).
 * `binding` selects how `digest` is interpreted (content_bound: the crossed object's T1 content-id;
 * content_free: a hiding commitment). `effect` is the crossed object's C5 effect class. `audience`
 * is the bound destination (empty-permitted). `at` is the crossing time, epoch ms. `ordering` is
 * the OPTIONAL field 6: null == ABSENT (reads correspondence-only).
 */
final class EgressAttestation
{
    public int $binding;
    public string $digest;
    public int $effect;
    public string $audience;
    public int $at;
    public ?OrderingDisclosure $ordering;

    public function __construct(int $binding, string $digest, int $effect, string $audience, int $at, ?OrderingDisclosure $ordering = null)
    {
        $this->binding = $binding;
        $this->digest = $digest;
        $this->effect = $effect;
        $this->audience = $audience;
        $this->at = $at;
        $this->ordering = $ordering;
    }

    /** Deterministic-CBOR encoding {1:binding, 2:digest, 3:effect, 4:audience, 5:at, ?6:ordering}.
     * Field 6 is OMITTED when $ordering is null. */
    public function bytes(): string
    {
        $pairs = [
            [new U(1), new U($this->binding)],
            [new U(2), new B($this->digest)],
            [new U(3), new U($this->effect)],
            [new U(4), new B($this->audience)],
            [new U(5), new U($this->at)],
        ];
        if ($this->ordering !== null) {
            $pairs[] = [new U(6), $this->ordering->toCbor()];
        }
        return Cbor::encode(new M($pairs));
    }

    /** The attestation's SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The attestation's T1 content-id (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }

    /** The attestation's C5 effect class, normalized fail-closed: a value the evaluator does not
     * recognize is treated as destructive, never as a weaker class. */
    public function effectClass(): int
    {
        return Policy::normalizeEffect($this->effect);
    }
}

/** An EgressAttestation that has passed signature verification. It carries NOTHING about WHO
 * served the bytes -- the authority is the signature, so the resolved evidence is identical
 * regardless of the serving party (the third-party re-serve property). */
final class ResolvedEgressAttestation
{
    public int $binding;
    public string $digest;
    public int $effect;
    public string $audience;
    public int $at;
    public ?OrderingDisclosure $ordering;

    public function __construct(int $binding, string $digest, int $effect, string $audience, int $at, ?OrderingDisclosure $ordering)
    {
        $this->binding = $binding;
        $this->digest = $digest;
        $this->effect = $effect;
        $this->audience = $audience;
        $this->at = $at;
        $this->ordering = $ordering;
    }
}
