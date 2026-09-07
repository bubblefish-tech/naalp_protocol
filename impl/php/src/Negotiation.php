<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C20 governed negotiation, advisory risk labels, and trust references for the PHP SDK
 * (design.md §23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4).
 *
 * C20 adds three signed surfaces carried on N-AALP's own signed object. It introduces NO new envelope,
 * encoding, signature, identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP
 * body (COSE_Sign1, §4), reusing the closed C5 effect lattice (Policy), the T1 content-id framing
 * (§2.3), and the §8.2 causal partial order (the `causes` field) UNCHANGED.
 *
 *   - Governed negotiation: a Message {1:negotiation, 2:role, 3:profile, 4:causes[]} is one signed step
 *     — an OFFER, a COUNTER, or an ACCEPT — causally linked to its predecessor(s) by content-id and
 *     SELECTING a profile from a CLOSED pre-registered set (no free-form/runtime capability, §23.9). An
 *     ACCEPT MUST DESCEND from its offer by walking the causes DAG (verifyAccept), else it is rejected
 *     (NotDescended). An unknown profile/role is rejected.
 *   - Advisory risk labels: a RiskLabel {1:code, 2:critical} + a LabeledObject {1:effect, 2:labels[]}.
 *     The R-2.5 critical-extension rule applies (an unknown CRITICAL label is rejected, an unknown
 *     non-critical one is ignored). LOAD-BEARING invariant: carrying a risk label NEVER changes an
 *     object's effect class — effectClass() derives from the effect field ALONE (Policy::normalizeEffect);
 *     the closed C5 lattice is untouched. Risk labels are an advisory dimension, not a fifth effect.
 *   - Trust references: a TrustRef {1:registry, 2:reference, 3:subject} carries a third-party trust
 *     statement as a CHECKABLE signed object — verifyTrustRef recomputes the referenced content-id over
 *     the external record. NO wire field weighs it: there is no score/rank/ordering and no scoring
 *     function, by design (§23.7).
 *
 * An independent transcription of impl/go/negotiation (cross-read against impl/python/naalp/negotiation.py),
 * graded against the shared vectors/negotiation/cases.json. Every check is fail-closed (§15): a failing
 * object is rejected whole, returns its named error, and causes no state change.
 *
 * CRYPTO SCOPE (PURE-ONLY): the corpus-graded deliverable — the deterministic body/head/content-id, the
 * closed role/profile/risk vocabularies, the critical-extension rule, the effect invariant, the descent
 * DAG, and the trust-ref content-id recompute — is pure and complete here. PHP cannot deterministically
 * sign or verify ML-DSA (FIPS 204); signMessage / signLabeledObject / signTrustRef therefore use a real
 * Ed25519 (RFC 8032) signature (ext-sodium) to demonstrate the signing binding in isolation, and the
 * matching verify* verify that Ed25519 signature with real crypto (a foreign key is rejected). The
 * profile argument is retained for interface parity with the ML-DSA reference; the ML-DSA profile floor
 * is NOT applied to the pure Ed25519 signature demonstration (Ed25519 is a level-0 classical leg).
 */

declare(strict_types=1);

namespace Naalp;

/**
 * A named, fail-closed C20 error; $kind is a stable string mirroring the Go/Rust/Python/Ruby error
 * kinds (NegMalformed, UnknownRole, UnknownProfile, NotDescended, NotOffer, NotAccept,
 * MalformedCriticalFlag, UnknownCriticalRisk, ReferenceMismatch, BadSignature).
 */
class NegotiationError extends \RuntimeException
{
    public string $kind;

    public function __construct(string $kind, string $msg = "")
    {
        $this->kind = $kind;
        parent::__construct($msg === "" ? $kind : "$kind: $msg");
    }
}

/**
 * One signed step of a governed negotiation: an offer, a counter, or an accept. It is CAUSALLY LINKED
 * to its predecessor(s) by content-id in $causes (empty for an offer) and SELECTS a pre-registered
 * profile.
 */
final class Message
{
    public string $negotiation;
    public int $role;
    public int $profile;
    /** @var array<int,string> content-ids of predecessor messages (raw bytes; empty for an offer) */
    public array $causes;

    /** @param array<int,string> $causes */
    public function __construct(string $negotiation, int $role, int $profile, array $causes = [])
    {
        $this->negotiation = $negotiation;
        $this->role = $role;
        $this->profile = $profile;
        $this->causes = \array_values($causes);
    }

    /** Deterministic-CBOR encoding {1: negotiation, 2: role, 3: profile, 4: causes[]}. */
    public function bytes(): string
    {
        $arr = [];
        foreach ($this->causes as $c) {
            $arr[] = new B($c);
        }
        return Cbor::encode(new M([
            [new U(1), new B($this->negotiation)],
            [new U(2), new U($this->role)],
            [new U(3), new U($this->profile)],
            [new U(4), new A($arr)],
        ]));
    }

    /** The Message's SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The Message's T1 content-id (50 octets) — the id a successor names in its causes. */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/**
 * One advisory risk label carried on an object. $code is the label code; $critical is the per-carriage
 * must-understand flag (1 = critical, 0 = advisory) — the uint 1/0, no CBOR boolean.
 */
final class RiskLabel
{
    public int $code;
    public int $critical;

    public function __construct(int $code, int $critical)
    {
        $this->code = $code;
        $this->critical = $critical;
    }

    /** Whether the label is carried critical (must-understand). */
    public function isCritical(): bool
    {
        return $this->critical === 1;
    }

    /** The label's CBOR map {1: code, 2: critical}. */
    public function toMap(): M
    {
        return new M([
            [new U(1), new U($this->code)],
            [new U(2), new U($this->critical)],
        ]);
    }

    /** Deterministic-CBOR encoding of the risk-label body. */
    public function bytes(): string
    {
        return Cbor::encode($this->toMap());
    }
}

/**
 * A minimal N-AALP object carrying an effect (field 1, C5) and a set of advisory risk labels. It exists
 * to demonstrate — provably, in isolation — the load-bearing invariant that carrying a risk label NEVER
 * changes the object's effect class.
 */
final class LabeledObject
{
    public int $effect;
    /** @var array<int,RiskLabel> */
    public array $labels;

    /** @param array<int,RiskLabel> $labels */
    public function __construct(int $effect, array $labels = [])
    {
        $this->effect = $effect;
        $this->labels = \array_values($labels);
    }

    /** Deterministic-CBOR encoding {1: effect, 2: labels[]}. */
    public function bytes(): string
    {
        $arr = [];
        foreach ($this->labels as $l) {
            $arr[] = $l->toMap();
        }
        return Cbor::encode(new M([
            [new U(1), new U($this->effect)],
            [new U(2), new A($arr)],
        ]));
    }

    /** The LabeledObject's SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The LabeledObject's T1 content-id (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }

    /**
     * The object's C5 effect class, derived from the effect field ALONE and normalized fail-closed
     * (unknown -> destructive, R-6.2). It DELIBERATELY does not consult the risk labels: a risk label is
     * an advisory dimension, never a fifth effect, so the closed lattice is untouched by any label the
     * object carries. This is the load-bearing C20 invariant.
     */
    public function effectClass(): int
    {
        return Policy::normalizeEffect($this->effect);
    }

    /** Apply the critical-extension rule to the object's carried labels (Negotiation::validateLabels). */
    public function validateLabels(): array
    {
        return Negotiation::validateLabels($this->labels);
    }
}

/**
 * A third-party trust statement carried as a CHECKABLE signed object. $registry is an opaque
 * external-registry identifier (an ERC-8004-style reputation/identity registry — a name, not a URL the
 * wire resolves); $reference is the T1 content-id of the referenced external record; $subject is the
 * opaque id the statement is about. The wire CARRIES the reference; NO field here weighs it.
 */
final class TrustRef
{
    public string $registry;
    public string $reference;
    public string $subject;

    public function __construct(string $registry, string $reference, string $subject)
    {
        $this->registry = $registry;
        $this->reference = $reference;
        $this->subject = $subject;
    }

    /** Deterministic-CBOR encoding {1: registry, 2: reference, 3: subject}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->registry)],
            [new U(2), new B($this->reference)],
            [new U(3), new B($this->subject)],
        ]));
    }

    /** The TrustRef's SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The TrustRef's own T1 content-id (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }

    /** The content-id the trust ref binds (the carried external-record reference). */
    public function referenceId(): string
    {
        return $this->reference;
    }

    /**
     * Whether the carried reference is the T1 content-id of $record — i.e. the reference recomputes over
     * the presented external bytes. This is the CHECK a relying party runs to confirm the reference names
     * those exact external bytes; it computes NO score. A changed record yields a different content-id.
     */
    public function bindsRecord(string $record): bool
    {
        return \hash_equals($this->reference, Cbor::contentId($record));
    }
}

/**
 * A TrustRef that has passed signature verification and (given the external record) the content-id
 * recompute. It carries NO score, rank, or trust weight — the protocol does not weigh trust.
 */
final class ResolvedTrustRef
{
    public string $registry;
    public string $reference;
    public string $subject;

    public function __construct(string $registry, string $reference, string $subject)
    {
        $this->registry = $registry;
        $this->reference = $reference;
        $this->subject = $subject;
    }
}

final class Negotiation
{
    /** The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain. */
    public const HEAD_SIZE = 48;

    // Negotiation roles (the closed set; a role outside it is rejected UnknownRole).
    public const ROLE_OFFER = 0;   // the initiating offer (the root of a negotiation; no causes)
    public const ROLE_COUNTER = 1; // a counter-offer chaining onto the offer or a prior counter
    public const ROLE_ACCEPT = 2;  // the accept; it MUST descend from its offer

    private const ROLE_NAMES = [self::ROLE_OFFER => "offer", self::ROLE_COUNTER => "counter", self::ROLE_ACCEPT => "accept"];

    // Pre-registered negotiation profiles (the closed set; a code outside it is UnknownProfile).
    public const PROFILE_BASELINE = 0;  // the baseline capability profile
    public const PROFILE_STREAMING = 1; // the native-streaming capability profile (C9)
    public const PROFILE_BATCH = 2;     // the batched-delivery capability profile

    private const PROFILE_NAMES = [self::PROFILE_BASELINE => "baseline", self::PROFILE_STREAMING => "streaming", self::PROFILE_BATCH => "batch"];

    // Risk-label vocabulary classes (a registry attribute of the code, distinct from the critical flag).
    public const CLASS_INFORMING = 0; // purely informational
    public const CLASS_GATING = 1;    // a policy MAY require an additional gate when this label is present

    private const RISK_CLASS_NAMES = [self::CLASS_INFORMING => "informing", self::CLASS_GATING => "gating"];

    // The closed standard risk-label vocabulary.
    public const RISK_SENSITIVE = 1;  // gating: the object touches sensitive material
    public const RISK_EGRESS = 2;     // gating: the object causes data egress
    public const RISK_REVERSIBLE = 3; // informing: the object's effect is reversible

    /**
     * The first code of the private/experimental extensible range. A code at or above it is unknown to a
     * verifier that lacks it: carried critical it is rejected (R-2.5), carried non-critical it is ignored.
     */
    public const EXTENSIBLE_RANGE_START = 0x1000;

    /** The closed standard risk-label vocabulary: code -> class. */
    private const RISK_VOCAB = [
        self::RISK_SENSITIVE => self::CLASS_GATING,
        self::RISK_EGRESS => self::CLASS_GATING,
        self::RISK_REVERSIBLE => self::CLASS_INFORMING,
    ];

    // ==== governed negotiation ====================================================================

    /** Whether $r is one of the three defined negotiation roles. */
    public static function knownRole(int $r): bool
    {
        return \array_key_exists($r, self::ROLE_NAMES);
    }

    /** The role name, or "unknown" for an out-of-range code. */
    public static function roleName(int $r): string
    {
        return self::ROLE_NAMES[$r] ?? "unknown";
    }

    /** Whether $p is one of the pre-registered profiles (the closed set). */
    public static function isRegisteredProfile(int $p): bool
    {
        return \array_key_exists($p, self::PROFILE_NAMES);
    }

    /** The profile name, or "unknown" for an unregistered code. */
    public static function profileName(int $p): string
    {
        return self::PROFILE_NAMES[$p] ?? "unknown";
    }

    /** Build an offer (the root of a negotiation): role offer, no causes. */
    public static function newOffer(string $negotiation, int $profile): Message
    {
        return new Message($negotiation, self::ROLE_OFFER, $profile, []);
    }

    /** Build a counter chaining onto the predecessor named by $predecessorId. */
    public static function newCounter(string $negotiation, int $profile, string $predecessorId): Message
    {
        return new Message($negotiation, self::ROLE_COUNTER, $profile, [$predecessorId]);
    }

    /** Build an accept chaining onto the predecessor named by $predecessorId (checked by verifyAccept). */
    public static function newAccept(string $negotiation, int $profile, string $predecessorId): Message
    {
        return new Message($negotiation, self::ROLE_ACCEPT, $profile, [$predecessorId]);
    }

    /**
     * Reconstruct a Message from its body bytes alone. It does NOT validate the role or profile against
     * the closed sets — that is verifyMessage's job — so a message carrying an unknown role/profile can
     * be represented (and then rejected). Fail-closed (NegMalformed) on a non-canonical body, a non-map,
     * a mistyped/absent field, or a non-bstr cause.
     */
    public static function parseMessage(string $b): Message
    {
        $m = self::decodeMap($b);
        if ($m === null) {
            throw new NegotiationError("NegMalformed", "object is not a well-formed negotiation body");
        }
        $neg = self::bstrField($m, 1);
        $role = self::uintField($m, 2);
        $prof = self::uintField($m, 3);
        $causesV = self::field($m, 4);
        if ($neg === null || $role === null || $prof === null || !($causesV instanceof A)) {
            throw new NegotiationError("NegMalformed", "object is not a well-formed negotiation body");
        }
        $causes = [];
        foreach ($causesV->items as $e) {
            if (!($e instanceof B)) {
                throw new NegotiationError("NegMalformed", "cause is not a bstr");
            }
            $causes[] = $e->v;
        }
        return new Message($neg, $role, $prof, $causes);
    }

    /** The bare {1: alg} COSE_Sign1 protected header (§4). */
    public static function protectedHeader(int $alg): string
    {
        return Cbor::encode(new M([[new U(1), new N($alg)]]));
    }

    /**
     * The tagged COSE_Sign1 over the Message body. PURE-ONLY PHP: a real Ed25519 (RFC 8032) signature
     * standing in for the reference's ML-DSA signature.
     */
    public static function signMessage(Message $m, string $seed): string
    {
        return self::signBody($m->bytes(), $seed);
    }

    /**
     * Verify the Message's Ed25519 signature (real crypto), reconstruct it from the signed body bytes,
     * and validate it against the closed sets: the role MUST be offer/counter/accept (UnknownRole) and
     * the selected profile MUST be pre-registered (UnknownProfile). A bad signature is BadSignature. The
     * $profile argument is retained for interface parity with the ML-DSA reference (see the file header);
     * the pure Ed25519 demonstration does not apply the ML-DSA profile floor. Fail-closed.
     */
    public static function verifyMessage(string $obj, int $profile, string $pubkey): Message
    {
        $payload = self::verifyBody($obj, $pubkey);
        $m = self::parseMessage($payload);
        if (!self::knownRole($m->role)) {
            throw new NegotiationError("UnknownRole", "negotiation message role is not offer/counter/accept");
        }
        if (!self::isRegisteredProfile($m->profile)) {
            throw new NegotiationError("UnknownProfile", "negotiation selects a profile outside the closed set");
        }
        return $m;
    }

    /**
     * Build the content-id (hex) -> Message index the descent walk resolves predecessors through.
     *
     * @param array<int,Message> $msgs
     * @return array<string,Message>
     */
    public static function indexById(array $msgs): array
    {
        $byId = [];
        foreach ($msgs as $m) {
            $byId[\bin2hex($m->id())] = $m;
        }
        return $byId;
    }

    /**
     * Whether $from reaches $targetId by following causes edges resolved through $byId: a real
     * reachability walk over the causal DAG. A cause that cannot be resolved through $byId cannot extend
     * the chain, so a forged causes pointer to an id the verifier never saw does not manufacture descent.
     * Fail-closed.
     *
     * @param array<string,Message> $byId
     */
    public static function descends(Message $from, string $targetId, array $byId): bool
    {
        $target = \bin2hex($targetId);
        $seen = [];
        $stack = $from->causes;
        while (!empty($stack)) {
            $id = \array_pop($stack);
            $k = \bin2hex($id);
            if ($k === $target) {
                return true;
            }
            if (isset($seen[$k])) {
                continue;
            }
            $seen[$k] = true;
            if (!isset($byId[$k])) {
                continue; // an unresolved cause: the chain cannot be walked through it
            }
            foreach ($byId[$k]->causes as $c) {
                $stack[] = $c;
            }
        }
        return false;
    }

    /**
     * Whether $accept descends from $offer by walking the causes DAG through $byId (a counter or a chain
     * of counters between them is traversed). Performs no signature check.
     *
     * @param array<string,Message> $byId
     */
    public static function descendsMsg(Message $accept, Message $offer, array $byId): bool
    {
        return self::descends($accept, $offer->id(), $byId);
    }

    /**
     * Check an accept against its offer over a set of verified messages, fail-closed. It requires $offer
     * to be a genuine offer selecting a pre-registered profile (NotOffer / UnknownProfile), $accept to be
     * an accept selecting a pre-registered profile (NotAccept / UnknownProfile), and the accept to DESCEND
     * from the offer (NotDescended otherwise). Returns the AGREED profile. It authorizes nothing; it
     * accepts or rejects. $byId MUST index the negotiation's verified messages.
     *
     * @param array<string,Message> $byId
     */
    public static function verifyAccept(Message $accept, Message $offer, array $byId): int
    {
        if ($offer->role !== self::ROLE_OFFER) {
            throw new NegotiationError("NotOffer", "the object presented as the offer is not an offer role");
        }
        if (!self::isRegisteredProfile($offer->profile)) {
            throw new NegotiationError("UnknownProfile", "offer selects a profile outside the closed set");
        }
        if ($accept->role !== self::ROLE_ACCEPT) {
            throw new NegotiationError("NotAccept", "the object presented as the accept is not an accept role");
        }
        if (!self::isRegisteredProfile($accept->profile)) {
            throw new NegotiationError("UnknownProfile", "accept selects a profile outside the closed set");
        }
        if (!self::descendsMsg($accept, $offer, $byId)) {
            throw new NegotiationError("NotDescended", "accept does not descend from its offer along the causes chain");
        }
        return $accept->profile;
    }

    // ==== advisory risk labels ====================================================================

    /** The class name ("gating"/"informing"), or "" for an out-of-range value. */
    public static function riskClassName(int $c): string
    {
        return self::RISK_CLASS_NAMES[$c] ?? "";
    }

    /**
     * A code's vocabulary class and whether the code is a registered standard label.
     *
     * @return array{0:int,1:bool}
     */
    public static function riskClassOf(int $code): array
    {
        return \array_key_exists($code, self::RISK_VOCAB) ? [self::RISK_VOCAB[$code], true] : [self::CLASS_INFORMING, false];
    }

    /** Whether $code is in the closed standard vocabulary. */
    public static function isRegisteredRisk(int $code): bool
    {
        return \array_key_exists($code, self::RISK_VOCAB);
    }

    /** Whether $code lies in the private/experimental extensible range. */
    public static function inExtensibleRange(int $code): bool
    {
        return $code >= self::EXTENSIBLE_RANGE_START;
    }

    /**
     * Apply the critical-extension rule (R-2.5) to a set of carried risk labels: return the RECOGNIZED
     * (standard-vocabulary) labels, DROP unknown non-critical labels, and REJECT an unknown CRITICAL
     * label (UnknownCriticalRisk). A critical flag outside {0,1} is MalformedCriticalFlag. It NEVER
     * inspects or returns an effect — risk labels are an advisory dimension, never a fifth effect.
     * Fail-closed.
     *
     * @param array<int,RiskLabel> $labels
     * @return array<int,RiskLabel>
     */
    public static function validateLabels(array $labels): array
    {
        $recognized = [];
        foreach ($labels as $l) {
            if ($l->critical > 1) {
                throw new NegotiationError("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}");
            }
            if (self::isRegisteredRisk($l->code)) {
                $recognized[] = $l;
                continue;
            }
            if ($l->isCritical()) {
                throw new NegotiationError("UnknownCriticalRisk", "an unknown critical risk label is rejected (R-2.5)");
            }
            // unknown non-critical: ignored (dropped from the recognized set)
        }
        return $recognized;
    }

    /**
     * Reconstruct a LabeledObject from its body bytes alone. Fail-closed (NegMalformed) on a malformed
     * shape; a critical flag outside {0,1} is MalformedCriticalFlag.
     */
    public static function parseLabeledObject(string $b): LabeledObject
    {
        $m = self::decodeMap($b);
        if ($m === null) {
            throw new NegotiationError("NegMalformed", "object is not a well-formed labeled-object body");
        }
        $eff = self::uintField($m, 1);
        $labelsV = self::field($m, 2);
        if ($eff === null || !($labelsV instanceof A)) {
            throw new NegotiationError("NegMalformed", "object is not a well-formed labeled-object body");
        }
        $labels = [];
        foreach ($labelsV->items as $e) {
            $labels[] = self::riskLabelFromValue($e);
        }
        return new LabeledObject($eff, $labels);
    }

    /** The tagged COSE_Sign1 over the LabeledObject body (real Ed25519; see the file header). */
    public static function signLabeledObject(LabeledObject $o, string $seed): string
    {
        return self::signBody($o->bytes(), $seed);
    }

    /**
     * Verify the LabeledObject's Ed25519 signature, reconstruct the object, and apply the
     * critical-extension rule to its labels (an unknown critical label is rejected). Returns
     * [object, recognized_labels]. The returned object's effectClass is unchanged by any label.
     *
     * @return array{0:LabeledObject,1:array<int,RiskLabel>}
     */
    public static function verifyLabeledObject(string $obj, int $profile, string $pubkey): array
    {
        $payload = self::verifyBody($obj, $pubkey);
        $o = self::parseLabeledObject($payload);
        $recognized = self::validateLabels($o->labels);
        return [$o, $recognized];
    }

    /** Parse one risk-label map, rejecting a malformed shape or a critical flag outside {0,1}. */
    private static function riskLabelFromValue(mixed $v): RiskLabel
    {
        if (!($v instanceof M)) {
            throw new NegotiationError("NegMalformed", "risk label is not a map");
        }
        $code = self::uintField($v, 1);
        $crit = self::uintField($v, 2);
        if ($code === null || $crit === null) {
            throw new NegotiationError("NegMalformed", "risk label missing a field");
        }
        if ($crit > 1) {
            throw new NegotiationError("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}");
        }
        return new RiskLabel($code, $crit);
    }

    // ==== trust references (checkable, never weighed) =============================================

    /** Reconstruct a TrustRef from its body bytes alone. Fail-closed (NegMalformed). */
    public static function parseTrustRef(string $b): TrustRef
    {
        $m = self::decodeMap($b);
        if ($m === null) {
            throw new NegotiationError("NegMalformed", "object is not a well-formed trust-ref body");
        }
        $reg = self::bstrField($m, 1);
        $ref = self::bstrField($m, 2);
        $subj = self::bstrField($m, 3);
        if ($reg === null || $ref === null || $subj === null) {
            throw new NegotiationError("NegMalformed", "object is not a well-formed trust-ref body");
        }
        return new TrustRef($reg, $ref, $subj);
    }

    /** The tagged COSE_Sign1 over the TrustRef body (real Ed25519; see the file header). */
    public static function signTrustRef(TrustRef $r, string $seed): string
    {
        return self::signBody($r->bytes(), $seed);
    }

    /**
     * Verify a trust reference end-to-end: (1) verify the signed object's Ed25519 signature (real crypto;
     * BadSignature on failure); (2) reconstruct it from the signed bytes; and (3) confirm the reference by
     * RECOMPUTING the external record's content-id and requiring it to equal the carried reference
     * (ReferenceMismatch otherwise). Returns the resolved reference — and NOTHING that scores it: this
     * module has no trust-weighting function, by design. Fail-closed.
     */
    public static function verifyTrustRef(string $obj, int $profile, string $pubkey, string $externalRecord): ResolvedTrustRef
    {
        $payload = self::verifyBody($obj, $pubkey);
        $r = self::parseTrustRef($payload);
        if (!$r->bindsRecord($externalRecord)) {
            throw new NegotiationError("ReferenceMismatch", "trust-ref reference does not recompute over the record");
        }
        return new ResolvedTrustRef($r->registry, $r->reference, $r->subject);
    }

    // ==== signature helpers (real Ed25519 COSE_Sign1, demonstrated in isolation) ==================

    /** Sign a body with Ed25519 and assemble the tagged COSE_Sign1 object. */
    private static function signBody(string $body, string $seed): string
    {
        $prot = self::protectedHeader(Cose::ALG_ED25519);
        $sig = Cose::ed25519Sign($seed, Cose::toBeSignedRaw($prot, $body));
        return Cose::assembleSign1Raw($prot, $body, $sig);
    }

    /** Verify a tagged COSE_Sign1 object's Ed25519 signature and return its signed payload. */
    private static function verifyBody(string $obj, string $pubkey): string
    {
        [$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
        if (!Cose::ed25519Verify($pubkey, Cose::toBeSignedRaw($prot, $payload), $sig)) {
            throw new NegotiationError("BadSignature", "signature does not verify");
        }
        return $payload;
    }

    // ---- small deterministic-CBOR field accessors -----------------------------------------------

    private static function decodeMap(string $b): ?M
    {
        try {
            $v = Cbor::decode($b);
        } catch (NonCanonical $e) {
            return null;
        }
        return $v instanceof M ? $v : null;
    }

    private static function field(M $m, int $k): mixed
    {
        foreach ($m->pairs as [$key, $val]) {
            if ($key instanceof U && $key->v === $k) {
                return $val;
            }
        }
        return null;
    }

    private static function bstrField(M $m, int $k): ?string
    {
        $v = self::field($m, $k);
        return $v instanceof B ? $v->v : null;
    }

    private static function uintField(M $m, int $k): ?int
    {
        $v = self::field($m, $k);
        return $v instanceof U ? $v->v : null;
    }
}
