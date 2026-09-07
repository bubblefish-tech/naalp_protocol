<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP error object + the numeric error-code registry for the PHP SDK (design.md §3.5,
 * R3.3/R3.4, T3.3).
 *
 * The naalp-error object is the Control/Error body (channel 0x0000, kind 3, effect read_only) that
 * carries one fail-closed rejection reason as {1:code, 2:name, ?3:detail, ?4:subject}. The registry
 * is the ordered 129-entry name<->code table below (the code for NAMES[i] is i+1; 0 is reserved),
 * copied verbatim from the Go/Rust reference (impl/go/naalperror/naalperror.go,
 * impl/rust/src/naalperror.rs) so the table — and therefore every produced byte — is identical
 * across ports. NAMES is the single source the machine-readable registry
 * (vectors/registry/error-codes.csv) and the CDDL naalp-error-code enum are generated to match.
 *
 * Two dual-carriage rules keep the code/name pair unambiguous and forward-compatible: a registered
 * code whose name disagrees with the registry is rejected Malformed (the code is authoritative — the
 * strengthening direction); a code outside the registry is opaque and non-fatal (the name is
 * diagnostic only), so a receiver interoperates with a peer emitting a later-registered code.
 */

declare(strict_types=1);

namespace Naalp;

/** A structurally malformed naalp-error body, or a registered code whose name disagrees (§3.5). */
class Malformed extends \RuntimeException
{
    public string $kind = "Malformed";
}

/**
 * A decoded naalp-error body. Named "NaalpErrorObject" (not "Object") for the same reason Envelope's
 * decoded body is "NaalpObject": "Object" reads as a reserved type keyword in PHP by convention here.
 */
final class NaalpErrorObject
{
    public function __construct(
        public int $code,
        public string $name,
        public string $detail = "",     // "" if field 3 absent
        public ?string $subject = null, // null if field 4 absent; raw bytes otherwise
    ) {
    }
}

final class NaalpError
{
    /** Top of the RFC-Required standards range; codes >= 0x8000 are private-use. */
    public const STANDARDS_MAX = 0x7FFF;

    /**
     * The ordered error-code registry: the code for NAMES[i] is i+1 (0 is reserved and MUST NOT
     * appear on the wire). Order is the fields-of-record authority for every code (§3.5). Copied
     * verbatim from impl/go/naalperror/naalperror.go's Names — do not reorder.
     */
    public const NAMES = [
        "NonCanonical", "DepthExceeded", "Malformed", "ContentIdMismatch", "HeaderBodyMismatch",
        "UnsupportedVersion", "UnknownCriticalExt", "UnknownKind", "RangeError", "NonNFC",
        "WrongAudience", "TooLarge", "TooManyCauses", "TooManyExtensions", "TooManyChunks",
        "UnknownAlg", "KeyAlgMismatch", "ProfileDowngrade", "HybridIncomplete", "SuiteMismatch",
        "CompositeRefused", "BadSignature", "SignerMismatch", "RotationUnauthorized", "KeyRevoked",
        "EffectNotAuthorized", "UnauthenticatedPrincipal", "MalformedSafetyLabel", "ApprovalRequired",
        "ApprovalMismatch", "ApprovalExpired", "AlreadyConsumed", "ConsumeFork", "ConsumeForkInvalid",
        "ConsumeReceiptUnsigned", "LedgerCorrupt", "LedgerUnsigned", "AudienceMismatch",
        "FreshnessSelfAsserted", "UnknownRefusalOutcome", "RefusalDetailLeak", "ChainBroken",
        "Equivocation", "CausalViolation", "ReceiptUnsigned", "ForkProofInvalid", "StageOutOfOrder",
        "StreamDigestMismatch", "StreamStateError", "ConfidentialTransportRequired", "PeerUnauthenticated",
        "NotDelivered", "MappingError", "EffectDeclarationMismatch", "StateTransitionError",
        "CapExceedsParent", "TransformCycle", "InputGateBypass", "TaskStateError", "ScopeOverlapConflict",
        "ReconcileMismatch", "WrongFlow", "SeqGap", "AboveCeiling", "GapDetected", "CommitMismatch",
        "ContMalformed", "GrantExpired", "GrantNotYetValid", "GrantRevoked", "UntrustedChainRoot",
        "DelegationDepthExceeded", "GrantMalformed", "NameMalformed", "NameChainBroken",
        "NameForkProofInvalid", "IllegalTransition", "TaskChainBroken", "ForeignCard", "DescMalformed",
        "MalformedApprovalFlag", "DirForkProofInvalid", "ImporterMismatch", "UnknownDescriptionFormat",
        "VerifierKeyMismatch", "NegMalformed", "UnknownRole", "UnknownProfile", "NotDescended",
        "NotOffer", "NotAccept", "MalformedCriticalFlag", "UnknownCriticalRisk", "ReferenceMismatch",
        "MalformedAnnotation", "EffectUnderDeclared", "EffectOutsideLattice", "ToolCallMalformed",
        "PayMalformed", "UnknownPaymentFormat", "GwMalformed", "UnknownGatewayDecision", "UIMalformed",
        "UIChainBroken", "UnknownUIEventKind", "ActionSubstituted", "UINoConsent", "StaleEpoch",
        "Unauthorized", "OwnerImmutable", "MemberExists", "MemberUnknown", "OwnerExists", "RoleInvalid",
        "RoomOpMismatch", "OpUnknown", "PrincipalUnknown", "PrincipalExists", "RebindUnauthorized",
        // Evidence-record family (E6.3 egress + S1 decision-record + S3 checkpoint + R1/R8), codes 120-129.
        "EgMalformed", "UnknownEgressBinding", "DecisionMalformed", "UnknownOrderingBasis", "OrderingDisclosureMalformed",
        "TermDispositionMalformed", "CheckpointMalformed", "WitnessRootMismatch", "InclusionProofInvalid", "ForeignProfileMalformed", "HazardMalformed", "HazardNotCovered", "HazardUnknown",
    ];

    /**
     * Registered name for a code and whether the code is registered. A code of 0, or any value past
     * the registered range, is unregistered (opaque per the open-registry rule).
     *
     * @return array{0:string,1:bool}
     */
    public static function nameForCode(int $code): array
    {
        if ($code >= 1 && $code <= \count(self::NAMES)) {
            return [self::NAMES[$code - 1], true];
        }
        return ["", false];
    }

    /** Registered code for a name, or null when the name is unregistered. */
    public static function codeForName(string $name): ?int
    {
        $i = \array_search($name, self::NAMES, true);
        return $i === false ? null : $i + 1;
    }

    /**
     * Deterministic CBOR (RFC 8949 §4.2.1) of a naalp-error body {1:code, 2:name, ?3:detail,
     * ?4:subject}. $detail === "" omits field 3; $subject === null omits field 4. The integer keys
     * 1..4 are already in canonical ascending order.
     */
    public static function encode(int $code, string $name, string $detail = "", ?string $subject = null): string
    {
        $pairs = [
            [new U(1), new U($code)],
            [new U(2), new T($name)],
        ];
        if ($detail !== "") {
            $pairs[] = [new U(3), new T($detail)];
        }
        if ($subject !== null) {
            $pairs[] = [new U(4), new B($subject)];
        }
        return Cbor::encode(new M($pairs));
    }

    /**
     * Parse a naalp-error body and enforce the dual-carriage rules. A structurally malformed body
     * (not a map, a non-integer key, a wrong-typed or unknown field, or a missing code/name) is
     * rejected Malformed. A registered code whose name disagrees with the registry is rejected
     * Malformed (the code is authoritative). An unregistered code is accepted opaque (name
     * diagnostic only).
     */
    public static function decode(string $data): NaalpErrorObject
    {
        try {
            $v = Cbor::decode($data);
        } catch (\Throwable $e) {
            throw new Malformed("malformed naalp-error object");
        }
        if (!($v instanceof M)) {
            throw new Malformed("not a map");
        }
        $code = null;
        $name = null;
        $detail = "";
        $subject = null;
        foreach ($v->pairs as [$k, $val]) {
            if (!($k instanceof U)) {
                throw new Malformed("non-uint key");
            }
            switch ($k->v) {
                case 1:
                    if (!($val instanceof U)) {
                        throw new Malformed("field 1 wrong type");
                    }
                    $code = $val->v;
                    break;
                case 2:
                    if (!($val instanceof T)) {
                        throw new Malformed("field 2 wrong type");
                    }
                    $name = $val->v;
                    break;
                case 3:
                    if (!($val instanceof T)) {
                        throw new Malformed("field 3 wrong type");
                    }
                    $detail = $val->v;
                    break;
                case 4:
                    if (!($val instanceof B)) {
                        throw new Malformed("field 4 wrong type");
                    }
                    $subject = $val->v;
                    break;
                default:
                    throw new Malformed("unknown field " . $k->v); // closed grammar: unknown key is malformed
            }
        }
        if ($code === null || $name === null) {
            throw new Malformed("missing code or name");
        }
        [$regName, $registered] = self::nameForCode($code);
        if ($registered && $regName !== $name) {
            throw new Malformed("registered code disagrees with name"); // registered code + disagreeing name
        }
        return new NaalpErrorObject($code, $name, $detail, $subject);
    }
}
