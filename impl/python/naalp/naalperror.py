# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
The N-AALP error object and the numeric error-code registry (design.md §3.5, R3.3/R3.4, T3.3)
for the Python SDK.

The naalp-error object is the Control/Error body (channel 0x0000, kind 3, effect read_only) that
carries one fail-closed rejection reason as {1:code, 2:name, ?3:detail, ?4:subject}. The registry
is the ordered 129-entry name<->code table NAMES below (the code for NAMES[i] is i+1; 0 is
reserved). NAMES is the single source the machine-readable registry
(vectors/registry/error-codes.csv) and the CDDL naalp-error-code enum are generated to match, and
scripts/registry_drift.py asserts the three agree; the table itself is graded against the
non-circular oracle by the error.name_for_code conformance op. Byte-identical to impl/go/naalperror
and impl/rust/src/naalperror.rs.

Two dual-carriage rules keep the code/name pair unambiguous and forward-compatible: a registered
code whose name disagrees with the registry is rejected Malformed (the code is authoritative — the
strengthening direction); a code outside the registry is opaque and non-fatal (the name is
diagnostic only), so a receiver interoperates with a peer emitting a later-registered code.
"""
from . import cbor, envelope
from .cbor import U, B, T, M

# StandardsMax: the top of the RFC-Required standards range; codes >= 0x8000 are private-use.
STANDARDS_MAX = 0x7FFF

# NAMES is the ordered error-code registry: the code for NAMES[i] is i+1 (0 is reserved and MUST
# NOT appear on the wire). Order is the fields-of-record authority for every code (§3.5). Copied
# verbatim from impl/go/naalperror/naalperror.go -- do not reorder or edit here.
NAMES = [
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
    # Evidence-record family (E6.3 egress + S1 decision-record + S3 checkpoint + R1/R8), codes 120-129.
    "EgMalformed", "UnknownEgressBinding", "DecisionMalformed", "UnknownOrderingBasis", "OrderingDisclosureMalformed",
    "TermDispositionMalformed", "CheckpointMalformed", "WitnessRootMismatch", "InclusionProofInvalid", "ForeignProfileMalformed", "HazardMalformed", "HazardNotCovered", "HazardUnknown",
]

assert len(NAMES) == 132, "the naalp-error registry MUST carry exactly 132 entries (0 is reserved)"

_CODE_BY_NAME = {n: i + 1 for i, n in enumerate(NAMES)}


def name_for_code(code):
    """Return (name, registered) for a code. A code of 0, or any value past the registered range,
    is unregistered (opaque per the open-registry rule) -- returns ("", False)."""
    if 1 <= code <= len(NAMES):
        return NAMES[code - 1], True
    return "", False


def code_for_name(name):
    """Return (code, registered) for a name."""
    c = _CODE_BY_NAME.get(name)
    if c is None:
        return 0, False
    return c, True


class ErrorObject:
    """A decoded naalp-error body. detail == "" when field 3 is absent; subject is None when
    field 4 is absent."""
    __slots__ = ("code", "name", "detail", "subject")

    def __init__(self, code, name, detail="", subject=None):
        self.code = code
        self.name = name
        self.detail = detail
        self.subject = subject


def encode(code, name, detail="", subject=None):
    """Deterministic CBOR (RFC 8949 §4.2.1) of a naalp-error body {1:code, 2:name, ?3:detail,
    ?4:subject}. detail=="" omits field 3; subject is None omits field 4. The integer keys 1..4
    are already in canonical ascending order."""
    pairs = [(U(1), U(code)), (U(2), T(name))]
    if detail:
        pairs.append((U(3), T(detail)))
    if subject is not None:
        pairs.append((U(4), B(subject)))
    return cbor.encode(M(pairs))


def decode(data):
    """Parse a naalp-error body and enforce the dual-carriage rules. A structurally malformed body
    (not a map, a non-integer key, a wrong-typed or unknown field, or a missing code/name) is
    rejected envelope.EnvelopeError('Malformed'). A registered code whose name disagrees with the
    registry is rejected Malformed (the code is authoritative). An unregistered code is accepted
    opaque (name diagnostic only)."""
    try:
        v = cbor.decode(data)
    except Exception:
        raise envelope.EnvelopeError("Malformed", "malformed naalp-error object")
    if not isinstance(v, M):
        raise envelope.EnvelopeError("Malformed", "naalp-error body not a map")

    code = None
    name = None
    detail = ""
    subject = None
    have_code = have_name = False
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise envelope.EnvelopeError("Malformed", "non-uint field key")
        key = k.v
        if key == 1:
            if not isinstance(val, U):
                raise envelope.EnvelopeError("Malformed", "code not a uint")
            code = val.v
            have_code = True
        elif key == 2:
            if not isinstance(val, T):
                raise envelope.EnvelopeError("Malformed", "name not a tstr")
            name = val.v
            have_name = True
        elif key == 3:
            if not isinstance(val, T):
                raise envelope.EnvelopeError("Malformed", "detail not a tstr")
            detail = val.v
        elif key == 4:
            if not isinstance(val, B):
                raise envelope.EnvelopeError("Malformed", "subject not a bstr")
            subject = val.v
        else:
            raise envelope.EnvelopeError("Malformed", "unknown field key")  # closed grammar

    if not have_code or not have_name:
        raise envelope.EnvelopeError("Malformed", "missing code or name")

    reg_name, registered = name_for_code(code)
    if registered and reg_name != name:
        raise envelope.EnvelopeError("Malformed", "registered code + disagreeing name")

    return ErrorObject(code=code, name=name, detail=detail, subject=subject)
