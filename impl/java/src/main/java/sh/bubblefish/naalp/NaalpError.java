// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.HashMap;
import java.util.Map;

/**
 * The N-AALP error object and the numeric error-code registry for the Java SDK (design.md §3.5,
 * R3.3/R3.4, T3.3). The naalp-error object is the Control/Error body (channel 0x0000, kind 3,
 * effect read_only) that carries one fail-closed rejection reason as
 * {@code {1:code, 2:name, ?3:detail, ?4:subject}}. The registry is the ordered 129-entry
 * name&lt;-&gt;code table {@link #NAMES} (the code for {@code NAMES[i]} is {@code i+1}; 0 is
 * reserved), copied verbatim from the Go/Rust reference ({@code impl/go/naalperror/naalperror.go},
 * {@code impl/rust/src/naalperror.rs}) so the table — and therefore every produced byte — is
 * identical across ports. {@link #NAMES} is the single source the machine-readable registry
 * ({@code vectors/registry/error-codes.csv}) and the CDDL {@code naalp-error-code} enum are
 * generated to match, and the table is graded against the non-circular oracle by the
 * {@code error.name_for_code} conformance op.
 *
 * <p>Two dual-carriage rules keep the code/name pair unambiguous and forward-compatible: a
 * registered code whose name disagrees with the registry is rejected {@code Malformed} (the code
 * is authoritative — the strengthening direction); a code outside the registry is opaque and
 * non-fatal (the name is diagnostic only), so a receiver interoperates with a peer emitting a
 * later-registered code.
 */
public final class NaalpError {
    private NaalpError() {}

    /** Top of the RFC-Required standards range; codes &gt;= 0x8000 are private-use. */
    public static final long STANDARDS_MAX = 0x7FFF;

    /**
     * The ordered error-code registry: the code for {@code NAMES[i]} is {@code i+1} (0 is
     * reserved and MUST NOT appear on the wire). Order is the fields-of-record authority for
     * every code (§3.5). Copied verbatim from impl/go/naalperror/naalperror.go's Names — do not
     * reorder.
     */
    public static final String[] NAMES = {
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
    };

    private static final Map<String, Long> CODE_BY_NAME = new HashMap<>();
    static {
        for (int i = 0; i < NAMES.length; i++) {
            CODE_BY_NAME.put(NAMES[i], (long) (i + 1));
        }
    }

    /** The looked-up code: its registered name (empty if unregistered) and whether it is registered. */
    public static final class Lookup {
        public final String name;
        public final boolean registered;
        Lookup(String name, boolean registered) {
            this.name = name;
            this.registered = registered;
        }
    }

    /**
     * Registered name for a code and whether the code is registered. A code of 0, or any value
     * past the registered range, is unregistered (opaque per the open-registry rule).
     */
    public static Lookup nameForCode(long code) {
        if (code >= 1 && code <= NAMES.length) {
            return new Lookup(NAMES[(int) (code - 1)], true);
        }
        return new Lookup("", false);
    }

    /** Registered code for a name, or {@code null} when the name is unregistered. */
    public static Long codeForName(String name) {
        return CODE_BY_NAME.get(name);
    }

    /** A decoded naalp-error body. */
    public static final class Object {
        public final long code;
        public final String name;
        public final String detail;   // "" if field 3 absent
        public final byte[] subject;  // null if field 4 absent

        public Object(long code, String name, String detail, byte[] subject) {
            this.code = code;
            this.name = name;
            this.detail = detail;
            this.subject = subject;
        }
    }

    /**
     * Deterministic CBOR (RFC 8949 §4.2.1) of a naalp-error body {@code {1:code, 2:name,
     * ?3:detail, ?4:subject}}. {@code detail == ""} omits field 3; {@code subject == null} omits
     * field 4. The integer keys 1..4 are already in canonical ascending order. {@code code}
     * carries the CBOR-unsigned-integer bit pattern (Java {@code long} is signed, but
     * {@link Cbor.U} treats its argument as an unsigned uint64, matching the Go/Rust {@code
     * uint64} reference — see {@link Cbor#encode}'s head-selection by unsigned magnitude).
     */
    public static byte[] encode(long code, String name, String detail, byte[] subject) {
        java.util.List<Cbor.Pair> pairs = new java.util.ArrayList<>(4);
        pairs.add(new Cbor.Pair(new Cbor.U(1), new Cbor.U(code)));
        pairs.add(new Cbor.Pair(new Cbor.U(2), new Cbor.T(name)));
        if (detail != null && !detail.isEmpty()) {
            pairs.add(new Cbor.Pair(new Cbor.U(3), new Cbor.T(detail)));
        }
        if (subject != null) {
            pairs.add(new Cbor.Pair(new Cbor.U(4), new Cbor.B(subject)));
        }
        return Cbor.encode(new Cbor.M(pairs));
    }

    /**
     * Parse a naalp-error body and enforce the dual-carriage rules. A structurally malformed body
     * (not a map, a non-integer key, a wrong-typed or unknown field, or a missing code/name) is
     * rejected {@code Malformed}. A registered code whose name disagrees with the registry is
     * rejected {@code Malformed} (the code is authoritative). An unregistered code is accepted
     * opaque (name diagnostic only).
     */
    public static Object decode(byte[] data) {
        Cbor.Value v;
        try {
            v = Cbor.decode(data);
        } catch (RuntimeException e) {
            throw new NaalpException("Malformed", "malformed naalp-error object");
        }
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("Malformed", "not a map");
        }
        Long code = null;
        String name = null;
        String detail = "";
        byte[] subject = null;
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U k)) {
                throw new NaalpException("Malformed", "non-uint key");
            }
            switch ((int) k.v) {
                case 1:
                    code = requireUint(p.val, "field 1 wrong type");
                    break;
                case 2:
                    name = requireTstr(p.val, "field 2 wrong type");
                    break;
                case 3:
                    detail = requireTstr(p.val, "field 3 wrong type");
                    break;
                case 4:
                    subject = requireBstr(p.val, "field 4 wrong type");
                    break;
                default:
                    throw new NaalpException("Malformed", "unknown field " + k.v); // closed grammar
            }
        }
        if (code == null || name == null) {
            throw new NaalpException("Malformed", "missing code or name");
        }
        Lookup reg = nameForCode(code);
        if (reg.registered && !reg.name.equals(name)) {
            throw new NaalpException("Malformed", "registered code disagrees with name");
        }
        return new Object(code, name, detail, subject);
    }

    private static long requireUint(Cbor.Value v, String msg) {
        if (!(v instanceof Cbor.U u)) {
            throw new NaalpException("Malformed", msg);
        }
        return u.v;
    }

    private static String requireTstr(Cbor.Value v, String msg) {
        if (!(v instanceof Cbor.T t)) {
            throw new NaalpException("Malformed", msg);
        }
        return t.v;
    }

    private static byte[] requireBstr(Cbor.Value v, String msg) {
        if (!(v instanceof Cbor.B b)) {
            throw new NaalpException("Malformed", msg);
        }
        return b.v;
    }
}
