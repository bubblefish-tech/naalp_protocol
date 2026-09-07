// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The N-AALP error object and the numeric error-code registry for the Swift SDK (design.md §3.5,
// R3.3/R3.4, T3.3). The naalp-error object is the Control/Error body (channel 0x0000, kind 3,
// effect read_only) that carries one fail-closed rejection reason as
// {1:code, 2:name, ?3:detail, ?4:subject}. The registry is the ordered 129-entry name<->code table
// below (the code for NAMES[i] is i+1; 0 is reserved). NAMES is the single source the machine-
// readable registry (vectors/registry/error-codes.csv) and the CDDL naalp-error-code enum are
// generated to match, and scripts/registry_drift.py asserts the three agree; the table itself is
// graded against the non-circular oracle by the error.name_for_code conformance op.
//
// Two dual-carriage rules keep the code/name pair unambiguous and forward-compatible: a registered
// code whose name disagrees with the registry is rejected Malformed (the code is authoritative — the
// strengthening direction); a code outside the registry is opaque and non-fatal (the name is
// diagnostic only), so a receiver interoperates with a peer emitting a later-registered code.
//
// Ported from impl/go/naalperror/naalperror.go (copied verbatim), cross-read against the
// byte-identical impl/rust/src/naalperror.rs, impl/typescript/naalp/naalperror.mjs and
// impl/ruby/lib/naalp/naalperror.rb. Named `Naalperror` (matching the Go/Rust/Ruby module name
// capitalized, not `NaalpError`) so it does not collide with the `NaalpError` Swift `Error` struct
// declared in Cbor.swift and used throughout this SDK for throwing.
public enum Naalperror {

    /// The top of the RFC-Required standards range; codes >= 0x8000 are private-use.
    public static let STANDARDS_MAX: UInt64 = 0x7FFF

    /// The ordered error-code registry: the code for NAMES[i] is i+1 (0 is reserved and MUST NOT
    /// appear on the wire). Order is the fields-of-record authority for every code (§3.5). Copied
    /// verbatim from impl/go/naalperror/naalperror.go Names.
    public static let NAMES: [String] = [
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
    ]

    private static let codeByName: [String: UInt64] = {
        var m: [String: UInt64] = [:]
        m.reserveCapacity(NAMES.count)
        for (i, n) in NAMES.enumerated() { m[n] = UInt64(i + 1) }
        return m
    }()

    /// Returns the registered name for `code` and whether the code is registered. A code of 0, or
    /// any value past the registered range, is unregistered (opaque per the open-registry rule).
    public static func nameForCode(_ code: UInt64) -> (name: String, registered: Bool) {
        if code >= 1 && code <= UInt64(NAMES.count) {
            return (NAMES[Int(code) - 1], true)
        }
        return ("", false)
    }

    /// Returns the registered code for `name` and whether the name is registered.
    public static func codeForName(_ name: String) -> (code: UInt64, registered: Bool) {
        if let c = codeByName[name] {
            return (c, true)
        }
        return (0, false)
    }

    /// A decoded naalp-error body. `detail` is "" if field 3 was absent; `subject` is nil if field
    /// 4 was absent.
    public struct ErrorObject {
        public var code: UInt64
        public var name: String
        public var detail: String
        public var subject: [UInt8]?

        public init(code: UInt64, name: String, detail: String = "", subject: [UInt8]? = nil) {
            self.code = code
            self.name = name
            self.detail = detail
            self.subject = subject
        }
    }

    /// Returns the deterministic CBOR (RFC 8949 §4.2.1) of a naalp-error body
    /// {1:code, 2:name, ?3:detail, ?4:subject}. `detail == ""` omits field 3; `subject == nil` omits
    /// field 4. The integer keys 1..4 are already in canonical ascending order.
    public static func encode(_ code: UInt64, _ name: String, _ detail: String = "", _ subject: [UInt8]? = nil) throws -> [UInt8] {
        var pairs: [(CborValue, CborValue)] = [
            (.u(1), .u(code)),
            (.u(2), .t(name)),
        ]
        if !detail.isEmpty {
            pairs.append((.u(3), .t(detail)))
        }
        if let subject = subject {
            pairs.append((.u(4), .b(subject)))
        }
        return try Cbor.encode(.m(pairs))
    }

    /// Parses a naalp-error body and enforces the dual-carriage rules. A structurally malformed
    /// body (not a map, a non-integer key, a wrong-typed or unknown field, or a missing code/name)
    /// is rejected Malformed. A registered code whose name disagrees with the registry is rejected
    /// Malformed (the code is authoritative). An unregistered code is accepted opaque (name
    /// diagnostic only).
    public static func decode(_ data: [UInt8]) throws -> ErrorObject {
        let v: CborValue
        do {
            v = try Cbor.decode(data)
        } catch {
            throw NaalpError("Malformed", "naalp-error body is not well-formed deterministic CBOR")
        }
        guard case let .m(pairs) = v else {
            throw NaalpError("Malformed", "naalp-error body is not a map")
        }

        var code: UInt64? = nil
        var name: String? = nil
        var detail: String = ""
        var subject: [UInt8]? = nil

        for (k, val) in pairs {
            guard case let .u(kn) = k else {
                throw NaalpError("Malformed", "non-uint naalp-error key")
            }
            switch kn {
            case 1:
                guard case let .u(c) = val else { throw NaalpError("Malformed", "code not a uint") }
                code = c
            case 2:
                guard case let .t(n) = val else { throw NaalpError("Malformed", "name not a tstr") }
                name = n
            case 3:
                guard case let .t(d) = val else { throw NaalpError("Malformed", "detail not a tstr") }
                detail = d
            case 4:
                guard case let .b(s) = val else { throw NaalpError("Malformed", "subject not a bstr") }
                subject = s
            default:
                throw NaalpError("Malformed", "unknown naalp-error field \(kn)") // closed grammar
            }
        }

        guard let haveCode = code, let haveName = name else {
            throw NaalpError("Malformed", "naalp-error body missing code or name")
        }

        let (regName, registered) = nameForCode(haveCode)
        if registered && regName != haveName {
            throw NaalpError("Malformed", "registered code disagrees with the registry name")
        }

        return ErrorObject(code: haveCode, name: haveName, detail: detail, subject: subject)
    }
}
