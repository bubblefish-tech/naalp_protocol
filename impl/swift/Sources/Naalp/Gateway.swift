// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C21 portable gateway-decision object for the Swift SDK (design.md §24; R-GW-1..6).
//
// A GatewayDecision is a SIGNED decision object an enforcement gateway of ANY vendor emits as
// PORTABLE EVIDENCE that it decided about an action. Its load-bearing property, exactly as the C18
// signed description, is that authority lives in the SIGNED BYTES, never in the connection or the
// host that served them: verifyDecision takes NO serving-party/connection identity, so the same
// signed decision RE-VERIFIES IDENTICALLY when a party OTHER than the gateway serves it (the
// third-party re-serve property). It introduces NO new envelope, encoding, signature, identity, or
// audit mechanism: the object is an ordinary signed N-AALP body (COSE_Sign1), reusing the closed C5
// effect lattice and the T1 content-id framing unchanged. This is the EVIDENCE FORMAT ONLY — never
// a policy language. Every check is fail-closed: a failing object is rejected whole, returns its
// named error, and causes no state change.
//
// An independent transcription of impl/go/gateway, graded against the shared
// vectors/gateway/cases.json.
//
// CRYPTO SCOPE (PURE-ONLY): the corpus-graded deliverable — the deterministic body/head/content-id,
// the closed decision set, and the strict-decoder rejections — is pure and complete here. Swift
// cannot deterministically sign or verify ML-DSA (FIPS 204) with SwiftDilithium 3.6.0; signDecision
// therefore uses a real Ed25519 (RFC 8032) signature to demonstrate the signing binding in
// isolation. verifyDecision is the full faithful transcription (alg registry + profile floor +
// signature + closed set); on the pure port its reachable branches are UnknownAlg and
// ProfileDowngrade (a level-0 Ed25519 object is below the level-3 floor), and it refuses an ML-DSA
// object (Unavailable, never a false green) rather than fake a verification result.

import Crypto
import Foundation

/// A signed decision an enforcement gateway emits as portable evidence. `decision` is the closed-set
/// outcome; `action` is the content id of the action decided about; `policy` is the opaque
/// deciding-policy identity (a name, not a program); `effect` is the action's C5 class.
public struct GatewayDecision {
    public let decision: UInt64
    public let action: [UInt8]
    public let policy: [UInt8]
    public let effect: UInt64
    /// OPTIONAL field 5 (R1); nil == absent (reads correspondence-only) -- never a stronger claim
    /// inferred from silence.
    public let ordering: OrderingDisclosure?
    /// OPTIONAL field 6 (R8); non-nil iff the decision was over foreign-protocol evidence.
    public let foreignProfile: ForeignProfilePin?

    public init(decision: UInt64, action: [UInt8], policy: [UInt8], effect: UInt64,
                ordering: OrderingDisclosure? = nil, foreignProfile: ForeignProfilePin? = nil) {
        self.decision = decision
        self.action = action
        self.policy = policy
        self.effect = effect
        self.ordering = ordering
        self.foreignProfile = foreignProfile
    }

    /// Deterministic-CBOR encoding {1: decision, 2: action, 3: policy, 4: effect, ?5: ordering,
    /// ?6: foreign-profile}. Fields 5/6 are OMITTED entirely when nil (the same omit-when-absent
    /// precedent as naalp-decision-record's optional fields 3/6/7).
    public func bytes() throws -> [UInt8] {
        var pairs: [(CborValue, CborValue)] = [
            (.u(1), .u(decision)),
            (.u(2), .b(action)),
            (.u(3), .b(policy)),
            (.u(4), .u(effect)),
        ]
        if let ordering = ordering {
            pairs.append((.u(5), ordering.toCbor()))
        }
        if let foreignProfile = foreignProfile {
            pairs.append((.u(6), foreignProfile.toCbor()))
        }
        return try Cbor.encode(.m(pairs))
    }

    /// The decision's SHA-384 head (48 octets).
    public func head() throws -> [UInt8] {
        return Array(SHA384.hash(data: Data(try bytes())))
    }

    /// The decision's T1 content-id: multihash(0x20, 0x30 [48]) || SHA-384(body) (50 octets).
    public func id() throws -> [UInt8] {
        return Cbor.contentId(try bytes())
    }

    /// The C5 effect class, normalized fail-closed: an unrecognized value is destructive (R-6.2).
    public func effectClass() -> Int {
        return Policy.normalizeEffect(Int(effect))
    }
}

/// A GatewayDecision that has passed signature verification. It carries NOTHING about who served the
/// bytes — the authority is the signature, so the resolved evidence is identical regardless of the
/// serving party (the third-party re-serve property).
public struct ResolvedDecision {
    public let decision: UInt64
    public let action: [UInt8]
    public let policy: [UInt8]
    public let effect: Int

    public init(decision: UInt64, action: [UInt8], policy: [UInt8], effect: Int) {
        self.decision = decision
        self.action = action
        self.policy = policy
        self.effect = effect
    }
}

public enum Gateway {
    /// The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
    public static let HEAD_SIZE = 48

    // The closed set a gateway may emit; a code outside the set is rejected (UnknownGatewayDecision).
    public static let DECISION_ALLOW: UInt64 = 0  // the gateway allows the action
    public static let DECISION_DENY: UInt64 = 1   // the gateway denies the action
    public static let DECISION_HOLD: UInt64 = 2   // the gateway holds the action pending a further step

    /// decision code -> name (diagnostics); an unknown code has no entry.
    static let decisionNames: [UInt64: String] = [
        DECISION_ALLOW: "allow",
        DECISION_DENY: "deny",
        DECISION_HOLD: "hold",
    ]

    /// Reports whether code is one of the closed decision codes.
    public static func isKnownDecision(_ code: UInt64) -> Bool {
        return decisionNames[code] != nil
    }

    /// The decision name, or "unknown".
    public static func decisionName(_ code: UInt64) -> String {
        return decisionNames[code] ?? "unknown"
    }

    /// Build a key -> value map from a decoded CBOR map's pairs, keyed by the UInt64 value of any
    /// `.u` key (mirrors the Go/Python/Java/Rust embedded-field accessor field(m, k): a key that is
    /// not `.u` simply does not match -- it never causes the whole map to be rejected). The strict
    /// canonical decoder has already ruled out duplicate keys.
    static func fieldsOf(_ pairs: [(CborValue, CborValue)]) -> [UInt64: CborValue] {
        var fields: [UInt64: CborValue] = [:]
        for (k, val) in pairs {
            if case let .u(kn) = k {
                fields[kn] = val
            }
        }
        return fields
    }

    /// Reconstruct a GatewayDecision from its body bytes alone. It does NOT validate the decision
    /// code against the closed set, the ordering-disclosure's basis-conditioned well-formedness, or
    /// the foreign-profile-pin's field well-formedness — those are verifyDecision's job (mirroring
    /// the decision-record parse/validate split), so a decision carrying an unknown code, or an
    /// ordering/foreign-profile that is structurally decodable but semantically malformed, can be
    /// represented (and then rejected). It DOES enforce field-1-4 presence/type and, when field 5/6
    /// is PRESENT, that it decodes to the expected CBOR shape: present-with-wrong-type fails here
    /// (GwMalformed), never silently treated as absent. Fail-closed on a malformed shape: a
    /// non-canonical body, a non-map, or an absent/wrong-typed field 1-4 is GwMalformed.
    public static func parseDecision(_ b: [UInt8]) throws -> GatewayDecision {
        let v: CborValue
        do {
            v = try Cbor.decode(b)
        } catch {
            throw NaalpError("GwMalformed", "decision body is not well-formed deterministic CBOR")
        }
        guard case let .m(pairs) = v else {
            throw NaalpError("GwMalformed", "decision body is not a map")
        }
        let fields = fieldsOf(pairs)
        guard case let .u(dec)? = fields[1],
              case let .b(action)? = fields[2],
              case let .b(pol)? = fields[3],
              case let .u(eff)? = fields[4] else {
            throw NaalpError("GwMalformed", "decision body missing or wrong-typed field 1-4")
        }
        var ordering: OrderingDisclosure? = nil
        if let ordV = fields[5] {
            guard let o = orderingFromCbor(ordV) else {
                throw NaalpError("GwMalformed", "field 5 (ordering) is present but malformed")
            }
            ordering = o
        }
        var foreignProfile: ForeignProfilePin? = nil
        if let fpV = fields[6] {
            guard let fp = foreignProfileFromCbor(fpV) else {
                throw NaalpError("GwMalformed", "field 6 (foreign-profile) is present but malformed")
            }
            foreignProfile = fp
        }
        return GatewayDecision(decision: dec, action: action, policy: pol, effect: eff,
                               ordering: ordering, foreignProfile: foreignProfile)
    }

    /// The bare {1: alg} COSE_Sign1 protected header (§4); `alg` is a negative COSE identifier
    /// carried as a negative CBOR integer whose argument is `-1 - alg`.
    public static func gatewayProtectedHeader(_ alg: Int) throws -> [UInt8] {
        let arg = UInt64(-1 - alg)
        return try Cbor.encode(.m([(.u(1), .n(arg))]))
    }

    /// Produce the tagged COSE_Sign1 object over the decision body, signed by the gateway. PURE-ONLY
    /// Swift: the signature is a real Ed25519 (RFC 8032) signature demonstrating the signing binding —
    /// the reference signs with ML-DSA, which the pure port cannot reproduce.
    public static func signDecision(_ d: GatewayDecision, _ alg: Int, _ seed: [UInt8]) throws -> [UInt8] {
        let prot = try gatewayProtectedHeader(alg)
        let payload = try d.bytes()
        let sig = try Cose.ed25519Sign(seed, try Cose.toBeSignedRaw(prot, payload))
        return try Cose.assembleSign1Raw(prot, payload, sig)
    }

    /// Read the alg (label 1) value from an encoded protected header.
    public static func algFromProtected(_ prot: [UInt8]) throws -> Int {
        let v = try Cbor.decode(prot)
        guard case let .m(pairs) = v else {
            throw NaalpError("GwMalformed", "protected header is not a map")
        }
        for (k, val) in pairs {
            if case let .u(kn) = k, kn == 1 {
                if case let .n(arg) = val { return -1 - Int(arg) }
                if case let .u(u) = val { return Int(u) }
            }
        }
        throw NaalpError("GwMalformed", "protected header has no alg")
    }

    /// Verify a gateway decision end-to-end and return the resolved evidence. It (1) verifies the
    /// signed object under the profile with real crypto (signature, alg registry, profile floor)
    /// against the gateway's key; (2) reconstructs it from the signed bytes; and (3) validates the
    /// decision code against the closed set (UnknownGatewayDecision). It takes NO serving-party or
    /// connection identity: the authority is the signature over the bytes, so the same obj yields an
    /// identical ResolvedDecision whether the gateway or an unrelated third party served it. Any
    /// failure returns its named error and resolves nothing (fail-closed).
    ///
    /// PURE-ONLY Swift: the profile floor is level 3 (ML-DSA), so a pure-Ed25519 (level-0) object is
    /// correctly rejected ProfileDowngrade here; an ML-DSA object is refused at the signature step
    /// (Unavailable — the pure port cannot verify ML-DSA) rather than passed silently.
    public static func verifyDecision(_ obj: [UInt8], _ profile: Int, _ alg: Int, _ pubkey: [UInt8]) throws -> ResolvedDecision {
        let (prot, payload, sig) = try Cose.parseSign1Raw(obj)
        let halg = try algFromProtected(prot)
        let (level, known) = Cose.algLevel(halg)
        if !known {
            throw NaalpError("UnknownAlg", "unregistered alg \(halg)")
        }
        if level < Cose.profileMinLevel(profile) {
            throw NaalpError("ProfileDowngrade", "signature level below the profile minimum")
        }
        if halg != alg {
            throw NaalpError("KeyAlgMismatch", "alg \(halg) does not match the verifier key alg \(alg)")
        }
        let tbs = try Cose.toBeSignedRaw(prot, payload)
        if halg == Cose.ALG_ED25519 {
            if !Cose.ed25519Verify(pubkey, tbs, sig) {
                throw NaalpError("BadSignature", "signature does not verify")
            }
        } else {
            // ML-DSA verification is unavailable on the pure Swift port (skip-tracked, never a false
            // green), exactly as Cose.coseVerify1 / Envelope.verify. Reachable only for a level-3+
            // object that passed the profile floor; a pure Ed25519 object is rejected at
            // ProfileDowngrade before this point.
            throw NaalpError("Unavailable", "ML-DSA verification requires a deterministic-from-seed FIPS 204 path unavailable in SwiftDilithium 3.6.0")
        }
        let d = try parseDecision(payload)
        if !isKnownDecision(d.decision) {
            throw NaalpError("UnknownGatewayDecision", "decision code \(d.decision) outside the closed set")
        }
        if let ordering = d.ordering {
            try ordering.validate()
        }
        if let foreignProfile = d.foreignProfile {
            try foreignProfile.validate()
        }
        return ResolvedDecision(decision: d.decision, action: d.action, policy: d.policy,
                                effect: Policy.normalizeEffect(Int(d.effect)))
    }
}

// =====================================================================================================
// Evidence-record family (E6.3 egress-attestation + S1 decision-record + S3 checkpoint + R1/R8
// ordering-disclosure / foreign-profile-pin), ported from impl/go/gateway/{ordering,decision_record,
// checkpoint,egress_attestation}.go; graded against the shared vectors/{decision_record,checkpoint,
// egress_attestation}/cases.json plus gateway/cases.json's optional_fields{} block.
//
// CRYPTO SCOPE (FULL, not pure-only): unlike the base GatewayDecision above (written before the
// Swift port's ML-DSA path landed), sign/verify for this family route through Cose.coseSign1 /
// Cose.coseVerify1, which dispatch real deterministic (rnd=0) FIPS-204 ML-DSA-65/-87 via
// swift-crypto's vendored BoringSSL (MlDsa.swift, task #96/#142) as well as Ed25519 — so the signed
// object is byte-identical to the Go/Rust/Python/Java references and the third-party re-serve
// property is demonstrated with the SAME real crypto the profile floor requires, not a stand-in.
// =====================================================================================================

// ---- ordering-disclosure embeddable group (design.md §26.3) ---------------------------------------
//
// `ordering-disclosure` states what, if anything, establishes decision->effect / record->event
// ORDER, and from which observational domain, rather than leaving the reader to assume more than the
// bytes support. It is carried as a field inside naalp-decision-record (mandatory, field 5),
// naalp-egress-attestation (optional, field 6), and naalp-gateway-decision (optional, field 5) —
// never as a top-level object of its own, so it has no bytes()/head()/id() of its own; it is embedded
// directly as a nested CBOR map value inside its carrying record.
//
// `correspondence-only` (0) is the weakest claim and the value a verifier MUST read when the field is
// ABSENT on an optional carrier — never a stronger claim inferred from silence. `single-boundary` (1)
// names one covering boundary. `external-mechanism` (2) names an external sequencing mechanism and,
// optionally, the log relation binding the record under it.
//
// Well-formedness is fail-closed and NATIVE: correspondence-only requires keys 2/3/4 absent;
// single-boundary requires key 2 present and 3/4 absent; external-mechanism requires key 3 present (4
// optional) and key 2 absent. Any violation rejects the WHOLE carrying record
// (OrderingDisclosureMalformed).

/// The embeddable group {1: basis, ?2: boundary, ?3: mechanism, ?4: relation} (design.md §26.3). It
/// is never a top-level signed object; it is always a field inside another record. The zero value
/// (basis = correspondenceOnly, no boundary/mechanism/relation) is the weakest claim and is exactly
/// what an ABSENT optional ordering-disclosure field reads as.
public struct OrderingDisclosure {
    public let basis: UInt64
    public let boundary: [UInt8]  // present iff basis == ORDERING_SINGLE_BOUNDARY
    public let mechanism: [UInt8] // present iff basis == ORDERING_EXTERNAL_MECHANISM
    public let relation: [UInt8]  // present ONLY when basis == ORDERING_EXTERNAL_MECHANISM (optional even then)

    public init(basis: UInt64, boundary: [UInt8] = [], mechanism: [UInt8] = [], relation: [UInt8] = []) {
        self.basis = basis
        self.boundary = boundary
        self.mechanism = mechanism
        self.relation = relation
    }

    /// Returns self as a nested CBOR map VALUE (never top-level bytes — self is always embedded as a
    /// field inside its carrying record, so it has no bytes()/head()/id() of its own).
    func toCbor() -> CborValue {
        var pairs: [(CborValue, CborValue)] = [(.u(1), .u(basis))]
        if !boundary.isEmpty {
            pairs.append((.u(2), .b(boundary)))
        }
        if !mechanism.isEmpty {
            pairs.append((.u(3), .b(mechanism)))
        }
        if !relation.isEmpty {
            pairs.append((.u(4), .b(relation)))
        }
        return .m(pairs)
    }

    /// Checks (a) basis is in the closed set (UnknownOrderingBasis) and (b) the basis-conditioned
    /// field well-formedness rule (design.md §26.3, native and fail-closed — any violation rejects
    /// the whole carrying record, OrderingDisclosureMalformed). UnknownOrderingBasis is checked and
    /// thrown FIRST: an out-of-set basis is never additionally reported as malformed.
    public func validate() throws {
        if !Gateway.isKnownOrderingBasis(basis) {
            throw NaalpError("UnknownOrderingBasis",
                              "ordering-disclosure basis is outside the closed set correspondence-only/single-boundary/external-mechanism")
        }
        switch basis {
        case Gateway.ORDERING_CORRESPONDENCE_ONLY:
            if !boundary.isEmpty || !mechanism.isEmpty || !relation.isEmpty {
                throw NaalpError("OrderingDisclosureMalformed", "correspondence-only requires keys 2/3/4 absent")
            }
        case Gateway.ORDERING_SINGLE_BOUNDARY:
            if boundary.isEmpty || !mechanism.isEmpty || !relation.isEmpty {
                throw NaalpError("OrderingDisclosureMalformed", "single-boundary requires key 2 present, keys 3/4 absent")
            }
        case Gateway.ORDERING_EXTERNAL_MECHANISM:
            if !boundary.isEmpty || mechanism.isEmpty {
                throw NaalpError("OrderingDisclosureMalformed", "external-mechanism requires key 2 absent, key 3 present")
            }
        default:
            break
        }
    }
}

/// The embeddable group {1: kind, ?2: source} (design.md §26.4). `kind` is carried as a plain uint
/// on the wire (the CDDL does not close its value set the way ordering-basis does), so
/// TermDisposition itself validates no closed set — only naalp-decision-record's own field-6 key set
/// (the record's own field numbers) is fail-closed (TermDispositionMalformed).
public struct TermDisposition {
    public let kind: UInt64
    public let source: [UInt8] // present iff kind == TERM_REPORTED

    public init(kind: UInt64, source: [UInt8] = []) {
        self.kind = kind
        self.source = source
    }

    func toCbor() -> CborValue {
        var pairs: [(CborValue, CborValue)] = [(.u(1), .u(kind))]
        if !source.isEmpty {
            pairs.append((.u(2), .b(source)))
        }
        return .m(pairs)
    }
}

// ---- ForeignProfilePin: GatewayDecision field 6, R8 ------------------------------------------------

/// The embeddable group {1: id, 2: revision} (naalp-foreign-profile-pin, R8). Present on
/// GatewayDecision field 6 iff the decision was over foreign-protocol evidence: it pins the foreign
/// evidence profile's identifier (an absolute URI) AND the revision pinned at decision time —
/// binding the reference, not just the class. Both fields are mandatory tstr; the group carries no
/// other keys. It is never a top-level signed object — always embedded as field 6 of its carrying
/// naalp-gateway-decision, so it has no bytes()/head()/id() of its own (mirroring OrderingDisclosure).
public struct ForeignProfilePin {
    public let id: String
    public let revision: String
    let unknownField: Bool // an unrecognized key besides 1/2 was present in the decoded CBOR map

    public init(id: String = "", revision: String = "") {
        self.id = id
        self.revision = revision
        self.unknownField = false
    }

    init(id: String, revision: String, unknownField: Bool) {
        self.id = id
        self.revision = revision
        self.unknownField = unknownField
    }

    /// Returns self as a nested CBOR map VALUE {1: tstr(id), 2: tstr(revision)}.
    func toCbor() -> CborValue {
        return .m([(.u(1), .t(id)), (.u(2), .t(revision))])
    }

    /// Checks the foreign-profile-pin's own well-formedness (R8): both id and revision are mandatory
    /// non-empty tstr, and no key besides 1/2 may be present. A missing, empty, or extra field
    /// rejects the WHOLE carrying naalp-gateway-decision (ForeignProfileMalformed).
    public func validate() throws {
        if id.isEmpty || revision.isEmpty || unknownField {
            throw NaalpError("ForeignProfileMalformed",
                              "foreign-profile-pin is not well-formed (id and revision are mandatory tstr, no other keys)")
        }
    }
}

// ---- naalp-decision-record: S1, the full governed-decision accountability record ------------------
//
// A DecisionRecord is the SIGNED record a governed decision point emits that it decided about an
// action under a CLOSED, uniquely-selected condition set. It carries the T/T+n accountability triple
// (§26.1): UNIQUE SELECTION (field 2, the governing set in the clear as content ids); GOVERNED-AT-T
// (field 3, the naalp-consume-receipt spent at decision time); BINDING-FIXED-BY-T (established
// off-record by inclusion under a witnessed naalp-checkpoint-root). The record is deliberately
// CLOCK-FREE: it carries no claimed timestamp anywhere in its own body; both time properties are
// POSITIONAL, never a self-asserted timestamp. It introduces no new envelope, encoding, signature, or
// identity mechanism: an ordinary N-AALP signed body (COSE_Sign1), reusing the closed gw-decision
// outcome vocabulary unchanged.

/// The governed-decision accountability record (design.md §26.4). `action` is the content id of the
/// action decided about; `governing` is the closed governing condition set, content ids, in the
/// clear (may be empty); `consume` is OPTIONAL field 3 (content id of the consume-receipt spent at
/// decision time; empty == absent); `outcome` is field 4 (allow/deny/hold, reuses the closed
/// gw-decision set); `ordering` is field 5, MANDATORY (no silent default — every record states its
/// ordering basis); `terms` is OPTIONAL field 6 (per-term observed/reported, keyed by this record's
/// OWN field numbers 1..5; empty == absent); `enforcement` is OPTIONAL field 7 (enforced(1)/
/// advised(2); 0 == absent).
public struct DecisionRecord {
    public let action: [UInt8]
    public let governing: [[UInt8]]
    public let consume: [UInt8]
    public let outcome: UInt64
    public let ordering: OrderingDisclosure
    public let terms: [UInt64: TermDisposition]
    public let enforcement: UInt64

    public init(action: [UInt8], governing: [[UInt8]], outcome: UInt64, ordering: OrderingDisclosure,
                consume: [UInt8] = [], terms: [UInt64: TermDisposition] = [:], enforcement: UInt64 = 0) {
        self.action = action
        self.governing = governing
        self.consume = consume
        self.outcome = outcome
        self.ordering = ordering
        self.terms = terms
        self.enforcement = enforcement
    }

    /// Deterministic-CBOR encoding {1:action, 2:governing[], ?3:consume, 4:outcome, 5:ordering,
    /// ?6:terms, ?7:enforcement}. Fields 3/6/7 are OMITTED when absent (consume empty, terms empty,
    /// enforcement zero) — the omit-when-absent precedent (naalp-approval ?6:audience).
    public func bytes() throws -> [UInt8] {
        var pairs: [(CborValue, CborValue)] = [
            (.u(1), .b(action)),
            (.u(2), .a(governing.map { .b($0) })),
        ]
        if !consume.isEmpty {
            pairs.append((.u(3), .b(consume)))
        }
        pairs.append((.u(4), .u(outcome)))
        pairs.append((.u(5), ordering.toCbor()))
        if !terms.isEmpty {
            let tpairs: [(CborValue, CborValue)] = terms.map { (.u($0.key), $0.value.toCbor()) }
            pairs.append((.u(6), .m(tpairs)))
        }
        if enforcement != 0 {
            pairs.append((.u(7), .u(enforcement)))
        }
        return try Cbor.encode(.m(pairs))
    }

    /// The record's SHA-384 head (48 octets).
    public func head() throws -> [UInt8] { Array(SHA384.hash(data: Data(try bytes()))) }

    /// The record's T1 content-id (50 octets).
    public func id() throws -> [UInt8] { Cbor.contentId(try bytes()) }
}

/// A DecisionRecord that has passed signature verification and full semantic validation.
public struct ResolvedDecisionRecord {
    public let action: [UInt8]
    public let governing: [[UInt8]]
    public let consume: [UInt8]
    public let outcome: UInt64
    public let ordering: OrderingDisclosure
    public let terms: [UInt64: TermDisposition]
    public let enforcement: UInt64
}

// ---- naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof: S3 ----------------------
//
// S3 is the neither-party anchor for the BINDING-FIXED-BY-T leg of the accountability triple
// (design.md §26.5). Tree construction follows RFC 9162 (https://www.rfc-editor.org/rfc/rfc9162.html)
// §2.1 EXACTLY, SHA-384-profiled: leaf hash = HASH(0x00 || leaf); interior node hash =
// HASH(0x01 || left || right); MTH({}) = HASH() (the empty hash); MTH({d0}) = LEAF_HASH(d0);
// MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the largest power of two k < n. §2.1.2's
// PATH(m, D[n]) recursion (leaf-to-root sibling order) generates the audit path; §2.1.3.1's inverse
// recursion recomputes the root from (leaf, index, size, path) and compares against the named root
// (InclusionProofInvalid on mismatch, fail-closed).
//
// naalp-checkpoint-root is a log operator's signed Merkle tree head over a leaf set of record
// content ids, chaining by `prev` (genesis = HEAD_SIZE zero bytes). naalp-witness-cosign carries the
// wire hook for an independent countersignature over one exact checkpoint by content id;
// naalp-inclusion-proof proves one record's content id was a leaf under a named checkpoint. Two
// witness-cosigned roots at one (log, size) carrying different root values are fork evidence.

/// A log operator's signed Merkle tree head over a leaf set of record content ids (design.md §26.5).
public struct CheckpointRoot {
    public let log: [UInt8]
    public let size: UInt64
    public let root: [UInt8]
    public let prev: [UInt8]
    public let at: UInt64

    public init(log: [UInt8], size: UInt64, root: [UInt8], prev: [UInt8], at: UInt64) {
        self.log = log
        self.size = size
        self.root = root
        self.prev = prev
        self.at = at
    }

    /// Deterministic-CBOR encoding {1:log, 2:size, 3:root, 4:prev, 5:at}.
    public func bytes() throws -> [UInt8] {
        return try Cbor.encode(.m([
            (.u(1), .b(log)),
            (.u(2), .u(size)),
            (.u(3), .b(root)),
            (.u(4), .b(prev)),
            (.u(5), .u(at)),
        ]))
    }

    /// The checkpoint's SHA-384 head (48 octets) — the `prev` the NEXT checkpoint chains from.
    public func head() throws -> [UInt8] { Array(SHA384.hash(data: Data(try bytes()))) }

    /// The checkpoint's T1 content-id (50 octets) — what an inclusion proof's `root` field and a
    /// witness-cosign's `root` field both name.
    public func id() throws -> [UInt8] { Cbor.contentId(try bytes()) }
}

/// A witness's countersignature over one exact checkpoint by content id (design.md §26.5). Whether
/// the witness's observational domain is genuinely distinct from both parties to the decisions the
/// checkpoint covers is a structural deployment fact checkable in substance at T+n — the wire
/// supplies the hook; it does not manufacture the independence itself.
public struct WitnessCosign {
    public let witness: [UInt8]
    public let root: [UInt8]
    public let at: UInt64

    public init(witness: [UInt8], root: [UInt8], at: UInt64) {
        self.witness = witness
        self.root = root
        self.at = at
    }

    /// Deterministic-CBOR encoding {1:witness, 2:root, 3:at}.
    public func bytes() throws -> [UInt8] {
        return try Cbor.encode(.m([
            (.u(1), .b(witness)),
            (.u(2), .b(root)),
            (.u(3), .u(at)),
        ]))
    }

    /// The cosign's SHA-384 head (48 octets).
    public func head() throws -> [UInt8] { Array(SHA384.hash(data: Data(try bytes()))) }

    /// The cosign's T1 content-id (50 octets).
    public func id() throws -> [UInt8] { Cbor.contentId(try bytes()) }
}

/// Proves one record's content id existed as a leaf under a named checkpoint (design.md §26.5, RFC
/// 9162 §2.1.3.1).
public struct InclusionProof {
    public let root: [UInt8]
    public let leaf: [UInt8]
    public let index: UInt64
    public let path: [[UInt8]]

    public init(root: [UInt8], leaf: [UInt8], index: UInt64, path: [[UInt8]]) {
        self.root = root
        self.leaf = leaf
        self.index = index
        self.path = path
    }

    /// Deterministic-CBOR encoding {1:root, 2:leaf, 3:index, 4:path[]}.
    public func bytes() throws -> [UInt8] {
        return try Cbor.encode(.m([
            (.u(1), .b(root)),
            (.u(2), .b(leaf)),
            (.u(3), .u(index)),
            (.u(4), .a(path.map { .b($0) })),
        ]))
    }

    /// The proof's SHA-384 head (48 octets).
    public func head() throws -> [UInt8] { Array(SHA384.hash(data: Data(try bytes()))) }

    /// The proof's T1 content-id (50 octets).
    public func id() throws -> [UInt8] { Cbor.contentId(try bytes()) }
}

/// Internal sentinel: the recursive root recomputation ran out of path entries (or had entries left
/// over) before reaching the single-leaf base case. Always surfaced to callers as
/// InclusionProofInvalid — never exported.
private struct PathLengthMismatch: Error {}

// ---- naalp-egress-attestation: E6.3 ----------------------------------------------------------------
//
// A naalp-egress-attestation is a SIGNED attestation a gateway/sidecar emits that an object of a
// given effect class, bound to a given audience, crossed an egress boundary at a given time —
// third-party verifiable WITHOUT the payload. It is a near-clone of GatewayDecision: the gateway is
// the SIGNER, and verifyEgressAttestation takes NO serving-party or connection identity — the
// authority is the signature over the bytes, so the identical attested evidence re-verifies whether
// the gateway or an unrelated third party serves it. `binding` is a closed set
// (content_bound/content_free); `digest` is either the T1 content-id of the crossed object
// (content_bound) or a hiding commitment SHA-384(content_id||salt) (content_free) — never both;
// `effect` is the C5 effect class of the crossed object; `audience` is the bound destination
// (empty-permitted); `at` is the crossing time in epoch milliseconds. Field 6 (`ordering`) is
// OPTIONAL: ABSENT reads correspondence-only, never a stronger claim inferred from silence.
//
// The content_free binding lets a gateway attest an egress crossing WITHOUT disclosing which object
// crossed. egressCommit/openEgressCommitment is the open/verify pair: the gateway (or anyone it
// later discloses content-id+salt to) can PROVE which object a content_free attestation names,
// without the attestation bytes themselves ever carrying the content-id.

/// A signed attestation a gateway/sidecar emits that an object crossed an egress boundary. `binding`
/// selects how `digest` is interpreted (content_bound: the crossed object's T1 content-id;
/// content_free: a hiding commitment). `effect` is the crossed object's C5 effect class. `audience`
/// is the bound destination (empty-permitted). `at` is the crossing time, epoch ms. `ordering` is
/// the OPTIONAL field 6: nil == ABSENT (reads correspondence-only).
public struct EgressAttestation {
    public let binding: UInt64
    public let digest: [UInt8]
    public let effect: UInt64
    public let audience: [UInt8]
    public let at: UInt64
    public let ordering: OrderingDisclosure?

    public init(binding: UInt64, digest: [UInt8], effect: UInt64, audience: [UInt8], at: UInt64,
                ordering: OrderingDisclosure? = nil) {
        self.binding = binding
        self.digest = digest
        self.effect = effect
        self.audience = audience
        self.at = at
        self.ordering = ordering
    }

    /// Deterministic-CBOR encoding {1: binding, 2: digest, 3: effect, 4: audience, 5: at,
    /// ?6: ordering}. Field 6 is OMITTED when `ordering` is nil.
    public func bytes() throws -> [UInt8] {
        var pairs: [(CborValue, CborValue)] = [
            (.u(1), .u(binding)),
            (.u(2), .b(digest)),
            (.u(3), .u(effect)),
            (.u(4), .b(audience)),
            (.u(5), .u(at)),
        ]
        if let ordering = ordering {
            pairs.append((.u(6), ordering.toCbor()))
        }
        return try Cbor.encode(.m(pairs))
    }

    /// The attestation's SHA-384 head (48 octets).
    public func head() throws -> [UInt8] { Array(SHA384.hash(data: Data(try bytes()))) }

    /// The attestation's T1 content-id (50 octets).
    public func id() throws -> [UInt8] { Cbor.contentId(try bytes()) }

    /// The C5 effect class, normalized fail-closed: a value the evaluator does not recognize is
    /// treated as destructive, never as a weaker class.
    public func effectClass() -> Int { Policy.normalizeEffect(Int(effect)) }
}

/// An EgressAttestation that has passed signature verification. It carries NOTHING about WHO served
/// the bytes — the authority is the signature, so the resolved evidence is identical regardless of
/// the serving party (the third-party re-serve property).
public struct ResolvedEgressAttestation {
    public let binding: UInt64
    public let digest: [UInt8]
    public let effect: Int
    public let audience: [UInt8]
    public let at: UInt64
    public let ordering: OrderingDisclosure?
}

extension Gateway {
    // ---- ordering-disclosure vocabulary -----------------------------------------------------------

    public static let ORDERING_CORRESPONDENCE_ONLY: UInt64 = 0 // the record orders only its own two-party construction (the weakest claim)
    public static let ORDERING_SINGLE_BOUNDARY: UInt64 = 1     // one boundary observed both terms and is named
    public static let ORDERING_EXTERNAL_MECHANISM: UInt64 = 2  // an external sequencing mechanism is named

    static let orderingBasisNames: [UInt64: String] = [
        ORDERING_CORRESPONDENCE_ONLY: "correspondence-only",
        ORDERING_SINGLE_BOUNDARY: "single-boundary",
        ORDERING_EXTERNAL_MECHANISM: "external-mechanism",
    ]

    /// Reports whether code is one of the closed ordering-basis codes.
    public static func isKnownOrderingBasis(_ code: UInt64) -> Bool { orderingBasisNames[code] != nil }

    /// The ordering-basis name, or "unknown".
    public static func orderingBasisName(_ code: UInt64) -> String { orderingBasisNames[code] ?? "unknown" }

    /// The weakest ordering-disclosure claim, exactly what a verifier reads for an absent optional
    /// ordering-disclosure field.
    public static func correspondenceOnly() -> OrderingDisclosure {
        return OrderingDisclosure(basis: ORDERING_CORRESPONDENCE_ONLY)
    }

    /// Decodes a nested ordering-disclosure map value. Returns nil on any wrong shape, including an
    /// optional key present under the WRONG CBOR type (never silently treated as absent).
    static func orderingFromCbor(_ v: CborValue) -> OrderingDisclosure? {
        guard case let .m(pairs) = v else { return nil }
        let fields = fieldsOf(pairs)
        guard case let .u(basis)? = fields[1] else { return nil }
        var boundary: [UInt8] = [], mechanism: [UInt8] = [], relation: [UInt8] = []
        if let v2 = fields[2] {
            guard case let .b(bs) = v2 else { return nil }
            boundary = bs
        }
        if let v3 = fields[3] {
            guard case let .b(bs) = v3 else { return nil }
            mechanism = bs
        }
        if let v4 = fields[4] {
            guard case let .b(bs) = v4 else { return nil }
            relation = bs
        }
        return OrderingDisclosure(basis: basis, boundary: boundary, mechanism: mechanism, relation: relation)
    }

    // ---- term-disposition / enforcement-disposition vocabularies (design.md §26.4) ---------------

    public static let ENFORCEMENT_ENFORCED: UInt64 = 1 // the producer states it actually enforces this outcome
    public static let ENFORCEMENT_ADVISED: UInt64 = 2  // the producer's own unverifiable self-account that it only advises

    public static let TERM_OBSERVED: UInt64 = 1 // the term was observed first-hand
    public static let TERM_REPORTED: UInt64 = 2 // the term was reported, relayed from a named source

    /// Decodes a nested term-disposition map value. Returns nil on any wrong shape.
    static func termDispositionFromCbor(_ v: CborValue) -> TermDisposition? {
        guard case let .m(pairs) = v else { return nil }
        let fields = fieldsOf(pairs)
        guard case let .u(kind)? = fields[1] else { return nil }
        var source: [UInt8] = []
        if let v2 = fields[2] {
            guard case let .b(bs) = v2 else { return nil }
            source = bs
        }
        return TermDisposition(kind: kind, source: source)
    }

    // ---- ForeignProfilePin decode ------------------------------------------------------------------

    /// Decodes a nested foreign-profile-pin map value. Decode is STRUCTURAL only, mirroring
    /// orderingFromCbor: a key present under the WRONG CBOR type fails decode (returns nil, never
    /// silently treated as absent); a key that is simply ABSENT decodes to the empty string, leaving
    /// the mandatory-presence check to validate(). A key besides 1/2 marks the group's unknown-field
    /// flag, also caught by validate() — the closed 2-key set is enforced semantically, not by
    /// refusing to decode a map that merely carries an extra key.
    static func foreignProfileFromCbor(_ v: CborValue) -> ForeignProfilePin? {
        guard case let .m(pairs) = v else { return nil }
        var id = ""
        var revision = ""
        var unknown = false
        for (k, val) in pairs {
            if case let .u(kn) = k, kn == 1 {
                guard case let .t(s) = val else { return nil }
                id = s
            } else if case let .u(kn) = k, kn == 2 {
                guard case let .t(s) = val else { return nil }
                revision = s
            } else {
                unknown = true
            }
        }
        return ForeignProfilePin(id: id, revision: revision, unknownField: unknown)
    }

    // ---- naalp-decision-record: S1 ------------------------------------------------------------------

    /// Reconstruct a DecisionRecord from its body bytes alone. It performs ONLY structural checks
    /// (mandatory-field presence and CBOR type); it does NOT validate the outcome against the closed
    /// gw-decision set, the ordering disclosure's basis-conditioned well-formedness, the deny/hold-
    /// with-consume rule, or the terms key set — see validateDecisionRecord. Fail-closed on any
    /// malformed shape (DecisionMalformed).
    public static func parseDecisionRecord(_ b: [UInt8]) throws -> DecisionRecord {
        let v: CborValue
        do {
            v = try Cbor.decode(b)
        } catch {
            throw NaalpError("DecisionMalformed", "decision-record body is not well-formed deterministic CBOR")
        }
        guard case let .m(pairs) = v else {
            throw NaalpError("DecisionMalformed", "decision-record body is not a map")
        }
        let fields = fieldsOf(pairs)
        guard case let .b(action)? = fields[1], case let .a(govArr)? = fields[2] else {
            throw NaalpError("DecisionMalformed", "missing or wrong-typed field 1/2")
        }
        var governing: [[UInt8]] = []
        governing.reserveCapacity(govArr.count)
        for e in govArr {
            guard case let .b(bs) = e else {
                throw NaalpError("DecisionMalformed", "governing array element not a bstr")
            }
            governing.append(bs)
        }
        var consume: [UInt8] = []
        if let cv = fields[3] {
            guard case let .b(cbs) = cv else {
                throw NaalpError("DecisionMalformed", "field 3 (consume) wrong type")
            }
            consume = cbs
        }
        guard case let .u(outcome)? = fields[4] else {
            throw NaalpError("DecisionMalformed", "missing or wrong-typed field 4 (outcome)")
        }
        guard let ordV = fields[5] else {
            throw NaalpError("DecisionMalformed", "missing mandatory field 5 (ordering)")
        }
        guard let ordering = orderingFromCbor(ordV) else {
            throw NaalpError("DecisionMalformed", "field 5 (ordering) malformed")
        }
        var terms: [UInt64: TermDisposition] = [:]
        if let tv = fields[6] {
            guard case let .m(tpairs) = tv else {
                throw NaalpError("DecisionMalformed", "field 6 (terms) wrong type")
            }
            for (k, val) in tpairs {
                guard case let .u(ku) = k else {
                    throw NaalpError("DecisionMalformed", "terms map key not a uint")
                }
                guard let td = termDispositionFromCbor(val) else {
                    throw NaalpError("DecisionMalformed", "terms map value malformed")
                }
                terms[ku] = td
            }
        }
        var enforcement: UInt64 = 0
        if let ev = fields[7] {
            guard case let .u(eu) = ev else {
                throw NaalpError("DecisionMalformed", "field 7 (enforcement) wrong type")
            }
            enforcement = eu
        }
        return DecisionRecord(action: action, governing: governing, outcome: outcome, ordering: ordering,
                              consume: consume, terms: terms, enforcement: enforcement)
    }

    /// Reports whether k is one of the record's own field numbers 1..5 — the only valid keys for the
    /// field-6 terms map (design.md §26.4; TermDispositionMalformed otherwise).
    static func validDecisionRecordTermKey(_ k: UInt64) -> Bool { k >= 1 && k <= 5 }

    /// Performs the semantic, closed-set, and native well-formedness checks parseDecisionRecord
    /// deliberately does not (mirroring verifyDecision's parse/validate split):
    ///
    ///  1. Outcome must be in the closed gw-decision set (UnknownGatewayDecision).
    ///  2. Ordering must satisfy its basis-conditioned well-formedness rule (UnknownOrderingBasis /
    ///     OrderingDisclosureMalformed) — checked BEFORE the deny/hold-consume rule so a record whose
    ///     ordering is itself malformed is never additionally reported as a consume violation.
    ///  3. A deny/hold outcome carrying a field-3 consume reference is rejected in full
    ///     (DecisionMalformed) — nothing was consumed, so a value here would assert authority spent
    ///     for an action the record's own outcome says was not taken.
    ///  4. Every terms map key must be one of the record's own field numbers 1..5
    ///     (TermDispositionMalformed) — the map discloses provenance of the record's OWN terms, not
    ///     an arbitrary side channel.
    public static func validateDecisionRecord(_ d: DecisionRecord) throws {
        if !isKnownDecision(d.outcome) {
            throw NaalpError("UnknownGatewayDecision", "decision-record outcome \(d.outcome) outside the closed set")
        }
        try d.ordering.validate()
        if d.outcome != DECISION_ALLOW && !d.consume.isEmpty {
            throw NaalpError("DecisionMalformed", "a deny/hold outcome must not carry a field-3 consume reference")
        }
        for k in d.terms.keys {
            if !validDecisionRecordTermKey(k) {
                throw NaalpError("TermDispositionMalformed", "a terms map key is outside the record's own field set 1..5")
            }
        }
    }

    /// Produces the tagged COSE_Sign1 object over the record body, signed by the governed decision
    /// point.
    public static func signDecisionRecord(_ d: DecisionRecord, _ alg: Int, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.coseSign1(alg, seed, try gatewayProtectedHeader(alg), try d.bytes())
    }

    /// Verifies a decision record end-to-end: (1) the signed object under the profile with real
    /// crypto (Cose.coseVerify1 — signature, alg registry, profile floor); (2) structural
    /// reconstruction (parseDecisionRecord); and (3) full semantic validation (validateDecisionRecord).
    /// It takes no serving-party or connection identity — the authority is the signature over the
    /// bytes, mirroring verifyDecision/R-GW-3. Any failure throws its named error and resolves
    /// nothing (fail-closed).
    public static func verifyDecisionRecord(_ obj: [UInt8], _ profile: Int, _ alg: Int, _ pubkey: [UInt8]) throws -> ResolvedDecisionRecord {
        let (prot, payload, _) = try Cose.parseSign1Raw(obj)
        let halg = try algFromProtected(prot)
        let (level, known) = Cose.algLevel(halg)
        if !known {
            throw NaalpError("UnknownAlg", "unregistered alg \(halg)")
        }
        if level < Cose.profileMinLevel(profile) {
            throw NaalpError("ProfileDowngrade", "signature level below the profile minimum")
        }
        if halg != alg {
            throw NaalpError("KeyAlgMismatch", "alg \(halg) does not match the verifier key alg \(alg)")
        }
        if try !Cose.coseVerify1(halg, pubkey, obj) {
            throw NaalpError("BadSignature", "signature does not verify")
        }
        let d = try parseDecisionRecord(payload)
        try validateDecisionRecord(d)
        return ResolvedDecisionRecord(action: d.action, governing: d.governing, consume: d.consume,
                                      outcome: d.outcome, ordering: d.ordering, terms: d.terms,
                                      enforcement: d.enforcement)
    }

    // ---- naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof: S3 -----------------

    /// The HEAD_SIZE all-zero prev value a log's first checkpoint chains from.
    public static func genesisPrev() -> [UInt8] { [UInt8](repeating: 0, count: HEAD_SIZE) }

    /// Reconstruct a CheckpointRoot from its body bytes alone. Fail-closed on any malformed shape
    /// (CheckpointMalformed): every one of the five fields is mandatory.
    public static func parseCheckpointRoot(_ b: [UInt8]) throws -> CheckpointRoot {
        let v: CborValue
        do {
            v = try Cbor.decode(b)
        } catch {
            throw NaalpError("CheckpointMalformed", "checkpoint-root body is not well-formed deterministic CBOR")
        }
        guard case let .m(pairs) = v else {
            throw NaalpError("CheckpointMalformed", "checkpoint-root body is not a map")
        }
        let fields = fieldsOf(pairs)
        guard case let .b(log)? = fields[1], case let .u(size)? = fields[2], case let .b(root)? = fields[3],
              case let .b(prev)? = fields[4], case let .u(at)? = fields[5] else {
            throw NaalpError("CheckpointMalformed", "missing or wrong-typed field 1-5")
        }
        return CheckpointRoot(log: log, size: size, root: root, prev: prev, at: at)
    }

    /// Produces the tagged COSE_Sign1 object over the checkpoint body, signed by the log operator.
    public static func signCheckpointRoot(_ c: CheckpointRoot, _ alg: Int, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.coseSign1(alg, seed, try gatewayProtectedHeader(alg), try c.bytes())
    }

    /// Reconstruct a WitnessCosign from its body bytes alone. Fail-closed on any malformed shape:
    /// every one of the three fields is mandatory.
    public static func parseWitnessCosign(_ b: [UInt8]) throws -> WitnessCosign {
        let v: CborValue
        do {
            v = try Cbor.decode(b)
        } catch {
            throw NaalpError("CheckpointMalformed", "witness-cosign body is not well-formed deterministic CBOR")
        }
        guard case let .m(pairs) = v else {
            throw NaalpError("CheckpointMalformed", "witness-cosign body is not a map")
        }
        let fields = fieldsOf(pairs)
        guard case let .b(witness)? = fields[1], case let .b(root)? = fields[2], case let .u(at)? = fields[3] else {
            throw NaalpError("CheckpointMalformed", "missing or wrong-typed field 1-3")
        }
        return WitnessCosign(witness: witness, root: root, at: at)
    }

    /// Produces the tagged COSE_Sign1 object over the cosign body, signed by the witness.
    public static func signWitnessCosign(_ w: WitnessCosign, _ alg: Int, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.coseSign1(alg, seed, try gatewayProtectedHeader(alg), try w.bytes())
    }

    /// Checks that w names the EXACT checkpoint it accompanies (WitnessRootMismatch, design.md
    /// §26.5): w.root must equal accompaniedCheckpointID, the content id of the naalp-checkpoint-root
    /// object w claims to cosign. Fail-closed.
    public static func validateWitnessCosign(_ w: WitnessCosign, _ accompaniedCheckpointID: [UInt8]) throws {
        if w.root != accompaniedCheckpointID {
            throw NaalpError("WitnessRootMismatch",
                              "witness-cosign names a root content id that does not match the checkpoint it accompanies")
        }
    }

    /// Reconstruct an InclusionProof from its body bytes alone. Fail-closed on any malformed shape:
    /// every one of the four fields is mandatory.
    public static func parseInclusionProof(_ b: [UInt8]) throws -> InclusionProof {
        let v: CborValue
        do {
            v = try Cbor.decode(b)
        } catch {
            throw NaalpError("CheckpointMalformed", "inclusion-proof body is not well-formed deterministic CBOR")
        }
        guard case let .m(pairs) = v else {
            throw NaalpError("CheckpointMalformed", "inclusion-proof body is not a map")
        }
        let fields = fieldsOf(pairs)
        guard case let .b(root)? = fields[1], case let .b(leaf)? = fields[2], case let .u(index)? = fields[3],
              case let .a(pathArr)? = fields[4] else {
            throw NaalpError("CheckpointMalformed", "missing or wrong-typed field 1-4")
        }
        var path: [[UInt8]] = []
        path.reserveCapacity(pathArr.count)
        for e in pathArr {
            guard case let .b(bs) = e else {
                throw NaalpError("CheckpointMalformed", "path array element not a bstr")
            }
            path.append(bs)
        }
        return InclusionProof(root: root, leaf: leaf, index: index, path: path)
    }

    // ---- RFC 9162 §2.1 Merkle tree math (SHA-384-profiled) -----------------------------------------

    /// leafHash = HASH(0x00 || leaf) (RFC 9162 §2.1's LEAF_HASH, leaf/interior domain separation).
    static func leafHash(_ leaf: [UInt8]) -> [UInt8] {
        var b: [UInt8] = [0x00]
        b.append(contentsOf: leaf)
        return Array(SHA384.hash(data: Data(b)))
    }

    /// nodeHash = HASH(0x01 || left || right) (RFC 9162 §2.1's NODE_HASH).
    static func nodeHash(_ l: [UInt8], _ r: [UInt8]) -> [UInt8] {
        var b: [UInt8] = [0x01]
        b.append(contentsOf: l)
        b.append(contentsOf: r)
        return Array(SHA384.hash(data: Data(b)))
    }

    /// The largest power of two strictly less than n (n > 1), per RFC 9162 §2.1's k = "the largest
    /// power of two smaller than n" (the split point).
    static func largestPowerOfTwoLessThan(_ n: Int) -> Int {
        var k = 1
        while 2 * k < n { k *= 2 }
        return k
    }

    /// Computes MTH(leaves) per RFC 9162 §2.1: MTH({}) = HASH() (SHA-384 of the empty string);
    /// MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the largest
    /// power of two k < n. leaves are raw leaf VALUES (record content ids); LEAF_HASH is applied
    /// internally — callers never hash a leaf before calling merkleRoot.
    public static func merkleRoot(_ leaves: [[UInt8]]) -> [UInt8] {
        let n = leaves.count
        if n == 0 {
            return Array(SHA384.hash(data: Data())) // MTH({}) = HASH(""), the empty-list base case
        }
        if n == 1 {
            return leafHash(leaves[0])
        }
        let k = largestPowerOfTwoLessThan(n)
        return nodeHash(merkleRoot(Array(leaves[0..<k])), merkleRoot(Array(leaves[k...])))
    }

    /// Computes the RFC 9162 §2.1.2 PATH(index, leaves) audit path (leaf-to-root sibling order — the
    /// array's FIRST entry is the leaf's immediate sibling, the LAST is closest to the root, exactly
    /// the order naalp-inclusion-proof's `path` field carries).
    public static func generateInclusionProofPath(_ leaves: [[UInt8]], _ index: Int) throws -> [[UInt8]] {
        if index < 0 || index >= leaves.count {
            throw NaalpError("InclusionProofInvalid", "leaf index out of range")
        }
        return genPath(leaves, index)
    }

    static func genPath(_ leaves: [[UInt8]], _ index: Int) -> [[UInt8]] {
        let n = leaves.count
        if n <= 1 {
            return [] // PATH(0, {d0}) = {} — the single-leaf base case
        }
        let k = largestPowerOfTwoLessThan(n)
        if index < k {
            var sub = genPath(Array(leaves[0..<k]), index)
            sub.append(merkleRoot(Array(leaves[k...])))
            return sub
        }
        var sub = genPath(Array(leaves[k...]), index - k)
        sub.append(merkleRoot(Array(leaves[0..<k])))
        return sub
    }

    /// The exact structural inverse of genPath: at each level it consumes the LAST remaining path
    /// entry (closest to the root) as this level's sibling and recurses into the appropriate half
    /// with the entries that remain.
    static func recomputeRoot(_ leafH: [UInt8], _ index: Int, _ size: Int, _ path: [[UInt8]]) throws -> [UInt8] {
        if size == 1 {
            if !path.isEmpty { throw PathLengthMismatch() }
            return leafH
        }
        if path.isEmpty { throw PathLengthMismatch() }
        let k = largestPowerOfTwoLessThan(size)
        let last = path[path.count - 1]
        let rest = Array(path[0..<(path.count - 1)])
        if index < k {
            let left = try recomputeRoot(leafH, index, k, rest)
            return nodeHash(left, last)
        }
        let right = try recomputeRoot(leafH, index - k, size - k, rest)
        return nodeHash(last, right)
    }

    /// Recomputes the audit path bottom-up (RFC 9162 §2.1.3.1, the inverse of PATH()) from (leaf,
    /// index, size, path) and compares the result against root. size is the tree size the proof is
    /// checked against — the resolved naalp-checkpoint-root's own `size` field, NOT carried inside
    /// naalp-inclusion-proof itself. Fail-closed: any mismatch, out-of-range index, or path-length
    /// mismatch is InclusionProofInvalid.
    public static func verifyInclusionProof(_ leaf: [UInt8], _ index: UInt64, _ size: UInt64,
                                            _ path: [[UInt8]], _ root: [UInt8]) throws {
        if size == 0 || index >= size {
            throw NaalpError("InclusionProofInvalid", "index out of range for the claimed tree size")
        }
        let got: [UInt8]
        do {
            got = try recomputeRoot(leafHash(leaf), Int(index), Int(size), path)
        } catch {
            throw NaalpError("InclusionProofInvalid", "inclusion path length does not match the claimed tree size")
        }
        if got != root {
            throw NaalpError("InclusionProofInvalid", "inclusion audit path does not recompute to the named root")
        }
    }

    // ---- naalp-egress-attestation: E6.3 -------------------------------------------------------------

    public static let BINDING_CONTENT_BOUND: UInt64 = 0 // digest is the crossed object's T1 content-id
    public static let BINDING_CONTENT_FREE: UInt64 = 1  // digest is a hiding commitment SHA-384(content_id||salt)

    static let bindingNames: [UInt64: String] = [
        BINDING_CONTENT_BOUND: "content_bound",
        BINDING_CONTENT_FREE: "content_free",
    ]

    /// Reports whether code is one of the closed binding codes.
    public static func isKnownBinding(_ code: UInt64) -> Bool { bindingNames[code] != nil }

    /// The binding name, or "unknown".
    public static func bindingName(_ code: UInt64) -> String { bindingNames[code] ?? "unknown" }

    /// Reconstruct an EgressAttestation from its body bytes alone. It does NOT validate the binding
    /// code against the closed set — that is verifyEgressAttestation's job — so an attestation
    /// carrying an unknown binding can be represented (and then rejected). Fail-closed on a
    /// malformed shape: every one of the five mandatory fields is required, and a present-but-
    /// wrong-typed field 6 fails here too.
    public static func parseEgressAttestation(_ b: [UInt8]) throws -> EgressAttestation {
        let v: CborValue
        do {
            v = try Cbor.decode(b)
        } catch {
            throw NaalpError("EgMalformed", "egress-attestation body is not well-formed deterministic CBOR")
        }
        guard case let .m(pairs) = v else {
            throw NaalpError("EgMalformed", "egress-attestation body is not a map")
        }
        let fields = fieldsOf(pairs)
        guard case let .u(binding)? = fields[1], case let .b(digest)? = fields[2], case let .u(effect)? = fields[3],
              case let .b(audience)? = fields[4], case let .u(at)? = fields[5] else {
            throw NaalpError("EgMalformed", "missing or wrong-typed field 1-5")
        }
        var ordering: OrderingDisclosure? = nil
        if let ordV = fields[6] {
            guard let o = orderingFromCbor(ordV) else {
                throw NaalpError("EgMalformed", "field 6 (ordering) is present but malformed")
            }
            ordering = o
        }
        return EgressAttestation(binding: binding, digest: digest, effect: effect, audience: audience, at: at, ordering: ordering)
    }

    /// Produces the tagged COSE_Sign1 object over the attestation body, signed by the gateway.
    public static func signEgressAttestation(_ a: EgressAttestation, _ alg: Int, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.coseSign1(alg, seed, try gatewayProtectedHeader(alg), try a.bytes())
    }

    /// Performs the semantic, closed-set checks parseEgressAttestation deliberately does not
    /// (mirroring verifyDecision's parse/verify split): the binding must be in the closed set
    /// (UnknownEgressBinding), and — if present — the field-6 ordering disclosure must satisfy its
    /// basis-conditioned well-formedness rule (UnknownOrderingBasis/OrderingDisclosureMalformed).
    public static func validateEgressAttestation(_ a: EgressAttestation) throws {
        if !isKnownBinding(a.binding) {
            throw NaalpError("UnknownEgressBinding",
                              "egress attestation binding code is outside the closed set content_bound/content_free")
        }
        if let ordering = a.ordering {
            try ordering.validate()
        }
    }

    /// Verifies an egress attestation end-to-end and returns the resolved evidence. It (1) verifies
    /// the signed object under the profile with real crypto (Cose.coseVerify1) against the GATEWAY's
    /// key; (2) reconstructs it from the signed bytes; and (3) validates the binding code against the
    /// closed set (UnknownEgressBinding), and the ordering disclosure if present. It takes NO
    /// serving-party or connection identity: the authority is the signature over the bytes, so the
    /// same obj yields an identical ResolvedEgressAttestation whether the gateway or an unrelated
    /// third party served it (the third-party re-serve property). Any failure throws its named error
    /// and resolves nothing (fail-closed).
    public static func verifyEgressAttestation(_ obj: [UInt8], _ profile: Int, _ alg: Int, _ pubkey: [UInt8]) throws -> ResolvedEgressAttestation {
        let (prot, payload, _) = try Cose.parseSign1Raw(obj)
        let halg = try algFromProtected(prot)
        let (level, known) = Cose.algLevel(halg)
        if !known {
            throw NaalpError("UnknownAlg", "unregistered alg \(halg)")
        }
        if level < Cose.profileMinLevel(profile) {
            throw NaalpError("ProfileDowngrade", "signature level below the profile minimum")
        }
        if halg != alg {
            throw NaalpError("KeyAlgMismatch", "alg \(halg) does not match the verifier key alg \(alg)")
        }
        if try !Cose.coseVerify1(halg, pubkey, obj) {
            throw NaalpError("BadSignature", "signature does not verify")
        }
        let a = try parseEgressAttestation(payload)
        try validateEgressAttestation(a)
        return ResolvedEgressAttestation(binding: a.binding, digest: a.digest, effect: Policy.normalizeEffect(Int(a.effect)),
                                         audience: a.audience, at: a.at, ordering: a.ordering)
    }

    // ---- content_free commitment open/verify pair -----------------------------------------------

    /// Constant-time byte comparison (mirrors crypto/subtle.ConstantTimeCompare): returns true iff a
    /// and b are equal length and byte-equal, without branching on the comparison result.
    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        if a.count != b.count { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }

    /// The content_free hiding commitment over an object's T1 content-id and a salt:
    /// SHA-384(objectCID || salt) (48 octets). The commitment reveals nothing about objectCID
    /// without the salt; a gateway builds it once to populate a content_free attestation's Digest
    /// field, and retains objectCID+salt to later prove which object crossed via
    /// openEgressCommitment.
    public static func egressCommit(_ objectCID: [UInt8], _ salt: [UInt8]) -> [UInt8] {
        var b = objectCID
        b.append(contentsOf: salt)
        return Array(SHA384.hash(data: Data(b)))
    }

    /// Proves which object crossed under a content_free attestation. It recomputes
    /// egressCommit(objectCID, salt) and compares it, in constant time, against a.digest. Returns
    /// true iff a is a content_free attestation AND the recomputed commitment matches: a wrong salt
    /// or a wrong objectCID both fail to open (return false), and a content_bound attestation never
    /// opens (its Digest is not a commitment).
    public static func openEgressCommitment(_ a: EgressAttestation, _ objectCID: [UInt8], _ salt: [UInt8]) -> Bool {
        if a.binding != BINDING_CONTENT_FREE { return false }
        let want = egressCommit(objectCID, salt)
        if want.count != a.digest.count { return false }
        return constantTimeEqual(want, a.digest)
    }
}
