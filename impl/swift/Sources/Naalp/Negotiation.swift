// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C20 — governed negotiation, advisory risk labels, and trust references for the Swift SDK
// (design.md §23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4).
//
// C20 adds three signed surfaces carried on N-AALP's own signed object. It introduces NO new envelope,
// encoding, signature, identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP
// body (COSE_Sign1), reusing the closed C5 effect lattice (Policy), the T1 content-id framing (§2.3),
// and the §8.2 causal partial order (the `causes` field) UNCHANGED.
//
// Task 5.1 — governed negotiation: a Message {1:negotiation, 2:role, 3:profile, 4:causes[]} is one signed
// step — an OFFER, a COUNTER, or an ACCEPT — causally linked to its predecessor(s) by content-id in
// `causes` (empty for an offer), SELECTING a profile from a CLOSED pre-registered set (no free-form or
// runtime capability, §23.9). An ACCEPT MUST DESCEND from its offer: walking the `causes` DAG from the
// accept must reach the offer's content-id (verifyAccept), else it is rejected (NotDescended). An unknown
// profile is rejected (UnknownProfile); an unknown role is rejected (UnknownRole).
//
// Task 5.2 — advisory risk labels: a RiskLabel {1:code, 2:critical} and a LabeledObject {1:effect,
// 2:labels[]}. `critical` is the per-carriage must-understand flag (uint 1/0; the spine carries no CBOR
// boolean, §3.1). The R-2.5 critical-extension rule applies: an unknown CRITICAL label is rejected
// (UnknownCriticalRisk); an unknown NON-critical label is ignored. The LOAD-BEARING invariant: carrying a
// risk label NEVER changes an object's effect class — effectClass derives from the effect field ALONE, so
// the closed C5 lattice is untouched. Risk labels are an advisory dimension, not a fifth effect.
//
// Task 5.3 — trust references: a TrustRef {1:registry, 2:reference, 3:subject} carries a third-party trust
// statement as a CHECKABLE signed object — `reference` is the T1 content-id of an EXTERNAL registry record.
// verifyTrustRef checks the signature and confirms the reference by RECOMPUTING that content-id over the
// external bytes (bindsRecord). But NO wire field WEIGHS the statement: there is no score, rank, or
// ordering, and this module provides NO scoring function — the protocol carries trust statements, it does
// not weigh them (§23.7). Which statement to believe is the relying party's, never a wire computation.
//
// An independent transcription of impl/go/negotiation (cross-read against impl/python/naalp/negotiation.py),
// graded against the shared vectors/negotiation/cases.json (values from the corpus, NEVER produced here).
// Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and causes
// no state change.
//
// CRYPTO SCOPE (PURE-ONLY, honest F2/F4): C20's cross-language SIGNED pins are real deterministic ML-DSA
// (FIPS 204) COSE_Sign1 objects (a signed offer, a signed read_only-with-labels labeled object, and a
// signed trust-ref A). Swift has no deterministic-from-seed ML-DSA signer (SwiftDilithium 3.6.0), so those
// signed pins are NOT reproducible here and are NOT faked. Every surface this port grades against the
// corpus — the Message/RiskLabel/LabeledObject/TrustRef bodies/heads/ids, the descent DAG + agreed profile,
// the effect-class-unchanged invariant, the R-2.5 critical-extension rule, the trust content-id recompute,
// and the NonCanonical / empty-vs-absent / look-alike wire edges — is signature-independent and pure. The
// signature BINDING (signMessage/verifyMessage, signLabeledObject/verifyLabeledObject,
// signTrustRef/verifyTrustRef) is demonstrated in isolation with a real Ed25519 (RFC 8032) round-trip via
// swift-crypto; the injected verify closure is the pure-tier stand-in for the reference's ML-DSA verifier.
// BadSignature / NonCanonical are the same kinds the reference carries.

import Crypto
import Foundation

public enum Negotiation {
    /// The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
    public static let HEAD_SIZE = 48

    /// A `(msg, sig) -> Bool` signature verifier the signed paths take by injection (Ed25519 on this pure
    /// Swift port; the reference resolves an ML-DSA verifier for the signer).
    public typealias Verify = (_ msg: [UInt8], _ sig: [UInt8]) -> Bool

    // ==== Task 5.1 — governed negotiation =========================================================

    /// The closed set of negotiation message roles. A role outside the set is rejected (UnknownRole).
    public static let ROLE_OFFER: UInt64 = 0   // the initiating offer (root of a negotiation; no causes)
    public static let ROLE_COUNTER: UInt64 = 1 // a counter-offer chaining onto the offer or a prior counter
    public static let ROLE_ACCEPT: UInt64 = 2  // the accept; it MUST descend from its offer

    static let roleNames: [UInt64: String] = [ROLE_OFFER: "offer", ROLE_COUNTER: "counter", ROLE_ACCEPT: "accept"]

    /// Whether r is one of the three defined negotiation roles.
    public static func knownRole(_ r: UInt64) -> Bool { return roleNames[r] != nil }

    /// The role name, or "unknown" for an out-of-range code.
    public static func roleName(_ r: UInt64) -> String { return roleNames[r] ?? "unknown" }

    /// The closed set of PRE-REGISTERED negotiation profiles. A negotiation SELECTS a pre-registered
    /// profile; it never carries a free-form capability string or a runtime-generated handler. A profile
    /// outside the set is rejected (UnknownProfile).
    public static let PROFILE_BASELINE: UInt64 = 0  // the baseline capability profile
    public static let PROFILE_STREAMING: UInt64 = 1 // the native-streaming capability profile (C9)
    public static let PROFILE_BATCH: UInt64 = 2     // the batched-delivery capability profile

    static let profileNames: [UInt64: String] = [PROFILE_BASELINE: "baseline", PROFILE_STREAMING: "streaming", PROFILE_BATCH: "batch"]

    /// Whether p is one of the pre-registered profiles (the closed set).
    public static func isRegisteredProfile(_ p: UInt64) -> Bool { return profileNames[p] != nil }

    /// The profile name, or "unknown" for an unregistered code.
    public static func profileName(_ p: UInt64) -> String { return profileNames[p] ?? "unknown" }

    /// One signed step of a governed negotiation: an offer, a counter, or an accept. It is causally linked
    /// to its predecessor(s) by content-id in `causes` (empty for an offer) and SELECTS a pre-registered
    /// profile.
    public struct Message {
        public let negotiation: [UInt8] // opaque negotiation id (ties the exchange together)
        public let role: UInt64         // offer / counter / accept (closed set)
        public let profile: UInt64      // the selected pre-registered profile (closed set; unknown rejected)
        public let causes: [[UInt8]]    // content-ids of predecessor messages (empty for an offer)

        public init(negotiation: [UInt8], role: UInt64, profile: UInt64, causes: [[UInt8]]) {
            self.negotiation = negotiation
            self.role = role
            self.profile = profile
            self.causes = causes
        }

        func toMap() -> CborValue {
            return .m([
                (.u(1), .b(negotiation)),
                (.u(2), .u(role)),
                (.u(3), .u(profile)),
                (.u(4), .a(causes.map { .b($0) })),
            ])
        }

        /// Deterministic-CBOR encoding {1: negotiation, 2: role, 3: profile, 4: causes[]}.
        public func bytes() throws -> [UInt8] { return try Cbor.encode(toMap()) }

        /// The Message's SHA-384 head (48 octets).
        public func head() throws -> [UInt8] { return Array(SHA384.hash(data: Data(try bytes()))) }

        /// The Message's T1 content-id (50 octets) — the id a successor names in its causes.
        public func id() throws -> [UInt8] { return Cbor.contentId(try bytes()) }
    }

    /// Build an offer (the root of a negotiation): role offer, no causes.
    public static func newOffer(_ negotiation: [UInt8], _ profile: UInt64) -> Message {
        return Message(negotiation: negotiation, role: ROLE_OFFER, profile: profile, causes: [])
    }

    /// Build a counter chaining onto the predecessor named by predecessorID.
    public static func newCounter(_ negotiation: [UInt8], _ profile: UInt64, _ predecessorID: [UInt8]) -> Message {
        return Message(negotiation: negotiation, role: ROLE_COUNTER, profile: profile, causes: [predecessorID])
    }

    /// Build an accept chaining onto the predecessor named by predecessorID. It must descend from its
    /// offer (checked by verifyAccept).
    public static func newAccept(_ negotiation: [UInt8], _ profile: UInt64, _ predecessorID: [UInt8]) -> Message {
        return Message(negotiation: negotiation, role: ROLE_ACCEPT, profile: profile, causes: [predecessorID])
    }

    /// Reconstruct a Message from its body bytes alone. It does NOT validate the role or profile against
    /// the closed sets — that is verifyMessage's job — so a message carrying an unknown role or profile can
    /// be represented and then rejected. A malformed shape, a non-canonical body, or a mistyped field is
    /// NegMalformed (fail-closed).
    public static func parseMessage(_ b: [UInt8]) throws -> Message {
        guard let m = decodeMap(b) else {
            throw NaalpError("NegMalformed", "object is not a well-formed negotiation body")
        }
        guard let neg = bstrField(m, 1), let role = uintField(m, 2), let prof = uintField(m, 3),
              let causesV = field(m, 4), case let .a(items) = causesV else {
            throw NaalpError("NegMalformed", "object is not a well-formed negotiation body")
        }
        var causes: [[UInt8]] = []
        for e in items {
            guard case let .b(bs) = e else {
                throw NaalpError("NegMalformed", "cause is not a bstr")
            }
            causes.append(bs)
        }
        return Message(negotiation: neg, role: role, profile: prof, causes: causes)
    }

    /// Produce the tagged COSE_Sign1 object over the Message body with a real Ed25519 (RFC 8032) signature
    /// (the pure-tier stand-in for the reference's deterministic ML-DSA signer).
    public static func signMessage(_ m: Message, _ seed: [UInt8]) throws -> [UInt8] {
        return try signBody(try m.bytes(), seed)
    }

    /// Verify a Message's signature via the injected verifier, reconstruct it from the signed body bytes,
    /// and validate it against the closed sets: the role MUST be offer/counter/accept (UnknownRole) and the
    /// selected profile MUST be pre-registered (UnknownProfile). A bad signature is BadSignature; a
    /// malformed body is NegMalformed. Fail-closed. `verify` is `(msg, sig) -> Bool`.
    public static func verifyMessage(_ obj: [UInt8], _ verify: Verify) throws -> Message {
        let payload = try verifyBody(obj, verify)
        let m = try parseMessage(payload)
        if !knownRole(m.role) {
            throw NaalpError("UnknownRole", "negotiation message role is not offer/counter/accept")
        }
        if !isRegisteredProfile(m.profile) {
            throw NaalpError("UnknownProfile", "negotiation selects a profile outside the closed pre-registered set")
        }
        return m
    }

    /// Build the content-id -> Message index the descent walk resolves predecessors through (keyed by the
    /// T1 content-id bytes).
    public static func indexByID(_ msgs: [Message]) throws -> [[UInt8]: Message] {
        var byID: [[UInt8]: Message] = [:]
        for m in msgs { byID[try m.id()] = m }
        return byID
    }

    /// Whether `accept` reaches `offer` by following causes edges resolved through byID: a real reachability
    /// walk over the causal DAG (a counter or a chain of counters between them is traversed). A cause that
    /// cannot be resolved through byID cannot extend the chain, so a forged causes pointer to an id the
    /// verifier never saw does not manufacture descent. Fail-closed. It performs no signature check.
    public static func descends(_ accept: Message, _ offer: Message, _ byID: [[UInt8]: Message]) throws -> Bool {
        let target = try offer.id()
        var seen = Set<[UInt8]>()
        var stack = accept.causes
        while let id = stack.popLast() {
            if id == target { return true }
            if seen.contains(id) { continue }
            seen.insert(id)
            guard let pred = byID[id] else { continue } // an unresolved cause: cannot walk through it
            stack.append(contentsOf: pred.causes)
        }
        return false
    }

    /// Check an accept against its offer over a set of verified messages, fail-closed. It requires `offer`
    /// to be a genuine offer selecting a pre-registered profile (NotOffer / UnknownProfile), `accept` to be
    /// an accept selecting a pre-registered profile (NotAccept / UnknownProfile), and the accept to DESCEND
    /// from the offer by walking the causes DAG through byID (NotDescended otherwise). Returns the AGREED
    /// profile (the accept's selected pre-registered profile). It authorizes nothing; it accepts or rejects.
    public static func verifyAccept(_ accept: Message, _ offer: Message, _ byID: [[UInt8]: Message]) throws -> UInt64 {
        if offer.role != ROLE_OFFER {
            throw NaalpError("NotOffer", "the object presented as the offer is not an offer role")
        }
        if !isRegisteredProfile(offer.profile) {
            throw NaalpError("UnknownProfile", "offer selects a profile outside the closed set")
        }
        if accept.role != ROLE_ACCEPT {
            throw NaalpError("NotAccept", "the object presented as the accept is not an accept role")
        }
        if !isRegisteredProfile(accept.profile) {
            throw NaalpError("UnknownProfile", "accept selects a profile outside the closed set")
        }
        if !(try descends(accept, offer, byID)) {
            throw NaalpError("NotDescended", "accept does not descend from its offer along the causes chain")
        }
        return accept.profile
    }

    // ==== Task 5.2 — advisory risk labels =========================================================

    /// A risk label's advisory class in the vocabulary: informing (purely informational) or gating (a
    /// policy MAY gate on it). This is a REGISTRY attribute of the label code, distinct from the per-carriage
    /// critical flag.
    public static let CLASS_INFORMING: UInt64 = 0
    public static let CLASS_GATING: UInt64 = 1

    static let riskClassNames: [UInt64: String] = [CLASS_INFORMING: "informing", CLASS_GATING: "gating"]

    /// The class name ("gating"/"informing"), or "" for an out-of-range value.
    public static func riskClassName(_ c: UInt64) -> String { return riskClassNames[c] ?? "" }

    /// The closed standard risk-label vocabulary codes.
    public static let RISK_SENSITIVE: UInt64 = 1  // gating: the object touches sensitive material
    public static let RISK_EGRESS: UInt64 = 2     // gating: the object causes data egress
    public static let RISK_REVERSIBLE: UInt64 = 3 // informing: the object's effect is reversible

    /// The first code of the private/experimental extensible range. A code at or above it is unknown to a
    /// verifier that lacks it — carried critical it is rejected (R-2.5), carried non-critical it is ignored.
    public static let EXTENSIBLE_RANGE_START: UInt64 = 0x1000

    /// The closed standard risk-label vocabulary: code -> class.
    static let riskVocab: [UInt64: UInt64] = [RISK_SENSITIVE: CLASS_GATING, RISK_EGRESS: CLASS_GATING, RISK_REVERSIBLE: CLASS_INFORMING]

    /// A code's vocabulary class and whether the code is a registered standard label.
    public static func riskClassOf(_ code: UInt64) -> (UInt64, Bool) {
        if let c = riskVocab[code] { return (c, true) }
        return (CLASS_INFORMING, false)
    }

    /// Whether code is in the closed standard vocabulary.
    public static func isRegisteredRisk(_ code: UInt64) -> Bool { return riskVocab[code] != nil }

    /// Whether code lies in the private/experimental extensible range.
    public static func inExtensibleRange(_ code: UInt64) -> Bool { return code >= EXTENSIBLE_RANGE_START }

    /// One advisory risk label carried on an object. `code` is the label code; `critical` is the
    /// per-carriage must-understand flag (1 = critical, 0 = advisory) — the uint 1/0, no CBOR boolean.
    public struct RiskLabel {
        public let code: UInt64
        public let critical: UInt64
        public init(code: UInt64, critical: UInt64) {
            self.code = code
            self.critical = critical
        }

        /// Whether the label is carried critical (must-understand).
        public func isCritical() -> Bool { return critical == 1 }

        func toMap() -> CborValue { return .m([(.u(1), .u(code)), (.u(2), .u(critical))]) }

        /// Deterministic-CBOR encoding of the risk-label body.
        public func bytes() throws -> [UInt8] { return try Cbor.encode(toMap()) }
    }

    static func riskLabelFromValue(_ v: CborValue) throws -> RiskLabel {
        guard case let .m(pairs) = v else {
            throw NaalpError("NegMalformed", "risk label is not a map")
        }
        guard let code = uintField(pairs, 1), let crit = uintField(pairs, 2) else {
            throw NaalpError("NegMalformed", "risk label missing a field")
        }
        if crit > 1 {
            throw NaalpError("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}")
        }
        return RiskLabel(code: code, critical: crit)
    }

    /// Apply the R-2.5 critical-extension rule to a set of carried risk labels: return the RECOGNIZED
    /// (standard-vocabulary) labels, DROP unknown non-critical labels, and REJECT an unknown CRITICAL label
    /// (UnknownCriticalRisk). A critical flag outside {0,1} is MalformedCriticalFlag. It NEVER inspects or
    /// returns an effect — risk labels are an advisory dimension, never a fifth effect. Fail-closed.
    public static func validateLabels(_ labels: [RiskLabel]) throws -> [RiskLabel] {
        var recognized: [RiskLabel] = []
        for l in labels {
            if l.critical > 1 {
                throw NaalpError("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}")
            }
            if isRegisteredRisk(l.code) {
                recognized.append(l)
                continue
            }
            if l.isCritical() {
                throw NaalpError("UnknownCriticalRisk", "an unknown critical risk label is rejected (R-2.5)")
            }
            // unknown non-critical: ignored (dropped from the recognized set)
        }
        return recognized
    }

    /// A minimal N-AALP object carrying an effect (field 1, C5) and a set of advisory risk labels. It exists
    /// to demonstrate — provably, in isolation — the load-bearing invariant that carrying a risk label NEVER
    /// changes the object's effect class.
    public struct LabeledObject {
        public let effect: UInt64
        public let labels: [RiskLabel]
        public init(effect: UInt64, labels: [RiskLabel]) {
            self.effect = effect
            self.labels = labels
        }

        func toMap() -> CborValue {
            return .m([
                (.u(1), .u(effect)),
                (.u(2), .a(labels.map { $0.toMap() })),
            ])
        }

        /// Deterministic-CBOR encoding {1: effect, 2: labels[]}.
        public func bytes() throws -> [UInt8] { return try Cbor.encode(toMap()) }

        /// The LabeledObject's SHA-384 head (48 octets).
        public func head() throws -> [UInt8] { return Array(SHA384.hash(data: Data(try bytes()))) }

        /// The LabeledObject's T1 content-id (50 octets).
        public func id() throws -> [UInt8] { return Cbor.contentId(try bytes()) }

        /// The object's C5 effect class, derived from the effect field ALONE and normalized fail-closed
        /// (unknown -> destructive, R-6.2). It DELIBERATELY does not consult the risk labels: a risk label
        /// is an advisory dimension, never a fifth effect, so the closed lattice is untouched by any label
        /// the object carries. This is the load-bearing C20 invariant. (A `UInt64 > 3` is normalized to
        /// destructive without a `UInt64 -> Int` conversion trap.)
        public func effectClass() -> Int {
            if effect <= 3 { return Policy.normalizeEffect(Int(effect)) }
            return Policy.DESTRUCTIVE
        }

        /// Apply the critical-extension rule to the object's carried labels.
        public func validateLabels() throws -> [RiskLabel] { return try Negotiation.validateLabels(labels) }
    }

    /// Reconstruct a LabeledObject from its body bytes alone. A malformed shape is NegMalformed; a critical
    /// flag outside {0,1} is MalformedCriticalFlag. Fail-closed.
    public static func parseLabeledObject(_ b: [UInt8]) throws -> LabeledObject {
        guard let m = decodeMap(b) else {
            throw NaalpError("NegMalformed", "object is not a well-formed labeled-object body")
        }
        guard let eff = uintField(m, 1), let labelsV = field(m, 2), case let .a(items) = labelsV else {
            throw NaalpError("NegMalformed", "object is not a well-formed labeled-object body")
        }
        let labels = try items.map { try riskLabelFromValue($0) }
        return LabeledObject(effect: eff, labels: labels)
    }

    /// Produce the tagged COSE_Sign1 object over the LabeledObject body (real Ed25519).
    public static func signLabeledObject(_ o: LabeledObject, _ seed: [UInt8]) throws -> [UInt8] {
        return try signBody(try o.bytes(), seed)
    }

    /// Verify the signature via the injected verifier, reconstruct the object, and apply the
    /// critical-extension rule to its labels (an unknown critical label is rejected). Returns (object,
    /// recognized labels). The returned object's effectClass is unchanged by any label. Fail-closed.
    public static func verifyLabeledObject(_ obj: [UInt8], _ verify: Verify) throws -> (LabeledObject, [RiskLabel]) {
        let payload = try verifyBody(obj, verify)
        let o = try parseLabeledObject(payload)
        let recognized = try validateLabels(o.labels)
        return (o, recognized)
    }

    // ==== Task 5.3 — trust references (checkable, never weighed) ==================================

    /// A third-party trust statement carried as a CHECKABLE signed object. `registry` is an opaque
    /// external-registry identifier (an ERC-8004-style reputation/identity registry — a name, not a URL the
    /// wire resolves); `reference` is the T1 content-id of the referenced external record; `subject` is the
    /// opaque id the statement is about. The wire CARRIES the reference; NO field here weighs it — there is
    /// no score, rank, or ordering.
    public struct TrustRef {
        public let registry: [UInt8]
        public let reference: [UInt8]
        public let subject: [UInt8]
        public init(registry: [UInt8], reference: [UInt8], subject: [UInt8]) {
            self.registry = registry
            self.reference = reference
            self.subject = subject
        }

        func toMap() -> CborValue {
            return .m([
                (.u(1), .b(registry)),
                (.u(2), .b(reference)),
                (.u(3), .b(subject)),
            ])
        }

        /// Deterministic-CBOR encoding {1: registry, 2: reference, 3: subject}.
        public func bytes() throws -> [UInt8] { return try Cbor.encode(toMap()) }

        /// The TrustRef's SHA-384 head (48 octets).
        public func head() throws -> [UInt8] { return Array(SHA384.hash(data: Data(try bytes()))) }

        /// The TrustRef's own T1 content-id (50 octets).
        public func id() throws -> [UInt8] { return Cbor.contentId(try bytes()) }

        /// The content-id the trust ref binds (the carried external-record reference).
        public func referenceID() -> [UInt8] { return reference }

        /// Whether the carried reference is the T1 content-id of `record` — i.e. the reference recomputes
        /// over the presented external bytes. This is the CHECK a relying party runs to confirm the reference
        /// names those exact external bytes; it computes NO score. A changed record yields a different
        /// content-id, so bindsRecord returns false.
        public func bindsRecord(_ record: [UInt8]) -> Bool {
            return reference == Cbor.contentId(record)
        }
    }

    /// Reconstruct a TrustRef from its body bytes alone. Fail-closed (NegMalformed).
    public static func parseTrustRef(_ b: [UInt8]) throws -> TrustRef {
        guard let m = decodeMap(b) else {
            throw NaalpError("NegMalformed", "object is not a well-formed trust-ref body")
        }
        guard let reg = bstrField(m, 1), let ref = bstrField(m, 2), let subj = bstrField(m, 3) else {
            throw NaalpError("NegMalformed", "object is not a well-formed trust-ref body")
        }
        return TrustRef(registry: reg, reference: ref, subject: subj)
    }

    /// Produce the tagged COSE_Sign1 object over the TrustRef body (real Ed25519).
    public static func signTrustRef(_ r: TrustRef, _ seed: [UInt8]) throws -> [UInt8] {
        return try signBody(try r.bytes(), seed)
    }

    /// A TrustRef that has passed signature verification and (given the external record) the content-id
    /// recompute. It carries NO score, rank, or trust weight — the protocol does not weigh trust; which
    /// statement to believe is left to the relying party.
    public struct ResolvedTrustRef {
        public let registry: [UInt8]
        public let reference: [UInt8]
        public let subject: [UInt8]
    }

    /// Verify a trust reference end-to-end: (1) verify the signed object via the injected verifier
    /// (BadSignature); (2) reconstruct it from the signed bytes; and (3) confirm the reference by
    /// RECOMPUTING the external record's content-id and requiring it to equal the carried reference
    /// (ReferenceMismatch otherwise). Returns the resolved reference — and NOTHING that scores it: this
    /// module has no trust-weighting function, by design. Fail-closed.
    public static func verifyTrustRef(_ obj: [UInt8], _ verify: Verify, _ externalRecord: [UInt8]) throws -> ResolvedTrustRef {
        let payload = try verifyBody(obj, verify)
        let r = try parseTrustRef(payload)
        if !r.bindsRecord(externalRecord) {
            throw NaalpError("ReferenceMismatch", "trust-ref reference does not recompute over the record")
        }
        return ResolvedTrustRef(registry: r.registry, reference: r.reference, subject: r.subject)
    }

    // ---- signature helpers (real Ed25519 COSE_Sign1, demonstrated in isolation) -------------------

    /// The bare {1: nint(alg)} COSE_Sign1 protected header, as the reference cose.Sign1 emits. A negative-int
    /// CBOR head carries `arg` where the logical value is `-1 - alg`.
    static func protectedHeader(_ alg: Int) throws -> [UInt8] {
        return try Cbor.encode(.m([(.u(1), .n(UInt64(-1 - alg)))]))
    }

    static func signBody(_ payload: [UInt8], _ seed: [UInt8]) throws -> [UInt8] {
        let prot = try protectedHeader(Cose.ALG_ED25519)
        let sig = try Cose.ed25519Sign(seed, try Cose.toBeSignedRaw(prot, payload))
        return try Cose.assembleSign1Raw(prot, payload, sig)
    }

    static func verifyBody(_ obj: [UInt8], _ verify: Verify) throws -> [UInt8] {
        let (prot, payload, sig) = try Cose.parseSign1Raw(obj)
        if !verify(try Cose.toBeSignedRaw(prot, payload), sig) {
            throw NaalpError("BadSignature", "signature does not verify")
        }
        return payload
    }

    // ---- small deterministic-CBOR field accessors (strict decode; NonCanonical -> nil) ------------

    static func decodeMap(_ b: [UInt8]) -> [(CborValue, CborValue)]? {
        guard let v = try? Cbor.decode(b), case let .m(pairs) = v else {
            return nil
        }
        return pairs
    }

    static func field(_ m: [(CborValue, CborValue)], _ k: UInt64) -> CborValue? {
        for (kk, vv) in m {
            if case let .u(n) = kk, n == k { return vv }
        }
        return nil
    }

    static func bstrField(_ m: [(CborValue, CborValue)], _ k: UInt64) -> [UInt8]? {
        if case let .b(b)? = field(m, k) { return b }
        return nil
    }

    static func uintField(_ m: [(CborValue, CborValue)], _ k: UInt64) -> UInt64? {
        if case let .u(u)? = field(m, k) { return u }
        return nil
    }
}
