// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C3 object envelope for the Swift SDK — the single signed object every kind, channel,
// and transport reuses (design.md §2). The object body is a deterministic-CBOR map (fields
// 1..12) carried as the COSE_Sign1 payload; field 1 is the content id,
// multihash(0x20, SHA-384(canonical-body-without-field-1)) (§2.3). The COSE protected header
// carries the signature algorithm plus a routing copy of the signer, profile, and naalp-version
// (§2.1, §2.5); a verifier that finds the header copies disagreeing with the body rejects the
// object (HeaderBodyMismatch). Every failure is fail-closed with a named error and no partial
// application (§2.6).
//
// This is the ergonomic surface a developer uses: build an Object, produce its content id,
// its signing-input bytes, and assemble the tagged COSE_Sign1; verify one from the object +
// key + spec alone. The pure-CBOR/COSE bytes are byte-identical to the Go, Rust and Python
// reference implementations — the worked example in vectors/worked/example.json is the
// byte-level known-answer for the pure surface.
//
// PURE-ONLY CRYPTO (see Cose.swift): SwiftDilithium 3.6.0 has no deterministic-from-seed
// (NIST ACVP xi) FIPS 204 path, so this SDK does NOT produce ML-DSA signatures. The envelope
// therefore exposes the ML-DSA-agnostic surface — `contentId`, `toBeSigned`, `protectedHeader`,
// and `assembleSigned` (bring your own signature) — plus a real Ed25519 (RFC 8032) sign/verify
// on the COSE layer via swift-crypto, and a full structural `verify`. The ML-DSA *signature*
// step of `verify` is skip-tracked (throws `Unavailable`, never a false green), exactly as the
// conformance contract sanctions for a language whose available library has no such path.

import Crypto
import Foundation

// The wire constants (EnvelopeField.*, the protected-header NAALP_VERSION, and the COSE header
// label naalpHeaderLabel) are projected from spec/wire-constants.csv into WireConstants.swift in the
// same module, so this port cannot re-type or drift a wire value. See scripts/gen_wire_constants.py;
// gate_wire_constants compares the generated values against the CSV authority.

// --- profile / algorithm level policy (mirrors cose.alg_level / cose.profile_min_level) ---
//
// Added here so the envelope's profile-floor check is self-contained (the base Cose.swift
// carries only the alg identifiers). Ed25519 is classical (level 0) — valid only as a hybrid
// leg, and below every profile floor, so a pure-Ed25519 object is rejected at ProfileDowngrade.
extension Cose {
    public static let PROFILE_PUBLIC = 1
    public static let PROFILE_ENTERPRISE = 2
    public static let PROFILE_SOVEREIGN = 3

    /// NIST security level of a registered alg, and whether it is registered.
    public static func algLevel(_ alg: Int) -> (level: Int, known: Bool) {
        switch alg {
        case ALG_MLDSA87: return (5, true)
        case ALG_MLDSA65: return (3, true)
        case ALG_ED25519: return (0, true)
        default: return (0, false)
        }
    }

    /// Minimum signature level a profile accepts (Sovereign floors at level 5; else 3).
    public static func profileMinLevel(_ profile: Int) -> Int {
        return profile == PROFILE_SOVEREIGN ? 5 : 3
    }

    /// The Ed25519 (RFC 8032) public key for a 32-byte seed, via swift-crypto. Lets a caller
    /// derive the verification key + signer id for the pure Ed25519 sign/verify path.
    public static func ed25519PublicKey(_ seed: [UInt8]) throws -> [UInt8] {
        if seed.count != 32 {
            throw NaalpError("Malformed", "ed25519 secret key must be a 32-byte seed")
        }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed))
        return Array(key.publicKey.rawRepresentation)
    }
}

/// A `(channel, kind) -> Bool` predicate reporting whether a surface kind is registered. The
/// envelope owns the fail-closed dispatch (UnknownKind); the per-channel kind tables are the
/// surface layer's content (see `Channels`). A nil validator rejects every kind.
public typealias KindValidator = (_ channel: UInt64, _ kind: UInt64) -> Bool

public enum Envelope {

    /// A decoded N-AALP object body. `id` is populated by the assembly/signing paths (§2.3).
    public struct Object {
        public var id: [UInt8]?
        public var kind: UInt64
        public var channel: UInt64
        public var tier: UInt64
        public var signer: [UInt8]
        public var created: UInt64
        public var effect: UInt64
        public var causes: [[UInt8]]
        public var profile: UInt64
        public var body: CborValue
        public var ext: CborValue?   // field 11, non-critical; nil = absent
        public var cext: CborValue?  // field 12, critical; nil = absent
        // field 13 (§2.5.3): the single-use consume binding. Omit-when-empty -- a no-audience object
        // encodes byte-identically to a draft-00 object (additivity). Anchors version 2.
        public var audience: String
        // field 14 (§4.2): the signed suite declaration for the opt-in Public/Enterprise composite.
        // 0 = absent (a pure object); non-zero iff sign() detected a composite signing alg. Omitting
        // it for a pure object keeps the object byte-identical to a pre-composite object.
        public var suite: UInt64

        public init(kind: UInt64, channel: UInt64, signer: [UInt8], created: UInt64,
                    effect: UInt64, body: CborValue, tier: UInt64 = 0,
                    profile: UInt64 = UInt64(Cose.PROFILE_PUBLIC), causes: [[UInt8]] = [],
                    ext: CborValue? = nil, cext: CborValue? = nil, audience: String = "",
                    suite: UInt64 = 0) {
            self.id = nil
            self.kind = kind
            self.channel = channel
            self.tier = tier
            self.signer = signer
            self.created = created
            self.effect = effect
            self.causes = causes
            self.profile = profile
            self.body = body
            self.ext = ext
            self.cext = cext
            self.audience = audience
            self.suite = suite
        }

        /// Build the object body as a CBOR map. `Cbor.encode` emits canonical key order, so the
        /// append order here is irrelevant to the bytes.
        func bodyMap(includeID: Bool) throws -> CborValue {
            var pairs: [(CborValue, CborValue)] = []
            if includeID {
                guard let id = self.id else {
                    throw NaalpError("Malformed", "content id not set before body assembly")
                }
                pairs.append((.u(UInt64(EnvelopeField.id)), .b(id)))
            }
            pairs.append((.u(UInt64(EnvelopeField.kind)), .u(kind)))
            pairs.append((.u(UInt64(EnvelopeField.channel)), .u(channel)))
            pairs.append((.u(UInt64(EnvelopeField.tier)), .u(tier)))
            pairs.append((.u(UInt64(EnvelopeField.signer)), .b(signer)))
            pairs.append((.u(UInt64(EnvelopeField.created)), .u(created)))
            pairs.append((.u(UInt64(EnvelopeField.effect)), .u(effect)))
            pairs.append((.u(UInt64(EnvelopeField.causes)), .a(causes.map { .b($0) })))
            pairs.append((.u(UInt64(EnvelopeField.profile)), .u(profile)))
            pairs.append((.u(UInt64(EnvelopeField.body)), body))
            if let ext = self.ext {
                pairs.append((.u(UInt64(EnvelopeField.ext)), ext))
            }
            if let cext = self.cext {
                pairs.append((.u(UInt64(EnvelopeField.cext)), cext))
            }
            if !audience.isEmpty {
                pairs.append((.u(UInt64(EnvelopeField.audience)), .t(audience)))
            }
            if suite != 0 {
                pairs.append((.u(UInt64(EnvelopeField.suite)), .u(suite)))
            }
            return .m(pairs)
        }

        /// The object content id over the body WITHOUT field 1 (§2.3).
        public func contentId() throws -> [UInt8] {
            return try Cbor.contentId(bodyMap(includeID: false))
        }
    }

    // --- assembly surface (algorithm-agnostic; bring your own signature) ---

    /// The COSE protected header {1: alg, "naalp": {1:signer, 2:profile, 3:version}} as
    /// deterministic CBOR. `alg` is a negative COSE algorithm identifier (e.g. -49 = ML-DSA-65).
    public static func protectedHeader(_ alg: Int, _ signer: [UInt8], _ profile: UInt64) throws -> [UInt8] {
        // A negative-integer CBOR head carries the argument `arg` where the logical value is
        // `-1 - arg`, so `arg = -1 - alg`.
        let arg = UInt64(-1 - alg)
        let naalp = CborValue.m([
            (.u(1), .b(signer)),
            (.u(2), .u(profile)),
            (.u(3), .u(NAALP_VERSION)),
        ])
        return try Cbor.encode(.m([
            (.u(1), .n(arg)),
            (.t(naalpHeaderLabel), naalp),
        ]))
    }

    /// Content-id-bind the object and return the three signing inputs: the encoded body payload
    /// (with field 1), the serialized protected header, and the RFC 9052 §4.4 ToBeSigned bytes a
    /// signer signs. Mutates `obj.id`.
    public static func signingInputs(_ obj: inout Object, _ alg: Int) throws
        -> (payload: [UInt8], protected: [UInt8], toBeSigned: [UInt8]) {
        obj.id = try obj.contentId()
        let payload = try Cbor.encode(obj.bodyMap(includeID: true))
        let prot = try protectedHeader(alg, obj.signer, obj.profile)
        let tbs = try Cose.toBeSignedRaw(prot, payload)
        return (payload, prot, tbs)
    }

    /// Content-id-bind the object and return its COSE ToBeSigned bytes (RFC 9052 §4.4): the
    /// exact bytes a signer signs. Mutates `obj.id`.
    @discardableResult
    public static func toBeSigned(_ obj: inout Object, _ alg: Int) throws -> [UInt8] {
        return try signingInputs(&obj, alg).toBeSigned
    }

    /// Content-id-bind the object and assemble the tagged COSE_Sign1 object from an
    /// already-computed `signature` over `toBeSigned(&obj, alg)`. This is the ML-DSA-agnostic
    /// assembly path: pair it with any external FIPS 204 signer (or the Ed25519 path below) to
    /// produce a complete, self-describing signed object. Mutates `obj.id`.
    public static func assembleSigned(_ obj: inout Object, _ alg: Int, _ signature: [UInt8]) throws -> [UInt8] {
        let inputs = try signingInputs(&obj, alg)
        return try Cose.assembleSign1Raw(inputs.protected, inputs.payload, signature)
    }

    /// Sign a full object with Ed25519 (RFC 8032) via swift-crypto and return the tagged
    /// COSE_Sign1 bytes. Ed25519 is a classical (level-0) leg below every profile floor, so a
    /// pure-Ed25519 object is rejected by `verify` at ProfileDowngrade; this path exercises the
    /// real end-to-end assembly + a genuine signature (demonstrable in isolation) and is the
    /// pure surface's only from-key signing route (ML-DSA is skip-tracked). Mutates `obj.id`.
    public static func signEd25519(_ obj: inout Object, _ seed: [UInt8]) throws -> [UInt8] {
        let tbs = try toBeSigned(&obj, Cose.ALG_ED25519)
        let sig = try Cose.ed25519Sign(seed, tbs)
        return try assembleSigned(&obj, Cose.ALG_ED25519, sig)
    }

    /// The signed suite id carried in field 14 for the opt-in Public/Enterprise composite
    /// (design.md §4.2). Field 14 is present iff the object's alg is the composite id; a pure-ML-DSA
    /// (or pure-Ed25519) object omits it and stays byte-identical to a pre-composite object. This
    /// small-uint suite id is an N-AALP-provisional assignment. Byte-identical to impl/go, impl/rust.
    public static let SuiteMLDSA65Ed25519: UInt64 = 1

    /// Maps a composite signature alg id to its signed suite id (field 14). A non-composite alg
    /// returns nil, so field 14 is absent for a pure object.
    static func compositeSuiteForAlg(_ alg: Int) -> UInt64? {
        switch alg {
        case Cose.ALG_COMPOSITE_MLDSA65_ED25519:
            return SuiteMLDSA65Ed25519
        default:
            return nil
        }
    }

    /// Assembles, content-id-binds, and signs a full N-AALP object, mirroring impl/go/impl/rust's
    /// `Sign(o, signer)` exactly: the signed suite field (14) is set present iff `alg` is a
    /// composite id (§4.2), so a pure object omits it and stays byte-identical to a pre-composite
    /// object -- BEFORE the content id is computed, since the suite field is part of the signed
    /// body. `signFn` is this port's closure-based counterpart to Go's `cose.Signer.Sign(tbs)`: it
    /// receives the exact ToBeSigned bytes (RFC 9052 §4.4) and returns the raw signature (or
    /// composite value, via `Cose.compositeSign`, for the composite alg). Mutates `obj.id`/`obj.suite`.
    public static func sign(_ obj: inout Object, _ alg: Int, _ signFn: ([UInt8]) throws -> [UInt8]) throws -> [UInt8] {
        obj.suite = compositeSuiteForAlg(alg) ?? 0
        let inputs = try signingInputs(&obj, alg)
        let sig = try signFn(inputs.toBeSigned)
        return try Cose.assembleSign1Raw(inputs.protected, inputs.payload, sig)
    }

    // --- verify ---

    /// Verify a signed N-AALP object end-to-end, offline, from the object + key + spec alone
    /// (R-2.4). Returns the decoded Object on success, or throws the first named failure. Check
    /// order (fail-closed throughout): decode -> content-id -> field ranges -> header/body
    /// copies + version -> critical extensions -> kind/channel dispatch -> profile floor ->
    /// signature.
    ///
    /// PURE-ONLY: the Ed25519 signature branch is real (swift-crypto), but Ed25519 is always
    /// below the profile floor so it is rejected at ProfileDowngrade before the signature step;
    /// the ML-DSA signature branch throws `Unavailable` (skip-tracked, never a false green). Every
    /// structural check (content-id, ranges, header/body copies, critical extensions, kind
    /// dispatch, profile floor) is fully exercised regardless.
    @discardableResult
    public static func verify(_ profile: Int, _ alg: Int, _ pubkey: [UInt8],
                              _ kindValidator: KindValidator?, _ objBytes: [UInt8],
                              knownCext: Set<UInt64> = []) throws -> Object {
        // Object octet-size bound (§3.4, R7): reject an oversized signed object on the raw bytes,
        // before any parse (RFC 8949 §10 decoder-memory guard).
        if UInt64(objBytes.count) > MAX_OBJECT_SIZE {
            throw NaalpError("TooLarge", "object exceeds the maximum octet size (§3.4, R7)")
        }
        let (prot, payload, sig) = try Cose.parseSign1Raw(objBytes)
        // NonCanonical (§2.6) or over-nested -> DepthExceeded (§3.4, R7).
        let bv = try Cbor.decodeBounded(payload, Int(MAX_NESTING_DEPTH))
        guard case let .m(pairs) = bv else {
            throw NaalpError("Malformed", "body not a map")
        }

        // content-id: recompute over the body without field 1 and compare to the claimed id.
        var claimedID: [UInt8]? = nil
        var withoutID: [(CborValue, CborValue)] = []
        for (k, v) in pairs {
            if case let .u(kn) = k, kn == UInt64(EnvelopeField.id) {
                guard case let .b(idBytes) = v else {
                    throw NaalpError("Malformed", "id not a bstr")
                }
                claimedID = idBytes
                continue
            }
            withoutID.append((k, v))
        }
        guard let claimed = claimedID else {
            throw NaalpError("Malformed", "no content id")
        }
        if try Cbor.contentId(.m(withoutID)) != claimed {
            throw NaalpError("ContentIdMismatch", "recomputed id differs from the claimed id")
        }

        let obj = try objectFromMap(pairs)

        // A (channel 3, kind 0) Rotation object MUST be a tag-98 COSE_Sign co-signed by the old AND
        // new key (§5.2); a single-signature (tag-18) rotation is missing the old-key co-signature and
        // is rejected RotationUnauthorized (the single-Sign1 rotation-gap fix).
        if isRotationObject(obj.channel, obj.kind) {
            throw NaalpError("RotationUnauthorized", "single-signature rotation missing the old-key co-signature")
        }

        // field ranges (RangeError, §3.3 / R-3.3): channel 0..19, effect 0..3, profile 1..3.
        if obj.channel > 19 || obj.effect > 3 || obj.profile < 1 || obj.profile > 3 {
            throw NaalpError("RangeError", "field value outside its permitted range")
        }

        // protected-header copies vs body (HeaderBodyMismatch, §2.1) + version.
        let (halg, hsigner, hprofile, hversion) = try parseProtected(prot)
        if hversion != NAALP_VERSION {
            throw NaalpError("UnsupportedVersion", "unsupported naalp-version")
        }
        if hsigner != obj.signer || hprofile != obj.profile {
            throw NaalpError("HeaderBodyMismatch", "protected-header signer/profile disagree with the body")
        }

        // critical extensions: any unrecognized key rejects (§2.5, R-2.5). RecheckKey (13) is an
        // envelope-recognized critical key: a critical recheck naming an UNKNOWN procedure id is
        // rejected fail-closed (the critical-extension rule reaching the procedure it names); a
        // known procedure id is recognized regardless of the caller's knownCext set. A NON-critical
        // recheck (ext, field 11) is never rejected here -- an unknown non-critical procedure id is
        // ignored per the may-ignore rule (mirrors impl/go's decodeAndCheck).
        if let cext = obj.cext, case let .m(cpairs) = cext {
            for (k, v) in cpairs {
                guard case let .u(kn) = k else {
                    throw NaalpError("UnknownCriticalExt", "unrecognized critical extension key")
                }
                if kn == RecheckKey {
                    guard case let .u(procId) = v else {
                        throw NaalpError("Malformed", "recheck procedure id not a uint")
                    }
                    guard isKnownRecheckProcedure(procId) else {
                        throw NaalpError("UnknownCriticalExt", "unrecognized critical extension key")
                    }
                    continue
                }
                guard knownCext.contains(kn) else {
                    throw NaalpError("UnknownCriticalExt", "unrecognized critical extension key")
                }
            }
        }

        // kind/channel surface dispatch (UnknownKind, §2.6).
        guard let validator = kindValidator, validator(obj.channel, obj.kind) else {
            throw NaalpError("UnknownKind", "kind/channel not recognized by any surface")
        }

        // profile floor.
        let (level, known) = Cose.algLevel(halg)
        if !known {
            throw NaalpError("UnknownAlg", "unregistered alg")
        }
        if level < Cose.profileMinLevel(profile) {
            throw NaalpError("ProfileDowngrade", "signature level below the profile minimum")
        }
        if halg != alg {
            throw NaalpError("KeyAlgMismatch", "protected-header alg disagrees with the verifier key alg")
        }

        // signature (pure-only): Ed25519 is real; ML-DSA is skip-tracked.
        let tbs = try Cose.toBeSignedRaw(prot, payload)
        if halg == Cose.ALG_ED25519 {
            if !Cose.ed25519Verify(pubkey, tbs, sig) {
                throw NaalpError("BadSignature", "signature does not verify")
            }
            return obj
        }
        if halg == Cose.ALG_MLDSA65 || halg == Cose.ALG_MLDSA87 {
            throw NaalpError("Unavailable", "ML-DSA verification requires a deterministic-from-seed FIPS 204 path unavailable in SwiftDilithium 3.6.0")
        }
        throw NaalpError("UnknownAlg", "unregistered alg")
    }

    // --- §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) ---

    // The OPEN-DECISION toggle (design.md §4.4 profile floor applied to a rotation): a Sovereign/High
    // verifier gates the OLD (authorizing) leg by the profile floor too (DEFAULT, fail-closed) rather
    // than only the NEW leg. Ratified default = true (matches impl/go rotationOldLegFloorApplies).
    public static let ROTATION_OLD_LEG_FLOOR_APPLIES = true

    static func isRotationObject(_ channel: UInt64, _ kind: UInt64) -> Bool {
        return channel == 3 && kind == 0
    }

    static func isCompositeAlg(_ alg: Int) -> Bool {
        // The opt-in LAMPS composite algs (§4.2); a composite leg inside a rotation is undecided.
        return alg == -65537 || alg == -65538
    }

    /// Build a §5.2 Rotation object as a tag-98 COSE_Sign co-signed by the OLD then the NEW key in
    /// fixed order; the body protected header names the NEW (go-forward) key. Permitted ONLY for the
    /// Identity Rotation object (channel 3, kind 0); a composite leg is rejected fail-closed. Bytes are
    /// byte-identical to the Go/Rust/Python/TypeScript/Ruby/PHP/C#/Java/Kotlin reference
    /// implementations (deterministic ML-DSA via MlDsa / the swift-crypto BoringSSL shim).
    public static func signRotationObject(_ object: Object, _ oldAlg: Int, _ oldSeed: [UInt8],
                                          _ newAlg: Int, _ newSeed: [UInt8]) throws -> [UInt8] {
        if !isRotationObject(object.channel, object.kind) {
            throw NaalpError("UnknownKind", "tag-98 permitted only for the Identity Rotation object")
        }
        if isCompositeAlg(oldAlg) || isCompositeAlg(newAlg) {
            throw NaalpError("Malformed", "composite-inside-rotation is undecided")
        }
        var o = object
        o.id = try o.contentId()
        let payload = try Cbor.encode(o.bodyMap(includeID: true))
        let bodyProt = try protectedHeader(newAlg, o.signer, o.profile)
        let oldLeg = try Cose.signatureLeg(bodyProt, oldAlg, oldSeed, payload)
        let newLeg = try Cose.signatureLeg(bodyProt, newAlg, newSeed, payload)
        return try Cose.assembleSignRaw(bodyProt, payload, [oldLeg, newLeg])
    }

    /// Verify a tag-98 Rotation object (§5.2): the same object-body checks as verify(), then EXACTLY
    /// two legs in fixed order (old-key then new-key) BOTH verifying via MlDsa. Any missing/wrong/bad
    /// old leg is RotationUnauthorized. Permitted ONLY for (channel 3, kind 0).
    public static func verifyRotationObject(_ profile: Int, _ oldAlg: Int, _ oldPk: [UInt8],
                                            _ newAlg: Int, _ newPk: [UInt8],
                                            _ kindValidator: KindValidator?, _ objBytes: [UInt8],
                                            knownCext: Set<UInt64> = []) throws -> Object {
        // Object octet-size bound (§3.4, R7): the tag-98 rotation object is a top-level signed
        // object too, so it is size-checked on raw bytes before any parse.
        if UInt64(objBytes.count) > MAX_OBJECT_SIZE {
            throw NaalpError("TooLarge", "object exceeds the maximum octet size (§3.4, R7)")
        }
        let (bodyProt, payload, legs) = try Cose.parseSignRaw(objBytes)
        let bv = try Cbor.decodeBounded(payload, Int(MAX_NESTING_DEPTH))
        guard case let .m(pairs) = bv else { throw NaalpError("Malformed", "body not a map") }

        var claimedID: [UInt8]? = nil
        var withoutID: [(CborValue, CborValue)] = []
        for (k, v) in pairs {
            if case let .u(kn) = k, kn == UInt64(EnvelopeField.id) {
                guard case let .b(idBytes) = v else { throw NaalpError("Malformed", "id not a bstr") }
                claimedID = idBytes
                continue
            }
            withoutID.append((k, v))
        }
        guard let claimed = claimedID else { throw NaalpError("Malformed", "no content id") }
        if try Cbor.contentId(.m(withoutID)) != claimed {
            throw NaalpError("ContentIdMismatch", "recomputed id differs from the claimed id")
        }

        let obj = try objectFromMap(pairs)
        if obj.channel > 19 || obj.effect > 3 || obj.profile < 1 || obj.profile > 3 {
            throw NaalpError("RangeError", "field value outside its permitted range")
        }

        let (halg, hsigner, hprofile, hversion) = try parseProtected(bodyProt)
        if hversion != NAALP_VERSION { throw NaalpError("UnsupportedVersion", "unsupported naalp-version") }
        if hsigner != obj.signer || hprofile != obj.profile {
            throw NaalpError("HeaderBodyMismatch", "protected-header signer/profile disagree with the body")
        }
        if let cext = obj.cext, case let .m(cpairs) = cext {
            for (k, _) in cpairs {
                guard case let .u(kn) = k, knownCext.contains(kn) else {
                    throw NaalpError("UnknownCriticalExt", "unrecognized critical extension key")
                }
            }
        }

        // tag-98 is permitted ONLY for the Identity-channel Rotation object (channel 3, kind 0).
        if !isRotationObject(obj.channel, obj.kind) {
            throw NaalpError("UnknownKind", "tag-98 permitted only for the Identity Rotation object")
        }
        guard let validator = kindValidator, validator(obj.channel, obj.kind) else {
            throw NaalpError("UnknownKind", "kind/channel not recognized by any surface")
        }
        if isCompositeAlg(halg) { throw NaalpError("Malformed", "composite-inside-rotation is undecided") }
        if halg != newAlg { throw NaalpError("KeyAlgMismatch", "protected-header alg disagrees with the new key alg") }

        // EXACTLY two legs, fixed order (old, new). A missing/lone leg IS "old leg dropped".
        if legs.count != 2 { throw NaalpError("RotationUnauthorized", "rotation must carry exactly two legs") }
        let oldLegAlg = try Cose.algFromProtected(legs[0].prot)
        let newLegAlg = try Cose.algFromProtected(legs[1].prot)
        if isCompositeAlg(oldLegAlg) || isCompositeAlg(newLegAlg) {
            throw NaalpError("Malformed", "composite leg in a rotation")
        }
        if oldLegAlg != oldAlg || newLegAlg != newAlg {
            throw NaalpError("RotationUnauthorized", "legs not in (old, new) order")
        }

        // profile floor: the NEW (go-forward) leg always; the OLD leg iff the fail-closed toggle applies.
        let (newLevel, nknown) = Cose.algLevel(newLegAlg)
        if !nknown { throw NaalpError("UnknownAlg", "unregistered alg") }
        if newLevel < Cose.profileMinLevel(profile) {
            throw NaalpError("ProfileDowngrade", "new-leg level below the profile minimum")
        }
        if ROTATION_OLD_LEG_FLOOR_APPLIES {
            let (oldLevel, oknown) = Cose.algLevel(oldLegAlg)
            if !oknown { throw NaalpError("UnknownAlg", "unregistered alg") }
            if oldLevel < Cose.profileMinLevel(profile) {
                throw NaalpError("ProfileDowngrade", "old-leg level below the profile minimum")
            }
        }

        // both legs MUST verify over their per-signer ToBeSigned (deterministic ML-DSA via MlDsa).
        let oldTbs = try Cose.signatureToBeSigned(bodyProt, oldLegAlg, payload)
        if !(try MlDsa.verify(oldPk, oldTbs, legs[0].sig, oldLegAlg)) {
            throw NaalpError("RotationUnauthorized", "old leg does not verify")
        }
        let newTbs = try Cose.signatureToBeSigned(bodyProt, newLegAlg, payload)
        if !(try MlDsa.verify(newPk, newTbs, legs[1].sig, newLegAlg)) {
            throw NaalpError("RotationUnauthorized", "new leg does not verify")
        }
        return obj
    }

    // --- decode helpers ---

    /// Read the fixed body fields (1..12) into an Object. Unknown top-level field numbers or
    /// wrong field types are Malformed; extension carriers are fields 11/12.
    static func objectFromMap(_ pairs: [(CborValue, CborValue)]) throws -> Object {
        var kind: UInt64? = nil, channel: UInt64? = nil, tier: UInt64? = nil
        var signer: [UInt8]? = nil, created: UInt64? = nil, effect: UInt64? = nil
        var profile: UInt64? = nil
        var causes: [[UInt8]] = []
        var haveCauses = false
        var body: CborValue? = nil
        var ext: CborValue? = nil, cext: CborValue? = nil
        var audience: String = ""
        var suite: UInt64 = 0
        var idBytes: [UInt8]? = nil

        for (k, v) in pairs {
            guard case let .u(kn) = k else {
                throw NaalpError("Malformed", "non-uint body key")
            }
            switch Int(kn) {
            case EnvelopeField.id:
                guard case let .b(b) = v else { throw NaalpError("Malformed", "id not a bstr") }
                idBytes = b
            case EnvelopeField.kind:
                guard case let .u(u) = v else { throw NaalpError("Malformed", "kind not a uint") }
                kind = u
            case EnvelopeField.channel:
                guard case let .u(u) = v else { throw NaalpError("Malformed", "channel not a uint") }
                channel = u
            case EnvelopeField.tier:
                guard case let .u(u) = v else { throw NaalpError("Malformed", "tier not a uint") }
                tier = u
            case EnvelopeField.signer:
                guard case let .b(b) = v else { throw NaalpError("Malformed", "signer not a bstr") }
                signer = b
            case EnvelopeField.created:
                guard case let .u(u) = v else { throw NaalpError("Malformed", "created not a uint") }
                created = u
            case EnvelopeField.effect:
                guard case let .u(u) = v else { throw NaalpError("Malformed", "effect not a uint") }
                effect = u
            case EnvelopeField.causes:
                guard case let .a(items) = v else { throw NaalpError("Malformed", "causes not an array") }
                if UInt64(items.count) > MAX_CAUSES {  // causal fan-in bound (§3.4, R7)
                    throw NaalpError("TooManyCauses", "causes[] exceeds the maximum count (§3.4, R7)")
                }
                for it in items {
                    guard case let .b(b) = it else { throw NaalpError("Malformed", "cause not a bstr") }
                    causes.append(b)
                }
                haveCauses = true
            case EnvelopeField.profile:
                guard case let .u(u) = v else { throw NaalpError("Malformed", "profile not a uint") }
                profile = u
            case EnvelopeField.body:
                body = v
            case EnvelopeField.ext:
                guard case let .m(mm) = v else { throw NaalpError("Malformed", "ext not a map") }
                if UInt64(mm.count) > MAX_EXT {  // ext cardinality bound (§3.4, R7)
                    throw NaalpError("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)")
                }
                ext = v
            case EnvelopeField.cext:
                guard case let .m(mm) = v else { throw NaalpError("Malformed", "cext not a map") }
                if UInt64(mm.count) > MAX_CEXT {  // cext cardinality bound (§3.4, R7)
                    throw NaalpError("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)")
                }
                cext = v
            case EnvelopeField.audience:
                guard case let .t(s) = v else { throw NaalpError("Malformed", "audience not a tstr") }
                audience = s
            case EnvelopeField.suite:
                guard case let .u(u) = v else { throw NaalpError("Malformed", "suite not a uint") }
                suite = u
            default:
                throw NaalpError("Malformed", "unknown top-level field \(kn)")
            }
        }

        guard let kindV = kind, let channelV = channel, let tierV = tier, let signerV = signer,
              let createdV = created, let effectV = effect, let profileV = profile,
              let bodyV = body, haveCauses else {
            throw NaalpError("Malformed", "missing required body field")
        }
        var o = Object(kind: kindV, channel: channelV, signer: signerV, created: createdV,
                       effect: effectV, body: bodyV, tier: tierV, profile: profileV,
                       causes: causes, ext: ext, cext: cext, audience: audience, suite: suite)
        o.id = idBytes
        return o
    }

    /// The single-use consume binding gate (§2.5.3), checked at the point of use -- before the
    /// consume logic (the CAS append) -- NEVER inside verify(). An in-transit relay, ordering
    /// authority, or auditor legitimately verifies objects addressed to some OTHER authority; only
    /// the authority about to CONSUME an object enforces that the object is addressed to it. Three
    /// branches: (a) absent audience on a consume-once object -> WrongAudience; (b) an audience
    /// present but not this authority -> WrongAudience; (c) a non-consume-once object with no
    /// audience -> pass. Throws NaalpError("WrongAudience") on rejection.
    public static func checkAudience(_ o: Object, _ selfAuthority: String, _ consumeOnce: Bool) throws {
        if o.audience.isEmpty {
            if consumeOnce {
                throw NaalpError("WrongAudience", "consume-once object has no audience")
            }
            return
        }
        if o.audience != selfAuthority {
            throw NaalpError("WrongAudience", "object audience is not this consuming authority")
        }
    }

    // --- T1.3 recheck: the checkable-minimum re-check procedure (design.md §2.5, NAALP-REQ-111(c)) ---

    /// The ext/cext extension key under which an object NAMES the re-check procedure for the claim
    /// in its body (§2.5, NAALP-REQ-111(c) -- the "checkable minimum"). The value is a procedure id
    /// into the closed registry below. In the non-critical ext map (field 11) it is may-ignore; in
    /// the critical cext map (field 12) it is must-understand and an unknown procedure id is
    /// rejected fail-closed (UnknownCriticalExt), the same C3 critical-extension rule reaching the
    /// procedure it names. 13 does not collide with the safety-label ext key 1 (§6.4). Byte-identical
    /// to impl/go, impl/rust.
    public static let RecheckKey: UInt64 = 13

    /// The closed re-check procedure registry (design.md §2.5; T1.3); mirrors the spec
    /// recheck-procedure production and vectors/registry/recheck.csv.
    public static let RecheckRecomputeContentID: UInt64 = 1  // recompute the content id from the body and compare (§2.3)
    public static let RecheckVerifyCoseSign1: UInt64 = 2     // verify the COSE_Sign1 signature under the signer key (§4)
    public static let RecheckWalkCauses: UInt64 = 3          // walk the signed causal partial order offline (§8.2)
    public static let RecheckReplayConsumeCheck: UInt64 = 4  // replay the single-use consume ledger for the approval (§7.2)

    /// Reports whether `id` is a recognized re-check procedure. The registry is CLOSED: an id
    /// outside it is unknown, and an unknown id under the critical map is rejected (§2.5).
    public static func isKnownRecheckProcedure(_ id: UInt64) -> Bool {
        return id >= RecheckRecomputeContentID && id <= RecheckReplayConsumeCheck
    }

    /// Returns the re-check procedure `o` names (RecheckKey, §2.5): `present` is true when a
    /// procedure is named, and `critical` is true iff it is named in the cext map (field 12,
    /// must-understand) rather than the ext map (field 11, may-ignore). cext takes precedence when
    /// both carry the key. When no procedure is named the claim is attributable-only
    /// (NAALP-REQ-111).
    public static func recheck(_ o: Object) -> (id: UInt64, present: Bool, critical: Bool) {
        if let cext = o.cext, case let .m(pairs) = cext {
            for (k, v) in pairs {
                if case let .u(kn) = k, kn == RecheckKey {
                    if case let .u(val) = v {
                        return (val, true, true)
                    }
                    break
                }
            }
        }
        if let ext = o.ext, case let .m(pairs) = ext {
            for (k, v) in pairs {
                if case let .u(kn) = k, kn == RecheckKey {
                    if case let .u(val) = v {
                        return (val, true, false)
                    }
                    break
                }
            }
        }
        return (0, false, false)
    }

    /// Names `procID` as `o`'s re-check procedure. `critical` places it in the cext map (field 12,
    /// must-understand); otherwise the ext map (field 11, may-ignore). Creates the carrier if
    /// absent and leaves any other extension entries intact.
    public static func setRecheck(_ o: inout Object, _ procID: UInt64, _ critical: Bool) {
        let entry: (CborValue, CborValue) = (.u(RecheckKey), .u(procID))
        if critical {
            if let existing = o.cext, case let .m(existingPairs) = existing {
                var pairs = existingPairs
                var replaced = false
                for i in 0..<pairs.count {
                    if case let .u(kn) = pairs[i].0, kn == RecheckKey {
                        pairs[i] = entry
                        replaced = true
                        break
                    }
                }
                if !replaced { pairs.append(entry) }
                o.cext = .m(pairs)
            } else {
                o.cext = .m([entry])
            }
        } else {
            if let existing = o.ext, case let .m(existingPairs) = existing {
                var pairs = existingPairs
                var replaced = false
                for i in 0..<pairs.count {
                    if case let .u(kn) = pairs[i].0, kn == RecheckKey {
                        pairs[i] = entry
                        replaced = true
                        break
                    }
                }
                if !replaced { pairs.append(entry) }
                o.ext = .m(pairs)
            } else {
                o.ext = .m([entry])
            }
        }
    }

    // --- NA-IETF-1 producing-boundary disclosure (OPTIONAL, self-asserted ext key 15, §2.5.4) ---

    /// The ext extension key under which an object OPTIONALLY carries a per-object producing-boundary
    /// disclosure (design.md §2.5.4, NA-IETF-1): the trust boundary that emitted the object and
    /// whether that boundary OBSERVED the event it describes first-hand or is RELAYING a report of
    /// it. It lives in the NON-CRITICAL ext map (field 11): a verifier that does not understand it,
    /// or that reads a malformed value, ignores the entry and the object still verifies (may-ignore).
    /// Because ext (field 11) is part of the signed body/payload, the disclosure is covered by the
    /// SIGNER's own COSE_Sign1 signature -- it is a SELF-ASSERTED claim. 15 is the next free
    /// ext/cext key: it collides with neither the safety-label ext key 1 (§6.4), the recheck ext/cext
    /// key 13 (§2.5.1), nor the signer-counter ext key 14 (§2.5.2). Byte-identical to impl/go,
    /// impl/rust, and impl/python.
    ///
    /// The disclosure establishes record-order / observational domain, NOT cross-boundary event
    /// precedence (§ Security Considerations): each boundary's observational domain is authoritative
    /// only within itself. It is a NON-CRITICAL field only -- placing it in the critical cext map
    /// (field 12) is an unrecognized critical extension and is rejected fail-closed
    /// (UnknownCriticalExt), because a disclosure is never a must-understand verification gate.
    public static let ProducingBoundaryKey: UInt64 = 15

    /// The producing-boundary kind (design.md §2.5.4): a closed enum naming whether the emitting
    /// boundary witnessed the event directly or is relaying a report of it.
    public static let ProducingBoundaryObserved: UInt64 = 1  // witnessed the event directly (first-hand)
    public static let ProducingBoundaryReported: UInt64 = 2  // relaying a report it did not witness

    // The producing-boundary value sub-map keys (design.md §2.5.4).
    private static let pbFieldBoundary: UInt64 = 1    // bstr -- the emitting trust boundary (party id)
    private static let pbFieldKind: UInt64 = 2         // 1 observed / 2 reported
    private static let pbFieldReporting: UInt64 = 3    // bstr -- report origin; present iff kind = reported

    /// A decoded producing-boundary disclosure (ProducingBoundaryKey, §2.5.4). `boundary` is the
    /// emitting trust boundary (the same bstr party-id form as Object.signer). `kind` is
    /// ProducingBoundaryObserved or ProducingBoundaryReported. `reporting` names the report origin and
    /// is non-nil ONLY when `kind` is ProducingBoundaryReported (an observer relays from no one).
    public struct ProducingBoundary {
        public var boundary: [UInt8]
        public var kind: UInt64
        public var reporting: [UInt8]?

        public init(boundary: [UInt8], kind: UInt64, reporting: [UInt8]? = nil) {
            self.boundary = boundary
            self.kind = kind
            self.reporting = reporting
        }
    }

    /// Returns the producing-boundary disclosure `o` names (ProducingBoundaryKey, §2.5.4): `present`
    /// is true iff a WELL-FORMED disclosure is carried in the non-critical ext map (field 11) -- a
    /// non-empty boundary (key 1), a kind (key 2) in {observed, reported}, and a reporting-boundary
    /// (key 3) absent unless the kind is reported. A malformed value is IGNORED (`present == false`)
    /// and the object still verifies (may-ignore). The field is OPTIONAL: an absent disclosure
    /// (`present == false`) is valid. An unrecognized sub-key is ignored (may-ignore) and does not by
    /// itself make an otherwise well-formed value malformed.
    public static func producingBoundary(_ o: Object) -> (ProducingBoundary, Bool) {
        let notPresent = ProducingBoundary(boundary: [], kind: 0)
        guard let extVal = o.ext, case let .m(extPairs) = extVal else {
            return (notPresent, false)
        }
        var subPairs: [(CborValue, CborValue)]? = nil
        for (k, v) in extPairs {
            if case let .u(kn) = k, kn == ProducingBoundaryKey {
                guard case let .m(sp) = v else {
                    return (notPresent, false)
                }
                subPairs = sp
                break
            }
        }
        guard let sub = subPairs else {
            return (notPresent, false)
        }
        var boundary: [UInt8]? = nil
        var kind: UInt64? = nil
        var reporting: [UInt8]? = nil
        var haveReporting = false
        for (k, v) in sub {
            guard case let .u(kn) = k else {
                return (notPresent, false)
            }
            switch kn {
            case pbFieldBoundary:
                guard case let .b(b) = v else { return (notPresent, false) }
                boundary = b
            case pbFieldKind:
                guard case let .u(u) = v else { return (notPresent, false) }
                kind = u
            case pbFieldReporting:
                guard case let .b(b) = v else { return (notPresent, false) }
                reporting = b
                haveReporting = true
            default:
                break  // an unrecognized sub-key: may-ignore.
            }
        }
        // well-formedness (§2.5.4). Any failure returns present == false (may-ignore), never a throw.
        guard let b = boundary, !b.isEmpty else {
            return (notPresent, false)  // no boundary named
        }
        guard let k = kind, k == ProducingBoundaryObserved || k == ProducingBoundaryReported else {
            return (notPresent, false)  // absent or out-of-enum kind
        }
        if haveReporting && k != ProducingBoundaryReported {
            return (notPresent, false)  // a reporting-boundary under observed: an observer relays from no one
        }
        return (ProducingBoundary(boundary: b, kind: k, reporting: haveReporting ? reporting : nil), true)
    }

    /// Names `pb` as `o`'s producing-boundary disclosure in the NON-CRITICAL ext map (field 11),
    /// covered by the signer's COSE_Sign1 signature. Creates the ext carrier if absent and leaves any
    /// other extension entries intact. The reporting-boundary is emitted ONLY when non-nil AND the
    /// kind is reported, so a caller cannot accidentally emit a malformed observed-with-reporting
    /// disclosure (an observer relays from no one). Sub-map keys are appended in ascending order;
    /// `Cbor.encode` emits canonical CBOR regardless, so the object stays deterministic.
    public static func setProducingBoundary(_ o: inout Object, _ pb: ProducingBoundary) {
        var sub: [(CborValue, CborValue)] = [
            (.u(pbFieldBoundary), .b(pb.boundary)),
            (.u(pbFieldKind), .u(pb.kind)),
        ]
        if let reporting = pb.reporting, pb.kind == ProducingBoundaryReported {
            sub.append((.u(pbFieldReporting), .b(reporting)))
        }
        let entry: (CborValue, CborValue) = (.u(ProducingBoundaryKey), .m(sub))
        if let existing = o.ext, case let .m(existingPairs) = existing {
            var pairs = existingPairs
            var replaced = false
            for i in 0..<pairs.count {
                if case let .u(kn) = pairs[i].0, kn == ProducingBoundaryKey {
                    pairs[i] = entry
                    replaced = true
                    break
                }
            }
            if !replaced { pairs.append(entry) }
            o.ext = .m(pairs)
        } else {
            o.ext = .m([entry])
        }
    }

    /// Read {1: alg, "naalp": {1:signer, 2:profile, 3:version}} from a serialized protected
    /// header. Returns the logical (negative) alg identifier.
    static func parseProtected(_ prot: [UInt8]) throws -> (alg: Int, signer: [UInt8], profile: UInt64, version: UInt64) {
        // §3.1.1 (R5): the empty protected header is pinned to 0x40; a byte string wrapping an
        // empty CBOR map (the 0x41A0 form — its unwrapped content is the single byte 0xA0) is the
        // one redundant encoding RFC 9052 §3 otherwise permits, and MUST be rejected as
        // NonCanonical before the header is interpreted (otherwise it dies downstream as a generic
        // Malformed / no-alg, losing the determinism verdict).
        if prot.count == 1 && prot[0] == 0xA0 {
            throw NaalpError("NonCanonical", "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)")
        }
        let pv = try Cbor.decode(prot)
        guard case let .m(pairs) = pv else {
            throw NaalpError("Malformed", "protected header not a map")
        }
        var alg: Int? = nil, signer: [UInt8]? = nil, profile: UInt64? = nil, version: UInt64? = nil
        var haveNaalp = false
        for (k, v) in pairs {
            if case let .u(kn) = k, kn == 1 {
                guard case let .n(arg) = v else {
                    throw NaalpError("Malformed", "alg not a negative integer")
                }
                alg = -1 - Int(arg)
            } else if case let .t(label) = k, label == naalpHeaderLabel {
                guard case let .m(np) = v else {
                    throw NaalpError("Malformed", "naalp header not a map")
                }
                for (nk, nv) in np {
                    guard case let .u(nkn) = nk else { continue }
                    switch nkn {
                    case 1:
                        if case let .b(b) = nv { signer = b }
                    case 2:
                        if case let .u(u) = nv { profile = u }
                    case 3:
                        if case let .u(u) = nv { version = u }
                    default:
                        break
                    }
                }
                haveNaalp = true
            }
        }
        guard let algV = alg, haveNaalp, let signerV = signer, let profileV = profile,
              let versionV = version else {
            throw NaalpError("Malformed", "protected header missing routing fields")
        }
        return (algV, signerV, profileV, versionV)
    }
}
