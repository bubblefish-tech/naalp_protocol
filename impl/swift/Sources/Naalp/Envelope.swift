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

// Object body field numbers (design.md §2.1).
public enum EnvelopeField {
    public static let id = 1
    public static let kind = 2
    public static let channel = 3
    public static let tier = 4
    public static let signer = 5
    public static let created = 6
    public static let effect = 7
    public static let causes = 8
    public static let profile = 9
    public static let body = 10
    public static let ext = 11
    public static let cext = 12
}

// The protected-header naalp-version (design.md §2.5).
public let NAALP_VERSION: UInt64 = 1

// The COSE protected-header parameter (a text-string label, which cannot collide with any
// integer-labeled standard COSE parameter, RFC 9052 §3.1) under which N-AALP carries its
// routing copies {1:signer, 2:profile, 3:version}.
let naalpHeaderLabel = "naalp"

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

        public init(kind: UInt64, channel: UInt64, signer: [UInt8], created: UInt64,
                    effect: UInt64, body: CborValue, tier: UInt64 = 0,
                    profile: UInt64 = UInt64(Cose.PROFILE_PUBLIC), causes: [[UInt8]] = [],
                    ext: CborValue? = nil, cext: CborValue? = nil) {
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
        let (prot, payload, sig) = try Cose.parseSign1Raw(objBytes)
        let bv = try Cbor.decode(payload)  // rejects non-canonical CBOR (NonCanonical, §2.6)
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

        // critical extensions: any unrecognized key rejects (§2.5, R-2.5).
        if let cext = obj.cext, case let .m(cpairs) = cext {
            for (k, _) in cpairs {
                guard case let .u(kn) = k, knownCext.contains(kn) else {
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
                guard case .m = v else { throw NaalpError("Malformed", "ext not a map") }
                ext = v
            case EnvelopeField.cext:
                guard case .m = v else { throw NaalpError("Malformed", "cext not a map") }
                cext = v
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
                       causes: causes, ext: ext, cext: cext)
        o.id = idBytes
        return o
    }

    /// Read {1: alg, "naalp": {1:signer, 2:profile, 3:version}} from a serialized protected
    /// header. Returns the logical (negative) alg identifier.
    static func parseProtected(_ prot: [UInt8]) throws -> (alg: Int, signer: [UInt8], profile: UInt64, version: UInt64) {
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
