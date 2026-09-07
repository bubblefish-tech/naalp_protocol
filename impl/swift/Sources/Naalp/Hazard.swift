// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Manufacturing Add-ons Component F, the physical-hazard authorization extension (design.md
// addendum; requirements F1-F5; wire authority spec/naalp-draft-01.cddl, the frozen
// MANUFACTURING PHYSICAL-HAZARD productions).
// Swift port of impl/rust/naalp-hazard/src/lib.rs, mirroring impl/go/hazard/hazard.go and
// impl/csharp/Hazard.cs byte-for-byte.
//
// STATUS: FROZEN 2026-09-01 (Shawn-approved wire bytes). The naalp-hazard-claim (critical cext
// key 16) and naalp-hazard-authorization (Governance 0x0004 kind 7) productions are merged into
// the normative spec/naalp-draft-01.cddl naalp-artifact reachability root; the channel kind is
// registered in vectors/registry/channels.csv, the ext key in extension-keys.csv, and the three
// error codes (130/131/132) in error-codes.csv. This module is graded byte-identical against the
// shared vectors/hazard corpus (the non-circular oracle produced by tools/hazard_oracle.py).
//
// effect (Envelope field 7, Policy) describes DATA reversibility. hazard is a new, ORTHOGONAL
// dimension describing PHYSICAL danger: a data-reversible action may still be a high physical
// hazard. The two dimensions are never merged and neither derives the other.
//
// This module adds no new cryptography and no new CBOR codec of its own: every encode call
// delegates to Cbor.encode / Cbor.contentId, exactly as every other spine/extension module builds
// on the shared codec.
//
// The fail-closed rules (F2, F3):
//   - Hazard.HazardClass.fromCode is the ONE fail-closed decode entry point: any missing or
//     out-of-range raw value normalizes to .motionInSharedSpace -- the highest class -- never to
//     a weaker class. This mirrors the effect lattice's unknown-to-destructive rule, extended to
//     a domain-distinct closed set.
//   - Hazard.hazardAuthorized requires an EXACT class match (not a "<=" ceiling the way the
//     effect lattice's authorization works) AND full containment of the claim's envelope inside
//     the grant's, on every axis, the speed bound, and the time window. Any single failing
//     dimension denies the WHOLE claim -- there is no partial authorization.
//   - Hazard.hazardAuthorizedOptional additionally covers the case where an action carries NO
//     hazard claim at all: there is no envelope to check containment against, so it denies
//     immediately with a distinct error (HazardUnknown) rather than fabricating a sentinel
//     envelope and running the ordinary coverage check.

public enum Hazard {

    // ---- errors, mirroring impl/rust/naalp-hazard's err_hazard_* constructors byte-for-byte in
    // kind and message. ------------------------------------------------------------------------

    /// (HazardMalformed) a hazard-claim/hazard-authorization/envelope body is not the CDDL shape
    /// (spec/naalp-draft-01.cddl), a spatial-bounds axis has min > max, axes is empty, or frame
    /// is not Unicode NFC.
    public static func errMalformed() -> NaalpError {
        NaalpError("HazardMalformed", "hazard body is not the spec/naalp-draft-01.cddl shape, or an axis/frame is invalid")
    }

    /// (HazardNotCovered, design's E_HAZARD_UNCOV) a well-formed claim's class or envelope is not
    /// fully covered by the presented authorization.
    public static func errNotCovered() -> NaalpError {
        NaalpError("HazardNotCovered", "declared hazard class or envelope is not fully covered by the authorization")
    }

    /// (HazardUnknown, design's E_HAZARD_UNKNOWN) the hazard value for an action requiring one is
    /// unrecognized or absent, and -- for the fully-absent case -- no envelope exists to check
    /// coverage against at all.
    public static func errUnknown() -> NaalpError {
        NaalpError("HazardUnknown", "hazard value unrecognized or absent; no claim to check coverage against")
    }

    // ---- hazard-class (F2: closed, fail-closed to the highest class) --------------------------

    /// The closed five-value hazard-class vocabulary (spec/naalp-draft-01.cddl).
    /// `.motionInSharedSpace` is BOTH a named class (4) and the fail-closed default for an
    /// unrecognized or absent raw value (F2) -- the assumption that "the producer did not tell
    /// us" is at least as dangerous as the worst named class.
    public enum HazardClass: UInt8, Equatable {
        case none = 0
        case toolActuation = 1
        case thermal = 2
        case energyRelease = 3
        case motionInSharedSpace = 4

        /// The CDDL wire code (0..4).
        public var code: UInt8 { rawValue }

        /// Fail-closed decode (F2). `nil` (the raw value was absent) or any value outside 0...4
        /// (unrecognized) normalizes to `.motionInSharedSpace` -- never to a weaker class, and
        /// never a decode failure (there is no "invalid hazard" outcome; there is only "the
        /// worst case we must assume"). Takes a `UInt64?` so a malformed wire value outside even
        /// the byte range still normalizes correctly rather than trapping.
        public static func fromCode(_ code: UInt64?) -> HazardClass {
            if let code = code, code <= 4, let c = HazardClass(rawValue: UInt8(code)) {
                return c
            }
            return .motionInSharedSpace // F2: unknown/absent -> highest class
        }

        func toValue() -> CborValue { .u(UInt64(code)) }
    }

    // ---- spatial-bounds -------------------------------------------------------------------

    /// One signed axis-aligned bound, integer millimeters. MUST satisfy `min <= max`.
    public struct Axis: Equatable {
        public var min: Int64
        public var max: Int64
        public init(_ min: Int64, _ max: Int64) {
            self.min = min
            self.max = max
        }
    }

    private static func intValue(_ v: Int64) -> CborValue {
        v >= 0 ? .u(UInt64(v)) : .n(UInt64(-1 - v))
    }

    private static func intFromValue(_ v: CborValue) -> Int64? {
        switch v {
        case .u(let u):
            return Int64(exactly: u)
        case .n(let arg):
            guard let a = Int64(exactly: arg) else { return nil }
            return -1 - a
        default:
            return nil
        }
    }

    /// A named coordinate frame plus a signed axis-aligned bounding region in that frame,
    /// integer millimeters (spec/naalp-draft-01.cddl spatial-bounds). Fixed-point, not float:
    /// the N-AALP CBOR subset (CborValue) carries no floats, so a hazard envelope stays inside
    /// the same deterministic-CBOR discipline as every other production.
    public struct SpatialBounds: Equatable {
        public var frame: String
        /// Per-axis (min, max), millimeters, signed. MUST be non-empty; every entry MUST
        /// satisfy min <= max.
        public var axes: [Axis]

        public init(frame: String, axes: [Axis]) {
            self.frame = frame
            self.axes = axes
        }

        /// Structural validity (spec/naalp-draft-01.cddl): non-empty axes, every min <= max,
        /// frame non-empty and Unicode NFC.
        public func isWellFormed() -> Bool {
            if axes.isEmpty { return false }
            if axes.contains(where: { $0.min > $0.max }) { return false }
            if frame.isEmpty { return false }
            do {
                try Identity.requireNFC(frame)
                return true
            } catch {
                return false
            }
        }

        func toValue() -> CborValue {
            let encodedAxes: [CborValue] = axes.map { .a([intValue($0.min), intValue($0.max)]) }
            return .m([
                (.u(1), .t(frame)),
                (.u(2), .a(encodedAxes)),
            ])
        }

        /// Deterministic-CBOR encoding of {1:frame,2:axes}. Malformed input still encodes
        /// (encoding is not the validity gate); callers MUST check `isWellFormed()` before
        /// treating a `SpatialBounds` as authoritative, exactly as `fromValue` does on decode.
        public func bytes() throws -> [UInt8] { try Cbor.encode(toValue()) }

        /// Parse a spatial-bounds map. Rejects a non-map, an out-of-range/wrong-typed key or
        /// value, a missing key, empty axes, an axis with min > max, or a non-NFC/empty frame --
        /// fail-closed (HazardMalformed), never a partially-valid result.
        public static func fromValue(_ v: CborValue) throws -> SpatialBounds {
            guard case let .m(pairs) = v else { throw errMalformed() }
            var frame: String?
            var axes: [Axis]?
            for (k, val) in pairs {
                guard case let .u(key) = k else { throw errMalformed() }
                switch key {
                case 1:
                    guard case let .t(s) = val else { throw errMalformed() }
                    frame = s
                case 2:
                    guard case let .a(items) = val, !items.isEmpty else { throw errMalformed() }
                    var out: [Axis] = []
                    out.reserveCapacity(items.count)
                    for it in items {
                        guard case let .a(pair) = it, pair.count == 2,
                              let mn = intFromValue(pair[0]), let mx = intFromValue(pair[1]) else {
                            throw errMalformed()
                        }
                        if mn > mx { throw errMalformed() }
                        out.append(Axis(mn, mx))
                    }
                    axes = out
                default:
                    throw errMalformed()
                }
            }
            guard let f = frame, let a = axes else { throw errMalformed() }
            let sb = SpatialBounds(frame: f, axes: a)
            guard sb.isWellFormed() else { throw errMalformed() }
            return sb
        }
    }

    /// Full containment (F3): same frame id (a bound in one frame says nothing about a bound in
    /// a different, unrelated frame), the SAME axis count in the SAME order, and every claim
    /// axis's [min,max] a subset of the matching grant axis's [min,max].
    public static func spatialContained(_ claim: SpatialBounds, _ grant: SpatialBounds) -> Bool {
        if claim.frame != grant.frame { return false }
        if claim.axes.count != grant.axes.count { return false }
        for i in 0..<claim.axes.count {
            let c = claim.axes[i]
            let g = grant.axes[i]
            if c.min < g.min || c.max > g.max { return false }
        }
        return true
    }

    // ---- hazard-window ----------------------------------------------------------------------

    /// A validity window, epoch ms, the same convention as naalp-object field 6 (created) and
    /// naalp-delegation-grant fields 4/5.
    public struct HazardWindow: Equatable {
        public var notBefore: UInt64
        public var notAfter: UInt64

        public init(notBefore: UInt64, notAfter: UInt64) {
            self.notBefore = notBefore
            self.notAfter = notAfter
        }

        func toValue() -> CborValue {
            .m([
                (.u(1), .u(notBefore)),
                (.u(2), .u(notAfter)),
            ])
        }

        static func fromValue(_ v: CborValue) throws -> HazardWindow {
            guard case let .m(pairs) = v else { throw errMalformed() }
            var notBefore: UInt64?
            var notAfter: UInt64?
            for (k, val) in pairs {
                guard case let .u(key) = k, case let .u(n) = val else { throw errMalformed() }
                switch key {
                case 1: notBefore = n
                case 2: notAfter = n
                default: throw errMalformed()
                }
            }
            guard let nb = notBefore, let na = notAfter else { throw errMalformed() }
            return HazardWindow(notBefore: nb, notAfter: na)
        }
    }

    // ---- hazard-envelope ----------------------------------------------------------------------

    /// The full physical envelope a claim or an authorization bounds itself by. All three fields
    /// are MANDATORY on the wire (spec/naalp-draft-01.cddl) -- a silently-absent axis would be
    /// fail-OPEN in a physical-safety context, so an issuer that means "unbounded" states so
    /// explicitly with wide numeric bounds; the wire never infers permissiveness from silence
    /// here (deliberate contrast with naalp-delegation-grant's optional scope).
    public struct HazardEnvelope: Equatable {
        public var spatial: SpatialBounds
        /// Max instantaneous speed, millimeters per second.
        public var speedBoundMmS: UInt64
        public var window: HazardWindow

        public init(spatial: SpatialBounds, speedBoundMmS: UInt64, window: HazardWindow) {
            self.spatial = spatial
            self.speedBoundMmS = speedBoundMmS
            self.window = window
        }

        func toValue() -> CborValue {
            .m([
                (.u(1), spatial.toValue()),
                (.u(2), .u(speedBoundMmS)),
                (.u(3), window.toValue()),
            ])
        }

        /// Deterministic-CBOR encoding of {1:spatial,2:speed_bound,3:window}.
        public func bytes() throws -> [UInt8] { try Cbor.encode(toValue()) }

        /// The envelope's content id (T1 framing, Cbor.contentId): a pure function of the bytes
        /// above.
        public func contentId() throws -> [UInt8] { try Cbor.contentId(toValue()) }

        /// Parse a hazard-envelope map; fail-closed on any missing/malformed field.
        public static func fromValue(_ v: CborValue) throws -> HazardEnvelope {
            guard case let .m(pairs) = v else { throw errMalformed() }
            var spatial: SpatialBounds?
            var speed: UInt64?
            var window: HazardWindow?
            for (k, val) in pairs {
                guard case let .u(key) = k else { throw errMalformed() }
                switch key {
                case 1:
                    spatial = try SpatialBounds.fromValue(val)
                case 2:
                    guard case let .u(n) = val else { throw errMalformed() }
                    speed = n
                case 3:
                    window = try HazardWindow.fromValue(val)
                default:
                    throw errMalformed()
                }
            }
            guard let s = spatial, let sp = speed, let w = window else { throw errMalformed() }
            return HazardEnvelope(spatial: s, speedBoundMmS: sp, window: w)
        }
    }

    /// Full containment (F3): `spatialContained` AND `claim.speedBoundMmS <=
    /// grant.speedBoundMmS` AND the claim's window is a sub-interval of the grant's
    /// (`grant.notBefore <= claim.notBefore` and `claim.notAfter <= grant.notAfter`).
    public static func envelopeContained(_ claim: HazardEnvelope, _ grant: HazardEnvelope) -> Bool {
        spatialContained(claim.spatial, grant.spatial)
            && claim.speedBoundMmS <= grant.speedBoundMmS
            && grant.window.notBefore <= claim.window.notBefore
            && claim.window.notAfter <= grant.window.notAfter
    }

    // ---- naalp-hazard-claim / naalp-hazard-authorization --------------------------------------

    private static func hazardBodyToValue(_ cls: HazardClass, _ envelope: HazardEnvelope) -> CborValue {
        .m([
            (.u(1), cls.toValue()),
            (.u(2), envelope.toValue()),
        ])
    }

    private static func hazardBodyFromValue(_ v: CborValue) throws -> (HazardClass, HazardEnvelope) {
        guard case let .m(pairs) = v else { throw errMalformed() }
        var classCode: UInt64?
        var envelope: HazardEnvelope?
        for (k, val) in pairs {
            guard case let .u(key) = k else { throw errMalformed() }
            switch key {
            case 1:
                // An out-of-range class ON THE WIRE (not merely "absent") is a malformed body,
                // not a normalize-to-4 input: F2's fail-closed normalization is for the DECODE
                // step that produces a class from a less-structured source (see
                // HazardClass.fromCode), not for a CDDL-invalid hazard-class value already
                // claiming to be well-formed.
                guard case let .u(n) = val, n <= 4 else { throw errMalformed() }
                classCode = n
            case 2:
                envelope = try HazardEnvelope.fromValue(val)
            default:
                throw errMalformed()
            }
        }
        guard let cc = classCode, let env = envelope else { throw errMalformed() }
        return (HazardClass.fromCode(cc), env)
    }

    /// A signed physical-hazard claim (spec/naalp-draft-01.cddl naalp-hazard-claim). Carriage
    /// (the object it accompanies and how) is a wire-impact decision, not this module's concern.
    public struct HazardClaim: Equatable {
        public var hazardClass: HazardClass
        public var envelope: HazardEnvelope

        public init(hazardClass: HazardClass, envelope: HazardEnvelope) {
            self.hazardClass = hazardClass
            self.envelope = envelope
        }

        func toValue() -> CborValue { hazardBodyToValue(hazardClass, envelope) }

        /// Deterministic-CBOR encoding of {1:class,2:envelope}.
        public func bytes() throws -> [UInt8] { try Cbor.encode(toValue()) }

        /// The claim's content id (T1 framing).
        public func contentId() throws -> [UInt8] { try Cbor.contentId(toValue()) }

        /// Parse a naalp-hazard-claim body. Both class and envelope are mandatory -- a claim
        /// declaring one and omitting the other is HazardMalformed, not partially valid.
        public static func fromValue(_ v: CborValue) throws -> HazardClaim {
            let (cls, env) = try hazardBodyFromValue(v)
            return HazardClaim(hazardClass: cls, envelope: env)
        }
    }

    /// A signed physical-hazard authorization ("a grant" in requirements F3's language;
    /// spec/naalp-draft-01.cddl naalp-hazard-authorization). Same shape as `HazardClaim`
    /// deliberately: one envelope shape for both sides keeps the containment check symmetric.
    public struct HazardAuthorization: Equatable {
        public var hazardClass: HazardClass
        public var envelope: HazardEnvelope

        public init(hazardClass: HazardClass, envelope: HazardEnvelope) {
            self.hazardClass = hazardClass
            self.envelope = envelope
        }

        func toValue() -> CborValue { hazardBodyToValue(hazardClass, envelope) }

        /// Deterministic-CBOR encoding of {1:class,2:envelope}.
        public func bytes() throws -> [UInt8] { try Cbor.encode(toValue()) }

        /// The authorization's content id (T1 framing).
        public func contentId() throws -> [UInt8] { try Cbor.contentId(toValue()) }

        /// Parse a naalp-hazard-authorization body.
        public static func fromValue(_ v: CborValue) throws -> HazardAuthorization {
            let (cls, env) = try hazardBodyFromValue(v)
            return HazardAuthorization(hazardClass: cls, envelope: env)
        }
    }

    // ---- F3: grant-coverage authorization -----------------------------------------------------

    /// Authorize a well-formed, present claim against an authorization (F3): EXACT class match
    /// (not a "<=" ceiling -- see the module doc) AND `envelopeContained`. Any single failing
    /// dimension denies the WHOLE claim (HazardNotCovered) -- there is no partial authorization
    /// and no fail-open branch.
    public static func hazardAuthorized(_ claim: HazardClaim, _ grant: HazardAuthorization) throws {
        if claim.hazardClass != grant.hazardClass {
            throw errNotCovered()
        }
        if !envelopeContained(claim.envelope, grant.envelope) {
            throw errNotCovered()
        }
    }

    /// Authorize an OPTIONAL claim (F2's "absent" case at the object level, distinct from a
    /// present-but-unrecognized class byte inside a claim). `nil` -- no hazard-claim object
    /// exists at all for an action that requires one -- denies immediately (HazardUnknown)
    /// rather than fabricating a sentinel envelope and running the ordinary coverage check:
    /// there is no envelope to check containment against, so the honest outcome is a distinct
    /// error, not a coverage denial that implies an envelope was compared.
    public static func hazardAuthorizedOptional(_ claim: HazardClaim?, _ grant: HazardAuthorization) throws {
        guard let claim = claim else { throw errUnknown() }
        try hazardAuthorized(claim, grant)
    }
}
