// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C5 effect vocabulary and authorization for the Swift SDK (§6).
//
// The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an
// unrecognized value fails closed to destructive (R-6.2); authorization is the §6.1 lattice
// (action <= ceiling). The optional signed safety label is a CBOR map {1:risk, 2:scope}.

import Foundation

public enum Policy {
    public static let READ_ONLY = 0
    public static let IDEMPOTENT_WRITE = 1
    public static let NON_IDEMPOTENT_WRITE = 2
    public static let DESTRUCTIVE = 3

    static let names = ["read_only", "idempotent_write", "non_idempotent_write", "destructive"]

    /// Map a raw effect value to the closed set; anything outside 0..3 is destructive (R-6.2).
    public static func normalizeEffect(_ v: Int) -> Int {
        return (v >= 0 && v <= 3) ? v : DESTRUCTIVE
    }

    public static func safetyLabelName(_ e: Int) -> String {
        return names[normalizeEffect(e)]
    }

    /// The §6.1 lattice: an action of class `action` is permitted under `ceiling`
    /// iff `action <= ceiling`.
    public static func authorizes(_ ceiling: Int, _ action: Int) -> Bool {
        return action <= ceiling
    }

    /// The signed safety-label body {1: risk, 2: scope} (R-6.4).
    public static func safetyLabelBytes(_ risk: String, _ scope: String) throws -> [UInt8] {
        return try Cbor.encode(.m([
            (.u(1), .t(risk)),
            (.u(2), .t(scope)),
        ]))
    }

    /// Where a claimed identity came from; only a signature-derived identity is an authorization
    /// principal (R-6.5).
    public enum PrincipalSource: Int {
        case signature = 0         // the verified COSE signature's signer id
        case transportMetadata = 1 // e.g. a TLS peer name / connection tag
        case foreignHeader = 2     // e.g. an X-Agent-ID or a carried foreign header
        case clientName = 3        // e.g. a self-asserted clientInfo.name
    }

    /// Return the authorization principal id iff it is signature-derived and non-empty (R-6.5); a
    /// transport-metadata, foreign-header, or client-supplied name is refused UnauthenticatedPrincipal —
    /// it is never treated as an authorization identity.
    public static func resolveAuthPrincipal(_ src: PrincipalSource, _ id: String) throws -> String {
        if src != .signature || id.isEmpty {
            throw NaalpError("UnauthenticatedPrincipal",
                             "an authorization identity must be signature-derived, not transport/foreign/client-asserted")
        }
        return id
    }

    /// The non-critical ext key under which the optional safety label is carried (design §6.4).
    public static let safetyLabelExtKey = 1

    /// The OPTIONAL signed safety annotation (R-6.4): an accountable, attributable claim, not a
    /// guarantee the content is safe.
    public struct SafetyLabel: Equatable {
        public let risk: String
        public let scope: String
        public init(risk: String, scope: String) { self.risk = risk; self.scope = scope }
    }

    /// Extract the optional safety label from an object's ext map: (label, true) when a well-formed
    /// label is present, (nil, false) when absent, and throws MalformedSafetyLabel when the ext[1]
    /// entry is present but not exactly {1:tstr, 2:tstr} — rejected, never silently accepted.
    public static func safetyLabelFromExt(_ ext: [(CborValue, CborValue)]) throws -> (label: SafetyLabel?, present: Bool) {
        for (k, v) in ext {
            guard case let .u(kk) = k, kk == UInt64(safetyLabelExtKey) else { continue }
            guard case let .m(inner) = v else {
                throw NaalpError("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
            }
            var risk: String?
            var scope: String?
            for (ik, iv) in inner {
                guard case let .u(ikk) = ik, case let .t(ivv) = iv else {
                    throw NaalpError("MalformedSafetyLabel", "safety label entry is not {uint: tstr}")
                }
                if ikk == 1 { risk = ivv } else if ikk == 2 { scope = ivv }
            }
            guard let r = risk, let s = scope else {
                throw NaalpError("MalformedSafetyLabel", "safety label missing risk or scope")
            }
            return (SafetyLabel(risk: r, scope: s), true)
        }
        return (nil, false)
    }

    /// A capability an endpoint issues to an authenticated signer id: the most dangerous effect that
    /// principal is permitted to carry. The zero maxEffect (READ_ONLY) is the least-privilege default.
    public struct Grant {
        public let principal: String
        public let maxEffect: Int
        public init(principal: String, maxEffect: Int) { self.principal = principal; self.maxEffect = maxEffect }

        /// The endpoint policy check making the effect an authorization input, not a hint (R-6.3):
        /// resolve the presenter (refusing any non-signature source, R-6.5), require it to match this
        /// grant's principal, and deny an object effect exceeding the ceiling (normalized fail-closed,
        /// R-6.2). No side effect; throws on any failure.
        public func authorizeObject(_ src: PrincipalSource, _ presented: String, _ objectEffect: Int) throws {
            let who = try Policy.resolveAuthPrincipal(src, presented)
            if who != principal {
                throw NaalpError("EffectNotAuthorized", "object effect exceeds the granted capability")
            }
            if !Policy.authorizes(maxEffect, Policy.normalizeEffect(objectEffect)) {
                throw NaalpError("EffectNotAuthorized", "object effect exceeds the granted capability")
            }
        }
    }
}
