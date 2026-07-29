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
}
