// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Non-circular known-answer test for the Swift SDK's self-certifying signer id (§5.1). The
// expected signer_id for each signer comes from the COMMITTED independent oracle vector
// (vectors/identity/cases.json, produced by tools/signerid_oracle.py) — it is NOT recomputed by
// the SDK — so this test detects any mutation of the multihash-prefix / multicodec / base32
// derivation inside Identity.signerId. The public key is supplied by the vector, so no ML-DSA
// keygen is required: signerId derives the id from (alg, pubkey) bytes alone.
//
// Run:  swift test --package-path impl/swift --filter IdentityKatTests

import Foundation
import XCTest
@testable import Naalp

final class IdentityKatTests: XCTestCase {

    static func hexToBytes(_ s: String) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    /// Walk up from this source file to the committed identity vector (mirrors WorkedExampleTests).
    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/identity/cases.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    /// Map the vector's COSE alg code to the SDK's ALG constant. Returns nil for an unknown code so
    /// the caller fails loudly rather than silently skipping a signer. (-49 == ML-DSA-65,
    /// -50 == ML-DSA-87, -19 == Ed25519 — the codes are identical, mapped explicitly for clarity.)
    static func swiftAlg(_ jsonAlg: Int) -> Int? {
        switch jsonAlg {
        case Cose.ALG_MLDSA65: return Cose.ALG_MLDSA65
        case Cose.ALG_MLDSA87: return Cose.ALG_MLDSA87
        case Cose.ALG_ED25519: return Cose.ALG_ED25519
        default: return nil
        }
    }

    func testSignerIdMatchesCommittedVector() throws {
        guard let vec = Self.findVector() else {
            throw XCTSkip("committed identity vector not present (standalone build)")
        }
        guard let signers = vec["signers"] as? [[String: Any]] else {
            XCTFail("vector has no signers[] array"); return
        }
        XCTAssertGreaterThanOrEqual(signers.count, 3, "expected at least the 3 committed signers")

        var checked = 0
        for signer in signers {
            let name = signer["name"] as? String ?? "?"
            guard let jsonAlg = signer["alg"] as? Int else {
                XCTFail("signer \(name): missing integer alg"); continue
            }
            guard let pubHex = signer["pubkey_hex"] as? String else {
                XCTFail("signer \(name): missing pubkey_hex"); continue
            }
            guard let expected = signer["signer_id"] as? String else {
                XCTFail("signer \(name): missing committed signer_id"); continue
            }
            guard let alg = Self.swiftAlg(jsonAlg) else {
                XCTFail("signer \(name): unmapped alg \(jsonAlg)"); continue
            }
            let pubkey = Self.hexToBytes(pubHex)
            // Expected value is the COMMITTED signer_id from the independent oracle, not recomputed
            // here — so this comparison is non-circular (F3).
            let got = try Identity.signerId(alg, pubkey)
            XCTAssertEqual(got, expected,
                           "signer \(name) (alg \(jsonAlg)): derived signer id != committed vector")
            checked += 1
        }
        XCTAssertEqual(checked, signers.count, "every committed signer must be graded")
    }
}
