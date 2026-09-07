// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Known-answer tests for the opt-in LAMPS composite signature (§4.2) in the Swift SDK, graded
// against the committed non-circular oracle (tools/composite_oracle.py). Demonstrates in isolation
// (A9): M' construction, the composite signer id, the composite value's ML-DSA leg prefix, and a
// fail-closed verify that rejects a tampered leg on either side. The full byte-for-byte cross-port
// grade lives in the naalp-conform corpus (composite.mprime / composite.signerid / composite.sign
// consensus gate).
import XCTest
import Crypto
import Naalp

final class CompositeKatTests: XCTestCase {
    private func hexToBytes(_ s: String) -> [UInt8] {
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
    private func hex<S: Sequence>(_ b: S) -> String where S.Element == UInt8 {
        b.map { String(format: "%02x", $0) }.joined()
    }

    // The composite fixture (identical to composite_oracle.py / test_composite.py / the Go cmd).
    private let mldsaSeed = Array(UInt8(0)...UInt8(31))
    private let edSeed = Array("naalp-composite-ed25519-seed-32b".utf8)
    private let label = Array("COMPSIG-MLDSA65-Ed25519-SHA512".utf8)
    private let rawTbs = Array("parity-tbs-fixed".utf8)
    private let mprimeHex =
        "436f6d706f73697465416c676f726974686d5369676e61747572657332303235434f4d505349472d4d4c44534136352d456432353531392d5348413531320025a030ff90045a5dc053f7df1ad32b232056020a01d0ef32f6acbea5f525c8532d0a7ee08a8823f7eafaca57e1ab5bb06abc1ed6defb201bb81ee1be9275a30d"
    private let pinnedSignerId = "bciqprynbbhjimvhoque4zvkhftcwubtjahyw5ybwoqxxit5desygivi"

    private func edPublicKey() throws -> [UInt8] {
        Array(try Curve25519.Signing.PrivateKey(rawRepresentation: Data(edSeed)).publicKey.rawRepresentation)
    }

    func testComputeMprimeMatchesOracle() throws {
        let mp = try Cose.computeMprime(label, [], rawTbs)
        XCTAssertEqual(mp.count, 127)
        XCTAssertEqual(hex(mp), mprimeHex)
    }

    func testCompositeSignerIdMatchesOracle() throws {
        let mldsaPub = try MlDsa.keygenFromSeed(mldsaSeed, MlDsa.ALG_MLDSA65)
        let edPub = try edPublicKey()
        XCTAssertEqual(try Identity.compositeSignerId(MlDsa.ALG_MLDSA65, mldsaPub, edPub), pinnedSignerId)
    }

    func testCompositeSignReproducesOracleValueLeg() throws {
        let value = try Cose.compositeSign(mldsaSeed, edSeed, rawTbs)
        XCTAssertEqual(value.count, 3309 + 64)
        XCTAssertEqual(hex(value.prefix(24)), "ef8aa0a151bbc14b7167eff220c10c3bde251846ed032139")
    }

    func testCompositeVerifyIsFailClosedOnEitherLeg() throws {
        let mldsaPub = try MlDsa.keygenFromSeed(mldsaSeed, MlDsa.ALG_MLDSA65)
        let edPub = try edPublicKey()
        let value = try Cose.compositeSign(mldsaSeed, edSeed, rawTbs)
        XCTAssertTrue(try Cose.compositeVerify(mldsaPub, edPub, rawTbs, value))
        var badEd = value
        badEd[badEd.count - 1] ^= 0xff  // tamper the Ed25519 leg
        XCTAssertFalse(try Cose.compositeVerify(mldsaPub, edPub, rawTbs, badEd))
        var badMldsa = value
        badMldsa[0] ^= 0xff             // tamper the ML-DSA leg
        XCTAssertFalse(try Cose.compositeVerify(mldsaPub, edPub, rawTbs, badMldsa))
    }
}
