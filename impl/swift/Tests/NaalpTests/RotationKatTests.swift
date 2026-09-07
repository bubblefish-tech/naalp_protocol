// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Known-answer tests for the §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) in the
// Swift SDK, graded against the committed non-circular oracle (tools/rotation_oracle.py). The
// worked object's SHA-256 is pinned and equals the Go/Rust/Python/... reference (the same 6798-byte
// tag-98 object every port produces), so this is a cross-language byte-parity anchor, not a
// Swift-only self-check. Deterministic ML-DSA is provided by MlDsa (the swift-crypto BoringSSL
// shim). The tag-18 single-sig and non-rotation-kind rejects are carried by verify()/
// verifyRotationObject() and graded cross-port in the naalp-conform corpus (rotation.verify).
import XCTest
import Crypto
import Naalp

final class RotationKatTests: XCTestCase {
    private func hex<S: Sequence>(_ b: S) -> String where S.Element == UInt8 {
        b.map { String(format: "%02x", $0) }.joined()
    }

    // The worked rotation fixture (identical to tools/rotation_oracle.py).
    private let oldSeed = [UInt8](repeating: 0x0B, count: 32)
    private let newSeed = [UInt8](repeating: 0x16, count: 32)
    private let floorOldSeed = [UInt8](repeating: 0x21, count: 32)   // below-floor old ML-DSA-65
    private let floorNewSeed = [UInt8](repeating: 0x2C, count: 32)   // go-forward ML-DSA-87
    private let signer = Array("SIGNER_NEW".utf8)
    // SHA-256 of the 6798-byte tag-98 rotation object; byte-identical to the Go rotation.sign
    // reference and the oracle (a cross-language, non-circular anchor).
    private let objectSha256 = "298d5d5bac8a0bf556541784f3090ac7300897858e883dc3ab6e7625bc418194"

    private func rotationRecord() -> CborValue {
        .m([(.u(1), .t("signer-old")), (.u(2), .t("signer-new")), (.u(3), .u(1785000000000))])
    }

    private func workedObject(profile: UInt64 = 1) -> Envelope.Object {
        Envelope.Object(kind: 0, channel: 3, signer: signer, created: 1785000000000, effect: 2,
                        body: rotationRecord(), tier: 0, profile: profile)
    }

    private func kindOk(_ ch: UInt64, _ k: UInt64) -> Bool { ch == 3 && k == 0 }

    private func sha256Hex(_ b: [UInt8]) -> String {
        hex(Array(SHA256.hash(data: Data(b))))
    }

    private func assertRejects(_ expectedKind: String, _ block: () throws -> Void) {
        XCTAssertThrowsError(try block()) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, expectedKind)
        }
    }

    func testObjectByteParityWithReference() throws {
        let obj = try Envelope.signRotationObject(workedObject(), Cose.ALG_MLDSA65, oldSeed,
                                                  Cose.ALG_MLDSA65, newSeed)
        XCTAssertEqual(obj.count, 6798)
        XCTAssertEqual(sha256Hex(obj), objectSha256,
                       "rotation object diverged from the Go/Rust/oracle reference bytes")
    }

    func testRoundTripAccept() throws {
        let oldPub = try MlDsa.keygenFromSeed(oldSeed, Cose.ALG_MLDSA65)
        let newPub = try MlDsa.keygenFromSeed(newSeed, Cose.ALG_MLDSA65)
        let obj = try Envelope.signRotationObject(workedObject(), Cose.ALG_MLDSA65, oldSeed,
                                                  Cose.ALG_MLDSA65, newSeed)
        let o = try Envelope.verifyRotationObject(1, Cose.ALG_MLDSA65, oldPub, Cose.ALG_MLDSA65,
                                                  newPub, kindOk, obj)
        XCTAssertEqual(o.channel, 3)
        XCTAssertEqual(o.kind, 0)
    }

    func testOldLegDropped() throws {
        let oldPub = try MlDsa.keygenFromSeed(oldSeed, Cose.ALG_MLDSA65)
        let newPub = try MlDsa.keygenFromSeed(newSeed, Cose.ALG_MLDSA65)
        let obj = try Envelope.signRotationObject(workedObject(), Cose.ALG_MLDSA65, oldSeed,
                                                  Cose.ALG_MLDSA65, newSeed)
        let (bodyProt, payload, legs) = try Cose.parseSignRaw(obj)
        let oneLeg = try Cose.assembleSignRaw(bodyProt, payload, [legs[1]]) // keep only the new leg
        assertRejects("RotationUnauthorized") {
            _ = try Envelope.verifyRotationObject(1, Cose.ALG_MLDSA65, oldPub, Cose.ALG_MLDSA65,
                                                  newPub, self.kindOk, oneLeg)
        }
    }

    func testOldLegWrongKey() throws {
        let oldPub = try MlDsa.keygenFromSeed(oldSeed, Cose.ALG_MLDSA65)
        let newPub = try MlDsa.keygenFromSeed(newSeed, Cose.ALG_MLDSA65)
        // both legs signed by the NEW key -> the trusted old key cannot verify slot 0.
        let obj = try Envelope.signRotationObject(workedObject(), Cose.ALG_MLDSA65, newSeed,
                                                  Cose.ALG_MLDSA65, newSeed)
        assertRejects("RotationUnauthorized") {
            _ = try Envelope.verifyRotationObject(1, Cose.ALG_MLDSA65, oldPub, Cose.ALG_MLDSA65,
                                                  newPub, self.kindOk, obj)
        }
    }

    func testSovereignOldLegFloor() throws {
        // old=ML-DSA-65 (level 3), new=ML-DSA-87 (level 5), Sovereign floor 5 -> the sub-floor OLD
        // leg yields ProfileDowngrade under the ratified fail-closed default.
        let oldPub = try MlDsa.keygenFromSeed(floorOldSeed, Cose.ALG_MLDSA65)
        let newPub = try MlDsa.keygenFromSeed(floorNewSeed, Cose.ALG_MLDSA87)
        let obj = try Envelope.signRotationObject(workedObject(profile: 3), Cose.ALG_MLDSA65,
                                                  floorOldSeed, Cose.ALG_MLDSA87, floorNewSeed)
        assertRejects("ProfileDowngrade") {
            _ = try Envelope.verifyRotationObject(3, Cose.ALG_MLDSA65, oldPub, Cose.ALG_MLDSA87,
                                                  newPub, self.kindOk, obj)
        }
    }
}
