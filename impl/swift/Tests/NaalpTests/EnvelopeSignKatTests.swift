// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Envelope.sign(_:_:_:) structural known-answer tests for the Swift SDK -- the ML-DSA-agnostic
// convenience wrapper mirroring impl/go/impl/rust's `Sign(o, signer)`: it content-id-binds,
// detects the composite suite (§4.2, field 14) from the signing alg, and assembles the tagged
// COSE_Sign1 from an externally-produced signature (this port's closure-based counterpart to Go's
// `cose.Signer` interface -- the Swift SDK has no signer protocol, so `sign` takes a
// `([UInt8]) throws -> [UInt8]` closure over the RFC 9052 §4.4 ToBeSigned bytes instead).
//
// Two properties, both mutation-surviving and both demonstrated with REAL end-to-end crypto (no
// ML-DSA-agnostic skip-tracking applies here -- Cose.compositeSign/Cose.ed25519Sign are real):
//   1. COMPOSITE SETS THE SUITE [MUTATION ANCHOR] -- signing with the composite alg sets field 14
//      to SuiteMLDSA65Ed25519 on the wire AND on decode, and the produced composite signature
//      genuinely verifies. Dropping the compositeSuiteForAlg detection in sign() (always suite=0)
//      flips this test pass->fail.
//   2. PURE LEAVES THE SUITE ABSENT -- signing with a non-composite alg (Ed25519) leaves field 14
//      absent (suite=0) on the wire AND on decode, keeping the object byte-identical to a
//      pre-composite object.
//
// Run:  swift test --package-path impl/swift --filter EnvelopeSignKatTests

import Foundation
import XCTest
@testable import Naalp

final class EnvelopeSignKatTests: XCTestCase {

    static let mldsaSeed: [UInt8] = (1...32).map { UInt8($0) }
    static let edSeed: [UInt8] = (33...64).map { UInt8($0) }

    static func baseObject(profile: UInt64) -> Envelope.Object {
        Envelope.Object(kind: 2, channel: 4, signer: Array("SIGNER_A".utf8), created: 1785000000000,
                        effect: 2, body: .t("hello"), tier: 0, profile: profile)
    }

    // MARK: - 1. COMPOSITE SETS THE SUITE [MUTATION ANCHOR]

    func testSignCompositeSetsSuite() throws {
        let mldsaPub = try MlDsa.keygenFromSeed(Self.mldsaSeed, Cose.ALG_MLDSA65)
        let edPub = try Cose.ed25519PublicKey(Self.edSeed)

        var o = Self.baseObject(profile: UInt64(Cose.PROFILE_ENTERPRISE))
        let signed = try Envelope.sign(&o, Cose.ALG_COMPOSITE_MLDSA65_ED25519) { tbs in
            try Cose.compositeSign(Self.mldsaSeed, Self.edSeed, tbs)
        }
        XCTAssertEqual(o.suite, Envelope.SuiteMLDSA65Ed25519, "composite alg must set the signed suite field")

        // decode the wire bytes independently and confirm field 14 is present with the right value.
        let (prot, payload, sig) = try Cose.parseSign1Raw(signed)
        guard case let .m(pairs) = try Cbor.decode(payload) else { XCTFail("body not a map"); return }
        let decoded = try Envelope.objectFromMap(pairs)
        XCTAssertEqual(decoded.suite, Envelope.SuiteMLDSA65Ed25519, "decoded object must carry the signed suite")

        // and the signature sign() produced genuinely verifies (composite crypto is real).
        let tbs = try Cose.toBeSignedRaw(prot, payload)
        XCTAssertTrue(try Cose.compositeVerify(mldsaPub, edPub, tbs, sig),
                      "the composite signature produced by sign() must genuinely verify")
    }

    // MARK: - 2. PURE LEAVES THE SUITE ABSENT

    func testSignPureLeavesSuiteAbsent() throws {
        let edPub = try Cose.ed25519PublicKey(Self.edSeed)

        var o = Self.baseObject(profile: UInt64(Cose.PROFILE_PUBLIC))
        let signed = try Envelope.sign(&o, Cose.ALG_ED25519) { tbs in try Cose.ed25519Sign(Self.edSeed, tbs) }
        XCTAssertEqual(o.suite, 0, "a pure alg must leave the signed suite field absent")

        let (prot, payload, sig) = try Cose.parseSign1Raw(signed)
        guard case let .m(pairs) = try Cbor.decode(payload) else { XCTFail("body not a map"); return }
        let decoded = try Envelope.objectFromMap(pairs)
        XCTAssertEqual(decoded.suite, 0, "decoded pure object must carry no signed suite")

        // and the real Ed25519 signature sign() produced genuinely verifies.
        let tbs = try Cose.toBeSignedRaw(prot, payload)
        XCTAssertTrue(Cose.ed25519Verify(edPub, tbs, sig), "the Ed25519 signature produced by sign() must genuinely verify")
    }
}
