// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Envelope decoder resource bounds (design.md §3.4, R7) for the Swift SDK, mirroring
// impl/go/envelope/bounds_test.go: causes[] cardinality, ext/cext cardinality, CBOR nesting
// depth, and the object octet-size bound. Each bound is proven by a BOUNDARY PAIR: an
// otherwise-valid object AT the limit verifies, and an otherwise-valid object one past the limit
// is rejected with the named error. "Otherwise valid" is load-bearing for mutation survival:
// because the only defect is the bound, deleting the bound check makes the over-limit object
// verify, so a constant-return mutation is caught.
//
// PURE-ONLY CRYPTO CAVEAT (see Envelope.swift): `Envelope.verify()`'s ML-DSA signature branch
// throws `Unavailable` (skip-tracked, never a false green) even though `MlDsa.sign`/
// `MlDsa.keygenFromSeed` are real. So an "otherwise-valid, at-limit" object cannot return an
// accepted Object directly -- the established idiom for this exact situation (see
// ProducingBoundaryKatTests / RecheckKatTests / SignerCounterKatTests) is to assert it reaches
// the ML-DSA boundary (throws exactly `Unavailable`), proving every earlier structural check --
// including the bound under test -- passed. An over-limit object is rejected with its named
// error BEFORE the ML-DSA boundary, so that assertion is real and full-fidelity regardless of
// the pure-tier gap.
//
// Run:  swift test --package-path impl/swift --filter EnvelopeBoundsTests

import Foundation
import XCTest
@testable import Naalp

final class EnvelopeBoundsTests: XCTestCase {

    // A fixed ML-DSA-65 keypair (bytes 1..32), matching the established idiom in
    // ProducingBoundaryKatTests / RecheckKatTests / SignerCounterKatTests.
    static let seed: [UInt8] = (1...32).map { UInt8($0) }

    static func kindOk(_ ch: UInt64, _ k: UInt64) -> Bool { ch == 4 && k == 2 }

    static func baseObject() -> Envelope.Object {
        Envelope.Object(kind: 2, channel: 4, signer: Array("SIGNER_A".utf8), created: 1785000000000,
                        effect: 2, body: .t("hello"), tier: 0, profile: 1)
    }

    /// n content-id-shaped causes (a 50-byte bstr with the multihash prefix 0x20 0x30), so the
    /// object is otherwise valid at any cardinality.
    static func makeCauses(_ n: Int) -> [[UInt8]] {
        (0..<n).map { _ in
            var b = [UInt8](repeating: 0, count: 50)
            b[0] = 0x20
            b[1] = 0x30
            return b
        }
    }

    /// n distinct non-critical extension entries (unknown keys, which the may-ignore rule
    /// accepts), so the object is otherwise valid at any cardinality.
    static func makeExtMap(_ n: Int) -> CborValue {
        .m((0..<n).map { i in (.u(UInt64(100 + i)), .u(0)) })
    }

    /// k single-element arrays wrapping a zero scalar. As a body value it sits at depth 2 (the
    /// object body map is depth 1), so the innermost scalar is at depth 2+k.
    static func nestArrays(_ k: Int) -> CborValue {
        var v: CborValue = .u(0)
        for _ in 0..<k { v = .a([v]) }
        return v
    }

    /// Content-id-binds, ML-DSA-65 signs (real crypto, task #142), and assembles `o`.
    static func signMLDSA(_ o: Envelope.Object) throws -> [UInt8] {
        var obj = o
        let inputs = try Envelope.signingInputs(&obj, Cose.ALG_MLDSA65)
        let sig = try MlDsa.sign(seed, inputs.toBeSigned, Cose.ALG_MLDSA65)
        return try Cose.assembleSign1Raw(inputs.protected, inputs.payload, sig)
    }

    /// Asserts `signed` reaches the ML-DSA boundary (throws exactly Unavailable), proving every
    /// earlier structural check -- content-id, ranges, header/body copies, critical extensions,
    /// kind dispatch, profile floor, and the bound under test -- passed.
    static func expectAccept(_ signed: [UInt8], _ pk: [UInt8], _ msg: String,
                             file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, kindOk, signed),
            msg, file: file, line: line
        ) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Unavailable", msg, file: file, line: line)
        }
    }

    /// Asserts `signed` is rejected with the exact named error, fail-closed, before the ML-DSA
    /// boundary.
    static func expectReject(_ signed: [UInt8], _ kind: String, _ pk: [UInt8], _ msg: String,
                             file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, kindOk, signed),
            msg, file: file, line: line
        ) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, kind, msg, file: file, line: line)
        }
    }

    /// An object exactly AT each cardinality/depth bound verifies, so the boundary is inclusive
    /// and the reject tests below prove the boundary itself.
    func testBoundsAcceptAtLimit() throws {
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)

        var oc = Self.baseObject()
        oc.causes = Self.makeCauses(Int(MAX_CAUSES))
        Self.expectAccept(try Self.signMLDSA(oc), pk, "causes==MAX_CAUSES")

        var oe = Self.baseObject()
        oe.ext = Self.makeExtMap(Int(MAX_EXT))
        Self.expectAccept(try Self.signMLDSA(oe), pk, "ext==MAX_EXT")

        // body nested so the deepest scalar sits at exactly MAX_NESTING_DEPTH
        // (2 + (MAX_NESTING_DEPTH-2)).
        var od = Self.baseObject()
        od.body = Self.nestArrays(Int(MAX_NESTING_DEPTH) - 2)
        Self.expectAccept(try Self.signMLDSA(od), pk, "depth==MAX_NESTING_DEPTH")
    }

    /// An otherwise-valid object one past each bound is rejected with its named error
    /// (fail-closed). MUTATION TARGET.
    func testBoundsRejectOverLimit() throws {
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)

        var oc = Self.baseObject()
        oc.causes = Self.makeCauses(Int(MAX_CAUSES) + 1)
        Self.expectReject(try Self.signMLDSA(oc), "TooManyCauses", pk, "TooManyCauses")

        var oe = Self.baseObject()
        oe.ext = Self.makeExtMap(Int(MAX_EXT) + 1)
        Self.expectReject(try Self.signMLDSA(oe), "TooManyExtensions", pk, "TooManyExtensions(ext)")

        // cext over the limit also yields TooManyExtensions: the cardinality check in
        // objectFromMap fires before the critical-extension recognition check.
        var ox = Self.baseObject()
        ox.cext = Self.makeExtMap(Int(MAX_CEXT) + 1)
        Self.expectReject(try Self.signMLDSA(ox), "TooManyExtensions", pk, "TooManyExtensions(cext)")

        // body nested so the deepest scalar sits at MAX_NESTING_DEPTH+1.
        var od = Self.baseObject()
        od.body = Self.nestArrays(Int(MAX_NESTING_DEPTH) - 1)
        Self.expectReject(try Self.signMLDSA(od), "DepthExceeded", pk, "DepthExceeded")
    }

    /// Pins the object octet-size bound: a large-but-under-limit signed object reaches the
    /// ML-DSA boundary, and an otherwise-valid object over the limit is rejected TooLarge on the
    /// raw bytes before any parse (RFC 8949 §10 decoder-memory guard). MUTATION TARGET.
    func testBoundTooLarge() throws {
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)

        var under = Self.baseObject()
        under.body = .b([UInt8](repeating: 0, count: Int(MAX_OBJECT_SIZE) - 16384))
        let underSigned = try Self.signMLDSA(under)
        XCTAssertLessThanOrEqual(UInt64(underSigned.count), MAX_OBJECT_SIZE,
                                 "under-limit object is \(underSigned.count) bytes, expected <= \(MAX_OBJECT_SIZE)")
        Self.expectAccept(underSigned, pk, "under-limit reaches the ML-DSA boundary")

        var over = Self.baseObject()
        over.body = .b([UInt8](repeating: 0, count: Int(MAX_OBJECT_SIZE)))
        let overSigned = try Self.signMLDSA(over)
        XCTAssertGreaterThan(UInt64(overSigned.count), MAX_OBJECT_SIZE,
                             "over-limit object is \(overSigned.count) bytes, expected > \(MAX_OBJECT_SIZE)")
        Self.expectReject(overSigned, "TooLarge", pk, "TooLarge")
    }
}
