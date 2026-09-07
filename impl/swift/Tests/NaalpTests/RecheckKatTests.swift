// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// T1.3 recheck (the checkable-minimum re-check procedure, design.md §2.5, NAALP-REQ-110/111)
// known-answer tests for the Swift SDK, graded against the independent oracle
// (tools/recheck_oracle.py -> vectors/recheck/cases.json), mirroring
// impl/go/envelope/envelope_test.go's TestRecheckMatchesOracle/TestRecheckRejectPathIsReal/
// TestRecheckReaderRoundTrip.
//
// PURE-ONLY CRYPTO CAVEAT (see Envelope.swift / MlDsa.swift, and ProducingBoundaryKatTests.swift
// for the established idiom this file mirrors): `Envelope.verify()`'s ML-DSA signature branch
// still throws `Unavailable` (skip-tracked, never a false green) even though `MlDsa.sign`/
// `MlDsa.verify` (the deterministic BoringSSL shim) are real. So for a case whose corpus verdict
// is "accept", `verify()` cannot return an accepted Object directly -- the established idiom is to
// assert it reaches the ML-DSA boundary (throws exactly `Unavailable`, proving every earlier
// structural check -- content-id, ranges, header/body copies, critical extensions, kind dispatch,
// profile floor -- passed), independently confirm the signature is genuinely valid via
// `Cose.coseVerify1`, and reconstruct the verified Object via `Envelope.objectFromMap` on the
// decoded payload to read back `Envelope.recheck(...)`. A disposition reached BEFORE the ML-DSA
// step (UnknownCriticalExt for an unknown critical procedure id; NonCanonical for the negatives)
// is real and full-fidelity with the Go/Rust reference, no adaptation needed.
//
// Four properties, mirroring the reference tests, all mutation-surviving:
//   1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body
//      bytes; a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict
//      (adapted per the caveat above); and the parsed (id, present, critical) matches. Non-canonical
//      cext bytes are rejected NonCanonical at the codec.
//   2. REJECT PATH IS REAL [MUTATION ANCHOR] -- a CRITICAL recheck naming an UNKNOWN procedure id
//      is rejected UnknownCriticalExt; a known critical procedure and a non-critical UNKNOWN
//      procedure both verify, proving the reject is specific to unknown-under-critical.
//   3. READER ROUND TRIP -- setRecheck/recheck carry the id and criticality; a fresh object has
//      none; cext (critical) takes precedence over ext (non-critical) when both name the key.
//   4. IS KNOWN RECHECK PROCEDURE BOUNDARIES [MUTATION ANCHOR] -- the registry is exactly {1,2,3,4};
//      0 and 5 are unknown.
//
// Run:  swift test --package-path impl/swift --filter RecheckKatTests

import Foundation
import XCTest
@testable import Naalp

final class RecheckKatTests: XCTestCase {

    // A fixed ML-DSA-65 keypair for the round-trip tests (bytes 1..32), matching
    // impl/go/envelope/envelope_test.go's testSigner and ProducingBoundaryKatTests.seed.
    static let seed: [UInt8] = (1...32).map { UInt8($0) }

    static func kindOk(_ ch: UInt64, _ k: UInt64) -> Bool { ch == 4 && k == 2 }

    /// The shared base object (mirrors corpus.base_object in vectors/recheck/cases.json): kind=2,
    /// channel=4, tier=0, signer="SIGNER_A", created=1785000000000, effect=2, causes=[], profile=1
    /// (Public), body="hello". Built from logical fields, never from the oracle hex, so a constant
    /// encoder diverges from the pinned bytes.
    static func baseObject() -> Envelope.Object {
        Envelope.Object(kind: 2, channel: 4, signer: WorkedExampleTests.hexToBytes("5349474e45525f41"),
                        created: 1785000000000, effect: 2, body: .t("hello"), tier: 0, profile: 1)
    }

    /// Apply a case's recheck placement -- the ONLY variable per case.
    static func applyPlacement(_ o: inout Envelope.Object, _ placement: String, _ procID: UInt64?) {
        switch placement {
        case "cext":
            Envelope.setRecheck(&o, procID!, true)
        case "ext":
            Envelope.setRecheck(&o, procID!, false)
        case "ext_empty":
            o.ext = .m([]) // present but empty (no recheck) -- distinct bytes from absent
        case "absent":
            break // no ext, no cext
        default:
            XCTFail("unknown placement \(placement)")
        }
    }

    /// Walk up from this source file to the committed vector (mirrors ProducingBoundaryKatTests).
    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/recheck/cases.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    /// Assemble a signed COSE_Sign1 object over a RAW payload (not built from an Object), for the
    /// non-canonical negative case: mirrors impl/go/envelope/envelope_test.go's signRawPayload.
    static func signRawPayload(_ seed: [UInt8], _ payload: [UInt8]) throws -> [UInt8] {
        let prot = try Envelope.protectedHeader(Cose.ALG_MLDSA65, Array("SIGNER_A".utf8), 1)
        let tbs = try Cose.toBeSignedRaw(prot, payload)
        let sig = try MlDsa.sign(seed, tbs, Cose.ALG_MLDSA65)
        return try Cose.assembleSign1Raw(prot, payload, sig)
    }

    // MARK: - 1. MATCHES ORACLE

    func testRecheckMatchesOracle() throws {
        guard let corpus = Self.findVector() else {
            throw XCTSkip("committed recheck vector not present (standalone build)")
        }
        XCTAssertEqual(corpus["recheck_key"] as? Int, Int(Envelope.RecheckKey), "corpus key != impl key")
        guard let cases = corpus["cases"] as? [[String: Any]] else {
            XCTFail("corpus has no cases[] array"); return
        }
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)

        for tc in cases {
            let name = tc["name"] as? String ?? "?"
            let placement = tc["placement"] as? String ?? "absent"
            let procID: UInt64? = (tc["procedure_id"] as? Int).map { UInt64($0) }

            // byte parity: body-without-id, content id, full body (all pre-signature).
            var o = Self.baseObject()
            Self.applyPlacement(&o, placement, procID)
            let bodyNoId = try Cbor.encode(try o.bodyMap(includeID: false))
            XCTAssertEqual(WorkedExampleTests.toHex(bodyNoId), tc["body_no_id_hex"] as? String, "\(name): body-no-id")
            let cid = try o.contentId()
            XCTAssertEqual(WorkedExampleTests.toHex(cid), tc["content_id_hex"] as? String, "\(name): content-id")
            o.id = cid
            let full = try Cbor.encode(try o.bodyMap(includeID: true))
            XCTAssertEqual(WorkedExampleTests.toHex(full), tc["full_hex"] as? String, "\(name): full-body")

            // verdict: sign for real; assert accept vs the named error (see the file-level caveat).
            var o2 = Self.baseObject()
            Self.applyPlacement(&o2, placement, procID)
            let inputs = try Envelope.signingInputs(&o2, Cose.ALG_MLDSA65)
            let sig = try MlDsa.sign(Self.seed, inputs.toBeSigned, Cose.ALG_MLDSA65)
            let signed = try Cose.assembleSign1Raw(inputs.protected, inputs.payload, sig)

            let expect = tc["expect"] as? String ?? "?"
            if expect == "accept" {
                XCTAssertThrowsError(
                    try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, signed)
                ) { error in
                    XCTAssertEqual((error as? NaalpError)?.kind, "Unavailable", "\(name): expected the ML-DSA boundary")
                }
                XCTAssertTrue(try Cose.coseVerify1(Cose.ALG_MLDSA65, pk, signed),
                              "\(name): genuine ML-DSA signature must verify")

                // reconstruct the object exactly as verify() would up to the crypto boundary.
                let (_, payload, _) = try Cose.parseSign1Raw(signed)
                guard case let .m(pairs) = try Cbor.decode(payload) else {
                    XCTFail("\(name): body not a map"); continue
                }
                let decoded = try Envelope.objectFromMap(pairs)
                let (rid, present, critical) = Envelope.recheck(decoded)
                let wantPresent = tc["present"] as? Bool ?? false
                XCTAssertEqual(present, wantPresent, "\(name): present")
                if present {
                    XCTAssertEqual(rid, procID, "\(name): id")
                    let wantCritical = tc["critical"] as? Bool ?? false
                    XCTAssertEqual(critical, wantCritical, "\(name): critical")
                }
            } else {
                XCTAssertThrowsError(
                    try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, signed)
                ) { error in
                    XCTAssertEqual((error as? NaalpError)?.kind, expect, "\(name): expected \(expect)")
                }
            }
        }

        // non-canonical recheck bodies (keys out of order) are rejected at the CBOR layer -- fires
        // at decode, before content-id or the ML-DSA boundary, so it is fully real regardless of
        // the pure-surface ML-DSA gap.
        guard let negatives = corpus["negatives"] as? [[String: Any]] else { return }
        for neg in negatives {
            let name = neg["name"] as? String ?? "?"
            guard let payloadHex = neg["payload_hex"] as? String, let expect = neg["expect"] as? String else {
                XCTFail("negative \(name): missing payload_hex/expect"); continue
            }
            let raw = try Self.signRawPayload(Self.seed, WorkedExampleTests.hexToBytes(payloadHex))
            XCTAssertThrowsError(
                try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, raw)
            ) { error in
                XCTAssertEqual((error as? NaalpError)?.kind, expect, "negative \(name)")
            }
        }
    }

    // MARK: - 2. REJECT PATH IS REAL [MUTATION ANCHOR]

    /// MUTATION ANCHOR for the reject path: a CRITICAL recheck naming an UNKNOWN procedure id MUST
    /// be rejected with UnknownCriticalExt. If the special-cased RecheckKey branch in
    /// Envelope.verify() is mutated to accept (drop the `guard isKnownRecheckProcedure(...) else`
    /// throw), this test flips pass->fail. A known critical procedure and a non-critical unknown
    /// procedure both verify (reach the ML-DSA boundary), proving the reject is specific to
    /// unknown-under-critical and not a blanket denial.
    func testRecheckRejectPathIsReal() throws {
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)

        var criticalUnknown = Self.baseObject()
        Envelope.setRecheck(&criticalUnknown, 99, true) // unknown id, critical
        let iu = try Envelope.signingInputs(&criticalUnknown, Cose.ALG_MLDSA65)
        let su = try Cose.assembleSign1Raw(iu.protected, iu.payload, try MlDsa.sign(Self.seed, iu.toBeSigned, Cose.ALG_MLDSA65))
        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, su)
        ) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "UnknownCriticalExt", "critical unknown recheck must be rejected")
        }

        var criticalKnown = Self.baseObject()
        Envelope.setRecheck(&criticalKnown, Envelope.RecheckWalkCauses, true) // known id, critical
        let ik = try Envelope.signingInputs(&criticalKnown, Cose.ALG_MLDSA65)
        let sk = try Cose.assembleSign1Raw(ik.protected, ik.payload, try MlDsa.sign(Self.seed, ik.toBeSigned, Cose.ALG_MLDSA65))
        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, sk)
        ) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Unavailable", "known critical recheck must reach the ML-DSA boundary")
        }

        var nonCritUnknown = Self.baseObject()
        Envelope.setRecheck(&nonCritUnknown, 99, false) // unknown id, non-critical -> ignored
        let inn = try Envelope.signingInputs(&nonCritUnknown, Cose.ALG_MLDSA65)
        let sn = try Cose.assembleSign1Raw(inn.protected, inn.payload, try MlDsa.sign(Self.seed, inn.toBeSigned, Cose.ALG_MLDSA65))
        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, sn)
        ) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Unavailable", "unknown non-critical recheck must be ignored")
        }
    }

    // MARK: - 3. READER ROUND TRIP

    /// Proves setRecheck/recheck carry the id and criticality, and that cext (critical) takes
    /// precedence over ext (non-critical) when both name the key.
    func testRecheckReaderRoundTrip() {
        var o = Self.baseObject()
        let (_, present0, _) = Envelope.recheck(o)
        XCTAssertFalse(present0, "fresh object must have no recheck")

        Envelope.setRecheck(&o, Envelope.RecheckVerifyCoseSign1, false)
        var (id1, present1, critical1) = Envelope.recheck(o)
        XCTAssertTrue(present1)
        XCTAssertEqual(id1, Envelope.RecheckVerifyCoseSign1)
        XCTAssertFalse(critical1)

        Envelope.setRecheck(&o, Envelope.RecheckReplayConsumeCheck, true) // critical wins over the ext entry
        (id1, present1, critical1) = Envelope.recheck(o)
        XCTAssertTrue(present1)
        XCTAssertEqual(id1, Envelope.RecheckReplayConsumeCheck)
        XCTAssertTrue(critical1)
    }

    // MARK: - 4. IS KNOWN RECHECK PROCEDURE BOUNDARIES [MUTATION ANCHOR]

    /// MUTATION ANCHOR: the registry is exactly the closed set {1,2,3,4}; 0 and 5 (just below/above)
    /// are unknown. Making isKnownRecheckProcedure return true unconditionally flips this test
    /// pass->fail on the 0/5 assertions.
    func testIsKnownRecheckProcedureBoundaries() {
        XCTAssertTrue(Envelope.isKnownRecheckProcedure(1))
        XCTAssertTrue(Envelope.isKnownRecheckProcedure(2))
        XCTAssertTrue(Envelope.isKnownRecheckProcedure(3))
        XCTAssertTrue(Envelope.isKnownRecheckProcedure(4))
        XCTAssertFalse(Envelope.isKnownRecheckProcedure(0))
        XCTAssertFalse(Envelope.isKnownRecheckProcedure(5))
    }
}
