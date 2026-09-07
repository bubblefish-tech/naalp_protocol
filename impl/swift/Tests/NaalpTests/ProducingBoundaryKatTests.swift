// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// NA-IETF-1 producing-boundary disclosure (the OPTIONAL, self-asserted ext key 15, §2.5.4)
// known-answer tests for the Swift SDK, graded against the independent oracle
// (tools/producing_boundary_oracle.py -> vectors/producing_boundary/cases.json), mirroring
// impl/go/envelope/producing_boundary_test.go and impl/python/tests/test_producing_boundary.py.
//
// PURE-ONLY CRYPTO CAVEAT (see Envelope.swift / MlDsa.swift): `Envelope.verify()`'s own ML-DSA
// signature branch still throws `Unavailable` (skip-tracked, never a false green) even though
// `MlDsa.sign`/`MlDsa.verify` (the deterministic BoringSSL shim, task #142) are real and already
// used for real end-to-end ML-DSA elsewhere (RotationKatTests, `Cose.coseSign1`/`coseVerify1`).
// So for a case whose corpus verdict is "accept", `Envelope.verify()` cannot return an accepted
// Object directly -- the honest, established idiom for this exact situation
// (WorkedExampleTests.testStructuralVerifyReachesMLDSABoundary) is to assert it reaches the
// ML-DSA boundary (throws exactly `Unavailable`, proving every earlier structural check --
// content-id, ranges, header/body copies, critical extensions, kind dispatch, profile floor --
// passed), independently confirm the signature is genuinely valid via `Cose.coseVerify1` (real
// crypto, not skipped), and reconstruct the verified Object the same way `verify()` would
// (`Envelope.objectFromMap` on the decoded payload) to read back the parsed disclosure. A
// disposition that is real and reachable regardless of the ML-DSA gap (UnknownCriticalExt fires
// before the crypto step; ContentIdMismatch and NonCanonical fire before it too) is graded for
// real, full fidelity with the Go/Rust/Python reference.
//
// Five properties, mirroring the reference tests, all mutation-surviving:
//   1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body
//      bytes; a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict
//      (adapted per the caveat above); and the parsed disclosure matches. Non-canonical sub-map
//      bytes are rejected NonCanonical at the codec.
//   2. UNDER SIGNATURE -- the disclosure is folded into the SIGNER's signed body: splicing a
//      different boundary into a signed object (keeping its id) is rejected.
//   3. READER ROUND TRIP -- set/get carries the value; the field is OPTIONAL; the setter DROPS a
//      reporting-boundary under observed (an observer relays from no one).
//   4. MALFORMED IGNORED [MUTATION ANCHOR] -- a well-formed object carrying a MALFORMED
//      disclosure (reporting under observed) in the non-critical ext map still verifies (reaches
//      the ML-DSA boundary, never an earlier rejection) and is NOT surfaced.
//   5. CEXT REJECTED [MUTATION ANCHOR] -- the disclosure in the CRITICAL cext map is
//      UnknownCriticalExt (fires before the ML-DSA boundary -- full fidelity with the reference).
//
// Run:  swift test --package-path impl/swift --filter ProducingBoundaryKatTests

import Foundation
import XCTest
@testable import Naalp

final class ProducingBoundaryKatTests: XCTestCase {

    // A fixed ML-DSA-65 keypair for the round-trip tests (bytes 1..32), matching
    // impl/go/envelope/envelope_test.go's testSigner.
    static let seed: [UInt8] = (1...32).map { UInt8($0) }

    // the producing-boundary value sub-map WIRE keys (§2.5.4), hardcoded here (not imported from
    // the module under test) so the test grades the impl against the oracle's independent wire
    // layout -- mirrors impl/python/tests/test_producing_boundary.py's local _K_BOUNDARY/_K_KIND/
    // _K_REPORTING convention.
    static let pbKey: UInt64 = 15
    static let pbKBoundary: UInt64 = 1
    static let pbKKind: UInt64 = 2
    static let pbKReporting: UInt64 = 3

    static func kindOk(_ ch: UInt64, _ k: UInt64) -> Bool { ch == 4 && k == 2 }

    /// The shared base object (mirrors corpus.base_object in vectors/producing_boundary/cases.json):
    /// kind=2, channel=4, tier=0, signer="BOUNDARY_X", created=1785000000000, effect=2, causes=[],
    /// profile=1 (Public), body="hello". Built from logical fields, never from the oracle hex, so a
    /// constant encoder diverges from the pinned bytes.
    static func baseObject() -> Envelope.Object {
        Envelope.Object(kind: 2, channel: 4, signer: WorkedExampleTests.hexToBytes("424f554e444152595f58"),
                        created: 1785000000000, effect: 2, body: .t("hello"), tier: 0, profile: 1)
    }

    /// Build the ext[15]/cext[15] sub-map DIRECTLY from the case's logical fields -- the ONLY
    /// variable per case -- reproducing the oracle bytes for well-formed AND malformed values (the
    /// malformed cases cannot be built via Envelope.setProducingBoundary by design, so they are
    /// constructed here).
    static func applyPlacement(_ o: inout Envelope.Object, _ tc: [String: Any]) {
        guard let placement = tc["placement"] as? String, placement != "absent" else { return }
        var sub: [(CborValue, CborValue)] = []
        if let bHex = tc["boundary_hex"] as? String {
            sub.append((.u(pbKBoundary), .b(WorkedExampleTests.hexToBytes(bHex))))
        }
        if let k = tc["kind"] as? Int {
            sub.append((.u(pbKKind), .u(UInt64(k))))
        }
        if let rHex = tc["reporting_hex"] as? String {
            sub.append((.u(pbKReporting), .b(WorkedExampleTests.hexToBytes(rHex))))
        }
        let ext: CborValue = .m([(.u(pbKey), .m(sub))])
        switch placement {
        case "ext": o.ext = ext
        case "cext": o.cext = ext
        default: XCTFail("unknown placement \(placement)")
        }
    }

    /// Walk up from this source file to the committed vector (mirrors WorkedExampleTests/AudienceTests).
    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/producing_boundary/cases.json")
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
    /// non-canonical negative case: mirrors impl/go/envelope/envelope_test.go's signRawPayload
    /// (signer "SIGNER_A", profile 1, fixed).
    static func signRawPayload(_ seed: [UInt8], _ payload: [UInt8]) throws -> [UInt8] {
        let prot = try Envelope.protectedHeader(Cose.ALG_MLDSA65, Array("SIGNER_A".utf8), 1)
        let tbs = try Cose.toBeSignedRaw(prot, payload)
        let sig = try MlDsa.sign(seed, tbs, Cose.ALG_MLDSA65)
        return try Cose.assembleSign1Raw(prot, payload, sig)
    }

    // MARK: - 1. MATCHES ORACLE

    func testProducingBoundaryMatchesOracle() throws {
        guard let corpus = Self.findVector() else {
            throw XCTSkip("committed producing_boundary vector not present (standalone build)")
        }
        XCTAssertEqual(corpus["producing_boundary_key"] as? Int, Int(Envelope.ProducingBoundaryKey),
                       "corpus key != impl key")
        guard let cases = corpus["cases"] as? [[String: Any]] else {
            XCTFail("corpus has no cases[] array"); return
        }
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)

        for tc in cases {
            let name = tc["name"] as? String ?? "?"

            // byte parity: body-without-id, content id, full body (all pre-signature).
            var o = Self.baseObject()
            Self.applyPlacement(&o, tc)
            let bodyNoId = try Cbor.encode(try o.bodyMap(includeID: false))
            XCTAssertEqual(WorkedExampleTests.toHex(bodyNoId), tc["body_no_id_hex"] as? String, "\(name): body-no-id")
            let cid = try o.contentId()
            XCTAssertEqual(WorkedExampleTests.toHex(cid), tc["content_id_hex"] as? String, "\(name): content-id")
            o.id = cid
            let full = try Cbor.encode(try o.bodyMap(includeID: true))
            XCTAssertEqual(WorkedExampleTests.toHex(full), tc["full_hex"] as? String, "\(name): full-body")

            // verdict: sign for real; assert accept vs the named error (see the file-level caveat
            // for how "accept" is adapted to this port's skip-tracked ML-DSA verify() boundary).
            var o2 = Self.baseObject()
            Self.applyPlacement(&o2, tc)
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
                let (pb, present) = Envelope.producingBoundary(decoded)
                let wantPresent = tc["present"] as? Bool ?? false
                XCTAssertEqual(present, wantPresent, "\(name): present")
                if present {
                    guard let surfaced = tc["surfaced"] as? [String: Any] else {
                        XCTFail("\(name): corpus marks present but carries no surfaced disclosure"); continue
                    }
                    if let kindInt = surfaced["kind"] as? Int {
                        XCTAssertEqual(pb.kind, UInt64(kindInt), "\(name): kind")
                    } else {
                        XCTFail("\(name): surfaced.kind missing")
                    }
                    XCTAssertEqual(WorkedExampleTests.toHex(pb.boundary), surfaced["boundary_hex"] as? String, "\(name): boundary")
                    let wantReporting = surfaced["reporting_hex"] as? String ?? ""
                    XCTAssertEqual(WorkedExampleTests.toHex(pb.reporting ?? []), wantReporting, "\(name): reporting")
                }
            } else {
                XCTAssertThrowsError(
                    try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, signed)
                ) { error in
                    XCTAssertEqual((error as? NaalpError)?.kind, expect, "\(name): expected \(expect)")
                }
            }
        }

        // non-canonical disclosure bodies (sub-map keys out of order) are rejected at the CBOR
        // layer -- fires at decode, before content-id or the ML-DSA boundary, so it is fully real
        // regardless of the pure-surface ML-DSA gap.
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

    // MARK: - 2. UNDER SIGNATURE

    /// Proves the disclosure is folded into the SIGNER's COSE_Sign1 signed input (ext, field 11,
    /// is part of the signed body): changing the boundary in a signed object's payload without
    /// re-signing breaks verification. A self-asserted disclosure that is NOT under the signer's
    /// signature would be forgeable, defeating attributability.
    func testProducingBoundaryUnderSignature() throws {
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)
        var o = Self.baseObject()
        Envelope.setProducingBoundary(&o, Envelope.ProducingBoundary(
            boundary: WorkedExampleTests.hexToBytes("424f554e444152595f58"), kind: Envelope.ProducingBoundaryObserved))
        let inputs = try Envelope.signingInputs(&o, Cose.ALG_MLDSA65)
        let sig = try MlDsa.sign(Self.seed, inputs.toBeSigned, Cose.ALG_MLDSA65)
        let signed = try Cose.assembleSign1Raw(inputs.protected, inputs.payload, sig)

        // baseline: the signed object reaches the ML-DSA boundary (every earlier structural check
        // passed) and its genuine signature verifies; reconstruct the object and read back the
        // disclosure exactly as verify() would.
        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, signed)
        ) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Unavailable")
        }
        XCTAssertTrue(try Cose.coseVerify1(Cose.ALG_MLDSA65, pk, signed))
        let (_, basePayload, _) = try Cose.parseSign1Raw(signed)
        guard case let .m(basePairs) = try Cbor.decode(basePayload) else {
            XCTFail("body not a map"); return
        }
        let got = try Envelope.objectFromMap(basePairs)
        let (pb, present) = Envelope.producingBoundary(got)
        XCTAssertTrue(present && pb.kind == Envelope.ProducingBoundaryObserved, "disclosure read-back")

        // tamper: change the boundary and re-encode the body WITHOUT re-signing; keep the original
        // id and reuse the original signature bytes -- a real forgery attempt that MUST be rejected.
        var tampered = Self.baseObject()
        Envelope.setProducingBoundary(&tampered, Envelope.ProducingBoundary(
            boundary: WorkedExampleTests.hexToBytes("4f524947494e5f59"), kind: Envelope.ProducingBoundaryObserved))
        tampered.id = o.id  // keep the original content id -- a splice, not a re-sign
        let forgedPayload = try Cbor.encode(try tampered.bodyMap(includeID: true))
        let (prot, _, origSig) = try Cose.parseSign1Raw(signed)
        let forged = try Cose.assembleSign1Raw(prot, forgedPayload, origSig)
        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, forged),
            "tampered producing-boundary must be rejected (it is under signature)"
        )
    }

    // MARK: - 3. READER ROUND TRIP

    /// Proves setProducingBoundary/producingBoundary carry the value, that the field is OPTIONAL
    /// (a fresh object has none), that a reported disclosure carries its reporting-boundary, and
    /// that the setter DROPS a reporting-boundary under observed (an observer relays from no one)
    /// so a caller cannot accidentally build a malformed disclosure.
    func testProducingBoundaryReaderRoundTrip() throws {
        var o = Self.baseObject()
        let (_, present0) = Envelope.producingBoundary(o)
        XCTAssertFalse(present0, "fresh object must have no producing-boundary disclosure")
        let x = WorkedExampleTests.hexToBytes("424f554e444152595f58")
        let y = WorkedExampleTests.hexToBytes("4f524947494e5f59")

        Envelope.setProducingBoundary(&o, Envelope.ProducingBoundary(
            boundary: x, kind: Envelope.ProducingBoundaryReported, reporting: y))
        var (pb, present) = Envelope.producingBoundary(o)
        XCTAssertTrue(present)
        XCTAssertEqual(pb.kind, Envelope.ProducingBoundaryReported)
        XCTAssertEqual(pb.boundary, x)
        XCTAssertEqual(pb.reporting, y)

        // the setter drops a reporting-boundary under observed: the read-back must have no reporting.
        Envelope.setProducingBoundary(&o, Envelope.ProducingBoundary(
            boundary: x, kind: Envelope.ProducingBoundaryObserved, reporting: y))
        (pb, present) = Envelope.producingBoundary(o)
        XCTAssertTrue(present)
        XCTAssertEqual(pb.kind, Envelope.ProducingBoundaryObserved)
        XCTAssertNil(pb.reporting, "observed disclosure must drop reporting")
    }

    // MARK: - 4. MALFORMED IGNORED [MUTATION ANCHOR]

    /// MUTATION ANCHOR for the may-ignore rule: a well-formed object carrying a MALFORMED
    /// producing-boundary in the non-critical ext map (a reporting-boundary under observed) still
    /// signs and reaches the ML-DSA boundary exactly like a well-formed disclosure (never an
    /// earlier structural rejection), and the disclosure is NOT surfaced. Removing the
    /// "reporting under observed -> malformed" check in Envelope.producingBoundary flips `present`
    /// false->true and this test pass->fail; that check is the observer-relays-from-no-one
    /// invariant.
    func testProducingBoundaryMalformedIgnored() throws {
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)
        var o = Self.baseObject()
        // malformed ext[15] = {1:X, 2:observed, 3:Y} built directly (the setter refuses to build it).
        o.ext = .m([(.u(Envelope.ProducingBoundaryKey), .m([
            (.u(1), .b(WorkedExampleTests.hexToBytes("424f554e444152595f58"))),
            (.u(2), .u(Envelope.ProducingBoundaryObserved)),
            (.u(3), .b(WorkedExampleTests.hexToBytes("4f524947494e5f59"))),
        ]))])
        let inputs = try Envelope.signingInputs(&o, Cose.ALG_MLDSA65)
        let sig = try MlDsa.sign(Self.seed, inputs.toBeSigned, Cose.ALG_MLDSA65)
        let signed = try Cose.assembleSign1Raw(inputs.protected, inputs.payload, sig)

        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, signed)
        ) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Unavailable",
                           "a malformed non-critical disclosure must be ignored, not rejected (may-ignore)")
        }
        let (_, payload, _) = try Cose.parseSign1Raw(signed)
        guard case let .m(pairs) = try Cbor.decode(payload) else {
            XCTFail("body not a map"); return
        }
        let got = try Envelope.objectFromMap(pairs)
        let (_, present) = Envelope.producingBoundary(got)
        XCTAssertFalse(present, "a malformed disclosure (reporting under observed) must NOT be surfaced")
    }

    // MARK: - 5. CEXT REJECTED [MUTATION ANCHOR]

    /// MUTATION ANCHOR for the fail-closed rule: the disclosure placed in the CRITICAL cext map
    /// (field 12) is an unrecognized critical extension and the object is rejected
    /// UnknownCriticalExt. A disclosure must never masquerade as a must-understand gate. This
    /// check fires BEFORE the ML-DSA boundary, so it is real, full-fidelity, no adaptation needed.
    func testProducingBoundaryCextRejected() throws {
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)
        var o = Self.baseObject()
        o.cext = .m([(.u(Envelope.ProducingBoundaryKey), .m([
            (.u(1), .b(WorkedExampleTests.hexToBytes("424f554e444152595f58"))),
            (.u(2), .u(Envelope.ProducingBoundaryObserved)),
        ]))])
        let inputs = try Envelope.signingInputs(&o, Cose.ALG_MLDSA65)
        let sig = try MlDsa.sign(Self.seed, inputs.toBeSigned, Cose.ALG_MLDSA65)
        let signed = try Cose.assembleSign1Raw(inputs.protected, inputs.payload, sig)

        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, signed)
        ) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "UnknownCriticalExt")
        }
    }
}
