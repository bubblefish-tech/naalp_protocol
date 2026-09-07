// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// T1.6 the OPTIONAL per-signer forward-only counter (design.md §2.5.2, NAALP-REQ-120) and
// DetectSignerDuplication known-answer tests for the Swift SDK, graded against the independent
// oracle (tools/signer_counter_oracle.py -> vectors/signer_counter/cases.json), mirroring
// impl/go/envelope/signer_counter_test.go.
//
// PURE-ONLY CRYPTO CAVEAT (see Envelope.swift / RecheckKatTests.swift for the established idiom):
// `Envelope.verify()`'s ML-DSA signature branch throws `Unavailable` (skip-tracked, never a false
// green). For a case whose corpus verdict is "accept", the disposition is adapted to asserting the
// ML-DSA boundary is reached + an independent `Cose.coseVerify1` pass + reconstructing the object
// via `Envelope.objectFromMap` to read back `Envelope.signerCounter(...)`. A disposition reached
// BEFORE the ML-DSA step (UnknownCriticalExt for the cext placement; NonCanonical for the
// negatives) is real and full-fidelity, no adaptation needed. `DetectSignerDuplication` itself does
// no signing at all -- it is graded directly against the oracle's detection scenarios.
//
// Six properties, mirroring the reference tests, all mutation-surviving:
//   1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body
//      bytes and accept/reject verdict (adapted per the caveat above); the parsed (seq, present)
//      matches.
//   2. UNDER SIGNATURE -- the counter is folded into the SIGNER's signed body: splicing a different
//      counter into a signed object (keeping its id) is rejected.
//   3. READER ROUND TRIP -- setSignerCounter/signerCounter carry the value; the field is OPTIONAL;
//      a present counter of value 0 reads back present (present is keyed on the key, not the value).
//   4. DETECTION MATCHES ORACLE -- detectSignerDuplication reproduces every oracle scenario's exact
//      findings (signer, counter, and the ordered set of content ids).
//   5. ONE SEQUENCE NOT FLAGGED [MUTATION ANCHOR] -- a single sequence (one object per value, or an
//      honest forward-only run) is never flagged; detection requires two conflicting sequences to
//      physically meet.
//   6. ABSENT VALIDATES [MUTATION ANCHOR] -- an object carrying no counter Signs and Verifies (the
//      field is OPTIONAL, never mandatory).
//
// Run:  swift test --package-path impl/swift --filter SignerCounterKatTests

import Foundation
import XCTest
@testable import Naalp

final class SignerCounterKatTests: XCTestCase {

    // A fixed ML-DSA-65 keypair for the round-trip tests (bytes 1..32), matching
    // impl/go/envelope/envelope_test.go's testSigner and RecheckKatTests.seed.
    static let seed: [UInt8] = (1...32).map { UInt8($0) }

    static let signerAHex = "5349474e45525f41" // SIGNER_A
    static let signerBHex = "5349474e45525f42" // SIGNER_B

    static func kindOk(_ ch: UInt64, _ k: UInt64) -> Bool { ch == 4 && k == 2 }

    /// The shared base object (mirrors corpus.base_object in vectors/signer_counter/cases.json):
    /// kind=2, channel=4, tier=0, signer=SIGNER_A, created=1785000000000, effect=2, causes=[],
    /// profile=1 (Public), body="hello", with an optional per-object signer/body override. Built
    /// from logical fields, never from the oracle hex, so a constant encoder diverges from the
    /// pinned bytes.
    static func baseObject(signerHex: String? = nil, bodyStr: String? = nil) -> Envelope.Object {
        let sh = (signerHex?.isEmpty == false) ? signerHex! : signerAHex
        let bs = (bodyStr?.isEmpty == false) ? bodyStr! : "hello"
        return Envelope.Object(kind: 2, channel: 4, signer: WorkedExampleTests.hexToBytes(sh),
                                created: 1785000000000, effect: 2, body: .t(bs), tier: 0, profile: 1)
    }

    /// Apply a case's counter placement -- the ONLY variable per case. "cext" builds the map
    /// DIRECTLY (setSignerCounter is ext-only by design), mirroring impl/go's applyPlacement.
    static func applyPlacement(_ o: inout Envelope.Object, _ placement: String, _ counter: UInt64?) {
        switch placement {
        case "ext":
            Envelope.setSignerCounter(&o, counter!)
        case "cext":
            o.cext = .m([(.u(Envelope.SignerCounterKey), .u(counter!))])
        case "ext_empty":
            o.ext = .m([]) // present but empty (no counter) -- distinct bytes from absent
        case "absent":
            break // no ext, no cext
        default:
            XCTFail("unknown placement \(placement)")
        }
    }

    /// Walk up from this source file to the committed vector (mirrors RecheckKatTests).
    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/signer_counter/cases.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    /// A counter from the corpus is a bare JSON number (<= 2^53) or a QUOTED decimal string
    /// (> 2^53, so a float64 JSON decoder cannot round it -- R12 / NAALP-01-03). Read either form
    /// as the exact UInt64; nil for JSON null / absent.
    static func counterU64(_ v: Any?) -> UInt64? {
        if let n = v as? NSNumber { return n.uint64Value }
        if let s = v as? String { return UInt64(s) }
        return nil
    }

    /// Assemble a signed COSE_Sign1 object over a RAW payload (not built from an Object), for the
    /// non-canonical negative case.
    static func signRawPayload(_ seed: [UInt8], _ payload: [UInt8]) throws -> [UInt8] {
        let prot = try Envelope.protectedHeader(Cose.ALG_MLDSA65, Array("SIGNER_A".utf8), 1)
        let tbs = try Cose.toBeSignedRaw(prot, payload)
        let sig = try MlDsa.sign(seed, tbs, Cose.ALG_MLDSA65)
        return try Cose.assembleSign1Raw(prot, payload, sig)
    }

    // MARK: - 1. MATCHES ORACLE

    func testSignerCounterMatchesOracle() throws {
        guard let corpus = Self.findVector() else {
            throw XCTSkip("committed signer_counter vector not present (standalone build)")
        }
        XCTAssertEqual(corpus["counter_key"] as? Int, Int(Envelope.SignerCounterKey), "corpus key != impl key")
        guard let cases = corpus["cases"] as? [[String: Any]] else {
            XCTFail("corpus has no cases[] array"); return
        }
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)

        for tc in cases {
            let name = tc["name"] as? String ?? "?"
            let placement = tc["placement"] as? String ?? "absent"
            let counter: UInt64? = Self.counterU64(tc["counter"])
            let signerHex = tc["signer_hex"] as? String
            let bodyStr = tc["body_str"] as? String

            // byte parity: body-without-id, content id, full body (all pre-signature).
            var o = Self.baseObject(signerHex: signerHex, bodyStr: bodyStr)
            Self.applyPlacement(&o, placement, counter)
            let bodyNoId = try Cbor.encode(try o.bodyMap(includeID: false))
            XCTAssertEqual(WorkedExampleTests.toHex(bodyNoId), tc["body_no_id_hex"] as? String, "\(name): body-no-id")
            let cid = try o.contentId()
            XCTAssertEqual(WorkedExampleTests.toHex(cid), tc["content_id_hex"] as? String, "\(name): content-id")
            o.id = cid
            let full = try Cbor.encode(try o.bodyMap(includeID: true))
            XCTAssertEqual(WorkedExampleTests.toHex(full), tc["full_hex"] as? String, "\(name): full-body")

            // verdict: sign for real; assert accept vs the named error.
            var o2 = Self.baseObject(signerHex: signerHex, bodyStr: bodyStr)
            Self.applyPlacement(&o2, placement, counter)
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

                let (_, payload, _) = try Cose.parseSign1Raw(signed)
                guard case let .m(pairs) = try Cbor.decode(payload) else {
                    XCTFail("\(name): body not a map"); continue
                }
                let decoded = try Envelope.objectFromMap(pairs)
                let (seq, present) = Envelope.signerCounter(decoded)
                let wantPresent = tc["present"] as? Bool ?? false
                XCTAssertEqual(present, wantPresent, "\(name): present")
                if present {
                    XCTAssertEqual(seq, counter, "\(name): value")
                }
            } else {
                XCTAssertThrowsError(
                    try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, signed)
                ) { error in
                    XCTAssertEqual((error as? NaalpError)?.kind, expect, "\(name): expected \(expect)")
                }
            }
        }

        // non-canonical counter bodies (ext keys out of order) are rejected at the CBOR layer.
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

    /// Proves the counter is folded into the SIGNER's COSE_Sign1 signed input (ext, field 11, is
    /// part of the signed body): flipping the counter value in a signed object's payload without
    /// re-signing breaks verification.
    func testSignerCounterUnderSignature() throws {
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)
        var o = Self.baseObject()
        Envelope.setSignerCounter(&o, 5)
        let inputs = try Envelope.signingInputs(&o, Cose.ALG_MLDSA65)
        let sig = try MlDsa.sign(Self.seed, inputs.toBeSigned, Cose.ALG_MLDSA65)
        let signed = try Cose.assembleSign1Raw(inputs.protected, inputs.payload, sig)

        // baseline: the signed object reaches the ML-DSA boundary and its genuine signature
        // verifies; reconstruct the object and read back counter 5.
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
        let (seq0, present0) = Envelope.signerCounter(got)
        XCTAssertTrue(present0 && seq0 == 5, "counter read-back")

        // tamper: change the counter to 6 and re-encode the body WITHOUT re-signing; keep the
        // original id and reuse the original signature bytes -- a real forgery attempt.
        var tampered = Self.baseObject()
        Envelope.setSignerCounter(&tampered, 6)
        tampered.id = o.id // keep the original (counter=5) content id -- a splice, not a re-sign
        let forgedPayload = try Cbor.encode(try tampered.bodyMap(includeID: true))
        let (prot, _, origSig) = try Cose.parseSign1Raw(signed)
        let forged = try Cose.assembleSign1Raw(prot, forgedPayload, origSig)
        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, forged),
            "tampered counter must be rejected (it is under signature)"
        )
    }

    // MARK: - 3. READER ROUND TRIP

    /// Proves setSignerCounter/signerCounter carry the value, that the field is OPTIONAL (a fresh
    /// object has none), and that a present counter of value 0 reads back present (present is keyed
    /// on the key, not the value).
    func testSignerCounterReaderRoundTrip() {
        var o = Self.baseObject()
        let (_, present0) = Envelope.signerCounter(o)
        XCTAssertFalse(present0, "fresh object must have no counter")

        Envelope.setSignerCounter(&o, 42)
        var (seq, present) = Envelope.signerCounter(o)
        XCTAssertTrue(present)
        XCTAssertEqual(seq, 42)

        Envelope.setSignerCounter(&o, 0) // present with value zero
        (seq, present) = Envelope.signerCounter(o)
        XCTAssertTrue(present, "present-zero counter must read back present")
        XCTAssertEqual(seq, 0)
    }

    // MARK: - 4. DETECTION MATCHES ORACLE

    /// Reconstructs each detection scenario's presented objects from their logical fields,
    /// cross-checks each recomputed content id against the oracle's, and asserts
    /// detectSignerDuplication reproduces the oracle's exact findings.
    func testDetectSignerDuplicationMatchesOracle() throws {
        guard let corpus = Self.findVector() else {
            throw XCTSkip("committed signer_counter vector not present (standalone build)")
        }
        guard let detection = corpus["detection"] as? [String: Any],
              let scenarios = detection["scenarios"] as? [[String: Any]] else {
            XCTFail("corpus has no detection.scenarios[] array"); return
        }
        for sc in scenarios {
            let name = sc["name"] as? String ?? "?"
            guard let objDicts = sc["objects"] as? [[String: Any]] else {
                XCTFail("\(name): no objects[]"); continue
            }
            var objs: [Envelope.Object] = []
            for od in objDicts {
                let signerHex = od["signer_hex"] as? String
                let bodyStr = od["body_str"] as? String
                let counter: UInt64? = Self.counterU64(od["counter"])
                var o = Self.baseObject(signerHex: signerHex, bodyStr: bodyStr)
                if let c = counter {
                    Envelope.setSignerCounter(&o, c)
                }
                let id = try o.contentId()
                XCTAssertEqual(WorkedExampleTests.toHex(id), od["content_id_hex"] as? String,
                               "\(name): scenario object content-id")
                objs.append(o)
            }
            let findings = Envelope.detectSignerDuplication(objs)
            guard let expect = sc["expect"] as? [[String: Any]] else {
                XCTFail("\(name): no expect[]"); continue
            }
            XCTAssertEqual(findings.count, expect.count, "\(name): findings count")
            for (i, want) in expect.enumerated() where i < findings.count {
                let got = findings[i]
                XCTAssertEqual(WorkedExampleTests.toHex(got.signer), want["signer_hex"] as? String, "\(name): finding \(i) signer")
                let wantCounter = Self.counterU64(want["counter"])
                XCTAssertEqual(got.counter, wantCounter, "\(name): finding \(i) counter")
                let wantIds = want["ids_hex"] as? [String] ?? []
                XCTAssertEqual(got.ids.count, wantIds.count, "\(name): finding \(i) ids count")
                for (j, idHex) in wantIds.enumerated() where j < got.ids.count {
                    XCTAssertEqual(WorkedExampleTests.toHex(got.ids[j]), idHex, "\(name): finding \(i) id \(j)")
                }
            }
        }
    }

    // MARK: - 5. ONE SEQUENCE NOT FLAGGED [MUTATION ANCHOR]

    /// MUTATION ANCHOR: a single sequence (one object per value) MUST NOT be flagged -- detection
    /// requires two conflicting sequences to physically meet. Relaxing the `idset.count < 2` guard
    /// in detectSignerDuplication to `< 1` (flag from one) flips this test pass->fail; that is the
    /// whole detection-not-prevention line.
    func testDetectOneSequenceNotFlagged() throws {
        // one object alone at position 5.
        var one = Self.baseObject(bodyStr: "holder")
        Envelope.setSignerCounter(&one, 5)
        XCTAssertEqual(Envelope.detectSignerDuplication([one]).count, 0, "one sequence alone must not be flagged")

        // a full honest forward-only sequence from one signer (1,2,3) is also one sequence -> not flagged.
        var seqObjs: [Envelope.Object] = []
        for (i, body) in ["s1", "s2", "s3"].enumerated() {
            var o = Self.baseObject(bodyStr: body)
            Envelope.setSignerCounter(&o, UInt64(i + 1))
            seqObjs.append(o)
        }
        XCTAssertEqual(Envelope.detectSignerDuplication(seqObjs).count, 0, "an honest forward-only sequence must not be flagged")
    }

    /// Two DISTINCT objects, SAME signer id, SAME counter value, presented TOGETHER -> flagged
    /// once, surfacing BOTH content ids.
    func testDetectTwoConflictingFlagged() throws {
        var holder = Self.baseObject(bodyStr: "holder")
        Envelope.setSignerCounter(&holder, 5)
        var thief = Self.baseObject(bodyStr: "thief")
        Envelope.setSignerCounter(&thief, 5)

        let f = Envelope.detectSignerDuplication([holder, thief])
        XCTAssertEqual(f.count, 1, "two conflicting sequences must be flagged once")
        XCTAssertEqual(f[0].counter, 5)
        XCTAssertEqual(f[0].ids.count, 2, "both conflicting content ids must be surfaced")
        let hid = try holder.contentId()
        let tid = try thief.contentId()
        let surfaced = Set(f[0].ids)
        XCTAssertTrue(surfaced.contains(hid) && surfaced.contains(tid),
                      "the finding must surface both the holder's and the thief's content ids")
    }

    /// Two objects from one signer at DIFFERENT (forward-only consistent) positions are not
    /// flagged; nor are two different signers at one position.
    func testDetectForwardOnlyConsistentNotFlagged() {
        var a5 = Self.baseObject(bodyStr: "holder")
        Envelope.setSignerCounter(&a5, 5)
        var a6 = Self.baseObject(bodyStr: "next")
        Envelope.setSignerCounter(&a6, 6)
        XCTAssertEqual(Envelope.detectSignerDuplication([a5, a6]).count, 0, "forward-only-consistent sequence must not be flagged")

        var b5 = Self.baseObject(signerHex: Self.signerBHex, bodyStr: "other")
        Envelope.setSignerCounter(&b5, 5)
        XCTAssertEqual(Envelope.detectSignerDuplication([a5, b5]).count, 0, "different signers at one value must not be flagged")
    }

    // MARK: - 6. ABSENT VALIDATES [MUTATION ANCHOR]

    /// MUTATION ANCHOR: an object carrying NO counter Signs and Verifies. Making the field
    /// mandatory (e.g. adding a reject-if-absent check) flips this test pass->fail.
    func testSignerCounterAbsentValidates() throws {
        let pk = try MlDsa.keygenFromSeed(Self.seed, Cose.ALG_MLDSA65)
        var o = Self.baseObject()
        let (_, presentBefore) = Envelope.signerCounter(o)
        XCTAssertFalse(presentBefore, "object built without a counter must have none")

        let inputs = try Envelope.signingInputs(&o, Cose.ALG_MLDSA65)
        let sig = try MlDsa.sign(Self.seed, inputs.toBeSigned, Cose.ALG_MLDSA65)
        let signed = try Cose.assembleSign1Raw(inputs.protected, inputs.payload, sig)

        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, Self.kindOk, signed)
        ) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Unavailable",
                           "an object with an absent counter must verify (the field is OPTIONAL)")
        }
        let (_, payload, _) = try Cose.parseSign1Raw(signed)
        guard case let .m(pairs) = try Cbor.decode(payload) else {
            XCTFail("body not a map"); return
        }
        let got = try Envelope.objectFromMap(pairs)
        let (_, presentAfter) = Envelope.signerCounter(got)
        XCTAssertFalse(presentAfter, "verified object must report no counter")
    }
}
