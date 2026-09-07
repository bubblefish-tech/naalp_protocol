// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C8 delivery higher-tier conformance for the Swift SDK (design.md §9; R-9.1..9.4), graded against
// the shared independent corpus vectors/delivery/cases.json (NOT produced by this code).
//
// CORPUS-GRADED (pure, signature-independent): the four stage names, the delivery.update body
// byte-for-byte, the T1 content-id framing, and the durable WAL tracker's monotonic replay (advance
// returns the exact oracle update bytes; regression is StageOutOfOrder; a re-report is idempotent; a
// reopened tracker recovers the acked stage — persist-before-ack).
//
// STRUCTURAL (pure, concurrency): the full-duplex switchboard relays both directions concurrently.
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the delivery.update signature and the
// content-free relay's retained audit trail. Swift is PURE-ONLY for ML-DSA (SwiftDilithium 3.6.0 has
// no deterministic-from-seed FIPS 204 path), so the reference's ML-DSA update signature is demonstrated
// here with a real Ed25519 (RFC 8032) round-trip via swift-crypto; the relay's receipts are
// Ed25519-signed and verified with Audit.verifyChain. The reference's ML-DSA cross-language pins are
// NOT reproducible in the pure tier and are NOT fabricated (honest F2/F4), mirroring the PHP port.
//
// Written test-first: Naalp.Delivery is absent until Delivery.swift lands, so this fails RED with a
// compile error ("cannot find 'Delivery' in scope"); a mutation swapping the update body's stage/at
// keys flips "delivery update bytes == oracle".
//
// Run:  swift test --filter DeliveryTests

import XCTest
@testable import Naalp

final class DeliveryTests: XCTestCase {

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

    static func toHex(_ b: [UInt8]) -> String {
        let d = Array("0123456789abcdef")
        var s = ""
        for x in b { s.append(d[Int(x >> 4)]); s.append(d[Int(x & 0x0f)]) }
        return s
    }

    static func u64(_ v: Any?) throws -> UInt64 {
        return try XCTUnwrap(v as? NSNumber, "expected a JSON number").uint64Value
    }

    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/delivery/cases.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    static func loadVector() throws -> [String: Any] {
        guard let v = findVector() else {
            throw XCTSkip("vectors/delivery/cases.json not present (standalone build)")
        }
        return v
    }

    // 1. every stage value maps to the oracle name; an out-of-range value is "unknown".
    func testStageNamesMatchOracle() throws {
        let c = try Self.loadVector()
        let stages = try XCTUnwrap(c["stages"] as? [[String: Any]])
        for s in stages {
            let value = try Self.u64(s["value"])
            XCTAssertEqual(Delivery.stageName(value), s["name"] as? String, "stage name == oracle")
        }
        XCTAssertEqual(Delivery.stageName(99), "unknown", "out-of-range stage is unknown")
    }

    // 2. THE LOAD-BEARING property and the mutation target: each signed delivery.update body
    //    (deterministic CBOR {1:obj,2:stage,3:at}) equals the oracle byte-for-byte.
    func testUpdateBytesMatchOracle() throws {
        let c = try Self.loadVector()
        let obj = Self.hexToBytes(try XCTUnwrap(c["obj_content_id_hex"] as? String))
        let updates = try XCTUnwrap(c["updates"] as? [[String: Any]])
        for uv in updates {
            let stage = try Self.u64(uv["stage"])
            let at = try Self.u64(uv["at"])
            let du = Delivery.DeliveryUpdate(obj: obj, stage: stage, at: at)
            XCTAssertEqual(Self.toHex(try du.bytes()), uv["body_hex"] as? String, "delivery update bytes == oracle")
        }
    }

    // 3. the T1 content-id framing is multihash(0x20 sha2-384, 0x30 len-48) || SHA-384(bytes): the
    //    oracle obj content-id carries that framing, and Delivery.contentId reproduces it (cross-checked
    //    against the independently-graded Hashing.sha384).
    func testContentIdFraming() throws {
        let c = try Self.loadVector()
        let objCid = Self.hexToBytes(try XCTUnwrap(c["obj_content_id_hex"] as? String))
        XCTAssertEqual(objCid.count, 50, "content id is 2 + 48 octets")
        XCTAssertEqual(Array(objCid.prefix(2)), [0x20, 0x30], "content id multihash prefix")
        let sample = Array("delivery-framing-sample".utf8)
        XCTAssertEqual(Delivery.contentId(sample), [0x20, 0x30] + Hashing.sha384(sample),
                       "content id framing == 0x2030 || SHA-384")
    }

    // 4. CORPUS-GRADED tracker replay: advancing through the oracle stages returns the exact oracle
    //    update bytes and persists monotonically; a re-report is idempotent, a regression is
    //    StageOutOfOrder, and a reopened (replayed) tracker recovers the acked stage (persist-before-ack).
    func testTrackerMonotonicReplayAndRegression() throws {
        let c = try Self.loadVector()
        let obj = Self.hexToBytes(try XCTUnwrap(c["obj_content_id_hex"] as? String))
        let updates = try XCTUnwrap(c["updates"] as? [[String: Any]])
        // index the oracle bodies by stage
        var bodyByStage: [UInt64: String] = [:]
        var atByStage: [UInt64: UInt64] = [:]
        for uv in updates {
            let s = try Self.u64(uv["stage"])
            bodyByStage[s] = uv["body_hex"] as? String
            atByStage[s] = try Self.u64(uv["at"])
        }
        let path = NSTemporaryDirectory() + "naalp-delivery-\(UUID().uuidString).wal"
        defer { try? FileManager.default.removeItem(atPath: path) }

        let tr = try Delivery.openTracker(path)
        for stage: UInt64 in [0, 1, 2] {
            let ack = try tr.advance(obj, stage, atByStage[stage]!)
            XCTAssertEqual(Self.toHex(try ack.bytes()), bodyByStage[stage], "advance stage \(stage) bytes == oracle")
        }
        // re-report the current stage: idempotent no-op (does not throw).
        XCTAssertNoThrow(try tr.advance(obj, 2, 999), "re-report current stage is idempotent")
        // regress to an earlier stage: StageOutOfOrder.
        XCTAssertThrowsError(try tr.advance(obj, 1, 999)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "StageOutOfOrder", "stage regression rejected")
        }
        _ = try tr.advance(obj, 3, atByStage[3]!)
        XCTAssertEqual(tr.stage(obj).0, 3, "final stage recorded")
        try tr.close()

        // Reopen: the acked stage survived (persist-before-ack); regression still refused.
        let tr2 = try Delivery.openTracker(path)
        defer { try? tr2.close() }
        let (recovered, seen) = tr2.stage(obj)
        XCTAssertTrue(seen, "reopened tracker recovers the object")
        XCTAssertEqual(recovered, 3, "acked stage survived a reopen")
        XCTAssertThrowsError(try tr2.advance(obj, 0, 200)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "StageOutOfOrder", "regression after recovery rejected")
        }
    }

    // 5. ED25519-DEMONSTRATED (isolation, NOT corpus-graded): a delivery.update signs and verifies under
    //    the observer's key; a tampered update (different stage) does not verify.
    func testEd25519UpdateSignVerifyDemo() throws {
        let c = try Self.loadVector()
        let obj = Self.hexToBytes(try XCTUnwrap(c["obj_content_id_hex"] as? String))
        let seed = [UInt8](repeating: 0x51, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let u = Delivery.DeliveryUpdate(obj: obj, stage: 2, at: 102)
        let sig = try Delivery.signUpdate(u, seed)
        XCTAssertTrue(try Delivery.verifyUpdate(u, pk, sig), "ed25519 delivery update verifies")
        let tampered = Delivery.DeliveryUpdate(obj: obj, stage: 3, at: 102)
        XCTAssertFalse(try Delivery.verifyUpdate(tampered, pk, sig), "tampered update rejected")
        let foreignPk = try Cose.ed25519PublicKey([UInt8](repeating: 0x52, count: 32))
        XCTAssertFalse(try Delivery.verifyUpdate(u, foreignPk, sig), "foreign-key update rejected")
    }

    // 6. STRUCTURAL (concurrency): the switchboard relays both directions concurrently and in order,
    //    with per-direction capacity 1 (a one-object mailbox would deadlock).
    func testSwitchboardFullDuplex() throws {
        let sb = Delivery.Switchboard(1)
        let n = 100
        let group = DispatchGroup()
        let q = DispatchQueue.global()
        var gotAB = [[UInt8]]()
        var gotBA = [[UInt8]]()
        group.enter(); q.async { for i in 0..<n { sb.left().send([UInt8(i % 251), 0xAB]) }; group.leave() }
        group.enter(); q.async { for _ in 0..<n { gotAB.append(sb.right().recv()) }; group.leave() }
        group.enter(); q.async { for i in 0..<n { sb.right().send([UInt8(i % 251), 0xBA]) }; group.leave() }
        group.enter(); q.async { for _ in 0..<n { gotBA.append(sb.left().recv()) }; group.leave() }
        let r = group.wait(timeout: .now() + 15)
        sb.close()
        XCTAssertEqual(r, .success, "switchboard completed (no deadlock)")
        XCTAssertEqual(gotAB.count, n, "A->B delivered all")
        XCTAssertEqual(gotBA.count, n, "B->A delivered all")
        for i in 0..<n {
            XCTAssertEqual(gotAB[i], [UInt8(i % 251), 0xAB], "A->B object \(i) in order/content")
            XCTAssertEqual(gotBA[i], [UInt8(i % 251), 0xBA], "B->A object \(i) in order/content")
        }
    }

    // 7. ED25519-DEMONSTRATED (isolation): a content-free relay routes objects and retains only a valid
    //    signed audit trail over content ids — no payload at rest (R-9.4).
    func testContentFreeRelayDemo() throws {
        let seed = [UInt8](repeating: 0x32, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let verify: (_ m: [UInt8], _ s: [UInt8]) -> Bool = { m, s in Cose.ed25519Verify(pk, m, s) }
        let relay = Delivery.ContentFreeRelay(seed: seed)
        let payloads = [Array("object one".utf8), Array("object two".utf8), Array("object three".utf8)]
        for (i, p) in payloads.enumerated() {
            let out = try relay.route(p, UInt64(100 + i))
            XCTAssertEqual(out, p, "relay forwards the object unchanged")
        }
        let (receipts, sigs) = relay.auditTrail()
        XCTAssertEqual(receipts.count, payloads.count, "one receipt per routed object")
        XCTAssertNoThrow(try Audit.verifyChain(receipts, sigs, verify), "relay audit trail is a valid signed chain")
        for (i, p) in payloads.enumerated() {
            XCTAssertEqual(receipts[i].obj, Delivery.contentId(p), "receipt references the content id, not the payload")
        }
    }
}
