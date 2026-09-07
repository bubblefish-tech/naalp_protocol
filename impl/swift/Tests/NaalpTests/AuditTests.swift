// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C7 audit higher-tier conformance for the Swift SDK (design.md §8; R-8.1..8.6, R-12.2, R-12.3),
// graded against the shared independent corpus vectors/audit/cases.json (NOT produced by this code).
//
// CORPUS-GRADED (pure, signature-independent): the receipt body + chain head (SHA-384) per receipt,
// the final chain head, the ChainBroken linkage verdict, the fork-proof framing witness (preimage,
// signatures elided), the fork-proof fail-closed early rejects (ForkProofInvalid), the equivocation
// structural condition (one seq, different objects), and the causal verdicts + POSITION-tie-break
// topological order (distinct from federation reconcile's content-id tie-break).
//
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the authority's signed receipt chain and the
// auditor's fork-proof detection over real signatures. Swift is PURE-ONLY for ML-DSA (SwiftDilithium
// 3.6.0 has no deterministic-from-seed FIPS 204 path), so the reference's ML-DSA receipt / fork-proof
// signatures are demonstrated here with a real Ed25519 (RFC 8032) sign/verify round-trip via
// swift-crypto, exactly as WorkedExampleTests demonstrates the object signature surface. The
// reference's cross-language ML-DSA-65 signed pins are NOT reproducible in the pure tier and are NOT
// fabricated here (honest F2/F4), mirroring the committed PHP port.
//
// Written test-first: Naalp.Audit is absent until Audit.swift lands, so this fails RED with a compile
// error ("cannot find 'Audit' in scope"); a mutation that swaps the receipt body's seq/at keys flips
// "receipt body == oracle".
//
// Run:  swift test --filter AuditTests

import XCTest
@testable import Naalp

final class AuditTests: XCTestCase {

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

    /// Cross-platform numeric read: corelibs-foundation deserializes JSON numbers as NSNumber, and a
    /// bare `as? UInt64` can return nil on Linux — go through NSNumber.
    static func u64(_ v: Any?) throws -> UInt64 {
        return try XCTUnwrap(v as? NSNumber, "expected a JSON number").uint64Value
    }

    /// Walk up from this source file to find the committed corpus (mirrors WorkedExampleTests).
    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/audit/cases.json")
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
            throw XCTSkip("vectors/audit/cases.json not present (standalone build)")
        }
        return v
    }

    // 1. Every receipt's body (deterministic CBOR {1:prev,2:obj,3:seq,4:at}) and its chain head
    //    (SHA-384 of the body) equal the oracle, and the final head chains through. THE LOAD-BEARING
    //    property and the mutation target: swapping the seq/at keys flips "receipt body == oracle".
    func testReceiptBytesAndHeadMatchOracle() throws {
        let c = try Self.loadVector()
        let chain = try XCTUnwrap(c["chain"] as? [String: Any])
        let receipts = try XCTUnwrap(chain["receipts"] as? [[String: Any]])
        var head = [UInt8](repeating: 0, count: Audit.HEAD_SIZE)
        for rv in receipts {
            let prev = Self.hexToBytes(try XCTUnwrap(rv["prev_hex"] as? String))
            let obj = Self.hexToBytes(try XCTUnwrap(rv["obj_hex"] as? String))
            let seq = try Self.u64(rv["seq"])
            let at = try Self.u64(rv["at"])
            XCTAssertEqual(prev, head, "receipt prev chains to previous head")
            let r = Audit.Receipt(prev: prev, obj: obj, seq: seq, at: at)
            XCTAssertEqual(Self.toHex(try r.bytes()), rv["body_hex"] as? String, "receipt body == oracle")
            XCTAssertEqual(Self.toHex(try r.head()), rv["head_after_hex"] as? String, "receipt head == oracle")
            head = try r.head()
        }
        XCTAssertEqual(Self.toHex(head), chain["final_head_hex"] as? String, "final chain head == oracle")
    }

    // 2. a chain with a broken prev/seq linkage is rejected ChainBroken (signature-independent).
    func testChainBrokenRejected() throws {
        let c = try Self.loadVector()
        let cb = try XCTUnwrap(c["chain_broken"] as? [String: Any])
        let rows = try XCTUnwrap(cb["receipts"] as? [[String: Any]])
        let receipts = try rows.map { rv in
            Audit.Receipt(prev: Self.hexToBytes(try XCTUnwrap(rv["prev_hex"] as? String)),
                          obj: Self.hexToBytes(try XCTUnwrap(rv["obj_hex"] as? String)),
                          seq: try Self.u64(rv["seq"]), at: try Self.u64(rv["at"]))
        }
        XCTAssertThrowsError(try Audit.verifyChainLinks(receipts)) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, cb["expect"] as? String, "chain broken rejected")
        }
    }

    /// Build the two conflicting receipts from the fork_proof corpus entry (which carries prev/seq/at
    /// and both objects); their bodies equal both the fork_proof and equivocation oracle bodies.
    static func forkReceipts(_ fp: [String: Any]) throws -> (Audit.Receipt, Audit.Receipt) {
        let prev = hexToBytes(try XCTUnwrap(fp["prev_hex"] as? String))
        let seq = try u64(fp["seq"])
        let at = try u64(fp["at"])
        let a = Audit.Receipt(prev: prev, obj: hexToBytes(try XCTUnwrap(fp["obj_a_hex"] as? String)), seq: seq, at: at)
        let b = Audit.Receipt(prev: prev, obj: hexToBytes(try XCTUnwrap(fp["obj_b_hex"] as? String)), seq: seq, at: at)
        return (a, b)
    }

    // 3. the equivocation structural condition: two receipts at ONE seq naming DIFFERENT objects. The
    //    bodies match the oracle; the condition matches the oracle's "Equivocation" verdict.
    func testEquivocationStructuralCondition() throws {
        let c = try Self.loadVector()
        let fp = try XCTUnwrap(c["fork_proof"] as? [String: Any])
        let (a, b) = try Self.forkReceipts(fp)
        XCTAssertEqual(Self.toHex(try a.bytes()), fp["body_a_hex"] as? String, "receipt A body == oracle")
        XCTAssertEqual(Self.toHex(try b.bytes()), fp["body_b_hex"] as? String, "receipt B body == oracle")
        let equiv = try XCTUnwrap(c["equivocation"] as? [String: Any])
        XCTAssertEqual(Self.toHex(try a.bytes()),
                       (equiv["receipt_a"] as? [String: Any])?["body_hex"] as? String, "equivocation A body == oracle")
        XCTAssertEqual(Self.toHex(try b.bytes()),
                       (equiv["receipt_b"] as? [String: Any])?["body_hex"] as? String, "equivocation B body == oracle")
        let isEquivocation = (a.seq == b.seq) && (a.obj != b.obj)
        XCTAssertTrue(isEquivocation, "one seq, different objects")
        XCTAssertEqual(isEquivocation ? "Equivocation" : "none", equiv["expect"] as? String, "equivocation verdict == oracle")
    }

    // 4. the fork-proof framing witness (preimage, both signatures elided to empty) equals the oracle.
    func testForkProofPreimageMatchesOracle() throws {
        let c = try Self.loadVector()
        let fp = try XCTUnwrap(c["fork_proof"] as? [String: Any])
        let (a, b) = try Self.forkReceipts(fp)
        let signer = Self.hexToBytes(try XCTUnwrap(fp["signer_hex"] as? String))
        let ext = try Self.u64(fp["ext_counter"])
        // Signatures are elided in the preimage; use non-empty placeholders to prove the elision.
        let proof = Audit.newForkProof(signer, a, [0xde, 0xad], b, [0xbe, 0xef], ext)
        XCTAssertEqual(Self.toHex(try proof.preimage()), fp["preimage_hex"] as? String, "fork-proof preimage == oracle")
    }

    // 5. fail-closed early rejects (reached before any signature check): an unnamed signer, a
    //    seq-mismatch, and a same-object proof are all ForkProofInvalid regardless of the verifier.
    func testForkProofFailClosedRejects() throws {
        let c = try Self.loadVector()
        let fp = try XCTUnwrap(c["fork_proof"] as? [String: Any])
        let (a, b) = try Self.forkReceipts(fp)
        let signer = Self.hexToBytes(try XCTUnwrap(fp["signer_hex"] as? String))
        let acceptAll: (_ m: [UInt8], _ s: [UInt8]) -> Bool = { _, _ in true }

        let empty = Audit.newForkProof([], a, [0x01], b, [0x02], 0)
        XCTAssertThrowsError(try empty.verify(acceptAll)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ForkProofInvalid", "empty signer rejected")
        }
        let bAtSeq2 = Audit.Receipt(prev: b.prev, obj: b.obj, seq: b.seq + 1, at: b.at)
        let seqMismatch = Audit.newForkProof(signer, a, [0x01], bAtSeq2, [0x02], 0)
        XCTAssertThrowsError(try seqMismatch.verify(acceptAll)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ForkProofInvalid", "seq mismatch rejected")
        }
        let sameObj = Audit.newForkProof(signer, a, [0x01], a, [0x02], 0)
        XCTAssertThrowsError(try sameObj.verify(acceptAll)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ForkProofInvalid", "same object rejected")
        }
    }

    /// Build Audit.CausalNode[] from a corpus nodes array (binary ids/causes + integer position).
    static func causalNodes(_ raw: [[String: Any]]) throws -> [Audit.CausalNode] {
        return try raw.map { n in
            Audit.CausalNode(id: hexToBytes(try XCTUnwrap(n["id_hex"] as? String)),
                             causes: (try XCTUnwrap(n["causes_hex"] as? [String])).map { hexToBytes($0) },
                             position: try u64(n["position"]))
        }
    }

    // 6. a valid causal graph verifies, and its POSITION-tie-break topological order equals the oracle.
    func testCausalValidTopoOrderMatchesOracle() throws {
        let c = try Self.loadVector()
        let cv = try XCTUnwrap(c["causal_valid"] as? [String: Any])
        let nodes = try Self.causalNodes(try XCTUnwrap(cv["nodes"] as? [[String: Any]]))
        XCTAssertNoThrow(try Audit.verifyCausal(nodes))
        let order = try Audit.topoOrder(nodes)
        XCTAssertEqual(order.map { Self.toHex($0) }, cv["topo_order_hex"] as? [String], "topo order == oracle")
    }

    // 7. a cycle is rejected fail-closed (CausalViolation).
    func testCausalCycleRejected() throws {
        let c = try Self.loadVector()
        let cc = try XCTUnwrap(c["causal_cycle"] as? [String: Any])
        let nodes = try Self.causalNodes(try XCTUnwrap(cc["nodes"] as? [[String: Any]]))
        XCTAssertThrowsError(try Audit.topoOrder(nodes)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, cc["expect"] as? String, "cycle rejected")
        }
    }

    // 8. a future cause (a present cause at a later position than its effect) is CausalViolation.
    func testCausalFutureCauseRejected() throws {
        let c = try Self.loadVector()
        let cf = try XCTUnwrap(c["causal_future"] as? [String: Any])
        let nodes = try Self.causalNodes(try XCTUnwrap(cf["nodes"] as? [[String: Any]]))
        XCTAssertThrowsError(try Audit.verifyCausal(nodes)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, cf["expect"] as? String, "future cause rejected")
        }
    }

    // 9. ED25519-DEMONSTRATED (isolation, NOT corpus-graded): an authority signs a receipt chain that
    //    verifies under its key; an auditor observing two conflicting receipts mints a ForkProof that
    //    verifies under the accused key and is rejected under a foreign key. This exercises the signed
    //    audit paths in isolation; it is NOT the corpus-graded ML-DSA surface (PURE-ONLY Swift).
    func testEd25519AuthorityChainAndAuditorDemo() throws {
        let seed = [UInt8](repeating: 0x33, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let verify: (_ m: [UInt8], _ s: [UInt8]) -> Bool = { m, s in Cose.ed25519Verify(pk, m, s) }

        let auth = Audit.Authority(seed: seed)
        var receipts: [Audit.Receipt] = []
        var sigs: [[UInt8]] = []
        for i in 0..<3 {
            let (r, sig) = try auth.append(Cbor.contentId(Array("obj-\(i)".utf8)), UInt64(100 + i))
            receipts.append(r); sigs.append(sig)
        }
        XCTAssertNoThrow(try Audit.verifyChain(receipts, sigs, verify), "signed chain verifies")

        // Two conflicting receipts at one seq -> the auditor mints a ForkProof.
        let signerId = Array("bauthority-x".utf8)
        let auditor = Audit.Auditor(verify: verify, signer: signerId)
        let objA = Cbor.contentId(Array("a".utf8))
        let objB = Cbor.contentId(Array("b".utf8))
        let rA = Audit.Receipt(prev: [UInt8](repeating: 0, count: Audit.HEAD_SIZE), obj: objA, seq: 5, at: 500)
        let rB = Audit.Receipt(prev: [UInt8](repeating: 0, count: Audit.HEAD_SIZE), obj: objB, seq: 5, at: 501)
        let sigA = try Cose.ed25519Sign(seed, try rA.bytes())
        let sigB = try Cose.ed25519Sign(seed, try rB.bytes())
        XCTAssertNil(try auditor.observe(rA, sigA), "first receipt observed, no conflict yet")
        let proof = try XCTUnwrap(try auditor.observe(rB, sigB), "conflict mints a fork proof")
        XCTAssertNoThrow(try proof.verify(verify), "fork proof verifies under the accused key")

        let foreignPk = try Cose.ed25519PublicKey([UInt8](repeating: 0x44, count: 32))
        let foreignVerify: (_ m: [UInt8], _ s: [UInt8]) -> Bool = { m, s in Cose.ed25519Verify(foreignPk, m, s) }
        XCTAssertThrowsError(try proof.verify(foreignVerify)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ReceiptUnsigned", "fork proof rejected under a foreign key")
        }
    }
}
