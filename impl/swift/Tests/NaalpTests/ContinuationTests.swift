// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C17 N-AALP-CONT flow-continuation higher-tier conformance for the Swift SDK (design.md §20;
// R-CONT-1..7), graded against the shared independent corpus vectors/continuation/cases.json (values
// from the corpus, NEVER produced by this code).
//
// CORPUS-GRADED (pure, signature-independent): the FlowOpen body/head/id (incl. the minimal FlowOpen and
// empty-vs-populated approvals); each Continuation link body/head and the whole-chain final head; the
// Checkpoint body + prefix verdict; the FlowCommit body; the AboveCeiling refusal; GapDetected on a
// non-contiguous prefix; WrongFlow on a link replayed under a different FlowOpen; RangeError on an
// out-of-lattice ceiling/effect; the big_seq (<2^63) full byte-exact round-trip; the u64::MAX
// checkpoint overflow (decode-graded -> GapDetected, per the deterministic-CBOR >=2^63 path); the
// descending-key NonCanonical rejection; and the 2-field-FlowCommit-as-Checkpoint look-alike rejection.
//
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the FlowOpen / FlowCommit full signatures. Swift
// is PURE-ONLY for ML-DSA (SwiftDilithium 3.6.0 has no deterministic-from-seed FIPS 204 path), so the
// reference's ONE-full-ML-DSA-signature-opens/commits-the-flow property is demonstrated with a real
// Ed25519 (RFC 8032) COSE_Sign1 through Cose.coseVerify1 (which applies no profile floor — Ed25519 is
// level 0 and every profile floors at 3, so a profile-floored verify would reject before the signature
// step). The chain-binding checks (WrongFlow, CommitMismatch) are pure and corpus-graded. Honest F2/F4:
// the reference's ML-DSA cross-language signed pins are NOT reproducible here and are NOT fabricated.
//
// Written test-first: Naalp.Continuation is absent until Continuation.swift lands, so this fails RED
// with "cannot find 'Continuation' in scope". The load-bearing mutation removing the AboveCeiling check
// in verifyContinuation flips "above-ceiling continuation refused AboveCeiling".
//
// Run:  swift test --filter ContinuationTests

import Foundation
import XCTest
@testable import Naalp

final class ContinuationTests: XCTestCase {

    static func hexToBytes(_ s: String) -> [UInt8] {
        var out = [UInt8](); out.reserveCapacity(s.count / 2)
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
            let p = dir.appendingPathComponent("vectors/continuation/cases.json")
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
            throw XCTSkip("vectors/continuation/cases.json not present (standalone build)")
        }
        return v
    }

    /// Build the corpus FlowOpen A.
    static func openA(_ c: [String: Any]) throws -> Continuation.FlowOpen {
        let fo = try XCTUnwrap(c["flow_open"] as? [String: Any])
        let apps = try XCTUnwrap(fo["approvals_hex"] as? [String]).map { hexToBytes($0) }
        return Continuation.FlowOpen(
            flowID: hexToBytes(try XCTUnwrap(fo["flow_id_hex"] as? String)),
            effectCeiling: try u64(fo["effect_ceiling"]),
            approvals: apps)
    }

    /// Build the three corpus continuation links (each with its corpus prev/effect/payload).
    static func links(_ c: [String: Any], _ flowOpenID: [UInt8]) throws -> [Continuation.Link] {
        let arr = try XCTUnwrap(c["continuations"] as? [[String: Any]])
        return try arr.map { cv in
            Continuation.Link(
                flowOpenID: flowOpenID,
                seq: try u64(cv["seq"]),
                effect: try u64(cv["effect"]),
                payloadID: hexToBytes(try XCTUnwrap(cv["payload_id_hex"] as? String)),
                prev: hexToBytes(try XCTUnwrap(cv["prev_hex"] as? String)))
        }
    }

    // 1. FlowOpen body/head/id byte-parity, plus the minimal FlowOpen and empty-vs-populated approvals.
    func testFlowOpenByteParity() throws {
        let c = try Self.loadVector()
        let fo = try XCTUnwrap(c["flow_open"] as? [String: Any])
        let open = try Self.openA(c)
        XCTAssertEqual(Self.toHex(try open.bytes()), fo["body_hex"] as? String, "flow-open body == oracle")
        XCTAssertEqual(Self.toHex(try open.head()), fo["head_hex"] as? String, "flow-open head == oracle")
        XCTAssertEqual(Self.toHex(try open.id()), fo["id_hex"] as? String, "flow-open id == oracle")

        let m = try XCTUnwrap(c["minimal"] as? [String: Any])
        let minimal = Continuation.FlowOpen(
            flowID: Self.hexToBytes(try XCTUnwrap(m["flow_id_hex"] as? String)),
            effectCeiling: try Self.u64(m["effect_ceiling"]),
            approvals: (m["approvals_hex"] as? [String] ?? []).map { Self.hexToBytes($0) })
        XCTAssertEqual(Self.toHex(try minimal.bytes()), m["body_hex"] as? String, "minimal flow-open body == oracle")
        XCTAssertEqual(Self.toHex(try minimal.id()), m["id_hex"] as? String, "minimal flow-open id == oracle")

        let ev = try XCTUnwrap(c["empty_vs_nonempty"] as? [String: Any])
        let emptyV = try XCTUnwrap(ev["empty_approvals"] as? [String: Any])
        let oneV = try XCTUnwrap(ev["one_approval"] as? [String: Any])
        let empty = Continuation.FlowOpen(flowID: open.flowID, effectCeiling: open.effectCeiling, approvals: [])
        XCTAssertEqual(Self.toHex(try empty.bytes()), emptyV["body_hex"] as? String, "empty-approvals body == oracle")
        XCTAssertEqual(Self.toHex(try empty.id()), emptyV["id_hex"] as? String, "empty-approvals id == oracle")
        XCTAssertEqual(Self.toHex(try open.id()), oneV["id_hex"] as? String, "one-approval id == oracle")
        XCTAssertNotEqual(Self.toHex(try empty.id()), Self.toHex(try open.id()), "empty vs populated approvals differ by id")
    }

    // 2. THE chain byte-parity: each Continuation link body/head equals the oracle, and verifyChain over
    //    the whole ordered sequence returns the oracle's final head.
    func testContinuationChainByteParity() throws {
        let c = try Self.loadVector()
        let open = try Self.openA(c)
        let ls = try Self.links(c, try open.id())
        let arr = try XCTUnwrap(c["continuations"] as? [[String: Any]])
        for (i, link) in ls.enumerated() {
            XCTAssertEqual(Self.toHex(try link.bytes()), arr[i]["body_hex"] as? String, "continuation \(i) body == oracle")
            XCTAssertEqual(Self.toHex(try link.head()), arr[i]["head_hex"] as? String, "continuation \(i) head == oracle")
        }
        let finalHead = try Continuation.verifyChain(open, ls)
        XCTAssertEqual(Self.toHex(finalHead), c["final_head_hex"] as? String, "whole-chain final head == oracle")
    }

    // 3. AboveCeiling + the load-bearing mutation target: a continuation whose effect exceeds the
    //    FlowOpen ceiling is refused AboveCeiling (and its body/head still equal the oracle).
    func testAboveCeilingRefused() throws {
        let c = try Self.loadVector()
        let open = try Self.openA(c)
        let ac = try XCTUnwrap(c["above_ceiling"] as? [String: Any])
        let link = Continuation.Link(
            flowOpenID: try open.id(),
            seq: try Self.u64(ac["seq"]),
            effect: try Self.u64(ac["effect"]),
            payloadID: Self.hexToBytes(try XCTUnwrap(ac["payload_id_hex"] as? String)),
            prev: Self.hexToBytes(try XCTUnwrap(ac["prev_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try link.bytes()), ac["body_hex"] as? String, "above-ceiling body == oracle")
        XCTAssertEqual(Self.toHex(try link.head()), ac["head_hex"] as? String, "above-ceiling head == oracle")
        XCTAssertThrowsError(
            try Continuation.verifyContinuation(link, flowOpenID: try open.id(),
                                                prevHead: link.prev, expectedSeq: link.seq,
                                                ceiling: try Self.u64(ac["ceiling"])),
            "above-ceiling continuation must be refused") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "AboveCeiling", "above-ceiling continuation refused AboveCeiling")
        }
    }

    // 4. Checkpoint confirms a contiguous prefix (body == oracle; the prefix verifies).
    func testCheckpointVerifiesPrefix() throws {
        let c = try Self.loadVector()
        let open = try Self.openA(c)
        let ls = try Self.links(c, try open.id())
        let cp = try XCTUnwrap(c["checkpoint"] as? [String: Any])
        let checkpoint = Continuation.Checkpoint(
            flowOpenID: try open.id(),
            throughSeq: try Self.u64(cp["through_seq"]),
            head: Self.hexToBytes(try XCTUnwrap(cp["head_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try checkpoint.bytes()), cp["body_hex"] as? String, "checkpoint body == oracle")
        // through_seq 1 confirms the prefix seq 0..1 (2 links).
        XCTAssertNoThrow(try Continuation.verifyCheckpoint(checkpoint, open, Array(ls[0...1])), "contiguous prefix verifies")
    }

    // 5. GapDetected: a non-contiguous prefix (seq0, seq2 — seq1 dropped) fails the checkpoint.
    func testGapDetected() throws {
        let c = try Self.loadVector()
        let open = try Self.openA(c)
        let ls = try Self.links(c, try open.id())
        let gap = try XCTUnwrap(c["gap"] as? [String: Any])
        let checkpoint = Continuation.Checkpoint(
            flowOpenID: try open.id(),
            throughSeq: try Self.u64(gap["through_seq"]),
            head: Self.hexToBytes(try XCTUnwrap(gap["claimed_head_hex"] as? String)))
        let noncontiguous = [ls[0], ls[2]] // seq1 dropped
        XCTAssertThrowsError(try Continuation.verifyCheckpoint(checkpoint, open, noncontiguous), "gap must be detected") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "GapDetected", "dropped link detected GapDetected")
        }
    }

    // 6. WrongFlow: a continuation carrying FlowOpen A's id/prev verified under FlowOpen B is refused.
    func testReplayWrongFlow() throws {
        let c = try Self.loadVector()
        let openA = try Self.openA(c)
        let rep = try XCTUnwrap(c["replay"] as? [String: Any])
        // reconstruct FlowOpen B from its body bytes.
        let openB = try Continuation.parseFlowOpen(Self.hexToBytes(try XCTUnwrap(rep["flow_open_b_body_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try openB.head()), rep["flow_open_b_head_hex"] as? String, "flow-open B head == oracle")
        XCTAssertEqual(Self.toHex(try openB.id()), rep["flow_open_b_id_hex"] as? String, "flow-open B id == oracle")
        let link0 = try Self.links(c, try openA.id())[0] // carries A's id and prev = head(A)
        XCTAssertThrowsError(
            try Continuation.verifyContinuation(link0, flowOpenID: try openB.id(),
                                                prevHead: try openB.head(), expectedSeq: 0,
                                                ceiling: openB.effectCeiling),
            "A's link under B must be refused") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "WrongFlow", "link replayed under a different FlowOpen -> WrongFlow")
        }
    }

    // 7. RangeError: an out-of-lattice (4) ceiling or continuation effect is rejected on decode, never
    //    normalized to destructive.
    func testRangeRejectOnDecode() throws {
        let c = try Self.loadVector()
        let rr = try XCTUnwrap(c["range_reject"] as? [String: Any])
        XCTAssertThrowsError(try Continuation.parseFlowOpen(Self.hexToBytes(try XCTUnwrap(rr["flow_open_ceiling_body_hex"] as? String))), "ceiling 4") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "RangeError", "out-of-lattice ceiling -> RangeError")
        }
        XCTAssertThrowsError(try Continuation.parseContinuation(Self.hexToBytes(try XCTUnwrap(rr["continuation_effect_body_hex"] as? String))), "effect 4") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "RangeError", "out-of-lattice effect -> RangeError")
        }
    }

    // 8. checkpoint_overflow (>=2^63 decode path): through_seq = u64::MAX decodes byte-exact through
    //    ParseCheckpoint, and VerifyCheckpoint refuses it GapDetected (no MAX+1 contiguous links).
    func testCheckpointOverflowDecodeGraded() throws {
        let c = try Self.loadVector()
        let open = try Self.openA(c)
        let co = try XCTUnwrap(c["checkpoint_overflow"] as? [String: Any])
        let cp = try Continuation.parseCheckpoint(Self.hexToBytes(try XCTUnwrap(co["body_hex"] as? String)))
        XCTAssertEqual(cp.throughSeq, UInt64.max, "u64::MAX through_seq decodes byte-exact")
        XCTAssertEqual(String(cp.throughSeq), co["through_seq_str"] as? String, "decoded through_seq == oracle string")
        XCTAssertThrowsError(try Continuation.verifyCheckpoint(cp, open, []), "MAX+1 links impossible") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "GapDetected", "u64::MAX checkpoint refused GapDetected")
        }
    }

    // 9. big_seq (<2^63) full round-trip: seq 0x0102030405060708 rides byte-exact through the link body
    //    (uint64 all the way, no float64 corruption) and re-decodes to the same value.
    func testBigSeqRoundTrip() throws {
        let c = try Self.loadVector()
        let open = try Self.openA(c)
        let bs = try XCTUnwrap(c["big_seq"] as? [String: Any])
        let seq = try XCTUnwrap(UInt64(try XCTUnwrap(bs["seq_str"] as? String)))
        XCTAssertGreaterThan(seq, UInt64(1) << 53, "oracle big seq is > 2^53")
        let link = Continuation.Link(
            flowOpenID: try open.id(), seq: seq, effect: try Self.u64(bs["effect"]),
            payloadID: Self.hexToBytes(try XCTUnwrap(bs["payload_id_hex"] as? String)),
            prev: Self.hexToBytes(try XCTUnwrap(bs["prev_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try link.bytes()), bs["body_hex"] as? String, "big-seq body == oracle")
        XCTAssertEqual(Self.toHex(try link.head()), bs["head_hex"] as? String, "big-seq head == oracle")
        let recovered = try Continuation.parseContinuation(try link.bytes())
        XCTAssertEqual(recovered.seq, seq, "big seq round-trips byte-exact (>2^53 not corrupted)")
    }

    // 10. FlowCommit body + the descending-key NonCanonical rejection + the 2-field look-alike.
    func testFlowCommitAndWireEdges() throws {
        let c = try Self.loadVector()
        let open = try Self.openA(c)
        let fc = try XCTUnwrap(c["flow_commit"] as? [String: Any])
        let commit = Continuation.FlowCommit(
            flowOpenID: try open.id(),
            finalHead: Self.hexToBytes(try XCTUnwrap(fc["final_head_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try commit.bytes()), fc["body_hex"] as? String, "flow-commit body == oracle")

        let koo = try XCTUnwrap(c["keys_out_of_order"] as? [String: Any])
        XCTAssertNoThrow(try Cbor.decode(Self.hexToBytes(try XCTUnwrap(koo["canonical_commit_body_hex"] as? String))), "canonical commit decodes")
        XCTAssertThrowsError(try Cbor.decode(Self.hexToBytes(try XCTUnwrap(koo["noncanonical_commit_body_hex"] as? String))), "descending keys") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NonCanonical", "descending-key body rejected NonCanonical")
        }

        let la = try XCTUnwrap(c["look_alike"] as? [String: Any])
        XCTAssertThrowsError(try Continuation.parseCheckpoint(Self.hexToBytes(try XCTUnwrap(la["flow_commit_body_hex"] as? String))), "2-field commit as checkpoint") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ContMalformed", "2-field FlowCommit is not a 3-field Checkpoint")
        }
    }

    // 11. ED25519-DEMONSTRATED (isolation): the FlowOpen and FlowCommit full signatures. The one full
    //     signature opens the flow (verify + reconstruct the authority from the bytes alone); a foreign
    //     key is rejected; the FlowCommit binds the recomputed chain head (CommitMismatch on a wrong head).
    func testEd25519FullSignatureDemo() throws {
        let c = try Self.loadVector()
        let open = try Self.openA(c)
        let ls = try Self.links(c, try open.id())
        let seed = [UInt8](repeating: 0x33, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)

        let openObj = try Continuation.signFlowOpen(open, seed)
        let reopened = try Continuation.verifyFlowOpen(openObj, pk)
        XCTAssertEqual(Self.toHex(try reopened.bytes()), Self.toHex(try open.bytes()), "FlowOpen reconstructed from its signed bytes alone")
        let foreignPk = try Cose.ed25519PublicKey([UInt8](repeating: 0x44, count: 32))
        XCTAssertThrowsError(try Continuation.verifyFlowOpen(openObj, foreignPk), "foreign-key FlowOpen") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "BadSignature", "foreign-key signed FlowOpen rejected")
        }

        let finalHead = try Continuation.verifyChain(open, ls)
        let commit = Continuation.FlowCommit(flowOpenID: try open.id(), finalHead: finalHead)
        let commitObj = try Continuation.signFlowCommit(commit, seed)
        XCTAssertNoThrow(try Continuation.verifyFlowCommit(commitObj, pk, open, ls), "flow commit binds the recomputed chain head")

        // CommitMismatch: a commit claiming the wrong final head (the checkpoint head) fails.
        let cp = try XCTUnwrap(c["checkpoint"] as? [String: Any])
        let wrong = Continuation.FlowCommit(flowOpenID: try open.id(),
                                            finalHead: Self.hexToBytes(try XCTUnwrap(cp["head_hex"] as? String)))
        let wrongObj = try Continuation.signFlowCommit(wrong, seed)
        XCTAssertThrowsError(try Continuation.verifyFlowCommit(wrongObj, pk, open, ls), "wrong final head") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "CommitMismatch", "flow commit final_head != recomputed chain -> CommitMismatch")
        }
    }
}
