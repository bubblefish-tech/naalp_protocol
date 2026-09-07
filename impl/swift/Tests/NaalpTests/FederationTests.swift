// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Federation higher-tier conformance for the Swift SDK (design.md §8.4; design-channels.md §7;
// R-8.6), graded against the shared independent corpus vectors/federation/cases.json (NOT produced
// by this code). Reconcile is the deterministic linearization of the union causal DAG, tie-broken
// among causally-concurrent objects by content id (bytewise ascending): it MUST equal the oracle
// order, be causally valid, and beat the naive content-id sort (which is NOT causally valid here).
// The tier-1 Reconcile record MUST encode to the oracle bytes, and reconcile MUST be
// scope-independent (R-8.6).
//
// CORPUS-GRADED (pure): reconcile order, causal validity, naive-sort baseline, record bytes, scope
// independence, cycle rejection.
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the tier-1 authority's signature over the
// record. Swift is PURE-ONLY for ML-DSA (SwiftDilithium 3.6.0 has no deterministic-from-seed FIPS
// 204 path), so the reference's ML-DSA Reconcile signature is demonstrated here with a real Ed25519
// (RFC 8032) sign/verify round-trip via swift-crypto, exactly as WorkedExampleTests demonstrates
// the object signature surface.
//
// Written test-first: Naalp.Federation is absent until Federation.swift lands, so this fails RED
// with a compile error; a mutation that inverts the causal-graph tie-break flips
// "reconcile order == oracle".
//
// Run:  swift test --filter FederationTests

import XCTest
@testable import Naalp

final class FederationTests: XCTestCase {

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

    /// Walk up from this source file to find the committed corpus (mirrors WorkedExampleTests).
    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/federation/cases.json")
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
            throw XCTSkip("vectors/federation/cases.json not present (standalone build)")
        }
        return v
    }

    /// Build the corpus nodes as Federation.CausalNode[] (binary ids/causes).
    static func corpusNodes(_ c: [String: Any]) throws -> [Federation.CausalNode] {
        let raw = try XCTUnwrap(c["nodes"] as? [[String: Any]])
        return try raw.map { n in
            let id = hexToBytes(try XCTUnwrap(n["id_hex"] as? String))
            let causes = (try XCTUnwrap(n["causes_hex"] as? [String])).map { hexToBytes($0) }
            return Federation.CausalNode(id: id, causes: causes)
        }
    }

    // 1. reconcile == the independent oracle order (the load-bearing property; the mutation target).
    func testReconcileOrderMatchesOracle() throws {
        let c = try Self.loadVector()
        let nodes = try Self.corpusNodes(c)
        let order = try Federation.reconcile(nodes)
        XCTAssertEqual(order.map { Self.toHex($0) }, c["reconcile_order_hex"] as? [String],
                       "reconcile order == oracle")
    }

    // 2. the reconcile order is causally valid (every present cause precedes its effect).
    func testReconcileOrderCausallyValid() throws {
        let c = try Self.loadVector()
        let nodes = try Self.corpusNodes(c)
        let order = try Federation.reconcile(nodes)
        XCTAssertEqual(Federation.causallyValid(order, nodes),
                       c["reconcile_order_causally_valid"] as? Bool,
                       "reconcile order causally valid == oracle")
    }

    // 3. the naive content-id sort's causal validity matches the oracle — here it is NOT valid, so
    //    it is the mutation baseline: a reconcile that degrades to the naive sort would be caught.
    func testNaiveSortCausalValidityMatchesOracle() throws {
        let c = try Self.loadVector()
        let nodes = try Self.corpusNodes(c)
        let naive = (try XCTUnwrap(c["naive_content_id_sort_hex"] as? [String])).map { Self.hexToBytes($0) }
        XCTAssertEqual(Federation.causallyValid(naive, nodes),
                       c["naive_causally_valid"] as? Bool,
                       "naive content-id sort causally valid == oracle")
    }

    // 4. the tier-1 Reconcile record encodes to the oracle bytes {1:[authorities], 2:[order]}.
    func testReconcileRecordBytesMatchOracle() throws {
        let c = try Self.loadVector()
        let nodes = try Self.corpusNodes(c)
        let order = try Federation.reconcile(nodes)
        let authorities = try XCTUnwrap(c["authorities"] as? [String])
        let rec = Federation.ReconcileRecord(authorities: authorities, order: order)
        XCTAssertEqual(Self.toHex(try rec.bytes()), c["record_hex"] as? String,
                       "reconcile record bytes == oracle")
    }

    // 5. R-8.6: reconcile depends only on the causal graph, not on input (scope) order — reversing
    //    the input reconciles identically.
    func testScopeIndependence() throws {
        let c = try Self.loadVector()
        let nodes = try Self.corpusNodes(c)
        let order = try Federation.reconcile(nodes)
        let reversed = try Federation.reconcile(nodes.reversed())
        XCTAssertEqual(reversed.map { Self.toHex($0) }, order.map { Self.toHex($0) },
                       "scope independence (reversed input)")
    }

    // 6. an out-of-lattice cycle is rejected fail-closed (CausalViolation).
    func testCycleRejected() throws {
        let a = Self.hexToBytes("2030" + String(repeating: "aa", count: 48))
        let b = Self.hexToBytes("2030" + String(repeating: "bb", count: 48))
        let cyclic = [Federation.CausalNode(id: a, causes: [b]),
                      Federation.CausalNode(id: b, causes: [a])]
        XCTAssertThrowsError(try Federation.reconcile(cyclic)) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "CausalViolation", "cycle rejected")
        }
    }

    // 7. ED25519-DEMONSTRATED (isolation): a tier-1 authority signs the Reconcile record; the raw
    //    signature verifies under its key, and a tampered record does NOT verify. This exercises the
    //    signing binding in isolation; it is NOT the corpus-graded ML-DSA surface (PURE-ONLY Swift).
    func testEd25519ReconcileSignVerify() throws {
        let c = try Self.loadVector()
        let nodes = try Self.corpusNodes(c)
        let order = try Federation.reconcile(nodes)
        let authorities = try XCTUnwrap(c["authorities"] as? [String])
        let rec = Federation.ReconcileRecord(authorities: authorities, order: order)

        let seed = [UInt8](repeating: 0x2a, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let sig = try Federation.signReconcile(rec, seed)
        XCTAssertTrue(try Federation.verifyReconcile(rec, pk, sig),
                      "ed25519 reconcile-record sign/verify")
        let tampered = Federation.ReconcileRecord(authorities: ["bauthority-z"], order: rec.order)
        XCTAssertFalse(try Federation.verifyReconcile(tampered, pk, sig),
                       "ed25519 tampered record rejected")
    }
}
