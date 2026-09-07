// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// VerifyReconcileOrderTests exercises the verify-event choke point of the Reconcile state machine
// (draft "## Reconcile state machine"): an independent recomputation agrees with the record
// (verified), disagrees on a causally-valid but non-deterministic order (ReconcileMismatch), rejects
// a wrong-length claim (ReconcileMismatch), or rejects a node set that is not a valid partial order
// (CausalViolation). The mutation that neuters the order comparison flips the mismatch cases.
//
// Mirrors impl/go/federation/verify_reconcile_test.go's TestVerifyReconcileOrder and
// impl/rust/src/federation.rs's test_verify_reconcile_order.

import XCTest
@testable import Naalp

final class VerifyReconcileOrderTests: XCTestCase {

    // Two causally-INDEPENDENT objects (no cause between them). reconcile orders concurrent objects
    // by content id bytewise-ascending, so idA < idB => the one deterministic order is [idA, idB].
    static let idA: [UInt8] = [0x01]
    static let idB: [UInt8] = [0x02]
    static var concurrent: [Federation.CausalNode] {
        [Federation.CausalNode(id: idA, causes: []), Federation.CausalNode(id: idB, causes: [])]
    }

    // verify agrees: the claimed order IS the deterministic order -> verified (no throw).
    func testVerifyReconcileOrderAgrees() throws {
        let rec = Federation.ReconcileRecord(authorities: ["auth-1"], order: [Self.idA, Self.idB])
        XCTAssertNoThrow(try Federation.verifyReconcileOrder(rec, Self.concurrent),
                         "agreeing record rejected")
    }

    // verify ReconcileMismatch: a causally-VALID-but-different order (the two objects are concurrent,
    // so [idB, idA] is causally valid) is not the deterministic order -> ReconcileMismatch.
    func testVerifyReconcileOrderMismatch() throws {
        let rec = Federation.ReconcileRecord(authorities: ["auth-1"], order: [Self.idB, Self.idA])
        XCTAssertThrowsError(try Federation.verifyReconcileOrder(rec, Self.concurrent)) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "ReconcileMismatch",
                           "a record claiming a non-deterministic order was accepted")
        }
    }

    // verify wrong-length claim -> ReconcileMismatch (a claim that drops or adds an element).
    func testVerifyReconcileOrderMismatchLength() throws {
        let rec = Federation.ReconcileRecord(authorities: ["auth-1"], order: [Self.idA])
        XCTAssertThrowsError(try Federation.verifyReconcileOrder(rec, Self.concurrent)) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "ReconcileMismatch",
                           "a wrong-length claim was accepted")
        }
    }

    // CausalViolation: a cyclic node set is not a valid partial order; the recomputation rejects it
    // before any order comparison, so the record is rejected under the graph fault, fail-closed.
    func testVerifyReconcileOrderCausalViolation() throws {
        let idC: [UInt8] = [0x03]
        let idD: [UInt8] = [0x04]
        let cyclic = [Federation.CausalNode(id: idC, causes: [idD]),
                      Federation.CausalNode(id: idD, causes: [idC])]
        let rec = Federation.ReconcileRecord(authorities: ["auth-1"], order: [idC, idD])
        XCTAssertThrowsError(try Federation.verifyReconcileOrder(rec, cyclic)) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "CausalViolation",
                           "a cyclic graph was accepted")
        }
    }
}
