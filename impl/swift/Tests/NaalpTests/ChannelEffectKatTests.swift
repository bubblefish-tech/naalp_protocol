// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Known-answer test for the twenty-channel effect-classification table (design-channels.md §1..§20,
// effect vocabulary §6). The expected effect for every one of the 65 baseline kinds is transcribed
// from the design authority (read_only=0, idempotent_write=1, non_idempotent_write=2, destructive=3),
// independently of the Channels registry it grades. It exercises Channels.checkEffect — which had NO
// test callers, so any effect-declaration mutation was invisible to `swift test` — on the accept path
// (the declared effect passes), the reject path (any other effect is refused EffectDeclarationMismatch),
// and the two variable-effect kinds (StreamOpen, Carriage) which accept 0..3 and reject out-of-range.
// A mutation of any kind's declared effect in Channels.swift flips this test red.
//
// Run:  swift test --package-path impl/swift --filter ChannelEffectKatTests

import Foundation
import XCTest
@testable import Naalp

final class ChannelEffectKatTests: XCTestCase {

    // Effect vocabulary (design-channels.md §6), sourced from the SPEC — not the impl under test.
    static let RO = 0, IW = 1, NIW = 2, DE = 3

    // (channel, kind, name, expected effect) for every FIXED-effect baseline kind.
    static let fixed: [(ch: Int, kind: Int, name: String, effect: Int)] = [
        // 0x0000 Control
        (0x0000, 0, "Hello", RO), (0x0000, 1, "Bye", IW), (0x0000, 2, "Ack", RO), (0x0000, 3, "Error", RO),
        // 0x0001 Memory
        (0x0001, 0, "MemoryOffer", IW), (0x0001, 1, "MemoryAccept", IW), (0x0001, 2, "MemoryWrite", NIW),
        (0x0001, 3, "MemoryRead", RO), (0x0001, 4, "MemoryExpire", DE), (0x0001, 5, "MemoryRevoke", DE),
        // 0x0002 Capability
        (0x0002, 0, "CapIssue", NIW), (0x0002, 1, "CapDelegate", NIW), (0x0002, 2, "CapRevoke", DE), (0x0002, 3, "CapLookup", RO),
        // 0x0003 Identity
        (0x0003, 0, "Rotation", NIW), (0x0003, 1, "Revocation", DE), (0x0003, 2, "ForeignLink", IW), (0x0003, 3, "KeyAnnounce", RO),
        // 0x0004 Governance
        (0x0004, 0, "PolicyPublish", NIW), (0x0004, 1, "Approval", NIW), (0x0004, 2, "ApprovalHeld", RO), (0x0004, 3, "Consume", NIW),
        // 0x0005 Immune
        (0x0005, 0, "AnomalyReport", RO), (0x0005, 1, "Quarantine", DE), (0x0005, 2, "QuarantineLift", NIW),
        // 0x0006 Federation
        (0x0006, 0, "AuthorityAnnounce", RO), (0x0006, 1, "ScopeReceipt", NIW),
        // 0x0007 Settlement
        (0x0007, 0, "SettleIntent", NIW), (0x0007, 1, "SettleReceipt", NIW), (0x0007, 2, "SettleReject", IW),
        // 0x0008 Compliance
        (0x0008, 0, "ComplianceRecord", NIW), (0x0008, 1, "ComplianceQuery", RO), (0x0008, 2, "ComplianceReport", RO),
        // 0x0009 Sensory
        (0x0009, 0, "Observation", RO), (0x0009, 1, "Subscribe", IW), (0x0009, 2, "Unsubscribe", IW),
        // 0x000A Telemetry
        (0x000A, 0, "Metric", RO), (0x000A, 1, "HealthReport", RO),
        // 0x000B Audit
        (0x000B, 0, "Receipt", NIW), (0x000B, 1, "AuditQuery", RO), (0x000B, 2, "ForkProof", RO),
        // 0x000C Stream (StreamOpen at kind 0 is variable — see `variable` below)
        (0x000C, 1, "StreamCommit", RO), (0x000C, 2, "StreamCheckpoint", RO),
        // 0x000E Commerce
        (0x000E, 0, "Offer", RO), (0x000E, 1, "Order", NIW), (0x000E, 2, "Fulfil", NIW), (0x000E, 3, "Cancel", DE),
        // 0x000F Interaction
        (0x000F, 0, "Elicit", RO), (0x000F, 1, "Respond", IW), (0x000F, 2, "Confirm", NIW),
        // 0x0010 Discovery
        (0x0010, 0, "DiscoveryRecord", RO), (0x0010, 1, "DiscoveryQuery", RO),
        // 0x0011 Workflow
        (0x0011, 0, "TaskCreate", NIW), (0x0011, 1, "TaskInput", NIW), (0x0011, 2, "TaskCancel", DE), (0x0011, 3, "TaskResult", NIW),
        // 0x0012 Knowledge
        (0x0012, 0, "Assert", NIW), (0x0012, 1, "Retract", DE), (0x0012, 2, "KnowledgeQuery", RO),
        // 0x0013 Spatial
        (0x0013, 0, "FrameDefine", IW), (0x0013, 1, "Pose", RO), (0x0013, 2, "StateUpdate", RO), (0x0013, 3, "SnapshotQuery", RO),
    ]

    // The two variable-effect kinds (design-channels.md §12 Stream StreamOpen, §13 Bridge Carriage).
    static let variable: [(ch: Int, kind: Int, name: String)] = [
        (0x000C, 0, "StreamOpen"),
        (0x000D, 0, "Carriage"),
    ]

    func testChannelEffectClassificationKAT() throws {
        // Guard against a silently-truncated table: 65 baseline kinds = 63 fixed + 2 variable.
        XCTAssertEqual(Self.fixed.count, 63, "fixed-effect kind count")
        XCTAssertEqual(Self.variable.count, 2, "variable-effect kind count")

        for t in Self.fixed {
            let at = "0x\(String(format: "%04x", t.ch))/\(t.kind) \(t.name)"
            // The registry's declared effect must equal the spec authority's effect.
            let got = try Channels.lookup(t.ch, t.kind)
            XCTAssertEqual(got.name, t.name, "\(at): kind name")
            XCTAssertEqual(got.effect, t.effect, "\(at): declared effect")
            XCTAssertFalse(got.variable, "\(at): must be fixed-effect")

            // checkEffect accepts the declared effect ...
            XCTAssertNoThrow(try Channels.checkEffect(t.ch, t.kind, t.effect),
                             "\(at): checkEffect must accept the declared effect")
            // ... and refuses any other effect with EffectDeclarationMismatch.
            let wrong = (t.effect + 1) % 4
            XCTAssertThrowsError(try Channels.checkEffect(t.ch, t.kind, wrong),
                                 "\(at): checkEffect must reject effect \(wrong)") { err in
                XCTAssertEqual((err as? NaalpError)?.kind, "EffectDeclarationMismatch", "\(at): reject error kind")
            }
        }

        for v in Self.variable {
            let at = "0x\(String(format: "%04x", v.ch))/\(v.kind) \(v.name)"
            let got = try Channels.lookup(v.ch, v.kind)
            XCTAssertEqual(got.name, v.name, "\(at): kind name")
            XCTAssertTrue(got.variable, "\(at): must be variable-effect")
            // A variable-effect kind accepts every declared effect 0..3 ...
            for e in 0...3 {
                XCTAssertNoThrow(try Channels.checkEffect(v.ch, v.kind, e),
                                 "\(at): variable kind must accept effect \(e)")
            }
            // ... and rejects an out-of-range effect with EffectDeclarationMismatch.
            XCTAssertThrowsError(try Channels.checkEffect(v.ch, v.kind, 4),
                                 "\(at): variable kind must reject out-of-range effect 4") { err in
                XCTAssertEqual((err as? NaalpError)?.kind, "EffectDeclarationMismatch", "\(at): reject error kind")
            }
        }
    }
}
