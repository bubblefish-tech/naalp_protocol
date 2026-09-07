// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Non-circular known-answer test for the STEP-2 channels-cluster additions (task #174): the
// channel state-machine surface (design-channels.md §1..§20) — Channel/ChannelSpec lookup and
// AllowedTransition — graded against the independent per-channel oracle
// vectors/channels/<dir>/cases.json (Go == Rust == Swift == oracle), Spatial's TransformCycle
// structural check (design-channels.md §20), and the Workflow durable input/approval gate whose
// crash test proves InputGateBypass cannot occur (design-channels.md §18). Values come from the
// committed independent oracle, NEVER recomputed by this code (F3).
//
// Run:  swift test --package-path impl/swift --filter ChannelsKat

import Foundation
import XCTest
@testable import Naalp

final class ChannelsKatTests: XCTestCase {

    // ---- vector loading (mirrors ApprovalKatTests) -------------------------------------------------

    static func findVector(_ relPath: String) -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent(relPath)
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    static func tempGatePath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("naalp-channels-kat-\(UUID().uuidString).wal").path
    }

    private func str(_ d: [String: Any], _ k: String) -> String { d[k] as? String ?? "" }
    private func u64(_ d: [String: Any], _ k: String) -> UInt64 { (d[k] as? NSNumber)?.uint64Value ?? 0 }
    private func arr(_ d: [String: Any], _ k: String) -> [[String: Any]] { d[k] as? [[String: Any]] ?? [] }

    // All twenty baseline channel directory names (design-channels.md §1..§20), lowercased channel
    // names — mirrors Go's channels_test.go loader (strings.ToLower(ch.Name)).
    static let channelDirs: [(id: Int, name: String, dir: String)] = [
        (0x0000, "Control", "control"), (0x0001, "Memory", "memory"), (0x0002, "Capability", "capability"),
        (0x0003, "Identity", "identity"), (0x0004, "Governance", "governance"), (0x0005, "Immune", "immune"),
        (0x0006, "Federation", "federation"), (0x0007, "Settlement", "settlement"), (0x0008, "Compliance", "compliance"),
        (0x0009, "Sensory", "sensory"), (0x000A, "Telemetry", "telemetry"), (0x000B, "Audit", "audit"),
        (0x000C, "Stream", "stream"), (0x000D, "Bridge", "bridge"), (0x000E, "Commerce", "commerce"),
        (0x000F, "Interaction", "interaction"), (0x0010, "Discovery", "discovery"), (0x0011, "Workflow", "workflow"),
        (0x0012, "Knowledge", "knowledge"), (0x0013, "Spatial", "spatial"),
    ]

    private func channelVec(_ dir: String) throws -> [String: Any] {
        guard let v = Self.findVector("vectors/channels/\(dir)/cases.json") else {
            throw XCTSkip("committed vectors/channels/\(dir) vector not present (standalone build)")
        }
        return v
    }

    // 1. the frozen impl registry's id/name/kinds/states/transitions/errors equal the independent
    //    per-channel oracle, for all twenty channels (Go == Rust == Swift == oracle).
    func testTableMatchesOracle() throws {
        for c in Self.channelDirs {
            let v = try channelVec(c.dir)
            guard let spec = Channels.channel(c.id) else {
                XCTFail("\(c.name): channel \(c.id) not registered"); continue
            }
            XCTAssertEqual(u64(v, "channel_id"), UInt64(c.id), "\(c.name): channel id")
            XCTAssertEqual(str(v, "name"), spec.name, "\(c.name): name")

            let vKinds = arr(v, "kinds")
            XCTAssertEqual(vKinds.count, spec.kinds.count, "\(c.name): kind count")
            for (i, k) in spec.kinds.enumerated() where i < vKinds.count {
                XCTAssertEqual(u64(vKinds[i], "code"), UInt64(k.code), "\(c.name) kind \(i): code")
                XCTAssertEqual(str(vKinds[i], "name"), k.name, "\(c.name) kind \(i): name")
                XCTAssertEqual(u64(vKinds[i], "effect"), UInt64(k.effect), "\(c.name) kind \(i): effect")
                XCTAssertEqual((vKinds[i]["variable"] as? Bool) ?? false, k.variable, "\(c.name) kind \(i): variable")
            }

            let vStates = (v["states"] as? [String]) ?? []
            XCTAssertEqual(vStates, spec.states, "\(c.name): states")

            let vTransitions = arr(v, "transitions")
            XCTAssertEqual(vTransitions.count, spec.transitions.count, "\(c.name): transition count")
            for (i, t) in spec.transitions.enumerated() where i < vTransitions.count {
                XCTAssertEqual(str(vTransitions[i], "from"), t.from, "\(c.name) transition \(i): from")
                XCTAssertEqual(str(vTransitions[i], "to"), t.to, "\(c.name) transition \(i): to")
            }

            let vErrors = (v["errors"] as? [String]) ?? []
            XCTAssertEqual(vErrors, spec.errors, "\(c.name): errors")
        }
    }

    // 2. AllowedTransition: every transition the oracle declares for a channel is allowed, and every
    //    OTHER ordered pair among that channel's declared states is denied — exhaustive per channel,
    //    over all twenty channels. An unregistered channel id permits nothing.
    func testAllowedTransitionKAT() throws {
        for c in Self.channelDirs {
            let v = try channelVec(c.dir)
            let vStates = (v["states"] as? [String]) ?? []
            let vTransitions = Set(arr(v, "transitions").map { "\(str($0, "from"))->\(str($0, "to"))" })
            for from in vStates {
                for to in vStates {
                    let want = vTransitions.contains("\(from)->\(to)")
                    let got = Channels.allowedTransition(c.id, from, to)
                    XCTAssertEqual(got, want, "\(c.name) \(from)->\(to): allowed=\(got) want \(want)")
                }
            }
        }
        XCTAssertFalse(Channels.allowedTransition(0xFFFF, "a", "b"), "unregistered channel must deny every transition")
    }

    // 3. Spatial's TransformCycle (design-channels.md §20): a valid acyclic frame tree is accepted; a
    //    cyclic one is rejected fail-closed. (Structural — not vector-graded in the Go reference either;
    //    channels_test.go's TestTransformCycle uses the same synthetic trees.)
    func testCheckFrameTreeAcceptsTreeRejectsCycle() throws {
        XCTAssertNoThrow(try Channels.checkFrameTree(["base": "", "arm": "base", "hand": "arm"]),
                          "valid frame tree rejected")
        XCTAssertThrowsError(try Channels.checkFrameTree(["a": "b", "b": "c", "c": "a"]),
                             "cyclic frame tree accepted") { err in
            XCTAssertEqual((err as? NaalpError)?.kind, "TransformCycle")
        }
        // A larger, deeper acyclic tree with a shared ancestor must also pass.
        XCTAssertNoThrow(try Channels.checkFrameTree([
            "world": "", "base": "world", "arm": "base", "hand": "arm", "finger": "hand", "camera": "world",
        ]), "valid multi-branch frame tree rejected")
    }

    // 4. THE RED-EVIDENCE MUTATION ANCHOR: the gated crash test (design-channels.md §18) — a task
    //    cannot reach "running" without passing the input/approval gate, and a crash (close -> reopen)
    //    recovers to the pre-gate status rather than bypassing it. Neutering the input-gate check in
    //    WorkflowGate.run so a pre-gate status also falls into the "running" branch is the mutation
    //    this test is designed to catch.
    func testWorkflowInputGateBypass() throws {
        let path = Self.tempGatePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let g = try Channels.openWorkflowGate(path)
        try g.create("t1", false)

        // Running before input is InputGateBypass.
        XCTAssertThrowsError(try g.run("t1"), "task ran before its input gate") { err in
            XCTAssertEqual((err as? NaalpError)?.kind, "InputGateBypass")
        }

        // Simulate a crash right after create: close() flushes and closes the WAL, then reopening
        // recovers the pre-gate durable status rather than bypassing it.
        try g.close()
        let g2 = try Channels.openWorkflowGate(path)
        defer { try? g2.close() }
        XCTAssertEqual(g2.status("t1"), "awaiting-input", "crash bypassed the gate")
        XCTAssertThrowsError(try g2.run("t1"), "task ran after crash without passing the gate") { err in
            XCTAssertEqual((err as? NaalpError)?.kind, "InputGateBypass")
        }

        // Supplying input opens the gate; only then may it run.
        try g2.supplyInput("t1")
        try g2.run("t1")
        XCTAssertEqual(g2.status("t1"), "running")
    }

    // 5. Every other WorkflowGate transition is fail-closed TaskStateError: a duplicate Create, and
    //    SupplyInput/Run on an unknown task. The approval-gated path (Create needsApproval=true) moves
    //    awaiting-approval -> approved on SupplyInput, then Run succeeds.
    func testWorkflowGateTaskStateErrorsAndApprovalPath() throws {
        let path = Self.tempGatePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let g = try Channels.openWorkflowGate(path)
        defer { try? g.close() }

        try g.create("t1", true)
        XCTAssertThrowsError(try g.create("t1", true), "duplicate create accepted") { err in
            XCTAssertEqual((err as? NaalpError)?.kind, "TaskStateError")
        }
        XCTAssertThrowsError(try g.supplyInput("unknown"), "supplyInput on unknown task accepted") { err in
            XCTAssertEqual((err as? NaalpError)?.kind, "TaskStateError")
        }
        XCTAssertThrowsError(try g.run("unknown"), "run on unknown task accepted") { err in
            XCTAssertEqual((err as? NaalpError)?.kind, "TaskStateError")
        }

        try g.supplyInput("t1")
        XCTAssertEqual(g.status("t1"), "approved")
        try g.run("t1")
        XCTAssertEqual(g.status("t1"), "running")
    }
}
