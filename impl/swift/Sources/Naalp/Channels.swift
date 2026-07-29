// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C10 channel registry for the Swift SDK — the frozen twenty-channel baseline surface
// (design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 65 kinds, each with a declared
// effect (variable-effect for Stream StreamOpen / Bridge Carriage). An independent transcription
// of the design, cross-checked against the shared conformance corpus (== Go == Rust == oracle).

import Foundation

public enum Channels {
    // read_only, idempotent_write, non_idempotent_write, destructive
    static let RO = 0, IW = 1, NIW = 2, DE = 3

    public struct Kind {
        let code: Int
        let name: String
        let effect: Int
        let variable: Bool
    }

    // channel code -> (channel name, kinds)
    static let table: [Int: (name: String, kinds: [Kind])] = [
        0x0000: ("Control", [
            Kind(code: 0, name: "Hello", effect: RO, variable: false),
            Kind(code: 1, name: "Bye", effect: IW, variable: false),
            Kind(code: 2, name: "Ack", effect: RO, variable: false),
            Kind(code: 3, name: "Error", effect: RO, variable: false),
        ]),
        0x0001: ("Memory", [
            Kind(code: 0, name: "MemoryOffer", effect: IW, variable: false),
            Kind(code: 1, name: "MemoryAccept", effect: IW, variable: false),
            Kind(code: 2, name: "MemoryWrite", effect: NIW, variable: false),
            Kind(code: 3, name: "MemoryRead", effect: RO, variable: false),
            Kind(code: 4, name: "MemoryExpire", effect: DE, variable: false),
            Kind(code: 5, name: "MemoryRevoke", effect: DE, variable: false),
        ]),
        0x0002: ("Capability", [
            Kind(code: 0, name: "CapIssue", effect: NIW, variable: false),
            Kind(code: 1, name: "CapDelegate", effect: NIW, variable: false),
            Kind(code: 2, name: "CapRevoke", effect: DE, variable: false),
            Kind(code: 3, name: "CapLookup", effect: RO, variable: false),
        ]),
        0x0003: ("Identity", [
            Kind(code: 0, name: "Rotation", effect: NIW, variable: false),
            Kind(code: 1, name: "Revocation", effect: DE, variable: false),
            Kind(code: 2, name: "ForeignLink", effect: IW, variable: false),
            Kind(code: 3, name: "KeyAnnounce", effect: RO, variable: false),
        ]),
        0x0004: ("Governance", [
            Kind(code: 0, name: "PolicyPublish", effect: NIW, variable: false),
            Kind(code: 1, name: "Approval", effect: NIW, variable: false),
            Kind(code: 2, name: "ApprovalHeld", effect: RO, variable: false),
            Kind(code: 3, name: "Consume", effect: NIW, variable: false),
        ]),
        0x0005: ("Immune", [
            Kind(code: 0, name: "AnomalyReport", effect: RO, variable: false),
            Kind(code: 1, name: "Quarantine", effect: DE, variable: false),
            Kind(code: 2, name: "QuarantineLift", effect: NIW, variable: false),
        ]),
        0x0006: ("Federation", [
            Kind(code: 0, name: "AuthorityAnnounce", effect: RO, variable: false),
            Kind(code: 1, name: "ScopeReceipt", effect: NIW, variable: false),
        ]),
        0x0007: ("Settlement", [
            Kind(code: 0, name: "SettleIntent", effect: NIW, variable: false),
            Kind(code: 1, name: "SettleReceipt", effect: NIW, variable: false),
            Kind(code: 2, name: "SettleReject", effect: IW, variable: false),
        ]),
        0x0008: ("Compliance", [
            Kind(code: 0, name: "ComplianceRecord", effect: NIW, variable: false),
            Kind(code: 1, name: "ComplianceQuery", effect: RO, variable: false),
            Kind(code: 2, name: "ComplianceReport", effect: RO, variable: false),
        ]),
        0x0009: ("Sensory", [
            Kind(code: 0, name: "Observation", effect: RO, variable: false),
            Kind(code: 1, name: "Subscribe", effect: IW, variable: false),
            Kind(code: 2, name: "Unsubscribe", effect: IW, variable: false),
        ]),
        0x000A: ("Telemetry", [
            Kind(code: 0, name: "Metric", effect: RO, variable: false),
            Kind(code: 1, name: "HealthReport", effect: RO, variable: false),
        ]),
        0x000B: ("Audit", [
            Kind(code: 0, name: "Receipt", effect: NIW, variable: false),
            Kind(code: 1, name: "AuditQuery", effect: RO, variable: false),
            Kind(code: 2, name: "ForkProof", effect: RO, variable: false),
        ]),
        0x000C: ("Stream", [
            Kind(code: 0, name: "StreamOpen", effect: RO, variable: true),
            Kind(code: 1, name: "StreamCommit", effect: RO, variable: false),
            Kind(code: 2, name: "StreamCheckpoint", effect: RO, variable: false),
        ]),
        0x000D: ("Bridge", [
            Kind(code: 0, name: "Carriage", effect: RO, variable: true),
        ]),
        0x000E: ("Commerce", [
            Kind(code: 0, name: "Offer", effect: RO, variable: false),
            Kind(code: 1, name: "Order", effect: NIW, variable: false),
            Kind(code: 2, name: "Fulfil", effect: NIW, variable: false),
            Kind(code: 3, name: "Cancel", effect: DE, variable: false),
        ]),
        0x000F: ("Interaction", [
            Kind(code: 0, name: "Elicit", effect: RO, variable: false),
            Kind(code: 1, name: "Respond", effect: IW, variable: false),
            Kind(code: 2, name: "Confirm", effect: NIW, variable: false),
        ]),
        0x0010: ("Discovery", [
            Kind(code: 0, name: "DiscoveryRecord", effect: RO, variable: false),
            Kind(code: 1, name: "DiscoveryQuery", effect: RO, variable: false),
        ]),
        0x0011: ("Workflow", [
            Kind(code: 0, name: "TaskCreate", effect: NIW, variable: false),
            Kind(code: 1, name: "TaskInput", effect: NIW, variable: false),
            Kind(code: 2, name: "TaskCancel", effect: DE, variable: false),
            Kind(code: 3, name: "TaskResult", effect: NIW, variable: false),
        ]),
        0x0012: ("Knowledge", [
            Kind(code: 0, name: "Assert", effect: NIW, variable: false),
            Kind(code: 1, name: "Retract", effect: DE, variable: false),
            Kind(code: 2, name: "KnowledgeQuery", effect: RO, variable: false),
        ]),
        0x0013: ("Spatial", [
            Kind(code: 0, name: "FrameDefine", effect: IW, variable: false),
            Kind(code: 1, name: "Pose", effect: RO, variable: false),
            Kind(code: 2, name: "StateUpdate", effect: RO, variable: false),
            Kind(code: 3, name: "SnapshotQuery", effect: RO, variable: false),
        ]),
    ]

    /// Return (name, effect, variable) for a (channel, kind), or throw UnknownKind.
    public static func lookup(_ channel: Int, _ kind: Int) throws -> (name: String, effect: Int, variable: Bool) {
        guard let ch = table[channel] else {
            throw NaalpError("UnknownKind", "channel 0x\(String(channel, radix: 16)) not registered")
        }
        for k in ch.kinds where k.code == kind {
            return (k.name, k.effect, k.variable)
        }
        throw NaalpError("UnknownKind", "kind \(kind) not in channel 0x\(String(channel, radix: 16))")
    }

    /// A fixed-effect kind's object must carry its declared effect; a variable kind accepts 0..3.
    public static func checkEffect(_ channel: Int, _ kind: Int, _ effect: Int) throws {
        let (_, declared, variable) = try lookup(channel, kind)
        if variable {
            if effect > DE {
                throw NaalpError("EffectDeclarationMismatch", "effect \(effect) out of range")
            }
            return
        }
        if effect != declared {
            throw NaalpError("EffectDeclarationMismatch", "object effect \(effect) != declared \(declared)")
        }
    }
}
