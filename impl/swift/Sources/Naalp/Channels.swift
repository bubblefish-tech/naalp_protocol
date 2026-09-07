// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C10 channel registry for the Swift SDK — the frozen twenty-channel baseline surface
// (design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 74 kinds, each with a declared
// effect (variable-effect for Stream StreamOpen / Bridge Carriage), each channel's state machine
// (AllowedTransition), the Spatial coordinate-frame acyclicity check (CheckFrameTree,
// design-channels.md §20), and the durable Workflow input/approval gate whose crash test proves
// InputGateBypass cannot occur (design-channels.md §18). An independent transcription of the
// design (mirrors impl/go/channels/channels.go and impl/rust/src/channels.rs), cross-checked
// against the shared conformance corpus (== Go == Rust == oracle).

import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

public enum Channels {
    // read_only, idempotent_write, non_idempotent_write, destructive
    static let RO = 0, IW = 1, NIW = 2, DE = 3

    public struct Kind {
        let code: Int
        let name: String
        let effect: Int
        let variable: Bool
    }

    /// One channel's frozen baseline surface (design-channels.md §1..§20) — mirrors Go's
    /// channels.ChannelSpec / Rust's ChannelSpec: id, name, kinds, the channel's declared states,
    /// its allowed state transitions (from -> to pairs), and its named errors.
    public struct ChannelSpec {
        let id: Int
        let name: String
        let kinds: [Kind]
        let states: [String]
        let transitions: [(from: String, to: String)]
        let errors: [String]
    }

    // channel code -> the channel's frozen spec (name, kinds, states, transitions, errors)
    static let table: [Int: ChannelSpec] = [
        0x0000: ChannelSpec(id: 0x0000, name: "Control", kinds: [
            Kind(code: 0, name: "Hello", effect: RO, variable: false),
            Kind(code: 1, name: "Bye", effect: IW, variable: false),
            Kind(code: 2, name: "Ack", effect: RO, variable: false),
            Kind(code: 3, name: "Error", effect: RO, variable: false),
        ], states: ["open", "closing"], transitions: [("open", "closing")],
           errors: ["UnknownKind", "ProfileMismatch"]),
        0x0001: ChannelSpec(id: 0x0001, name: "Memory", kinds: [
            Kind(code: 0, name: "MemoryOffer", effect: IW, variable: false),
            Kind(code: 1, name: "MemoryAccept", effect: IW, variable: false),
            Kind(code: 2, name: "MemoryWrite", effect: NIW, variable: false),
            Kind(code: 3, name: "MemoryRead", effect: RO, variable: false),
            Kind(code: 4, name: "MemoryExpire", effect: DE, variable: false),
            Kind(code: 5, name: "MemoryRevoke", effect: DE, variable: false),
        ], states: ["offered", "accepted", "live", "expired", "revoked"],
           transitions: [("offered", "accepted"), ("accepted", "live"), ("live", "expired"), ("live", "revoked")],
           errors: ["AccessDenied", "MemoryError"]),
        0x0002: ChannelSpec(id: 0x0002, name: "Capability", kinds: [
            Kind(code: 0, name: "CapIssue", effect: NIW, variable: false),
            Kind(code: 1, name: "CapDelegate", effect: NIW, variable: false),
            Kind(code: 2, name: "CapRevoke", effect: DE, variable: false),
            Kind(code: 3, name: "CapLookup", effect: RO, variable: false),
        ], states: ["issued", "delegated", "revoked", "expired"],
           transitions: [("issued", "delegated"), ("delegated", "delegated"), ("issued", "revoked"),
                         ("delegated", "revoked"), ("issued", "expired"), ("delegated", "expired")],
           errors: ["CapExceedsParent", "CapRevoked"]),
        0x0003: ChannelSpec(id: 0x0003, name: "Identity", kinds: [
            Kind(code: 0, name: "Rotation", effect: NIW, variable: false),
            Kind(code: 1, name: "Revocation", effect: DE, variable: false),
            Kind(code: 2, name: "ForeignLink", effect: IW, variable: false),
            Kind(code: 3, name: "KeyAnnounce", effect: RO, variable: false),
        ], states: ["active", "rotated", "revoked"],
           transitions: [("active", "rotated"), ("rotated", "rotated"), ("active", "revoked"), ("rotated", "revoked")],
           errors: ["RotationUnauthorized", "KeyRevoked", "SignerMismatch"]),
        0x0004: ChannelSpec(id: 0x0004, name: "Governance", kinds: [
            Kind(code: 0, name: "PolicyPublish", effect: NIW, variable: false),
            Kind(code: 1, name: "Approval", effect: NIW, variable: false),
            Kind(code: 2, name: "ApprovalHeld", effect: RO, variable: false),
            Kind(code: 3, name: "Consume", effect: NIW, variable: false),
            Kind(code: 4, name: "GatewayDecision", effect: NIW, variable: false),
            Kind(code: 5, name: "DecisionRecord", effect: NIW, variable: false),
            Kind(code: 6, name: "EgressAttestation", effect: NIW, variable: false),
            Kind(code: 7, name: "HazardAuthorization", effect: NIW, variable: false),
        ], states: ["requested", "held", "approved", "consumed", "expired"],
           transitions: [("requested", "held"), ("requested", "approved"), ("approved", "consumed"),
                         ("held", "approved"), ("requested", "expired"), ("approved", "expired")],
           errors: ["ApprovalRequired", "ApprovalMismatch", "AlreadyConsumed", "EffectNotAuthorized"]),
        0x0005: ChannelSpec(id: 0x0005, name: "Immune", kinds: [
            Kind(code: 0, name: "AnomalyReport", effect: RO, variable: false),
            Kind(code: 1, name: "Quarantine", effect: DE, variable: false),
            Kind(code: 2, name: "QuarantineLift", effect: NIW, variable: false),
        ], states: ["normal", "quarantined", "lifted", "permanent"],
           transitions: [("normal", "quarantined"), ("quarantined", "lifted"), ("quarantined", "permanent")],
           errors: ["AccessDenied"]),
        0x0006: ChannelSpec(id: 0x0006, name: "Federation", kinds: [
            Kind(code: 0, name: "AuthorityAnnounce", effect: RO, variable: false),
            Kind(code: 1, name: "ScopeReceipt", effect: NIW, variable: false),
        ], states: ["announced", "ordering"], transitions: [("announced", "ordering")],
           errors: ["AuthorityUnknown", "ScopeOverlapConflict"]),
        0x0007: ChannelSpec(id: 0x0007, name: "Settlement", kinds: [
            Kind(code: 0, name: "SettleIntent", effect: NIW, variable: false),
            Kind(code: 1, name: "SettleReceipt", effect: NIW, variable: false),
            Kind(code: 2, name: "SettleReject", effect: IW, variable: false),
            Kind(code: 3, name: "PaymentImport", effect: NIW, variable: false),
            Kind(code: 4, name: "PaymentChargeBinding", effect: NIW, variable: false),
        ], states: ["intent", "receipt", "reject"], transitions: [("intent", "receipt"), ("intent", "reject")],
           errors: ["ValueMismatch", "SettleExpired"]),
        0x0008: ChannelSpec(id: 0x0008, name: "Compliance", kinds: [
            Kind(code: 0, name: "ComplianceRecord", effect: NIW, variable: false),
            Kind(code: 1, name: "ComplianceQuery", effect: RO, variable: false),
            Kind(code: 2, name: "ComplianceReport", effect: RO, variable: false),
        ], states: ["appended"], transitions: [], errors: ["RecordUnsigned", "JurisdictionUnknown"]),
        0x0009: ChannelSpec(id: 0x0009, name: "Sensory", kinds: [
            Kind(code: 0, name: "Observation", effect: RO, variable: false),
            Kind(code: 1, name: "Subscribe", effect: IW, variable: false),
            Kind(code: 2, name: "Unsubscribe", effect: IW, variable: false),
        ], states: ["active", "cancelled"], transitions: [("active", "cancelled")],
           errors: ["SubscriptionUnknown"]),
        0x000A: ChannelSpec(id: 0x000A, name: "Telemetry", kinds: [
            Kind(code: 0, name: "Metric", effect: RO, variable: false),
            Kind(code: 1, name: "HealthReport", effect: RO, variable: false),
        ], states: ["stateless"], transitions: [], errors: ["MetricMalformed"]),
        0x000B: ChannelSpec(id: 0x000B, name: "Audit", kinds: [
            Kind(code: 0, name: "Receipt", effect: NIW, variable: false),
            Kind(code: 1, name: "AuditQuery", effect: RO, variable: false),
            Kind(code: 2, name: "ForkProof", effect: RO, variable: false),
            Kind(code: 3, name: "CheckpointRoot", effect: NIW, variable: false),
            Kind(code: 4, name: "WitnessCosign", effect: NIW, variable: false),
            Kind(code: 5, name: "InclusionProof", effect: RO, variable: false),
        ], states: ["appended"], transitions: [], errors: ["ChainBroken", "Equivocation", "ReceiptUnsigned"]),
        0x000C: ChannelSpec(id: 0x000C, name: "Stream", kinds: [
            Kind(code: 0, name: "StreamOpen", effect: RO, variable: true),
            Kind(code: 1, name: "StreamCommit", effect: RO, variable: false),
            Kind(code: 2, name: "StreamCheckpoint", effect: RO, variable: false),
        ], states: ["open", "committed"], transitions: [("open", "committed")],
           errors: ["StreamDigestMismatch", "FlowControlError"]),
        0x000D: ChannelSpec(id: 0x000D, name: "Bridge", kinds: [
            Kind(code: 0, name: "Carriage", effect: RO, variable: true),
        ], states: ["carried"], transitions: [],
           errors: ["EnvelopeMalformed", "ProtocolUnsupported", "MethodUnsupported", "NotDelivered", "EffectNotAuthorized"]),
        0x000E: ChannelSpec(id: 0x000E, name: "Commerce", kinds: [
            Kind(code: 0, name: "Offer", effect: RO, variable: false),
            Kind(code: 1, name: "Order", effect: NIW, variable: false),
            Kind(code: 2, name: "Fulfil", effect: NIW, variable: false),
            Kind(code: 3, name: "Cancel", effect: DE, variable: false),
        ], states: ["offer", "order", "fulfil", "cancel"],
           transitions: [("offer", "order"), ("order", "fulfil"), ("order", "cancel")],
           errors: ["OfferExpired", "ApprovalRequired", "OrderMismatch"]),
        0x000F: ChannelSpec(id: 0x000F, name: "Interaction", kinds: [
            Kind(code: 0, name: "Elicit", effect: RO, variable: false),
            Kind(code: 1, name: "Respond", effect: IW, variable: false),
            Kind(code: 2, name: "Confirm", effect: NIW, variable: false),
            Kind(code: 3, name: "UiEvent", effect: NIW, variable: false),
        ], states: ["elicit", "respond", "confirm", "timeout"],
           transitions: [("elicit", "respond"), ("elicit", "confirm"), ("elicit", "timeout")],
           errors: ["InteractionTimeout", "ElicitUnauthorized"]),
        0x0010: ChannelSpec(id: 0x0010, name: "Discovery", kinds: [
            Kind(code: 0, name: "DiscoveryRecord", effect: RO, variable: false),
            Kind(code: 1, name: "DiscoveryQuery", effect: RO, variable: false),
        ], states: ["fresh", "stale"], transitions: [("fresh", "stale")],
           errors: ["RecordExpired", "TrustAnchorUnknown"]),
        0x0011: ChannelSpec(id: 0x0011, name: "Workflow", kinds: [
            Kind(code: 0, name: "TaskCreate", effect: NIW, variable: false),
            Kind(code: 1, name: "TaskInput", effect: NIW, variable: false),
            Kind(code: 2, name: "TaskCancel", effect: DE, variable: false),
            Kind(code: 3, name: "TaskResult", effect: NIW, variable: false),
        ], states: ["created", "awaiting-input", "awaiting-approval", "running", "result", "cancelled"],
           transitions: [("created", "awaiting-input"), ("created", "awaiting-approval"),
                         ("awaiting-input", "running"), ("awaiting-approval", "running"),
                         ("running", "result"), ("created", "cancelled"), ("awaiting-input", "cancelled"),
                         ("awaiting-approval", "cancelled"), ("running", "cancelled")],
           errors: ["TaskStateError", "InputGateBypass", "ApprovalRequired"]),
        0x0012: ChannelSpec(id: 0x0012, name: "Knowledge", kinds: [
            Kind(code: 0, name: "Assert", effect: NIW, variable: false),
            Kind(code: 1, name: "Retract", effect: DE, variable: false),
            Kind(code: 2, name: "KnowledgeQuery", effect: RO, variable: false),
        ], states: ["asserted", "retracted"], transitions: [("asserted", "retracted")],
           errors: ["FactUnsigned", "RetractUnknown"]),
        0x0013: ChannelSpec(id: 0x0013, name: "Spatial", kinds: [
            Kind(code: 0, name: "FrameDefine", effect: IW, variable: false),
            Kind(code: 1, name: "Pose", effect: RO, variable: false),
            Kind(code: 2, name: "StateUpdate", effect: RO, variable: false),
            Kind(code: 3, name: "SnapshotQuery", effect: RO, variable: false),
        ], states: ["defined", "observed"], transitions: [("defined", "observed")],
           errors: ["FrameUnknown", "TransformCycle"]),
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

    /// Returns the frozen spec for a channel id, or nil if unregistered — mirrors Go
    /// channels.Channel(id) / Rust channels::channel(id).
    public static func channel(_ id: Int) -> ChannelSpec? {
        return table[id]
    }

    /// Reports whether a channel permits a state transition from -> to (design-channels.md's
    /// per-channel state machines). An unregistered channel permits nothing.
    public static func allowedTransition(_ channel: Int, _ from: String, _ to: String) -> Bool {
        guard let ch = table[channel] else { return false }
        return ch.transitions.contains { $0.from == from && $0.to == to }
    }

    /// Enforces Spatial's TransformCycle (design-channels.md §20): the coordinate-frame
    /// child -> parent links must form a tree (acyclic). A frame mapping to "" (or absent) is a
    /// root. Throws TransformCycle on the first cycle found; otherwise returns normally.
    public static func checkFrameTree(_ parent: [String: String]) throws {
        let white = 0, gray = 1, black = 2
        var color: [String: Int] = [:]
        func visit(_ f: String) -> Bool {
            color[f] = gray
            if let p = parent[f], !p.isEmpty {
                switch color[p] ?? white {
                case gray:
                    return true
                case white:
                    if visit(p) { return true }
                default:
                    break
                }
            }
            color[f] = black
            return false
        }
        for f in parent.keys where (color[f] ?? white) == white {
            if visit(f) {
                throw NaalpError("TransformCycle", "coordinate frame tree contains a cycle")
            }
        }
    }

    // ---- Workflow input gate (design-channels.md §18): the crash test that InputGateBypass cannot
    // occur. ----------------------------------------------------------------------------------------

    /// A durable, WAL-backed Workflow task-status tracker (design-channels.md §18). A task's status
    /// is persisted (written + fsynced) before it is acknowledged (spine §9.2, mirroring
    /// Approval.Ledger's persist-before-ack WAL idiom), so a crash recovers to the last durable
    /// status and can NEVER bypass the input/approval gate: reaching "running" requires an explicit
    /// input/approval step that a crash cannot manufacture.
    public final class WorkflowGate {
        private let lock = NSLock()
        private let fh: FileHandle
        private var statusMap: [String: String] = [:]
        private var closed = false

        private init(fh: FileHandle) {
            self.fh = fh
        }

        /// Opens (creating if needed) a WAL-backed gate at `path` and replays it.
        static func open(_ path: String) throws -> WorkflowGate {
            if !FileManager.default.fileExists(atPath: path) {
                _ = FileManager.default.createFile(atPath: path, contents: nil)
            }
            guard let fh = FileHandle(forUpdatingAtPath: path) else {
                throw NaalpError("WorkflowGateIO", "cannot open the workflow gate WAL")
            }
            let g = WorkflowGate(fh: fh)
            let data = (try? Data(contentsOf: URL(fileURLWithPath: path))) ?? Data()
            try g.replay([UInt8](data))
            return g
        }

        /// Replays the length-prefixed WAL (each record: a uint32 big-endian length, then
        /// "<task>\0<status>"), rebuilding the durable status map. A record with no NUL separator
        /// is Malformed (fail-closed rather than silently trusted).
        private func replay(_ bytes: [UInt8]) throws {
            var pos = 0
            while pos < bytes.count {
                if pos + 4 > bytes.count {
                    throw NaalpError("Malformed", "truncated workflow gate length prefix")
                }
                let n = (UInt32(bytes[pos]) << 24) | (UInt32(bytes[pos + 1]) << 16)
                    | (UInt32(bytes[pos + 2]) << 8) | UInt32(bytes[pos + 3])
                pos += 4
                let recLen = Int(n)
                if pos + recLen > bytes.count {
                    throw NaalpError("Malformed", "truncated workflow gate record")
                }
                let rec = Array(bytes[pos..<(pos + recLen)])
                pos += recLen
                guard let nul = rec.firstIndex(of: 0) else {
                    throw NaalpError("Malformed", "workflow gate record")
                }
                let task = String(decoding: rec[rec.startIndex..<nul], as: UTF8.self)
                let st = String(decoding: rec[rec.index(after: nul)...], as: UTF8.self)
                statusMap[task] = st
            }
        }

        /// Appends `task\0status` to the WAL and fsyncs it before updating memory
        /// (persist-before-ack, spine §9.2). A failed or short write throws WorkflowGateIO and the
        /// caller's in-memory state is left unchanged (fail-closed).
        private func persist(_ task: String, _ status: String) throws {
            var rec = Array(task.utf8)
            rec.append(0)
            rec.append(contentsOf: Array(status.utf8))
            let n = UInt32(rec.count)
            let framed: [UInt8] = [UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff),
                                    UInt8((n >> 8) & 0xff), UInt8(n & 0xff)] + rec
            let fd = fh.fileDescriptor
            lseek(fd, 0, SEEK_END)
            var off = 0
            try framed.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return }
                while off < framed.count {
                    let w = write(fd, base + off, framed.count - off)
                    if w <= 0 {
                        throw NaalpError("WorkflowGateIO", "short write to the workflow gate WAL")
                    }
                    off += w
                }
            }
            if fsync(fd) != 0 {
                throw NaalpError("WorkflowGateIO", "fsync of the workflow gate WAL failed")
            }
            statusMap[task] = status
        }

        /// Records a new task in a non-terminal pre-gate status. TaskCreate never lands in
        /// "running": it lands in "awaiting-input" (or "awaiting-approval"), persisted before
        /// returning. A duplicate create is TaskStateError.
        public func create(_ task: String, _ needsApproval: Bool) throws {
            lock.lock(); defer { lock.unlock() }
            if statusMap[task] != nil {
                throw NaalpError("TaskStateError", "workflow task state transition not permitted")
            }
            try persist(task, needsApproval ? "awaiting-approval" : "awaiting-input")
        }

        /// Advances a task past its input gate (awaiting-input -> input-supplied) or approval gate
        /// (awaiting-approval -> approved). Only these transitions may precede `run`; any other
        /// current status is TaskStateError.
        public func supplyInput(_ task: String) throws {
            lock.lock(); defer { lock.unlock() }
            switch statusMap[task] {
            case "awaiting-input":
                try persist(task, "input-supplied")
            case "awaiting-approval":
                try persist(task, "approved")
            default:
                throw NaalpError("TaskStateError", "workflow task state transition not permitted")
            }
        }

        /// Moves a task to "running" only if it has passed the gate. A task still "awaiting-input"
        /// or "awaiting-approval" cannot run: that is InputGateBypass, forbidden — a task may not
        /// execute on input that was never supplied/authorized. An unknown/terminal status is
        /// TaskStateError.
        public func run(_ task: String) throws {
            lock.lock(); defer { lock.unlock() }
            switch statusMap[task] {
            case "input-supplied", "approved":
                try persist(task, "running")
            case "awaiting-input", "awaiting-approval":
                throw NaalpError("InputGateBypass", "a task reached running without passing the input/approval gate")
            default:
                throw NaalpError("TaskStateError", "workflow task state transition not permitted")
            }
        }

        /// The task's durable status, or nil if unknown.
        public func status(_ task: String) -> String? {
            lock.lock(); defer { lock.unlock() }
            return statusMap[task]
        }

        /// Flushes and closes the WAL. A gate call after close fails-closed at the WAL write.
        public func close() throws {
            lock.lock(); defer { lock.unlock() }
            if closed { return }
            closed = true
            fh.closeFile()
        }
    }

    /// Opens (creating if needed) a durable WAL-backed workflow gate at `path` and replays it —
    /// mirrors Go's channels.OpenWorkflowGate / Rust's channels::open_workflow_gate.
    public static func openWorkflowGate(_ path: String) throws -> WorkflowGate {
        return try WorkflowGate.open(path)
    }
}
