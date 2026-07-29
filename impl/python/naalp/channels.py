# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP C10 channel registry for the Python SDK — the frozen twenty-channel baseline surface
(design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 65 kinds, each with a declared
effect (variable-effect for Stream StreamOpen / Bridge Carriage). An independent transcription of
the design, cross-checked against the shared conformance corpus (== Go == Rust == oracle).
"""
RO, IW, NIW, DE = 0, 1, 2, 3  # read_only, idempotent_write, non_idempotent_write, destructive

# each kind: (code, name, effect, variable)
TABLE = {
    0x0000: ("Control", [(0, "Hello", RO, False), (1, "Bye", IW, False), (2, "Ack", RO, False), (3, "Error", RO, False)]),
    0x0001: ("Memory", [(0, "MemoryOffer", IW, False), (1, "MemoryAccept", IW, False), (2, "MemoryWrite", NIW, False),
                        (3, "MemoryRead", RO, False), (4, "MemoryExpire", DE, False), (5, "MemoryRevoke", DE, False)]),
    0x0002: ("Capability", [(0, "CapIssue", NIW, False), (1, "CapDelegate", NIW, False), (2, "CapRevoke", DE, False), (3, "CapLookup", RO, False)]),
    0x0003: ("Identity", [(0, "Rotation", NIW, False), (1, "Revocation", DE, False), (2, "ForeignLink", IW, False), (3, "KeyAnnounce", RO, False)]),
    0x0004: ("Governance", [(0, "PolicyPublish", NIW, False), (1, "Approval", NIW, False), (2, "ApprovalHeld", RO, False), (3, "Consume", NIW, False)]),
    0x0005: ("Immune", [(0, "AnomalyReport", RO, False), (1, "Quarantine", DE, False), (2, "QuarantineLift", NIW, False)]),
    0x0006: ("Federation", [(0, "AuthorityAnnounce", RO, False), (1, "ScopeReceipt", NIW, False)]),
    0x0007: ("Settlement", [(0, "SettleIntent", NIW, False), (1, "SettleReceipt", NIW, False), (2, "SettleReject", IW, False)]),
    0x0008: ("Compliance", [(0, "ComplianceRecord", NIW, False), (1, "ComplianceQuery", RO, False), (2, "ComplianceReport", RO, False)]),
    0x0009: ("Sensory", [(0, "Observation", RO, False), (1, "Subscribe", IW, False), (2, "Unsubscribe", IW, False)]),
    0x000A: ("Telemetry", [(0, "Metric", RO, False), (1, "HealthReport", RO, False)]),
    0x000B: ("Audit", [(0, "Receipt", NIW, False), (1, "AuditQuery", RO, False), (2, "ForkProof", RO, False)]),
    0x000C: ("Stream", [(0, "StreamOpen", RO, True), (1, "StreamCommit", RO, False), (2, "StreamCheckpoint", RO, False)]),
    0x000D: ("Bridge", [(0, "Carriage", RO, True)]),
    0x000E: ("Commerce", [(0, "Offer", RO, False), (1, "Order", NIW, False), (2, "Fulfil", NIW, False), (3, "Cancel", DE, False)]),
    0x000F: ("Interaction", [(0, "Elicit", RO, False), (1, "Respond", IW, False), (2, "Confirm", NIW, False)]),
    0x0010: ("Discovery", [(0, "DiscoveryRecord", RO, False), (1, "DiscoveryQuery", RO, False)]),
    0x0011: ("Workflow", [(0, "TaskCreate", NIW, False), (1, "TaskInput", NIW, False), (2, "TaskCancel", DE, False), (3, "TaskResult", NIW, False)]),
    0x0012: ("Knowledge", [(0, "Assert", NIW, False), (1, "Retract", DE, False), (2, "KnowledgeQuery", RO, False)]),
    0x0013: ("Spatial", [(0, "FrameDefine", IW, False), (1, "Pose", RO, False), (2, "StateUpdate", RO, False), (3, "SnapshotQuery", RO, False)]),
}


class UnknownKind(ValueError):
    kind = "UnknownKind"


class EffectDeclarationMismatch(ValueError):
    kind = "EffectDeclarationMismatch"


def lookup(channel: int, kind: int):
    """Return (name, effect, variable) for a (channel, kind), or raise UnknownKind."""
    ch = TABLE.get(channel)
    if ch is None:
        raise UnknownKind("channel 0x%04x not registered" % channel)
    for code, name, effect, variable in ch[1]:
        if code == kind:
            return name, effect, variable
    raise UnknownKind("kind %d not in channel 0x%04x" % (kind, channel))


def check_effect(channel: int, kind: int, effect: int) -> None:
    """A fixed-effect kind's object must carry its declared effect; a variable kind accepts 0..3."""
    _name, declared, variable = lookup(channel, kind)
    if variable:
        if effect > DE:
            raise EffectDeclarationMismatch("effect %d out of range" % effect)
        return
    if effect != declared:
        raise EffectDeclarationMismatch("object effect %d != declared %d" % (effect, declared))
