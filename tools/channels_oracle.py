# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C10 — the twenty channel surfaces, baseline tier (T12).

Non-circular authority (NOT the code under test): the frozen channel table of
`design-channels.md` (§1..§20), transcribed here independently of the Go/Rust surface code.
A channel surface adds ONLY kind codes and their declared effects over the one spine
(R-11.3); this oracle fixes, per channel: the channel id + name, every baseline kind (code,
name, declared effect, and whether the effect is variable), the state set + allowed state
transitions, and the named error vocabulary. Go and Rust build their channel tables and assert
equality against these vectors; Go == oracle and Rust == oracle ⟹ Go == Rust.

Effect codes (C5): 0 read_only, 1 idempotent_write, 2 non_idempotent_write, 3 destructive.
A kind whose effect is "per the carried/stream action" is marked variable (effect authorized at
run time by C5, not fixed by the kind).

Emits vectors/channels/<name>/cases.json (20 files) + vectors/registry/channels.csv (LF).
"""
import io
import json
import os

RO, IW, NIW, DE = 0, 1, 2, 3

# (channel_id, dir_name, Name, kinds=[(code,name,effect,variable)], states=[...],
#  transitions=[(from,to)], errors=[...])
CHANNELS = [
    (0x0000, "control", "Control",
     [(0, "Hello", RO, False), (1, "Bye", IW, False), (2, "Ack", RO, False), (3, "Error", RO, False)],
     ["open", "closing"], [("open", "closing")],
     ["UnknownKind", "ProfileMismatch"]),
    (0x0001, "memory", "Memory",
     [(0, "MemoryOffer", IW, False), (1, "MemoryAccept", IW, False), (2, "MemoryWrite", NIW, False),
      (3, "MemoryRead", RO, False), (4, "MemoryExpire", DE, False), (5, "MemoryRevoke", DE, False)],
     ["offered", "accepted", "live", "expired", "revoked"],
     [("offered", "accepted"), ("accepted", "live"), ("live", "expired"), ("live", "revoked")],
     ["AccessDenied", "MemoryError"]),
    (0x0002, "capability", "Capability",
     [(0, "CapIssue", NIW, False), (1, "CapDelegate", NIW, False), (2, "CapRevoke", DE, False), (3, "CapLookup", RO, False)],
     ["issued", "delegated", "revoked", "expired"],
     [("issued", "delegated"), ("delegated", "delegated"), ("issued", "revoked"), ("delegated", "revoked"), ("issued", "expired"), ("delegated", "expired")],
     ["CapExceedsParent", "CapRevoked"]),
    (0x0003, "identity", "Identity",
     [(0, "Rotation", NIW, False), (1, "Revocation", DE, False), (2, "ForeignLink", IW, False), (3, "KeyAnnounce", RO, False)],
     ["active", "rotated", "revoked"],
     [("active", "rotated"), ("rotated", "rotated"), ("active", "revoked"), ("rotated", "revoked")],
     ["RotationUnauthorized", "KeyRevoked", "SignerMismatch"]),
    (0x0004, "governance", "Governance",
     [(0, "PolicyPublish", NIW, False), (1, "Approval", NIW, False), (2, "ApprovalHeld", RO, False), (3, "Consume", NIW, False)],
     ["requested", "held", "approved", "consumed", "expired"],
     [("requested", "held"), ("requested", "approved"), ("approved", "consumed"), ("held", "approved"), ("requested", "expired"), ("approved", "expired")],
     ["ApprovalRequired", "ApprovalMismatch", "AlreadyConsumed", "EffectNotAuthorized"]),
    (0x0005, "immune", "Immune",
     [(0, "AnomalyReport", RO, False), (1, "Quarantine", DE, False), (2, "QuarantineLift", NIW, False)],
     ["normal", "quarantined", "lifted", "permanent"],
     [("normal", "quarantined"), ("quarantined", "lifted"), ("quarantined", "permanent")],
     ["AccessDenied"]),
    (0x0006, "federation", "Federation",
     [(0, "AuthorityAnnounce", RO, False), (1, "ScopeReceipt", NIW, False)],
     ["announced", "ordering"], [("announced", "ordering")],
     ["AuthorityUnknown", "ScopeOverlapConflict"]),
    (0x0007, "settlement", "Settlement",
     [(0, "SettleIntent", NIW, False), (1, "SettleReceipt", NIW, False), (2, "SettleReject", IW, False)],
     ["intent", "receipt", "reject"], [("intent", "receipt"), ("intent", "reject")],
     ["ValueMismatch", "SettleExpired"]),
    (0x0008, "compliance", "Compliance",
     [(0, "ComplianceRecord", NIW, False), (1, "ComplianceQuery", RO, False), (2, "ComplianceReport", RO, False)],
     ["appended"], [],
     ["RecordUnsigned", "JurisdictionUnknown"]),
    (0x0009, "sensory", "Sensory",
     [(0, "Observation", RO, False), (1, "Subscribe", IW, False), (2, "Unsubscribe", IW, False)],
     ["active", "cancelled"], [("active", "cancelled")],
     ["SubscriptionUnknown"]),
    (0x000A, "telemetry", "Telemetry",
     [(0, "Metric", RO, False), (1, "HealthReport", RO, False)],
     ["stateless"], [],
     ["MetricMalformed"]),
    (0x000B, "audit", "Audit",
     [(0, "Receipt", NIW, False), (1, "AuditQuery", RO, False), (2, "ForkProof", RO, False)],
     ["appended"], [],
     ["ChainBroken", "Equivocation", "ReceiptUnsigned"]),
    (0x000C, "stream", "Stream",
     [(0, "StreamOpen", RO, True), (1, "StreamCommit", RO, False), (2, "StreamCheckpoint", RO, False)],
     ["open", "committed"], [("open", "committed")],
     ["StreamDigestMismatch", "FlowControlError"]),
    (0x000D, "bridge", "Bridge",
     [(0, "Carriage", RO, True)],
     ["carried"], [],
     ["EnvelopeMalformed", "ProtocolUnsupported", "MethodUnsupported", "NotDelivered", "EffectNotAuthorized"]),
    (0x000E, "commerce", "Commerce",
     [(0, "Offer", RO, False), (1, "Order", NIW, False), (2, "Fulfil", NIW, False), (3, "Cancel", DE, False)],
     ["offer", "order", "fulfil", "cancel"],
     [("offer", "order"), ("order", "fulfil"), ("order", "cancel")],
     ["OfferExpired", "ApprovalRequired", "OrderMismatch"]),
    (0x000F, "interaction", "Interaction",
     [(0, "Elicit", RO, False), (1, "Respond", IW, False), (2, "Confirm", NIW, False)],
     ["elicit", "respond", "confirm", "timeout"],
     [("elicit", "respond"), ("elicit", "confirm"), ("elicit", "timeout")],
     ["InteractionTimeout", "ElicitUnauthorized"]),
    (0x0010, "discovery", "Discovery",
     [(0, "DiscoveryRecord", RO, False), (1, "DiscoveryQuery", RO, False)],
     ["fresh", "stale"], [("fresh", "stale")],
     ["RecordExpired", "TrustAnchorUnknown"]),
    (0x0011, "workflow", "Workflow",
     [(0, "TaskCreate", NIW, False), (1, "TaskInput", NIW, False), (2, "TaskCancel", DE, False), (3, "TaskResult", NIW, False)],
     ["created", "awaiting-input", "awaiting-approval", "running", "result", "cancelled"],
     [("created", "awaiting-input"), ("created", "awaiting-approval"), ("awaiting-input", "running"),
      ("awaiting-approval", "running"), ("running", "result"), ("created", "cancelled"),
      ("awaiting-input", "cancelled"), ("awaiting-approval", "cancelled"), ("running", "cancelled")],
     ["TaskStateError", "InputGateBypass", "ApprovalRequired"]),
    (0x0012, "knowledge", "Knowledge",
     [(0, "Assert", NIW, False), (1, "Retract", DE, False), (2, "KnowledgeQuery", RO, False)],
     ["asserted", "retracted"], [("asserted", "retracted")],
     ["FactUnsigned", "RetractUnknown"]),
    (0x0013, "spatial", "Spatial",
     [(0, "FrameDefine", IW, False), (1, "Pose", RO, False), (2, "StateUpdate", RO, False), (3, "SnapshotQuery", RO, False)],
     ["defined", "observed"], [("defined", "observed")],
     ["FrameUnknown", "TransformCycle"]),
]


def channel_case(cid, name, kinds, states, transitions, errors):
    return {
        "source": "design-channels.md §1..§20; a surface adds only kind codes + declared effects over the spine (R-11.3).",
        "channel_id": cid,
        "name": name,
        "kinds": [{"code": c, "name": n, "effect": e, "variable": v} for (c, n, e, v) in kinds],
        "states": states,
        "transitions": [{"from": a, "to": b} for (a, b) in transitions],
        "errors": errors,
    }


def build_and_write():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.join(here, "..")
    # per-channel vectors
    for (cid, dir_name, name, kinds, states, transitions, errors) in CHANNELS:
        data = channel_case(cid, name, kinds, states, transitions, errors)
        out = os.path.join(root, "vectors", "channels", dir_name, "cases.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with io.open(out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
    # machine-readable channel/kind/effect registry
    csv_path = os.path.join(root, "vectors", "registry", "channels.csv")
    effect_names = {RO: "read_only", IW: "idempotent_write", NIW: "non_idempotent_write", DE: "destructive"}
    with io.open(csv_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("channel_id,channel_name,kind_code,kind_name,effect,variable_effect\n")
        for (cid, _dir, name, kinds, _s, _t, _e) in CHANNELS:
            for (c, kn, e, v) in kinds:
                eff = "variable" if v else effect_names[e]
                f.write("0x%04X,%s,%d,%s,%s,%s\n" % (cid, name, c, kn, eff, "true" if v else "false"))
    return len(CHANNELS), sum(len(k) for (_a, _b, _c, k, _s, _t, _e) in CHANNELS)


def main():
    nchan, nkinds = build_and_write()
    print("wrote %d channel vectors + vectors/registry/channels.csv (%d kinds total)" % (nchan, nkinds))


if __name__ == "__main__":
    main()
