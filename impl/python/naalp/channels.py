# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP C10 channel registry for the Python SDK — the frozen twenty-channel baseline surface
(design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 74 kinds, each with a declared
effect (variable-effect for Stream StreamOpen / Bridge Carriage). An independent transcription of
the design, cross-checked against the shared conformance corpus (== Go == Rust == oracle).

Also ported (channels parity cluster, task #174; design-channels.md §18, §20; mirrors
impl/go/channels/channels.go and impl/rust/src/channels.rs): the per-channel state machine
(ChannelSpec/KindSpec + channel()/all_channels()/allowed_transition()), Spatial's TransformCycle
structural check (check_frame_tree), and the Workflow durable input/approval gate
(WorkflowGate/open_workflow_gate) whose crash test proves InputGateBypass cannot occur -- a task's
status is persisted (flushed + fsynced) before it is acknowledged, so a crash recovers to the last
durable status and can never manufacture a bypass of the input/approval gate.

NOTE (baseline_notes): Capability's CapExceedsParent delegation-ceiling check already exists as a
real wiring in impl/python/naalp/delegation.py (verify_chain step 6, via policy.authorizes) -- it
is not duplicated here as a standalone check_delegation(); this port's per-channel table below
still carries CapExceedsParent in Capability's `errors` list for oracle parity.
"""
import os
import threading

RO, IW, NIW, DE = 0, 1, 2, 3  # read_only, idempotent_write, non_idempotent_write, destructive

# each kind: (code, name, effect, variable)
TABLE = {
    0x0000: ("Control", [(0, "Hello", RO, False), (1, "Bye", IW, False), (2, "Ack", RO, False), (3, "Error", RO, False)]),
    0x0001: ("Memory", [(0, "MemoryOffer", IW, False), (1, "MemoryAccept", IW, False), (2, "MemoryWrite", NIW, False),
                        (3, "MemoryRead", RO, False), (4, "MemoryExpire", DE, False), (5, "MemoryRevoke", DE, False)]),
    0x0002: ("Capability", [(0, "CapIssue", NIW, False), (1, "CapDelegate", NIW, False), (2, "CapRevoke", DE, False), (3, "CapLookup", RO, False)]),
    0x0003: ("Identity", [(0, "Rotation", NIW, False), (1, "Revocation", DE, False), (2, "ForeignLink", IW, False), (3, "KeyAnnounce", RO, False)]),
    0x0004: ("Governance", [(0, "PolicyPublish", NIW, False), (1, "Approval", NIW, False), (2, "ApprovalHeld", RO, False), (3, "Consume", NIW, False), (4, "GatewayDecision", NIW, False), (5, "DecisionRecord", NIW, False), (6, "EgressAttestation", NIW, False), (7, "HazardAuthorization", NIW, False)]),
    0x0005: ("Immune", [(0, "AnomalyReport", RO, False), (1, "Quarantine", DE, False), (2, "QuarantineLift", NIW, False)]),
    0x0006: ("Federation", [(0, "AuthorityAnnounce", RO, False), (1, "ScopeReceipt", NIW, False)]),
    0x0007: ("Settlement", [(0, "SettleIntent", NIW, False), (1, "SettleReceipt", NIW, False), (2, "SettleReject", IW, False), (3, "PaymentImport", NIW, False), (4, "PaymentChargeBinding", NIW, False)]),
    0x0008: ("Compliance", [(0, "ComplianceRecord", NIW, False), (1, "ComplianceQuery", RO, False), (2, "ComplianceReport", RO, False)]),
    0x0009: ("Sensory", [(0, "Observation", RO, False), (1, "Subscribe", IW, False), (2, "Unsubscribe", IW, False)]),
    0x000A: ("Telemetry", [(0, "Metric", RO, False), (1, "HealthReport", RO, False)]),
    0x000B: ("Audit", [(0, "Receipt", NIW, False), (1, "AuditQuery", RO, False), (2, "ForkProof", RO, False), (3, "CheckpointRoot", NIW, False), (4, "WitnessCosign", NIW, False), (5, "InclusionProof", RO, False)]),
    0x000C: ("Stream", [(0, "StreamOpen", RO, True), (1, "StreamCommit", RO, False), (2, "StreamCheckpoint", RO, False)]),
    0x000D: ("Bridge", [(0, "Carriage", RO, True)]),
    0x000E: ("Commerce", [(0, "Offer", RO, False), (1, "Order", NIW, False), (2, "Fulfil", NIW, False), (3, "Cancel", DE, False)]),
    0x000F: ("Interaction", [(0, "Elicit", RO, False), (1, "Respond", IW, False), (2, "Confirm", NIW, False), (3, "UiEvent", NIW, False)]),
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


# ---- per-channel state machine (design-channels.md §1..§20) -----------------------------------
#
# states/transitions/errors per channel id, transcribed from the Go authority (impl/go/channels/
# channels.go Table) and cross-checked against the independent oracle vectors/channels/<name>/
# cases.json (== Go == Rust == oracle). Kept separate from TABLE (kinds only) so the pre-existing
# lookup()/check_effect() surface above is untouched.
_STATE_MACHINE = {
    0x0000: (["open", "closing"], [("open", "closing")], ["UnknownKind", "ProfileMismatch"]),
    0x0001: (["offered", "accepted", "live", "expired", "revoked"],
             [("offered", "accepted"), ("accepted", "live"), ("live", "expired"), ("live", "revoked")],
             ["AccessDenied", "MemoryError"]),
    0x0002: (["issued", "delegated", "revoked", "expired"],
             [("issued", "delegated"), ("delegated", "delegated"), ("issued", "revoked"),
              ("delegated", "revoked"), ("issued", "expired"), ("delegated", "expired")],
             ["CapExceedsParent", "CapRevoked"]),
    0x0003: (["active", "rotated", "revoked"],
             [("active", "rotated"), ("rotated", "rotated"), ("active", "revoked"), ("rotated", "revoked")],
             ["RotationUnauthorized", "KeyRevoked", "SignerMismatch"]),
    0x0004: (["requested", "held", "approved", "consumed", "expired"],
             [("requested", "held"), ("requested", "approved"), ("approved", "consumed"),
              ("held", "approved"), ("requested", "expired"), ("approved", "expired")],
             ["ApprovalRequired", "ApprovalMismatch", "AlreadyConsumed", "EffectNotAuthorized"]),
    0x0005: (["normal", "quarantined", "lifted", "permanent"],
             [("normal", "quarantined"), ("quarantined", "lifted"), ("quarantined", "permanent")],
             ["AccessDenied"]),
    0x0006: (["announced", "ordering"], [("announced", "ordering")], ["AuthorityUnknown", "ScopeOverlapConflict"]),
    0x0007: (["intent", "receipt", "reject"], [("intent", "receipt"), ("intent", "reject")],
             ["ValueMismatch", "SettleExpired"]),
    0x0008: (["appended"], [], ["RecordUnsigned", "JurisdictionUnknown"]),
    0x0009: (["active", "cancelled"], [("active", "cancelled")], ["SubscriptionUnknown"]),
    0x000A: (["stateless"], [], ["MetricMalformed"]),
    0x000B: (["appended"], [], ["ChainBroken", "Equivocation", "ReceiptUnsigned"]),
    0x000C: (["open", "committed"], [("open", "committed")], ["StreamDigestMismatch", "FlowControlError"]),
    0x000D: (["carried"], [], ["EnvelopeMalformed", "ProtocolUnsupported", "MethodUnsupported",
                                "NotDelivered", "EffectNotAuthorized"]),
    0x000E: (["offer", "order", "fulfil", "cancel"],
             [("offer", "order"), ("order", "fulfil"), ("order", "cancel")],
             ["OfferExpired", "ApprovalRequired", "OrderMismatch"]),
    0x000F: (["elicit", "respond", "confirm", "timeout"],
             [("elicit", "respond"), ("elicit", "confirm"), ("elicit", "timeout")],
             ["InteractionTimeout", "ElicitUnauthorized"]),
    0x0010: (["fresh", "stale"], [("fresh", "stale")], ["RecordExpired", "TrustAnchorUnknown"]),
    0x0011: (["created", "awaiting-input", "awaiting-approval", "running", "result", "cancelled"],
             [("created", "awaiting-input"), ("created", "awaiting-approval"),
              ("awaiting-input", "running"), ("awaiting-approval", "running"),
              ("running", "result"), ("created", "cancelled"), ("awaiting-input", "cancelled"),
              ("awaiting-approval", "cancelled"), ("running", "cancelled")],
             ["TaskStateError", "InputGateBypass", "ApprovalRequired"]),
    0x0012: (["asserted", "retracted"], [("asserted", "retracted")], ["FactUnsigned", "RetractUnknown"]),
    0x0013: (["defined", "observed"], [("defined", "observed")], ["FrameUnknown", "TransformCycle"]),
}


class KindSpec:
    """One baseline object kind of a channel: its code, name, declared effect, and whether the
    effect is variable (mirrors Go channels.KindSpec / Rust channels::KindSpec)."""

    __slots__ = ("code", "name", "effect", "variable")

    def __init__(self, code, name, effect, variable):
        self.code = code
        self.name = name
        self.effect = effect
        self.variable = variable

    def __repr__(self):
        return "KindSpec(code=%d, name=%r, effect=%d, variable=%r)" % (self.code, self.name, self.effect, self.variable)


class ChannelSpec:
    """One channel's frozen baseline surface: id, name, its KindSpec list, its named states, its
    permitted (from, to) transitions, and its named errors (mirrors Go channels.ChannelSpec / Rust
    channels::ChannelSpec)."""

    __slots__ = ("id", "name", "kinds", "states", "transitions", "errors")

    def __init__(self, id, name, kinds, states, transitions, errors):
        self.id = id
        self.name = name
        self.kinds = kinds
        self.states = states
        self.transitions = transitions
        self.errors = errors

    def __repr__(self):
        return "ChannelSpec(id=%#06x, name=%r)" % (self.id, self.name)


def _build_channel_specs():
    specs = {}
    for cid, (name, kinds) in TABLE.items():
        states, transitions, errors = _STATE_MACHINE[cid]
        kind_specs = [KindSpec(code, kname, effect, variable) for (code, kname, effect, variable) in kinds]
        specs[cid] = ChannelSpec(cid, name, kind_specs, list(states), list(transitions), list(errors))
    return specs


_CHANNEL_SPECS = _build_channel_specs()


def channel(channel_id: int):
    """Return the ChannelSpec for a channel id, or None if it is not registered (mirrors Go
    channels.Channel(id) (*ChannelSpec, bool) / Rust channels::channel(id) -> Option<ChannelSpec>,
    adapted to the Pythonic None-for-absent idiom)."""
    return _CHANNEL_SPECS.get(channel_id)


def all_channels():
    """All twenty registered ChannelSpecs, in ascending channel-id order."""
    return [_CHANNEL_SPECS[cid] for cid in sorted(_CHANNEL_SPECS)]


def allowed_transition(channel_id: int, frm: str, to: str) -> bool:
    """Whether channel_id permits a state transition from -> to (mirrors Go/Rust AllowedTransition).
    An unregistered channel id never allows any transition."""
    c = _CHANNEL_SPECS.get(channel_id)
    if c is None:
        return False
    for a, b in c.transitions:
        if a == frm and b == to:
            return True
    return False


class TransformCycle(ValueError):
    kind = "TransformCycle"


def check_frame_tree(parent) -> None:
    """Enforce Spatial's TransformCycle (design-channels.md §20): the coordinate-frame child->
    parent links in `parent` (a dict mapping a frame name to its parent frame name, or "" / absent
    for a root) must form a tree (acyclic). Raises TransformCycle on a cycle; returns None
    otherwise (mirrors Go/Rust CheckFrameTree's three-colour DFS)."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {}

    def visit(f):
        color[f] = GRAY
        p = parent.get(f)
        if p:
            c = color.get(p, WHITE)
            if c == GRAY:
                return True
            if c == WHITE and visit(p):
                return True
        color[f] = BLACK
        return False

    for f in parent:
        if color.get(f, WHITE) == WHITE and visit(f):
            raise TransformCycle("coordinate frame tree contains a cycle")
    return None


# ---- Workflow input gate (design-channels.md §18): the crash test that InputGateBypass cannot occur.

class InputGateBypass(ValueError):
    kind = "InputGateBypass"


class TaskStateError(ValueError):
    kind = "TaskStateError"


class WorkflowGateMalformed(ValueError):
    kind = "Malformed"


class WorkflowGate:
    """A durable, WAL-backed Workflow task-status tracker (design-channels.md §18). A task's status
    is persisted (written, flushed, and fsynced) before it is acknowledged (spine §9.2), so a crash
    recovers to the last durable status and can NEVER bypass the input/approval gate: reaching
    "running" requires an explicit input/approval step a crash cannot manufacture. Mirrors Go
    WorkflowGate / Rust WorkflowGate: each WAL record is a 4-byte big-endian length prefix followed
    by `task NUL status`. Use open_workflow_gate() to construct one."""

    def __init__(self, path):
        self._lock = threading.Lock()
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        self._f = os.fdopen(fd, "r+b")
        self._status = {}
        self._replay()

    def _replay(self):
        self._f.seek(0)
        while True:
            lb = self._f.read(4)
            if len(lb) == 0:
                break
            if len(lb) != 4:
                raise WorkflowGateMalformed("truncated length prefix")
            n = int.from_bytes(lb, "big")
            rec = self._f.read(n)
            if len(rec) != n:
                raise WorkflowGateMalformed("truncated record")
            nul = rec.find(b"\x00")
            if nul < 0:
                raise WorkflowGateMalformed("workflow gate record")
            task = rec[:nul].decode("utf-8")
            status = rec[nul + 1:].decode("utf-8")
            self._status[task] = status

    def _persist(self, task, status):
        rec = task.encode("utf-8") + b"\x00" + status.encode("utf-8")
        framed = len(rec).to_bytes(4, "big") + rec
        self._f.seek(0, os.SEEK_END)
        self._f.write(framed)
        self._f.flush()
        os.fsync(self._f.fileno())  # persist-before-ack (spine §9.2)
        self._status[task] = status

    def create(self, task: str, needs_approval: bool) -> None:
        """Record a new task in a non-terminal pre-gate status. TaskCreate never lands in
        "running": it lands in "awaiting-input" (or "awaiting-approval"), persisted before
        returning. Raises TaskStateError if the task already exists."""
        with self._lock:
            if task in self._status:
                raise TaskStateError("task already exists")
            self._persist(task, "awaiting-approval" if needs_approval else "awaiting-input")

    def supply_input(self, task: str) -> None:
        """Advance a task past its input gate (awaiting-input -> input-supplied) or approval gate
        (awaiting-approval -> approved). Only these transitions may precede run()."""
        with self._lock:
            s = self._status.get(task)
            if s == "awaiting-input":
                self._persist(task, "input-supplied")
            elif s == "awaiting-approval":
                self._persist(task, "approved")
            else:
                raise TaskStateError("task not awaiting input or approval")

    def run(self, task: str) -> None:
        """Move a task to "running" only if it has passed the gate. A task still "awaiting-input"
        or "awaiting-approval" cannot run: that is InputGateBypass, and it is forbidden. An unknown
        task is TaskStateError."""
        with self._lock:
            s = self._status.get(task)
            if s in ("input-supplied", "approved"):
                self._persist(task, "running")
            elif s in ("awaiting-input", "awaiting-approval"):
                raise InputGateBypass("a task reached running without passing the input/approval gate")
            else:
                raise TaskStateError("task not in a runnable state")

    def status(self, task: str):
        """The task's durable status, or None if the task is unknown."""
        with self._lock:
            return self._status.get(task)

    def close(self) -> None:
        """Flush and close the WAL."""
        with self._lock:
            self._f.close()


def open_workflow_gate(path) -> WorkflowGate:
    """Open (creating if needed) a WAL-backed workflow gate at path and replay it (mirrors Go
    OpenWorkflowGate / Rust open_workflow_gate)."""
    return WorkflowGate(path)
