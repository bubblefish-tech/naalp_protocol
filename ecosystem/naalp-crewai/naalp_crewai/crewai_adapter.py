# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
The N-AALP Governance Kit's reference framework adapter for CrewAI (ecosystem-viral-wire
design.md sec.2.1 "Framework adapters (G1)"; requirements.md AC-1.1.*).

Verified against the CURRENTLY INSTALLED `crewai` package (1.15.20, on a Python 3.13
interpreter -- see the "why Python 3.13" note below) this session, per Section B1/E8 (never
build a framework integration from training-data memory of a young, moving plugin API): the D5
ranking pass (a dated 2026-09-07 research pass) characterized
CrewAI's OSS human-approval surface from `docs.crewai.com` pages read the same day as "guardrail
(post-hoc, on the task's FINAL output) + event bus (documented as observational)" -- i.e. no
clean pre-effect gate. Reading the ACTUALLY INSTALLED 1.15.20 source (never the docs) found a
newer, undocumented-on-those-pages mechanism that supersedes that finding:

    from crewai.hooks import register_before_tool_call_hook, HookAborted
    register_before_tool_call_hook(fn)   # fn(ToolCallHookContext) -> bool | None
                                          #   False, or raising HookAborted, BLOCKS the tool
                                          #   BEFORE it ever runs; True/None allows it.

Confirmed live this session, by reading `crewai/utilities/tool_utils.py` (both the sync
`execute_tool_and_check_finality` and the async `aexecute_tool_and_check_finality`) and then
DRIVING it directly with a real `crewai.tools.structured_tool.CrewStructuredTool` and a real
`crewai.agents.parser.AgentAction` (no LLM, no Crew.kickoff() needed -- `agent`/`task`/`crew` are
all optional on this call): `run_before_tool_call_hooks(hook_context)` is called and, on a block,
the wrapped tool's own Python callable is NEVER invoked -- confirmed by an actual side-effecting
call counter that stayed at zero. This is therefore a REAL pre-effect interception point, not a
"gate at whichever hook CAN, with an honest limitation" fallback the requirement anticipated
CrewAI might force; the limitation this module actually carries is narrower and is stated in
`NaalpCrewAIGuard`'s own docstring below (synchronous-only decision, no cross-process durable
suspend the way LangGraph's `interrupt()` provides).

**The one safety-critical property this reading also surfaced (RED-EVIDENCE M1's whole reason
to exist):** CrewAI's hook dispatcher, `crewai/hooks/dispatch.py`, states in its own module
docstring "`HookAborted` propagates by design. Any other exception raised by a hook is swallowed
(fail-open) to preserve the framework's protection against a buggy user hook." Confirmed live
this session: a `before_tool_call` hook that raises a plain `ValueError` does NOT block the tool
-- the tool still runs, with only a stdout warning printed when the executing agent is verbose.
This means a naive port of the ADK/LangGraph adapters' style (let `naalp.policy.PolicyError` /
`naalp.approval.ApprovalError` propagate as ordinary Python exceptions out of the gate) would be
a SILENT FAIL-OPEN on CrewAI: a real, correctly-computed authorization/approval refusal would be
swallowed by CrewAI's own dispatcher and the destructive tool call would proceed anyway. Every
refusal path in `NaalpCrewAIGuard.before_tool_call_hook` is therefore wrapped so it re-raises as
`crewai.hooks.HookAborted` explicitly -- never a bare core exception -- which IS the one exception
class CrewAI's dispatcher propagates rather than swallowing (confirmed live: a `HookAborted` hook
correctly blocks; the wrapped tool's call counter never advances).

**Why Python 3.13, not 3.14, for this one adapter:** every released `crewai` version (checked
live via `pip index versions crewai`, 2026-09-07) declares `Requires-Python >=3.10,<3.14` --
`crewai` genuinely cannot be installed on the repo's default Python 3.14.3 interpreter (a real,
currently-true upstream constraint, not a stale or memory-based one); a separate Python 3.13.13
interpreter is already present on this development machine and crewai + pytest install and run
cleanly on it (its path is machine-specific and therefore not written into this repo-committed
file -- see RED-EVIDENCE.md for the exact run command, which names the interpreter as a
placeholder). This module and its tests import only the already-source-only
`naalp`/`naalp_kit`/`naalp_hitl` packages, which run unchanged under 3.13.

Uses the SAME generic foreign-carriage surface `naalp_adk_plugin.adk_plugin` and
`naalp_langgraph.langgraph_adapter` use (`naalp.channels.TABLE[13] ==
('Bridge', [(0, 'Carriage', 0, True)])`, variable effect) -- CrewAI, like ADK and LangGraph, is a
framework this protocol does not natively know the shape of; this module never invents a new
(channel, kind) pair of its own. `canonical_json_bytes`, `ChainRecorder`, and the deterministic
args -> `naalp.cbor` Value encoder are duplicated locally rather than imported from
`naalp_langgraph` -- same convention as every other ecosystem package (each is independently
installable).

design.md sec.2.1's canonical adapter contract, specialised here to CrewAI's real hook:

    on_effecting_action(action, args, ctx) ->
        effect = classify(action)                      # closed lattice; unknown -> destructive
        require authorize(principal, effect, audience)  # else refuse (UNCONDITIONAL)
        if effect in {non_idempotent, destructive}:
            approval = hitl.request(content_id(action,args))  # single-use, args-bound
            require approval.valid                       # else refuse + D6 audit
        result = forward(action, args)
        return receipt.sign(action, args, principal, effect, result_hash)

split across CrewAI's two real, separate hook calls: `before_tool_call_hook` performs classify ->
authorize -> gate (raising `HookAborted` on any refusal, so `forward()` -- CrewAI's own real tool
invocation -- is never reached); `after_tool_call_hook` performs the receipt.sign(...) step once
CrewAI has already produced the real result, using the SAME `context.tool_input` object the
before-hook may have mutated in place for an `edit` outcome (CrewAI passes the identical dict
instance to both calls for one tool call -- confirmed live this session: mutating
`context.tool_input` in `before_tool_call_hook` changes the arguments the wrapped tool function
actually receives).
"""
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before naalp/naalp_kit/naalp_hitl imports)

from naalp_kit import binding
from naalp import approval, cbor, policy
from naalp.cbor import U, N, B, T, A, M

from naalp_hitl.durable import DurableHITLInterceptor, Reject, Approve, Edit

try:
    from crewai.hooks import HookAborted, register_before_tool_call_hook as _crewai_register_before
    from crewai.hooks import register_after_tool_call_hook as _crewai_register_after
    from crewai.hooks import unregister_before_tool_call_hook as _crewai_unregister_before
    from crewai.hooks import unregister_after_tool_call_hook as _crewai_unregister_after
except ImportError as _e:  # pragma: no cover -- exercised only in an environment without crewai
    raise ImportError(
        "naalp_crewai requires the 'crewai' package (NaalpCrewAIGuard registers real "
        "crewai.hooks.register_before_tool_call_hook/register_after_tool_call_hook callbacks); "
        "install it with `pip install crewai` (crewai requires Python >=3.10,<3.14)."
    ) from _e


# The generic foreign-carriage surface (design.md sec.13; naalp.channels.TABLE[13] == ('Bridge',
# [(0, 'Carriage', 0, True)])) -- variable effect, exactly the "framework this protocol does not
# natively know" case this adapter exists for. This module never invents a new (channel, kind)
# pair of its own -- the same registered surface naalp_adk_plugin (K1, ADK) and naalp_langgraph
# already use.
CHANNEL_BRIDGE = 0x000D
KIND_CARRIAGE = 0


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding for an opaque CrewAI tool-call payload (tool name + args, or
    a call+result pair) before it becomes a K0 CapturedAction.payload -- same convention as
    naalp_langgraph.langgraph_adapter.canonical_json_bytes / naalp_adk_plugin.adk_plugin.
    canonical_json_bytes, kept local (each ecosystem package is independently installable). K0
    never parses this back out (K0-4); it exists only so the SAME logical tool call/result
    produces the SAME payload bytes run to run, for content-id stability."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class ChainRecorder:
    """This adapter's append-only, length-prefixed session log -- a local copy of
    naalp_langgraph.langgraph_adapter.ChainRecorder's / naalp_adk_plugin.adk_plugin.
    ChainRecorder's exact contract (each ecosystem package is independently installable), so a
    CrewAI deployment gets the same causal-chaining provenance a LangGraph or ADK deployment
    already gets.

    Each record is a 4-byte big-endian length prefix followed by the exact signed N-AALP object
    bytes, written to a caller-supplied binary stream. ChainRecorder performs NO cryptography and
    computes NO content ids itself: the caller (NaalpCrewAIGuard, below) already knows each
    object's real content id, obtained from `naalp_kit.binding.sign_action` +
    `naalp_kit.binding.verify_action` -- the same core the object was checked against, never
    invented or independently derived here (F3, non-circular)."""

    def __init__(self, stream):
        self._stream = stream
        self._last_id: Dict[str, bytes] = {}

    def append(self, session_key: str, signed_bytes: bytes, content_id: bytes) -> None:
        """Persist one signed object and record it as the new head of `session_key`'s chain."""
        if not isinstance(signed_bytes, (bytes, bytearray)):
            raise TypeError("ChainRecorder.append: signed_bytes must be raw octets")
        if not isinstance(content_id, (bytes, bytearray)) or len(content_id) == 0:
            raise TypeError("ChainRecorder.append: content_id must be non-empty raw octets")
        import struct
        record = struct.pack(">I", len(signed_bytes)) + bytes(signed_bytes)
        self._stream.write(record)
        flush = getattr(self._stream, "flush", None)
        if flush is not None:
            flush()
        self._last_id[str(session_key)] = bytes(content_id)

    def last_cause(self, session_key: str) -> Tuple[bytes, ...]:
        """The `causes` tuple for the NEXT CapturedAction in this session: empty if this is the
        first object recorded for `session_key`, else a one-element tuple holding the most
        recently appended object's content id."""
        prev = self._last_id.get(str(session_key))
        return (prev,) if prev is not None else ()

    @staticmethod
    def read_all(stream) -> Sequence[bytes]:
        """Read every length-prefixed record back out of a log stream, in append order. Raises
        ValueError on a truncated length-prefix or record (a corrupted/incomplete log is never
        silently accepted as complete)."""
        import struct
        records = []
        while True:
            header = stream.read(4)
            if not header:
                break
            if len(header) != 4:
                raise ValueError("ChainRecorder log truncated mid-length-prefix")
            (n,) = struct.unpack(">I", header)
            payload = stream.read(n)
            if len(payload) != n:
                raise ValueError("ChainRecorder log truncated mid-record")
            records.append(payload)
        return records


# ---- deterministic tool-input -> naalp.cbor Value, for content-id binding only -----------------
#
# A local, adapter-owned convention (never a registered N-AALP wire schema, never decoded back by
# anything) -- identical in shape to naalp_langgraph.langgraph_adapter's own encoder -- that maps
# an arbitrary JSON-safe CrewAI `tool_input` dict onto naalp.cbor's Value ADT deterministically and
# totally, purely so `naalp.cbor.content_id()` can bind an approval to the EXACT args a human is
# asked to approve (design.md sec.7.1: changing any argument changes the content id).
_NULL_SENTINEL = "\x00naalp-crewai-null\x00"  # a text value no real string arg is expected to collide with


def _to_cbor_value(v: Any):
    if isinstance(v, bool):
        return U(1) if v else U(0)
    if isinstance(v, int):
        return U(v) if v >= 0 else N(v)
    if isinstance(v, float):
        return T(repr(v))  # no float major type in this Value ADT; deterministic text form
    if v is None:
        return T(_NULL_SENTINEL)
    if isinstance(v, (bytes, bytearray)):
        return B(bytes(v))
    if isinstance(v, str):
        return T(v)
    if isinstance(v, (list, tuple)):
        return A([_to_cbor_value(x) for x in v])
    if isinstance(v, dict):
        return M([(T(str(k)), _to_cbor_value(val)) for k, val in v.items()])
    raise TypeError("naalp_crewai: cannot bind a content id to a %r value" % (type(v),))


def args_content_id(tool_input: Dict[str, Any]) -> bytes:
    """The exact args content id a CrewAI tool call's approval is bound to -- a pure pass-through
    to the real `naalp.cbor.content_id` (S-3: always 50 bytes) over this module's own
    deterministic args encoding, above."""
    return cbor.content_id(_to_cbor_value(dict(tool_input)))


def _jsonable(value: Any) -> Any:
    """Best-effort recursive coercion of an arbitrary tool result into a JSON-encodable shape for
    canonical_json_bytes, WITHOUT interpreting its meaning (this adapter never decides what a
    tool result "means" -- this only makes it representable as opaque bytes). Local copy of
    naalp_langgraph.langgraph_adapter._jsonable's / naalp_adk_plugin.adk_plugin._jsonable's exact
    contract."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return _jsonable(model_dump())
        except Exception:  # noqa: BLE001 -- fall through to repr below
            pass
    try:
        json.dumps(value)
        return value
    except TypeError:
        return repr(value)


class MalformedDecision(TypeError):
    """Raised when this adapter's decision source (the injectable `decision_fn`) returns a value
    that is not one of the three documented decision shapes (True / False / a dict of edited
    args) -- a defect in the caller's decision-source code, not a Part-1/K0/G2 error with an
    analogue of its own (mirrors naalp_langgraph.langgraph_adapter.MalformedResumeDecision and
    naalp_kit.binding's own SignFailed/MalformedBody convention: a named error for a "no Part-1
    analogue" outcome, never silently coerced into one of the three valid shapes)."""


@dataclass(frozen=True)
class Receipt:
    """What `NaalpCrewAIGuard.after_tool_call_hook` records once a gated (or ungated) CrewAI
    tool call has actually executed: design.md's `receipt.sign(action, args, principal, effect,
    result_hash)`. `signed_bytes` is the real signed N-AALP object (byte-identical, for its
    N-AALP object fields, to the Go/Rust reference for the same logical effect -- AC-1.1.2);
    `content_id` is that object's real content id (naalp_kit.binding.VerifiedAction.content_id,
    S-3: 50 bytes)."""

    signed_bytes: bytes
    content_id: bytes
    effect: int
    causes: Sequence[bytes]


@dataclass(frozen=True)
class _PendingGate:
    """Correlates one `before_tool_call_hook` call with its matching, LATER,
    `after_tool_call_hook` call for the SAME CrewAI tool call. CrewAI constructs a fresh
    `ToolCallHookContext` object for each of the two calls, so `id(context)` cannot be used to
    correlate them -- but `context.tool_input` is the SAME dict object (`tool_calling.arguments`)
    across both calls for one tool call (confirmed live this session), so `id(context.tool_input)`
    is this module's correlation key. `cleared=True` means the gate was passed (authorized and,
    if required, approved) and the tool actually ran or is about to; `cleared=False` means the
    gate refused the call (an exception was raised and translated into HookAborted before this
    entry could be marked cleared) -- `after_tool_call_hook` uses this to avoid emitting a
    "receipt" (which design.md's error table forbids: "no receipt claiming success") for a call
    that was blocked before it ever executed."""

    session_key: str
    effect: int
    cleared: bool = False


EffectClassifier = Callable[[str, Dict[str, Any]], Optional[int]]
DecisionFn = Callable[[Any, bytes, int, str, str], Any]  # (context, pause_content_id, effect, kind, args_summary) -> True/False/dict


class NaalpCrewAIGuard:
    """The N-AALP Governance Kit's reference framework adapter for CrewAI (design.md 2.1, G1):
    intercepts a CrewAI tool call at the real `crewai.hooks.register_before_tool_call_hook`/
    `register_after_tool_call_hook` seam and routes it through the foundation -- classify effect
    (closed lattice; unknown -> destructive, K0-3), audience-bound authorize (else refuse,
    UNCONDITIONALLY -- design.md's pseudocode never makes this an opt-in mode), gate
    non-idempotent/destructive effects through the durable G2 HITL approval bound to the EXACT
    args, then emit a PQ-signed (ML-DSA, via the real Part-1 core) receipt once CrewAI has
    actually run the tool. Fails closed throughout: an unrecognized effect defaults to
    DESTRUCTIVE (never a guessed benign default); a denied authorization, a rejected approval, an
    invalid/expired/mismatched/already-consumed approval, or any other internal failure of this
    adapter's own gate all become `crewai.hooks.HookAborted` -- the ONE exception class CrewAI's
    dispatcher does not silently swallow (module docstring) -- so the tool's own callable is
    NEVER reached on a refusal.

    **Honest limitation (distinct from the LangGraph landmark adapter):** CrewAI's
    `before_tool_call` hook is a single, fully synchronous Python call that must return within
    that one call -- there is no CrewAI-native equivalent of LangGraph's `interrupt()`, which
    suspends the ENTIRE graph run and lets a genuinely separate, later process resume it via
    `Command(resume=...)`. This adapter still uses the durable, crash-safe
    `naalp_hitl.durable.DurableHITLInterceptor` (`pause()` persists before any decision is
    solicited, exactly as it does for the LangGraph adapter, so a crash between `pause()` and the
    decision is recoverable by a separate process calling `interceptor.resume()` against the same
    `store_dir`), but under normal operation the human decision is obtained SYNCHRONOUSLY, inside
    the one hook call, via the injectable `decision_fn` (defaulting to CrewAI's own
    `context.request_human_input()` blocking terminal prompt) -- never via a real cross-process
    suspend. `decision_fn` follows the identical True/False/dict-of-edited-args protocol
    `naalp_langgraph.langgraph_adapter` maps LangGraph's `Command(resume=...)` onto, so a caller
    that already has a synchronous decision source (a queue, a web callback already resolved,
    a test double) can supply it directly without touching a terminal.

    `signer` is this adapter's own N-AALP signing identity (the AGENT/service principal whose
    grant authorizes each effecting action). `grant` is the `naalp.policy.Grant` every captured
    action's declared effect is authorized against -- REQUIRED (never optional; design.md 2.1's
    `on_effecting_action` makes `require authorize(...)` an unconditional step). `interceptor` is
    the caller-constructed `naalp_hitl.durable.DurableHITLInterceptor` this adapter gates
    non-idempotent/destructive effects through -- this module owns none of its ledger,
    refusal-log, or single-use-marker state; it only supplies the ORIGINAL missing half, a real
    signed ApprovalRecord minted from `approver_seed` the moment a decision arrives. `audience`
    MUST be the same audience string `interceptor` was itself constructed with."""

    def __init__(
        self,
        signer: "Any",  # naalp.ez.Signer
        recorder: ChainRecorder,
        interceptor: DurableHITLInterceptor,
        grant: "policy.Grant",
        *,
        audience: str,
        approver_id: str,
        approver_alg: int,
        approver_seed: bytes,
        decision_fn: Optional[DecisionFn] = None,
        approval_grant_effect: Optional[int] = None,
        approval_validity_ms: int = 5 * 60 * 1000,
        effect_classifier: Optional[EffectClassifier] = None,
        nonce_fn: Optional[Callable[[], bytes]] = None,
    ):
        self._signer = signer
        self._recorder = recorder
        self._interceptor = interceptor
        self._grant = grant
        self._audience = audience
        self._approver_id = approver_id
        self._approver_alg = approver_alg
        self._approver_seed = bytes(approver_seed)
        self._decision_fn = decision_fn or self._default_decision_fn
        self._approval_grant_effect = approval_grant_effect
        self._approval_validity_ms = approval_validity_ms
        self._effect_classifier = effect_classifier
        if nonce_fn is None:
            import os as _os
            nonce_fn = lambda: _os.urandom(16)  # noqa: E731
        self._nonce_fn = nonce_fn
        self._pending: Dict[int, _PendingGate] = {}
        self._receipts_by_session: Dict[str, List[Receipt]] = {}

    # -- registration: wire this guard into CrewAI's real, process-global hook lists -------

    def install(self) -> None:
        """Register this guard's `before_tool_call_hook`/`after_tool_call_hook` on CrewAI's real,
        process-global hook registries (`crewai.hooks.register_before_tool_call_hook`/
        `register_after_tool_call_hook`) -- these are the SAME lists
        `crewai.utilities.tool_utils.execute_tool_and_check_finality` reads from for every real
        tool call, in every Crew/Agent/LiteAgent in this process."""
        _crewai_register_before(self.before_tool_call_hook)
        _crewai_register_after(self.after_tool_call_hook)

    def uninstall(self) -> None:
        """The inverse of install() -- removes this guard's two hooks from CrewAI's global
        registries. Safe to call even if install() was never called (returns quietly)."""
        _crewai_unregister_before(self.before_tool_call_hook)
        _crewai_unregister_after(self.after_tool_call_hook)

    # -- shared plumbing (identical structure to naalp_langgraph's/naalp_adk_plugin's own K1/landmark) --

    def _classify_effect(self, kind: str, tool_input: Dict[str, Any]) -> Optional[int]:
        if self._effect_classifier is None:
            return None
        return self._effect_classifier(kind, dict(tool_input))

    def _session_key(self, context: Any) -> str:
        """CrewAI's `ToolCallHookContext` carries `task` (optionally None), not an explicit
        session/thread id the way LangGraph's `thread_id` or ADK's `invocation_id` do. When a
        real `crewai.task.Task` is present, its own stable `id` (a UUID4, `frozen=True` on the
        Task's own pydantic model) is the session key, so every tool call within one Task's
        execution chains together; outside a Task (a bare Agent/LiteAgent call, as this module's
        own unit tests exercise directly) every call shares one honest, explicitly-named
        fallback key rather than a fabricated per-call one."""
        task = getattr(context, "task", None)
        task_id = getattr(task, "id", None)
        return "crewai-task:%s" % (task_id,) if task_id is not None else "crewai:no-task"

    def _principal(self, context: Any) -> str:
        """Best-effort D6 audit "source" label from CrewAI's own `context.agent.role`, when an
        Agent is present -- an honest absence ("") when it is not, never a fabricated identity.
        This label is NEVER what authorization is decided against (that is always the SIGNER's
        own identity, checked by `naalp.policy.Grant.authorize_object` inside
        `binding.authorize_action`, unrelated to which CrewAI Agent happens to be attached to a
        given hook context) -- it only labels the D6 refusal-log entry a rejected approval
        produces."""
        agent = getattr(context, "agent", None)
        role = getattr(agent, "role", None) if agent is not None else None
        return str(role) if role else ""

    def _capture_and_record(
        self, session_key: str, payload: bytes, effect: Optional[int],
    ) -> Tuple["binding.VerifiedAction", bytes]:
        """Build a CapturedAction chained to this session's last recorded object, sign it
        through K0, self-verify it (through K0's own verify_action -- the same core path any
        other consumer of this log would use) to obtain its real content id, append it to the
        chain recorder, and return (VerifiedAction, signed_bytes). Raises K0's/the core's named
        errors directly (K0-5) -- there is no swallow-and-continue path here."""
        action = binding.CapturedAction(
            channel=CHANNEL_BRIDGE, kind=KIND_CARRIAGE, payload=payload,
            effect=effect, causes=self._recorder.last_cause(session_key),
        )
        signed = binding.sign_action(self._signer, action)
        verified = binding.verify_action(self._signer.public_key, signed)
        self._recorder.append(session_key, signed, verified.content_id)
        return verified, signed

    def _mint_approval(self, content_id: bytes, effect: int) -> Tuple["approval.ApprovalRecord", bytes]:
        """Mint and sign a REAL N-AALP ApprovalRecord binding `content_id`, using this adapter's
        own approver identity -- the role `naalp_hitl.frontend.TerminalFrontend.request_approval`
        plays for a terminal front end, specialised here to CrewAI's synchronous
        before_tool_call-hook substrate, which itself carries only a bare approve/reject/edit
        decision VALUE (via `decision_fn`), never a signed object. `grant` (the ApprovalRecord's
        own ceiling field, distinct from the K0 policy.Grant above) defaults to exactly the
        required effect unless the adapter was constructed with a higher
        `approval_grant_effect`."""
        grant_effect = effect if self._approval_grant_effect is None else self._approval_grant_effect
        record = approval.ApprovalRecord(
            content_id, self._approver_id, grant_effect, self._nonce_fn(),
            self._interceptor.now_ms() + self._approval_validity_ms, self._audience,
        )
        sig = approval.sign_approval(record, self._approver_alg, self._approver_seed)
        return record, sig

    def _decision_to_outcome(self, pause_content_id: bytes, decision: Any, original_args: Dict[str, Any]):
        """Map a `decision_fn` return value onto exactly one of `Reject()` / `Approve(record,
        sig)` / `Edit(new_args_cbor_value, record, sig)`, returning `(outcome, forwarded_args_
        dict)` -- the identical True/False/dict-of-edited-args protocol
        `naalp_langgraph.langgraph_adapter._decision_to_outcome` maps LangGraph's `Command(
        resume=...)` onto (G2's own approve/reject/edit triple, requirements.md AC-2.2.1)."""
        if decision is False:
            return Reject(), original_args
        if decision is True:
            paused = self._interceptor.store.load(pause_content_id)
            record, sig = self._mint_approval(pause_content_id, paused.effect)
            return Approve(record, sig), original_args
        if isinstance(decision, dict):
            edited_value = _to_cbor_value(dict(decision))
            edited_id = cbor.content_id(edited_value)
            paused = self._interceptor.store.load(pause_content_id)
            record, sig = self._mint_approval(edited_id, paused.effect)
            return Edit(edited_value, record, sig), dict(decision)
        raise MalformedDecision(
            "naalp_crewai: decision_fn must return True, False, or a dict of edited args -- "
            "got %r" % (decision,)
        )

    def _default_decision_fn(self, context: Any, pause_content_id: bytes, effect: int, kind: str,
                              args_summary: str) -> Any:
        """The production default decision source: CrewAI's own
        `ToolCallHookContext.request_human_input` (a real, blocking terminal prompt -- pauses
        CrewAI's live console output, reads a line from stdin, resumes it). Returns True on
        `'y'`/`'yes'`/`'approve'` (case-insensitive), False on anything else. This default has no
        way to express an `edit` decision interactively (there is no structured-args prompt on a
        bare terminal line) -- a caller that needs `edit` supplies its OWN `decision_fn` instead,
        exactly as `naalp_hitl.frontend.TerminalFrontend`'s own terminal front end is one
        concrete, replaceable `HumanInterface`."""
        prompt = (
            "N-AALP approval request -- kind=%r effect=%d content-id=%s\nargs: %s\n"
            "Approve? [y/N]: " % (kind, effect, pause_content_id.hex(), args_summary)
        )
        answer = context.request_human_input(prompt=prompt, default_message="Type 'y' to approve:")
        return answer.strip().lower() in ("y", "yes", "approve")

    # -- the real CrewAI hooks ---------------------------------------------------------------

    def before_tool_call_hook(self, context: Any) -> Optional[bool]:
        """The REAL pre-effect gate: registered on `crewai.hooks.register_before_tool_call_hook`,
        this is the function `crewai.utilities.tool_utils.execute_tool_and_check_finality` calls,
        for every real CrewAI tool call, BEFORE the wrapped tool's own callable ever runs
        (confirmed live this session -- see module docstring). Returns `None` to allow the call
        (CrewAI's own convention); on ANY refusal -- an authorization denial, a rejected/invalid/
        expired/mismatched/already-consumed approval, or a malformed decision -- raises
        `crewai.hooks.HookAborted` DIRECTLY (never lets a bare `naalp.policy.PolicyError` /
        `naalp.approval.ApprovalError` / this module's own `MalformedDecision` escape uncaught),
        because CrewAI's dispatcher silently swallows (fail-open) any exception that is not a
        `HookAborted` (module docstring) -- letting a core refusal escape as a bare exception
        here would be a SILENT FAIL-OPEN security defect, not a safe failure."""
        session_key = self._session_key(context)
        tool_input = context.tool_input
        payload = canonical_json_bytes({"tool": context.tool_name, "args": dict(tool_input)})
        try:
            effect = self._classify_effect(context.tool_name, tool_input)
            verified, _pre_signed = self._capture_and_record(session_key, payload, effect)
            effect = verified.effect  # K0-3's fail-closed default, cryptographically re-derived
            self._pending[id(tool_input)] = _PendingGate(session_key, effect, cleared=False)

            # AUTHORIZE -- UNCONDITIONAL (design.md: "require authorize(...) # else refuse"; never
            # gated behind an opt-in mode).
            binding.authorize_action(verified, self._grant)

            if self._interceptor.requires_approval(effect):
                args_summary = json.dumps(dict(tool_input), sort_keys=True)[:500]
                pause_content_id = self._interceptor.pause(
                    context.tool_name, effect, _to_cbor_value(dict(tool_input)),
                    args_summary=args_summary, principal=self._principal(context),
                )
                decision = self._decision_fn(context, pause_content_id, effect, context.tool_name, args_summary)
                outcome, final_args = self._decision_to_outcome(pause_content_id, decision, dict(tool_input))
                self._interceptor.resume(pause_content_id, outcome)  # raises, D6-audited, on any refusal
                if final_args != dict(tool_input):
                    # AC-2.2.1, at the CrewAI seam: mutate the SAME dict object CrewAI will
                    # actually call the tool with -- in place, never by rebinding the attribute
                    # (CrewAI's own docstring: "Do NOT replace the dict... will not affect the
                    # actual tool execution" -- confirmed live this session by counting real
                    # side-effecting calls before/after an in-place edit).
                    tool_input.clear()
                    tool_input.update(final_args)

            self._pending[id(tool_input)] = _PendingGate(session_key, effect, cleared=True)
            return None  # allow: CrewAI now calls the real tool
        except HookAborted:
            raise
        except (policy.PolicyError, approval.ApprovalError, binding.GovernanceKitError,
                MalformedDecision) as err:
            # A NAMED core/K0/G2 refusal -- translate to the one exception CrewAI's dispatcher
            # does not swallow (module docstring's fail-open finding).
            raise HookAborted(reason="%s: %s" % (getattr(err, "kind", type(err).__name__), err),
                               source=self) from err
        except Exception as err:  # noqa: BLE001 -- ANY other internal failure fails CLOSED too
            # CLAUDE.md: "FAIL-CLOSED: an object failing any check is rejected whole ... No
            # fail-open path, ever." An unexpected bug in this adapter's own code is exactly the
            # class of failure CrewAI's dispatcher would otherwise silently swallow into an
            # ALLOWED tool call -- that is never acceptable for an effect-authorization gate, so
            # it is translated to HookAborted like every named refusal above, not re-raised bare.
            raise HookAborted(reason="naalp_crewai internal error: %r" % (err,), source=self) from err

    def after_tool_call_hook(self, context: Any) -> Optional[str]:
        """Records the receipt.sign(...) step of design.md 2.1's contract, once CrewAI has
        actually produced a real result for a call this guard's before-hook cleared (never for a
        call it refused -- design.md's error table: "no receipt claiming success"). Registered on
        `crewai.hooks.register_after_tool_call_hook`; always returns `None` (never rewrites the
        tool's own result -- the receipt is exposed via `receipts_for()`/`last_receipt_for()`,
        never inlined into the LLM-facing text CrewAI returns). Never raises: an after-hook
        `HookAborted` propagates UNCAUGHT out of CrewAI's own `run_after_tool_call_hooks` (it has
        no enclosing try/except, unlike the before-hook path -- confirmed by reading
        `crewai/utilities/tool_utils.py`), so this hook catches its OWN failures internally
        rather than risk crashing an agent step over a receipt-recording defect after the real
        effect has already happened; a failure here is a best-effort miss (no receipt recorded
        for that call), never a raised exception."""
        tool_input = context.tool_input
        entry = self._pending.pop(id(tool_input), None)
        if entry is None or not entry.cleared:
            return None  # untracked, or a refused call this guard never cleared -- no receipt
        try:
            result_payload = canonical_json_bytes({
                "tool": context.tool_name, "args": dict(tool_input),
                "result": _jsonable(context.raw_tool_result), "effect": entry.effect,
            })
            receipt_verified, receipt_bytes = self._capture_and_record(
                entry.session_key, result_payload, entry.effect,
            )
        except Exception:  # noqa: BLE001 -- see docstring: never let this escape as an exception
            return None
        receipt = Receipt(
            signed_bytes=receipt_bytes, content_id=receipt_verified.content_id,
            effect=entry.effect, causes=receipt_verified.causes,
        )
        self._receipts_by_session.setdefault(entry.session_key, []).append(receipt)
        return None

    # -- receipt access (never inlined into a tool's own result) -----------------------------

    def receipts_for(self, session_key: str) -> List[Receipt]:
        """Every receipt recorded for `session_key`, in append order."""
        return list(self._receipts_by_session.get(session_key, ()))

    def last_receipt_for(self, session_key: str) -> Optional[Receipt]:
        """The most recently recorded receipt for `session_key`, or `None` if none yet."""
        receipts = self._receipts_by_session.get(session_key)
        return receipts[-1] if receipts else None


__all__ = [
    "NaalpCrewAIGuard",
    "ChainRecorder",
    "Receipt",
    "MalformedDecision",
    "CHANNEL_BRIDGE",
    "KIND_CARRIAGE",
    "canonical_json_bytes",
    "args_content_id",
]
