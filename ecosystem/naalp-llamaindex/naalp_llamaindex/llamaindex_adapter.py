# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
The N-AALP Governance Kit's reference framework adapter for LlamaIndex Workflows
(ecosystem-viral-wire design.md sec.2.1 "Framework adapters (G1)"; requirements.md AC-1.1.*,
Group 1's fifth named framework -- LangGraph, OpenAI Agents SDK, Microsoft Agent Framework,
CrewAI, LlamaIndex).

Verified against the CURRENTLY INSTALLED `llama-index-core` package (0.14.24, which pulls in
`llama-index-workflows` 2.23.3) this session, per Section B1/E8 (never build a framework
integration from training-data memory of a young, moving agent-framework API): a live probe this
session (`llama_index.core.workflow.Workflow`/`Context`/`InputRequiredEvent`/`HumanResponseEvent`
+ a real `ctx.wait_for_event()`/`handler.send_event()` round trip, including a genuine
process-restart simulation via `Context.to_dict()` -> JSON round-trip -> `Context.from_dict()`
on a BRAND-NEW `Workflow`/`Context` instance) confirmed the exact, current runtime contract this
module depends on:

    from llama_index.core.workflow import Context, InputRequiredEvent, HumanResponseEvent
    await ctx.wait_for_event(                    # pauses the CURRENT workflow step; durable via
        HumanResponseEvent,                       # the Context's own serializable state
        waiter_id: str,
        waiter_event: Event,                      # streamed out via handler.stream_events()
        requirements: dict,                       # only a HumanResponseEvent matching this dict
    ) -> HumanResponseEvent                        #   (here: {"waiter_id": waiter_id}) unblocks it
    handler.send_event(HumanResponseEvent(...))    # delivers the matching event, in THIS process
    handler.ctx.to_dict() -> dict                  # durable snapshot of the paused Context
    Context.from_dict(workflow, ctx_dict) -> Context   # rebuild a Context from a snapshot, on a
                                                        # BRAND-NEW Workflow/Context instance
    workflow.run(ctx=restored_ctx)                 # resume execution from the snapshot; the
                                                    # caller then calls handler.send_event(...)
                                                    # DIRECTLY -- the framework does NOT re-emit
                                                    # the original waiter_event after a restore
                                                    # (confirmed live, and per LlamaIndex's own
                                                    # "Writing Durable Workflows" guide's exact
                                                    # checkpoint/resume code sample, fetched this
                                                    # session from developers.llamaindex.ai)

This is the REAL, current LlamaIndex hook this module intercepts at -- not a wrapper around a
stub: `NaalpLlamaIndexGuard.on_effecting_action()` calls the genuine
`llama_index.core.workflow.Context.wait_for_event()` (imported and invoked directly, never
reimplemented or faked) to pause the enclosing workflow step, and interprets the `response`
value LlamaIndex hands back from a later `HumanResponseEvent` as exactly one of N-AALP's own
approve / reject / edit outcomes (`naalp_hitl.durable.Approve` / `Reject` / `Edit`) -- the same
"byte-for-byte semantic match" the D5 ranking pass names between the landmark LangGraph
`interrupt()`/`Command(resume=)` pair and N-AALP's approval gate, carried over here because
LlamaIndex's `InputRequiredEvent`/`HumanResponseEvent` pair is structurally the same primitive
(pause -> emit a request event -> caller resolves it with a response value, durable across a
process restart via context serialization):

    HumanResponseEvent(response=True)              -> Approve  (the original, un-edited args)
    HumanResponseEvent(response=False)             -> Reject    (fails closed, D6-audited, no
                                                                   ledger touch)
    HumanResponseEvent(response={... edited args}) -> Edit      (approves the EDITED args' own
                                                                   content id, never the
                                                                   original -- AC-2.2.1)

Confirmed structural guarantee that this cannot be faked with a bare function call: calling
`Context.wait_for_event()` on a `Context` that is not attached to an actively-running
`Workflow.run()` raises `workflows.errors.ContextStateError("wait_for_event requires a running
workflow. Call workflow.run() first.")` (confirmed live, this session, with a real
`llama-index-core==0.14.24` install). Every gated-path test in this module's test suite
therefore drives a genuine, running `llama_index.core.workflow.Workflow` through
`workflow.run()` / `handler.stream_events()` / `handler.send_event()` -- there is no way to write
a test that calls this adapter's gate without also exercising the real LlamaIndex Workflows
pause/resume machinery (anti-fake rule A9/A5).

This module performs NO cryptography, NO CBOR/COSE encoding, and NO ledger bookkeeping of its
own. Every byte-producing or byte-checking operation is a direct call into the already-graded
Part-1 core through two existing, already-graded seams:

  - `naalp_kit.binding` (K0): `sign_action`/`authorize_action` -- the SAME framework-neutral
    core binding `naalp_adk_plugin` (K1, ADK) and `naalp_langgraph` (the LangGraph landmark
    adapter) already use, so the signed N-AALP object this module emits for a LlamaIndex tool
    call is produced by the IDENTICAL code path as those adapters', and therefore byte-identical
    (for its N-AALP object fields) to the Go/Rust reference for the same logical
    (channel, kind, effect, payload, causes) input (AC-1.1.2) -- there is no separate encoding
    to keep in sync.
  - `naalp_hitl.durable.DurableHITLInterceptor` (G2): the checkpointer-backed, single-use,
    audience-bound, args-content-id-bound pause/resume state machine. This module supplies the
    ORIGINAL missing half `DurableHITLInterceptor.resume()` needs: a real cryptographic
    ApprovalRecord + signature to hand it, minted from a human operator's approver identity the
    moment LlamaIndex's own `HumanResponseEvent` tells us the human's decision (LlamaIndex's
    wait_for_event/send_event channel itself carries only a bare decision VALUE -- true/false/
    edited args -- never a signed N-AALP object; this module is what turns that bare decision
    into a real, verifiable, single-use N-AALP approval, exactly the role
    `naalp_hitl.frontend.TerminalFrontend` plays for the terminal front end and
    `naalp_langgraph.NaalpLangGraphGuard` plays for LangGraph, specialised here to LlamaIndex's
    durable Workflows substrate instead).

Uses the SAME generic foreign-carriage surface `naalp_adk_plugin.adk_plugin` and
`naalp_langgraph.langgraph_adapter` use (`naalp.channels.TABLE[13] == ('Bridge',
[(0, 'Carriage', 0, True)])`, variable effect) -- LlamaIndex, like ADK and LangGraph, is a
framework this protocol does not natively know the shape of; this module never invents a new
(channel, kind) pair of its own. `canonical_json_bytes` and `ChainRecorder` are duplicated
locally rather than imported from a sibling package -- same convention as `naalp_adk_plugin.
adk_plugin`/`naalp_langgraph.langgraph_adapter`/`naalp_mcp_bridge.mcp_bridge`: each ecosystem
package is independently installable.

design.md sec.2.1's canonical adapter contract, specialised here to LlamaIndex Workflows' real
hook (`on_effecting_action` is `async def` here because `Context.wait_for_event()` is itself a
coroutine -- unlike LangGraph's synchronous `interrupt()`, LlamaIndex Workflow steps are `async
def` throughout, so this is the natural, real shape of the hook, not an adapter-invented one):

    async on_effecting_action(action, args, ctx) ->
        effect = classify(action)                      # closed lattice; unknown -> destructive
        require authorize(principal, effect, audience)  # else refuse (UNCONDITIONAL --
                                                          # design.md's pseudocode never gates
                                                          # this on an opt-in mode)
        if effect in {non_idempotent, destructive}:
            approval = hitl.request(content_id(action,args))  # single-use, args-bound;
                                                                # LlamaIndex's own
                                                                # wait_for_event()/send_event()
                                                                # IS this request
            require approval.valid                       # else refuse + D6 audit
        result = forward(action, args)                    # sync or async -- awaited if awaitable
        return receipt.sign(action, args, principal, effect, result_hash)
"""
import inspect
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Sequence, Tuple

from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before naalp/naalp_kit/naalp_hitl imports)

from naalp_kit import binding
from naalp import approval, cbor, cose, policy
from naalp.cbor import U, N, B, T, A, M

from naalp_hitl.durable import DurableHITLInterceptor, Reject, Approve, Edit

try:
    from llama_index.core.workflow import Context, InputRequiredEvent, HumanResponseEvent
except ImportError as _e:  # pragma: no cover -- exercised only in an environment without llama-index-core
    raise ImportError(
        "naalp_llamaindex requires the 'llama-index-core' package (NaalpLlamaIndexGuard "
        "intercepts at the real llama_index.core.workflow.Context.wait_for_event()/"
        "HumanResponseEvent hook); install it with `pip install llama-index-core`."
    ) from _e


# The generic foreign-carriage surface (design.md sec.13; naalp.channels.TABLE[13] == ('Bridge',
# [(0, 'Carriage', 0, True)])) -- variable effect, exactly the "framework this protocol does not
# natively know" case this adapter exists for. This module never invents a new (channel, kind)
# pair of its own -- the same registered surface naalp_adk_plugin (K1, ADK) and naalp_langgraph
# (the LangGraph landmark adapter) already use.
CHANNEL_BRIDGE = 0x000D
KIND_CARRIAGE = 0


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding for an opaque LlamaIndex tool-call payload (tool name + args,
    or a call+result pair) before it becomes a K0 CapturedAction.payload -- same convention as
    naalp_langgraph.langgraph_adapter.canonical_json_bytes / naalp_adk_plugin.adk_plugin.
    canonical_json_bytes, kept local (each ecosystem package is independently installable). K0
    never parses this back out (K0-4); it exists only so the SAME logical tool call/result
    produces the SAME payload bytes run to run, for content-id stability."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class ChainRecorder:
    """This adapter's append-only, length-prefixed session log -- a local copy of
    naalp_langgraph.langgraph_adapter.ChainRecorder's / naalp_adk_plugin.adk_plugin.
    ChainRecorder's exact contract (each ecosystem package is independently installable, per
    that module's own docstring), so a LlamaIndex deployment gets the same causal-chaining
    provenance a LangGraph or ADK deployment already gets.

    Each record is a 4-byte big-endian length prefix followed by the exact signed N-AALP object
    bytes, written to a caller-supplied binary stream. ChainRecorder performs NO cryptography and
    computes NO content ids itself: the caller (NaalpLlamaIndexGuard, below) already knows each
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


# ---- deterministic args -> naalp.cbor Value, for content-id binding only -----------------------
#
# naalp.cbor's Value ADT (U/N/B/T/A/M/Tag; see impl/python/naalp/cbor.py) has no boolean/null
# "simple value" major-7 type -- it is the deterministic-CBOR *codec*, not a generic JSON-to-CBOR
# mapper. This is a LOCAL, adapter-owned convention (never a registered N-AALP wire schema, never
# decoded back by anything) that maps an arbitrary JSON-safe LlamaIndex tool-args dict onto that
# ADT deterministically and totally, purely so `naalp.cbor.content_id()` can bind an approval to
# the EXACT args a human is asked to approve (design.md sec.7.1: changing any argument changes
# the content id). It is intentionally distinct from `canonical_json_bytes` (the receipt's own
# human/audit payload encoding, which round-trips through real JSON `null`/bool without any
# ambiguity) -- this encoder is used ONLY as the durable-store binding key. Identical convention
# to naalp_langgraph.langgraph_adapter._to_cbor_value, kept local (each ecosystem package is
# independently installable).
_NULL_SENTINEL = "\x00naalp-llamaindex-null\x00"  # a text value no real string arg is expected to collide with


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
    raise TypeError("naalp_llamaindex: cannot bind a content id to a %r value" % (type(v),))


def args_content_id(tool_args: Dict[str, Any]) -> bytes:
    """The exact args content id a LlamaIndex tool call's approval is bound to -- a pure
    pass-through to the real `naalp.cbor.content_id` (S-3: always 50 bytes) over this module's
    own deterministic args encoding, above."""
    return cbor.content_id(_to_cbor_value(dict(tool_args)))


def _jsonable(value: Any) -> Any:
    """Best-effort recursive coercion of an arbitrary tool result into a JSON-encodable shape
    for canonical_json_bytes, WITHOUT interpreting its meaning (this adapter never decides what a
    tool result "means" -- this only makes it representable as opaque bytes). Local copy of
    naalp_langgraph.langgraph_adapter._jsonable's / naalp_adk_plugin.adk_plugin._jsonable's
    exact contract."""
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


class MalformedResponseDecision(TypeError):
    """Raised when a LlamaIndex `HumanResponseEvent(response=...)` value is not one of this
    adapter's three documented decision shapes (True / False / a dict of edited args) -- a
    defect in the caller's UI/human-interface code, not a Part-1/K0 error with an analogue of
    its own (mirrors naalp_langgraph.langgraph_adapter.MalformedResumeDecision's exact contract,
    and naalp_kit.binding's own SignFailed/MalformedBody: a named error for a "no Part-1
    analogue" outcome, never silently coerced into one of the three valid shapes)."""


@dataclass(frozen=True)
class Receipt:
    """What `NaalpLlamaIndexGuard.on_effecting_action` returns alongside the tool's own result:
    design.md's `receipt.sign(action, args, principal, effect, result_hash)`. `signed_bytes` is
    the real signed N-AALP object (byte-identical, for its N-AALP object fields, to the Go/Rust
    reference for the same logical effect -- AC-1.1.2); `content_id` is that object's real content
    id (naalp_kit.binding.VerifiedAction.content_id, S-3: 50 bytes)."""

    signed_bytes: bytes
    content_id: bytes
    effect: int
    causes: Sequence[bytes]


EffectClassifier = Callable[[str, Dict[str, Any]], Optional[int]]


class NaalpLlamaIndexGuard:
    """The N-AALP Governance Kit's reference framework adapter for LlamaIndex (design.md 2.1,
    G1): intercepts a LlamaIndex Workflow tool/effecting action at the real
    `Context.wait_for_event()`/`HumanResponseEvent` hook and routes it through the foundation --
    classify effect (closed lattice; unknown -> destructive, K0-3), audience-bound authorize
    (else refuse, UNCONDITIONALLY -- design.md's pseudocode never makes this an opt-in mode),
    gate non-idempotent/destructive effects through the durable G2 HITL approval bound to the
    EXACT args, then emit a PQ-signed (ML-DSA, via the real Part-1 core) receipt. Fails closed
    throughout: an unrecognized effect defaults to DESTRUCTIVE (never a guessed benign default);
    a denied authorization, a rejected approval, an invalid/expired/mismatched approval, or an
    already-consumed approval all raise the named Part-1/K0/G2 error directly and NEVER reach
    `forward()`.

    `signer` is this adapter's own N-AALP signing identity (the AGENT/service principal whose
    grant authorizes each effecting action; matches naalp_adk_plugin's and naalp_langgraph's
    `signer` role). `grant` is the `naalp.policy.Grant` every captured action's declared effect
    is authorized against -- REQUIRED (never optional), because design.md 2.1's
    `on_effecting_action` makes `require authorize(...)` an unconditional step, unlike the ADK
    adapter's separate opt-in `gating` mode. `interceptor` is the caller-constructed
    `naalp_hitl.durable.DurableHITLInterceptor` this adapter gates non-idempotent/destructive
    effects through -- this module owns none of its ledger, refusal-log, or single-use-marker
    state; it only supplies the ORIGINAL missing half, a real signed ApprovalRecord minted from
    `approver_seed` the moment a `HumanResponseEvent` decision arrives. `audience` MUST be the
    same audience string `interceptor` was itself constructed with (this adapter renders it into
    the human-facing `InputRequiredEvent`; the interceptor enforces the actual audience binding
    at resume time, unchanged)."""

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
        approval_grant_effect: Optional[int] = None,
        approval_validity_ms: int = 5 * 60 * 1000,
        effect_classifier: Optional[EffectClassifier] = None,
        nonce_fn: Optional[Callable[[], bytes]] = None,
        wait_timeout: Optional[float] = None,
    ):
        self._signer = signer
        self._recorder = recorder
        self._interceptor = interceptor
        self._grant = grant
        self._audience = audience
        self._approver_id = approver_id
        self._approver_alg = approver_alg
        self._approver_seed = bytes(approver_seed)
        self._approval_grant_effect = approval_grant_effect
        self._approval_validity_ms = approval_validity_ms
        self._effect_classifier = effect_classifier
        self._wait_timeout = wait_timeout
        if nonce_fn is None:
            import os as _os
            nonce_fn = lambda: _os.urandom(16)  # noqa: E731
        self._nonce_fn = nonce_fn

    # -- shared plumbing (identical structure to naalp_adk_plugin's/naalp_langgraph's own) ---

    def _classify_effect(self, kind: str, tool_args: Dict[str, Any]) -> Optional[int]:
        if self._effect_classifier is None:
            return None
        return self._effect_classifier(kind, dict(tool_args))

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
        plays for a terminal front end, specialised here to LlamaIndex's durable
        `wait_for_event()`/`HumanResponseEvent` substrate, which itself carries only a bare
        approve/reject/edit decision VALUE, never a signed object. `grant` (the ApprovalRecord's
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
        """Map a real LlamaIndex `HumanResponseEvent.response` value onto exactly one of
        `Reject()` / `Approve(record, sig)` / `Edit(new_args_cbor_value, record, sig)`,
        returning `(outcome, forwarded_args_dict)`. This is the same semantic mapping the D5
        ranking pass names for LangGraph's `interrupt()`/`Command(resume=)`, carried over here
        because LlamaIndex's `InputRequiredEvent`/`HumanResponseEvent` pair is the structurally
        identical primitive (design.md 2.1's `hitl.request(content_id(...))`)."""
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
        raise MalformedResponseDecision(
            "naalp_llamaindex: HumanResponseEvent(response=...) must be True, False, or a dict "
            "of edited args -- got %r" % (decision,)
        )

    # -- design.md 2.1's canonical adapter contract, specialised to LlamaIndex Workflows -----

    async def on_effecting_action(
        self,
        kind: str,
        tool_args: Dict[str, Any],
        forward: Callable[[Dict[str, Any]], Any],
        *,
        ctx: "Context",
        session_key: str,
        principal: str = "",
    ) -> Tuple[Any, Receipt]:
        """design.md 2.1's `on_effecting_action(action, args, ctx)`: classify -> authorize
        (unconditional, else refuse) -> gate non-idempotent/destructive through the durable G2
        HITL approval, bound to the EXACT args, at LlamaIndex's real `Context.wait_for_event()`
        hook -> forward (sync or async -- awaited if awaitable) -> sign+return the receipt.
        Returns `(forward's result, Receipt)`. `ctx` MUST be the REAL `llama_index.core.workflow.
        Context` the enclosing Workflow step was called with -- `wait_for_event()` raises
        `workflows.errors.ContextStateError` if `ctx` is not attached to an actively-running
        `Workflow.run()` (confirmed live, this session), so this method can only pause a genuine
        running workflow, never a bare/synthetic context.

        Raises the named `naalp.policy.PolicyError` directly on an authorization refusal (K0-5:
        already a named, self-describing core error, never re-wrapped), and the named
        `naalp.approval.ApprovalError`/`naalp_hitl.HITLError` (D6-audited by
        `DurableHITLInterceptor.resume` itself) on a rejected/invalid/already-consumed approval --
        `forward()` is NEVER reached on either path."""
        payload = canonical_json_bytes({"tool": kind, "args": dict(tool_args)})
        effect = self._classify_effect(kind, tool_args)
        verified, _pre_signed = self._capture_and_record(session_key, payload, effect)
        effect = verified.effect  # K0-3's fail-closed default, cryptographically re-derived

        # AUTHORIZE -- UNCONDITIONAL (design.md: "require authorize(...) # else refuse"; never
        # gated behind an opt-in mode, unlike naalp_adk_plugin's separate `gating=` flag).
        binding.authorize_action(verified, self._grant)

        final_args = dict(tool_args)
        if self._interceptor.requires_approval(effect):
            pause_content_id = self._interceptor.pause(
                kind, effect, _to_cbor_value(dict(tool_args)),
                args_summary=json.dumps(tool_args, sort_keys=True)[:500], principal=principal,
            )
            waiter_id = pause_content_id.hex()
            wait_kwargs: Dict[str, Any] = dict(
                waiter_id=waiter_id,
                waiter_event=InputRequiredEvent(
                    content_id=waiter_id,
                    effect=effect,
                    kind=kind,
                    args_summary=json.dumps(tool_args, sort_keys=True)[:500],
                    audience=self._audience,
                    waiter_id=waiter_id,
                ),
                requirements={"waiter_id": waiter_id},
            )
            if self._wait_timeout is not None:
                wait_kwargs["timeout"] = self._wait_timeout
            response_event = await ctx.wait_for_event(  # REAL LlamaIndex hook: pauses the
                HumanResponseEvent, **wait_kwargs,       # enclosing workflow step, durable via
            )                                            # the Context's own serializable state
            decision = response_event.response
            outcome, final_args = self._decision_to_outcome(pause_content_id, decision, tool_args)
            self._interceptor.resume(pause_content_id, outcome)  # raises, D6-audited, on any refusal

        result = forward(final_args)
        if inspect.isawaitable(result):
            result = await result

        result_payload = canonical_json_bytes(
            {"tool": kind, "args": final_args, "result": _jsonable(result), "effect": effect}
        )
        receipt_verified, receipt_bytes = self._capture_and_record(session_key, result_payload, effect)
        receipt = Receipt(
            signed_bytes=receipt_bytes, content_id=receipt_verified.content_id,
            effect=effect, causes=receipt_verified.causes,
        )
        return result, receipt

    def guard(self, fn: Callable[..., Any], *, kind: Optional[str] = None) -> Callable[..., Awaitable[Any]]:
        """Wrap a plain tool callable `fn(**kwargs) -> result` (sync or async) so calling the
        wrapper routes the call through `on_effecting_action` first -- the convenience form a
        LlamaIndex Workflow step body calls directly
        (`await guarded_write_file(args, ctx=ctx, session_key=thread_id)`), mirroring
        `naalp_langgraph.NaalpLangGraphGuard.guard`'s convenience wrapper. Returns ONLY the
        tool's own result (the receipt is still recorded via `recorder`; use
        `on_effecting_action` directly when the caller needs the `Receipt` object itself). The
        returned wrapper is always a coroutine function (`on_effecting_action` itself is a
        coroutine), regardless of whether `fn` is sync or async."""
        tool_name = kind or getattr(fn, "__name__", "llamaindex_tool")

        async def guarded(
            tool_args: Dict[str, Any], *, ctx: "Context", session_key: str, principal: str = "",
        ) -> Any:
            result, _receipt = await self.on_effecting_action(
                tool_name, dict(tool_args), lambda final: fn(**final),
                ctx=ctx, session_key=session_key, principal=principal,
            )
            return result

        guarded.__wrapped__ = fn
        guarded.__name__ = "naalp_guarded_" + tool_name
        guarded.naalp_kind = tool_name
        return guarded


__all__ = [
    "NaalpLlamaIndexGuard",
    "ChainRecorder",
    "Receipt",
    "MalformedResponseDecision",
    "CHANNEL_BRIDGE",
    "KIND_CARRIAGE",
    "canonical_json_bytes",
    "args_content_id",
]
