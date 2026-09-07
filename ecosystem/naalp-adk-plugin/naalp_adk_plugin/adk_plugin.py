# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
K1 -- the N-AALP Governance Kit's reference framework adapter for Google's Agent Development
Kit (ADK) (the N-AALP Governance Kit design
plus the chain recorder).

This module is a THIN translation layer only: it constructs a K0 `naalp_kit.binding.CapturedAction`
from an ADK plugin callback's real arguments and calls K0 (`sign_action`/`verify_action`/
`authorize_action`) to do the actual provenance/authorization work. It adds no cryptography, no
CBOR encoding, and no channel-registry logic of its own -- every one of those is delegated to K0
and, through K0, to the real Part-1 core.

Verified against the CURRENTLY INSTALLED `google-adk` package (2.8.0) this session, per Section
B1/E8 (never build a framework integration from training-data memory of a young, moving plugin
API): `google.adk.plugins.base_plugin.BasePlugin` is an ABC with `__init__(self, name: str)`, and
its callbacks are all coroutine methods taking keyword-only arguments:

    async def before_tool_callback(self, *, tool, tool_args, tool_context) -> Optional[dict]
    async def after_tool_callback(self, *, tool, tool_args, tool_context, result) -> Optional[dict]
    async def on_event_callback(self, *, invocation_context, event) -> Optional[Event]

`before_tool_callback`/`after_tool_callback` returning a non-`None` dict SHORT-CIRCUITS: for
`before_tool_callback` the dict is returned immediately as the tool's result WITHOUT the tool
ever running (this is ADK's own gating primitive, per base_plugin.py's docstring: "If a
dictionary is returned, it will stop the tool execution and return this response immediately").
Returning `None` from any callback leaves ADK's own behavior unchanged (K1's observe-only mode,
the default here). `tool_context.invocation_id` (a `str` property inherited from
`ReadonlyContext`, confirmed in google/adk/agents/readonly_context.py) is the one stable
per-invocation key this module uses to key the chain recorder's causal linkage; ADK's own
`Session`/`Context` objects are otherwise live framework state this module never holds onto or
serializes.

K1 does NOT decide whether a tool call is a good idea (no intent judgment, per the kit's design
stance) -- gating mode only checks whether the CALLING SIGNER'S GRANT covers the CapturedAction's
declared C5 effect (naalp.policy's real closed four-value lattice, via K0's authorize_action);
it never inspects tool_args content or tool semantics. An action with no per-tool effect
classification supplied by the embedding developer resolves through K0-3's fail-closed default
(naalp_kit.binding.resolve_effect): every ADK tool call is captured on the Bridge channel's
baseline Carriage kind (13, 0) -- naalp.channels.TABLE's variable-effect "generic foreign
carriage" surface, the same one design.md sec.13 names for a framework this protocol does not
natively know the shape of -- so an unclassified action defaults to DESTRUCTIVE, the most severe
class, never a guessed benign default.
"""
import json
import struct
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before naalp_kit/naalp imports)

from naalp_kit import binding
from naalp import ez, policy

try:
    from google.adk.plugins.base_plugin import BasePlugin
except ImportError as _e:  # pragma: no cover -- exercised only in an environment without google-adk
    raise ImportError(
        "naalp_adk_plugin requires the 'google-adk' package (K1 is a BasePlugin subclass "
        "registered on a real ADK Runner); install it with `pip install google-adk`."
    ) from _e


# The generic foreign-carriage surface (design.md sec.13; naalp.channels.TABLE[13] == ('Bridge',
# [(0, 'Carriage', 0, True)])) -- variable effect, exactly the "framework this protocol does not
# natively know" case K1 exists for. K1 never invents a new (channel, kind) pair of its own.
CHANNEL_BRIDGE = 0x000D
KIND_CARRIAGE = 0


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding for an opaque ADK payload (tool name + args, or a
    call+result pair) before it becomes a K0 CapturedAction.payload -- same convention as
    ecosystem/naalp-mcp-bridge/naalp_mcp_bridge.mcp_bridge.canonical_json_bytes, kept local
    (each ecosystem package is independently installable). K0 never parses this back out
    (K0-4); it exists only so the SAME logical tool call/result produces the SAME payload
    bytes run to run, for content-id stability."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class ChainRecorder:
    """K1's append-only, length-prefixed session log (the "chain recorder" named alongside K1 in
    the intake's deliverable list, item 4: "hands back each object's content id so a result can
    chain to its call").

    Each record is a 4-byte big-endian length prefix followed by the exact signed N-AALP object
    bytes, written to a caller-supplied binary stream (a real file opened `'ab'`, or an
    in-memory `io.BytesIO` for tests) -- nothing here re-encodes or interprets the signed bytes.
    ChainRecorder performs NO cryptography and computes NO content ids itself: the caller (the
    plugin, below) already knows each object's real content id, because it obtained it from
    `naalp_kit.binding.verify_action` -- the same core the object was checked against, never
    invented or independently derived here (F3, non-circular). ChainRecorder's only job is to
    persist the bytes and remember, per session key, the LAST content id appended, so the next
    captured action in that session can chain to it via `CapturedAction.causes`."""

    def __init__(self, stream):
        self._stream = stream
        self._last_id: Dict[str, bytes] = {}

    def append(self, session_key: str, signed_bytes: bytes, content_id: bytes) -> None:
        """Persist one signed object and record it as the new head of `session_key`'s chain."""
        if not isinstance(signed_bytes, (bytes, bytearray)):
            raise TypeError("ChainRecorder.append: signed_bytes must be raw octets")
        if not isinstance(content_id, (bytes, bytearray)) or len(content_id) == 0:
            raise TypeError("ChainRecorder.append: content_id must be non-empty raw octets")
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
        """Read every length-prefixed record back out of a log stream, in append order -- the
        read-side counterpart K5 (the offline verifier/replay, not built by this task) will use
        to reconstruct a session's signed-object chain. Raises ValueError on a truncated
        length-prefix or record (a corrupted/incomplete log is never silently accepted as
        complete)."""
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


EffectClassifier = Callable[[str, Dict[str, Any]], Optional[int]]


class NaalpGovernancePlugin(BasePlugin):
    """K1-1..K1-7: one `BasePlugin` subclass, registered globally on an ADK `Runner`
    (`Runner(..., plugins=[NaalpGovernancePlugin(...)])`), that emits a signed, chained N-AALP
    object for every tool call, tool result, and runner event, through K0.

    Two modes (K1-6/K1-7):

    - **observe-only** (`gating=False`, the default): every callback returns `None` in every
      case -- ADK's own tool execution and event flow are NEVER modified, only observed and
      recorded. This is the safe default for adopting N-AALP into an existing agent without
      changing its behavior.
    - **gating** (`gating=True`, opt-in, K1-5): `before_tool_callback` additionally calls K0's
      `authorize_action` against a caller-supplied `naalp.policy.Grant`; when the CapturedAction's
      declared effect is NOT covered by the grant, `before_tool_callback` returns a dict (ADK's
      own deny-return convention, base_plugin.py: "it will stop the tool execution and return
      this response immediately") instead of `None`, denying the tool call BEFORE it runs.
      `after_tool_callback`/`on_event_callback` never gate (K1-5 scopes gating to the point
      where a tool call can still be prevented; a result or event has already happened).

    `effect_classifier`, if supplied, maps `(tool_name, tool_args) -> Optional[int]` to a caller
    declared C5 effect (naalp.policy.READ_ONLY..DESTRUCTIVE); returning `None` (or omitting the
    classifier) leaves K0-3's fail-closed default in force for that action."""

    def __init__(
        self,
        signer: "ez.Signer",
        recorder: ChainRecorder,
        *,
        gating: bool = False,
        grant: Optional["policy.Grant"] = None,
        effect_classifier: Optional[EffectClassifier] = None,
        name: str = "naalp_governance",
    ):
        super().__init__(name=name)
        self._signer = signer
        self._recorder = recorder
        self._gating = bool(gating)
        self._grant = grant
        self._effect_classifier = effect_classifier
        if self._gating and self._grant is None:
            raise ValueError(
                "NaalpGovernancePlugin(gating=True) requires a grant= naalp.policy.Grant "
                "to authorize the declared effect against"
            )

    # -- shared plumbing ------------------------------------------------------------------

    def _classify_effect(self, tool_name: str, tool_args: Dict[str, Any]) -> Optional[int]:
        if self._effect_classifier is None:
            return None
        return self._effect_classifier(tool_name, dict(tool_args))

    def _capture_and_record(self, session_key: str, payload: bytes,
                             effect: Optional[int]) -> "binding.VerifiedAction":
        """Build a CapturedAction chained to this session's last recorded object, sign it
        through K0, self-verify it (through K0's own verify_action -- the same core path any
        other consumer of this log would use) to obtain its real content id, append it to the
        chain recorder, and return the VerifiedAction for the caller to (optionally) authorize.
        Raises K0's/the core's named errors directly (K0-5) -- there is no swallow-and-continue
        path here."""
        action = binding.CapturedAction(
            channel=CHANNEL_BRIDGE, kind=KIND_CARRIAGE, payload=payload,
            effect=effect, causes=self._recorder.last_cause(session_key),
        )
        signed = binding.sign_action(self._signer, action)
        verified = binding.verify_action(self._signer.public_key, signed)
        self._recorder.append(session_key, signed, verified.content_id)
        return verified

    # -- K1-3/K1-6: tool call capture + optional gating ------------------------------------

    async def before_tool_callback(self, *, tool, tool_args, tool_context):
        session_key = tool_context.invocation_id
        payload = canonical_json_bytes({"tool": tool.name, "args": dict(tool_args)})
        effect = self._classify_effect(tool.name, tool_args)
        verified = self._capture_and_record(session_key, payload, effect)
        if not self._gating:
            return None  # observe-only: never modifies ADK's tool-execution flow
        try:
            binding.authorize_action(verified, self._grant)
        except policy.PolicyError as e:
            # K1-5: the ADK deny-return -- a non-None dict short-circuits the tool call and IS
            # the response (base_plugin.py); the tool never runs.
            return {
                "naalp_governance_denied": True,
                "kind": e.kind,
                "reason": str(e),
                "tool": tool.name,
            }
        return None  # authorized: proceed with the tool call unmodified

    # -- K1-4: tool result capture (never gates -- the call already ran) ------------------

    async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
        session_key = tool_context.invocation_id
        payload = canonical_json_bytes(
            {"tool": tool.name, "args": dict(tool_args), "result": _jsonable(result)}
        )
        effect = self._classify_effect(tool.name, tool_args)
        self._capture_and_record(session_key, payload, effect)
        return None  # K1 only records provenance here; it never rewrites a tool's own result

    # -- K1-3: runner event capture --------------------------------------------------------

    async def on_event_callback(self, *, invocation_context, event):
        session_key = invocation_context.invocation_id
        model_dump_json = getattr(event, "model_dump_json", None)
        if model_dump_json is not None:
            payload = model_dump_json().encode("utf-8")  # pydantic BaseModel (google-adk Event)
        else:
            payload = canonical_json_bytes(_jsonable(event))
        self._capture_and_record(session_key, payload, effect=None)
        return None  # K1 only records provenance here; it never replaces the runner's event


def _jsonable(value: Any) -> Any:
    """Best-effort recursive coercion of an arbitrary tool result / non-pydantic event into a
    JSON-encodable shape for canonical_json_bytes, WITHOUT interpreting its meaning (K1 never
    decides what a tool result "means" -- this only makes it representable as opaque bytes).
    Falls back to `repr()` for anything json.dumps still cannot handle."""
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


__all__ = [
    "NaalpGovernancePlugin", "ChainRecorder",
    "CHANNEL_BRIDGE", "KIND_CARRIAGE", "canonical_json_bytes",
]
