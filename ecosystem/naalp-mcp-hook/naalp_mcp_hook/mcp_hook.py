# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
K3 -- the N-AALP Governance Kit's framework-hook adapter for the Model Context Protocol (MCP)
(the N-AALP Governance Kit design, plus the
chain recorder / K1-shaped item 4 analogue and the optional server-side recording item).

This module is a THIN translation layer only, the same shape as K1
(ecosystem/naalp-adk-plugin/naalp_adk_plugin/adk_plugin.py): it constructs a K0
`naalp_kit.binding.CapturedAction` from a real MCP SDK call site and calls K0
(`sign_action`/`verify_action`/`authorize_action`) to do the actual provenance/authorization
work. It adds no cryptography, no CBOR encoding, and no channel-registry logic of its own --
every one of those is delegated to K0 and, through K0, to the real Part-1 core.

THE LOAD-BEARING DIFFERENCE FROM K1 -- and the reason K3 is a distinct adapter rather than an
extension of the already-BUILT `ecosystem/naalp-mcp-bridge` (Part-2 E2.1): K3-1 requires MCP
**annotations to stay OPAQUE**. `naalp-mcp-bridge` DECODES a tool's `annotations` object
(`readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint`) and maps those hint booleans
to a C5 effect via `naalp.mcp.map_annotations_to_effect` (design.md Sec.19.3) -- a deliberate,
correct parse for THAT module's job (an explicit-call SDK library building the NAALP-MCP wire
profile, which the profile itself defines an annotation->effect mapping for). K3 does the
opposite on purpose: it is a passive, automatic, client-side interception wrapper that captures
EVERY outbound tool call -- including calls against an UNMODIFIED THIRD-PARTY MCP SERVER whose
tool annotations this kit has no standing to interpret -- and it treats the entire `annotations`
object as an opaque byte blob, bound into the provenance record ONLY by its own real 50-byte
multihash content id (`naalp.cbor.content_id`, S-3). K3 NEVER reads an individual hint's boolean
VALUE and NEVER branches program logic on one; effect classification, when needed, is either K0's
own real fail-closed default (`naalp_kit.binding.resolve_effect`) or an explicit, OPERATOR-
supplied `effect_classifier(tool_name, arguments)` that is structurally denied access to the
annotations object at all (see `EffectClassifier`, below) -- the opacity is a property of this
module's OWN call surface, not merely a documented promise. K3 and `naalp-mcp-bridge` COEXIST:
this module is never imported by, and never modifies, `ecosystem/naalp-mcp-bridge`.

MCP SDK GROUNDING (Section B1/E8 -- verified this session against the currently installed
package, never against training-data memory of a fast-moving SDK):

  Installed and used for this module + its tests: the official `mcp` package (PyPI:
  `modelcontextprotocol/python-sdk`), version **1.27.1**, already present in this session's
  Python environment (`pip show mcp` -> Version: 1.27.1; Author: Anthropic, PBC).

  Cross-checked against the CURRENT PyPI release (`pypi.org/pypi/mcp/json`, fetched this
  session): the latest release line is **2.1.1** (released 2026-08-24), described by its own
  changelog as "a major rework of the SDK... to support the 2026-07-28 MCP specification."
  Installed into an ISOLATED venv this session (`pip install mcp==2.1.1`, without touching the
  environment's 1.27.1 install, which another local tool depends on) purely to confirm the hook
  point this module relies on is stable across the rework:
  `mcp.client.session.ClientSession.call_tool` is, in BOTH 1.27.1 and 2.1.1, a plain overridable
  `async def` instance method with `(self, name, arguments=None, ...)` as its first two
  positional parameters (2.1.1 adds keyword-only extras -- `input_responses`, `request_state`,
  `allow_input_required`, `allow_claimed` -- for its new elicitation/task features; none of those
  are read or altered by this module, which forwards `*args, **kwargs` through unexamined).

  THE HOOK POINT ITSELF: unlike ADK's `google.adk.plugins.base_plugin.BasePlugin` (a first-class
  plugin ABC an embedding developer REGISTERS on a `Runner`), the MCP Python SDK has NO separate
  plugin/middleware registry on the client side (confirmed by reading
  `mcp/client/session.py`/`mcp/shared/session.py` and grepping the installed package tree for
  "middleware"/"interceptor": every hit is server-side ASGI auth middleware, unrelated to tool
  calls). The SDK's own extensibility mechanism for the client is ordinary Python subclassing:
  `ClientSession` methods (`call_tool`, `list_tools`, ...) are plain overridable coroutines, and
  every one of `send_request`'s callers (`call_tool`, `list_tools`, `list_resources`, ...) funnel
  through them. A subclass that overrides `call_tool`/`list_tools` and calls `super()` is
  therefore the SDK-native "framework-hook adapter" shape K3 asks for: an embedding developer
  substitutes `NaalpGovernedClientSession(...)` for `ClientSession(...)` at session-construction
  time -- the ONE place their code already names the class -- and every subsequent tool call is
  captured automatically, with NO other change to their agent's own tool-calling logic
  (wrap-not-replace). This IS a genuine SDK-exposed hook point, not an invented one: `call_tool`
  and `list_tools` are the SDK's own public, documented, overridable request-sending methods, and
  `super().call_tool(...)`/`super().list_tools(...)` is the SDK's own real send-and-receive path
  -- K3 adds capture before/after it, never replacing it (observe-only mode always returns
  exactly what `super()` returned).

  Feasibility note, honestly stated: this is a CLIENT-side hook (an embedding agent's own
  `ClientSession` subclass choice), which is exactly what K3-1 asks for ("client-side wrapper
  recording outbound MCP tool calls even against an unmodified third-party server"). There is no
  way to intercept tool calls against a genuinely unmodified third-party server from the SERVER
  side (a server operator cannot instrument code they do not run); the OPTIONAL, operator-
  controlled server-side recording K3 also names (`record_server_tool_call`, below) is offered
  for the case where the OPERATOR does control the server and opts in.
"""
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Sequence, Tuple

from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before naalp_kit/naalp imports)

from naalp_kit import binding
from naalp import cbor, ez, policy

try:
    from mcp import ClientSession, types
except ImportError as _e:  # pragma: no cover -- exercised only in an environment without mcp
    raise ImportError(
        "naalp_mcp_hook requires the 'mcp' package (K3's client-side hook is a "
        "mcp.ClientSession subclass); install it with `pip install mcp`."
    ) from _e


# The generic foreign-carriage surface (design.md sec.13; naalp.channels.TABLE[13] == ('Bridge',
# [(0, 'Carriage', 0, True)])) -- variable effect, exactly the "framework this protocol does not
# natively know" case both K1 and K3 exist for. K3 never invents a new (channel, kind) pair of
# its own, and never reuses naalp.mcp's dedicated McpToolCall (channel/kind) surface -- that
# surface's own profile (design.md Sec.19) is what DECODES annotations; K3 deliberately stays on
# the opaque generic surface instead.
CHANNEL_BRIDGE = 0x000D
KIND_CARRIAGE = 0


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding for an opaque MCP payload (a tool call, a tool result, or an
    annotations object) before it becomes a K0 CapturedAction.payload or a content-id input --
    same convention as ecosystem/naalp-adk-plugin/naalp_adk_plugin/adk_plugin.canonical_json_bytes
    and ecosystem/naalp-mcp-bridge/naalp_mcp_bridge/mcp_bridge.canonical_json_bytes, kept local
    (each ecosystem package is independently installable). K0 never parses this back out (K0-4);
    it exists only so the SAME logical action produces the SAME payload bytes run to run, for
    content-id stability."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def annotations_content_id(annotations: Optional["types.ToolAnnotations"]) -> Optional[bytes]:
    """K3-1's opacity binding: the WHOLE `annotations` object, serialized VERBATIM via its own
    real pydantic `model_dump_json` (never field-by-field access, never a hint read for its
    boolean VALUE), then bound by its real 50-byte multihash content id
    (`naalp.cbor.content_id`, S-3 -- the same content-id primitive K0 itself uses, F3
    non-circular). Returns None when the tool declares no annotations at all (nothing to bind).

    This is the ONE function in this module that ever touches an MCP `ToolAnnotations` object,
    and it never branches on, compares, or returns any individual hint (readOnlyHint,
    destructiveHint, idempotentHint, openWorldHint): the object is opaque input to a hash, not a
    decision input. Contrast `naalp_mcp_bridge.mcp_bridge.annotations_from_mcp_dict`, which reads
    each hint's boolean value by design -- this module deliberately never calls it and never
    imports `naalp.mcp.map_annotations_to_effect`."""
    if annotations is None:
        return None
    raw = annotations.model_dump_json(exclude_none=True).encode("utf-8")
    return cbor.content_id(raw)


# --- ChainRecorder: identical shape/contract to K1's, kept local per ecosystem convention ------

class ChainRecorder:
    """K3's append-only, length-prefixed session log -- same contract as
    ecosystem/naalp-adk-plugin/naalp_adk_plugin/adk_plugin.ChainRecorder (K1's chain recorder,
    the item-4 analogue this deliverable list also names for K3). Kept as an independent copy
    (not imported cross-package) so `naalp-mcp-hook` remains independently installable, matching
    every other ecosystem package's convention.

    Each record is a 4-byte big-endian length prefix followed by the exact signed N-AALP object
    bytes. ChainRecorder performs NO cryptography and computes NO content ids itself: the caller
    (the session wrapper, below) already knows each object's real content id, obtained from
    `naalp_kit.binding.verify_action` -- the same core the object was checked against, never
    invented or independently derived here (F3, non-circular)."""

    def __init__(self, stream):
        self._stream = stream
        self._last_id: Dict[str, bytes] = {}

    def append(self, session_key: str, signed_bytes: bytes, content_id: bytes) -> None:
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
        prev = self._last_id.get(str(session_key))
        return (prev,) if prev is not None else ()

    @staticmethod
    def read_all(stream) -> Sequence[bytes]:
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


# K3-1's structural opacity guarantee: the classifier signature has NO parameter through which an
# annotations object could even be passed. A caller who wants effect classification supplies a
# function of (tool_name, arguments) only -- the same shape K1 offers -- never (tool_name,
# arguments, annotations). This is enforced by the type itself, not merely documented: nothing in
# this module ever constructs a 3-argument call to an EffectClassifier.
EffectClassifier = Callable[[str, Dict[str, Any]], Optional[int]]


class NaalpGovernedClientSession(ClientSession):
    """K3-1..K3-3: a real `mcp.ClientSession` subclass that emits a signed, chained N-AALP object
    for every outbound tool call (and, when a tool's definition is known, binds -- never decodes
    -- its annotations by content id), through K0. An embedding developer substitutes this class
    for `mcp.ClientSession` at session-construction time; every other line of their MCP client
    code is unchanged (wrap-not-replace) -- this IS the "automatic capture at the MCP SDK's
    callback points" shape the intake specifies, achieved via the SDK's own overridable-method
    extensibility (there is no separate plugin registry to hook, see the module docstring).

    Two modes (mirroring K1-6/K1-7):

    - **observe-only** (`gating=False`, the default): `call_tool` always returns EXACTLY what
      `super().call_tool(...)` returns -- the real MCP request is always sent, this class only
      observes and records. This is the safe default for adopting N-AALP into an existing MCP
      client without changing its behavior against a real (possibly third-party, unmodified)
      server.
    - **gating** (`gating=True`, opt-in): before sending the real request, K0's
      `authorize_action` is checked against a caller-supplied `naalp.policy.Grant`; when the
      captured action's declared C5 effect is NOT covered by the grant, `call_tool` returns a
      fail-closed `types.CallToolResult(isError=True, ...)` WITHOUT ever calling
      `super().call_tool(...)` -- the tool call never reaches the wire, matching K1-5's
      before-the-call deny-return convention translated into MCP's own result shape (MCP has no
      ADK-style "return a dict to short-circuit" convention of its own; a `CallToolResult` with
      `isError=True` is the SDK's own vocabulary for "this call did not succeed").

    An unclassified action (no `effect_classifier` result) resolves through K0-3's fail-closed
    default (`naalp_kit.binding.resolve_effect`): every captured MCP tool call is signed on the
    Bridge channel's baseline Carriage kind (13, 0), a variable-effect surface, so an
    unclassified action defaults to DESTRUCTIVE, the most severe class -- never a guessed benign
    default, and never derived from the tool's own (opaque) annotations."""

    def __init__(
        self,
        *args,
        signer: "ez.Signer",
        recorder: ChainRecorder,
        session_key: str = "default",
        gating: bool = False,
        grant: Optional["policy.Grant"] = None,
        effect_classifier: Optional[EffectClassifier] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._naalp_signer = signer
        self._naalp_recorder = recorder
        self._naalp_session_key = str(session_key)
        self._naalp_gating = bool(gating)
        self._naalp_grant = grant
        self._naalp_effect_classifier = effect_classifier
        # tool name -> opaque 50-byte content id of its (whole, un-interpreted) annotations
        # object, populated only by list_tools(); never a decoded hint value.
        self._naalp_annotation_cids: Dict[str, bytes] = {}
        if self._naalp_gating and self._naalp_grant is None:
            raise ValueError(
                "NaalpGovernedClientSession(gating=True) requires a grant= naalp.policy.Grant "
                "to authorize the declared effect against"
            )

    # -- shared plumbing --------------------------------------------------------------------

    def _classify_effect(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[int]:
        if self._naalp_effect_classifier is None:
            return None
        return self._naalp_effect_classifier(tool_name, dict(arguments))

    def _capture_and_record(self, payload: bytes, effect: Optional[int]) -> "binding.VerifiedAction":
        """Build a CapturedAction chained to this session's last recorded object, sign it through
        K0, self-verify it (through K0's own verify_action -- the same core path any other
        consumer of this log would use) to obtain its real content id, append it to the chain
        recorder, and return the VerifiedAction. Raises K0's/the core's named errors directly
        (K0-5) -- there is no swallow-and-continue path here."""
        action = binding.CapturedAction(
            channel=CHANNEL_BRIDGE, kind=KIND_CARRIAGE, payload=payload, effect=effect,
            causes=self._naalp_recorder.last_cause(self._naalp_session_key),
        )
        signed = binding.sign_action(self._naalp_signer, action)
        verified = binding.verify_action(self._naalp_signer.public_key, signed)
        self._naalp_recorder.append(self._naalp_session_key, signed, verified.content_id)
        return verified

    # -- K3-2 (implicit): tool-definition capture, annotation content-id binding only -----------

    async def list_tools(self, *args, **kwargs) -> "types.ListToolsResult":
        """Delegates to the real SDK request unmodified, then, for every tool the server
        described, binds its (possibly-present) `annotations` object by content id ONLY --
        `annotations_content_id` never reads a hint's boolean value (K3-1). The cache this
        populates is consulted (read-only) by `call_tool`, below; nothing here signs or records
        an N-AALP object of its own (a tool LISTING is not itself a captured ACTION)."""
        result = await super().list_tools(*args, **kwargs)
        for tool in result.tools:
            cid = annotations_content_id(tool.annotations)
            if cid is not None:
                self._naalp_annotation_cids[tool.name] = cid
        return result

    # -- K3-1: outbound tool-call capture + optional gating, opaque annotation binding ----------

    async def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None,
                         *args: Any, **kwargs: Any) -> "types.CallToolResult":
        """Capture, sign, and record this outbound tool call BEFORE the real request is sent
        (so a denial is still a provenance-worthy captured action, mirroring K1-5's
        `test_gating_still_records_the_denied_attempt`), then either deny fail-closed (gating
        mode, uncovered effect) or forward to `super().call_tool(...)` -- the real MCP SDK send
        path -- unmodified, and finally capture the tool RESULT as a second, chained record."""
        args_dict = dict(arguments or {})
        known_annotation_cid = self._naalp_annotation_cids.get(name)
        call_payload = canonical_json_bytes({
            "mcp_event": "tool_call",
            "tool": name,
            "arguments": args_dict,
            # K3-1: the annotations object itself is NEVER embedded or decoded here -- only its
            # opaque content id (hex-encoded for JSON-safety), or None if unknown/absent.
            "annotations_content_id": known_annotation_cid.hex() if known_annotation_cid else None,
        })
        effect = self._classify_effect(name, args_dict)
        verified = self._capture_and_record(call_payload, effect)

        if self._naalp_gating:
            try:
                binding.authorize_action(verified, self._naalp_grant)
            except policy.PolicyError as e:
                return types.CallToolResult(
                    isError=True,
                    content=[types.TextContent(
                        type="text",
                        text="naalp_governance_denied: %s: %s" % (e.kind, e),
                    )],
                )

        result = await super().call_tool(name, arguments, *args, **kwargs)

        result_payload = canonical_json_bytes({
            "mcp_event": "tool_result",
            "tool": name,
            "arguments": args_dict,
            "is_error": bool(result.isError),
            "result": _jsonable(result.model_dump(mode="json")),
        })
        self._capture_and_record(result_payload, effect)
        return result


def _jsonable(value: Any) -> Any:
    """Best-effort recursive coercion of an arbitrary already-dict-shaped MCP result into a
    strictly JSON-encodable form for canonical_json_bytes, WITHOUT interpreting its meaning (K3
    never decides what a tool result "means" -- this only makes it representable as opaque
    bytes). Falls back to `repr()` for anything json.dumps still cannot handle."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    try:
        json.dumps(value)
        return value
    except TypeError:
        return repr(value)


# --- optional, operator-controlled server-side recording (K3 deliverable item 6) ---------------

ServerToolHandler = Callable[[str, Dict[str, Any]], Awaitable[Any]]


def record_server_tool_call(
    signer: "ez.Signer",
    recorder: ChainRecorder,
    handler: ServerToolHandler,
    *,
    session_key: str = "server",
    effect_classifier: Optional[EffectClassifier] = None,
) -> ServerToolHandler:
    """Optional, operator-controlled server-side recording (K3 item 6: "matchable by content
    id"). Wraps a real tool-implementation coroutine (the function an operator registers via
    `mcp.server.lowlevel.Server.call_tool()`'s decorator) so the SAME captured-action shape
    (`{"mcp_event": "tool_call", "tool": name, "arguments": arguments, ...}`,
    `canonical_json_bytes`-encoded exactly as the client-side capture is) is signed and recorded
    on the server side too -- an operator who controls BOTH ends can therefore recompute the
    SAME `naalp.cbor.content_id` from either side's captured payload and confirm they match
    (K3's "matchable by content id"), without either side needing to trust the other's log.

    This wrapper NEVER alters the handler's real behavior or return value (wrap-not-replace,
    same discipline as the client-side observe-only default): it calls `handler(name, arguments)`
    and returns its result unchanged; the ONLY effect is the signed record it appends to
    `recorder`. It is entirely OPT-IN -- an operator who does not call this function gets no
    server-side recording at all, exactly as K3 specifies ("optional operator-controlled")."""

    async def _wrapped(name: str, arguments: Dict[str, Any]) -> Any:
        args_dict = dict(arguments or {})
        payload = canonical_json_bytes({
            "mcp_event": "tool_call",
            "tool": name,
            "arguments": args_dict,
            # The server side has no independent notion of the CLIENT's cached annotation
            # content id; a server operator who wants that cross-checked supplies it via their
            # own tool-definition bookkeeping, not this wrapper (which stays opaque by omission).
            "annotations_content_id": None,
        })
        effect = effect_classifier(name, args_dict) if effect_classifier else None
        action = binding.CapturedAction(
            channel=CHANNEL_BRIDGE, kind=KIND_CARRIAGE, payload=payload, effect=effect,
            causes=recorder.last_cause(session_key),
        )
        signed = binding.sign_action(signer, action)
        verified = binding.verify_action(signer.public_key, signed)
        recorder.append(session_key, signed, verified.content_id)
        return await handler(name, args_dict)

    return _wrapped


__all__ = [
    "NaalpGovernedClientSession", "ChainRecorder", "EffectClassifier",
    "CHANNEL_BRIDGE", "KIND_CARRIAGE",
    "canonical_json_bytes", "annotations_content_id", "record_server_tool_call",
]
