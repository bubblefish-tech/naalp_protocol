# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""K2 -- the N-AALP Governance Kit's framework-hook adapter for the A2A (Agent2Agent) protocol
SDK (the N-AALP Governance Kit design).

This module is a THIN translation layer only: it constructs a K0 `naalp_kit.binding.CapturedAction`
from a real `a2a-sdk` framework callback's arguments and calls K0 (`sign_action`/`verify_action`/
`authorize_action`) to do the actual provenance/authorization work. It adds no cryptography, no
CBOR encoding, and no channel-registry logic of its own -- every one of those is delegated to K0
and, through K0, to the real Part-1 core. K2 never parses or interprets the A2A message content it
captures (K2-2, K2-4): the framework-native protobuf request/response is embedded VERBATIM as raw
wire octets (its own `SerializeToString(deterministic=True)` bytes -- the exact bytes A2A would
put on the wire, never re-encoded or field-inspected by this module).

Verified against the CURRENTLY INSTALLED `a2a-sdk` package (1.1.2) this session, per Section
B1/E8 (never build a framework integration from training-data memory). Read directly from
`a2a/client/interceptors.py`, `a2a/client/base_client.py`, and
`a2a/server/request_handlers/request_handler.py` in the installed package this session. The SDK
exposes TWO distinct, genuine framework-hook points -- not explicit-call functions the developer
must remember to invoke, but abstract interfaces the framework's OWN dispatch code calls
automatically once an implementation is registered, exactly the same shape as K1's
`google.adk.plugins.base_plugin.BasePlugin`:

  1. **Outbound (client side): `a2a.client.interceptors.ClientCallInterceptor`.** `BaseClient`
     (the transport-independent base every real A2A client transport composes) calls
     `_execute_with_interceptors`/`_execute_stream_with_interceptors` for EVERY client method
     (`send_message`, `get_task`, `cancel_task`, `list_tasks`, ...); those, in turn, call
     `interceptor.before(args)` before the transport call and `interceptor.after(args)` after
     it returns, for every interceptor in the list the caller passed to
     `ClientFactory.create(card, interceptors=[...])` (confirmed in `base_client.py`
     `_intercept_before`/`_intercept_after`; the interceptor list is threaded straight from
     `client_factory.py`'s public `create()`). `args.input`/`args.result` carry the REAL
     protobuf request/response message for that call (`a2a.types.a2a_pb2.SendMessageRequest`,
     `.Task`, `.SendMessageResponse`, etc.) -- confirmed by constructing each directly against
     the installed package this session. Setting `args.early_return` inside `before()` makes
     `_intercept_before` short-circuit the transport call entirely (confirmed:
     `if args.early_return: return {'early_return': ..., 'executed': ...}`, and
     `_execute_with_interceptors` never calls `transport_call` in that branch) -- ADK's
     "deny-return" convention, expressed as a typed field instead of a dict. Raising inside
     either `before()` or `after()` is UNCAUGHT by the SDK (`_intercept_before`/`_intercept_after`
     have no `try`/`except` around the interceptor call) and propagates straight to the caller of
     `send_message`/`get_task`/etc. -- confirmed the correct, and simpler, deny mechanism for K2
     (see NaalpA2AClientInterceptor below): it needs no fabricated stand-in response object of
     whichever proto type a given method happens to return.

  2. **Inbound (server side): `a2a.server.request_handlers.request_handler.RequestHandler`.**
     This ABC (9 abstract coroutine methods, confirmed by reading `request_handler.py`) is the
     interface EVERY real A2A server transport (JSON-RPC, gRPC, REST -- `request_handler.py`'s
     own docstring: "This interface defines the methods that an A2A server implementation must
     provide to handle incoming A2A requests from any transport") dispatches inbound requests
     through automatically; `DefaultRequestHandler` is the SDK's own reference implementation of
     it. A2A has no separate before/after interceptor CHAIN on the server side the way the client
     does -- so K2's inbound half is a DECORATOR implementing the SAME `RequestHandler` ABC,
     wrapping a real delegate `RequestHandler` (in production, a `DefaultRequestHandler`) and
     registered in its place wherever the embedding application constructs its A2A server. This
     is a real framework-hook (the server dispatches through the ABC, not through an explicit
     call this module's own code makes), the same wrap-and-register-in-place shape K1 uses for
     `BasePlugin` on an ADK `Runner`.

K2 governs the two message-carrying methods on each side: `send_message`/`send_message_streaming`
(client) and `on_message_send`/`on_message_send_stream` (server) -- the actual "agent-to-agent
message" surface K2-1/K2-2 name. The other 7 `RequestHandler` methods (task get/list/cancel, push-
notification-config CRUD, agent-card retrieval) are control-plane/ancillary, not an agent-to-agent
MESSAGE, and are named here as an explicit non-scope for follow-up rather than silently omitted:
`NaalpA2ARequestHandler` still implements all 9 (a partial ABC cannot be instantiated) but the
other 7 are pure delegation with no capture/gate.

K2 COEXISTS with, and never modifies, `ecosystem/naalp-a2a-bridge` (the pre-existing explicit-call
SDK library that bridges A2A Agent Cards + TaskState activity into signed, chained
naalp-description-import / naalp-task-transition objects via `naalp.description`/`naalp.naming`,
a CARD/TASK-STATE-SPECIFIC wire shape the developer invokes inline). K2 is the GENERIC,
opaque-message, automatic-hook counterpart the intake calls for: it never decodes A2A Card or
TaskState semantics and is signed on the same generic foreign-carriage surface K1/K3 already use
(`naalp.channels.TABLE[13]` == Bridge/Carriage, variable-effect -- "a framework this protocol does
not natively know the shape of", design.md sec.13), never a new (channel, kind) pair of its own.

K2 does NOT decide whether an A2A message is a good idea (no intent judgment, per the kit's design
stance) -- gating mode only checks whether the SIGNING PRINCIPAL'S GRANT covers the captured
message's declared C5 effect (naalp.policy's real closed four-value lattice, via K0's
authorize_action); it never inspects message content. An action with no per-call effect
classification supplied by the embedding developer resolves through K0-3's fail-closed default
(naalp_kit.binding.resolve_effect): every A2A message defaults to DESTRUCTIVE, the most severe
class, never a guessed benign default.
"""
import struct
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before naalp_kit/naalp imports)

from naalp_kit import binding
from naalp import ez, policy

try:
    from a2a.client.interceptors import AfterArgs, BeforeArgs, ClientCallInterceptor
except ImportError as _e:  # pragma: no cover -- exercised only in an environment without a2a-sdk
    raise ImportError(
        "naalp_a2a_hook requires the 'a2a-sdk' package (K2's outbound half is a "
        "ClientCallInterceptor registered on a real A2A Client); install it with "
        "`pip install a2a-sdk`."
    ) from _e

from a2a.server.context import ServerCallContext
from a2a.server.request_handlers.request_handler import RequestHandler
from a2a.types.a2a_pb2 import (
    AgentCard,
    CancelTaskRequest,
    DeleteTaskPushNotificationConfigRequest,
    GetExtendedAgentCardRequest,
    GetTaskPushNotificationConfigRequest,
    GetTaskRequest,
    ListTaskPushNotificationConfigsRequest,
    ListTaskPushNotificationConfigsResponse,
    ListTasksRequest,
    ListTasksResponse,
    Message,
    SendMessageRequest,
    SubscribeToTaskRequest,
    Task,
    TaskPushNotificationConfig,
)


# The generic foreign-carriage surface (design.md sec.13; naalp.channels.TABLE[13] == ('Bridge',
# [(0, 'Carriage', 0, True)])) -- variable effect, exactly the "framework this protocol does not
# natively know" case K2 exists for. K2 never invents a new (channel, kind) pair of its own; same
# constants K1 (naalp_adk_plugin) and K3 (naalp_mcp_hook) already use.
CHANNEL_BRIDGE = 0x000D
KIND_CARRIAGE = 0

_DEFAULT_SESSION_KEY = "default"


def canonical_proto_bytes(message: Any) -> bytes:
    """K2's opaque payload encoding: the REAL protobuf wire bytes of an A2A message, via the
    message's own `SerializeToString(deterministic=True)` -- deterministic map-field ordering
    (confirmed this session: two independently-built equal messages produce identical bytes),
    so the SAME logical A2A call produces the SAME payload bytes run to run (content-id
    stability), and K2 does not re-encode, re-order, or interpret a single field (K2-4)."""
    return message.SerializeToString(deterministic=True)


class ChainRecorder:
    """K2's append-only, length-prefixed session log -- the same shape K1's/K3's ChainRecorder
    uses (kept local per this repo's convention: each ecosystem package is independently
    installable). Each record is a 4-byte big-endian length prefix followed by the exact signed
    N-AALP object bytes, written to a caller-supplied binary stream. ChainRecorder performs NO
    cryptography and computes NO content ids itself: the caller already knows each object's real
    content id, obtained from `naalp_kit.binding.verify_action` -- the same core the object was
    checked against, never invented or independently derived here (F3, non-circular)."""

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
        """Read every length-prefixed record back out of a log stream, in append order. Raises
        ValueError on a truncated length-prefix or record (a corrupted/incomplete log is never
        silently accepted as complete)."""
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


EffectClassifier = Callable[[str, Any], Optional[int]]


def _classify(classifier: Optional[EffectClassifier], method: str, message: Any) -> Optional[int]:
    if classifier is None:
        return None
    return classifier(method, message)


def _capture_and_record(
    signer: "ez.Signer", recorder: ChainRecorder, session_key: str,
    payload: bytes, effect: Optional[int],
) -> "binding.VerifiedAction":
    """Shared K0 plumbing for both hook points below: build a CapturedAction chained to this
    session's last recorded object, sign it through K0, self-verify it (through K0's own
    verify_action -- the same core path any other consumer of this log would use) to obtain its
    real content id, append it to the chain recorder, and return the VerifiedAction for the
    caller to (optionally) authorize. Raises K0's/the core's named errors directly (K0-5) -- no
    swallow-and-continue path."""
    action = binding.CapturedAction(
        channel=CHANNEL_BRIDGE, kind=KIND_CARRIAGE, payload=payload,
        effect=effect, causes=recorder.last_cause(session_key),
    )
    signed = binding.sign_action(signer, action)
    verified = binding.verify_action(signer.public_key, signed)
    recorder.append(session_key, signed, verified.content_id)
    return verified


# --- Outbound: NaalpA2AClientInterceptor (K2-1) -------------------------------------------------

class NaalpA2AClientInterceptor(ClientCallInterceptor):
    """K2-1/K2-4: a real `a2a.client.interceptors.ClientCallInterceptor`, registered on an A2A
    `Client` (`ClientFactory(...).create(card, interceptors=[NaalpA2AClientInterceptor(...)])`),
    that wraps every OUTBOUND agent-to-agent call in a signed, chained N-AALP object (`before`)
    and verifies the corresponding INBOUND response before it is returned to the caller
    (`after`) -- through K0, never re-implemented here. The A2A wire message itself is never
    altered (K2-1: "unmodified body") -- K2 only observes and, optionally, gates.

    Two modes, the same K1/K3 convention:

    - **observe-only** (`gating=False`, the default): `before`/`after` only sign+record; the A2A
      call proceeds and returns exactly what the transport produced.
    - **gating** (`gating=True`, opt-in): after signing+recording, K0's `authorize_action` is
      checked against a caller-supplied `naalp.policy.Grant`. On refusal, `naalp.policy.PolicyError`
      (already a named, self-describing core error -- K0-5, never re-wrapped) is raised directly
      out of `before()`/`after()`; the A2A SDK does not catch it (confirmed in `base_client.py`
      `_intercept_before`/`_intercept_after` -- no `try`/`except` around the interceptor call), so
      it propagates straight to the caller of `send_message`/`get_task`/etc. A `before()` raise
      means `transport_call` is NEVER invoked -- the outbound message is never sent. An `after()`
      raise means the received result is NEVER returned to the caller -- "verifies INBOUND before
      delivery, rejects with a named reason on failure" (K2-2), satisfied without fabricating a
      stand-in response object of whatever proto type a given method happens to return.
    """

    def __init__(
        self,
        signer: "ez.Signer",
        recorder: ChainRecorder,
        *,
        gating: bool = False,
        grant: Optional["policy.Grant"] = None,
        effect_classifier: Optional[EffectClassifier] = None,
        session_key: str = _DEFAULT_SESSION_KEY,
    ):
        self._signer = signer
        self._recorder = recorder
        self._gating = bool(gating)
        self._grant = grant
        self._effect_classifier = effect_classifier
        self._session_key = str(session_key)
        if self._gating and self._grant is None:
            raise ValueError(
                "NaalpA2AClientInterceptor(gating=True) requires a grant= naalp.policy.Grant "
                "to authorize the declared effect against"
            )

    async def before(self, args: "BeforeArgs") -> None:
        payload = canonical_proto_bytes(args.input)
        effect = _classify(self._effect_classifier, args.method, args.input)
        verified = _capture_and_record(
            self._signer, self._recorder, self._session_key, payload, effect,
        )
        if self._gating:
            binding.authorize_action(verified, self._grant)  # raises policy.PolicyError, unwrapped

    async def after(self, args: "AfterArgs") -> None:
        if args.early_return:
            return  # a prior interceptor already denied this call; nothing new was received
        payload = canonical_proto_bytes(args.result)
        effect = _classify(self._effect_classifier, args.method, args.result)
        verified = _capture_and_record(
            self._signer, self._recorder, self._session_key, payload, effect,
        )
        if self._gating:
            binding.authorize_action(verified, self._grant)  # raises policy.PolicyError, unwrapped


# --- Inbound: NaalpA2ARequestHandler (K2-2) -----------------------------------------------------

def _context_session_key(params: SendMessageRequest, fallback: str) -> str:
    """Best-effort session key for the SERVER side: the real A2A `Message.context_id` field
    correlates a whole conversation across multiple `message/send` calls (a genuine field on the
    real message, never invented) when the caller populated it; an empty/absent context id falls
    back to the per-instance default, exactly as a single `NaalpA2AClientInterceptor` instance
    scopes chaining to one client relationship."""
    ctx = getattr(params.message, "context_id", "") if params.HasField("message") else ""
    return ctx if ctx else fallback


class NaalpA2ARequestHandler(RequestHandler):
    """K2-2/K2-4: a real `a2a.server.request_handlers.request_handler.RequestHandler`, wrapping a
    delegate `RequestHandler` (in production, a real `DefaultRequestHandler`) and registered in
    its place wherever the embedding application constructs its A2A server. Every real A2A
    server transport (JSON-RPC/gRPC/REST) dispatches inbound requests through this ABC
    automatically (request_handler.py's own docstring) -- the same wrap-and-register-in-place
    shape K1 uses for `BasePlugin`.

    K2 governs the message-carrying surface only: `on_message_send`/`on_message_send_stream`
    capture+record the INBOUND request through K0 and, in gating mode, authorize it BEFORE
    delegating -- a refusal raises `naalp.policy.PolicyError` directly and the wrapped delegate's
    method is NEVER called, so the message is never delivered to the local agent's execution
    (K2-2: "verifies INBOUND before delivery, rejects with a named reason on failure"). The other
    7 `RequestHandler` methods (task get/list/cancel, push-notification-config CRUD, agent-card
    retrieval) are pure delegation -- named out of scope here (control-plane/ancillary, not an
    agent-to-agent MESSAGE); a partial ABC cannot be instantiated, so they are still implemented.
    """

    def __init__(
        self,
        delegate: RequestHandler,
        signer: "ez.Signer",
        recorder: ChainRecorder,
        *,
        gating: bool = False,
        grant: Optional["policy.Grant"] = None,
        effect_classifier: Optional[EffectClassifier] = None,
        session_key: str = _DEFAULT_SESSION_KEY,
    ):
        self._delegate = delegate
        self._signer = signer
        self._recorder = recorder
        self._gating = bool(gating)
        self._grant = grant
        self._effect_classifier = effect_classifier
        self._session_key = str(session_key)
        if self._gating and self._grant is None:
            raise ValueError(
                "NaalpA2ARequestHandler(gating=True) requires a grant= naalp.policy.Grant "
                "to authorize the declared effect against"
            )

    def _capture_inbound_message(self, method: str, params: SendMessageRequest) -> None:
        payload = canonical_proto_bytes(params)
        effect = _classify(self._effect_classifier, method, params)
        session_key = _context_session_key(params, self._session_key)
        verified = _capture_and_record(
            self._signer, self._recorder, session_key, payload, effect,
        )
        if self._gating:
            binding.authorize_action(verified, self._grant)  # raises policy.PolicyError, unwrapped

    # -- K2-2: inbound agent-to-agent message capture + optional gating, before delivery --------

    async def on_message_send(self, params: SendMessageRequest, context: ServerCallContext):
        self._capture_inbound_message("on_message_send", params)
        return await self._delegate.on_message_send(params, context)

    async def on_message_send_stream(self, params: SendMessageRequest, context: ServerCallContext):
        self._capture_inbound_message("on_message_send_stream", params)
        async for event in self._delegate.on_message_send_stream(params, context):
            yield event

    # -- Out of K2's message-carrying scope: pure delegation, named for follow-up ---------------

    async def on_get_task(self, params: GetTaskRequest, context: ServerCallContext):
        return await self._delegate.on_get_task(params, context)

    async def on_list_tasks(self, params: ListTasksRequest, context: ServerCallContext):
        return await self._delegate.on_list_tasks(params, context)

    async def on_cancel_task(self, params: CancelTaskRequest, context: ServerCallContext):
        return await self._delegate.on_cancel_task(params, context)

    async def on_create_task_push_notification_config(
        self, params: TaskPushNotificationConfig, context: ServerCallContext,
    ):
        return await self._delegate.on_create_task_push_notification_config(params, context)

    async def on_get_task_push_notification_config(
        self, params: GetTaskPushNotificationConfigRequest, context: ServerCallContext,
    ):
        return await self._delegate.on_get_task_push_notification_config(params, context)

    async def on_subscribe_to_task(self, params: SubscribeToTaskRequest, context: ServerCallContext):
        async for event in self._delegate.on_subscribe_to_task(params, context):
            yield event

    async def on_list_task_push_notification_configs(
        self, params: ListTaskPushNotificationConfigsRequest, context: ServerCallContext,
    ) -> ListTaskPushNotificationConfigsResponse:
        return await self._delegate.on_list_task_push_notification_configs(params, context)

    async def on_delete_task_push_notification_config(
        self, params: DeleteTaskPushNotificationConfigRequest, context: ServerCallContext,
    ) -> None:
        return await self._delegate.on_delete_task_push_notification_config(params, context)

    async def on_get_extended_agent_card(
        self, params: GetExtendedAgentCardRequest, context: ServerCallContext,
    ) -> AgentCard:
        return await self._delegate.on_get_extended_agent_card(params, context)


__all__ = [
    "NaalpA2AClientInterceptor", "NaalpA2ARequestHandler", "ChainRecorder",
    "CHANNEL_BRIDGE", "KIND_CARRIAGE", "canonical_proto_bytes",
]
