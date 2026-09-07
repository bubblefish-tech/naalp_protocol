# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Mutation-surviving tests for K2, the N-AALP Governance Kit's framework-hook adapter for the A2A
protocol SDK (ecosystem/naalp-a2a-hook/naalp_a2a_hook/a2a_hook.py). Every assertion here would
fail if its target function were replaced by a constant return (anti-fake rule A5).

Non-circularity (F3): every recorded signed object is independently decoded and verified through
`naalp.ez.verify` -- the same real, already-graded Part-1 core -- never merely re-read through
naalp_a2a_hook's own bookkeeping. The one exception is `binding._extract_payload`, reused from K0
(a DIFFERENT, already-graded module) purely to pull the opaque payload bytes back out of a
verified body for comparison; K2's OWN new code (payload construction, chain-recorder bookkeeping,
the gating decision) is never used to validate itself.

`before`/`after` are real `a2a.client.interceptors.ClientCallInterceptor` coroutine methods,
driven here with `asyncio.run(...)`. `BeforeArgs`/`AfterArgs`/`SendMessageRequest`/
`SendMessageResponse`/`AgentCard` are REAL `a2a-sdk` protobuf/dataclass objects constructed
directly, confirmed instantiable this session against the installed `a2a-sdk==1.1.2`.

`on_message_send`/`on_message_send_stream` are real `a2a.server.request_handlers.request_handler.
RequestHandler` abstract methods. The DELEGATE handler in these tests is a minimal concrete
`RequestHandler` subclass (implementing all 9 abstract methods with fixed, call-counted bodies) --
constructing the SDK's own full reference implementation (`DefaultRequestHandler`) requires a
`TaskStore` + `AgentExecutor` + `EventQueueManager` + `RequestContextBuilder` graph that is the
SDK's OWN test surface, not this module's (same reasoning naalp-adk-plugin's test docstring gives
for not constructing a full ADK `InvocationContext`/`Session`/`RunConfig` graph). K2 itself is
written purely against the abstract `RequestHandler` interface (never against `DefaultRequestHandler`
internals), so it works identically against any real `RequestHandler` implementation.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1, using the real Python interpreter -- not the
Microsoft Store `python`/`python3` execution-alias stubs, which hang):
    PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-a2a-hook/tests/test_a2a_hook.py -v
"""
import asyncio
import io
import os
import sys

import pytest

# ecosystem/naalp-a2a-hook's package dir name has a hyphen and so cannot itself be part of a
# dotted import path; insert its own directory (the parent of this tests/ dir) onto sys.path so
# `naalp_a2a_hook` (the underscore package, sibling of tests/) is importable regardless of the
# invocation cwd -- same convention naalp-adk-plugin's tests/test_adk_plugin.py uses directly
# (a separate tests/_paths.py module is deliberately NOT used here: naalp-a2a-bridge's own
# tests/_paths.py shares that bare module name, and pytest collecting both suites in one session
# caches modules in sys.modules by name with no package __init__.py to disambiguate them).
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from naalp_a2a_hook.a2a_hook import (
    NaalpA2AClientInterceptor, NaalpA2ARequestHandler, ChainRecorder,
    CHANNEL_BRIDGE, KIND_CARRIAGE, canonical_proto_bytes,
)
from naalp_kit import binding
from naalp import cose, ez, policy

from a2a.client.interceptors import BeforeArgs, AfterArgs
from a2a.server.context import ServerCallContext
from a2a.server.request_handlers.request_handler import RequestHandler
from a2a.types.a2a_pb2 import (
    AgentCard, Message, Role, SendMessageRequest, SendMessageResponse, Task, TaskState,
    GetTaskRequest,
)


def _seed(b):
    return bytes([b]) * 32


def _signer(b=0x31):
    return ez.Signer(_seed(b), alg=cose.ALG_MLDSA65, profile=cose.PROFILE_PUBLIC)


def _agent_card(name="peer-agent"):
    card = AgentCard()
    card.name = name
    return card


def _send_message_request(text, context_id="", message_id="m1"):
    req = SendMessageRequest()
    req.message.message_id = message_id
    req.message.role = Role.ROLE_USER
    part = req.message.parts.add()
    part.text = text
    if context_id:
        req.message.context_id = context_id
    return req


def _send_message_response(text, message_id="m2"):
    resp = SendMessageResponse()
    resp.message.message_id = message_id
    resp.message.role = Role.ROLE_AGENT
    part = resp.message.parts.add()
    part.text = text
    return resp


def _decode_and_verify(signer, signed_bytes):
    """Independently decode+verify a signed object through the real Part-1 core (F3), NOT
    through naalp_a2a_hook's own code path."""
    return ez.verify(signer.public_key, signed_bytes)


# --- canonical_proto_bytes -----------------------------------------------------------------

def test_canonical_proto_bytes_is_deterministic_across_equal_messages():
    a = _send_message_request("hello")
    b = _send_message_request("hello")
    assert canonical_proto_bytes(a) == canonical_proto_bytes(b)


def test_canonical_proto_bytes_differs_when_content_differs():
    a = _send_message_request("hello")
    b = _send_message_request("goodbye")
    assert canonical_proto_bytes(a) != canonical_proto_bytes(b)


def test_canonical_proto_bytes_returns_bytes():
    assert isinstance(canonical_proto_bytes(_send_message_request("x")), bytes)


# --- ChainRecorder (same shape as K1's; smoke only -- full behaviour already graded there) ---

def test_chain_recorder_append_and_last_cause_round_trip():
    rec = ChainRecorder(io.BytesIO())
    assert rec.last_cause("s") == ()
    rec.append("s", b"x", b"\x01" * 50)
    assert rec.last_cause("s") == (b"\x01" * 50,)


# --- NaalpA2AClientInterceptor construction -------------------------------------------------

def test_client_interceptor_construction_requires_grant_when_gating_enabled():
    with pytest.raises(ValueError):
        NaalpA2AClientInterceptor(_signer(), ChainRecorder(io.BytesIO()), gating=True)


def test_client_interceptor_construction_gating_with_grant_succeeds():
    grant = policy.Grant(principal="whoever", max_effect=policy.DESTRUCTIVE)
    interceptor = NaalpA2AClientInterceptor(
        _signer(), ChainRecorder(io.BytesIO()), gating=True, grant=grant,
    )
    assert interceptor._gating is True


# --- before(): outbound wrap, observe-only ----------------------------------------------------

def test_before_signs_a_real_verifiable_object_on_the_bridge_carriage_kind():
    signer = _signer()
    stream = io.BytesIO()
    interceptor = NaalpA2AClientInterceptor(signer, ChainRecorder(stream))
    args = BeforeArgs(input=_send_message_request("read the file"), method="send_message",
                       agent_card=_agent_card())
    asyncio.run(interceptor.before(args))
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)  # F3: real, independent core verify
    assert obj.channel == CHANNEL_BRIDGE
    assert obj.kind == KIND_CARRIAGE
    assert obj.signer == signer.signer_id.encode("utf-8")


def test_before_payload_carries_the_real_wire_bytes_opaquely():
    signer = _signer()
    stream = io.BytesIO()
    interceptor = NaalpA2AClientInterceptor(signer, ChainRecorder(stream))
    req = _send_message_request("delete row 42")
    args = BeforeArgs(input=req, method="send_message", agent_card=_agent_card())
    asyncio.run(interceptor.before(args))
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)
    recovered = binding._extract_payload(obj.body)  # reuse K0's own graded extractor
    assert recovered == canonical_proto_bytes(req)  # never re-encoded, K2-4


def test_before_fail_closed_effect_default_is_destructive_when_unclassified():
    signer = _signer()
    stream = io.BytesIO()
    interceptor = NaalpA2AClientInterceptor(signer, ChainRecorder(stream))  # no classifier
    args = BeforeArgs(input=_send_message_request("x"), method="send_message",
                       agent_card=_agent_card())
    asyncio.run(interceptor.before(args))
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)
    assert obj.effect == policy.DESTRUCTIVE  # K0-3's fail-closed default, never a guessed benign


def test_before_honors_a_caller_supplied_effect_classifier():
    signer = _signer()
    stream = io.BytesIO()
    interceptor = NaalpA2AClientInterceptor(
        signer, ChainRecorder(stream), effect_classifier=lambda method, msg: policy.READ_ONLY,
    )
    args = BeforeArgs(input=_send_message_request("x"), method="send_message",
                       agent_card=_agent_card())
    asyncio.run(interceptor.before(args))
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)
    assert obj.effect == policy.READ_ONLY


# --- after(): inbound verify-and-record, observe-only ------------------------------------------

def test_after_records_the_inbound_response_chained_to_the_outbound_object():
    signer = _signer()
    stream = io.BytesIO()
    interceptor = NaalpA2AClientInterceptor(signer, ChainRecorder(stream))
    before_args = BeforeArgs(input=_send_message_request("x"), method="send_message",
                              agent_card=_agent_card())
    asyncio.run(interceptor.before(before_args))
    after_args = AfterArgs(result=_send_message_response("ok"), method="send_message",
                            agent_card=_agent_card())
    asyncio.run(interceptor.after(after_args))
    stream.seek(0)
    outbound_record, inbound_record = ChainRecorder.read_all(stream)
    outbound_obj = _decode_and_verify(signer, outbound_record)
    inbound_obj = _decode_and_verify(signer, inbound_record)
    assert list(inbound_obj.causes) == [outbound_obj.id]  # causal chain, K0's own content id


def test_after_skips_recording_when_a_prior_interceptor_already_denied():
    signer = _signer()
    stream = io.BytesIO()
    interceptor = NaalpA2AClientInterceptor(signer, ChainRecorder(stream))
    args = AfterArgs(result=None, method="send_message", agent_card=_agent_card(),
                      early_return=True)
    asyncio.run(interceptor.after(args))
    assert stream.getvalue() == b""  # nothing recorded -- no new event actually happened


# --- gating: outbound deny (before never sends) -------------------------------------------------

def test_gating_before_raises_policy_error_when_effect_exceeds_grant_ceiling():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.READ_ONLY)
    interceptor = NaalpA2AClientInterceptor(
        signer, ChainRecorder(io.BytesIO()), gating=True, grant=grant,
    )
    args = BeforeArgs(input=_send_message_request("x"), method="send_message",
                       agent_card=_agent_card())
    with pytest.raises(policy.PolicyError):
        asyncio.run(interceptor.before(args))


def test_gating_before_still_records_the_denied_attempt():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.READ_ONLY)
    stream = io.BytesIO()
    interceptor = NaalpA2AClientInterceptor(
        signer, ChainRecorder(stream), gating=True, grant=grant,
    )
    args = BeforeArgs(input=_send_message_request("x"), method="send_message",
                       agent_card=_agent_card())
    with pytest.raises(policy.PolicyError):
        asyncio.run(interceptor.before(args))
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)  # provenance survives even a refusal
    obj = _decode_and_verify(signer, record)
    assert obj.effect == policy.DESTRUCTIVE  # unclassified -> fail-closed default, > READ_ONLY


def test_gating_before_succeeds_when_grant_covers_the_effect():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.DESTRUCTIVE)
    interceptor = NaalpA2AClientInterceptor(
        signer, ChainRecorder(io.BytesIO()), gating=True, grant=grant,
        effect_classifier=lambda method, msg: policy.READ_ONLY,
    )
    args = BeforeArgs(input=_send_message_request("x"), method="send_message",
                       agent_card=_agent_card())
    asyncio.run(interceptor.before(args))  # does not raise


def test_gating_before_denies_on_principal_mismatch():
    signer = _signer()
    grant = policy.Grant(principal="someone-else", max_effect=policy.DESTRUCTIVE)
    interceptor = NaalpA2AClientInterceptor(
        signer, ChainRecorder(io.BytesIO()), gating=True, grant=grant,
    )
    args = BeforeArgs(input=_send_message_request("x"), method="send_message",
                       agent_card=_agent_card())
    with pytest.raises(policy.PolicyError):
        asyncio.run(interceptor.before(args))


# --- gating: inbound deny (after rejects before delivery) --------------------------------------

def test_gating_after_raises_policy_error_when_inbound_effect_exceeds_grant_ceiling():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.READ_ONLY)
    interceptor = NaalpA2AClientInterceptor(
        signer, ChainRecorder(io.BytesIO()), gating=True, grant=grant,
    )
    args = AfterArgs(result=_send_message_response("ok"), method="send_message",
                      agent_card=_agent_card())
    with pytest.raises(policy.PolicyError):
        asyncio.run(interceptor.after(args))


# --- NaalpA2ARequestHandler: a real RequestHandler delegate wrapping fixture --------------------

class _CountingDelegate(RequestHandler):
    """A minimal, concrete `RequestHandler` -- see module docstring for why this stands in for a
    real `DefaultRequestHandler` in these tests. Every method is call-counted so a test can prove
    a gated-and-denied inbound message never reaches it."""

    def __init__(self):
        self.calls = []

    async def on_get_task(self, params, context):
        self.calls.append("on_get_task")
        return None

    async def on_list_tasks(self, params, context):
        self.calls.append("on_list_tasks")
        return None

    async def on_cancel_task(self, params, context):
        self.calls.append("on_cancel_task")
        return None

    async def on_message_send(self, params, context):
        self.calls.append("on_message_send")
        task = Task()
        task.id = "t1"
        task.status.state = TaskState.TASK_STATE_COMPLETED
        return task

    async def on_message_send_stream(self, params, context):
        self.calls.append("on_message_send_stream")
        task = Task()
        task.id = "t1"
        task.status.state = TaskState.TASK_STATE_WORKING
        yield task

    async def on_create_task_push_notification_config(self, params, context):
        self.calls.append("on_create_task_push_notification_config")
        return None

    async def on_get_task_push_notification_config(self, params, context):
        self.calls.append("on_get_task_push_notification_config")
        return None

    async def on_subscribe_to_task(self, params, context):
        self.calls.append("on_subscribe_to_task")
        return
        yield  # pragma: no cover -- makes this a real async generator

    async def on_list_task_push_notification_configs(self, params, context):
        self.calls.append("on_list_task_push_notification_configs")
        return None

    async def on_delete_task_push_notification_config(self, params, context):
        self.calls.append("on_delete_task_push_notification_config")
        return None

    async def on_get_extended_agent_card(self, params, context):
        self.calls.append("on_get_extended_agent_card")
        return None


def test_request_handler_construction_requires_grant_when_gating_enabled():
    with pytest.raises(ValueError):
        NaalpA2ARequestHandler(_CountingDelegate(), _signer(), ChainRecorder(io.BytesIO()), gating=True)


def test_request_handler_is_a_real_a2a_request_handler_subclass():
    handler = NaalpA2ARequestHandler(_CountingDelegate(), _signer(), ChainRecorder(io.BytesIO()))
    assert isinstance(handler, RequestHandler)


def test_request_handler_passthrough_delegates_out_of_scope_methods_unmodified():
    delegate = _CountingDelegate()
    handler = NaalpA2ARequestHandler(delegate, _signer(), ChainRecorder(io.BytesIO()))
    asyncio.run(handler.on_get_task(GetTaskRequest(), ServerCallContext()))
    assert delegate.calls == ["on_get_task"]  # pure delegation, no capture/gate for this surface


def test_on_message_send_observe_only_records_and_returns_the_delegate_result_unmodified():
    signer = _signer()
    stream = io.BytesIO()
    delegate = _CountingDelegate()
    handler = NaalpA2ARequestHandler(delegate, signer, ChainRecorder(stream))
    req = _send_message_request("hello peer")
    result = asyncio.run(handler.on_message_send(req, ServerCallContext()))
    assert delegate.calls == ["on_message_send"]
    assert result.id == "t1"  # exactly the delegate's own result, never altered
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)
    recovered = binding._extract_payload(obj.body)
    assert recovered == canonical_proto_bytes(req)


def test_on_message_send_gating_denies_before_the_delegate_is_ever_called():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.READ_ONLY)
    delegate = _CountingDelegate()
    handler = NaalpA2ARequestHandler(
        delegate, signer, ChainRecorder(io.BytesIO()), gating=True, grant=grant,
    )
    req = _send_message_request("delete everything")
    with pytest.raises(policy.PolicyError):
        asyncio.run(handler.on_message_send(req, ServerCallContext()))
    assert delegate.calls == []  # K2-2: rejected BEFORE delivery -- the local agent never ran


def test_on_message_send_gating_succeeds_when_grant_covers_the_effect():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.DESTRUCTIVE)
    delegate = _CountingDelegate()
    handler = NaalpA2ARequestHandler(
        delegate, signer, ChainRecorder(io.BytesIO()), gating=True, grant=grant,
        effect_classifier=lambda method, msg: policy.READ_ONLY,
    )
    req = _send_message_request("hello")
    result = asyncio.run(handler.on_message_send(req, ServerCallContext()))
    assert delegate.calls == ["on_message_send"]
    assert result.id == "t1"


async def _drain(agen):
    return [x async for x in agen]


def test_on_message_send_stream_observe_only_delegates_and_yields_events():
    signer = _signer()
    delegate = _CountingDelegate()
    handler = NaalpA2ARequestHandler(delegate, signer, ChainRecorder(io.BytesIO()))
    req = _send_message_request("stream this")
    events = asyncio.run(_drain(handler.on_message_send_stream(req, ServerCallContext())))
    assert delegate.calls == ["on_message_send_stream"]
    assert len(events) == 1 and events[0].id == "t1"


def test_on_message_send_stream_gating_denies_before_any_event_is_yielded():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.READ_ONLY)
    delegate = _CountingDelegate()
    handler = NaalpA2ARequestHandler(
        delegate, signer, ChainRecorder(io.BytesIO()), gating=True, grant=grant,
    )
    req = _send_message_request("stream this destructively")
    with pytest.raises(policy.PolicyError):
        asyncio.run(_drain(handler.on_message_send_stream(req, ServerCallContext())))
    assert delegate.calls == []  # denied before the delegate's stream ever started


def test_session_key_derived_from_context_id_chains_causally_across_calls():
    signer = _signer()
    stream = io.BytesIO()
    delegate = _CountingDelegate()
    handler = NaalpA2ARequestHandler(delegate, signer, ChainRecorder(stream))
    req1 = _send_message_request("first", context_id="conv-A", message_id="m1")
    req2 = _send_message_request("second", context_id="conv-A", message_id="m2")
    asyncio.run(handler.on_message_send(req1, ServerCallContext()))
    asyncio.run(handler.on_message_send(req2, ServerCallContext()))
    stream.seek(0)
    first_record, second_record = ChainRecorder.read_all(stream)
    first_obj = _decode_and_verify(signer, first_record)
    second_obj = _decode_and_verify(signer, second_record)
    assert list(second_obj.causes) == [first_obj.id]


def test_session_key_different_context_ids_are_independent_chains():
    signer = _signer()
    stream = io.BytesIO()
    delegate = _CountingDelegate()
    handler = NaalpA2ARequestHandler(delegate, signer, ChainRecorder(stream))
    req_a = _send_message_request("first", context_id="conv-A", message_id="m1")
    req_b = _send_message_request("first", context_id="conv-B", message_id="m2")
    asyncio.run(handler.on_message_send(req_a, ServerCallContext()))
    asyncio.run(handler.on_message_send(req_b, ServerCallContext()))
    stream.seek(0)
    _record_a, record_b = ChainRecorder.read_all(stream)
    obj_b = _decode_and_verify(signer, record_b)
    assert list(obj_b.causes) == []  # a different conversation -- no causal link to conv-A
