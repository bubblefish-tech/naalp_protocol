# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Mutation-surviving tests for the N-AALP Microsoft Agent Framework (MSAF) adapter
(ecosystem/naalp-msaf/naalp_msaf/msaf_adapter.py). Every gated-path test here drives a REAL
`agent_framework.Agent`, composed with a REAL `agent_framework.FunctionInvocationLayer` chat
client, through `agent.run()` -- `agent_framework.FunctionMiddleware.process()` is never called
directly with a hand-built context: MSAF's own function-invocation loop is what invokes it, on
every real `Agent.run()` call (confirmed live this session; a bare duck-typed chat client that
only implements `SupportsChatGetResponse`, NOT composed from `FunctionInvocationLayer`, is never
wrapped with function-invocation handling and never drives the middleware pipeline at all --
proven by a live probe this session), so there is no way to exercise the gate without also
exercising MSAF's real function-invocation loop, its real `FunctionMiddlewarePipeline.execute()`,
and its real `MiddlewareTermination`/`MiddlewareFailure` control-flow (anti-fake rule A9/A5).

Non-circularity (F3): every recorded signed object is independently decoded and verified through
`naalp.ez.verify` -- the same real, already-graded Part-1 core -- never merely re-read through
naalp_msaf's own bookkeeping.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1, using the real Python interpreter -- not the
Microsoft Store `python`/`python3` execution-alias stubs, which hang):
    PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-msaf/tests/test_msaf_adapter.py -v
"""
import asyncio
import io
import json
import os
import sys

import pytest

# ecosystem/naalp-msaf's package dir name has a hyphen and so cannot itself be part of a dotted
# import path; insert its own directory (the parent of this tests/ dir) onto sys.path so
# `naalp_msaf` (the underscore package, sibling of tests/) is importable regardless of the
# invocation cwd -- same problem naalp-langgraph's/naalp-openai-agents's tests solve identically.
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

import agent_framework as af

from naalp_msaf import (
    NaalpMSAFMiddleware, ChainRecorder, MalformedResumeDecision,
    CHANNEL_BRIDGE, KIND_CARRIAGE, canonical_json_bytes, args_content_id,
)
from naalp_hitl import JsonlRefusalLog
from naalp_hitl.durable import DurableHITLInterceptor
from naalp import approval, cose, ez, policy

APPROVER_ID = "human-approver-1"
AUDIENCE = "svc:msaf-agent"
IDENTITY = "msaf-hitl-interceptor-1"
APPROVER_ALG = cose.ALG_MLDSA65


def _seed(b):
    return bytes([b]) * 32


def _signer(b=0x31):
    return ez.Signer(_seed(b), alg=cose.ALG_MLDSA65, profile=cose.PROFILE_PUBLIC)


def _approver_seed(b=0x71):
    return _seed(b)


def _approver_pubkey(seed):
    return cose.mldsa_keygen("ML-DSA-65", seed)


class _ScriptedClient(af.FunctionInvocationLayer, af.BaseChatClient):
    """A REAL `agent_framework.BaseChatClient`, composed with the REAL
    `agent_framework.FunctionInvocationLayer` mixin (confirmed live this session: this exact
    composition is what makes `Agent` drive its real function-invocation loop -- a bare
    duck-typed `SupportsChatGetResponse` client is never wrapped, per `Agent.__init__`'s own
    warning path, read live this session). Scripted, network-free: on any call whose message
    history carries no `function_result` content yet, requests exactly one call to `tool_name`
    with `tool_args`; once a result is present, returns a final text response. No LLM, no
    network -- every response is a fixed, real `agent_framework.ChatResponse` object."""

    def __init__(self, *, tool_name: str, tool_args: dict, call_id: str = "call-1", **kwargs):
        super().__init__(**kwargs)
        self.tool_name = tool_name
        self.tool_args = tool_args
        self.call_id = call_id
        self.calls = 0

    async def _inner_get_response(self, *, messages, stream, options, **kwargs):
        self.calls += 1
        has_result = any(c.type == "function_result" for m in messages for c in m.contents)
        if not has_result:
            return af.ChatResponse(
                messages=af.Message(
                    role="assistant",
                    contents=[
                        af.Content.from_function_call(
                            call_id=self.call_id, name=self.tool_name, arguments=dict(self.tool_args),
                        )
                    ],
                ),
                response_id="r%d" % self.calls,
                finish_reason="tool_calls",
            )
        return af.ChatResponse(
            messages=af.Message(role="assistant", contents=[af.Content.from_text("done")]),
            response_id="r%d" % self.calls,
            finish_reason="stop",
        )


class _Harness:
    """One tempdir-backed DurableHITLInterceptor + middleware, real end to end -- nothing faked."""

    def __init__(self, tmp_path, *, grant_ceiling=policy.DESTRUCTIVE, effect_classifier=None,
                 signer_seed=0x31, principal=None):
        self.signer = _signer(signer_seed)
        self.approver_seed = _approver_seed()
        self.approver_pk = _approver_pubkey(self.approver_seed)
        self.ledger = approval.open_ledger(os.path.join(str(tmp_path), "consume.wal"))
        self.refusal_log = JsonlRefusalLog(os.path.join(str(tmp_path), "refusals.jsonl"))
        self.interceptor = DurableHITLInterceptor(
            self.ledger, APPROVER_ALG, self.approver_pk, AUDIENCE, IDENTITY,
            self.refusal_log, os.path.join(str(tmp_path), "paused"),
        )
        self.stream_records = []
        self.recorder = ChainRecorder(_ListStream(self.stream_records))
        grant_principal = principal if principal is not None else self.signer.signer_id
        self.grant = policy.Grant(principal=grant_principal, max_effect=grant_ceiling)
        self.middleware = NaalpMSAFMiddleware(
            self.signer, self.recorder, self.interceptor, self.grant,
            audience=AUDIENCE, approver_id=APPROVER_ID, approver_alg=APPROVER_ALG,
            approver_seed=self.approver_seed, effect_classifier=effect_classifier,
        )

    def close(self):
        self.ledger.close()


class _ListStream:
    """A tiny binary-stream stand-in that records writes as a list of byte chunks (so
    ChainRecorder's length-prefix framing can be re-parsed with io.BytesIO when a test wants
    to), used only so tests can inspect writes without a real file."""

    def __init__(self, sink):
        self._sink = sink

    def write(self, data):
        self._sink.append(bytes(data))

    def flush(self):
        pass


def _decode_and_verify(signer, signed_bytes):
    """Independently decode+verify a signed object through the real Part-1 core (F3), NOT
    through naalp_msaf's own code path."""
    return ez.verify(signer.public_key, signed_bytes)


async def _run_agent_async(middleware, func, *, tool_name, tool_args, call_id="call-1"):
    """Drive one REAL `agent_framework.Agent.run()` call against `func` (a plain Python callable
    -- wrapped by `agent_framework.tool()` into a real `FunctionTool`), with `middleware`
    registered as the agent's REAL `FunctionMiddleware`. Returns the real `AgentResponse`."""
    tool = af.tool(func, name=tool_name)
    client = _ScriptedClient(tool_name=tool_name, tool_args=tool_args, call_id=call_id)
    agent = af.Agent(client=client, tools=[tool], middleware=[middleware])
    return await agent.run("please %s" % tool_name)


def _run_agent(middleware, func, *, tool_name, tool_args, call_id="call-1"):
    """Synchronous wrapper (`asyncio.run`) so tests stay plain `def` functions -- no
    `pytest-asyncio` dependency, same convention as
    `naalp_openai_agents`'s own `_run()` test helper."""
    return asyncio.run(_run_agent_async(middleware, func, tool_name=tool_name, tool_args=tool_args, call_id=call_id))


def _result_dict(response):
    """Pull the `function_result` content's `.result` value out of a real AgentResponse.
    `agent_framework.Content.from_function_result`'s own docstring (read live this session)
    states its `.result` field is ALWAYS "the concatenated text from text items, for backwards
    compatibility" -- i.e. a JSON-encoded string, whatever Python value the tool (or this
    module's own pending-marker dict, for a gated call) actually produced -- so this helper
    round-trips it back through `json.loads` to recover the structured value tests assert on."""
    for m in response.messages:
        for c in m.contents:
            if c.type == "function_result":
                if isinstance(c.result, str):
                    try:
                        return json.loads(c.result)
                    except (TypeError, ValueError):
                        return c.result
                return c.result
    return None


# --- canonical_json_bytes / args_content_id --------------------------------------------------

def test_canonical_json_bytes_is_deterministic_regardless_of_key_order():
    a = canonical_json_bytes({"b": 1, "a": 2})
    b = canonical_json_bytes({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_args_content_id_is_deterministic():
    a = args_content_id({"path": "/tmp/x", "n": 3})
    b = args_content_id({"n": 3, "path": "/tmp/x"})
    assert a == b
    assert len(a) == 50  # S-3: 2-byte multihash prefix + 48-byte SHA-384 digest


def test_args_content_id_changes_with_different_args():
    a = args_content_id({"amount": 10})
    b = args_content_id({"amount": 1})
    assert a != b


def test_args_content_id_matches_the_durable_interceptors_own_pause_content_id(tmp_path):
    """The content id this module's own gate-status check keys on MUST be identical to the one
    `DurableHITLInterceptor.pause()` computes internally (`cbor.content_id(args)`), or the two
    would never agree on which pending record belongs to which call."""
    h = _Harness(tmp_path)
    try:
        tool_args = {"path": "/etc/passwd"}
        from naalp_msaf.msaf_adapter import _to_cbor_value
        pause_id = h.interceptor.pause("cat_file", policy.DESTRUCTIVE, _to_cbor_value(tool_args))
        assert pause_id == args_content_id(tool_args)
    finally:
        h.close()


# --- ChainRecorder (local copy) ----------------------------------------------------------------

def test_chain_recorder_append_and_last_cause_round_trip():
    rec = ChainRecorder(_ListStream([]))
    assert rec.last_cause("s") == ()
    rec.append("s", b"first", b"\x01" * 50)
    assert rec.last_cause("s") == (b"\x01" * 50,)
    rec.append("s", b"second", b"\x02" * 50)
    assert rec.last_cause("s") == (b"\x02" * 50,)
    assert rec.last_cause("other") == ()


def test_chain_recorder_rejects_non_bytes_signed_bytes():
    rec = ChainRecorder(_ListStream([]))
    with pytest.raises(TypeError):
        rec.append("s", "not bytes", b"\x01" * 50)


# --- on_effecting_action (process()): below-threshold effect never gates -----------------------

def test_read_only_effect_never_pauses_and_forwards_immediately(tmp_path):
    h = _Harness(tmp_path, effect_classifier=lambda k, a: policy.READ_ONLY)
    try:
        forward_calls = []

        def list_files(path: str) -> dict:
            forward_calls.append({"path": path})
            return {"rows": [1, 2, 3]}

        resp = _run_agent(h.middleware, list_files, tool_name="list_files", tool_args={"path": "/tmp"})
        result = _result_dict(resp)
        assert result == {"rows": [1, 2, 3]}
        assert forward_calls == [{"path": "/tmp"}]

        receipt = h.middleware.receipt_for("default", "call-1")
        assert receipt is not None
        assert receipt.effect == policy.READ_ONLY
        obj = _decode_and_verify(h.signer, receipt.signed_bytes)  # F3: independent core verify
        assert obj.channel == CHANNEL_BRIDGE
        assert obj.kind == KIND_CARRIAGE
        assert obj.effect == policy.READ_ONLY
    finally:
        h.close()


# --- P-CLOSED: unclassified effect defaults to DESTRUCTIVE -> approval required -----------------
# (RED-EVIDENCE M1 target: the `self._interceptor.requires_approval(effect)` gating check.)

def test_unclassified_effect_defaults_destructive_and_pauses_the_run(tmp_path):
    """AC-1.1.3: an unrecognized effect class is treated destructive, which requires approval --
    proven here by observing the REAL MSAF `Agent.run()` actually TERMINATE the tool-calling loop
    via `MiddlewareTermination` (the tool's own Python body never executes) for an action with NO
    effect_classifier supplied, even though nothing about its name ("list_files") suggests
    destructiveness. If the fail-closed default were broken (a benign default guessed instead of
    DESTRUCTIVE, or the gating threshold check disabled), the tool would run immediately and this
    assertion would fail."""
    h = _Harness(tmp_path)  # no effect_classifier -> K0-3 fail-closed default applies
    try:
        def list_files(path: str) -> dict:
            pytest.fail("the tool body must never run before the action has actually been approved")

        resp = _run_agent(h.middleware, list_files, tool_name="list_files", tool_args={"path": "/tmp"})
        pending = _result_dict(resp)
        assert pending is not None and pending.get("naalp_status") == "pending", (
            "an unclassified action must default to DESTRUCTIVE and pause the run"
        )
        assert pending["effect"] == policy.DESTRUCTIVE
        assert h.middleware.receipt_for("default", "call-1") is None  # no receipt: never ran
    finally:
        h.close()


# --- resolve_pending(): approve / reject ---------------------------------------------------------

def test_approve_true_resumes_on_a_later_run_and_forwards_the_real_args(tmp_path):
    h = _Harness(tmp_path)
    try:
        forward_calls = []

        def delete_row(id: int) -> dict:
            forward_calls.append({"id": id})
            return {"status": "deleted"}

        first = _run_agent(h.middleware, delete_row, tool_name="delete_row", tool_args={"id": 42})
        assert _result_dict(first)["naalp_status"] == "pending"
        assert forward_calls == []

        content_id = args_content_id({"id": 42})
        h.middleware.resolve_pending(content_id, True)  # mints + consumes a REAL ML-DSA approval

        second = _run_agent(h.middleware, delete_row, tool_name="delete_row", tool_args={"id": 42})
        assert _result_dict(second) == {"status": "deleted"}
        assert forward_calls == [{"id": 42}]  # forwarded exactly once, with the real args

        receipt = h.middleware.receipt_for("default", "call-1")
        assert receipt is not None
        assert receipt.effect == policy.DESTRUCTIVE
        obj = _decode_and_verify(h.signer, receipt.signed_bytes)
        from naalp_kit import binding as _binding
        recovered = json.loads(_binding._extract_payload(obj.body))
        assert recovered["tool"] == "delete_row"
        assert recovered["args"] == {"id": 42}
        assert recovered["result"] == {"status": "deleted"}

        assert h.interceptor.store.load(content_id).status == "approved"
    finally:
        h.close()


def test_reject_false_fails_closed_and_the_tool_body_never_runs(tmp_path):
    h = _Harness(tmp_path)
    try:
        forward_calls = []

        def rm_rf(path: str) -> str:
            forward_calls.append(path)
            return "SHOULD NOT HAPPEN"

        first = _run_agent(h.middleware, rm_rf, tool_name="rm_rf", tool_args={"path": "/"}, call_id="call-x")
        assert _result_dict(first)["naalp_status"] == "pending"

        content_id = args_content_id({"path": "/"})
        with pytest.raises(approval.ApprovalError) as exc_info:
            h.middleware.resolve_pending(content_id, False)
        assert exc_info.value.kind == "ApprovalDenied"
        assert forward_calls == []  # the action was NEVER forwarded

        # A caller who re-submits the SAME tool call after a rejection hits MSAF's real
        # fail-closed escape (MiddlewareFailure), never the tool body.
        with pytest.raises(af.MiddlewareFailure):
            _run_agent(h.middleware, rm_rf, tool_name="rm_rf", tool_args={"path": "/"}, call_id="call-x")
        assert forward_calls == []

        assert h.interceptor.store.load(content_id).status == "rejected"

        # D6: the refusal was durably logged.
        entries = h.refusal_log.read_all()
        assert len(entries) == 1
        assert entries[0]["outcome_reason"] == "ApprovalDenied"
    finally:
        h.close()


def test_resolve_pending_rejects_a_non_bool_decision(tmp_path):
    h = _Harness(tmp_path)
    try:
        with pytest.raises(MalformedResumeDecision):
            h.middleware.resolve_pending(b"\x00" * 50, "not-a-valid-decision-shape")
    finally:
        h.close()


# --- authorize is UNCONDITIONAL (design.md 2.1): denies BEFORE the tool ever runs, via
#     MiddlewareFailure (MSAF's real fail-closed escape, never an absorbed tool-error) ------------

def test_authorize_denies_via_middleware_failure_when_grant_ceiling_too_low(tmp_path):
    h = _Harness(tmp_path, grant_ceiling=policy.READ_ONLY, effect_classifier=lambda k, a: policy.IDEMPOTENT_WRITE)
    try:
        def upsert_row(id: int) -> str:
            pytest.fail("the tool body must never run when authorization is refused")

        with pytest.raises(af.MiddlewareFailure) as exc_info:
            _run_agent(h.middleware, upsert_row, tool_name="upsert_row", tool_args={"id": 1})
        assert exc_info.value.__cause__ is not None
        assert exc_info.value.__cause__.kind == "EffectNotAuthorized"
    finally:
        h.close()


def test_authorize_denies_when_grant_principal_does_not_match_the_signer(tmp_path):
    h = _Harness(tmp_path, principal="a-different-signer-id", effect_classifier=lambda k, a: policy.READ_ONLY)
    try:
        def read_db(q: str) -> str:
            pytest.fail("the tool body must never run when authorization is refused")

        with pytest.raises(af.MiddlewareFailure):
            _run_agent(h.middleware, read_db, tool_name="read_db", tool_args={"q": "select 1"})
    finally:
        h.close()


# --- causal chaining across two guarded calls in the same session ------------------------------

def test_receipts_chain_within_a_session(tmp_path):
    """Each real (ungated) invocation of `process()` appends TWO records to the recorder -- a
    pre-action capture (signed BEFORE authorize, so authorization is checked against a real,
    signature-derived identity, K0's own discipline) and the receipt itself, chained to it. Read
    the RAW log back independently (F3) and confirm the second call's pre-action capture names
    the first call's receipt as its cause."""
    h = _Harness(tmp_path, effect_classifier=lambda k, a: policy.READ_ONLY)
    try:
        def tool_a(x: int = 0) -> str:
            return "ok-a"

        def tool_b(x: int = 1) -> str:
            return "ok-b"

        _run_agent(h.middleware, tool_a, tool_name="a", tool_args={}, call_id="call-a")
        _run_agent(h.middleware, tool_b, tool_name="b", tool_args={"x": 1}, call_id="call-b")

        records = ChainRecorder.read_all(io.BytesIO(b"".join(h.stream_records)))
        assert len(records) == 4  # 2 calls * (pre-action + receipt)

        decoded = [_decode_and_verify(h.signer, r) for r in records]
        assert decoded[0].causes == []
        assert decoded[1].causes == [decoded[0].id]
        assert decoded[2].causes == [decoded[1].id]
        assert decoded[3].causes == [decoded[2].id]
    finally:
        h.close()
