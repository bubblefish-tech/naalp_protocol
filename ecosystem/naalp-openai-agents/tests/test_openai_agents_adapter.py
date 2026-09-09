# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Mutation-surviving tests for the N-AALP OpenAI-Agents-SDK adapter
(ecosystem/naalp-openai-agents/naalp_openai_agents/openai_agents_adapter.py). Every gated-path
test here drives a REAL `agents.Agent` through a REAL `agents.Runner.run()`, using a
`ScriptedModel` (a real `agents.models.interface.Model` implementation returning pre-scripted
responses -- never a network call, and never a fake of `naalp_openai_agents` itself) so the
actual SDK machinery -- `agents.function_tool(needs_approval=...)`, `result.interruptions`,
`RunState.approve()`/`.reject()`, `Runner.run(agent, state)` -- is exercised for real (anti-fake
rule A9/A5): there is no code path in this test file that calls this adapter's tool body or
`needs_approval` callable directly, bypassing the SDK.

Non-circularity (F3): every recorded signed object is independently decoded and verified through
`naalp.ez.verify` -- the same real, already-graded Part-1 core -- never merely re-read through
naalp_openai_agents's own bookkeeping.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1, using the real Python interpreter -- not the
Microsoft Store `python`/`python3` execution-alias stubs, which hang):
    PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-openai-agents/tests/test_openai_agents_adapter.py -v
"""
import asyncio
import io
import json
import os
import sys

import pytest

# ecosystem/naalp-openai-agents's package dir name has a hyphen and so cannot itself be part of a
# dotted import path; insert its own directory (the parent of this tests/ dir) onto sys.path so
# `naalp_openai_agents` (the underscore package, sibling of tests/) is importable regardless of
# the invocation cwd -- same problem naalp-langgraph's/naalp-adk-plugin's tests solve identically.
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from naalp_openai_agents import (
    NaalpOpenAIAgentsGuard, ChainRecorder, MalformedResumeDecision,
    CHANNEL_BRIDGE, KIND_CARRIAGE, canonical_json_bytes, args_content_id,
)
from naalp_hitl import JsonlRefusalLog
from naalp_hitl.durable import DurableHITLInterceptor
from naalp import approval, cose, ez, policy
from naalp_kit import binding as _binding

from agents import Agent, Runner, RunContextWrapper
from agents.exceptions import UserError
from agents.items import ModelResponse
from agents.usage import Usage
from agents.models.interface import Model

from openai.types.responses import ResponseFunctionToolCall
from openai.types.responses.response_output_message import ResponseOutputMessage
from openai.types.responses.response_output_text import ResponseOutputText

APPROVER_ID = "human-approver-1"
AUDIENCE = "svc:openai-agents-agent"
IDENTITY = "openai-agents-hitl-interceptor-1"
APPROVER_ALG = cose.ALG_MLDSA65


def _seed(b):
    return bytes([b]) * 32


def _signer(b=0x31):
    return ez.Signer(_seed(b), alg=cose.ALG_MLDSA65, profile=cose.PROFILE_PUBLIC)


def _approver_seed(b=0x71):
    return _seed(b)


def _approver_pubkey(seed):
    return cose.mldsa_keygen("ML-DSA-65", seed)


class _Harness:
    """One tempdir-backed DurableHITLInterceptor + guard, real end to end -- nothing faked."""

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
        self.guard = NaalpOpenAIAgentsGuard(
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
    through naalp_openai_agents's own code path."""
    return ez.verify(signer.public_key, signed_bytes)


class ScriptedModel(Model):
    """A REAL `agents.models.interface.Model` implementation returning a fixed, pre-scripted
    sequence of `ModelResponse`s -- confirmed live this session to drive a genuine
    `agents.Agent`/`agents.Runner.run()` round trip with NO network access (no OPENAI_API_KEY
    needed). This is a fake MODEL (the LLM), never a fake of `naalp_openai_agents` itself or of
    the SDK's own `needs_approval`/`interruptions`/`RunState` machinery -- every one of those
    stays real."""

    def __init__(self, script):
        self._script = list(script)
        self._i = 0

    async def get_response(self, system_instructions, input, model_settings, tools,
                            output_schema, handoffs, tracing, *, previous_response_id,
                            conversation_id, prompt):
        item = self._script[self._i]
        self._i += 1
        return ModelResponse(output=[item], usage=Usage(), response_id="resp-%d" % self._i)

    async def stream_response(self, *a, **kw):  # pragma: no cover -- Runner.run never streams
        raise NotImplementedError


def make_call(name, args, call_id):
    return ResponseFunctionToolCall(
        type="function_call", name=name, arguments=json.dumps(args), call_id=call_id,
    )


def make_message(text):
    return ResponseOutputMessage(
        id="msg-" + text, type="message", role="assistant", status="completed",
        content=[ResponseOutputText(type="output_text", text=text, annotations=[])],
    )


def _run(agent, input_or_state, **kw):
    return asyncio.run(Runner.run(agent, input_or_state, **kw))


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


def test_args_content_id_distinguishes_none_from_missing_key_shape():
    a = args_content_id({"x": None})
    b = args_content_id({"x": "y"})
    assert a != b


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


# --- on_effecting_action: below-threshold effect never gates -----------------------------------

def test_read_only_effect_never_interrupts_and_forwards_immediately(tmp_path):
    h = _Harness(tmp_path, effect_classifier=lambda k, a: policy.READ_ONLY)
    try:
        calls = []

        def list_files(ctx: RunContextWrapper, path: str) -> dict:
            calls.append(path)
            return {"rows": [1, 2, 3]}

        tool = h.guard.tool(list_files, kind="list_files")
        model = ScriptedModel([make_call("list_files", {"path": "/tmp"}, "c1"), make_message("done")])
        agent = Agent(name="t", tools=[tool], model=model)
        result = _run(agent, "list files", context="sess-read-only")

        assert result.interruptions == []  # a read-only action never pauses the run
        assert calls == ["/tmp"]

        receipt = h.guard.receipt_for("sess-read-only", "c1")
        assert receipt is not None
        assert receipt.effect == policy.READ_ONLY
        obj = _decode_and_verify(h.signer, receipt.signed_bytes)  # F3: independent core verify
        assert obj.channel == CHANNEL_BRIDGE
        assert obj.kind == KIND_CARRIAGE
        assert obj.effect == policy.READ_ONLY
    finally:
        h.close()


# --- P-CLOSED: unclassified effect defaults to DESTRUCTIVE -> approval required -----------------
# (RED-EVIDENCE M1 target: NaalpOpenAIAgentsGuard.needs_approval's returned gate decision.)

def test_unclassified_effect_defaults_destructive_and_requires_approval(tmp_path):
    """AC-1.1.3: an unrecognized effect class is treated destructive, which requires approval --
    proven here by observing the REAL `agents.Runner.run()` actually PAUSE (`result.
    interruptions` is non-empty) for an action with NO effect_classifier supplied, even though
    nothing about its name ("list_files") suggests destructiveness, and by observing the tool's
    own body NEVER ran (`calls == []`). If the fail-closed default were broken (a benign default
    guessed instead of DESTRUCTIVE, or the needs_approval gate disabled), the run would complete
    immediately and this assertion would fail."""
    h = _Harness(tmp_path)  # no effect_classifier -> K0-3 fail-closed default applies
    try:
        calls = []

        def list_files(ctx: RunContextWrapper, path: str) -> dict:
            calls.append(path)
            return {"rows": [1, 2, 3]}

        tool = h.guard.tool(list_files, kind="list_files")
        model = ScriptedModel([make_call("list_files", {"path": "/tmp"}, "c1")])
        agent = Agent(name="t", tools=[tool], model=model)
        result = _run(agent, "list files", context="sess-unclassified")

        assert len(result.interruptions) == 1, "an unclassified action must default to DESTRUCTIVE and pause for approval"
        assert calls == [], "forward() must never run before a real approval is granted"
        item = result.interruptions[0]
        assert item.name == "list_files"
        assert json.loads(item.arguments) == {"path": "/tmp"}
    finally:
        h.close()


# --- resolve_interruption: approve / reject ------------------------------------------------------

def test_approve_true_resumes_and_forwards_the_original_args(tmp_path):
    h = _Harness(tmp_path)
    try:
        calls = []

        def delete_row(ctx: RunContextWrapper, row_id: int) -> dict:
            calls.append(row_id)
            return {"status": "deleted", "row_id": row_id}

        tool = h.guard.tool(delete_row, kind="delete_row")
        model = ScriptedModel([
            make_call("delete_row", {"row_id": 42}, "call-approve"),
            make_message("done"),
        ])
        agent = Agent(name="t", tools=[tool], model=model)

        result = _run(agent, "delete row 42", context="sess-approve")
        assert len(result.interruptions) == 1
        item = result.interruptions[0]

        state = h.guard.resolve_interruption(result.to_state(), item, True, principal="agent:bot-1")
        result2 = _run(agent, state)

        assert result2.interruptions == []
        assert calls == [42]  # unedited args forwarded verbatim

        receipt = h.guard.receipt_for("sess-approve", item.call_id)
        assert receipt is not None
        assert receipt.effect == policy.DESTRUCTIVE
        obj = _decode_and_verify(h.signer, receipt.signed_bytes)
        recovered = json.loads(_binding._extract_payload(obj.body))
        assert recovered["tool"] == "delete_row"
        assert recovered["args"] == {"row_id": 42}
        assert recovered["result"] == {"status": "deleted", "row_id": 42}

        # RED-EVIDENCE M2 target: resolve_interruption's real cryptographic consume, proven by
        # the durable store's OWN status transition -- not merely that the tool ran.
        assert h.interceptor.store.load(args_content_id({"row_id": 42})).status == "approved"
    finally:
        h.close()


def test_reject_false_fails_closed_and_forward_never_runs(tmp_path):
    h = _Harness(tmp_path)
    try:
        calls = []

        def rm_rf(ctx: RunContextWrapper, path: str) -> str:
            calls.append(path)
            return "SHOULD NOT HAPPEN"

        tool = h.guard.tool(rm_rf, kind="rm_rf")
        model = ScriptedModel([make_call("rm_rf", {"path": "/"}, "call-reject")])
        agent = Agent(name="t", tools=[tool], model=model)

        result = _run(agent, "rm -rf /", context="sess-reject")
        item = result.interruptions[0]
        state = result.to_state()

        with pytest.raises(approval.ApprovalError) as exc_info:
            h.guard.resolve_interruption(state, item, False, principal="agent:bot-2")
        assert exc_info.value.kind == "ApprovalDenied"
        assert calls == []  # the action was NEVER forwarded
        assert h.interceptor.store.load(args_content_id({"path": "/"})).status == "rejected"

        # D6: the refusal was durably logged, including the real source principal.
        entries = h.refusal_log.read_all()
        assert len(entries) == 1
        assert entries[0]["source_principal"] == "agent:bot-2"
        assert entries[0]["outcome_reason"] == "ApprovalDenied"
    finally:
        h.close()


def test_malformed_resume_decision_raises_a_named_error(tmp_path):
    h = _Harness(tmp_path)
    try:
        def rm_rf(ctx: RunContextWrapper, path: str) -> str:
            pytest.fail("forward() must never run on a malformed resume decision")

        tool = h.guard.tool(rm_rf, kind="rm_rf")
        model = ScriptedModel([make_call("rm_rf", {"path": "/"}, "call-malformed")])
        agent = Agent(name="t", tools=[tool], model=model)
        result = _run(agent, "rm -rf /", context="sess-malformed")
        item = result.interruptions[0]
        with pytest.raises(MalformedResumeDecision):
            h.guard.resolve_interruption(result.to_state(), item, "not-a-valid-decision-shape")
    finally:
        h.close()


# --- authorize is UNCONDITIONAL (design.md 2.1): denies whenever the tool body actually runs ----

def test_authorize_denies_before_any_interrupt_when_grant_ceiling_too_low(tmp_path):
    """Below-threshold effect (IDEMPOTENT_WRITE) never gates, so this drives the UNGATED path:
    authorize is checked, and denies, on the SAME single Runner.run() call that would otherwise
    have forwarded immediately -- proving authorize is unconditional, not merely a side effect of
    the approval gate."""
    h = _Harness(tmp_path, grant_ceiling=policy.READ_ONLY,
                 effect_classifier=lambda k, a: policy.IDEMPOTENT_WRITE)
    try:
        calls = []

        def upsert_row(ctx: RunContextWrapper, row_id: int) -> str:
            calls.append(row_id)
            return "SHOULD NOT HAPPEN"

        tool = h.guard.tool(upsert_row, kind="upsert_row")
        model = ScriptedModel([make_call("upsert_row", {"row_id": 1}, "call-authz-deny")])
        agent = Agent(name="t", tools=[tool], model=model)

        with pytest.raises(UserError) as exc_info:
            _run(agent, "upsert", context="sess-authz-deny")
        assert isinstance(exc_info.value.__cause__, policy.PolicyError)
        assert exc_info.value.__cause__.kind == "EffectNotAuthorized"
        assert calls == []
    finally:
        h.close()


def test_authorize_denies_when_grant_principal_does_not_match_the_signer_even_after_a_real_approval(tmp_path):
    """The gated path: authorize is checked inside the wrapped tool body, which for a gated
    effect only runs AFTER a real approval was granted and consumed -- so a principal mismatch
    still refuses the action (forward() never runs), even though a genuine cryptographic
    approval was already spent verifying this adapter's fail-closed conjunction (P-ADAPTER:
    effect-auth AND approval, not either alone) holds regardless of check order."""
    h = _Harness(tmp_path, principal="a-different-signer-id")
    try:
        calls = []

        def read_db(ctx: RunContextWrapper, q: str) -> str:
            calls.append(q)
            return "SHOULD NOT HAPPEN"

        tool = h.guard.tool(read_db, kind="read_db")
        model = ScriptedModel([make_call("read_db", {"q": "select 1"}, "call-authz-mismatch")])
        agent = Agent(name="t", tools=[tool], model=model)

        result = _run(agent, "read", context="sess-authz-mismatch")
        item = result.interruptions[0]
        state = h.guard.resolve_interruption(result.to_state(), item, True, principal="agent:whoever")

        with pytest.raises(UserError) as exc_info:
            _run(agent, state)
        assert isinstance(exc_info.value.__cause__, policy.PolicyError)
        assert calls == []
    finally:
        h.close()


# --- causal chaining across guarded calls in the same OpenAI-Agents-SDK "session" ---------------

def test_receipts_chain_within_a_session_and_not_across_sessions(tmp_path):
    """Each guarded tool invocation appends TWO records to its session's chain -- a pre-action
    capture (signed BEFORE authorize/forward, so authorization is checked against a real,
    signature-derived identity, K0's own discipline) and the receipt itself, chained to it. Read
    the RAW log back independently (F3) and confirm every record's `causes` names exactly the
    immediately preceding record's real id within the SAME session (keyed by the `context=`
    value passed to `Runner.run`), and that a fresh session's first record has no causes at all."""
    h = _Harness(tmp_path, effect_classifier=lambda k, a: policy.READ_ONLY)
    try:
        def a_tool(ctx: RunContextWrapper) -> str:
            return "ok"

        def b_tool(ctx: RunContextWrapper, x: int) -> str:
            return "ok"

        def c_tool(ctx: RunContextWrapper) -> str:
            return "ok"

        tool_a = h.guard.tool(a_tool, kind="a")
        tool_b = h.guard.tool(b_tool, kind="b")
        tool_c = h.guard.tool(c_tool, kind="c")

        def run_one(tool, name, args, context):
            model = ScriptedModel([make_call(name, args, "c-" + name), make_message("done")])
            agent = Agent(name="t", tools=[tool], model=model)
            return _run(agent, "go", context=context)

        run_one(tool_a, "a", {}, "shared-thread")
        run_one(tool_b, "b", {"x": 1}, "shared-thread")
        run_one(tool_c, "c", {}, "a-different-session")

        records = ChainRecorder.read_all(io.BytesIO(b"".join(h.stream_records)))
        assert len(records) == 6  # 2 calls * 2 records + 1 call * 2 records, in append order

        decoded = [_decode_and_verify(h.signer, r) for r in records]
        # "shared-thread": 4 records, each chaining to the one immediately before it.
        assert decoded[0].causes == []
        assert decoded[1].causes == [decoded[0].id]
        assert decoded[2].causes == [decoded[1].id]
        assert decoded[3].causes == [decoded[2].id]
        # "a-different-session": a FRESH chain, never touching "shared-thread"'s records.
        assert decoded[4].causes == []
        assert decoded[5].causes == [decoded[4].id]
        assert decoded[4].id not in (decoded[i].id for i in range(4))
    finally:
        h.close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
