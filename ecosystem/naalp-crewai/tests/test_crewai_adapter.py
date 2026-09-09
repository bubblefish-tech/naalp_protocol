# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Mutation-surviving tests for the N-AALP CrewAI adapter
(ecosystem/naalp-crewai/naalp_crewai/crewai_adapter.py). Every gated-path test here drives the
REAL, currently-installed `crewai` (1.15.20) tool-call machinery --
`crewai.utilities.tool_utils.execute_tool_and_check_finality`, the exact function CrewAI's own
agent executor calls for every real tool call -- with a real `crewai.tools.structured_tool.
CrewStructuredTool` wrapping a plain Python function whose calls are counted, and a real
`crewai.agents.parser.AgentAction`. No LLM, no `Crew.kickoff()` is needed: `agent`/`task`/`crew`
are all optional parameters of this real CrewAI entry point (confirmed live this session), so
these tests exercise CrewAI's genuine hook-dispatch code path end to end without faking any part
of the framework's own machinery (anti-fake rule A9/A5).

Non-circularity (F3): every recorded signed object is independently decoded and verified through
`naalp.ez.verify` -- the same real, already-graded Part-1 core -- never merely re-read through
naalp_crewai's own bookkeeping.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1; crewai requires Python <3.14, so this suite
runs on a separate Python 3.13 interpreter -- see RED-EVIDENCE.md for the exact invocation):
    PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-crewai/tests/test_crewai_adapter.py -v
"""
import json
import os
import sys

import pytest

# ecosystem/naalp-crewai's package dir name has a hyphen and so cannot itself be part of a
# dotted import path; insert its own directory (the parent of this tests/ dir) onto sys.path so
# `naalp_crewai` (the underscore package, sibling of tests/) is importable regardless of the
# invocation cwd -- same problem naalp-langgraph's/naalp-adk-plugin's tests solve identically.
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from naalp_crewai import (
    NaalpCrewAIGuard, ChainRecorder, MalformedDecision,
    CHANNEL_BRIDGE, KIND_CARRIAGE, canonical_json_bytes, args_content_id,
)
from naalp_hitl import JsonlRefusalLog
from naalp_hitl.durable import DurableHITLInterceptor
from naalp import approval, cose, ez, policy

import crewai.hooks as crewai_hooks
from crewai.agents.parser import AgentAction
from crewai.task import Task
from crewai.tools.structured_tool import CrewStructuredTool

APPROVER_ID = "human-approver-1"
AUDIENCE = "svc:crewai-agent"
IDENTITY = "crewai-hitl-interceptor-1"
APPROVER_ALG = cose.ALG_MLDSA65


def _seed(b):
    return bytes([b]) * 32


def _signer(b=0x41):
    return ez.Signer(_seed(b), alg=cose.ALG_MLDSA65, profile=cose.PROFILE_PUBLIC)


def _approver_seed(b=0x81):
    return _seed(b)


def _approver_pubkey(seed):
    return cose.mldsa_keygen("ML-DSA-65", seed)


class _ListStream:
    """A tiny binary-stream stand-in that records writes as a list of byte chunks, used only so
    tests can inspect writes without a real file."""

    def __init__(self, sink):
        self._sink = sink

    def write(self, data):
        self._sink.append(bytes(data))

    def flush(self):
        pass


class _Harness:
    """One tempdir-backed DurableHITLInterceptor + guard, real end to end -- nothing faked. Also
    clears CrewAI's process-global tool-call hook registries on entry/exit so tests never
    pollute each other (`crewai.hooks` lists are process-wide, not per-instance)."""

    def __init__(self, tmp_path, *, grant_ceiling=policy.DESTRUCTIVE, effect_classifier=None,
                 signer_seed=0x41, principal=None, decision_fn=None):
        crewai_hooks.clear_all_tool_call_hooks()
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
        self.guard = NaalpCrewAIGuard(
            self.signer, self.recorder, self.interceptor, self.grant,
            audience=AUDIENCE, approver_id=APPROVER_ID, approver_alg=APPROVER_ALG,
            approver_seed=self.approver_seed, decision_fn=decision_fn, effect_classifier=effect_classifier,
        )
        self.guard.install()

    def close(self):
        self.guard.uninstall()
        crewai_hooks.clear_all_tool_call_hooks()
        self.ledger.close()


def _decode_and_verify(signer, signed_bytes):
    """Independently decode+verify a signed object through the real Part-1 core (F3), NOT
    through naalp_crewai's own code path."""
    return ez.verify(signer.public_key, signed_bytes)


def _make_tool(fn, name):
    return CrewStructuredTool.from_function(fn, name=name, description="test tool: " + name)


def _drive(tool, kind, args, *, task=None):
    """Drive the REAL CrewAI tool-call dispatch for one call: build a real AgentAction (no LLM
    text-parsing needed -- crewai.tools.tool_usage.ToolUsage._original_tool_calling reads
    action.tool/action.tool_input directly, confirmed by reading its source this session) and
    call CrewAI's own execute_tool_and_check_finality, which internally calls
    run_before_tool_call_hooks/run_after_tool_call_hooks -- the exact real interception point."""
    from crewai.utilities.tool_utils import execute_tool_and_check_finality
    action = AgentAction(thought="", tool=kind, tool_input=json.dumps(args), text="irrelevant")
    return execute_tool_and_check_finality(action, [tool], task=task)


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


# --- _default_decision_fn (pure mapping, unit-tested directly) --------------------------------

class _FakeCtxForDefaultDecision:
    def __init__(self, answer):
        self._answer = answer

    def request_human_input(self, prompt, default_message="Press Enter to continue, or provide feedback:"):
        return self._answer


def test_default_decision_fn_maps_yes_variants_to_true(tmp_path):
    h = _Harness(tmp_path)
    try:
        for ans in ("y", "Y", "yes", "YES", "approve", "Approve"):
            ctx = _FakeCtxForDefaultDecision(ans)
            assert h.guard._default_decision_fn(ctx, b"\x00" * 50, policy.DESTRUCTIVE, "k", "s") is True
    finally:
        h.close()


def test_default_decision_fn_maps_anything_else_to_false(tmp_path):
    h = _Harness(tmp_path)
    try:
        for ans in ("n", "no", "", "nope", "maybe"):
            ctx = _FakeCtxForDefaultDecision(ans)
            assert h.guard._default_decision_fn(ctx, b"\x00" * 50, policy.DESTRUCTIVE, "k", "s") is False
    finally:
        h.close()


# --- before_tool_call_hook: below-threshold effect never gates, real tool actually runs --------

def test_read_only_effect_never_blocks_and_the_real_tool_actually_runs(tmp_path):
    h = _Harness(tmp_path, effect_classifier=lambda k, a: policy.READ_ONLY)
    try:
        calls = []

        def list_files(path):
            calls.append(path)
            return {"rows": [1, 2, 3]}

        tool = _make_tool(list_files, "list_files")
        task = Task(description="d", expected_output="e")
        result = _drive(tool, "list_files", {"path": "/tmp"}, task=task)

        assert calls == ["/tmp"]  # the REAL tool actually ran
        # CrewAI's own ToolResult.result is the LLM-facing STRINGIFIED form of whatever the tool
        # returned (confirmed live this session); the receipt below carries the real structured
        # value via context.raw_tool_result, not this string.
        assert result.result == str({"rows": [1, 2, 3]})

        session_key = "crewai-task:%s" % (task.id,)
        receipt = h.guard.last_receipt_for(session_key)
        assert receipt is not None
        assert receipt.effect == policy.READ_ONLY
        obj = _decode_and_verify(h.signer, receipt.signed_bytes)  # F3: independent core verify
        assert obj.channel == CHANNEL_BRIDGE
        assert obj.kind == KIND_CARRIAGE
        assert obj.effect == policy.READ_ONLY
    finally:
        h.close()


# --- P-CLOSED: unclassified effect defaults to DESTRUCTIVE -> approval required -----------------
# (RED-EVIDENCE M1 target: the try/except translation of a core refusal into HookAborted.)

def test_unclassified_effect_defaults_destructive_and_a_rejection_blocks_the_real_tool(tmp_path):
    """AC-1.1.3: an unrecognized effect class is treated destructive, which requires approval --
    proven here by observing that the REAL CrewAI tool callable is NEVER invoked (its call
    counter stays at zero) when the decision source rejects, even though nothing about the tool's
    name ("list_files") suggests destructiveness. If the fail-closed translation into
    `HookAborted` were broken (e.g. a refusal allowed to propagate as a bare exception, which
    CrewAI's own dispatcher silently swallows -- confirmed live this session), the real tool
    callable WOULD run and this assertion would fail."""
    decisions = []

    def reject_everything(context, pause_content_id, effect, kind, args_summary):
        decisions.append((kind, effect))
        return False

    h = _Harness(tmp_path, decision_fn=reject_everything)  # no effect_classifier -> K0-3 default
    try:
        calls = []

        def list_files(path):
            calls.append(path)
            return "SHOULD NOT HAPPEN"

        tool = _make_tool(list_files, "list_files")
        task = Task(description="d", expected_output="e")
        result = _drive(tool, "list_files", {"path": "/tmp"}, task=task)

        assert calls == [], "the real tool must never run when the decision source rejects"
        assert decisions == [("list_files", policy.DESTRUCTIVE)], "an unclassified action must default to DESTRUCTIVE"
        assert result.result_as_answer is False
        assert "blocked" in result.result.lower()
    finally:
        h.close()


# --- approve / reject / edit, through the REAL hook dispatch ------------------------------------

def test_approve_true_runs_the_real_tool_with_the_original_args_and_records_a_receipt(tmp_path):
    def approve_everything(context, pause_content_id, effect, kind, args_summary):
        return True

    h = _Harness(tmp_path, decision_fn=approve_everything)
    try:
        calls = []

        def delete_row(id):
            calls.append(id)
            return {"status": "deleted"}

        tool = _make_tool(delete_row, "delete_row")
        task = Task(description="d", expected_output="e")
        result = _drive(tool, "delete_row", {"id": 42}, task=task)

        assert calls == [42]
        assert result.result == str({"status": "deleted"})

        session_key = "crewai-task:%s" % (task.id,)
        receipt = h.guard.last_receipt_for(session_key)
        assert receipt.effect == policy.DESTRUCTIVE
        obj = _decode_and_verify(h.signer, receipt.signed_bytes)
        from naalp_kit import binding as _binding
        recovered = json.loads(_binding._extract_payload(obj.body))
        assert recovered["tool"] == "delete_row"
        assert recovered["args"] == {"id": 42}
        assert recovered["result"] == {"status": "deleted"}

        assert h.interceptor.store.load(args_content_id({"id": 42})).status == "approved"
    finally:
        h.close()


def test_reject_false_fails_closed_and_the_real_tool_never_runs(tmp_path):
    def reject_everything(context, pause_content_id, effect, kind, args_summary):
        return False

    h = _Harness(tmp_path, decision_fn=reject_everything)
    try:
        calls = []

        def rm_rf(path):
            calls.append(path)
            return "SHOULD NOT HAPPEN"

        tool = _make_tool(rm_rf, "rm_rf")
        task = Task(description="d", expected_output="e")

        _drive(tool, "rm_rf", {"path": "/"}, task=task)

        assert calls == []  # the action was NEVER forwarded
        assert h.interceptor.store.load(args_content_id({"path": "/"})).status == "rejected"

        # D6: the refusal was durably logged.
        entries = h.refusal_log.read_all()
        assert len(entries) == 1
        assert entries[0]["outcome_reason"] == "ApprovalDenied"

        # No receipt was recorded for a refused call.
        assert h.guard.last_receipt_for("crewai-task:%s" % (task.id,)) is None
    finally:
        h.close()


def test_edit_binds_the_approval_to_the_edited_args_and_the_real_tool_runs_with_them(tmp_path):
    """AC-2.2.1, at the CrewAI seam: a `decision_fn` returning a dict of edited args must (a)
    mutate the SAME dict object CrewAI will call the real tool with, so the real tool actually
    executes against the EDITED args, and (b) bind the approval/receipt to the edited content id,
    never the original."""

    def edit_amount(context, pause_content_id, effect, kind, args_summary):
        return {"account": "acct-9", "amount": 1}

    h = _Harness(tmp_path, decision_fn=edit_amount)
    try:
        calls = []

        def wire_transfer(account, amount):
            calls.append({"account": account, "amount": amount})
            return {"status": "transferred", "amount": amount}

        tool = _make_tool(wire_transfer, "wire_transfer")
        task = Task(description="d", expected_output="e")
        result = _drive(tool, "wire_transfer", {"account": "acct-9", "amount": 250000}, task=task)

        assert calls == [{"account": "acct-9", "amount": 1}]  # the REAL tool ran with EDITED args
        assert result.result == str({"status": "transferred", "amount": 1})

        original_id = args_content_id({"account": "acct-9", "amount": 250000})
        stored = h.interceptor.store.load(original_id)
        assert stored.status == "edited"
        assert stored.edited_content_id == args_content_id({"account": "acct-9", "amount": 1})

        receipt = h.guard.last_receipt_for("crewai-task:%s" % (task.id,))
        obj = _decode_and_verify(h.signer, receipt.signed_bytes)
        from naalp_kit import binding as _binding
        recovered = json.loads(_binding._extract_payload(obj.body))
        assert recovered["args"] == {"account": "acct-9", "amount": 1}  # receipt records the EDIT
    finally:
        h.close()


def test_malformed_decision_raises_and_the_real_tool_never_runs(tmp_path):
    def bogus_decision(context, pause_content_id, effect, kind, args_summary):
        return "not-a-valid-decision-shape"

    h = _Harness(tmp_path, decision_fn=bogus_decision)
    try:
        calls = []

        def rm_rf(path):
            calls.append(path)
            return "SHOULD NOT HAPPEN"

        tool = _make_tool(rm_rf, "rm_rf")
        _drive(tool, "rm_rf", {"path": "/"})

        assert calls == []
    finally:
        h.close()


# --- authorize is UNCONDITIONAL (design.md 2.1): denies BEFORE any decision is even solicited ----

def test_authorize_denies_before_any_decision_is_solicited_when_grant_ceiling_too_low(tmp_path):
    decisions = []

    def record_decision(context, pause_content_id, effect, kind, args_summary):
        decisions.append(True)
        return True

    h = _Harness(
        tmp_path, grant_ceiling=policy.READ_ONLY,
        effect_classifier=lambda k, a: policy.IDEMPOTENT_WRITE, decision_fn=record_decision,
    )
    try:
        calls = []

        def upsert_row(id):
            calls.append(id)
            return "SHOULD NOT HAPPEN"

        tool = _make_tool(upsert_row, "upsert_row")
        _drive(tool, "upsert_row", {"id": 1})

        assert calls == []
        assert decisions == [], "authorize must refuse BEFORE any decision is even solicited"
    finally:
        h.close()


def test_authorize_denies_when_grant_principal_does_not_match_the_signer(tmp_path):
    h = _Harness(tmp_path, principal="a-different-signer-id")
    try:
        calls = []

        def read_db(q):
            calls.append(q)
            return "SHOULD NOT HAPPEN"

        tool = _make_tool(read_db, "read_db")
        _drive(tool, "read_db", {"q": "select 1"})

        assert calls == []
    finally:
        h.close()


# --- CrewAI's own fail-open property, documented + guarded against -----------------------------

def test_crewai_dispatcher_itself_fails_open_on_a_bare_exception_from_an_unrelated_hook(tmp_path):
    """Documents, empirically, the exact framework property `before_tool_call_hook`'s
    try/except-translate-to-HookAborted exists to defend against (module docstring): CrewAI's
    OWN dispatcher (crewai/hooks/dispatch.py) silently swallows any exception from a hook that is
    NOT a HookAborted, and the tool still runs. This is CrewAI's property, not naalp_crewai's --
    verified independently of the guard, using a throwaway hook, so a future crewai release that
    changed this behavior would be caught here rather than silently invalidating the safety
    argument in the adapter's docstring."""
    crewai_hooks.clear_all_tool_call_hooks()
    try:
        calls = []

        def buggy_hook(context):
            raise ValueError("a buggy hook, not ours")

        def plain_tool(x):
            calls.append(x)
            return "ran"

        crewai_hooks.register_before_tool_call_hook(buggy_hook)
        tool = _make_tool(plain_tool, "plain_tool")
        result = _drive(tool, "plain_tool", {"x": 1})

        assert calls == [1], "CrewAI's dispatcher fails OPEN on a bare (non-HookAborted) exception"
        assert result.result == "ran"
    finally:
        crewai_hooks.clear_all_tool_call_hooks()


# --- causal chaining across two guarded calls in the same CrewAI Task -------------------------

def test_receipts_chain_within_a_task_and_not_across_tasks(tmp_path):
    """Each `before_tool_call_hook`+`after_tool_call_hook` pair appends TWO records to its
    session's chain -- a pre-action capture (signed BEFORE authorize/gate, so authorization is
    checked against a real, signature-derived identity, K0's own discipline) and the receipt
    itself, chained to it. Read the RAW log back independently (F3) and confirm every record's
    `causes` names exactly the immediately preceding record's real id within the SAME task, and
    that a fresh task's first record has no causes at all."""
    h = _Harness(tmp_path, effect_classifier=lambda k, a: policy.READ_ONLY)
    try:
        def noop(**kwargs):
            return "ok"

        task_a = Task(description="a", expected_output="e")
        task_b = Task(description="b", expected_output="e")

        tool_a = _make_tool(lambda: "ok", "a")
        tool_b = _make_tool(lambda x: "ok", "b")
        tool_c = _make_tool(lambda: "ok", "c")

        _drive(tool_a, "a", {}, task=task_a)
        _drive(tool_b, "b", {"x": 1}, task=task_a)
        _drive(tool_c, "c", {}, task=task_b)

        import io as _io
        records = ChainRecorder.read_all(_io.BytesIO(b"".join(h.stream_records)))
        assert len(records) == 6  # 2 calls * 2 records + 1 call * 2 records, in append order

        decoded = [_decode_and_verify(h.signer, r) for r in records]
        # task_a: 4 records, each chaining to the one immediately before it.
        assert decoded[0].causes == []
        assert decoded[1].causes == [decoded[0].id]
        assert decoded[2].causes == [decoded[1].id]
        assert decoded[3].causes == [decoded[2].id]
        # task_b: a FRESH chain, never touching task_a's records.
        assert decoded[4].causes == []
        assert decoded[5].causes == [decoded[4].id]
        assert decoded[4].id not in (decoded[i].id for i in range(4))
    finally:
        h.close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
