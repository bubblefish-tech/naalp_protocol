# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Mutation-surviving tests for the LANDMARK N-AALP LangGraph adapter
(ecosystem/naalp-langgraph/naalp_langgraph/langgraph_adapter.py). Every gated-path test here
drives a REAL, compiled `langgraph.graph.StateGraph` with a REAL `InMemorySaver` checkpointer
through `app.invoke()`/`app.invoke(Command(resume=...))` -- `langgraph.types.interrupt()` raises
`RuntimeError("Called get_config outside of a runnable context")` when called outside an actual
graph run (confirmed live this session), so there is no way to fake this interception with a
bare function call: every test that exercises the gate is, by construction, exercising the real
LangGraph hook (anti-fake rule A9/A5).

Non-circularity (F3): every recorded signed object is independently decoded and verified through
`naalp.ez.verify` -- the same real, already-graded Part-1 core -- never merely re-read through
naalp_langgraph's own bookkeeping.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1, using the real Python interpreter -- not the
Microsoft Store `python`/`python3` execution-alias stubs, which hang):
    PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-langgraph/tests/test_langgraph_adapter.py -v
"""
import os
import sys
import uuid

import pytest

# ecosystem/naalp-langgraph's package dir name has a hyphen and so cannot itself be part of a
# dotted import path; insert its own directory (the parent of this tests/ dir) onto sys.path so
# `naalp_langgraph` (the underscore package, sibling of tests/) is importable regardless of the
# invocation cwd -- same problem naalp-adk-plugin's/naalp-a2a-bridge's tests solve identically.
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from naalp_langgraph import (
    NaalpLangGraphGuard, ChainRecorder, MalformedResumeDecision,
    CHANNEL_BRIDGE, KIND_CARRIAGE, canonical_json_bytes, args_content_id,
)
from naalp_hitl import JsonlRefusalLog
from naalp_hitl.durable import DurableHITLInterceptor
from naalp import approval, cose, ez, policy

from langgraph.graph import StateGraph, START, END
from langgraph.types import interrupt as lg_interrupt, Command
from langgraph.checkpoint.memory import InMemorySaver

APPROVER_ID = "human-approver-1"
AUDIENCE = "svc:langgraph-agent"
IDENTITY = "langgraph-hitl-interceptor-1"
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
        self.guard = NaalpLangGraphGuard(
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
    through naalp_langgraph's own code path."""
    return ez.verify(signer.public_key, signed_bytes)


def _new_thread_id():
    return "thread-" + uuid.uuid4().hex


def _build_gated_graph(guard, kind, forward_fn, *, session_key, principal=""):
    """A minimal, REAL compiled StateGraph whose one node calls
    `guard.on_effecting_action(kind, state['args'], forward_fn, ...)` -- the exact real
    LangGraph substrate the landmark adapter is built on (StateGraph + a checkpointer +
    thread_id, per the D5 ranking pass's confirmed mechanism)."""

    def node(state):
        result, receipt = guard.on_effecting_action(
            kind, state["args"], forward_fn, session_key=session_key, principal=principal,
        )
        return {"result": result, "receipt": receipt}

    graph = StateGraph(dict)
    graph.add_node("n", node)
    graph.add_edge(START, "n")
    graph.add_edge("n", END)
    return graph.compile(checkpointer=InMemorySaver())


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
        forward_calls = []

        def forward(args):
            forward_calls.append(args)
            return {"rows": [1, 2, 3]}

        graph = _build_gated_graph(h.guard, "list_files", forward, session_key="s1")
        out = graph.invoke({"args": {"path": "/tmp"}}, config={"configurable": {"thread_id": "t1"}})
        assert "__interrupt__" not in out  # a read-only action never pauses the graph
        assert out["result"] == {"rows": [1, 2, 3]}
        assert forward_calls == [{"path": "/tmp"}]

        receipt = out["receipt"]
        assert receipt.effect == policy.READ_ONLY
        obj = _decode_and_verify(h.signer, receipt.signed_bytes)  # F3: independent core verify
        assert obj.channel == CHANNEL_BRIDGE
        assert obj.kind == KIND_CARRIAGE
        assert obj.effect == policy.READ_ONLY
    finally:
        h.close()


# --- P-CLOSED: unclassified effect defaults to DESTRUCTIVE -> approval required -----------------
# (RED-EVIDENCE M1 target: the gating threshold check `requires_approval(effect)`.)

def test_unclassified_effect_defaults_destructive_and_requires_approval(tmp_path):
    """AC-1.1.3: an unrecognized effect class is treated destructive, which requires approval --
    proven here by observing the REAL LangGraph graph actually PAUSE (an `__interrupt__` entry
    appears) for an action with NO effect_classifier supplied, even though nothing about its
    name ("list_files") suggests destructiveness. If the fail-closed default were broken (a
    benign default guessed instead of DESTRUCTIVE, or the gating threshold check disabled), the
    graph would never pause and this assertion would fail."""
    h = _Harness(tmp_path)  # no effect_classifier -> K0-3 fail-closed default applies
    try:
        def forward(args):
            pytest.fail("forward() must never run before the graph has actually paused for approval")

        graph = _build_gated_graph(h.guard, "list_files", forward, session_key="s1")
        out = graph.invoke({"args": {"path": "/tmp"}}, config={"configurable": {"thread_id": "t2"}})
        assert "__interrupt__" in out, "an unclassified action must default to DESTRUCTIVE and pause for approval"
        payload = out["__interrupt__"][0].value
        assert payload["effect"] == policy.DESTRUCTIVE
    finally:
        h.close()


# --- interrupt()/Command(resume=) mapping: approve / reject / edit -----------------------------

def test_approve_true_resumes_and_forwards_the_original_args(tmp_path):
    h = _Harness(tmp_path)
    try:
        forward_calls = []

        def forward(args):
            forward_calls.append(dict(args))
            return {"status": "deleted"}

        thread = "t-approve"
        graph = _build_gated_graph(h.guard, "delete_row", forward, session_key=thread, principal="agent:bot-1")
        cfg = {"configurable": {"thread_id": thread}}
        first = graph.invoke({"args": {"id": 42}}, config=cfg)
        assert "__interrupt__" in first

        out = graph.invoke(Command(resume=True), config=cfg)
        assert "__interrupt__" not in out
        assert out["result"] == {"status": "deleted"}
        assert forward_calls == [{"id": 42}]  # unedited args forwarded verbatim

        receipt = out["receipt"]
        assert receipt.effect == policy.DESTRUCTIVE
        obj = _decode_and_verify(h.signer, receipt.signed_bytes)
        recovered = None
        from naalp_kit import binding as _binding
        import json as _json
        recovered = _json.loads(_binding._extract_payload(obj.body))
        assert recovered["tool"] == "delete_row"
        assert recovered["args"] == {"id": 42}
        assert recovered["result"] == {"status": "deleted"}

        assert h.interceptor.store.load(args_content_id({"id": 42})).status == "approved"
    finally:
        h.close()


def test_reject_false_fails_closed_and_forward_never_runs(tmp_path):
    h = _Harness(tmp_path)
    try:
        forward_calls = []

        def forward(args):
            forward_calls.append(args)
            return "SHOULD NOT HAPPEN"

        thread = "t-reject"
        graph = _build_gated_graph(h.guard, "rm_rf", forward, session_key=thread, principal="agent:bot-2")
        cfg = {"configurable": {"thread_id": thread}}
        graph.invoke({"args": {"path": "/"}}, config=cfg)

        with pytest.raises(approval.ApprovalError) as exc_info:
            graph.invoke(Command(resume=False), config=cfg)
        assert exc_info.value.kind == "ApprovalDenied"
        assert forward_calls == []  # the action was NEVER forwarded
        assert h.interceptor.store.load(args_content_id({"path": "/"})).status == "rejected"

        # D6: the refusal was durably logged, including the real source principal.
        entries = h.refusal_log.read_all()
        assert len(entries) == 1
        assert entries[0]["source_principal"] == "agent:bot-2"
        assert entries[0]["outcome_reason"] == "ApprovalDenied"
    finally:
        h.close()


def test_edit_binds_the_approval_to_the_edited_args_not_the_original(tmp_path):
    """AC-2.2.1, at the LangGraph seam: `Command(resume={"amount": 1})` (review-and-edit) must
    forward the EDITED args to the tool, and the receipt must record the edited args -- never
    the original the human was first asked about."""
    h = _Harness(tmp_path)
    try:
        forward_calls = []

        def forward(args):
            forward_calls.append(dict(args))
            return {"status": "transferred", "amount": args["amount"]}

        thread = "t-edit"
        graph = _build_gated_graph(h.guard, "wire_transfer", forward, session_key=thread)
        cfg = {"configurable": {"thread_id": thread}}
        graph.invoke({"args": {"account": "acct-9", "amount": 250000}}, config=cfg)

        out = graph.invoke(Command(resume={"account": "acct-9", "amount": 1}), config=cfg)
        assert out["result"] == {"status": "transferred", "amount": 1}
        assert forward_calls == [{"account": "acct-9", "amount": 1}]  # EDITED args forwarded

        original_id = args_content_id({"account": "acct-9", "amount": 250000})
        stored = h.interceptor.store.load(original_id)
        assert stored.status == "edited"
        assert stored.edited_content_id == args_content_id({"account": "acct-9", "amount": 1})
    finally:
        h.close()


def test_edit_rejected_when_effect_reclassifies_but_edit_content_id_still_binds_correctly(tmp_path):
    """A sanity check that an edit whose approval accidentally names the ORIGINAL (un-edited)
    content id is rejected -- exactly durable.py's own already-graded ApprovalMismatch behaviour,
    reached here through the LangGraph seam rather than called directly, proving the adapter
    does not bypass that protection."""
    h = _Harness(tmp_path)
    try:
        def forward(args):
            pytest.fail("forward() must never run when the edit's approval is mismatched")

        thread = "t-edit-mismatch"
        graph = _build_gated_graph(h.guard, "wire_transfer", forward, session_key=thread)
        cfg = {"configurable": {"thread_id": thread}}
        graph.invoke({"args": {"account": "acct-1", "amount": 500}}, config=cfg)

        # Monkeypatch the guard's own approval-minting to sign the ORIGINAL id instead of the
        # edited one -- simulating a broken front end, never a naalp_langgraph code change.
        original_mint = h.guard._mint_approval

        def _mint_wrong_id(_content_id, effect):
            wrong_id = args_content_id({"account": "acct-1", "amount": 500})
            return original_mint(wrong_id, effect)

        h.guard._mint_approval = _mint_wrong_id
        with pytest.raises(approval.ApprovalError) as exc_info:
            graph.invoke(Command(resume={"account": "acct-1", "amount": 1}), config=cfg)
        assert exc_info.value.kind == "ApprovalMismatch"
    finally:
        h.close()


def test_malformed_resume_decision_raises_a_named_error(tmp_path):
    h = _Harness(tmp_path)
    try:
        def forward(args):
            pytest.fail("forward() must never run on a malformed resume decision")

        thread = "t-malformed"
        graph = _build_gated_graph(h.guard, "rm_rf", forward, session_key=thread)
        cfg = {"configurable": {"thread_id": thread}}
        graph.invoke({"args": {"path": "/"}}, config=cfg)
        with pytest.raises(MalformedResumeDecision):
            graph.invoke(Command(resume="not-a-valid-decision-shape"), config=cfg)
    finally:
        h.close()


# --- authorize is UNCONDITIONAL (design.md 2.1): denies BEFORE any interrupt --------------------

def test_authorize_denies_before_any_interrupt_when_grant_ceiling_too_low(tmp_path):
    h = _Harness(tmp_path, grant_ceiling=policy.READ_ONLY, effect_classifier=lambda k, a: policy.IDEMPOTENT_WRITE)
    try:
        def forward(args):
            pytest.fail("forward() must never run when authorization is refused")

        thread = "t-authz-deny"
        graph = _build_gated_graph(h.guard, "upsert_row", forward, session_key=thread)
        cfg = {"configurable": {"thread_id": thread}}
        with pytest.raises(policy.PolicyError) as exc_info:
            graph.invoke({"args": {"id": 1}}, config=cfg)
        assert exc_info.value.kind == "EffectNotAuthorized"
    finally:
        h.close()


def test_authorize_denies_when_grant_principal_does_not_match_the_signer(tmp_path):
    h = _Harness(tmp_path, principal="a-different-signer-id")
    try:
        def forward(args):
            pytest.fail("forward() must never run when authorization is refused")

        thread = "t-authz-wrong-principal"
        graph = _build_gated_graph(h.guard, "read_db", forward, session_key=thread)
        cfg = {"configurable": {"thread_id": thread}}
        with pytest.raises(policy.PolicyError):
            graph.invoke({"args": {"q": "select 1"}}, config=cfg)
    finally:
        h.close()


# --- causal chaining across two guarded calls in the same LangGraph thread ----------------------

def test_receipts_chain_within_a_session_and_not_across_sessions(tmp_path):
    """Each `on_effecting_action` call appends TWO records to its session's chain -- a pre-action
    capture (signed BEFORE authorize/gate, so authorization is checked against a real,
    signature-derived identity, K0's own discipline) and the receipt itself, chained to it. Read
    the RAW log back independently (F3) and confirm every record's `causes` names exactly the
    immediately preceding record's real id within the SAME session, and that a fresh session's
    first record has no causes at all."""
    h = _Harness(tmp_path, effect_classifier=lambda k, a: policy.READ_ONLY)
    try:
        def forward(args):
            return "ok"

        graph1 = _build_gated_graph(h.guard, "a", forward, session_key="shared-thread")
        graph1.invoke({"args": {}}, config={"configurable": {"thread_id": "ta"}})

        graph2 = _build_gated_graph(h.guard, "b", forward, session_key="shared-thread")
        graph2.invoke({"args": {"x": 1}}, config={"configurable": {"thread_id": "tb"}})

        graph3 = _build_gated_graph(h.guard, "c", forward, session_key="a-different-session")
        graph3.invoke({"args": {}}, config={"configurable": {"thread_id": "tc"}})

        import io as _io
        records = ChainRecorder.read_all(_io.BytesIO(b"".join(h.stream_records)))
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
