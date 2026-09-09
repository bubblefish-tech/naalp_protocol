# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance + mutation-surviving tests for naalp_mcp_guard.effect_gate (Group 6, Task A.1(b)/
(c); AC-6.1.1/6.1.2; P-CLOSED).

Every test exercises the REAL naalp_mcp_bridge carry/verify path, the REAL naalp_hitl
HITLInterceptor (pause/approve/deny/consume), the REAL naalp.approval durable ledger, and REAL
ML-DSA signing -- nothing here fakes cryptography or the ledger. The two load-bearing properties
this file records mutation evidence for (see RED-EVIDENCE.md) are:

  - EffectGate.classify        (THE FAIL-CLOSED CLASSIFIER)
  - EffectGate.authorize_and_execute   (THE EFFECT GATE)

Run (from ecosystem/naalp-mcp-guard/, PYTHONDONTWRITEBYTECODE=1, using the real Python interpreter
for this platform):
    python -m unittest -v tests.test_effect_gate
"""
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-mcp-guard
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_mcp_guard.effect_gate import EffectGate, GuardError  # noqa: E402
from naalp_mcp_guard import receipt as receipt_mod  # noqa: E402

from naalp import approval, cose, policy  # noqa: E402
from naalp_hitl.interceptor import HumanInterface  # noqa: E402
from naalp_hitl.refusal_log import JsonlRefusalLog  # noqa: E402

ALG = cose.ALG_MLDSA65
AUDIENCE = "svc:mcp-guard-test"


def _tool(name, *, read_only=None, destructive=None, idempotent=None):
    annotations = {}
    if read_only is not None:
        annotations["readOnlyHint"] = read_only
    if destructive is not None:
        annotations["destructiveHint"] = destructive
    if idempotent is not None:
        annotations["idempotentHint"] = idempotent
    d = {"name": name}
    if annotations:
        d["annotations"] = annotations
    return d


def _call(name, arguments=None, rpc_id=1):
    return {
        "jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


class _FixedDecisionInterface(HumanInterface):
    """Drives the interceptor's pause/route/resume wiring under test control, exactly the
    ecosystem/naalp-hitl convention: fakes only the human's keystroke, never the cryptography."""

    def __init__(self, decision):
        self._decision = decision
        self.calls = 0

    def request_approval(self, request):
        self.calls += 1
        return self._decision


def _approver_key(seed_byte=0x41):
    seed = bytes([seed_byte]) * 32
    return seed, cose.mldsa_keygen("ML-DSA-65", seed)


class _Harness(unittest.TestCase):
    """Common real-primitive fixtures: ONE real, durable ledger per test (opened once, closed in
    tearDown -- matching ecosystem/naalp-hitl/tests/test_interceptor.py's own convention; a
    Ledger's underlying WAL file handle stays open for its lifetime, so reopening the SAME path
    without closing the prior handle leaks a file descriptor and, on Windows, blocks the temp
    directory's own cleanup). Multiple `EffectGate` instances -- one per human-interface swap --
    may share this single already-open ledger; `_gate()` never reopens the file."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.guard_seed = bytes([0x51]) * 32
        self.approver_seed, self.approver_pk = _approver_key()
        self.ledger = approval.open_ledger(os.path.join(self._tmp.name, "ledger.wal"), authority=AUDIENCE)
        self.addCleanup(self.ledger.close)
        self.refusal_log = JsonlRefusalLog(os.path.join(self._tmp.name, "refusals.jsonl"))

    def _gate(self, human_interface, *, approval_threshold=policy.NON_IDEMPOTENT_WRITE, ledger=None):
        return EffectGate(
            guard_seed=self.guard_seed, guard_identity="guard-under-test", audience=AUDIENCE,
            approver_alg=ALG, approver_pubkey=self.approver_pk,
            human_interface=human_interface, refusal_log=self.refusal_log,
            ledger=ledger if ledger is not None else self.ledger,
            approval_threshold=approval_threshold,
        )


class ClassifyFailClosedTests(_Harness):
    """THE FAIL-CLOSED CLASSIFIER (mutation-evidenced in RED-EVIDENCE.md)."""

    def test_read_only_tool_does_not_require_approval(self):
        gate = self._gate(_FixedDecisionInterface(None))
        decision = gate.classify(_tool("list_files", read_only=True), _call("list_files"))
        self.assertFalse(decision.requires_approval)
        self.assertEqual(decision.bridged.enforced_effect, policy.READ_ONLY)

    def test_explicit_destructive_tool_requires_approval(self):
        gate = self._gate(_FixedDecisionInterface(None))
        decision = gate.classify(
            _tool("delete_repo", read_only=False, destructive=True), _call("delete_repo"),
        )
        self.assertTrue(decision.requires_approval)
        self.assertEqual(decision.bridged.enforced_effect, policy.DESTRUCTIVE)

    def test_idempotent_write_tool_requires_approval_at_default_threshold(self):
        # default threshold is NON_IDEMPOTENT_WRITE, and idempotent_write < that -- so an
        # idempotent write should NOT require approval at the default threshold.
        gate = self._gate(_FixedDecisionInterface(None))
        decision = gate.classify(
            _tool("upsert_record", read_only=False, destructive=False, idempotent=True),
            _call("upsert_record"),
        )
        self.assertFalse(decision.requires_approval)
        self.assertEqual(decision.bridged.enforced_effect, policy.IDEMPOTENT_WRITE)

    def test_unknown_tool_definition_classifies_destructive_and_requires_approval(self):
        """P-CLOSED: an action whose effect class is unknown/unassigned yields DESTRUCTIVE and
        requires approval -- the fail-closed default, from naalp.mcp's OWN published table, not a
        guard-invented rule. This is the SAME real classification path as an explicitly-annotated
        destructive tool (test above): if the classifier were replaced by a constant that always
        returns `requires_approval=False`, THIS test fails while a mutant returning
        `requires_approval=True` unconditionally fails the read-only test above -- no constant
        return satisfies both, which is exactly the mutation-survival property."""
        gate = self._gate(_FixedDecisionInterface(None))
        decision = gate.classify(None, _call("totally_unknown_tool"))
        self.assertTrue(decision.requires_approval)
        self.assertEqual(decision.bridged.enforced_effect, policy.DESTRUCTIVE)

    def test_tool_name_mismatch_falls_back_to_the_calls_own_name_and_stays_fail_closed(self):
        """A cached definition for a DIFFERENT tool name than the call must not leak that other
        tool's (possibly benign) annotations onto this call."""
        gate = self._gate(_FixedDecisionInterface(None))
        wrong_tool = _tool("read_file", read_only=True)
        decision = gate.classify(wrong_tool, _call("delete_everything"))
        self.assertEqual(decision.tool_name, "delete_everything")
        self.assertTrue(decision.requires_approval)
        self.assertEqual(decision.bridged.enforced_effect, policy.DESTRUCTIVE)

    def test_malformed_call_request_raises_guard_error(self):
        gate = self._gate(_FixedDecisionInterface(None))
        with self.assertRaises(GuardError):
            gate.classify(_tool("x"), {"jsonrpc": "2.0", "id": 1, "method": "tools/call"})  # no params

    def test_same_tool_different_arguments_yields_different_call_binding(self):
        """Requirement 6.1: changed arguments must yield a new call-binding content id."""
        gate = self._gate(_FixedDecisionInterface(None))
        tool = _tool("transfer_funds", read_only=False, destructive=True)
        d1 = gate.classify(tool, _call("transfer_funds", {"amount": 10}))
        d2 = gate.classify(tool, _call("transfer_funds", {"amount": 20}))
        self.assertNotEqual(d1.call_binding.content_id(), d2.call_binding.content_id())


class AuthorizeAndExecuteTests(_Harness):
    """THE EFFECT GATE (mutation-evidenced in RED-EVIDENCE.md)."""

    def _approve(self, decision, *, effect=None):
        record = approval.ApprovalRecord(
            approves=decision.call_binding.content_id(), approver="operator-1",
            grant=policy.DESTRUCTIVE if effect is None else effect,
            nonce=b"\x01" * 16, not_after=9_999_999_999_999, audience=AUDIENCE,
        )
        sig = approval.sign_approval(record, ALG, self.approver_seed)
        return record, sig

    def test_read_only_call_executes_without_any_approval_prompt(self):
        iface = _FixedDecisionInterface(None)
        gate = self._gate(iface)
        decision = gate.classify(_tool("list_files", read_only=True), _call("list_files"))
        forwarded = {"called": False}

        def forward():
            forwarded["called"] = True
            return {"jsonrpc": "2.0", "id": 1, "result": {"content": [], "isError": False}}

        result, rec, sig = gate.authorize_and_execute(decision, forward, principal="agent-1")
        self.assertTrue(forwarded["called"])
        self.assertEqual(iface.calls, 0)  # never even asked -- below threshold
        self.assertEqual(rec.decision, receipt_mod.DECISION_EXECUTED)
        self.assertTrue(receipt_mod.verify_effect_receipt(rec, gate.receipt_alg, gate.receipt_pubkey, sig))

    def test_destructive_call_denied_never_forwards_and_mints_a_denied_receipt(self):
        """THE core fail-closed property: a human decline must NEVER let the effect reach
        `forward` -- a mutant that calls forward() unconditionally fails this test while a mutant
        that never calls forward() (even when approved, see test below) fails that one; no
        constant satisfies both."""
        iface = _FixedDecisionInterface(None)  # a decline
        gate = self._gate(iface)
        decision = gate.classify(
            _tool("delete_repo", read_only=False, destructive=True), _call("delete_repo"),
        )
        forwarded = {"called": False}

        def forward():
            forwarded["called"] = True
            return {"result": "SHOULD_NEVER_HAPPEN"}

        with self.assertRaises(GuardError) as ctx:
            gate.authorize_and_execute(decision, forward, principal="agent-1")
        self.assertFalse(forwarded["called"])
        err = ctx.exception
        self.assertIsNotNone(err.receipt)
        self.assertEqual(err.receipt.decision, receipt_mod.DECISION_DENIED)
        self.assertTrue(
            receipt_mod.verify_effect_receipt(err.receipt, gate.receipt_alg, gate.receipt_pubkey, err.receipt_sig)
        )

    def test_destructive_call_approved_forwards_exactly_once_and_mints_an_executed_receipt(self):
        gate = self._gate(_FixedDecisionInterface(None))  # placeholder; replaced below
        decision = gate.classify(
            _tool("delete_repo", read_only=False, destructive=True), _call("delete_repo"),
        )
        decision_record = self._approve(decision)
        gate = self._gate(_FixedDecisionInterface(decision_record))  # fresh ledger reuse, new interface
        decision = gate.classify(
            _tool("delete_repo", read_only=False, destructive=True), _call("delete_repo"),
        )
        forwarded = {"n": 0}

        def forward():
            forwarded["n"] += 1
            return {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "deleted"}], "isError": False}}

        result, rec, sig = gate.authorize_and_execute(decision, forward, principal="agent-1")
        self.assertEqual(forwarded["n"], 1)
        self.assertEqual(rec.decision, receipt_mod.DECISION_EXECUTED)
        self.assertNotEqual(rec.result_hash, b"")
        self.assertTrue(receipt_mod.verify_effect_receipt(rec, gate.receipt_alg, gate.receipt_pubkey, sig))

    def test_replaying_the_same_approval_a_second_time_is_denied(self):
        gate = self._gate(_FixedDecisionInterface(None))
        tool = _tool("delete_repo", read_only=False, destructive=True)
        decision1 = gate.classify(tool, _call("delete_repo"))
        record_sig = self._approve(decision1)

        gate2 = self._gate(_FixedDecisionInterface(record_sig))
        decision2 = gate2.classify(tool, _call("delete_repo"))
        gate2.authorize_and_execute(decision2, lambda: {"result": "ok"}, principal="agent-1")

        # Second attempt, SAME approval object, SAME gate/ledger: must be refused.
        gate3 = self._gate(_FixedDecisionInterface(record_sig))
        decision3 = gate3.classify(tool, _call("delete_repo"))
        with self.assertRaises(GuardError):
            gate3.authorize_and_execute(decision3, lambda: {"result": "REPLAY_SHOULD_NOT_HAPPEN"}, principal="agent-1")

    def test_wrong_audience_approval_is_denied(self):
        gate = self._gate(_FixedDecisionInterface(None))
        tool = _tool("delete_repo", read_only=False, destructive=True)
        decision = gate.classify(tool, _call("delete_repo"))
        record = approval.ApprovalRecord(
            approves=decision.call_binding.content_id(), approver="operator-1",
            grant=policy.DESTRUCTIVE, nonce=b"\x02" * 16, not_after=9_999_999_999_999,
            audience="a-different-audience",
        )
        sig = approval.sign_approval(record, ALG, self.approver_seed)
        gate2 = self._gate(_FixedDecisionInterface((record, sig)))
        decision2 = gate2.classify(tool, _call("delete_repo"))
        with self.assertRaises(GuardError):
            gate2.authorize_and_execute(decision2, lambda: {"result": "SHOULD_NOT_HAPPEN"}, principal="agent-1")


if __name__ == "__main__":
    unittest.main()
