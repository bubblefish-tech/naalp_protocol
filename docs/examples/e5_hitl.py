# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP cookbook: the HITL (human-in-the-loop) pattern (E5.2, R8.2), via `naalp_hitl`.

`naalp_hitl.HITLInterceptor` wraps any effecting action whose effect class requires
human sign-off: PAUSE the action, route a real `ApprovalRequest` to a pluggable
`HumanInterface` (a terminal front end here; a web or chat front end plugs into the same
contract), and RESUME (call the action's `execute`) only after a real, single-use,
audience-bound N-AALP approval object has been verified and durably consumed --
otherwise fail closed, with the action never running.

This recipe runs the SAME destructive action through the gate twice: once where the
human approves (the action runs), and once where the human declines (the action never
runs, and no partial state changes).

Run (from the repository root):
    python docs/examples/e5_hitl.py
"""
import os
import sys
import tempfile

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))
_p = os.path.join(_REPO_ROOT, "ecosystem", "naalp-hitl")
if _p not in sys.path:
    sys.path.insert(0, _p)

from naalp_hitl import HITLError, HITLInterceptor, PendingAction, TerminalFrontend  # noqa: E402
from naalp import approval, cose, policy  # noqa: E402
from naalp.cbor import M, T, U  # noqa: E402

AUDIENCE = "svc:database-admin-hitl-cookbook"


def _make_interceptor(ledger, approver_seed, human_answer):
    approver_pk = cose.mldsa_keygen("ML-DSA-65", approver_seed)
    answers = iter([human_answer])
    frontend = TerminalFrontend(
        "db-admin-1", approver_seed, input_fn=lambda _p: next(answers)
    )
    return HITLInterceptor(
        ledger, cose.ALG_MLDSA65, approver_pk, AUDIENCE, "hitl-cookbook", frontend,
    )


def main() -> int:
    approver_seed = bytes([0x91]) * 32

    with tempfile.TemporaryDirectory() as d:
        ledger = approval.open_ledger(os.path.join(d, "consume.wal"))
        try:
            print("=" * 74)
            print("The human APPROVES: the destructive action runs exactly once")
            print("=" * 74)
            executed = []

            def _drop_table():
                executed.append("TABLE_DROPPED")
                return "TABLE_DROPPED"

            action_a = PendingAction(
                kind="db.drop_table", effect=policy.DESTRUCTIVE,
                args=M([(U(1), T("stale_sessions"))]),
                args_summary="DROP TABLE stale_sessions (retention policy expired)",
                execute=_drop_table,
            )
            interceptor_yes = _make_interceptor(ledger, approver_seed, "y")
            outcome = interceptor_yes.intercept(action_a)
            print("intercept() outcome:", outcome)
            print("action executed:", executed)
            assert outcome == "TABLE_DROPPED" and executed == ["TABLE_DROPPED"]

            print()
            print("=" * 74)
            print("The human DECLINES: the SAME kind of action never runs, no state change")
            print("=" * 74)
            executed_b = []

            def _drop_other_table():
                executed_b.append("SHOULD_NEVER_APPEAR")
                return "SHOULD_NEVER_APPEAR"

            action_b = PendingAction(
                kind="db.drop_table", effect=policy.DESTRUCTIVE,
                args=M([(U(1), T("customer_orders"))]),
                args_summary="DROP TABLE customer_orders",
                execute=_drop_other_table,
            )
            interceptor_no = _make_interceptor(ledger, approver_seed, "n")
            try:
                interceptor_no.intercept(action_b)
                print("FAIL: the declined action ran -- this would be a security bug")
                return 1
            except HITLError as e:
                print("intercept() raised:", e.kind)
            print("action executed:", executed_b)
            assert executed_b == []

            print()
            print("ledger entries: %d (one append, for the APPROVED action only --" % len(ledger))
            print("the declined request never touched the ledger)")
            assert len(ledger) == 1
        finally:
            ledger.close()

    print("\nHITL COOKBOOK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
