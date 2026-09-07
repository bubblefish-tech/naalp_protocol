# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""A9 isolation demonstration for the N-AALP HITL interceptor (E0.1/R1; D6 audit trail): a
concrete pause -> human-terminal-approval -> verify+consume -> resume run with a real ML-DSA-65
approver key, a real signed N-AALP approval object, and a real durable consume ledger --
followed by a reuse of that SAME approval object, shown failing closed (AlreadyConsumed); then a
D6 pass showing a below-threshold refusal (Layer-1-only audit log) and an at-threshold refusal
(Layer-1 log + a real signed AU-10 non-repudiation record, verified, and its coarse Refusal
round-tripped through parse_refusal).

Run (from ecosystem/naalp-hitl/, using the real Python on this machine, not the Microsoft
Store `python` stub):
    python scripts/isolation_demo.py
"""
import os
import sys
import tempfile

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-hitl
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_hitl import (  # noqa: E402
    ApprovalRequest, PendingAction, HITLInterceptor, TerminalFrontend, JsonlRefusalLog,
    verify_refusal_record,
)
from naalp import approval, cbor, cose, policy  # noqa: E402
from naalp.cbor import U, T, M  # noqa: E402


def main() -> int:
    seed = bytes([0x42]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    approver_id = "ops-approver-1"
    audience = "svc:payments-hitl-demo"

    signing_seed = bytes([0x77]) * 32
    signing_pk = cose.mldsa_keygen("ML-DSA-65", signing_seed)

    with tempfile.TemporaryDirectory() as d:
        ledger = approval.open_ledger(os.path.join(d, "consume.wal"))
        refusal_log = JsonlRefusalLog(os.path.join(d, "refusals.jsonl"))
        try:
            print("=" * 72)
            print("PASS 1: pause -> human approves (terminal front end) -> verify+consume -> resume")
            print("=" * 72)

            # A scripted stdin answer ("y") stands in for the human operator's keystroke; every
            # step downstream of that keystroke -- signing, verification, the ledger -- is real,
            # unfaked code.
            answers = iter(["y"])
            frontend = TerminalFrontend(approver_id, seed, input_fn=lambda _p: next(answers))
            interceptor = HITLInterceptor(
                ledger, cose.ALG_MLDSA65, pk, audience, "hitl-interceptor-demo", frontend,
                refusal_log=refusal_log, signing_alg=cose.ALG_MLDSA65, signing_seed=signing_seed,
            )

            args1 = M([(U(1), T("acct-778-441")), (U(2), U(500_000))])
            executed = []

            def _wire():
                executed.append("WIRE_EXECUTED")
                return "WIRE_EXECUTED"

            action = PendingAction(
                kind="wire_transfer",
                effect=policy.DESTRUCTIVE,
                args=args1,
                args_summary="wire 500000 (cents) from treasury to acct-778-441",
                execute=_wire,
            )
            result = interceptor.intercept(action)
            print("intercept() returned: %r" % (result,))
            print("action actually executed: %r" % (executed,))
            print("ledger entries after pass 1: %d" % len(ledger))
            assert result == "WIRE_EXECUTED" and executed == ["WIRE_EXECUTED"] and len(ledger) == 1

            print()
            print("=" * 72)
            print("PASS 2: mint ONE approval object, consume it once, then REPLAY it -> fail closed")
            print("=" * 72)

            args2 = M([(U(1), T("acct-999-222")), (U(2), U(75_000))])
            args2_id = cbor.content_id(args2)
            req = ApprovalRequest(
                content_id=args2_id,
                effect=policy.DESTRUCTIVE,
                kind="wire_transfer",
                args_summary="wire 75000 (cents) from treasury to acct-999-222",
                audience=audience,
            )
            answers2 = iter(["y"])
            frontend2 = TerminalFrontend(approver_id, seed, input_fn=lambda _p: next(answers2))
            rec, sig = frontend2.request_approval(req)  # ONE real signed approval, minted once
            print("minted approval id: %s" % rec.id().hex())

            interceptor.verify_and_consume(rec, sig, args2_id, policy.DESTRUCTIVE)
            print("first consume of this approval object: OK (ledger entries: %d)" % len(ledger))

            try:
                interceptor.verify_and_consume(rec, sig, args2_id, policy.DESTRUCTIVE)
                print("FAIL: reuse was NOT rejected -- this would be a security bug")
                return 1
            except approval.ApprovalError as e:
                print("reuse of the SAME approval object correctly rejected fail-closed: kind=%s" % e.kind)
                assert e.kind == "AlreadyConsumed"

            print("ledger entries after pass 2: %d (exactly one append for this approval id)" % len(ledger))
            assert len(ledger) == 2  # pass-1's entry + pass-2's single successful consume

            print()
            print("=" * 72)
            print("PASS 3a: D6 -- a BELOW-threshold refusal gets a Layer-1 audit entry, no signed record")
            print("=" * 72)

            args3 = M([(U(1), T("acct-low-1")), (U(2), U(10))])
            args3_id = cbor.content_id(args3)
            # A record that does not bind args3 at all -> ApprovalMismatch, for a NON_IDEMPOTENT_WRITE
            # action -- below the interceptor's default non_repudiation_threshold (DESTRUCTIVE).
            mismatched = approval.ApprovalRecord(
                cbor.content_id(M([(U(1), T("acct-someone-else"))])), approver_id,
                policy.NON_IDEMPOTENT_WRITE, b"\x21" * 8, interceptor.now_ms() + 60_000, audience,
            )
            mismatched_sig = approval.sign_approval(mismatched, cose.ALG_MLDSA65, seed)
            try:
                interceptor.verify_and_consume(
                    mismatched, mismatched_sig, args3_id, policy.NON_IDEMPOTENT_WRITE,
                    kind="update_profile", principal="agent:low-risk-bot",
                )
                print("FAIL: mismatched approval was NOT rejected -- this would be a security bug")
                return 1
            except approval.ApprovalError as e:
                print("refused fail-closed: kind=%s" % e.kind)
                assert e.kind == "ApprovalMismatch"
                assert e.d6.record is None and e.d6.record_sig is None and e.d6.refusal is None, (
                    "below threshold must NEVER mint a signed record, even with a signing key configured"
                )

            entries = refusal_log.read_all()
            print("Layer-1 log entries so far: %d" % len(entries))
            # entry 0 is PASS 2's AlreadyConsumed replay refusal (same interceptor, same sink);
            # entry 1 is this pass's ApprovalMismatch refusal.
            assert len(entries) == 2
            last = entries[-1]
            print("  what_kind=%r outcome_reason=%r source_principal=%r approver_identity=%r"
                  % (last["what_kind"], last["outcome_reason"],
                     last["source_principal"], last["approver_identity"]))
            assert last["outcome_reason"] == "ApprovalMismatch"
            assert last["source_principal"] == "agent:low-risk-bot"

            print()
            print("=" * 72)
            print("PASS 3b: D6 -- an AT-threshold refusal ALSO mints a real signed AU-10 record")
            print("=" * 72)

            args4 = M([(U(1), T("acct-high-1")), (U(2), U(1_000_000))])
            args4_id = cbor.content_id(args4)
            underscoped = approval.ApprovalRecord(
                args4_id, approver_id, policy.READ_ONLY, b"\x22" * 8,
                interceptor.now_ms() + 60_000, audience,
            )
            underscoped_sig = approval.sign_approval(underscoped, cose.ALG_MLDSA65, seed)
            try:
                interceptor.verify_and_consume(
                    underscoped, underscoped_sig, args4_id, policy.DESTRUCTIVE,
                    kind="wire_transfer", principal="agent:high-risk-bot",
                )
                print("FAIL: an under-scoped approval was NOT rejected -- this would be a security bug")
                return 1
            except approval.ApprovalError as e:
                print("refused fail-closed: kind=%s" % e.kind)
                assert e.kind == "ApprovalRequired"
                d6 = e.d6
                assert d6.record is not None and d6.record_sig is not None and d6.refusal is not None
                verified = verify_refusal_record(d6.record, cose.ALG_MLDSA65, signing_pk, d6.record_sig)
                print("signed refusal-decision record verifies under the interceptor's pubkey: %r" % verified)
                assert verified
                assert d6.refusal.outcome == approval.REFUSAL_HELD
                assert d6.refusal.record == d6.record.content_id()
                parsed = approval.parse_refusal(d6.refusal.bytes())
                print("parse_refusal(refusal.bytes()) -> outcome=%d record=%s"
                      % (parsed.outcome, parsed.record.hex()))
                assert parsed.outcome == approval.REFUSAL_HELD
                assert parsed.record == d6.record.content_id()

            entries = refusal_log.read_all()
            print("Layer-1 log entries after pass 3b: %d" % len(entries))
            assert len(entries) == 3

            print()
            print("ISOLATION DEMO: PASS")
            return 0
        finally:
            ledger.close()


if __name__ == "__main__":
    raise SystemExit(main())
