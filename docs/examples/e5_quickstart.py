# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP quickstart (E5.1, R8.1): install -> a verified, audience-bound, HITL-gated
effecting object, in the Python application core.

This script is the exact code behind docs/quickstart.md. It runs the full lifecycle of
one N-AALP effecting object, using only the Part-1 SDK (`naalp`, under impl/python) and
three Part-2 ecosystem packages (`naalp_codec`, `naalp_validator`, `naalp_hitl`):

  1. Build a real agent identity (ML-DSA-65, post-quantum, FIPS 204).
  2. Build the object's args body with `naalp_codec`'s value classes (U/T/M -- the
     blessed deterministic-CBOR codec binding, re-exporting the Part-1 codec directly, so
     this is not a second encoder) and a candidate effecting object -- a DESTRUCTIVE
     Workflow/TaskCancel, bound to an audience -- then validate it with `naalp_validator`
     BEFORE it is ever signed.
  3. Sign it and verify it offline with the Part-1 envelope primitives: a "verified
     effecting object."
  4. Gate the actual side effect behind `naalp_hitl`: pause, route a real ApprovalRequest
     to a human approver, verify + durably consume a real, single-use, audience-bound
     N-AALP approval object, and only then resume (execute).
  5. Show the single-use guarantee: replaying the SAME approval a second time is refused
     fail-closed (`AlreadyConsumed`), with no state change and no re-execution.

Run (from the repository root, using the real Python on this machine -- not the
Microsoft Store `python` stub):
    python docs/examples/e5_quickstart.py
"""
import os
import sys
import tempfile

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))  # docs/examples -> docs -> repo root
for _pkg in ("naalp-hitl", "naalp-validator", "naalp-codec"):
    _p = os.path.join(_REPO_ROOT, "ecosystem", _pkg)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from naalp_hitl import ApprovalRequest, HITLInterceptor, PendingAction, TerminalFrontend  # noqa: E402
from naalp_validator import validate  # noqa: E402
from naalp_codec import M, T, U  # noqa: E402  (the blessed codec binding's own value classes)
from naalp import approval, cbor, cose, envelope, identity, policy  # noqa: E402

WORKFLOW_CHANNEL = 0x0011  # Workflow channel
TASK_CANCEL = 2            # declared effect: DESTRUCTIVE (channels.py TABLE)
AUDIENCE = "svc:workflow-cancel-quickstart"


def main() -> int:
    print("=" * 78)
    print("STEP 1: a real post-quantum agent identity (ML-DSA-65, FIPS 204)")
    print("=" * 78)
    seed = bytes([0x11]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    sid = identity.signer_id(cose.ALG_MLDSA65, pk)
    print("agent signer id:", sid)

    print()
    print("=" * 78)
    print("STEP 2: build the candidate effecting object and validate it BEFORE signing")
    print("=" * 78)
    args = M([(U(1), T("task-4821")), (U(2), T("cancel: upstream vendor SLA breach"))])
    candidate = envelope.Object(
        kind=TASK_CANCEL, channel=WORKFLOW_CHANNEL, signer=sid.encode("utf-8"),
        created=1785000000000, effect=policy.DESTRUCTIVE, profile=cose.PROFILE_PUBLIC,
        body=args, audience=AUDIENCE,
    )
    result = validate(candidate)
    print("pre-sign validation: valid=%s violations=%s" % (result.valid, result.violations))
    assert result.valid

    print()
    print("=" * 78)
    print("STEP 3: sign it, then verify it offline -- a verified effecting object")
    print("=" * 78)
    signed_bytes = envelope.sign(candidate, cose.ALG_MLDSA65, seed)
    print("signed object: %d bytes, content id %s..." % (len(signed_bytes), candidate.id.hex()[:16]))
    verified = envelope.verify(
        cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, pk,
        lambda c, k: (c, k) == (WORKFLOW_CHANNEL, TASK_CANCEL), signed_bytes,
    )
    print("verify(): channel=0x%04x kind=%d effect=%d audience=%r" % (
        verified.channel, verified.kind, verified.effect, verified.audience))
    assert verified.id == candidate.id and verified.effect == policy.DESTRUCTIVE
    assert verified.audience == AUDIENCE

    print()
    print("=" * 78)
    print("STEP 4: gate the side effect behind HITL -- pause, approve, verify+consume, resume")
    print("=" * 78)
    approver_seed = bytes([0x22]) * 32
    approver_pk = cose.mldsa_keygen("ML-DSA-65", approver_seed)
    executed = []

    def _cancel_task():
        executed.append("TASK_CANCELLED")
        return "TASK_CANCELLED"

    action = PendingAction(
        kind="workflow.task_cancel", effect=policy.DESTRUCTIVE, args=args,
        args_summary="cancel task-4821 (upstream vendor SLA breach)", execute=_cancel_task,
    )

    with tempfile.TemporaryDirectory() as d:
        ledger = approval.open_ledger(os.path.join(d, "consume.wal"))
        try:
            # A scripted "y" stands in for the human approver's real terminal keystroke;
            # everything downstream of it -- signing, verification, the ledger -- is real,
            # unfaked code.
            answers = iter(["y"])
            frontend = TerminalFrontend(
                "ops-approver-1", approver_seed, input_fn=lambda _p: next(answers)
            )
            interceptor = HITLInterceptor(
                ledger, cose.ALG_MLDSA65, approver_pk, AUDIENCE, "quickstart-interceptor", frontend,
            )
            outcome = interceptor.intercept(action)
            print("intercept() outcome:", outcome)
            print("action actually executed:", executed)
            assert outcome == "TASK_CANCELLED" and executed == ["TASK_CANCELLED"]

            print()
            print("=" * 78)
            print("STEP 5: fail closed -- replaying the SAME approval object a second time")
            print("=" * 78)
            # The HITL approval binds the ARGS' content id (naalp.cbor.content_id(action.args)),
            # not the full envelope object's content id -- STEP 4's intercept() computed this
            # same value internally; here it is computed explicitly to mint a second, distinct
            # approval for the identical action.
            args_id = cbor.content_id(action.args)
            req = ApprovalRequest(
                content_id=args_id, effect=policy.DESTRUCTIVE, kind="workflow.task_cancel",
                args_summary=action.args_summary, audience=AUDIENCE,
            )
            answers2 = iter(["y"])
            frontend2 = TerminalFrontend(
                "ops-approver-1", approver_seed, input_fn=lambda _p: next(answers2)
            )
            rec, sig = frontend2.request_approval(req)  # ONE real signed approval, minted once
            interceptor.verify_and_consume(rec, sig, args_id, policy.DESTRUCTIVE)
            print("first consume of this approval object: OK (ledger entries: %d)" % len(ledger))
            try:
                interceptor.verify_and_consume(rec, sig, args_id, policy.DESTRUCTIVE)
                print("FAIL: reuse was NOT rejected -- this would be a security bug")
                return 1
            except approval.ApprovalError as e:
                print("replay of the SAME approval object rejected fail-closed: kind=%s" % e.kind)
                assert e.kind == "AlreadyConsumed"
        finally:
            ledger.close()

    print()
    print("QUICKSTART: a signed, semantically-validated, offline-verified, audience-bound,")
    print("HITL-approved, single-use-consumed effecting object -- verified end to end.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
