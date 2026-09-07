# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Isolation demonstration (A9) for the N-AALP verify-at-use guard (Part-2 ecosystem task E6.1,
requirement R12.1): concrete input -> concrete output, independent of any other ecosystem
component (no HITL interceptor, no semantic validator, no N-PAMP transport) -- just
naalp_verify_at_use called directly against the real Part-1 approval, identity, and CBOR
primitives, with a real on-disk consume ledger.

Run:  python examples/isolation_demo.py   (from ecosystem/naalp-verify-at-use/)
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from naalp_verify_at_use import GuardedAction, VerifyAtUseGuard  # noqa: E402 (puts impl/python on sys.path)
from naalp import approval, cbor, cose, identity, policy  # noqa: E402
from naalp.cbor import U, T, M  # noqa: E402

ALG = cose.ALG_MLDSA65
AUDIENCE = "svc:payments"
GUARD_IDENTITY = "payments-guard-1"


def _keypair(seed_byte):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def main():
    print("=== N-AALP verify-at-use guard -- isolation demo ===\n")
    tmpdir = tempfile.mkdtemp(prefix="naalp_verify_at_use_demo_")
    try:
        seed, pk = _keypair(0x55)
        ledger = approval.open_ledger(os.path.join(tmpdir, "consume.wal"))
        clock_ms = {"now": 1_800_000_000_000}  # a controllable use-time clock, in epoch ms

        guard = VerifyAtUseGuard(
            ledger, ALG, pk, AUDIENCE, GUARD_IDENTITY, clock=lambda: clock_ms["now"]
        )

        # 1. Build a real args object and a real, validly-signed N-AALP approval over it,
        #    granted DESTRUCTIVE, valid until clock_ms["now"] + 5000.
        args = M([(U(1), T("acct-42")), (U(2), U(250_000))])
        args_id = cbor.content_id(args)
        approval_rec = approval.ApprovalRecord(
            args_id, "approver-1", policy.DESTRUCTIVE, b"\x01" * 8,
            clock_ms["now"] + 5_000, AUDIENCE,
        )
        sig = approval.sign_approval(approval_rec, ALG, seed)

        executed = []
        action = GuardedAction(
            args=args, effect=policy.NON_IDEMPOTENT_WRITE, kind="wire_transfer",
            run=lambda: executed.append("TRANSFERRED") or "TRANSFERRED",
        )

        # 2. A valid approval, re-verified AT THE MOMENT OF EXECUTION -> resumes exactly once.
        print("1. A valid approval, re-verified at use-time:")
        result = guard.execute(action, approval_rec, sig)
        print("   result =", result)
        assert result == "TRANSFERRED"
        assert executed == ["TRANSFERRED"]
        assert ledger.is_consumed(approval_rec.id())

        # 3. REPLAY the identical approval -> single-use-at-settlement rejects it fail-closed,
        #    and the action never runs a second time.
        print("\n2. Replaying the SAME approval a second time:")
        second_action = GuardedAction(
            args=args, effect=policy.NON_IDEMPOTENT_WRITE,
            run=lambda: executed.append("SHOULD-NOT-RUN"),
        )
        try:
            guard.execute(second_action, approval_rec, sig)
            raised = None
        except approval.ApprovalError as e:
            raised = e.kind
        print("   raised =", raised)
        assert raised == "AlreadyConsumed"
        assert "SHOULD-NOT-RUN" not in executed

        # 4. A SECOND approval, valid AT ISSUANCE, but by the time execution is attempted the
        #    use-time clock has moved PAST its not_after -- min-over-path authority means the
        #    grant that existed at issuance is not the authority that exists at use.
        print("\n3. A second approval, valid at issuance, expired by use-time:")
        approval_rec2 = approval.ApprovalRecord(
            args_id, "approver-1", policy.DESTRUCTIVE, b"\x02" * 8,
            clock_ms["now"] + 1_000, AUDIENCE,  # valid for the next second
        )
        sig2 = approval.sign_approval(approval_rec2, ALG, seed)
        clock_ms["now"] += 2_000  # use-time has now moved past not_after
        third_action = GuardedAction(
            args=args, effect=policy.NON_IDEMPOTENT_WRITE,
            run=lambda: executed.append("SHOULD-NOT-RUN-2"),
        )
        try:
            guard.execute(third_action, approval_rec2, sig2)
            raised2 = None
        except approval.ApprovalError as e:
            raised2 = e.kind
        print("   raised =", raised2)
        assert raised2 == "ApprovalExpired"
        assert "SHOULD-NOT-RUN-2" not in executed

        # 5. A THIRD approval, fresh and unexpired, but the approver's SIGNING KEY has since
        #    been revoked as of this use-time instant -- a fact orthogonal to the approval's
        #    own not_after, and one this guard re-checks on every use.
        print("\n4. A fresh approval, but the approver key is revoked as of use-time:")
        approver_id = identity.signer_id(ALG, pk)
        guard.register_revocation(
            approver_id, identity.RevocationRecord(approver_id, clock_ms["now"] - 1)
        )
        approval_rec3 = approval.ApprovalRecord(
            args_id, "approver-1", policy.DESTRUCTIVE, b"\x03" * 8,
            clock_ms["now"] + 5_000, AUDIENCE,
        )
        sig3 = approval.sign_approval(approval_rec3, ALG, seed)
        fourth_action = GuardedAction(
            args=args, effect=policy.NON_IDEMPOTENT_WRITE,
            run=lambda: executed.append("SHOULD-NOT-RUN-3"),
        )
        try:
            guard.execute(fourth_action, approval_rec3, sig3)
            raised3 = None
        except approval.ApprovalError as e:
            raised3 = e.kind
        print("   raised =", raised3)
        assert raised3 == "KeyRevoked"
        assert "SHOULD-NOT-RUN-3" not in executed

        # 6. A wrong-audience approval -- named for a different service -- is refused before
        #    the ledger is ever touched.
        print("\n5. A fresh, unrevoked approval named for the WRONG audience:")
        seed4, pk4 = _keypair(0x66)
        guard4 = VerifyAtUseGuard(
            ledger, ALG, pk4, AUDIENCE, GUARD_IDENTITY, clock=lambda: clock_ms["now"]
        )
        approval_rec4 = approval.ApprovalRecord(
            args_id, "approver-2", policy.DESTRUCTIVE, b"\x04" * 8,
            clock_ms["now"] + 5_000, "svc:some-other-service",
        )
        sig4 = approval.sign_approval(approval_rec4, ALG, seed4)
        fifth_action = GuardedAction(
            args=args, effect=policy.NON_IDEMPOTENT_WRITE,
            run=lambda: executed.append("SHOULD-NOT-RUN-4"),
        )
        try:
            guard4.execute(fifth_action, approval_rec4, sig4)
            raised4 = None
        except approval.ApprovalError as e:
            raised4 = e.kind
        print("   raised =", raised4)
        assert raised4 == "AudienceMismatch"
        assert "SHOULD-NOT-RUN-4" not in executed

        print("\n=== all isolation assertions held ===")
        print("ledger consumed count =", len(ledger))
        assert len(ledger) == 1  # only the ONE valid execution in step 1 ever appended
        ledger.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
