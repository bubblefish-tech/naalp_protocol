# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance + mutation-surviving tests for the N-AALP verify-at-use guard (E6.1/R12.1).

Every test here exercises the REAL Part-1 primitives (naalp.approval, naalp.identity,
naalp.cbor) through the guard's thin wrapper -- no cryptography, ledger, or identity logic is
faked. The four required fail-closed properties named in the requirement text ("a
grant/approval valid at issuance but expired, consumed, revoked, or out-of-audience at
use-time SHALL be refused fail-closed with a named error") are:
  - test_valid_at_issuance_expired_at_use_time_fails_closed      -- expired
  - test_reuse_fails_closed / *_through_execute_never_runs_a_second_time -- consumed
  - test_valid_at_issuance_key_revoked_at_use_time_fails_closed  -- revoked
  - test_wrong_audience_fails_closed                             -- out-of-audience

OracleGroundingTests establish F3 non-circularity BEFORE any of those tests run: they confirm
the two Part-1 wire primitives this guard's checks depend on -- the approval body's
deterministic-CBOR bytes, and the C4 signer id -- match an authority outside naalp.approval /
naalp.identity / naalp.cbor (tools/approval_oracle.py, tools/cbor_oracle.py,
tools/signerid_oracle.py -- existing top-level oracle tools, read-only, none of which is the
code under test here or in Part-1).

Run (from ecosystem/naalp-verify-at-use/, PYTHONDONTWRITEBYTECODE=1, using the real Python
interpreter for this platform -- on Windows the Microsoft-Store `python`/`python3`
execution-alias stubs resolve ahead of a real install on PATH and hang, so invoke the actual
interpreter binary directly rather than the bare `python` command):
    PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_verify_at_use
"""
import json
import os
import sys
import tempfile
import threading
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-verify-at-use
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

_REPO_ROOT = os.path.normpath(os.path.join(_PKG_ROOT, "..", ".."))
_TOOLS_DIR = os.path.join(_REPO_ROOT, "tools")
_VECTORS_DIR = os.path.join(_REPO_ROOT, "vectors")

from naalp_verify_at_use import (  # noqa: E402
    GuardedAction,
    VerifyAtUseGuard,
    default_clock_ms,
)
from naalp import approval, cbor, cose, identity, policy  # noqa: E402
from naalp.cbor import U, T, M  # noqa: E402

# READ-ONLY import of existing top-level oracle tools (F3 non-circular authorities). Nothing
# in this test file writes to tools/ or to vectors/; both are read exactly as they already
# exist in the tree.
sys.path.insert(0, _TOOLS_DIR)
import approval_oracle    # noqa: E402
import cbor_oracle        # noqa: E402
import signerid_oracle    # noqa: E402

ALG = cose.ALG_MLDSA65
APPROVER_ID_LABEL = "approver-1"   # naalp.approval.ApprovalRecord.approver is a free-form label
AUDIENCE = "svc:payments-verify-at-use"
IDENTITY = "verify-at-use-guard-1"


def _approver_key(seed_byte=0x21):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def _args_map(account, amount):
    return M([(U(1), T(account)), (U(2), U(amount))])


# ---- F3 non-circular vector helpers ------------------------------------------------------

def _load_approval_oracle_case():
    """The independent tools/approval_oracle.py case for approval "A": its args content id and
    its exact expected approval-body bytes -- both built by tools/cbor_oracle.py, NOT
    naalp.cbor. Re-deriving the SAME body through naalp.approval.ApprovalRecord and comparing
    bytes is a genuine non-circular check on the wire encoding this guard's args-binding check
    (naalp.approval.verify_approval, inside consume_approval) depends on."""
    case = approval_oracle.build()
    a = case["approvals"][0]
    return {
        "args_content_id": bytes.fromhex(case["args"]["content_id_hex"]),
        "approves": bytes.fromhex(a["approves_hex"]),
        "approver": a["approver"],
        "grant": a["grant"],
        "nonce": bytes.fromhex(a["nonce_hex"]),
        "not_after": a["not_after"],
        "expected_record_bytes": bytes.fromhex(a["record_hex"]),
    }


def _pinned_identity_signer():
    """The pinned Ed25519 case from the GRADED vectors/identity/cases.json corpus (built by
    tools/signerid_oracle.py against RFC 8032's own published test key): a real
    (alg, pubkey, signer_id) triple this test checks naalp.identity.signer_id() against
    without this package having derived any of the three values itself."""
    with open(os.path.join(_VECTORS_DIR, "identity", "cases.json"), "r", encoding="utf-8") as f:
        ids = json.load(f)
    ed = next(s for s in ids["signers"] if s["name"] == "Ed25519")
    return {
        "alg": ed["alg"],
        "pubkey": bytes.fromhex(ed["pubkey_hex"]),
        "expected_signer_id": ed["signer_id"],
    }


class OracleGroundingTests(unittest.TestCase):
    """F3: confirm the Part-1 primitives this guard's checks are built on -- the approval
    body's deterministic-CBOR bytes and the C4 signer id -- actually match an authority
    outside naalp.approval / naalp.identity / naalp.cbor, before any guard test relies on
    them being correct."""

    def test_approval_body_bytes_match_the_independent_cbor_oracle(self):
        case = _load_approval_oracle_case()
        rec = approval.ApprovalRecord(
            case["approves"], case["approver"], case["grant"], case["nonce"], case["not_after"]
        )
        self.assertEqual(
            rec.bytes(), case["expected_record_bytes"],
            "naalp.approval.ApprovalRecord.bytes() must match tools/approval_oracle.py's "
            "independent (cbor_oracle-built) expected bytes",
        )
        self.assertEqual(bytes(rec.approves), case["args_content_id"])

    def test_signer_id_matches_the_independent_signerid_oracle(self):
        fx = _pinned_identity_signer()
        # (1) the pinned, graded fixture -- an id no part of this package derived.
        self.assertEqual(identity.signer_id(fx["alg"], fx["pubkey"]), fx["expected_signer_id"])
        # (2) the same independent constructor, invoked directly, on a freshly generated key
        #     this test's own guard tests will sign with -- not only the one pinned fixture.
        _seed, pk = _approver_key(0x21)
        oracle_id = signerid_oracle.signer_id(signerid_oracle.CODE_MLDSA65, pk)
        self.assertEqual(identity.signer_id(ALG, pk), oracle_id)

    def test_revocation_record_bytes_match_the_independent_cbor_oracle(self):
        fx = _pinned_identity_signer()
        rec = identity.RevocationRecord(fx["expected_signer_id"], 5_000)
        expected = cbor_oracle.encode(("map", [(1, fx["expected_signer_id"]), (2, 5_000)]))
        self.assertEqual(rec.bytes(), expected)


class VerifyAtUseGuardFailClosedTests(unittest.TestCase):
    """The core re-verify-at-execute-boundary properties (R12.1), exercised at the guard's
    verify_and_consume() choke point (the same choke point execute() calls internally)."""

    def setUp(self):
        self.seed, self.pk = _approver_key(0x21)
        self.tmpdir = tempfile.TemporaryDirectory()
        self.ledger = approval.open_ledger(os.path.join(self.tmpdir.name, "consume.wal"))
        self.guard = VerifyAtUseGuard(self.ledger, ALG, self.pk, AUDIENCE, IDENTITY)
        self.args = _args_map("acct-42", 500000)
        self.args_id = cbor.content_id(self.args)

    def tearDown(self):
        self.ledger.close()
        self.tmpdir.cleanup()

    def _approval(self, grant=policy.DESTRUCTIVE, not_after=None, audience=AUDIENCE, nonce=b"\x01" * 8):
        not_after = (self.guard.now_ms() + 60_000) if not_after is None else not_after
        rec = approval.ApprovalRecord(self.args_id, APPROVER_ID_LABEL, grant, nonce, not_after, audience)
        sig = approval.sign_approval(rec, ALG, self.seed)
        return rec, sig

    # (a) a valid approval, re-verified at use-time -> consumes exactly once
    def test_valid_approval_re_verifies_and_consumes_once(self):
        rec, sig = self._approval()
        entry = self.guard.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(entry.seq, 0)
        self.assertTrue(self.ledger.is_consumed(rec.id()))
        self.assertEqual(len(self.ledger), 1)

    # -- consumed: reuse of the SAME approval -> AlreadyConsumed, no second append
    def test_reuse_fails_closed(self):
        rec, sig = self._approval()
        self.guard.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        with self.assertRaises(approval.ApprovalError) as cm:
            self.guard.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(cm.exception.kind, "AlreadyConsumed")
        self.assertEqual(len(self.ledger), 1, "a rejected reuse must append nothing")

    # -- expired: valid AT ISSUANCE (not_after is in the future relative to issuance), but the
    #    USE-TIME clock has moved past it by the moment of the re-check -> ApprovalExpired.
    #    This is the exact property R12.1 names: "valid at issuance but expired ... at use-time".
    def test_valid_at_issuance_expired_at_use_time_fails_closed(self):
        soon = self.guard.now_ms() + 10  # a real deadline in the near future -- valid right now
        rec, sig = self._approval(not_after=soon)
        use_time = soon + 1  # the use-time instant has moved past not_after
        with self.assertRaises(approval.ApprovalError) as cm:
            self.guard.verify_and_consume(
                rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE, pos_time=use_time
            )
        self.assertEqual(cm.exception.kind, "ApprovalExpired")
        self.assertEqual(len(self.ledger), 0, "a rejected expiry must append nothing")

    # -- out-of-audience: a wrong-audience approval -> AudienceMismatch, no append
    def test_wrong_audience_fails_closed(self):
        rec, sig = self._approval(audience="svc:some-other-service")
        with self.assertRaises(approval.ApprovalError) as cm:
            self.guard.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(cm.exception.kind, "AudienceMismatch")
        self.assertEqual(len(self.ledger), 0, "a rejected audience mismatch must append nothing")

    # -- revoked: valid AT ISSUANCE, but the approver's signing key has since been revoked as
    #    of the USE-TIME instant -> KeyRevoked, no append. Distinct from expiry: the APPROVAL
    #    itself carries a perfectly fresh not_after; it is the KEY that is no longer live.
    def test_valid_at_issuance_key_revoked_at_use_time_fails_closed(self):
        rec, sig = self._approval()
        approver_id = identity.signer_id(ALG, self.pk)
        revoked_not_after = self.guard.now_ms() - 1  # revoked strictly before use-time
        self.guard.register_revocation(
            approver_id, identity.RevocationRecord(approver_id, revoked_not_after)
        )
        with self.assertRaises(approval.ApprovalError) as cm:
            self.guard.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(cm.exception.kind, "KeyRevoked")
        self.assertEqual(len(self.ledger), 0, "a rejected key revocation must append nothing")

    # a revocation dated strictly AFTER use-time does not (yet) revoke: the guard judges
    # liveness AT pos_time, matching naalp.identity.revoked_at's own semantics exactly.
    def test_key_revoked_only_in_the_future_does_not_block_use_now(self):
        rec, sig = self._approval()
        approver_id = identity.signer_id(ALG, self.pk)
        future_revoke = self.guard.now_ms() + 60_000
        self.guard.register_revocation(
            approver_id, identity.RevocationRecord(approver_id, future_revoke)
        )
        entry = self.guard.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(entry.seq, 0)

    # min-over-path authority: a granted effect below the action's required effect -> ApprovalRequired
    def test_wrong_effect_class_fails_closed(self):
        rec, sig = self._approval(grant=policy.READ_ONLY)
        with self.assertRaises(approval.ApprovalError) as cm:
            self.guard.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(cm.exception.kind, "ApprovalRequired")
        self.assertEqual(len(self.ledger), 0)

    # a signature that does not verify under the approver's registered public key
    def test_bad_signature_fails_closed(self):
        rec, _sig = self._approval()
        wrong_seed, _wrong_pk = _approver_key(0x99)  # a DIFFERENT keypair entirely
        bad_sig = approval.sign_approval(rec, ALG, wrong_seed)
        with self.assertRaises(approval.ApprovalError) as cm:
            self.guard.verify_and_consume(rec, bad_sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(cm.exception.kind, "BadSignature")
        self.assertEqual(len(self.ledger), 0)

    # a changed argument changes the content id, so a stale approval no longer matches
    def test_args_mismatch_fails_closed(self):
        rec, sig = self._approval()
        different_args_id = cbor.content_id(_args_map("acct-42", 999999))
        with self.assertRaises(approval.ApprovalError) as cm:
            self.guard.verify_and_consume(
                rec, sig, different_args_id, policy.NON_IDEMPOTENT_WRITE
            )
        self.assertEqual(cm.exception.kind, "ApprovalMismatch")
        self.assertEqual(len(self.ledger), 0)


class VerifyAtUseGuardThroughExecuteTests(unittest.TestCase):
    """The full fail-closed matrix, driven THROUGH execute() -- never verify_and_consume()
    directly -- with a real GuardedAction whose run() appends to a spy list. Every assertion
    checks BOTH the raised error kind AND that the spy stayed empty (the action's side effect
    must not have happened on any fail-closed path)."""

    def setUp(self):
        self.seed, self.pk = _approver_key(0x31)
        self.tmpdir = tempfile.TemporaryDirectory()
        self.ledger = approval.open_ledger(os.path.join(self.tmpdir.name, "consume.wal"))
        self.args = _args_map("acct-77", 4200)
        self.args_id = cbor.content_id(self.args)

    def tearDown(self):
        self.ledger.close()
        self.tmpdir.cleanup()

    def _record(self, grant=policy.DESTRUCTIVE, not_after=None, audience=AUDIENCE, nonce=b"\x03" * 8):
        not_after = (default_clock_ms() + 60_000) if not_after is None else not_after
        return approval.ApprovalRecord(self.args_id, APPROVER_ID_LABEL, grant, nonce, not_after, audience)

    def _spied_action(self, effect=policy.NON_IDEMPOTENT_WRITE):
        executed = []

        def _run():
            executed.append("RAN")
            return "RAN"

        return GuardedAction(args=self.args, effect=effect, run=_run, kind="wire_transfer"), executed

    def test_valid_approval_executes_exactly_once(self):
        rec = self._record()
        sig = approval.sign_approval(rec, ALG, self.seed)
        guard = VerifyAtUseGuard(self.ledger, ALG, self.pk, AUDIENCE, IDENTITY)
        action, executed = self._spied_action()
        result = guard.execute(action, rec, sig)
        self.assertEqual(result, "RAN")
        self.assertEqual(executed, ["RAN"])
        self.assertTrue(self.ledger.is_consumed(rec.id()))

    def test_reuse_through_execute_never_runs_a_second_time(self):
        rec = self._record()
        sig = approval.sign_approval(rec, ALG, self.seed)
        guard = VerifyAtUseGuard(self.ledger, ALG, self.pk, AUDIENCE, IDENTITY)

        first_action, first_executed = self._spied_action()
        self.assertEqual(guard.execute(first_action, rec, sig), "RAN")
        self.assertEqual(first_executed, ["RAN"])

        second_action, second_executed = self._spied_action()
        with self.assertRaises(approval.ApprovalError) as cm:
            guard.execute(second_action, rec, sig)
        self.assertEqual(cm.exception.kind, "AlreadyConsumed")
        self.assertEqual(
            second_executed, [], "a replayed approval must never execute the action a second time"
        )

    def test_expired_at_use_through_execute_never_runs(self):
        past = default_clock_ms() - 1
        rec = self._record(not_after=past)
        sig = approval.sign_approval(rec, ALG, self.seed)
        guard = VerifyAtUseGuard(self.ledger, ALG, self.pk, AUDIENCE, IDENTITY)
        action, executed = self._spied_action()
        with self.assertRaises(approval.ApprovalError) as cm:
            guard.execute(action, rec, sig)
        self.assertEqual(cm.exception.kind, "ApprovalExpired")
        self.assertEqual(executed, [])

    def test_wrong_audience_through_execute_never_runs(self):
        rec = self._record(audience="svc:some-other-service")
        sig = approval.sign_approval(rec, ALG, self.seed)
        guard = VerifyAtUseGuard(self.ledger, ALG, self.pk, AUDIENCE, IDENTITY)
        action, executed = self._spied_action()
        with self.assertRaises(approval.ApprovalError) as cm:
            guard.execute(action, rec, sig)
        self.assertEqual(cm.exception.kind, "AudienceMismatch")
        self.assertEqual(executed, [])

    def test_revoked_key_through_execute_never_runs(self):
        rec = self._record()
        sig = approval.sign_approval(rec, ALG, self.seed)
        approver_id = identity.signer_id(ALG, self.pk)
        revoked = {approver_id: identity.RevocationRecord(approver_id, default_clock_ms() - 1)}
        guard = VerifyAtUseGuard(self.ledger, ALG, self.pk, AUDIENCE, IDENTITY, revocations=revoked)
        action, executed = self._spied_action()
        with self.assertRaises(approval.ApprovalError) as cm:
            guard.execute(action, rec, sig)
        self.assertEqual(cm.exception.kind, "KeyRevoked")
        self.assertEqual(executed, [])


class VerifyAtUseGuardConcurrencyTests(unittest.TestCase):
    """Exactly-once-under-race: the SAME pre-signed approval, consumed by several concurrent
    execute() calls, must let exactly one succeed and reject every other AlreadyConsumed, with
    the action's run() invoked exactly once.

    #241: dilithium_py's ML-DSA implementation is NOT thread-safe for SIGNING. The approval is
    therefore signed ONCE, single-threaded, before any worker thread starts; only the guard's
    verify+consume path (signature verification plus the ledger's own single lock) is raced."""

    def test_exactly_once_under_race(self):
        seed, pk = _approver_key(0x41)
        tmpdir = tempfile.TemporaryDirectory()
        ledger = None
        try:
            ledger = approval.open_ledger(os.path.join(tmpdir.name, "consume.wal"))
            guard = VerifyAtUseGuard(ledger, ALG, pk, AUDIENCE, IDENTITY)
            args = _args_map("acct-race", 1)
            args_id = cbor.content_id(args)
            rec = approval.ApprovalRecord(
                args_id, APPROVER_ID_LABEL, policy.DESTRUCTIVE, b"\x05" * 8,
                default_clock_ms() + 60_000, AUDIENCE,
            )
            sig = approval.sign_approval(rec, ALG, seed)  # sign ONCE, single-threaded (#241)

            ran = []
            errors = []
            ran_lock = threading.Lock()

            def _run():
                with ran_lock:
                    ran.append(1)
                return "RAN"

            def worker():
                action = GuardedAction(args=args, effect=policy.NON_IDEMPOTENT_WRITE, run=_run)
                try:
                    guard.execute(action, rec, sig)
                except approval.ApprovalError as e:
                    errors.append(e.kind)

            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(ran), 1, "the action must run exactly once under a race")
            self.assertEqual(len(errors), 7)
            self.assertTrue(all(k == "AlreadyConsumed" for k in errors), errors)
            self.assertEqual(len(ledger), 1)
        finally:
            if ledger is not None:
                ledger.close()
            tmpdir.cleanup()


if __name__ == "__main__":
    unittest.main()
