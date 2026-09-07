# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance + mutation-surviving tests for the N-AALP HITL interceptor (E0.1/R1).

Every test here exercises the REAL Part-1 approval primitive (naalp.approval) through the
interceptor's thin wrapper -- no cryptography or ledger logic is faked. The four required
fail-closed cases (task bar) are:
  - test_valid_approval_resumes_once           (a) a valid approval resumes exactly once
  - test_reuse_of_same_approval_fails_closed   (b) reusing the SAME approval -> AlreadyConsumed
  - test_expired_approval_fails_closed         (c) an expired approval -> ApprovalExpired
  - test_wrong_audience_approval_fails_closed  (d) a wrong-audience approval -> AudienceMismatch

Each has a recorded mutation (see the accompanying report) that flips it red when its
corresponding check in naalp_hitl/interceptor.py is defeated.

Run (from ecosystem/naalp-hitl/, PYTHONDONTWRITEBYTECODE=1, using the real Python on this
machine -- not the Microsoft Store `python` stub):
    python -m unittest -v tests.test_interceptor
"""
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-hitl
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_hitl import (  # noqa: E402
    ApprovalRequest,
    PendingAction,
    HumanInterface,
    HITLInterceptor,
    HITLError,
    TerminalFrontend,
    default_clock_ms,
    RefusalLog,
    RefusalLogEntry,
    JsonlRefusalLog,
    RefusalDecisionRecord,
    sign_refusal_record,
    verify_refusal_record,
)
from naalp import approval, cbor, cose, policy  # noqa: E402
from naalp.cbor import U, T, M  # noqa: E402

ALG = cose.ALG_MLDSA65
APPROVER_ID = "approver-1"
AUDIENCE = "svc:payments-hitl"
IDENTITY = "hitl-interceptor-1"


def _approver_key(seed_byte=0x07):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def _args_map(account, amount):
    return M([(U(1), T(account)), (U(2), U(amount))])


class _FixedDecisionFrontend(HumanInterface):
    """A HumanInterface stub that returns one pre-built decision (or None) -- drives the
    interceptor's pause/route/resume wiring under test control without touching real
    stdin/stdout. The decision itself (a real signed approval, or a decline) is built by the
    test using the real naalp.approval primitives; this stub fakes only the human's keystroke,
    never the cryptography or the ledger."""

    def __init__(self, decision):
        self._decision = decision
        self.calls = 0

    def request_approval(self, request):
        self.calls += 1
        return self._decision


class HITLInterceptorFailClosedTests(unittest.TestCase):
    """The four required fail-closed cases, exercised at the interceptor's verify_and_consume
    choke point (the same choke point intercept() calls internally)."""

    def setUp(self):
        self.seed, self.pk = _approver_key()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.ledger = approval.open_ledger(os.path.join(self.tmpdir.name, "consume.wal"))
        self.refusal_log = JsonlRefusalLog(os.path.join(self.tmpdir.name, "refusals.jsonl"))
        self.interceptor = HITLInterceptor(
            self.ledger, ALG, self.pk, AUDIENCE, IDENTITY, human_interface=None,
            refusal_log=self.refusal_log,
        )
        self.args = _args_map("acct-42", 500000)
        self.args_id = cbor.content_id(self.args)

    def tearDown(self):
        self.ledger.close()
        self.tmpdir.cleanup()

    def _approval(self, grant=policy.DESTRUCTIVE, not_after=None, audience=AUDIENCE, nonce=b"\x01" * 8):
        not_after = (self.interceptor.now_ms() + 60_000) if not_after is None else not_after
        rec = approval.ApprovalRecord(self.args_id, APPROVER_ID, grant, nonce, not_after, audience)
        sig = approval.sign_approval(rec, ALG, self.seed)
        return rec, sig

    # (a) a valid approval -> resume once
    def test_valid_approval_resumes_once(self):
        rec, sig = self._approval()
        entry = self.interceptor.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(entry.seq, 0)
        self.assertTrue(self.ledger.is_consumed(rec.id()))
        self.assertEqual(len(self.ledger), 1)

    # (b) the SAME approval reused -> fail-closed (AlreadyConsumed)
    def test_reuse_of_same_approval_fails_closed(self):
        rec, sig = self._approval()
        self.interceptor.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        with self.assertRaises(approval.ApprovalError) as cm:
            self.interceptor.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(cm.exception.kind, "AlreadyConsumed")
        self.assertEqual(len(self.ledger), 1, "a rejected reuse must append nothing")

    # (c) an expired (not_after) approval -> fail-closed (ApprovalExpired)
    def test_expired_approval_fails_closed(self):
        past = self.interceptor.now_ms() - 1
        rec, sig = self._approval(not_after=past)
        with self.assertRaises(approval.ApprovalError) as cm:
            self.interceptor.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(cm.exception.kind, "ApprovalExpired")
        self.assertEqual(len(self.ledger), 0, "a rejected expiry must append nothing")

    # (d) a wrong-audience approval -> fail-closed (AudienceMismatch)
    def test_wrong_audience_approval_fails_closed(self):
        rec, sig = self._approval(audience="svc:some-other-service")
        with self.assertRaises(approval.ApprovalError) as cm:
            self.interceptor.verify_and_consume(rec, sig, self.args_id, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(cm.exception.kind, "AudienceMismatch")
        self.assertEqual(len(self.ledger), 0, "a rejected audience mismatch must append nothing")


class HITLInterceptorFailClosedThroughInterceptTests(unittest.TestCase):
    """The full required fail-closed matrix (task bar b/c/d/e/f), each driven THROUGH
    intercept() -- never verify_and_consume() directly -- with a real PendingAction whose
    execute() appends to a spy list. Every assertion below checks BOTH the raised error kind
    AND that the spy stayed empty (the task's explicit bar: 'assert the action's side effect
    did NOT happen on every fail-closed path, use a spy/flag, not just that an exception was
    raised'). (a) valid-resume lives in HITLInterceptorPauseResumeTests
    .test_approved_action_pauses_then_resumes; (g) front-end decline lives in
    .test_denied_approval_fails_closed_and_never_executes below."""

    def setUp(self):
        self.seed, self.pk = _approver_key(0x11)
        self.wrong_seed, _wrong_pk = _approver_key(0x99)  # a DIFFERENT approver keypair entirely
        self.tmpdir = tempfile.TemporaryDirectory()
        self.ledger = approval.open_ledger(os.path.join(self.tmpdir.name, "consume.wal"))
        self.refusal_log = JsonlRefusalLog(os.path.join(self.tmpdir.name, "refusals.jsonl"))
        self.args = _args_map("acct-77", 4200)
        self.args_id = cbor.content_id(self.args)

    def tearDown(self):
        self.ledger.close()
        self.tmpdir.cleanup()

    def _record(self, grant=policy.DESTRUCTIVE, not_after=None, audience=AUDIENCE, nonce=b"\x03" * 8):
        not_after = (default_clock_ms() + 60_000) if not_after is None else not_after
        return approval.ApprovalRecord(self.args_id, APPROVER_ID, grant, nonce, not_after, audience)

    def _spied_action(self, effect=policy.NON_IDEMPOTENT_WRITE):
        executed = []

        def _run():
            executed.append("RAN")
            return "RAN"

        return PendingAction(kind="wire_transfer", effect=effect, args=self.args, execute=_run), executed

    def _assert_fails_closed(self, decision, expected_kind, effect=policy.NON_IDEMPOTENT_WRITE):
        frontend = _FixedDecisionFrontend(decision)
        interceptor = HITLInterceptor(
            self.ledger, ALG, self.pk, AUDIENCE, IDENTITY, frontend, refusal_log=self.refusal_log
        )
        action, executed = self._spied_action(effect)
        with self.assertRaises(approval.ApprovalError) as cm:
            interceptor.intercept(action)
        self.assertEqual(cm.exception.kind, expected_kind)
        self.assertEqual(executed, [], "a %s-rejected approval must never execute the action" % expected_kind)
        return cm.exception

    # (b) a signature that does not verify under the approver's registered public key
    def test_bad_signature_fails_closed(self):
        rec = self._record()
        bad_sig = approval.sign_approval(rec, ALG, self.wrong_seed)  # signed by the WRONG key
        self._assert_fails_closed((rec, bad_sig), "BadSignature")

    # (c) an expired approval, driven through the full intercept() pipeline (not verify_and_consume)
    def test_expired_fails_closed_through_intercept(self):
        past = default_clock_ms() - 1
        rec = self._record(not_after=past)
        sig = approval.sign_approval(rec, ALG, self.seed)
        self._assert_fails_closed((rec, sig), "ApprovalExpired")

    # (d) a wrong-audience approval, driven through the full intercept() pipeline
    def test_wrong_audience_fails_closed_through_intercept(self):
        rec = self._record(audience="svc:some-other-service")
        sig = approval.sign_approval(rec, ALG, self.seed)
        self._assert_fails_closed((rec, sig), "AudienceMismatch")

    # (f) a granted effect that does not cover the action's required effect class
    def test_wrong_effect_class_fails_closed(self):
        rec = self._record(grant=policy.READ_ONLY)  # a read-only grant cannot authorize a write
        sig = approval.sign_approval(rec, ALG, self.seed)
        self._assert_fails_closed((rec, sig), "ApprovalRequired", effect=policy.NON_IDEMPOTENT_WRITE)

    # (e) single-use: the SAME approval object replayed through a SECOND intercept() call must
    # fail closed and must NOT execute the action a second time.
    def test_reuse_of_same_approval_fails_closed_through_intercept(self):
        rec = self._record()
        sig = approval.sign_approval(rec, ALG, self.seed)
        frontend = _FixedDecisionFrontend((rec, sig))
        interceptor = HITLInterceptor(
            self.ledger, ALG, self.pk, AUDIENCE, IDENTITY, frontend, refusal_log=self.refusal_log
        )

        first_action, first_executed = self._spied_action()
        self.assertEqual(interceptor.intercept(first_action), "RAN")
        self.assertEqual(first_executed, ["RAN"])

        second_action, second_executed = self._spied_action()
        with self.assertRaises(approval.ApprovalError) as cm:
            interceptor.intercept(second_action)
        self.assertEqual(cm.exception.kind, "AlreadyConsumed")
        self.assertEqual(
            second_executed, [], "a replayed approval must never execute the action a second time"
        )


class HITLInterceptorPauseResumeTests(unittest.TestCase):
    """End-to-end pause -> human interface -> verify+consume -> resume wiring (R1.1)."""

    def setUp(self):
        self.seed, self.pk = _approver_key(0x09)
        self.tmpdir = tempfile.TemporaryDirectory()
        self.ledger = approval.open_ledger(os.path.join(self.tmpdir.name, "consume.wal"))
        self.refusal_log = JsonlRefusalLog(os.path.join(self.tmpdir.name, "refusals.jsonl"))

    def tearDown(self):
        self.ledger.close()
        self.tmpdir.cleanup()

    def test_below_threshold_executes_without_pausing(self):
        frontend = _FixedDecisionFrontend(decision=None)
        interceptor = HITLInterceptor(
            self.ledger, ALG, self.pk, AUDIENCE, IDENTITY, frontend, refusal_log=self.refusal_log
        )
        action = PendingAction(
            kind="read_balance",
            effect=policy.READ_ONLY,
            args=_args_map("acct-1", 0),
            execute=lambda: "READ_OK",
        )
        result = interceptor.intercept(action)
        self.assertEqual(result, "READ_OK")
        self.assertEqual(frontend.calls, 0, "a read-only action must never pause for a human")
        self.assertEqual(self.refusal_log.read_all(), [], "an action that never paused refused nothing")

    def test_denied_approval_fails_closed_and_never_executes(self):
        frontend = _FixedDecisionFrontend(decision=None)  # the human declines
        interceptor = HITLInterceptor(
            self.ledger, ALG, self.pk, AUDIENCE, IDENTITY, frontend, refusal_log=self.refusal_log
        )
        executed = []
        action = PendingAction(
            kind="wire_transfer",
            effect=policy.DESTRUCTIVE,
            args=_args_map("acct-9", 100),
            execute=lambda: executed.append(1),
            principal="agent:treasury-bot-1",
        )
        with self.assertRaises(HITLError) as cm:
            interceptor.intercept(action)
        self.assertEqual(cm.exception.kind, "ApprovalDenied")
        self.assertEqual(executed, [], "a denied action must never execute")
        # D6 Layer 1: the AU-3 entry was really persisted (durable effect, not just "no crash").
        entries = self.refusal_log.read_all()
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["what_kind"], "wire_transfer")
        self.assertEqual(e["what_content_id"], cbor.content_id(action.args).hex())
        self.assertEqual(e["where_identity"], IDENTITY)
        self.assertEqual(e["where_audience"], AUDIENCE)
        self.assertEqual(e["source_principal"], "agent:treasury-bot-1")
        self.assertEqual(e["outcome_reason"], "ApprovalDenied")
        self.assertEqual(e["approver_identity"], "", "no approval object ever existed to name an approver")
        # D6 Layer 2: no signing key was configured on this interceptor -> never fabricated.
        self.assertIsNone(cm.exception.d6.record)
        self.assertIsNone(cm.exception.d6.record_sig)
        self.assertIsNone(cm.exception.d6.refusal)

    def test_approved_action_pauses_then_resumes(self):
        args = _args_map("acct-9", 250000)
        args_id = cbor.content_id(args)
        rec = approval.ApprovalRecord(
            args_id, APPROVER_ID, policy.DESTRUCTIVE, b"\x02" * 8, 9_999_999_999_999, AUDIENCE
        )
        sig = approval.sign_approval(rec, ALG, self.seed)
        frontend = _FixedDecisionFrontend(decision=(rec, sig))
        interceptor = HITLInterceptor(
            self.ledger, ALG, self.pk, AUDIENCE, IDENTITY, frontend, refusal_log=self.refusal_log
        )
        executed = []

        def _do():
            executed.append("TRANSFERRED")
            return "TRANSFERRED"

        action = PendingAction(kind="wire_transfer", effect=policy.DESTRUCTIVE, args=args, execute=_do)
        result = interceptor.intercept(action)
        self.assertEqual(result, "TRANSFERRED")
        self.assertEqual(executed, ["TRANSFERRED"])
        self.assertEqual(frontend.calls, 1)
        self.assertTrue(self.ledger.is_consumed(rec.id()))
        self.assertEqual(self.refusal_log.read_all(), [], "a resumed action refused nothing")


class TerminalFrontendTests(unittest.TestCase):
    """R1.3: the terminal front end really signs a real N-AALP approval (or really declines)."""

    def test_terminal_frontend_signs_real_approval_on_yes(self):
        seed, pk = _approver_key(0x0A)
        lines = []
        frontend = TerminalFrontend(
            APPROVER_ID, seed, input_fn=lambda _p: "y", output_fn=lines.append, clock=lambda: 1_000_000
        )
        req = ApprovalRequest(
            content_id=cbor.content_id(_args_map("acct-1", 1)),
            effect=policy.DESTRUCTIVE,
            kind="wire_transfer",
            args_summary="acct-1 / 1",
            audience=AUDIENCE,
        )
        decision = frontend.request_approval(req)
        self.assertIsNotNone(decision)
        rec, sig = decision
        self.assertEqual(rec.approves, req.content_id)
        self.assertEqual(rec.audience, AUDIENCE)
        self.assertTrue(
            cose.cose_verify1_raw(ALG, pk, rec.bytes(), sig), "terminal-issued approval must really verify"
        )
        self.assertTrue(any("N-AALP HITL approval request" in l for l in lines))

    def test_terminal_frontend_returns_none_on_no(self):
        seed, _pk = _approver_key(0x0B)
        frontend = TerminalFrontend(APPROVER_ID, seed, input_fn=lambda _p: "n", output_fn=lambda _l: None)
        req = ApprovalRequest(
            content_id=b"x" * 50, effect=policy.DESTRUCTIVE, kind="k", args_summary="", audience=AUDIENCE
        )
        self.assertIsNone(frontend.request_approval(req))


SIGNING_ALG = cose.ALG_MLDSA65


def _signing_key(seed_byte=0x21):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


class _RaisingRefusalLog(RefusalLog):
    """A RefusalLog whose record() always raises -- used to prove a logging failure propagates
    and still blocks execution (fail-closed), rather than being silently swallowed."""

    def __init__(self):
        self.calls = 0

    def record(self, entry):
        self.calls += 1
        raise IOError("simulated durable-log failure")


class HITLInterceptorD6AuditTests(unittest.TestCase):
    """D6: the AU-2/AU-3 structured refusal log (Layer 1) and the AU-10 non-repudiation signed
    refusal-decision record (Layer 2), exercised at verify_and_consume's choke point with real
    ML-DSA signing and verification throughout -- no cryptography or the outcome mapping is
    faked."""

    def setUp(self):
        self.approver_seed, self.approver_pk = _approver_key(0x31)
        self.signing_seed, self.signing_pk = _signing_key(0x32)
        self.tmpdir = tempfile.TemporaryDirectory()
        self.ledger = approval.open_ledger(os.path.join(self.tmpdir.name, "consume.wal"))
        self.refusal_log = JsonlRefusalLog(os.path.join(self.tmpdir.name, "refusals.jsonl"))
        self.args = _args_map("acct-nr-1", 999)
        self.args_id = cbor.content_id(self.args)

    def tearDown(self):
        self.ledger.close()
        self.tmpdir.cleanup()

    def _interceptor(self, non_repudiation_threshold=policy.DESTRUCTIVE, with_signing_key=True):
        return HITLInterceptor(
            self.ledger, ALG, self.approver_pk, AUDIENCE, IDENTITY, human_interface=None,
            refusal_log=self.refusal_log,
            signing_alg=SIGNING_ALG if with_signing_key else None,
            signing_seed=self.signing_seed if with_signing_key else None,
            non_repudiation_threshold=non_repudiation_threshold,
        )

    def _bad_signature_refusal(self, interceptor, required_effect=policy.DESTRUCTIVE):
        # BadSignature: signed by a key that is NOT the approver's registered public key.
        rec = approval.ApprovalRecord(
            self.args_id, APPROVER_ID, policy.DESTRUCTIVE, b"\x09" * 8,
            interceptor.now_ms() + 60_000, AUDIENCE,
        )
        wrong_seed, _wrong_pk = _approver_key(0xEE)
        bad_sig = approval.sign_approval(rec, ALG, wrong_seed)
        with self.assertRaises(approval.ApprovalError) as cm:
            interceptor.verify_and_consume(
                rec, bad_sig, self.args_id, required_effect, kind="wire_transfer", principal="agent:x",
            )
        self.assertEqual(cm.exception.kind, "BadSignature")
        return cm.exception

    # ---- Layer 1: the structured log persists on every refusal path (durable-effect assertions) ----

    def test_layer1_persists_every_au3_field_on_bad_signature(self):
        interceptor = self._interceptor(with_signing_key=False)
        self._bad_signature_refusal(interceptor)
        entries = self.refusal_log.read_all()
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["what_kind"], "wire_transfer")
        self.assertEqual(e["what_content_id"], self.args_id.hex())
        self.assertIsInstance(e["when_ms"], int)
        self.assertEqual(e["where_identity"], IDENTITY)
        self.assertEqual(e["where_audience"], AUDIENCE)
        self.assertEqual(e["source_principal"], "agent:x")
        self.assertEqual(e["outcome_reason"], "BadSignature")
        self.assertEqual(e["approver_identity"], APPROVER_ID, "the CLAIMED approver id is logged even though its signature did not verify")

    def test_layer1_persists_on_direct_verify_and_consume_with_default_kind_and_principal(self):
        # Exercised WITHOUT kind=/principal= (the four original direct-call tests' calling
        # convention) -- the log entry honestly records "" rather than fabricating context.
        interceptor = self._interceptor(with_signing_key=False)
        rec = approval.ApprovalRecord(
            self.args_id, APPROVER_ID, policy.DESTRUCTIVE, b"\x0a" * 8,
            interceptor.now_ms() - 1, AUDIENCE,  # already expired
        )
        sig = approval.sign_approval(rec, ALG, self.approver_seed)
        with self.assertRaises(approval.ApprovalError) as cm:
            interceptor.verify_and_consume(rec, sig, self.args_id, policy.DESTRUCTIVE)
        self.assertEqual(cm.exception.kind, "ApprovalExpired")
        e = self.refusal_log.read_all()[0]
        self.assertEqual(e["what_kind"], "")
        self.assertEqual(e["source_principal"], "")
        self.assertEqual(e["approver_identity"], APPROVER_ID)

    def test_logging_failure_propagates_and_still_blocks_execution(self):
        raising_log = _RaisingRefusalLog()
        interceptor = HITLInterceptor(
            self.ledger, ALG, self.approver_pk, AUDIENCE, IDENTITY, human_interface=None,
            refusal_log=raising_log,
        )
        rec = approval.ApprovalRecord(
            self.args_id, APPROVER_ID, policy.DESTRUCTIVE, b"\x0b" * 8,
            interceptor.now_ms() - 1, AUDIENCE,
        )
        sig = approval.sign_approval(rec, ALG, self.approver_seed)
        with self.assertRaises(IOError):
            interceptor.verify_and_consume(rec, sig, self.args_id, policy.DESTRUCTIVE)
        self.assertEqual(raising_log.calls, 1, "the sink must actually have been asked to persist")
        self.assertFalse(self.ledger.is_consumed(rec.id()), "a refusal must never consume, logging fault or not")

    # ---- Layer 2: signed non-repudiation record, gated on effect threshold AND a signing key ----

    def test_layer2_mints_a_real_verifiable_signed_record_at_threshold(self):
        interceptor = self._interceptor(non_repudiation_threshold=policy.DESTRUCTIVE)
        err = self._bad_signature_refusal(interceptor, required_effect=policy.DESTRUCTIVE)
        d6 = err.d6
        self.assertIsNotNone(d6.record)
        self.assertIsNotNone(d6.record_sig)
        self.assertIsNotNone(d6.refusal)
        # the signed record really verifies under the interceptor's OWN signing identity's pubkey
        self.assertTrue(verify_refusal_record(d6.record, SIGNING_ALG, self.signing_pk, d6.record_sig))
        # it does NOT verify under an unrelated key (a forged/wrong-key signature must be caught)
        _other_seed, other_pk = _signing_key(0x99)
        self.assertFalse(verify_refusal_record(d6.record, SIGNING_ALG, other_pk, d6.record_sig))
        # the coarse Refusal references this exact record's content id, and nothing else
        self.assertEqual(d6.refusal.record, d6.record.content_id())
        self.assertEqual(d6.refusal.outcome, approval.REFUSAL_UNVERIFIABLE)
        # parse_refusal(refusal.bytes()) reconstructs the correct outcome + content id (R-TDCS-3)
        parsed = approval.parse_refusal(d6.refusal.bytes())
        self.assertEqual(parsed.outcome, approval.REFUSAL_UNVERIFIABLE)
        self.assertEqual(parsed.record, d6.record.content_id())

    def test_layer2_absent_below_threshold_even_with_signing_key_configured(self):
        # threshold = DESTRUCTIVE, but this refusal is for a NON_IDEMPOTENT_WRITE action.
        interceptor = self._interceptor(non_repudiation_threshold=policy.DESTRUCTIVE)
        err = self._bad_signature_refusal(interceptor, required_effect=policy.NON_IDEMPOTENT_WRITE)
        self.assertIsNone(err.d6.record, "below threshold: NEVER mint a signed record, key or no key")
        self.assertIsNone(err.d6.record_sig)
        self.assertIsNone(err.d6.refusal)
        # Layer 1 still ran regardless.
        self.assertEqual(len(self.refusal_log.read_all()), 1)

    def test_layer2_absent_without_a_signing_key_even_at_threshold(self):
        interceptor = self._interceptor(with_signing_key=False)
        err = self._bad_signature_refusal(interceptor, required_effect=policy.DESTRUCTIVE)
        self.assertIsNone(err.d6.record, "no signing key configured: never fabricate a signature")
        self.assertIsNone(err.d6.record_sig)
        self.assertIsNone(err.d6.refusal)

    # ---- outcome mapping: every interceptor refusal kind maps onto the closed R-TDCS-3 set ----

    def test_outcome_mapping_for_every_refusal_kind(self):
        interceptor = self._interceptor(non_repudiation_threshold=policy.DESTRUCTIVE)

        def _refuse(rec_kwargs, required_effect=policy.DESTRUCTIVE, principal="agent:m"):
            defaults = dict(
                approves=self.args_id, approver=APPROVER_ID, grant=policy.DESTRUCTIVE,
                nonce=b"\x0c" * 8, not_after=interceptor.now_ms() + 60_000, audience=AUDIENCE,
            )
            defaults.update(rec_kwargs)
            rec = approval.ApprovalRecord(**defaults)
            sig = approval.sign_approval(rec, ALG, self.approver_seed)
            with self.assertRaises(approval.ApprovalError) as cm:
                interceptor.verify_and_consume(
                    rec, sig, self.args_id, required_effect, kind="k", principal=principal,
                )
            return cm.exception

        # ApprovalMismatch (wrong args bound) -> DENIED: this exact evidence can never authorize
        # THESE args; re-presenting the same object never later succeeds.
        wrong_id = cbor.content_id(_args_map("acct-other", 1))
        err = _refuse({"approves": wrong_id})
        self.assertEqual(err.kind, "ApprovalMismatch")
        self.assertEqual(err.d6.refusal.outcome, approval.REFUSAL_DENIED)

        # ApprovalExpired -> DENIED (terminal for this object).
        err = _refuse({"not_after": interceptor.now_ms() - 1})
        self.assertEqual(err.kind, "ApprovalExpired")
        self.assertEqual(err.d6.refusal.outcome, approval.REFUSAL_DENIED)

        # AudienceMismatch -> DENIED (terminal for this object in this context).
        err = _refuse({"audience": "svc:some-other-service"})
        self.assertEqual(err.kind, "AudienceMismatch")
        self.assertEqual(err.d6.refusal.outcome, approval.REFUSAL_DENIED)

        # ApprovalRequired (grant below the required effect: the effect ceiling) -> HELD: a
        # properly-scoped approval (a further step) would resolve it.
        err = _refuse({"grant": policy.READ_ONLY}, required_effect=policy.DESTRUCTIVE)
        self.assertEqual(err.kind, "ApprovalRequired")
        self.assertEqual(err.d6.refusal.outcome, approval.REFUSAL_HELD)

        # AlreadyConsumed -> DENIED (this exact approval's one use is spent).
        rec = approval.ApprovalRecord(
            self.args_id, APPROVER_ID, policy.DESTRUCTIVE, b"\x0d" * 8,
            interceptor.now_ms() + 60_000, AUDIENCE,
        )
        sig = approval.sign_approval(rec, ALG, self.approver_seed)
        interceptor.verify_and_consume(rec, sig, self.args_id, policy.DESTRUCTIVE, kind="k")
        with self.assertRaises(approval.ApprovalError) as cm:
            interceptor.verify_and_consume(rec, sig, self.args_id, policy.DESTRUCTIVE, kind="k")
        self.assertEqual(cm.exception.kind, "AlreadyConsumed")
        self.assertEqual(cm.exception.d6.refusal.outcome, approval.REFUSAL_DENIED)

        # ApprovalDenied (human decline, driven through intercept()) -> DENIED.
        frontend = _FixedDecisionFrontend(decision=None)
        denial_interceptor = HITLInterceptor(
            self.ledger, ALG, self.approver_pk, AUDIENCE, IDENTITY, frontend,
            refusal_log=self.refusal_log, signing_alg=SIGNING_ALG, signing_seed=self.signing_seed,
        )
        action = PendingAction(
            kind="wire_transfer", effect=policy.DESTRUCTIVE, args=_args_map("acct-hh", 5),
            execute=lambda: "SHOULD_NOT_RUN",
        )
        with self.assertRaises(HITLError) as cm:
            denial_interceptor.intercept(action)
        self.assertEqual(cm.exception.kind, "ApprovalDenied")
        self.assertEqual(cm.exception.d6.refusal.outcome, approval.REFUSAL_DENIED)


if __name__ == "__main__":
    unittest.main()
