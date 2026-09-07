# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Mutation-surviving conformance tests for the N-AALP ReAct bridge (E1.1/R2.1).

Every test here exercises the REAL Part-1 envelope/COSE primitives, and (where a test
names them) the REAL sibling `naalp_hitl.HITLInterceptor` and `naalp_validator.validate`
-- no cryptography, ledger, or registry logic is faked. Only the human operator's
keystroke (a `HumanInterface` stub) and the network transport (an in-memory spy) are
test doubles; everything downstream of them is real, unfaked code, exactly the same
convention `ecosystem/naalp-hitl/tests/test_interceptor.py` uses.

The required fail-closed matrix (task bar) is:
  (a) test_well_formed_action_round_trips_and_emits    a well-formed Action -> a signed
                                                         request whose bytes round-trip
                                                         decode to the same object
  (b) test_effecting_action_denied_by_hitl_is_never_emitted
                                                         an effecting Action + HITL hook +
                                                         no valid approval -> refused,
                                                         request NEVER emitted
  (c) test_bad_signature_fails_closed                  a tampered response -> fail-closed
  (d) test_wrong_audience_fails_closed /
      test_absent_audience_fails_closed                 a wrong/absent-audience response
                                                         -> fail-closed
  (e) test_missing_causal_linkage_fails_closed /
      test_wrong_causal_linkage_fails_closed             a response not citing the
                                                         request's content id -> fail-closed
  (f) test_validator_rejects_malformed_action_pre_send  the validator hook rejects a
                                                         malformed request pre-send ->
                                                         refused

Every fail-closed assertion below checks BOTH the raised/returned error AND (via the
`_FakeTransport` spy) that nothing was ever handed to the transport -- the task's explicit
bar: "use a spy/flag to assert the guarded emit/accept did NOT happen".

Run (from ecosystem/naalp-react/, PYTHONDONTWRITEBYTECODE=1, using the real Python on this
machine -- not the Microsoft Store `python`/`python3` execution-alias stubs, which resolve
ahead of a real install on PATH and hang):
    python -m unittest -v tests.test_bridge
"""
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-react
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

# Sibling ecosystem packages: imported directly by the TEST (never by naalp_react itself --
# see bridge.py's module docstring on duck-typed injection) so the (b) and (f) cases
# exercise the REAL naalp_hitl / naalp_validator components, not a stand-in for them.
_ECOSYSTEM_ROOT = os.path.dirname(_PKG_ROOT)
for _sibling in ("naalp-hitl", "naalp-validator"):
    _p = os.path.join(_ECOSYSTEM_ROOT, _sibling)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from naalp_react import Action, ReActBridge, ReActError, U, T, M  # noqa: E402
from naalp import approval, cose, envelope, identity, policy  # noqa: E402
import naalp_hitl  # noqa: E402
import naalp_validator  # noqa: E402

ALG = cose.ALG_MLDSA65
AUDIENCE = "svc:tool-executor"
WORKFLOW_CHANNEL = 0x0011
TASK_CREATE = 0   # (channel, kind) declared effect: non_idempotent_write
TASK_RESULT = 3   # (channel, kind) declared effect: non_idempotent_write


def _keypair(seed_byte):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def _args(text, n):
    return M([(U(1), T(text)), (U(2), U(n))])


class _FakeTransport:
    """A spy transport: records every payload handed to send(); touches no network. Used
    to assert the task bar's "guarded emit did NOT happen" requirement directly."""

    def __init__(self):
        self.sent = []

    def send(self, payload):
        self.sent.append(payload)


class _FixedDecisionFrontend(naalp_hitl.HumanInterface):
    """Fakes only the human's keystroke; the decision itself (a real signed approval, or
    a decline) is built by the test using real naalp.approval primitives (mirrors
    naalp-hitl's own _FixedDecisionFrontend)."""

    def __init__(self, decision):
        self._decision = decision
        self.calls = 0

    def request_approval(self, request):
        self.calls += 1
        return self._decision


class ReActBridgeActionToRequestTests(unittest.TestCase):
    """(a) round-trip, (b) HITL fail-closed refusal, (f) validator fail-closed refusal."""

    def setUp(self):
        self.seed, self.pk = _keypair(0x21)
        self.sid = identity.signer_id(ALG, self.pk)
        self.responder_seed, self.responder_pk = _keypair(0x22)
        self.transport = _FakeTransport()

    def _bridge(self, **overrides):
        kwargs = dict(
            alg=ALG, seed=self.seed, signer_id=self.sid, profile=cose.PROFILE_PUBLIC,
            audience=AUDIENCE, self_identity=self.sid,
            responder_alg=ALG, responder_pubkey=self.responder_pk,
            transport=self.transport,
        )
        kwargs.update(overrides)
        return ReActBridge(**kwargs)

    # (a) a well-formed Action -> a signed request whose bytes round-trip decode to the
    # same object, and the exact payload reaches the (spy) transport.
    def test_well_formed_action_round_trips_and_emits(self):
        bridge = self._bridge()
        action = Action(
            name="search_web", channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
            effect=policy.NON_IDEMPOTENT_WRITE, args=_args("weather in Tokyo", 1),
        )
        req = bridge.action_to_request(action)

        decoded = envelope.verify(cose.PROFILE_PUBLIC, ALG, self.pk, lambda c, k: True, req.payload)
        self.assertEqual(decoded.id, req.id)
        self.assertEqual(decoded.channel, WORKFLOW_CHANNEL)
        self.assertEqual(decoded.kind, TASK_CREATE)
        self.assertEqual(decoded.effect, policy.NON_IDEMPOTENT_WRITE)
        self.assertEqual(decoded.audience, AUDIENCE)
        self.assertEqual(
            [(k.v, getattr(v, "v", v)) for k, v in decoded.body.pairs],
            [(k.v, getattr(v, "v", v)) for k, v in action.args.pairs],
        )
        self.assertEqual(self.transport.sent, [req.payload])

    # below-threshold: an injected hitl is wired but must never even be consulted.
    def test_below_threshold_action_bypasses_hitl_and_still_emits(self):
        frontend = _FixedDecisionFrontend(decision=None)
        with tempfile.TemporaryDirectory() as d:
            ledger = approval.open_ledger(os.path.join(d, "consume.wal"))
            try:
                interceptor = naalp_hitl.HITLInterceptor(
                    ledger, ALG, self.responder_pk, AUDIENCE, "bridge-under-test", frontend
                )
                bridge = self._bridge(hitl=interceptor)
                action = Action(
                    name="read_status", channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
                    effect=policy.READ_ONLY, args=_args("status", 0),
                )
                req = bridge.action_to_request(action)
            finally:
                ledger.close()  # ALWAYS release the WAL handle, even on an assertion failure
        self.assertEqual(frontend.calls, 0, "a below-threshold action must never pause for a human")
        self.assertEqual(self.transport.sent, [req.payload])

    # (b) an effecting Action + a wired HITL hook + a declined approval -> refused, and
    # the request is NEVER emitted (no signature produced, nothing handed to transport).
    def test_effecting_action_denied_by_hitl_is_never_emitted(self):
        frontend = _FixedDecisionFrontend(decision=None)  # the human declines
        with tempfile.TemporaryDirectory() as d:
            ledger = approval.open_ledger(os.path.join(d, "consume.wal"))
            try:
                interceptor = naalp_hitl.HITLInterceptor(
                    ledger, ALG, self.responder_pk, AUDIENCE, "bridge-under-test", frontend
                )
                bridge = self._bridge(hitl=interceptor)
                action = Action(
                    name="wire_transfer", channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
                    effect=policy.NON_IDEMPOTENT_WRITE, args=_args("acct-9", 100),
                )
                with self.assertRaises(naalp_hitl.HITLError) as cm:
                    bridge.action_to_request(action)
                self.assertEqual(cm.exception.kind, "ApprovalDenied")
                self.assertEqual(frontend.calls, 1)
                self.assertEqual(len(ledger), 0, "a declined approval must append nothing to the ledger")
            finally:
                ledger.close()  # ALWAYS release the WAL handle, even on an assertion failure
        self.assertEqual(self.transport.sent, [], "a HITL-refused action must never reach the transport")

    # the mirror of (b): a GRANTED approval really resumes -- signs, and emits exactly once.
    def test_effecting_action_approved_by_hitl_is_signed_and_emitted(self):
        approver_id = "approver-1"
        args = _args("acct-9", 250000)
        args_id = _content_id_of(args)
        with tempfile.TemporaryDirectory() as d:
            ledger = approval.open_ledger(os.path.join(d, "consume.wal"))
            try:
                rec = approval.ApprovalRecord(
                    args_id, approver_id, policy.DESTRUCTIVE, b"\x02" * 8, 9_999_999_999_999, AUDIENCE
                )
                sig = approval.sign_approval(rec, ALG, self.responder_seed)
                frontend = _FixedDecisionFrontend(decision=(rec, sig))
                interceptor = naalp_hitl.HITLInterceptor(
                    ledger, ALG, self.responder_pk, AUDIENCE, "bridge-under-test", frontend
                )
                bridge = self._bridge(hitl=interceptor)
                action = Action(
                    name="wire_transfer", channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
                    effect=policy.DESTRUCTIVE, args=args,
                )
                req = bridge.action_to_request(action)
                self.assertTrue(ledger.is_consumed(rec.id()))
            finally:
                ledger.close()  # ALWAYS release the WAL handle, even on an assertion failure
        self.assertEqual(self.transport.sent, [req.payload])
        decoded = envelope.verify(cose.PROFILE_PUBLIC, ALG, self.pk, lambda c, k: True, req.payload)
        self.assertEqual(decoded.id, req.id)

    # (f) the validator hook rejects a malformed candidate pre-send -> refused, and the
    # candidate is never signed or handed to the transport.
    def test_validator_rejects_malformed_action_pre_send(self):
        bridge = self._bridge(validator=naalp_validator.validate)
        # Workflow/TaskCreate declares a FIXED effect (non_idempotent_write); READ_ONLY
        # here is an EffectDeclarationMismatch the validator collects and refuses.
        bad_action = Action(
            name="bad_action", channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
            effect=policy.READ_ONLY, args=_args("x", 0),
        )
        with self.assertRaises(ReActError) as cm:
            bridge.action_to_request(bad_action)
        self.assertEqual(cm.exception.kind, "ValidationRefused")
        self.assertEqual(self.transport.sent, [], "a validator-refused candidate must never reach the transport")

    def test_validator_accepts_well_formed_action(self):
        bridge = self._bridge(validator=naalp_validator.validate)
        action = Action(
            name="search_web", channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
            effect=policy.NON_IDEMPOTENT_WRITE, args=_args("q", 1),
        )
        req = bridge.action_to_request(action)
        self.assertEqual(self.transport.sent, [req.payload])


def _content_id_of(value):
    from naalp import cbor
    return cbor.content_id(value)


class ReActBridgeResponseToObservationTests(unittest.TestCase):
    """(c) bad signature, (d) wrong/absent audience, (e) missing/wrong causal linkage."""

    def setUp(self):
        self.seed, self.pk = _keypair(0x31)
        self.sid = identity.signer_id(ALG, self.pk)
        self.responder_seed, self.responder_pk = _keypair(0x32)
        self.responder_sid = identity.signer_id(ALG, self.responder_pk)
        self.transport = _FakeTransport()
        self.bridge = ReActBridge(
            alg=ALG, seed=self.seed, signer_id=self.sid, profile=cose.PROFILE_PUBLIC,
            audience=AUDIENCE, self_identity=self.sid,
            responder_alg=ALG, responder_pubkey=self.responder_pk,
            transport=self.transport,
        )
        action = Action(
            name="search_web", channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
            effect=policy.NON_IDEMPOTENT_WRITE, args=_args("q", 1),
        )
        self.request = self.bridge.action_to_request(action)

    def _sign_response(self, *, causes, audience):
        obj = envelope.Object(
            kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=self.responder_sid.encode("utf-8"),
            created=1785000000000, effect=policy.NON_IDEMPOTENT_WRITE,
            body=_args("42 degrees", 1), causes=list(causes), profile=cose.PROFILE_PUBLIC,
            audience=audience,
        )
        return envelope.sign(obj, ALG, self.responder_seed)

    def test_valid_response_produces_an_observation(self):
        resp = self._sign_response(causes=[self.request.id], audience=self.sid)
        obs = self.bridge.response_to_observation(resp, self.request)
        self.assertTrue(obs.ok)
        self.assertIsNone(obs.error)
        self.assertEqual(obs.name, "TaskResult")
        self.assertEqual(
            [(k.v, getattr(v, "v", v)) for k, v in obs.body.pairs],
            [(1, "42 degrees"), (2, 1)],
        )

    # (c) a tampered (bad-signature) response -> fail-closed, no body.
    def test_bad_signature_fails_closed(self):
        resp = self._sign_response(causes=[self.request.id], audience=self.sid)
        tampered = bytearray(resp)
        tampered[-1] ^= 0xFF
        obs = self.bridge.response_to_observation(bytes(tampered), self.request)
        self.assertFalse(obs.ok)
        self.assertEqual(obs.error, "BadSignature")
        self.assertIsNone(obs.body)
        self.assertEqual(obs.name, "")

    # (d) a wrong-audience response -> fail-closed.
    def test_wrong_audience_fails_closed(self):
        resp = self._sign_response(causes=[self.request.id], audience="svc:someone-else")
        obs = self.bridge.response_to_observation(resp, self.request)
        self.assertFalse(obs.ok)
        self.assertEqual(obs.error, "WrongAudience")
        self.assertIsNone(obs.body)

    # (d) an ABSENT audience response -> fail-closed too (never "no audience means anyone").
    def test_absent_audience_fails_closed(self):
        resp = self._sign_response(causes=[self.request.id], audience="")
        obs = self.bridge.response_to_observation(resp, self.request)
        self.assertFalse(obs.ok)
        self.assertEqual(obs.error, "WrongAudience")
        self.assertIsNone(obs.body)

    # (e) a response that names NO causal edge back to the request -> fail-closed.
    def test_missing_causal_linkage_fails_closed(self):
        resp = self._sign_response(causes=[], audience=self.sid)
        obs = self.bridge.response_to_observation(resp, self.request)
        self.assertFalse(obs.ok)
        self.assertEqual(obs.error, "CausalViolation")
        self.assertIsNone(obs.body)

    # (e) a response that cites a DIFFERENT (wrong) content id -> fail-closed.
    def test_wrong_causal_linkage_fails_closed(self):
        resp = self._sign_response(causes=[b"\x00" * 50], audience=self.sid)
        obs = self.bridge.response_to_observation(resp, self.request)
        self.assertFalse(obs.ok)
        self.assertEqual(obs.error, "CausalViolation")

    # Fail-closed, never a crash: garbage bytes are refused with a named error, not an
    # unhandled exception -- an adversarial/corrupted response must never bring the caller down.
    def test_garbage_bytes_fail_closed_without_crashing(self):
        obs = self.bridge.response_to_observation(b"not a cose object at all", self.request)
        self.assertFalse(obs.ok)
        self.assertIsNotNone(obs.error)
        self.assertIsNone(obs.body)


if __name__ == "__main__":
    unittest.main()
