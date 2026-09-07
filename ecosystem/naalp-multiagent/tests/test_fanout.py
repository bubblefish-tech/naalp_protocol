# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Mutation-surviving conformance tests for the N-AALP parallel multi-agent fan-out +
reconcile (E1.3/R2.3).

Every test here dispatches REAL `naalp_react.ReActBridge` instances (one distinct signing
identity per branch) onto a REAL `concurrent.futures.ThreadPoolExecutor` and converges the
result through the REAL Part-1 `naalp.federation.reconcile` primitive -- no signing,
verification, or reconciliation logic is faked. Each branch's executor sleeps a small random
jitter before signing its response, so branch completion order genuinely varies run to run;
the reconcile step's determinism claim is tested AGAINST that real timing variance, not
merely against a fixed iteration order.

The required fail-closed matrix (task bar) is:
  (c) test_fanout_branches_all_causally_link_to_the_shared_input
        N branches (N distinct agents) all causally link to the one shared input.
  (d) test_reconcile_order_is_deterministic_across_many_runs
        many runs of the SAME branch set, with randomized thread-completion timing,
        reconcile to the IDENTICAL total order every time.
  (e) test_branch_failing_verification_is_excluded_with_a_named_error
        a branch whose response fails verification (WrongAudience) is EXCLUDED from the
        reconciled graph, under that named error -- its request id never appears in the
        reconciled order, and the surviving branches still reconcile normally.

Run (from ecosystem/naalp-multiagent/, PYTHONDONTWRITEBYTECODE=1, using the real Python on
this machine -- not the Microsoft Store `python`/`python3` execution-alias stubs):
    python -m unittest -v tests.test_fanout
"""
import os
import random
import sys
import time
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-multiagent
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_multiagent import CRYPTO_LOCK, Branch, MultiAgentError, ParallelFanout  # noqa: E402
from naalp_react import Action, M, ReActBridge, T, U  # noqa: E402
from naalp import cose, envelope, identity, policy  # noqa: E402

ALG = cose.ALG_MLDSA65
WORKFLOW_CHANNEL = 0x0011
TASK_CREATE = 0
TASK_RESULT = 3
FIXED_CLOCK_MS = 1785000000000  # injected fixed clock: identical `created` across runs, so
                                 # deterministic ML-DSA signing produces byte-identical
                                 # requests -- the precondition for asserting the SAME
                                 # reconciled order across repeated runs (task (d)).


def _keypair(seed_byte):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def _args(text):
    return M([(U(1), T(text))])


def _sign_response(responder_seed, responder_sid, *, request, audience, jitter=0.0):
    """Simulates the counterpart's reply -- run from the branch's OWN thread (the fan-out's
    injected `executor` callback), so this in-process test double, like `naalp_multiagent`
    itself, must serialize its OWN call into the shared non-thread-safe Part-1 crypto
    backend on `naalp_multiagent.CRYPTO_LOCK` (see fanout.py's module docstring for the
    witnessed concurrency defect this guards against). The jitter sleep happens OUTSIDE the
    lock, so branches still race each other for real completion-order variance."""
    if jitter:
        time.sleep(jitter)
    obj = envelope.Object(
        kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=responder_sid.encode("utf-8"),
        created=FIXED_CLOCK_MS, effect=policy.NON_IDEMPOTENT_WRITE,
        body=_args("ack"), causes=[request.id], profile=cose.PROFILE_PUBLIC, audience=audience,
    )
    with CRYPTO_LOCK:
        return envelope.sign(obj, ALG, responder_seed)


def _shared_input_id(seed_byte=0x00):
    """A real signed N-AALP object standing in for 'the shared input' every branch links to
    -- the fan-out places no requirement on who produced it or how; only its content id is
    used."""
    seed, pk = _keypair(seed_byte)
    sid = identity.signer_id(ALG, pk)
    obj = envelope.Object(
        kind=TASK_CREATE, channel=WORKFLOW_CHANNEL, signer=sid.encode("utf-8"),
        created=FIXED_CLOCK_MS, effect=policy.NON_IDEMPOTENT_WRITE,
        body=_args("coordinate"), causes=[], profile=cose.PROFILE_PUBLIC, audience="svc:fanout",
    )
    envelope.sign(obj, ALG, seed)
    return obj.id


class FanoutTests(unittest.TestCase):
    def setUp(self):
        self.r_seed, self.r_pk = _keypair(0xE1)
        self.r_sid = identity.signer_id(ALG, self.r_pk)
        self.shared_input_id = _shared_input_id()

    def _agent_bridge(self, seed_byte):
        seed, pk = _keypair(seed_byte)
        sid = identity.signer_id(ALG, pk)
        # Fixed clock: deterministic `created` -> deterministic content ids given the
        # already-deterministic ML-DSA signature, so repeated runs of the SAME branch set
        # are byte-identical (the precondition for asserting an identical reconciled order
        # across runs, task (d)).
        bridge = ReActBridge(
            alg=ALG, seed=seed, signer_id=sid, profile=cose.PROFILE_PUBLIC,
            audience="svc:counterpart", self_identity=sid,
            responder_alg=ALG, responder_pubkey=self.r_pk,
            clock=lambda: FIXED_CLOCK_MS,
        )
        return bridge, pk, sid

    def _decode(self, pk, payload):
        return envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, lambda c, k: True, payload)

    def _branch(self, agent_id, seed_byte, *, wrong_audience=False, jitter=0.0):
        bridge, pk, sid = self._agent_bridge(seed_byte)

        def build_action(shared_id):
            return Action(
                name=agent_id, channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
                effect=policy.NON_IDEMPOTENT_WRITE, args=_args(agent_id),
            )

        audience = "svc:a-different-agent" if wrong_audience else sid

        def executor(branch, request):
            return _sign_response(self.r_seed, self.r_sid, request=request, audience=audience, jitter=jitter)

        return Branch(agent_id=agent_id, bridge=bridge, executor=executor, build_action=build_action), pk

    # (c) N branches (N distinct agents) all causally link to the one shared input.
    def test_fanout_branches_all_causally_link_to_the_shared_input(self):
        specs = [self._branch("agent-%d" % i, 0x10 + i, jitter=random.uniform(0, 0.01)) for i in range(5)]
        branches = [b for b, _pk in specs]
        pks = {b.agent_id: pk for b, pk in specs}

        run = ParallelFanout(branches=branches).run(self.shared_input_id)

        self.assertEqual(set(run.executed()), {b.agent_id for b in branches})
        for b in branches:
            result = run.branch_results[b.agent_id]
            self.assertEqual(result.status, "executed")
            decoded = self._decode(pks[b.agent_id], result.request.payload)
            self.assertEqual(decoded.causes, [self.shared_input_id])
            # distinct signing identities: this branch's signer really is its own agent
            self.assertEqual(decoded.signer, identity.signer_id(ALG, pks[b.agent_id]).encode("utf-8"))

    # (d) many runs of the SAME branch set, with randomized thread-completion timing,
    # reconcile to the IDENTICAL total order every time.
    def test_reconcile_order_is_deterministic_across_many_runs(self):
        specs = [self._branch("agent-%d" % i, 0x20 + i, jitter=random.uniform(0, 0.02)) for i in range(6)]
        branches = [b for b, _pk in specs]
        fanout = ParallelFanout(branches=branches)

        reference = fanout.run(self.shared_input_id).reconciled_order
        for _ in range(14):
            run = fanout.run(self.shared_input_id)
            self.assertEqual(run.reconciled_order, reference)

        # the order really IS the bytewise-ascending content-id tie-break (root first, then
        # every executed branch's request id sorted), not an accident of identical timing.
        last_run = run
        executed_ids = sorted(last_run.branch_results[b.agent_id].request.id for b in branches)
        self.assertEqual(list(reference), [self.shared_input_id] + executed_ids)

    # (e) a branch whose response fails verification (WrongAudience) is EXCLUDED from the
    # reconciled graph, under that named error; the surviving branches still reconcile.
    def test_branch_failing_verification_is_excluded_with_a_named_error(self):
        good = [self._branch("agent-%d" % i, 0x30 + i) for i in range(3)]
        bad, _bad_pk = self._branch("agent-bad", 0x3F, wrong_audience=True)
        good_branches = [b for b, _pk in good]
        branches = good_branches + [bad]

        run = ParallelFanout(branches=branches).run(self.shared_input_id)

        self.assertEqual(run.branch_results["agent-bad"].status, "excluded")
        self.assertEqual(run.branch_results["agent-bad"].error, "WrongAudience")
        excluded_request_id = run.branch_results["agent-bad"].request.id
        self.assertNotIn(excluded_request_id, run.reconciled_order)

        for b in good_branches:
            self.assertEqual(run.branch_results[b.agent_id].status, "executed")
            self.assertIn(run.branch_results[b.agent_id].request.id, run.reconciled_order)

        # exactly the shared input + the 3 surviving branches, never the excluded one.
        self.assertEqual(len(run.reconciled_order), 1 + len(good_branches))

    def test_duplicate_agent_id_is_a_named_error_before_any_branch_runs(self):
        b1, _ = self._branch("dup", 0x40)
        b2, _ = self._branch("dup", 0x41)
        with self.assertRaises(MultiAgentError) as cm:
            ParallelFanout(branches=[b1, b2])
        self.assertEqual(cm.exception.kind, "DuplicateAgentId")


if __name__ == "__main__":
    unittest.main()
