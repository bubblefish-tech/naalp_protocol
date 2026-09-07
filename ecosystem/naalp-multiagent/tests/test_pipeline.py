# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Mutation-surviving conformance tests for the N-AALP sequential multi-agent pipeline
(E1.3/R2.3).

Every test here exercises THREE DISTINCT real `naalp_react.ReActBridge` instances (three
distinct signing identities -- "agent A", "agent B", "agent C") -- no signing, verification,
or registry logic is faked. The only test double is the `_SpyBridge` wrapper below, a SPY:
it records every call and then delegates to the real bridge, exactly the same convention
`ecosystem/naalp-plan/tests/test_orchestrator.py`'s `_SpyBridge` uses.

The required fail-closed matrix (task bar) is:
  (a) test_three_stage_pipeline_runs_in_order_with_causal_chain
        agent A -> agent B -> agent C executes in order; each stage's signed request
        causally links to its PREDECESSOR's signed request content id (never its own
        agent's prior request, never the response).
  (b) test_stage_refusal_blocks_downstream_and_it_is_never_signed_or_run
        agent B's response fails verification (WrongAudience) -> agent C's stage is NEVER
        signed, NEVER executed (spy-asserted on both agent C's bridge and its executor).

Run (from ecosystem/naalp-multiagent/, PYTHONDONTWRITEBYTECODE=1, using the real Python on
this machine -- not the Microsoft Store `python`/`python3` execution-alias stubs, which
resolve ahead of a real install on PATH and hang):
    python -m unittest -v tests.test_pipeline
"""
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-multiagent
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_multiagent import SequentialPipeline, Stage  # noqa: E402  (puts naalp_plan + naalp_react + impl/python on sys.path)
from naalp_react import Action, M, ReActBridge, T, U  # noqa: E402
from naalp import cose, envelope, identity, policy  # noqa: E402

ALG = cose.ALG_MLDSA65
WORKFLOW_CHANNEL = 0x0011
TASK_CREATE = 0   # (channel, kind) declared effect: non_idempotent_write
TASK_RESULT = 3   # (channel, kind) declared effect: non_idempotent_write


def _keypair(seed_byte):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def _args(text):
    return M([(U(1), T(text))])


def _sign_response(responder_seed, responder_sid, *, request, audience):
    """A real, correctly-signed response object, causally linked back to `request`,
    addressed to `audience` (the responding stage's own required response audience)."""
    obj = envelope.Object(
        kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=responder_sid.encode("utf-8"),
        created=1785000000000, effect=policy.NON_IDEMPOTENT_WRITE,
        body=_args("ack"), causes=[request.id], profile=cose.PROFILE_PUBLIC, audience=audience,
    )
    return envelope.sign(obj, ALG, responder_seed)


class _SpyBridge:
    """Wraps a real `ReActBridge`, recording every `action_to_request` /
    `response_to_observation` call before delegating -- a spy, never a fake: all signing and
    verification behaviour is the real bridge's own."""

    def __init__(self, real_bridge):
        self._real = real_bridge
        self.calls_to_sign = []
        self.calls_to_verify = []

    def action_to_request(self, action):
        self.calls_to_sign.append(action)
        return self._real.action_to_request(action)

    def response_to_observation(self, response_bytes, request):
        self.calls_to_verify.append(response_bytes)
        return self._real.response_to_observation(response_bytes, request)


class _RecordingExecutor:
    """A synchronous request/response spy: invokes the injected response-building callable
    `(request) -> bytes` and records how many times it was actually invoked."""

    def __init__(self, responder):
        self._responder = responder
        self.invocations = 0

    def __call__(self, stage, request):
        self.invocations += 1
        return self._responder(request)


class SequentialPipelineTests(unittest.TestCase):
    def setUp(self):
        # Three DISTINCT agents -- three distinct signing identities -- plus one distinct
        # "counterpart" identity that signs every stage's real response (mirroring
        # test_orchestrator.py's responder_seed/responder_sid convention).
        self.a_seed, self.a_pk = _keypair(0xA1)
        self.b_seed, self.b_pk = _keypair(0xB1)
        self.c_seed, self.c_pk = _keypair(0xC1)
        self.a_sid = identity.signer_id(ALG, self.a_pk)
        self.b_sid = identity.signer_id(ALG, self.b_pk)
        self.c_sid = identity.signer_id(ALG, self.c_pk)

        self.r_seed, self.r_pk = _keypair(0xD1)
        self.r_sid = identity.signer_id(ALG, self.r_pk)

    def _bridge(self, seed, sid):
        real = ReActBridge(
            alg=ALG, seed=seed, signer_id=sid, profile=cose.PROFILE_PUBLIC,
            audience="svc:counterpart", self_identity=sid,
            responder_alg=ALG, responder_pubkey=self.r_pk,
        )
        return _SpyBridge(real)

    def _decode(self, pk, payload):
        return envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, lambda c, k: True, payload)

    def _action(self, name):
        return Action(
            name=name, channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
            effect=policy.NON_IDEMPOTENT_WRITE, args=_args(name),
        )

    def _three_agent_stages(self, *, b_audience=None):
        bridge_a = self._bridge(self.a_seed, self.a_sid)
        bridge_b = self._bridge(self.b_seed, self.b_sid)
        bridge_c = self._bridge(self.c_seed, self.c_sid)

        exec_a = _RecordingExecutor(
            lambda request: _sign_response(self.r_seed, self.r_sid, request=request, audience=self.a_sid)
        )
        exec_b = _RecordingExecutor(
            lambda request: _sign_response(
                self.r_seed, self.r_sid, request=request, audience=(b_audience or self.b_sid)
            )
        )
        exec_c = _RecordingExecutor(
            lambda request: _sign_response(self.r_seed, self.r_sid, request=request, audience=self.c_sid)
        )

        stages = [
            Stage(agent_id="agent-A", bridge=bridge_a, executor=exec_a,
                  build_action=lambda obs: self._action("stage_a")),
            Stage(agent_id="agent-B", bridge=bridge_b, executor=exec_b,
                  build_action=lambda obs: self._action("stage_b")),
            Stage(agent_id="agent-C", bridge=bridge_c, executor=exec_c,
                  build_action=lambda obs: self._action("stage_c")),
        ]
        bridges = {"agent-A": bridge_a, "agent-B": bridge_b, "agent-C": bridge_c}
        executors = {"agent-A": exec_a, "agent-B": exec_b, "agent-C": exec_c}
        return stages, bridges, executors

    # (a) agent A -> agent B -> agent C executes in order; each stage's signed request
    # causally links to its PREDECESSOR's signed request content id.
    def test_three_stage_pipeline_runs_in_order_with_causal_chain(self):
        stages, _bridges, executors = self._three_agent_stages()
        run = SequentialPipeline(stages=stages).run()

        self.assertEqual([r.agent_id for r in run.results], ["agent-A", "agent-B", "agent-C"])
        for r in run.results:
            self.assertEqual(r.status, "executed", r.agent_id)
            self.assertTrue(r.observation.ok, r.agent_id)

        decoded_a = self._decode(self.a_pk, run.result_for("agent-A").request.payload)
        decoded_b = self._decode(self.b_pk, run.result_for("agent-B").request.payload)
        decoded_c = self._decode(self.c_pk, run.result_for("agent-C").request.payload)
        self.assertEqual(decoded_a.causes, [])
        self.assertEqual(decoded_b.causes, [run.result_for("agent-A").request.id])
        self.assertEqual(decoded_c.causes, [run.result_for("agent-B").request.id])
        # Distinct signing identities: each stage's signer field really is that agent's own.
        self.assertEqual(decoded_a.signer, self.a_sid.encode("utf-8"))
        self.assertEqual(decoded_b.signer, self.b_sid.encode("utf-8"))
        self.assertEqual(decoded_c.signer, self.c_sid.encode("utf-8"))
        self.assertEqual(executors["agent-A"].invocations, 1)
        self.assertEqual(executors["agent-B"].invocations, 1)
        self.assertEqual(executors["agent-C"].invocations, 1)

    # (b) agent B's response fails verification (WrongAudience) -> agent C's stage is NEVER
    # signed, NEVER executed.
    def test_stage_refusal_blocks_downstream_and_it_is_never_signed_or_run(self):
        stages, bridges, executors = self._three_agent_stages(b_audience="svc:a-different-agent")
        run = SequentialPipeline(stages=stages).run()

        self.assertEqual(run.result_for("agent-A").status, "executed")
        self.assertEqual(run.result_for("agent-B").status, "refused")
        self.assertEqual(run.result_for("agent-B").observation.error, "WrongAudience")
        self.assertEqual(run.result_for("agent-C").status, "blocked")
        self.assertIsNone(run.result_for("agent-C").request)
        self.assertIsNone(run.result_for("agent-C").observation)
        # spy assertion: agent-C's Action was NEVER handed to ITS bridge to sign, and its
        # executor entry was never invoked -- the guarded non-execution.
        self.assertEqual(bridges["agent-C"].calls_to_sign, [])
        self.assertEqual(bridges["agent-C"].calls_to_verify, [])
        self.assertEqual(executors["agent-C"].invocations, 0)
        # agent A's stage was unaffected (it ran before the refusal).
        self.assertEqual(executors["agent-A"].invocations, 1)
        self.assertEqual(executors["agent-B"].invocations, 1)

    # A single-stage pipeline is the degenerate chain: no prior Observation exists, so
    # build_action(None) is what actually runs, and causes[] is empty.
    def test_single_stage_pipeline_has_no_prior_observation_and_empty_causes(self):
        bridge_a = self._bridge(self.a_seed, self.a_sid)
        seen_obs = []

        def build_action(obs):
            seen_obs.append(obs)
            return self._action("solo")

        exec_a = _RecordingExecutor(
            lambda request: _sign_response(self.r_seed, self.r_sid, request=request, audience=self.a_sid)
        )
        stages = [Stage(agent_id="agent-A", bridge=bridge_a, executor=exec_a, build_action=build_action)]
        run = SequentialPipeline(stages=stages).run()

        self.assertEqual(run.result_for("agent-A").status, "executed")
        self.assertEqual(seen_obs, [None])
        decoded = self._decode(self.a_pk, run.result_for("agent-A").request.payload)
        self.assertEqual(decoded.causes, [])

    # A downstream stage's build_action really does receive the prior stage's verified
    # Observation body (the "feeds" semantics R2.3 names) -- not merely a causal edge.
    def test_downstream_build_action_receives_prior_observation_body(self):
        bridge_a = self._bridge(self.a_seed, self.a_sid)
        bridge_b = self._bridge(self.b_seed, self.b_sid)
        seen_obs = []

        def build_action_b(obs):
            seen_obs.append(obs)
            return self._action("stage_b")

        exec_a = _RecordingExecutor(
            lambda request: _sign_response(self.r_seed, self.r_sid, request=request, audience=self.a_sid)
        )
        exec_b = _RecordingExecutor(
            lambda request: _sign_response(self.r_seed, self.r_sid, request=request, audience=self.b_sid)
        )
        stages = [
            Stage(agent_id="agent-A", bridge=bridge_a, executor=exec_a,
                  build_action=lambda obs: self._action("stage_a")),
            Stage(agent_id="agent-B", bridge=bridge_b, executor=exec_b, build_action=build_action_b),
        ]
        run = SequentialPipeline(stages=stages).run()

        self.assertEqual(run.result_for("agent-B").status, "executed")
        self.assertEqual(len(seen_obs), 1)
        self.assertIsNotNone(seen_obs[0])
        self.assertTrue(seen_obs[0].ok)
        self.assertEqual(seen_obs[0].name, "TaskResult")


if __name__ == "__main__":
    unittest.main()
