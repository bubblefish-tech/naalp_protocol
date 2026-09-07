# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Mutation-surviving conformance tests for the N-AALP Plan-and-Execute orchestrator
(E1.2/R2.2).

Every test here exercises the REAL sibling `naalp_react.ReActBridge` (and, where a test
names it, the REAL sibling `naalp_validator.validate`) -- no signing, verification, or
registry logic is faked. The only test doubles are the `_SpyBridge`/`_ScriptedExecutor`
wrappers below, and both are SPIES: they record every call and then delegate to the real
bridge / a real signed-response builder, exactly the same convention
`ecosystem/naalp-react/tests/test_bridge.py`'s `_FakeTransport` uses.

The required fail-closed matrix (task bar) is:
  (a) test_linear_plan_executes_in_order_with_causal_chain
        A->B->C executes in order; each node's signed request causally links to its
        predecessor's signed request content id.
  (b) test_diamond_plan_causal_edges_are_the_set_of_prereqs
        A->{B,C}->D executes; D's decoded causes[] == {B's request id, C's request id}.
  (c) test_prerequisite_refused_observation_blocks_downstream_and_it_is_never_signed
        A prerequisite whose response fails verification (WrongAudience) -> its dependent
        is NEVER signed, NEVER executed (spy-asserted on both the bridge and the executor).
  (d) test_cyclic_plan_is_rejected_before_any_signing
        A plan with a cycle raises PlanError("CyclicPlan", ...) and the bridge is never
        even consulted (spy-asserted zero calls).
  (e) test_own_request_validation_refusal_blocks_downstream
        A node whose own request fails pre-send validation is refused; its dependent is
        blocked and never reaches the bridge or the executor.

Run (from ecosystem/naalp-plan/, PYTHONDONTWRITEBYTECODE=1, using the real Python on this
machine -- not the Microsoft Store `python`/`python3` execution-alias stubs, which resolve
ahead of a real install on PATH and hang):
    python -m unittest -v tests.test_orchestrator
"""
import os
import sys
import unittest
from typing import Callable, Dict, List

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-plan
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

# Sibling ecosystem package: imported directly by the TEST (never by naalp_plan itself --
# see orchestrator.py's module docstring on duck-typed injection) so test (e) exercises the
# REAL naalp_validator.validate, not a stand-in for it.
_ECOSYSTEM_ROOT = os.path.dirname(_PKG_ROOT)
_VALIDATOR_DIR = os.path.join(_ECOSYSTEM_ROOT, "naalp-validator")
if _VALIDATOR_DIR not in sys.path:
    sys.path.insert(0, _VALIDATOR_DIR)

from naalp_plan import PlanError, PlanOrchestrator, Task  # noqa: E402
from naalp_react import Action, ReActBridge, U, T, M  # noqa: E402
from naalp import cose, envelope, identity, policy  # noqa: E402
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


def _valid_response_builder(responder_seed, responder_sid, self_identity):
    """A real, correctly-signed, correctly-addressed, correctly-causally-linked response
    builder: `(request) -> bytes`."""

    def _build(request):
        obj = envelope.Object(
            kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=responder_sid.encode("utf-8"),
            created=1785000000000, effect=policy.NON_IDEMPOTENT_WRITE,
            body=_args("done", 1), causes=[request.id], profile=cose.PROFILE_PUBLIC,
            audience=self_identity,
        )
        return envelope.sign(obj, ALG, responder_seed)

    return _build


def _wrong_audience_response_builder(responder_seed, responder_sid):
    """A real, correctly-signed, correctly-causally-linked response addressed to the WRONG
    agent -- `response_to_observation` must refuse it `WrongAudience`."""

    def _build(request):
        obj = envelope.Object(
            kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=responder_sid.encode("utf-8"),
            created=1785000000000, effect=policy.NON_IDEMPOTENT_WRITE,
            body=_args("done", 1), causes=[request.id], profile=cose.PROFILE_PUBLIC,
            audience="svc:a-different-agent",
        )
        return envelope.sign(obj, ALG, responder_seed)

    return _build


class _SpyBridge:
    """Wraps a real `ReActBridge`, recording every `action_to_request` /
    `response_to_observation` call before delegating -- a spy, never a fake: all signing
    and verification behaviour is the real bridge's own. Used to assert the task bar's
    "guarded execution did NOT happen" requirement directly."""

    def __init__(self, real_bridge: ReActBridge):
        self._real = real_bridge
        self.calls_to_sign: List[Action] = []
        self.calls_to_verify: List[bytes] = []

    def action_to_request(self, action):
        self.calls_to_sign.append(action)
        return self._real.action_to_request(action)

    def response_to_observation(self, response_bytes, request):
        self.calls_to_verify.append(response_bytes)
        return self._real.response_to_observation(response_bytes, request)


class _ScriptedExecutor:
    """A synchronous request/response spy: for a given task id, invokes the injected
    response-building callable `(request) -> bytes`, and records every task id it was
    actually invoked for."""

    def __init__(self, responders: Dict[str, Callable]):
        self._responders = responders
        self.called_for: List[str] = []

    def __call__(self, task, request):
        self.called_for.append(task.id)
        return self._responders[task.id](request)


class PlanOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.seed, self.pk = _keypair(0x41)
        self.sid = identity.signer_id(ALG, self.pk)
        self.responder_seed, self.responder_pk = _keypair(0x42)
        self.responder_sid = identity.signer_id(ALG, self.responder_pk)
        real_bridge = ReActBridge(
            alg=ALG, seed=self.seed, signer_id=self.sid, profile=cose.PROFILE_PUBLIC,
            audience=AUDIENCE, self_identity=self.sid,
            responder_alg=ALG, responder_pubkey=self.responder_pk,
        )
        self.spy_bridge = _SpyBridge(real_bridge)

    def _action(self, name, effect=policy.NON_IDEMPOTENT_WRITE, text="x", n=0):
        return Action(name=name, channel=WORKFLOW_CHANNEL, kind=TASK_CREATE, effect=effect, args=_args(text, n))

    def _decode(self, payload):
        return envelope.verify(cose.PROFILE_PUBLIC, ALG, self.pk, lambda c, k: True, payload)

    # (a) A->B->C executes in order; each node's signed request causally links to its
    # predecessor's signed request content id.
    def test_linear_plan_executes_in_order_with_causal_chain(self):
        responders = {
            tid: _valid_response_builder(self.responder_seed, self.responder_sid, self.sid)
            for tid in ("A", "B", "C")
        }
        executor = _ScriptedExecutor(responders)
        orch = PlanOrchestrator(bridge=self.spy_bridge, executor=executor)

        tasks = [
            Task(id="A", action=self._action("step_a")),
            Task(id="B", action=self._action("step_b"), prereqs=("A",)),
            Task(id="C", action=self._action("step_c"), prereqs=("B",)),
        ]
        run = orch.run(tasks)

        self.assertEqual(run.order, ("A", "B", "C"))
        for tid in ("A", "B", "C"):
            self.assertEqual(run.results[tid].status, "executed", tid)
            self.assertTrue(run.results[tid].observation.ok, tid)

        decoded_a = self._decode(run.results["A"].request.payload)
        decoded_b = self._decode(run.results["B"].request.payload)
        decoded_c = self._decode(run.results["C"].request.payload)
        self.assertEqual(decoded_a.causes, [])
        self.assertEqual(decoded_b.causes, [run.request_id_for("A")])
        self.assertEqual(decoded_c.causes, [run.request_id_for("B")])
        self.assertEqual(executor.called_for, ["A", "B", "C"])

    # (b) A->{B,C}->D executes; D's decoded causes[] == {B's request id, C's request id}.
    def test_diamond_plan_causal_edges_are_the_set_of_prereqs(self):
        ids = ("A", "B", "C", "D")
        responders = {
            tid: _valid_response_builder(self.responder_seed, self.responder_sid, self.sid) for tid in ids
        }
        executor = _ScriptedExecutor(responders)
        orch = PlanOrchestrator(bridge=self.spy_bridge, executor=executor)

        tasks = [
            Task(id="A", action=self._action("a")),
            Task(id="B", action=self._action("b"), prereqs=("A",)),
            Task(id="C", action=self._action("c"), prereqs=("A",)),
            Task(id="D", action=self._action("d"), prereqs=("B", "C")),
        ]
        run = orch.run(tasks)

        self.assertEqual(run.order, ("A", "B", "C", "D"))
        for tid in ids:
            self.assertEqual(run.results[tid].status, "executed", tid)

        decoded_d = self._decode(run.results["D"].request.payload)
        self.assertEqual(len(decoded_d.causes), 2)
        self.assertEqual(
            set(decoded_d.causes),
            {run.request_id_for("B"), run.request_id_for("C")},
        )
        self.assertEqual(executor.called_for, ["A", "B", "C", "D"])

    # (c) a prerequisite whose response fails verification (WrongAudience) -> its dependent
    # is NEVER signed and NEVER executed.
    def test_prerequisite_refused_observation_blocks_downstream_and_it_is_never_signed(self):
        responders = {"A": _wrong_audience_response_builder(self.responder_seed, self.responder_sid)}
        executor = _ScriptedExecutor(responders)
        orch = PlanOrchestrator(bridge=self.spy_bridge, executor=executor)

        tasks = [
            Task(id="A", action=self._action("a")),
            Task(id="B", action=self._action("b"), prereqs=("A",)),
        ]
        run = orch.run(tasks)

        self.assertEqual(run.results["A"].status, "refused")
        self.assertEqual(run.results["A"].observation.error, "WrongAudience")
        self.assertEqual(run.results["B"].status, "blocked")
        self.assertIsNone(run.results["B"].request)
        self.assertIsNone(run.results["B"].observation)
        # spy assertion: B's Action was NEVER handed to the bridge to sign, and B's
        # executor entry was never invoked either -- the guarded non-execution.
        self.assertEqual([a.name for a in self.spy_bridge.calls_to_sign], ["a"])
        self.assertEqual(executor.called_for, ["A"])

    # (d) a plan with a cycle is rejected with a named error before any node is signed.
    def test_cyclic_plan_is_rejected_before_any_signing(self):
        executor = _ScriptedExecutor({})
        orch = PlanOrchestrator(bridge=self.spy_bridge, executor=executor)

        tasks = [
            Task(id="A", action=self._action("a"), prereqs=("B",)),
            Task(id="B", action=self._action("b"), prereqs=("A",)),
        ]
        with self.assertRaises(PlanError) as cm:
            orch.run(tasks)
        self.assertEqual(cm.exception.kind, "CyclicPlan")
        self.assertEqual(self.spy_bridge.calls_to_sign, [], "a cyclic plan must never reach the bridge to sign")
        self.assertEqual(self.spy_bridge.calls_to_verify, [])
        self.assertEqual(executor.called_for, [])

    # a self-loop (a task naming itself as its own prerequisite) is the degenerate cycle.
    def test_self_loop_is_rejected_as_a_cycle(self):
        executor = _ScriptedExecutor({})
        orch = PlanOrchestrator(bridge=self.spy_bridge, executor=executor)
        tasks = [Task(id="A", action=self._action("a"), prereqs=("A",))]
        with self.assertRaises(PlanError) as cm:
            orch.run(tasks)
        self.assertEqual(cm.exception.kind, "CyclicPlan")
        self.assertEqual(self.spy_bridge.calls_to_sign, [])

    # (e) a node whose own request fails pre-send validation is refused; its dependent is
    # blocked and never reaches the bridge or the executor.
    def test_own_request_validation_refusal_blocks_downstream(self):
        validating_real_bridge = ReActBridge(
            alg=ALG, seed=self.seed, signer_id=self.sid, profile=cose.PROFILE_PUBLIC,
            audience=AUDIENCE, self_identity=self.sid,
            responder_alg=ALG, responder_pubkey=self.responder_pk,
            validator=naalp_validator.validate,
        )
        spy_bridge = _SpyBridge(validating_real_bridge)
        executor = _ScriptedExecutor({})
        orch = PlanOrchestrator(bridge=spy_bridge, executor=executor)

        # Workflow/TaskCreate declares a FIXED effect (non_idempotent_write); READ_ONLY here
        # is an EffectDeclarationMismatch the validator collects and refuses pre-send.
        bad_action = self._action("bad", effect=policy.READ_ONLY)
        tasks = [
            Task(id="A", action=bad_action),
            Task(id="B", action=self._action("b"), prereqs=("A",)),
        ]
        run = orch.run(tasks)

        self.assertEqual(run.results["A"].status, "refused")
        self.assertIn("ValidationRefused", run.results["A"].detail)
        self.assertIsNone(run.results["A"].request)
        self.assertEqual(run.results["B"].status, "blocked")
        self.assertIsNone(run.results["B"].request)
        self.assertEqual(executor.called_for, [], "neither task ever reached the executor")
        self.assertEqual([a.name for a in spy_bridge.calls_to_sign], ["bad"])

    # Structural gates, both before any signing: a duplicate task id and an unknown
    # prerequisite are each their own named PlanError, distinct from "CyclicPlan".
    def test_duplicate_task_id_is_a_named_error(self):
        executor = _ScriptedExecutor({})
        orch = PlanOrchestrator(bridge=self.spy_bridge, executor=executor)
        tasks = [Task(id="A", action=self._action("a1")), Task(id="A", action=self._action("a2"))]
        with self.assertRaises(PlanError) as cm:
            orch.run(tasks)
        self.assertEqual(cm.exception.kind, "DuplicateTaskId")
        self.assertEqual(self.spy_bridge.calls_to_sign, [])

    def test_unknown_prerequisite_is_a_named_error(self):
        executor = _ScriptedExecutor({})
        orch = PlanOrchestrator(bridge=self.spy_bridge, executor=executor)
        tasks = [Task(id="A", action=self._action("a"), prereqs=("ghost",))]
        with self.assertRaises(PlanError) as cm:
            orch.run(tasks)
        self.assertEqual(cm.exception.kind, "UnknownPrerequisite")
        self.assertEqual(self.spy_bridge.calls_to_sign, [])

    # An executor failure (a transport-level error, distinct from a verification refusal)
    # also refuses that node and blocks its dependents -- never a fabricated Observation.
    def test_executor_failure_refuses_the_node_and_blocks_downstream(self):
        def _boom(request):
            raise RuntimeError("transport unreachable")

        executor = _ScriptedExecutor({"A": _boom})
        orch = PlanOrchestrator(bridge=self.spy_bridge, executor=executor)
        tasks = [
            Task(id="A", action=self._action("a")),
            Task(id="B", action=self._action("b"), prereqs=("A",)),
        ]
        run = orch.run(tasks)
        self.assertEqual(run.results["A"].status, "refused")
        self.assertIsNotNone(run.results["A"].request)
        self.assertIsNone(run.results["A"].observation)
        self.assertIn("transport unreachable", run.results["A"].detail)
        self.assertEqual(run.results["B"].status, "blocked")


if __name__ == "__main__":
    unittest.main()
