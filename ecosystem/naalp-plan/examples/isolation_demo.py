# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Isolation demonstration (A9) for the N-AALP Plan-and-Execute orchestrator (E1.2/R2.2): a
concrete diamond plan (A -> {B, C} -> D) run standalone with no dependency beyond
`naalp_plan` + the sibling `naalp_react` bridge + the Part-1 `naalp` SDK (no HITL
interceptor, no semantic validator, no N-PAMP transport) -- concrete input, concrete
output, independent of any other ecosystem component.

Two passes:
  PASS 1: the diamond plan executes end to end. Every node's signed request content id and
           its causal edges (`causes[]`) are printed, along with each node's Observation.
  PASS 2: the SAME plan shape, but B's response is addressed to the wrong agent -- shown
           refusing closed with the exact named error, and D (which depends on both B and
           C) is shown NEVER signed, NEVER executed, exactly as the fail-closed contract
           requires.

Run:  python examples/isolation_demo.py   (from ecosystem/naalp-plan/)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from naalp_plan import PlanOrchestrator, Task  # noqa: E402  (puts naalp_react + impl/python on sys.path)
from naalp_react import Action, M, ReActBridge, T, U  # noqa: E402
from naalp import cose, envelope, identity, policy  # noqa: E402

WORKFLOW_CHANNEL, TASK_CREATE, TASK_RESULT = 0x0011, 0, 3
ALG = cose.ALG_MLDSA65


def _make_action(name):
    return Action(
        name=name, channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
        effect=policy.NON_IDEMPOTENT_WRITE, args=M([(U(1), T(name))]),
        args_summary=name,
    )


def _sign_response(responder_seed, responder_sid, *, request, audience):
    """A real, correctly-signed response object, addressed to `audience`, causally linked
    back to `request`."""
    obj = envelope.Object(
        kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=responder_sid.encode("utf-8"),
        created=1785000000000, effect=policy.NON_IDEMPOTENT_WRITE,
        body=M([(U(1), T("done"))]), causes=[request.id],
        profile=cose.PROFILE_PUBLIC, audience=audience,
    )
    return envelope.sign(obj, ALG, responder_seed)


class _ToolExecutor:
    """The orchestrator's injected `executor`: routes each task's signed request to a
    per-task tool-executor callable and returns the raw response bytes -- exactly the
    "send this signed request, get the response bytes back" step this class exists to
    inject (never a hidden network call)."""

    def __init__(self, responders):
        self._responders = responders
        self.invocations = []

    def __call__(self, task, request):
        self.invocations.append(task.id)
        return self._responders[task.id](request)


def main() -> int:
    # --- fixed identities (a real agent and a real tool-executor responder) ---
    agent_seed = bytes([0x61]) * 32
    agent_pk = cose.mldsa_keygen("ML-DSA-65", agent_seed)
    agent_sid = identity.signer_id(ALG, agent_pk)

    responder_seed = bytes([0x62]) * 32
    responder_pk = cose.mldsa_keygen("ML-DSA-65", responder_seed)
    responder_sid = identity.signer_id(ALG, responder_pk)

    bridge = ReActBridge(
        alg=ALG, seed=agent_seed, signer_id=agent_sid, profile=cose.PROFILE_PUBLIC,
        audience="svc:planner-tool", self_identity=agent_sid,
        responder_alg=ALG, responder_pubkey=responder_pk,
    )

    def _decode(payload):
        return envelope.verify(cose.PROFILE_PUBLIC, ALG, agent_pk, lambda c, k: True, payload)

    print("=" * 72)
    print("PASS 1: diamond plan A -> {B, C} -> D, every node executes and links causally")
    print("=" * 72)

    plan = [
        Task(id="A", action=_make_action("fetch_itinerary")),
        Task(id="B", action=_make_action("price_flights"), prereqs=("A",)),
        Task(id="C", action=_make_action("price_hotels"), prereqs=("A",)),
        Task(id="D", action=_make_action("book_trip"), prereqs=("B", "C")),
    ]
    responders = {
        tid: (lambda request, _rs=responder_seed, _rsid=responder_sid, _aud=agent_sid:
              _sign_response(_rs, _rsid, request=request, audience=_aud))
        for tid in ("A", "B", "C", "D")
    }
    executor = _ToolExecutor(responders)
    orchestrator = PlanOrchestrator(bridge=bridge, executor=executor)

    run = orchestrator.run(plan)
    print("Execution order:", run.order)
    for tid in run.order:
        result = run.results[tid]
        req_id = result.request.id.hex()[:16] if result.request else None
        causes = _decode(result.request.payload).causes if result.request else None
        causes_hex = [c.hex()[:16] for c in causes] if causes is not None else None
        print(
            "  %s: status=%s request_id=%s... causes=%s observation_ok=%s"
            % (tid, result.status, req_id, causes_hex, result.observation.ok if result.observation else None)
        )
    assert run.order == ("A", "B", "C", "D")
    assert all(run.results[tid].status == "executed" for tid in "ABCD")
    decoded_d = _decode(run.results["D"].request.payload)
    assert set(decoded_d.causes) == {run.request_id_for("B"), run.request_id_for("C")}
    assert executor.invocations == ["A", "B", "C", "D"]

    print()
    print("=" * 72)
    print("PASS 2: B's response is addressed to the WRONG agent -> D never signed, never run")
    print("=" * 72)

    def _wrong_audience_for_b(request):
        return _sign_response(responder_seed, responder_sid, request=request, audience="svc:a-different-agent")

    responders2 = dict(responders)
    responders2["B"] = _wrong_audience_for_b
    executor2 = _ToolExecutor(responders2)
    orchestrator2 = PlanOrchestrator(bridge=bridge, executor=executor2)

    run2 = orchestrator2.run(plan)
    for tid in run2.order:
        result = run2.results[tid]
        err = result.observation.error if result.observation else None
        print("  %s: status=%s error=%s detail=%s" % (tid, result.status, err, result.detail))

    assert run2.results["A"].status == "executed"
    assert run2.results["B"].status == "refused"
    assert run2.results["B"].observation.error == "WrongAudience"
    assert run2.results["C"].status == "executed"
    assert run2.results["D"].status == "blocked", "D depends on the refused B and must never run"
    assert run2.results["D"].request is None, "D must never even be signed"
    assert run2.results["D"].observation is None, "D must never have a fabricated Observation"
    assert executor2.invocations == ["A", "B", "C"], "D's executor entry must never be invoked"

    print()
    print("ISOLATION DEMO: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
