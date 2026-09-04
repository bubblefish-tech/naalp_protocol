# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP cookbook: the Plan-and-Execute pattern (E5.2, R8.2), via `naalp_plan`.

`naalp_plan.PlanOrchestrator` runs a task graph -- a set of `Task`s, each naming its
prerequisite task ids -- in dependency order, signing each node's request through the
same `naalp_react.ReActBridge` used in the ReAct recipe, and stamping each node's
request with `causes[]` pointing at the content ids of the prerequisites it actually
depended on: the causal graph on the wire IS the plan's dependency graph, not a separate
side record of it.

This recipe runs a small diamond plan: fetch an itinerary, then price flights and price
hotels in parallel (both depend only on the itinerary), then book the trip (which depends
on both prices).

Run (from the repository root):
    python docs/examples/e5_plan.py
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))
_p = os.path.join(_REPO_ROOT, "ecosystem", "naalp-plan")
if _p not in sys.path:
    sys.path.insert(0, _p)

from naalp_plan import PlanOrchestrator, Task  # noqa: E402  (puts naalp_react + impl/python on sys.path)
from naalp_react import Action, M, ReActBridge, T, U  # noqa: E402
from naalp import cose, envelope, identity, policy  # noqa: E402

WORKFLOW_CHANNEL, TASK_CREATE, TASK_RESULT = 0x0011, 0, 3
ALG = cose.ALG_MLDSA65
# A fixed clock -- not wall time -- so `created` (and therefore every content id printed
# below) is IDENTICAL on every run: this script's output is meant to be reproduced exactly,
# not merely resemble what is printed in docs/cookbook.md.
CLOCK_MS = 1785000000000


def _action(name):
    return Action(
        name=name, channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
        effect=policy.NON_IDEMPOTENT_WRITE, args=M([(U(1), T(name))]), args_summary=name,
    )


def main() -> int:
    agent_seed = bytes([0x81]) * 32
    agent_pk = cose.mldsa_keygen("ML-DSA-65", agent_seed)
    agent_sid = identity.signer_id(ALG, agent_pk)

    tool_seed = bytes([0x82]) * 32
    tool_pk = cose.mldsa_keygen("ML-DSA-65", tool_seed)
    tool_sid = identity.signer_id(ALG, tool_pk)

    bridge = ReActBridge(
        alg=ALG, seed=agent_seed, signer_id=agent_sid, profile=cose.PROFILE_PUBLIC,
        audience="svc:trip-planner", self_identity=agent_sid,
        responder_alg=ALG, responder_pubkey=tool_pk, clock=lambda: CLOCK_MS,
    )

    def _decode(payload):
        return envelope.verify(cose.PROFILE_PUBLIC, ALG, agent_pk, lambda c, k: True, payload)

    def _tool_executor(task, request):
        """Every task's `execute` step: a real tool-executor signs a real N-AALP response,
        causally linked back to the request it answers and addressed to the agent."""
        obj = envelope.Object(
            kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=tool_sid.encode("utf-8"),
            created=CLOCK_MS, effect=policy.NON_IDEMPOTENT_WRITE,
            body=M([(U(1), T("done: %s" % task.id))]), causes=[request.id],
            profile=cose.PROFILE_PUBLIC, audience=agent_sid,
        )
        return envelope.sign(obj, ALG, tool_seed)

    plan = [
        Task(id="fetch_itinerary", action=_action("fetch_itinerary")),
        Task(id="price_flights", action=_action("price_flights"), prereqs=("fetch_itinerary",)),
        Task(id="price_hotels", action=_action("price_hotels"), prereqs=("fetch_itinerary",)),
        Task(id="book_trip", action=_action("book_trip"), prereqs=("price_flights", "price_hotels")),
    ]
    orchestrator = PlanOrchestrator(bridge=bridge, executor=_tool_executor)
    run = orchestrator.run(plan)

    print("Execution order:", run.order)
    for tid in run.order:
        result = run.results[tid]
        causes = _decode(result.request.payload).causes
        print("  %-16s status=%-9s causes=%s" % (tid, result.status, [c.hex()[:12] for c in causes]))

    assert run.order == (
        "fetch_itinerary", "price_flights", "price_hotels", "book_trip")
    assert all(run.results[t].status == "executed" for t in
               ("fetch_itinerary", "price_flights", "price_hotels", "book_trip"))
    book_causes = set(_decode(run.results["book_trip"].request.payload).causes)
    assert book_causes == {
        run.request_id_for("price_flights"), run.request_id_for("price_hotels")}
    print("\n'book_trip' causally cites BOTH 'price_flights' and 'price_hotels' -- the wire")
    print("causal graph IS the plan's dependency graph.")

    print("\nPLAN COOKBOOK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
