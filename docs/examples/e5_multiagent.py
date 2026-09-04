# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP cookbook: multi-agent interaction shapes (E5.2, R8.2), via `naalp_multiagent`.

Two shapes, both built from the same `naalp_react.ReActBridge` primitive used in the
ReAct recipe -- there is no second signing path, just two ways of composing several
DISTINCT agent identities around it:

  - `SequentialPipeline`: agent A's Observation feeds agent B's next Action, which feeds
    agent C's -- a chain, each stage causally linked to the one before it.
  - `ParallelFanout`: several DISTINCT agents act on the SAME shared input concurrently,
    then `naalp_multiagent` reconciles their signed results into one deterministic total
    order using the Part-1 reconcile primitive -- the same order every time, regardless
    of thread-scheduling nondeterminism.

Run (from the repository root):
    python docs/examples/e5_multiagent.py
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))
_p = os.path.join(_REPO_ROOT, "ecosystem", "naalp-multiagent")
if _p not in sys.path:
    sys.path.insert(0, _p)

from naalp_multiagent import (  # noqa: E402  (puts naalp_react + impl/python on sys.path)
    CRYPTO_LOCK, Branch, ParallelFanout, SequentialPipeline, Stage,
)
from naalp_react import Action, M, ReActBridge, T, U  # noqa: E402
from naalp import cose, envelope, identity, policy  # noqa: E402

WORKFLOW_CHANNEL, TASK_CREATE, TASK_RESULT = 0x0011, 0, 3
ALG = cose.ALG_MLDSA65
CLOCK_MS = 1785000000000


def _agent(seed_byte):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk, identity.signer_id(ALG, pk)


def _action(name):
    return Action(
        name=name, channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
        effect=policy.NON_IDEMPOTENT_WRITE, args=M([(U(1), T(name))]), args_summary=name,
    )


def main() -> int:
    # One shared counterpart identity answers every request in both shapes below.
    counterpart_seed, counterpart_pk, counterpart_sid = _agent(0xC0)

    def _respond(request, *, audience):
        obj = envelope.Object(
            kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=counterpart_sid.encode("utf-8"),
            created=CLOCK_MS, effect=policy.NON_IDEMPOTENT_WRITE, body=M([(U(1), T("ack"))]),
            causes=[request.id], profile=cose.PROFILE_PUBLIC, audience=audience,
        )
        with CRYPTO_LOCK:  # ParallelFanout drives responders from a thread pool
            return envelope.sign(obj, ALG, counterpart_seed)

    def _bridge_for(seed, sid):
        return ReActBridge(
            alg=ALG, seed=seed, signer_id=sid, profile=cose.PROFILE_PUBLIC,
            audience="svc:counterpart", self_identity=sid, responder_alg=ALG,
            responder_pubkey=counterpart_pk, clock=lambda: CLOCK_MS,
        )

    print("=" * 74)
    print("SEQUENTIAL: three DISTINCT agents, drafter -> reviewer -> booker")
    print("=" * 74)
    draft_seed, _draft_pk, draft_sid = _agent(0xA0)
    review_seed, _review_pk, review_sid = _agent(0xB0)
    book_seed, _book_pk, book_sid = _agent(0xD0)

    stages = [
        Stage(
            agent_id="drafter", bridge=_bridge_for(draft_seed, draft_sid),
            executor=lambda stage, request: _respond(request, audience=draft_sid),
            build_action=lambda obs: _action("draft_itinerary"),
        ),
        Stage(
            agent_id="reviewer", bridge=_bridge_for(review_seed, review_sid),
            executor=lambda stage, request: _respond(request, audience=review_sid),
            build_action=lambda obs: _action("review_itinerary"),
        ),
        Stage(
            agent_id="booker", bridge=_bridge_for(book_seed, book_sid),
            executor=lambda stage, request: _respond(request, audience=book_sid),
            build_action=lambda obs: _action("book_itinerary"),
        ),
    ]
    seq_run = SequentialPipeline(stages=stages).run()
    for r in seq_run.results:
        print("  %-9s status=%s" % (r.agent_id, r.status))
    assert [r.status for r in seq_run.results] == ["executed", "executed", "executed"]

    print()
    print("=" * 74)
    print("PARALLEL: five DISTINCT agents fan out on ONE shared input, then reconcile")
    print("=" * 74)
    coordinator_seed, _cpk, coordinator_sid = _agent(0xE0)
    shared_obj = envelope.Object(
        kind=TASK_CREATE, channel=WORKFLOW_CHANNEL, signer=coordinator_sid.encode("utf-8"),
        created=CLOCK_MS, effect=policy.NON_IDEMPOTENT_WRITE, body=M([(U(1), T("plan_trip"))]),
        causes=[], profile=cose.PROFILE_PUBLIC, audience="svc:fanout",
    )
    envelope.sign(shared_obj, ALG, coordinator_seed)
    shared_input_id = shared_obj.id

    branches = []
    for i in range(5):
        seed, _pk, sid = _agent(0x40 + i)
        branches.append(Branch(
            agent_id="specialist-%d" % i, bridge=_bridge_for(seed, sid),
            executor=lambda branch, request, _sid=sid: _respond(request, audience=_sid),
            build_action=lambda shared_id, _i=i: _action("specialist-task-%d" % _i),
        ))

    par_run = ParallelFanout(branches=branches).run(shared_input_id)
    print("  branch results:", {aid: r.status for aid, r in sorted(par_run.branch_results.items())})
    print("  reconciled order:", [cid.hex()[:12] for cid in par_run.reconciled_order])
    assert set(par_run.executed()) == {b.agent_id for b in branches}

    par_run2 = ParallelFanout(branches=branches).run(shared_input_id)
    print("  reconciled order (second run):", [cid.hex()[:12] for cid in par_run2.reconciled_order])
    assert par_run.reconciled_order == par_run2.reconciled_order
    print("  same total order on both runs, despite concurrent thread scheduling: CONFIRMED")

    print("\nMULTI-AGENT COOKBOOK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
