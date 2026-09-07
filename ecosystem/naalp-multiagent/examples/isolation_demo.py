# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Isolation demonstration (A9) for the N-AALP multi-agent interaction shapes (E1.3/R2.3): both
shapes run standalone with no dependency beyond `naalp_multiagent` + the sibling
`naalp_react` bridge + the Part-1 `naalp` SDK (no HITL interceptor, no semantic validator, no
N-PAMP transport) -- concrete input, concrete output, independent of any other ecosystem
component.

Four passes:
  PASS 1: SEQUENTIAL pipeline, three DISTINCT agents (A -> B -> C), all execute; prints each
           stage's signed request content id and its causal edge back to its predecessor.
  PASS 2: SEQUENTIAL pipeline, agent B's response is addressed to the wrong agent -- shown
           refusing closed with the exact named error, and agent C's stage is shown NEVER
           signed, NEVER run.
  PASS 3: PARALLEL fan-out, five DISTINCT agents on one shared input, converged by the real
           Part-1 reconcile primitive; prints every branch's causal edge and the reconciled
           total order, then re-runs the SAME fan-out to show the order is identical.
  PASS 4: PARALLEL fan-out, one branch's response is addressed to the wrong agent -- shown
           EXCLUDED under its named error, absent from the reconciled order, while the
           surviving branches still reconcile normally.

Run:  python examples/isolation_demo.py   (from ecosystem/naalp-multiagent/)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from naalp_multiagent import (  # noqa: E402  (puts naalp_react + impl/python on sys.path)
    CRYPTO_LOCK, Branch, ParallelFanout, SequentialPipeline, Stage,
)
from naalp_react import Action, M, ReActBridge, T, U  # noqa: E402
from naalp import cose, envelope, identity, policy  # noqa: E402

WORKFLOW_CHANNEL, TASK_CREATE, TASK_RESULT = 0x0011, 0, 3
ALG = cose.ALG_MLDSA65
FIXED_CLOCK_MS = 1785000000000


def _keypair(seed_byte):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def _agent(seed_byte):
    seed, pk = _keypair(seed_byte)
    return seed, pk, identity.signer_id(ALG, pk)


def _args(text):
    return M([(U(1), T(text))])


def _action(name):
    return Action(
        name=name, channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
        effect=policy.NON_IDEMPOTENT_WRITE, args=_args(name), args_summary=name,
    )


def _decode(pk, payload):
    return envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, lambda c, k: True, payload)


def _sign_response(responder_seed, responder_sid, *, request, audience):
    """Simulates a counterpart's reply. Serialized on CRYPTO_LOCK because it is invoked
    from inside the fan-out's own thread pool in PASS 3/4 (see fanout.py's module docstring
    for the witnessed non-thread-safe Part-1 ML-DSA backend this guards against)."""
    obj = envelope.Object(
        kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=responder_sid.encode("utf-8"),
        created=FIXED_CLOCK_MS, effect=policy.NON_IDEMPOTENT_WRITE,
        body=_args("ack"), causes=[request.id], profile=cose.PROFILE_PUBLIC, audience=audience,
    )
    with CRYPTO_LOCK:
        return envelope.sign(obj, ALG, responder_seed)


def main() -> int:
    # A single shared "counterpart" identity signs every response in every pass below
    # (mirroring naalp-plan's own isolation demo).
    r_seed, r_pk = _keypair(0xF0)
    r_sid = identity.signer_id(ALG, r_pk)

    def bridge_for(seed, sid):
        return ReActBridge(
            alg=ALG, seed=seed, signer_id=sid, profile=cose.PROFILE_PUBLIC,
            audience="svc:counterpart", self_identity=sid,
            responder_alg=ALG, responder_pubkey=r_pk, clock=lambda: FIXED_CLOCK_MS,
        )

    # =====================================================================================
    print("=" * 78)
    print("PASS 1: sequential pipeline, three DISTINCT agents A -> B -> C, all execute")
    print("=" * 78)

    a_seed, a_pk, a_sid = _agent(0xA1)
    b_seed, b_pk, b_sid = _agent(0xB1)
    c_seed, c_pk, c_sid = _agent(0xC1)
    pks = {"agent-A": a_pk, "agent-B": b_pk, "agent-C": c_pk}

    def make_stages(*, b_wrong_audience=False):
        return [
            Stage(
                agent_id="agent-A", bridge=bridge_for(a_seed, a_sid),
                executor=lambda stage, request: _sign_response(r_seed, r_sid, request=request, audience=a_sid),
                build_action=lambda obs: _action("draft_itinerary"),
            ),
            Stage(
                agent_id="agent-B", bridge=bridge_for(b_seed, b_sid),
                executor=lambda stage, request: _sign_response(
                    r_seed, r_sid, request=request,
                    audience=("svc:a-different-agent" if b_wrong_audience else b_sid),
                ),
                build_action=lambda obs: _action("review_itinerary"),
            ),
            Stage(
                agent_id="agent-C", bridge=bridge_for(c_seed, c_sid),
                executor=lambda stage, request: _sign_response(r_seed, r_sid, request=request, audience=c_sid),
                build_action=lambda obs: _action("book_itinerary"),
            ),
        ]

    run1 = SequentialPipeline(stages=make_stages()).run()
    for r in run1.results:
        req_id = r.request.id.hex()[:16] if r.request else None
        causes = _decode(pks[r.agent_id], r.request.payload).causes if r.request else None
        causes_hex = [c.hex()[:16] for c in causes] if causes is not None else None
        print("  %s: status=%s request_id=%s... causes=%s" % (r.agent_id, r.status, req_id, causes_hex))
    assert [r.status for r in run1.results] == ["executed", "executed", "executed"]
    decoded_b = _decode(b_pk, run1.result_for("agent-B").request.payload)
    decoded_c = _decode(c_pk, run1.result_for("agent-C").request.payload)
    assert decoded_b.causes == [run1.result_for("agent-A").request.id]
    assert decoded_c.causes == [run1.result_for("agent-B").request.id]

    # =====================================================================================
    print()
    print("=" * 78)
    print("PASS 2: sequential pipeline, agent B's response is addressed WRONG -> agent C")
    print("        never signed, never run")
    print("=" * 78)

    run2 = SequentialPipeline(stages=make_stages(b_wrong_audience=True)).run()
    for r in run2.results:
        err = r.observation.error if r.observation else None
        print("  %s: status=%s error=%s detail=%s" % (r.agent_id, r.status, err, r.detail))
    assert run2.result_for("agent-A").status == "executed"
    assert run2.result_for("agent-B").status == "refused"
    assert run2.result_for("agent-B").observation.error == "WrongAudience"
    assert run2.result_for("agent-C").status == "blocked"
    assert run2.result_for("agent-C").request is None, "agent-C must never even be signed"

    # =====================================================================================
    print()
    print("=" * 78)
    print("PASS 3: parallel fan-out, five DISTINCT agents on one shared input + reconcile")
    print("=" * 78)

    coordinator_seed, coordinator_pk, coordinator_sid = _agent(0xD0)
    shared_obj = envelope.Object(
        kind=TASK_CREATE, channel=WORKFLOW_CHANNEL, signer=coordinator_sid.encode("utf-8"),
        created=FIXED_CLOCK_MS, effect=policy.NON_IDEMPOTENT_WRITE,
        body=_args("coordinate_trip"), causes=[], profile=cose.PROFILE_PUBLIC, audience="svc:fanout",
    )
    envelope.sign(shared_obj, ALG, coordinator_seed)
    shared_input_id = shared_obj.id
    print("  shared input id: %s..." % shared_input_id.hex()[:16])

    def make_branch(agent_id, seed_byte, *, wrong_audience=False):
        seed, pk, sid = _agent(seed_byte)
        audience = "svc:a-different-agent" if wrong_audience else sid
        branch = Branch(
            agent_id=agent_id, bridge=bridge_for(seed, sid),
            executor=lambda branch, request: _sign_response(r_seed, r_sid, request=request, audience=audience),
            build_action=lambda shared_id: _action(agent_id),
        )
        return branch, pk

    good_specs = [make_branch("agent-%d" % i, 0x10 + i) for i in range(5)]
    good_branches = [b for b, _pk in good_specs]
    good_pks = {b.agent_id: pk for b, pk in good_specs}

    fanout = ParallelFanout(branches=good_branches)
    run3a = fanout.run(shared_input_id)
    for b in good_branches:
        result = run3a.branch_results[b.agent_id]
        decoded = _decode(good_pks[b.agent_id], result.request.payload)
        print(
            "  %s: status=%s request_id=%s... causes=%s"
            % (b.agent_id, result.status, result.request.id.hex()[:16], [c.hex()[:16] for c in decoded.causes])
        )
    print("  reconciled order:", [cid.hex()[:16] + "..." for cid in run3a.reconciled_order])
    assert set(run3a.executed()) == {b.agent_id for b in good_branches}
    for b in good_branches:
        decoded = _decode(good_pks[b.agent_id], run3a.branch_results[b.agent_id].request.payload)
        assert decoded.causes == [shared_input_id]

    run3b = fanout.run(shared_input_id)
    print("  reconciled order (second run):", [cid.hex()[:16] + "..." for cid in run3b.reconciled_order])
    assert run3a.reconciled_order == run3b.reconciled_order, "two runs must reconcile to the identical order"
    print("  two runs reconcile to the IDENTICAL order: CONFIRMED")

    # =====================================================================================
    print()
    print("=" * 78)
    print("PASS 4: parallel fan-out, one branch's response is addressed WRONG -> excluded,")
    print("        absent from the reconciled order; survivors still reconcile")
    print("=" * 78)

    bad_branch, _bad_pk = make_branch("agent-bad", 0x3F, wrong_audience=True)
    fanout2 = ParallelFanout(branches=good_branches + [bad_branch])
    run4 = fanout2.run(shared_input_id)
    for aid, result in sorted(run4.branch_results.items()):
        print("  %s: status=%s error=%s" % (aid, result.status, result.error))
    print("  reconciled order:", [cid.hex()[:16] + "..." for cid in run4.reconciled_order])

    assert run4.branch_results["agent-bad"].status == "excluded"
    assert run4.branch_results["agent-bad"].error == "WrongAudience"
    excluded_id = run4.branch_results["agent-bad"].request.id
    assert excluded_id not in run4.reconciled_order
    assert set(run4.executed()) == {b.agent_id for b in good_branches}
    assert len(run4.reconciled_order) == 1 + len(good_branches)

    print()
    print("ISOLATION DEMO: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
