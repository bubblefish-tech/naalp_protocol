# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Isolation demonstration (A9) for the N-AALP ReAct bridge (E1.1/R2.1): a concrete
Thought -> Action -> [sign+encode] -> (in-memory transport) -> [verify+causal-link] ->
Observation round trip, run standalone with no dependency beyond `naalp_react` + the
Part-1 `naalp` SDK (no HITL interceptor, no semantic validator, no N-PAMP transport) --
concrete input, concrete output, independent of any other ecosystem component.

Two passes:
  PASS 1: a well-formed Action becomes a signed request; a correctly-linked response
           becomes a real, typed Observation.
  PASS 2: the same request, but three DISTINCT malformed responses -- a tampered
           signature, a wrong audience, and a missing causal link -- each verified and
           shown failing closed with the exact named error, never a crash and never a
           silently-accepted body.

Run:  python examples/isolation_demo.py   (from ecosystem/naalp-react/)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from naalp_react import Action, M, ReActBridge, T, U  # noqa: E402  (puts impl/python + naalp_codec on sys.path)
from naalp import cose, envelope, identity, policy  # noqa: E402


class _InMemoryTransport:
    """A fake transport: appends every sent payload to a list. No network, no globals --
    injected into the bridge exactly like a real one would be."""

    def __init__(self):
        self.sent = []

    def send(self, payload):
        self.sent.append(payload)


def main() -> int:
    # --- fixed identities (a real agent and a real tool-executor responder) ---
    agent_seed = bytes([0x51]) * 32
    agent_pk = cose.mldsa_keygen("ML-DSA-65", agent_seed)
    agent_sid = identity.signer_id(cose.ALG_MLDSA65, agent_pk)

    responder_seed = bytes([0x52]) * 32
    responder_pk = cose.mldsa_keygen("ML-DSA-65", responder_seed)
    responder_sid = identity.signer_id(cose.ALG_MLDSA65, responder_pk)

    transport = _InMemoryTransport()
    bridge = ReActBridge(
        alg=cose.ALG_MLDSA65,
        seed=agent_seed,
        signer_id=agent_sid,
        profile=cose.PROFILE_PUBLIC,
        audience="svc:weather-tool",
        self_identity=agent_sid,
        responder_alg=cose.ALG_MLDSA65,
        responder_pubkey=responder_pk,
        transport=transport,
    )

    WORKFLOW_CHANNEL, TASK_CREATE, TASK_RESULT = 0x0011, 0, 3

    print("=" * 72)
    print("PASS 1: Thought -> Action -> signed request -> Observation (the happy path)")
    print("=" * 72)

    # Build the args body through naalp_react's own re-exported naalp_codec value classes
    # (never a raw unwrapped Python dict -- module docstring, "no second codec").

    action = Action(
        name="get_weather", channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
        effect=policy.NON_IDEMPOTENT_WRITE, args=M([(U(1), T("Tokyo"))]),
        args_summary="get_weather(city='Tokyo')",
    )
    request = bridge.action_to_request(action)
    print("Action:  %s" % (action.args_summary,))
    print("Request: %d signed bytes, content id %s..." % (len(request.payload), request.id.hex()[:16]))
    print("Transport received exactly this request:", transport.sent == [request.payload])
    assert transport.sent == [request.payload]

    # The (fake) tool-executor responds asynchronously: a REAL signed N-AALP object,
    # addressed back to the agent, citing the request's content id in causes[].
    response_obj = envelope.Object(
        kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=responder_sid.encode("utf-8"),
        created=1785000000000, effect=policy.NON_IDEMPOTENT_WRITE,
        body=M([(U(1), T("72F and sunny"))]), causes=[request.id],
        profile=cose.PROFILE_PUBLIC, audience=agent_sid,
    )
    response_bytes = envelope.sign(response_obj, cose.ALG_MLDSA65, responder_seed)

    observation = bridge.response_to_observation(response_bytes, request)
    print("Observation: ok=%s kind=%r body=%r" % (
        observation.ok, observation.name,
        [(k.v, v.v) for k, v in observation.body.pairs] if observation.ok else None,
    ))
    assert observation.ok is True
    assert observation.name == "TaskResult"
    assert observation.error is None
    assert [(k.v, v.v) for k, v in observation.body.pairs] == [(1, "72F and sunny")]

    print()
    print("=" * 72)
    print("PASS 2: three distinct malformed responses to the SAME request, each refused")
    print("=" * 72)

    # 2a. Tampered signature.
    tampered = bytearray(response_bytes)
    tampered[-1] ^= 0xFF
    obs_bad_sig = bridge.response_to_observation(bytes(tampered), request)
    print("2a. tampered signature -> ok=%s error=%s" % (obs_bad_sig.ok, obs_bad_sig.error))
    assert obs_bad_sig.ok is False and obs_bad_sig.error == "BadSignature" and obs_bad_sig.body is None

    # 2b. Wrong audience (addressed to a different agent).
    wrong_audience_obj = envelope.Object(
        kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=responder_sid.encode("utf-8"),
        created=1785000000000, effect=policy.NON_IDEMPOTENT_WRITE,
        body=M([(U(1), T("72F and sunny"))]), causes=[request.id],
        profile=cose.PROFILE_PUBLIC, audience="svc:a-different-agent",
    )
    wrong_audience_bytes = envelope.sign(wrong_audience_obj, cose.ALG_MLDSA65, responder_seed)
    obs_wrong_aud = bridge.response_to_observation(wrong_audience_bytes, request)
    print("2b. wrong audience     -> ok=%s error=%s" % (obs_wrong_aud.ok, obs_wrong_aud.error))
    assert obs_wrong_aud.ok is False and obs_wrong_aud.error == "WrongAudience" and obs_wrong_aud.body is None

    # 2c. Missing causal linkage (a real, correctly-addressed, correctly-signed response --
    # but to a DIFFERENT request; it never cites THIS request's content id).
    unlinked_obj = envelope.Object(
        kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=responder_sid.encode("utf-8"),
        created=1785000000000, effect=policy.NON_IDEMPOTENT_WRITE,
        body=M([(U(1), T("72F and sunny"))]), causes=[],
        profile=cose.PROFILE_PUBLIC, audience=agent_sid,
    )
    unlinked_bytes = envelope.sign(unlinked_obj, cose.ALG_MLDSA65, responder_seed)
    obs_unlinked = bridge.response_to_observation(unlinked_bytes, request)
    print("2c. missing causal link -> ok=%s error=%s" % (obs_unlinked.ok, obs_unlinked.error))
    assert obs_unlinked.ok is False and obs_unlinked.error == "CausalViolation" and obs_unlinked.body is None

    print()
    print("ISOLATION DEMO: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
