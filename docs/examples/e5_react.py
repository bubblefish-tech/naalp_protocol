# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP cookbook: the ReAct pattern (E5.2, R8.2), via `naalp_react`.

A ReAct agent's loop is Thought -> Action -> Observation. `naalp_react.ReActBridge` turns
each Action into a real, signed N-AALP request object and turns the counterpart's signed
response back into a typed Observation -- verifying signature, audience, and causal
linkage (the response must cite the request's content id in `causes[]`) before the agent
ever sees it. A response that fails any of those checks becomes a typed, non-crashing
Observation with `ok=False` and a named error, never a silently-accepted body.

Run (from the repository root):
    python docs/examples/e5_react.py
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))
_p = os.path.join(_REPO_ROOT, "ecosystem", "naalp-react")
if _p not in sys.path:
    sys.path.insert(0, _p)

from naalp_react import Action, M, ReActBridge, T, U  # noqa: E402  (puts impl/python on sys.path)
from naalp import cose, envelope, identity, policy  # noqa: E402

WORKFLOW_CHANNEL, TASK_CREATE, TASK_RESULT = 0x0011, 0, 3
ALG = cose.ALG_MLDSA65
# A fixed clock -- not wall time -- so `created` (and therefore every content id printed
# below) is IDENTICAL on every run: this script's output is meant to be reproduced exactly,
# not merely resemble what is printed in docs/cookbook.md.
CLOCK_MS = 1785000000000


class _InMemoryTransport:
    """A minimal transport: appends every sent payload to a list. A real transport (N-PAMP,
    HTTP, ...) implements the same one-method `send(payload)` contract."""

    def __init__(self):
        self.sent = []

    def send(self, payload):
        self.sent.append(payload)


def main() -> int:
    # The agent's own identity, and the tool-executor's identity it expects responses from.
    agent_seed = bytes([0x71]) * 32
    agent_pk = cose.mldsa_keygen("ML-DSA-65", agent_seed)
    agent_sid = identity.signer_id(ALG, agent_pk)

    tool_seed = bytes([0x72]) * 32
    tool_pk = cose.mldsa_keygen("ML-DSA-65", tool_seed)
    tool_sid = identity.signer_id(ALG, tool_pk)

    transport = _InMemoryTransport()
    bridge = ReActBridge(
        alg=ALG, seed=agent_seed, signer_id=agent_sid, profile=cose.PROFILE_PUBLIC,
        audience="svc:weather-tool", self_identity=agent_sid,
        responder_alg=ALG, responder_pubkey=tool_pk, transport=transport,
        clock=lambda: CLOCK_MS,
    )

    print("Thought: I need the current weather in Tokyo before I recommend a departure time.")
    action = Action(
        name="get_weather", channel=WORKFLOW_CHANNEL, kind=TASK_CREATE,
        effect=policy.NON_IDEMPOTENT_WRITE, args=M([(U(1), T("Tokyo"))]),
        args_summary="get_weather(city='Tokyo')",
    )

    # Action -> a real signed N-AALP request, sent over the injected transport.
    request = bridge.action_to_request(action)
    print("Action -> signed request: %d bytes, content id %s..." % (
        len(request.payload), request.id.hex()[:16]))
    print("transport received exactly this request:", transport.sent == [request.payload])

    # The tool executor answers with a REAL signed N-AALP object, causally linked back to
    # the request's content id and addressed to the agent.
    response_obj = envelope.Object(
        kind=TASK_RESULT, channel=WORKFLOW_CHANNEL, signer=tool_sid.encode("utf-8"),
        created=CLOCK_MS, effect=policy.NON_IDEMPOTENT_WRITE,
        body=M([(U(1), T("72F and sunny"))]), causes=[request.id],
        profile=cose.PROFILE_PUBLIC, audience=agent_sid,
    )
    response_bytes = envelope.sign(response_obj, ALG, tool_seed)

    # Response bytes -> a verified, typed Observation.
    observation = bridge.response_to_observation(response_bytes, request)
    print("Observation: ok=%s body=%r" % (
        observation.ok, [(k.v, v.v) for k, v in observation.body.pairs]))
    print("Thought: 72F and sunny -- a good departure window.")
    assert observation.ok is True
    assert [(k.v, v.v) for k, v in observation.body.pairs] == [(1, "72F and sunny")]

    # A tampered response is never a crash and never silently accepted: it becomes a
    # typed refusal the agent's loop can branch on.
    tampered = bytearray(response_bytes)
    tampered[-1] ^= 0xFF
    bad = bridge.response_to_observation(bytes(tampered), request)
    print("A tampered response instead yields: ok=%s error=%s" % (bad.ok, bad.error))
    assert bad.ok is False and bad.error == "BadSignature"

    print("\nREACT COOKBOOK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
