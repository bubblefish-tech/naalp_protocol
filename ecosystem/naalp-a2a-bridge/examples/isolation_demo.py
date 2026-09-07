# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""A9 isolation demonstration for the N-AALP A2A agent-coordination bridge (E2.2, R4.1-4.3):
carry a real, foreign-native A2A Agent Card and a real foreign-native A2A task-state activity
through the bridge into signed N-AALP wire objects with real ML-DSA-65 keys, hand ONLY the wire
bytes to a fresh verifier, and show the verifier recovers the exact original foreign-native
representation -- octet-exact for the card, value-exact for the activity -- with the declared
per-skill effect intact. Then shows the two failure modes the whole module exists to enforce: an
illegal A2A state transition is refused before a single signature is spent on it, and a task
activity presented alongside an unrelated (even independently valid) card attestation is refused
rather than silently accepted.

Run (from ecosystem/naalp-a2a-bridge/, using the real Python on this machine, not the Microsoft
Store `python` stub):
    python examples/isolation_demo.py
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-a2a-bridge
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_a2a_bridge import (  # noqa: E402
    ForeignTaskEvent, SkillMapping, bridge_activity, bridge_card, verify_and_recover,
)
from naalp import cose, naming, policy  # noqa: E402


def _seed(b):
    return bytes([b]) * 32


# The A2A Agent Card exactly as a developer's A2A client would fetch it -- raw JSON bytes, never
# parsed or re-serialized by this bridge (carriage, not adoption).
CARD_BYTES = (
    b'{"protocolVersion":"0.2.5","name":"billing-agent","url":"https://agent.example/a2a",'
    b'"skills":[{"id":"submit","name":"Submit invoice"},{"id":"get","name":"Get status"}]}'
)


def main() -> int:
    print("=" * 72)
    print("PASS 1: bridge a real A2A Agent Card + a real A2A task-state activity")
    print("=" * 72)

    card_seed = _seed(0xC1)
    card_pk = cose.mldsa_keygen("ML-DSA-65", card_seed)
    mappings = [
        SkillMapping("submit", policy.NON_IDEMPOTENT_WRITE, True),
        SkillMapping("get", policy.READ_ONLY, False),
    ]
    im, card_obj = bridge_card(card_seed, CARD_BYTES, mappings)
    print("signed card-import id (the task profile's bound scope): %s" % im.id().hex())

    task_seed = _seed(0xC2)
    task_pk = cose.mldsa_keygen("ML-DSA-65", task_seed)
    # Exactly the sequence of A2A TaskState strings an A2A client's status-update stream would
    # report for one invoice-submission task.
    activity = [
        ForeignTaskEvent("task-9001", "working"),
        ForeignTaskEvent("task-9001", "input-required"),
        ForeignTaskEvent("task-9001", "working"),
        ForeignTaskEvent("task-9001", "completed"),
    ]
    transitions, activity_objs = bridge_activity(activity, im.id(), task_seed)
    print("signed task-transition chain: %d transitions, final state %s" % (
        len(transitions), naming.state_name(transitions[-1].to)))

    print()
    print("=" * 72)
    print("PASS 2: a FRESH verifier, holding ONLY the wire bytes, recovers the original activity")
    print("=" * 72)
    # Simulate "a counterparty received these bytes": nothing but card_obj/activity_objs and the
    # two independently-held public keys crosses this boundary.
    resolved_card, recovered_card_bytes, im2, verified, recovered_activity = verify_and_recover(
        card_obj, card_pk, activity_objs, task_pk)

    print("recovered card bytes octet-identical: %r" % (recovered_card_bytes == CARD_BYTES,))
    assert recovered_card_bytes == CARD_BYTES
    print("recovered activity value-identical: %r" % (recovered_activity == activity,))
    assert recovered_activity == activity

    submit_op, ok = im2.operation("submit")
    assert ok
    print("declared effect for 'submit' survived the boundary: %s (approval required: %r)" % (
        policy.safety_label_name(submit_op.effect_class()), submit_op.requires_approval_flag()))
    assert submit_op.effect_class() == policy.NON_IDEMPOTENT_WRITE
    assert submit_op.requires_approval_flag() is True

    print()
    print("=" * 72)
    print("PASS 3: an illegal A2A state transition is refused BEFORE any signature is spent")
    print("=" * 72)
    bad_activity = [
        ForeignTaskEvent("task-9002", "working"),
        ForeignTaskEvent("task-9002", "completed"),   # terminal
        ForeignTaskEvent("task-9002", "working"),      # illegal: no out-edge from a terminal state
    ]
    try:
        bridge_activity(bad_activity, im.id(), task_seed)
        print("FAIL: an illegal A2A transition was accepted -- this would be a security bug")
        return 1
    except naming.NamingError as e:
        print("illegal transition correctly refused fail-closed: kind=%s" % e.kind)
        assert e.kind == "IllegalTransition"

    print()
    print("=" * 72)
    print("PASS 4: an activity bound to a FOREIGN card scope is refused (non-circular binding)")
    print("=" * 72)
    other_seed = _seed(0xC3)
    other_pk = cose.mldsa_keygen("ML-DSA-65", other_seed)
    other_im, _other_card_obj = bridge_card(
        other_seed, b'{"protocolVersion":"0.2.5","name":"other-agent","skills":[]}', [])
    assert other_im.id() != im.id()

    # This activity is genuinely, correctly bound to the OTHER card's scope.
    foreign_scoped_activity = [ForeignTaskEvent("task-9003", "working")]
    _, foreign_objs = bridge_activity(foreign_scoped_activity, other_im.id(), task_seed)
    try:
        # Verified against card_obj (the FIRST card) -- both card_obj and foreign_objs are each
        # independently, genuinely valid; they simply do not name the same scope.
        verify_and_recover(card_obj, card_pk, foreign_objs, task_pk)
        print("FAIL: an activity bound to a foreign card scope verified -- this would be a security bug")
        return 1
    except naming.NamingError as e:
        print("foreign-card-scoped activity correctly refused: kind=%s" % e.kind)
        assert e.kind == "ForeignCard"

    print()
    print("ISOLATION DEMO: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
