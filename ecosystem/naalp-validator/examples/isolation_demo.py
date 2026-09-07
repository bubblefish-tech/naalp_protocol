# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Isolation demonstration (A9) for the N-AALP semantic validator: concrete input -> concrete
output, independent of any other component (no HITL interceptor, no N-PAMP transport, no
signing key) -- just naalp_validator called directly on a candidate object.

Run:  python examples/isolation_demo.py   (from ecosystem/naalp-validator/)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from naalp_validator import pre_send_hook, validate  # noqa: E402  (puts impl/python on sys.path)
from naalp import envelope  # noqa: E402
from naalp.cbor import T  # noqa: E402

_SIGNER = bytes.fromhex("5349474e45525f41")


def main():
    print("=== N-AALP semantic validator -- isolation demo ===\n")

    # 1. A well-formed candidate: Control/Hello (channel 0x0000, kind 0, read_only).
    good = envelope.Object(
        kind=0, channel=0x0000, signer=_SIGNER, created=1785000000000, effect=0,
        profile=1, body=T("hello"),
    )
    result = validate(good)
    print("1. Well-formed Control/Hello object:")
    print("   valid  =", result.valid)
    print("   result =", result)
    assert result.valid

    # 2. A hallucinated candidate: an LLM invented kind 42 on the Control channel, declared
    #    a Sovereign-tier profile that doesn't exist (4), and attached 1200 causal edges.
    hallucinated = envelope.Object(
        kind=42, channel=0x0000, signer=_SIGNER, created=1785000000000, effect=0,
        profile=4, body=T("hello"), causes=[b"c"] * 1200,
    )
    result2 = validate(hallucinated)
    print("\n2. Hallucinated object (unknown kind + bad profile + too many causes):")
    print("   valid  =", result2.valid)
    for v in result2.violations:
        print("   violation: %-24s field=%-10s %s" % (v.error, v.field, v.detail))
    assert not result2.valid
    assert {v.error for v in result2.violations} == {"UnknownKind", "RangeError", "TooManyCauses"}

    # 3. A Governance/Consume object (the one baseline consume-once kind) missing its audience
    #    -- the object that WOULD spend the single-use consume ledger, built with no consuming
    #    authority named. Caught here, before signing, instead of failing at the ledger.
    unbound_consume = envelope.Object(
        kind=3, channel=0x0004, signer=_SIGNER, created=1785000000000, effect=2,
        profile=1, body=T("consume-me"),
    )
    result3 = validate(unbound_consume)
    print("\n3. Consume-once object with no audience:")
    print("   valid  =", result3.valid)
    print("   violations =", result3.violations)
    assert not result3.valid
    assert result3.errors() == ["WrongAudience"]

    # 4. The same object, correctly bound -- passes.
    bound_consume = envelope.Object(
        kind=3, channel=0x0004, signer=_SIGNER, created=1785000000000, effect=2,
        profile=1, body=T("consume-me"), audience="ledger-authority-7",
    )
    result4 = validate(bound_consume)
    print("\n4. Same object, correctly audience-bound:")
    print("   valid  =", result4.valid)
    assert result4.valid

    # 5. The firewall-hook entry point (R3.3), driving the same hallucinated object.
    decision = pre_send_hook(hallucinated)
    print("\n5. Firewall-hook decision on the hallucinated object:")
    print("   allow =", decision.allow)
    print("   bool(decision) =", bool(decision))
    assert decision.allow is False

    # 6. The firewall hook actually GATES a guarded action -- not just reports a verdict.
    #    A real gateway calls pre_send_hook() then only invokes sign-and-send if it allows;
    #    this demonstrates that exact calling convention with a spy standing in for the
    #    guarded action, proving the denied object never reaches it.
    sent = []

    def guarded_sign_and_send(obj):
        sent.append(obj)
        return "sent-on-the-wire"

    deny_decision = pre_send_hook(hallucinated)
    if deny_decision:
        guarded_sign_and_send(hallucinated)
    print("\n6. Firewall hook gating a guarded sign-and-send action:")
    print("   deny_decision.allow =", deny_decision.allow)
    print("   guarded action ran  =", bool(sent))
    assert deny_decision.allow is False
    assert sent == []  # the guarded action must NOT run on deny

    allow_decision = pre_send_hook(bound_consume)
    if allow_decision:
        guarded_sign_and_send(bound_consume)
    print("   allow_decision.allow =", allow_decision.allow)
    print("   guarded action ran   =", bool(sent))
    assert allow_decision.allow is True
    assert sent == [bound_consume]  # the guarded action must run when allowed

    print("\n=== all isolation assertions held ===")


if __name__ == "__main__":
    main()
