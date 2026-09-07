# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""A9 isolation demonstration for the N-AALP OPA/Rego policy integration (E3.2/R5.2): a
concrete real-object -> real-OPA-engine-consult -> Allow/Deny run, using a real ML-DSA-65
key pair, a real signed+verified N-AALP object, and the real `opa` binary evaluating the
checked-in policy at naalp_opa_policy/policies/naalp_authz.rego -- followed by the SAME
scenario denied for a policy reason (wrong audience), and then denied again purely because
the policy engine itself is unreachable (fail-closed, never fail-open).

Run (from ecosystem/naalp-opa-policy/, using the real Python on this machine, not the
Microsoft Store `python` stub). Requires the real `opa` binary on PATH.
    python examples/isolation_demo.py
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-opa-policy
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_opa_policy import (  # noqa: E402
    DEFAULT_POLICY_DIR,
    OPAEngine,
    authorize_with_policy,
    build_input,
)
from naalp import cose, envelope, identity, policy  # noqa: E402
from naalp.cbor import T  # noqa: E402

ALG = cose.ALG_MLDSA65
ANY_KIND = lambda ch, k: True  # noqa: E731


def _signed_and_verified(seed, pk, *, effect, audience, kind=1, channel=4):
    obj = envelope.Object(
        kind=kind, channel=channel, signer=pk, created=1785000000000, effect=effect,
        body=T("wire-transfer-request"), audience=audience,
    )
    signed = envelope.sign(obj, ALG, seed)
    return envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, ANY_KIND, signed)


def main() -> int:
    seed = bytes([0x55]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    principal = identity.signer_id(ALG, pk)
    grant = policy.Grant(principal=principal, max_effect=policy.NON_IDEMPOTENT_WRITE)

    print("=" * 72)
    print("PASS 1: a real, policy-conformant N-AALP object -> real OPA engine -> Allow -> execute")
    print("=" * 72)
    engine = OPAEngine(policy_dir=DEFAULT_POLICY_DIR)
    allowed_obj = _signed_and_verified(seed, pk, effect=policy.IDEMPOTENT_WRITE, audience="svc:payments")
    print("input document sent to the real opa engine: %r" % (build_input(allowed_obj, ALG, pk, grant),))
    executed = []

    def _wire():
        executed.append("WIRE_EXECUTED")
        return "WIRE_EXECUTED"

    authorize_with_policy(allowed_obj, ALG, pk, grant, engine)  # must not raise
    result = _wire()  # the action is executed ONLY past a successful authorize_with_policy call
    print("policy consult: ALLOW -- action executed: %r" % (executed,))
    assert result == "WIRE_EXECUTED" and executed == ["WIRE_EXECUTED"]

    print()
    print("=" * 72)
    print("PASS 2: the SAME principal, an object addressed to the WRONG audience -> Deny -> refused")
    print("=" * 72)
    denied_obj = _signed_and_verified(seed, pk, effect=policy.IDEMPOTENT_WRITE, audience="svc:unrelated-service")
    executed2 = []

    def _wire2():
        executed2.append("SHOULD_NEVER_RUN")
        return "SHOULD_NEVER_RUN"

    try:
        authorize_with_policy(denied_obj, ALG, pk, grant, engine)
        _wire2()
        print("FAIL: a wrong-audience object was NOT refused -- this would be a security bug")
        return 1
    except policy.PolicyError as e:
        print("policy consult: DENY (kind=%s) -- action never executed: %r" % (e.kind, executed2))
        assert e.kind == "EffectNotAuthorized"
        assert executed2 == []

    print()
    print("=" * 72)
    print("PASS 3: a policy-conformant object again, but the OPA engine itself is UNREACHABLE")
    print("        -> fail-closed Deny (never fail-open), even though a working engine allows it")
    print("=" * 72)
    broken_engine = OPAEngine(policy_dir=DEFAULT_POLICY_DIR, opa_binary="naalp-opa-binary-does-not-exist")
    reachable_obj = _signed_and_verified(seed, pk, effect=policy.IDEMPOTENT_WRITE, audience="svc:payments")
    # Confirm the SAME object is allowed by the real, reachable engine, so PASS 3's denial is
    # provably caused by engine unreachability, not by the object itself.
    authorize_with_policy(reachable_obj, ALG, pk, grant, engine)  # must not raise
    executed3 = []

    def _wire3():
        executed3.append("SHOULD_NEVER_RUN")
        return "SHOULD_NEVER_RUN"

    try:
        authorize_with_policy(reachable_obj, ALG, pk, grant, broken_engine)
        _wire3()
        print("FAIL: an unreachable engine was treated as an ALLOW -- this would be a security bug")
        return 1
    except policy.PolicyError as e:
        print("policy consult: DENY (kind=%s, engine unreachable) -- action never executed: %r"
              % (e.kind, executed3))
        assert e.kind == "EffectNotAuthorized"
        assert executed3 == []

    print()
    print("ISOLATION DEMO: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
