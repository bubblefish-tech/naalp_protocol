# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance + mutation-surviving tests for the N-AALP OPA/Rego policy integration
(E3.2/R5.2).

Every test here exercises the REAL `opa` binary (github.com/open-policy-agent/opa) against
the checked-in policy at naalp_opa_policy/policies/naalp_authz.rego -- no Rego evaluation is
faked -- and, for the mapping tests, the REAL Part-1 cryptographic primitives (naalp.cose,
naalp.envelope, naalp.identity, naalp.policy) -- no signature verification or identity
derivation is faked either.

OracleGroundingTests runs FIRST and establishes F3 non-circularity: it confirms every {input,
expected} pair in vectors/conformance_vectors.json -- hand-derived from reading
naalp_authz.rego's three rule bodies -- matches what the REAL opa engine actually returns for
that policy, BEFORE any fail-closed or mutation test below relies on "the policy means what we
say it means."

MappingConformanceTests reproduces a subset of those same logical scenarios through REAL,
cryptographically-verified N-AALP objects (naalp.envelope.sign / naalp.envelope.verify) and
confirms naalp_opa_policy.build_input + authorize_with_policy reach the identical Allow/Deny
outcome the hand-derived vector predicts -- proving the MAPPING code (the thing this package
actually owns) wires the real object's fields into the real engine correctly.

FailClosedMutationTests carries the four required fail-closed properties, each with a
recorded mutation (see RED-EVIDENCE.md) that flips it red when the corresponding line in
naalp_opa_policy/opa_policy.py is defeated:
  - test_engine_unreachable_denies_even_a_would_be_allow          (M1: OPAEngine.decide's
    except-branch)
  - test_deny_is_actually_enforced_before_a_would_be_allow        (M2: authorize_with_policy's
    engine consult)
  - test_signer_resolved_from_verified_pubkey_not_self_asserted_field (M3: build_input's
    principal resolution)
  - test_undefined_query_result_denies_even_a_would_be_allow      (M4: OPAEngine.decide's
    undefined-result branch)

Run (from ecosystem/naalp-opa-policy/, PYTHONDONTWRITEBYTECODE=1, using the real Python
interpreter for this platform -- on Windows the Microsoft-Store `python`/`python3`
execution-alias stubs resolve ahead of a real install on PATH and hang, so invoke the actual
interpreter binary directly rather than the bare `python` command):
    PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_opa_policy

Requires the real `opa` binary on PATH (github.com/open-policy-agent/opa, installed this
session via `winget install --id open-policy-agent.opa -e`).
"""
import json
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-opa-policy
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_opa_policy import (  # noqa: E402
    DEFAULT_POLICY_DIR,
    OPAEngine,
    OPAEngineError,
    authorize_with_policy,
    build_input,
)
from naalp import cose, envelope, identity, policy  # noqa: E402
from naalp.cbor import T  # noqa: E402

_VECTORS_PATH = os.path.join(_PKG_ROOT, "vectors", "conformance_vectors.json")
ALG = cose.ALG_MLDSA65
ANY_KIND = lambda ch, k: True  # noqa: E731 -- this package tests policy consult, not kind/channel registration


def _key(seed_byte):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def _signed_object(seed, pk, *, effect, audience, signer_field=None, kind=1, channel=4):
    """Build and sign a real N-AALP object, then verify it through the real Part-1 primitive
    (naalp.envelope.verify) -- returns the VERIFIED Object, exactly what a real caller of this
    package would hold before calling authorize_with_policy. `signer_field` defaults to the
    real pubkey bytes (the ordinary case); tests that need to demonstrate the self-asserted-
    signer-field failure pass a DIFFERENT value deliberately."""
    obj = envelope.Object(
        kind=kind, channel=channel, signer=(signer_field if signer_field is not None else pk),
        created=1785000000000, effect=effect, body=T("payload"), audience=audience,
    )
    signed = envelope.sign(obj, ALG, seed)
    return envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, ANY_KIND, signed)


def _load_vectors():
    with open(_VECTORS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class OracleGroundingTests(unittest.TestCase):
    """F3 non-circularity, established BEFORE any test below trusts the policy's meaning: every
    hand-derived {input, expected} pair in vectors/conformance_vectors.json is confirmed
    against the REAL opa engine evaluating the REAL checked-in policy."""

    def test_conformance_vectors_match_real_engine(self):
        data = _load_vectors()
        engine = OPAEngine(policy_dir=DEFAULT_POLICY_DIR)
        self.assertGreaterEqual(len(data["vectors"]), 8, "at least 8 hand-derived vectors")
        for vector in data["vectors"]:
            with self.subTest(vector=vector["name"]):
                got = engine.decide(vector["input"])
                self.assertEqual(
                    got, vector["expected"],
                    "%s: real opa engine returned %r, vector expects %r (%s)"
                    % (vector["name"], got, vector["expected"], vector["reason"]),
                )


class MappingConformanceTests(unittest.TestCase):
    """Reproduce a subset of the SAME logical scenarios the vectors already ground, through
    REAL cryptographically-verified N-AALP objects, and confirm the mapping+integration
    (build_input, authorize_with_policy) reaches the identical Allow/Deny outcome."""

    def setUp(self):
        self.seed, self.pk = _key(0x11)
        self.principal = identity.signer_id(ALG, self.pk)
        self.engine = OPAEngine(policy_dir=DEFAULT_POLICY_DIR)

    def test_matching_read_only_object_is_allowed(self):
        obj = _signed_object(self.seed, self.pk, effect=policy.READ_ONLY, audience="svc:payments")
        grant = policy.Grant(principal=self.principal, max_effect=policy.DESTRUCTIVE)
        authorize_with_policy(obj, ALG, self.pk, grant, self.engine)  # must not raise

    def test_destructive_effect_over_ceiling_is_denied(self):
        obj = _signed_object(self.seed, self.pk, effect=policy.DESTRUCTIVE, audience="svc:payments")
        grant = policy.Grant(principal=self.principal, max_effect=policy.IDEMPOTENT_WRITE)
        with self.assertRaises(policy.PolicyError) as cm:
            authorize_with_policy(obj, ALG, self.pk, grant, self.engine)
        self.assertEqual(cm.exception.kind, "EffectNotAuthorized")

    def test_wrong_audience_object_is_denied(self):
        obj = _signed_object(self.seed, self.pk, effect=policy.READ_ONLY, audience="svc:unrelated")
        grant = policy.Grant(principal=self.principal, max_effect=policy.DESTRUCTIVE)
        with self.assertRaises(policy.PolicyError) as cm:
            authorize_with_policy(obj, ALG, self.pk, grant, self.engine)
        self.assertEqual(cm.exception.kind, "EffectNotAuthorized")

    def test_build_input_matches_grounded_vector_shape(self):
        """build_input's OUTPUT for a real object must be the exact shape the grounded
        vectors use (design.md 'Governance (R5)': effect/audience/kind/channel/signer/grant)."""
        obj = _signed_object(self.seed, self.pk, effect=policy.IDEMPOTENT_WRITE, audience="svc:payments",
                              kind=7, channel=9)
        grant = policy.Grant(principal=self.principal, max_effect=policy.DESTRUCTIVE)
        doc = build_input(obj, ALG, self.pk, grant)
        self.assertEqual(doc, {
            "effect": policy.IDEMPOTENT_WRITE, "audience": "svc:payments", "kind": 7, "channel": 9,
            "signer": self.principal, "grant": {"principal": self.principal, "max_effect": policy.DESTRUCTIVE},
        })


class FailClosedMutationTests(unittest.TestCase):
    """The four required fail-closed properties (see module docstring + RED-EVIDENCE.md)."""

    def setUp(self):
        self.seed, self.pk = _key(0x22)
        self.principal = identity.signer_id(ALG, self.pk)

    # M1 -- an unreachable engine must deny, even where a working engine WOULD have allowed.
    def test_engine_unreachable_denies_even_a_would_be_allow(self):
        obj = _signed_object(self.seed, self.pk, effect=policy.READ_ONLY, audience="svc:payments")
        grant = policy.Grant(principal=self.principal, max_effect=policy.DESTRUCTIVE)
        broken_engine = OPAEngine(policy_dir=DEFAULT_POLICY_DIR, opa_binary="naalp-opa-binary-does-not-exist")
        # Sanity: confirm the SAME scenario is allowed by a REAL, reachable engine, so a
        # denial below is provably caused by the broken engine, not by the policy's own logic.
        real_engine = OPAEngine(policy_dir=DEFAULT_POLICY_DIR)
        authorize_with_policy(obj, ALG, self.pk, grant, real_engine)  # must not raise
        with self.assertRaises(policy.PolicyError) as cm:
            authorize_with_policy(obj, ALG, self.pk, grant, broken_engine)
        self.assertEqual(cm.exception.kind, "EffectNotAuthorized")

    def test_opa_engine_error_raises_opaengineerror_internally(self):
        """Direct unit check on the lower-level choke point OPAEngineError is meant to
        represent, independent of decide()'s fail-closed wrapping."""
        broken_engine = OPAEngine(policy_dir=DEFAULT_POLICY_DIR, opa_binary="naalp-opa-binary-does-not-exist")
        with self.assertRaises(OPAEngineError):
            broken_engine._run({"effect": 0, "audience": "", "kind": 0, "channel": 0,
                                 "signer": "x", "grant": {"principal": "x", "max_effect": 0}})

    # M2 -- a real Deny must actually be enforced (never silently skipped).
    def test_deny_is_actually_enforced_before_a_would_be_allow(self):
        obj = _signed_object(self.seed, self.pk, effect=policy.DESTRUCTIVE, audience="svc:payments")
        grant = policy.Grant(principal=self.principal, max_effect=policy.READ_ONLY)
        engine = OPAEngine(policy_dir=DEFAULT_POLICY_DIR)
        with self.assertRaises(policy.PolicyError) as cm:
            authorize_with_policy(obj, ALG, self.pk, grant, engine)
        self.assertEqual(cm.exception.kind, "EffectNotAuthorized")

    # M3 -- the identity fed to the policy MUST be signature-derived, never the object's own
    # self-asserted `signer` body field.
    def test_signer_resolved_from_verified_pubkey_not_self_asserted_field(self):
        obj = _signed_object(
            self.seed, self.pk, effect=policy.READ_ONLY, audience="svc:payments",
            signer_field=b"attacker-claimed-identity-not-the-real-signer",
        )
        # The grant is issued to the REAL, cryptographically-verified principal -- never to the
        # object's self-asserted field.
        grant = policy.Grant(principal=self.principal, max_effect=policy.DESTRUCTIVE)
        engine = OPAEngine(policy_dir=DEFAULT_POLICY_DIR)
        doc = build_input(obj, ALG, self.pk, grant)
        self.assertEqual(doc["signer"], self.principal, "input.signer must be the resolved principal")
        self.assertNotEqual(
            doc["signer"], obj.signer,
            "the object's self-asserted signer body field must never leak into the OPA input",
        )
        authorize_with_policy(obj, ALG, self.pk, grant, engine)  # must not raise

    # M4 -- an undefined query result (opa ran cleanly but the query resolved to nothing) must
    # deny, even where the SAME input against the real rule WOULD have allowed.
    def test_undefined_query_result_denies_even_a_would_be_allow(self):
        obj = _signed_object(self.seed, self.pk, effect=policy.READ_ONLY, audience="svc:payments")
        grant = policy.Grant(principal=self.principal, max_effect=policy.DESTRUCTIVE)
        real_query_engine = OPAEngine(policy_dir=DEFAULT_POLICY_DIR)
        authorize_with_policy(obj, ALG, self.pk, grant, real_query_engine)  # must not raise
        undefined_query_engine = OPAEngine(
            policy_dir=DEFAULT_POLICY_DIR, query="data.naalp.authz.no_such_rule_exists"
        )
        with self.assertRaises(policy.PolicyError) as cm:
            authorize_with_policy(obj, ALG, self.pk, grant, undefined_query_engine)
        self.assertEqual(cm.exception.kind, "EffectNotAuthorized")


if __name__ == "__main__":
    unittest.main()
