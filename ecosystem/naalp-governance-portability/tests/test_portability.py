# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
K4 -- mutation-surviving portability conformance tests
(ecosystem/naalp-governance-portability). Every assertion here would fail if
`naalp_kit.binding.resolve_effect`, any of K1/K2/K3's own gating/effect-capture logic, or this
suite's own `corpus.expected_effect`/`expected_denied` oracle were replaced by a constant return
(anti-fake rule A5).

Non-circularity (F3): every `NormalizedOutcome.verified` object is independently re-decoded
through `naalp.ez.verify` by `harness.py` (never through an adapter's own bookkeeping), and every
`expected_*` value this suite asserts against comes from `naalp_governance_portability.corpus`'s
own oracle functions -- which call K0's shared, already-graded `resolve_effect`/`authorize_object`
and the real, frozen `naalp.channels.TABLE` registry directly. No expected value in this file is
ever read back out of one adapter's emitted object to grade a sibling adapter -- that would only
prove adapter-A agrees with adapter-A.

What "portability" means here, precisely (K4-1..K4-3): for the SAME logical governance action,
signed through K1 (google-adk), K2 (a2a-sdk), and K3 (mcp) via each framework's OWN real
callback/hook shape, the GOVERNANCE-RELEVANT structure K0 actually signs is IDENTICAL across all
three -- same (channel, kind) pair, same resolved C5 effect, same single-field opaque-body
wrapper shape, and the same authorization/fail-closed OUTCOME (denied vs allowed, and which
named error class) -- even though each framework's own observable denial SURFACE differs (a
dict for K1, a raised exception for K2, an `isError` result for K3) and each framework's own
opaque payload BYTES differ (JSON vs protobuf wire shape) -- both of which are the "framework-
specific wrapping" this corpus deliberately does NOT require to be identical.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1, using the real Python interpreter -- not the
Microsoft Store `python`/`python3` execution-alias stubs, which hang):
    PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-governance-portability/tests/test_portability.py -v
"""
import os
import sys

import pytest

# ecosystem/naalp-governance-portability's package dir name has a hyphen and so cannot itself be
# part of a dotted import path; insert its own directory (the parent of this tests/ dir) onto
# sys.path so `naalp_governance_portability` (the underscore package, sibling of tests/) is
# importable regardless of invocation cwd -- same convention every other ecosystem package's
# tests/ directory uses.
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from naalp_governance_portability import corpus, harness
from naalp import cbor, channels, cose, ez, policy


def _seed(b):
    return bytes([b]) * 32


def _signer(b=0x51):
    return ez.Signer(_seed(b), alg=cose.ALG_MLDSA65, profile=cose.PROFILE_PUBLIC)


DRIVERS = {
    "K1-ADK": harness.run_k1,
    "K2-A2A": harness.run_k2,
    "K3-MCP": harness.run_k3,
}

GATED_CASE_IDS = [c.case_id for c in corpus.CASES if c.grant_max_effect is not None]
OBSERVE_CASE_IDS = [
    c.case_id for c in corpus.CASES if c.grant_max_effect is None and not c.force_core_failure
]


# --- corpus oracle sanity (the independent authority itself, graded before it grades anyone) ---

def test_corpus_channel_kind_are_the_frozen_bridge_carriage_surface():
    name, declared, variable = channels.lookup(corpus.CHANNEL_BRIDGE, corpus.KIND_CARRIAGE)
    assert (corpus.CHANNEL_BRIDGE, corpus.KIND_CARRIAGE) == (0x000D, 0)
    assert variable is True
    assert declared == policy.READ_ONLY


def test_expected_effect_honors_an_explicit_declared_effect():
    case = corpus.CASES_BY_ID["observe_explicit_read_only"]
    assert corpus.expected_effect(case) == policy.READ_ONLY


def test_expected_effect_fail_closed_default_is_destructive_when_unclassified():
    case = corpus.CASES_BY_ID["observe_fail_closed_default"]
    assert corpus.expected_effect(case) == policy.DESTRUCTIVE


def test_expected_denied_true_when_effect_exceeds_ceiling():
    case = corpus.CASES_BY_ID["gated_deny_uncovered_destructive"]
    assert corpus.expected_denied(case) is True


def test_expected_denied_false_when_effect_is_within_ceiling():
    case = corpus.CASES_BY_ID["gated_allow_covered_write"]
    assert corpus.expected_denied(case) is False


def test_expected_denied_raises_for_a_non_gated_case():
    case = corpus.CASES_BY_ID["observe_explicit_read_only"]
    with pytest.raises(ValueError):
        corpus.expected_denied(case)


# --- K4-1/K4-2: per-adapter, per-case portability against the independent oracle ---------------

@pytest.mark.parametrize("adapter_name", sorted(DRIVERS.keys()))
@pytest.mark.parametrize("case_id", [c.case_id for c in corpus.CASES if not c.force_core_failure])
def test_every_adapter_signs_the_case_on_the_bridge_carriage_surface(adapter_name, case_id):
    case = corpus.CASES_BY_ID[case_id]
    outcome = DRIVERS[adapter_name](case, _signer())
    assert outcome.core_error is None, "unexpected core failure: %r" % (outcome.core_error,)
    assert outcome.verified is not None, "adapter produced no signed object to verify"
    assert outcome.verified.channel == corpus.CHANNEL_BRIDGE
    assert outcome.verified.kind == corpus.KIND_CARRIAGE


@pytest.mark.parametrize("adapter_name", sorted(DRIVERS.keys()))
@pytest.mark.parametrize("case_id", [c.case_id for c in corpus.CASES if not c.force_core_failure])
def test_every_adapter_resolves_the_same_independent_expected_effect(adapter_name, case_id):
    case = corpus.CASES_BY_ID[case_id]
    outcome = DRIVERS[adapter_name](case, _signer())
    assert outcome.verified.effect == corpus.expected_effect(case)


@pytest.mark.parametrize("adapter_name", sorted(DRIVERS.keys()))
@pytest.mark.parametrize("case_id", [c.case_id for c in corpus.CASES if not c.force_core_failure])
def test_every_adapter_produces_the_identical_k0_body_wrapper_structure(adapter_name, case_id):
    """K4's byte-identical-BODY claim, precisely scoped: the STRUCTURE K0's `build_body` wraps
    every adapter's opaque payload in -- a single-field CBOR map, key literal 1, a bstr value --
    is identical across K1/K2/K3 for every case. The opaque payload BYTES inside that field are
    framework-native by design and are NOT asserted identical here (that is the legitimate
    "framework-specific wrapping" this corpus does not require to match)."""
    case = corpus.CASES_BY_ID[case_id]
    outcome = DRIVERS[adapter_name](case, _signer())
    body = outcome.verified.body
    assert isinstance(body, cbor.M)
    assert len(body.pairs) == 1
    (key, value) = body.pairs[0]
    assert isinstance(key, cbor.U) and key.v == 1
    assert isinstance(value, cbor.B)
    assert isinstance(value.v, (bytes, bytearray)) and len(value.v) > 0


# --- K4-3: fail-closed cases, first-class corpus entries ----------------------------------------

@pytest.mark.parametrize("adapter_name", sorted(DRIVERS.keys()))
def test_every_adapter_denies_the_same_way_when_effect_exceeds_the_grant_ceiling(adapter_name):
    case = corpus.CASES_BY_ID["gated_deny_uncovered_destructive"]
    outcome = DRIVERS[adapter_name](case, _signer())
    assert outcome.core_error is None
    assert corpus.expected_denied(case) is True
    assert outcome.adapter_denied is True  # the adapter's OWN observable surface agrees
    assert outcome.adapter_denial_kind == "EffectNotAuthorized"
    # the action is STILL captured+signed before the deny decision in every adapter (K1-5's
    # "a denial is still a provenance-worthy captured action") -- never silently dropped:
    assert outcome.verified is not None
    assert outcome.verified.effect == corpus.expected_effect(case)


@pytest.mark.parametrize("adapter_name", sorted(DRIVERS.keys()))
def test_every_adapter_denies_the_fail_closed_default_under_a_read_only_ceiling(adapter_name):
    case = corpus.CASES_BY_ID["gated_deny_fail_closed_default_under_read_only_ceiling"]
    outcome = DRIVERS[adapter_name](case, _signer())
    assert corpus.expected_effect(case) == policy.DESTRUCTIVE  # the fail-closed default itself
    assert corpus.expected_denied(case) is True
    assert outcome.adapter_denied is True
    assert outcome.adapter_denial_kind == "EffectNotAuthorized"


@pytest.mark.parametrize("adapter_name", sorted(DRIVERS.keys()))
def test_every_adapter_allows_when_effect_is_within_the_grant_ceiling(adapter_name):
    case = corpus.CASES_BY_ID["gated_allow_covered_write"]
    outcome = DRIVERS[adapter_name](case, _signer())
    assert corpus.expected_denied(case) is False
    assert outcome.adapter_denied is False  # the fail-open CONTRAST: gating is not always-deny
    assert outcome.verified is not None
    assert outcome.verified.effect == corpus.expected_effect(case)


@pytest.mark.parametrize("adapter_name", sorted(DRIVERS.keys()))
def test_every_adapter_surfaces_the_same_named_error_on_a_forced_core_sign_failure(adapter_name):
    case = corpus.CASES_BY_ID["core_sign_failure"]
    outcome = DRIVERS[adapter_name](case, _signer())
    assert outcome.verified is None  # never unsigned-as-signed (K0-5)
    assert outcome.core_error is not None
    assert getattr(outcome.core_error, "kind", None) == "E_SIGN_FAILED"
    assert type(outcome.core_error) is binding_module().SignFailed


def binding_module():
    from naalp_kit import binding
    return binding


def test_k0_direct_unknown_channel_kind_is_rejected_fail_closed():
    """The one K4-3 fail-closed entry no adapter can drive through its own public surface (S-1:
    every adapter hardcodes CHANNEL_BRIDGE/KIND_CARRIAGE) -- exercised directly against K0, the
    shared framework-neutral layer, and honestly named as such rather than silently omitted."""
    from naalp import channels as _channels
    err = harness.run_k0_unknown_kind(_signer())
    assert isinstance(err, _channels.UnknownKind)


# --- causal chaining: identical behavior across all three adapters' ChainRecorders -------------

def test_causal_chaining_behaves_identically_across_all_three_adapters():
    signer = _signer(0x60)
    k1_first, k1_second = harness.run_k1_chain(signer)
    k2_first, k2_second = harness.run_k2_chain(signer)
    k3_first, k3_second = harness.run_k3_chain(signer)
    for first, second, adapter_name in (
        (k1_first, k1_second, "K1-ADK"), (k2_first, k2_second, "K2-A2A"), (k3_first, k3_second, "K3-MCP"),
    ):
        assert first.causes == [], "%s: the first captured action in a fresh session must not chain" % adapter_name
        assert second.causes == [first.id], (
            "%s: the second captured action must chain to the first's REAL content id" % adapter_name
        )
        assert first.channel == corpus.CHANNEL_BRIDGE and first.kind == corpus.KIND_CARRIAGE
        assert second.channel == corpus.CHANNEL_BRIDGE and second.kind == corpus.KIND_CARRIAGE
