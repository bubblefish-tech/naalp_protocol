# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
K4 -- the N-AALP Governance Kit's framework-neutral portability corpus
(the N-AALP Governance Kit design).

A `GovernanceCase` is a LOGICAL governance action (a tool name + arguments + a caller-declared
C5 effect + an optional authorization grant), expressed with NO framework vocabulary at all.
`naalp_governance_portability.harness` drives each case through K1 (ADK), K2 (A2A), and K3
(MCP) using each framework's own real stimulus shape, then asserts every adapter's real,
independently-verified output agrees with this module's `expected_effect()` / `expected_denied()`
-- the corpus's own oracle functions, which are never derived from any adapter's output (F3,
non-circular): they call K0's own documented, already-graded functions
(`naalp_kit.binding.resolve_effect`, `naalp_kit.binding.authorize_action` against an
independently-reconstructed `VerifiedAction`) and the real, frozen channel registry
(`naalp.channels.TABLE`) directly -- the SAME shared infrastructure every adapter calls, but
never one adapter's own emitted bytes used to grade a sibling adapter.

K4-1/K4-2 (portability, byte-identical BODY *structure*): every K1/K2/K3 adapter signs its
captured action through K0's `build_body()`, which wraps the framework-native payload VERBATIM
and opaquely as a single-field CBOR map `{1: bstr}` (binding.py's `_PAYLOAD_FIELD`). The
framework-native payload bytes themselves are NOT expected to be byte-identical across
frameworks (a JSON tool-call dict and a protobuf A2A message are different wire shapes by
design -- "the framework-specific wrapping differs" per the K4 task brief); what MUST be
byte-identical across every adapter, for the SAME logical case, is the GOVERNANCE-RELEVANT
structure K0 actually signs: the (channel, kind) pair, the resolved effect, the body's
single-field wrapper shape, and the verification/authorization RESULT. This module's
`STRUCTURAL_ORACLE` names exactly that claim; `harness.py`'s assertions enforce it per case per
adapter.

K4-3 (fail-closed corpus entries, first-class): `CASES` includes an absent-effect case
(fail-closed default), a gated-deny case (uncovered effect), a gated-allow case (covered
effect, the fail-open contrast that proves gating is not merely "always deny"), and a forced
core-sign-failure case. `UNKNOWN_KIND_CASE` is the one entry that cannot be driven through any
of K1/K2/K3's own public surface (every adapter hardcodes the Bridge/Carriage (channel, kind)
pair per S-1 -- none exposes a caller-controlled channel/kind) and is therefore exercised
directly against K0, honestly documented as K0-direct rather than silently omitted.
"""
from dataclasses import dataclass
from typing import Optional

from . import _bootstrap  # noqa: F401

from naalp_kit import binding
from naalp import channels, policy

# The ONE (channel, kind) surface every K1/K2/K3 adapter signs its captured, framework-neutral
# actions under (design.md sec.13; naalp.channels.TABLE[0x000D] == ('Bridge',
# [(0, 'Carriage', READ_ONLY, True)])) -- the generic foreign-carriage surface, variable effect.
CHANNEL_BRIDGE = 0x000D
KIND_CARRIAGE = 0

_NAME, _DECLARED_EFFECT, _VARIABLE = channels.lookup(CHANNEL_BRIDGE, KIND_CARRIAGE)
if not _VARIABLE:
    # K4's independent oracle assumes Bridge/Carriage stays variable-effect (K0-3's fail-closed
    # DESTRUCTIVE default only applies to a variable-effect kind); if the frozen registry ever
    # changes this, the corpus's assumption breaks LOUDLY at import time rather than silently
    # grading the wrong default.
    raise AssertionError(
        "K4 corpus assumption broken: naalp.channels.TABLE[0x000D] Carriage kind is no longer "
        "variable-effect -- update corpus.py's fail-closed-default expectations before using it"
    )


@dataclass(frozen=True)
class GovernanceCase:
    """One framework-neutral logical governance action. `tool_name`/`args` describe the action
    in vocabulary every K1/K2/K3 harness driver translates into its OWN framework's real
    stimulus (an ADK tool call, an A2A message, an MCP tool call) -- never a shared payload
    encoding, because the payload encoding IS framework-native by design (K4's portability claim
    is about the signed GOVERNANCE content, not about forcing three different wire formats to
    produce the same bytes)."""

    case_id: str
    description: str
    tool_name: str
    args: dict
    declared_effect: Optional[int]            # None => K0-3's fail-closed default applies
    grant_max_effect: Optional[int] = None     # None => this case is observe-only (no gating)
    expect_denied: Optional[bool] = None       # meaningful only when grant_max_effect is set
    force_core_failure: bool = False


def expected_effect(case: "GovernanceCase") -> int:
    """K4's independent (F3) oracle for a case's expected signed effect: K0's own documented,
    already-graded `resolve_effect`, called directly against the real frozen registry -- never
    read back out of any adapter's emitted object. Every one of K1/K2/K3 delegates to this exact
    function internally; using it as ground truth here measures whether an adapter reached K0
    with the RIGHT declared_effect input for a given case, not whether K0 itself resolves
    correctly (K0 is graded independently in naalp_kit/tests/test_binding.py)."""
    return binding.resolve_effect(CHANNEL_BRIDGE, KIND_CARRIAGE, case.declared_effect)


def expected_denied(case: "GovernanceCase") -> bool:
    """K4's independent (F3) oracle for whether a gated case's action should be denied:
    re-derives the authorization outcome directly from `naalp.policy.authorizes` against the
    case's own `expected_effect()` and `grant_max_effect` -- the same real closed-lattice
    comparison `naalp.policy.Grant.authorize_object` performs, computed here from the corpus's
    OWN declared inputs, never read back out of any adapter's returned denial dict/exception/
    result shape."""
    if case.grant_max_effect is None:
        raise ValueError("expected_denied() is only meaningful for a gated case (grant_max_effect set)")
    return not policy.authorizes(case.grant_max_effect, policy.normalize_effect(expected_effect(case)))


CASES = [
    GovernanceCase(
        case_id="observe_explicit_read_only",
        description="An explicitly classified read-only action, observe-only mode (no grant).",
        tool_name="read_file",
        args={"path": "/etc/hosts"},
        declared_effect=policy.READ_ONLY,
    ),
    GovernanceCase(
        case_id="observe_fail_closed_default",
        description=(
            "An UNCLASSIFIED action (no effect_classifier result) -- K0-3's fail-closed default "
            "(the most severe class, never a guessed benign one) must apply identically in "
            "every adapter."
        ),
        tool_name="unclassified_action",
        args={},
        declared_effect=None,
    ),
    GovernanceCase(
        case_id="gated_deny_uncovered_destructive",
        description="A destructive action against a read-only-ceiling grant -- must be denied in every adapter.",
        tool_name="delete_everything",
        args={"target": "*"},
        declared_effect=policy.DESTRUCTIVE,
        grant_max_effect=policy.READ_ONLY,
        expect_denied=True,
    ),
    GovernanceCase(
        case_id="gated_allow_covered_write",
        description=(
            "An idempotent-write action within a non-idempotent-write ceiling -- must be "
            "ALLOWED in every adapter (the fail-open contrast: gating is not merely a blanket "
            "always-deny)."
        ),
        tool_name="upsert_row",
        args={"id": 7},
        declared_effect=policy.IDEMPOTENT_WRITE,
        grant_max_effect=policy.NON_IDEMPOTENT_WRITE,
        expect_denied=False,
    ),
    GovernanceCase(
        case_id="gated_deny_fail_closed_default_under_read_only_ceiling",
        description=(
            "An UNCLASSIFIED action under a read-only-ceiling grant -- the fail-closed "
            "DESTRUCTIVE default must exceed the ceiling and be denied in every adapter."
        ),
        tool_name="unspecified_effect_tool",
        args={},
        declared_effect=None,
        grant_max_effect=policy.READ_ONLY,
        expect_denied=True,
    ),
    GovernanceCase(
        case_id="core_sign_failure",
        description=(
            "A forced core-signer failure (K0-5, K4-3) -- must surface as the SAME named error "
            "(E_SIGN_FAILED) in every adapter, never an unsigned-as-signed result."
        ),
        tool_name="anything",
        args={},
        declared_effect=policy.READ_ONLY,
        force_core_failure=True,
    ),
]

CASES_BY_ID = {c.case_id: c for c in CASES}

# K4-3's one K0-direct-only fail-closed entry: none of K1/K2/K3 exposes a caller-controlled
# channel/kind (S-1: every adapter hardcodes CHANNEL_BRIDGE/KIND_CARRIAGE), so "an unknown
# (channel, kind)" cannot be driven through any adapter's own public surface. Documented here
# rather than silently omitted from the corpus.
UNKNOWN_CHANNEL = 0x1234
UNKNOWN_KIND = 99
UNKNOWN_KIND_CASE_ID = "unknown_channel_kind_k0_direct"


__all__ = [
    "CHANNEL_BRIDGE", "KIND_CARRIAGE",
    "GovernanceCase", "CASES", "CASES_BY_ID",
    "expected_effect", "expected_denied",
    "UNKNOWN_CHANNEL", "UNKNOWN_KIND", "UNKNOWN_KIND_CASE_ID",
]
