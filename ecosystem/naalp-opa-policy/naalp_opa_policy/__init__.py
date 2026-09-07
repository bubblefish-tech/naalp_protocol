# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_opa_policy -- the N-AALP OPA/Rego policy-enforcement integration (Part-2 ecosystem
task E3.2, requirement R5.2).

Lets an administrator write a Rego policy inspecting an N-AALP object's authenticated
{effect, audience, kind, signer, channel} plus a caller-resolved {grant}, and REFUSES an
action before it executes if the policy denies -- consulted BEFORE the SDK's own Part-1
authorization floor (naalp.policy.Grant.authorize_object), never as a replacement for it.
See opa_policy.py for the engine wrapper, the input-document mapping, and the fail-closed
integration.
"""
from .opa_policy import (
    DEFAULT_POLICY_DIR,
    DEFAULT_QUERY,
    OPAEngine,
    OPAEngineError,
    authorize_with_policy,
    build_input,
)

__all__ = [
    "DEFAULT_POLICY_DIR",
    "DEFAULT_QUERY",
    "OPAEngine",
    "OPAEngineError",
    "authorize_with_policy",
    "build_input",
]

__version__ = "0.1.0"
