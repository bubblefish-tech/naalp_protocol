# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""K4 -- the N-AALP Governance Kit's portability conformance corpus + harness.

See `naalp_governance_portability.corpus` for the framework-neutral case set and its
independent (F3, non-circular) expected-outcome oracle, and `naalp_governance_portability.harness`
for the per-adapter drivers that exercise K1 (ADK), K2 (A2A), and K3 (MCP) against each case.
"""
from . import _bootstrap  # noqa: F401
