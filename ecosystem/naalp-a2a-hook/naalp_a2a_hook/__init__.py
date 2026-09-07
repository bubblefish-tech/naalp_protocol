# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_a2a_hook -- the N-AALP Governance Kit's K2 framework-hook adapter for the A2A
(Agent2Agent) protocol. See a2a_hook.py for the module docstring and
the N-AALP Governance Kit design for the
deliverable this implements. COEXISTS with, and never modifies, `ecosystem/naalp-a2a-bridge`
(the pre-existing explicit-call SDK library that bridges A2A Agent Card + TaskState semantics
specifically) -- K2 is the opaque, automatic, framework-hook counterpart K2-1/K2-2 require."""
from .a2a_hook import (  # noqa: F401
    NaalpA2AClientInterceptor,
    NaalpA2ARequestHandler,
    ChainRecorder,
    CHANNEL_BRIDGE,
    KIND_CARRIAGE,
    canonical_proto_bytes,
)

__all__ = [
    "NaalpA2AClientInterceptor", "NaalpA2ARequestHandler", "ChainRecorder",
    "CHANNEL_BRIDGE", "KIND_CARRIAGE", "canonical_proto_bytes",
]
