# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_mcp_hook -- the N-AALP Governance Kit's K3 framework-hook adapter for the Model Context
Protocol (MCP). See mcp_hook.py for the module docstring and
the N-AALP Governance Kit design for the
deliverable this implements. COEXISTS with, and never modifies, `ecosystem/naalp-mcp-bridge`
(the pre-existing explicit-call SDK library that DECODES annotations for the NAALP-MCP wire
profile) -- K3 is the opaque, automatic, framework-hook counterpart K3-1 requires."""
from .mcp_hook import (  # noqa: F401
    NaalpGovernedClientSession,
    ChainRecorder,
    EffectClassifier,
    CHANNEL_BRIDGE,
    KIND_CARRIAGE,
    canonical_json_bytes,
    annotations_content_id,
    record_server_tool_call,
)

__all__ = [
    "NaalpGovernedClientSession", "ChainRecorder", "EffectClassifier",
    "CHANNEL_BRIDGE", "KIND_CARRIAGE",
    "canonical_json_bytes", "annotations_content_id", "record_server_tool_call",
]
