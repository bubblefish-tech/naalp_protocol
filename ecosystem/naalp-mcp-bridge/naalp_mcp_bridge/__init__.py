# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_mcp_bridge -- the N-AALP MCP tool-integration bridge (Part-2 ecosystem task E2.1,
requirement R4.1/4.2/4.3; design.md Sec.19 "The NAALP-MCP binding profile").

Maps a foreign-native MCP tool call (a tool definition + a JSON-RPC 2.0 tools/call request,
straight from a developer's MCP stack) into a signed N-AALP McpToolCall object, and back --
octet-exact, with the profile's signed effect claim, more-severe resolution, and per-call
approval binding enforced throughout. See mcp_bridge.py for the carry/receive machinery."""
from .mcp_bridge import (
    BridgeError,
    CarriedCall,
    BridgedCall,
    annotations_from_mcp_dict,
    canonical_json_bytes,
    carry_tool_call,
    carry_tool_call_from_objects,
    receive_tool_call,
    bridged_call_request,
)

__all__ = [
    "BridgeError",
    "CarriedCall",
    "BridgedCall",
    "annotations_from_mcp_dict",
    "canonical_json_bytes",
    "carry_tool_call",
    "carry_tool_call_from_objects",
    "receive_tool_call",
    "bridged_call_request",
]

__version__ = "0.1.0"
