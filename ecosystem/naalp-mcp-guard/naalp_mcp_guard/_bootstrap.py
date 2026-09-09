# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Repo-relative sys.path setup so naalp_mcp_guard can import and REUSE (design.md "Buy-before-
make"): the real Part-1 Python SDK (impl/python's `naalp` package), the already-built
`naalp_mcp_bridge` package (Family-1 checks + the annotation->effect mapping + the signed
McpToolCall wire object), and the already-built `naalp_hitl` package (the pause/human-approval/
D6-audit interceptor). This module adds no cryptography, ledger, or approval logic of its own --
`naalp-mcp-guard` is packaging glue over these three, exactly as design.md Sec.2.7 specifies.

Importing this module is a side effect only (it does not export anything); every other module in
this package imports it first, before importing anything from `naalp`, `naalp_mcp_bridge`, or
`naalp_hitl`. Every path here is computed at runtime relative to this file's own location -- no
absolute path is ever written into a committed file (bubblefish-lessons [abs-path-leak])."""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)            # ecosystem/naalp-mcp-guard
_ECOSYSTEM = os.path.dirname(_PKG_ROOT)           # ecosystem/
_REPO_ROOT = os.path.dirname(_ECOSYSTEM)          # naalp_draft-01/
_IMPL_PYTHON = os.path.normpath(os.path.join(_REPO_ROOT, "impl", "python"))
_MCP_BRIDGE_PKG = os.path.normpath(os.path.join(_ECOSYSTEM, "naalp-mcp-bridge"))
_HITL_PKG = os.path.normpath(os.path.join(_ECOSYSTEM, "naalp-hitl"))

for _p in (_IMPL_PYTHON, _MCP_BRIDGE_PKG, _HITL_PKG):
    if _p not in sys.path:
        sys.path.insert(0, _p)
