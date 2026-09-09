# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Repo-relative sys.path setup so naalp_crewai can import the K0 framework-neutral core
binding (`naalp_kit`, repo root), transitively through it the Part-1 Python SDK (impl/python's
`naalp` package), and the G2 durable HITL package (`naalp_hitl`, ecosystem/naalp-hitl) -- design
principle: "wrap-not-replace" (the N-AALP Governance Kit design). This package adds no
cryptography, encoding, registry, or ledger logic of its own; it is a thin CrewAI-specific
translation over K0 + naalp_hitl.durable, mirroring naalp_kit/_bootstrap.py's,
naalp_adk_plugin/_bootstrap.py's, and naalp_langgraph/_bootstrap.py's convention.

Importing this module is a side effect only (it does not export anything); every other module
in this package imports it first, before importing anything from `naalp_kit`, `naalp_hitl`, or
`naalp`.
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
# naalp_crewai/ -> naalp-crewai/ -> ecosystem/ -> naalp_draft-01/ (repo root)
_REPO_ROOT = os.path.normpath(os.path.join(_THIS_DIR, "..", "..", ".."))
_IMPL_PYTHON = os.path.normpath(os.path.join(_REPO_ROOT, "impl", "python"))
_NAALP_HITL_PKG_DIR = os.path.normpath(os.path.join(_REPO_ROOT, "ecosystem", "naalp-hitl"))
for _p in (_REPO_ROOT, _IMPL_PYTHON, _NAALP_HITL_PKG_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)
