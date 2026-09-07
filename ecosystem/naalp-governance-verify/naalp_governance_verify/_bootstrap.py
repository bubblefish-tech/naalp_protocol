# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Repo-relative sys.path setup so naalp_governance_verify can import BOTH the K0 framework-
neutral core binding (`naalp_kit`, repo root) and, transitively through it, the Part-1 Python SDK
(impl/python's `naalp` package) -- design principle: "wrap-not-replace"
(the N-AALP Governance Kit design). This package adds no
cryptography, encoding, or registry logic of its own; it is a thin, framework-agnostic verifier
over K0's signed-object shape, mirroring naalp_kit/_bootstrap.py's and
ecosystem/naalp-mcp-hook/naalp_mcp_hook/_bootstrap.py's convention.

Importing this module is a side effect only (it does not export anything); every other module in
this package imports it first, before importing anything from `naalp_kit` or `naalp`.
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
# naalp_governance_verify/ -> naalp-governance-verify/ -> ecosystem/ -> naalp_draft-01/ (repo root)
_REPO_ROOT = os.path.normpath(os.path.join(_THIS_DIR, "..", "..", ".."))
_IMPL_PYTHON = os.path.normpath(os.path.join(_REPO_ROOT, "impl", "python"))
for _p in (_REPO_ROOT, _IMPL_PYTHON):
    if _p not in sys.path:
        sys.path.insert(0, _p)
