# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Repo-relative sys.path setup so naalp_governance_portability can import K0
(`naalp_kit`, repo root), the three real K1/K2/K3 adapter packages it drives (their own
hyphenated directory names -- `ecosystem/naalp-adk-plugin`, `ecosystem/naalp-a2a-hook`,
`ecosystem/naalp-mcp-hook` -- cannot themselves be dotted import paths, so each one's own
directory must be on sys.path for its underscore package to import), and, transitively through
K0, the Part-1 Python SDK (impl/python's `naalp` package).

This package adds no cryptography, encoding, channel-registry, or adapter logic of its own; it
consumes K0 and K1/K2/K3 strictly READ-ONLY (it never imports anything FROM them that mutates
their own modules) to build the K4 portability conformance corpus + harness
(the N-AALP Governance Kit design).

Importing this module is a side effect only (it does not export anything); every other module in
this package imports it first, before importing anything from `naalp_kit`, `naalp`, or an
adapter package.
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
# naalp_governance_portability/ -> naalp-governance-portability/ -> ecosystem/ -> naalp_draft-01/ (repo root)
_ECOSYSTEM = os.path.normpath(os.path.join(_THIS_DIR, "..", ".."))
_REPO_ROOT = os.path.normpath(os.path.join(_ECOSYSTEM, ".."))
_IMPL_PYTHON = os.path.normpath(os.path.join(_REPO_ROOT, "impl", "python"))
_K1_DIR = os.path.join(_ECOSYSTEM, "naalp-adk-plugin")
_K2_DIR = os.path.join(_ECOSYSTEM, "naalp-a2a-hook")
_K3_DIR = os.path.join(_ECOSYSTEM, "naalp-mcp-hook")
for _p in (_REPO_ROOT, _IMPL_PYTHON, _K1_DIR, _K2_DIR, _K3_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)
