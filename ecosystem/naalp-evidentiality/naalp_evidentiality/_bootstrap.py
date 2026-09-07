# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Repo-relative sys.path setup so naalp_evidentiality can import and REUSE the Part-1
Python SDK (impl/python's `naalp` package) instead of re-implementing any cryptography,
identity, or audit-chain logic (design.md "Buy-before-make": evidentiality is N-AALP-specific
glue over the real signature/oracle/authority/recompute primitives, not a second copy of them).

Importing this module is a side effect only (it does not export anything); every other
module in this package imports it first, before importing anything from `naalp`.
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
# naalp_evidentiality/ -> naalp-evidentiality/ -> ecosystem/ -> naalp_draft-01/ -> impl/python
_IMPL_PYTHON = os.path.normpath(os.path.join(_THIS_DIR, "..", "..", "..", "impl", "python"))
if _IMPL_PYTHON not in sys.path:
    sys.path.insert(0, _IMPL_PYTHON)
