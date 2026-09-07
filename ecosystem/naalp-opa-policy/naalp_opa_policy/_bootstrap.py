# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Repo-relative sys.path setup so naalp_opa_policy can import and REUSE the Part-1 Python SDK
(impl/python's `naalp` package) instead of re-implementing any cryptography, effect lattice,
or object-model logic (design.md "Buy-before-make": this package is a policy-engine
integration, not a second copy of naalp.policy or naalp.envelope).

Importing this module is a side effect only (it does not export anything); every other module
in this package imports it first, before importing anything from `naalp`.
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
# naalp_opa_policy/ -> naalp-opa-policy/ -> ecosystem/ -> naalp_draft-01/ -> impl/python
_IMPL_PYTHON = os.path.normpath(os.path.join(_THIS_DIR, "..", "..", "..", "impl", "python"))
if _IMPL_PYTHON not in sys.path:
    sys.path.insert(0, _IMPL_PYTHON)
