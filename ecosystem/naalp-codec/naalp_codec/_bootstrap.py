# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Repo-relative import bootstrap for the deterministic-CBOR codec binding.

This package REUSES the Part-1 Python reference SDK (`impl/python/naalp`) rather than
reimplementing the CBOR codec (the repository's non-negotiable discipline: no second
object encoding, no duplicated wire truth). The `naalp` package is not installed (no
`pip install -e`) in this checkout, so this module locates `impl/python` by walking
upward from this file -- never an absolute path -- and inserts it onto `sys.path` exactly
once, before anything imports `naalp`.

The walk looks for a directory that contains `impl/python/naalp/__init__.py`; this is
robust to the exact nesting depth of `ecosystem/naalp-codec/` and mirrors the existing
`ensure_naalp_on_path()` convention used by `ecosystem/naalp-validator/naalp_validator/_bootstrap.py`
and the upward-walk convention used by `impl/python/tests/test_audience.py`.
"""
import os
import sys


class NaalpSdkNotFound(RuntimeError):
    """Raised when the Part-1 `impl/python/naalp` package cannot be located by walking
    upward from this file. Fail loud rather than silently importing nothing."""


def _find_impl_python(start):
    d = os.path.abspath(start)
    for _ in range(8):
        candidate = os.path.join(d, "impl", "python")
        marker = os.path.join(candidate, "naalp", "__init__.py")
        if os.path.isfile(marker):
            return candidate
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def ensure_naalp_on_path():
    """Idempotent: insert `impl/python` onto sys.path[0] if not already present, and
    return the resolved path. Raises NaalpSdkNotFound if it cannot be located."""
    here = os.path.dirname(os.path.abspath(__file__))
    impl_python = _find_impl_python(here)
    if impl_python is None:
        raise NaalpSdkNotFound(
            "could not locate impl/python/naalp by walking up from %r; "
            "the naalp-codec package must live inside the naalp_draft-01 tree" % here
        )
    if impl_python not in sys.path:
        sys.path.insert(0, impl_python)
    return impl_python


ensure_naalp_on_path()
