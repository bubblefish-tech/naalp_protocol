# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Repo-relative import bootstrap for the N-AALP ReAct bridge.

This package REUSES the Part-1 Python reference SDK (`impl/python/naalp`) for every
signing, verification, and encoding primitive it needs -- it defines no second object
encoding and performs no cryptography of its own (design.md "Buy-before-make": the bridge
is N-AALP-specific glue -- Thought->Action->Observation <-> signed-object translation --
not a second copy of the envelope/COSE primitive). The `naalp` package is not installed
(no `pip install -e`) in this checkout, so this module locates `impl/python` by walking
upward from this file -- never an absolute path -- and inserts it onto `sys.path` exactly
once, before anything imports `naalp`.

The walk looks for a directory that contains `impl/python/naalp/__init__.py`; this is
robust to the exact nesting depth of `ecosystem/naalp-react/` and mirrors the identical
convention used by `ecosystem/naalp-codec/naalp_codec/_bootstrap.py` and
`ecosystem/naalp-validator/naalp_validator/_bootstrap.py`.

The bridge ALSO imports (never reimplements) the sibling `naalp_codec` package for every
raw CBOR value-construction / encode / decode / content-id it performs directly (R7's
codec-parity discipline: one blessed encoder, never a second one) -- so this module also
locates `ecosystem/naalp-codec` by the same upward-walk and adds it to `sys.path`.
"""
import os
import sys


class NaalpSdkNotFound(RuntimeError):
    """Raised when the Part-1 `impl/python/naalp` package (or the sibling `naalp_codec`
    package) cannot be located by walking upward from this file. Fail loud rather than
    silently importing nothing."""


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


def _find_naalp_codec_dir(start):
    d = os.path.abspath(start)
    for _ in range(8):
        candidate = os.path.join(d, "ecosystem", "naalp-codec")
        marker = os.path.join(candidate, "naalp_codec", "__init__.py")
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
            "the naalp-react package must live inside the naalp_draft-01 tree" % here
        )
    if impl_python not in sys.path:
        sys.path.insert(0, impl_python)
    return impl_python


def ensure_naalp_codec_on_path():
    """Idempotent: insert `ecosystem/naalp-codec` (the directory containing the
    `naalp_codec` package) onto sys.path[0] if not already present, and return the
    resolved path. Raises NaalpSdkNotFound if it cannot be located."""
    here = os.path.dirname(os.path.abspath(__file__))
    codec_dir = _find_naalp_codec_dir(here)
    if codec_dir is None:
        raise NaalpSdkNotFound(
            "could not locate ecosystem/naalp-codec by walking up from %r; "
            "the naalp-react package must live inside the naalp_draft-01 tree" % here
        )
    if codec_dir not in sys.path:
        sys.path.insert(0, codec_dir)
    return codec_dir


ensure_naalp_on_path()
ensure_naalp_codec_on_path()
