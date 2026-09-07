# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Repo-relative import bootstrap for the N-AALP Plan-and-Execute orchestrator.

This package builds ON the sibling `ecosystem/naalp-react` ReAct bridge (E1.1/R2.1) for
every per-node sign/verify operation it performs -- it defines no second signing path and
performs no cryptography or CBOR encoding of its own (E1.2/R2.2: "reuse the ReAct bridge's
action_to_request / response_to_observation for the per-node sign/verify"). `naalp_react`
is not installed (no `pip install -e`) in this checkout, so this module locates
`ecosystem/naalp-react` by walking upward from this file -- never an absolute path -- and
inserts it onto `sys.path` exactly once, before anything imports `naalp_react`.

Importing `naalp_react` then runs ITS OWN `_bootstrap.py` as a side effect (it puts
`impl/python` and `ecosystem/naalp-codec` on `sys.path` in turn), so this module does not
duplicate that walk -- it only needs to find `naalp_react` itself; everything naalp_react
depends on rides in for free the moment it is imported.

The walk looks for a directory that contains `naalp_react/__init__.py`; this mirrors the
identical upward-walk convention used by `naalp_react/_bootstrap.py`,
`naalp_codec/_bootstrap.py`, `naalp_validator/_bootstrap.py`, and `naalp_hitl/_bootstrap.py`.
"""
import os
import sys


class NaalpPlanSdkNotFound(RuntimeError):
    """Raised when the sibling `ecosystem/naalp-react` package cannot be located by walking
    upward from this file. Fail loud rather than silently importing nothing."""


def _find_naalp_react_dir(start):
    d = os.path.abspath(start)
    for _ in range(8):
        candidate = os.path.join(d, "ecosystem", "naalp-react")
        marker = os.path.join(candidate, "naalp_react", "__init__.py")
        if os.path.isfile(marker):
            return candidate
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def ensure_naalp_react_on_path():
    """Idempotent: insert `ecosystem/naalp-react` (the directory containing the
    `naalp_react` package) onto sys.path[0] if not already present, and return the resolved
    path. Raises NaalpPlanSdkNotFound if it cannot be located."""
    here = os.path.dirname(os.path.abspath(__file__))
    react_dir = _find_naalp_react_dir(here)
    if react_dir is None:
        raise NaalpPlanSdkNotFound(
            "could not locate ecosystem/naalp-react by walking up from %r; "
            "the naalp-plan package must live inside the naalp_draft-01 tree" % here
        )
    if react_dir not in sys.path:
        sys.path.insert(0, react_dir)
    return react_dir


ensure_naalp_react_on_path()
