# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Repo-relative import bootstrap for the N-AALP multi-agent interaction shapes package.

This package builds ON the sibling `ecosystem/naalp-react` ReAct bridge (E1.1/R2.1) for
every per-stage/per-branch sign/verify operation it performs (`pipeline.py`, `fanout.py`),
and directly on the Part-1 reference SDK (`impl/python/naalp`) for the deterministic
reconcile primitive (`reconcile.py`'s `naalp.federation.reconcile`) -- it defines no second
object encoding, no second reconciliation algorithm, and performs no cryptography of its own
(design.md "Buy-before-make").

See `pipeline.py`'s module docstring for WHY this package calls `naalp_react.ReActBridge`
directly rather than routing through the sibling `naalp_plan.PlanOrchestrator` (E1.2): that
orchestrator's own causal-edge wiring is scoped to ITS OWN task prereqs within one DAG run
under one bridge, and has no way to accept an externally-supplied predecessor content id from
a prior, independently-run stage under a DIFFERENT bridge -- exactly the shape a cross-agent
chain or fan-out requires. `naalp_multiagent` therefore sits at the SAME layer as
`naalp_plan` (both build directly on `naalp_react`), not on top of it.

Neither `naalp_react` nor `naalp` (impl/python) is installed (no `pip install -e`) in this
checkout, so this module locates BOTH by walking upward from this file -- never an absolute
path -- and inserts each onto `sys.path` exactly once, before anything imports them. This
mirrors the identical dual-ensure convention `naalp_react/_bootstrap.py` itself uses for
`impl/python` + `ecosystem/naalp-codec` (rather than relying on a transitive import cascade
that would only fire if some OTHER module happened to import `naalp_react` first).
"""
import os
import sys


class NaalpMultiagentSdkNotFound(RuntimeError):
    """Raised when a required sibling/Part-1 package cannot be located by walking upward
    from this file. Fail loud rather than silently importing nothing."""


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


def ensure_naalp_react_on_path():
    """Idempotent: insert `ecosystem/naalp-react` (the directory containing the
    `naalp_react` package) onto sys.path[0] if not already present, and return the resolved
    path. Raises NaalpMultiagentSdkNotFound if it cannot be located."""
    here = os.path.dirname(os.path.abspath(__file__))
    react_dir = _find_naalp_react_dir(here)
    if react_dir is None:
        raise NaalpMultiagentSdkNotFound(
            "could not locate ecosystem/naalp-react by walking up from %r; "
            "the naalp-multiagent package must live inside the naalp_draft-01 tree" % here
        )
    if react_dir not in sys.path:
        sys.path.insert(0, react_dir)
    return react_dir


def ensure_naalp_on_path():
    """Idempotent: insert `impl/python` onto sys.path[0] if not already present, and return
    the resolved path. Raises NaalpMultiagentSdkNotFound if it cannot be located."""
    here = os.path.dirname(os.path.abspath(__file__))
    impl_python = _find_impl_python(here)
    if impl_python is None:
        raise NaalpMultiagentSdkNotFound(
            "could not locate impl/python/naalp by walking up from %r; "
            "the naalp-multiagent package must live inside the naalp_draft-01 tree" % here
        )
    if impl_python not in sys.path:
        sys.path.insert(0, impl_python)
    return impl_python


ensure_naalp_react_on_path()
ensure_naalp_on_path()
