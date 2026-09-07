# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
The reconcile step for N-AALP multi-agent parallel fan-out (Part-2 ecosystem task E1.3,
requirement R2.3): converge a set of independently-signed, causally-linked N-AALP objects
produced by MULTIPLE agents into one deterministic total order.

This module performs NO topological sort, NO cycle detection, and NO tie-break logic of its
own: `reconcile_nodes` is a direct, undecorated call to the real Part-1 tier-1 federated-
ordering primitive `naalp.federation.reconcile` (design.md Sec.8.4; design-channels.md Sec.7)
-- the SAME deterministic linearization (Kahn's algorithm over the union causal DAG, ties
broken by content id, bytewise ascending) every ordering authority in the protocol already
uses to merge multiple scopes/authorities into one order (R-8.6: "any split of the same
objects reconciles to the same order"). `naalp_multiagent`'s N parallel agents ARE exactly
that federation.py docstring's "multiple independent authorities": this module supplies no
second reconciliation algorithm, only a thin, directly-callable entry point plus the
`CausalNode` type callers use to build the graph `naalp.federation.reconcile` expects.

A cyclic or otherwise inconsistent causal graph is rejected by `naalp.graph.verify_causal`
(invoked internally by `federation.reconcile`) with the registered `CausalViolation` error
(`naalp.naalperror.NAMES`) -- propagated here UNCHANGED, never renamed or wrapped, because it
is already the correct, registered semantic name for "this causal input is not a valid
partial order" (the same reuse-not-reinvent convention the sibling `naalp_react.bridge`
follows for `WrongAudience`/`CausalViolation`: a Part-1 registered error is never given a
second, competing name at the ecosystem layer).
"""
from . import _bootstrap  # noqa: F401  (side-effecting import: puts naalp_plan + naalp_react + impl/python on sys.path)

from naalp import federation
from naalp.federation import CausalNode  # noqa: F401  (re-exported for callers building a graph)

__all__ = ["CausalNode", "reconcile_nodes"]


def reconcile_nodes(nodes):
    """Deterministically linearize the union causal DAG over `nodes` (an iterable of
    `naalp.federation.CausalNode`, each an object's content id plus the content ids it
    causally depends on) via the real Part-1 reconcile primitive. Returns a tuple of content
    ids (bytes) in the deterministic total order -- the shared root(s) before their
    dependents, ties among causally-concurrent objects broken bytewise-ascending by content
    id. Raises `naalp.graph.CausalViolation` (propagated from `naalp.federation.reconcile` /
    `naalp.graph.verify_causal`) if `nodes` is not a valid partial order -- a cycle, including
    a node that names itself (directly or transitively) among its own causes -- fail-closed,
    before any order is ever produced."""
    return tuple(federation.reconcile(list(nodes)))
