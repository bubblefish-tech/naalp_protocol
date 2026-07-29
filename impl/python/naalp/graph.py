# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP causal graph (C7, §8.2-§8.3) and federation reconcile (T13, §8.6) for the Python SDK.

verify_causal enforces no-future-cause (a present cause may not sit at a later position than its
effect) and acyclicity. reconcile is the deterministic merge: a topological linearization of the
union causal DAG, ties broken by content id (bytewise), scope-independent (R-8.6).
"""
from . import cbor
from .cbor import A, B, T


class CausalViolation(ValueError):
    kind = "CausalViolation"


def verify_causal(nodes):
    """nodes: list of (id: bytes, causes: list[bytes], position: int)."""
    idx = {bytes(nid): i for i, (nid, _causes, _pos) in enumerate(nodes)}
    # no future cause
    for nid, causes, pos in nodes:
        for c in causes:
            j = idx.get(bytes(c))
            if j is not None and nodes[j][2] > pos:
                raise CausalViolation("cause at a later position than its effect")
    # acyclic (3-colour DFS over effect -> cause edges)
    WHITE, GRAY, BLACK = 0, 1, 2
    color = [WHITE] * len(nodes)

    def has_cycle(i):
        color[i] = GRAY
        for c in nodes[i][1]:
            j = idx.get(bytes(c))
            if j is None:
                continue
            if color[j] == GRAY:
                return True
            if color[j] == WHITE and has_cycle(j):
                return True
        color[i] = BLACK
        return False

    for i in range(len(nodes)):
        if color[i] == WHITE and has_cycle(i):
            raise CausalViolation("causal graph contains a cycle")


def reconcile(nodes):
    """Deterministic topological merge over the union causal DAG; ties break by content id."""
    verify_causal(nodes)
    ids = [bytes(nid) for nid, _c, _p in nodes]
    present = set(ids)
    causes = [[bytes(c) for c in cs if bytes(c) in present] for _nid, cs, _p in nodes]
    indeg = [len(cs) for cs in causes]
    done = [False] * len(nodes)
    order = []
    while len(order) < len(nodes):
        pick = -1
        for i in range(len(nodes)):
            if done[i] or indeg[i] != 0:
                continue
            if pick == -1 or ids[i] < ids[pick]:
                pick = i
        if pick == -1:
            raise CausalViolation("no ready node (unreachable after verify_causal)")
        done[pick] = True
        order.append(ids[pick])
        for j in range(len(nodes)):
            if not done[j] and ids[pick] in causes[j]:
                indeg[j] -= 1
    return order


def reconcile_record(authorities, order) -> bytes:
    """The tier-1 Reconcile body {1: [authorities], 2: [order content-ids]}."""
    auth = A([T(a) for a in authorities])
    ordr = A([B(o) for o in order])
    return cbor.encode(cbor.M([(cbor.U(1), auth), (cbor.U(2), ordr)]))
