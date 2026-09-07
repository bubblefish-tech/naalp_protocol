# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""N-AALP Federation higher tier (tier 1) for the Python SDK -- federated ordering by a
deterministic reconcile-merge over the shared causal graph (design.md §8.4; design-channels.md §7;
R-8.6, R-15A.2, R-15A.3).

The baseline tier is a single ordering authority's monotonic receipt chain (C7). The higher tier
lets multiple independent authorities each order their own scope and reconcile over the shared
causal graph -- the partial order every authority already signs over (§8.2). Reconcile is a
DETERMINISTIC linearization of the union causal DAG: a topological sort whose tie-break among
causally-concurrent objects is the object content id (bytewise ascending). Because it depends only
on the causal graph (not on how scopes are split), any split of the same objects reconciles to the
same order -- so moving from single-authority to federated ordering requires no envelope or object
change (R-8.6).

Ported from impl/go/federation; the causal partial order is checked by the shared naalp.graph
(the C7/audit foundation), exactly as the reference reuses the audit layer. Graded against the
shared vectors/federation/cases.json.
"""
from dataclasses import dataclass
from typing import List

from . import cbor, cose, graph
from .cbor import U, B, T, A, M


class ReconcileMismatch(ValueError):
    """The verify-event reject of the Reconcile state machine (draft "## Reconcile state machine",
    error code 61): an independent recomputation of the deterministic linearization disagrees with
    the total order a Reconcile record claims, so the record is rejected whole. Raised by
    verify_reconcile_order."""

    kind = "ReconcileMismatch"


@dataclass(frozen=True)
class CausalNode:
    """A node's place in the shared causal graph: its content id and the content ids of its causes
    (envelope field 8). The federated tier reconciles by these causal edges and the content-id
    tie-break."""

    id: bytes
    causes: list


def reconcile(nodes):
    """Reconcile deterministically merges the objects of a shared causal graph into one total order
    (design.md §8.4). It first verifies the graph is a valid partial order (acyclic, no
    future-cause) via the shared naalp.graph, then linearizes it with Kahn's algorithm, breaking
    ties among ready nodes by content id (bytewise ascending). The result is causally consistent and
    deterministic. A duplicate object id (scope overlap) is ordered once (resolved)."""
    graph.verify_causal([(n.id, list(n.causes), 0) for n in nodes])
    ids = [bytes(n.id) for n in nodes]
    present = set(ids)
    causes = [[bytes(c) for c in n.causes if bytes(c) in present] for n in nodes]
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
            # unreachable after verify_causal, but fail-closed rather than loop forever
            raise graph.CausalViolation("no ready node")
        done[pick] = True
        order.append(ids[pick])
        for j in range(len(nodes)):
            if not done[j] and ids[pick] in causes[j]:
                indeg[j] -= 1
    return order


def causally_valid(order, nodes):
    """Reports whether an order places every object's (present) causes before it."""
    pos = {bytes(id_): k for k, id_ in enumerate(order)}
    for n in nodes:
        np_ = pos.get(bytes(n.id))
        if np_ is None:
            continue
        for c in n.causes:
            cp = pos.get(bytes(c))
            if cp is not None and cp > np_:
                return False
    return True


@dataclass(frozen=True)
class ReconcileRecord:
    """The tier-1 Reconcile object body (design-channels.md §7): the authorities reconciled and the
    resulting deterministic total order (object content ids). Signed with the C2 crypto over its
    deterministic-CBOR bytes; it orders the identical signed objects the baseline already produced
    (no envelope change)."""

    authorities: list
    order: list

    def bytes(self):
        """Deterministic-CBOR encoding {1: [authorities], 2: [order content-ids]}."""
        auth = A([T(a) for a in self.authorities])
        ordr = A([B(o) for o in self.order])
        return cbor.encode(M([(U(1), auth), (U(2), ordr)]))


def sign_reconcile(record, alg, seed):
    """Sign a Reconcile record with a tier-1 ordering authority's ML-DSA key: a raw deterministic
    signature over the record's deterministic-CBOR bytes."""
    return cose.mldsa_sign(alg, seed, record.bytes())


def verify_reconcile(record, alg, pubkey, sig):
    """Verify a raw Reconcile-record signature under the authority's public key."""
    return cose.mldsa_verify(alg, pubkey, record.bytes(), sig)


def verify_reconcile_order(record, nodes):
    """The verify-event choke point of the Reconcile state machine (draft "## Reconcile state
    machine"). A verifier independently re-runs the deterministic linearization over the identical
    causal graph and rejects the record whole (ReconcileMismatch) if the recomputed total order
    differs from the one the record claims. It MUST recompute via reconcile() -- the content-id
    tie-break -- and NEVER a position/index tie-break, whose tie-break would spuriously disagree on
    causally-concurrent objects. A node set that is not a valid partial order is rejected under that
    fault (CausalViolation, propagated), fail-closed. Returns None only when the record's claimed
    order is byte-for-byte the deterministic order (verified).

    This is distinct from the per-port signature-verify verify_reconcile(record, alg, pubkey, sig),
    which checks the COSE signature over the record bytes; verify_reconcile_order verifies the
    ORDER, not the signature. Named ...order uniformly across all ten ports so one parity token
    cannot collide with the signature-verify name."""
    recomputed = reconcile(nodes)  # CausalViolation propagates: the graph is not a valid partial order
    if len(recomputed) != len(record.order):
        raise ReconcileMismatch(
            "independent linearization disagrees with the reconcile record's claimed order")
    for got, want in zip(recomputed, record.order):
        if bytes(got) != bytes(want):
            raise ReconcileMismatch(
                "independent linearization disagrees with the reconcile record's claimed order")
    return None
