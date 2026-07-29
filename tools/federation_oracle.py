# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for T13 — federated ordering (the Federation higher tier, design §8.4 /
design-channels.md §7; R-8.6, R-15A.2, R-15A.3).

Non-circular authority (NOT the code under test): a from-scratch deterministic-merge model over
the shared causal graph. Multiple ordering authorities each order their own scope; reconciliation
is a DETERMINISTIC linearization of the union causal DAG — a topological sort where the tie-break
among causally-concurrent objects is the object content id (bytewise ascending). This is
scope-independent: any split of the objects across authorities reconciles to the SAME order given
the same causal graph, so moving from single-authority to federated ordering needs no wire change
(R-8.6). Content ids use the T1 framing multihash(0x20, SHA-384(canonical CBOR)); the Reconcile
record body is built by the T1-graded CBOR constructor.

Emits vectors/federation/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)


def cid(name):
    b = cbor_oracle.encode(("map", [(1, name)]))
    return b"\x20\x30" + hashlib.sha384(b).digest()


def reconcile(nodes):
    """Deterministic merge: Kahn's topological sort over the causal DAG, tie-broken by content id
    (bytewise ascending). `nodes` is a list of (id_bytes, [cause_bytes...])."""
    ids = [n[0] for n in nodes]
    causes = {n[0]: [c for c in n[1] if c in ids] for n in nodes}  # only present causes constrain
    indeg = {i: len(causes[i]) for i in ids}
    emitted = []
    done = set()
    while len(emitted) < len(ids):
        ready = sorted(i for i in ids if i not in done and indeg[i] == 0)  # bytewise tie-break
        pick = ready[0]
        done.add(pick)
        emitted.append(pick)
        for i in ids:
            if i not in done and pick in causes[i]:
                indeg[i] -= 1
    return emitted


def causally_valid(order, nodes):
    pos = {i: k for k, i in enumerate(order)}
    causes = {n[0]: n[1] for n in nodes}
    for i in order:
        for c in causes[i]:
            if c in pos and pos[c] > pos[i]:
                return False
    return True


def build():
    a, b, c, d, e = cid("objA"), cid("objB"), cid("objC"), cid("objD"), cid("objE")
    # Graph: A -> B, A -> C, {B,C} -> D, D -> E  (edges point cause -> effect).
    nodes = [
        ("A", a, []),
        ("B", b, [a]),
        ("C", c, [a]),
        ("D", d, [b, c]),
        ("E", e, [d]),
    ]
    merge_input = [(n[1], n[2]) for n in nodes]
    order = reconcile(merge_input)
    assert causally_valid(order, merge_input), "oracle merge must be causally valid"

    # A causality-ignoring merge (pure content-id sort) — the mutation baseline.
    naive = sorted([n[1] for n in nodes])

    authorities = ["bauthority-x", "bauthority-y"]
    # Reconcile record body {1: authorities (tstr array), 2: order (bstr content-id array)}.
    record = cbor_oracle.encode(("map", [
        (1, [s for s in authorities]),
        (2, [o for o in order]),
    ]))

    return {
        "source": ("design §8.4 / design-channels §7; reconcile = deterministic topological sort "
                   "of the union causal DAG, tie-broken by content id (bytewise); scope-independent "
                   "so federated ordering needs no wire change (R-8.6)."),
        "nodes": [{"name": n[0], "id_hex": n[1].hex(), "causes_hex": [x.hex() for x in n[2]]} for n in nodes],
        "reconcile_order_hex": [o.hex() for o in order],
        "reconcile_order_causally_valid": True,
        "naive_content_id_sort_hex": [o.hex() for o in naive],
        "naive_causally_valid": causally_valid(naive, merge_input),
        "authorities": authorities,
        "record_hex": record.hex(),
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "federation", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  reconcile order:", [n["name"] for n in data["nodes"] if True][:0] or [o[:8] for o in data["reconcile_order_hex"]])
    print("  naive sort causally valid?", data["naive_causally_valid"])


if __name__ == "__main__":
    main()
