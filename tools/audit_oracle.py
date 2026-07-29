# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C7 — audit chain + causal graph + tiered ordering (T7).

Non-circular authority (NOT the code under test):
  * Receipt bodies and object content ids are built by the shared deterministic-CBOR
    constructor (cbor_oracle, graded against RFC 8949 in T1).
  * The receipt chain is a from-scratch hash chain (design §8.1): a receipt body is
    {1:prev, 2:obj, 3:seq, 4:at}; the chain head after a receipt is SHA-384(body); the
    genesis prev is 48 zero bytes. Reorder / omit / substitute all break a `prev` link.
  * The causal-graph verdicts (valid DAG, cycle, future-cause) are computed here by an
    independent topological check over (content-id, causes, position) tuples (design §8.3).
  * Object/authority signatures are NOT modelled here (Python has no ML-DSA); the signature
    checks (ReceiptUnsigned, the causal edge proven by a real signature) are graded in Go and
    Rust with real crypto. Go == oracle and Rust == oracle on the bytes ⟹ Go == Rust.

Emits vectors/audit/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

GENESIS = b"\x00" * 48  # SHA-384 width; the empty-chain prev


def cid(name):
    """Content id (T1 framing) of a tiny worked object {1: name}."""
    b = cbor_oracle.encode(("map", [(1, name)]))
    return b"\x20\x30" + hashlib.sha384(b).digest()


def receipt_bytes(prev, obj, seq, at):
    return cbor_oracle.encode(("map", [(1, prev), (2, obj), (3, seq), (4, at)]))


def head(body):
    return hashlib.sha384(body).digest()


def build():
    a, b, c, x = cid("objA"), cid("objB"), cid("objC"), cid("objX")

    # A monotonic receipt chain (baseline single-authority tier, §8.1).
    r0 = receipt_bytes(GENESIS, a, 0, 100)
    h0 = head(r0)
    r1 = receipt_bytes(h0, b, 1, 101)
    h1 = head(r1)
    r2 = receipt_bytes(h1, c, 2, 102)
    h2 = head(r2)
    chain = {
        "genesis_prev_hex": GENESIS.hex(),
        "receipts": [
            {"seq": 0, "prev_hex": GENESIS.hex(), "obj_hex": a.hex(), "at": 100,
             "body_hex": r0.hex(), "head_after_hex": h0.hex()},
            {"seq": 1, "prev_hex": h0.hex(), "obj_hex": b.hex(), "at": 101,
             "body_hex": r1.hex(), "head_after_hex": h1.hex()},
            {"seq": 2, "prev_hex": h1.hex(), "obj_hex": c.hex(), "at": 102,
             "body_hex": r2.hex(), "head_after_hex": h2.hex()},
        ],
        "final_head_hex": h2.hex(),
    }

    # ChainBroken: a receipt at seq 1 whose prev is genesis instead of head(r0).
    broken_body = receipt_bytes(GENESIS, b, 1, 101)
    chain_broken = {
        "receipts": [
            {"seq": 0, "prev_hex": GENESIS.hex(), "obj_hex": a.hex(), "at": 100, "body_hex": r0.hex()},
            {"seq": 1, "prev_hex": GENESIS.hex(), "obj_hex": b.hex(), "at": 101, "body_hex": broken_body.hex()},
        ],
        "expect": "ChainBroken",
    }

    # Equivocation: two receipts by one authority at seq 1 naming different objects (§8.5).
    eq_a = receipt_bytes(h0, b, 1, 101)
    eq_b = receipt_bytes(h0, x, 1, 101)
    equivocation = {
        "seq": 1,
        "receipt_a": {"obj_hex": b.hex(), "body_hex": eq_a.hex()},
        "receipt_b": {"obj_hex": x.hex(), "body_hex": eq_b.hex()},
        "expect": "Equivocation",
    }

    # Causal graph (§8.2/§8.3): a valid DAG, a cycle, and a future-cause.
    causal_valid = {
        "nodes": [
            {"name": "A", "id_hex": a.hex(), "causes_hex": [], "position": 0},
            {"name": "B", "id_hex": b.hex(), "causes_hex": [a.hex()], "position": 1},
            {"name": "C", "id_hex": c.hex(), "causes_hex": [a.hex(), b.hex()], "position": 2},
        ],
        "valid": True,
        "topo_order_hex": [a.hex(), b.hex(), c.hex()],
    }
    causal_cycle = {
        "nodes": [
            {"name": "X", "id_hex": x.hex(), "causes_hex": [a.hex()], "position": 0},
            {"name": "A", "id_hex": a.hex(), "causes_hex": [x.hex()], "position": 0},
        ],
        "expect": "CausalViolation",
    }
    causal_future = {
        # P (position 1) names cause C (position 2): a cause it could not have seen.
        "nodes": [
            {"name": "P", "id_hex": b.hex(), "causes_hex": [c.hex()], "position": 1},
            {"name": "C", "id_hex": c.hex(), "causes_hex": [], "position": 2},
        ],
        "expect": "CausalViolation",
    }

    return {
        "source": ("design §8; receipt body {1:prev,2:obj,3:seq,4:at}; chain head = "
                   "SHA-384(receipt body); genesis prev = 48 zero bytes; content ids in T1 "
                   "framing multihash(0x20, SHA-384); causal verdicts by independent topo check."),
        "chain": chain,
        "chain_broken": chain_broken,
        "equivocation": equivocation,
        "causal_valid": causal_valid,
        "causal_cycle": causal_cycle,
        "causal_future": causal_future,
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "audit", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  chain final head=%s..." % data["chain"]["final_head_hex"][:16])


if __name__ == "__main__":
    main()
