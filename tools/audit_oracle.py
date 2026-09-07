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
  * ForkProof (draft-01, §8.5, finding #70): the non-repudiable equivocation proof carries the
    accused authority's TWO conflicting signatures (SigA over body-a, SigB over body-b), plus an
    external monotonic counter (T2.1) bound into the proof against replay/reorder. Its wire body
    is {1:signer, 2:ext_counter, 3:body_a, 4:sig_a, 5:body_b, 6:sig_b} (deterministic CBOR). The
    oracle emits the FRAMING WITNESS `preimage_hex` — the same body with the two signature bstrs
    ELIDED to empty — which Go and Rust reproduce byte-for-byte; the deterministic ML-DSA
    signatures themselves are graded by the two-implementation byte-parity (cose.sign1 consensus,
    anchored to the NIST keyGen KAT), exactly as every other signed object is (envelope_oracle).
    The Verify positive/negative cases run in the impl suites with real crypto.

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

# ForkProof worked-vector constants (draft-01, §8.5). The signer id is an opaque authority id in
# the envelope field-5 form (the real key is C4/T4), chosen here so the framing witness is
# independently reproducible; the external counter is a worked value bound into the proof (T2.1).
FORK_SIGNER = b"\x41\x55\x54\x48\x30\x31"  # "AUTH01" — accused authority signer id (opaque bstr)
FORK_EXT_COUNTER = 7                        # external monotonic counter bound into the proof (T2.1)


def cid(name):
    """Content id (T1 framing) of a tiny worked object {1: name}."""
    b = cbor_oracle.encode(("map", [(1, name)]))
    return b"\x20\x30" + hashlib.sha384(b).digest()


def receipt_bytes(prev, obj, seq, at):
    return cbor_oracle.encode(("map", [(1, prev), (2, obj), (3, seq), (4, at)]))


def head(body):
    return hashlib.sha384(body).digest()


def fork_proof_preimage(signer, ext_counter, body_a, body_b):
    """The draft-01 ForkProof framing witness: the deterministic-CBOR body
    {1:signer, 2:ext_counter, 3:body_a, 4:sig_a, 5:body_b, 6:sig_b} with the two signature
    byte-strings ELIDED to empty. Go and Rust reproduce this byte-for-byte; the real ML-DSA
    signatures are graded separately by two-implementation deterministic byte-parity (§8.5)."""
    return cbor_oracle.encode(("map", [
        (1, signer),        # accused authority signer id
        (2, ext_counter),   # external monotonic counter (T2.1)
        (3, body_a),        # receipt A body (bstr) — signed input for sig-a
        (4, b""),           # sig-a elided in the framing witness
        (5, body_b),        # receipt B body (bstr) — signed input for sig-b (different obj, same seq)
        (6, b""),           # sig-b elided in the framing witness
    ]))


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

    # ForkProof (draft-01, §8.5, finding #70): the non-repudiable proof binds the accused
    # authority's signer id, the external counter (T2.1), and BOTH conflicting receipt bodies
    # (eq_a naming obj B, eq_b naming obj X — same seq 1, DIFFERENT objects). The oracle emits the
    # framing witness (signatures elided); Go/Rust splice in the real deterministic ML-DSA
    # signatures over body_a/body_b and grade byte-parity + Verify (positive/negative) themselves.
    fp_preimage = fork_proof_preimage(FORK_SIGNER, FORK_EXT_COUNTER, eq_a, eq_b)
    fork_proof = {
        "signer_hex": FORK_SIGNER.hex(),
        "ext_counter": FORK_EXT_COUNTER,
        # Receipt A and B fields (self-contained so a consumer can rebuild both receipts): same seq,
        # same prev = head(receipt 0), DIFFERENT objects.
        "seq": 1,
        "prev_hex": h0.hex(),
        "at": 101,
        "obj_a_hex": b.hex(),       # receipt A object (differs from B → equivocation)
        "obj_b_hex": x.hex(),       # receipt B object
        "body_a_hex": eq_a.hex(),   # signed input for sig-a (receipt A body)
        "body_b_hex": eq_b.hex(),   # signed input for sig-b (receipt B body)
        "preimage_hex": fp_preimage.hex(),  # {1:signer,2:ext_counter,3:body_a,4:'',5:body_b,6:''}
        "note": ("Verify accepts iff signer present, seq_a==seq_b, obj_a!=obj_b, and BOTH sigs "
                 "verify under the accused key; it FAILS CLOSED (ForkProofInvalid) on same-obj, "
                 "seq-mismatch, or empty signer, and (ReceiptUnsigned) on a tampered signature."),
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
                   "framing multihash(0x20, SHA-384); causal verdicts by independent topo check; "
                   "draft-01 ForkProof body {1:signer,2:ext_counter,3:body_a,4:sig_a,5:body_b,"
                   "6:sig_b}, framing witness (sigs elided) reproduced by Go/Rust (§8.5)."),
        "chain": chain,
        "chain_broken": chain_broken,
        "equivocation": equivocation,
        "fork_proof": fork_proof,
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
    print("  fork-proof preimage=%s... (%d bytes, sigs elided)"
          % (data["fork_proof"]["preimage_hex"][:16], len(data["fork_proof"]["preimage_hex"]) // 2))


if __name__ == "__main__":
    main()
