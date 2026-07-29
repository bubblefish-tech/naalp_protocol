# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C6 — approval + single-use consume ledger (T6).

Non-circular authority (NOT the code under test):
  * The approval body and the consume-ledger entry are built by the shared deterministic-CBOR
    constructor (cbor_oracle, graded against RFC 8949 in T1).
  * Content ids (the args id and the approval id) use the T1 framing exactly:
    multihash(0x20, SHA-384(canonical CBOR)) = 0x20 0x30 || SHA-384(bytes), 50 bytes.
  * The ledger is a from-scratch model of the compare-and-set, hash-chained set of
    design §7.2: entries chain by SHA-384, genesis head is 48 zero bytes, and a second
    consume of the same approval id is rejected (AlreadyConsumed). Go and Rust run the same
    scenario against their WAL-backed ledger and assert byte-identical entries + chain heads
    and the same accept/reject outcomes.
  * The approver / consumer identities are real signer ids taken from the T4 identity corpus
    (an independent authority), used here only as opaque string labels.

Emits vectors/approval/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

GENESIS = b"\x00" * 48  # SHA-384 output width; the empty-chain head


def cid(b):
    """Content id with the T1 framing: multihash(0x20, SHA-384(bytes))."""
    return b"\x20\x30" + hashlib.sha384(b).digest()


def head(entry_bytes):
    """The chain head after appending an entry: SHA-384 of the entry bytes (which carry the
    prior head in field 2, so tampering any entry breaks the next entry's linkage)."""
    return hashlib.sha384(entry_bytes).digest()


def approval_bytes(approves, approver, grant, nonce, not_after):
    return cbor_oracle.encode(("map", [
        (1, approves),      # content id of the exact canonical args object (§7.1)
        (2, approver),      # approver signer id
        (3, grant),         # granted effect class (0..3)
        (4, nonce),         # anti-replay nonce
        (5, not_after),     # expiry, epoch ms
    ]))


def entry_bytes(seq, prev, approval_id, by):
    return cbor_oracle.encode(("map", [
        (1, seq),           # ledger sequence position
        (2, prev),          # prior chain head
        (3, approval_id),   # the approval content id being consumed
        (4, by),            # consumer signer id
    ]))


def build():
    ids = json.load(open(os.path.join(HERE, "..", "vectors", "identity", "cases.json")))
    approver = ids["signers"][0]["signer_id"]
    c1 = ids["signers"][0]["signer_id"]
    c2 = ids["signers"][1]["signer_id"]

    # A worked args object; the approval binds its content id (§7.1).
    args_bytes = cbor_oracle.encode(("map", [(1, "transfer"), (2, 100)]))
    args_id = cid(args_bytes)

    # Two approvals over the same args, distinguished by nonce (so they have distinct ids).
    nonce_a, nonce_b = b"\x01" * 16, b"\x02" * 16
    not_after = 1000
    a_bytes = approval_bytes(args_id, approver, 2, nonce_a, not_after)
    b_bytes = approval_bytes(args_id, approver, 2, nonce_b, not_after)
    a_id, b_id = cid(a_bytes), cid(b_bytes)
    assert a_id != b_id, "distinct nonces must give distinct approval ids"

    # Ledger scenario: consume A, consume B, then re-consume A (rejected).
    e0 = entry_bytes(0, GENESIS, a_id, c1)
    h1 = head(e0)
    e1 = entry_bytes(1, h1, b_id, c1)
    h2 = head(e1)

    consumes = [
        {"approval_id_hex": a_id.hex(), "by": c1, "expect": "ok",
         "seq": 0, "entry_hex": e0.hex(), "head_after_hex": h1.hex()},
        {"approval_id_hex": b_id.hex(), "by": c1, "expect": "ok",
         "seq": 1, "entry_hex": e1.hex(), "head_after_hex": h2.hex()},
        {"approval_id_hex": a_id.hex(), "by": c2, "expect": "AlreadyConsumed"},
    ]

    return {
        "source": ("design §7; content-id = multihash(0x20, SHA-384(canonical CBOR)) (T1); "
                   "ledger = compare-and-set hash chain, head_n = SHA-384(entry_n), genesis "
                   "= 48 zero bytes; approver/consumer ids from the T4 identity corpus."),
        "args": {"content_id_hex": args_id.hex()},
        "approvals": [
            {"name": "A", "approves_hex": args_id.hex(), "approver": approver, "grant": 2,
             "nonce_hex": nonce_a.hex(), "not_after": not_after,
             "record_hex": a_bytes.hex(), "approval_id_hex": a_id.hex()},
            {"name": "B", "approves_hex": args_id.hex(), "approver": approver, "grant": 2,
             "nonce_hex": nonce_b.hex(), "not_after": not_after,
             "record_hex": b_bytes.hex(), "approval_id_hex": b_id.hex()},
        ],
        "ledger": {
            "genesis_head_hex": GENESIS.hex(),
            "consumes": consumes,
            "final_head_hex": h2.hex(),
        },
        "expiry": {"not_after": not_after, "valid_at": not_after, "expired_at": not_after + 1},
        "mismatch": {"wrong_args_id_hex": cid(b"a different args object").hex()},
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "approval", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  approval A id=%s..." % data["approvals"][0]["approval_id_hex"][:16])
    print("  final chain head=%s..." % data["ledger"]["final_head_hex"][:16])


if __name__ == "__main__":
    main()
