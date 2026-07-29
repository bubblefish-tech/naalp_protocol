# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C9 — native streaming + per-stream commitment (T9).

Non-circular authority (NOT the code under test):
  * The stream commitment is a rolling SHA-384 over the chunks in absolute-offset order
    (design §10.2): digest = SHA-384(chunk[0] || chunk[1] || ... ), computed here with the
    standard-library hashlib — independent of the Go/Rust streaming code. A checkpoint's
    digest_so_far is SHA-384 over the prefix through that offset (FIPS 180-4 SHA-384).
  * The StreamOpen / StreamCommit / StreamCheckpoint bodies are built by the shared
    deterministic-CBOR constructor (cbor_oracle, graded against RFC 8949 in T1).
  * Effect refusal at open and full-duplex operation are behavioural properties graded in Go
    and Rust; this oracle fixes the digest + body bytes so Go == oracle == Rust.

Emits vectors/stream/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)


def sha384(b):
    return hashlib.sha384(b).digest()


def cid(name):
    b = cbor_oracle.encode(("map", [(1, name)]))
    return b"\x20\x30" + sha384(b)


def build():
    stream_id = bytes.fromhex("00112233445566778899aabbccddeeff")
    substream = 3
    effect = 1  # idempotent_write
    approval = cid("approved-args")  # the approval binding at open (§10.2 / R-10.3)

    # Chunks in absolute-offset order (design §10.2).
    parts = [b"hello ", b"streaming ", b"world"]
    chunks = []
    off = 0
    for p in parts:
        chunks.append({"offset": off, "data_hex": p.hex()})
        off += len(p)

    concat = b"".join(parts)
    final_digest = sha384(concat)  # rolling SHA-384 over the complete ordered stream

    # Checkpoints: digest_so_far = SHA-384 of the prefix through that offset.
    checkpoints = [
        {"through_offset": len(parts[0]), "digest_so_far_hex": sha384(parts[0]).hex()},
        {"through_offset": len(parts[0]) + len(parts[1]),
         "digest_so_far_hex": sha384(parts[0] + parts[1]).hex()},
    ]

    open_body = cbor_oracle.encode(("map", [
        (1, stream_id), (2, effect), (3, approval), (4, substream),
    ]))
    commit_body = cbor_oracle.encode(("map", [(1, stream_id), (2, final_digest)]))
    checkpoint_body = cbor_oracle.encode(("map", [
        (1, stream_id), (2, checkpoints[0]["through_offset"]),
        (3, bytes.fromhex(checkpoints[0]["digest_so_far_hex"])),
    ]))

    # Tamper: flip one byte of chunk index 1; the recomputed digest differs.
    tampered = bytearray(parts[1])
    tampered[0] ^= 0x01
    tamper_concat = parts[0] + bytes(tampered) + parts[2]

    return {
        "source": ("design §10; commitment = rolling SHA-384 over chunks in absolute-offset "
                   "order; StreamOpen {1:stream_id,2:effect,3:approval?,4:substream}; "
                   "StreamCommit {1:stream_id,2:digest}; StreamCheckpoint "
                   "{1:stream_id,2:through_offset,3:digest_so_far}."),
        "stream_id_hex": stream_id.hex(),
        "substream": substream,
        "effect": effect,
        "approval_hex": approval.hex(),
        "chunks": chunks,
        "final_digest_hex": final_digest.hex(),
        "checkpoints": checkpoints,
        "open_body_hex": open_body.hex(),
        "commit_body_hex": commit_body.hex(),
        "checkpoint_body_hex": checkpoint_body.hex(),
        "tamper": {"chunk_index": 1, "flipped_data_hex": bytes(tampered).hex(),
                   "digest_hex": sha384(tamper_concat).hex()},
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "stream", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  chunks=%d final_digest=%s..." % (len(data["chunks"]), data["final_digest_hex"][:16]))


if __name__ == "__main__":
    main()
