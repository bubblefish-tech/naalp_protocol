# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C8 — delivery stages + persist-before-ack + switchboard (T8).

Non-circular authority (NOT the code under test):
  * The delivery.update body is built by the shared deterministic-CBOR constructor
    (cbor_oracle, graded against RFC 8949 in T1): {1:obj, 2:stage, 3:at}.
  * The object content id uses the T1 framing multihash(0x20, SHA-384).
  * The four stage values/names are the design §9.1 chain
    persisted_origin(0) -> accepted_relay(1) -> persisted_target(2) -> presented(3).
  * Persist-before-ack (crash recovery), the full-duplex switchboard, and the content-free
    relay are behavioural properties graded in Go and Rust (a crash test, a concurrency test,
    and an audit-trail check); this oracle fixes the update bytes so Go == oracle == Rust.

Emits vectors/delivery/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

STAGES = [
    (0, "persisted_origin"),
    (1, "accepted_relay"),
    (2, "persisted_target"),
    (3, "presented"),
]


def cid(name):
    b = cbor_oracle.encode(("map", [(1, name)]))
    return b"\x20\x30" + hashlib.sha384(b).digest()


def update_bytes(obj, stage, at):
    return cbor_oracle.encode(("map", [(1, obj), (2, stage), (3, at)]))


def build():
    obj = cid("deliverable")
    updates = []
    for i, (stage, _name) in enumerate(STAGES):
        at = 100 + i
        updates.append({"stage": stage, "at": at, "body_hex": update_bytes(obj, stage, at).hex()})
    return {
        "source": ("design §9; delivery.update body {1:obj, 2:stage, 3:at}; four monotonic "
                   "stages persisted_origin(0) -> accepted_relay(1) -> persisted_target(2) -> "
                   "presented(3); content id in T1 framing multihash(0x20, SHA-384)."),
        "stages": [{"value": v, "name": n} for (v, n) in STAGES],
        "obj_content_id_hex": obj.hex(),
        "updates": updates,
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "delivery", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  stages=%d obj=%s..." % (len(data["stages"]), data["obj_content_id_hex"][:16]))


if __name__ == "__main__":
    main()
