# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for the collaboration / rooms membership higher-tier surface
(feature #64) — a Phase-3 ADDITIVE tier-1 surface over the frozen draft-00 spine.

It grades three recorded maintainer decisions:
  * #4a Membership carriage — every membership change (create, add_member, remove_member,
        change_role, add_owner) is a first-class SIGNED object that is CURSOR-OCCUPYING
        (a real ordered position in the per-room log), RECEIPT-CHAINED (woven into the
        append-only audit/receipt chain, design §8.1), and EPOCH-BUMPING (each accepted op
        increments a membership epoch; an op carrying a stale epoch is rejected).
  * #4b O2 ownership — multi-owner, ADD-ONLY: rooms may have many owners; add_owner adds
        one; an owner is never removed or demoted (so a room can never become ownerless).
  * #3  Delivery Model B — a principal registry mapping a semantic principal id -> a durable
        Handle; deliveries address the semantic id, resolved to the Handle at send time
        (a durable naming layer above the connection-scoped N-PAMP PeerHandle, R-1.4).

Non-circular authority (NOT the code under test):
  * Every op/receipt/binding body is built by the shared deterministic-CBOR constructor
    (cbor_oracle, graded against RFC 8949 §4.2.1 in T1).
  * A content id is multihash(0x20, SHA-384(body)) — the T1 framing (design §2.3), computed
    here over the FULL op body map (an op body's field 1 is `room`, not an id-to-exclude, so
    this does NOT reuse cbor_oracle.content_id which drops field 1 for the envelope).
  * The per-room log and the per-principal binding chains are from-scratch SHA-384 hash chains
    (design §8.1): head-after = SHA-384(body); the body carries the prior head; genesis prev is
    48 zero bytes. Reorder / omit / substitute all break a `prev` link.
  * Object/authority SIGNATURES are NOT modelled here (Python has no ML-DSA); the signed
    end-to-end envelope, stale-epoch rejection, owner-immutability, unauthorized-actor
    rejection, and rebind-on-rotation continuity are graded in Go and Rust with real crypto.
    Go == oracle and Rust == oracle on every byte here  ==>  Go == Rust.

Emits vectors/rooms/cases.json (LF-normalized).
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

# Operation codes (naalp-room-op field 2).
OP_CREATE, OP_ADD_MEMBER, OP_REMOVE_MEMBER, OP_CHANGE_ROLE, OP_ADD_OWNER = 0, 1, 2, 3, 4
OP_NAME = {0: "create", 1: "add_member", 2: "remove_member", 3: "change_role", 4: "add_owner"}
# Role codes (naalp-room-op field 5).
ROLE_MEMBER, ROLE_ADMIN, ROLE_OWNER = 0, 1, 2
ROLE_NAME = {0: "member", 1: "admin", 2: "owner"}


def op_body(room, op, epoch, subject, role):
    """Deterministic CBOR of a room-op body {1:room,2:op,3:epoch,4:subject,5:role}."""
    return cbor_oracle.encode(("map", [(1, room), (2, op), (3, epoch), (4, subject), (5, role)]))


def cid(body):
    """Content id (T1 framing) over the FULL body bytes: multihash(0x20, SHA-384(body))."""
    return b"\x20\x30" + hashlib.sha384(body).digest()


def receipt_body(prev, obj, seq, at):
    """The frozen naalp-receipt body {1:prev,2:obj,3:seq,4:at} (design §8.1) — the room log."""
    return cbor_oracle.encode(("map", [(1, prev), (2, obj), (3, seq), (4, at)]))


def binding_body(principal, handle, epoch, prev):
    """Deterministic CBOR of a principal-binding {1:principal,2:handle,3:epoch,4:prev}."""
    return cbor_oracle.encode(("map", [(1, principal), (2, handle), (3, epoch), (4, prev)]))


def head(body):
    return hashlib.sha384(body).digest()


def build_rooms():
    # A stable, reproducible room id (T1 content-id framing over a fixed label).
    room = cid(cbor_oracle.encode("naalp-room:collab-1"))

    # The worked membership sequence. `role` is the role assigned to `subject`;
    # `epoch` is the membership epoch the op is built against (== room epoch at build).
    steps = [
        (OP_CREATE,        "alice", ROLE_OWNER),   # alice is the first owner + member
        (OP_ADD_MEMBER,    "bob",   ROLE_MEMBER),  # bob joins as a plain member
        (OP_ADD_MEMBER,    "carol", ROLE_ADMIN),   # carol joins as an admin
        (OP_ADD_OWNER,     "bob",   ROLE_OWNER),   # bob promoted to owner (add-only)
        (OP_CHANGE_ROLE,   "carol", ROLE_MEMBER),  # carol admin -> member (carol is not an owner: allowed)
        (OP_REMOVE_MEMBER, "carol", ROLE_MEMBER),  # carol removed (a non-owner: allowed)
    ]

    ops = []
    chain = []
    log_head = GENESIS
    epoch = 0
    # Independent membership-state model, so the oracle also fixes the expected final state.
    members = {}   # subject -> role
    owners = set()
    for seq, (op, subject, role) in enumerate(steps):
        body = op_body(room, op, epoch, subject, role)
        oc = cid(body)
        ops.append({
            "seq": seq,
            "op": op,
            "op_name": OP_NAME[op],
            "epoch_at_build": epoch,
            "subject": subject,
            "role": role,
            "role_name": ROLE_NAME[role],
            "body_hex": body.hex(),
            "op_content_id_hex": oc.hex(),
            "epoch_after": epoch + 1,
        })
        # The room log receipt over this op's content id (cursor = seq).
        rb = receipt_body(log_head, oc, seq, 200 + seq)
        ha = head(rb)
        chain.append({
            "seq": seq,
            "prev_hex": log_head.hex(),
            "obj_hex": oc.hex(),
            "at": 200 + seq,
            "body_hex": rb.hex(),
            "head_after_hex": ha.hex(),
        })
        log_head = ha
        # Apply the mutation in the independent model.
        if op == OP_CREATE:
            members[subject] = ROLE_OWNER
            owners.add(subject)
        elif op == OP_ADD_MEMBER:
            members[subject] = role
        elif op == OP_ADD_OWNER:
            members[subject] = ROLE_OWNER
            owners.add(subject)
        elif op == OP_CHANGE_ROLE:
            members[subject] = role
        elif op == OP_REMOVE_MEMBER:
            members.pop(subject, None)
        epoch += 1

    final_members = sorted([{"subject": s, "role": r, "role_name": ROLE_NAME[r]} for s, r in members.items()],
                           key=lambda m: m["subject"])
    return {
        "room_id_hex": room.hex(),
        "genesis_prev_hex": GENESIS.hex(),
        "ops": ops,
        "room_log": chain,
        "final_log_head_hex": log_head.hex(),
        "final_epoch": epoch,
        "final_members": final_members,
        "final_owners": sorted(owners),
        # A stale-epoch scenario the impls drive with real crypto: op #1 (add_member bob) is
        # built against epoch 1; after it is accepted the room is at epoch 2, so REPLAYING an op
        # still carrying epoch 1 MUST be rejected (StaleEpoch). This lists the operative values.
        "stale_epoch_case": {"built_epoch": 1, "room_epoch_after_first_accept": 2, "expect": "StaleEpoch"},
        # Owner immutability (add-only): removing or demoting alice (an owner) MUST be rejected.
        "owner_immutable_case": {"owner": "alice", "expect": "OwnerImmutable"},
    }


def build_registry():
    # Delivery Model B: a semantic principal id -> a durable Handle, per-principal signed chain.
    # Handles are opaque here; in the impls they are real durable signer ids and a rebind is
    # authorized by a co-signed rotation (R-1.4), graded behaviourally in Go/Rust.
    bindings = []
    # agent:alice v1
    b_a1 = binding_body("agent:alice", "handle-alice-v1", 0, GENESIS)
    h_a1 = head(b_a1)
    bindings.append({"principal": "agent:alice", "handle": "handle-alice-v1", "epoch": 0,
                     "prev_hex": GENESIS.hex(), "body_hex": b_a1.hex(), "head_after_hex": h_a1.hex()})
    # agent:bob v1 (its own chain, genesis prev)
    b_b1 = binding_body("agent:bob", "handle-bob-v1", 0, GENESIS)
    h_b1 = head(b_b1)
    bindings.append({"principal": "agent:bob", "handle": "handle-bob-v1", "epoch": 0,
                     "prev_hex": GENESIS.hex(), "body_hex": b_b1.hex(), "head_after_hex": h_b1.hex()})
    # agent:alice v2 (rebind on rotation: prev = alice v1 head, epoch bumped)
    b_a2 = binding_body("agent:alice", "handle-alice-v2", 1, h_a1)
    h_a2 = head(b_a2)
    bindings.append({"principal": "agent:alice", "handle": "handle-alice-v2", "epoch": 1,
                     "prev_hex": h_a1.hex(), "body_hex": b_a2.hex(), "head_after_hex": h_a2.hex()})
    resolve = {"agent:alice": "handle-alice-v2", "agent:bob": "handle-bob-v1"}
    # A stale-epoch rebind (replaying epoch 1 against a principal already at epoch 1) must be
    # rejected — the same monotonic-epoch guard as the membership log, applied to the registry.
    return {
        "bindings": bindings,
        "resolve": resolve,
        "stale_rebind_case": {"principal": "agent:alice", "built_epoch": 1,
                              "principal_epoch_after": 2, "expect": "StaleEpoch"},
    }


def build():
    return {
        "source": ("N-AALP collaboration/rooms membership (feature #64), a tier-1 additive surface "
                   "over the frozen draft-00 spine. room-op body {1:room,2:op,3:epoch,4:subject,5:role}; "
                   "op codes 0 create/1 add_member/2 remove_member/3 change_role/4 add_owner; role codes "
                   "0 member/1 admin/2 owner. The room log is the frozen naalp-receipt chain over op "
                   "content ids (design §8.1); content id = multihash(0x20, SHA-384(body)). principal "
                   "binding {1:principal,2:handle,3:epoch,4:prev}, per-principal SHA-384 chain (Delivery "
                   "Model B, R-1.4). Signatures/behaviour graded in Go+Rust with real crypto."),
        "rooms": build_rooms(),
        "registry": build_registry(),
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "rooms", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    r = data["rooms"]
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  room=%s... ops=%d final_epoch=%d owners=%s log_head=%s..." % (
        r["room_id_hex"][:16], len(r["ops"]), r["final_epoch"], r["final_owners"],
        r["final_log_head_hex"][:16]))


if __name__ == "__main__":
    main()
