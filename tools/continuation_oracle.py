# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C17 — N-AALP-CONT flow continuation (design.md §20).

N-AALP-CONT generalizes the C9 native-streaming pattern (one full signature over an open, cheap
prefix proofs, one full signature over a commit) into a domain-agnostic *flow*: a single ML-DSA
FlowOpen fixes the flow's effect ceiling and approval bindings (authority reconstructable from the
FlowOpen bytes alone, no session state); cheap hash-chained Continuations extend the flow, each
carrying its own effect that MUST stay at or below the ceiling; signed Checkpoints let a verifier
confirm a prefix and detect a gap/reorder; a single ML-DSA FlowCommit binds the whole ordered
sequence with one signature regardless of the number of continuations.

Non-circular authority (NOT the code under test):
  * Every object body is built by the shared deterministic-CBOR constructor (cbor_oracle, graded
    against RFC 8949 in T1) — never by the Go/Rust continuation code.
  * The content-id framing is the T1 multihash: 0x20 0x30 || SHA-384(canonical body) (design §2.3).
  * The continuation chain is a from-scratch SHA-384 hash chain (the same construction as the C7
    audit receipt chain, design §8.1): each link's head is SHA-384(link body); a link's `prev`
    field is the previous link's head; the chain's genesis prev is the FlowOpen's head (48 octets),
    which anchors every link to THIS FlowOpen — a link replayed under a different FlowOpen has a
    non-matching flow_open_id AND a broken prev. Reorder / omit / substitute all break a `prev`
    link (GapDetected at the next checkpoint / commit). Computed here with the standard-library
    hashlib, independent of the Go/Rust code.
  * The four-effect lattice values (read_only=0 < idempotent_write=1 < non_idempotent_write=2 <
    destructive=3) and the ceiling rule (a continuation effect strictly above the ceiling is
    refused) are behavioural properties graded in Go and Rust; this oracle fixes the body + head
    bytes so Go == oracle == Rust, and fixes the above-ceiling / gap / replay inputs so both
    implementations reject them identically. ML-DSA signatures over FlowOpen / FlowCommit are
    deterministic (FIPS 204, empty context) and are cross-checked Go == Rust in the impl tests;
    Python stdlib has no ML-DSA, so this oracle fixes only the SIGNED INPUT (the body bytes), not
    the signature.

Emits vectors/continuation/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

# Effect lattice (design §6; policy.go): read_only < idempotent_write < non_idempotent_write < destructive.
READ_ONLY, IDEMPOTENT_WRITE, NON_IDEMPOTENT_WRITE, DESTRUCTIVE = 0, 1, 2, 3


def sha384(b):
    return hashlib.sha384(b).digest()


def cid(b):
    """T1 content-id framing: multihash(0x20, SHA-384(bytes)) = 0x20 0x30 || SHA-384(b) (50 octets)."""
    return b"\x20\x30" + sha384(b)


def flow_open_body(flow_id, ceiling, approvals):
    # {1: flow_id, 2: effect_ceiling, 3: approvals[]}  (approvals is a CBOR array of content-ids).
    return cbor_oracle.encode(("map", [(1, flow_id), (2, ceiling), (3, list(approvals))]))


def continuation_body(flow_open_id, seq, effect, payload_id, prev):
    # {1: flow_open_id, 2: seq, 3: effect, 4: payload_id, 5: prev}  (5 fields — a shape no other kind uses).
    return cbor_oracle.encode(("map", [
        (1, flow_open_id), (2, seq), (3, effect), (4, payload_id), (5, prev),
    ]))


def checkpoint_body(flow_open_id, through_seq, head):
    # {1: flow_open_id, 2: through_seq, 3: head}  (3 fields; field 3 is a bstr head).
    return cbor_oracle.encode(("map", [(1, flow_open_id), (2, through_seq), (3, head)]))


def flow_commit_body(flow_open_id, final_head):
    # {1: flow_open_id, 2: final_head}  (2 fields — the signed terminal, distinct from the 3-field checkpoint).
    return cbor_oracle.encode(("map", [(1, flow_open_id), (2, final_head)]))


def build():
    # ---- FlowOpen A: the one full signature that fixes the flow's authority ------------------
    flow_id_a = bytes.fromhex("f100000000000000000000000000000a")
    ceiling = NON_IDEMPOTENT_WRITE  # 2 — the cheap path may not exceed this
    approvals = [cid(b"approval-A")]  # content-ids of the approvals authorizing the flow up to the ceiling
    open_a = flow_open_body(flow_id_a, ceiling, approvals)
    open_a_head = sha384(open_a)          # the chain genesis prev (48 octets)
    open_a_id = cid(open_a)               # flow_open_id carried by every child object (50 octets)

    # ---- The cheap Continuation chain (each effect <= ceiling) --------------------------------
    steps = [
        {"seq": 0, "effect": READ_ONLY,            "payload": b"step-0"},
        {"seq": 1, "effect": IDEMPOTENT_WRITE,     "payload": b"step-1"},
        {"seq": 2, "effect": NON_IDEMPOTENT_WRITE, "payload": b"step-2"},
    ]
    continuations = []
    prev = open_a_head
    for s in steps:
        pid = cid(s["payload"])
        body = continuation_body(open_a_id, s["seq"], s["effect"], pid, prev)
        head = sha384(body)
        continuations.append({
            "seq": s["seq"], "effect": s["effect"],
            "payload_id_hex": pid.hex(), "prev_hex": prev.hex(),
            "body_hex": body.hex(), "head_hex": head.hex(),
        })
        prev = head
    final_head = prev

    # ---- Checkpoint over the prefix seq 0..1 (through_seq = 1) --------------------------------
    cp_through = 1
    cp_head = continuations[cp_through]["head_hex"]
    cp_body = checkpoint_body(open_a_id, cp_through, bytes.fromhex(cp_head))

    # ---- FlowCommit binding the whole ordered sequence with one signature ---------------------
    commit_body = flow_commit_body(open_a_id, final_head)

    # ---- Ceiling enforcement: a Continuation whose effect (destructive=3) exceeds the ceiling.
    # Its body is well-formed; the impls MUST reject it AboveCeiling before it joins the chain.
    above_prev = continuations[-1]["head_hex"]
    above_pid = cid(b"escalate")
    above_body = continuation_body(open_a_id, 3, DESTRUCTIVE, above_pid, bytes.fromhex(above_prev))
    above = {
        "seq": 3, "effect": DESTRUCTIVE, "ceiling": ceiling,
        "payload_id_hex": above_pid.hex(), "prev_hex": above_prev,
        "body_hex": above_body.hex(), "head_hex": sha384(above_body).hex(),
        "reject": "AboveCeiling",
    }

    # ---- Gap detection: drop seq 1, then a checkpoint claiming through_seq 2 over [seq0, seq2].
    # seq2's prev still points at seq1's head, so recomputing the chain over the contiguous prefix
    # {seq0} then seq2 breaks (seq2.prev != head(seq0)) -> GapDetected.
    gap = {
        "present_seqs": [0, 2], "missing_seq": 1, "through_seq": 2,
        "claimed_head_hex": final_head.hex(),
        "recomputed_after_seq0_hex": continuations[0]["head_hex"],
        "detect": "GapDetected",
        "note": "seq2.prev (head of seq1) != head(seq0); the prefix is non-contiguous.",
    }

    # ---- Range rejects (C17 audit fix 0a): the effect_ceiling and a continuation effect are the
    # CLOSED C5 lattice (0..3). A value OUTSIDE the lattice (e.g. 4) is well-formed CBOR but not a
    # legal effect; both impls MUST reject it RangeError, NOT normalize it to destructive (which would
    # silently make an out-of-range ceiling the MOST-permissive one — a fail-open for a ceiling).
    OUT_OF_LATTICE = 4
    ceiling4_body = flow_open_body(flow_id_a, OUT_OF_LATTICE, approvals)
    effect4_body = continuation_body(open_a_id, 0, OUT_OF_LATTICE, cid(b"step-0"), open_a_head)
    range_reject = {
        "out_of_lattice_value": OUT_OF_LATTICE,
        "flow_open_ceiling_body_hex": ceiling4_body.hex(),  # FlowOpen with effect_ceiling = 4
        "continuation_effect_body_hex": effect4_body.hex(),  # Continuation with effect = 4
        "reject": "RangeError",
        "note": ("effect_ceiling (flow-open field 2) and effect (continuation field 3) are the closed "
                 "`effect` enum 0..3; 4 is rejected RangeError, never normalized to destructive."),
    }

    # ---- Checkpoint counter overflow (C17 audit fix 0c): through_seq is a 0-based index, so the
    # contiguous prefix length is through_seq+1. At through_seq = 2^64-1 that addition overflows
    # (Go wraps to 0 and would false-accept an EMPTY prefix; Rust panics in debug). Both impls MUST
    # reject through_seq = u64::MAX as GapDetected. The value is carried as a JSON STRING because it
    # exceeds 2^53 and a float64 JSON decoder would round its low octets before any adapter runs.
    # The checkpoint head is the FlowOpen head — exactly what recomputing over an EMPTY prefix yields
    # (VerifyChain([]) == open head) — so the head comparison would PASS. That isolates the overflow
    # guard as the ONLY thing that rejects this checkpoint: without the u64::MAX guard, through_seq+1
    # wraps to 0, the empty-prefix count check passes, and the (matching) head is accepted — a
    # false-accept. With the guard both impls reject GapDetected.
    U64_MAX = (1 << 64) - 1
    overflow_body = checkpoint_body(open_a_id, U64_MAX, open_a_head)
    checkpoint_overflow = {
        "through_seq_str": str(U64_MAX),  # STRING (>2^53) — never a bare JSON number
        "head_hex": open_a_head.hex(),    # = VerifyChain([]) head, so only the overflow guard rejects
        "body_hex": overflow_body.hex(),
        "prefix_len": 0,  # an empty prefix presented against the u64::MAX claim
        "reject": "GapDetected",
        "note": "through_seq = u64::MAX; through_seq+1 overflows -> reject GapDetected (no MAX+1 links).",
    }

    # ---- Oversized-counter round-trip (Phase 6 edge case #3, the >2^53 discipline): a continuation
    # seq above 2^53. 0x0102030405060708 = 72623859790382856 > 2^53 = 9007199254740992. It MUST
    # round-trip byte-exact through BOTH impls (uint64/u64 all the way, no float64), so the body head
    # and content stay stable. In THIS JSON the value is carried as a STRING, never a bare number: a
    # float64 JSON decoder (JS Number, Go interface{}) silently rounds it and corrupts the low octets
    # BEFORE any adapter runs. This oracle uses Python's arbitrary-precision int, so its body_hex is
    # computed losslessly; the impls parse seq_str with a 64-bit integer parser, never a float.
    BIG_SEQ = 0x0102030405060708
    assert BIG_SEQ > (1 << 53)
    big_seq_pid = cid(b"big-seq-step")
    big_seq_body = continuation_body(open_a_id, BIG_SEQ, IDEMPOTENT_WRITE, big_seq_pid, open_a_head)
    big_seq = {
        "seq_str": str(BIG_SEQ),  # STRING (>2^53) — never a bare JSON number
        "effect": IDEMPOTENT_WRITE,
        "payload_id_hex": big_seq_pid.hex(),
        "prev_hex": open_a_head.hex(),
        "body_hex": big_seq_body.hex(),
        "head_hex": sha384(big_seq_body).hex(),
        "note": "seq = 0x0102030405060708 (>2^53) MUST round-trip byte-exact; carried as a JSON string.",
    }

    # ---- Minimal object (Phase 6 edge case #4): the smallest valid FlowOpen — an empty flow_id,
    # ceiling read_only (0), and NO approvals. It MUST verify (encode + parse) and have a stable
    # content-id, distinct from any richer object.
    minimal_open_body = flow_open_body(b"", READ_ONLY, [])
    minimal = {
        "flow_id_hex": "",
        "effect_ceiling": READ_ONLY,
        "approvals_hex": [],
        "body_hex": minimal_open_body.hex(),
        "head_hex": sha384(minimal_open_body).hex(),
        "id_hex": cid(minimal_open_body).hex(),
        "note": "smallest valid FlowOpen: empty flow_id, ceiling read_only, no approvals.",
    }

    # ---- Empty-vs-absent (Phase 6 edge case #2): a FlowOpen's approvals[] is a PRESENT list; an
    # empty approvals list is DISTINCT on the wire (and by content-id) from... there is no 'absent'
    # form (field 3 is mandatory), so the meaningful empty-vs-nonempty distinction is graded here:
    # an empty-approvals FlowOpen and a one-approval FlowOpen over the same flow_id + ceiling encode
    # to DIFFERENT bytes and DIFFERENT ids (the empty list is not conflated with a populated one).
    empty_approvals_body = flow_open_body(flow_id_a, ceiling, [])
    one_approval_body = flow_open_body(flow_id_a, ceiling, [cid(b"approval-A")])
    assert empty_approvals_body != one_approval_body
    empty_vs_nonempty = {
        "empty_approvals": {
            "body_hex": empty_approvals_body.hex(),
            "id_hex": cid(empty_approvals_body).hex(),
        },
        "one_approval": {
            "body_hex": one_approval_body.hex(),
            "id_hex": cid(one_approval_body).hex(),
        },
        "note": "an empty approvals[] is distinct on the wire and by content-id from a populated one.",
    }

    # ---- Keys-out-of-order (Phase 6 edge case #1): a hand-built non-canonical FlowCommit whose two
    # map keys are in DESCENDING order (2 then 1). The content is identical to the canonical FlowCommit
    # {1: flow_open_id, 2: final_head}; the strict deterministic-CBOR decoder MUST reject it
    # NonCanonical (RFC 8949 §4.2.1 sorted-keys rule; the shared C1 codec, graded in T1). Built here
    # by hand (NOT via cbor_oracle.encode, which always sorts) so the bytes are genuinely mis-ordered.
    fc_fid = open_a_id
    fc_final = final_head
    # canonical: 0xA2 (map,2) then key 1 (0x01) val bstr(fid) then key 2 (0x02) val bstr(final_head)
    k1 = cbor_oracle.encode(1) + cbor_oracle.encode(fc_fid)
    k2 = cbor_oracle.encode(2) + cbor_oracle.encode(fc_final)
    noncanon_commit = bytes([0xA2]) + k2 + k1  # keys emitted 2,1 (descending) — non-canonical
    canon_commit = flow_commit_body(fc_fid, fc_final)
    assert noncanon_commit != canon_commit and len(noncanon_commit) == len(canon_commit)
    keys_out_of_order = {
        "canonical_commit_body_hex": canon_commit.hex(),
        "noncanonical_commit_body_hex": noncanon_commit.hex(),
        "reject": "NonCanonical",
        "note": "same content, keys in descending order (2 then 1) — the strict decoder rejects NonCanonical.",
    }

    # ---- Look-alike (Phase 6 edge case #5): a 2-field object that resembles a FlowCommit but is a
    # Checkpoint-shaped body missing field 3 (3 fields vs 2) would be a different shape. Here the
    # cross-production look-alike is a FlowCommit body decoded as a Checkpoint: a FlowCommit is
    # {1:bstr,2:bstr} (2 fields) while a Checkpoint is {1:bstr,2:uint,3:bstr} (3 fields), so a
    # FlowCommit body fed to ParseCheckpoint is rejected (missing field 3 / wrong field-2 type).
    look_alike = {
        "flow_commit_body_hex": canon_commit.hex(),
        "note": "a 2-field FlowCommit body fed to ParseCheckpoint is rejected — Checkpoint is 3 fields.",
    }

    # ---- Replay under a different FlowOpen: FlowOpen B differs only in flow_id, so its head/id
    # differ; the FlowOpen-A continuation chain does not validate against B (WrongFlow + broken prev).
    flow_id_b = bytes.fromhex("f100000000000000000000000000000b")
    open_b = flow_open_body(flow_id_b, ceiling, approvals)
    open_b_head = sha384(open_b)
    open_b_id = cid(open_b)
    replay = {
        "flow_open_b_body_hex": open_b.hex(),
        "flow_open_b_head_hex": open_b_head.hex(),
        "flow_open_b_id_hex": open_b_id.hex(),
        "detect": "WrongFlow",
        "note": ("continuation seq0 carries flow_open_id = A and prev = head(A); verifying it under "
                 "FlowOpen B fails: flow_open_id != B.id, and prev != head(B)."),
    }

    return {
        "source": ("design §20; FlowOpen {1:flow_id,2:effect_ceiling,3:approvals[]} (full ML-DSA sig); "
                   "Continuation {1:flow_open_id,2:seq,3:effect,4:payload_id,5:prev} (cheap; head = "
                   "SHA-384(body); prev[0] = SHA-384(FlowOpen body); prev[i] = head[i-1]); Checkpoint "
                   "{1:flow_open_id,2:through_seq,3:head}; FlowCommit {1:flow_open_id,2:final_head} "
                   "(full ML-DSA sig). Content-id = multihash(0x20, SHA-384). Effect lattice "
                   "read_only=0<idempotent_write=1<non_idempotent_write=2<destructive=3; a continuation "
                   "effect above the ceiling is refused AboveCeiling."),
        "flow_open": {
            "flow_id_hex": flow_id_a.hex(), "effect_ceiling": ceiling,
            "approvals_hex": [a.hex() for a in approvals],
            "body_hex": open_a.hex(), "head_hex": open_a_head.hex(), "id_hex": open_a_id.hex(),
        },
        "continuations": continuations,
        "final_head_hex": final_head.hex(),
        "checkpoint": {"through_seq": cp_through, "head_hex": cp_head, "body_hex": cp_body.hex()},
        "flow_commit": {"final_head_hex": final_head.hex(), "body_hex": commit_body.hex()},
        "above_ceiling": above,
        "gap": gap,
        "replay": replay,
        "range_reject": range_reject,
        "checkpoint_overflow": checkpoint_overflow,
        "big_seq": big_seq,
        "minimal": minimal,
        "empty_vs_nonempty": empty_vs_nonempty,
        "keys_out_of_order": keys_out_of_order,
        "look_alike": look_alike,
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "continuation", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  continuations=%d final_head=%s... open_id=%s..." % (
        len(data["continuations"]), data["final_head_hex"][:16], data["flow_open"]["id_hex"][:16]))


if __name__ == "__main__":
    main()
