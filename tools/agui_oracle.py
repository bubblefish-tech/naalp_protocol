# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C21 task 5B.2 — NAALP-AGUI UI-consent binding (design.md §24).

NAALP-AGUI binds a human-in-the-loop approval, captured in a user-interface event stream (the AG-UI
tool-lifecycle events an agent shows a user), to the EXACT action bytes by content-id, and RECEIPT-
CHAINS the shown events so the shown sequence is provable offline. It reuses the C7 audit receipt-
chain construction (§8.1) unchanged — head = SHA-384(body), genesis prev = 48 zero bytes, a monotonic
seq, the prior head carried in `prev` so editing or omitting an event breaks the next event's linkage —
and the §7 approval binding, adding NO new mechanism:

  * naalp-ui-event {1: session, 2: kind, 3: action, 4: seq, 5: prev} — one shown tool-lifecycle event.
    `kind` is a closed set (shown / args-shown / approved / rejected); `action` is the T1 content-id of
    the action bytes shown to the user at this step; the chain is receipt-chained by `prev`/`seq`.

The load-bearing properties, graded by both implementations:
  * A UI approval verifies ONLY against the EXACT action shown: the executed action's content-id MUST
    equal the shown+approved event's `action`, else the substitution is rejected (ActionSubstituted).
  * A removed/omitted shown-event is detected with its POSITION (a chain hole), the same way the §8.5
    audit fork proof and the §22 name-history hole report a position.

Non-circular authority (NOT the code under test):
  * Every body is built by the shared deterministic-CBOR constructor (cbor_oracle, graded against
    RFC 8949 in T1) — never by the Go/Rust agui code.
  * head = SHA-384(body); content-id = multihash(0x20, SHA-384(body)) (design §2.3); the action
    content-id = multihash(0x20, SHA-384(action bytes)) — all computed here with stdlib hashlib.
  * The event-kind vocabulary and the chain heads / hole position are fixed here from the design.
  * The human approval is the §7 primitive (graded in the approval oracle); this oracle fixes the
    action content-id the approval binds (the shown+approved event's `action`).

Emits vectors/agui/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

GENESIS = b"\x00" * 48  # SHA-384 output width; the empty-chain prev

# Closed UI-event-kind vocabulary (AG-UI tool-lifecycle events transcribed to the spine). A kind
# outside the set is rejected (UnknownUIEventKind).
KIND_SHOWN, KIND_ARGS_SHOWN, KIND_APPROVED, KIND_REJECTED = 0, 1, 2, 3
UNKNOWN_KIND = 99
KIND_VOCAB = [
    ("shown", KIND_SHOWN),
    ("args-shown", KIND_ARGS_SHOWN),
    ("approved", KIND_APPROVED),
    ("rejected", KIND_REJECTED),
]


def sha384(b):
    return hashlib.sha384(b).digest()


def cid(b):
    """T1 content-id framing: multihash(0x20, SHA-384(bytes)) = 0x20 0x30 || SHA-384(b) (50 octets)."""
    return b"\x20\x30" + sha384(b)


def noncanon_map(pairs):
    """Hand-build a CBOR map carrying the SAME pairs but with top-level keys emitted in DESCENDING
    order — non-canonical per RFC 8949 §4.2.1 (the strict shared decoder rejects it NonCanonical).
    `pairs` is the canonical ascending list [(k, v), ...]; built by hand, NOT via cbor_oracle.encode."""
    n = len(pairs)
    assert n < 24
    out = bytes([0xA0 | n])
    for (k, v) in reversed(pairs):
        out += cbor_oracle.encode(k) + cbor_oracle.encode(v)
    return out


def event_body(session, kind, action, seq, prev):
    # {1: session (bstr), 2: kind (uint), 3: action (bstr, content-id), 4: seq (uint), 5: prev (bstr)}.
    return cbor_oracle.encode(("map", [(1, session), (2, kind), (3, action), (4, seq), (5, prev)]))


def event_out(session, kind, action, seq, prev):
    body = event_body(session, kind, action, seq, prev)
    return {
        "kind": kind, "seq": seq, "prev_hex": prev.hex(), "action_hex": action.hex(),
        "body_hex": body.hex(), "head_hex": sha384(body).hex(), "id_hex": cid(body).hex(),
    }


def build_edge_cases(session, action_cid):
    """Standard wire-format edge cases (Part 1). #3 (oversized) and #4 (minimal) are already emitted
    above; this adds:
      #1 keys-out-of-order: a ui-event body whose top-level keys are DESCENDING (5,4,3,2,1) — rejected
         NonCanonical by the strict shared decoder ParseUIEvent routes through.
      #2 empty-vs-absent (the action field 3, a bstr): an empty action is PRESENT and valid and is
         DISTINCT by content-id from a populated one, and BOTH differ from a body whose action field is
         ABSENT (rejected UIMalformed — field 3 is mandatory).
      #5 look-alike: NAALP-AGUI defines a SINGLE body kind, so the look-alike is a near-miss — a
         ui-event-shaped body lacking its field-5 chain back-pointer (`prev`), which a lax parser would
         admit as an unchained event; ParseUIEvent rejects it UIMalformed."""
    # #1 keys-out-of-order over a shown ui-event (seq 0, genesis prev).
    koo_pairs = [(1, session), (2, KIND_SHOWN), (3, action_cid), (4, 0), (5, GENESIS)]
    koo_canon = event_body(session, KIND_SHOWN, action_cid, 0, GENESIS)
    koo_noncanon = noncanon_map(koo_pairs)
    assert koo_noncanon != koo_canon and len(koo_noncanon) == len(koo_canon)
    keys_out_of_order = {
        "action_hex": action_cid.hex(),
        "canonical_body_hex": koo_canon.hex(),
        "noncanonical_body_hex": koo_noncanon.hex(),
        "reject": "NonCanonical",
        "note": "same content, top-level keys emitted descending (5,4,3,2,1) - the strict decoder rejects NonCanonical.",
    }

    # #2 empty-vs-absent (action field 3).
    empty_action = event_body(session, KIND_SHOWN, b"", 0, GENESIS)
    populated_action = event_body(session, KIND_SHOWN, action_cid, 0, GENESIS)
    absent_action = cbor_oracle.encode(("map", [(1, session), (2, KIND_SHOWN), (4, 0), (5, GENESIS)]))  # field 3 OMITTED
    assert empty_action != populated_action != absent_action and empty_action != absent_action
    empty_vs_absent = {
        "empty_action": {"body_hex": empty_action.hex(), "id_hex": cid(empty_action).hex()},
        "populated_action": {"action_hex": action_cid.hex(), "body_hex": populated_action.hex(), "id_hex": cid(populated_action).hex()},
        "absent_field": {"body_hex": absent_action.hex(), "reject": "UIMalformed"},
        "note": ("an empty action bstr is present and valid, distinct by content-id from a populated one; "
                 "both differ from a body whose action field is absent (rejected - field 3 is mandatory)."),
    }

    # #5 look-alike: a ui-event missing field 5 (prev) — a near-miss (agui has one body kind).
    la_body = cbor_oracle.encode(("map", [(1, session), (2, KIND_SHOWN), (3, action_cid), (4, 0)]))  # field 5 OMITTED
    look_alike = {
        "body_hex": la_body.hex(),
        "reject": "UIMalformed",
        "note": "a ui-event-shaped body lacking its field-5 chain back-pointer (prev) is rejected UIMalformed.",
    }

    return {
        "keys_out_of_order": keys_out_of_order,
        "empty_vs_absent": empty_vs_absent,
        "look_alike": look_alike,
        "done_note": "edge cases #3 (oversized seq) and #4 (minimal) are emitted as top-level big_seq/minimal.",
    }


def build():
    session = b"ui-sess-0001"

    # The action shown to the user (a tool-call the agent proposes). The whole UI stream names its
    # content-id; the human approves THAT content-id.
    action_bytes = b'{"tool":"transfer_funds","args":{"to":"acct-42","amount":"19.99"}}'
    action_cid = cid(action_bytes)
    # A SUBSTITUTED action (a different destination) — a different content-id. Executing this after the
    # user approved `action_bytes` is the substitution the profile rejects.
    substituted_bytes = b'{"tool":"transfer_funds","args":{"to":"acct-99","amount":"19.99"}}'
    substituted_cid = cid(substituted_bytes)
    assert substituted_cid != action_cid

    # The shown chain: shown -> args-shown -> approved, receipt-chained by prev/seq. Every event names
    # the SAME action content-id (what the user saw and approved).
    ev0 = event_out(session, KIND_SHOWN, action_cid, 0, GENESIS)
    h0 = bytes.fromhex(ev0["head_hex"])
    ev1 = event_out(session, KIND_ARGS_SHOWN, action_cid, 1, h0)
    h1 = bytes.fromhex(ev1["head_hex"])
    ev2 = event_out(session, KIND_APPROVED, action_cid, 2, h1)
    h2 = bytes.fromhex(ev2["head_hex"])

    # A gappy chain [ev0, ev2] with ev1 OMITTED: at presented index 1, ev2.seq=2 != 1 (and its prev
    # does not link to ev0's head), so the hole is detected at position 1.
    hole_chain = ["ev0", "ev2"]
    hole_position = 1

    vocab = [{"name": n, "code": c} for (n, c) in KIND_VOCAB]

    # ---- Oversized-counter round-trip (Phase 6 edge case #3, the >2^53 discipline): a UI-event seq
    # above 2^53. 0x0102030405060708 = 72623859790382856 > 2^53. It MUST round-trip byte-exact
    # (uint64/u64, no float64). Carried as a JSON STRING (a float64 decoder rounds it); this oracle
    # uses Python arbitrary-precision.
    BIG_SEQ = 0x0102030405060708
    assert BIG_SEQ > (1 << 53)
    big_body = event_body(session, KIND_SHOWN, action_cid, BIG_SEQ, GENESIS)
    big_seq = {
        "seq_str": str(BIG_SEQ), "kind": KIND_SHOWN, "action_hex": action_cid.hex(), "prev_hex": GENESIS.hex(),
        "body_hex": big_body.hex(), "head_hex": sha384(big_body).hex(), "id_hex": cid(big_body).hex(),
        "note": "ui-event seq = 0x0102030405060708 (>2^53) round-trips byte-exact; carried as a string.",
    }

    # ---- Minimal object (Phase 6 edge case #4): the smallest valid ui-event — empty session, kind
    # shown, empty action, seq 0, genesis prev. It encodes, reconstructs, and has a stable content-id.
    min_body = event_body(b"", KIND_SHOWN, b"", 0, GENESIS)
    minimal = {
        "session_hex": "", "kind": KIND_SHOWN, "action_hex": "", "seq": 0, "prev_hex": GENESIS.hex(),
        "body_hex": min_body.hex(), "head_hex": sha384(min_body).hex(), "id_hex": cid(min_body).hex(),
    }

    return {
        "source": ("design §24; naalp-ui-event {1:session,2:kind,3:action,4:seq,5:prev} is a receipt-"
                   "chained shown tool-lifecycle event (C7 chain: head=SHA-384(body), genesis prev=48 "
                   "zero bytes, prior head in field 5); the shown+approved event names the action's T1 "
                   "content-id, and a §7 human approval binds THAT content-id — a substituted action "
                   "(different content-id) is rejected (ActionSubstituted); an omitted shown-event is a "
                   "detectable hole with position. head=SHA-384(body); content-id=multihash(0x20,SHA-384)."),
        "genesis_hex": GENESIS.hex(),
        "kind_vocabulary": vocab,
        "unknown_kind": UNKNOWN_KIND,
        "session_hex": session.hex(),
        "action_bytes_hex": action_bytes.hex(),
        "action_cid_hex": action_cid.hex(),
        "substituted_bytes_hex": substituted_bytes.hex(),
        "substituted_cid_hex": substituted_cid.hex(),
        "chain": {"events": [ev0, ev1, ev2], "final_head_hex": h2.hex()},
        "big_seq": big_seq,
        "minimal": minimal,
        "edge_cases": build_edge_cases(session, action_cid),
        "hole": {"present_indices": hole_chain, "position": hole_position},
        "note": ("the shown chain proves action_cid_hex was shown to the user; the human approval binds "
                 "action_cid_hex; executing substituted_bytes_hex (a different content-id) is "
                 "ActionSubstituted; omitting event ev1 leaves a hole detected at position 1."),
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "agui", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  action cid=%s... substituted cid=%s..." % (data["action_cid_hex"][:16], data["substituted_cid_hex"][:16]))
    print("  chain: %d events, hole at position %d" % (len(data["chain"]["events"]), data["hole"]["position"]))


if __name__ == "__main__":
    main()
