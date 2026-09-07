# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C19 — name bindings + the signed A2A task-state profile (design.md §22).

C19 is two receipt-chained, signed, OFFLINE-WALKABLE surfaces carried on N-AALP's own signed
object, reusing the C7 receipt-chain construction (design §8.1) unchanged:

  * naalp-name-binding {1: name, 2: signer, 3: seq, 4: prev} — a name-to-signer binding chained
    like an audit receipt: prev = SHA-384(previous binding body), genesis prev = 48 zero bytes,
    seq monotonic per name. A key ROTATION is a NEW binding chaining onto the prior one (a new
    signer at the next seq). The binding is DATED BY ITS CHAIN POSITION (seq); the envelope's
    `created` field is advisory only. A name's history is WALKABLE offline (the signer
    succession), and a deleted/omitted binding leaves a detectable HOLE at the first-broken
    position (gap-evident, exactly as the audit chain / directory fork report position). Two
    bindings by ONE authority at the SAME (name, seq) naming DIFFERENT signers are a FORK,
    reported at that seq position (as the §8.5 audit fork proof reports an equivocation position).

  * naalp-task-transition {1: task, 2: card, 3: from, 4: to, 5: seq, 6: prev} — one signed,
    receipt-CHAINED A2A task-lifecycle state transition. The A2A (Agent2Agent) TaskState set is
    an IMPORTED vocabulary (carriage, not adoption): submitted, working, input-required,
    auth-required, completed, canceled, failed, rejected. The A2A specification (spec §4.1.3)
    defines the state set and the terminal/interrupted categories NORMATIVELY (terminal =
    {completed, canceled, failed, rejected}; interrupted = {input-required, auth-required}; start
    = submitted) but leaves the exact legal edges to implementations; the edge set below is
    DERIVED from those documented category rules (active/interrupted -> interrupted/terminal;
    interrupted -> working; submitted -> working; terminal has no out-edge). `card` is the
    content-id of the A2A Agent Card attestation (a C18 naalp-description-import with format
    a2a-agent-card) that binds the task profile to an agent/operation. An illegal edge, a
    non-contiguous `from`, a transition out of a terminal state, or a gap/reorder in the chain is
    detected; a transition whose `card` differs from the bound card attestation is a foreign card.

Non-circular authority (NOT the code under test):
  * Every object body is built by the shared deterministic-CBOR constructor (cbor_oracle, graded
    against RFC 8949 in T1) — never by the Go/Rust naming code.
  * head = SHA-384(body); content-id = multihash(0x20, SHA-384(body)) (design §2.3) — computed
    here with standard-library hashlib. Genesis prev = 48 zero bytes (the C7 chain genesis).
  * The A2A state codes, terminal/interrupted categories, and the derived legal-edge set are
    fixed here from the A2A spec's documented state semantics (not read from the impl); Go and
    Rust grade their transition table against this independently-listed edge set.
  * The card attestation content-id is derived here from the A2A Agent Card import body built by
    cbor_oracle (the same field layout the C18 naalp-description-import uses), so Go/Rust
    description.Import.ID() == this card_id independently.
  * ML-DSA signatures are deterministic (FIPS 204, empty context) and cross-checked Go == Rust in
    the impl tests; Python stdlib has no ML-DSA, so this oracle fixes only the SIGNED INPUT (the
    body bytes), not the signature.

Emits vectors/naming/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

GENESIS = b"\x00" * 48  # SHA-384 width; the empty-chain prev (the C7 audit-chain genesis)

# Effect lattice (design §6): read_only < idempotent_write < non_idempotent_write < destructive.
READ_ONLY, IDEMPOTENT_WRITE, NON_IDEMPOTENT_WRITE, DESTRUCTIVE = 0, 1, 2, 3

# Foreign description format codes (design §21; naalp-description-format registry). The card
# attestation carries an A2A Agent Card (format 1).
FMT_A2A_CARD = 1

# A2A TaskState codes — the imported A2A vocabulary (carriage, not adoption). The state SET and
# the terminal/interrupted categories are from the A2A spec §4.1.3.
SUBMITTED, WORKING, INPUT_REQUIRED, AUTH_REQUIRED = 0, 1, 2, 3
COMPLETED, CANCELED, FAILED, REJECTED = 4, 5, 6, 7
START = SUBMITTED
ACTIVE = (SUBMITTED, WORKING)
INTERRUPTED = (INPUT_REQUIRED, AUTH_REQUIRED)
TERMINAL = (COMPLETED, CANCELED, FAILED, REJECTED)


def sha384(b):
    return hashlib.sha384(b).digest()


def cid(b):
    """T1 content-id framing: multihash(0x20, SHA-384(bytes)) = 0x20 0x30 || SHA-384(b) (50 octets)."""
    return b"\x20\x30" + sha384(b)


# ---- name bindings ---------------------------------------------------------------------------

def binding_body(name, signer, seq, prev):
    # {1: name (tstr), 2: signer (bstr), 3: seq (uint), 4: prev (bstr, 48 octets; genesis zero)}.
    return cbor_oracle.encode(("map", [(1, name), (2, signer), (3, seq), (4, prev)]))


def first_hole_position(seqs):
    """The first index at which a presented (possibly gappy) binding list breaks contiguity: the
    index i where the i-th presented binding's seq != i. Returns (-1, False) when contiguous."""
    for i, s in enumerate(seqs):
        if s != i:
            return i, True
    return -1, False


# ---- A2A task transitions --------------------------------------------------------------------

def transition_body(task, card, frm, to, seq, prev):
    # {1: task (bstr), 2: card (bstr, content-id), 3: from (state), 4: to (state), 5: seq, 6: prev}.
    return cbor_oracle.encode(("map", [(1, task), (2, card), (3, frm), (4, to), (5, seq), (6, prev)]))


def operation_body(name, effect, requires_approval):
    return ("map", [(1, name), (2, effect), (3, requires_approval)])


def import_body(importer, fmt, foreign, operations):
    # The C18 naalp-description-import layout {1:importer,2:format,3:foreign,4:[operation]}; the
    # card attestation content-id is derived from this body, independent of the impl.
    ops = [operation_body(*op) for op in operations]
    return cbor_oracle.encode(("map", [(1, importer), (2, fmt), (3, foreign), (4, ops)]))


def legal_edges():
    """The derived A2A legal-edge set (see module docstring): from the documented category rules.
    submitted -> working; active/interrupted -> interrupted (active only) / terminal; interrupted
    -> working; terminal -> nothing; no self-loops."""
    edges = []
    edges.append((SUBMITTED, WORKING))                       # begin processing (the only active->active edge)
    for s in ACTIVE:                                         # active -> interrupted
        for t in INTERRUPTED:
            edges.append((s, t))
    for s in ACTIVE:                                         # active -> terminal
        for t in TERMINAL:
            edges.append((s, t))
    for s in INTERRUPTED:                                    # interrupted -> working (client acted)
        edges.append((s, WORKING))
    for s in INTERRUPTED:                                    # interrupted -> terminal
        for t in TERMINAL:
            edges.append((s, t))
    return edges


def illegal_edges():
    """A representative set of edges the table MUST reject: terminal out-edges, return-to-submitted,
    interrupted->interrupted, self-loops, interrupted->submitted, and an out-of-range state."""
    return [
        (COMPLETED, WORKING),        # terminal has no out-edge
        (CANCELED, WORKING),
        (FAILED, WORKING),
        (REJECTED, WORKING),
        (WORKING, SUBMITTED),        # cannot return to the start state
        (INPUT_REQUIRED, AUTH_REQUIRED),  # interrupted -> interrupted is not allowed
        (AUTH_REQUIRED, INPUT_REQUIRED),
        (WORKING, WORKING),          # no self-loop
        (SUBMITTED, SUBMITTED),      # no self-loop
        (INPUT_REQUIRED, SUBMITTED), # interrupted -> submitted is not allowed
        (SUBMITTED, 8),              # 8 is not a defined A2A state
    ]


def build():
    # ---- name-binding chain (rotation A -> B -> C), dated by chain position -------------------
    name = "agent.billing.example"
    signer_a = b"SIGNER_KEY_A"
    signer_b = b"SIGNER_KEY_B"
    signer_c = b"SIGNER_KEY_C"
    signer_x = b"SIGNER_KEY_X"  # the equivocating (fork) successor at seq 1

    b0 = binding_body(name, signer_a, 0, GENESIS)
    h0 = sha384(b0)
    b1 = binding_body(name, signer_b, 1, h0)  # rotation A -> B
    h1 = sha384(b1)
    b2 = binding_body(name, signer_c, 2, h1)  # rotation B -> C
    h2 = sha384(b2)

    bindings = [
        {"seq": 0, "signer_hex": signer_a.hex(), "prev_hex": GENESIS.hex(),
         "body_hex": b0.hex(), "head_hex": h0.hex(), "id_hex": cid(b0).hex()},
        {"seq": 1, "signer_hex": signer_b.hex(), "prev_hex": h0.hex(),
         "body_hex": b1.hex(), "head_hex": h1.hex(), "id_hex": cid(b1).hex()},
        {"seq": 2, "signer_hex": signer_c.hex(), "prev_hex": h1.hex(),
         "body_hex": b2.hex(), "head_hex": h2.hex(), "id_hex": cid(b2).hex()},
    ]
    walk = [{"seq": bd["seq"], "signer_hex": bd["signer_hex"]} for bd in bindings]

    # Hole: a deleted binding at seq 1 leaves the presented list [b0(seq0), b2(seq2)] non-contiguous
    # at position 1 (b2.seq == 2 != 1, and b2.prev == h1 != h0).
    hole_present_seqs = [0, 2]
    hole_pos, hole_is = first_hole_position(hole_present_seqs)
    assert hole_is and hole_pos == 1, "expected a detected hole at position 1"

    # Fork: two bindings by ONE authority at the SAME (name, seq=1) naming DIFFERENT signers (B vs X),
    # both chaining onto h0 — an equivocation reported at seq position 1.
    b1p = binding_body(name, signer_x, 1, h0)
    fork = {
        "b_prime": {"seq": 1, "signer_hex": signer_x.hex(), "prev_hex": h0.hex(),
                    "body_hex": b1p.hex(), "head_hex": sha384(b1p).hex()},
        "position": 1,
        "note": "same name + seq 1, signer B vs signer X, both prev == head(binding 0) => fork at seq 1.",
    }

    # ---- the A2A Agent Card attestation (a C18 import, format a2a-agent-card) -----------------
    importer = b"IMPORTER_ID_A"
    # A carried A2A Agent Card, octet-for-octet (carriage, not adoption).
    foreign = (b'{"protocolVersion":"0.2.5","name":"billing-agent",'
               b'"url":"https://agent.example/a2a",'
               b'"skills":[{"id":"submit","name":"Submit invoice"},'
               b'{"id":"get","name":"Get status"}]}')
    card_ops = [
        ("submit", IDEMPOTENT_WRITE, 1),  # the A2A skill "submit" maps to idempotent_write, approval
        ("get",    READ_ONLY,        0),  # the A2A skill "get" maps to read_only, no approval
    ]
    card_import = import_body(importer, FMT_A2A_CARD, foreign, card_ops)
    card_id = cid(card_import)  # the attestation content-id the task profile binds

    # ---- the A2A transition chain (dated by chain position; card-bound) -----------------------
    task = b"task-0001"
    edges_in_chain = [
        (SUBMITTED, WORKING),          # seq 0: submitted -> working
        (WORKING, INPUT_REQUIRED),     # seq 1: working -> input-required (interrupted)
        (INPUT_REQUIRED, WORKING),     # seq 2: input-required -> working (client provided input)
        (WORKING, COMPLETED),          # seq 3: working -> completed (terminal)
    ]
    legal_set = set(legal_edges())
    for e in edges_in_chain:
        assert e in legal_set, "chain edge %r must be legal" % (e,)

    transitions = []
    prev = GENESIS
    for seq, (frm, to) in enumerate(edges_in_chain):
        body = transition_body(task, card_id, frm, to, seq, prev)
        h = sha384(body)
        transitions.append({
            "seq": seq, "from": frm, "to": to, "prev_hex": prev.hex(),
            "body_hex": body.hex(), "head_hex": h.hex(), "id_hex": cid(body).hex(),
        })
        prev = h

    # Gap: a deleted transition at seq 1 leaves the presented list [t0(seq0), t2(seq2)] broken at
    # position 1.
    gap_present_seqs = [0, 2]
    gap_pos, gap_is = first_hole_position(gap_present_seqs)
    assert gap_is and gap_pos == 1, "expected a detected transition gap at position 1"

    # A foreign card id (a different attestation) the chain verifier must reject as a foreign card.
    foreign_card_id = cid(import_body(b"IMPORTER_ID_B", FMT_A2A_CARD, foreign, card_ops))
    assert foreign_card_id != card_id

    # ---- Oversized-counter round-trip (Phase 6 edge case #3, the >2^53 discipline): a name-binding
    # seq and a task-transition seq above 2^53. 0x0102030405060708 = 72623859790382856 > 2^53. Both
    # MUST round-trip byte-exact through both impls (uint64/u64, no float64). Carried as JSON STRINGS
    # (a float64 JSON decoder would round the low octets); this oracle uses Python arbitrary-precision.
    BIG_SEQ = 0x0102030405060708
    assert BIG_SEQ > (1 << 53)
    big_bind_body = binding_body(name, signer_a, BIG_SEQ, GENESIS)
    big_binding = {
        "seq_str": str(BIG_SEQ), "signer_hex": signer_a.hex(), "prev_hex": GENESIS.hex(),
        "body_hex": big_bind_body.hex(), "head_hex": sha384(big_bind_body).hex(),
        "id_hex": cid(big_bind_body).hex(),
        "note": "name-binding seq = 0x0102030405060708 (>2^53) round-trips byte-exact; carried as a string.",
    }
    big_trans_body = transition_body(task, card_id, SUBMITTED, WORKING, BIG_SEQ, GENESIS)
    big_transition = {
        "seq_str": str(BIG_SEQ), "from": SUBMITTED, "to": WORKING, "prev_hex": GENESIS.hex(),
        "body_hex": big_trans_body.hex(), "head_hex": sha384(big_trans_body).hex(),
        "id_hex": cid(big_trans_body).hex(),
        "note": "task-transition seq = 0x0102030405060708 (>2^53) round-trips byte-exact; carried as a string.",
    }

    # ---- Minimal objects (Phase 6 edge case #4): the smallest valid binding (empty name, empty
    # signer, seq 0, genesis prev) and the smallest valid transition (empty task/card, submitted->
    # working, seq 0, genesis prev). Both encode + reconstruct + have stable content-ids.
    min_bind_body = binding_body("", b"", 0, GENESIS)
    minimal_binding = {
        "name_utf8": "", "signer_hex": "", "seq": 0, "prev_hex": GENESIS.hex(),
        "body_hex": min_bind_body.hex(), "head_hex": sha384(min_bind_body).hex(),
        "id_hex": cid(min_bind_body).hex(),
    }
    min_trans_body = transition_body(b"", b"", SUBMITTED, WORKING, 0, GENESIS)
    minimal_transition = {
        "task_hex": "", "card_hex": "", "from": SUBMITTED, "to": WORKING, "seq": 0, "prev_hex": GENESIS.hex(),
        "body_hex": min_trans_body.hex(), "head_hex": sha384(min_trans_body).hex(),
        "id_hex": cid(min_trans_body).hex(),
    }

    # ---- Keys-out-of-order (Phase 6 edge case #1): a hand-built name-binding body with map keys in
    # DESCENDING order (4,3,2,1). Same content as b0; the strict decoder MUST reject it NonCanonical.
    kv = {
        1: cbor_oracle.encode(name),
        2: cbor_oracle.encode(signer_a),
        3: cbor_oracle.encode(0),
        4: cbor_oracle.encode(GENESIS),
    }
    noncanon_binding = bytes([0xA4])  # map, 4 pairs
    for k in (4, 3, 2, 1):  # descending key order
        noncanon_binding += cbor_oracle.encode(k) + kv[k]
    assert noncanon_binding != b0 and len(noncanon_binding) == len(b0)
    keys_out_of_order = {
        "canonical_binding_body_hex": b0.hex(),
        "noncanonical_binding_body_hex": noncanon_binding.hex(),
        "reject": "NonCanonical",
        "note": "same content, keys emitted 4,3,2,1 (descending) — the strict decoder rejects NonCanonical.",
    }

    # ---- Look-alike (Phase 6 edge case #5): a 4-field name-binding body fed to ParseTransition (which
    # expects 6 fields) is rejected; a 6-field transition body fed to ParseNameBinding is rejected.
    look_alike = {
        "binding_body_hex": b0.hex(),
        "transition_body_hex": transitions[0]["body_hex"],
        "note": "a 4-field binding fed to ParseTransition and a 6-field transition fed to ParseNameBinding are both rejected.",
    }

    return {
        "source": ("design §22; naalp-name-binding {1:name,2:signer,3:seq,4:prev} chained like the "
                   "C7 audit receipt (head=SHA-384(body); genesis prev=48 zero bytes; seq monotonic; "
                   "dated by chain position, envelope created advisory); rotation = a new binding "
                   "chaining on; hole detected at the first-broken position; fork = one authority at "
                   "the same (name,seq) naming different signers, reported at that seq. "
                   "naalp-task-transition {1:task,2:card,3:from,4:to,5:seq,6:prev} = one receipt-"
                   "chained A2A state transition; A2A TaskState is an imported vocabulary (spec "
                   "§4.1.3: start=submitted; terminal={completed,canceled,failed,rejected}; "
                   "interrupted={input-required,auth-required}); legal edges derived from those "
                   "category rules; card = content-id of the A2A Agent Card import (C18). "
                   "head=SHA-384(body); content-id=multihash(0x20,SHA-384)."),
        "name": {
            "name_utf8": name,
            "genesis_prev_hex": GENESIS.hex(),
            "bindings": bindings,
            "walk": walk,
            "hole": {"present_seqs": hole_present_seqs, "first_hole_position": hole_pos,
                     "note": "a deleted binding at seq 1 breaks contiguity at position 1."},
            "fork": fork,
            "big_seq": big_binding,
            "minimal": minimal_binding,
            "keys_out_of_order": keys_out_of_order,
            "look_alike": look_alike,
        },
        "a2a": {
            "states": {
                "submitted": SUBMITTED, "working": WORKING, "input_required": INPUT_REQUIRED,
                "auth_required": AUTH_REQUIRED, "completed": COMPLETED, "canceled": CANCELED,
                "failed": FAILED, "rejected": REJECTED,
                "start": START, "terminal": list(TERMINAL), "interrupted": list(INTERRUPTED),
            },
            "legal_edges": [list(e) for e in legal_edges()],
            "illegal_edges": [list(e) for e in illegal_edges()],
            "card": {
                "importer_hex": importer.hex(),
                "format": FMT_A2A_CARD,
                "foreign_hex": foreign.hex(),
                "operations": [{"name": n, "effect": e, "requires_approval": r} for (n, e, r) in card_ops],
                "import_body_hex": card_import.hex(),
                "card_id_hex": card_id.hex(),
                "note": ("the A2A Agent Card import (C18, format a2a-agent-card); the task profile "
                         "binds to this attestation's content-id (import.ID())."),
            },
            "task_utf8": task.decode(),
            "genesis_prev_hex": GENESIS.hex(),
            "transitions": transitions,
            "gap": {"present_seqs": gap_present_seqs, "first_gap_position": gap_pos,
                    "note": "a deleted transition at seq 1 breaks contiguity at position 1."},
            "foreign_card_id_hex": foreign_card_id.hex(),
            "big_seq": big_transition,
            "minimal": minimal_transition,
        },
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "naming", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  name %s: %d bindings, walk %d, hole@%d, fork@%d" % (
        data["name"]["name_utf8"], len(data["name"]["bindings"]), len(data["name"]["walk"]),
        data["name"]["hole"]["first_hole_position"], data["name"]["fork"]["position"]))
    print("  a2a: %d legal edges, %d illegal edges, %d transitions, gap@%d, card_id=%s..." % (
        len(data["a2a"]["legal_edges"]), len(data["a2a"]["illegal_edges"]),
        len(data["a2a"]["transitions"]), data["a2a"]["gap"]["first_gap_position"],
        data["a2a"]["card"]["card_id_hex"][:16]))


if __name__ == "__main__":
    main()
