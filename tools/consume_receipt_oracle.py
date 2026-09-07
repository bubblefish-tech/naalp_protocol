# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for T1.5 — the ledger-signed consume receipt with forward-only position
(NAALP-REQ-121; coding-instructions §1.3). It is the non-circular authority the two reference
implementations (impl/go/approval, impl/rust/src/approval.rs) are graded against: Go == Rust ==
oracle on every consume-receipt body, AND Go == Rust == oracle on every fork/benign verdict.

WHAT the consume receipt IS (coding-instructions §1.3, NAALP-REQ-121). The single-use consume
ledger already rejects a second spend of one approval on ONE reachable ledger (C6, AlreadyConsumed).
REQ-121 makes a double-spend *provable across a partition*: it moves the anti-double-spend counter
OFF the requester and ONTO the consuming ledger (the ordering authority). A consume receipt binds

    { 1: ledger, 2: approval_id, 3: position }

  * ledger      — the consuming ledger's own signer id (the ORDERING AUTHORITY; never the requester)
  * approval_id — the approval content id consumed (the compare-and-set key)
  * position    — the ledger's own FORWARD-ONLY position bound to this consume

and is SIGNED BY THE LEDGER key over those exact bytes. Because the requester cannot forge the
ledger's position or signature, a partition that spends one approval twice leaves TWO ledger-signed
receipts against ONE approval id, each carrying a position drawn from forked state — a contradiction
authored by neither the requester nor a thief, provable the instant the two receipts are compared.
It does not PREVENT the second spend (both sides complete); it makes the double-spend detectable in
bytes neither party could repudiate, and approvals carry an expiry so the exposure window is bounded
(coding-instructions §1.1). Keyed by approval content id, FIRST-APPEND-WINS: on a single reachable
ledger the first consume assigns exactly one position and one receipt; a byte-identical re-emission
is a benign duplicate, and a second receipt for the same approval id with a DIFFERENT position (or a
DIFFERENT ledger) is a detected FORK, never silently accepted.

THE FORK VERDICT (independent model, from the §1.3 text). Two ledger-signed receipts are a FORK iff
they name the SAME approval id and are NOT byte-identical — i.e. they conflict in position and/or in
ledger id. Same approval id + byte-identical bytes = a benign duplicate (a ledger re-presenting its
own receipt). Different approval ids = two independent consumes, not a fork. The double-spend the
protocol makes provable is exactly "one single-use approval id, two distinct ledger-signed receipts".

NON-CIRCULARITY (project standing rule; F3). This file is written from the §1.3 text and shares
NO code with impl/go or impl/rust (it does not import them). Receipt bodies are built by the shared
deterministic-CBOR constructor (cbor_oracle, itself graded against RFC 8949 §4.2.1 in T1); approval
ids use the T1 content-id framing multihash(0x20, SHA-384(...)) (design.md §2.3). The fork/benign
VERDICT for every receipt pair comes from the from-scratch `is_fork()` model below, read directly
from the requirement text — never from the code under test.

THE LEDGER SIGNATURE. The bytes the ledger signs (the receipt body, field 1..3) are reproduced by
this oracle byte-for-byte, so an impl that mis-frames the signed input diverges here. Python has no
deterministic FIPS-204 ML-DSA in this oracle set (as with cbor/cose/audit), so the signature BYTES
themselves are graded the established non-circular way: the two reference implementations sign the
same body with the same NIST-anchored seed and MUST produce byte-identical signatures (deterministic
ML-DSA, rnd=0), each verifying under the ledger key (the cose.sign1 consensus, anchored to the NIST
keyGen KAT). Go==oracle and Rust==oracle on the signed body ⟹ Go==Rust on the signature. The impls
run VerifyConsumeReceipt (accept a valid ledger signature; fail-closed on an unnamed ledger, a wrong
key, or a tampered signature) with real crypto.

Emits vectors/consume_receipt/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

enc = cbor_oracle.encode

# Consume-receipt body field numbers (coding-instructions §1.3, NAALP-REQ-121).
FIELD_LEDGER = 1       # the consuming ledger's signer id (the ordering authority)
FIELD_APPROVAL_ID = 2  # the approval content id consumed (the CAS key)
FIELD_POSITION = 3     # the ledger's forward-only position bound to this consume

# Worked ledger signer ids — opaque authority ids in the envelope field-5 form (the real key is
# C4/T4). Chosen so the framing is independently reproducible; the ledger ML-DSA signature is graded
# by the two-implementation deterministic byte-parity (see the module docstring).
LEDGER_A = b"\x4c\x45\x44\x47\x45\x52\x30\x31"  # "LEDGER01"
LEDGER_B = b"\x4c\x45\x44\x47\x45\x52\x30\x32"  # "LEDGER02" — a distinct ordering authority


def cid(name):
    """Content id (T1 framing, design.md §2.3) of a tiny worked object {1: name}. Stands for an
    approval content id — an opaque 50-byte id whose provenance is the approval object (graded in
    C6); the receipt only binds the id, so its internal structure is immaterial here."""
    b = enc(("map", [(1, name)]))
    return b"\x20\x30" + hashlib.sha384(b).digest()


def receipt_bytes(ledger, approval_id, position):
    """Deterministic-CBOR encoding of the consume-receipt body {1: ledger, 2: approval_id,
    3: position} — the exact bytes the ledger signs (REQ-121)."""
    return enc(("map", [
        (FIELD_LEDGER, ledger),
        (FIELD_APPROVAL_ID, approval_id),
        (FIELD_POSITION, position),
    ]))


def is_fork(a, b):
    """The independent fork verdict (from the §1.3 text): two ledger-signed receipts are a FORK iff
    they name the SAME approval id and are NOT byte-identical (conflict in position and/or ledger).
    `a` and `b` are (ledger, approval_id, position) tuples."""
    same_approval = a[1] == b[1]
    identical = receipt_bytes(*a) == receipt_bytes(*b)
    return same_approval and not identical


def receipt_case(name, ledger, approval_id, position, note):
    body = receipt_bytes(ledger, approval_id, position)
    return {
        "name": name,
        "note": note,
        "ledger_hex": ledger.hex(),
        "approval_id_hex": approval_id.hex(),
        "position": position,
        "body_hex": body.hex(),
    }


def fork_case(name, a, b, note):
    """a, b are (ledger, approval_id, position) tuples."""
    verdict = "fork" if is_fork(a, b) else "benign"
    return {
        "name": name,
        "note": note,
        "a": {"ledger_hex": a[0].hex(), "approval_id_hex": a[1].hex(), "position": a[2],
              "body_hex": receipt_bytes(*a).hex()},
        "b": {"ledger_hex": b[0].hex(), "approval_id_hex": b[1].hex(), "position": b[2],
              "body_hex": receipt_bytes(*b).hex()},
        "expect": verdict,
    }


def build_wire_cases(approval_x):
    """Section-4 wire-format cases: keys out of order (non-canonical reject), a position too large
    for a receiving language's normal integer, and empty-value vs absent-value (empty != absent)."""
    # keys out of order: the receipt body with keys {3,2,1} in NON-canonical descending order. The
    # deterministic decoder MUST reject it (NonCanonical) BEFORE any receipt rule runs (R-3.1).
    canonical = receipt_bytes(LEDGER_A, approval_x, 5)
    # hand-build a 3-key map with keys emitted 3,2,1 (canonical requires 1,2,3 ascending).
    noncanon = cbor_oracle.enc_head(5, 3)
    noncanon += enc(FIELD_POSITION) + enc(5)
    noncanon += enc(FIELD_APPROVAL_ID) + enc(approval_x)
    noncanon += enc(FIELD_LEDGER) + enc(LEDGER_A)

    # position too large for a normal int: 2^53 (beyond a float64/JS-safe integer) and 2^64-1
    # (max uint64). A receiving language MUST decode these as a 64-bit unsigned position, not round.
    big_53 = receipt_bytes(LEDGER_A, approval_x, 1 << 53)
    big_max = receipt_bytes(LEDGER_A, approval_x, (1 << 64) - 1)

    # empty value vs absent value (empty != absent; design.md §3.3, R-3.3). An EMPTY ledger id
    # (present, zero-length bstr) is a well-formed receipt whose bytes differ from a non-empty one
    # and which VerifyConsumeReceipt REJECTS fail-closed (an unnamed ordering authority is not
    # evidence). An ABSENT ledger field (a 2-key map missing key 1) is a structurally different,
    # malformed receipt — distinct bytes again. The pair isolates the single variable.
    empty_ledger = receipt_bytes(b"", approval_x, 5)
    absent_ledger = enc(("map", [(FIELD_APPROVAL_ID, approval_x), (FIELD_POSITION, 5)]))
    assert empty_ledger != absent_ledger, "empty ledger id must differ from an absent ledger field"

    return {
        "keys_out_of_order": {
            "note": "receipt body with keys emitted 3,2,1 (non-canonical) -> the decoder rejects "
                    "NonCanonical before any receipt rule runs",
            "payload_hex": noncanon.hex(),
            "canonical_payload_hex": canonical.hex(),
            "expect": "NonCanonical",
        },
        "position_too_large": [
            {"name": "position_2_53", "position": 1 << 53, "body_hex": big_53.hex(),
             "note": "position 2^53 (beyond a JS/float64-safe integer) decodes as a 64-bit uint"},
            {"name": "position_uint64_max", "position": (1 << 64) - 1, "body_hex": big_max.hex(),
             "note": "position 2^64-1 (max uint64) decodes without overflow/round"},
        ],
        "empty_ledger": {
            "note": "ledger id present-but-empty (zero-length bstr): well-formed bytes, but "
                    "VerifyConsumeReceipt rejects an unnamed ordering authority (fail-closed)",
            "ledger_hex": "",
            "approval_id_hex": approval_x.hex(),
            "position": 5,
            "body_hex": empty_ledger.hex(),
            "expect_verify": "ConsumeReceiptUnsigned",
        },
        "absent_ledger": {
            "note": "ledger field ABSENT (2-key map {2,3}): a structurally malformed receipt; its "
                    "bytes differ from the empty-ledger receipt (empty != absent)",
            "approval_id_hex": approval_x.hex(),
            "position": 5,
            "body_hex": absent_ledger.hex(),
            "expect": "Malformed",
        },
    }


def build():
    approval_x = cid("approvalX")
    approval_y = cid("approvalY")

    # A minimal positive receipt (the base worked object; §1.3).
    base = receipt_case("base", LEDGER_A, approval_x, 5,
                        "ledger LEDGER01 binds approval X to its forward-only position 5, signed by "
                        "the ledger key (REQ-121)")

    # The forward-only sequence a single honest ledger emits: positions strictly increase, one
    # receipt per distinct approval id (X at 5, Y at 6). This is the no-fork baseline.
    seq = [
        receipt_case("seq0", LEDGER_A, approval_x, 5, "LEDGER01 consumes approval X at position 5"),
        receipt_case("seq1", LEDGER_A, approval_y, 6, "LEDGER01 consumes approval Y at position 6"),
    ]

    forks = [
        # (a) same ledger, SAME approval id, DIFFERENT positions -> a partition of one ledger's
        # forward-only counter contradicts itself. FORK.
        fork_case("same_ledger_diff_position",
                  (LEDGER_A, approval_x, 5), (LEDGER_A, approval_x, 9),
                  "one ledger, one approval id, two positions (5 vs 9) drawn from forked state -> FORK"),
        # (b) TWO different ledgers each sign a receipt for the SAME approval id -> the single-use
        # approval was consumed by two ordering authorities. A cross-ledger double spend. FORK
        # (they also differ in ledger id, so they are not byte-identical).
        fork_case("cross_ledger_same_approval",
                  (LEDGER_A, approval_x, 5), (LEDGER_B, approval_x, 5),
                  "two ledgers, one approval id, same position -> a single-use approval spent twice -> FORK"),
        fork_case("cross_ledger_diff_position",
                  (LEDGER_A, approval_x, 5), (LEDGER_B, approval_x, 12),
                  "two ledgers, one approval id, different positions -> FORK"),
        # A benign duplicate: same ledger, same approval id, same position -> byte-identical -> a
        # ledger re-presenting its own receipt is NOT a fork.
        fork_case("benign_duplicate",
                  (LEDGER_A, approval_x, 5), (LEDGER_A, approval_x, 5),
                  "byte-identical re-emission of the same receipt -> benign, NOT a fork"),
        # Different approval ids -> two independent consumes, NOT a fork (even on one ledger).
        fork_case("distinct_approvals",
                  (LEDGER_A, approval_x, 5), (LEDGER_A, approval_y, 6),
                  "different approval ids -> two independent consumes, NOT a fork"),
    ]

    return {
        "note": ("Independent oracle for T1.5 consume receipt (NAALP-REQ-121; coding-instructions "
                 "§1.3). The receipt body {1: ledger, 2: approval_id, 3: position} binds an approval "
                 "content id to the CONSUMING LEDGER's forward-only position and is SIGNED BY THE "
                 "LEDGER key (the anti-double-spend counter is under the ordering authority, never "
                 "the requester). First-append-wins by approval id; a second receipt for one approval "
                 "id with a different position/ledger is a detectable FORK. Go and Rust reproduce "
                 "every body_hex AND every fork/benign verdict over REAL ML-DSA-65 ledger-signed "
                 "receipts, so Go==Rust==oracle. Verdicts come from the from-scratch is_fork() model "
                 "in this file, NOT impl/go or impl/rust. Generated by tools/consume_receipt_oracle.py; "
                 "do not hand-edit."),
        "fields": {"ledger": FIELD_LEDGER, "approval_id": FIELD_APPROVAL_ID, "position": FIELD_POSITION},
        "ledgers": {"a_hex": LEDGER_A.hex(), "b_hex": LEDGER_B.hex()},
        "approvals": {"x_hex": approval_x.hex(), "y_hex": approval_y.hex()},
        "base": base,
        "sequence": seq,
        "forks": forks,
        "wire": build_wire_cases(approval_x),
    }


def _r12_stringify(node):
    # R12 (NAALP-01-03): carry any 64-bit counter/position > 2^53-1 as a decimal STRING so a
    # float64 JSON decoder (JS Number, Go interface{}, and the shared runner's own decode+re-marshal
    # step) cannot silently round the low octets before an adapter's string-tolerant u64 parses it.
    # Representation-only: the signed CBOR bytes (body_hex) are computed from the integer BEFORE this
    # walk and are unchanged.
    if isinstance(node, bool):
        return node
    if isinstance(node, int):
        return str(node) if abs(node) > (1 << 53) - 1 else node
    if isinstance(node, dict):
        return {k: _r12_stringify(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_r12_stringify(v) for v in node]
    return node


def main():
    data = _r12_stringify(build())
    out = os.path.normpath(os.path.join(HERE, "..", "vectors", "consume_receipt", "cases.json"))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # newline="\n" forces LF on every platform (Python text mode would emit CRLF on Windows,
    # diverging the worktree vector from the LF-normalized git blob and breaking a pinned gate).
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  base receipt body=%s... (%d bytes)"
          % (data["base"]["body_hex"][:24], len(data["base"]["body_hex"]) // 2))
    for fk in data["forks"]:
        print("  fork case %-28s -> %s" % (fk["name"], fk["expect"]))
    for b in data["wire"]["position_too_large"]:
        print("  wire %-22s position=%s" % (b["name"], b["position"]))


if __name__ == "__main__":
    main()
