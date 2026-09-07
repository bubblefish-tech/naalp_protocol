# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C21 task 5B.1 — NAALP-PAY payment import (design.md §24).

NAALP-PAY imports a foreign payment payload (an AP2 mandate, an Agentic Commerce Protocol delegated
token, an x402 payload) octet-for-octet as OPAQUE foreign bytes (carriage, not adoption) inside a
signed N-AALP object, and turns it into a value-bearing charge that N-AALP governs with its OWN added
guarantees: the charge is bound to amount + currency + payee + expiry + the foreign payload's
content-id, carried as a signed APPROVAL under the existing value-bearing rule (§7), and SPENT
SINGLE-USE through the §7 consume ledger. There is NO fifth effect and NO payment-specific ledger:
the spend is a non_idempotent_write authorized and consumed exactly as any other approval.

  * naalp-payment-import {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign} —
    the wrapper body (envelope field 10). `format` selects the imported payment FORMAT from a closed
    registry (payment-format.csv); `foreign` carries the imported payload octet-for-octet.

  * naalp-payment-charge-binding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
    6: foreign_id} — the exact value the approval binds by content-id. `foreign_id` is the T1
    content-id of the foreign payload (carriage binding), so a substituted payload changes it. Because
    the approval binds THIS binding's content-id, a wrong-amount OR wrong-payee OR wrong-currency OR
    substituted-payload charge yields a different content-id and no longer matches the approval
    (ApprovalMismatch), and a replayed charge is rejected by the ledger (AlreadyConsumed).

Non-circular authority (NOT the code under test):
  * Every body is built by the shared deterministic-CBOR constructor (cbor_oracle, graded against
    RFC 8949 in T1) — never by the Go/Rust payment code.
  * head = SHA-384(body); content-id = multihash(0x20, SHA-384(body)) (design §2.3) — computed here
    with standard-library hashlib.
  * The format vocabulary is fixed here from the design; Go and Rust grade against these values.
  * The approval body and the consume ledger are the §7 primitives (graded in the approval oracle);
    this oracle fixes only the charge-binding content-ids the approval binds (the `approves` value).

Emits vectors/payment/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

# Effect lattice (design §6): a payment spend is a non_idempotent_write — the value-bearing rule.
NON_IDEMPOTENT_WRITE = 2

# Closed payment-format vocabulary (vectors/registry/payment-format.csv). These name the imported
# FORMAT carried octet-for-octet — not an adopted schema; a code outside the set is rejected.
FORMAT_AP2, FORMAT_ACP, FORMAT_X402 = 1, 2, 3
UNKNOWN_FORMAT = 99  # a format code outside the closed set — rejected
FORMAT_VOCAB = [
    ("ap2-mandate", FORMAT_AP2),
    ("acp-delegated-token", FORMAT_ACP),
    ("x402-payload", FORMAT_X402),
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


def import_body(fmt, amount, currency, payee, not_after, foreign):
    # {1: format, 2: amount, 3: currency (tstr), 4: payee (bstr), 5: not_after, 6: foreign (bstr)}.
    return cbor_oracle.encode(("map", [(1, fmt), (2, amount), (3, currency), (4, payee), (5, not_after), (6, foreign)]))


def charge_binding_body(fmt, amount, currency, payee, not_after, foreign_id):
    # {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign_id (bstr, content-id)}.
    return cbor_oracle.encode(("map", [(1, fmt), (2, amount), (3, currency), (4, payee), (5, not_after), (6, foreign_id)]))


def import_out(fmt, amount, currency, payee, not_after, foreign):
    body = import_body(fmt, amount, currency, payee, not_after, foreign)
    fid = cid(foreign)
    cb = charge_binding_body(fmt, amount, currency, payee, not_after, fid)
    return {
        "format": fmt, "amount": amount, "currency": currency,
        "payee_hex": payee.hex(), "not_after": not_after, "foreign_hex": foreign.hex(),
        "foreign_id_hex": fid.hex(),
        "body_hex": body.hex(), "head_hex": sha384(body).hex(), "id_hex": cid(body).hex(),
        "charge_binding": {"body_hex": cb.hex(), "head_hex": sha384(cb).hex(), "id_hex": cid(cb).hex()},
    }


def build_edge_cases():
    """Standard wire-format edge cases (Part 1). #3 (oversized amount) and #4 (minimal) are already
    emitted above; this adds:
      #1 keys-out-of-order: an import body whose top-level keys are DESCENDING (6,5,4,3,2,1) — rejected
         NonCanonical by the strict shared decoder ParsePaymentImport routes through.
      #2 empty-vs-absent (the foreign payload, field 6, a bstr): an empty foreign payload is PRESENT and
         valid with its OWN foreign_id (the carriage binding), DISTINCT from a populated one, and BOTH
         differ from a body whose foreign field is ABSENT (rejected PayMalformed — field 6 is mandatory).
         NAALP-PAY has no truly-optional field, so the meaningful empty-vs-nonempty is the foreign bstr.
      #5 look-alike: naalp-payment-import and naalp-payment-charge-binding share ONE 6-field shape by
         design, so there is no structurally-distinct in-family sibling; the look-alike is a near-miss
         with a wrong field-3 (currency) type — a bstr where a tstr is required (as a foreign object
         might carry) — which ParsePaymentImport rejects PayMalformed."""
    fmt, amount, currency = FORMAT_AP2, 1999, "USD"
    payee = b"merchant:acme-store"
    not_after = 1785000000000
    foreign = b'{"ap2":"mandate","cart_id":"c-77"}'

    # #1 keys-out-of-order.
    koo_pairs = [(1, fmt), (2, amount), (3, currency), (4, payee), (5, not_after), (6, foreign)]
    koo_canon = import_body(fmt, amount, currency, payee, not_after, foreign)
    koo_noncanon = noncanon_map(koo_pairs)
    assert koo_noncanon != koo_canon and len(koo_noncanon) == len(koo_canon)
    keys_out_of_order = {
        "format": fmt, "amount": amount, "currency": currency, "payee_hex": payee.hex(),
        "not_after": not_after, "foreign_hex": foreign.hex(),
        "canonical_body_hex": koo_canon.hex(),
        "noncanonical_body_hex": koo_noncanon.hex(),
        "reject": "NonCanonical",
        "note": "same content, top-level keys emitted descending (6,5,4,3,2,1) - the strict decoder rejects NonCanonical.",
    }

    # #2 empty-vs-absent (foreign payload, field 6).
    empty_foreign_body = import_body(fmt, amount, currency, payee, not_after, b"")
    populated_body = import_body(fmt, amount, currency, payee, not_after, foreign)
    absent_foreign_body = cbor_oracle.encode(("map", [(1, fmt), (2, amount), (3, currency), (4, payee), (5, not_after)]))  # field 6 OMITTED
    assert empty_foreign_body != populated_body != absent_foreign_body and empty_foreign_body != absent_foreign_body
    assert cid(b"") != cid(foreign), "empty and populated foreign must have distinct foreign_ids"
    empty_vs_absent = {
        "empty_foreign": {"body_hex": empty_foreign_body.hex(), "id_hex": cid(empty_foreign_body).hex(),
                          "foreign_id_hex": cid(b"").hex()},
        "populated_foreign": {"foreign_hex": foreign.hex(), "body_hex": populated_body.hex(),
                              "id_hex": cid(populated_body).hex(), "foreign_id_hex": cid(foreign).hex()},
        "absent_field": {"body_hex": absent_foreign_body.hex(), "reject": "PayMalformed"},
        "note": ("an empty foreign payload is present and valid with its own foreign_id (the carriage "
                 "binding), distinct from a populated one; both differ from a body whose foreign field is "
                 "absent (rejected - field 6 is mandatory)."),
    }

    # #5 look-alike: currency (field 3) as a bstr instead of a tstr (a near-miss; payment-import and
    # charge-binding share one 6-field shape, so field-3's tstr type is the distinguishing check).
    la_body = cbor_oracle.encode(("map", [(1, fmt), (2, amount), (3, b"USD"), (4, payee), (5, not_after), (6, foreign)]))
    look_alike = {
        "body_hex": la_body.hex(),
        "reject": "PayMalformed",
        "note": "field 3 (currency) as a bstr where a tstr is required — ParsePaymentImport rejects PayMalformed.",
    }

    return {
        "keys_out_of_order": keys_out_of_order,
        "empty_vs_absent": empty_vs_absent,
        "look_alike": look_alike,
        "done_note": "edge cases #3 (oversized amount) and #4 (minimal) are emitted as top-level big_amount/minimal.",
    }


def build():
    not_after = 1785000000000

    ap2_foreign = b'{"ap2":"mandate","cart_id":"c-77","max_amount":"19.99","currency":"USD"}'
    acp_foreign = b'{"acp":"delegated_token","token":"tok_9f3","cap":"45.00","currency":"USD"}'
    x402_foreign = b'{"x402":"payment","scheme":"exact","amount":"1.00","asset":"USDC"}'

    ap2 = import_out(FORMAT_AP2, 1999, "USD", b"merchant:acme-store", not_after, ap2_foreign)
    acp = import_out(FORMAT_ACP, 4500, "USD", b"merchant:widgets-inc", not_after, acp_foreign)
    x402 = import_out(FORMAT_X402, 100, "USD", b"api:weather-svc", not_after, x402_foreign)

    # Wrong-amount and wrong-payee variants of the AP2 charge: a DIFFERENT charge-binding content-id,
    # so an approval bound to the honest AP2 charge no longer matches (ApprovalMismatch). The foreign
    # payload is unchanged; only the bound value differs.
    fid = bytes.fromhex(ap2["foreign_id_hex"])
    wrong_amount_cb = charge_binding_body(FORMAT_AP2, 9999, "USD", b"merchant:acme-store", not_after, fid)
    wrong_payee_cb = charge_binding_body(FORMAT_AP2, 1999, "USD", b"merchant:evil-store", not_after, fid)
    # A substituted foreign payload changes the foreign_id, hence the charge-binding content-id.
    substituted_foreign = ap2_foreign.replace(b'"max_amount":"19.99"', b'"max_amount":"9999.00"')
    substituted_fid = cid(substituted_foreign)
    substituted_cb = charge_binding_body(FORMAT_AP2, 1999, "USD", b"merchant:acme-store", not_after, substituted_fid)

    honest_cid = ap2["charge_binding"]["id_hex"]
    assert cid(wrong_amount_cb).hex() != honest_cid, "wrong amount must change the charge cid"
    assert cid(wrong_payee_cb).hex() != honest_cid, "wrong payee must change the charge cid"
    assert cid(substituted_cb).hex() != honest_cid, "a substituted payload must change the charge cid"

    vocab = [{"name": n, "code": c} for (n, c) in FORMAT_VOCAB]

    # ---- Oversized-counter round-trip (Phase 6 edge case #3, the >2^53 discipline): a charge amount
    # (minor units) above 2^53. 0x0102030405060708 = 72623859790382856 > 2^53. It MUST round-trip
    # byte-exact through both impls (uint64/u64, no float64) in BOTH the import body and the
    # charge-binding. Carried as a JSON STRING (a float64 decoder rounds it); Python is lossless here.
    BIG_AMOUNT = 0x0102030405060708
    assert BIG_AMOUNT > (1 << 53)
    ba_payee = b"merchant:acme-store"
    ba_body = import_body(FORMAT_AP2, BIG_AMOUNT, "USD", ba_payee, not_after, ap2_foreign)
    ba_fid = cid(ap2_foreign)
    ba_cb = charge_binding_body(FORMAT_AP2, BIG_AMOUNT, "USD", ba_payee, not_after, ba_fid)
    big_amount = {
        "format": FORMAT_AP2, "amount_str": str(BIG_AMOUNT), "currency": "USD",
        "payee_hex": ba_payee.hex(), "not_after": not_after, "foreign_hex": ap2_foreign.hex(),
        "foreign_id_hex": ba_fid.hex(),
        "body_hex": ba_body.hex(), "head_hex": sha384(ba_body).hex(), "id_hex": cid(ba_body).hex(),
        "charge_binding": {"body_hex": ba_cb.hex(), "head_hex": sha384(ba_cb).hex(), "id_hex": cid(ba_cb).hex()},
        "note": "charge amount = 0x0102030405060708 (>2^53) round-trips byte-exact; carried as a string.",
    }

    # ---- Minimal object (Phase 6 edge case #4): the smallest valid payment-import — format ap2,
    # amount 0, empty currency/payee, not_after 0, empty foreign. It encodes + has a stable content-id.
    min_body = import_body(FORMAT_AP2, 0, "", b"", 0, b"")
    minimal = {
        "format": FORMAT_AP2, "amount": 0, "currency": "", "payee_hex": "", "not_after": 0, "foreign_hex": "",
        "body_hex": min_body.hex(), "head_hex": sha384(min_body).hex(), "id_hex": cid(min_body).hex(),
    }

    return {
        "source": ("design §24; naalp-payment-import {1:format,2:amount,3:currency,4:payee,"
                   "5:not_after,6:foreign} imports AP2 / Agentic Commerce Protocol / x402 payloads "
                   "octet-for-octet as opaque foreign bytes (carriage-not-adoption); the "
                   "naalp-payment-charge-binding {1:format,2:amount,3:currency,4:payee,5:not_after,"
                   "6:foreign_id} is what a §7 approval binds by content-id, adding replay + binding "
                   "guarantees: the charge is a non_idempotent_write spent SINGLE-USE through the §7 "
                   "consume ledger (AlreadyConsumed on replay), and a wrong amount/payee/currency or a "
                   "substituted foreign payload changes the charge content-id (ApprovalMismatch). No "
                   "fifth effect, no payment-specific ledger. head=SHA-384(body); "
                   "content-id=multihash(0x20,SHA-384)."),
        "format_vocabulary": vocab,
        "unknown_format": UNKNOWN_FORMAT,
        "charge_effect": NON_IDEMPOTENT_WRITE,
        "imports": {"ap2": ap2, "acp": acp, "x402": x402},
        "big_amount": big_amount,
        "minimal": minimal,
        "edge_cases": build_edge_cases(),
        "mismatch": {
            "wrong_amount_charge_id_hex": cid(wrong_amount_cb).hex(),
            "wrong_payee_charge_id_hex": cid(wrong_payee_cb).hex(),
            "substituted_foreign_hex": substituted_foreign.hex(),
            "substituted_foreign_id_hex": substituted_fid.hex(),
            "substituted_charge_id_hex": cid(substituted_cb).hex(),
        },
        "note": ("the approval binds the charge-binding content-id (imports.ap2.charge_binding.id_hex); "
                 "a replayed spend is AlreadyConsumed at the ledger, a wrong amount/payee/currency or "
                 "substituted payload is ApprovalMismatch."),
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "payment", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # newline="\n" forces LF on every platform so the worktree vector matches the LF-normalized git
    # blob and any hash-pinned vector gate stays green in CI.
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    ap2 = data["imports"]["ap2"]
    print("  ap2 import id=%s... charge id=%s..." % (ap2["id_hex"][:16], ap2["charge_binding"]["id_hex"][:16]))
    print("  formats: %s, charge effect=%d (non_idempotent_write)" % (
        [v["name"] for v in data["format_vocabulary"]], data["charge_effect"]))


if __name__ == "__main__":
    main()
