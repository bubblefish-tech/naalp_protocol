# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for the two R-TDCS wire additions (design.md §25, C22):

  * R-TDCS-5 — the OPTIONAL audience field (?6) on naalp-approval. An approval that names an
    audience binds it UNDER SIGNATURE (so it cannot be moved to another context); an approval
    with no audience encodes byte-identically to a 5-field approval (field 6 omitted, not an
    empty sentinel). Both bytes and the content id are constructed here, independently.

  * R-TDCS-3 — the party-visible coarse refusal object naalp-refusal = {1: outcome, 2: record},
    where `outcome` is the closed set {denied:0, held:1, unverifiable:2} and `record` is the
    content id of the FULL signed record carrying the discriminating detail. The refusal carries
    ONLY those two fields: the detail (here, a held-result body with a free-form `reason`) lives
    only in the full record, referenced by content id — never in the party-visible refusal. The
    negative cases (an unknown outcome code, an extra field carrying the reason, a missing record
    id) are what a conformant parser MUST reject (UnknownRefusalOutcome / RefusalDetailLeak).

Non-circular authority (NOT the code under test):
  * All bodies are built by the shared deterministic-CBOR constructor (cbor_oracle, graded
    against RFC 8949 in T1).
  * Content ids use the T1 framing exactly: multihash(0x20, SHA-384(canonical CBOR)) =
    0x20 0x30 || SHA-384(bytes), 50 bytes.
  * The approver identity is a real signer id from the T4 identity corpus (an independent
    authority), used here only as an opaque string label.

Emits vectors/trust_decision/cases.json (LF-normalized). Go and Rust both grade against this file.
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

# Closed refusal-outcome set (design.md §25; CDDL refusal-outcome).
DENIED, HELD, UNVERIFIABLE = 0, 1, 2


def cid(b):
    """Content id with the T1 framing: multihash(0x20, SHA-384(bytes))."""
    return b"\x20\x30" + hashlib.sha384(b).digest()


def approval_bytes(approves, approver, grant, nonce, not_after, audience=None):
    """naalp-approval {1:approves,2:approver,3:grant,4:nonce,5:not_after,?6:audience}. Field 6 is
    OMITTED when audience is falsy — an empty string is not a distinct value (CDDL note)."""
    fields = [
        (1, approves),
        (2, approver),
        (3, grant),
        (4, nonce),
        (5, not_after),
    ]
    if audience:
        fields.append((6, audience))
    return cbor_oracle.encode(("map", fields))


def held_body(approves, reason):
    """A full signed record that carries discriminating detail (a naalp-approval-held body). Its
    `reason` is the detail that MUST NOT appear in the party-visible refusal."""
    return cbor_oracle.encode(("map", [(1, approves), (2, reason)]))


def refusal_bytes(outcome, record_id):
    """naalp-refusal {1:outcome, 2:record}. Coarse outcome + content id of the full record only."""
    return cbor_oracle.encode(("map", [(1, outcome), (2, record_id)]))


def build():
    ids = json.load(open(os.path.join(HERE, "..", "vectors", "identity", "cases.json")))
    approver = ids["signers"][0]["signer_id"]

    args_bytes = cbor_oracle.encode(("map", [(1, "transfer"), (2, 100)]))
    args_id = cid(args_bytes)
    nonce = b"\x07" * 16
    not_after = 1000

    # ---- R-TDCS-5: audience field ------------------------------------------------------------
    ctx_match = "billing.example.v1"
    ctx_mismatch = "payments.example.v1"
    absent_bytes = approval_bytes(args_id, approver, 2, nonce, not_after)  # field 6 omitted
    present_bytes = approval_bytes(args_id, approver, 2, nonce, not_after, audience=ctx_match)
    # Naming an audience changes the signed bytes (⟹ a distinct content id), so a portable verdict
    # cannot be silently moved to another context.
    assert present_bytes != absent_bytes, "an audience must change the approval bytes"
    assert cid(present_bytes) != cid(absent_bytes), "an audience must change the approval id"
    # An empty-string audience must encode identically to absent (empty is not a distinct value).
    assert approval_bytes(args_id, approver, 2, nonce, not_after, audience="") == absent_bytes

    # ---- R-TDCS-3: coarse refusal object -----------------------------------------------------
    leaked_reason = "insufficient approver quorum: 1 of 2 required approvers signed"
    full_record = held_body(args_id, leaked_reason)  # the detail-carrying full signed record
    full_record_id = cid(full_record)

    refusal_cases = []
    for name, outcome in (("denied", DENIED), ("held", HELD), ("unverifiable", UNVERIFIABLE)):
        rb = refusal_bytes(outcome, full_record_id)
        # The party-visible refusal references the record by content id; the detail is NOT in it.
        assert leaked_reason.encode("utf-8") not in rb, "the reason must not leak into the refusal"
        assert full_record_id in rb, "the refusal must carry the record content id"
        refusal_cases.append({"name": name, "outcome": outcome, "record_hex": rb.hex()})

    # Negative cases a conformant parser MUST reject.
    unknown_outcome = refusal_bytes(3, full_record_id)                       # UnknownRefusalOutcome
    detail_leak_extra = cbor_oracle.encode(("map", [                        # RefusalDetailLeak (extra field 3)
        (1, HELD), (2, full_record_id), (3, leaked_reason)]))
    missing_record = cbor_oracle.encode(("map", [(1, HELD)]))               # RefusalDetailLeak (no record id)
    empty_record = refusal_bytes(HELD, b"")                                 # RefusalDetailLeak (empty record id)

    return {
        "source": ("design §25 (C22, R-TDCS-3/5); bodies built by the shared RFC-8949 CBOR "
                   "constructor (T1); content id = multihash(0x20, SHA-384(canonical CBOR)); "
                   "approver id from the T4 identity corpus."),
        "audience": {
            "approver": approver,
            "approves_hex": args_id.hex(),
            "grant": 2,
            "nonce_hex": nonce.hex(),
            "not_after": not_after,
            "use_context_match": ctx_match,
            "use_context_mismatch": ctx_mismatch,
            "cases": [
                {"name": "audience_present", "audience": ctx_match,
                 "record_hex": present_bytes.hex(), "approval_id_hex": cid(present_bytes).hex()},
                {"name": "audience_absent", "audience": "",
                 "record_hex": absent_bytes.hex(), "approval_id_hex": cid(absent_bytes).hex()},
            ],
        },
        "refusal": {
            "full_record_hex": full_record.hex(),
            "full_record_id_hex": full_record_id.hex(),
            "leaked_reason": leaked_reason,
            "cases": refusal_cases,
            "reject": {
                "unknown_outcome_hex": unknown_outcome.hex(),
                "detail_leak_extra_field_hex": detail_leak_extra.hex(),
                "missing_record_hex": missing_record.hex(),
                "empty_record_hex": empty_record.hex(),
            },
        },
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "trust_decision", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  audience present id=%s..." % data["audience"]["cases"][0]["approval_id_hex"][:16])
    print("  full record id=%s..." % data["refusal"]["full_record_id_hex"][:16])


if __name__ == "__main__":
    main()
