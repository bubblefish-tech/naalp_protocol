# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for S1 — the governed-decision accountability record (design.md section 26,
"THE GOVERNED-DECISION RECORD"; spec/naalp-draft-01.cddl naalp-decision-record, FROZEN commit
c488c6d3). Carries two legs of the T/T+n accountability triple natively: UNIQUE SELECTION (field 2,
the closed governing condition set, content ids in the clear) and GOVERNED-AT-T (field 3, the
consume-receipt spent at decision time). The record is deliberately CLOCK-FREE: it carries no
timestamp field anywhere in its own body — both time properties are POSITIONAL (a consume-receipt's
ledger position; inclusion under a witnessed checkpoint, S3), never a self-asserted clock value. This
oracle emits no `at`/epoch-ms field for that reason; every other N-AALP object in this codebase does.

  naalp-decision-record = {
    1: action,                          bstr, content id of the action decided about
    2: governing,                       [* bstr], closed governing set, content ids, MAY be empty
    ?3: consume,                        bstr, content id of the naalp-consume-receipt spent (PRESENT
                                         only for a consuming allow; a deny/hold carrying field 3 is
                                         rejected DecisionMalformed in full — nothing was consumed)
    4: outcome,                         gw-decision (allow=0/deny=1/hold=2, reused unchanged)
    5: ordering,                        ordering-disclosure (embedded group), MANDATORY (unlike the
                                         optional carriers on naalp-gateway-decision / -egress-
                                         attestation — a full accountability record always states its
                                         ordering basis; there is no silent default here)
    ?6: terms,                          {* uint => term-disposition}, keyed by THIS record's own
                                         field numbers 1..5 only; an out-of-set key is
                                         TermDispositionMalformed
    ?7: enforcement,                    enforcement-disposition (enforced=1/advised=2)
  }

  ordering-disclosure = {1: basis, ?2: boundary, ?3: mechanism, ?4: relation} (embedded group, not a
  top-level object; NO content-id of its own). Well-formedness is fail-closed and basis-conditioned:
    correspondence-only (0) -> keys 2/3/4 ALL absent
    single-boundary      (1) -> key 2 PRESENT, keys 3/4 absent
    external-mechanism   (2) -> key 3 PRESENT (4 optional), key 2 absent
  Any violation is OrderingDisclosureMalformed on the WHOLE carrying record (native field, not a
  may-ignore ext). A basis value outside {0,1,2} is UnknownOrderingBasis.

  term-disposition = {1: kind, ?2: source} reuses the section 2.5.4 producing-boundary kind codes
  (1 observed / 2 reported, confirmed against tools/producing_boundary_oracle.py PB_KIND vocabulary
  this session — not assumed from memory).

Non-circular authority (NOT the code under test):
  * Every body is built by the shared deterministic-CBOR constructor (cbor_oracle, graded against
    RFC 8949 in T1) — never by the Go/Rust decision-record code.
  * head = SHA-384(body); content-id = multihash(0x20, SHA-384(body)) (design section 2.3) — stdlib
    hashlib, matching every sibling oracle in this family (gateway_oracle.cid, egress_attestation_
    oracle.cid). The body carries no self-referential id field (unlike the base envelope's field-1
    id/body-without-field-1 split in cbor_oracle.content_id) — this production's content-id is over
    the WHOLE encoded body, exactly as design.md section 26.2 states ("head = SHA-384(body),
    content-id = multihash(0x20, SHA-384(body)), exactly as every other N-AALP object").
  * The gw-decision outcome vocabulary, the ordering-basis vocabulary, and the enforcement-
    disposition vocabulary are fixed here directly from the CDDL text read this session; Go and Rust
    grade against these values.

Emits vectors/decision_record/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

# ---- closed vocabularies, fixed from the CDDL text (spec/naalp-draft-01.cddl) ------------------

# gw-decision (reused unchanged from naalp-gateway-decision / design section 24).
ALLOW, DENY, HOLD = 0, 1, 2
UNKNOWN_OUTCOME = 99  # outside {0,1,2}; reuses UnknownGatewayDecision (same closed set, section 24.7)

# ordering-basis (design section 26.3).
CORRESPONDENCE_ONLY, SINGLE_BOUNDARY, EXTERNAL_MECHANISM = 0, 1, 2
UNKNOWN_ORDERING_BASIS = 99  # outside {0,1,2} -> UnknownOrderingBasis

# term-disposition kind (reuses the section 2.5.4 producing-boundary codes; confirmed this session
# against tools/producing_boundary_oracle.py: OBSERVED = 1, REPORTED = 2).
TD_OBSERVED, TD_REPORTED = 1, 2

# enforcement-disposition (design CDDL: `enforcement-disposition = &(enforced: 1, advised: 2,)` —
# NOTE these are 1-indexed, unlike the 0-indexed gw-decision / ordering-basis / egress-binding sets).
ENFORCED, ADVISED = 1, 2

# Effect lattice, referenced only in doc strings/comments here (the decision-record body itself
# carries no effect field — it is folded into `outcome`, unlike naalp-gateway-decision field 4).


def sha384(b):
    return hashlib.sha384(b).digest()


def cid(b):
    """T1 content-id framing: multihash(0x20, SHA-384(bytes)) = 0x20 0x30 || SHA-384(b) (50 octets)."""
    return b"\x20\x30" + sha384(b)


def noncanon_map(pairs):
    """Hand-build a CBOR map carrying the SAME pairs but with top-level keys emitted in DESCENDING
    order — non-canonical per RFC 8949 section 4.2.1 (the strict shared decoder rejects it
    NonCanonical). `pairs` is the canonical ascending list [(k, v), ...]; built by hand, NOT via
    cbor_oracle.encode's map path (which always sorts)."""
    n = len(pairs)
    assert n < 24
    out = bytes([0xA0 | n])
    for (k, v) in reversed(pairs):
        out += cbor_oracle.encode(k) + cbor_oracle.encode(v)
    return out


def ordering_group(basis, boundary=None, mechanism=None, relation=None):
    """The embeddable ordering-disclosure group {1: basis, ?2: boundary, ?3: mechanism,
    ?4: relation}. Only the fields actually passed are included, matching the basis-conditioned
    well-formedness rule (design section 26.3) — a caller building a MALFORMED fixture on purpose
    passes fields that violate the rule; this constructor does not itself enforce the rule (that is
    the verifier's job under test)."""
    pairs = [(1, basis)]
    if boundary is not None:
        pairs.append((2, boundary))
    if mechanism is not None:
        pairs.append((3, mechanism))
    if relation is not None:
        pairs.append((4, relation))
    return ("map", pairs)


def term_disposition_group(kind, source=None):
    """The embeddable term-disposition group {1: kind, ?2: source}."""
    pairs = [(1, kind)]
    if source is not None:
        pairs.append((2, source))
    return ("map", pairs)


def decision_record_body(action, governing, outcome, ordering, consume=None, terms=None, enforcement=None):
    """{1: action, 2: governing[], ?3: consume, 4: outcome, 5: ordering, ?6: terms, ?7: enforcement}.
    `ordering` is an ordering_group(...) tuple; `terms` (if given) is a dict {fieldnum: (kind, source)}
    built into the embedded {* uint => term-disposition} map here."""
    pairs = [(1, action), (2, list(governing))]
    if consume is not None:
        pairs.append((3, consume))
    pairs.append((4, outcome))
    pairs.append((5, ordering))
    if terms is not None:
        term_pairs = [(k, term_disposition_group(*v) if isinstance(v, tuple) else v) for (k, v) in terms.items()]
        pairs.append((6, ("map", term_pairs)))
    if enforcement is not None:
        pairs.append((7, enforcement))
    return cbor_oracle.encode(("map", pairs)), pairs


def record_out(name, action, governing, outcome, ordering, consume=None, terms=None, enforcement=None, note=""):
    body, pairs = decision_record_body(action, governing, outcome, ordering, consume, terms, enforcement)
    return {
        "name": name,
        "action_hex": action.hex(),
        "governing_hex": [g.hex() for g in governing],
        "consume_hex": (consume.hex() if consume is not None else None),
        "outcome": outcome,
        "body_hex": body.hex(),
        "head_hex": sha384(body).hex(),
        "id_hex": cid(body).hex(),
        "note": note,
    }


def build_ordering_examples(relation_cid):
    """One decision-record ordering leg per ordering-basis value, isolating ONLY that field over a
    shared base (DENY/no-consume, empty governing, no terms/enforcement) so the ordering encoding is
    the single variable — the same isolation idiom cbor_oracle uses for empty-vs-absent."""
    action = cid(b"action:read-report")
    boundary = bytes.fromhex("5349474e45525f42") + b"-boundary"  # a signer-id-shaped boundary value
    mechanism = b"external-log:acme-transparency-v1"

    correspondence = record_out(
        "correspondence_only", action, [], DENY,
        ordering_group(CORRESPONDENCE_ONLY),
        note="the weakest claim: no boundary, no mechanism, no relation. Also the value a verifier "
             "MUST read when ordering is ABSENT on the optional carriers (gateway-decision, "
             "egress-attestation) — never inferred stronger from silence.",
    )
    single_boundary = record_out(
        "single_boundary", action, [], DENY,
        ordering_group(SINGLE_BOUNDARY, boundary=boundary),
        note="one boundary observed both terms and is named; a real, checkable claim, but NOT "
             "neither-party (one observational domain, not two).",
    )
    external_mechanism = record_out(
        "external_mechanism", action, [], DENY,
        ordering_group(EXTERNAL_MECHANISM, mechanism=mechanism, relation=relation_cid),
        note="an external sequencing mechanism is named together with the log relation binding this "
             "record under it (here, a naalp-checkpoint-root content id) — the strongest on-wire "
             "claim, composing with S3 to carry binding-fixed-by-T.",
    )
    external_mechanism_no_relation = record_out(
        "external_mechanism_no_relation", action, [], DENY,
        ordering_group(EXTERNAL_MECHANISM, mechanism=mechanism),
        note="external-mechanism with relation (field 4) ABSENT — relation is OPTIONAL even under "
             "external-mechanism per the CDDL ('key 3 present (4 optional)').",
    )
    return {
        "correspondence_only": correspondence,
        "single_boundary": single_boundary,
        "external_mechanism": external_mechanism,
        "external_mechanism_no_relation": external_mechanism_no_relation,
    }


def build_ordering_malformed():
    """Basis-conditioned well-formedness violations (design section 26.3): each rejects the WHOLE
    carrying record OrderingDisclosureMalformed (or UnknownOrderingBasis for the out-of-set basis
    case), never a may-ignore skip."""
    action = cid(b"action:read-report")
    boundary = b"boundary-signer-X"
    mechanism = b"external-log:acme-transparency-v1"
    relation = cid(b"checkpoint-example")

    cases = {}

    # correspondence-only (0) with boundary (key 2) ALSO present -> malformed.
    body, _ = decision_record_body(action, [], DENY, ordering_group(CORRESPONDENCE_ONLY, boundary=boundary))
    cases["correspondence_with_boundary"] = {
        "body_hex": body.hex(), "reject": "OrderingDisclosureMalformed",
        "note": "basis=correspondence-only but key 2 (boundary) is present; correspondence-only requires 2/3/4 all absent.",
    }

    # single-boundary (1) with mechanism (key 3) ALSO present -> malformed.
    body, _ = decision_record_body(action, [], DENY, ordering_group(SINGLE_BOUNDARY, boundary=boundary, mechanism=mechanism))
    cases["single_boundary_with_mechanism"] = {
        "body_hex": body.hex(), "reject": "OrderingDisclosureMalformed",
        "note": "basis=single-boundary but key 3 (mechanism) is also present; single-boundary requires 3/4 absent.",
    }

    # single-boundary (1) MISSING boundary (key 2) -> malformed.
    body, _ = decision_record_body(action, [], DENY, ordering_group(SINGLE_BOUNDARY))
    cases["single_boundary_missing_boundary"] = {
        "body_hex": body.hex(), "reject": "OrderingDisclosureMalformed",
        "note": "basis=single-boundary but key 2 (boundary) is absent; single-boundary requires key 2 present.",
    }

    # external-mechanism (2) with boundary (key 2) present (should be absent) -> malformed.
    body, _ = decision_record_body(action, [], DENY, ordering_group(EXTERNAL_MECHANISM, boundary=boundary, mechanism=mechanism, relation=relation))
    cases["external_mechanism_with_boundary"] = {
        "body_hex": body.hex(), "reject": "OrderingDisclosureMalformed",
        "note": "basis=external-mechanism but key 2 (boundary) is present; external-mechanism requires key 2 absent.",
    }

    # external-mechanism (2) MISSING mechanism (key 3) -> malformed.
    body, _ = decision_record_body(action, [], DENY, ordering_group(EXTERNAL_MECHANISM, relation=relation))
    cases["external_mechanism_missing_mechanism"] = {
        "body_hex": body.hex(), "reject": "OrderingDisclosureMalformed",
        "note": "basis=external-mechanism but key 3 (mechanism) is absent; external-mechanism requires key 3 present.",
    }

    # basis value outside {0,1,2} -> UnknownOrderingBasis (checked BEFORE the well-formedness rule,
    # since the rule is only meaningful over a known basis value).
    body, _ = decision_record_body(action, [], DENY, ordering_group(UNKNOWN_ORDERING_BASIS))
    cases["unknown_ordering_basis"] = {
        "body_hex": body.hex(), "reject": "UnknownOrderingBasis",
        "note": "ordering-disclosure field 1 (basis) = 99, outside the closed {0,1,2} set.",
    }

    return cases


def build():
    action = cid(b"tool:export_customer_data")
    policy_a = cid(b"policy:standing-export-policy-v1")
    policy_b = cid(b"policy:break-glass-override-v1")
    consume_receipt_cid = cid(b"consume-receipt:seq-0042")
    checkpoint_relation_cid = cid(b"checkpoint-example")
    origin = b"boundary:relay-partner-3"

    # 1. ALLOW that consumed a single-use authority (governed-at-T leg present).
    allow_consuming = record_out(
        "allow_consuming", action, [policy_a], ALLOW,
        ordering_group(CORRESPONDENCE_ONLY), consume=consume_receipt_cid,
        note="an ALLOW that spent a single-use authority at decision time: field 3 (consume) names "
             "the naalp-consume-receipt content id that was spent. Governed-at-T leg present.",
    )

    # 2. ALLOW governed by standing policy alone — consumed NOTHING (field 3 legitimately absent on
    #    an allow too, per design section 26.4: field 3 is present ONLY for an allow that consumed a
    #    single-use authority, implying an allow may also consume nothing).
    allow_no_consume = record_out(
        "allow_no_consume", action, [policy_a], ALLOW,
        ordering_group(CORRESPONDENCE_ONLY),
        note="an ALLOW governed by standing policy alone: field 3 (consume) absent because no "
             "single-use authority was spent. Distinct content-id from allow_consuming (isolates "
             "field 3 present-vs-absent as the single variable).",
    )
    assert allow_consuming["id_hex"] != allow_no_consume["id_hex"], \
        "consume present-vs-absent must produce distinct content ids"

    # 3. DENY, two governing conditions, single-boundary ordering.
    deny_two_governing = record_out(
        "deny_two_governing", action, [policy_a, policy_b], DENY,
        ordering_group(SINGLE_BOUNDARY, boundary=b"boundary-signer-X"),
        note="a DENY naming two governing conditions in the clear (unique-selection leg): "
             "identification AND availability together, not a hash or a count.",
    )

    # 4. HOLD, governed by nothing beyond the decision itself (governing = [] — legitimately empty).
    hold_empty_governing = record_out(
        "hold_empty_governing", action, [], HOLD,
        ordering_group(EXTERNAL_MECHANISM, mechanism=b"external-log:acme-transparency-v1",
                       relation=checkpoint_relation_cid),
        note="a HOLD with governing=[] (empty is legal only when no governing condition beyond the "
             "decision itself exists); ordering = external-mechanism, relation names a "
             "naalp-checkpoint-root content id (S3 composition).",
    )

    # 5/6. DENY / HOLD carrying a consume reference anyway -> DecisionMalformed (the strengthening
    #      direction: never accept a claim the record's own outcome contradicts).
    deny_body, _ = decision_record_body(action, [policy_a], DENY, ordering_group(CORRESPONDENCE_ONLY),
                                          consume=consume_receipt_cid)
    hold_body, _ = decision_record_body(action, [], HOLD, ordering_group(CORRESPONDENCE_ONLY),
                                          consume=consume_receipt_cid)
    deny_with_consume_rejected = {
        "body_hex": deny_body.hex(), "reject": "DecisionMalformed",
        "note": "outcome=deny but field 3 (consume) is present anyway — nothing was consumed by a "
                "refusal, so a value here asserts authority spent for an action the record's own "
                "outcome says was not taken.",
    }
    hold_with_consume_rejected = {
        "body_hex": hold_body.hex(), "reject": "DecisionMalformed",
        "note": "outcome=hold but field 3 (consume) is present anyway — same rejection as deny.",
    }

    # 7. terms (field 6): valid dispositions over the record's own field numbers 1 and 4.
    terms_valid = record_out(
        "terms_valid", action, [policy_a], ALLOW,
        ordering_group(CORRESPONDENCE_ONLY), consume=consume_receipt_cid,
        terms={1: (TD_OBSERVED,), 4: (TD_REPORTED, origin)},
        note="field 6 discloses that field 1 (action) was OBSERVED first-hand and field 4 (outcome) "
             "was REPORTED, relayed from `origin` — reuses the section 2.5.4 kind codes (1/2), keyed "
             "by this record's own field numbers.",
    )

    # 8. terms with a key OUTSIDE the record's own field set (1..5) -> TermDispositionMalformed.
    terms_bad_body, _ = decision_record_body(
        action, [policy_a], ALLOW, ordering_group(CORRESPONDENCE_ONLY), consume=consume_receipt_cid,
        terms={6: (TD_OBSERVED,)},   # key 6 is the record's own `terms` field — outside {1..5}
    )
    terms_key_outside_field_set_rejected = {
        "body_hex": terms_bad_body.hex(), "reject": "TermDispositionMalformed",
        "note": "field 6 (terms) carries a key of 6, which is NOT one of the record's own field "
                "numbers 1..5 (6 is the terms map's own field number) — fail-closed, the whole "
                "record is rejected.",
    }

    # 9/10. enforcement (field 7): enforced / advised.
    enforcement_enforced = record_out(
        "enforcement_enforced", action, [policy_a], DENY, ordering_group(CORRESPONDENCE_ONLY),
        enforcement=ENFORCED,
        note="field 7 = enforced (1): the producer states it actually enforces this outcome.",
    )
    enforcement_advised = record_out(
        "enforcement_advised", action, [policy_a], DENY, ordering_group(CORRESPONDENCE_ONLY),
        enforcement=ADVISED,
        note="field 7 = advised (2): the producer's own unverifiable self-account that it only "
             "advises, rather than enforces, this outcome.",
    )

    # 11. unknown outcome (field 4 outside {0,1,2}) -> reuses UnknownGatewayDecision (the SAME closed
    #     gw-decision set naalp-gateway-decision already registers the error for, section 24.7).
    unknown_outcome_body, _ = decision_record_body(action, [], UNKNOWN_OUTCOME, ordering_group(CORRESPONDENCE_ONLY))
    unknown_outcome_rejected = {
        "body_hex": unknown_outcome_body.hex(), "reject": "UnknownGatewayDecision",
        "note": "field 4 (outcome) = 99, outside the closed gw-decision set {allow=0,deny=1,hold=2} "
                "the field reuses unchanged from naalp-gateway-decision.",
    }

    # 12. minimal record: empty action, empty governing, DENY, correspondence-only, no optional fields.
    minimal = record_out(
        "minimal", b"", [], DENY, ordering_group(CORRESPONDENCE_ONLY),
        note="smallest valid decision-record: empty action bstr, governing=[], deny, "
             "correspondence-only, no consume/terms/enforcement.",
    )

    # 13. keys-out-of-order: canonical vs non-canonical encoding of the terms_valid body.
    canon_body, canon_pairs = decision_record_body(
        action, [policy_a], ALLOW, ordering_group(CORRESPONDENCE_ONLY), consume=consume_receipt_cid,
        terms={1: (TD_OBSERVED,), 4: (TD_REPORTED, origin)},
    )
    noncanon_body = noncanon_map(canon_pairs)
    assert noncanon_body != canon_body and len(noncanon_body) == len(canon_body)
    keys_out_of_order = {
        "canonical_body_hex": canon_body.hex(),
        "noncanonical_body_hex": noncanon_body.hex(),
        "reject": "NonCanonical",
        "note": "same content as terms_valid, top-level keys emitted descending — the strict shared "
                "decoder rejects NonCanonical.",
    }

    # 14. look-alike: a naalp-gateway-decision body {1:uint,2:bstr,3:bstr,4:uint} fed to the
    #     decision-record parser — field 1 is a uint (decision) where the decision-record's field 1
    #     (action) requires a bstr; structurally rejected.
    la_body = cbor_oracle.encode(("map", [(1, ALLOW), (2, action), (3, b"policy:acme"), (4, 0)]))
    look_alike = {
        "body_hex": la_body.hex(), "reject": "DecisionMalformed",
        "note": "a naalp-gateway-decision body (this family's own sibling near-clone) fed to "
                "ParseDecisionRecord: field 1 is a uint (gw-decision) where field 1 (action) "
                "requires a bstr, and field 5 (the mandatory ordering group) is entirely absent.",
    }

    return {
        "source": ("design.md section 26.4 / spec/naalp-draft-01.cddl naalp-decision-record "
                   "(FROZEN commit c488c6d3). naalp-decision-record {1:action,2:governing[],"
                   "?3:consume,4:outcome,5:ordering,?6:terms,?7:enforcement} is the SIGNED record a "
                   "governed decision point emits that it decided about an action under a CLOSED, "
                   "uniquely-selected condition set. CLOCK-FREE by design: no timestamp field "
                   "anywhere in the body; both time properties (governed-at-T, binding-fixed-by-T) "
                   "are POSITIONAL. head=SHA-384(body); content-id=multihash(0x20,SHA-384(body)), "
                   "exactly as every other N-AALP object in this family."),
        "outcome_vocabulary": [{"name": n, "code": c} for (n, c) in (("allow", ALLOW), ("deny", DENY), ("hold", HOLD))],
        "ordering_basis_vocabulary": [{"name": n, "code": c} for (n, c) in
                                      (("correspondence-only", CORRESPONDENCE_ONLY),
                                       ("single-boundary", SINGLE_BOUNDARY),
                                       ("external-mechanism", EXTERNAL_MECHANISM))],
        "enforcement_disposition_vocabulary": [{"name": n, "code": c} for (n, c) in (("enforced", ENFORCED), ("advised", ADVISED))],
        "term_disposition_kind_vocabulary": [{"name": n, "code": c} for (n, c) in (("observed", TD_OBSERVED), ("reported", TD_REPORTED))],
        "action_cid_hex": action.hex(),
        "policy_a_cid_hex": policy_a.hex(),
        "policy_b_cid_hex": policy_b.hex(),
        "consume_receipt_cid_hex": consume_receipt_cid.hex(),
        "records": {
            "allow_consuming": allow_consuming,
            "allow_no_consume": allow_no_consume,
            "deny_two_governing": deny_two_governing,
            "hold_empty_governing": hold_empty_governing,
            "terms_valid": terms_valid,
            "enforcement_enforced": enforcement_enforced,
            "enforcement_advised": enforcement_advised,
            "minimal": minimal,
        },
        "ordering_examples": build_ordering_examples(checkpoint_relation_cid),
        "negative": {
            "deny_with_consume_rejected": deny_with_consume_rejected,
            "hold_with_consume_rejected": hold_with_consume_rejected,
            "terms_key_outside_field_set_rejected": terms_key_outside_field_set_rejected,
            "unknown_outcome_rejected": unknown_outcome_rejected,
            "ordering_malformed": build_ordering_malformed(),
            "keys_out_of_order": keys_out_of_order,
            "look_alike": look_alike,
        },
        "note": ("every *_hex value in this corpus is produced by the shared deterministic-CBOR "
                 "constructor (cbor_oracle, T1) plus stdlib hashlib SHA-384 — never by the Go/Rust "
                 "decision-record code under test. Go and Rust are graded byte-for-byte against "
                 "these bodies, heads, and content ids (Go == Rust == oracle)."),
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "decision_record", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    for (name, rec) in data["records"].items():
        print("  %-20s id=%s..." % (name, rec["id_hex"][:16]))
    print("  ordering examples: %s" % list(data["ordering_examples"].keys()))
    print("  negative cases: %s" % [k for k in data["negative"].keys()])


if __name__ == "__main__":
    main()
