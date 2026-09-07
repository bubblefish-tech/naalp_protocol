# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C20 — governed negotiation, advisory risk labels, and trust (design.md §23).

C20 adds three signed surfaces carried on N-AALP's own signed object, introducing NO new envelope,
encoding, signature, identity, or audit mechanism (R-11.3): each object below is an ordinary
COSE_Sign1 over a deterministic-CBOR body, reusing the closed C5 effect lattice, the T1 content-id
framing (§2.3), and the §8.2 causal partial order (`causes`) UNCHANGED.

  * naalp-negotiation-{offer,counter,accept} {1: negotiation, 2: role, 3: profile, 4: [* cause]} —
    a GOVERNED negotiation. offer / counter / accept are signed, CAUSALLY-LINKED objects: each
    references its predecessor by content-id in `causes` (the same list-of-content-ids shape the
    §8.2 partial order uses). Each SELECTS a profile from a CLOSED, PRE-REGISTERED set
    (negotiation-profile enum) — there are no runtime-generated handlers and no free-form capability
    strings on the wire, by design. An accept MUST DESCEND from its offer: walking the `causes` DAG
    from the accept must reach the offer's content-id, or the accept is rejected (NotDescended). An
    unknown profile code is rejected (UnknownProfile). An unknown role is rejected (UnknownRole).

  * naalp-risk-label {1: code, 2: critical} + naalp-labeled-object {1: effect, 2: [* risk-label]} —
    an ADVISORY risk-label dimension. The vocabulary (risk-labels.csv) is a closed standard set —
    sensitive (gating), egress (gating), reversible (informing) — plus a private/experimental
    extensible range. `critical` is the per-carriage must-understand flag (uint 1/0 — the N-AALP
    spine carries no CBOR boolean, §3.1). The critical-extension rule (R-2.5) applies: an unknown
    CRITICAL label is rejected (UnknownCriticalRisk); an unknown NON-critical label is ignored. The
    LOAD-BEARING invariant: adding or carrying a risk label NEVER changes an object's effect class —
    the effect is field 7 alone, normalized by the closed C5 lattice; risk labels are an ADVISORY
    dimension, not a fifth effect. This oracle fixes labeled-object bodies at every effect class,
    with and without labels, so both implementations grade that the effect class is unchanged.

  * naalp-trust-ref {1: registry, 2: reference, 3: subject} — a third-party trust statement carried
    as a CHECKABLE signed object. `reference` is the T1 content-id of an EXTERNAL registry record (an
    ERC-8004-style reputation/identity registry record). A verifier CONFIRMS the reference by
    recomputing that content-id over the external bytes; the object's signature checks. But NO wire
    field WEIGHS the statement: there is no score, rank, or ordering on the wire — the protocol takes
    no position on which trust statement outranks which. The oracle emits the external record and its
    content-id (so the impl recomputes and matches) and a tampered record (whose content-id differs).

Non-circular authority (NOT the code under test):
  * Every object body is built by the shared deterministic-CBOR constructor (cbor_oracle, graded
    against RFC 8949 in T1) — never by the Go/Rust negotiation code.
  * head = SHA-384(body); content-id = multihash(0x20, SHA-384(body)) (design §2.3) — computed here
    with standard-library hashlib.
  * The negotiation roles/profiles, the risk-label vocabulary + classes + extensible range, the
    critical-extension outcomes, the effect lattice, and the descend/not-descended graph outcomes are
    fixed here from the design; Go and Rust grade against these independently-listed values.
  * ML-DSA signatures are deterministic (FIPS 204, empty context) and cross-checked Go == Rust in the
    impl tests; Python stdlib has no ML-DSA, so this oracle fixes only the SIGNED INPUT (the body
    bytes), not the signature.

Emits vectors/negotiation/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

# Effect lattice (design §6): read_only < idempotent_write < non_idempotent_write < destructive.
READ_ONLY, IDEMPOTENT_WRITE, NON_IDEMPOTENT_WRITE, DESTRUCTIVE = 0, 1, 2, 3

# Negotiation roles (closed set; naalp negotiation-role enum).
ROLE_OFFER, ROLE_COUNTER, ROLE_ACCEPT = 0, 1, 2

# Pre-registered negotiation profiles (closed set; negotiation-profile enum). NOT free-form strings,
# NOT runtime-generated handlers — a verifier rejects any profile code outside this set.
PROFILE_BASELINE, PROFILE_STREAMING, PROFILE_BATCH = 0, 1, 2
UNKNOWN_PROFILE = 99  # a profile code outside the closed set — rejected

# Risk-label vocabulary (closed standard set; vectors/registry/risk-labels.csv). Each label carries a
# vocabulary CLASS: gating (a policy MAY gate on it) or informing (purely informational).
CLASS_INFORMING, CLASS_GATING = "informing", "gating"
RISK_SENSITIVE, RISK_EGRESS, RISK_REVERSIBLE = 1, 2, 3
RISK_VOCAB = [
    ("sensitive",  RISK_SENSITIVE,  CLASS_GATING),
    ("egress",     RISK_EGRESS,     CLASS_GATING),
    ("reversible", RISK_REVERSIBLE, CLASS_INFORMING),
]
# The private/experimental extensible range: codes at or above this are not in the standard set and
# are unknown to a verifier that lacks them (rejected if carried critical, ignored if not).
EXTENSIBLE_RANGE_START = 0x1000
UNKNOWN_RISK_A = 0x1000  # an unknown code in the extensible range
UNKNOWN_RISK_B = 0x2000  # another unknown code in the extensible range

CRITICAL, NONCRITICAL = 1, 0


def sha384(b):
    return hashlib.sha384(b).digest()


def cid(b):
    """T1 content-id framing: multihash(0x20, SHA-384(bytes)) = 0x20 0x30 || SHA-384(b) (50 octets)."""
    return b"\x20\x30" + sha384(b)


def noncanon_map(pairs):
    """Hand-build a CBOR map carrying the SAME pairs but with top-level keys emitted in DESCENDING
    order — non-canonical per RFC 8949 §4.2.1 (the strict shared decoder rejects it NonCanonical).
    `pairs` is the canonical ascending list [(k, v), ...]; each value is encoded canonically, only the
    top-level key order is wrong. Built by hand, NOT via cbor_oracle.encode (which always sorts)."""
    n = len(pairs)
    assert n < 24
    out = bytes([0xA0 | n])
    for (k, v) in reversed(pairs):
        out += cbor_oracle.encode(k) + cbor_oracle.encode(v)
    return out


# ---- negotiation ------------------------------------------------------------------------------

def message_body(negotiation, role, profile, causes):
    # {1: negotiation (bstr), 2: role (uint), 3: profile (uint), 4: [* cause content-id (bstr)]}.
    return cbor_oracle.encode(("map", [(1, negotiation), (2, role), (3, profile), (4, list(causes))]))


def msg_out(negotiation, role, profile, causes):
    body = message_body(negotiation, role, profile, causes)
    return {
        "role": role, "profile": profile,
        "causes_hex": [c.hex() for c in causes],
        "body_hex": body.hex(), "head_hex": sha384(body).hex(), "id_hex": cid(body).hex(),
    }


# ---- risk labels ------------------------------------------------------------------------------

def risk_label_body(code, critical):
    # {1: code (uint), 2: critical (uint 1/0 — no CBOR boolean on the spine)}.
    return cbor_oracle.encode(("map", [(1, code), (2, critical)]))


def labeled_object_body(effect, labels):
    # {1: effect (uint, C5), 2: [* risk-label]}.
    label_vals = [("map", [(1, c), (2, cr)]) for (c, cr) in labels]
    return cbor_oracle.encode(("map", [(1, effect), (2, label_vals)]))


# ---- trust ref --------------------------------------------------------------------------------

def trust_ref_body(registry, reference, subject):
    # {1: registry (bstr), 2: reference (bstr, content-id), 3: subject (bstr)}.
    return cbor_oracle.encode(("map", [(1, registry), (2, reference), (3, subject)]))


def build_edge_cases():
    """Standard wire-format edge cases (Part 1), mirroring the C17 continuation family:
      #1 keys-out-of-order: a negotiation-message body whose top-level keys are DESCENDING (4,3,2,1) —
         rejected NonCanonical by the strict shared decoder ParseMessage routes through.
      #2 empty-vs-absent: the causes[] (message field 4) and the labels[] (labeled-object field 2) are
         PRESENT arrays. An empty causes[]/labels[] is DISTINCT by content-id from a populated one, and
         BOTH are distinct from a body whose field is ABSENT (which is rejected NegMalformed — the field
         is mandatory). "empty present != omitted."
      #4 minimal: the smallest legal offer (empty negotiation id, offer, baseline, no causes), the
         smallest labeled-object (read_only, no labels), and the smallest trust-ref (empty fields).
      #5 look-alike: a trust-ref body {1:bstr,2:bstr,3:bstr} fed to ParseMessage, and a message body
         {1:bstr,2:uint,3:uint,4:arr} fed to ParseTrustRef, are each rejected NegMalformed — a
         cross-KIND rejection beyond the offer/accept role-literal already graded by VerifyAccept/CDDL.
      #3 (oversized >2^53 counter) is N/A: the C20 bodies carry no 64-bit counter field."""
    neg = b"neg-0001"

    # #1 keys-out-of-order over an offer {1:negotiation,2:role,3:profile,4:causes[]}.
    koo_pairs = [(1, neg), (2, ROLE_OFFER), (3, PROFILE_BASELINE), (4, [])]
    koo_canon = message_body(neg, ROLE_OFFER, PROFILE_BASELINE, [])
    koo_noncanon = noncanon_map(koo_pairs)
    assert koo_noncanon != koo_canon and len(koo_noncanon) == len(koo_canon)
    keys_out_of_order = {
        "canonical_offer_body_hex": koo_canon.hex(),
        "noncanonical_offer_body_hex": koo_noncanon.hex(),
        "reject": "NonCanonical",
        "note": "same content, top-level keys emitted descending (4,3,2,1) - the strict decoder rejects NonCanonical.",
    }

    # #2 empty-vs-absent: causes[] (message field 4).
    one_cause = cid(b"predecessor-message")
    causes_empty = message_body(neg, ROLE_OFFER, PROFILE_BASELINE, [])         # present empty array
    causes_one = message_body(neg, ROLE_OFFER, PROFILE_BASELINE, [one_cause])  # present populated array
    causes_absent = cbor_oracle.encode(("map", [(1, neg), (2, ROLE_OFFER), (3, PROFILE_BASELINE)]))  # field 4 OMITTED
    assert causes_empty != causes_one != causes_absent and causes_empty != causes_absent
    # #2 empty-vs-absent: labels[] (labeled-object field 2).
    labels_empty = labeled_object_body(READ_ONLY, [])
    labels_one = labeled_object_body(READ_ONLY, [(RISK_SENSITIVE, CRITICAL)])
    labels_absent = cbor_oracle.encode(("map", [(1, READ_ONLY)]))              # field 2 OMITTED
    assert labels_empty != labels_one != labels_absent and labels_empty != labels_absent
    empty_vs_absent = {
        "causes": {
            "empty_present": {"body_hex": causes_empty.hex(), "id_hex": cid(causes_empty).hex()},
            "one_cause": {"cause_hex": one_cause.hex(), "body_hex": causes_one.hex(), "id_hex": cid(causes_one).hex()},
            "absent_field": {"body_hex": causes_absent.hex(), "reject": "NegMalformed"},
        },
        "labels": {
            "empty_present": {"body_hex": labels_empty.hex(), "id_hex": cid(labels_empty).hex()},
            "one_label": {"code": RISK_SENSITIVE, "critical": CRITICAL, "body_hex": labels_one.hex(), "id_hex": cid(labels_one).hex()},
            "absent_field": {"body_hex": labels_absent.hex(), "reject": "NegMalformed"},
        },
        "note": ("an empty causes[]/labels[] is distinct by content-id from a populated one; both differ "
                 "from a body whose field is absent (rejected - the field is mandatory)."),
    }

    # #4 minimal offer / labeled-object / trust-ref.
    min_offer = message_body(b"", ROLE_OFFER, PROFILE_BASELINE, [])
    min_labeled = labeled_object_body(READ_ONLY, [])
    min_tref = trust_ref_body(b"", b"", b"")
    minimal = {
        "offer": {"negotiation_hex": "", "role": ROLE_OFFER, "profile": PROFILE_BASELINE,
                  "body_hex": min_offer.hex(), "id_hex": cid(min_offer).hex()},
        "labeled_object": {"effect": READ_ONLY, "body_hex": min_labeled.hex(), "id_hex": cid(min_labeled).hex()},
        "trust_ref": {"body_hex": min_tref.hex(), "id_hex": cid(min_tref).hex()},
        "note": "smallest legal offer (empty neg id), labeled-object (read_only, no labels), trust-ref (empty fields).",
    }

    # #5 look-alike (cross-KIND): a trust-ref body fed to ParseMessage, and a message body fed to
    # ParseTrustRef, are each rejected NegMalformed (wrong field types for the target kind).
    la_tref = trust_ref_body(b"erc-8004:reputation", cid(b"external-record"), b"subject-x")
    la_msg = message_body(neg, ROLE_OFFER, PROFILE_BASELINE, [])
    look_alike = {
        "trust_ref_as_message": {"body_hex": la_tref.hex(), "reject": "NegMalformed",
                                 "note": "a {1:bstr,2:bstr,3:bstr} trust-ref fed to ParseMessage: field 2 is not the uint role."},
        "message_as_trust_ref": {"body_hex": la_msg.hex(), "reject": "NegMalformed",
                                 "note": "a {1:bstr,2:uint,3:uint,4:arr} message fed to ParseTrustRef: field 2 is not a bstr reference."},
    }

    return {
        "keys_out_of_order": keys_out_of_order,
        "empty_vs_absent": empty_vs_absent,
        "minimal": minimal,
        "look_alike": look_alike,
        "oversized_note": "edge case #3 (oversized >2^53 counter) is N/A: the C20 bodies carry no 64-bit counter.",
    }


def build():
    # ==== Task 5.1 — governed negotiation ======================================================
    neg1 = b"neg-0001"
    offer = msg_out(neg1, ROLE_OFFER, PROFILE_BASELINE, [])
    offer_id = bytes.fromhex(offer["id_hex"])
    counter = msg_out(neg1, ROLE_COUNTER, PROFILE_STREAMING, [offer_id])
    counter_id = bytes.fromhex(counter["id_hex"])
    accept = msg_out(neg1, ROLE_ACCEPT, PROFILE_STREAMING, [counter_id])  # descends offer->counter->accept

    # A SECOND, DISTINCT offer (a different profile => a different content-id) whose accept descends
    # from IT, never from the first offer. This is the "accept not descended from THIS offer" case.
    offer2 = msg_out(neg1, ROLE_OFFER, PROFILE_BATCH, [])
    offer2_id = bytes.fromhex(offer2["id_hex"])
    accept_bad = msg_out(neg1, ROLE_ACCEPT, PROFILE_BATCH, [offer2_id])  # descends from offer2, NOT from offer

    # An offer selecting a profile OUTSIDE the closed set — rejected (UnknownProfile).
    unknown_profile_offer = msg_out(neg1, ROLE_OFFER, UNKNOWN_PROFILE, [])
    # A message carrying an unknown role code — rejected (UnknownRole).
    unknown_role = msg_out(neg1, 9, PROFILE_BASELINE, [])

    # The descend/not-descend graph outcomes over the full message set {offer, counter, accept,
    # offer2, accept_bad}: accept descends from offer; accept_bad does not.
    negotiation = {
        "negotiation_hex": neg1.hex(),
        "roles": {"offer": ROLE_OFFER, "counter": ROLE_COUNTER, "accept": ROLE_ACCEPT},
        "profiles": {"baseline": PROFILE_BASELINE, "streaming": PROFILE_STREAMING, "batch": PROFILE_BATCH},
        "unknown_profile": UNKNOWN_PROFILE,
        "offer": offer,
        "counter": counter,
        "accept": accept,
        "offer2": offer2,
        "accept_not_descended": accept_bad,
        "unknown_profile_offer": unknown_profile_offer,
        "unknown_role_message": unknown_role,
        "descends": {"accept_from_offer": True, "accept_bad_from_offer": False},
        "agreed_profile": PROFILE_STREAMING,  # the accept's selected pre-registered profile
        "note": ("offer/counter/accept are signed causally-linked objects; the accept descends from "
                 "the offer by walking the causes DAG; the selected profile is one of the closed "
                 "pre-registered set; unknown profile/role and a non-descended accept are rejected."),
    }

    # ==== Task 5.2 — advisory risk labels ======================================================
    vocab = [{"name": n, "code": c, "class": cl} for (n, c, cl) in RISK_VOCAB]
    # Sample carried labels (each a signed-body fragment).
    sample_labels = {
        "sensitive_critical":   {"code": RISK_SENSITIVE,  "critical": CRITICAL,
                                 "body_hex": risk_label_body(RISK_SENSITIVE, CRITICAL).hex()},
        "egress_noncritical":   {"code": RISK_EGRESS,     "critical": NONCRITICAL,
                                 "body_hex": risk_label_body(RISK_EGRESS, NONCRITICAL).hex()},
        "reversible_noncritical": {"code": RISK_REVERSIBLE, "critical": NONCRITICAL,
                                 "body_hex": risk_label_body(RISK_REVERSIBLE, NONCRITICAL).hex()},
        "unknown_critical":     {"code": UNKNOWN_RISK_A,  "critical": CRITICAL,
                                 "body_hex": risk_label_body(UNKNOWN_RISK_A, CRITICAL).hex()},
        "unknown_noncritical":  {"code": UNKNOWN_RISK_B,  "critical": NONCRITICAL,
                                 "body_hex": risk_label_body(UNKNOWN_RISK_B, NONCRITICAL).hex()},
    }

    # The carried-label set carried on the labeled objects below: a gating "sensitive" (critical) and
    # a gating "egress" (non-critical). Both are recognized; NEITHER changes the effect class.
    carried = [(RISK_SENSITIVE, CRITICAL), (RISK_EGRESS, NONCRITICAL)]

    # A labeled object at EACH effect class, with the carried labels AND without any labels. The
    # LOAD-BEARING invariant: the effect class is `effect` normalized, identical with or without the
    # labels — risk labels never alter the effect (the closed lattice is untouched).
    effect_names = {0: "read_only", 1: "idempotent_write", 2: "non_idempotent_write", 3: "destructive"}
    labeled = []
    for e in (READ_ONLY, IDEMPOTENT_WRITE, NON_IDEMPOTENT_WRITE, DESTRUCTIVE):
        with_body = labeled_object_body(e, carried)
        without_body = labeled_object_body(e, [])
        labeled.append({
            "effect": e, "effect_name": effect_names[e], "effect_class": e,  # normalize(e) == e for 0..3
            "with_labels": {"body_hex": with_body.hex(), "head_hex": sha384(with_body).hex(),
                            "id_hex": cid(with_body).hex()},
            "without_labels": {"body_hex": without_body.hex(), "head_hex": sha384(without_body).hex(),
                               "id_hex": cid(without_body).hex()},
        })

    # Validation outcomes (the critical-extension rule R-2.5):
    #  * a recognized-plus-unknown-noncritical set validates, recognized = the two known labels;
    #  * a set containing an unknown CRITICAL label is rejected.
    validate = {
        "recognized_set": {
            "carried": [
                {"code": RISK_SENSITIVE, "critical": CRITICAL},
                {"code": RISK_REVERSIBLE, "critical": NONCRITICAL},
                {"code": UNKNOWN_RISK_B, "critical": NONCRITICAL},  # unknown non-critical -> ignored
            ],
            "recognized_codes": [RISK_SENSITIVE, RISK_REVERSIBLE],  # the unknown non-critical is dropped
            "error": None,
        },
        "unknown_critical_rejected": {
            "carried": [{"code": UNKNOWN_RISK_A, "critical": CRITICAL}],
            "error": "UnknownCriticalRisk",
        },
    }

    risk = {
        "vocabulary": vocab,
        "extensible_range_start": EXTENSIBLE_RANGE_START,
        "sample_labels": sample_labels,
        "carried_on_labeled_objects": [{"code": c, "critical": cr} for (c, cr) in carried],
        "labeled_objects": labeled,
        "validate": validate,
        "note": ("risk labels are an ADVISORY dimension: carrying one NEVER changes the effect class "
                 "(the closed C5 lattice is untouched). An unknown critical label is rejected (R-2.5); "
                 "an unknown non-critical one is ignored. gating/informing is a vocabulary attribute; "
                 "critical/non-critical is a per-carriage flag."),
    }

    # ==== Task 5.3 — trust reference (checkable, never weighed) =================================
    # An EXTERNAL registry record (ERC-8004-style). It deliberately carries a "score" field to make
    # the point that the wire CARRIES the reference but never READS or WEIGHS the score.
    external_record = (b'{"schema":"erc-8004-reputation","subject":"agent-billing-0001",'
                       b'"score":"87","attestor":"did:example:registry-a"}')
    reference = cid(external_record)              # the content-id the trust ref binds
    tampered_record = external_record.replace(b'"score":"87"', b'"score":"99"')
    tampered_reference = cid(tampered_record)     # a changed record yields a different content-id
    assert tampered_reference != reference

    registry_a = b"erc-8004:reputation"
    registry_b = b"erc-8004:identity"            # a SECOND registry referencing the same record
    subject = b"agent-billing-0001"

    tref_a = trust_ref_body(registry_a, reference, subject)
    tref_b = trust_ref_body(registry_b, reference, subject)
    trust = {
        "registry_a_hex": registry_a.hex(),
        "registry_b_hex": registry_b.hex(),
        "subject_hex": subject.hex(),
        "external_record_hex": external_record.hex(),
        "reference_hex": reference.hex(),
        "tampered_record_hex": tampered_record.hex(),
        "tampered_reference_hex": tampered_reference.hex(),
        "ref_a": {"body_hex": tref_a.hex(), "head_hex": sha384(tref_a).hex(), "id_hex": cid(tref_a).hex()},
        "ref_b": {"body_hex": tref_b.hex(), "head_hex": sha384(tref_b).hex(), "id_hex": cid(tref_b).hex()},
        "note": ("a carried reputation/registry reference verifies by recomputing its content-id over "
                 "the external record; NO wire field scores it. Two registries referencing the same "
                 "record verify symmetrically — the wire weighs neither; resolution is the relying "
                 "party's, never a wire computation."),
    }

    return {
        "source": ("design §23; naalp-negotiation-{offer,counter,accept} {1:negotiation,2:role,"
                   "3:profile,4:[cause]} (signed, causally-linked; accept must descend from offer via "
                   "the causes DAG; profile from the closed pre-registered set; unknown profile/role "
                   "rejected); naalp-risk-label {1:code,2:critical} + naalp-labeled-object "
                   "{1:effect,2:[risk-label]} (advisory; effect class unchanged by labels; unknown "
                   "critical rejected, unknown non-critical ignored per R-2.5); naalp-trust-ref "
                   "{1:registry,2:reference,3:subject} (checkable by content-id recompute; never "
                   "weighed on the wire). head=SHA-384(body); content-id=multihash(0x20,SHA-384)."),
        "negotiation": negotiation,
        "risk": risk,
        "trust": trust,
        "edge_cases": build_edge_cases(),
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "negotiation", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # newline="\n" forces LF on every platform so the worktree vector matches the LF-normalized git
    # blob and any hash-pinned vector gate stays green in CI.
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    n = data["negotiation"]
    print("  negotiation: offer id=%s... accept descends=%s, bad descends=%s, agreed profile=%d" % (
        n["offer"]["id_hex"][:16], n["descends"]["accept_from_offer"],
        n["descends"]["accept_bad_from_offer"], n["agreed_profile"]))
    print("  risk: %d vocab labels, %d labeled objects (effect unchanged), extensible@0x%x" % (
        len(data["risk"]["vocabulary"]), len(data["risk"]["labeled_objects"]),
        data["risk"]["extensible_range_start"]))
    print("  trust: ref_a id=%s... reference=%s..." % (
        data["trust"]["ref_a"]["id_hex"][:16], data["trust"]["reference_hex"][:16]))


if __name__ == "__main__":
    main()
