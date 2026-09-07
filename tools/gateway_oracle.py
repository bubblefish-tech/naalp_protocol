# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C21 task 5B.3 — the portable gateway decision object (design.md §24).

A naalp-gateway-decision is a SIGNED decision object an enforcement gateway of ANY vendor emits as
PORTABLE EVIDENCE that it decided about an action. Its authority is the SIGNATURE OVER THE BYTES,
never the connection or host that served them (exactly as the C18 signed description): so the same
signed decision RE-VERIFIES IDENTICALLY when served by a party OTHER than the gateway (the third-party
re-serve property). This is the EVIDENCE FORMAT ONLY — it carries a decision, the action it is about,
the deciding policy's identity, and the effect class; it defines NO policy language.

  * naalp-gateway-decision {1: decision, 2: action, 3: policy, 4: effect, ?5: ordering-disclosure,
    ?6: naalp-foreign-profile-pin} — `decision` is a closed set (allow / deny / hold); `action` is the
    T1 content-id of the action decided about; `policy` is the opaque policy identity (a name, NOT a
    policy program); `effect` is the C5 effect class of the action. Field 5 (R1, OPTIONAL) is the
    shared `ordering-disclosure` embeddable group already frozen by S1 (naalp-decision-record) —
    ABSENT reads correspondence-only, never a stronger claim; mandatory fields 1-4 are validated
    FIRST, so a body failing a mandatory-field check is GwMalformed regardless of any 5/6. Field 6
    (R8, OPTIONAL) is `naalp-foreign-profile-pin` {1: tstr id, 2: tstr revision}, present iff the
    decision was over foreign-protocol evidence — it pins the foreign evidence profile's identifier
    (an absolute URI) AND the revision pinned at decision time (binding the reference, not just the
    class).

Non-circular authority (NOT the code under test):
  * Every body is built by the shared deterministic-CBOR constructor (cbor_oracle, graded against
    RFC 8949 in T1) — never by the Go/Rust gateway code.
  * head = SHA-384(body); content-id = multihash(0x20, SHA-384(body)) (design §2.3) — stdlib hashlib.
  * The decision vocabulary and the effect lattice are fixed here from the design; Go and Rust grade
    against these values. ML-DSA signatures are deterministic and cross-checked Go == Rust in the impl
    tests; Python stdlib has no ML-DSA, so this oracle fixes only the SIGNED INPUT (the body bytes).

Emits vectors/gateway/cases.json (LF-normalized).
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

# Closed decision vocabulary. A code outside the set is rejected (UnknownGatewayDecision).
DECISION_ALLOW, DECISION_DENY, DECISION_HOLD = 0, 1, 2
UNKNOWN_DECISION = 99
DECISION_VOCAB = [
    ("allow", DECISION_ALLOW),
    ("deny", DECISION_DENY),
    ("hold", DECISION_HOLD),
]

# ordering-basis (design §26.3; spec/naalp-draft-01.cddl `ordering-basis`), fixed here from the CDDL
# text directly, matching the independent duplication convention every sibling oracle in this family
# uses (decision_record_oracle.py, egress_attestation_oracle.py) rather than importing a shared
# constant module.
CORRESPONDENCE_ONLY, SINGLE_BOUNDARY, EXTERNAL_MECHANISM = 0, 1, 2


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


def decision_body(decision, action, policy, effect, ordering=None, foreign_profile=None):
    # {1: decision (uint), 2: action (bstr, content-id), 3: policy (bstr), 4: effect (uint),
    #  ?5: ordering-disclosure, ?6: naalp-foreign-profile-pin}. `ordering`/`foreign_profile`, when
    # given, are ("map", [...]) tuples (see ordering_group()/foreign_profile_pin() below); the
    # default None on both keeps every EXISTING call site (the three base decisions + all Part-1
    # edge cases) byte-identical to before this field was added.
    pairs = [(1, decision), (2, action), (3, policy), (4, effect)]
    if ordering is not None:
        pairs.append((5, ordering))
    if foreign_profile is not None:
        pairs.append((6, foreign_profile))
    return cbor_oracle.encode(("map", pairs))


def ordering_group(basis, boundary=None, mechanism=None, relation=None):
    """The embeddable ordering-disclosure group {1: basis, ?2: boundary, ?3: mechanism,
    ?4: relation} (design §26.3) — the SAME shared field-5/6 group naalp-decision-record already
    freezes; duplicated here (not imported) matching this file's own independent-oracle convention.
    Only the fields actually passed are included."""
    pairs = [(1, basis)]
    if boundary is not None:
        pairs.append((2, boundary))
    if mechanism is not None:
        pairs.append((3, mechanism))
    if relation is not None:
        pairs.append((4, relation))
    return ("map", pairs)


def foreign_profile_pin(profile_id, revision):
    """The embeddable naalp-foreign-profile-pin group {1: tstr id, 2: tstr revision} (R8). Both
    fields are plain Python str -> cbor_oracle.encode's str branch emits tstr (major type 3)."""
    return ("map", [(1, profile_id), (2, revision)])


def decision_out(decision, action, policy, effect):
    body = decision_body(decision, action, policy, effect)
    return {
        "decision": decision, "effect": effect, "policy_hex": policy.hex(), "action_hex": action.hex(),
        "body_hex": body.hex(), "head_hex": sha384(body).hex(), "id_hex": cid(body).hex(),
    }


def build_edge_cases(action_cid, policy):
    """Standard wire-format edge cases (Part 1):
      #1 keys-out-of-order: a decision body whose top-level keys are DESCENDING (4,3,2,1) — rejected
         NonCanonical by the strict shared decoder ParseDecision routes through.
      #2 empty-vs-absent (the policy field 3, a bstr): an empty policy identity is PRESENT and valid,
         DISTINCT by content-id from a populated one, and BOTH differ from a body whose policy field is
         ABSENT (rejected GwMalformed — field 3 is mandatory).
      #4 minimal decision: allow, empty action, empty policy, read_only — encodes, round-trips, verifies.
      #5 look-alike: naalp-gateway-decision defines a SINGLE body kind, so the look-alike is a SIBLING
         C21 body — a naalp-ui-event {1:bstr session,2:uint kind,3:bstr action,4:uint seq,5:bstr prev} —
         whose field 1 is a bstr where the decision uint is required; ParseDecision rejects it GwMalformed.
      #3 (oversized >2^53 counter) is N/A: the gateway-decision body carries no 64-bit counter field."""
    # #1 keys-out-of-order over a deny decision.
    koo_pairs = [(1, DECISION_DENY), (2, action_cid), (3, policy), (4, DESTRUCTIVE)]
    koo_canon = decision_body(DECISION_DENY, action_cid, policy, DESTRUCTIVE)
    koo_noncanon = noncanon_map(koo_pairs)
    assert koo_noncanon != koo_canon and len(koo_noncanon) == len(koo_canon)
    keys_out_of_order = {
        "decision": DECISION_DENY, "action_hex": action_cid.hex(), "policy_hex": policy.hex(), "effect": DESTRUCTIVE,
        "canonical_body_hex": koo_canon.hex(),
        "noncanonical_body_hex": koo_noncanon.hex(),
        "reject": "NonCanonical",
        "note": "same content, top-level keys emitted descending (4,3,2,1) - the strict decoder rejects NonCanonical.",
    }

    # #2 empty-vs-absent (policy field 3).
    empty_policy_body = decision_body(DECISION_ALLOW, action_cid, b"", IDEMPOTENT_WRITE)
    populated_policy_body = decision_body(DECISION_ALLOW, action_cid, policy, IDEMPOTENT_WRITE)
    absent_policy_body = cbor_oracle.encode(("map", [(1, DECISION_ALLOW), (2, action_cid), (4, IDEMPOTENT_WRITE)]))  # field 3 OMITTED
    assert empty_policy_body != populated_policy_body != absent_policy_body and empty_policy_body != absent_policy_body
    empty_vs_absent = {
        "empty_policy": {"body_hex": empty_policy_body.hex(), "id_hex": cid(empty_policy_body).hex()},
        "populated_policy": {"policy_hex": policy.hex(), "body_hex": populated_policy_body.hex(), "id_hex": cid(populated_policy_body).hex()},
        "absent_field": {"body_hex": absent_policy_body.hex(), "reject": "GwMalformed"},
        "note": ("an empty policy identity is present and valid, distinct by content-id from a populated "
                 "one; both differ from a body whose policy field is absent (rejected - field 3 is mandatory)."),
    }

    # #4 minimal decision: allow, empty action, empty policy, read_only.
    min_body = decision_body(DECISION_ALLOW, b"", b"", READ_ONLY)
    minimal = {
        "decision": DECISION_ALLOW, "action_hex": "", "policy_hex": "", "effect": READ_ONLY,
        "body_hex": min_body.hex(), "id_hex": cid(min_body).hex(),
        "note": "smallest valid decision: allow, empty action, empty policy, read_only.",
    }

    # #5 look-alike: a naalp-ui-event body (a sibling C21 kind) fed to the gateway-decision parser.
    la_session = b"ui-sess"
    la_body = cbor_oracle.encode(("map", [(1, la_session), (2, 0), (3, action_cid), (4, 0), (5, b"\x00" * 48)]))
    look_alike = {
        "body_hex": la_body.hex(),
        "reject": "GwMalformed",
        "note": "a ui-event {1:bstr,2:uint,3:bstr,4:uint,5:bstr} fed to ParseDecision: field 1 is not the uint decision.",
    }

    return {
        "keys_out_of_order": keys_out_of_order,
        "empty_vs_absent": empty_vs_absent,
        "minimal": minimal,
        "look_alike": look_alike,
        "oversized_note": "edge case #3 (oversized >2^53 counter) is N/A: the gateway-decision body carries no 64-bit counter.",
    }


def build_optional_fields(action_cid, policy):
    """R1 ordering (field 5) + R8 foreign-profile (field 6) additive vectors. decision/action/
    policy/effect are held constant (allow, action_cid, policy, idempotent_write) across the
    positive cases so field 5/6 presence is the isolated variable.

      with_ordering            - field 5 (single-boundary) present, field 6 absent.
      with_foreign_profile     - field 6 present, field 5 absent.
      with_both                - field 5 (external-mechanism, with relation) AND field 6 both present.
      foreign_profile_malformed (reject) - field 6 present but omits key 2 (revision) -> VerifyDecision
        must return ForeignProfileMalformed (ParseDecision decodes it structurally fine; the missing
        mandatory sub-field is a semantic Validate() rejection, not a decode failure).
      ordering_malformed (reject) - field 5 basis=external-mechanism(2) but key 2 (boundary) is ALSO
        present -> VerifyDecision must return OrderingDisclosureMalformed.
    """
    decision, effect = DECISION_ALLOW, IDEMPOTENT_WRITE
    boundary = b"SIGNER_B-boundary"
    mechanism = b"external-log:acme-transparency-v1"
    relation = cid(b"checkpoint-example")
    profile_id = "https://example-registry.test/profiles/acme"
    profile_rev = "2026-01"

    ord_single = ordering_group(SINGLE_BOUNDARY, boundary=boundary)
    with_ordering_body = decision_body(decision, action_cid, policy, effect, ordering=ord_single)
    with_ordering = {
        "decision": decision, "action_hex": action_cid.hex(), "policy_hex": policy.hex(), "effect": effect,
        "ordering": {"basis": SINGLE_BOUNDARY, "boundary_hex": boundary.hex()},
        "body_hex": with_ordering_body.hex(), "head_hex": sha384(with_ordering_body).hex(),
        "id_hex": cid(with_ordering_body).hex(),
        "note": "field 5 present (single-boundary), field 6 absent.",
    }

    fp = foreign_profile_pin(profile_id, profile_rev)
    with_fp_body = decision_body(decision, action_cid, policy, effect, foreign_profile=fp)
    with_foreign_profile = {
        "decision": decision, "action_hex": action_cid.hex(), "policy_hex": policy.hex(), "effect": effect,
        "foreign_profile": {"id": profile_id, "revision": profile_rev},
        "body_hex": with_fp_body.hex(), "head_hex": sha384(with_fp_body).hex(),
        "id_hex": cid(with_fp_body).hex(),
        "note": "field 6 present, field 5 absent.",
    }

    ord_ext = ordering_group(EXTERNAL_MECHANISM, mechanism=mechanism, relation=relation)
    with_both_body = decision_body(decision, action_cid, policy, effect, ordering=ord_ext, foreign_profile=fp)
    with_both = {
        "decision": decision, "action_hex": action_cid.hex(), "policy_hex": policy.hex(), "effect": effect,
        "ordering": {"basis": EXTERNAL_MECHANISM, "mechanism_hex": mechanism.hex(), "relation_hex": relation.hex()},
        "foreign_profile": {"id": profile_id, "revision": profile_rev},
        "body_hex": with_both_body.hex(), "head_hex": sha384(with_both_body).hex(),
        "id_hex": cid(with_both_body).hex(),
        "note": "field 5 (external-mechanism, with relation) AND field 6 both present.",
    }

    fp_missing_revision = ("map", [(1, profile_id)])  # key 2 (revision) OMITTED
    fp_malformed_body = decision_body(decision, action_cid, policy, effect, foreign_profile=fp_missing_revision)
    foreign_profile_malformed = {
        "body_hex": fp_malformed_body.hex(),
        "reject": "ForeignProfileMalformed",
        "note": ("field 6 present but omits key 2 (revision): id and revision are both mandatory tstr. "
                 "ParseDecision decodes the body structurally fine (field 6 present, id populated); "
                 "VerifyDecision's ForeignProfilePin.Validate() rejects the missing revision."),
    }

    ord_bad = ordering_group(EXTERNAL_MECHANISM, boundary=boundary, mechanism=mechanism)
    ord_malformed_body = decision_body(decision, action_cid, policy, effect, ordering=ord_bad)
    ordering_malformed = {
        "body_hex": ord_malformed_body.hex(),
        "reject": "OrderingDisclosureMalformed",
        "note": ("field 5 basis=external-mechanism but key 2 (boundary) is also present; "
                 "external-mechanism requires key 2 absent."),
    }

    return {
        "with_ordering": with_ordering,
        "with_foreign_profile": with_foreign_profile,
        "with_both": with_both,
        "foreign_profile_malformed": foreign_profile_malformed,
        "ordering_malformed": ordering_malformed,
    }


def build():
    # The action the gateway decided about (a proposed effecting call). Its content-id is what the
    # decision names in field 2 — the decision is about the exact action bytes.
    action_bytes = b'{"tool":"delete_bucket","args":{"bucket":"prod-logs"}}'
    action_cid = cid(action_bytes)
    policy = b"policy:acme-egress-v3"  # the opaque deciding-policy identity (a name, not a program)

    allow = decision_out(DECISION_ALLOW, action_cid, policy, IDEMPOTENT_WRITE)
    deny = decision_out(DECISION_DENY, action_cid, policy, DESTRUCTIVE)
    hold = decision_out(DECISION_HOLD, action_cid, policy, NON_IDEMPOTENT_WRITE)

    vocab = [{"name": n, "code": c} for (n, c) in DECISION_VOCAB]

    return {
        "source": ("design §24; naalp-gateway-decision {1:decision,2:action,3:policy,4:effect} is a "
                   "signed decision object an enforcement gateway of any vendor emits as portable "
                   "evidence. Its authority is the signature over the bytes, never the connection, so "
                   "it verifies offline and re-verifies IDENTICALLY when served by a party other than "
                   "the gateway (third-party re-serve). Evidence format only; no policy language. "
                   "decision in {allow,deny,hold}; action = content-id of the decided action; policy = "
                   "opaque policy identity; effect = C5 class. head=SHA-384(body); "
                   "content-id=multihash(0x20,SHA-384)."),
        "decision_vocabulary": vocab,
        "unknown_decision": UNKNOWN_DECISION,
        "action_bytes_hex": action_bytes.hex(),
        "action_cid_hex": action_cid.hex(),
        "policy_hex": policy.hex(),
        "decisions": {"allow": allow, "deny": deny, "hold": hold},
        "edge_cases": build_edge_cases(action_cid, policy),
        "optional_fields": build_optional_fields(action_cid, policy),
        "note": ("all three decision bodies are ordinary COSE_Sign1 payloads; VerifyDecision takes NO "
                 "serving-party/connection identity, so the same bytes verify identically whether the "
                 "gateway or a third party serves them."),
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "gateway", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  allow id=%s... action cid=%s..." % (
        data["decisions"]["allow"]["id_hex"][:16], data["action_cid_hex"][:16]))
    print("  decisions: %s" % [v["name"] for v in data["decision_vocabulary"]])
    print("  optional_fields: %s" % list(data["optional_fields"].keys()))


if __name__ == "__main__":
    main()
