# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
RECONCILED against the FROZEN wire authority (spec/naalp-draft-01.cddl, commit c488c6d3; design.md
section 26.6): this file was built pre-freeze for the HELD 5-field E6.3 shape; the frozen CDDL adds
ONE optional field, `?6: ordering-disclosure` (design section 26.2/26.6), on top of the already-held
fields 1-5, unchanged. Fields 1-5 below (binding/digest/effect/audience/at) are BYTE-IDENTICAL to the
pre-freeze shape this file already produced — every existing pinned 5-field vector is unaffected —
and this reconciliation ADDS field-6 coverage (present-vs-absent, and the shared ordering-disclosure
well-formedness rules from design section 26.3) rather than changing anything already emitted.

Independent oracle for E6.3 — the egress-attestation object.

A naalp-egress-attestation is a SIGNED attestation a GATEWAY/SIDECAR emits that an object of a
given effect class, bound to a given audience, crossed an egress boundary at a given time — third-
party verifiable WITHOUT the payload. It is a near-clone of naalp-gateway-decision (design §24,
graded by tools/gateway_oracle.py): the gateway is the SIGNER, and verification takes NO serving-
party identity (the third-party re-serve property). It introduces NO new envelope, encoding,
signature, or identity mechanism.

  * naalp-egress-attestation {1: binding, 2: digest, 3: effect, 4: audience, 5: at, ?6: ordering} —
    `binding` is a closed set (content_bound=0 / content_free=1); `digest` is either the T1
    content-id of the crossed object (content_bound) or a hiding commitment
    SHA-384(content_id||salt) (content_free); `effect` is the C5 effect class; `audience` is the
    bound destination (empty-permitted); `at` is the crossing time in epoch milliseconds; `ordering`
    (field 6, OPTIONAL, design section 26.6) is an embedded ordering-disclosure group — ABSENT reads
    correspondence-only, never a stronger claim (design section 26.3), and is byte-compatible: an
    attestation carrying no field 6 encodes identically to the pre-freeze 5-field shape.

Non-circular authority (NOT the code under test):
  * Every body is built by the shared deterministic-CBOR constructor (cbor_oracle, graded against
    RFC 8949 in T1) — never by the Go/Rust gateway code.
  * head = SHA-384(body); content-id = multihash(0x20, SHA-384(body)) (design §2.3) — stdlib
    hashlib, matching gateway_oracle.py's cid().
  * The commitment = SHA-384(content_id || salt) — stdlib hashlib, computed here independent of
    EgressCommit under test.
  * The binding vocabulary and the effect lattice are fixed here from the design; Go and Rust grade
    against these values. ML-DSA signatures are deterministic and cross-checked Go == Rust in the
    impl tests; Python stdlib has no ML-DSA, so this oracle fixes only the SIGNED INPUT (the body
    bytes) — the cross-language SIGNED digest pin is computed and hardcoded once from a Go/Rust run
    (see EGRESS-RED-EVIDENCE.md), exactly as gateway_test.go's crossLangPinnedSignedDecisionSHA384.

64-bit-field discipline: field 5 (`at`, epoch ms) is a genuine 64-bit counter-shaped field (unlike
naalp-gateway-decision, which carries none). Per the nonce.derive seq lesson, every `at` value in
this corpus is ALSO emitted as an `at_str` decimal string (lossless at any width); Go/Rust tests
parse `at_str` (strconv.ParseUint / str::parse::<u64>()), never a bare JSON number, so no float64
JSON decoder anywhere in the toolchain can round an oversized epoch-ms value.

Emits vectors/egress_attestation/cases.json (LF-normalized).
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

# Closed binding vocabulary. A code outside the set is rejected (UnknownEgressBinding).
BINDING_CONTENT_BOUND, BINDING_CONTENT_FREE = 0, 1
UNKNOWN_BINDING = 99
BINDING_VOCAB = [
    ("content_bound", BINDING_CONTENT_BOUND),
    ("content_free", BINDING_CONTENT_FREE),
]

MAX_UINT64 = (1 << 64) - 1


def sha384(b):
    return hashlib.sha384(b).digest()


def cid(b):
    """T1 content-id framing: multihash(0x20, SHA-384(bytes)) = 0x20 0x30 || SHA-384(b) (50 octets)."""
    return b"\x20\x30" + sha384(b)


def commit(object_cid, salt):
    """The content_free hiding commitment: SHA-384(object_cid || salt) (48 octets). Computed here
    independent of gateway.EgressCommit under test (the non-circular oracle authority)."""
    return sha384(object_cid + salt)


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


# ordering-basis (design section 26.3), shared closed vocabulary with naalp-decision-record's field
# 5 and naalp-gateway-decision's optional field 5 (decision_record_oracle.py carries the same
# constants; duplicated here per this codebase's established per-oracle-file convention).
CORRESPONDENCE_ONLY, SINGLE_BOUNDARY, EXTERNAL_MECHANISM = 0, 1, 2
UNKNOWN_ORDERING_BASIS = 99


def ordering_group(basis, boundary=None, mechanism=None, relation=None):
    """The embeddable ordering-disclosure group {1: basis, ?2: boundary, ?3: mechanism,
    ?4: relation} (design section 26.2/26.3). Only the fields passed are included; a caller building
    a deliberately MALFORMED fixture passes fields that violate the basis-conditioned rule."""
    pairs = [(1, basis)]
    if boundary is not None:
        pairs.append((2, boundary))
    if mechanism is not None:
        pairs.append((3, mechanism))
    if relation is not None:
        pairs.append((4, relation))
    return ("map", pairs)


def attestation_body(binding, digest, effect, audience, at, ordering=None):
    # {1: binding (uint), 2: digest (bstr), 3: effect (uint), 4: audience (bstr), 5: at (uint),
    #  ?6: ordering (embedded ordering-disclosure group, design section 26.6)}. `ordering=None`
    # (the default) omits field 6 entirely, reproducing the pre-freeze 5-field shape byte-for-byte.
    pairs = [(1, binding), (2, digest), (3, effect), (4, audience), (5, at)]
    if ordering is not None:
        pairs.append((6, ordering))
    return cbor_oracle.encode(("map", pairs))


def attestation_out(binding, digest, effect, audience, at, ordering=None):
    body = attestation_body(binding, digest, effect, audience, at, ordering)
    return {
        "binding": binding,
        "digest_hex": digest.hex(), "effect": effect, "audience_hex": audience.hex(),
        "at_str": str(at),
        "body_hex": body.hex(), "head_hex": sha384(body).hex(), "id_hex": cid(body).hex(),
    }


def build_commitment_open(object_cid, wrong_object_cid, salt, wrong_salt, content_free_digest_hex):
    """The content_free commitment open/verify fixtures: a correct (object_cid, salt) pair OPENS
    the attestation's digest; a wrong salt OR a wrong object_cid must both FAIL to open."""
    assert commit(object_cid, salt).hex() == content_free_digest_hex, "oracle commitment must equal the content_free attestation digest"
    assert commit(object_cid, wrong_salt).hex() != content_free_digest_hex
    assert commit(wrong_object_cid, salt).hex() != content_free_digest_hex
    return {
        "object_cid_hex": object_cid.hex(),
        "wrong_object_cid_hex": wrong_object_cid.hex(),
        "salt_hex": salt.hex(),
        "wrong_salt_hex": wrong_salt.hex(),
        "commitment_hex": content_free_digest_hex,
        "note": ("OpenEgressCommitment(attestation, object_cid, salt) must be true; the wrong salt "
                 "and the wrong object_cid must both make it false. binding must be content_free — "
                 "a content_bound attestation never opens."),
    }


def build_edge_cases(object_cid, audience):
    """Standard wire-format edge cases (Part 1):
      #1 keys-out-of-order: an attestation body whose top-level keys are DESCENDING (5,4,3,2,1) —
         rejected NonCanonical by the strict shared decoder ParseEgressAttestation routes through.
      #2 empty-vs-absent (the audience field 4, empty-permitted): an empty audience is PRESENT and
         valid, DISTINCT by content-id from a populated one, and BOTH differ from a body whose
         audience field is ABSENT (rejected EgMalformed — field 4 is mandatory even though empty is
         permitted).
      #3 oversized counter: `at` (field 5) carries a value > 2^53 (2^64-1) — the full 64-bit range
         must round-trip losslessly; encoded via at_str (decimal string), never a bare JSON number.
      #4 minimal attestation: content_bound, empty digest, read_only, empty audience, at=0 —
         encodes, round-trips, verifies.
      #5 look-alike: naalp-egress-attestation is a near-clone of the SIBLING C21 body
         naalp-gateway-decision {1:uint,2:bstr,3:bstr,4:uint} (four fields, no field 5) fed to
         ParseEgressAttestation, which requires five mandatory fields; rejected EgMalformed."""
    # #1 keys-out-of-order over a content_free attestation.
    at_typical = 1735689600000  # 2025-01-01T00:00:00Z in epoch ms — well under 2^53
    digest_cf = commit(object_cid, b"\x01" * 32)
    koo_pairs = [(1, BINDING_CONTENT_FREE), (2, digest_cf), (3, DESTRUCTIVE), (4, audience), (5, at_typical)]
    koo_canon = attestation_body(BINDING_CONTENT_FREE, digest_cf, DESTRUCTIVE, audience, at_typical)
    koo_noncanon = noncanon_map(koo_pairs)
    assert koo_noncanon != koo_canon and len(koo_noncanon) == len(koo_canon)
    keys_out_of_order = {
        "binding": BINDING_CONTENT_FREE, "digest_hex": digest_cf.hex(), "effect": DESTRUCTIVE,
        "audience_hex": audience.hex(), "at_str": str(at_typical),
        "canonical_body_hex": koo_canon.hex(),
        "noncanonical_body_hex": koo_noncanon.hex(),
        "reject": "NonCanonical",
        "note": "same content, top-level keys emitted descending (5,4,3,2,1) - the strict decoder rejects NonCanonical.",
    }

    # #2 empty-vs-absent (audience field 4).
    empty_audience_body = attestation_body(BINDING_CONTENT_BOUND, object_cid, IDEMPOTENT_WRITE, b"", at_typical)
    populated_audience_body = attestation_body(BINDING_CONTENT_BOUND, object_cid, IDEMPOTENT_WRITE, audience, at_typical)
    absent_audience_body = cbor_oracle.encode(("map", [(1, BINDING_CONTENT_BOUND), (2, object_cid), (3, IDEMPOTENT_WRITE), (5, at_typical)]))  # field 4 OMITTED
    assert empty_audience_body != populated_audience_body != absent_audience_body and empty_audience_body != absent_audience_body
    empty_vs_absent = {
        "empty_audience": {"body_hex": empty_audience_body.hex(), "id_hex": cid(empty_audience_body).hex()},
        "populated_audience": {"audience_hex": audience.hex(), "body_hex": populated_audience_body.hex(), "id_hex": cid(populated_audience_body).hex()},
        "absent_field": {"body_hex": absent_audience_body.hex(), "reject": "EgMalformed"},
        "note": ("an empty audience is present and valid (empty-permitted), distinct by content-id "
                 "from a populated one; both differ from a body whose audience field is absent "
                 "(rejected - field 4 is mandatory even though the empty string is a legal value)."),
    }

    # #3 oversized counter: at = 2^64-1, the top of the field's range.
    oversized_body = attestation_body(BINDING_CONTENT_BOUND, object_cid, READ_ONLY, audience, MAX_UINT64)
    oversized_counter = {
        "binding": BINDING_CONTENT_BOUND, "digest_hex": object_cid.hex(), "effect": READ_ONLY,
        "audience_hex": audience.hex(), "at_str": str(MAX_UINT64),
        "body_hex": oversized_body.hex(), "id_hex": cid(oversized_body).hex(),
        "note": ("at = 2^64-1 (the full uint64 range), > 2^53 - carried as at_str (decimal string) "
                 "so no float64 JSON decoder anywhere in the toolchain can round it; the CBOR body "
                 "itself carries the raw 64-bit uint unchanged."),
    }

    # #4 minimal attestation: content_bound, empty digest, read_only, empty audience, at=0.
    min_body = attestation_body(BINDING_CONTENT_BOUND, b"", READ_ONLY, b"", 0)
    minimal = {
        "binding": BINDING_CONTENT_BOUND, "digest_hex": "", "effect": READ_ONLY,
        "audience_hex": "", "at_str": "0",
        "body_hex": min_body.hex(), "id_hex": cid(min_body).hex(),
        "note": "smallest valid attestation: content_bound, empty digest, empty audience, read_only, at=0.",
    }

    # #5 look-alike: a naalp-gateway-decision body (this construct's own sibling/near-clone) fed to
    # ParseEgressAttestation, which requires five mandatory fields (gateway-decision has four).
    la_policy = b"policy:acme-egress-v3"
    la_body = cbor_oracle.encode(("map", [(1, BINDING_CONTENT_FREE), (2, object_cid), (3, la_policy), (4, DESTRUCTIVE)]))
    look_alike = {
        "body_hex": la_body.hex(),
        "reject": "EgMalformed",
        "note": ("a naalp-gateway-decision body {1:uint,2:bstr,3:bstr,4:uint} (this construct's own "
                 "near-clone sibling) fed to ParseEgressAttestation: field 5 (at) is absent."),
    }

    return {
        "keys_out_of_order": keys_out_of_order,
        "empty_vs_absent": empty_vs_absent,
        "oversized_counter": oversized_counter,
        "minimal": minimal,
        "look_alike": look_alike,
    }


def build():
    # The object that crosses the egress boundary (a proposed effecting call's output). Its
    # content-id is what a content_bound attestation names directly in field 2, and what a
    # content_free attestation's commitment hides.
    object_bytes = b'{"tool":"export_customer_data","args":{"table":"users","rows":4821}}'
    object_cid = cid(object_bytes)
    wrong_object_bytes = b'{"tool":"export_customer_data","args":{"table":"invoices","rows":90}}'
    wrong_object_cid = cid(wrong_object_bytes)
    audience = b"acme-partner-endpoint"

    salt = bytes(range(32))            # deterministic fixed salt (oracle authority, not real RNG)
    wrong_salt = bytes(range(31, -1, -1))  # a DIFFERENT deterministic salt

    at_bound = 1735689600000    # 2025-01-01T00:00:00Z epoch ms
    at_free = 1738368000000     # 2025-02-01T00:00:00Z epoch ms

    content_bound = attestation_out(BINDING_CONTENT_BOUND, object_cid, IDEMPOTENT_WRITE, audience, at_bound)

    cf_digest = commit(object_cid, salt)
    content_free = attestation_out(BINDING_CONTENT_FREE, cf_digest, DESTRUCTIVE, audience, at_free)

    # field 6 (ordering, design section 26.6) reconciliation: field-6-ABSENT reproduces the
    # pre-freeze 5-field bytes exactly (asserted below); field-6-PRESENT is a distinct, byte-
    # compatible addition, one worked example per ordering-basis value.
    assert content_bound["body_hex"] == attestation_body(BINDING_CONTENT_BOUND, object_cid, IDEMPOTENT_WRITE, audience, at_bound).hex(), \
        "field-6-absent must byte-match the pre-freeze 5-field shape"
    mechanism_name = b"external-log:acme-transparency-v1"
    checkpoint_relation_cid = cid(b"checkpoint-example")  # ties into S3 (naalp-checkpoint-root cid)
    with_ordering_correspondence = attestation_out(
        BINDING_CONTENT_BOUND, object_cid, IDEMPOTENT_WRITE, audience, at_bound,
        ordering=ordering_group(CORRESPONDENCE_ONLY))
    with_ordering_single_boundary = attestation_out(
        BINDING_CONTENT_BOUND, object_cid, IDEMPOTENT_WRITE, audience, at_bound,
        ordering=ordering_group(SINGLE_BOUNDARY, boundary=b"boundary-signer-X"))
    with_ordering_external_mechanism = attestation_out(
        BINDING_CONTENT_FREE, cf_digest, DESTRUCTIVE, audience, at_free,
        ordering=ordering_group(EXTERNAL_MECHANISM, mechanism=mechanism_name, relation=checkpoint_relation_cid))
    assert content_bound["id_hex"] != with_ordering_correspondence["id_hex"], \
        "field-6-absent vs field-6-present(correspondence-only) must be distinct content ids"

    # ordering malformed on this carrier (design section 26.3 applies identically to every carrier):
    # single-boundary (1) with mechanism (key 3) ALSO present -> OrderingDisclosureMalformed.
    ordering_malformed_body = attestation_body(
        BINDING_CONTENT_BOUND, object_cid, IDEMPOTENT_WRITE, audience, at_bound,
        ordering=ordering_group(SINGLE_BOUNDARY, boundary=b"boundary-signer-X", mechanism=mechanism_name))
    ordering_malformed = {
        "body_hex": ordering_malformed_body.hex(), "reject": "OrderingDisclosureMalformed",
        "note": "field 6 basis=single-boundary but key 3 (mechanism) is also present; single-boundary requires 3/4 absent.",
    }
    unknown_ordering_basis_body = attestation_body(
        BINDING_CONTENT_BOUND, object_cid, IDEMPOTENT_WRITE, audience, at_bound,
        ordering=ordering_group(UNKNOWN_ORDERING_BASIS))
    unknown_ordering_basis = {
        "body_hex": unknown_ordering_basis_body.hex(), "reject": "UnknownOrderingBasis",
        "note": "field 6 basis = 99, outside the closed {0,1,2} ordering-basis set.",
    }

    vocab = [{"name": n, "code": c} for (n, c) in BINDING_VOCAB]

    return {
        "source": ("E6.3 (held at the wire-freeze gate); naalp-egress-attestation "
                   "{1:binding,2:digest,3:effect,4:audience,5:at} is a signed attestation a "
                   "gateway/sidecar emits that an object of a given effect class, bound to a given "
                   "audience, crossed an egress boundary at a given time - third-party verifiable "
                   "WITHOUT the payload. A near-clone of naalp-gateway-decision (design section 24). "
                   "Its authority is the signature over the bytes, never the connection, so it "
                   "verifies offline and re-verifies IDENTICALLY when served by a party other than "
                   "the gateway (third-party re-serve). binding in {content_bound,content_free}; "
                   "digest = T1 content-id (content_bound) or SHA-384(content_id||salt) hiding "
                   "commitment (content_free); effect = C5 class; audience = bound destination "
                   "(empty-permitted); at = epoch ms. head=SHA-384(body); "
                   "content-id=multihash(0x20,SHA-384)."),
        "binding_vocabulary": vocab,
        "unknown_binding": UNKNOWN_BINDING,
        "object_bytes_hex": object_bytes.hex(),
        "object_cid_hex": object_cid.hex(),
        "wrong_object_bytes_hex": wrong_object_bytes.hex(),
        "wrong_object_cid_hex": wrong_object_cid.hex(),
        "audience_hex": audience.hex(),
        "attestations": {"content_bound": content_bound, "content_free": content_free},
        "attestations_with_ordering": {
            "correspondence_only": with_ordering_correspondence,
            "single_boundary": with_ordering_single_boundary,
            "external_mechanism": with_ordering_external_mechanism,
        },
        "ordering_basis_vocabulary": [{"name": n, "code": c} for (n, c) in
                                      (("correspondence-only", CORRESPONDENCE_ONLY),
                                       ("single-boundary", SINGLE_BOUNDARY),
                                       ("external-mechanism", EXTERNAL_MECHANISM))],
        "commitment_open": build_commitment_open(object_cid, wrong_object_cid, salt, wrong_salt, cf_digest.hex()),
        "edge_cases": build_edge_cases(object_cid, audience),
        "negative_ordering": {
            "ordering_malformed_single_boundary_with_mechanism": ordering_malformed,
            "unknown_ordering_basis": unknown_ordering_basis,
        },
        "note": ("both attestation bodies are ordinary COSE_Sign1 payloads; VerifyEgressAttestation "
                 "takes NO serving-party/connection identity, so the same bytes verify identically "
                 "whether the gateway or a third party serves them. The cross-language SIGNED-object "
                 "digest pin (Go and Rust ML-DSA-65 over the content_free body, all-0x11 32-byte "
                 "seed) is computed once from a Go/Rust run and hardcoded in both impls' tests, "
                 "exactly as gateway_test.go's crossLangPinnedSignedDecisionSHA384 - Python stdlib "
                 "has no ML-DSA so this oracle cannot compute it independently."),
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "egress_attestation", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  content_bound id=%s... object cid=%s..." % (
        data["attestations"]["content_bound"]["id_hex"][:16], data["object_cid_hex"][:16]))
    print("  content_free  id=%s... commitment=%s..." % (
        data["attestations"]["content_free"]["id_hex"][:16], data["commitment_open"]["commitment_hex"][:16]))
    print("  bindings: %s" % [v["name"] for v in data["binding_vocabulary"]])
    print("  field-6 ordering examples: %s" % list(data["attestations_with_ordering"].keys()))
    print("  negative_ordering: %s" % list(data["negative_ordering"].keys()))


if __name__ == "__main__":
    main()
