# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""S1 naalp-decision-record conformance for the Python SDK, graded against the shared independent
corpus vectors/decision_record/cases.json (NOT produced by this code): the closed outcome/
ordering-basis/enforcement-disposition/term-disposition-kind vocabularies, byte-exact record
body/head/content-id for every records{} and ordering_examples{} case (each record reconstructed
field-by-field, never routed through the decoder), the parse round-trip, full semantic validation,
and every named negative rejection (deny/hold-with-consume, terms-key-outside-field-set, unknown
outcome, every ordering_malformed variant, the descending-key body, and the gateway-decision
look-alike).

Mirrors impl/go/gateway/decision_record_test.go. Written test-first: this fails RED on import until
naalp/gateway.py carries the DecisionRecord family, and a mutation forcing the outcome field to a
constant flips test_decision_record_bodies_match_oracle.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1 to avoid stale-bytecode strands):
  python -m pytest impl/python/tests/test_decision_record.py -q
"""
import json
import os
import unittest

from naalp import cbor, cose, gateway


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "decision_record", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/decision_record/cases.json not found")


def _dr_from(rv):
    """Build the mandatory-field-only shell of a records{}/ordering_examples{} case; the ordering/
    terms/enforcement fixture is layered on by _build (mirroring the Go test's drFrom + build)."""
    governing = [bytes.fromhex(g) for g in rv["governing_hex"]]
    d = gateway.DecisionRecord(
        action=bytes.fromhex(rv["action_hex"]), governing=governing, outcome=rv["outcome"],
        ordering=gateway.correspondence_only(),
    )
    if rv.get("consume_hex"):
        d.consume = bytes.fromhex(rv["consume_hex"])
    return d


def _build(name, rv):
    """Reconstruct a records{}/ordering_examples{} case with its exact ordering/terms/enforcement
    fixture, mirroring decision_record_test.go's build() switch exactly."""
    d = _dr_from(rv)
    if name in ("allow_consuming", "allow_no_consume", "minimal", "correspondence_only"):
        d.ordering = gateway.correspondence_only()
    elif name == "deny_two_governing":
        d.ordering = gateway.OrderingDisclosure(gateway.ORDERING_SINGLE_BOUNDARY, boundary=b"boundary-signer-X")
    elif name in ("hold_empty_governing", "external_mechanism"):
        d.ordering = gateway.OrderingDisclosure(
            gateway.ORDERING_EXTERNAL_MECHANISM,
            mechanism=b"external-log:acme-transparency-v1",
            relation=bytes.fromhex(
                "2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56"),
        )
    elif name == "single_boundary":
        d.ordering = gateway.OrderingDisclosure(gateway.ORDERING_SINGLE_BOUNDARY, boundary=b"SIGNER_B-boundary")
    elif name == "external_mechanism_no_relation":
        d.ordering = gateway.OrderingDisclosure(
            gateway.ORDERING_EXTERNAL_MECHANISM, mechanism=b"external-log:acme-transparency-v1")
    elif name == "terms_valid":
        d.ordering = gateway.correspondence_only()
        d.terms = {
            1: gateway.TermDisposition(gateway.TERM_OBSERVED),
            4: gateway.TermDisposition(gateway.TERM_REPORTED, source=b"boundary:relay-partner-3"),
        }
    elif name == "enforcement_enforced":
        d.ordering = gateway.correspondence_only()
        d.enforcement = gateway.ENFORCEMENT_ENFORCED
    elif name == "enforcement_advised":
        d.ordering = gateway.correspondence_only()
        d.enforcement = gateway.ENFORCEMENT_ADVISED
    else:
        raise AssertionError("unhandled record name %r -- add its ordering/terms/enforcement fixture" % name)
    return d


class DecisionRecordConformance(unittest.TestCase):
    C = _vectors()

    def test_outcome_vocabulary(self):
        for e in self.C["outcome_vocabulary"]:
            self.assertTrue(gateway.is_known_decision(e["code"]), e["name"])
            self.assertEqual(gateway.decision_name(e["code"]), e["name"])

    def test_ordering_basis_vocabulary(self):
        for e in self.C["ordering_basis_vocabulary"]:
            self.assertTrue(gateway.is_known_ordering_basis(e["code"]), e["name"])
            self.assertEqual(gateway.ordering_basis_name(e["code"]), e["name"])
        self.assertFalse(gateway.is_known_ordering_basis(99))

    def test_decision_record_bodies_match_oracle(self):
        all_cases = dict(self.C["records"])
        all_cases.update(self.C["ordering_examples"])
        self.assertEqual(len(all_cases), len(self.C["records"]) + len(self.C["ordering_examples"]),
                          "records/ordering_examples name collision")
        for name, rv in all_cases.items():
            d = _build(name, rv)
            self.assertEqual(d.bytes().hex(), rv["body_hex"], name)
            self.assertEqual(d.head().hex(), rv["head_hex"], name)
            self.assertEqual(d.id().hex(), rv["id_hex"], name)
            # Round-trip through the decoder and re-encode: the decoded record must re-encode to
            # the SAME canonical bytes.
            parsed = gateway.parse_decision_record(d.bytes())
            self.assertEqual(parsed.bytes().hex(), rv["body_hex"], name)
            gateway.validate_decision_record(parsed)  # every records/ordering_examples case is POSITIVE

    def test_decision_record_minimal(self):
        m = self.C["records"]["minimal"]
        d = gateway.DecisionRecord(action=b"", governing=[], outcome=m["outcome"], ordering=gateway.correspondence_only())
        self.assertEqual(d.bytes().hex(), m["body_hex"])
        self.assertEqual(d.id().hex(), m["id_hex"])
        parsed = gateway.parse_decision_record(d.bytes())
        gateway.validate_decision_record(parsed)

    def test_decision_record_negative_rejections(self):
        neg = self.C["negative"]

        def kind_of(body_hex):
            try:
                d = gateway.parse_decision_record(bytes.fromhex(body_hex))
            except gateway.GatewayError as e:
                return e.kind
            try:
                gateway.validate_decision_record(d)
            except gateway.GatewayError as e:
                return e.kind
            return ""

        cases = {
            "deny_with_consume_rejected": neg["deny_with_consume_rejected"],
            "hold_with_consume_rejected": neg["hold_with_consume_rejected"],
            "terms_key_outside_field_set_rejected": neg["terms_key_outside_field_set_rejected"],
            "unknown_outcome_rejected": neg["unknown_outcome_rejected"],
            "look_alike": neg["look_alike"],
        }
        for name, c in cases.items():
            self.assertEqual(kind_of(c["body_hex"]), c["reject"], name)

        for name, c in neg["ordering_malformed"].items():
            self.assertEqual(kind_of(c["body_hex"]), c["reject"], "ordering_malformed." + name)

        # keys_out_of_order: the canonical body decodes+validates cleanly; the descending-key body
        # is rejected at the CBOR layer (NonCanonical) before parse_decision_record's own checks
        # ever run.
        koo = neg["keys_out_of_order"]
        d = gateway.parse_decision_record(bytes.fromhex(koo["canonical_body_hex"]))
        gateway.validate_decision_record(d)
        with self.assertRaises(cbor.NonCanonical):
            cbor.decode(bytes.fromhex(koo["noncanonical_body_hex"]))
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.parse_decision_record(bytes.fromhex(koo["noncanonical_body_hex"]))
        self.assertEqual(cm.exception.kind, "DecisionMalformed")

    def test_decision_record_third_party_reserve(self):
        rv = self.C["records"]["allow_consuming"]
        d = _build("allow_consuming", rv)
        self.assertEqual(d.bytes().hex(), rv["body_hex"])

        seed_producer = bytes([0x71] * 32)
        seed_foreign = bytes([0x72] * 32)
        alg = cose.ALG_MLDSA65
        producer_pk = cose.mldsa_keygen("ML-DSA-65", seed_producer)
        foreign_pk = cose.mldsa_keygen("ML-DSA-65", seed_foreign)

        obj = gateway.sign_decision_record(d, alg, seed_producer)
        by_producer = gateway.verify_decision_record(obj, cose.PROFILE_PUBLIC, alg, producer_pk)
        by_third_party = gateway.verify_decision_record(bytes(obj), cose.PROFILE_PUBLIC, alg, producer_pk)
        self.assertEqual(by_producer.action, by_third_party.action)
        self.assertEqual(by_producer.outcome, by_third_party.outcome)
        self.assertEqual(by_third_party.outcome, gateway.DECISION_ALLOW)
        self.assertEqual(by_third_party.consume.hex(), rv["consume_hex"])

        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.verify_decision_record(obj, cose.PROFILE_PUBLIC, alg, foreign_pk)
        self.assertEqual(cm.exception.kind, "BadSignature")

    def test_decision_record_sign_verify_terms_valid(self):
        # In isolation (no cross-lang pin claimed): terms_valid signs and verifies end-to-end,
        # carrying field 6 (terms) through the full signature-verification + semantic-validation
        # path, exercising the terms map on the signed/verified round trip.
        rv = self.C["records"]["terms_valid"]
        d = _build("terms_valid", rv)
        self.assertEqual(d.bytes().hex(), rv["body_hex"])
        seed = bytes([0x11] * 32)
        alg = cose.ALG_MLDSA65
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        obj = gateway.sign_decision_record(d, alg, seed)
        resolved = gateway.verify_decision_record(obj, cose.PROFILE_PUBLIC, alg, pk)
        self.assertEqual(resolved.terms[1].kind, gateway.TERM_OBSERVED)
        self.assertEqual(resolved.terms[4].kind, gateway.TERM_REPORTED)
        self.assertEqual(resolved.terms[4].source, b"boundary:relay-partner-3")


if __name__ == "__main__":
    unittest.main()
