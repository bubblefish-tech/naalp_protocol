# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""E6.3 naalp-egress-attestation conformance for the Python SDK, graded against the shared
independent corpus vectors/egress_attestation/cases.json (NOT produced by this code): the closed
binding vocabulary, byte-exact attestation body/head/content-id (including the oversized 2^64-1
counter and field-6 ordering-disclosure variants), the content_free commitment open/verify pair,
the third-party re-serve property (and the vendor-only mutation it must survive), and every named
edge case (descending-key body, empty-vs-absent audience, minimal, gateway-decision look-alike,
missing mandatory `at`, ordering-malformed variants).

Mirrors impl/go/gateway/egress_attestation_test.go. Written test-first: this fails RED on import
until naalp/gateway.py carries the EgressAttestation family, and a mutation forcing OpenEgress
Commitment to always return True flips test_open_egress_commitment.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1 to avoid stale-bytecode strands):
  python -m pytest impl/python/tests/test_egress_attestation.py -q
"""
import json
import os
import unittest

from naalp import cbor, cose, gateway


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "egress_attestation", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/egress_attestation/cases.json not found")


def _att_from(av):
    return gateway.EgressAttestation(
        binding=av["binding"], digest=bytes.fromhex(av["digest_hex"]), effect=av["effect"],
        audience=bytes.fromhex(av["audience_hex"]), at=int(av["at_str"]))


class EgressAttestationConformance(unittest.TestCase):
    C = _vectors()

    def test_byte_parity_against_oracle(self):
        for name, av in {"content_bound": self.C["attestations"]["content_bound"],
                          "content_free": self.C["attestations"]["content_free"]}.items():
            a = _att_from(av)
            self.assertEqual(a.bytes().hex(), av["body_hex"], name)
            self.assertEqual(a.head().hex(), av["head_hex"], name)
            self.assertEqual(a.id().hex(), av["id_hex"], name)
        for e in self.C["binding_vocabulary"]:
            self.assertTrue(gateway.is_known_binding(e["code"]), e["name"])
            self.assertEqual(gateway.binding_name(e["code"]), e["name"])
        self.assertFalse(gateway.is_known_binding(self.C["unknown_binding"]))

    def test_oversized_counter(self):
        e = self.C["edge_cases"]["oversized_counter"]
        self.assertEqual(e["at_str"], "18446744073709551615")
        a = _att_from(e)
        self.assertEqual(a.at, (1 << 64) - 1)
        self.assertEqual(a.bytes().hex(), e["body_hex"])
        parsed = gateway.parse_egress_attestation(a.bytes())
        self.assertEqual(parsed.at, a.at)

    def test_third_party_reserve(self):
        seed_gw = bytes([0x61] * 32)
        seed_foreign = bytes([0x62] * 32)
        alg = cose.ALG_MLDSA65
        gw_pk = cose.mldsa_keygen("ML-DSA-65", seed_gw)
        foreign_pk = cose.mldsa_keygen("ML-DSA-65", seed_foreign)

        a = _att_from(self.C["attestations"]["content_bound"])
        obj = gateway.sign_egress_attestation(a, alg, seed_gw)

        by_gateway = gateway.verify_egress_attestation(obj, cose.PROFILE_PUBLIC, alg, gw_pk)
        by_third_party = gateway.verify_egress_attestation(bytes(obj), cose.PROFILE_PUBLIC, alg, gw_pk)
        self.assertEqual(by_gateway.binding, by_third_party.binding)
        self.assertEqual(by_gateway.digest, by_third_party.digest)
        self.assertEqual(by_gateway.effect, by_third_party.effect)
        self.assertEqual(by_gateway.audience, by_third_party.audience)
        self.assertEqual(by_gateway.at, by_third_party.at)
        self.assertEqual(by_third_party.binding, gateway.BINDING_CONTENT_BOUND)
        self.assertEqual(by_third_party.digest.hex(), self.C["object_cid_hex"])

        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.verify_egress_attestation(obj, cose.PROFILE_PUBLIC, alg, foreign_pk)
        self.assertEqual(cm.exception.kind, "BadSignature")

        bad = gateway.EgressAttestation(
            binding=self.C["unknown_binding"], digest=bytes.fromhex(self.C["object_cid_hex"]),
            effect=0, audience=bytes.fromhex(self.C["audience_hex"]), at=0)
        bad_obj = gateway.sign_egress_attestation(bad, alg, seed_gw)
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.verify_egress_attestation(bad_obj, cose.PROFILE_PUBLIC, alg, gw_pk)
        self.assertEqual(cm.exception.kind, "UnknownEgressBinding")

    def test_vendor_only_mutation(self):
        # Mirrors TestEgressVendorOnlyMutation: the honest verify_egress_attestation takes NO
        # serving-party identity, so a mutant "vendor-only" verifier that additionally requires
        # serving_party == gateway_id wrongly rejects a third party re-serving the identical bytes.
        seed_gw = bytes([0x61] * 32)
        alg = cose.ALG_MLDSA65
        gw_pk = cose.mldsa_keygen("ML-DSA-65", seed_gw)
        gateway_id = b"gateway-id-0x61"
        third_party = b"did:example:mirror-cache"

        a = _att_from(self.C["attestations"]["content_free"])
        obj = gateway.sign_egress_attestation(a, alg, seed_gw)
        gateway.verify_egress_attestation(obj, cose.PROFILE_PUBLIC, alg, gw_pk)  # honest: no raise

        def mutant_verify(obj_, gw_pk_, gateway_id_, serving_party):
            gateway.verify_egress_attestation(obj_, cose.PROFILE_PUBLIC, alg, gw_pk_)
            if serving_party != gateway_id_:
                raise gateway.GatewayError("EgMalformed", "stands in for a not-served-by-vendor rejection")

        mutant_verify(obj, gw_pk, gateway_id, gateway_id)  # accepts the vendor serving it
        with self.assertRaises(gateway.GatewayError):
            mutant_verify(obj, gw_pk, gateway_id, third_party)  # wrongly rejects the third party

    def test_open_egress_commitment(self):
        co = self.C["commitment_open"]
        a = _att_from(self.C["attestations"]["content_free"])
        self.assertEqual(a.digest.hex(), co["commitment_hex"])

        object_cid = bytes.fromhex(co["object_cid_hex"])
        wrong_object_cid = bytes.fromhex(co["wrong_object_cid_hex"])
        salt = bytes.fromhex(co["salt_hex"])
        wrong_salt = bytes.fromhex(co["wrong_salt_hex"])

        self.assertEqual(gateway.egress_commit(object_cid, salt).hex(), co["commitment_hex"])
        self.assertTrue(gateway.open_egress_commitment(a, object_cid, salt))
        self.assertFalse(gateway.open_egress_commitment(a, object_cid, wrong_salt))
        self.assertFalse(gateway.open_egress_commitment(a, wrong_object_cid, salt))
        self.assertFalse(gateway.open_egress_commitment(a, wrong_object_cid, wrong_salt))

        bound = _att_from(self.C["attestations"]["content_bound"])
        self.assertFalse(gateway.open_egress_commitment(bound, object_cid, salt))

    def test_keys_out_of_order_rejected(self):
        e = self.C["edge_cases"]["keys_out_of_order"]
        a = gateway.EgressAttestation(
            binding=e["binding"], digest=bytes.fromhex(e["digest_hex"]), effect=e["effect"],
            audience=bytes.fromhex(e["audience_hex"]), at=int(e["at_str"]))
        self.assertEqual(a.bytes().hex(), e["canonical_body_hex"])
        canon = bytes.fromhex(e["canonical_body_hex"])
        noncanon = bytes.fromhex(e["noncanonical_body_hex"])
        cbor.decode(canon)  # should decode
        gateway.parse_egress_attestation(canon)  # should parse
        with self.assertRaises(cbor.NonCanonical):
            cbor.decode(noncanon)
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.parse_egress_attestation(noncanon)
        self.assertEqual(cm.exception.kind, "EgMalformed")

    def test_empty_vs_absent_audience(self):
        ea = self.C["edge_cases"]["empty_vs_absent"]
        object_cid = self.C["object_cid_hex"]
        empty = gateway.EgressAttestation(
            binding=gateway.BINDING_CONTENT_BOUND, digest=bytes.fromhex(object_cid), effect=1,
            audience=b"", at=1735689600000)
        populated = gateway.EgressAttestation(
            binding=gateway.BINDING_CONTENT_BOUND, digest=bytes.fromhex(object_cid), effect=1,
            audience=bytes.fromhex(ea["populated_audience"]["audience_hex"]), at=1735689600000)
        self.assertEqual(empty.bytes().hex(), ea["empty_audience"]["body_hex"])
        self.assertEqual(populated.bytes().hex(), ea["populated_audience"]["body_hex"])
        self.assertNotEqual(empty.id(), populated.id())
        self.assertEqual(empty.id().hex(), ea["empty_audience"]["id_hex"])
        gateway.parse_egress_attestation(empty.bytes())
        gateway.parse_egress_attestation(populated.bytes())
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.parse_egress_attestation(bytes.fromhex(ea["absent_field"]["body_hex"]))
        self.assertEqual(cm.exception.kind, "EgMalformed")

    def test_minimal(self):
        m = self.C["edge_cases"]["minimal"]
        a = gateway.EgressAttestation(
            binding=m["binding"], digest=bytes.fromhex(m["digest_hex"]), effect=m["effect"],
            audience=bytes.fromhex(m["audience_hex"]), at=int(m["at_str"]))
        self.assertEqual(a.bytes().hex(), m["body_hex"])
        self.assertEqual(a.id().hex(), m["id_hex"])
        gateway.parse_egress_attestation(a.bytes())
        seed = bytes([0x63] * 32)
        alg = cose.ALG_MLDSA65
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        obj = gateway.sign_egress_attestation(a, alg, seed)
        gateway.verify_egress_attestation(obj, cose.PROFILE_PUBLIC, alg, pk)  # no raise

    def test_look_alike_rejected(self):
        la = self.C["edge_cases"]["look_alike"]
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.parse_egress_attestation(bytes.fromhex(la["body_hex"]))
        self.assertEqual(cm.exception.kind, la["reject"])

    def test_ordering_byte_parity(self):
        for e in self.C["ordering_basis_vocabulary"]:
            self.assertTrue(gateway.is_known_ordering_basis(e["code"]), e["name"])
            self.assertEqual(gateway.ordering_basis_name(e["code"]), e["name"])

        def build(name, av):
            a = _att_from(av)
            if name == "correspondence_only":
                a.ordering = gateway.correspondence_only()
            elif name == "single_boundary":
                a.ordering = gateway.OrderingDisclosure(gateway.ORDERING_SINGLE_BOUNDARY, boundary=b"boundary-signer-X")
            elif name == "external_mechanism":
                a.ordering = gateway.OrderingDisclosure(
                    gateway.ORDERING_EXTERNAL_MECHANISM,
                    mechanism=b"external-log:acme-transparency-v1",
                    relation=bytes.fromhex(
                        "2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56"),
                )
            else:
                raise AssertionError("unhandled attestations_with_ordering name %r" % name)
            return a

        for name, av in self.C["attestations_with_ordering"].items():
            a = build(name, av)
            self.assertEqual(a.bytes().hex(), av["body_hex"], name)
            self.assertEqual(a.head().hex(), av["head_hex"], name)
            self.assertEqual(a.id().hex(), av["id_hex"], name)
            parsed = gateway.parse_egress_attestation(a.bytes())
            self.assertIsNotNone(parsed.ordering, name)
            self.assertEqual(parsed.bytes().hex(), av["body_hex"], name)
            gateway.validate_egress_attestation(parsed)  # no raise

        plain = gateway.parse_egress_attestation(_att_from(self.C["attestations"]["content_bound"]).bytes())
        self.assertIsNone(plain.ordering)

    def test_ordering_negative(self):
        def kind_of(body_hex):
            try:
                a = gateway.parse_egress_attestation(bytes.fromhex(body_hex))
            except gateway.GatewayError as e:
                return e.kind
            try:
                gateway.validate_egress_attestation(a)
            except gateway.GatewayError as e:
                return e.kind
            return ""

        sbwm = self.C["negative_ordering"]["ordering_malformed_single_boundary_with_mechanism"]
        self.assertEqual(kind_of(sbwm["body_hex"]), sbwm["reject"])
        uob = self.C["negative_ordering"]["unknown_ordering_basis"]
        self.assertEqual(kind_of(uob["body_hex"]), uob["reject"])

    def test_missing_at_field_rejected(self):
        # Isolates the field-5 (`at`) mandatory check: fields 1-4 correctly typed, field 5 absent.
        from naalp.cbor import U, B, M
        body = cbor.encode(M([
            (U(1), U(gateway.BINDING_CONTENT_BOUND)),
            (U(2), B(bytes([0x20, 0x30]))),
            (U(3), U(1)),
            (U(4), B(b"")),
        ]))
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.parse_egress_attestation(body)
        self.assertEqual(cm.exception.kind, "EgMalformed")


if __name__ == "__main__":
    unittest.main()
