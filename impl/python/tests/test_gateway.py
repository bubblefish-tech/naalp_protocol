# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C21 portable gateway-decision conformance for the Python SDK, graded against the shared
independent corpus vectors/gateway/cases.json (NOT produced by this code): the closed decision
vocabulary, the byte-exact decision body/head/content-id for allow/deny/hold, the parse round-trip,
and the fail-closed edge cases (non-canonical body -> NonCanonical/GwMalformed, absent mandatory
field -> GwMalformed, a look-alike object -> GwMalformed, empty vs populated policy distinct by
content-id, and the minimal decision).

The sign/verify_decision round-trip and the third-party re-serve property are demonstrated in
isolation only: the corpus carries no signed COSE_Sign1 vector, seed, or public key, so those are
NOT corpus-graded here (stated honestly). What the corpus grades is the evidence-object bytes.

Written test-first; the gateway module is absent until ported, so this fails RED on import until
impl/python/naalp/gateway.py lands, and a mutation forcing the decision field to a constant flips
test_decision_bodies_match_oracle.

Run:  python -m unittest -v tests.test_gateway      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cbor, cose, gateway, policy


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "gateway", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/gateway/cases.json not found")


class GatewayConformance(unittest.TestCase):
    C = _vectors()

    def test_decision_vocabulary(self):
        for d in self.C["decision_vocabulary"]:
            self.assertTrue(gateway.is_known_decision(d["code"]), d["name"])
            self.assertEqual(gateway.decision_name(d["code"]), d["name"])
        self.assertFalse(gateway.is_known_decision(self.C["unknown_decision"]))
        self.assertEqual(gateway.decision_name(self.C["unknown_decision"]), "unknown")

    def test_decision_bodies_match_oracle(self):
        for name, d in self.C["decisions"].items():
            gd = gateway.GatewayDecision(
                d["decision"], bytes.fromhex(d["action_hex"]),
                bytes.fromhex(d["policy_hex"]), d["effect"])
            self.assertEqual(gd.bytes().hex(), d["body_hex"], name)
            self.assertEqual(gd.head().hex(), d["head_hex"], name)
            self.assertEqual(gd.id().hex(), d["id_hex"], name)
            self.assertEqual(gd.effect_class(), policy.normalize_effect(d["effect"]), name)

    def test_parse_decision_roundtrips(self):
        for name, d in self.C["decisions"].items():
            gd = gateway.parse_decision(bytes.fromhex(d["body_hex"]))
            self.assertEqual(gd.decision, d["decision"], name)
            self.assertEqual(gd.action, bytes.fromhex(d["action_hex"]), name)
            self.assertEqual(gd.policy, bytes.fromhex(d["policy_hex"]), name)
            self.assertEqual(gd.effect, d["effect"], name)

    def test_noncanonical_body_rejected(self):
        ec = self.C["edge_cases"]["keys_out_of_order"]
        # the strict decoder rejects the descending-key body (the corpus 'reject' value)
        with self.assertRaises(cbor.NonCanonical):
            cbor.decode(bytes.fromhex(ec["noncanonical_body_hex"]))
        # parse_decision fails closed to GwMalformed
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.parse_decision(bytes.fromhex(ec["noncanonical_body_hex"]))
        self.assertEqual(cm.exception.kind, "GwMalformed")
        # the canonical form of the same content parses
        gd = gateway.parse_decision(bytes.fromhex(ec["canonical_body_hex"]))
        self.assertEqual(gd.decision, ec["decision"])

    def test_empty_vs_absent_policy(self):
        ev = self.C["edge_cases"]["empty_vs_absent"]
        empty = gateway.parse_decision(bytes.fromhex(ev["empty_policy"]["body_hex"]))
        self.assertEqual(empty.policy, b"")
        self.assertEqual(empty.id().hex(), ev["empty_policy"]["id_hex"])
        populated = gateway.parse_decision(bytes.fromhex(ev["populated_policy"]["body_hex"]))
        self.assertEqual(populated.id().hex(), ev["populated_policy"]["id_hex"])
        # an empty policy identity is present and valid, distinct by content-id from a populated one
        self.assertNotEqual(empty.id(), populated.id())
        # field 3 (policy) is mandatory: a body missing it is rejected fail-closed
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.parse_decision(bytes.fromhex(ev["absent_field"]["body_hex"]))
        self.assertEqual(cm.exception.kind, "GwMalformed")

    def test_minimal_decision(self):
        m = self.C["edge_cases"]["minimal"]
        gd = gateway.GatewayDecision(
            m["decision"], bytes.fromhex(m["action_hex"]),
            bytes.fromhex(m["policy_hex"]), m["effect"])
        self.assertEqual(gd.bytes().hex(), m["body_hex"])
        self.assertEqual(gd.id().hex(), m["id_hex"])

    def test_look_alike_rejected(self):
        la = self.C["edge_cases"]["look_alike"]
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.parse_decision(bytes.fromhex(la["body_hex"]))
        self.assertEqual(cm.exception.kind, la["reject"])

    def test_sign_verify_and_third_party_reserve_in_isolation(self):
        # NOT corpus-graded: the gateway corpus has no signed COSE vector or key. This demonstrates
        # sign/verify_decision and the third-party re-serve property in isolation with a local seed.
        d = self.C["decisions"]["deny"]
        gd = gateway.GatewayDecision(
            d["decision"], bytes.fromhex(d["action_hex"]),
            bytes.fromhex(d["policy_hex"]), d["effect"])
        seed = bytes(32)
        alg = cose.ALG_MLDSA65
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        obj = gateway.sign_decision(gd, alg, seed)
        resolved = gateway.verify_decision(obj, cose.PROFILE_PUBLIC, alg, pk)
        self.assertEqual(resolved.decision, d["decision"])
        self.assertEqual(resolved.action, bytes.fromhex(d["action_hex"]))
        self.assertEqual(resolved.policy, bytes.fromhex(d["policy_hex"]))
        self.assertEqual(resolved.effect, policy.normalize_effect(d["effect"]))
        # third-party re-serve: verify_decision takes NO serving-party identity, so the identical
        # bytes verify identically regardless of who served them.
        resolved2 = gateway.verify_decision(bytes(obj), cose.PROFILE_PUBLIC, alg, pk)
        self.assertEqual((resolved2.decision, resolved2.effect), (resolved.decision, resolved.effect))
        # tampered signature -> BadSignature
        tampered = bytearray(obj)
        tampered[-1] ^= 1
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.verify_decision(bytes(tampered), cose.PROFILE_PUBLIC, alg, pk)
        self.assertEqual(cm.exception.kind, "BadSignature")
        # an out-of-set decision code -> UnknownGatewayDecision (closed-set enforcement)
        bad = gateway.GatewayDecision(self.C["unknown_decision"], b"", b"", 0)
        bad_obj = gateway.sign_decision(bad, alg, seed)
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.verify_decision(bad_obj, cose.PROFILE_PUBLIC, alg, pk)
        self.assertEqual(cm.exception.kind, "UnknownGatewayDecision")


class GatewayOptionalFieldsConformance(unittest.TestCase):
    """R1 ordering (field 5) + R8 foreign-profile (field 6) conformance, graded against the
    optional_fields{} block of the SAME vectors/gateway/cases.json corpus. Mirrors the
    optional-fields section of impl/go/gateway/gateway_test.go."""

    C = GatewayConformance.C

    def test_existing_decision_bodies_unchanged(self):
        # NON-REGRESSION: adding optional fields 5/6 must not perturb the pre-existing 4-field
        # decision bodies at all. Pins the allow/deny/hold body_hex values as they stood BEFORE
        # this change, independent of the vector file's own drift.
        pinned_allow = "a401000258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330401"
        pinned_deny = "a401010258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330403"
        pinned_hold = "a401020258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330402"
        self.assertEqual(self.C["decisions"]["allow"]["body_hex"], pinned_allow)
        self.assertEqual(self.C["decisions"]["deny"]["body_hex"], pinned_deny)
        self.assertEqual(self.C["decisions"]["hold"]["body_hex"], pinned_hold)
        for name, dv in self.C["decisions"].items():
            gd = gateway.GatewayDecision(dv["decision"], bytes.fromhex(dv["action_hex"]),
                                          bytes.fromhex(dv["policy_hex"]), dv["effect"])
            self.assertEqual(gd.bytes().hex(), dv["body_hex"], name)

    def test_optional_fields_round_trip(self):
        of = self.C["optional_fields"]

        with self.subTest("with_ordering"):
            wo = of["with_ordering"]
            d = gateway.GatewayDecision(
                wo["decision"], bytes.fromhex(wo["action_hex"]), bytes.fromhex(wo["policy_hex"]), wo["effect"],
                ordering=gateway.OrderingDisclosure(wo["ordering"]["basis"], boundary=bytes.fromhex(wo["ordering"]["boundary_hex"])))
            self.assertEqual(d.bytes().hex(), wo["body_hex"])
            self.assertEqual(d.id().hex(), wo["id_hex"])
            parsed = gateway.parse_decision(bytes.fromhex(wo["body_hex"]))
            self.assertIsNotNone(parsed.ordering)
            self.assertIsNone(parsed.foreign_profile)
            self.assertEqual(parsed.ordering.basis, wo["ordering"]["basis"])
            self.assertEqual(parsed.ordering.boundary, bytes.fromhex(wo["ordering"]["boundary_hex"]))
            parsed.ordering.validate()  # no raise

        with self.subTest("with_foreign_profile"):
            wf = of["with_foreign_profile"]
            d = gateway.GatewayDecision(
                wf["decision"], bytes.fromhex(wf["action_hex"]), bytes.fromhex(wf["policy_hex"]), wf["effect"],
                foreign_profile=gateway.ForeignProfilePin(wf["foreign_profile"]["id"], wf["foreign_profile"]["revision"]))
            self.assertEqual(d.bytes().hex(), wf["body_hex"])
            self.assertEqual(d.id().hex(), wf["id_hex"])
            parsed = gateway.parse_decision(bytes.fromhex(wf["body_hex"]))
            self.assertIsNone(parsed.ordering)
            self.assertIsNotNone(parsed.foreign_profile)
            self.assertEqual(parsed.foreign_profile.id, wf["foreign_profile"]["id"])
            self.assertEqual(parsed.foreign_profile.revision, wf["foreign_profile"]["revision"])
            parsed.foreign_profile.validate()  # no raise

        with self.subTest("with_both"):
            wb = of["with_both"]
            d = gateway.GatewayDecision(
                wb["decision"], bytes.fromhex(wb["action_hex"]), bytes.fromhex(wb["policy_hex"]), wb["effect"],
                ordering=gateway.OrderingDisclosure(
                    wb["ordering"]["basis"], mechanism=bytes.fromhex(wb["ordering"]["mechanism_hex"]),
                    relation=bytes.fromhex(wb["ordering"]["relation_hex"])),
                foreign_profile=gateway.ForeignProfilePin(wb["foreign_profile"]["id"], wb["foreign_profile"]["revision"]))
            self.assertEqual(d.bytes().hex(), wb["body_hex"])
            self.assertEqual(d.id().hex(), wb["id_hex"])
            parsed = gateway.parse_decision(bytes.fromhex(wb["body_hex"]))
            self.assertIsNotNone(parsed.ordering)
            self.assertIsNotNone(parsed.foreign_profile)
            parsed.ordering.validate()
            parsed.foreign_profile.validate()
            # Full end-to-end: signs and verifies with both optional fields present.
            seed = bytes([0x71] * 32)
            alg = cose.ALG_MLDSA65
            pk = cose.mldsa_keygen("ML-DSA-65", seed)
            obj = gateway.sign_decision(d, alg, seed)
            gateway.verify_decision(obj, cose.PROFILE_PUBLIC, alg, pk)  # no raise

    def test_foreign_profile_malformed_rejected(self):
        # field 6 present but omits key 2 (revision): parse_decision decodes it structurally fine;
        # verify_decision's ForeignProfilePin.validate() rejects the missing revision, proving the
        # semantic check actually runs, not just the structural decode.
        body = bytes.fromhex(self.C["optional_fields"]["foreign_profile_malformed"]["body_hex"])
        parsed = gateway.parse_decision(body)
        self.assertIsNotNone(parsed.foreign_profile)
        with self.assertRaises(gateway.GatewayError) as cm:
            parsed.foreign_profile.validate()
        self.assertEqual(cm.exception.kind, "ForeignProfileMalformed")

        seed = bytes([0x72] * 32)
        alg = cose.ALG_MLDSA65
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        obj = cose.cose_sign1(alg, seed, gateway.gateway_protected_header(alg), body)
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.verify_decision(obj, cose.PROFILE_PUBLIC, alg, pk)
        self.assertEqual(cm.exception.kind, "ForeignProfileMalformed")

    def test_ordering_malformed_rejected(self):
        # field 5 basis=external-mechanism(2) but key 2 (boundary) is ALSO present:
        # verify_decision's OrderingDisclosure.validate() rejects it.
        body = bytes.fromhex(self.C["optional_fields"]["ordering_malformed"]["body_hex"])
        parsed = gateway.parse_decision(body)
        self.assertIsNotNone(parsed.ordering)
        with self.assertRaises(gateway.GatewayError) as cm:
            parsed.ordering.validate()
        self.assertEqual(cm.exception.kind, "OrderingDisclosureMalformed")

        seed = bytes([0x73] * 32)
        alg = cose.ALG_MLDSA65
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        obj = cose.cose_sign1(alg, seed, gateway.gateway_protected_header(alg), body)
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.verify_decision(obj, cose.PROFILE_PUBLIC, alg, pk)
        self.assertEqual(cm.exception.kind, "OrderingDisclosureMalformed")

    def test_foreign_profile_pin_validate(self):
        # Direct unit test of ForeignProfilePin.validate() (no oracle vector needed): missing/empty
        # id or revision is rejected; both present and non-empty passes.
        cases = [
            ("both present", gateway.ForeignProfilePin("https://example.test/p", "1"), False),
            ("missing id", gateway.ForeignProfilePin("", "1"), True),
            ("missing revision", gateway.ForeignProfilePin("https://example.test/p", ""), True),
            ("both empty", gateway.ForeignProfilePin("", ""), True),
        ]
        for name, pin, want_err in cases:
            with self.subTest(name):
                if want_err:
                    with self.assertRaises(gateway.GatewayError) as cm:
                        pin.validate()
                    self.assertEqual(cm.exception.kind, "ForeignProfileMalformed")
                else:
                    pin.validate()  # no raise

    def test_foreign_profile_extra_key_rejected(self):
        # A field-6 map carrying a THIRD key (3) beyond the closed {1,2} set decodes structurally
        # (the extra key does not fail decode) but fails validate() (ForeignProfileMalformed),
        # exactly as a missing or empty field does. Hand-built directly (not oracle-driven).
        from naalp.cbor import U, B, T, M
        fp = M([
            (U(1), T("https://example-registry.test/profiles/acme")),
            (U(2), T("2026-01")),
            (U(3), T("unexpected")),
        ])
        m = M([
            (U(1), U(gateway.DECISION_ALLOW)),
            (U(2), B(bytes.fromhex(self.C["action_cid_hex"]))),
            (U(3), B(bytes.fromhex(self.C["policy_hex"]))),
            (U(4), U(1)),
            (U(6), fp),
        ])
        body = cbor.encode(m)
        parsed = gateway.parse_decision(body)
        self.assertIsNotNone(parsed.foreign_profile)
        self.assertEqual(parsed.foreign_profile.id, "https://example-registry.test/profiles/acme")
        self.assertEqual(parsed.foreign_profile.revision, "2026-01")
        with self.assertRaises(gateway.GatewayError) as cm:
            parsed.foreign_profile.validate()
        self.assertEqual(cm.exception.kind, "ForeignProfileMalformed")


if __name__ == "__main__":
    unittest.main()
