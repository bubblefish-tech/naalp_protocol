# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C20 governed negotiation, advisory risk labels, and checkable trust references for the Python
SDK, graded against the shared independent corpus vectors/negotiation/cases.json (NOT produced by
this code): the negotiation message / labeled-object / trust-ref body/head/content-id bytes, the
governed-negotiation descent decision (an accept must descend from its offer along the causes DAG),
the R-2.5 risk-label critical-extension rule, the load-bearing C20 invariant that a risk label never
changes an object's effect class, and the trust-ref content-id recompute (checkable, never weighed).

The negotiation / labeled-object / trust-ref SIGNATURES are real deterministic ML-DSA-65 (COSE_Sign1)
demonstrated in isolation (sign -> verify -> foreign-key-rejected); the corpus carries no signed
vector for C20, so signing is NOT corpus-graded (stated honestly, D5).

Written test-first; the negotiation module is absent until ported, so this fails RED on import until
impl/python/naalp/negotiation.py lands. Mutation: forcing negotiation.descends() to a constant True
(so a non-descended accept is wrongly accepted) flips test_governed_negotiation_descent.

Run:  python -m unittest tests.test_negotiation      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cose, negotiation, policy


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "negotiation", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/negotiation/cases.json not found")


ALG = cose.ALG_MLDSA65
SEED = bytes([0x11]) * 32
PK = cose.mldsa_keygen("ML-DSA-65", SEED)
FOREIGN_SEED = bytes([0x22]) * 32
FOREIGN_PK = cose.mldsa_keygen("ML-DSA-65", FOREIGN_SEED)


def hb(s):
    return bytes.fromhex(s)


class NegotiationConformance(unittest.TestCase):
    C = _vectors()

    # ---- corpus-graded: byte parity ----------------------------------------------------------

    def _msg_from(self, neg, mv):
        return negotiation.Message(
            neg, mv["role"], mv["profile"], [hb(h) for h in mv["causes_hex"]]
        )

    def test_message_bodies_match_oracle(self):
        neg = hb(self.C["negotiation"]["negotiation_hex"])
        for name in ("offer", "counter", "accept", "offer2", "accept_not_descended",
                     "unknown_profile_offer", "unknown_role_message"):
            mv = self.C["negotiation"][name]
            m = self._msg_from(neg, mv)
            self.assertEqual(m.bytes().hex(), mv["body_hex"], "%s body" % name)
            self.assertEqual(m.head().hex(), mv["head_hex"], "%s head" % name)
            self.assertEqual(m.id().hex(), mv["id_hex"], "%s id" % name)

    def _carried_labels(self):
        return [negotiation.RiskLabel(c["code"], c["critical"])
                for c in self.C["risk"]["carried_on_labeled_objects"]]

    def test_labeled_object_bodies_match_oracle(self):
        labels = self._carried_labels()
        for lo in self.C["risk"]["labeled_objects"]:
            with_labels = negotiation.LabeledObject(lo["effect"], labels)
            self.assertEqual(with_labels.bytes().hex(), lo["with_labels"]["body_hex"],
                             "effect %d with-labels body" % lo["effect"])
            self.assertEqual(with_labels.head().hex(), lo["with_labels"]["head_hex"])
            self.assertEqual(with_labels.id().hex(), lo["with_labels"]["id_hex"])
            without = negotiation.LabeledObject(lo["effect"], [])
            self.assertEqual(without.bytes().hex(), lo["without_labels"]["body_hex"],
                             "effect %d without-labels body" % lo["effect"])
            self.assertEqual(without.head().hex(), lo["without_labels"]["head_hex"])

    def test_trust_ref_bodies_match_oracle(self):
        t = self.C["trust"]
        ref_a = negotiation.TrustRef(hb(t["registry_a_hex"]), hb(t["reference_hex"]), hb(t["subject_hex"]))
        self.assertEqual(ref_a.bytes().hex(), t["ref_a"]["body_hex"])
        self.assertEqual(ref_a.head().hex(), t["ref_a"]["head_hex"])
        self.assertEqual(ref_a.id().hex(), t["ref_a"]["id_hex"])
        ref_b = negotiation.TrustRef(hb(t["registry_b_hex"]), hb(t["reference_hex"]), hb(t["subject_hex"]))
        self.assertEqual(ref_b.bytes().hex(), t["ref_b"]["body_hex"])
        self.assertEqual(ref_b.head().hex(), t["ref_b"]["head_hex"])
        self.assertEqual(ref_b.id().hex(), t["ref_b"]["id_hex"])

    # ---- corpus-graded: governed negotiation (MUTATION TARGET) -------------------------------

    def test_governed_negotiation_descent(self):
        n = self.C["negotiation"]
        neg = hb(n["negotiation_hex"])
        offer = self._msg_from(neg, n["offer"])
        counter = self._msg_from(neg, n["counter"])
        accept = self._msg_from(neg, n["accept"])
        offer2 = self._msg_from(neg, n["offer2"])
        accept_bad = self._msg_from(neg, n["accept_not_descended"])

        # The causes wiring reproduces the oracle DAG: counter->offer, accept->counter (descends),
        # and accept_bad->offer2 (does NOT descend from offer).
        self.assertEqual(counter.causes[0], offer.id())
        self.assertEqual(accept.causes[0], counter.id())
        self.assertEqual(accept_bad.causes[0], offer2.id())

        by_id = negotiation.index_by_id([offer, counter, accept, offer2, accept_bad])

        # The honest accept descends from the offer and yields the agreed pre-registered profile.
        self.assertEqual(negotiation.descends(accept, offer.id(), by_id),
                         n["descends"]["accept_from_offer"])
        self.assertTrue(negotiation.descends_msg(accept, offer, by_id))
        agreed = negotiation.verify_accept(accept, offer, by_id)
        self.assertEqual(agreed, n["agreed_profile"])

        # The bad accept does NOT descend from the offer and is rejected NotDescended.
        self.assertEqual(negotiation.descends(accept_bad, offer.id(), by_id),
                         n["descends"]["accept_bad_from_offer"])
        self.assertFalse(negotiation.descends_msg(accept_bad, offer, by_id))
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.verify_accept(accept_bad, offer, by_id)
        self.assertEqual(cm.exception.kind, "NotDescended")

        # Presenting a non-offer as the offer, or a non-accept as the accept, is fail-closed.
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.verify_accept(accept, counter, by_id)
        self.assertEqual(cm.exception.kind, "NotOffer")
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.verify_accept(counter, offer, by_id)
        self.assertEqual(cm.exception.kind, "NotAccept")

        # No free-form/runtime capability is negotiable: only the closed pre-registered set.
        self.assertFalse(negotiation.is_registered_profile(n["unknown_profile"]))
        for p in (negotiation.PROFILE_BASELINE, negotiation.PROFILE_STREAMING, negotiation.PROFILE_BATCH):
            self.assertTrue(negotiation.is_registered_profile(p))

    # ---- corpus-graded: risk labels ----------------------------------------------------------

    def test_risk_critical_extension_rule(self):
        r = self.C["risk"]
        for e in r["vocabulary"]:
            cls, ok = negotiation.risk_class_of(e["code"])
            self.assertTrue(ok, "vocab code %d registered" % e["code"])
            self.assertEqual(negotiation.risk_class_name(cls), e["class"])
        self.assertEqual(negotiation.EXTENSIBLE_RANGE_START, r["extensible_range_start"])

        rec = [negotiation.RiskLabel(c["code"], c["critical"])
               for c in r["validate"]["recognized_set"]["carried"]]
        got = negotiation.validate_labels(rec)
        want_codes = r["validate"]["recognized_set"]["recognized_codes"]
        self.assertEqual([l.code for l in got], want_codes)
        for l in got:
            self.assertTrue(negotiation.is_registered_risk(l.code))

        crit = [negotiation.RiskLabel(c["code"], c["critical"])
                for c in r["validate"]["unknown_critical_rejected"]["carried"]]
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.validate_labels(crit)
        self.assertEqual(cm.exception.kind, r["validate"]["unknown_critical_rejected"]["error"])

        # A malformed critical flag (outside {0,1}) is rejected at parse time (no CBOR boolean).
        bad = negotiation.LabeledObject(0, [negotiation.RiskLabel(negotiation.RISK_SENSITIVE, 2)])
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.parse_labeled_object(bad.bytes())
        self.assertEqual(cm.exception.kind, "MalformedCriticalFlag")

    def test_risk_label_effect_class_unchanged(self):
        labels = self._carried_labels()
        # The carried set must include a GATING label so the invariant's mutation seam is real.
        self.assertTrue(any(negotiation.risk_class_of(l.code) == (negotiation.CLASS_GATING, True)
                            for l in labels))
        for lo in self.C["risk"]["labeled_objects"]:
            with_labels = negotiation.LabeledObject(lo["effect"], labels)
            without = negotiation.LabeledObject(lo["effect"], [])
            want = policy.normalize_effect(lo["effect"])
            self.assertEqual(with_labels.effect_class(), want)
            self.assertEqual(without.effect_class(), want)
            self.assertEqual(with_labels.effect_class(), without.effect_class())
            self.assertEqual(with_labels.effect_class(), lo["effect_class"])
        # A read_only object carrying the gating "sensitive" label is still read_only.
        sensitive = negotiation.LabeledObject(
            policy.READ_ONLY, [negotiation.RiskLabel(negotiation.RISK_SENSITIVE, 1)])
        self.assertEqual(sensitive.effect_class(), policy.READ_ONLY)

    # ---- corpus-graded: trust references -----------------------------------------------------

    def test_trust_ref_checkable_never_weighed(self):
        t = self.C["trust"]
        record = hb(t["external_record_hex"])
        reference = hb(t["reference_hex"])
        tampered = hb(t["tampered_record_hex"])
        ref_a = negotiation.TrustRef(hb(t["registry_a_hex"]), reference, hb(t["subject_hex"]))
        # The carried reference is the content-id of the external record (checkable by recompute).
        self.assertTrue(ref_a.binds_record(record))
        self.assertFalse(ref_a.binds_record(tampered))

        # Signature + content-id recompute (signing demonstrated in isolation, not corpus-graded).
        obj = negotiation.sign_trust_ref(ref_a, ALG, SEED)
        resolved = negotiation.verify_trust_ref(obj, cose.PROFILE_PUBLIC, ALG, PK, record)
        self.assertEqual(resolved.reference, reference)
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.verify_trust_ref(obj, cose.PROFILE_PUBLIC, ALG, PK, tampered)
        self.assertEqual(cm.exception.kind, "ReferenceMismatch")
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.verify_trust_ref(obj, cose.PROFILE_PUBLIC, ALG, FOREIGN_PK, record)
        self.assertEqual(cm.exception.kind, "BadSignature")

        # Two DIFFERENT registries referencing the SAME record both verify; the wire weighs neither.
        ref_b = negotiation.TrustRef(hb(t["registry_b_hex"]), reference, hb(t["subject_hex"]))
        obj_b = negotiation.sign_trust_ref(ref_b, ALG, SEED)
        resolved_b = negotiation.verify_trust_ref(obj_b, cose.PROFILE_PUBLIC, ALG, PK, record)
        self.assertEqual(resolved.reference, resolved_b.reference)
        self.assertNotEqual(resolved.registry, resolved_b.registry)

    # ---- corpus-graded: wire-format edge cases -----------------------------------------------

    def test_edge_keys_out_of_order(self):
        e = self.C["edge_cases"]["keys_out_of_order"]
        offer = negotiation.Message(b"neg-0001", negotiation.ROLE_OFFER, negotiation.PROFILE_BASELINE, [])
        self.assertEqual(offer.bytes().hex(), e["canonical_offer_body_hex"])
        canon = hb(e["canonical_offer_body_hex"])
        noncanon = hb(e["noncanonical_offer_body_hex"])
        self.assertIsNotNone(negotiation.parse_message(canon))
        with self.assertRaises(cose.cbor.NonCanonical):
            cose.cbor.decode(noncanon)
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.parse_message(noncanon)
        self.assertEqual(cm.exception.kind, "NegMalformed")

    def test_edge_empty_vs_absent(self):
        ec = self.C["edge_cases"]["empty_vs_absent"]["causes"]
        neg = b"neg-0001"
        empty = negotiation.Message(neg, negotiation.ROLE_OFFER, negotiation.PROFILE_BASELINE, [])
        one = negotiation.Message(neg, negotiation.ROLE_OFFER, negotiation.PROFILE_BASELINE,
                                  [hb(ec["one_cause"]["cause_hex"])])
        self.assertEqual(empty.bytes().hex(), ec["empty_present"]["body_hex"])
        self.assertEqual(one.bytes().hex(), ec["one_cause"]["body_hex"])
        self.assertNotEqual(empty.id(), one.id())
        self.assertEqual(empty.id().hex(), ec["empty_present"]["id_hex"])
        self.assertIsNotNone(negotiation.parse_message(empty.bytes()))
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.parse_message(hb(ec["absent_field"]["body_hex"]))
        self.assertEqual(cm.exception.kind, "NegMalformed")

        el = self.C["edge_cases"]["empty_vs_absent"]["labels"]
        empty_lo = negotiation.LabeledObject(0, [])
        one_lo = negotiation.LabeledObject(0, [negotiation.RiskLabel(el["one_label"]["code"], el["one_label"]["critical"])])
        self.assertEqual(empty_lo.bytes().hex(), el["empty_present"]["body_hex"])
        self.assertEqual(one_lo.bytes().hex(), el["one_label"]["body_hex"])
        self.assertNotEqual(empty_lo.id(), one_lo.id())
        self.assertEqual(empty_lo.id().hex(), el["empty_present"]["id_hex"])
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.parse_labeled_object(hb(el["absent_field"]["body_hex"]))
        self.assertEqual(cm.exception.kind, "NegMalformed")

    def test_edge_minimal(self):
        m = self.C["edge_cases"]["minimal"]
        offer = negotiation.Message(b"", negotiation.ROLE_OFFER, negotiation.PROFILE_BASELINE, [])
        self.assertEqual(offer.bytes().hex(), m["offer"]["body_hex"])
        self.assertEqual(offer.id().hex(), m["offer"]["id_hex"])
        lo = negotiation.LabeledObject(m["labeled_object"]["effect"], [])
        self.assertEqual(lo.bytes().hex(), m["labeled_object"]["body_hex"])
        self.assertEqual(lo.id().hex(), m["labeled_object"]["id_hex"])
        tr = negotiation.TrustRef(b"", b"", b"")
        self.assertEqual(tr.bytes().hex(), m["trust_ref"]["body_hex"])
        self.assertEqual(tr.id().hex(), m["trust_ref"]["id_hex"])

    def test_edge_look_alike(self):
        la = self.C["edge_cases"]["look_alike"]
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.parse_message(hb(la["trust_ref_as_message"]["body_hex"]))
        self.assertEqual(cm.exception.kind, "NegMalformed")
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.parse_trust_ref(hb(la["message_as_trust_ref"]["body_hex"]))
        self.assertEqual(cm.exception.kind, "NegMalformed")

    # ---- isolation (NOT corpus-graded): real ML-DSA sign/verify ------------------------------

    def test_sign_verify_messages_in_isolation(self):
        neg = hb(self.C["negotiation"]["negotiation_hex"])
        offer = self._msg_from(neg, self.C["negotiation"]["offer"])
        obj = negotiation.sign_message(offer, ALG, SEED)
        vm = negotiation.verify_message(obj, cose.PROFILE_PUBLIC, ALG, PK)
        self.assertEqual(vm.id(), offer.id())
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.verify_message(obj, cose.PROFILE_PUBLIC, ALG, FOREIGN_PK)
        self.assertEqual(cm.exception.kind, "BadSignature")

        # An unknown profile and an unknown role are rejected at verify time.
        unk_prof = negotiation.sign_message(self._msg_from(neg, self.C["negotiation"]["unknown_profile_offer"]), ALG, SEED)
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.verify_message(unk_prof, cose.PROFILE_PUBLIC, ALG, PK)
        self.assertEqual(cm.exception.kind, "UnknownProfile")
        unk_role = negotiation.sign_message(self._msg_from(neg, self.C["negotiation"]["unknown_role_message"]), ALG, SEED)
        with self.assertRaises(negotiation.NegotiationError) as cm:
            negotiation.verify_message(unk_role, cose.PROFILE_PUBLIC, ALG, PK)
        self.assertEqual(cm.exception.kind, "UnknownRole")

        # A labeled object round-trips through sign/verify with its recognized labels.
        labeled = negotiation.LabeledObject(0, self._carried_labels())
        lobj = negotiation.sign_labeled_object(labeled, ALG, SEED)
        obj2, recognized = negotiation.verify_labeled_object(lobj, cose.PROFILE_PUBLIC, ALG, PK)
        self.assertEqual(obj2.effect_class(), policy.READ_ONLY)
        self.assertEqual([l.code for l in recognized], [1, 2])


if __name__ == "__main__":
    unittest.main()
