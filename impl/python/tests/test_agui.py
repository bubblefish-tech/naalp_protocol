# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C21 NAALP-AGUI UI-consent-binding conformance for the Python SDK (design.md §24; R-AGUI-1..6),
graded against the shared independent corpus vectors/agui/cases.json (NOT produced by this code): the
closed UI-event kind vocabulary, the receipt-chained UIEvent body/head/id bytes (including the
minimal event and the >2^53 seq carried as a string), the action content ids (shown vs substituted),
the shown-chain walk with its final head, the malformed/absent-field/non-canonical rejections, and the
hole-detection position for an omitted shown-event.

The consent binding itself -- a human §7 approval bound to the EXACT action content id shown, and the
rejection of a SUBSTITUTED action (different content id) -- and the signed shown-chain are real
behaviour demonstrated in isolation with REAL deterministic ML-DSA-65 (the corpus carries no signed
vector, stated honestly, so those are NOT corpus-graded), reusing the corpus action/substituted ids.

Written test-first; the agui module is absent until ported, so this fails RED on import until
impl/python/naalp/agui.py lands, and a mutation forcing the event kind field to a constant flips
test_event_bodies_match_oracle.

Run:  python -m unittest -v tests.test_agui      (from impl/python/)
"""
import json
import os
import unittest

from naalp import agui, approval, cbor, cose, identity, policy


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "agui", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/agui/cases.json not found")


ALG = cose.ALG_MLDSA65
PROFILE = cose.PROFILE_PUBLIC


class _Key:
    __slots__ = ("seed", "pk", "id")

    def __init__(self, n):
        self.seed = bytes([n & 0xFF] * 32)
        self.pk = cose.mldsa_keygen("ML-DSA-65", self.seed)
        self.id = identity.signer_id(ALG, self.pk)


def _hb(s):
    return bytes.fromhex(s)


class AguiConformance(unittest.TestCase):
    C = _vectors()

    # ---- the closed UI-event kind vocabulary ----------------------------------------------

    def test_kind_vocabulary(self):
        for kv in self.C["kind_vocabulary"]:
            self.assertEqual(agui.kind_name(kv["code"]), kv["name"], kv)
            self.assertTrue(agui.is_known_kind(kv["code"]))
        self.assertFalse(agui.is_known_kind(self.C["unknown_kind"]))
        self.assertEqual(agui.kind_name(self.C["unknown_kind"]), "unknown")

    # ---- UIEvent body / head / id bytes (THE mutation target) ------------------------------

    def test_event_bodies_match_oracle(self):
        evs = self.C["chain"]["events"]
        self.assertTrue(evs)
        sess = _hb(self.C["session_hex"])
        for ev in evs:
            e = agui.UIEvent(sess, ev["kind"], _hb(ev["action_hex"]), ev["seq"], _hb(ev["prev_hex"]))
            self.assertEqual(e.bytes().hex(), ev["body_hex"], ev["kind"])
            self.assertEqual(e.head().hex(), ev["head_hex"], ev["kind"])
            self.assertEqual(e.id().hex(), ev["id_hex"], ev["kind"])

        # the minimal event (empty session/action, seq 0, genesis prev).
        mn = self.C["minimal"]
        e = agui.UIEvent(_hb(mn["session_hex"]), mn["kind"], _hb(mn["action_hex"]), mn["seq"],
                         _hb(mn["prev_hex"]))
        self.assertEqual(e.bytes().hex(), mn["body_hex"])
        self.assertEqual(e.id().hex(), mn["id_hex"])

        # a >2^53 seq (carried in the corpus as a STRING to avoid float64 rounding) round-trips exact.
        bs = self.C["big_seq"]
        e = agui.UIEvent(sess, bs["kind"], _hb(bs["action_hex"]), int(bs["seq_str"]), _hb(bs["prev_hex"]))
        self.assertEqual(e.bytes().hex(), bs["body_hex"])
        self.assertEqual(e.id().hex(), bs["id_hex"])

    # ---- action content ids (shown vs substituted) -----------------------------------------

    def test_action_content_ids_match_oracle(self):
        self.assertEqual(agui.content_id(_hb(self.C["action_bytes_hex"])).hex(),
                         self.C["action_cid_hex"])
        self.assertEqual(agui.content_id(_hb(self.C["substituted_bytes_hex"])).hex(),
                         self.C["substituted_cid_hex"])
        self.assertNotEqual(self.C["action_cid_hex"], self.C["substituted_cid_hex"])

    # ---- the shown-chain walk (contiguity, heads) ------------------------------------------

    def _chain_events(self):
        sess = _hb(self.C["session_hex"])
        return [agui.UIEvent(sess, ev["kind"], _hb(ev["action_hex"]), ev["seq"], _hb(ev["prev_hex"]))
                for ev in self.C["chain"]["events"]]

    def test_walk_shown_matches_oracle(self):
        shown = agui.walk_shown(self._chain_events())
        self.assertEqual(len(shown), 3)
        self.assertEqual(shown[-1].head.hex(), self.C["chain"]["final_head_hex"])
        # each event re-parses from its own body bytes.
        for e, ev in zip(self._chain_events(), self.C["chain"]["events"]):
            got = agui.parse_ui_event(e.bytes())
            self.assertEqual(got.kind, ev["kind"])
            self.assertEqual(got.seq, ev["seq"])

    # ---- malformed / absent-field / non-canonical rejections -------------------------------

    def test_rejections(self):
        ec = self.C["edge_cases"]
        # a body whose mandatory field 5 (prev) is absent is UIMalformed.
        with self.assertRaises(agui.AguiError) as cm:
            agui.parse_ui_event(_hb(ec["empty_vs_absent"]["absent_field"]["body_hex"]))
        self.assertEqual(cm.exception.kind, "UIMalformed")
        # a ui-event-shaped body lacking its field-5 back-pointer is UIMalformed.
        with self.assertRaises(agui.AguiError) as cm:
            agui.parse_ui_event(_hb(ec["look_alike"]["body_hex"]))
        self.assertEqual(cm.exception.kind, "UIMalformed")
        # descending-key body is rejected NonCanonical at decode.
        with self.assertRaises(cbor.NonCanonical):
            cbor.decode(_hb(ec["keys_out_of_order"]["noncanonical_body_hex"]))
        # an empty action is a valid, distinct wire body from a populated one.
        eva = ec["empty_vs_absent"]
        e_empty = agui.parse_ui_event(_hb(eva["empty_action"]["body_hex"]))
        self.assertEqual(e_empty.id().hex(), eva["empty_action"]["id_hex"])
        self.assertEqual(e_empty.action, b"")

    # ---- hole detection: an omitted shown-event leaves a positioned hole --------------------

    def test_hole_detection_matches_oracle(self):
        evs = self._chain_events()
        # a contiguous chain has no hole.
        self.assertEqual(agui.detect_hole(evs), (0, False))
        # omit ev1 (present indices ev0, ev2): the gap is detected at the corpus position.
        gappy = [evs[0], evs[2]]
        pos, hole = agui.detect_hole(gappy)
        self.assertTrue(hole)
        self.assertEqual(pos, self.C["hole"]["position"])
        # walking a gappy chain is UIChainBroken.
        with self.assertRaises(agui.AguiError) as cm:
            agui.walk_shown(gappy)
        self.assertEqual(cm.exception.kind, "UIChainBroken")

    # ---- the consent binding, in isolation (NOT corpus-graded; uses corpus action ids) ------

    def _signed_consent_chain(self, ui_key, action_cid):
        """A real ML-DSA-65 signed shown chain: shown -> args-shown -> approved, all naming
        action_cid, receipt-chained."""
        events, objs = [], []
        h = agui.genesis()
        sess = _hb(self.C["session_hex"])
        for seq, kind in ((0, agui.KIND_SHOWN), (1, agui.KIND_ARGS_SHOWN), (2, agui.KIND_APPROVED)):
            e = agui.UIEvent(sess, kind, action_cid, seq, h)
            objs.append(agui.sign_ui_event(e, ALG, ui_key.seed))
            events.append(e)
            h = e.head()
        return events, objs

    def test_verify_consent_binds_exact_action(self):
        ui = _Key(31)
        approver = _Key(32)
        action_bytes = _hb(self.C["action_bytes_hex"])
        action_cid = _hb(self.C["action_cid_hex"])
        events, objs = self._signed_consent_chain(ui, action_cid)

        # the signed shown chain verifies structurally + cryptographically.
        got = agui.verify_shown_chain(objs, PROFILE, ALG, ui.pk)
        self.assertEqual(len(got), 3)

        # a human §7 approval binding the shown action content id.
        appr = approval.ApprovalRecord(action_cid, approver.id, policy.DESTRUCTIVE, b"\x01", 1_000_000)
        sig = approval.sign_approval(appr, ALG, approver.seed)
        # executing the EXACT action shown+approved is authorized.
        self.assertIsNone(agui.verify_consent(events, action_bytes, appr, ALG, approver.pk, sig, 500))

        # executing a SUBSTITUTED action (different content id) is rejected ActionSubstituted.
        with self.assertRaises(agui.AguiError) as cm:
            agui.verify_consent(events, _hb(self.C["substituted_bytes_hex"]), appr, ALG, approver.pk,
                                sig, 500)
        self.assertEqual(cm.exception.kind, "ActionSubstituted")

    def test_verify_consent_no_approved_event(self):
        # a shown chain with NO approved event has no human consent to bind.
        ui = _Key(33)
        approver = _Key(34)
        action_cid = _hb(self.C["action_cid_hex"])
        sess = _hb(self.C["session_hex"])
        e0 = agui.UIEvent(sess, agui.KIND_SHOWN, action_cid, 0, agui.genesis())
        e1 = agui.UIEvent(sess, agui.KIND_ARGS_SHOWN, action_cid, 1, e0.head())
        appr = approval.ApprovalRecord(action_cid, approver.id, policy.DESTRUCTIVE, b"\x01", 1_000_000)
        sig = approval.sign_approval(appr, ALG, approver.seed)
        with self.assertRaises(agui.AguiError) as cm:
            agui.verify_consent([e0, e1], _hb(self.C["action_bytes_hex"]), appr, ALG, approver.pk,
                                sig, 500)
        self.assertEqual(cm.exception.kind, "UINoConsent")

    def test_verify_shown_chain_rejects_tampered_signature(self):
        ui = _Key(35)
        action_cid = _hb(self.C["action_cid_hex"])
        _events, objs = self._signed_consent_chain(ui, action_cid)
        bad = bytearray(objs[1])
        bad[-1] ^= 1
        objs[1] = bytes(bad)
        with self.assertRaises(Exception) as cm:
            agui.verify_shown_chain(objs, PROFILE, ALG, ui.pk)
        self.assertEqual(getattr(cm.exception, "kind", None), "BadSignature")


if __name__ == "__main__":
    unittest.main()
