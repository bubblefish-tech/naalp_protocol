# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C8 delivery conformance for the Python SDK, graded against the shared independent corpus
vectors/delivery/cases.json (NOT produced by this code): the four monotonic stage names, the
byte-exact signed delivery.update body for each stage, and the T1 content-id framing.

The remaining C8 substance -- the persist-before-acknowledge WAL tracker, the live full-duplex
switchboard, and the content-free relay (whose audit trail is a real C7 chain over content ids) --
is real behaviour demonstrated in isolation (a tempfile WAL, threads, and the shared naalp.audit
chain); the corpus carries no vector for those, so they are NOT corpus-graded (stated honestly).
The delivery.update SIGNATURE is real deterministic ML-DSA-65, also demonstrated in isolation.

Written test-first; the delivery module is absent until ported, so this fails RED on import until
impl/python/naalp/delivery.py lands, and a mutation forcing the encoded stage field to a constant
flips test_update_bodies_match_oracle.

Run:  python -m unittest -v tests.test_delivery      (from impl/python/)
"""
import json
import os
import tempfile
import unittest

from naalp import audit, cose, delivery


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "delivery", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/delivery/cases.json not found")


ALG = cose.ALG_MLDSA65
SEED = bytes(32)
PK = cose.mldsa_keygen("ML-DSA-65", SEED)


class DeliveryConformance(unittest.TestCase):
    C = _vectors()

    def test_stage_vocabulary(self):
        for s in self.C["stages"]:
            self.assertEqual(delivery.stage_name(s["value"]), s["name"], s)
        self.assertEqual(delivery.stage_name(99), "unknown")
        # the four stage constants align with the corpus values, monotonic in order
        self.assertEqual(
            [delivery.STAGE_PERSISTED_ORIGIN, delivery.STAGE_ACCEPTED_RELAY,
             delivery.STAGE_PERSISTED_TARGET, delivery.STAGE_PRESENTED],
            [s["value"] for s in self.C["stages"]],
        )

    def test_update_bodies_match_oracle(self):
        # THIS is the mutation-target assertion: each of the four stages encodes a distinct body.
        obj = bytes.fromhex(self.C["obj_content_id_hex"])
        for uv in self.C["updates"]:
            u = delivery.DeliveryUpdate(obj, uv["stage"], uv["at"])
            self.assertEqual(u.bytes().hex(), uv["body_hex"], "update stage=%d" % uv["stage"])

    def test_sign_verify_update_in_isolation(self):
        # NOT corpus-graded (no signature vector). Real deterministic ML-DSA round-trip.
        obj = bytes.fromhex(self.C["obj_content_id_hex"])
        u = delivery.DeliveryUpdate(obj, delivery.STAGE_PRESENTED, 103)
        sig = delivery.sign_update(u, ALG, SEED)
        self.assertTrue(delivery.verify_update(u, ALG, PK, sig))
        bad = bytearray(sig)
        bad[-1] ^= 1
        self.assertFalse(delivery.verify_update(u, ALG, PK, bytes(bad)))

    def test_tracker_monotonic_persist_and_replay(self):
        # Real WAL behaviour in isolation: monotonic stages, persist-before-ack, StageOutOfOrder on
        # regression, idempotent re-report, and durable recovery after reopen.
        obj = bytes.fromhex(self.C["obj_content_id_hex"])
        fd, path = tempfile.mkstemp(suffix=".wal")
        os.close(fd)
        try:
            t = delivery.open_tracker(path)
            t.advance(obj, delivery.STAGE_PERSISTED_ORIGIN, 100)
            t.advance(obj, delivery.STAGE_PERSISTED_TARGET, 102)  # skipping ahead is permitted
            with self.assertRaises(delivery.DeliveryError) as cm:
                t.advance(obj, delivery.STAGE_ACCEPTED_RELAY, 103)  # regression rejected
            self.assertEqual(cm.exception.kind, "StageOutOfOrder")
            # re-reporting the current stage is an idempotent no-op that still returns the update
            same = t.advance(obj, delivery.STAGE_PERSISTED_TARGET, 104)
            self.assertEqual(same.stage, delivery.STAGE_PERSISTED_TARGET)
            self.assertEqual(t.stage(obj), (delivery.STAGE_PERSISTED_TARGET, True))
            t.close()
            # reopen -> replay recovers the last durable stage
            t2 = delivery.open_tracker(path)
            self.assertEqual(t2.stage(obj), (delivery.STAGE_PERSISTED_TARGET, True))
            self.assertEqual(t2.stage(b"unseen"), (0, False))
            t2.close()
        finally:
            os.remove(path)

    def test_switchboard_full_duplex(self):
        # Two connections held open, objects relayed through both directions concurrently.
        sb = delivery.Switchboard(4)
        try:
            left, right = sb.left(), sb.right()
            left.send(b"L->R")
            right.send(b"R->L")
            self.assertEqual(right.recv(), b"L->R")
            self.assertEqual(left.recv(), b"R->L")
        finally:
            sb.close()

    def test_content_free_relay_audit_trail_verifies(self):
        # A relay retains only a C7 receipt chain over content ids (no payload). The retained trail
        # verifies as a valid chain, and the content-id framing matches the shared T1 framing.
        relay = delivery.ContentFreeRelay(ALG, SEED)
        a = relay.route(b"object-one", 100)
        b = relay.route(b"object-two", 101)
        self.assertEqual(a, b"object-one")  # returned for immediate forwarding
        self.assertEqual(b, b"object-two")
        receipts, sigs = relay.audit_trail()
        self.assertEqual(len(receipts), 2)
        # the receipt names the object's content id, not the payload
        self.assertEqual(receipts[0].obj, delivery.content_id(b"object-one"))
        self.assertEqual(delivery.content_id(b"object-one")[:2], b"\x20\x30")  # T1 framing prefix
        self.assertIsNone(audit.verify_chain(receipts, sigs, ALG, PK))


if __name__ == "__main__":
    unittest.main()
