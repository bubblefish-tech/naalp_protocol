# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C? collaboration/rooms membership conformance for the Python SDK (feature #64), graded against
the shared independent corpus vectors/rooms/cases.json (NOT produced by this code): the membership
op body/content-id byte parity, the receipt-chained room log (bodies + heads via the C7 audit
authority) with the epoch progression and final membership/ownership state, the principal-binding
wire bodies + per-principal chain heads, and the fail-closed behavioural surface (StaleEpoch,
Unauthorized, OwnerImmutable, add-only ownership, RebindUnauthorized) exercised with REAL
ML-DSA-65 signed objects and a REAL co-signed key rotation.

Two graded surfaces: the RoomOp / Binding wire bodies (byte-graded == oracle) and the room state
machine + Delivery-Model-B principal registry (behaviour-graded). Every check is fail-closed (§15):
an op that fails any check is rejected whole, returns its named error, and causes no state change.
Ported from impl/go/rooms; graded against vectors/rooms/cases.json.

The membership object path is a REAL signed N-AALP envelope (tier-1 Governance, real ML-DSA-65
verify + signer-id binding), and the rebind path is a REAL co-signed identity rotation (no
stand-ins). test_stale_epoch_rejected is the mutation target: disabling the epoch-bump check lets a
stale-view op replay, so the StaleEpoch assertion flips.

Written test-first; the module is absent until ported, so this fails RED on import until
impl/python/naalp/rooms.py lands.

Run:  python -m unittest -v tests.test_rooms      (from impl/python/)
"""
import json
import os
import unittest

from naalp import audit, channels, cose, envelope, identity, rooms


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "rooms", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/rooms/cases.json not found")


def _hb(s):
    return bytes.fromhex(s)


ALG = cose.ALG_MLDSA65
PROFILE = cose.PROFILE_PUBLIC


def _key(seed_byte):
    """A real ML-DSA-65 keypair from an all-<seed_byte> 32-byte seed; returns (seed, pk, signer_id)."""
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk, identity.signer_id(ALG, pk)


class RoomsConformance(unittest.TestCase):
    C = _vectors()

    # ---- membership op body / content-id byte parity (design §2.3) ------------------------

    def test_op_bodies_match_oracle(self):
        rj = self.C["rooms"]
        room = _hb(rj["room_id_hex"])
        self.assertTrue(rj["ops"])
        for oj in rj["ops"]:
            op = rooms.RoomOp(room, oj["op"], oj["epoch_at_build"], oj["subject"], oj["role"])
            self.assertEqual(op.bytes().hex(), oj["body_hex"], oj["op_name"])
            self.assertEqual(op.content_id().hex(), oj["op_content_id_hex"], oj["op_name"])

    # ---- the full run: receipt-chained log + state machine (byte + value) ------------------

    def test_room_run_matches_oracle(self):
        rj = self.C["rooms"]
        room = _hb(rj["room_id_hex"])
        seed, pk, _ = _key(90)          # the room's ordering authority
        auth = audit.Authority(ALG, seed)
        ops, log = rj["ops"], rj["room_log"]

        create = ops[0]
        cop = rooms.RoomOp(room, create["op"], create["epoch_at_build"], create["subject"], create["role"])
        rm, rec0, cursor0 = rooms.create_room(cop, create["subject"], auth, log[0]["at"])
        self.assertEqual(cursor0, 0)
        self.assertEqual(rm.epoch(), 1)
        self._check_receipt(rec0, log[0])

        for i in range(1, len(ops)):
            oj = ops[i]
            op = rooms.RoomOp(room, oj["op"], oj["epoch_at_build"], oj["subject"], oj["role"])
            self.assertEqual(oj["epoch_at_build"], rm.epoch(), "built epoch tracks room epoch")
            rec, cursor = rm.apply(op, create["subject"], log[i]["at"])
            self.assertEqual(cursor, oj["seq"], "cursor == oracle seq")
            self.assertEqual(rm.epoch(), oj["epoch_after"], "epoch bumped")
            self._check_receipt(rec, log[i])

        self.assertEqual(rm.epoch(), rj["final_epoch"])
        self.assertEqual(rm.owners(), rj["final_owners"])
        for m in rj["final_members"]:
            role, ok = rm.role_of(m["subject"])
            self.assertTrue(ok, m["subject"])
            self.assertEqual(role, m["role"], m["subject"])
        receipts, sigs = rm.log()
        self.assertIsNone(audit.verify_chain(receipts, sigs, ALG, pk))
        self.assertEqual(receipts[-1].head().hex(), rj["final_log_head_hex"])

    def _check_receipt(self, rec, want):
        self.assertEqual(rec.bytes().hex(), want["body_hex"], "receipt body seq=%d" % want["seq"])
        self.assertEqual(rec.head().hex(), want["head_after_hex"], "receipt head seq=%d" % want["seq"])
        self.assertEqual(rec.obj.hex(), want["obj_hex"], "receipt obj seq=%d" % want["seq"])

    # ---- signed membership end-to-end (REAL ML-DSA-65 through the spine) --------------------

    def test_signed_membership_end_to_end(self):
        room = bytes([0x20, 0x30, 1, 2, 3, 4])
        oseed, opk, oid = _key(50)
        _, _, bobid = _key(51)
        aseed, _, _ = _key(91)
        auth = audit.Authority(ALG, aseed)

        create = rooms.RoomOp(room, rooms.OP_CREATE, 0, oid, rooms.ROLE_OWNER)
        rm, _, _ = rooms.create_room(create, oid, auth, 1000)

        add = rooms.RoomOp(room, rooms.OP_ADD_MEMBER, rm.epoch(), bobid, rooms.ROLE_MEMBER)
        obj = add.envelope_object(oid.encode(), 1001, PROFILE, [])
        signed = envelope.sign(obj, ALG, oseed)
        rec, cursor = rm.apply_signed(PROFILE, ALG, opk, signed, 1001)
        self.assertEqual(cursor, 1)
        role, ok = rm.role_of(bobid)
        self.assertTrue(ok)
        self.assertEqual(role, rooms.ROLE_MEMBER)

        # A baseline-only verifier (no tier licensed) rejects the tier-1 room kind as UnknownKind.
        def baseline(ch, k):
            try:
                channels.lookup(ch, k)
                return True
            except channels.UnknownKind:
                return False

        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify(PROFILE, ALG, opk, baseline, signed)
        self.assertEqual(cm.exception.kind, "UnknownKind")

    # ---- EPOCH-BUMPING: StaleEpoch (THIS is the mutation-target assertion) ------------------

    def test_stale_epoch_rejected(self):
        room = bytes([9, 9, 9])
        _, _, oid = _key(52)
        _, _, bobid = _key(53)
        _, _, carolid = _key(54)
        aseed, _, _ = _key(92)
        auth = audit.Authority(ALG, aseed)
        rm, _, _ = rooms.create_room(
            rooms.RoomOp(room, rooms.OP_CREATE, 0, oid, rooms.ROLE_OWNER), oid, auth, 1)
        e = rm.epoch()                                  # both ops build against this epoch
        rm.apply(rooms.RoomOp(room, rooms.OP_ADD_MEMBER, e, bobid, rooms.ROLE_MEMBER), oid, 2)
        with self.assertRaises(rooms.RoomsError) as cm:
            rm.apply(rooms.RoomOp(room, rooms.OP_ADD_MEMBER, e, carolid, rooms.ROLE_MEMBER), oid, 3)
        self.assertEqual(cm.exception.kind, "StaleEpoch")
        self.assertFalse(rm.role_of(carolid)[1], "no state change on a rejected stale-epoch op")
        # The same op rebuilt against the CURRENT epoch is accepted.
        rm.apply(rooms.RoomOp(room, rooms.OP_ADD_MEMBER, rm.epoch(), carolid, rooms.ROLE_MEMBER), oid, 4)
        self.assertTrue(rm.role_of(carolid)[1])

    # ---- only an owner may change membership (fail-closed) ---------------------------------

    def test_unauthorized_actor_rejected(self):
        room = bytes([7, 7])
        _, _, oid = _key(55)
        _, _, bobid = _key(56)
        _, _, malloryid = _key(57)
        aseed, _, _ = _key(93)
        auth = audit.Authority(ALG, aseed)
        rm, _, _ = rooms.create_room(
            rooms.RoomOp(room, rooms.OP_CREATE, 0, oid, rooms.ROLE_OWNER), oid, auth, 1)
        rm.apply(rooms.RoomOp(room, rooms.OP_ADD_MEMBER, rm.epoch(), bobid, rooms.ROLE_MEMBER), oid, 2)
        # mallory (not even a member) tries to add themselves as owner.
        with self.assertRaises(rooms.RoomsError) as cm:
            rm.apply(rooms.RoomOp(room, rooms.OP_ADD_OWNER, rm.epoch(), malloryid, rooms.ROLE_OWNER), malloryid, 3)
        self.assertEqual(cm.exception.kind, "Unauthorized")
        # bob (a member, not an owner) also cannot add a member.
        with self.assertRaises(rooms.RoomsError):
            rm.apply(rooms.RoomOp(room, rooms.OP_ADD_MEMBER, rm.epoch(), malloryid, rooms.ROLE_MEMBER), bobid, 4)
        self.assertEqual(rm.owner_count(), 1, "owner count unchanged on rejected ops")

    # ---- O2: add-only ownership, never ownerless -------------------------------------------

    def test_add_only_ownership_no_ownerless(self):
        room = bytes([5])
        _, _, aliceid = _key(58)
        _, _, bobid = _key(59)
        aseed, _, _ = _key(94)
        auth = audit.Authority(ALG, aseed)
        rm, _, _ = rooms.create_room(
            rooms.RoomOp(room, rooms.OP_CREATE, 0, aliceid, rooms.ROLE_OWNER), aliceid, auth, 1)
        self.assertEqual(rm.owner_count(), 1)
        rm.apply(rooms.RoomOp(room, rooms.OP_ADD_OWNER, rm.epoch(), bobid, rooms.ROLE_OWNER), aliceid, 2)
        self.assertEqual(rm.owner_count(), 2)
        self.assertTrue(rm.is_owner(bobid))
        # remove_member(alice) — an owner — is refused OwnerImmutable.
        with self.assertRaises(rooms.RoomsError) as cm:
            rm.apply(rooms.RoomOp(room, rooms.OP_REMOVE_MEMBER, rm.epoch(), aliceid, rooms.ROLE_MEMBER), bobid, 3)
        self.assertEqual(cm.exception.kind, "OwnerImmutable")
        # change_role(alice -> member) — demoting an owner — is refused OwnerImmutable.
        with self.assertRaises(rooms.RoomsError) as cm:
            rm.apply(rooms.RoomOp(room, rooms.OP_CHANGE_ROLE, rm.epoch(), aliceid, rooms.ROLE_MEMBER), bobid, 4)
        self.assertEqual(cm.exception.kind, "OwnerImmutable")
        # re-add of an existing owner is refused OwnerExists.
        with self.assertRaises(rooms.RoomsError) as cm:
            rm.apply(rooms.RoomOp(room, rooms.OP_ADD_OWNER, rm.epoch(), bobid, rooms.ROLE_OWNER), aliceid, 5)
        self.assertEqual(cm.exception.kind, "OwnerExists")
        self.assertGreaterEqual(rm.owner_count(), 1)

    # ---- Delivery Model B: principal-binding wire bytes (byte parity) ----------------------

    def test_binding_bytes_match_oracle(self):
        for bj in self.C["registry"]["bindings"]:
            b = rooms.Binding(bj["principal"], bj["handle"], bj["epoch"], _hb(bj["prev_hex"]))
            self.assertEqual(b.bytes().hex(), bj["body_hex"], "%s@%d body" % (bj["principal"], bj["epoch"]))
            self.assertEqual(b.head().hex(), bj["head_after_hex"], "%s@%d head" % (bj["principal"], bj["epoch"]))

    # ---- Delivery Model B: rebind-on-rotation (REAL co-signed rotation) ---------------------

    def test_principal_registry_rebind_on_rotation(self):
        v1seed, v1pk, v1id = _key(60)   # alice v1
        v2seed, v2pk, v2id = _key(61)   # alice v2 (rotated-to)
        _, _, evilid = _key(62)

        pr = rooms.PrincipalRegistry()
        pr.bind("agent:alice", v1id)
        self.assertEqual(pr.resolve("agent:alice"), v1id)

        # A valid co-signed rotation v1 -> v2 authorises the rebind; the semantic id survives.
        rot = identity.RotationRecord(v1id, v2id, 100)
        old_sig, new_sig = identity.sign_rotation(rot, ALG, v1seed, v2seed)
        pr.rebind("agent:alice", v2id, rot, ALG, v1pk, ALG, v2pk, old_sig, new_sig)
        self.assertEqual(pr.resolve("agent:alice"), v2id)

        # A hijack: a rotation to an unrelated key not proven continuous with the current handle is
        # refused (signed with the WRONG old key), and the registry is unchanged.
        bad = identity.RotationRecord(v2id, evilid, 200)
        bo, bn = identity.sign_rotation(bad, ALG, v1seed, v2seed)  # old leg signed by v1, not v2
        with self.assertRaises(rooms.RoomsError) as cm:
            pr.rebind("agent:alice", evilid, bad, ALG, v1pk, ALG, v2pk, bo, bn)
        self.assertEqual(cm.exception.kind, "RebindUnauthorized")
        self.assertEqual(pr.resolve("agent:alice"), v2id)

        # An unknown principal resolves fail-closed.
        with self.assertRaises(rooms.RoomsError) as cm:
            pr.resolve("agent:nobody")
        self.assertEqual(cm.exception.kind, "PrincipalUnknown")

    # ---- double-bind refused; first binding is genesis (prev == zero) ----------------------

    def test_bind_duplicate_and_genesis(self):
        _, _, aid = _key(63)
        pr = rooms.PrincipalRegistry()
        b = pr.bind("agent:alice", aid)
        self.assertEqual(b.epoch, 0)
        self.assertEqual(b.prev, rooms.genesis_head())
        with self.assertRaises(rooms.RoomsError) as cm:
            pr.bind("agent:alice", aid)
        self.assertEqual(cm.exception.kind, "PrincipalExists")


if __name__ == "__main__":
    unittest.main()
