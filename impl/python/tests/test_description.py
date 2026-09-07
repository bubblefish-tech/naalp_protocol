# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C18 signed description / directory / import conformance for the Python SDK (design.md §21;
R-DESC-1..8), graded against the shared independent corpus vectors/description/cases.json (NOT
produced by this code): the Operation / Description / Directory / Import body-head-id bytes, the
foreign-id binding, the fork-detection first-differing position (fork, length-fork, different-version,
duplicate), and the closed foreign-format rejection.

The offline-verification property (authority in the SIGNED bytes, not the serving host), the
directory fork proof, and the confused-deputy import rule (the wrapping signer is the sole
authorization identity, a foreign identity never becomes one) are real behaviour demonstrated in
isolation with REAL deterministic ML-DSA-65 (the corpus carries no signed-object vector, stated
honestly, so those are NOT corpus-graded).

Written test-first; the description module is absent until ported, so this fails RED on import until
impl/python/naalp/description.py lands, and a mutation forcing the operation effect field to a
constant flips test_operation_bodies_match_oracle.

Run:  python -m unittest -v tests.test_description      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cbor, cose, description, identity, policy
from naalp.cbor import U, T, M


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "description", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/description/cases.json not found")


ALG = cose.ALG_MLDSA65
PROFILE = cose.PROFILE_PUBLIC


class _Key:
    __slots__ = ("seed", "pk", "id")

    def __init__(self, n):
        self.seed = bytes([n & 0xFF] * 32)
        self.pk = cose.mldsa_keygen("ML-DSA-65", self.seed)
        self.id = identity.signer_id(ALG, self.pk)


def _ops(op_dicts):
    return [description.Operation(o["name"], o["effect"], o["requires_approval"]) for o in op_dicts]


class DescriptionConformance(unittest.TestCase):
    C = _vectors()

    # ---- Operation body bytes (THE mutation target) ---------------------------------------

    def test_operation_bodies_match_oracle(self):
        ops = self.C["description"]["operations"]
        self.assertTrue(ops)
        for o in ops:
            op = description.Operation(o["name"], o["effect"], o["requires_approval"])
            self.assertEqual(op.bytes().hex(), o["body_hex"], o["name"])
            self.assertEqual(op.effect_class(), policy.normalize_effect(o["effect"]), o["name"])
            self.assertEqual(op.requires_approval_flag(), o["requires_approval"] == 1, o["name"])

    # ---- Description body / head / id ------------------------------------------------------

    def test_description_body_matches_oracle(self):
        dv = self.C["description"]
        d = description.Description(bytes.fromhex(dv["service_hex"]), _ops(dv["operations"]))
        self.assertEqual(d.bytes().hex(), dv["body_hex"])
        self.assertEqual(d.head().hex(), dv["head_hex"])
        self.assertEqual(d.id().hex(), dv["id_hex"])
        # the operation table reconstructs from the body bytes ALONE (offline-verifiable)
        parsed = description.parse_description(d.bytes())
        op, ok = parsed.operation("write_record")
        self.assertTrue(ok)
        self.assertEqual(op.effect_class(), policy.NON_IDEMPOTENT_WRITE)
        self.assertTrue(op.requires_approval_flag())

    def test_malformed_approval_flag_rejected(self):
        # requires_approval outside {0,1} is rejected (no CBOR boolean), never defaulted.
        m = M([(U(1), T("x")), (U(2), U(0)), (U(3), U(2))])
        with self.assertRaises(description.DescriptionError) as cm:
            description.operation_from_value(m)
        self.assertEqual(cm.exception.kind, "MalformedApprovalFlag")

    # ---- Directory body / head / id + fork detection ---------------------------------------

    def _dir_a(self):
        dv = self.C["directory"]
        return description.Directory(bytes.fromhex(dv["directory_hex"]), dv["version"],
                                     [bytes.fromhex(m) for m in dv["members_a_hex"]])

    def test_directory_bodies_match_oracle(self):
        dv = self.C["directory"]
        a = self._dir_a()
        self.assertEqual(a.bytes().hex(), dv["a"]["body_hex"])
        self.assertEqual(a.head().hex(), dv["a"]["head_hex"])
        self.assertEqual(a.id().hex(), dv["a"]["id_hex"])
        b = description.Directory(bytes.fromhex(dv["directory_hex"]), dv["version"],
                                  [bytes.fromhex(m) for m in dv["fork"]["members_b_hex"]])
        self.assertEqual(b.bytes().hex(), dv["fork"]["b"]["body_hex"])
        self.assertEqual(b.id().hex(), dv["fork"]["b"]["id_hex"])

    def test_fork_detection_matches_oracle(self):
        dv = self.C["directory"]
        a = self._dir_a()
        b = description.Directory(bytes.fromhex(dv["directory_hex"]), dv["version"],
                                  [bytes.fromhex(m) for m in dv["fork"]["members_b_hex"]])
        pos, fork = description.detect_fork(a, b)
        self.assertTrue(fork)
        self.assertEqual(pos, dv["fork"]["first_differing_position"])

        # a truncated member list forks at the length of the shorter list.
        short = description.Directory(bytes.fromhex(dv["directory_hex"]), dv["version"],
                                      [bytes.fromhex(m) for m in dv["length_fork"]["members_short_hex"]])
        pos2, fork2 = description.detect_fork(a, short)
        self.assertTrue(fork2)
        self.assertEqual(pos2, dv["length_fork"]["first_differing_position"])

        # a different version is a legitimate succession, not a fork.
        other_ver = description.Directory(bytes.fromhex(dv["directory_hex"]),
                                          dv["different_version"]["version"], a.members)
        self.assertEqual(description.detect_fork(a, other_ver), (0, False))

        # identical directories are a benign duplicate (no fork) -- corpus records position -1.
        self.assertEqual(description.detect_fork(a, self._dir_a()), (0, False))

    # ---- Import body / head / id / foreign-id + closed foreign-format -----------------------

    def test_import_body_matches_oracle(self):
        iv = self.C["import"]
        im = description.Import(bytes.fromhex(iv["importer_hex"]), iv["format"],
                                bytes.fromhex(iv["foreign_hex"]), _ops(iv["operations"]))
        self.assertEqual(im.bytes().hex(), iv["body_hex"])
        self.assertEqual(im.head().hex(), iv["head_hex"])
        self.assertEqual(im.id().hex(), iv["id_hex"])
        self.assertEqual(im.foreign_id().hex(), iv["foreign_id_hex"])

    def test_unknown_format_rejected(self):
        uf = self.C["import"]["unknown_format"]
        with self.assertRaises(description.DescriptionError) as cm:
            description.parse_import(bytes.fromhex(uf["body_hex"]))
        self.assertEqual(cm.exception.kind, "UnknownDescriptionFormat")

    # ---- offline verification, in isolation (NOT corpus-graded) ----------------------------

    def test_offline_verification_roundtrip(self):
        signer = _Key(21)
        dv = self.C["description"]
        d = description.Description(bytes.fromhex(dv["service_hex"]), _ops(dv["operations"]))
        signed = description.sign_description(d, ALG, signer.seed)
        # the SAME signed bytes verify identically no matter who serves them (authority = signature)
        got = description.verify_description(signed, PROFILE, ALG, signer.pk)
        self.assertEqual(got.bytes(), d.bytes())
        op, ok = got.operation("purge")
        self.assertTrue(ok)
        self.assertEqual(op.effect_class(), policy.DESTRUCTIVE)
        # a tampered copy is rejected BadSignature (the bytes are the authority)
        bad = bytearray(signed)
        bad[-1] ^= 1
        with self.assertRaises(Exception) as cm:
            description.verify_description(bytes(bad), PROFILE, ALG, signer.pk)
        self.assertEqual(getattr(cm.exception, "kind", None), "BadSignature")

    def test_directory_fork_proof_in_isolation(self):
        signer = _Key(22)
        dv = self.C["directory"]
        a = description.Directory(bytes.fromhex(dv["directory_hex"]), dv["version"],
                                  [bytes.fromhex(m) for m in dv["members_a_hex"]])
        b = description.Directory(bytes.fromhex(dv["directory_hex"]), dv["version"],
                                  [bytes.fromhex(m) for m in dv["fork"]["members_b_hex"]])
        sa = description.sign_directory(a, ALG, signer.seed)
        sb = description.sign_directory(b, ALG, signer.seed)
        fp = description.DirectoryForkProof(signer.id.encode(), sa, sb)
        pos = fp.verify(PROFILE, ALG, signer.pk)
        self.assertEqual(pos, dv["fork"]["first_differing_position"])
        # a "fork proof" of one directory against itself is not evidence of equivocation.
        fp_same = description.DirectoryForkProof(signer.id.encode(), sa, sa)
        with self.assertRaises(description.DescriptionError) as cm:
            fp_same.verify(PROFILE, ALG, signer.pk)
        self.assertEqual(cm.exception.kind, "DirForkProofInvalid")

    def test_import_confused_deputy_in_isolation(self):
        # The importer (the wrapping signer, recomputed from the verifying key) is the SOLE authority;
        # a foreign identity in the carried bytes never becomes one (R-14.6).
        signer = _Key(23)
        iv = self.C["import"]
        foreign = bytes.fromhex(iv["foreign_hex"])
        im = description.Import(signer.id.encode(), description.FORMAT_ANP_DESCRIPTION, foreign,
                                _ops(iv["operations"]))
        signed = description.sign_import(im, ALG, signer.seed)
        r = description.verify_import(signed, PROFILE, ALG, signer.pk)
        self.assertEqual(r.authority_id, signer.id)          # recomputed from the key
        self.assertEqual(r.foreign_id, description.content_id(foreign))
        # a signer that names a DIFFERENT importer than its own key id imports as nobody -> rejected.
        forged = description.Import(b"SOMEONE_ELSE", description.FORMAT_ANP_DESCRIPTION, foreign,
                                    _ops(iv["operations"]))
        signed_forged = description.sign_import(forged, ALG, signer.seed)
        with self.assertRaises(description.DescriptionError) as cm:
            description.verify_import(signed_forged, PROFILE, ALG, signer.pk)
        self.assertEqual(cm.exception.kind, "ImporterMismatch")


if __name__ == "__main__":
    unittest.main()
