# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
§5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) known-answer + fail-closed tests
for the Python SDK.

Mutation-surviving properties:
  1. BYTE PARITY -- sign_rotation_object over the fixed worked fixture reproduces the Go/Rust/
     oracle bytes: the SHA-256 of the 6798-byte tag-98 object is pinned and equals the Go
     rotation.sign reference (Python == Go == Rust == oracle on the whole two-leg object).
  2. Round-trip -- verify_rotation_object accepts a co-signed rotation (both legs, old then new).
  3. Fail-closed reject family -- a tag-18 single-signature rotation, a dropped old leg, a
     wrong-key old leg, a tag-98 object on a non-rotation (channel,kind), and a Sovereign verifier
     over a rotation whose OLD key is below the profile floor are ALL rejected with the named kind.

Run:  python -m unittest -v tests.test_rotation   (from impl/python/)
"""
import hashlib
import unittest

from naalp import cbor, cose, envelope

_OLD_SEED = bytes([0x0B]) * 32   # old ML-DSA-65 key
_NEW_SEED = bytes([0x16]) * 32   # new ML-DSA-65 key (go-forward)
_FLOOR_OLD_SEED = bytes([0x21]) * 32   # below-floor old ML-DSA-65 key (33)
_FLOOR_NEW_SEED = bytes([0x2C]) * 32   # go-forward ML-DSA-87 key (44)
# SHA-256 of the 6798-byte tag-98 rotation object for the fixed worked fixture; byte-identical to
# the Go rotation.sign reference and tools/rotation_oracle.py (a cross-language, non-circular
# anchor, not a Python-only self-check).
_OBJECT_SHA256 = "298d5d5bac8a0bf556541784f3090ac7300897858e883dc3ab6e7625bc418194"

_SIGNER = b"SIGNER_NEW"
_NOT_BEFORE = 1785000000000


def _rotation_record():
    # field-10 naalp-rotation body {1: old_id, 2: new_id, 3: not_before}
    return cbor.M([(cbor.U(1), cbor.T("signer-old")), (cbor.U(2), cbor.T("signer-new")),
                   (cbor.U(3), cbor.U(_NOT_BEFORE))])


def _worked_object(profile=cose.PROFILE_PUBLIC):
    return envelope.Object(kind=0, channel=3, signer=_SIGNER, created=1785000000000, effect=2,
                           body=_rotation_record(), tier=0, profile=profile)


def _kind_ok(ch, k):
    return ch == 3 and k == 0


class RotationTest(unittest.TestCase):
    def test_object_byte_parity_with_reference(self):
        obj = envelope.sign_rotation_object(_worked_object(), cose.ALG_MLDSA65, _OLD_SEED,
                                            cose.ALG_MLDSA65, _NEW_SEED)
        self.assertEqual(len(obj), 6798)
        self.assertEqual(hashlib.sha256(obj).hexdigest(), _OBJECT_SHA256,
                         "rotation object diverged from the Go/Rust/oracle reference bytes")

    def test_roundtrip_accept(self):
        old_pk = cose.mldsa_keygen("ML-DSA-65", _OLD_SEED)
        new_pk = cose.mldsa_keygen("ML-DSA-65", _NEW_SEED)
        obj = envelope.sign_rotation_object(_worked_object(), cose.ALG_MLDSA65, _OLD_SEED,
                                            cose.ALG_MLDSA65, _NEW_SEED)
        o = envelope.verify_rotation_object(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, old_pk,
                                            cose.ALG_MLDSA65, new_pk, _kind_ok, obj)
        self.assertEqual((o.channel, o.kind), (3, 0))

    def test_tag18_single_sig_rejected(self):
        # a channel-3/kind-0 object signed as a normal single-signature COSE_Sign1 (tag 18) is a
        # rotation missing the old-key co-signature -> the general verify rejects RotationUnauthorized.
        new_pk = cose.mldsa_keygen("ML-DSA-65", _NEW_SEED)
        obj = envelope.sign(_worked_object(), cose.ALG_MLDSA65, _NEW_SEED)  # tag-18
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, new_pk, _kind_ok, obj)
        self.assertEqual(cm.exception.kind, "RotationUnauthorized")

    def test_old_leg_dropped(self):
        # the mutation anchor: dropping the old leg (one leg) MUST be rejected RotationUnauthorized.
        # Disabling the exactly-two-legs check in verify_rotation_object flips this test.
        old_pk = cose.mldsa_keygen("ML-DSA-65", _OLD_SEED)
        new_pk = cose.mldsa_keygen("ML-DSA-65", _NEW_SEED)
        obj = envelope.sign_rotation_object(_worked_object(), cose.ALG_MLDSA65, _OLD_SEED,
                                            cose.ALG_MLDSA65, _NEW_SEED)
        bp, pl, legs = cose.parse_sign_raw(obj)
        one_leg = cose.assemble_sign_raw(bp, pl, [legs[1]])  # keep only the new leg
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify_rotation_object(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, old_pk,
                                            cose.ALG_MLDSA65, new_pk, _kind_ok, one_leg)
        self.assertEqual(cm.exception.kind, "RotationUnauthorized")

    def test_old_leg_wrong_key(self):
        # both legs signed by the NEW key -> the trusted old key cannot verify slot 0.
        old_pk = cose.mldsa_keygen("ML-DSA-65", _OLD_SEED)
        new_pk = cose.mldsa_keygen("ML-DSA-65", _NEW_SEED)
        obj = envelope.sign_rotation_object(_worked_object(), cose.ALG_MLDSA65, _NEW_SEED,
                                            cose.ALG_MLDSA65, _NEW_SEED)
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify_rotation_object(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, old_pk,
                                            cose.ALG_MLDSA65, new_pk, _kind_ok, obj)
        self.assertEqual(cm.exception.kind, "RotationUnauthorized")

    def test_non_rotation_kind(self):
        # a tag-98 object built over a non-rotation (channel 4, kind 2) is UnknownKind.
        old_pk = cose.mldsa_keygen("ML-DSA-65", _OLD_SEED)
        new_pk = cose.mldsa_keygen("ML-DSA-65", _NEW_SEED)
        o = envelope.Object(kind=2, channel=4, signer=_SIGNER, created=1785000000000, effect=2,
                            body=cbor.T("hello"), tier=0, profile=1)
        o.id = o.content_id()
        payload = cbor.encode(o._body_map(True))
        body_prot = envelope._protected_header(cose.ALG_MLDSA65, o.signer, o.profile)
        legs = [cose.signature_leg(body_prot, cose.ALG_MLDSA65, _OLD_SEED, payload),
                cose.signature_leg(body_prot, cose.ALG_MLDSA65, _NEW_SEED, payload)]
        obj = cose.assemble_sign_raw(body_prot, payload, legs)
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify_rotation_object(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, old_pk,
                                            cose.ALG_MLDSA65, new_pk, lambda ch, k: True, obj)
        self.assertEqual(cm.exception.kind, "UnknownKind")

    def test_sovereign_old_leg_floor(self):
        # old=ML-DSA-65 (level 3), new=ML-DSA-87 (level 5), Sovereign floor 5 -> the sub-floor OLD
        # leg yields ProfileDowngrade under the ratified fail-closed default.
        old_pk = cose.mldsa_keygen("ML-DSA-65", _FLOOR_OLD_SEED)
        new_pk = cose.mldsa_keygen("ML-DSA-87", _FLOOR_NEW_SEED)
        obj = envelope.sign_rotation_object(_worked_object(profile=cose.PROFILE_SOVEREIGN),
                                            cose.ALG_MLDSA65, _FLOOR_OLD_SEED,
                                            cose.ALG_MLDSA87, _FLOOR_NEW_SEED)
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify_rotation_object(cose.PROFILE_SOVEREIGN, cose.ALG_MLDSA65, old_pk,
                                            cose.ALG_MLDSA87, new_pk, _kind_ok, obj)
        self.assertEqual(cm.exception.kind, "ProfileDowngrade")


if __name__ == "__main__":
    unittest.main()
