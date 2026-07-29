# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
The full-object known-answer test: the reference worked object (fixed seed 0x2a*32) MUST be
reproduced byte-for-byte, and the resulting object MUST verify and reject tampering. When the
repository's committed vector (vectors/worked/example.json) is present the exact bytes are
compared; standalone (after pip install) the crypto round-trip is still checked self-contained.

Run:  python -m unittest -v tests.test_worked_example      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cose, identity, envelope
from naalp.cbor import U, B, T, M

_SEED = bytes([0x2A]) * 32
_ALG = cose.ALG_MLDSA65
# short, self-contained KAT anchors (from vectors/worked/example.json)
_SIGNER_ID = "bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua"
_CONTENT_ID_HEX = "2030192922f9be80623bea1c689ddfe91dc15303abc851c8811b86cf9e53b837b5cc99d9c17e3acf95279f55e48203f79134"
_ARGS_ID_HEX = "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff"


def _worked_object():
    pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
    signer_id = identity.signer_id(_ALG, pk)
    body = M([
        (U(1), B(bytes.fromhex(_ARGS_ID_HEX))),
        (U(2), T(signer_id)),
        (U(3), U(2)),
        (U(4), B(bytes([1, 2, 3, 4, 5, 6, 7, 8]))),
        (U(5), U(1785000000000)),
    ])
    obj = envelope.Object(
        kind=1, channel=4, tier=0, signer=signer_id.encode("utf-8"),
        created=1785000000000, effect=2, profile=cose.PROFILE_PUBLIC, body=body,
    )
    return pk, signer_id, obj


def _find_vector():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "worked", "example.json")
        if os.path.isfile(p):
            return p
        d = os.path.dirname(d)
    return None


class WorkedExample(unittest.TestCase):
    def test_signer_and_content_id(self):
        pk, signer_id, obj = _worked_object()
        self.assertEqual(signer_id, _SIGNER_ID)
        self.assertEqual(obj.content_id().hex(), _CONTENT_ID_HEX)

    def test_sign_verify_roundtrip(self):
        pk, _sid, obj = _worked_object()
        signed = envelope.sign(obj, _ALG, _SEED)
        got = envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, lambda c, k: (c, k) == (4, 1), signed)
        self.assertEqual((got.kind, got.channel, got.effect), (1, 4, 2))

    def test_tamper_rejected(self):
        pk, _sid, obj = _worked_object()
        signed = bytearray(envelope.sign(obj, _ALG, _SEED))
        signed[-1] ^= 1
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, lambda c, k: True, bytes(signed))
        self.assertEqual(cm.exception.kind, "BadSignature")

    def test_byte_exact_vs_committed_vector(self):
        p = _find_vector()
        if not p:
            self.skipTest("committed vector not present (standalone install)")
        with open(p, encoding="utf-8") as f:
            want = json.load(f)
        _pk, _sid, obj = _worked_object()
        self.assertEqual(envelope.sign(obj, _ALG, _SEED).hex(), want["signed_object_hex"])


if __name__ == "__main__":
    unittest.main()
