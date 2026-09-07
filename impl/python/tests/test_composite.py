# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
LAMPS opt-in composite signature (alg -65537, design.md §4.2) known-answer + fail-closed
tests for the Python SDK.

Mutation-surviving properties:
  1. BYTE PARITY -- the composite signature value for fixed seeds+tbs reproduces the Go/Rust
     reference bytes: the SHA-256 of the 3373-byte value (mldsaSig 3309 || edSig 64) is pinned,
     and equals the Go impl/go/cose CompositeSigner output for the same inputs (verified
     byte-identical cross-language, so Python == Go == Rust on the composite crypto core).
  2. M' construction -- M' = Prefix || Label || len(ctx)=0x00 || SHA-512(M) (§4.2).
  3. Round-trip -- composite_verify accepts a valid composite (both legs over M').
  4. Fail-closed -- a tampered ML-DSA leg, a tampered Ed25519 leg, a wrong-length value, and a
     wrong message are ALL rejected (valid-iff-both; RFC 9955 strong non-separability, §4.2/§4.5).

Run:  python -m unittest -v tests.test_composite   (from impl/python/)
"""
import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from naalp import cose

_SEED = bytes(range(32))
_ED_SEED = b"naalp-composite-ed25519-seed-32b"
_TBS = b"parity-tbs-fixed"
# SHA-256 of the 3373-byte composite value for (_SEED, _ED_SEED, _TBS). This value is
# byte-identical to the Go reference (impl/go/cose CompositeSigner{ML65,Ed}.Sign) for the same
# seeds+tbs -- a cross-language, non-circular anchor, not a Python-only self-check.
_VALUE_SHA256 = "424ccd9ac5c96024f2c5a780705749b927b5f1cede4460cd099ebdfbb2b8d9d1"
# SHA-256 of the full 3506-byte composite object (envelope.sign_composite over the fixed worked
# object, ML-DSA seed = bytes(0..31), Ed25519 seed = _ED_SEED). Byte-identical to the Go
# cmd/naalp-composite output for the same seed -- the object-level cross-language KAT that the
# conformance harness (record_cross_port_objects) grades.
_OBJECT_SHA256 = "d0768cfc7948c189cee5ecf2336fa2f2b62a35ad4def84c801da86a0f6133181"
# Composite signer-id (§5.1) for the ML-DSA-65 + Ed25519 keypair derived from (_SEED, _ED_SEED);
# byte-identical to Go identity.CompositeSignerID for the same keys.
_COMPOSITE_SIGNER_ID = "bciqprynbbhjimvhoque4zvkhftcwubtjahyw5ybwoqxxit5desygivi"

_MLDSA65_SIG = 3309
_ED25519_SIG = 64


def _pubkeys():
    from dilithium_py.ml_dsa import ML_DSA_65
    ml_pk, _sk = ML_DSA_65.key_derive(_SEED)
    ed_pk = Ed25519PrivateKey.from_private_bytes(_ED_SEED).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    return ml_pk, ed_pk


class CompositeTest(unittest.TestCase):
    def test_mprime_construction(self):
        m = cose.compute_mprime(cose._COMPOSITE_LABEL_MLDSA65_ED25519, b"", _TBS)
        self.assertEqual(m[:32], b"CompositeAlgorithmSignatures2025")
        self.assertEqual(m[32:62], b"COMPSIG-MLDSA65-Ed25519-SHA512")
        self.assertEqual(m[62], 0, "len(ctx) octet must be 0x00 for empty N-AALP context")
        self.assertEqual(m[63:], hashlib.sha512(_TBS).digest())

    def test_byte_parity_with_go_reference(self):
        val = cose.composite_sign(_SEED, _ED_SEED, _TBS)
        self.assertEqual(len(val), _MLDSA65_SIG + _ED25519_SIG)
        self.assertEqual(hashlib.sha256(val).hexdigest(), _VALUE_SHA256,
                         "composite value diverged from the Go/Rust reference bytes")

    def test_object_byte_parity_with_go_reference(self):
        from naalp import envelope, cbor
        o = envelope.Object(kind=2, channel=4, tier=0, signer=b"SIGNER_A",
                            created=1785000000000, effect=2, causes=None, profile=1,
                            body=cbor.T("hello"))
        obj = envelope.sign_composite(o, _SEED, _ED_SEED)
        self.assertEqual(len(obj), 3506)
        self.assertEqual(o.suite, envelope.SUITE_MLDSA65_ED25519, "field 14 must be set present")
        self.assertEqual(hashlib.sha256(obj).hexdigest(), _OBJECT_SHA256,
                         "composite object diverged from the Go cmd/naalp-composite bytes")

    def test_roundtrip_valid(self):
        ml_pk, ed_pk = _pubkeys()
        val = cose.composite_sign(_SEED, _ED_SEED, _TBS)
        self.assertTrue(cose.composite_verify(ml_pk, ed_pk, _TBS, val))

    def test_composite_signer_id_parity(self):
        from naalp import identity
        ml_pk, ed_pk = _pubkeys()
        sid = identity.composite_signer_id(cose.ALG_MLDSA65, ml_pk, ed_pk)
        self.assertEqual(sid, _COMPOSITE_SIGNER_ID, "composite signer id diverged from Go")
        # downgrade-resistant: substituting either leg changes the id
        self.assertNotEqual(identity.composite_signer_id(cose.ALG_MLDSA65, ml_pk, b"\x00" * 32), sid)
        self.assertNotEqual(identity.composite_signer_id(cose.ALG_MLDSA65, b"\x00" * 1952, ed_pk), sid)

    def test_object_roundtrip_verify(self):
        from naalp import envelope, cbor
        ml_pk, ed_pk = _pubkeys()
        o = envelope.Object(kind=2, channel=4, tier=0, signer=b"SIGNER_A", created=1785000000000,
                            effect=2, causes=None, profile=1, body=cbor.T("hello"))
        obj = envelope.sign_composite(o, _SEED, _ED_SEED)
        pubkey = ml_pk + ed_pk  # composite verifying key = mldsaPub || ed25519Pub
        vo = envelope.verify(1, cose.ALG_COMPOSITE_65_ED25519, pubkey, lambda ch, k: True, obj)
        self.assertEqual(vo.suite, envelope.SUITE_MLDSA65_ED25519)
        bad = bytearray(obj)
        bad[-1] ^= 1  # tamper the Ed25519 leg -> composite fails -> BadSignature
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify(1, cose.ALG_COMPOSITE_65_ED25519, pubkey, lambda ch, k: True, bytes(bad))
        self.assertEqual(cm.exception.kind, "BadSignature")

    def test_fail_closed(self):
        ml_pk, ed_pk = _pubkeys()
        val = cose.composite_sign(_SEED, _ED_SEED, _TBS)
        tamper_mldsa = bytes([val[0] ^ 1]) + val[1:]
        tamper_ed = val[:-1] + bytes([val[-1] ^ 1])
        self.assertFalse(cose.composite_verify(ml_pk, ed_pk, _TBS, tamper_mldsa), "tampered ML-DSA leg")
        self.assertFalse(cose.composite_verify(ml_pk, ed_pk, _TBS, tamper_ed), "tampered Ed25519 leg")
        self.assertFalse(cose.composite_verify(ml_pk, ed_pk, _TBS, val[:-1]), "wrong-length value")
        self.assertFalse(cose.composite_verify(ml_pk, ed_pk, b"other-message", val), "wrong message")


if __name__ == "__main__":
    unittest.main()
