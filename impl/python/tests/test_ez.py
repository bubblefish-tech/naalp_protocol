# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Tests for naalp.ez — the ergonomic convenience surface.

These prove the wrapper (a) produces the *same wire bytes as the raw SDK* for identical logical
input (so it adds no second encoding and reimplements no crypto — A10 / names-are-contracts),
(b) round-trips sign -> verify, (c) is fail-closed on tamper, wrong key, unknown kind, mislabeled
effect, missing variable effect, and unsupported algorithm. Each is mutation-surviving: replacing
Signer.sign or ez.verify with a constant return flips at least one assertion to failure.

Run:  python -m unittest -v tests.test_ez      (from impl/python/)
"""
import unittest

from naalp import channels, cose, envelope, identity, ez
from naalp.cbor import U, T, M

_SEED = bytes([0x2A]) * 32
_ALG = cose.ALG_MLDSA65
_INTERACTION, _RESPOND = 0x000F, 1          # fixed effect: idempotent_write (1)
_STREAM, _STREAMOPEN = 0x000C, 0            # variable effect
_MLDSA65_PK_LEN = 1952                       # FIPS 204 ML-DSA-65 public key size


def _body(text="hi B"):
    return M([(U(1), T(text))])


class ErgonomicLayer(unittest.TestCase):
    def test_signer_derives_real_identity(self):
        s = ez.Signer(_SEED, alg=_ALG)
        # public key is really derived (correct FIPS 204 size) and the signer id recomputes from it
        self.assertEqual(len(s.public_key), _MLDSA65_PK_LEN)
        self.assertEqual(s.signer_id, identity.signer_id(_ALG, s.public_key))

    def test_bytes_identical_to_raw_sdk(self):
        # ez.Signer.sign must equal the raw envelope.sign path for the same logical object.
        s = ez.Signer(_SEED, alg=_ALG)
        created = 1785000000000
        via_ez = s.sign(_INTERACTION, _RESPOND, _body(), created=created)

        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        sid = identity.signer_id(_ALG, pk)
        _n, declared, _v = channels.lookup(_INTERACTION, _RESPOND)
        raw_obj = envelope.Object(
            kind=_RESPOND, channel=_INTERACTION, signer=sid.encode("utf-8"),
            created=created, effect=declared, profile=cose.PROFILE_PUBLIC, body=_body(),
        )
        via_raw = envelope.sign(raw_obj, _ALG, _SEED)
        self.assertEqual(via_ez, via_raw)  # no second encoding, no reimplemented crypto

    def test_roundtrip_and_message(self):
        s = ez.Signer(_SEED, alg=_ALG)
        signed = s.sign(_INTERACTION, _RESPOND, _body("payload-42"))
        obj = ez.verify(s.public_key, signed)
        self.assertEqual((obj.channel, obj.kind), (_INTERACTION, _RESPOND))
        self.assertEqual(obj.signer, s.signer_id.encode("utf-8"))
        text = next(v.v for k, v in obj.body.pairs if isinstance(k, U) and k.v == 1)
        self.assertEqual(text, "payload-42")

    def test_effect_autoderived_from_registry(self):
        s = ez.Signer(_SEED, alg=_ALG)
        obj = ez.verify(s.public_key, s.sign(_INTERACTION, _RESPOND, _body()))
        _n, declared, _v = channels.lookup(_INTERACTION, _RESPOND)
        self.assertEqual(obj.effect, declared)

    def test_tamper_rejected(self):
        s = ez.Signer(_SEED, alg=_ALG)
        signed = bytearray(s.sign(_INTERACTION, _RESPOND, _body()))
        signed[-1] ^= 0x01
        with self.assertRaises(envelope.EnvelopeError) as cm:
            ez.verify(s.public_key, bytes(signed))
        self.assertEqual(cm.exception.kind, "BadSignature")

    def test_wrong_key_rejected(self):
        s = ez.Signer(_SEED, alg=_ALG)
        signed = s.sign(_INTERACTION, _RESPOND, _body())
        other_pk = cose.mldsa_keygen("ML-DSA-65", bytes([0x99]) * 32)
        with self.assertRaises(envelope.EnvelopeError) as cm:
            ez.verify(other_pk, signed)
        self.assertEqual(cm.exception.kind, "BadSignature")

    def test_unknown_kind_rejected(self):
        s = ez.Signer(_SEED, alg=_ALG)
        with self.assertRaises(channels.UnknownKind):
            s.sign(0x00FF, 0, _body())

    def test_mislabeled_fixed_effect_rejected(self):
        s = ez.Signer(_SEED, alg=_ALG)
        # Respond is a fixed idempotent_write kind; forcing destructive must be refused.
        with self.assertRaises(channels.EffectDeclarationMismatch):
            s.sign(_INTERACTION, _RESPOND, _body(), effect=channels.DE)

    def test_variable_effect_requires_explicit_effect(self):
        s = ez.Signer(_SEED, alg=_ALG)
        with self.assertRaises(ValueError):
            s.sign(_STREAM, _STREAMOPEN, _body())          # StreamOpen has a variable effect
        signed = s.sign(_STREAM, _STREAMOPEN, _body(), effect=channels.RO)
        self.assertEqual(ez.verify(s.public_key, signed).effect, channels.RO)

    def test_unsupported_alg_rejected(self):
        with self.assertRaises(ValueError):
            ez.Signer(_SEED, alg=cose.ALG_ED25519)         # level-0 hybrid leg, not a standalone signer

    def test_bad_seed_length_rejected(self):
        with self.assertRaises(ValueError):
            ez.Signer(bytes(16), alg=_ALG)


if __name__ == "__main__":
    unittest.main()
