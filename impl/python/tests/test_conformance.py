# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Self-contained conformance smoke tests over the SDK primitives, anchored to independent
standards vectors (FIPS 180-4 SHA-384, RFC 8949 canonical CBOR, the multiformats signer-id,
the §6.1 effect lattice). The authoritative cross-language grading is the naalp-conform harness
against the 239-case corpus; these keep the published package independently checkable.

Run:  python -m unittest -v tests.test_conformance      (from impl/python/)
"""
import hashlib
import unittest

from naalp import cbor, cose, identity, policy, records, channels
from naalp.cbor import U, B, T, M, NonCanonical


class Primitives(unittest.TestCase):
    def test_sha384_kat(self):
        self.assertEqual(
            hashlib.sha384(b"abc").hexdigest(),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        )

    def test_cbor_canonical_encode_and_content_id(self):
        # canonical map: keys emitted in bytewise-ascending order regardless of input order
        m = M([(U(3), U(4)), (U(2), U(0))])
        self.assertEqual(cbor.encode(m).hex(), "a2020003 04".replace(" ", ""))
        cid = cbor.content_id(cbor.encode(m))
        self.assertEqual(cid[:2], bytes([0x20, 0x30]))            # multihash sha2-384 prefix
        self.assertEqual(len(cid), 2 + 48)

    def test_cbor_rejects_non_canonical(self):
        for bad in ["a202000100", "1800", "9f00ff", "a201000101"]:   # out-of-order/non-shortest/indefinite/dup
            with self.assertRaises(NonCanonical):
                cbor.decode(bytes.fromhex(bad))

    def test_cose_tobesigned_rfc9052(self):
        tbs = cose.to_be_signed_raw(bytes.fromhex("a1013830"), bytes.fromhex("a10700"))
        self.assertTrue(tbs.startswith(bytes.fromhex("846a5369676e617475726531")))  # ["Signature1", ...]

    def test_signer_id_form(self):
        pk = cose.mldsa_keygen("ML-DSA-65", bytes(32))
        sid = identity.signer_id(cose.ALG_MLDSA65, pk)
        self.assertTrue(sid.startswith("b"))                       # multibase base32 prefix

    def test_effect_lattice(self):
        self.assertEqual(policy.normalize_effect(99), policy.DESTRUCTIVE)   # unknown -> destructive
        self.assertTrue(policy.authorizes(policy.NON_IDEMPOTENT_WRITE, policy.IDEMPOTENT_WRITE))
        self.assertFalse(policy.authorizes(policy.READ_ONLY, policy.DESTRUCTIVE))

    def test_channels_registry(self):
        name, effect, variable = channels.lookup(0x0004, 1)        # Governance.Approval
        self.assertEqual((name, effect, variable), ("Approval", policy.NON_IDEMPOTENT_WRITE, False))
        with self.assertRaises(channels.UnknownKind):
            channels.lookup(0x0000, 9999)

    def test_records_deterministic(self):
        # a receipt body round-trips to stable bytes and the head is SHA-384 of it
        body = records.receipt_body(bytes(48), bytes.fromhex("2030" + "00" * 48), 0, 100)
        self.assertEqual(records.receipt_head(body), hashlib.sha384(body).digest())


if __name__ == "__main__":
    unittest.main()
