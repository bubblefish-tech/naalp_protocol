# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance + mutation-surviving tests for naalp_mcp_guard.receipt (Group 6, AC-6.2.1).

Every test here exercises REAL naalp.cose ML-DSA signing/verification and REAL naalp.cbor
deterministic encoding through the receipt's thin wrapper -- no cryptography is faked.

Run (from ecosystem/naalp-mcp-guard/, PYTHONDONTWRITEBYTECODE=1, using the real Python interpreter
for this platform -- not the Microsoft-Store `python`/`python3` execution-alias stubs):
    python -m unittest -v tests.test_receipt
"""
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-mcp-guard
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_mcp_guard import receipt as receipt_mod  # noqa: E402
from naalp import cose  # noqa: E402

ALG = cose.ALG_MLDSA65


def _seed(byte_value=0x11):
    return bytes([byte_value]) * 32


def _make_receipt(**overrides):
    fields = dict(
        tool_id=b"\x01" * 50, args_id=b"\x02" * 50, call_id=b"\x03" * 50,
        effect=2, decision=receipt_mod.DECISION_EXECUTED, reason="",
        result_hash=b"\x04" * 50, principal="agent-1", tool_name="send_email",
        guard_identity="guard-1", created_ms=1_800_000_000_000,
    )
    fields.update(overrides)
    return receipt_mod.EffectReceipt(**fields)


class EffectReceiptBodyTests(unittest.TestCase):
    def test_bytes_is_deterministic(self):
        r = _make_receipt()
        self.assertEqual(r.bytes(), r.bytes())

    def test_different_effect_changes_content_id(self):
        a = _make_receipt(effect=0)
        b = _make_receipt(effect=3)
        self.assertNotEqual(a.content_id(), b.content_id())

    def test_rejects_bad_decision(self):
        r = _make_receipt(decision="maybe")
        with self.assertRaises(receipt_mod.ReceiptError):
            r.bytes()

    def test_rejects_effect_outside_lattice(self):
        r = _make_receipt(effect=4)
        with self.assertRaises(receipt_mod.ReceiptError):
            r.bytes()


class SignVerifyTests(unittest.TestCase):
    def test_real_signature_verifies(self):
        seed = _seed()
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        r = _make_receipt()
        sig = receipt_mod.sign_effect_receipt(r, ALG, seed)
        self.assertTrue(receipt_mod.verify_effect_receipt(r, ALG, pk, sig))

    def test_tampered_body_fails_in_process_verify(self):
        seed = _seed()
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        r = _make_receipt()
        sig = receipt_mod.sign_effect_receipt(r, ALG, seed)
        tampered = _make_receipt(tool_name="delete_all_data")
        self.assertFalse(receipt_mod.verify_effect_receipt(tampered, ALG, pk, sig))


class OfflineVerifyFileTests(unittest.TestCase):
    """THE OFFLINE VERIFIER load-bearing case (Group 6 AC-6.2.1). `verify_receipt_bytes` is the
    exact function the `verify` CLI command calls -- fully offline, public-key only."""

    def setUp(self):
        self.seed = _seed(0x22)
        self.pk = cose.mldsa_keygen("ML-DSA-65", self.seed)
        self.receipt = _make_receipt()
        self.sig = receipt_mod.sign_effect_receipt(self.receipt, ALG, self.seed)
        self.data = (
            __import__("json").dumps(
                receipt_mod.receipt_file_dict(self.receipt, ALG, self.pk, self.sig)
            ).encode("utf-8")
        )

    def test_valid_receipt_passes(self):
        self.assertTrue(receipt_mod.verify_receipt_bytes(self.data))

    def test_tampered_body_hex_fails(self):
        import json
        obj = json.loads(self.data)
        body = bytearray(bytes.fromhex(obj["body"]))
        body[0] ^= 0xFF  # single-bit(-ish) tamper of the signed body
        obj["body"] = bytes(body).hex()
        tampered = json.dumps(obj).encode("utf-8")
        self.assertFalse(receipt_mod.verify_receipt_bytes(tampered))

    def test_tampered_signature_fails(self):
        import json
        obj = json.loads(self.data)
        sig = bytearray(bytes.fromhex(obj["sig"]))
        sig[0] ^= 0xFF
        obj["sig"] = bytes(sig).hex()
        tampered = json.dumps(obj).encode("utf-8")
        self.assertFalse(receipt_mod.verify_receipt_bytes(tampered))

    def test_tampered_pubkey_fails(self):
        import json
        obj = json.loads(self.data)
        pk = bytearray(bytes.fromhex(obj["pubkey"]))
        pk[0] ^= 0xFF
        obj["pubkey"] = bytes(pk).hex()
        tampered = json.dumps(obj).encode("utf-8")
        self.assertFalse(receipt_mod.verify_receipt_bytes(tampered))

    def test_wrong_key_fails(self):
        """A receipt whose signature is real but whose embedded pubkey is a DIFFERENT real key
        (not the one that actually signed it) must fail -- this catches a mutation that verifies
        only "is pubkey well-formed" rather than "does pubkey verify THIS signature"."""
        import json
        other_seed = _seed(0x33)
        other_pk = cose.mldsa_keygen("ML-DSA-65", other_seed)
        obj = json.loads(self.data)
        obj["pubkey"] = other_pk.hex()
        forged = json.dumps(obj).encode("utf-8")
        self.assertFalse(receipt_mod.verify_receipt_bytes(forged))

    def test_garbage_bytes_fail_closed_not_raise(self):
        self.assertFalse(receipt_mod.verify_receipt_bytes(b"not json at all"))

    def test_wrong_version_fails(self):
        import json
        obj = json.loads(self.data)
        obj["naalp_mcp_guard_receipt"] = 999
        wrong_version = json.dumps(obj).encode("utf-8")
        self.assertFalse(receipt_mod.verify_receipt_bytes(wrong_version))

    def test_unregistered_algorithm_fails_closed(self):
        import json
        obj = json.loads(self.data)
        obj["alg"] = -1  # not a registered ML-DSA algorithm id
        bad_alg = json.dumps(obj).encode("utf-8")
        self.assertFalse(receipt_mod.verify_receipt_bytes(bad_alg))

    def test_write_and_read_back_receipt_file_round_trips(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "receipt.json")
            receipt_mod.write_receipt_file(path, self.receipt, ALG, self.pk, self.sig)
            with open(path, "rb") as f:
                data = f.read()
            self.assertTrue(receipt_mod.verify_receipt_bytes(data))


if __name__ == "__main__":
    unittest.main()
