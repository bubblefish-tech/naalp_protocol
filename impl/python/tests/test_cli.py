# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Tests for naalp.cli — the command-line tool, driven in-process through cli.main(argv).

Proves the sign|verify round-trip exits 0 and prints the decoded object, and that verify is
fail-closed: a tampered object, a wrong key, and an unknown channel/kind each exit non-zero.
Mutation-surviving: bypassing the verify path (constant exit 0) flips the tamper/wrong-key cases.

Run:  python -m unittest -v tests.test_cli      (from impl/python/)
"""
import contextlib
import io
import os
import tempfile
import unittest

from naalp import cli, cose

_SEED_HEX = ("2a" * 32)
_PK = cose.mldsa_keygen("ML-DSA-65", bytes.fromhex(_SEED_HEX))
_PK_HEX = _PK.hex()
_INTERACTION, _RESPOND = "15", "1"          # Interaction / Respond


def _run(argv):
    """Run cli.main(argv), returning (rc, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="naalp-cli-")
        self.env = os.path.join(self.dir, "obj.bin")

    def _sign(self, message="cli hello"):
        rc, _out, _err = _run([
            "sign", "--seed-hex", _SEED_HEX, "--channel", _INTERACTION, "--kind", _RESPOND,
            "--message", message, "--out", self.env,
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.getsize(self.env) > 0)

    def test_keygen_matches_sdk(self):
        rc, out, _err = _run(["keygen", "--seed-hex", _SEED_HEX])
        self.assertEqual(rc, 0)
        self.assertIn("pubkey    " + _PK_HEX, out)
        self.assertIn("signer-id ", out)

    def test_sign_then_verify_roundtrip(self):
        self._sign("round-trip-message")
        rc, out, _err = _run(["verify", "--pubkey-hex", _PK_HEX, "--in", self.env])
        self.assertEqual(rc, 0)
        self.assertIn("verify OK", out)
        self.assertIn("Interaction", out)
        self.assertIn("round-trip-message", out)

    def test_verify_tampered_nonzero(self):
        self._sign()
        with open(self.env, "rb") as f:
            data = bytearray(f.read())
        data[-1] ^= 0x01
        with open(self.env, "wb") as f:
            f.write(data)
        rc, _out, err = _run(["verify", "--pubkey-hex", _PK_HEX, "--in", self.env])
        self.assertNotEqual(rc, 0)
        self.assertIn("verify FAILED", err)

    def test_verify_wrong_key_nonzero(self):
        self._sign()
        other = cose.mldsa_keygen("ML-DSA-65", bytes([0x99]) * 32).hex()
        rc, _out, _err = _run(["verify", "--pubkey-hex", other, "--in", self.env])
        self.assertNotEqual(rc, 0)

    def test_sign_unknown_kind_nonzero(self):
        rc, _out, err = _run([
            "sign", "--seed-hex", _SEED_HEX, "--channel", "99", "--kind", "0",
            "--message", "x", "--out", self.env,
        ])
        self.assertNotEqual(rc, 0)
        self.assertIn("unknown channel/kind", err)


if __name__ == "__main__":
    unittest.main()
