# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
The object-audience (field 13, §2.5.3) known-answer + gate tests for the Python SDK.

Three properties, all mutation-surviving:
  1. BYTE MATCH -- an audience-bearing object reproduces the independent oracle's content id,
     payload, protected header, and to-be-signed bytes (vectors/envelope/cases.json
     object_with_audience), i.e. Python == Go == Rust == tools/envelope_oracle.py.
  2. check_audience -- the three-branch point-of-use gate (absent+consume-once -> WrongAudience;
     present+foreign -> WrongAudience; else pass).
  3. consume_object -- the gate is enforced at the consume choke point BEFORE the compare-and-set:
     a wrong/absent audience is rejected WrongAudience with NO ledger append; an unnamed ledger
     refuses LedgerUnsigned; a correct audience consumes exactly once (second -> AlreadyConsumed).

Run:  python -m unittest -v tests.test_audience      (from impl/python/)
"""
import json
import os
import tempfile
import unittest

from naalp import cbor, cose, envelope, approval
from naalp.cbor import U, B, T, M

_ALG = cose.ALG_MLDSA65          # -49
_SIGNER = bytes.fromhex("5349474e45525f41")   # "SIGNER_A", the oracle's fixed synthetic signer
_AUDIENCE = "consuming-authority-xyz"


def _audience_object():
    """The oracle's fixed worked object (kind=2, channel=4, created=1785000000000, effect=2,
    profile=1, body='hello') carrying the field-13 audience."""
    return envelope.Object(
        kind=2, channel=4, tier=0, signer=_SIGNER, created=1785000000000, effect=2,
        profile=1, body=T("hello"), audience=_AUDIENCE,
    )


def _find_vector():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "envelope", "cases.json")
        if os.path.isfile(p):
            return p
        d = os.path.dirname(d)
    return None


class AudienceBytesMatchOracle(unittest.TestCase):
    def test_byte_exact_vs_oracle(self):
        p = _find_vector()
        if not p:
            self.skipTest("committed oracle vector not present (standalone install)")
        with open(p, encoding="utf-8") as f:
            want = json.load(f)["object_with_audience"]
        o = _audience_object()
        o.id = o.content_id()
        payload = cbor.encode(o._body_map(True))
        prot = envelope._protected_header(_ALG, o.signer, o.profile)
        tbs = cose.to_be_signed_raw(prot, payload)
        self.assertEqual(o.content_id().hex(), want["content_id_hex"], "content id")
        self.assertEqual(payload.hex(), want["payload_hex"], "payload")
        self.assertEqual(prot.hex(), want["protected_hex"], "protected header")
        self.assertEqual(tbs.hex(), want["tobesigned_hex"], "to-be-signed")

    def test_omit_when_empty_is_additive(self):
        # A no-audience object must encode WITHOUT field 13 (byte-identical to a draft-00 object):
        # the empty audience is absent, not an empty tstr.
        o = envelope.Object(kind=2, channel=4, tier=0, signer=_SIGNER, created=1785000000000,
                            effect=2, profile=1, body=T("hello"))
        body_hex = cbor.encode(o._body_map(False)).hex()
        self.assertNotIn("0d", body_hex[-8:], "no-audience body must not carry field 13 (0x0d)")
        # and the audience object's body IS longer by exactly the field-13 pair
        oa = _audience_object()
        self.assertGreater(len(cbor.encode(oa._body_map(False))), len(cbor.encode(o._body_map(False))))


class CheckAudienceBranches(unittest.TestCase):
    def _pass(self, aud, consume_once):
        o = envelope.Object(kind=2, channel=4, signer=b"x", created=0, effect=0, body=T("x"),
                            audience=aud)
        self.assertIsNone(envelope.check_audience(o, "authority-A", consume_once))

    def _reject(self, aud, consume_once):
        o = envelope.Object(kind=2, channel=4, signer=b"x", created=0, effect=0, body=T("x"),
                            audience=aud)
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.check_audience(o, "authority-A", consume_once)
        self.assertEqual(cm.exception.kind, "WrongAudience")

    def test_consume_once_correct_passes(self):
        self._pass("authority-A", True)

    def test_consume_once_foreign_rejected(self):
        self._reject("authority-B", True)

    def test_consume_once_absent_rejected(self):
        self._reject("", True)

    def test_unrestricted_absent_passes(self):
        self._pass("", False)

    def test_unrestricted_correct_passes(self):
        self._pass("authority-A", False)

    def test_unrestricted_foreign_rejected(self):
        # an audience that names someone else is rejected even for a non-consume-once object
        self._reject("authority-B", False)


class ConsumeObjectAudience(unittest.TestCase):
    def setUp(self):
        fd, self._path = tempfile.mkstemp(prefix="naalp-audience-ledger-")
        os.close(fd)
        self._ledgers = []

    def tearDown(self):
        for led in self._ledgers:
            try:
                led.close()
            except Exception:
                pass
        try:
            os.remove(self._path)
        except OSError:
            pass

    def _open(self, authority):
        led = approval.open_ledger(self._path, authority=authority)
        self._ledgers.append(led)
        return led

    def _obj(self, aud):
        return envelope.Object(kind=2, channel=4, signer=b"x", created=0, effect=0, body=T("x"),
                               audience=aud)

    def test_wrong_audience_rejected_no_append(self):
        led = self._open("authority-A")
        aid = bytes(range(50))
        with self.assertRaises(envelope.EnvelopeError) as cm:
            led.consume_object(self._obj("authority-B"), aid, "consumer")
        self.assertEqual(cm.exception.kind, "WrongAudience")
        self.assertEqual(len(led), 0, "a rejected consume MUST NOT append a ledger entry")

    def test_absent_audience_rejected_no_append(self):
        led = self._open("authority-A")
        aid = bytes(range(50))
        with self.assertRaises(envelope.EnvelopeError) as cm:
            led.consume_object(self._obj(""), aid, "consumer")
        self.assertEqual(cm.exception.kind, "WrongAudience")
        self.assertEqual(len(led), 0)

    def test_correct_audience_consumes_once(self):
        led = self._open("authority-A")
        aid = bytes(range(50))
        led.consume_object(self._obj("authority-A"), aid, "consumer")
        self.assertEqual(len(led), 1)
        with self.assertRaises(approval.ApprovalError) as cm:
            led.consume_object(self._obj("authority-A"), aid, "consumer")
        self.assertEqual(cm.exception.kind, "AlreadyConsumed")

    def test_unnamed_ledger_refuses(self):
        led = self._open("")   # no consuming authority
        aid = bytes(range(50))
        with self.assertRaises(approval.ApprovalError) as cm:
            led.consume_object(self._obj("authority-A"), aid, "consumer")
        self.assertEqual(cm.exception.kind, "LedgerUnsigned")


if __name__ == "__main__":
    unittest.main()
