# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
T1.3 recheck (the checkable-minimum field, NAALP-REQ-110/111, design.md §2.5) known-answer
tests for the Python SDK, graded against the independent oracle (tools/recheck_oracle.py ->
vectors/recheck/cases.json), i.e. Python == Go == Rust == oracle.

Four properties, mirroring impl/go/envelope/envelope_test.go's T1.3 section, all
mutation-surviving:
  1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body
     bytes; a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; and
     the parsed recheck (present/id/critical) matches. Non-canonical cext bytes are rejected
     NonCanonical at the codec.
  2. REJECT PATH IS REAL [MUTATION ANCHOR] -- a CRITICAL recheck naming an UNKNOWN procedure id
     is rejected UnknownCriticalExt; a known critical procedure and an unknown non-critical
     procedure both verify, proving the reject is specific to unknown-under-critical.
  3. READER ROUND-TRIP -- set/get carries the id and criticality; cext takes precedence over ext
     when both name the key.
  4. REGISTRY BOUNDARIES [MUTATION ANCHOR] -- the closed registry is exactly {1,2,3,4}.

Run:  python -m unittest -v tests.test_recheck      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cbor, cose, envelope
from naalp.cbor import M, T

_ALG = cose.ALG_MLDSA65
_SEED = bytes(range(32))  # a LOCAL test signing seed -- the verdict is a sign+verify round-trip.


def _kind_ok(_ch, _k):
    return True


def _load():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "recheck", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    return None


def _base_object(corpus):
    base = corpus["base_object"]
    return envelope.Object(
        kind=base["kind"], channel=base["channel"], tier=base["tier"],
        signer=bytes.fromhex(base["signer_hex"]), created=base["created"], effect=base["effect"],
        causes=[bytes.fromhex(h) for h in base["causes_hex"]], profile=base["profile"],
        body=T(base["body_str"]),
    )


def _apply_placement(o, placement, procedure_id):
    """Build the object via the ONLY variable per case -- the recheck placement -- exactly as
    impl/go/envelope/envelope_test.go's buildRecheckObject does."""
    if placement == "cext":
        o.set_recheck(procedure_id, True)
    elif placement == "ext":
        o.set_recheck(procedure_id, False)
    elif placement == "ext_empty":
        o.ext = M([])  # present but empty (no recheck) -- distinct bytes from absent
    elif placement == "absent":
        pass  # no ext, no cext
    else:
        raise AssertionError("unknown placement %r" % placement)


class RecheckMatchesOracle(unittest.TestCase):
    def test_matches_oracle(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed recheck vector not present (standalone install)")
        self.assertEqual(corpus["recheck_key"], envelope.RECHECK_KEY, "corpus key != impl key")
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        for tc in corpus["cases"]:
            with self.subTest(name=tc["name"]):
                o = _base_object(corpus)
                _apply_placement(o, tc["placement"], tc.get("procedure_id"))

                # byte parity: body-without-id, content id, full body (all pre-signature).
                self.assertEqual(cbor.encode(o._body_map(False)).hex(), tc["body_no_id_hex"], "body-no-id")
                cid = o.content_id()
                self.assertEqual(cid.hex(), tc["content_id_hex"], "content-id")
                o.id = cid
                self.assertEqual(cbor.encode(o._body_map(True)).hex(), tc["full_hex"], "full-body")

                # verdict: sign for real + verify offline; assert accept vs the named error.
                o2 = _base_object(corpus)
                _apply_placement(o2, tc["placement"], tc.get("procedure_id"))
                signed = envelope.sign(o2, _ALG, _SEED)
                if tc["expect"] == "accept":
                    got = envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
                    rid, present, critical = got.recheck()
                    self.assertEqual(present, tc["present"], "present")
                    if present:
                        self.assertEqual(rid, tc["procedure_id"], "id")
                        self.assertEqual(critical, tc["critical"], "critical")
                else:
                    with self.assertRaises(envelope.EnvelopeError) as cm:
                        envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
                    self.assertEqual(cm.exception.kind, tc["expect"], "verdict error")

        # non-canonical recheck bodies (cext keys out of order) are rejected at the CBOR layer.
        for neg in corpus.get("negatives", []):
            with self.subTest(name="negative_" + neg["name"]):
                o = _base_object(corpus)
                prot = envelope._protected_header(_ALG, o.signer, o.profile)
                signed = cose.cose_sign1(_ALG, _SEED, prot, bytes.fromhex(neg["payload_hex"]))
                with self.assertRaises(Exception) as cm:
                    envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
                self.assertEqual(getattr(cm.exception, "kind", None), neg["expect"], "negative verdict")


class RecheckRejectPathIsReal(unittest.TestCase):
    """MUTATION ANCHOR: a CRITICAL recheck naming an UNKNOWN procedure id MUST be rejected with
    UnknownCriticalExt. If verify()'s cext loop is mutated to drop the
    is_known_recheck_procedure check (e.g. always accept), this test flips pass->fail. A known
    critical procedure and a non-critical unknown procedure both verify, proving the reject is
    specific to unknown-under-critical and not a blanket denial."""

    def test_reject_path_is_real(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed recheck vector not present")
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)

        critical_unknown = _base_object(corpus)
        critical_unknown.set_recheck(99, True)  # unknown id, critical
        su = envelope.sign(critical_unknown, _ALG, _SEED)
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, su)
        self.assertEqual(cm.exception.kind, "UnknownCriticalExt")

        critical_known = _base_object(corpus)
        critical_known.set_recheck(envelope.RECHECK_WALK_CAUSES, True)  # known id, critical
        sk = envelope.sign(critical_known, _ALG, _SEED)
        envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, sk)  # must not raise

        non_crit_unknown = _base_object(corpus)
        non_crit_unknown.set_recheck(99, False)  # unknown id, non-critical -> ignored
        sn = envelope.sign(non_crit_unknown, _ALG, _SEED)
        envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, sn)  # must not raise


class RecheckReaderRoundTrip(unittest.TestCase):
    """Proves recheck()/set_recheck() carry the id and criticality, and that cext (critical)
    takes precedence over ext (non-critical) when both name the key."""

    def test_reader_round_trip(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed recheck vector not present")
        o = _base_object(corpus)
        _rid, present, _c = o.recheck()
        self.assertFalse(present, "fresh object must have no recheck")

        o.set_recheck(envelope.RECHECK_VERIFY_COSE_SIGN1, False)
        rid, present, critical = o.recheck()
        self.assertTrue(present)
        self.assertEqual(rid, envelope.RECHECK_VERIFY_COSE_SIGN1)
        self.assertFalse(critical)

        o.set_recheck(envelope.RECHECK_REPLAY_CONSUME_CHECK, True)  # critical wins over the ext entry
        rid, present, critical = o.recheck()
        self.assertTrue(present)
        self.assertEqual(rid, envelope.RECHECK_REPLAY_CONSUME_CHECK)
        self.assertTrue(critical)


class IsKnownRecheckProcedureBoundaries(unittest.TestCase):
    """MUTATION ANCHOR: the re-check procedure registry is CLOSED at exactly {1,2,3,4}. Making
    is_known_recheck_procedure return True unconditionally (or True for any id >= 1) flips this
    test pass->fail, and would also silently disable RecheckRejectPathIsReal's reject branch."""

    def test_boundaries(self):
        self.assertFalse(envelope.is_known_recheck_procedure(0))
        for i in (1, 2, 3, 4):
            self.assertTrue(envelope.is_known_recheck_procedure(i))
        self.assertFalse(envelope.is_known_recheck_procedure(5))
        self.assertFalse(envelope.is_known_recheck_procedure(99))


if __name__ == "__main__":
    unittest.main()
