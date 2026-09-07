# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
T1.6 per-signer forward-only counter (the OPTIONAL detection field, NAALP-REQ-120) known-answer
tests for the Python SDK, graded against the independent oracle (tools/signer_counter_oracle.py
-> vectors/signer_counter/cases.json), i.e. Python == Go == Rust == oracle.

Six properties, mirroring impl/go/envelope/signer_counter_test.go, all mutation-surviving:
  1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body
     bytes; a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; and
     the parsed counter (present/value) matches. Non-canonical ext bytes are rejected
     NonCanonical at the codec.
  2. UNDER SIGNATURE -- the counter is folded into the SIGNER's COSE_Sign1 signed input (ext,
     field 11, is part of the signed body): splicing a different counter into a signed object is
     rejected.
  3. READER ROUND-TRIP -- set/get carries the value; the field is OPTIONAL; a present counter of
     value 0 reads back present.
  4. DETECT MATCHES ORACLE -- detect_signer_duplication reproduces every scenario's findings
     (signer, counter, and the SET of conflicting content ids).
  5. ONE SEQUENCE NOT FLAGGED [MUTATION ANCHOR] -- a single sequence (one object per value, or a
     full honest forward-only run) is never flagged; detection requires two conflicting
     sequences to physically meet.
  6. ABSENT VALIDATES [MUTATION ANCHOR] -- an object carrying no counter Signs and Verifies; the
     field is never mandatory.

Run:  python -m unittest -v tests.test_signer_counter      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cbor, cose, envelope
from naalp.cbor import U, M, T

_ALG = cose.ALG_MLDSA65
_SEED = bytes(range(32))  # a LOCAL test signing seed -- the verdict is a sign+verify round-trip.


def _kind_ok(_ch, _k):
    return True


def _load():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "signer_counter", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    return None


def _base_object(corpus, signer_hex=None, body_str=None):
    """Build the shared base object (fields 2..10) from logical fields, with an optional
    signer/body override -- never from the oracle hex, so a constant encoder diverges."""
    base = corpus["base_object"]
    sh = signer_hex or base["signer_hex"]
    bs = body_str if body_str is not None else base["body_str"]
    return envelope.Object(
        kind=base["kind"], channel=base["channel"], tier=base["tier"],
        signer=bytes.fromhex(sh), created=base["created"], effect=base["effect"],
        causes=[bytes.fromhex(h) for h in base["causes_hex"]], profile=base["profile"],
        body=T(bs),
    )


def _u64(v):
    """A counter from the corpus is a bare JSON number (<= 2^53) or a QUOTED decimal string
    (> 2^53, so a float64 JSON decoder cannot round it -- R12 / NAALP-01-03). Normalize either
    form to the exact Python int; None passes through unchanged."""
    return int(v) if isinstance(v, str) else v


def _apply_placement(o, placement, counter):
    """Apply the case's counter placement -- the ONLY variable per case."""
    counter = _u64(counter)
    if placement == "ext":
        o.set_signer_counter(counter)
    elif placement == "cext":
        # the counter placed in the CRITICAL map is an unrecognized critical extension.
        o.cext = M([(U(envelope.SIGNER_COUNTER_KEY), U(counter))])
    elif placement == "ext_empty":
        o.ext = M([])  # present but empty (no counter) -- distinct bytes from absent
    elif placement == "absent":
        pass  # no ext, no cext
    else:
        raise AssertionError("unknown placement %r" % placement)


class SignerCounterMatchesOracle(unittest.TestCase):
    def test_matches_oracle(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed signer_counter vector not present (standalone install)")
        self.assertEqual(corpus["counter_key"], envelope.SIGNER_COUNTER_KEY, "corpus key != impl key")
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        for tc in corpus["cases"]:
            with self.subTest(name=tc["name"]):
                o = _base_object(corpus, tc.get("signer_hex"), tc.get("body_str"))
                _apply_placement(o, tc["placement"], tc.get("counter"))

                # byte parity: body-without-id, content id, full body.
                self.assertEqual(cbor.encode(o._body_map(False)).hex(), tc["body_no_id_hex"], "body-no-id")
                cid = o.content_id()
                self.assertEqual(cid.hex(), tc["content_id_hex"], "content-id")
                o.id = cid
                self.assertEqual(cbor.encode(o._body_map(True)).hex(), tc["full_hex"], "full-body")

                # verdict: sign for real and verify offline; assert accept vs the named error.
                o2 = _base_object(corpus, tc.get("signer_hex"), tc.get("body_str"))
                _apply_placement(o2, tc["placement"], tc.get("counter"))
                signed = envelope.sign(o2, _ALG, _SEED)
                if tc["expect"] == "accept":
                    got = envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
                    seq, present = got.signer_counter()
                    self.assertEqual(present, tc["present"], "present")
                    if present:
                        self.assertEqual(seq, _u64(tc["counter"]), "value")
                else:
                    with self.assertRaises(envelope.EnvelopeError) as cm:
                        envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
                    self.assertEqual(cm.exception.kind, tc["expect"], "verdict error")

        # non-canonical counter bodies (ext keys out of order) are rejected at the CBOR layer.
        for neg in corpus.get("negatives", []):
            with self.subTest(name="negative_" + neg["name"]):
                o = _base_object(corpus)
                prot = envelope._protected_header(_ALG, o.signer, o.profile)
                signed = cose.cose_sign1(_ALG, _SEED, prot, bytes.fromhex(neg["payload_hex"]))
                with self.assertRaises(Exception) as cm:
                    envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
                self.assertEqual(getattr(cm.exception, "kind", None), neg["expect"], "negative verdict")


class SignerCounterUnderSignature(unittest.TestCase):
    """Proves the counter is folded into the SIGNER's COSE_Sign1 signed input (ext, field 11, is
    part of the signed body): flipping the counter value in a signed object's payload breaks
    verification. A signer-signed (not ledger-signed) counter is the whole point."""

    def test_under_signature(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed signer_counter vector not present")
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        o = _base_object(corpus)
        o.set_signer_counter(5)
        signed = envelope.sign(o, _ALG, _SEED)
        # baseline: the signed object verifies and reads back counter 5.
        got = envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
        seq, present = got.signer_counter()
        self.assertTrue(present and seq == 5, "counter read-back")

        # tamper: change the counter to 6 and re-encode the body WITHOUT re-signing; the object
        # must be rejected (the content id no longer matches the signed body / the signature no
        # longer covers it).
        tampered = _base_object(corpus)
        tampered.set_signer_counter(6)
        tampered.id = o.id  # keep the original (counter=5) content id -- a splice, not a re-sign
        payload = cbor.encode(tampered._body_map(True))
        # reuse the ORIGINAL protected header + signature bytes from the counter=5 object (a real
        # forgery attempt).
        prot, _payload, orig_sig = cose.parse_sign1_raw(signed)
        forged = cose.assemble_sign1_raw(prot, payload, orig_sig)
        with self.assertRaises(Exception):
            envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, forged)


class SignerCounterReaderRoundTrip(unittest.TestCase):
    """Proves set_signer_counter()/signer_counter() carry the value, that the field is OPTIONAL
    (a fresh object has none), and that a present counter of value 0 reads back present (present
    is keyed on the key, not the value)."""

    def test_reader_round_trip(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed signer_counter vector not present")
        o = _base_object(corpus)
        _seq, present = o.signer_counter()
        self.assertFalse(present, "fresh object must have no counter")

        o.set_signer_counter(42)
        seq, present = o.signer_counter()
        self.assertTrue(present and seq == 42, "counter read back wrong")

        o.set_signer_counter(0)  # present with value zero
        seq, present = o.signer_counter()
        self.assertTrue(present and seq == 0, "present-zero counter must read back present")


def _build_scenario_objects(corpus, objs):
    """Reconstruct a detection scenario's presented objects from their logical fields and
    cross-check each recomputed content id against the oracle's."""
    out = []
    for ro in objs:
        o = _base_object(corpus, ro.get("signer_hex"), ro.get("body_str"))
        if ro.get("counter") is not None:
            o.set_signer_counter(_u64(ro["counter"]))
        cid = o.content_id()
        if cid.hex() != ro["content_id_hex"]:
            raise AssertionError("scenario object content-id\n got %s\nwant %s" % (cid.hex(), ro["content_id_hex"]))
        out.append(o)
    return out


class DetectSignerDuplicationMatchesOracle(unittest.TestCase):
    """Grades detect_signer_duplication over every scenario in the independent oracle: the impl
    reconstructs the presented set and MUST reproduce the oracle's exact findings (signer,
    counter, and the SET of surfaced content ids)."""

    def test_matches_oracle(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed signer_counter vector not present")
        for sc in corpus["detection"]["scenarios"]:
            with self.subTest(name=sc["name"]):
                objs = _build_scenario_objects(corpus, sc["objects"])
                findings = envelope.detect_signer_duplication(objs)
                self.assertEqual(len(findings), len(sc["expect"]), "findings count")
                for got, want in zip(findings, sc["expect"]):
                    self.assertEqual(got.signer.hex(), want["signer_hex"], "finding signer")
                    self.assertEqual(got.counter, _u64(want["counter"]), "finding counter")
                    self.assertEqual([i.hex() for i in got.ids], want["ids_hex"], "finding ids")


class DetectOneSequenceNotFlagged(unittest.TestCase):
    """MUTATION ANCHOR for the detection function: a single sequence (one object per value) MUST
    NOT be flagged -- detection requires two conflicting sequences to physically meet. Relaxing
    the `len(idset) < 2` guard in detect_signer_duplication to `< 1` (flag from one) flips this
    test pass->fail; that is the whole detection-not-prevention line."""

    def test_one_sequence_not_flagged(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed signer_counter vector not present")
        # one object alone at position 5.
        one = _base_object(corpus, body_str="holder")
        one.set_signer_counter(5)
        self.assertEqual(envelope.detect_signer_duplication([one]), [], "one sequence alone must not be flagged")

        # a full honest forward-only sequence from one signer (1,2,3) is also one sequence -> not flagged.
        seq_objs = []
        for i, body in enumerate(("s1", "s2", "s3"), start=1):
            o = _base_object(corpus, body_str=body)
            o.set_signer_counter(i)
            seq_objs.append(o)
        self.assertEqual(envelope.detect_signer_duplication(seq_objs), [],
                          "an honest forward-only sequence must not be flagged")


class DetectTwoConflictingFlagged(unittest.TestCase):
    """Two DISTINCT objects, SAME signer id, SAME counter value, presented TOGETHER -> flagged
    once, surfacing BOTH content ids. This is the duplication fingerprint and it is only
    observable because both objects are present."""

    def test_two_conflicting_flagged(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed signer_counter vector not present")
        holder = _base_object(corpus, body_str="holder")
        holder.set_signer_counter(5)
        thief = _base_object(corpus, body_str="thief")
        thief.set_signer_counter(5)

        f = envelope.detect_signer_duplication([holder, thief])
        self.assertEqual(len(f), 1, "two conflicting sequences must be flagged once")
        self.assertEqual(f[0].counter, 5)
        self.assertEqual(len(f[0].ids), 2, "both conflicting content ids must be surfaced")
        hid = holder.content_id()
        tid = thief.content_id()
        surfaced = set(f[0].ids)
        self.assertIn(hid, surfaced)
        self.assertIn(tid, surfaced)


class DetectForwardOnlyConsistentNotFlagged(unittest.TestCase):
    """Two objects from one signer at DIFFERENT (forward-only consistent) positions are not
    flagged; nor are two different signers at one position."""

    def test_forward_only_and_cross_signer(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed signer_counter vector not present")
        a5 = _base_object(corpus, body_str="holder")
        a5.set_signer_counter(5)
        a6 = _base_object(corpus, body_str="next")
        a6.set_signer_counter(6)
        self.assertEqual(envelope.detect_signer_duplication([a5, a6]), [],
                          "forward-only-consistent sequence must not be flagged")

        # per-signer: SIGNER_B at position 5 does not conflict with SIGNER_A at position 5.
        b_hex = corpus["detection"]["signers"]["b_hex"]
        b5 = _base_object(corpus, signer_hex=b_hex, body_str="other")
        b5.set_signer_counter(5)
        self.assertEqual(envelope.detect_signer_duplication([a5, b5]), [],
                          "different signers at one value must not be flagged")


class SignerCounterAbsentValidates(unittest.TestCase):
    """MUTATION ANCHOR for optionality: an object carrying NO counter Signs and Verifies. Making
    the field mandatory (e.g. adding a reject-if-absent check to verify()) flips this test
    pass->fail."""

    def test_absent_validates(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed signer_counter vector not present")
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        o = _base_object(corpus)
        _seq, present = o.signer_counter()
        self.assertFalse(present, "object built without a counter must have none")
        signed = envelope.sign(o, _ALG, _SEED)
        got = envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
        _seq, present = got.signer_counter()
        self.assertFalse(present, "verified object must report no counter")


if __name__ == "__main__":
    unittest.main()
