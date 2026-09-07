# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
NA-IETF-1 producing-boundary disclosure (the OPTIONAL, self-asserted ext key 15, §2.5.4) known-answer
tests for the Python SDK, graded against the independent oracle (tools/producing_boundary_oracle.py
-> vectors/producing_boundary/cases.json), i.e. Python == Go == Rust == oracle.

Five properties, mirroring impl/go/envelope/producing_boundary_test.go, all mutation-surviving:
  1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body bytes;
     a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; and the parsed
     disclosure (present/kind/boundary/reporting) matches. Non-canonical sub-map bytes are rejected
     NonCanonical at the codec.
  2. UNDER SIGNATURE -- the disclosure is folded into the SIGNER's signed body: splicing a different
     boundary into a signed object (keeping its id + signature) is rejected.
  3. READER ROUND-TRIP -- set/get carries the value; the field is OPTIONAL; the setter DROPS a
     reporting-boundary under observed (an observer relays from no one).
  4. MALFORMED IGNORED [MUTATION ANCHOR] -- a well-formed object carrying a MALFORMED disclosure
     (reporting under observed) in the non-critical ext map still verifies and is NOT surfaced.
  5. CEXT REJECTED [MUTATION ANCHOR] -- the disclosure in the CRITICAL cext map is UnknownCriticalExt.

Run:  python -m unittest -v tests.test_producing_boundary      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cbor, cose, envelope
from naalp.cbor import U, B, T, M

_ALG = cose.ALG_MLDSA65
_SEED = bytes(range(32))   # a LOCAL test signing seed -- the verdict is a sign+verify round-trip, not
                           # a reproduction of the oracle's signature (full_hex is the object BODY, not
                           # a signed COSE object, so byte-parity needs no signing).

# the producing-boundary value sub-map WIRE keys (§2.5.4), used to build ext/cext DIRECTLY so the test
# grades the impl against the oracle's independent wire layout, not the impl's own private constants.
_K_BOUNDARY, _K_KIND, _K_REPORTING = 1, 2, 3


def _kind_ok(_ch, _k):
    return True


def _load():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "producing_boundary", "cases.json")
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


def _apply_placement(o, tc):
    """Build the ext[15]/cext[15] sub-map DIRECTLY from the case's logical fields (the ONLY variable
    per case), reproducing the oracle bytes for well-formed AND malformed values -- the malformed
    cases cannot be built via set_producing_boundary by design, so they are constructed here."""
    if tc["placement"] == "absent":
        return
    sub = []
    if tc.get("boundary_hex") is not None:
        sub.append((U(_K_BOUNDARY), B(bytes.fromhex(tc["boundary_hex"]))))
    if tc.get("kind") is not None:
        sub.append((U(_K_KIND), U(tc["kind"])))
    if tc.get("reporting_hex") is not None:
        sub.append((U(_K_REPORTING), B(bytes.fromhex(tc["reporting_hex"]))))
    ext = M([(U(envelope.PRODUCING_BOUNDARY_KEY), M(sub))])
    if tc["placement"] == "ext":
        o.ext = ext
    elif tc["placement"] == "cext":
        o.cext = ext
    else:
        raise AssertionError("unknown placement %r" % tc["placement"])


class ProducingBoundaryMatchesOracle(unittest.TestCase):
    def test_matches_oracle(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed producing_boundary vector not present (standalone install)")
        self.assertEqual(corpus["producing_boundary_key"], envelope.PRODUCING_BOUNDARY_KEY,
                         "corpus key != impl key")
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        for tc in corpus["cases"]:
            with self.subTest(name=tc["name"]):
                o = _base_object(corpus)
                _apply_placement(o, tc)
                # byte parity: body-without-id, content id, full body (all pre-signature).
                self.assertEqual(cbor.encode(o._body_map(False)).hex(), tc["body_no_id_hex"], "body-no-id")
                cid = o.content_id()
                self.assertEqual(cid.hex(), tc["content_id_hex"], "content-id")
                o.id = cid
                self.assertEqual(cbor.encode(o._body_map(True)).hex(), tc["full_hex"], "full-body")

                # verdict: sign for real + verify offline; assert accept vs the named error.
                o2 = _base_object(corpus)
                _apply_placement(o2, tc)
                signed = envelope.sign(o2, _ALG, _SEED)
                if tc["expect"] == "accept":
                    got = envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
                    pb, present = envelope.producing_boundary(got)
                    self.assertEqual(present, tc["present"], "present")
                    if present:
                        s = tc["surfaced"]
                        self.assertEqual(pb.kind, s["kind"], "kind")
                        self.assertEqual(pb.boundary.hex(), s["boundary_hex"], "boundary")
                        want_rep = s["reporting_hex"] or ""
                        self.assertEqual((pb.reporting or b"").hex(), want_rep, "reporting")
                else:
                    with self.assertRaises(envelope.EnvelopeError) as cm:
                        envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
                    self.assertEqual(cm.exception.kind, tc["expect"], "verdict error")

        # non-canonical disclosure bodies (sub-map keys out of order) are rejected at the CBOR layer.
        for neg in corpus.get("negatives", []):
            with self.subTest(name="negative_" + neg["name"]):
                o = _base_object(corpus)
                prot = envelope._protected_header(_ALG, o.signer, o.profile)
                signed = cose.cose_sign1(_ALG, _SEED, prot, bytes.fromhex(neg["payload_hex"]))
                with self.assertRaises(Exception) as cm:
                    envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
                self.assertEqual(getattr(cm.exception, "kind", None), neg["expect"], "negative verdict")


class ProducingBoundaryUnderSignature(unittest.TestCase):
    def test_under_signature(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed producing_boundary vector not present")
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        o = _base_object(corpus)
        envelope.set_producing_boundary(
            o, envelope.ProducingBoundary(bytes.fromhex("424f554e444152595f58"),
                                          envelope.PRODUCING_BOUNDARY_OBSERVED))
        signed = envelope.sign(o, _ALG, _SEED)
        got = envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
        pb, present = envelope.producing_boundary(got)
        self.assertTrue(present and pb.kind == envelope.PRODUCING_BOUNDARY_OBSERVED, "read-back")

        # tamper: change boundary, keep the original id, reuse the original signature (a splice).
        tampered = _base_object(corpus)
        envelope.set_producing_boundary(
            tampered, envelope.ProducingBoundary(bytes.fromhex("4f524947494e5f59"),
                                                 envelope.PRODUCING_BOUNDARY_OBSERVED))
        tampered.id = o.id  # keep original content id -- a splice, not a re-sign
        payload = cbor.encode(tampered._body_map(True))
        prot, _p, sig = cose.parse_sign1_raw(signed)
        forged = cose.assemble_sign1_raw(prot, payload, sig)
        with self.assertRaises(Exception):
            envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, forged)


class ProducingBoundaryReaderRoundTrip(unittest.TestCase):
    def test_reader_round_trip(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed producing_boundary vector not present")
        o = _base_object(corpus)
        _, present = envelope.producing_boundary(o)
        self.assertFalse(present, "fresh object must have no producing-boundary disclosure")
        x = bytes.fromhex("424f554e444152595f58")
        y = bytes.fromhex("4f524947494e5f59")

        envelope.set_producing_boundary(o, envelope.ProducingBoundary(x, envelope.PRODUCING_BOUNDARY_REPORTED, y))
        pb, present = envelope.producing_boundary(o)
        self.assertTrue(present)
        self.assertEqual(pb.kind, envelope.PRODUCING_BOUNDARY_REPORTED)
        self.assertEqual(pb.boundary, x)
        self.assertEqual(pb.reporting, y)

        # the setter drops a reporting-boundary under observed: read-back has no reporting.
        envelope.set_producing_boundary(o, envelope.ProducingBoundary(x, envelope.PRODUCING_BOUNDARY_OBSERVED, y))
        pb, present = envelope.producing_boundary(o)
        self.assertTrue(present)
        self.assertEqual(pb.kind, envelope.PRODUCING_BOUNDARY_OBSERVED)
        self.assertIsNone(pb.reporting, "observed disclosure must drop reporting")


class ProducingBoundaryMalformedIgnored(unittest.TestCase):
    """MUTATION ANCHOR: dropping the reporting-under-observed check in producing_boundary() flips
    present false->true and this test pass->fail; that check is the observer-relays-from-no-one
    invariant."""

    def test_malformed_ignored(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed producing_boundary vector not present")
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        o = _base_object(corpus)
        # malformed ext[15] = {1:X, 2:observed, 3:Y} built directly (the setter refuses to build it).
        o.ext = M([(U(envelope.PRODUCING_BOUNDARY_KEY), M([
            (U(_K_BOUNDARY), B(bytes.fromhex("424f554e444152595f58"))),
            (U(_K_KIND), U(envelope.PRODUCING_BOUNDARY_OBSERVED)),
            (U(_K_REPORTING), B(bytes.fromhex("4f524947494e5f59"))),
        ]))])
        signed = envelope.sign(o, _ALG, _SEED)
        got = envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)  # must NOT raise (may-ignore)
        _, present = envelope.producing_boundary(got)
        self.assertFalse(present, "a malformed disclosure (reporting under observed) must NOT be surfaced")


class ProducingBoundaryCextRejected(unittest.TestCase):
    """MUTATION ANCHOR: the disclosure in the CRITICAL cext map (field 12) is an unrecognized critical
    extension -> UnknownCriticalExt, fail-closed. A disclosure must never masquerade as a
    must-understand gate."""

    def test_cext_rejected(self):
        corpus = _load()
        if not corpus:
            self.skipTest("committed producing_boundary vector not present")
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        o = _base_object(corpus)
        o.cext = M([(U(envelope.PRODUCING_BOUNDARY_KEY), M([
            (U(_K_BOUNDARY), B(bytes.fromhex("424f554e444152595f58"))),
            (U(_K_KIND), U(envelope.PRODUCING_BOUNDARY_OBSERVED)),
        ]))])
        signed = envelope.sign(o, _ALG, _SEED)
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
        self.assertEqual(cm.exception.kind, "UnknownCriticalExt")


if __name__ == "__main__":
    unittest.main()
