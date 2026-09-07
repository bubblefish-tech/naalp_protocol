# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C12 foreign carriage by class for the Python SDK, graded against the shared independent PER-CLASS
corpus. vectors/carriage/ is NOT a single cases.json: it is one subdirectory per carriage class --
vectors/carriage/{jsonrpc,http,msg,stream,doc,opaque}/cases.json -- and each carriage class is graded
against its OWN subdir's vectors. For every class the carriage body encodes to the oracle bytes and
recovers its foreign message byte-identical (octet-exact), proving the foreign field is carried
verbatim and never re-serialized, canonicalized, or rewritten (R-14.4/R-14.7).

N-AALP carries a foreign agent protocol by wrapping its message octet-for-octet in a signed N-AALP
carriage object; the OPAQUE class makes any protocol -- including an undefined one -- carriable on an
experimental protocol id with no registration (R-18.6). The carriage object's signer remains the
authority: a foreign principal named inside the foreign bytes never becomes an N-AALP authorization
identity (R-14.6), demonstrated in isolation over a real signed envelope object (NOT corpus-graded).

Written test-first; the carriage module is absent until ported, so this fails RED on import until
impl/python/naalp/carriage.py lands. Mutation: forcing the encoded class field (key 2) to the constant
0 in CarriageBody.to_value makes every non-JSONRPC class body diverge from the oracle and flips
test_per_class_octet_exact_round_trip.

Run:  python -m unittest tests.test_carriage      (from impl/python/)
"""
import csv
import json
import os
import unittest

from naalp import carriage, cbor, cose, envelope


def _repo_root():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        if os.path.isdir(os.path.join(d, "vectors", "carriage")):
            return d
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/carriage not found")


ROOT = _repo_root()


def _class_vectors(dir_):
    with open(os.path.join(ROOT, "vectors", "carriage", dir_, "cases.json"), encoding="utf-8") as f:
        return json.load(f)


# (subdir, expected class code) -- every carriage class present under vectors/carriage/.
CLASS_DIRS = [
    ("jsonrpc", carriage.CLASS_JSONRPC),
    ("http", carriage.CLASS_HTTP),
    ("msg", carriage.CLASS_MSG),
    ("stream", carriage.CLASS_STREAM),
    ("doc", carriage.CLASS_DOC),
    ("opaque", carriage.CLASS_OPAQUE),
]


def hb(s):
    return bytes.fromhex(s)


class CarriageConformance(unittest.TestCase):

    def test_per_class_octet_exact_round_trip(self):
        # MUTATION TARGET. R-14.7: each carriage class encodes to its own subdir's oracle bytes and
        # recovers its foreign message byte-identical (octet-exact).
        for dir_, want_class in CLASS_DIRS:
            c = _class_vectors(dir_)
            self.assertEqual(c["class"], want_class, "%s class code" % dir_)
            foreign = hb(c["foreign_hex"])
            cb = carriage.carry(c["protocol_id"], c["class"], c["content_type"],
                                hb(c["correlation_hex"]), c["method"], foreign)
            self.assertEqual(cb.bytes().hex(), c["body_hex"], "%s body bytes" % dir_)
            # Round-trip: decode the carriage body and recover the foreign octets exactly.
            rec = carriage.carriage_from_value(cbor.decode(cb.bytes()))
            self.assertEqual(rec.foreign, foreign, "%s foreign octet-exact" % dir_)
            self.assertEqual(rec.protocol_id, c["protocol_id"])
            self.assertEqual(rec.klass, c["class"])
            self.assertEqual(rec.method, c["method"])

    def test_opaque_undefined_protocol(self):
        # R-18.6: an undefined protocol carries under OPAQUE on an experimental protocol id (no
        # registration), byte-exact.
        c = _class_vectors("opaque")
        self.assertEqual(carriage.protocol_range(c["protocol_id"]), "experimental")
        blob = bytes([0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80])
        cb = carriage.carry(c["protocol_id"], carriage.CLASS_OPAQUE, 1, b"", "", blob)
        rec = carriage.carriage_from_value(cbor.decode(cb.bytes()))
        self.assertEqual(rec.foreign, blob)

    def test_protocol_range_boundaries(self):
        # design §13.4 range classification, and the registry CSV's assigned ids are all standards.
        for id_, want in {0x00: "reserved", 0x01: "standards", 0x0F: "standards", 0x10: "experimental",
                          0x7F: "experimental", 0x80: "private", 0xFF: "private", 0x100: "invalid"}.items():
            self.assertEqual(carriage.protocol_range(id_), want, "range(%#x)" % id_)
        with open(os.path.join(ROOT, "vectors", "registry", "protocols.csv"), encoding="utf-8") as f:
            rows = list(csv.reader(f))
        self.assertGreater(len(rows), 1)
        for r in rows[1:]:  # header: protocol_id,name,class,range,reference
            id_ = int(r[0], 16)
            self.assertEqual(carriage.protocol_range(id_), "standards", "registry id %s" % r[0])
            self.assertEqual(r[3], "standards")

    def test_mapping_error_on_unknown_class(self):
        # R-14.8: an unrepresentable class is a typed mapping error, never a silent drop.
        with self.assertRaises(carriage.CarriageError) as cm:
            carriage.carry(0x10, 99, 0, b"", "x", b"y")
        self.assertEqual(cm.exception.kind, "MappingError")

    def test_not_delivered(self):
        # R-14.8: a below-foreign failure reports NotDelivered and never a false "delivered".
        with self.assertRaises(carriage.CarriageError) as cm:
            carriage.report(False)
        self.assertEqual(cm.exception.kind, "NotDelivered")
        rep = carriage.report(True)
        self.assertTrue(rep.delivered)

    def test_malformed_body_rejected(self):
        # A carriage body missing the mandatory foreign field (key 6) is rejected Malformed.
        m = cbor.M([(cbor.U(1), cbor.U(1)), (cbor.U(2), cbor.U(0)), (cbor.U(3), cbor.U(0)),
                    (cbor.U(4), cbor.B(b"")), (cbor.U(5), cbor.T("m"))])
        with self.assertRaises(carriage.CarriageError) as cm:
            carriage.carriage_from_value(m)
        self.assertEqual(cm.exception.kind, "Malformed")

    def test_identity_containment_isolation(self):
        # R-14.6 (NOT corpus-graded): a foreign principal named inside the foreign bytes confers no
        # authority; the authorizing principal is the N-AALP signer of the carriage object, over a real
        # signed envelope object. The foreign body recovers octet-exact from the signed object.
        seed = bytes([80]) * 32
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        foreign = b'{"jsonrpc":"2.0","method":"tools/call","params":{"from":"attacker-principal"}}'
        cb = carriage.carry(0x01, carriage.CLASS_JSONRPC, 0, bytes([1, 2, 3, 4]), "tools/call", foreign)
        obj = envelope.Object(kind=0, channel=13, signer=pk, created=100, effect=0,
                              body=cb.to_value(), tier=0, profile=cose.PROFILE_PUBLIC)
        signed = envelope.sign(obj, cose.ALG_MLDSA65, seed)
        o = envelope.verify(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, pk, lambda ch, k: True, signed)
        auth = carriage.carriage_authority(o)
        self.assertEqual(auth, pk)
        self.assertNotIn(b"attacker-principal", auth)
        rec = carriage.carriage_from_value(o.body)
        self.assertEqual(rec.foreign, foreign)
        self.assertIn(b"attacker-principal", rec.foreign)  # present but non-authoritative


if __name__ == "__main__":
    unittest.main()
