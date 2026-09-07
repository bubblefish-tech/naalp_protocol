# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C11 transport-binding conformance for the Python SDK, graded against the shared
independent corpus vectors/transport/cases.json (NOT produced by this code): the media
type, the four bindings' confidentiality/peer-auth guarantees, framing round-trip, and
the §12.3/§12.4 emit boundary matrix. Written test-first; the module is absent until
ported, so this fails RED on import until impl/python/naalp/transport.py lands, and a
mutation to the emit boundary or a transport flag flips a named assertion.

Run:  python -m unittest -v tests.test_transport      (from impl/python/)
"""
import json
import os
import unittest

from naalp import transport


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "transport", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/transport/cases.json not found")


class TransportConformance(unittest.TestCase):
    C = _vectors()

    def test_media_type(self):
        self.assertEqual(transport.MEDIA_TYPE, self.C["media_type"])

    def test_transport_variants_match_corpus(self):
        for t in self.C["transports"]:
            got, ok = transport.by_name(t["name"])
            self.assertTrue(ok, "unknown transport %s" % t["name"])
            self.assertEqual(
                (got.confidential, got.peer_authenticated),
                (t["confidential"], t["peer_authenticated"]),
                "guarantees mismatch for %s" % t["name"],
            )

    def test_frame_roundtrips_object_bytes_unchanged(self):
        t, _ = transport.by_name("npamp")
        mu = transport.frame(t, b"\x01\x02\x03")
        self.assertEqual(mu.media_type, transport.MEDIA_TYPE)
        self.assertEqual(mu.object(), b"\x01\x02\x03")

    def test_object_rejects_wrong_media_type(self):
        mu = transport.MessageUnit("npamp", "application/json", b"x")
        with self.assertRaises(transport.TransportError) as cm:
            mu.object()
        self.assertEqual(cm.exception.kind, "Malformed")

    def test_emit_boundary_matrix(self):
        for c in self.C["emit_matrix"]:
            t, ok = transport.by_name(c["transport"])
            self.assertTrue(ok, "unknown transport %s" % c["transport"])
            if c["result"] == "ok":
                mu = transport.emit(t, b"obj", c["sensitive"], c["require_peer_auth"])
                self.assertEqual(mu.object(), b"obj", c)
            else:
                with self.assertRaises(transport.TransportError) as cm:
                    transport.emit(t, b"obj", c["sensitive"], c["require_peer_auth"])
                self.assertEqual(cm.exception.kind, c["result"], c)


if __name__ == "__main__":
    unittest.main()
