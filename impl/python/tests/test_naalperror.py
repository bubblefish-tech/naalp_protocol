# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
T3.3 naalp-error object + numeric error-code registry known-answer tests for the Python SDK,
mirroring impl/go/naalperror/naalperror.go and impl/rust/src/naalperror.rs (design.md §3.5,
R3.3/R3.4). The encode KATs are hand-computed canonical CBOR, independent of the oracle and of
impl/go -- Python MUST reproduce the same bytes as Go and Rust.

Run:  python -m unittest -v tests.test_naalperror      (from impl/python/)
"""
import unittest

from naalp import envelope, naalperror


class RegistrySizeAndIndex(unittest.TestCase):
    def test_registry_size_and_index(self):
        self.assertEqual(len(naalperror.NAMES), 132)
        for i, n in enumerate(naalperror.NAMES):
            code, registered = naalperror.code_for_name(n)
            self.assertTrue(registered)
            self.assertEqual(code, i + 1)
            name, reg2 = naalperror.name_for_code(i + 1)
            self.assertTrue(reg2)
            self.assertEqual(name, n)


class EncodeKat(unittest.TestCase):
    """Hand-computed canonical CBOR of {1:code, 2:name}, independent of the oracle and impl/go."""

    def test_encode_kat_1_noncanonical(self):
        got = naalperror.encode(1, "NonCanonical", "", None)
        self.assertEqual(got.hex(), "a20101026c4e6f6e43616e6f6e6963616c")

    def test_encode_kat_52_notdelivered(self):
        got = naalperror.encode(52, "NotDelivered", "", None)
        self.assertEqual(got.hex(), "a2011834026c4e6f7444656c697665726564")


class DualCarriageMismatchIsMalformed(unittest.TestCase):
    def test_dual_carriage_mismatch_is_malformed(self):
        # code 22 = BadSignature, wrong name -> registered code + disagreeing name -> Malformed.
        b = naalperror.encode(22, "NotDelivered", "", None)
        with self.assertRaises(envelope.EnvelopeError) as cm:
            naalperror.decode(b)
        self.assertEqual(cm.exception.kind, "Malformed")


class UnknownCodeIsOpaque(unittest.TestCase):
    def test_unknown_code_is_opaque(self):
        b = naalperror.encode(60000, "SomeFutureError", "", None)
        o = naalperror.decode(b)
        self.assertEqual(o.code, 60000)
        self.assertEqual(o.name, "SomeFutureError")


class FullGrammarRoundTrip(unittest.TestCase):
    def test_full_grammar_round_trip(self):
        subj = bytes(50)
        b = naalperror.encode(22, "BadSignature", "reason", subj)
        o = naalperror.decode(b)
        self.assertEqual(o.detail, "reason")
        self.assertEqual(len(o.subject), 50)


class MalformedStructuralRejections(unittest.TestCase):
    """The dual-carriage MALFORMED half: a structurally malformed body (not a map, a non-integer
    key, a wrong-typed or unknown field, or a missing code/name) is rejected Malformed."""

    def test_not_a_map(self):
        from naalp.cbor import U, encode as cbor_encode
        with self.assertRaises(envelope.EnvelopeError) as cm:
            naalperror.decode(cbor_encode(U(1)))
        self.assertEqual(cm.exception.kind, "Malformed")

    def test_unknown_field_key(self):
        from naalp.cbor import U, T, M, encode as cbor_encode
        body = cbor_encode(M([(U(1), U(1)), (U(2), T("NonCanonical")), (U(5), U(9))]))
        with self.assertRaises(envelope.EnvelopeError) as cm:
            naalperror.decode(body)
        self.assertEqual(cm.exception.kind, "Malformed")

    def test_missing_name(self):
        from naalp.cbor import U, M, encode as cbor_encode
        body = cbor_encode(M([(U(1), U(1))]))
        with self.assertRaises(envelope.EnvelopeError) as cm:
            naalperror.decode(body)
        self.assertEqual(cm.exception.kind, "Malformed")

    def test_wrong_typed_code(self):
        from naalp.cbor import U, T, M, encode as cbor_encode
        body = cbor_encode(M([(U(1), T("not-a-uint")), (U(2), T("NonCanonical"))]))
        with self.assertRaises(envelope.EnvelopeError) as cm:
            naalperror.decode(body)
        self.assertEqual(cm.exception.kind, "Malformed")


if __name__ == "__main__":
    unittest.main()
