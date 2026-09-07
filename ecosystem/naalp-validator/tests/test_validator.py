# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Known-answer tests for the N-AALP semantic validator (naalp_validator.validator).

Non-circularity (F3): expected kind/effect/variable verdicts and the set of legal error
NAMES are read directly from vectors/registry/{channels,error-codes}.csv via tests/_paths.py
-- an independent parse that imports neither naalp.channels nor naalp_validator -- never
from the validator under test or from naalp.channels (which, though already graded
elsewhere, is still the code this validator calls; an oracle built from it would prove only
self-agreement).

Coverage: an ACCEPT case per structural shape (fixed-effect kind, variable-effect kind,
consume-once kind with a correct audience, boundary-exact causes/ext counts, boundary-exact
nesting depth) and one MUST-REJECT case per distinct violation NAME the validator can emit:
Malformed, RangeError (x3: channel/effect/profile), UnknownKind, EffectDeclarationMismatch,
WrongAudience (x2: consume-once-absent, foreign-with-self_authority), TooManyCauses,
TooManyExtensions, TooLarge, DepthExceeded, NonCanonical, TooManyChunks.

Run:  python -m pytest -v tests/test_validator.py
      (from ecosystem/naalp-validator/, with PYTHONDONTWRITEBYTECODE=1; on a Windows checkout
      where a bare "python" resolves to a Store stub, invoke the real interpreter by its own
      full path instead)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from naalp_validator import validator as V  # noqa: E402
from naalp import cbor, envelope  # noqa: E402
from naalp.cbor import U, T, M, A  # noqa: E402

_SIGNER = bytes.fromhex("5349474e45525f41")  # "SIGNER_A" -- a fixed synthetic signer; validate()
                                              # performs no cryptography, so its bytes are inert

_CHANNELS = _paths.load_channels_csv()
_ERROR_NAMES = _paths.load_registered_error_names()


def _obj(channel, kind, effect, **kw):
    kw.setdefault("body", T("x"))
    kw.setdefault("profile", 1)
    kw.setdefault("created", 1785000000000)
    return envelope.Object(kind=kind, channel=channel, signer=_SIGNER, effect=effect, **kw)


def _nested(depth):
    """An array nested `depth` times around a leaf text string."""
    v = T("leaf")
    for _ in range(depth):
        v = A([v])
    return v


class ErrorNamesAreRegistered(unittest.TestCase):
    """Every error name this test file (and by construction, the validator) uses must be a
    REAL, registered N-AALP error -- proves the corpus below isn't inventing verdicts."""

    def test_all_expected_error_names_are_registered(self):
        used = {
            "Malformed", "RangeError", "UnknownKind", "EffectDeclarationMismatch",
            "WrongAudience", "TooManyCauses", "TooManyExtensions", "TooLarge",
            "DepthExceeded", "NonCanonical", "TooManyChunks",
        }
        self.assertTrue(used.issubset(_ERROR_NAMES), used - _ERROR_NAMES)


class AcceptValidCandidates(unittest.TestCase):
    def test_fixed_effect_kind_correct_effect(self):
        # Independently, from the CSV: (0x0000, 0) == Control/Hello, effect read_only (0).
        name, effect, variable = _CHANNELS[(0x0000, 0)]
        self.assertEqual((name, effect, variable), ("Hello", 0, False))
        r = V.validate(_obj(0x0000, 0, effect))
        self.assertTrue(r.valid, r.violations)

    def test_variable_effect_kind_accepts_every_enum_value(self):
        # (0x000C, 0) == Stream/StreamOpen, variable effect: CSV says variable_effect=true.
        name, effect, variable = _CHANNELS[(0x000C, 0)]
        self.assertEqual(name, "StreamOpen")
        self.assertTrue(variable)
        for e in (0, 1, 2, 3):
            with self.subTest(effect=e):
                r = V.validate(_obj(0x000C, 0, e))
                self.assertTrue(r.valid, r.violations)

    def test_consume_once_kind_with_correct_audience(self):
        name, effect, _ = _CHANNELS[(0x0004, 3)]
        self.assertEqual(name, "Consume")
        r = V.validate(_obj(0x0004, 3, effect, audience="authority-A"))
        self.assertTrue(r.valid, r.violations)

    def test_causes_at_exact_boundary_accepted(self):
        r = V.validate(_obj(0x0000, 0, 0, causes=[b"c"] * V.MAX_CAUSES))
        self.assertTrue(r.valid, r.violations)

    def test_ext_at_exact_boundary_accepted(self):
        ext = M([(U(i), U(1)) for i in range(V.MAX_EXT)])
        r = V.validate(_obj(0x0000, 0, 0, ext=ext))
        self.assertTrue(r.valid, r.violations)

    def test_nesting_at_boundary_accepted(self):
        # Empirically confirmed against this validator's own decode_bounded reuse: 14 wrapping
        # arrays around a leaf stays within MAX_NESTING_DEPTH (16); this is the accept side of
        # the boundary the reject test below crosses.
        r = V.validate(_obj(0x0000, 0, 0, body=_nested(14)))
        self.assertTrue(r.valid, r.violations)

    def test_dict_candidate_accepted(self):
        r = V.validate({
            "kind": 0, "channel": 0, "signer": _SIGNER, "created": 1, "effect": 0,
            "body": T("x"), "profile": 1,
        })
        self.assertTrue(r.valid, r.violations)

    def test_foreign_audience_without_self_authority_is_unverifiable_not_rejected(self):
        # Documented design boundary: pre-sign, with no self_authority supplied, a present
        # audience cannot be confirmed foreign, so it is NOT flagged (see validator.py's
        # docstring on the self_authority parameter).
        r = V.validate(_obj(0x0000, 0, 0, audience="someone-else"))
        self.assertTrue(r.valid, r.violations)

    def test_ext_as_plain_dict_with_cbor_typed_values_accepted(self):
        # _pair_count's dict-sugar path (validator.py docstring) wraps only the KEYS of a
        # plain-dict ext for the caller; the values must already be Part-1 CBOR value
        # objects. This is the accept side of a real bug found in this audit: a plain dict
        # with correctly-typed values previously reached cbor.encode() unwrapped and was
        # rejected with a leaked "not a cbor value" Malformed, even though _pair_count had
        # already accepted it as well-formed.
        r = V.validate(_obj(0x0000, 0, 0, ext={0: U(1), 1: T("y")}))
        self.assertTrue(r.valid, r.violations)

    def test_cext_as_plain_dict_with_cbor_typed_values_accepted(self):
        r = V.validate(_obj(0x0000, 0, 0, cext={0: U(1)}))
        self.assertTrue(r.valid, r.violations)


class RejectMalformed(unittest.TestCase):
    def test_wrong_type_candidate_rejected(self):
        r = V.validate(object())
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["Malformed"])

    def test_dict_missing_required_field_rejected(self):
        r = V.validate({"kind": 0, "channel": 0, "signer": _SIGNER, "created": 1, "effect": 0, "profile": 1})
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["Malformed"])

    def test_wrong_type_field_rejected(self):
        o = _obj(0x0000, 0, 0)
        o.channel = "zero"  # a hallucinated string where the wire needs a uint
        r = V.validate(o)
        self.assertFalse(r.valid)
        self.assertIn("Malformed", r.errors())

    def test_body_none_rejected(self):
        r = V.validate(_obj(0x0000, 0, 0, body=None))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["Malformed"])

    def test_ill_typed_ext_rejected(self):
        o = _obj(0x0000, 0, 0)
        o.ext = {"not-an-int": 1}
        r = V.validate(o)
        self.assertFalse(r.valid)
        self.assertIn("Malformed", r.errors())

    def test_ext_as_plain_dict_with_raw_python_value_rejected(self):
        # The dict-sugar path (see AcceptValidCandidates above) wraps only KEYS. A raw,
        # un-wrapped Python value (an LLM's most natural but wire-invalid output) is still
        # not a valid CBOR value object and MUST be rejected, not silently coerced -- this
        # module defines no second codec and must not invent value-coercion rules.
        r = V.validate(_obj(0x0000, 0, 0, ext={0: 1}))
        self.assertFalse(r.valid)
        self.assertIn("Malformed", r.errors())


class RejectRangeError(unittest.TestCase):
    def test_channel_out_of_range(self):
        r = V.validate(_obj(20, 0, 0))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["RangeError"])

    def test_effect_out_of_range(self):
        r = V.validate(_obj(0x0000, 0, 4))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["RangeError"])

    def test_profile_out_of_range(self):
        r = V.validate(_obj(0x0000, 0, 0, profile=4))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["RangeError"])

    def test_variable_kind_effect_out_of_range_is_range_error_not_effect_mismatch(self):
        # Precedence fidelity to envelope.verify(): RangeError precedes the effect-class check.
        r = V.validate(_obj(0x000C, 0, 4))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["RangeError"])


class RejectUnknownKind(unittest.TestCase):
    def test_unregistered_kind_in_registered_channel(self):
        self.assertNotIn((0x0000, 99), _CHANNELS)  # confirm the oracle agrees it's unregistered
        r = V.validate(_obj(0x0000, 99, 0))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["UnknownKind"])


class RejectEffectDeclarationMismatch(unittest.TestCase):
    def test_fixed_effect_kind_wrong_effect(self):
        # From the CSV oracle: (0x0004, 0) == Governance/PolicyPublish, effect non_idempotent_write (2).
        name, declared, variable = _CHANNELS[(0x0004, 0)]
        self.assertEqual((name, declared, variable), ("PolicyPublish", 2, False))
        wrong_effect = 0
        self.assertNotEqual(wrong_effect, declared)
        r = V.validate(_obj(0x0004, 0, wrong_effect))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["EffectDeclarationMismatch"])


class RejectWrongAudience(unittest.TestCase):
    def test_consume_once_kind_with_no_audience(self):
        r = V.validate(_obj(0x0004, 3, 2))  # Governance/Consume, no audience
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["WrongAudience"])

    def test_foreign_audience_rejected_when_self_authority_known(self):
        r = V.validate(_obj(0x0000, 0, 0, audience="someone-else"), self_authority="authority-A")
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["WrongAudience"])


class RejectTooManyCauses(unittest.TestCase):
    def test_causes_over_boundary(self):
        r = V.validate(_obj(0x0000, 0, 0, causes=[b"c"] * (V.MAX_CAUSES + 1)))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["TooManyCauses"])


class RejectTooManyExtensions(unittest.TestCase):
    def test_ext_over_boundary(self):
        ext = M([(U(i), U(1)) for i in range(V.MAX_EXT + 1)])
        r = V.validate(_obj(0x0000, 0, 0, ext=ext))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["TooManyExtensions"])

    def test_cext_over_boundary(self):
        cext = M([(U(i), U(1)) for i in range(V.MAX_CEXT + 1)])
        r = V.validate(_obj(0x0000, 0, 0, cext=cext))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["TooManyExtensions"])

    def test_ext_as_plain_dict_over_boundary_rejected(self):
        ext = {i: U(1) for i in range(V.MAX_EXT + 1)}
        r = V.validate(_obj(0x0000, 0, 0, ext=ext))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["TooManyExtensions"])


class RejectTooLarge(unittest.TestCase):
    def test_body_over_max_octet_size(self):
        r = V.validate(_obj(0x0000, 0, 0, body=T("x" * (V.MAX_OBJECT_SIZE + 16))))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["TooLarge"])


class RejectDepthExceeded(unittest.TestCase):
    def test_nesting_over_boundary(self):
        r = V.validate(_obj(0x0000, 0, 0, body=_nested(15)))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["DepthExceeded"])

    def test_nesting_well_over_boundary(self):
        r = V.validate(_obj(0x0000, 0, 0, body=_nested(40)))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["DepthExceeded"])


class RejectNonCanonical(unittest.TestCase):
    def test_duplicate_ext_key(self):
        dup = M([(U(1), U(1)), (U(1), U(2))])
        r = V.validate(_obj(0x0000, 0, 0, ext=dup))
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["NonCanonical"])


class StreamChunkCount(unittest.TestCase):
    def test_at_boundary_accepted(self):
        r = V.validate_stream_chunk_count(V.MAX_STREAM_CHUNKS)
        self.assertTrue(r.valid, r.violations)

    def test_over_boundary_rejected(self):
        r = V.validate_stream_chunk_count(V.MAX_STREAM_CHUNKS + 1)
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["TooManyChunks"])

    def test_negative_count_rejected(self):
        r = V.validate_stream_chunk_count(-1)
        self.assertFalse(r.valid)
        self.assertEqual(r.errors(), ["Malformed"])


class MultipleViolationsCollected(unittest.TestCase):
    """validate() collects, it does not fail-fast (module docstring) -- confirm two
    independent, simultaneous violations both surface in one call."""

    def test_unknown_kind_and_too_many_causes_both_reported(self):
        r = V.validate(_obj(0x0000, 99, 0, causes=[b"c"] * (V.MAX_CAUSES + 1)))
        self.assertFalse(r.valid)
        self.assertEqual(set(r.errors()), {"UnknownKind", "TooManyCauses"})


if __name__ == "__main__":
    unittest.main()
