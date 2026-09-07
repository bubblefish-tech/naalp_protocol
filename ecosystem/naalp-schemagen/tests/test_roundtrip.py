# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Tests for naalp_schemagen.roundtrip: JSON-Schema -> object -> E0.3 codec -> E0.2 validator.

Non-circularity: byte-consistency is proven via naalp_codec.verify_roundtrip (the REAL E0.3
codec's own determinism proof, not a check invented here), and envelope-level semantic
correctness is proven via naalp_validator.validate (the REAL E0.2 validator, not a check
invented here). This test file supplies only the JSON Schema, the instance, and the
(kind, channel, effect) triple -- exactly what a caller of round_trip() must supply.

Run:  python -m pytest -v tests/test_roundtrip.py
      (from ecosystem/naalp-schemagen/, with PYTHONDONTWRITEBYTECODE=1; on a Windows
      checkout where a bare "python" resolves to a Store stub, invoke the real interpreter
      by its own full path instead.)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _fixtures as F  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from naalp_schemagen import generator as G  # noqa: E402
from naalp_schemagen import jsonschema_core as J  # noqa: E402
from naalp_schemagen import roundtrip as R  # noqa: E402


class SchemaARoundTrip(unittest.TestCase):
    """Schema A: read_only Control/Hello (channel 0x0000, kind 0, effect 0). No audience
    involved -- proves the plain, non-effecting path."""

    def test_conforming_instance_round_trips_byte_consistently_and_validates(self):
        rt = R.round_trip(
            F.SCHEMA_TASK_NOTE, F.INSTANCE_TASK_NOTE,
            kind=0, channel=0x0000, effect=0, signer=F.SIGNER, created=F.CREATED,
        )
        self.assertTrue(rt.byte_consistent)
        self.assertTrue(rt.validation.valid, rt.validation.violations)
        self.assertTrue(rt.valid)
        self.assertEqual(rt.object.audience, "")

    def test_body_actually_reflects_the_instance_not_a_constant(self):
        rt = R.round_trip(
            F.SCHEMA_TASK_NOTE, F.INSTANCE_TASK_NOTE,
            kind=0, channel=0x0000, effect=0, signer=F.SIGNER, created=F.CREATED,
        )
        keys = {k.v for k, _ in rt.object.body.pairs}
        self.assertEqual(keys, {"task_id", "priority", "tags"})
        values = {k.v: v for k, v in rt.object.body.pairs}
        self.assertEqual(values["task_id"].v, "abc123")
        self.assertEqual(values["priority"].v, 7)

    def test_a_second_conforming_instance_produces_different_bytes(self):
        rt1 = R.round_trip(
            F.SCHEMA_TASK_NOTE, F.INSTANCE_TASK_NOTE,
            kind=0, channel=0x0000, effect=0, signer=F.SIGNER, created=F.CREATED,
        )
        other_instance = {"task_id": "zzz999", "priority": 1, "tags": []}
        rt2 = R.round_trip(
            F.SCHEMA_TASK_NOTE, other_instance,
            kind=0, channel=0x0000, effect=0, signer=F.SIGNER, created=F.CREATED,
        )
        self.assertNotEqual(rt1.body_bytes, rt2.body_bytes)

    def test_schema_violating_instance_is_rejected_by_the_generated_validator(self):
        validator = G.generate_validator(F.SCHEMA_TASK_NOTE)
        outcome = validator.validate(F.INSTANCE_TASK_NOTE_BAD)
        self.assertFalse(outcome.valid)
        self.assertTrue(any("maximum" in v.message for v in outcome.violations))


class SchemaBRoundTrip(unittest.TestCase):
    """Schema B: effecting Governance/Consume (channel 0x0004, kind 3, effect
    non_idempotent_write=2), the one baseline consume-once kind (design.md sec.2.5.3;
    naalp_validator.CONSUME_ONCE_KINDS). Proves the audience-lifting path end to end."""

    def test_conforming_instance_round_trips_and_lifts_audience_to_the_envelope(self):
        rt = R.round_trip(
            F.SCHEMA_CONSUME_REQUEST, F.INSTANCE_CONSUME_REQUEST,
            kind=3, channel=0x0004, effect=2, signer=F.SIGNER, created=F.CREATED,
        )
        self.assertTrue(rt.byte_consistent)
        self.assertTrue(rt.validation.valid, rt.validation.violations)
        self.assertTrue(rt.valid)
        self.assertEqual(rt.object.audience, "ledger-authority-7")

    def test_audience_is_not_duplicated_inside_the_body(self):
        rt = R.round_trip(
            F.SCHEMA_CONSUME_REQUEST, F.INSTANCE_CONSUME_REQUEST,
            kind=3, channel=0x0004, effect=2, signer=F.SIGNER, created=F.CREATED,
        )
        keys = {k.v for k, _ in rt.object.body.pairs}
        self.assertEqual(keys, {"resource_id", "quantity"})
        self.assertNotIn("audience", keys)

    def test_schema_violating_instance_is_rejected_before_any_wire_attempt(self):
        validator = G.generate_validator(F.SCHEMA_CONSUME_REQUEST)
        outcome = validator.validate(F.INSTANCE_CONSUME_REQUEST_BAD)
        self.assertFalse(outcome.valid)
        self.assertTrue(any("maximum" in v.message for v in outcome.violations))

    def test_defense_in_depth_missing_audience_rejected_by_the_real_envelope_validator(self):
        # Even if a schema author forgets the reserved 'audience' property (the generator
        # warns on exactly this, see test_generator.py), the REAL E0.2 semantic validator
        # independently refuses the resulting consume-once object at the envelope layer.
        rt = R.round_trip(
            F.SCHEMA_EFFECTING_NO_AUDIENCE, F.INSTANCE_EFFECTING_NO_AUDIENCE,
            kind=3, channel=0x0004, effect=2, signer=F.SIGNER, created=F.CREATED,
        )
        self.assertFalse(rt.valid)
        self.assertFalse(rt.validation.valid)
        self.assertEqual(rt.validation.errors(), ["WrongAudience"])


class UnrepresentableTypesRefused(unittest.TestCase):
    def test_boolean_instance_refused(self):
        with self.assertRaises(R.NaalpUnrepresentable):
            R.build_cbor_value({"type": "boolean"}, True)

    def test_null_instance_refused(self):
        with self.assertRaises(R.NaalpUnrepresentable):
            R.build_cbor_value({"type": "null"}, None)

    def test_number_type_refused_even_for_a_whole_value(self):
        with self.assertRaises(R.NaalpUnrepresentable):
            R.build_cbor_value({"type": "number"}, 3.0)

    def test_type_mismatch_refused(self):
        with self.assertRaises(R.NaalpUnrepresentable):
            R.build_cbor_value({"type": "string"}, 5)


if __name__ == "__main__":
    unittest.main()
