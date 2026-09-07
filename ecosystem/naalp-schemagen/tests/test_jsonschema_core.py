# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Tests for naalp_schemagen.jsonschema_core: the hand-rolled JSON-Schema 2020-12 core-subset
instance validator.

Run:  python -m pytest -v tests/test_jsonschema_core.py
      (from ecosystem/naalp-schemagen/, with PYTHONDONTWRITEBYTECODE=1; on a Windows
      checkout where a bare "python" resolves to a Store stub, invoke the real interpreter
      by its own full path instead.)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from naalp_schemagen import jsonschema_core as J  # noqa: E402


class AcceptValidInstances(unittest.TestCase):
    def test_nested_object_array_string_integer(self):
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 8},
                "scores": {"type": "array", "items": {"type": "integer", "maximum": 10}, "maxItems": 3},
            },
            "required": ["name"],
            "additionalProperties": False,
        }
        outcome = J.validate_instance(schema, {"name": "abc", "scores": [1, 2, 3]})
        self.assertTrue(outcome.valid, outcome.violations)

    def test_enum_accepts_a_member(self):
        outcome = J.validate_instance({"enum": ["a", "b"]}, "a")
        self.assertTrue(outcome.valid)

    def test_const_accepts_the_exact_value(self):
        outcome = J.validate_instance({"const": 7}, 7)
        self.assertTrue(outcome.valid)

    def test_union_type_accepts_either_branch(self):
        schema = {"type": ["string", "integer"]}
        self.assertTrue(J.validate_instance(schema, "x").valid)
        self.assertTrue(J.validate_instance(schema, 5).valid)

    def test_pattern_accepts_a_matching_string(self):
        outcome = J.validate_instance({"type": "string", "pattern": r"^[a-z]+$"}, "abc")
        self.assertTrue(outcome.valid)


class RejectMissingRequired(unittest.TestCase):
    def test_missing_required_property_is_a_violation(self):
        schema = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}
        outcome = J.validate_instance(schema, {})
        self.assertFalse(outcome.valid)
        self.assertIn("missing required property 'a'", outcome.violations[0].message)


class RejectAdditionalProperties(unittest.TestCase):
    def test_extra_key_rejected_when_closed(self):
        schema = {"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": False}
        outcome = J.validate_instance(schema, {"a": "x", "b": "y"})
        self.assertFalse(outcome.valid)

    def test_extra_key_accepted_when_open_by_default(self):
        schema = {"type": "object", "properties": {"a": {"type": "string"}}}
        outcome = J.validate_instance(schema, {"a": "x", "b": "y"})
        self.assertTrue(outcome.valid)


class RejectWrongType(unittest.TestCase):
    def test_string_schema_rejects_an_integer_instance(self):
        outcome = J.validate_instance({"type": "string"}, 5)
        self.assertFalse(outcome.valid)

    def test_union_type_rejects_a_non_member_type(self):
        outcome = J.validate_instance({"type": ["string", "integer"]}, [1, 2])
        self.assertFalse(outcome.valid)

    def test_bool_is_not_accepted_as_integer(self):
        # Python's bool is an int subclass; JSON Schema treats them as distinct types.
        outcome = J.validate_instance({"type": "integer"}, True)
        self.assertFalse(outcome.valid)


class RejectOutOfBounds(unittest.TestCase):
    def test_string_too_long(self):
        outcome = J.validate_instance({"type": "string", "maxLength": 3}, "abcd")
        self.assertFalse(outcome.valid)

    def test_string_too_short(self):
        outcome = J.validate_instance({"type": "string", "minLength": 3}, "ab")
        self.assertFalse(outcome.valid)

    def test_array_too_many_items(self):
        outcome = J.validate_instance({"type": "array", "maxItems": 2}, [1, 2, 3])
        self.assertFalse(outcome.valid)

    def test_array_too_few_items(self):
        outcome = J.validate_instance({"type": "array", "minItems": 2}, [1])
        self.assertFalse(outcome.valid)

    def test_integer_over_maximum(self):
        outcome = J.validate_instance({"type": "integer", "maximum": 10}, 11)
        self.assertFalse(outcome.valid)

    def test_integer_under_minimum(self):
        outcome = J.validate_instance({"type": "integer", "minimum": 0}, -1)
        self.assertFalse(outcome.valid)

    def test_exclusive_maximum_rejects_the_boundary_value(self):
        outcome = J.validate_instance({"type": "integer", "exclusiveMaximum": 10}, 10)
        self.assertFalse(outcome.valid)

    def test_exclusive_minimum_rejects_the_boundary_value(self):
        outcome = J.validate_instance({"type": "integer", "exclusiveMinimum": 0}, 0)
        self.assertFalse(outcome.valid)

    def test_pattern_rejects_a_non_matching_string(self):
        outcome = J.validate_instance({"type": "string", "pattern": r"^[a-z]+$"}, "ABC")
        self.assertFalse(outcome.valid)

    def test_enum_rejects_a_non_member(self):
        outcome = J.validate_instance({"enum": ["a", "b"]}, "c")
        self.assertFalse(outcome.valid)

    def test_const_rejects_a_different_value(self):
        outcome = J.validate_instance({"const": 7}, 8)
        self.assertFalse(outcome.valid)


class CollectAllViolations(unittest.TestCase):
    """Mirrors naalp_validator's own 'COLLECT, don't fail-fast' discipline."""

    def test_multiple_violations_reported_together(self):
        schema = {
            "type": "object",
            "properties": {
                "a": {"type": "string", "maxLength": 2},
                "b": {"type": "integer", "maximum": 5},
            },
            "required": ["a", "c"],
            "additionalProperties": False,
        }
        outcome = J.validate_instance(schema, {"a": "toolong", "b": 99, "d": 1})
        self.assertFalse(outcome.valid)
        messages = " | ".join(v.message for v in outcome.violations)
        self.assertIn("missing required property 'c'", messages)
        self.assertIn("maxLength", messages)
        self.assertIn("maximum", messages)
        self.assertIn("unexpected additional property 'd'", messages)
        self.assertGreaterEqual(len(outcome.violations), 4)


class SchemaMalformedRaisesSchemaError(unittest.TestCase):
    def test_non_dict_schema_raises(self):
        with self.assertRaises(J.SchemaError):
            J.validate_instance("not-a-schema", 1)

    def test_bad_type_keyword_raises(self):
        with self.assertRaises(J.SchemaError):
            J.validate_instance({"type": "not-a-real-type"}, 1)

    def test_required_entry_not_a_string_raises(self):
        with self.assertRaises(J.SchemaError):
            J.validate_instance({"type": "object", "required": [1]}, {})


if __name__ == "__main__":
    unittest.main()
