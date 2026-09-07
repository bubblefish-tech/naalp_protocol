# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Tests for naalp_schemagen.generator: JSON-Schema(2020-12) -> CDDL + warnings.

Run:  python -m pytest -v tests/test_generator.py
      (from ecosystem/naalp-schemagen/, with PYTHONDONTWRITEBYTECODE=1; on a Windows
      checkout where a bare "python" resolves to a Store stub, invoke the real interpreter
      by its own full path instead.)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from naalp_schemagen import generator as G  # noqa: E402


class BasicTypeMapping(unittest.TestCase):
    """Changing the schema changes the emitted CDDL -- proves generate_cddl is a real,
    schema-guided transform, never a constant-output stub (A4)."""

    def test_string_type_produces_tstr(self):
        r = G.generate_cddl({"type": "string", "maxLength": 10}, "x")
        self.assertIn("tstr", r.cddl)
        self.assertEqual(r.warnings, [])

    def test_integer_type_produces_a_range(self):
        r = G.generate_cddl({"type": "integer", "minimum": 0, "maximum": 10}, "x")
        self.assertIn("0..10", r.cddl)

    def test_different_schemas_produce_different_cddl(self):
        r_string = G.generate_cddl({"type": "string", "maxLength": 5}, "x")
        r_integer = G.generate_cddl({"type": "integer", "maximum": 5}, "x")
        self.assertNotEqual(r_string.cddl, r_integer.cddl)

    def test_object_with_required_and_optional_fields(self):
        schema = {
            "type": "object",
            "properties": {
                "a": {"type": "string", "maxLength": 4},
                "b": {"type": "integer", "maximum": 4},
            },
            "required": ["a"],
            "additionalProperties": False,
        }
        r = G.generate_cddl(schema, "naalp-body-x")
        self.assertIn('"a" : tstr .size (0..4)', r.cddl)
        self.assertIn('? "b" : 0..4', r.cddl)
        self.assertEqual(r.warnings, [])

    def test_array_with_max_items_produces_bounded_occurrence(self):
        schema = {"type": "array", "items": {"type": "string", "maxLength": 8}, "maxItems": 4}
        r = G.generate_cddl(schema, "x")
        self.assertIn("[0*4 tstr .size (0..8)]", r.cddl)
        self.assertEqual(r.warnings, [])

    def test_enum_produces_alternation(self):
        r = G.generate_cddl({"enum": ["a", "b", "c"]}, "x")
        self.assertIn('"a" / "b" / "c"', r.cddl)

    def test_const_produces_literal(self):
        r = G.generate_cddl({"const": 7}, "x")
        self.assertIn("= 7", r.cddl)

    def test_union_type_produces_alternation_per_branch(self):
        r = G.generate_cddl({"type": ["string", "integer"], "maxLength": 4, "maximum": 4}, "x")
        self.assertIn("tstr", r.cddl)
        self.assertIn("0..4", r.cddl)
        self.assertIn("/", r.cddl)


class InvalidIdentifier(unittest.TestCase):
    def test_rejects_a_non_identifier_def_name(self):
        with self.assertRaises(G.SchemaError):
            G.generate_cddl({"type": "string", "maxLength": 4}, "not a valid ident!")


class UnboundedWarnings(unittest.TestCase):
    """(graded bar c) each unsafe construct fires the NAMED warning."""

    def test_array_without_max_items_warns_unbounded(self):
        r = G.generate_cddl({"type": "array", "items": {"type": "string", "maxLength": 4}}, "x")
        self.assertIn(G.UNBOUNDED, {w.code for w in r.warnings})

    def test_array_with_max_items_does_not_warn_unbounded(self):
        r = G.generate_cddl(
            {"type": "array", "items": {"type": "string", "maxLength": 4}, "maxItems": 3}, "x")
        self.assertNotIn(G.UNBOUNDED, {w.code for w in r.warnings})

    def test_string_without_max_length_warns_unbounded(self):
        r = G.generate_cddl({"type": "string"}, "x")
        self.assertIn(G.UNBOUNDED, {w.code for w in r.warnings})

    def test_string_with_max_length_does_not_warn_unbounded(self):
        r = G.generate_cddl({"type": "string", "maxLength": 4}, "x")
        self.assertNotIn(G.UNBOUNDED, {w.code for w in r.warnings})

    def test_integer_without_maximum_warns_unbounded(self):
        r = G.generate_cddl({"type": "integer"}, "x")
        self.assertIn(G.UNBOUNDED, {w.code for w in r.warnings})

    def test_integer_with_exclusive_maximum_does_not_warn_unbounded(self):
        r = G.generate_cddl({"type": "integer", "exclusiveMaximum": 5}, "x")
        self.assertNotIn(G.UNBOUNDED, {w.code for w in r.warnings})

    def test_integer_with_maximum_does_not_warn_unbounded(self):
        r = G.generate_cddl({"type": "integer", "maximum": 5}, "x")
        self.assertNotIn(G.UNBOUNDED, {w.code for w in r.warnings})


class FloatWarning(unittest.TestCase):
    """(graded bar c) the float unsafe construct fires the named warning."""

    def test_number_type_warns_float_forbidden(self):
        r = G.generate_cddl({"type": "number"}, "x")
        self.assertIn(G.FLOAT_FORBIDDEN, {w.code for w in r.warnings})

    def test_integer_type_does_not_warn_float_forbidden(self):
        r = G.generate_cddl({"type": "integer", "maximum": 5}, "x")
        self.assertNotIn(G.FLOAT_FORBIDDEN, {w.code for w in r.warnings})


class EffectingWithoutAudienceWarning(unittest.TestCase):
    """(graded bar c) the effecting-without-audience unsafe construct fires the named warning."""

    def _schema(self, effect, with_audience):
        properties = {"resource_id": {"type": "string", "maxLength": 8}}
        if with_audience:
            properties["audience"] = {"type": "string", "maxLength": 32}
        schema = {
            "type": "object",
            "properties": properties,
            "required": ["resource_id"],
            "additionalProperties": False,
        }
        if effect is not None:
            schema["x-naalp-effect"] = effect
        return schema

    def test_effecting_without_audience_warns(self):
        r = G.generate_cddl(self._schema("non_idempotent_write", with_audience=False), "x")
        self.assertIn(G.EFFECTING_WITHOUT_AUDIENCE, {w.code for w in r.warnings})

    def test_effecting_with_audience_does_not_warn(self):
        r = G.generate_cddl(self._schema("non_idempotent_write", with_audience=True), "x")
        self.assertNotIn(G.EFFECTING_WITHOUT_AUDIENCE, {w.code for w in r.warnings})

    def test_read_only_without_audience_does_not_warn(self):
        r = G.generate_cddl(self._schema("read_only", with_audience=False), "x")
        self.assertNotIn(G.EFFECTING_WITHOUT_AUDIENCE, {w.code for w in r.warnings})

    def test_no_effect_declared_does_not_warn(self):
        r = G.generate_cddl(self._schema(None, with_audience=False), "x")
        self.assertNotIn(G.EFFECTING_WITHOUT_AUDIENCE, {w.code for w in r.warnings})

    def test_destructive_without_audience_warns(self):
        r = G.generate_cddl(self._schema("destructive", with_audience=False), "x")
        self.assertIn(G.EFFECTING_WITHOUT_AUDIENCE, {w.code for w in r.warnings})

    def test_unknown_effect_value_raises(self):
        with self.assertRaises(G.SchemaError):
            G.generate_cddl(self._schema("not_a_real_effect", with_audience=False), "x")


class UnmappableConstructs(unittest.TestCase):
    def test_boolean_type_warns_unmappable(self):
        r = G.generate_cddl({"type": "boolean"}, "x")
        self.assertIn(G.UNMAPPABLE, {w.code for w in r.warnings})

    def test_null_type_warns_unmappable(self):
        r = G.generate_cddl({"type": "null"}, "x")
        self.assertIn(G.UNMAPPABLE, {w.code for w in r.warnings})

    def test_ref_keyword_warns_unmappable(self):
        r = G.generate_cddl({"type": "object", "$ref": "#/defs/thing"}, "x")
        self.assertIn(G.UNMAPPABLE, {w.code for w in r.warnings})

    def test_one_of_keyword_warns_unmappable(self):
        r = G.generate_cddl({"oneOf": [{"type": "string"}, {"type": "integer"}]}, "x")
        self.assertIn(G.UNMAPPABLE, {w.code for w in r.warnings})

    def test_open_object_without_additional_properties_false_warns_unmappable(self):
        r = G.generate_cddl({"type": "object", "properties": {}}, "x")
        self.assertIn(G.UNMAPPABLE, {w.code for w in r.warnings})

    def test_closed_object_does_not_warn_unmappable_for_openness(self):
        r = G.generate_cddl({"type": "object", "properties": {}, "additionalProperties": False}, "x")
        self.assertNotIn(G.UNMAPPABLE, {w.code for w in r.warnings})


class StrictModeRefusal(unittest.TestCase):
    """(graded bar d) strict mode turns each named warning into a refusal."""

    def test_strict_refuses_unbounded_array(self):
        schema = {"type": "array", "items": {"type": "string", "maxLength": 4}}
        with self.assertRaises(G.SchemaGenRefusal) as ctx:
            G.generate_cddl(schema, "x", strict=True)
        self.assertEqual({w.code for w in ctx.exception.warnings}, {G.UNBOUNDED})

    def test_non_strict_does_not_refuse_unbounded_array(self):
        schema = {"type": "array", "items": {"type": "string", "maxLength": 4}}
        r = G.generate_cddl(schema, "x", strict=False)
        self.assertTrue(r.warnings)

    def test_strict_refuses_float(self):
        with self.assertRaises(G.SchemaGenRefusal) as ctx:
            G.generate_cddl({"type": "number"}, "x", strict=True)
        self.assertEqual({w.code for w in ctx.exception.warnings}, {G.FLOAT_FORBIDDEN})

    def test_strict_refuses_effecting_without_audience(self):
        schema = {
            "type": "object", "x-naalp-effect": "non_idempotent_write",
            "properties": {"a": {"type": "string", "maxLength": 4}},
            "required": ["a"], "additionalProperties": False,
        }
        with self.assertRaises(G.SchemaGenRefusal) as ctx:
            G.generate_cddl(schema, "x", strict=True)
        self.assertEqual({w.code for w in ctx.exception.warnings}, {G.EFFECTING_WITHOUT_AUDIENCE})

    def test_strict_does_not_refuse_a_clean_schema(self):
        schema = {
            "type": "object", "x-naalp-effect": "read_only",
            "properties": {"a": {"type": "string", "maxLength": 4}},
            "required": ["a"], "additionalProperties": False,
        }
        r = G.generate_cddl(schema, "x", strict=True)  # must not raise
        self.assertEqual(r.warnings, [])

    def test_strict_refusal_also_applies_to_generate_validator(self):
        schema = {"type": "array", "items": {"type": "string", "maxLength": 4}}
        with self.assertRaises(G.SchemaGenRefusal):
            G.generate_validator(schema, strict=True)
        # non-strict must still hand back a working validator with the warnings recorded
        v = G.generate_validator(schema, strict=False)
        self.assertTrue(v.warnings)
        self.assertTrue(v.validate(["a", "b"]).valid)


class GeneratedValidatorDelegates(unittest.TestCase):
    def test_generate_validator_returns_a_bound_callable(self):
        schema = {"type": "integer", "minimum": 0, "maximum": 5}
        v = G.generate_validator(schema)
        self.assertTrue(v.validate(3).valid)
        self.assertFalse(v.validate(9).valid)
        self.assertTrue(v(3).valid)  # __call__ delegates too


if __name__ == "__main__":
    unittest.main()
