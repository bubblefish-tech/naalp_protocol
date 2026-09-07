# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Tests for naalp_schemagen.prompts: the LLM prompt-template pack (R10 item 5) is real and
usable, not placeholder text -- every template mentions the specific N-AALP vocabulary it
must teach an LLM to use correctly.

Run:  python -m pytest -v tests/test_prompts.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from naalp_schemagen import prompts as P  # noqa: E402


class PromptPackIsReal(unittest.TestCase):
    def test_at_least_three_templates_exist(self):
        names = P.list_prompts()
        self.assertGreaterEqual(len(names), 3)

    def test_unknown_prompt_raises_and_names_the_available_ones(self):
        with self.assertRaises(FileNotFoundError) as ctx:
            P.load_prompt("does-not-exist")
        for name in P.list_prompts():
            self.assertIn(name, str(ctx.exception))

    def test_object_body_schema_template_teaches_the_forbidden_types(self):
        text = P.load_prompt("object_body_schema")
        self.assertIn("x-naalp-effect", text)
        self.assertIn("maxLength", text)
        self.assertIn("maxItems", text)
        self.assertIn("maximum", text)
        self.assertIn('"number"', text)
        self.assertIn('"boolean"', text)
        self.assertIn('"null"', text)
        self.assertGreater(len(text), 500)  # a real template, not a stub sentence

    def test_effecting_kind_audience_template_teaches_the_audience_rule(self):
        text = P.load_prompt("effecting_kind_audience")
        self.assertIn("audience", text)
        self.assertIn("x-naalp-effect", text)
        self.assertIn("EffectingWithoutAudience", text)
        self.assertGreater(len(text), 500)

    def test_bounded_constraints_template_teaches_all_three_bounds(self):
        text = P.load_prompt("bounded_constraints")
        self.assertIn("maxLength", text)
        self.assertIn("maxItems", text)
        self.assertIn("maximum", text)
        self.assertIn("Unbounded", text)
        self.assertGreater(len(text), 500)

    def test_every_listed_template_file_is_actually_loadable(self):
        for name in P.list_prompts():
            text = P.load_prompt(name)
            self.assertGreater(len(text.strip()), 0)


if __name__ == "__main__":
    unittest.main()
