# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance tests for the register-mixed -> tighten-to-strict migration policy (N2.2).

RFC 8594 Sunset value format and RFC 9745 Deprecation value format are exercised against
byte-exact expected strings, not against a re-implementation of `email.utils.formatdate`.

Run (from ecosystem/naalp-mixed-mode/): python -m pytest tests/test_migration.py
"""
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_mixed_mode import STATE_MIXED, STATE_STRICT, MigrationError, MigrationPolicy  # noqa: E402


class MigrationPolicyTests(unittest.TestCase):
    def test_starts_mixed_by_default(self):
        mp = MigrationPolicy(deprecated_since_epoch_seconds=0, sunset_epoch_seconds=0)
        self.assertEqual(mp.state, STATE_MIXED)

    def test_inverted_timestamps_refused_at_construction(self):
        # RFC 9745: "the timestamp given in the Sunset HTTP header field MUST NOT be earlier
        # than the one given in the Deprecation header field."
        with self.assertRaises(MigrationError) as cm:
            MigrationPolicy(deprecated_since_epoch_seconds=2000, sunset_epoch_seconds=1000)
        self.assertEqual(cm.exception.kind, "InvertedTimestamps")

    def test_equal_timestamps_are_permitted(self):
        mp = MigrationPolicy(deprecated_since_epoch_seconds=1000, sunset_epoch_seconds=1000)
        self.assertEqual(mp.state, STATE_MIXED)

    def test_tighten_transitions_mixed_to_strict(self):
        mp = MigrationPolicy(deprecated_since_epoch_seconds=0, sunset_epoch_seconds=0)
        mp.tighten_to_strict()
        self.assertEqual(mp.state, STATE_STRICT)

    def test_tightening_twice_is_refused(self):
        mp = MigrationPolicy(deprecated_since_epoch_seconds=0, sunset_epoch_seconds=0)
        mp.tighten_to_strict()
        with self.assertRaises(MigrationError) as cm:
            mp.tighten_to_strict()
        self.assertEqual(cm.exception.kind, "AlreadyStrict")

    def test_deprecation_header_is_at_unix_timestamp_token(self):
        # RFC 9745 §3: an Item Structured Header Field Date, "@<unix-timestamp>".
        mp = MigrationPolicy(deprecated_since_epoch_seconds=1688169599, sunset_epoch_seconds=1688169599)
        self.assertEqual(mp.deprecation_headers()["Deprecation"], "@1688169599")

    def test_sunset_header_is_imf_fixdate(self):
        # RFC 8594 §3 example value shape: "Sat, 31 Dec 2018 23:59:59 GMT".
        # epoch 1546300799 == 2018-12-31T23:59:59Z.
        mp = MigrationPolicy(deprecated_since_epoch_seconds=0, sunset_epoch_seconds=1546300799)
        self.assertEqual(mp.deprecation_headers()["Sunset"], "Mon, 31 Dec 2018 23:59:59 GMT")

    def test_no_headers_once_tightened_to_strict(self):
        mp = MigrationPolicy(deprecated_since_epoch_seconds=0, sunset_epoch_seconds=0)
        self.assertTrue(mp.deprecation_headers())
        mp.tighten_to_strict()
        self.assertEqual(mp.deprecation_headers(), {})

    def test_unknown_initial_state_refused(self):
        with self.assertRaises(MigrationError) as cm:
            MigrationPolicy(deprecated_since_epoch_seconds=0, sunset_epoch_seconds=0, state="bogus")
        self.assertEqual(cm.exception.kind, "UnknownState")


if __name__ == "__main__":
    unittest.main()
