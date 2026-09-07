# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Manufacturing Add-ons Component F, naalp-hazard KAT for the Python SDK, graded against the
shared independent corpus vectors/hazard/cases.json (NOT produced by this code, frozen
2026-09-01): the F2 fail-closed hazard-class decode (including the >2^32 and >2^63-1
decimal-string oracle inputs), byte-exact claim/authorization/envelope encoding (including the
unicode_frame and negative_only_axis edge cases), the F3 grant-coverage containment matrix (6
allow rows, 9 deny rows), the F2/F4 absent-claim distinct-error behaviour, and structural
malformation rejection.

Mirrors impl/rust/naalp-hazard/src/lib.rs (the frozen reference), impl/csharp/Hazard.cs,
impl/java/.../Hazard.java, impl/kotlin/.../Hazard.kt, impl/php/src/Hazard.php, and
impl/ruby/lib/naalp/hazard.rb.

Run (PYTHONDONTWRITEBYTECODE=1 to avoid a stale-bytecode strand across a mutation/revert
cycle -- a known trap on this codec, see impl/python/RED-EVIDENCE.md):
  python -m unittest -v tests.test_hazard      (from impl/python/)
"""
import json
import os
import unittest

from naalp import hazard
from naalp.cbor import M, U


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "hazard", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/hazard/cases.json not found")


def _code_from_row(v):
    """`code`/`claim_class_code`/`grant_class_code` oracle fields carry a plain JSON int for
    values that fit a JSON-safe range, and a DECIMAL JSON STRING for the >2^63-1 case
    (`from_code`'s `9223372036854775808` row) so no language's JSON decoder ever routes it
    through a float64. Python ints are arbitrary-precision, so `int(str)` is a lossless,
    exact conversion -- never a float touches this value."""
    return int(v) if isinstance(v, str) else v


def _env_from(o):
    axes = [(a[0], a[1]) for a in o["axes"]]
    sb = hazard.SpatialBounds(o["frame"], axes)
    win = hazard.HazardWindow(o["not_before"], o["not_after"])
    return hazard.HazardEnvelope(sb, o["speed_bound_mm_s"], win)


class HazardKatTest(unittest.TestCase):
    C = _vectors()

    # ---- F2: fail-closed class decode (mutation anchor: a constant NONE return would pass
    # none of the non-zero cases; a constant MOTION_IN_SHARED_SPACE would fail the exact 0..3
    # cases). -----------------------------------------------------------------------------
    def test_from_code_fail_closed_matches_oracle(self):
        for row in self.C["from_code"]:
            code = _code_from_row(row["code"])
            want = row["class"]
            self.assertEqual(hazard.from_code(code), want, "from_code(%r)" % (row["code"],))
            self.assertEqual(hazard.class_name(want), row["class_name"])
        # Explicit oracle-independent assertions of the two named fail-closed cases (F2).
        self.assertEqual(
            hazard.from_code(None), hazard.MOTION_IN_SHARED_SPACE,
            "absent must normalize to the highest class")
        self.assertEqual(
            hazard.from_code(9), hazard.MOTION_IN_SHARED_SPACE,
            "unknown code must normalize to the highest class")
        self.assertEqual(
            hazard.from_code(1 << 128), hazard.MOTION_IN_SHARED_SPACE,
            "an out-of-u64-range code must still normalize, never raise")
        # The five in-range codes decode to themselves, never collapsing to the default.
        for code in range(0, 5):
            self.assertEqual(hazard.from_code(code), code)

    # ---- byte-level: encode matches the independent oracle (Python == Rust == oracle). -----
    def test_claim_and_authorization_bytes_match_oracle(self):
        for row in self.C["bodies"]:
            cls = hazard.from_code(row["class"])
            e = _env_from(row)
            claim = hazard.HazardClaim(cls, e)
            auth = hazard.HazardAuthorization(cls, e)
            want = row["body_hex"]
            self.assertEqual(claim.bytes().hex(), want, "claim %s" % row["name"])
            self.assertEqual(
                auth.bytes().hex(), want, "authorization %s (same shape as claim)" % row["name"])
            self.assertEqual(
                claim.content_id().hex(), row["content_id_hex"], "claim %s content-id" % row["name"])
            # The body is {1:class(single-byte, class in 0..4),2:envelope} -- the map head (a2)
            # + key-1 (01) + the single-byte class value + key-2 (02) is a fixed 4-byte/8-hex
            # prefix, so the remainder is exactly the envelope's own independent encoding.
            self.assertEqual(e.bytes().hex(), row["body_hex"][8:], "envelope %s" % row["name"])

    # Round-trip: from_value(to_value(x)) == x for every oracle body.
    def test_round_trip_matches_oracle(self):
        for row in self.C["bodies"]:
            e = _env_from(row)
            claim = hazard.HazardClaim(hazard.from_code(row["class"]), e)
            got = hazard.HazardClaim.from_value(claim.to_value())
            self.assertEqual(got.hazard_class, claim.hazard_class, "round-trip %s" % row["name"])
            self.assertEqual(got.envelope.spatial.frame, claim.envelope.spatial.frame, row["name"])
            self.assertEqual(got.envelope.spatial.axes, claim.envelope.spatial.axes, row["name"])
            self.assertEqual(
                got.envelope.speed_bound_mm_s, claim.envelope.speed_bound_mm_s, row["name"])
            self.assertEqual(got.envelope.window.not_before, claim.envelope.window.not_before, row["name"])
            self.assertEqual(got.envelope.window.not_after, claim.envelope.window.not_after, row["name"])

    # ---- F3: coverage matrix (mutation anchor: a constant "always allow" would pass none of
    # the deny rows; a constant "always deny" would fail all the allow rows). ----------------
    def test_coverage_matches_oracle(self):
        rows = self.C["coverage"]
        self.assertTrue(rows)
        allows, denies = 0, 0
        for row in rows:
            claim = hazard.HazardClaim(
                hazard.from_code(_code_from_row(row["claim_class_code"])), _env_from(row["claim_envelope"]))
            grant = hazard.HazardAuthorization(
                hazard.from_code(_code_from_row(row["grant_class_code"])), _env_from(row["grant_envelope"]))
            want_ok = row["authorized"]
            if want_ok:
                allows += 1
                try:
                    hazard.hazard_authorized(claim, grant)  # no raise
                except hazard.HazardError as e:
                    self.fail("%s: want authorized, got %s: %s" % (row["name"], type(e).__name__, e))
            else:
                denies += 1
                with self.assertRaises(hazard.HazardNotCovered, msg=row["name"]) as cm:
                    hazard.hazard_authorized(claim, grant)
                self.assertEqual(cm.exception.kind, "HazardNotCovered", row["name"])
        self.assertTrue(allows > 0 and denies > 0, "matrix needs both allows and denies")

    # F2/F4's "absent hazard" behavioural vector, at the OBJECT level (no claim at all):
    # distinct from an in-range-but-mismatched class, and distinct from an unrecognized class
    # byte inside a present claim (covered by test_coverage_matches_oracle's normalized rows).
    def test_absent_claim_denies_with_distinct_error(self):
        grant = hazard.HazardAuthorization(
            hazard.TOOL_ACTUATION,
            _env_from({"frame": "cell-7/world", "axes": [[0, 1000], [0, 1000], [0, 500]],
                       "speed_bound_mm_s": 500, "not_before": 0, "not_after": 1000}))
        with self.assertRaises(hazard.HazardUnknown) as cm:
            hazard.hazard_authorized_optional(None, grant)
        self.assertEqual(cm.exception.kind, "HazardUnknown")

        # A present, well-covered claim still authorizes through the same entry point.
        claim = hazard.HazardClaim(
            hazard.TOOL_ACTUATION,
            _env_from({"frame": "cell-7/world", "axes": [[100, 200], [100, 200], [0, 100]],
                       "speed_bound_mm_s": 100, "not_before": 10, "not_after": 900}))
        hazard.hazard_authorized_optional(claim, grant)  # no raise

    # ---- structural malformation (fail-closed, never partially valid) ---------------------
    def test_malformed_bodies_rejected(self):
        # empty axes
        bad = hazard.SpatialBounds("f", [])
        self.assertFalse(bad.is_well_formed())
        with self.assertRaises(hazard.HazardMalformed) as cm:
            hazard.SpatialBounds.from_value(bad.to_value())
        self.assertEqual(cm.exception.kind, "HazardMalformed")

        # min > max
        bad2 = hazard.SpatialBounds("f", [(10, -10)])
        self.assertFalse(bad2.is_well_formed())

        # non-NFC frame ('e' + combining acute, NFD not NFC)
        bad3 = hazard.SpatialBounds("é", [(0, 1)])
        self.assertFalse(bad3.is_well_formed())

        # wrong shape entirely (not a map)
        with self.assertRaises(hazard.HazardMalformed) as cm2:
            hazard.HazardClaim.from_value(U(0))
        self.assertEqual(cm2.exception.kind, "HazardMalformed")

        # class present, envelope missing
        partial = M([(U(1), U(1))])
        with self.assertRaises(hazard.HazardMalformed) as cm3:
            hazard.HazardClaim.from_value(partial)
        self.assertEqual(cm3.exception.kind, "HazardMalformed")

        # an explicit out-of-range class ON THE WIRE (not "absent") is malformed, not silently
        # normalized -- see _body_from_value's doc comment.
        good_env = _env_from(
            {"frame": "f", "axes": [[0, 1]], "speed_bound_mm_s": 1, "not_before": 0, "not_after": 1}).to_value()
        out_of_range = M([(U(1), U(99)), (U(2), good_env)])
        with self.assertRaises(hazard.HazardMalformed) as cm4:
            hazard.HazardClaim.from_value(out_of_range)
        self.assertEqual(cm4.exception.kind, "HazardMalformed")

    # ---- containment truth table (independent of the oracle file, direct assertions) ------
    def test_spatial_contained_truth_table(self):
        grant = hazard.SpatialBounds("f", [(0, 100), (0, 100)])
        # fully inside -> contained
        inside = hazard.SpatialBounds("f", [(10, 90), (10, 90)])
        self.assertTrue(hazard.spatial_contained(inside, grant))
        # equal bounds -> contained (closed interval)
        equal = hazard.SpatialBounds("f", [(0, 100), (0, 100)])
        self.assertTrue(hazard.spatial_contained(equal, grant))
        # one axis pokes outside -> not contained
        outside = hazard.SpatialBounds("f", [(10, 90), (10, 101)])
        self.assertFalse(hazard.spatial_contained(outside, grant))
        # different frame -> never contained regardless of numeric bounds
        wrong_frame = hazard.SpatialBounds("g", [(10, 90), (10, 90)])
        self.assertFalse(hazard.spatial_contained(wrong_frame, grant))
        # fewer axes -> never contained
        fewer = hazard.SpatialBounds("f", [(10, 90)])
        self.assertFalse(hazard.spatial_contained(fewer, grant))

    def test_envelope_contained_window_and_speed(self):
        def mk(axes, speed, w):
            return _env_from({"frame": "f", "axes": axes, "speed_bound_mm_s": speed,
                               "not_before": w[0], "not_after": w[1]})

        grant = mk([[0, 100]], 500, (100, 900))
        ok = mk([[0, 100]], 500, (100, 900))  # exact edges, closed interval
        self.assertTrue(hazard.envelope_contained(ok, grant))
        speed_over = mk([[0, 100]], 501, (100, 900))
        self.assertFalse(hazard.envelope_contained(speed_over, grant))
        starts_early = mk([[0, 100]], 500, (99, 900))
        self.assertFalse(hazard.envelope_contained(starts_early, grant))
        ends_late = mk([[0, 100]], 500, (100, 901))
        self.assertFalse(hazard.envelope_contained(ends_late, grant))


if __name__ == "__main__":
    unittest.main()
