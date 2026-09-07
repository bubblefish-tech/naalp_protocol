# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# Manufacturing Add-ons Component F, naalp-hazard KAT for the Ruby SDK, graded against the shared
# independent corpus vectors/hazard/cases.json (NOT produced by this code, frozen 2026-09-01):
# the F2 fail-closed hazard-class decode, byte-exact claim/authorization/envelope encoding
# (including the unicode_frame and negative_only_axis edge cases), the F3 grant-coverage
# containment matrix (both allow and deny rows), the F2/F4 absent-claim distinct-error behaviour,
# and structural malformation rejection.
#
# Mirrors impl/rust/naalp-hazard/src/lib.rs (the frozen reference), impl/csharp/Hazard.cs and
# impl/java/.../Hazard.java.
#
# Run:  ruby -Ilib -Itest test/test_hazard.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def hazard_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "hazard", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/hazard/cases.json not found"
end

def hbe(hex)
  [hex].pack("H*")
end

class HazardKatTest < Minitest::Test
  C = hazard_vectors

  def env_from(o)
    axes = o["axes"].map { |a| [a[0], a[1]] }
    sb = Naalp::Hazard::SpatialBounds.new(o["frame"], axes)
    win = Naalp::Hazard::HazardWindow.new(o["not_before"], o["not_after"])
    Naalp::Hazard::HazardEnvelope.new(sb, o["speed_bound_mm_s"], win)
  end

  # ---- F2: fail-closed class decode (mutation anchor: a constant NONE return would pass none
  # of the non-zero cases; a constant MOTION_IN_SHARED_SPACE would fail the exact 0..3 cases). --
  def test_from_code_fail_closed_matches_oracle
    C["from_code"].each do |row|
      input = row["code"]
      want = row["class"]
      assert_equal want, Naalp::Hazard.from_code(input), "from_code(#{input.inspect})"
    end
    # Explicit oracle-independent assertions of the two named fail-closed cases (F2).
    assert_equal Naalp::Hazard::MOTION_IN_SHARED_SPACE, Naalp::Hazard.from_code(nil),
                 "absent must normalize to the highest class"
    assert_equal Naalp::Hazard::MOTION_IN_SHARED_SPACE, Naalp::Hazard.from_code(9),
                 "unknown code must normalize to the highest class"
    assert_equal Naalp::Hazard::MOTION_IN_SHARED_SPACE, Naalp::Hazard.from_code(2**64),
                 "an out-of-range code must still normalize, never raise"
    # The five in-range codes decode to themselves, never collapsing to the default.
    (0..4).each { |code| assert_equal code, Naalp::Hazard.from_code(code) }
  end

  # ---- byte-level: encode matches the independent oracle (Ruby == Rust == oracle). ------------
  def test_claim_and_authorization_bytes_match_oracle
    C["bodies"].each do |row|
      cls = Naalp::Hazard.from_code(row["class"])
      e = env_from(row)
      claim = Naalp::Hazard::HazardClaim.new(cls, e)
      auth = Naalp::Hazard::HazardAuthorization.new(cls, e)
      want = row["body_hex"]
      assert_equal want, claim.bytes.unpack1("H*"), "claim #{row['name']}"
      assert_equal want, auth.bytes.unpack1("H*"), "authorization #{row['name']} (same shape as claim)"
      assert_equal row["content_id_hex"], claim.content_id.unpack1("H*"), "claim #{row['name']} content-id"
    end
  end

  # Round-trip: from_value(to_value(x)) == x for every oracle body.
  def test_round_trip_matches_oracle
    C["bodies"].each do |row|
      e = env_from(row)
      claim = Naalp::Hazard::HazardClaim.new(Naalp::Hazard.from_code(row["class"]), e)
      got = Naalp::Hazard.hazard_claim_from_value(claim.to_value)
      assert_equal claim.hazard_class, got.hazard_class, "round-trip #{row['name']}"
      assert_equal claim.envelope.spatial.frame, got.envelope.spatial.frame, "round-trip #{row['name']}"
      assert_equal claim.envelope.spatial.axes, got.envelope.spatial.axes, "round-trip #{row['name']}"
      assert_equal claim.envelope.speed_bound_mm_s, got.envelope.speed_bound_mm_s, "round-trip #{row['name']}"
      assert_equal claim.envelope.window.not_before, got.envelope.window.not_before, "round-trip #{row['name']}"
      assert_equal claim.envelope.window.not_after, got.envelope.window.not_after, "round-trip #{row['name']}"
    end
  end

  # ---- F3: coverage matrix (mutation anchor: a constant "always allow" would pass none of the
  # deny rows; a constant "always deny" would fail all the allow rows). -------------------------
  def test_coverage_matches_oracle
    rows = C["coverage"]
    refute_empty rows
    allows = 0
    denies = 0
    rows.each do |row|
      claim = Naalp::Hazard::HazardClaim.new(
        Naalp::Hazard.from_code(row["claim_class_code"]), env_from(row["claim_envelope"]))
      grant = Naalp::Hazard::HazardAuthorization.new(
        Naalp::Hazard.from_code(row["grant_class_code"]), env_from(row["grant_envelope"]))
      want_ok = row["authorized"]
      if want_ok
        allows += 1
        begin
          Naalp::Hazard.hazard_authorized(claim, grant) # no raise
        rescue StandardError => e
          flunk "#{row['name']}: want authorized, got #{e.class}: #{e.message}"
        end
      else
        denies += 1
        err = assert_raises(Naalp::Hazard::HazardNotCovered) { Naalp::Hazard.hazard_authorized(claim, grant) }
        assert_equal "HazardNotCovered", err.kind, row["name"]
      end
    end
    assert allows > 0 && denies > 0, "matrix needs both allows and denies"
  end

  # F2/F4's "absent hazard" behavioural vector, at the OBJECT level (no claim at all): distinct
  # from an in-range-but-mismatched class, and distinct from an unrecognized class byte inside a
  # present claim (covered by test_coverage_matches_oracle's normalized rows).
  def test_absent_claim_denies_with_distinct_error
    grant = Naalp::Hazard::HazardAuthorization.new(
      Naalp::Hazard::TOOL_ACTUATION,
      env_from({ "frame" => "cell-7/world", "axes" => [[0, 1000], [0, 1000], [0, 500]], "speed_bound_mm_s" => 500, "not_before" => 0, "not_after" => 1000 }))
    err = assert_raises(Naalp::Hazard::HazardUnknown) { Naalp::Hazard.hazard_authorized_optional(nil, grant) }
    assert_equal "HazardUnknown", err.kind

    # A present, well-covered claim still authorizes through the same entry point.
    claim = Naalp::Hazard::HazardClaim.new(
      Naalp::Hazard::TOOL_ACTUATION,
      env_from({ "frame" => "cell-7/world", "axes" => [[100, 200], [100, 200], [0, 100]], "speed_bound_mm_s" => 100, "not_before" => 10, "not_after" => 900 }))
    Naalp::Hazard.hazard_authorized_optional(claim, grant) # no raise
  end

  # ---- structural malformation (fail-closed, never partially valid) -----------------------
  def test_malformed_bodies_rejected
    # empty axes
    bad = Naalp::Hazard::SpatialBounds.new("f", [])
    refute bad.well_formed?
    err = assert_raises(Naalp::Hazard::HazardMalformed) { Naalp::Hazard.spatial_bounds_from_value(bad.to_value) }
    assert_equal "HazardMalformed", err.kind

    # min > max
    bad2 = Naalp::Hazard::SpatialBounds.new("f", [[10, -10]])
    refute bad2.well_formed?

    # non-NFC frame ('e' + combining acute, NFD not NFC)
    bad3 = Naalp::Hazard::SpatialBounds.new("é", [[0, 1]])
    refute bad3.well_formed?

    # wrong shape entirely (not a map)
    err2 = assert_raises(Naalp::Hazard::HazardMalformed) { Naalp::Hazard.hazard_claim_from_value(Naalp::CBOR::U.new(0)) }
    assert_equal "HazardMalformed", err2.kind

    # class present, envelope missing
    partial = Naalp::CBOR::M.new([[Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(1)]])
    err3 = assert_raises(Naalp::Hazard::HazardMalformed) { Naalp::Hazard.hazard_claim_from_value(partial) }
    assert_equal "HazardMalformed", err3.kind

    # an explicit out-of-range class ON THE WIRE (not "absent") is malformed, not silently
    # normalized -- see hazard_body_from_value's doc comment.
    good_env = env_from({ "frame" => "f", "axes" => [[0, 1]], "speed_bound_mm_s" => 1, "not_before" => 0, "not_after" => 1 }).to_value
    out_of_range = Naalp::CBOR::M.new([
      [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(99)],
      [Naalp::CBOR::U.new(2), good_env],
    ])
    err4 = assert_raises(Naalp::Hazard::HazardMalformed) { Naalp::Hazard.hazard_claim_from_value(out_of_range) }
    assert_equal "HazardMalformed", err4.kind
  end

  # ---- containment truth table (independent of the oracle file, direct assertions) ------
  def test_spatial_contained_truth_table
    grant = Naalp::Hazard::SpatialBounds.new("f", [[0, 100], [0, 100]])
    inside = Naalp::Hazard::SpatialBounds.new("f", [[10, 90], [10, 90]])
    assert Naalp::Hazard.spatial_contained(inside, grant)
    equal = Naalp::Hazard::SpatialBounds.new("f", [[0, 100], [0, 100]])
    assert Naalp::Hazard.spatial_contained(equal, grant)
    outside = Naalp::Hazard::SpatialBounds.new("f", [[10, 90], [10, 101]])
    refute Naalp::Hazard.spatial_contained(outside, grant)
    wrong_frame = Naalp::Hazard::SpatialBounds.new("g", [[10, 90], [10, 90]])
    refute Naalp::Hazard.spatial_contained(wrong_frame, grant)
    fewer = Naalp::Hazard::SpatialBounds.new("f", [[10, 90]])
    refute Naalp::Hazard.spatial_contained(fewer, grant)
  end

  def test_envelope_contained_window_and_speed
    mk = ->(axes, speed, w) { env_from({ "frame" => "f", "axes" => axes, "speed_bound_mm_s" => speed, "not_before" => w[0], "not_after" => w[1] }) }
    grant = mk.call([[0, 100]], 500, [100, 900])
    ok = mk.call([[0, 100]], 500, [100, 900]) # exact edges, closed interval
    assert Naalp::Hazard.envelope_contained(ok, grant)
    speed_over = mk.call([[0, 100]], 501, [100, 900])
    refute Naalp::Hazard.envelope_contained(speed_over, grant)
    starts_early = mk.call([[0, 100]], 500, [99, 900])
    refute Naalp::Hazard.envelope_contained(starts_early, grant)
    ends_late = mk.call([[0, 100]], 500, [100, 901])
    refute Naalp::Hazard.envelope_contained(ends_late, grant)
  end
end
