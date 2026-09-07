# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C5 effect vocabulary and authorization conformance for the Ruby SDK (design.md §6; R-6.1..6.5),
# graded against the shared independent corpus vectors/effect/cases.json (NOT produced by this
# code): the four effect names + Bridge SafetyLabel identity mapping, unknown-value fail-closed
# normalization (R-6.2), the full granted×effect authorization matrix via Grant#authorize_object
# (R-6.3), the principal-source gate -- only a signature-derived identity is ever an authorization
# principal (R-6.5) -- and the optional signed safety label's CBOR bytes plus its
# present/absent/malformed ext-map handling (R-6.4). AuthorizeObject unconditionally returning OK
# (bypassing both the principal check and the ceiling check) is the C5 mutation target: it flips
# test_authorization_matrix and test_principal_source_gate on a denied-row assertion.
#
# Run:  ruby -Ilib -Itest test/test_policy.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def effect_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "effect", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/effect/cases.json not found"
end

SRC_MAP = {
  "signature" => Naalp::Policy::SOURCE_SIGNATURE,
  "transport_metadata" => Naalp::Policy::SOURCE_TRANSPORT_METADATA,
  "foreign_header" => Naalp::Policy::SOURCE_FOREIGN_HEADER,
  "client_name" => Naalp::Policy::SOURCE_CLIENT_NAME,
}.freeze

class PolicyConformance < Minitest::Test
  C = effect_vectors

  # ---- effect names + Bridge SafetyLabel mapping (byte/name parity) ---------------------

  def test_effect_names_and_bridge_match_oracle
    effs = C["effects"]
    assert_equal 4, effs.length
    effs.each do |e|
      assert_equal e["safety_label"], Naalp::Policy.safety_label_name(e["value"]), "effect #{e['value']} name"
    end
    C["bridge_mapping"].each do |m|
      assert_equal m["effect"], Naalp::Policy.normalize_effect(m["npamp_u8"]), "bridge u8 #{m['npamp_u8']}"
    end
  end

  # ---- R-6.2: an unrecognized effect value normalizes fail-closed to destructive --------

  def test_normalize_unknown_is_destructive
    (0..3).each { |v| assert_equal v, Naalp::Policy.normalize_effect(v) }
    unk = C["unknown_normalization"]
    refute_empty unk
    unk.each do |u|
      got = Naalp::Policy.normalize_effect(u["input"])
      assert_equal u["effect"], got, "normalize(#{u['input']})"
      assert_equal Naalp::Policy::DESTRUCTIVE, got, "unknown #{u['input']} must be destructive"
    end
  end

  # ---- R-6.3: the full granted x effect authorization matrix, via Grant#authorize_object --

  def test_authorization_matrix
    rows = C["authorization_matrix"]
    assert_equal 16, rows.length
    allows = 0
    denies = 0
    rows.each do |r|
      g = Naalp::Policy::Grant.new("pA", r["granted"])
      if r["allow"]
        allows += 1
        g.authorize_object(Naalp::Policy::SOURCE_SIGNATURE, "pA", r["effect"])
      else
        denies += 1
        err = assert_raises(Naalp::Policy::PolicyError) do
          g.authorize_object(Naalp::Policy::SOURCE_SIGNATURE, "pA", r["effect"])
        end
        assert_equal "EffectNotAuthorized", err.kind, "granted=#{r['granted']} effect=#{r['effect']}"
      end
      # the raw lattice must agree with the matrix
      assert_equal r["allow"],
                   Naalp::Policy.authorizes(r["granted"], Naalp::Policy.normalize_effect(r["effect"])),
                   "Authorizes(#{r['granted']},#{r['effect']})"
    end
    assert allows > 0 && denies > 0, "matrix must contain both allows and denies (allows=#{allows} denies=#{denies})"
  end

  # ---- R-6.5: only a signature-derived identity is ever an authorization principal ------

  def test_principal_source_gate
    g = Naalp::Policy::Grant.new("pA", Naalp::Policy::DESTRUCTIVE) # maximally permissive ceiling
    C["principal_sources"].each do |ps|
      src = SRC_MAP.fetch(ps["source"]) { flunk "unknown principal source #{ps['source']} in corpus" }

      if ps["accepted"]
        assert_equal "pA", Naalp::Policy.resolve_auth_principal(src, "pA"), ps["source"]
      else
        err = assert_raises(Naalp::Policy::PolicyError) { Naalp::Policy.resolve_auth_principal(src, "pA") }
        assert_equal "UnauthenticatedPrincipal", err.kind, ps["source"]
      end

      # even a read_only object (within the ceiling) is denied from a non-signature source.
      if ps["accepted"]
        g.authorize_object(src, "pA", Naalp::Policy::READ_ONLY)
      else
        err = assert_raises(Naalp::Policy::PolicyError) { g.authorize_object(src, "pA", Naalp::Policy::READ_ONLY) }
        assert_equal "UnauthenticatedPrincipal", err.kind, ps["source"]
      end
    end
  end

  # ---- R-6.4: the safety-label CBOR equals the independently constructed oracle bytes ---

  def test_safety_label_bytes_match_oracle
    sl = C["safety_label"]
    got = Naalp::Policy::SafetyLabel.new(sl["risk"], sl["scope"]).encode
    assert_equal sl["cbor_hex"], got.unpack1("H*")
    # module-level convenience wrapper produces the same bytes
    assert_equal sl["cbor_hex"], Naalp::Policy.safety_label_bytes(sl["risk"], sl["scope"]).unpack1("H*")
  end

  # ---- SafetyLabelFromExt: present / absent / malformed, fail-closed --------------------

  def test_safety_label_from_ext
    sl = C["safety_label"]
    assert_equal sl["ext_key"], Naalp::Policy::SAFETY_LABEL_EXT_KEY

    label = Naalp::Policy::SafetyLabel.new(sl["risk"], sl["scope"])
    got, present = Naalp::Policy.safety_label_from_ext(label.ext)
    assert present
    assert_equal label, got

    # absent: an empty ext map
    got2, present2 = Naalp::Policy.safety_label_from_ext(Naalp::CBOR::M.new([]))
    assert_nil got2
    refute present2

    # absent: a nil ext
    got3, present3 = Naalp::Policy.safety_label_from_ext(nil)
    assert_nil got3
    refute present3

    # malformed: ext[1] present but not a map
    bad = Naalp::CBOR::M.new([[Naalp::CBOR::U.new(Naalp::Policy::SAFETY_LABEL_EXT_KEY), Naalp::CBOR::U.new(9)]])
    err = assert_raises(Naalp::Policy::PolicyError) { Naalp::Policy.safety_label_from_ext(bad) }
    assert_equal "MalformedSafetyLabel", err.kind

    # malformed: ext[1] a map missing the scope field
    bad2 = Naalp::CBOR::M.new([[Naalp::CBOR::U.new(Naalp::Policy::SAFETY_LABEL_EXT_KEY),
                                 Naalp::CBOR::M.new([[Naalp::CBOR::U.new(1), Naalp::CBOR::T.new("x")]])]])
    err2 = assert_raises(Naalp::Policy::PolicyError) { Naalp::Policy.safety_label_from_ext(bad2) }
    assert_equal "MalformedSafetyLabel", err2.kind
  end
end
