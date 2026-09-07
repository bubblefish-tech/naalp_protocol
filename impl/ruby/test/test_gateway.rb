# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C21 gateway-decision conformance for the Ruby SDK (design.md §24; R-GW-1..6), graded against
# the shared independent corpus vectors/gateway/cases.json (NOT produced by this code). A
# GatewayDecision {1:decision,2:action,3:policy,4:effect} is a signed decision an enforcement
# gateway of any vendor emits as portable evidence: its authority is the signature over the bytes,
# so it verifies offline and re-verifies IDENTICALLY when served by a party other than the gateway.
# The tests grade the deterministic body/head/content-id byte-for-byte, the closed decision set,
# the strict-decoder rejections (non-canonical / absent field / sibling look-alike), and the
# third-party re-serve property. Written test-first; the module is absent until ported, so this
# fails RED on require until impl/ruby/lib/naalp/gateway.rb lands, and forcing the decision field
# to a constant flips test_byte_parity_against_oracle.
#
# Run:  ruby -Ilib -Itest test/test_gateway.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def gateway_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "gateway", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/gateway/cases.json not found"
end

def hb(hex)
  [hex].pack("H*")
end

class GatewayConformance < Minitest::Test
  C = gateway_vectors

  def dec_from(dv)
    Naalp::Gateway::GatewayDecision.new(dv["decision"], hb(dv["action_hex"]), hb(dv["policy_hex"]), dv["effect"])
  end

  # Ruby encoding == the non-circular Python oracle, byte-for-byte, for every gateway decision
  # body/head/id. A mutation to any Bytes() field (key, value, tag) flips a *_hex assertion.
  def test_byte_parity_against_oracle
    %w[allow deny hold].each do |name|
      dv = C["decisions"][name]
      d = dec_from(dv)
      assert_equal dv["body_hex"], d.bytes.unpack1("H*"), "#{name} body bytes"
      assert_equal dv["head_hex"], d.head.unpack1("H*"), "#{name} head (SHA-384)"
      assert_equal dv["id_hex"], d.id.unpack1("H*"), "#{name} content-id"
    end
  end

  def test_decision_vocabulary_closed_set
    C["decision_vocabulary"].each do |e|
      assert Naalp::Gateway.known_decision?(e["code"]), "#{e['name']} (code #{e['code']}) must be known"
      assert_equal e["name"], Naalp::Gateway.decision_name(e["code"])
    end
    refute Naalp::Gateway.known_decision?(C["unknown_decision"]),
           "unknown decision #{C['unknown_decision']} must not be known"
    assert_equal "unknown", Naalp::Gateway.decision_name(C["unknown_decision"])
  end

  # Edge case #1: a body with top-level keys DESCENDING (4,3,2,1) is rejected NonCanonical by the
  # strict shared decoder; the canonical body parses.
  def test_keys_out_of_order_rejected
    e = C["edge_cases"]["keys_out_of_order"]
    d = Naalp::Gateway::GatewayDecision.new(e["decision"], hb(e["action_hex"]), hb(e["policy_hex"]), e["effect"])
    assert_equal e["canonical_body_hex"], d.bytes.unpack1("H*"), "canonical decision body"
    assert Naalp::Gateway.parse_decision(hb(e["canonical_body_hex"])), "canonical body should parse"
    assert_raises(Naalp::CBOR::NonCanonical) { Naalp::CBOR.decode(hb(e["noncanonical_body_hex"])) }
    err = assert_raises(Naalp::Gateway::GwMalformed) { Naalp::Gateway.parse_decision(hb(e["noncanonical_body_hex"])) }
    assert_equal "GwMalformed", err.kind
  end

  # Edge case #2: an empty policy identity is PRESENT and valid and DISTINCT by content-id from a
  # populated one; a body whose policy field is ABSENT is rejected GwMalformed (field 3 mandatory).
  def test_empty_vs_absent_policy
    ea = C["edge_cases"]["empty_vs_absent"]
    empty = Naalp::Gateway::GatewayDecision.new(Naalp::Gateway::DECISION_ALLOW, hb(C["action_cid_hex"]), "".b, 1)
    populated = Naalp::Gateway::GatewayDecision.new(Naalp::Gateway::DECISION_ALLOW, hb(C["action_cid_hex"]), hb(ea["populated_policy"]["policy_hex"]), 1)
    assert_equal ea["empty_policy"]["body_hex"], empty.bytes.unpack1("H*"), "empty-policy body"
    assert_equal ea["populated_policy"]["body_hex"], populated.bytes.unpack1("H*"), "populated-policy body"
    refute_equal empty.id.unpack1("H*"), populated.id.unpack1("H*"), "empty and populated must have distinct ids"
    assert_equal ea["empty_policy"]["id_hex"], empty.id.unpack1("H*"), "empty-policy id"
    assert Naalp::Gateway.parse_decision(empty.bytes)
    assert Naalp::Gateway.parse_decision(populated.bytes)
    err = assert_raises(Naalp::Gateway::GwMalformed) { Naalp::Gateway.parse_decision(hb(ea["absent_field"]["body_hex"])) }
    assert_equal "GwMalformed", err.kind
  end

  # Edge case #4: the smallest valid decision (allow, empty action, empty policy, read_only)
  # encodes to the oracle bytes, has a stable content-id, and round-trips through parse_decision.
  def test_minimal_decision
    m = C["edge_cases"]["minimal"]
    d = Naalp::Gateway::GatewayDecision.new(m["decision"], hb(m["action_hex"]), hb(m["policy_hex"]), m["effect"])
    assert_equal m["body_hex"], d.bytes.unpack1("H*"), "minimal decision body"
    assert_equal m["id_hex"], d.id.unpack1("H*"), "minimal decision id"
    parsed = Naalp::Gateway.parse_decision(d.bytes)
    assert_equal [m["decision"], m["effect"]], [parsed.decision, parsed.effect]
  end

  # Edge case #5: a sibling C21 body (naalp-ui-event {1:bstr,...}) whose field 1 is a bstr where the
  # decision uint is required is rejected GwMalformed.
  def test_look_alike_rejected
    err = assert_raises(Naalp::Gateway::GwMalformed) do
      Naalp::Gateway.parse_decision(hb(C["edge_cases"]["look_alike"]["body_hex"]))
    end
    assert_equal "GwMalformed", err.kind
  end

  # The effect class is normalized fail-closed: an unrecognized value is destructive (R-6.2).
  def test_effect_class_fail_closed
    d = Naalp::Gateway::GatewayDecision.new(Naalp::Gateway::DECISION_DENY, "".b, "".b, 99)
    assert_equal Naalp::Policy::DESTRUCTIVE, d.effect_class
  end

  # C21 checkpoint: a signed decision verifies offline and RE-VERIFIES IDENTICALLY when re-served by
  # a party OTHER than the gateway (authority is the signature over the bytes, not the connection).
  # A foreign key never verifies; an unknown decision code is rejected fail-closed.
  # (Skips loudly where deterministic ML-DSA is unavailable -- never a false green.)
  def test_third_party_reserve
    gw_seed = ("\x51" * 32).b
    foreign_seed = ("\x52" * 32).b
    begin
      gw_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", gw_seed)
      foreign_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", foreign_seed)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    alg = Naalp::COSE::ALG_MLDSA65
    d = dec_from(C["decisions"]["deny"])
    obj = Naalp::Gateway.sign_decision(d, alg, gw_seed)

    by_gateway = Naalp::Gateway.verify_decision(obj, Naalp::COSE::PROFILE_PUBLIC, alg, gw_pk)
    by_third_party = Naalp::Gateway.verify_decision(obj, Naalp::COSE::PROFILE_PUBLIC, alg, gw_pk)
    assert_equal [by_gateway.decision, by_gateway.action, by_gateway.policy, by_gateway.effect],
                 [by_third_party.decision, by_third_party.action, by_third_party.policy, by_third_party.effect],
                 "the re-served decision must resolve identically to the gateway-served one"
    assert_equal Naalp::Gateway::DECISION_DENY, by_third_party.decision
    assert_equal C["action_cid_hex"], by_third_party.action.unpack1("H*"), "resolved action == oracle content-id"

    err = assert_raises(Naalp::Gateway::BadSignature) do
      Naalp::Gateway.verify_decision(obj, Naalp::COSE::PROFILE_PUBLIC, alg, foreign_pk)
    end
    assert_equal "BadSignature", err.kind

    bad = Naalp::Gateway::GatewayDecision.new(C["unknown_decision"], hb(C["action_cid_hex"]), hb(C["policy_hex"]), 0)
    bad_obj = Naalp::Gateway.sign_decision(bad, alg, gw_seed)
    err2 = assert_raises(Naalp::Gateway::UnknownGatewayDecision) do
      Naalp::Gateway.verify_decision(bad_obj, Naalp::COSE::PROFILE_PUBLIC, alg, gw_pk)
    end
    assert_equal "UnknownGatewayDecision", err2.kind
  end
end

# R1 ordering (field 5) + R8 foreign-profile (field 6) conformance, graded against the
# optional_fields{} block of the SAME vectors/gateway/cases.json corpus. Mirrors the
# optional-fields section of impl/go/gateway/gateway_test.go and
# impl/python/tests/test_gateway.py's GatewayOptionalFieldsConformance.
class GatewayOptionalFieldsConformance < Minitest::Test
  C = GatewayConformance::C

  def test_existing_decision_bodies_unchanged
    # NON-REGRESSION: adding optional fields 5/6 must not perturb the pre-existing 4-field
    # decision bodies at all. Pins the allow/deny/hold body_hex values as they stood BEFORE this
    # change, independent of the vector file's own drift.
    pinned_allow = "a401000258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330401"
    pinned_deny = "a401010258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330403"
    pinned_hold = "a401020258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330402"
    assert_equal pinned_allow, C["decisions"]["allow"]["body_hex"]
    assert_equal pinned_deny, C["decisions"]["deny"]["body_hex"]
    assert_equal pinned_hold, C["decisions"]["hold"]["body_hex"]
    C["decisions"].each do |name, dv|
      gd = Naalp::Gateway::GatewayDecision.new(dv["decision"], hb(dv["action_hex"]), hb(dv["policy_hex"]), dv["effect"])
      assert_equal dv["body_hex"], gd.bytes.unpack1("H*"), name
    end
  end

  def test_optional_fields_round_trip
    of = C["optional_fields"]

    wo = of["with_ordering"]
    d = Naalp::Gateway::GatewayDecision.new(
      wo["decision"], hb(wo["action_hex"]), hb(wo["policy_hex"]), wo["effect"],
      ordering: Naalp::Gateway::OrderingDisclosure.new(wo["ordering"]["basis"], boundary: hb(wo["ordering"]["boundary_hex"])))
    assert_equal wo["body_hex"], d.bytes.unpack1("H*")
    assert_equal wo["id_hex"], d.id.unpack1("H*")
    parsed = Naalp::Gateway.parse_decision(hb(wo["body_hex"]))
    refute_nil parsed.ordering
    assert_nil parsed.foreign_profile
    assert_equal wo["ordering"]["basis"], parsed.ordering.basis
    assert_equal hb(wo["ordering"]["boundary_hex"]), parsed.ordering.boundary
    parsed.ordering.validate # no raise

    wf = of["with_foreign_profile"]
    d2 = Naalp::Gateway::GatewayDecision.new(
      wf["decision"], hb(wf["action_hex"]), hb(wf["policy_hex"]), wf["effect"],
      foreign_profile: Naalp::Gateway::ForeignProfilePin.new(wf["foreign_profile"]["id"], wf["foreign_profile"]["revision"]))
    assert_equal wf["body_hex"], d2.bytes.unpack1("H*")
    assert_equal wf["id_hex"], d2.id.unpack1("H*")
    parsed2 = Naalp::Gateway.parse_decision(hb(wf["body_hex"]))
    assert_nil parsed2.ordering
    refute_nil parsed2.foreign_profile
    assert_equal wf["foreign_profile"]["id"], parsed2.foreign_profile.id
    assert_equal wf["foreign_profile"]["revision"], parsed2.foreign_profile.revision
    parsed2.foreign_profile.validate # no raise

    wb = of["with_both"]
    d3 = Naalp::Gateway::GatewayDecision.new(
      wb["decision"], hb(wb["action_hex"]), hb(wb["policy_hex"]), wb["effect"],
      ordering: Naalp::Gateway::OrderingDisclosure.new(
        wb["ordering"]["basis"], mechanism: hb(wb["ordering"]["mechanism_hex"]), relation: hb(wb["ordering"]["relation_hex"])),
      foreign_profile: Naalp::Gateway::ForeignProfilePin.new(wb["foreign_profile"]["id"], wb["foreign_profile"]["revision"]))
    assert_equal wb["body_hex"], d3.bytes.unpack1("H*")
    assert_equal wb["id_hex"], d3.id.unpack1("H*")
    parsed3 = Naalp::Gateway.parse_decision(hb(wb["body_hex"]))
    refute_nil parsed3.ordering
    refute_nil parsed3.foreign_profile
    parsed3.ordering.validate
    parsed3.foreign_profile.validate
    # Full end-to-end: signs and verifies with both optional fields present.
    seed = ("\x71" * 32).b
    alg = Naalp::COSE::ALG_MLDSA65
    begin
      pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    obj = Naalp::Gateway.sign_decision(d3, alg, seed)
    Naalp::Gateway.verify_decision(obj, Naalp::COSE::PROFILE_PUBLIC, alg, pk) # no raise
  end

  def test_foreign_profile_malformed_rejected
    # field 6 present but omits key 2 (revision): parse_decision decodes it structurally fine;
    # verify_decision's ForeignProfilePin#validate rejects the missing revision, proving the
    # semantic check actually runs, not just the structural decode.
    body = hb(C["optional_fields"]["foreign_profile_malformed"]["body_hex"])
    parsed = Naalp::Gateway.parse_decision(body)
    refute_nil parsed.foreign_profile
    err = assert_raises(Naalp::Gateway::ForeignProfileMalformed) { parsed.foreign_profile.validate }
    assert_equal "ForeignProfileMalformed", err.kind

    seed = ("\x72" * 32).b
    alg = Naalp::COSE::ALG_MLDSA65
    begin
      pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    obj = Naalp::COSE.cose_sign1(alg, seed, Naalp::Gateway.gateway_protected_header(alg), body)
    err2 = assert_raises(Naalp::Gateway::ForeignProfileMalformed) { Naalp::Gateway.verify_decision(obj, Naalp::COSE::PROFILE_PUBLIC, alg, pk) }
    assert_equal "ForeignProfileMalformed", err2.kind
  end

  def test_ordering_malformed_rejected
    # field 5 basis=external-mechanism(2) but key 2 (boundary) is ALSO present: verify_decision's
    # OrderingDisclosure#validate rejects it.
    body = hb(C["optional_fields"]["ordering_malformed"]["body_hex"])
    parsed = Naalp::Gateway.parse_decision(body)
    refute_nil parsed.ordering
    err = assert_raises(Naalp::Gateway::OrderingDisclosureMalformed) { parsed.ordering.validate }
    assert_equal "OrderingDisclosureMalformed", err.kind

    seed = ("\x73" * 32).b
    alg = Naalp::COSE::ALG_MLDSA65
    begin
      pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    obj = Naalp::COSE.cose_sign1(alg, seed, Naalp::Gateway.gateway_protected_header(alg), body)
    err2 = assert_raises(Naalp::Gateway::OrderingDisclosureMalformed) { Naalp::Gateway.verify_decision(obj, Naalp::COSE::PROFILE_PUBLIC, alg, pk) }
    assert_equal "OrderingDisclosureMalformed", err2.kind
  end

  def test_foreign_profile_pin_validate
    # Direct unit test of ForeignProfilePin#validate (no oracle vector needed): missing/empty id
    # or revision is rejected; both present and non-empty passes.
    cases = [
      ["both present", Naalp::Gateway::ForeignProfilePin.new("https://example.test/p", "1"), false],
      ["missing id", Naalp::Gateway::ForeignProfilePin.new("", "1"), true],
      ["missing revision", Naalp::Gateway::ForeignProfilePin.new("https://example.test/p", ""), true],
      ["both empty", Naalp::Gateway::ForeignProfilePin.new("", ""), true],
    ]
    cases.each do |name, pin, want_err|
      if want_err
        err = assert_raises(Naalp::Gateway::ForeignProfileMalformed) { pin.validate }
        assert_equal "ForeignProfileMalformed", err.kind
      else
        pin.validate # no raise
      end
    end
  end

  def test_foreign_profile_extra_key_rejected
    # A field-6 map carrying a THIRD key (3) beyond the closed {1,2} set decodes structurally (the
    # extra key does not fail decode) but fails validate (ForeignProfileMalformed), exactly as a
    # missing or empty field does. Hand-built directly (not oracle-driven).
    fp = Naalp::CBOR::M.new([
      [Naalp::CBOR::U.new(1), Naalp::CBOR::T.new("https://example-registry.test/profiles/acme")],
      [Naalp::CBOR::U.new(2), Naalp::CBOR::T.new("2026-01")],
      [Naalp::CBOR::U.new(3), Naalp::CBOR::T.new("unexpected")],
    ])
    m = Naalp::CBOR::M.new([
      [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(Naalp::Gateway::DECISION_ALLOW)],
      [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(hb(C["action_cid_hex"]))],
      [Naalp::CBOR::U.new(3), Naalp::CBOR::B.new(hb(C["policy_hex"]))],
      [Naalp::CBOR::U.new(4), Naalp::CBOR::U.new(1)],
      [Naalp::CBOR::U.new(6), fp],
    ])
    body = Naalp::CBOR.encode(m)
    parsed = Naalp::Gateway.parse_decision(body)
    refute_nil parsed.foreign_profile
    assert_equal "https://example-registry.test/profiles/acme", parsed.foreign_profile.id
    assert_equal "2026-01", parsed.foreign_profile.revision
    err = assert_raises(Naalp::Gateway::ForeignProfileMalformed) { parsed.foreign_profile.validate }
    assert_equal "ForeignProfileMalformed", err.kind
  end
end
