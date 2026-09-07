# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# E6.3 naalp-egress-attestation conformance for the Ruby SDK, graded against the shared independent
# corpus vectors/egress_attestation/cases.json (NOT produced by this code): the closed binding
# vocabulary, byte-exact attestation body/head/content-id (including the oversized 2^64-1 counter
# and field-6 ordering-disclosure variants), the content_free commitment open/verify pair, the
# third-party re-serve property (and the vendor-only mutation it must survive), and every named
# edge case (descending-key body, empty-vs-absent audience, minimal, gateway-decision look-alike,
# missing mandatory `at`, ordering-malformed variants).
#
# Mirrors impl/python/tests/test_egress_attestation.py and impl/go/gateway/egress_attestation_test.go.
#
# Run:  ruby -Ilib -Itest test/test_egress_attestation.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def egress_attestation_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "egress_attestation", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/egress_attestation/cases.json not found"
end

def hbe(hex)
  [hex].pack("H*")
end

class EgressAttestationConformance < Minitest::Test
  C = egress_attestation_vectors

  def att_from(av)
    Naalp::Gateway::EgressAttestation.new(av["binding"], hbe(av["digest_hex"]), av["effect"], hbe(av["audience_hex"]), Integer(av["at_str"]))
  end

  def test_byte_parity_against_oracle
    { "content_bound" => C["attestations"]["content_bound"], "content_free" => C["attestations"]["content_free"] }.each do |name, av|
      a = att_from(av)
      assert_equal av["body_hex"], a.bytes.unpack1("H*"), name
      assert_equal av["head_hex"], a.head.unpack1("H*"), name
      assert_equal av["id_hex"], a.id.unpack1("H*"), name
    end
    C["binding_vocabulary"].each do |e|
      assert Naalp::Gateway.known_binding?(e["code"]), e["name"]
      assert_equal e["name"], Naalp::Gateway.binding_name(e["code"])
    end
    refute Naalp::Gateway.known_binding?(C["unknown_binding"])
  end

  def test_oversized_counter
    e = C["edge_cases"]["oversized_counter"]
    assert_equal "18446744073709551615", e["at_str"]
    a = att_from(e)
    assert_equal (1 << 64) - 1, a.at
    assert_equal e["body_hex"], a.bytes.unpack1("H*")
    parsed = Naalp::Gateway.parse_egress_attestation(a.bytes)
    assert_equal a.at, parsed.at
  end

  def test_third_party_reserve
    seed_gw = ("\x61" * 32).b
    seed_foreign = ("\x62" * 32).b
    alg = Naalp::COSE::ALG_MLDSA65
    begin
      gw_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed_gw)
      foreign_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed_foreign)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end

    a = att_from(C["attestations"]["content_bound"])
    obj = Naalp::Gateway.sign_egress_attestation(a, alg, seed_gw)

    by_gateway = Naalp::Gateway.verify_egress_attestation(obj, Naalp::COSE::PROFILE_PUBLIC, alg, gw_pk)
    by_third_party = Naalp::Gateway.verify_egress_attestation(obj.dup, Naalp::COSE::PROFILE_PUBLIC, alg, gw_pk)
    assert_equal by_gateway.binding, by_third_party.binding
    assert_equal by_gateway.digest, by_third_party.digest
    assert_equal by_gateway.effect, by_third_party.effect
    assert_equal by_gateway.audience, by_third_party.audience
    assert_equal by_gateway.at, by_third_party.at
    assert_equal Naalp::Gateway::BINDING_CONTENT_BOUND, by_third_party.binding
    assert_equal C["object_cid_hex"], by_third_party.digest.unpack1("H*")

    err = assert_raises(Naalp::Gateway::BadSignature) do
      Naalp::Gateway.verify_egress_attestation(obj, Naalp::COSE::PROFILE_PUBLIC, alg, foreign_pk)
    end
    assert_equal "BadSignature", err.kind

    bad = Naalp::Gateway::EgressAttestation.new(C["unknown_binding"], hbe(C["object_cid_hex"]), 0, hbe(C["audience_hex"]), 0)
    bad_obj = Naalp::Gateway.sign_egress_attestation(bad, alg, seed_gw)
    err2 = assert_raises(Naalp::Gateway::UnknownEgressBinding) do
      Naalp::Gateway.verify_egress_attestation(bad_obj, Naalp::COSE::PROFILE_PUBLIC, alg, gw_pk)
    end
    assert_equal "UnknownEgressBinding", err2.kind
  end

  def test_vendor_only_mutation
    # Mirrors TestEgressVendorOnlyMutation: the honest verify_egress_attestation takes NO
    # serving-party identity, so a mutant "vendor-only" verifier that additionally requires
    # serving_party == gateway_id wrongly rejects a third party re-serving the identical bytes.
    seed_gw = ("\x61" * 32).b
    alg = Naalp::COSE::ALG_MLDSA65
    begin
      gw_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed_gw)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    gateway_id = "gateway-id-0x61".b
    third_party = "did:example:mirror-cache".b

    a = att_from(C["attestations"]["content_free"])
    obj = Naalp::Gateway.sign_egress_attestation(a, alg, seed_gw)
    Naalp::Gateway.verify_egress_attestation(obj, Naalp::COSE::PROFILE_PUBLIC, alg, gw_pk) # honest: no raise

    mutant_verify = lambda do |obj_, gw_pk_, gateway_id_, serving_party|
      Naalp::Gateway.verify_egress_attestation(obj_, Naalp::COSE::PROFILE_PUBLIC, alg, gw_pk_)
      raise Naalp::Gateway::EgMalformed, "stands in for a not-served-by-vendor rejection" if serving_party != gateway_id_
    end

    mutant_verify.call(obj, gw_pk, gateway_id, gateway_id) # accepts the vendor serving it
    assert_raises(Naalp::Gateway::EgMalformed) { mutant_verify.call(obj, gw_pk, gateway_id, third_party) } # wrongly rejects the third party
  end

  def test_open_egress_commitment
    co = C["commitment_open"]
    a = att_from(C["attestations"]["content_free"])
    assert_equal co["commitment_hex"], a.digest.unpack1("H*")

    object_cid = hbe(co["object_cid_hex"])
    wrong_object_cid = hbe(co["wrong_object_cid_hex"])
    salt = hbe(co["salt_hex"])
    wrong_salt = hbe(co["wrong_salt_hex"])

    assert_equal co["commitment_hex"], Naalp::Gateway.egress_commit(object_cid, salt).unpack1("H*")
    assert Naalp::Gateway.open_egress_commitment(a, object_cid, salt)
    refute Naalp::Gateway.open_egress_commitment(a, object_cid, wrong_salt)
    refute Naalp::Gateway.open_egress_commitment(a, wrong_object_cid, salt)
    refute Naalp::Gateway.open_egress_commitment(a, wrong_object_cid, wrong_salt)

    bound = att_from(C["attestations"]["content_bound"])
    refute Naalp::Gateway.open_egress_commitment(bound, object_cid, salt)
  end

  def test_keys_out_of_order_rejected
    e = C["edge_cases"]["keys_out_of_order"]
    a = Naalp::Gateway::EgressAttestation.new(e["binding"], hbe(e["digest_hex"]), e["effect"], hbe(e["audience_hex"]), Integer(e["at_str"]))
    assert_equal e["canonical_body_hex"], a.bytes.unpack1("H*")
    canon = hbe(e["canonical_body_hex"])
    noncanon = hbe(e["noncanonical_body_hex"])
    Naalp::CBOR.decode(canon) # should decode
    Naalp::Gateway.parse_egress_attestation(canon) # should parse
    assert_raises(Naalp::CBOR::NonCanonical) { Naalp::CBOR.decode(noncanon) }
    err = assert_raises(Naalp::Gateway::EgMalformed) { Naalp::Gateway.parse_egress_attestation(noncanon) }
    assert_equal "EgMalformed", err.kind
  end

  def test_empty_vs_absent_audience
    ea = C["edge_cases"]["empty_vs_absent"]
    object_cid = C["object_cid_hex"]
    empty = Naalp::Gateway::EgressAttestation.new(Naalp::Gateway::BINDING_CONTENT_BOUND, hbe(object_cid), 1, "".b, 1735689600000)
    populated = Naalp::Gateway::EgressAttestation.new(Naalp::Gateway::BINDING_CONTENT_BOUND, hbe(object_cid), 1, hbe(ea["populated_audience"]["audience_hex"]), 1735689600000)
    assert_equal ea["empty_audience"]["body_hex"], empty.bytes.unpack1("H*")
    assert_equal ea["populated_audience"]["body_hex"], populated.bytes.unpack1("H*")
    refute_equal empty.id, populated.id
    assert_equal ea["empty_audience"]["id_hex"], empty.id.unpack1("H*")
    Naalp::Gateway.parse_egress_attestation(empty.bytes)
    Naalp::Gateway.parse_egress_attestation(populated.bytes)
    err = assert_raises(Naalp::Gateway::EgMalformed) { Naalp::Gateway.parse_egress_attestation(hbe(ea["absent_field"]["body_hex"])) }
    assert_equal "EgMalformed", err.kind
  end

  def test_minimal
    m = C["edge_cases"]["minimal"]
    a = Naalp::Gateway::EgressAttestation.new(m["binding"], hbe(m["digest_hex"]), m["effect"], hbe(m["audience_hex"]), Integer(m["at_str"]))
    assert_equal m["body_hex"], a.bytes.unpack1("H*")
    assert_equal m["id_hex"], a.id.unpack1("H*")
    Naalp::Gateway.parse_egress_attestation(a.bytes)
    seed = ("\x63" * 32).b
    alg = Naalp::COSE::ALG_MLDSA65
    begin
      pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    obj = Naalp::Gateway.sign_egress_attestation(a, alg, seed)
    Naalp::Gateway.verify_egress_attestation(obj, Naalp::COSE::PROFILE_PUBLIC, alg, pk) # no raise
  end

  def test_look_alike_rejected
    la = C["edge_cases"]["look_alike"]
    err = assert_raises(Naalp::Gateway::EgMalformed) do
      Naalp::Gateway.parse_egress_attestation(hbe(la["body_hex"]))
    end
    assert_equal la["reject"], err.kind
  end

  def test_ordering_byte_parity
    C["ordering_basis_vocabulary"].each do |e|
      assert Naalp::Gateway.known_ordering_basis?(e["code"]), e["name"]
      assert_equal e["name"], Naalp::Gateway.ordering_basis_name(e["code"])
    end

    build = lambda do |name, av|
      a = att_from(av)
      case name
      when "correspondence_only"
        a.ordering = Naalp::Gateway.correspondence_only
      when "single_boundary"
        a.ordering = Naalp::Gateway::OrderingDisclosure.new(Naalp::Gateway::ORDERING_SINGLE_BOUNDARY, boundary: "boundary-signer-X".b)
      when "external_mechanism"
        a.ordering = Naalp::Gateway::OrderingDisclosure.new(
          Naalp::Gateway::ORDERING_EXTERNAL_MECHANISM,
          mechanism: "external-log:acme-transparency-v1".b,
          relation: hbe("2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56"))
      else
        raise "unhandled attestations_with_ordering name #{name.inspect}"
      end
      a
    end

    C["attestations_with_ordering"].each do |name, av|
      a = build.call(name, av)
      assert_equal av["body_hex"], a.bytes.unpack1("H*"), name
      assert_equal av["head_hex"], a.head.unpack1("H*"), name
      assert_equal av["id_hex"], a.id.unpack1("H*"), name
      parsed = Naalp::Gateway.parse_egress_attestation(a.bytes)
      refute_nil parsed.ordering, name
      assert_equal av["body_hex"], parsed.bytes.unpack1("H*"), name
      Naalp::Gateway.validate_egress_attestation(parsed) # no raise
    end

    plain = Naalp::Gateway.parse_egress_attestation(att_from(C["attestations"]["content_bound"]).bytes)
    assert_nil plain.ordering
  end

  def test_ordering_negative
    kind_of = lambda do |body_hex|
      begin
        a = Naalp::Gateway.parse_egress_attestation(hbe(body_hex))
      rescue StandardError => e
        return e.kind
      end
      begin
        Naalp::Gateway.validate_egress_attestation(a)
      rescue StandardError => e
        return e.kind
      end
      ""
    end

    sbwm = C["negative_ordering"]["ordering_malformed_single_boundary_with_mechanism"]
    assert_equal sbwm["reject"], kind_of.call(sbwm["body_hex"])
    uob = C["negative_ordering"]["unknown_ordering_basis"]
    assert_equal uob["reject"], kind_of.call(uob["body_hex"])
  end

  def test_missing_at_field_rejected
    # Isolates the field-5 (`at`) mandatory check: fields 1-4 correctly typed, field 5 absent.
    body = Naalp::CBOR.encode(Naalp::CBOR::M.new([
      [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(Naalp::Gateway::BINDING_CONTENT_BOUND)],
      [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new([0x20, 0x30].pack("C*"))],
      [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(1)],
      [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new("".b)],
    ]))
    err = assert_raises(Naalp::Gateway::EgMalformed) { Naalp::Gateway.parse_egress_attestation(body) }
    assert_equal "EgMalformed", err.kind
  end
end
