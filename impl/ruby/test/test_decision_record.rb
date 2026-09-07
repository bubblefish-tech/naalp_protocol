# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# S1 naalp-decision-record conformance for the Ruby SDK, graded against the shared independent
# corpus vectors/decision_record/cases.json (NOT produced by this code): the closed outcome/
# ordering-basis/enforcement-disposition/term-disposition-kind vocabularies, byte-exact record
# body/head/content-id for every records{} and ordering_examples{} case (each record reconstructed
# field-by-field, never routed through the decoder), the parse round-trip, full semantic
# validation, and every named negative rejection (deny/hold-with-consume, terms-key-outside-
# field-set, unknown outcome, every ordering_malformed variant, the descending-key body, and the
# gateway-decision look-alike).
#
# Mirrors impl/python/tests/test_decision_record.py and impl/go/gateway/decision_record_test.go.
#
# Run:  ruby -Ilib -Itest test/test_decision_record.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def decision_record_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "decision_record", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/decision_record/cases.json not found"
end

def hbd(hex)
  [hex].pack("H*")
end

class DecisionRecordConformance < Minitest::Test
  C = decision_record_vectors

  # Build the mandatory-field-only shell of a records{}/ordering_examples{} case; the ordering/
  # terms/enforcement fixture is layered on by build (mirroring the Go test's drFrom + build).
  def dr_from(rv)
    governing = rv["governing_hex"].map { |g| hbd(g) }
    d = Naalp::Gateway::DecisionRecord.new(
      hbd(rv["action_hex"]), governing, rv["outcome"], Naalp::Gateway.correspondence_only)
    d.consume = hbd(rv["consume_hex"]) if rv["consume_hex"] && !rv["consume_hex"].empty?
    d
  end

  # Reconstruct a records{}/ordering_examples{} case with its exact ordering/terms/enforcement
  # fixture, mirroring decision_record_test.go's build() switch exactly.
  def build(name, rv)
    d = dr_from(rv)
    case name
    when "allow_consuming", "allow_no_consume", "minimal", "correspondence_only"
      d.ordering = Naalp::Gateway.correspondence_only
    when "deny_two_governing"
      d.ordering = Naalp::Gateway::OrderingDisclosure.new(Naalp::Gateway::ORDERING_SINGLE_BOUNDARY, boundary: "boundary-signer-X".b)
    when "hold_empty_governing", "external_mechanism"
      d.ordering = Naalp::Gateway::OrderingDisclosure.new(
        Naalp::Gateway::ORDERING_EXTERNAL_MECHANISM,
        mechanism: "external-log:acme-transparency-v1".b,
        relation: hbd("2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56"))
    when "single_boundary"
      d.ordering = Naalp::Gateway::OrderingDisclosure.new(Naalp::Gateway::ORDERING_SINGLE_BOUNDARY, boundary: "SIGNER_B-boundary".b)
    when "external_mechanism_no_relation"
      d.ordering = Naalp::Gateway::OrderingDisclosure.new(
        Naalp::Gateway::ORDERING_EXTERNAL_MECHANISM, mechanism: "external-log:acme-transparency-v1".b)
    when "terms_valid"
      d.ordering = Naalp::Gateway.correspondence_only
      d.terms = {
        1 => Naalp::Gateway::TermDisposition.new(Naalp::Gateway::TERM_OBSERVED),
        4 => Naalp::Gateway::TermDisposition.new(Naalp::Gateway::TERM_REPORTED, source: "boundary:relay-partner-3".b),
      }
    when "enforcement_enforced"
      d.ordering = Naalp::Gateway.correspondence_only
      d.enforcement = Naalp::Gateway::ENFORCEMENT_ENFORCED
    when "enforcement_advised"
      d.ordering = Naalp::Gateway.correspondence_only
      d.enforcement = Naalp::Gateway::ENFORCEMENT_ADVISED
    else
      raise "unhandled record name #{name.inspect} -- add its ordering/terms/enforcement fixture"
    end
    d
  end

  def test_outcome_vocabulary
    C["outcome_vocabulary"].each do |e|
      assert Naalp::Gateway.known_decision?(e["code"]), e["name"]
      assert_equal e["name"], Naalp::Gateway.decision_name(e["code"])
    end
  end

  def test_ordering_basis_vocabulary
    C["ordering_basis_vocabulary"].each do |e|
      assert Naalp::Gateway.known_ordering_basis?(e["code"]), e["name"]
      assert_equal e["name"], Naalp::Gateway.ordering_basis_name(e["code"])
    end
    refute Naalp::Gateway.known_ordering_basis?(99)
  end

  def test_decision_record_bodies_match_oracle
    all_cases = C["records"].merge(C["ordering_examples"])
    assert_equal C["records"].size + C["ordering_examples"].size, all_cases.size,
                 "records/ordering_examples name collision"
    all_cases.each do |name, rv|
      d = build(name, rv)
      assert_equal rv["body_hex"], d.bytes.unpack1("H*"), name
      assert_equal rv["head_hex"], d.head.unpack1("H*"), name
      assert_equal rv["id_hex"], d.id.unpack1("H*"), name
      # Round-trip through the decoder and re-encode: the decoded record must re-encode to the
      # SAME canonical bytes.
      parsed = Naalp::Gateway.parse_decision_record(d.bytes)
      assert_equal rv["body_hex"], parsed.bytes.unpack1("H*"), name
      Naalp::Gateway.validate_decision_record(parsed) # every records/ordering_examples case is POSITIVE
    end
  end

  def test_decision_record_minimal
    m = C["records"]["minimal"]
    d = Naalp::Gateway::DecisionRecord.new("".b, [], m["outcome"], Naalp::Gateway.correspondence_only)
    assert_equal m["body_hex"], d.bytes.unpack1("H*")
    assert_equal m["id_hex"], d.id.unpack1("H*")
    parsed = Naalp::Gateway.parse_decision_record(d.bytes)
    Naalp::Gateway.validate_decision_record(parsed)
  end

  def test_decision_record_negative_rejections
    neg = C["negative"]

    kind_of = lambda do |body_hex|
      begin
        d = Naalp::Gateway.parse_decision_record(hbd(body_hex))
      rescue StandardError => e
        return e.kind
      end
      begin
        Naalp::Gateway.validate_decision_record(d)
      rescue StandardError => e
        return e.kind
      end
      ""
    end

    {
      "deny_with_consume_rejected" => neg["deny_with_consume_rejected"],
      "hold_with_consume_rejected" => neg["hold_with_consume_rejected"],
      "terms_key_outside_field_set_rejected" => neg["terms_key_outside_field_set_rejected"],
      "unknown_outcome_rejected" => neg["unknown_outcome_rejected"],
      "look_alike" => neg["look_alike"],
    }.each do |name, c|
      assert_equal c["reject"], kind_of.call(c["body_hex"]), name
    end

    neg["ordering_malformed"].each do |name, c|
      assert_equal c["reject"], kind_of.call(c["body_hex"]), "ordering_malformed.#{name}"
    end

    # keys_out_of_order: the canonical body decodes+validates cleanly; the descending-key body is
    # rejected at the CBOR layer (NonCanonical) before parse_decision_record's own checks ever run.
    koo = neg["keys_out_of_order"]
    d = Naalp::Gateway.parse_decision_record(hbd(koo["canonical_body_hex"]))
    Naalp::Gateway.validate_decision_record(d)
    assert_raises(Naalp::CBOR::NonCanonical) { Naalp::CBOR.decode(hbd(koo["noncanonical_body_hex"])) }
    err = assert_raises(Naalp::Gateway::DecisionMalformed) { Naalp::Gateway.parse_decision_record(hbd(koo["noncanonical_body_hex"])) }
    assert_equal "DecisionMalformed", err.kind
  end

  def test_decision_record_third_party_reserve
    rv = C["records"]["allow_consuming"]
    d = build("allow_consuming", rv)
    assert_equal rv["body_hex"], d.bytes.unpack1("H*")

    seed_producer = ("\x71" * 32).b
    seed_foreign = ("\x72" * 32).b
    alg = Naalp::COSE::ALG_MLDSA65
    begin
      producer_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed_producer)
      foreign_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed_foreign)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end

    obj = Naalp::Gateway.sign_decision_record(d, alg, seed_producer)
    by_producer = Naalp::Gateway.verify_decision_record(obj, Naalp::COSE::PROFILE_PUBLIC, alg, producer_pk)
    by_third_party = Naalp::Gateway.verify_decision_record(obj.dup, Naalp::COSE::PROFILE_PUBLIC, alg, producer_pk)
    assert_equal by_producer.action, by_third_party.action
    assert_equal by_producer.outcome, by_third_party.outcome
    assert_equal Naalp::Gateway::DECISION_ALLOW, by_third_party.outcome
    assert_equal rv["consume_hex"], by_third_party.consume.unpack1("H*")

    err = assert_raises(Naalp::Gateway::BadSignature) do
      Naalp::Gateway.verify_decision_record(obj, Naalp::COSE::PROFILE_PUBLIC, alg, foreign_pk)
    end
    assert_equal "BadSignature", err.kind
  end

  def test_decision_record_sign_verify_terms_valid
    # In isolation (no cross-lang pin claimed): terms_valid signs and verifies end-to-end, carrying
    # field 6 (terms) through the full signature-verification + semantic-validation path,
    # exercising the terms map on the signed/verified round trip.
    rv = C["records"]["terms_valid"]
    d = build("terms_valid", rv)
    assert_equal rv["body_hex"], d.bytes.unpack1("H*")
    seed = ("\x11" * 32).b
    alg = Naalp::COSE::ALG_MLDSA65
    begin
      pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    obj = Naalp::Gateway.sign_decision_record(d, alg, seed)
    resolved = Naalp::Gateway.verify_decision_record(obj, Naalp::COSE::PROFILE_PUBLIC, alg, pk)
    assert_equal Naalp::Gateway::TERM_OBSERVED, resolved.terms[1].kind
    assert_equal Naalp::Gateway::TERM_REPORTED, resolved.terms[4].kind
    assert_equal "boundary:relay-partner-3".b, resolved.terms[4].source
  end
end
