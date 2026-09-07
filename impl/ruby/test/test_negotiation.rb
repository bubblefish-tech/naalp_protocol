# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C20 governed-negotiation / advisory-risk-label / trust-reference conformance for the Ruby SDK
# (design.md §23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4), graded against the shared independent
# corpus vectors/negotiation/cases.json (NOT produced by this code): the deterministic body / head /
# content-id of every negotiation Message, risk-label, LabeledObject and TrustRef byte-for-byte; the
# closed role/profile sets; the causal-DAG descent that governs an accept; the R-2.5 critical-extension
# rule; and the strict-decoder rejections (non-canonical, absent-mandatory-field, sibling look-alike).
#
# The load-bearing C20 invariants graded here: (1) an accept is honored only when it DESCENDS from its
# offer along the causes DAG (a non-descended accept is rejected); (2) carrying a risk label NEVER
# changes an object's effect class (the closed C5 lattice is untouched). The Message/LabeledObject/
# TrustRef signatures are real deterministic ML-DSA-65 (COSE_Sign1) demonstrated in isolation, but the
# corpus carries no signature vector, so they are NOT corpus-graded (stated honestly; skip-loud where
# deterministic ML-DSA is unavailable).
#
# Written test-first; the module is absent until ported, so this fails RED (uninitialized constant
# Naalp::Negotiation) until impl/ruby/lib/naalp/negotiation.rb lands, and a mutation forcing the causal
# descent walk to a constant true flips test_accept_must_descend_from_offer on its assertion.
#
# Run:  ruby -Ilib -Itest test/test_negotiation.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def negotiation_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "negotiation", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/negotiation/cases.json not found"
end

def hb(hex)
  [hex].pack("H*")
end

ALG = Naalp::COSE::ALG_MLDSA65

class NegotiationConformance < Minitest::Test
  C = negotiation_vectors
  NEG = C["negotiation"]

  # Build a Message straight from a negotiation-vector entry (scalar corpus fields only, never our
  # own output): negotiation id, role, profile, and the causes content-ids.
  def msg_from(nv)
    Naalp::Negotiation::Message.new(
      hb(NEG["negotiation_hex"]), nv["role"], nv["profile"], nv["causes_hex"].map { |h| hb(h) }
    )
  end

  def test_role_and_profile_vocabulary
    assert_equal Naalp::Negotiation::ROLE_OFFER, NEG["roles"]["offer"]
    assert_equal Naalp::Negotiation::ROLE_COUNTER, NEG["roles"]["counter"]
    assert_equal Naalp::Negotiation::ROLE_ACCEPT, NEG["roles"]["accept"]
    NEG["roles"].each { |name, code| assert Naalp::Negotiation.known_role?(code); assert_equal name, Naalp::Negotiation.role_name(code) }
    assert_equal Naalp::Negotiation::PROFILE_BASELINE, NEG["profiles"]["baseline"]
    assert_equal Naalp::Negotiation::PROFILE_STREAMING, NEG["profiles"]["streaming"]
    assert_equal Naalp::Negotiation::PROFILE_BATCH, NEG["profiles"]["batch"]
    NEG["profiles"].each { |name, code| assert Naalp::Negotiation.registered_profile?(code); assert_equal name, Naalp::Negotiation.profile_name(code) }
    refute Naalp::Negotiation.registered_profile?(NEG["unknown_profile"])
    assert_equal "unknown", Naalp::Negotiation.profile_name(NEG["unknown_profile"])
    assert_equal "unknown", Naalp::Negotiation.role_name(9)
  end

  # Ruby encoding == the non-circular oracle, byte-for-byte, for every negotiation message
  # body/head/id. A mutation to any Bytes() field (key, value, array) flips a *_hex assertion.
  def test_negotiation_bodies_match_oracle
    %w[offer counter accept offer2 accept_not_descended unknown_profile_offer unknown_role_message].each do |name|
      nv = NEG[name]
      m = msg_from(nv)
      assert_equal nv["body_hex"], m.bytes.unpack1("H*"), "#{name} body bytes"
      assert_equal nv["head_hex"], m.head.unpack1("H*"), "#{name} head (SHA-384)"
      assert_equal nv["id_hex"], m.id.unpack1("H*"), "#{name} content-id"
    end
  end

  # THE MUTATION TARGET. The load-bearing governance property: an accept is honored ONLY when it
  # DESCENDS from its offer by walking the causes DAG (offer <- counter <- accept). A non-descended
  # accept (accept_not_descended chains onto a DIFFERENT offer, offer2) does NOT descend from offer
  # and is rejected NotDescended. Forcing the descent walk to a constant true flips this on its
  # refute / assert_raises.
  def test_accept_must_descend_from_offer
    offer = msg_from(NEG["offer"])
    counter = msg_from(NEG["counter"])
    accept = msg_from(NEG["accept"])
    offer2 = msg_from(NEG["offer2"])
    bad = msg_from(NEG["accept_not_descended"])
    by_id = Naalp::Negotiation.index_by_id([offer, counter, accept, offer2, bad])

    assert_equal NEG["descends"]["accept_from_offer"], Naalp::Negotiation.descends_msg(accept, offer, by_id)
    assert_equal NEG["descends"]["accept_bad_from_offer"], Naalp::Negotiation.descends_msg(bad, offer, by_id)
    assert Naalp::Negotiation.descends_msg(accept, offer, by_id), "accept must descend from offer"
    refute Naalp::Negotiation.descends_msg(bad, offer, by_id), "a non-descended accept must NOT descend from offer"

    # verify_accept returns the AGREED profile only when the accept genuinely descends.
    assert_equal NEG["agreed_profile"], Naalp::Negotiation.verify_accept(accept, offer, by_id)
    err = assert_raises(Naalp::Negotiation::NegotiationError) do
      Naalp::Negotiation.verify_accept(bad, offer, by_id)
    end
    assert_equal "NotDescended", err.kind
  end

  def test_risk_label_bodies_and_vocabulary
    C["risk"]["vocabulary"].each do |e|
      cls, known = Naalp::Negotiation.risk_class_of(e["code"])
      assert known, "#{e['name']} must be a registered risk code"
      assert_equal e["class"], Naalp::Negotiation.risk_class_name(cls)
    end
    assert_equal C["risk"]["extensible_range_start"], Naalp::Negotiation::EXTENSIBLE_RANGE_START
    C["risk"]["sample_labels"].each do |name, lv|
      l = Naalp::Negotiation::RiskLabel.new(lv["code"], lv["critical"])
      assert_equal lv["body_hex"], l.bytes.unpack1("H*"), "risk label #{name} body"
    end
    # unknown critical is in the extensible range; unknown non-critical too.
    assert Naalp::Negotiation.in_extensible_range?(C["risk"]["sample_labels"]["unknown_critical"]["code"])
    refute Naalp::Negotiation.registered_risk?(C["risk"]["sample_labels"]["unknown_critical"]["code"])
  end

  # The load-bearing invariant, provable in isolation: a LabeledObject's effect class derives from
  # the effect field ALONE. The with-labels and without-labels bodies differ by content-id, yet the
  # effect_class is identical -- carrying a risk label never changes the effect.
  def test_labeled_object_effect_unchanged_by_labels
    carried = C["risk"]["carried_on_labeled_objects"].map { |lv| Naalp::Negotiation::RiskLabel.new(lv["code"], lv["critical"]) }
    C["risk"]["labeled_objects"].each do |ov|
      with = Naalp::Negotiation::LabeledObject.new(ov["effect"], carried)
      without = Naalp::Negotiation::LabeledObject.new(ov["effect"], [])
      assert_equal ov["with_labels"]["body_hex"], with.bytes.unpack1("H*"), "effect #{ov['effect']} with-labels body"
      assert_equal ov["with_labels"]["head_hex"], with.head.unpack1("H*"), "effect #{ov['effect']} with-labels head"
      assert_equal ov["with_labels"]["id_hex"], with.id.unpack1("H*"), "effect #{ov['effect']} with-labels id"
      assert_equal ov["without_labels"]["body_hex"], without.bytes.unpack1("H*"), "effect #{ov['effect']} without-labels body"
      assert_equal ov["without_labels"]["id_hex"], without.id.unpack1("H*"), "effect #{ov['effect']} without-labels id"
      refute_equal with.id.unpack1("H*"), without.id.unpack1("H*"), "with/without labels must have distinct ids"
      # the invariant: the effect class is unchanged by the presence of labels.
      assert_equal ov["effect_class"], with.effect_class
      assert_equal ov["effect_class"], without.effect_class
    end
  end

  def test_validate_labels_critical_extension
    rs = C["risk"]["validate"]["recognized_set"]
    carried = rs["carried"].map { |lv| Naalp::Negotiation::RiskLabel.new(lv["code"], lv["critical"]) }
    recognized = Naalp::Negotiation.validate_labels(carried)
    assert_equal rs["recognized_codes"], recognized.map(&:code), "unknown non-critical labels dropped; recognized kept"

    uc = C["risk"]["validate"]["unknown_critical_rejected"]
    bad = uc["carried"].map { |lv| Naalp::Negotiation::RiskLabel.new(lv["code"], lv["critical"]) }
    err = assert_raises(Naalp::Negotiation::NegotiationError) { Naalp::Negotiation.validate_labels(bad) }
    assert_equal uc["error"], err.kind

    # a critical flag outside {0,1} is rejected, never defaulted (the spine carries no CBOR boolean).
    err2 = assert_raises(Naalp::Negotiation::NegotiationError) do
      Naalp::Negotiation.validate_labels([Naalp::Negotiation::RiskLabel.new(1, 2)])
    end
    assert_equal "MalformedCriticalFlag", err2.kind
  end

  # A trust reference is CHECKABLE (its reference recomputes over the external record) but never
  # WEIGHED. Two registries referencing the same record verify symmetrically; a tampered record does
  # not recompute the carried reference.
  def test_trust_ref_bodies_and_binding
    t = C["trust"]
    ref_a = Naalp::Negotiation::TrustRef.new(hb(t["registry_a_hex"]), hb(t["reference_hex"]), hb(t["subject_hex"]))
    ref_b = Naalp::Negotiation::TrustRef.new(hb(t["registry_b_hex"]), hb(t["reference_hex"]), hb(t["subject_hex"]))
    assert_equal t["ref_a"]["body_hex"], ref_a.bytes.unpack1("H*"), "trust ref_a body"
    assert_equal t["ref_a"]["head_hex"], ref_a.head.unpack1("H*"), "trust ref_a head"
    assert_equal t["ref_a"]["id_hex"], ref_a.id.unpack1("H*"), "trust ref_a id"
    assert_equal t["ref_b"]["body_hex"], ref_b.bytes.unpack1("H*"), "trust ref_b body"
    assert_equal t["ref_b"]["id_hex"], ref_b.id.unpack1("H*"), "trust ref_b id"
    # the reference recomputes over the external record (checkable, symmetric across registries).
    assert ref_a.binds_record(hb(t["external_record_hex"])), "ref_a binds the external record"
    assert ref_b.binds_record(hb(t["external_record_hex"])), "ref_b binds the same record symmetrically"
    refute ref_a.binds_record(hb(t["tampered_record_hex"])), "a tampered record does not recompute the reference"
    # the tampered record's own content-id is the corpus tampered_reference.
    assert_equal t["tampered_reference_hex"], Naalp::CBOR.content_id(hb(t["tampered_record_hex"])).unpack1("H*")
  end

  def test_edge_cases
    ec = C["edge_cases"]
    # keys out of order -> NonCanonical from the strict decoder; the canonical body parses.
    ko = ec["keys_out_of_order"]
    assert_raises(Naalp::CBOR::NonCanonical) { Naalp::CBOR.decode(hb(ko["noncanonical_offer_body_hex"])) }
    err = assert_raises(Naalp::Negotiation::NegotiationError) { Naalp::Negotiation.parse_message(hb(ko["noncanonical_offer_body_hex"])) }
    assert_equal "NegMalformed", err.kind
    assert Naalp::Negotiation.parse_message(hb(ko["canonical_offer_body_hex"])), "canonical offer parses"

    # an absent mandatory causes[] / labels[] field is rejected NegMalformed.
    ea = ec["empty_vs_absent"]
    err2 = assert_raises(Naalp::Negotiation::NegotiationError) { Naalp::Negotiation.parse_message(hb(ea["causes"]["absent_field"]["body_hex"])) }
    assert_equal "NegMalformed", err2.kind
    err3 = assert_raises(Naalp::Negotiation::NegotiationError) { Naalp::Negotiation.parse_labeled_object(hb(ea["labels"]["absent_field"]["body_hex"])) }
    assert_equal "NegMalformed", err3.kind
    # an empty-but-present causes[] is distinct by content-id from a one-cause body.
    assert_equal ea["causes"]["empty_present"]["id_hex"], Naalp::Negotiation.parse_message(hb(ea["causes"]["empty_present"]["body_hex"])).then { |m| m.id.unpack1("H*") }
    assert_equal ea["causes"]["one_cause"]["id_hex"], Naalp::Negotiation.parse_message(hb(ea["causes"]["one_cause"]["body_hex"])).then { |m| m.id.unpack1("H*") }

    # minimal bodies.
    mn = ec["minimal"]
    off = Naalp::Negotiation::Message.new(hb(mn["offer"]["negotiation_hex"]), mn["offer"]["role"], mn["offer"]["profile"], [])
    assert_equal mn["offer"]["body_hex"], off.bytes.unpack1("H*"), "minimal offer body"
    assert_equal mn["offer"]["id_hex"], off.id.unpack1("H*"), "minimal offer id"
    lo = Naalp::Negotiation::LabeledObject.new(mn["labeled_object"]["effect"], [])
    assert_equal mn["labeled_object"]["body_hex"], lo.bytes.unpack1("H*"), "minimal labeled-object body"
    tr = Naalp::Negotiation::TrustRef.new("".b, "".b, "".b)
    assert_equal mn["trust_ref"]["body_hex"], tr.bytes.unpack1("H*"), "minimal trust-ref body"
    assert_equal mn["trust_ref"]["id_hex"], tr.id.unpack1("H*"), "minimal trust-ref id"

    # sibling look-alikes fed to the wrong parser are rejected NegMalformed.
    la = ec["look_alike"]
    e4 = assert_raises(Naalp::Negotiation::NegotiationError) { Naalp::Negotiation.parse_message(hb(la["trust_ref_as_message"]["body_hex"])) }
    assert_equal "NegMalformed", e4.kind
    e5 = assert_raises(Naalp::Negotiation::NegotiationError) { Naalp::Negotiation.parse_trust_ref(hb(la["message_as_trust_ref"]["body_hex"])) }
    assert_equal "NegMalformed", e5.kind
  end

  # NOT corpus-graded (no signature vector). Real deterministic ML-DSA-65 COSE_Sign1 round-trip in
  # isolation: a signed message verifies, a foreign key does not, and verify_message enforces the
  # closed role/profile sets. Skips LOUDLY where deterministic ML-DSA is unavailable.
  def test_full_signature_sign_verify_in_isolation
    seed = ("\x30" * 32).b
    foreign = ("\x31" * 32).b
    begin
      pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
      foreign_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", foreign)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    offer = Naalp::Negotiation.new_offer(hb(NEG["negotiation_hex"]), Naalp::Negotiation::PROFILE_BASELINE)
    obj = Naalp::Negotiation.sign_message(offer, ALG, seed)
    m = Naalp::Negotiation.verify_message(obj, Naalp::COSE::PROFILE_PUBLIC, ALG, pk)
    assert_equal Naalp::Negotiation::ROLE_OFFER, m.role
    err = assert_raises(Naalp::Negotiation::NegotiationError) do
      Naalp::Negotiation.verify_message(obj, Naalp::COSE::PROFILE_PUBLIC, ALG, foreign_pk)
    end
    assert_equal "BadSignature", err.kind

    # an unknown profile is rejected at verify (the closed pre-registered set).
    bad = Naalp::Negotiation::Message.new(hb(NEG["negotiation_hex"]), Naalp::Negotiation::ROLE_OFFER, NEG["unknown_profile"], [])
    bad_obj = Naalp::Negotiation.sign_message(bad, ALG, seed)
    err2 = assert_raises(Naalp::Negotiation::NegotiationError) do
      Naalp::Negotiation.verify_message(bad_obj, Naalp::COSE::PROFILE_PUBLIC, ALG, pk)
    end
    assert_equal "UnknownProfile", err2.kind
  end
end
