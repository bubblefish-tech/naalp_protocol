# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C12 foreign-carriage-by-class conformance for the Ruby SDK (design.md §13; R-14.1..14.8, R-18.6),
# graded against the shared independent PER-CLASS corpus vectors/carriage/<class>/cases.json (NOT one
# cases.json, and NOT produced by this code): each of the six carriage classes -- JSONRPC (0), HTTP (1),
# MSG (2), STREAM (3), DOC (4), OPAQUE (5) -- is graded against its OWN subdirectory oracle
# (vectors/carriage/{jsonrpc,http,msg,stream,doc,opaque}/cases.json). The tests grade the deterministic
# carriage-body bytes byte-for-byte for every class, the octet-for-octet recovery of the foreign
# message (R-14.4), the protocol-id ranges, the fail-closed class/foreign rejections, the honest
# delivery report, and the signer-is-authority rule.
#
# The LOAD-BEARING C12 property graded here: the foreign message is carried VERBATIM and MUST NOT be
# re-serialized, canonicalized, summarized, or rewritten (R-14.4); N-AALP metadata is carried AROUND it.
#
# Written test-first; the module is absent until ported, so this fails RED (uninitialized constant
# Naalp::Carriage) until impl/ruby/lib/naalp/carriage.rb lands, and a mutation rewriting the carried
# foreign field to empty flips test_carriage_bodies_match_oracle on its assertion.
#
# Run:  ruby -Ilib -Itest test/test_carriage.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

# subdir name -> expected numeric class code (the per-class oracle layout).
CARRIAGE_CLASSES = { "jsonrpc" => 0, "http" => 1, "msg" => 2, "stream" => 3, "doc" => 4, "opaque" => 5 }.freeze

def carriage_class_vectors(klass)
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "carriage", klass, "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/carriage/#{klass}/cases.json not found"
end

def hb(hex)
  [hex].pack("H*")
end

class CarriageConformance < Minitest::Test
  CLASSES = CARRIAGE_CLASSES.keys.each_with_object({}) { |k, h| h[k] = carriage_class_vectors(k) }

  def body_from(cv)
    Naalp::Carriage::CarriageBody.new(
      cv["protocol_id"], cv["class"], cv["content_type"],
      hb(cv["correlation_hex"]), cv["method"], hb(cv["foreign_hex"])
    )
  end

  def test_class_vocabulary
    assert_equal 0, Naalp::Carriage::CLASS_JSONRPC
    assert_equal 1, Naalp::Carriage::CLASS_HTTP
    assert_equal 2, Naalp::Carriage::CLASS_MSG
    assert_equal 3, Naalp::Carriage::CLASS_STREAM
    assert_equal 4, Naalp::Carriage::CLASS_DOC
    assert_equal 5, Naalp::Carriage::CLASS_OPAQUE
    %w[JSONRPC HTTP MSG STREAM DOC OPAQUE].each_with_index { |name, code| assert_equal name, Naalp::Carriage.class_name(code) }
    assert_equal "unknown", Naalp::Carriage.class_name(6)
  end

  # THE MUTATION TARGET. Ruby encoding == the non-circular oracle, byte-for-byte, for ALL SIX carriage
  # classes, EACH graded against its OWN per-class subdirectory oracle. The corpus `class` field must
  # equal the subdir's expected class code. Rewriting the carried foreign field to empty flips this on
  # its per-class assertion.
  def test_carriage_bodies_match_oracle
    CLASSES.each do |klass, cv|
      assert_equal CARRIAGE_CLASSES[klass], cv["class"], "#{klass} corpus class code"
      body = body_from(cv)
      assert_equal cv["body_hex"], body.bytes.unpack1("H*"), "#{klass} carriage body (vectors/carriage/#{klass})"
    end
  end

  # The load-bearing R-14.4 property: a carriage body decodes back to the foreign message OCTET-FOR-
  # OCTET, and re-encodes to the identical bytes -- N-AALP never re-serializes or rewrites the foreign
  # payload. Graded for every class against its own subdir oracle.
  def test_foreign_carried_octet_for_octet
    CLASSES.each do |klass, cv|
      parsed = Naalp::Carriage.carriage_from_value(Naalp::CBOR.decode(hb(cv["body_hex"])))
      assert_equal cv["foreign_hex"], parsed.foreign.unpack1("H*"), "#{klass} foreign recovered octet-for-octet"
      assert_equal cv["method"], parsed.method, "#{klass} method recovered"
      assert_equal cv["class"], parsed.klass, "#{klass} class recovered"
      assert_equal cv["protocol_id"], parsed.protocol_id, "#{klass} protocol_id recovered"
      # round-trip re-encode is byte-identical (verbatim carriage, R-14.4).
      assert_equal cv["body_hex"], parsed.bytes.unpack1("H*"), "#{klass} round-trip re-encode is byte-identical"
    end
  end

  def test_validate_class_and_protocol_range
    # a class code outside 0..5 is a MappingError, never a silent drop (R-14.8).
    err = assert_raises(Naalp::Carriage::CarriageError) { Naalp::Carriage.validate_class(6) }
    assert_equal "MappingError", err.kind
    assert_nil Naalp::Carriage.validate_class(Naalp::Carriage::CLASS_OPAQUE)
    # protocol-id ranges (design §13.4): the corpus uses standards (<=0x0F) and experimental (0x10..).
    assert_equal "reserved", Naalp::Carriage.protocol_range(0x00)
    assert_equal "standards", Naalp::Carriage.protocol_range(CLASSES["doc"]["protocol_id"])       # 2
    assert_equal "experimental", Naalp::Carriage.protocol_range(CLASSES["msg"]["protocol_id"])     # 16 = 0x10
    assert_equal "experimental", Naalp::Carriage.protocol_range(CLASSES["opaque"]["protocol_id"])  # 17 = 0x11
    assert_equal "private", Naalp::Carriage.protocol_range(0x80)
    assert_equal "invalid", Naalp::Carriage.protocol_range(0x100)
  end

  def test_carriage_from_value_rejects_malformed
    # a non-map value is Malformed.
    err = assert_raises(Naalp::Carriage::CarriageError) { Naalp::Carriage.carriage_from_value(Naalp::CBOR::U.new(1)) }
    assert_equal "Malformed", err.kind
    # a body missing the mandatory foreign field (key 6) is Malformed.
    no_foreign = Naalp::CBOR::M.new([
      [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(1)],
      [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(0)],
      [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(0)],
      [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new("".b)],
      [Naalp::CBOR::U.new(5), Naalp::CBOR::T.new("m")],
    ])
    err2 = assert_raises(Naalp::Carriage::CarriageError) { Naalp::Carriage.carriage_from_value(no_foreign) }
    assert_equal "Malformed", err2.kind
    # a well-formed body carrying an out-of-range class (6) is a MappingError.
    bad_class = Naalp::CBOR::M.new([
      [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(1)],
      [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(6)],
      [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(0)],
      [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new("".b)],
      [Naalp::CBOR::U.new(5), Naalp::CBOR::T.new("m")],
      [Naalp::CBOR::U.new(6), Naalp::CBOR::B.new("x".b)],
    ])
    err3 = assert_raises(Naalp::Carriage::CarriageError) { Naalp::Carriage.carriage_from_value(bad_class) }
    assert_equal "MappingError", err3.kind
  end

  def test_report_never_false_delivered
    rep = Naalp::Carriage.report(true)
    assert rep.delivered, "a real delivery reports delivered"
    err = assert_raises(Naalp::Carriage::CarriageError) { Naalp::Carriage.report(false) }
    assert_equal "NotDelivered", err.kind
  end

  # The authorizing principal of a carriage object is the N-AALP SIGNER of the object (envelope field
  # 5), never any foreign principal named inside the foreign bytes (R-14.6). Demonstrated on a real
  # Naalp::Envelope::Object.
  def test_carriage_authority_is_the_naalp_signer
    cv = CLASSES["jsonrpc"]
    body = body_from(cv)
    signer = ("\xAB" * 32).b
    obj = Naalp.object(kind: 1, channel: Naalp::Carriage::CLASS_JSONRPC, signer: signer,
                       created: 1785000000000, effect: Naalp::Policy::READ_ONLY,
                       body: Naalp::CBOR.decode(body.bytes))
    assert_equal signer, Naalp::Carriage.carriage_authority(obj), "authority is the N-AALP signer, not any foreign principal"
  end
end
