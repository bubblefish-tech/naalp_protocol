# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# The object-audience (field 13, §2.5.3) known-answer + gate tests for the Ruby SDK.
#
# Three properties, all mutation-surviving:
#   1. BYTE MATCH -- an audience-bearing object reproduces the independent oracle's content id,
#      payload, protected header, and to-be-signed bytes (vectors/envelope/cases.json
#      object_with_audience), i.e. Ruby == Go == Rust == Python == TS == tools/envelope_oracle.py.
#      (Pure encoding -- no ML-DSA -- so it runs regardless of OpenSSL version.)
#   2. check_audience -- the three-branch point-of-use gate.
#   3. consume_object -- the gate is enforced at the consume choke point BEFORE the compare-and-set:
#      a wrong/absent audience is rejected WrongAudience with NO ledger append; an unnamed ledger
#      refuses LedgerUnsigned; a correct audience consumes exactly once (second -> AlreadyConsumed).
#
# Run:  ruby -Ilib test/test_audience.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'tempfile'
require 'naalp'

include Naalp::CBOR

A_ALG = Naalp::COSE::ALG_MLDSA65               # -49
A_SIGNER = ["5349474e45525f41"].pack("H*")     # "SIGNER_A" (oracle's fixed synthetic signer)
A_AUDIENCE = "consuming-authority-xyz"

def audience_object
  Naalp.object(
    kind: 2, channel: 4, tier: 0, signer: A_SIGNER, created: 1785000000000,
    effect: 2, profile: 1, body: T.new("hello"), audience: A_AUDIENCE
  )
end

def find_envelope_vector
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "envelope", "cases.json")
    return p if File.file?(p)
    d = File.dirname(d)
  end
  nil
end

class AudienceBytesMatchOracle < Minitest::Test
  def test_byte_exact_vs_oracle
    p = find_envelope_vector
    skip "committed oracle vector not present (standalone install)" unless p
    want = JSON.parse(File.read(p, encoding: "utf-8"))["object_with_audience"]
    obj = audience_object
    obj.id = obj.content_id
    payload = Naalp::CBOR.encode(obj.body_map(true))
    prot = Naalp::Envelope.protected_header(A_ALG, A_SIGNER, 1)
    tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
    assert_equal want["content_id_hex"], obj.content_id.unpack1("H*"), "content id"
    assert_equal want["payload_hex"], payload.unpack1("H*"), "payload"
    assert_equal want["protected_hex"], prot.unpack1("H*"), "protected header"
    assert_equal want["tobesigned_hex"], tbs.unpack1("H*"), "to-be-signed"
  end

  def test_omit_when_empty_is_additive
    o = Naalp.object(kind: 2, channel: 4, tier: 0, signer: A_SIGNER, created: 1785000000000,
                     effect: 2, profile: 1, body: T.new("hello"))
    body_hex = Naalp::CBOR.encode(o.body_map(false)).unpack1("H*")
    refute_includes body_hex[-8..], "0d", "no-audience body must not carry field 13 (0x0d)"
    oa = audience_object
    assert Naalp::CBOR.encode(oa.body_map(false)).bytesize > Naalp::CBOR.encode(o.body_map(false)).bytesize
  end
end

class CheckAudienceBranches < Minitest::Test
  def gate_obj(aud)
    Naalp.object(kind: 2, channel: 4, signer: A_SIGNER, created: 0, effect: 0, body: T.new("x"), audience: aud)
  end

  def assert_passes(aud, consume_once)
    assert_nil Naalp::Envelope.check_audience(gate_obj(aud), "authority-A", consume_once)
  end

  def assert_wrong(aud, consume_once)
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp::Envelope.check_audience(gate_obj(aud), "authority-A", consume_once)
    end
    assert_equal "WrongAudience", err.kind
  end

  def test_consume_once_correct_passes;   assert_passes("authority-A", true);  end
  def test_consume_once_foreign_rejected; assert_wrong("authority-B", true);   end
  def test_consume_once_absent_rejected;  assert_wrong("", true);              end
  def test_unrestricted_absent_passes;    assert_passes("", false);            end
  def test_unrestricted_correct_passes;   assert_passes("authority-A", false); end
  def test_unrestricted_foreign_rejected; assert_wrong("authority-B", false);  end
end

class ConsumeObjectAudience < Minitest::Test
  def setup
    @tmp = Tempfile.new(["naalp-audience-ledger", ".wal"])
    @tmp.close
    @ledgers = []
  end

  def teardown
    @ledgers.each { |l| l.close rescue nil }
    @tmp.unlink rescue nil
  end

  def open_ledger(authority)
    led = Naalp::Approval.open_ledger(@tmp.path, authority)
    @ledgers << led
    led
  end

  def obj(aud)
    Naalp.object(kind: 2, channel: 4, signer: A_SIGNER, created: 0, effect: 0, body: T.new("x"), audience: aud)
  end

  def aid
    (0...50).to_a.pack("C*")
  end

  def test_wrong_audience_rejected_no_append
    led = open_ledger("authority-A")
    err = assert_raises(Naalp::Envelope::EnvelopeError) { led.consume_object(obj("authority-B"), aid, "consumer") }
    assert_equal "WrongAudience", err.kind
    assert_equal 0, led.count, "a rejected consume MUST NOT append a ledger entry"
  end

  def test_absent_audience_rejected_no_append
    led = open_ledger("authority-A")
    err = assert_raises(Naalp::Envelope::EnvelopeError) { led.consume_object(obj(""), aid, "consumer") }
    assert_equal "WrongAudience", err.kind
    assert_equal 0, led.count
  end

  def test_correct_audience_consumes_once
    led = open_ledger("authority-A")
    led.consume_object(obj("authority-A"), aid, "consumer")
    assert_equal 1, led.count
    err = assert_raises(Naalp::Approval::ApprovalError) { led.consume_object(obj("authority-A"), aid, "consumer") }
    assert_equal "AlreadyConsumed", err.kind
  end

  def test_unnamed_ledger_refuses
    led = open_ledger("")
    err = assert_raises(Naalp::Approval::ApprovalError) { led.consume_object(obj("authority-A"), aid, "consumer") }
    assert_equal "LedgerUnsigned", err.kind
  end
end
