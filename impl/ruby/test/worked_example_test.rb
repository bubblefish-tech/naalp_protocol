# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# The full-object known-answer test: the reference worked object (fixed seed 0x2a*32) MUST be
# reproduced byte-for-byte, and the resulting object MUST verify and reject tampering. When the
# repository's committed vector (vectors/worked/example.json) is present the exact bytes are
# compared; standalone (after a gem install) the crypto round-trip is still checked self-contained.
#
# Run:  ruby -Ilib test/worked_example_test.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

include Naalp::CBOR

SEED = ("\x2a" * 32).b
ALG = Naalp::COSE::ALG_MLDSA65
# short, self-contained KAT anchors (from vectors/worked/example.json)
SIGNER_ID = "bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua"
CONTENT_ID_HEX = "2030192922f9be80623bea1c689ddfe91dc15303abc851c8811b86cf9e53b837b5cc99d9c17e3acf95279f55e48203f79134"
ARGS_ID_HEX = "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff"

# deterministic ML-DSA needs OpenSSL >= 3.5; skip loudly (never a false green) where it is absent.
def mldsa_available?
  Naalp::COSE.mldsa_keygen("ML-DSA-65", ("\x00" * 32).b)
  true
rescue Exception
  false
end

def worked_object
  pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", SEED)
  signer_id = Naalp::Identity.signer_id(ALG, pk)
  body = M.new([
    [U.new(1), B.new([ARGS_ID_HEX].pack("H*"))],
    [U.new(2), T.new(signer_id)],
    [U.new(3), U.new(2)],
    [U.new(4), B.new([1, 2, 3, 4, 5, 6, 7, 8].pack("C*"))],
    [U.new(5), U.new(1785000000000)],
  ])
  obj = Naalp.object(
    kind: 1, channel: 4, tier: 0, signer: signer_id.b,
    created: 1785000000000, effect: 2, profile: Naalp::COSE::PROFILE_PUBLIC, body: body
  )
  [pk, signer_id, obj]
end

def find_vector
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "worked", "example.json")
    return p if File.file?(p)
    d = File.dirname(d)
  end
  nil
end

class WorkedExample < Minitest::Test
  def setup
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" unless mldsa_available?
  end

  def test_signer_and_content_id
    _pk, signer_id, obj = worked_object
    assert_equal SIGNER_ID, signer_id
    assert_equal CONTENT_ID_HEX, obj.content_id.unpack1("H*")
  end

  def test_sign_verify_roundtrip
    pk, _sid, obj = worked_object
    signed = Naalp.sign(obj, ALG, SEED)
    got = Naalp.verify(Naalp::COSE::PROFILE_PUBLIC, ALG, pk, ->(c, k) { [c, k] == [4, 1] }, signed)
    assert_equal [1, 4, 2], [got.kind, got.channel, got.effect]
  end

  def test_tamper_rejected
    pk, _sid, obj = worked_object
    signed = Naalp.sign(obj, ALG, SEED).dup
    signed.setbyte(signed.bytesize - 1, signed.getbyte(signed.bytesize - 1) ^ 1)
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp.verify(Naalp::COSE::PROFILE_PUBLIC, ALG, pk, ->(c, k) { true }, signed)
    end
    assert_equal "BadSignature", err.kind
  end

  def test_byte_exact_vs_committed_vector
    p = find_vector
    skip "committed vector not present (standalone install)" unless p
    want = JSON.parse(File.read(p, encoding: "utf-8"))
    _pk, _sid, obj = worked_object
    assert_equal want["signed_object_hex"], Naalp.sign(obj, ALG, SEED).unpack1("H*")
    assert_equal want["content_id_hex"], obj.content_id.unpack1("H*")
  end
end
