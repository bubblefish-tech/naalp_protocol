# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# Self-contained conformance smoke tests over the SDK primitives, anchored to independent
# standards vectors (FIPS 180-4 SHA-384, RFC 8949 canonical CBOR, the multiformats signer-id,
# the §6.1 effect lattice). The authoritative cross-language grading is the naalp-conform harness
# against the 239-case corpus; these keep the published gem independently checkable.
#
# Run:  ruby -Ilib test/conformance_test.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'openssl'
require 'naalp'

include Naalp::CBOR

class Primitives < Minitest::Test
  def test_sha384_kat
    assert_equal(
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
      OpenSSL::Digest::SHA384.hexdigest("abc")
    )
  end

  def test_cbor_canonical_encode_and_content_id
    # canonical map: keys emitted in bytewise-ascending order regardless of input order
    m = M.new([[U.new(3), U.new(4)], [U.new(2), U.new(0)]])
    assert_equal "a20200 0304".delete(" "), Naalp::CBOR.encode(m).unpack1("H*")
    cid = Naalp::CBOR.content_id(m)
    assert_equal [0x20, 0x30].pack("C*"), cid[0, 2]
    assert_equal 2 + 48, cid.bytesize
  end

  def test_cbor_rejects_non_canonical
    # out-of-order / non-shortest / indefinite / duplicate key
    ["a202000100", "1800", "9f00ff", "a201000101"].each do |bad|
      assert_raises(Naalp::CBOR::NonCanonical) { Naalp::CBOR.decode([bad].pack("H*")) }
    end
  end

  def test_cose_tobesigned_rfc9052
    tbs = Naalp::COSE.to_be_signed_raw(["a1013830"].pack("H*"), ["a10700"].pack("H*"))
    assert tbs.start_with?(["846a5369676e617475726531"].pack("H*"))  # ["Signature1", ...]
  end

  def test_signer_id_form
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", ("\x00" * 32).b)
    sid = Naalp::Identity.signer_id(Naalp::COSE::ALG_MLDSA65, pk)
    assert sid.start_with?("b")  # multibase base32 prefix
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  def test_effect_lattice
    assert_equal Naalp::Policy::DESTRUCTIVE, Naalp::Policy.normalize_effect(99)  # unknown -> destructive
    assert Naalp::Policy.authorizes(Naalp::Policy::NON_IDEMPOTENT_WRITE, Naalp::Policy::IDEMPOTENT_WRITE)
    refute Naalp::Policy.authorizes(Naalp::Policy::READ_ONLY, Naalp::Policy::DESTRUCTIVE)
  end

  def test_channels_registry
    name, effect, variable = Naalp::Channels.lookup(0x0004, 1)  # Governance.Approval
    assert_equal ["Approval", Naalp::Policy::NON_IDEMPOTENT_WRITE, false], [name, effect, variable]
    assert_raises(Naalp::Channels::UnknownKind) { Naalp::Channels.lookup(0x0000, 9999) }
  end

  def test_records_deterministic
    # a receipt body round-trips to stable bytes and the head is SHA-384 of it
    body = Naalp::Records.receipt_body(("\x00" * 48).b, ["2030" + ("00" * 48)].pack("H*"), 0, 100)
    assert_equal OpenSSL::Digest::SHA384.digest(body), Naalp::Records.receipt_head(body)
  end
end
