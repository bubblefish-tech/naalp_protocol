# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# The N-AALP error object and the numeric error-code registry for the Ruby SDK (design.md §3.5,
# R3.3/R3.4, T3.3), ported from impl/go/naalperror/naalperror_test.go (cross-read against the
# byte-identical impl/rust/src/naalperror.rs test module). Pins the registry size/order, the
# hand-computed canonical-CBOR KATs (independent of the oracle and of impl/go/impl/rust), the full
# grammar round-trip, and the two dual-carriage rules: a registered code with a disagreeing name is
# rejected Malformed (the strengthening direction); a code outside the registry is accepted opaque
# (open-registry contract).
#
# Run:  ruby -Ilib -Itest test/test_naalperror.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'naalp'

class NaalperrorTest < Minitest::Test
  # TestRegistrySize: pins the registry to exactly 129 unique names with no gaps (the
  # fields-of-record invariant: code == index+1, sequential 1..129). A mutation that drops or
  # duplicates an entry flips this and the code/name relationship below.
  def test_registry_size_and_index
    names = Naalp::Naalperror::NAMES
    assert_equal 132, names.length
    seen = {}
    names.each_with_index do |n, i|
      refute seen[n], "duplicate name #{n.inspect} at code #{i + 1}"
      seen[n] = true
      code, registered = Naalp::Naalperror.code_for_name(n)
      assert registered, "code_for_name(#{n.inspect}) must be registered"
      assert_equal i + 1, code
    end
  end

  # TestEncodeKAT: pins the deterministic naalp-error body bytes against hand-computed CBOR
  # (independent of the oracle and of impl/go/impl/rust/impl/typescript): a2 (map-2) 01 <code> 02
  # <tstr name>. A mutation of encode flips it.
  def test_encode_kat
    # code 1 (single-byte uint), name "NonCanonical" (12 bytes -> tstr head 0x6c).
    b1 = Naalp::Naalperror.encode(1, "NonCanonical", "", nil)
    assert_equal "a20101026c4e6f6e43616e6f6e6963616c", b1.unpack1("H*")
    # code 52 (>=24 -> two-byte uint 18 34), name "NotDelivered" (12 bytes).
    b2 = Naalp::Naalperror.encode(52, "NotDelivered", "", nil)
    assert_equal "a2011834026c4e6f7444656c697665726564", b2.unpack1("H*")
  end

  # TestEncodeDecodeFull: exercises the optional fields 3 and 4 (map grows to a4, keys stay
  # ascending). A mutation that drops a field or mis-orders keys flips this round-trip.
  def test_encode_decode_full
    code, registered = Naalp::Naalperror.code_for_name("BadSignature")
    assert registered
    subj = ([0x20, 0x30].pack("C*") + ("\x00".b * 48))
    b = Naalp::Naalperror.encode(code, "BadSignature", "reason", subj)
    o = Naalp::Naalperror.decode(b)
    assert_equal "BadSignature", o.name
    assert_equal "reason", o.detail
    assert_equal 50, o.subject.bytesize
  end

  # TestDualCarriageMismatch: a registered code carrying the wrong registered name is rejected
  # Malformed (the strengthening direction). A mutation that skips the name check flips this.
  def test_dual_carriage_mismatch_is_malformed
    code, registered = Naalp::Naalperror.code_for_name("BadSignature") # code 22
    assert registered
    b = Naalp::Naalperror.encode(code, "NotDelivered", "", nil) # code 22, name of code 52
    err = assert_raises(Naalp::Naalperror::Error) { Naalp::Naalperror.decode(b) }
    assert_equal "Malformed", err.kind
  end

  # TestUnknownCodeOpaque: a code outside the registry is accepted opaque (open-registry contract).
  # A mutation that rejects unknown codes flips this.
  def test_unknown_code_is_opaque
    b = Naalp::Naalperror.encode(60000, "SomeFutureError", "", nil)
    o = Naalp::Naalperror.decode(b)
    assert_equal 60000, o.code
    assert_equal "SomeFutureError", o.name
  end

  # TestNameForCode: pins a few known code->name entries + the unregistered boundary.
  def test_name_for_code
    { 1 => "NonCanonical", 22 => "BadSignature", 119 => "RebindUnauthorized" }.each do |code, want|
      name, registered = Naalp::Naalperror.name_for_code(code)
      assert registered, "code #{code} must be registered"
      assert_equal want, name
    end
    [0, 133, 60000].each do |code|
      _name, registered = Naalp::Naalperror.name_for_code(code)
      refute registered, "code #{code} should be unregistered"
    end
  end

  # The exact MANDATORY KATs named in the task: decode of a wrong-name-for-a-registered-code body is
  # rejected Malformed, and decode of an unregistered-code body is accepted opaque.
  def test_mandatory_kats
    assert_equal "a20101026c4e6f6e43616e6f6e6963616c",
                 Naalp::Naalperror.encode(1, "NonCanonical", "", nil).unpack1("H*")
    assert_equal "a2011834026c4e6f7444656c697665726564",
                 Naalp::Naalperror.encode(52, "NotDelivered", "", nil).unpack1("H*")

    b_mismatch = Naalp::Naalperror.encode(22, "NotDelivered", "", nil) # 22=BadSignature, wrong name
    err = assert_raises(Naalp::Naalperror::Error) { Naalp::Naalperror.decode(b_mismatch) }
    assert_equal "Malformed", err.kind

    b_unknown = Naalp::Naalperror.encode(60000, "SomeFutureError", "", nil)
    o = Naalp::Naalperror.decode(b_unknown)
    assert_equal 60000, o.code
  end
end
