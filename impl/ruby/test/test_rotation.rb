# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) known-answer + fail-closed tests
# for the Ruby SDK.
#
# Mutation-surviving properties:
#   1. BYTE PARITY -- sign_rotation_object over the fixed worked fixture reproduces the Go/Rust/
#      oracle bytes: the SHA-256 of the 6798-byte tag-98 object is pinned and equals the Go
#      rotation.sign reference (Ruby == Go == Rust == Python == oracle on the whole two-leg object).
#   2. Round-trip -- verify_rotation_object accepts a co-signed rotation (both legs, old then new).
#   3. Fail-closed reject family -- a tag-18 single-signature rotation, a dropped old leg, a
#      wrong-key old leg, a tag-98 object on a non-rotation (channel,kind), and a Sovereign verifier
#      over a rotation whose OLD key is below the profile floor are ALL rejected with the named kind.
#
# Run:  ruby -Ilib -Itest test/test_rotation.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'digest'
require 'naalp'

include Naalp::CBOR

OLD_SEED = ("\x0B" * 32).b        # old ML-DSA-65 key
NEW_SEED = ("\x16" * 32).b        # new ML-DSA-65 key (go-forward)
FLOOR_OLD_SEED = ("\x21" * 32).b  # below-floor old ML-DSA-65 key (33)
FLOOR_NEW_SEED = ("\x2C" * 32).b  # go-forward ML-DSA-87 key (44)
# SHA-256 of the 6798-byte tag-98 rotation object for the fixed worked fixture; byte-identical to
# the Go rotation.sign reference and tools/rotation_oracle.py (a cross-language, non-circular
# anchor, not a Ruby-only self-check).
ROTATION_OBJECT_SHA256 = "298d5d5bac8a0bf556541784f3090ac7300897858e883dc3ab6e7625bc418194"

ROTATION_SIGNER = "SIGNER_NEW".b
ROTATION_NOT_BEFORE = 1785000000000

# deterministic ML-DSA needs OpenSSL >= 3.5; skip loudly (never a false green) where it is absent.
def rotation_mldsa_available?
  Naalp::COSE.mldsa_keygen("ML-DSA-65", ("\x00" * 32).b)
  true
rescue Exception
  false
end

def rotation_record
  # field-10 naalp-rotation body {1: old_id, 2: new_id, 3: not_before}
  M.new([
    [U.new(1), T.new("signer-old")],
    [U.new(2), T.new("signer-new")],
    [U.new(3), U.new(ROTATION_NOT_BEFORE)],
  ])
end

def rotation_worked_object(profile: Naalp::COSE::PROFILE_PUBLIC)
  Naalp.object(
    kind: 0, channel: 3, signer: ROTATION_SIGNER, created: ROTATION_NOT_BEFORE, effect: 2,
    body: rotation_record, tier: 0, profile: profile
  )
end

def rotation_kind_ok
  ->(ch, k) { ch == 3 && k == 0 }
end

class RotationTest < Minitest::Test
  def setup
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" unless rotation_mldsa_available?
  end

  def test_object_byte_parity_with_reference
    obj = Naalp::Envelope.sign_rotation_object(rotation_worked_object, Naalp::COSE::ALG_MLDSA65, OLD_SEED,
                                               Naalp::COSE::ALG_MLDSA65, NEW_SEED)
    assert_equal 6798, obj.bytesize
    assert_equal ROTATION_OBJECT_SHA256, Digest::SHA256.hexdigest(obj),
                 "rotation object diverged from the Go/Rust/oracle reference bytes"
  end

  def test_roundtrip_accept
    old_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", OLD_SEED)
    new_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", NEW_SEED)
    obj = Naalp::Envelope.sign_rotation_object(rotation_worked_object, Naalp::COSE::ALG_MLDSA65, OLD_SEED,
                                               Naalp::COSE::ALG_MLDSA65, NEW_SEED)
    o = Naalp::Envelope.verify_rotation_object(Naalp::COSE::PROFILE_PUBLIC, Naalp::COSE::ALG_MLDSA65, old_pk,
                                               Naalp::COSE::ALG_MLDSA65, new_pk, rotation_kind_ok, obj)
    assert_equal [3, 0], [o.channel, o.kind]
  end

  def test_tag18_single_sig_rejected
    # a channel-3/kind-0 object signed as a normal single-signature COSE_Sign1 (tag 18) is a
    # rotation missing the old-key co-signature -> the general verify rejects RotationUnauthorized.
    new_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", NEW_SEED)
    obj = Naalp::Envelope.sign(rotation_worked_object, Naalp::COSE::ALG_MLDSA65, NEW_SEED) # tag-18
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, Naalp::COSE::ALG_MLDSA65, new_pk, rotation_kind_ok, obj)
    end
    assert_equal "RotationUnauthorized", err.kind
  end

  def test_old_leg_dropped
    # the mutation anchor: dropping the old leg (one leg) MUST be rejected RotationUnauthorized.
    # Disabling the exactly-two-legs check in verify_rotation_object flips this test.
    old_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", OLD_SEED)
    new_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", NEW_SEED)
    obj = Naalp::Envelope.sign_rotation_object(rotation_worked_object, Naalp::COSE::ALG_MLDSA65, OLD_SEED,
                                               Naalp::COSE::ALG_MLDSA65, NEW_SEED)
    body_prot, payload, legs = Naalp::COSE.parse_sign_raw(obj)
    one_leg = Naalp::COSE.assemble_sign_raw(body_prot, payload, [legs[1]]) # keep only the new leg
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp::Envelope.verify_rotation_object(Naalp::COSE::PROFILE_PUBLIC, Naalp::COSE::ALG_MLDSA65, old_pk,
                                             Naalp::COSE::ALG_MLDSA65, new_pk, rotation_kind_ok, one_leg)
    end
    assert_equal "RotationUnauthorized", err.kind
  end

  def test_old_leg_wrong_key
    # both legs signed by the NEW key -> the trusted old key cannot verify slot 0.
    old_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", OLD_SEED)
    new_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", NEW_SEED)
    obj = Naalp::Envelope.sign_rotation_object(rotation_worked_object, Naalp::COSE::ALG_MLDSA65, NEW_SEED,
                                               Naalp::COSE::ALG_MLDSA65, NEW_SEED)
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp::Envelope.verify_rotation_object(Naalp::COSE::PROFILE_PUBLIC, Naalp::COSE::ALG_MLDSA65, old_pk,
                                             Naalp::COSE::ALG_MLDSA65, new_pk, rotation_kind_ok, obj)
    end
    assert_equal "RotationUnauthorized", err.kind
  end

  def test_non_rotation_kind
    # a tag-98 object built over a non-rotation (channel 4, kind 2) is UnknownKind.
    old_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", OLD_SEED)
    new_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", NEW_SEED)
    o = Naalp::Envelope::Object.new(kind: 2, channel: 4, signer: ROTATION_SIGNER,
                                    created: ROTATION_NOT_BEFORE, effect: 2, body: T.new("hello"),
                                    tier: 0, profile: Naalp::COSE::PROFILE_PUBLIC)
    o.id = o.content_id
    payload = Naalp::CBOR.encode(o.body_map(true))
    body_prot = Naalp::Envelope.protected_header(Naalp::COSE::ALG_MLDSA65, o.signer, o.profile)
    old_leg = Naalp::COSE.signature_leg(body_prot, Naalp::COSE::ALG_MLDSA65, OLD_SEED, payload)
    new_leg = Naalp::COSE.signature_leg(body_prot, Naalp::COSE::ALG_MLDSA65, NEW_SEED, payload)
    obj = Naalp::COSE.assemble_sign_raw(body_prot, payload, [old_leg, new_leg])
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp::Envelope.verify_rotation_object(Naalp::COSE::PROFILE_PUBLIC, Naalp::COSE::ALG_MLDSA65, old_pk,
                                             Naalp::COSE::ALG_MLDSA65, new_pk, ->(c, k) { true }, obj)
    end
    assert_equal "UnknownKind", err.kind
  end

  def test_sovereign_old_leg_floor
    # old=ML-DSA-65 (level 3), new=ML-DSA-87 (level 5), Sovereign floor 5 -> the sub-floor OLD
    # leg yields ProfileDowngrade under the ratified fail-closed default.
    old_pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", FLOOR_OLD_SEED)
    new_pk = Naalp::COSE.mldsa_keygen("ML-DSA-87", FLOOR_NEW_SEED)
    obj = Naalp::Envelope.sign_rotation_object(rotation_worked_object(profile: Naalp::COSE::PROFILE_SOVEREIGN),
                                               Naalp::COSE::ALG_MLDSA65, FLOOR_OLD_SEED,
                                               Naalp::COSE::ALG_MLDSA87, FLOOR_NEW_SEED)
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp::Envelope.verify_rotation_object(Naalp::COSE::PROFILE_SOVEREIGN, Naalp::COSE::ALG_MLDSA65, old_pk,
                                             Naalp::COSE::ALG_MLDSA87, new_pk, rotation_kind_ok, obj)
    end
    assert_equal "ProfileDowngrade", err.kind
  end
end
