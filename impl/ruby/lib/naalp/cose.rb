# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C2 signing layer for the Ruby SDK: the COSE_Sign1 (RFC 9052) signing-input and
# object assembly, plus deterministic ML-DSA (FIPS 204, rnd=0) and Ed25519 (RFC 8032).
#
# The deterministic ML-DSA path uses the platform OpenSSL (>= 3.5) ML-DSA provider with the
# signature parameter deterministic=1 (which fixes the FIPS 204 rnd to 32 zero bytes) and a
# seed-only PKCS#8 private key (the [0] seed CHOICE), producing signatures and public keys
# byte-identical to the Go (CIRCL), Rust (fips204) and Python (dilithium-py) references —
# cross-checked against the shared conformance corpus and the NIST ACVP keyGen vectors.
require 'openssl'
require_relative 'cbor'

module Naalp
  module COSE
    include Naalp::CBOR

    ALG_MLDSA65 = -49
    ALG_MLDSA87 = -50
    ALG_ED25519 = -19

    PROFILE_PUBLIC = 1
    PROFILE_ENTERPRISE = 2
    PROFILE_SOVEREIGN = 3

    TAG_SIGN1 = 18

    # DER of the AlgorithmIdentifier SEQUENCE { OID } per parameter set (no params).
    MLDSA_OID_DER = {
      "ML-DSA-65" => ["300b0609608648016503040312"].pack("H*"),
      "ML-DSA-87" => ["300b0609608648016503040313"].pack("H*"),
    }.freeze
    ALG_TO_PARAM = { ALG_MLDSA65 => "ML-DSA-65", ALG_MLDSA87 => "ML-DSA-87" }.freeze

    module_function

    # NIST security level of a registered alg, and whether it is registered. Ed25519 is
    # classical (level 0), valid only as a hybrid leg. Returns [level, known].
    def alg_level(alg)
      case alg
      when ALG_MLDSA87 then [5, true]
      when ALG_MLDSA65 then [3, true]
      when ALG_ED25519 then [0, true]
      else [0, false]
      end
    end

    # Minimum signature level a profile accepts (Sovereign floors at level 5; else 3).
    def profile_min_level(profile)
      profile == PROFILE_SOVEREIGN ? 5 : 3
    end

    def to_be_signed_raw(protected_bytes, payload)
      Naalp::CBOR.encode(
        Naalp::CBOR::A.new([
          Naalp::CBOR::T.new("Signature1"),
          Naalp::CBOR::B.new(protected_bytes),
          Naalp::CBOR::B.new("".b),
          Naalp::CBOR::B.new(payload),
        ])
      )
    end

    def assemble_sign1_raw(protected_bytes, payload, sig)
      Naalp::CBOR.encode(
        Naalp::CBOR::Tag.new(TAG_SIGN1, Naalp::CBOR::A.new([
          Naalp::CBOR::B.new(protected_bytes),
          Naalp::CBOR::M.new([]),
          Naalp::CBOR::B.new(payload),
          Naalp::CBOR::B.new(sig),
        ]))
      )
    end

    def parse_sign1_raw(obj)
      v = Naalp::CBOR.decode(obj)
      unless v.is_a?(Naalp::CBOR::Tag) && v.n == TAG_SIGN1 && v.content.is_a?(Naalp::CBOR::A)
        raise "not a tagged COSE_Sign1"
      end
      arr = v.content.items
      unless arr.length == 4 && arr[0].is_a?(Naalp::CBOR::B) &&
             arr[2].is_a?(Naalp::CBOR::B) && arr[3].is_a?(Naalp::CBOR::B)
        raise "malformed COSE_Sign1 array"
      end
      [arr[0].v, arr[2].v, arr[3].v]
    end

    # --- ML-DSA (FIPS 204) via OpenSSL ---

    # Build a seed-only PKCS#8 (OneAsymmetricKey) DER for an ML-DSA private key: the privateKey
    # OCTET STRING wraps the [0] IMPLICIT seed CHOICE (0x80 0x20 || 32-byte seed).
    def mldsa_seed_der(param, seed)
      raise "ml-dsa seed must be 32 bytes" if seed.bytesize != 32
      algid = MLDSA_OID_DER[param] or raise "unknown ML-DSA parameter set #{param}"
      seed_choice = [0x80, 0x20].pack("C*") + seed
      priv_os = [0x04, seed_choice.bytesize].pack("C*") + seed_choice
      inner = [0x02, 0x01, 0x00].pack("C*") + algid + priv_os
      [0x30, inner.bytesize].pack("C*") + inner
    end

    def mldsa_key_from_seed(param, seed)
      OpenSSL::PKey.read(mldsa_seed_der(param, seed))
    end

    def mldsa_keygen(param, seed)
      mldsa_key_from_seed(param, seed).raw_public_key
    end

    def mldsa_sign(alg, seed, tbs)
      param = ALG_TO_PARAM[alg] or raise "alg #{alg} is not an ML-DSA algorithm"
      key = mldsa_key_from_seed(param, seed)
      key.sign(nil, tbs, { "deterministic" => 1 })
    end

    def mldsa_verify(alg, pk, tbs, sig)
      param = ALG_TO_PARAM[alg] or raise "alg #{alg} is not an ML-DSA algorithm"
      pub = OpenSSL::PKey.new_raw_public_key(param, pk)
      pub.verify(nil, sig, tbs)
    end

    # --- Ed25519 (RFC 8032) via OpenSSL ---

    def ed25519_sign(seed, msg)
      raise "ed25519 secret key must be a 32-byte seed" if seed.bytesize != 32
      OpenSSL::PKey.new_raw_private_key("ED25519", seed).sign(nil, msg)
    end

    def ed25519_verify(pk, msg, sig)
      OpenSSL::PKey.new_raw_public_key("ED25519", pk).verify(nil, sig, msg)
    rescue OpenSSL::PKey::PKeyError
      false
    end

    def cose_sign1(alg, seed, protected_bytes, payload)
      tbs = to_be_signed_raw(protected_bytes, payload)
      sig = mldsa_sign(alg, seed, tbs)
      assemble_sign1_raw(protected_bytes, payload, sig)
    end

    # Verify a raw signature over already-assembled ToBeSigned bytes, dispatching by alg.
    def cose_verify1_raw(alg, pk, tbs, sig)
      case alg
      when ALG_MLDSA65, ALG_MLDSA87
        mldsa_verify(alg, pk, tbs, sig)
      when ALG_ED25519
        ed25519_verify(pk, tbs, sig)
      else
        raise "unknown alg #{alg}"
      end
    end

    def cose_verify1(alg, pk, obj)
      protected_bytes, payload, sig = parse_sign1_raw(obj)
      tbs = to_be_signed_raw(protected_bytes, payload)
      cose_verify1_raw(alg, pk, tbs, sig)
    end
  end
end
