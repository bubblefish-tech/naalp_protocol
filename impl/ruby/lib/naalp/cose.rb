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

    # --- COSE_Sign (tag 98) multi-signature support: the §5.2 Rotation object co-signature ---

    TAG_SIGN = 98

    # One COSE_Signature protected header: {1: alg} (RFC 9052 §4).
    def leg_protected(alg)
      Naalp::CBOR.encode(Naalp::CBOR::M.new([[Naalp::CBOR::U.new(1), Naalp::CBOR::N.new(alg)]]))
    end

    # The per-signer COSE_Signature signing input for a COSE_Sign (RFC 9052 §4.4):
    # det-CBOR(["Signature", body_protected, sign_protected, external_aad(empty), payload]). Note the
    # five-element "Signature" structure (with the per-leg sign_protected) vs the four-element
    # "Signature1" of a COSE_Sign1.
    def signature_to_be_signed(body_prot, signer_alg, payload)
      Naalp::CBOR.encode(Naalp::CBOR::A.new([
        Naalp::CBOR::T.new("Signature"),
        Naalp::CBOR::B.new(body_prot),
        Naalp::CBOR::B.new(leg_protected(signer_alg)),
        Naalp::CBOR::B.new("".b),
        Naalp::CBOR::B.new(payload),
      ]))
    end

    # Build one COSE_Signature leg: [leg_protected_bytes, signature_bytes].
    def signature_leg(body_prot, alg, seed, payload)
      sprot = leg_protected(alg)
      sig = mldsa_sign(alg, seed, signature_to_be_signed(body_prot, alg, payload))
      [sprot, sig]
    end

    # The tagged COSE_Sign object: 98([body_prot, {}, payload, [[sprot, {}, sig], ...]]).
    def assemble_sign_raw(body_prot, payload, legs)
      sig_arr = Naalp::CBOR::A.new(legs.map do |(sprot, sig)|
        Naalp::CBOR::A.new([Naalp::CBOR::B.new(sprot), Naalp::CBOR::M.new([]), Naalp::CBOR::B.new(sig)])
      end)
      Naalp::CBOR.encode(Naalp::CBOR::Tag.new(TAG_SIGN, Naalp::CBOR::A.new([
        Naalp::CBOR::B.new(body_prot), Naalp::CBOR::M.new([]), Naalp::CBOR::B.new(payload), sig_arr,
      ])))
    end

    # Recover [body_prot, payload, [[sprot, sig], ...]] from a tagged COSE_Sign object.
    def parse_sign_raw(obj)
      v = Naalp::CBOR.decode(obj)
      unless v.is_a?(Naalp::CBOR::Tag) && v.n == TAG_SIGN && v.content.is_a?(Naalp::CBOR::A)
        raise "not a tagged COSE_Sign"
      end
      arr = v.content.items
      unless arr.length == 4 && arr[0].is_a?(Naalp::CBOR::B) &&
             arr[2].is_a?(Naalp::CBOR::B) && arr[3].is_a?(Naalp::CBOR::A)
        raise "malformed COSE_Sign array"
      end
      legs = arr[3].items.map do |e|
        unless e.is_a?(Naalp::CBOR::A) && e.items.length == 3 &&
               e.items[0].is_a?(Naalp::CBOR::B) && e.items[2].is_a?(Naalp::CBOR::B)
          raise "malformed COSE_Signature leg"
        end
        [e.items[0].v, e.items[2].v]
      end
      [arr[0].v, arr[2].v, legs]
    end

    # Extract the alg (label 1) value from a serialized leg protected header {1: alg}.
    def alg_from_protected(prot)
      # §3.1.1 (R5): reject the redundant 0x41A0 encoding of an empty protected header (a bstr
      # wrapping an empty map; its unwrapped content is the single byte 0xA0) as NonCanonical,
      # before interpreting the header -- the empty protected header is pinned to 0x40.
      if prot.bytesize == 1 && prot.getbyte(0) == 0xA0
        raise Naalp::CBOR::NonCanonical, "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)"
      end
      v = Naalp::CBOR.decode(prot)
      raise "protected header not a map" unless v.is_a?(Naalp::CBOR::M)
      v.pairs.each do |k, val|
        return val.v if k.is_a?(Naalp::CBOR::U) && k.v == 1 && val.is_a?(Naalp::CBOR::N)
      end
      raise "no alg in protected header"
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

    # --- LAMPS opt-in composite signature (alg -65537, design.md §4.2) ---

    ALG_COMPOSITE_65_ED25519 = -65537 # COMPSIG-MLDSA65-Ed25519-SHA512
    ALG_COMPOSITE_44_ED25519 = -65538 # edge; RESERVED, not implemented
    COMPOSITE_PREFIX = "CompositeAlgorithmSignatures2025".b
    COMPOSITE_LABEL_MLDSA65_ED25519 = "COMPSIG-MLDSA65-Ed25519-SHA512".b
    MLDSA65_SIG_SIZE = 3309 # FIPS 204 ML-DSA-65 signature size
    MLDSA65_PUB_SIZE = 1952 # FIPS 204 ML-DSA-65 pubkey size (composite split point)

    # The LAMPS composite message representative M' = Prefix || Label || len(ctx) || ctx ||
    # SHA-512(M) (design.md §4.2). len(ctx) is a single length octet; the N-AALP composite context
    # is empty, so the octet is 0x00. Both legs sign this same M'.
    def compute_mprime(label, ctx, m)
      raise "composite context exceeds one length octet" if ctx.bytesize > 255

      COMPOSITE_PREFIX + label + [ctx.bytesize].pack("C") + ctx + OpenSSL::Digest::SHA512.digest(m)
    end

    # The LAMPS composite signature value over the COSE ToBeSigned tbs: mldsaSig || tradSig
    # (ML-DSA-65 first, raw concatenation; §4.2). The ML-DSA leg is deterministic (rnd=0) with
    # context = the suite Label octets (OpenSSL context-string); the Ed25519 leg signs M' with no
    # context.
    def composite_sign(mldsa_seed, ed_seed, tbs)
      mprime = compute_mprime(COMPOSITE_LABEL_MLDSA65_ED25519, "".b, tbs)
      key = mldsa_key_from_seed("ML-DSA-65", mldsa_seed)
      mldsa_sig = key.sign(nil, mprime,
                           { "deterministic" => 1, "context-string" => COMPOSITE_LABEL_MLDSA65_ED25519 })
      trad_sig = ed25519_sign(ed_seed, mprime)
      mldsa_sig + trad_sig # ML-DSA first (LAMPS order)
    end

    # Valid IFF BOTH the ML-DSA-65 leg (context = Label) and the Ed25519 leg (no context) validate
    # over M'. A value of the wrong length is malformed and rejected. A stripped or re-interpreted
    # lone leg has no valid composite because M' binds both components (RFC 9955; §4.2/§4.5).
    def composite_verify(mldsa_pk, ed_pk, m, sig)
      return false if sig.bytesize != MLDSA65_SIG_SIZE + 64

      mprime = compute_mprime(COMPOSITE_LABEL_MLDSA65_ED25519, "".b, m)
      pub = OpenSSL::PKey.new_raw_public_key("ML-DSA-65", mldsa_pk)
      mldsa_ok = pub.verify(nil, sig[0, MLDSA65_SIG_SIZE], mprime,
                            { "context-string" => COMPOSITE_LABEL_MLDSA65_ED25519 })
      ed_ok = ed25519_verify(ed_pk, mprime, sig[MLDSA65_SIG_SIZE..])
      mldsa_ok && ed_ok
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
