# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C4 identity for the Ruby SDK: the self-certifying signer id (§5.1) and the NFC rule.
#
# signer id = multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))),
# identical in form to the N-PAMP PeerHandle. Multicodec codes are from the multiformats
# registry: ed25519-pub 0xed, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212; multihash sha2-256 0x12.
require 'openssl'
require_relative 'cose'

module Naalp
  module Identity
    class UnknownAlg < StandardError
      def kind; "UnknownAlg"; end
    end
    class SignerMismatch < StandardError
      def kind; "SignerMismatch"; end
    end
    class NonNFC < StandardError
      def kind; "NonNFC"; end
    end

    MULTICODEC = {
      Naalp::COSE::ALG_ED25519 => 0xED,
      Naalp::COSE::ALG_MLDSA65 => 0x1211,
      Naalp::COSE::ALG_MLDSA87 => 0x1212,
    }.freeze
    MH_SHA256 = 0x12

    # RFC 4648 base32, lowercase alphabet, no padding.
    B32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567".freeze

    module_function

    def uvarint(n)
      out = []
      loop do
        b = n & 0x7F
        n >>= 7
        if n != 0
          out << (b | 0x80)
        else
          out << b
          break
        end
      end
      out.pack("C*")
    end

    def base32_lower_nopad(data)
      value = 0
      bits = 0
      out = +""
      data.each_byte do |b|
        value = (value << 8) | b
        bits += 8
        while bits >= 5
          out << B32_ALPHABET[(value >> (bits - 5)) & 31]
          bits -= 5
        end
      end
      out << B32_ALPHABET[(value << (5 - bits)) & 31] if bits > 0
      out
    end

    def signer_id(alg, pubkey)
      mc = MULTICODEC[alg]
      raise UnknownAlg, "no multicodec for alg #{alg}" if mc.nil?
      tagged = uvarint(mc) + pubkey.dup.force_encoding(Encoding::BINARY)
      digest = OpenSSL::Digest::SHA256.digest(tagged)
      mh = uvarint(MH_SHA256) + uvarint(digest.bytesize) + digest
      "b" + base32_lower_nopad(mh)
    end

    # The self-certifying signer id for a composite key pair (§5.1). The SHA-256 preimage is the
    # multicodec-tagged ML-DSA public key concatenated with the multicodec-tagged Ed25519 public
    # key -- using only existing official multicodecs (no minted code) -- so stripping or
    # substituting either leg changes the id (=> SignerMismatch before verify). Downgrade-resistant.
    def composite_signer_id(mldsa_alg, mldsa_pub, ed_pub)
      unless [Naalp::COSE::ALG_MLDSA65, Naalp::COSE::ALG_MLDSA87].include?(mldsa_alg)
        raise UnknownAlg, "composite signer id requires an ML-DSA alg, got #{mldsa_alg}"
      end
      preimage = uvarint(MULTICODEC[mldsa_alg]) + mldsa_pub.dup.force_encoding(Encoding::BINARY) +
                 uvarint(MULTICODEC[Naalp::COSE::ALG_ED25519]) + ed_pub.dup.force_encoding(Encoding::BINARY)
      digest = OpenSSL::Digest::SHA256.digest(preimage)
      mh = uvarint(MH_SHA256) + uvarint(digest.bytesize) + digest
      "b" + base32_lower_nopad(mh)
    end

    def check_signer(claimed, alg, pubkey)
      unless signer_id(alg, pubkey) == claimed
        raise SignerMismatch, "signer id does not recompute from the key"
      end
    end

    def require_nfc(s)
      s = s.dup.force_encoding(Encoding::UTF_8)
      raise NonNFC, "string is not valid UTF-8" unless s.valid_encoding?
      raise NonNFC, "string is not Unicode NFC" unless s.unicode_normalize(:nfc) == s
    end

    # ---- key rotation (design §5.2): the co-signed old->new link ------------------------------
    #
    # ADDITIVE (draft-01, C4 rotation primitive; zero edits to the existing C4 surface above). The
    # self-certifying signer id survives a key rotation: a RotationRecord binds the old id to the new id
    # from a not_before position, co-signed by BOTH keys, so attribution to the durable identity is
    # preserved across rotation (R-1.4). This is the C4 primitive the Delivery-Model-B principal
    # registry (Naalp::Rooms) composes on for a rotation-authorised rebind, exactly as the Go reference
    # places SignRotation/VerifyRotation in identity (impl/go/identity §128) and the Python port places
    # them in identity.py.

    # A named, fail-closed rotation error; #kind is the stable "RotationUnauthorized" kind (§5.2, §5.5).
    class RotationUnauthorized < StandardError
      def kind; "RotationUnauthorized"; end
    end

    # Links an old signer id to a new one from `not_before` (§5.2). Its signed bytes are the
    # deterministic-CBOR map {1: old, 2: new, 3: not_before}.
    RotationRecord = Struct.new(:old, :new, :not_before) do
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::T.new(old)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::T.new(new)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(not_before)],
        ]))
      end
    end

    # Co-sign a rotation with BOTH the old and new keys (§5.2): each leg is a raw deterministic ML-DSA
    # signature over the rotation body. Returns [old_sig, new_sig].
    def sign_rotation(r, alg, old_seed, new_seed)
      m = r.bytes
      [Naalp::COSE.mldsa_sign(alg, old_seed, m), Naalp::COSE.mldsa_sign(alg, new_seed, m)]
    end

    # Confirm a rotation is authorized (§5.2, §5.5): the old and new keys derive the ids in the record
    # AND both signatures verify. Any failure -- an id that does not recompute from its key or a
    # signature that does not verify -- is RotationUnauthorized (fail-closed). A substitution not
    # co-signed by the old key cannot pass, so the durable id cannot be hijacked to an unrelated key.
    def verify_rotation(r, old_alg, old_pub, new_alg, new_pub, old_sig, new_sig)
      begin
        raise RotationUnauthorized, "old key does not derive the record's old id" if signer_id(old_alg, old_pub) != r.old
        raise RotationUnauthorized, "new key does not derive the record's new id" if signer_id(new_alg, new_pub) != r.new
      rescue UnknownAlg
        raise RotationUnauthorized, "rotation names an unregistered algorithm"
      end
      m = r.bytes
      unless Naalp::COSE.cose_verify1_raw(old_alg, old_pub, m, old_sig) &&
             Naalp::COSE.cose_verify1_raw(new_alg, new_pub, m, new_sig)
        raise RotationUnauthorized, "a rotation signature does not verify under its key"
      end
      nil
    rescue OpenSSL::PKey::PKeyError
      raise RotationUnauthorized, "a rotation signature does not verify under its key"
    end

    # ---- revocation, foreign-identity linkage, durable thread (design §5.3/§5.4, R-1.4) --------
    #
    # ADDITIVE ENVELOPE-adjacent RECORD + THREAD surfaces, ported byte-for-byte from the Go/Rust
    # reference (impl/go/identity, impl/rust/src/identity.rs) and matching the already-landed
    # csharp/Identity.cs port: RevocationRecord, VerifyRevocation, RevokedAt, ForeignLinkRecord,
    # VerifyForeignLink, RotationEvidence, Thread, Thread#attributable, resolve_thread.

    # A named, fail-closed signature error; #kind is the stable "BadSignature" kind, reused from
    # the C2 cose layer's naming convention (the same string every other Ruby module raises on a
    # signature that fails to verify).
    class BadSignature < StandardError
      def kind; "BadSignature"; end
    end

    # Marks a key dead from `not_after` (§5.3). Signed bytes: deterministic-CBOR {1: key, 2: not_after}.
    RevocationRecord = Struct.new(:key, :not_after) do
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::T.new(key)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(not_after)],
        ]))
      end
    end

    # Confirms a revocation is validly signed (§5.3): by the key it revokes, or by a
    # deployer-configured recovery key. `recovery_ids` is the deployer's set of authorized
    # recovery-key signer ids; a revocation whose signer is neither `r.key` nor a member of
    # `recovery_ids` is rejected SignerMismatch (§5.5), fail-closed -- an empty `recovery_ids`
    # admits only the revoked key itself. The signer id is recomputed from the presented key and
    # checked BEFORE the signature (membership before signature, fail-closed). `UnknownAlg` from
    # the id recompute propagates unchanged.
    def verify_revocation(r, alg, pub, sig, recovery_ids)
      id = signer_id(alg, pub) # UnknownAlg propagates unchanged
      authorized = (id == r.key) || recovery_ids.include?(id)
      raise SignerMismatch, "signer id is neither the revoked key nor an authorized recovery key" unless authorized
      raise BadSignature, "signature verification failed" unless Naalp::COSE.cose_verify1_raw(alg, pub, r.bytes, sig)
      nil
    end

    # Reports whether an object fixed at authoritative position `pos_time` is after the
    # revocation (i.e. revoked); objects fixed at or before not_after stay valid (§5.3).
    def revoked_at(r, pos_time)
      pos_time > r.not_after
    end

    # Cross-signs a foreign identity to a signer id (§5.4). Signed bytes: deterministic-CBOR
    # {1: controls, 2: foreign_id, 3: not_after}. It is signed by the FOREIGN identity's key.
    ForeignLinkRecord = Struct.new(:controls, :foreign_id, :not_after) do
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::T.new(controls)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::T.new(foreign_id)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(not_after)],
        ]))
      end
    end

    # Reports whether a foreign-identity link confers linkage at time `now`. A non-NFC
    # foreign_id is rejected (NonNFC), checked first. An expired link or a bad cross-signature
    # confers NO linkage but is not itself an error -- it simply does not link (the object
    # remains valid on its own signature, §5.4/§5.5). It NEVER overrides the key-derived id.
    def verify_foreign_link(r, foreign_alg, foreign_pub, sig, now)
      require_nfc(r.foreign_id)
      return false if now > r.not_after # expired: confers no authority (ignored)
      return false unless Naalp::COSE.cose_verify1_raw(foreign_alg, foreign_pub, r.bytes, sig) # bad/absent cross-signature: no linkage
      true
    end

    # ---- durable identity thread (rotation-surviving attribution, R-1.4) -------------------------

    # One verified rotation step: the record plus the two keys (alg, pubkey) and their co-signatures.
    RotationEvidence = Struct.new(:record, :old_alg, :old_pub, :new_alg, :new_pub, :old_sig, :new_sig)

    # A durable identity: a root signer id continued by a chain of rotations.
    Thread = Struct.new(:root, :current, :chain) do
      # Reports whether an object whose body signer id is `signer` belongs to this durable
      # thread (any id in the chain, including a pre-rotation key, R-1.4).
      def attributable(signer)
        chain.include?(signer)
      end
    end

    # Verifies an ordered rotation chain and returns the durable identity thread. Each rotation
    # must be authorized (co-signed) and link the previous `new` to the next `old`; a break
    # yields RotationUnauthorized. A receipt signed under any id in chain is attributable to
    # root, so it stays attributable after rotation (R-1.4).
    def resolve_thread(evs)
      raise RotationUnauthorized, "empty rotation-evidence chain" if evs.empty?
      root = evs[0].record.old
      chain = [root]
      prev_new = root
      evs.each do |e|
        raise RotationUnauthorized, "rotation chain is not contiguous" if e.record.old != prev_new
        verify_rotation(e.record, e.old_alg, e.old_pub, e.new_alg, e.new_pub, e.old_sig, e.new_sig)
        chain << e.record.new
        prev_new = e.record.new
      end
      Thread.new(root, prev_new, chain)
    end
  end
end
