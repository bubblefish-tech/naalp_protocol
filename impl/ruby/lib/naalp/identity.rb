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
  end
end
