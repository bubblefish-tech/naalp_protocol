# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C21 (task 5B.1) NAALP-PAY payment import for the Ruby SDK (design.md §24; R-PAY-1..6).
#
# NAALP-PAY imports a foreign payment payload -- an AP2 mandate, an Agentic Commerce Protocol
# delegated token, an x402 payload -- octet-for-octet as OPAQUE foreign bytes (carriage, not
# adoption): the foreign bytes are never re-serialized, canonicalized, or rewritten, and a foreign
# identity inside them never becomes an N-AALP authorization identity. It introduces NO new envelope,
# encoding, signature, identity, effect, or ledger mechanism: the imported payload becomes a
# value-bearing charge that N-AALP governs with its OWN added guarantees, reusing the closed C5 effect
# lattice (Naalp::Policy). There is NO fifth effect and NO payment-specific ledger.
#
# The added guarantees over the imported formats:
#
#   - PaymentImport {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign} is the
#     wrapper body. `format` selects the imported FORMAT from the closed payment-format registry;
#     `foreign` carries the imported payload octet-for-octet. An unknown format is rejected
#     (UnknownPaymentFormat).
#   - THE CHARGE IS BOUND. ChargeBinding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
#     6: foreign_id} names the exact value a §7 approval binds by content id -- including the foreign
#     payload's content id (the carriage binding). A wrong-amount, wrong-payee, wrong-currency, or
#     substituted-payload charge yields a different content id and no longer matches the approval.
#
# Every check is fail-closed (§15): a failing charge is rejected whole and returns its named error.
#
# Ported from impl/go/payment (cross-read against impl/python/naalp/payment.py). The PaymentImport
# SIGNATURE is a bare-{1:alg} COSE_Sign1 (as the reference's cose.Sign1) with real deterministic
# ML-DSA. Graded against vectors/payment/cases.json.
#
# AuthorizeCharge (design.md §24) composes the EXISTING §7 approval object + single-use consume
# ledger (Naalp::Approval) UNCHANGED, exactly as impl/go/payment.AuthorizeCharge: it binds the exact
# charge by content id (Naalp::Approval.verify_approval), requires the approval's granted effect to
# cover the charge (Naalp::Policy.authorizes), and spends the approval single-use through
# Naalp::Approval::Ledger#consume (AlreadyConsumed on replay). There is NO payment-specific ledger.
# The signed/consume path is demonstrated in isolation (the corpus carries no signed or consume
# vector for this surface); the value-bearing binding property IS corpus-graded via the mismatch
# content-ids (test_charge_binding_mismatch_ids) that AuthorizeCharge's approval binding rejects.
require 'openssl'
require_relative 'cbor'
require_relative 'cose'
require_relative 'policy'
require_relative 'approval'

module Naalp
  module Payment
    # The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
    HEAD_SIZE = 48

    # The C5 effect a payment spend carries: a non_idempotent_write. A charge is value-bearing and not
    # safely repeatable, which is why it is spent single-use through the §7 ledger.
    CHARGE_EFFECT = Naalp::Policy::NON_IDEMPOTENT_WRITE

    # Payment format codes (design §24; the closed payment-format registry). A code outside the closed
    # set is rejected (UnknownPaymentFormat).
    FORMAT_AP2_MANDATE = 1 # AP2 mandate
    FORMAT_ACP_TOKEN   = 2 # Agentic Commerce Protocol delegated token
    FORMAT_X402        = 3 # x402 payload

    FORMAT_NAMES = {
      FORMAT_AP2_MANDATE => "ap2-mandate",
      FORMAT_ACP_TOKEN => "acp-delegated-token",
      FORMAT_X402 => "x402-payload",
    }.freeze

    # A named, fail-closed payment error; #kind is the stable error kind (§15).
    class PayError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # Wraps a foreign payment payload as a value-bearing charge. Format selects the imported format
    # (closed registry); Amount/Currency/Payee/NotAfter are the bound charge terms; Foreign is the
    # imported payload carried octet-for-octet (carriage, not adoption).
    PaymentImport = Struct.new(:format, :amount, :currency, :payee, :not_after, :foreign) do
      # Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
      # 6: foreign}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(format)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(amount)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::T.new(currency)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new(payee)],
          [Naalp::CBOR::U.new(5), Naalp::CBOR::U.new(not_after)],
          [Naalp::CBOR::U.new(6), Naalp::CBOR::B.new(foreign)],
        ]))
      end

      # The SHA-384 head (48 octets).
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The T1 content-id (50 octets): multihash(0x20, SHA-384(body)).
      def id
        Naalp::CBOR.content_id(bytes)
      end

      # The T1 content-id of the carried foreign payload -- the hash the charge binding binds (the
      # carriage binding). A substituted payload yields a different foreign_id.
      def foreign_id
        Naalp::CBOR.content_id(foreign.dup.force_encoding(Encoding::BINARY))
      end

      # The exact charge value an approval binds for this import (amount + currency + payee + expiry +
      # the foreign payload's content id). A change to any bound term -- including the foreign payload
      # -- changes the binding's content id.
      def charge_binding
        ChargeBinding.new(format, amount, currency, payee, not_after, foreign_id)
      end
    end

    # Names the exact charge by value: format, amount, currency, payee, expiry, and the foreign
    # payload's content id. A §7 approval binds THIS binding's content id, so a change to any bound
    # term invalidates a prior approval (ApprovalMismatch).
    ChargeBinding = Struct.new(:format, :amount, :currency, :payee, :not_after, :foreign_id) do
      # Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
      # 6: foreign_id}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(format)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(amount)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::T.new(currency)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new(payee)],
          [Naalp::CBOR::U.new(5), Naalp::CBOR::U.new(not_after)],
          [Naalp::CBOR::U.new(6), Naalp::CBOR::B.new(foreign_id)],
        ]))
      end

      # The SHA-384 head (48 octets).
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The charge content id an approval binds: multihash(0x20, SHA-384(binding)).
      def content_id
        Naalp::CBOR.content_id(bytes)
      end
    end

    module_function

    # Whether code is one of the closed payment formats.
    def registered_format?(code)
      FORMAT_NAMES.key?(code)
    end

    # The registry name of a format code, or 'unknown'.
    def format_name(code)
      FORMAT_NAMES.fetch(code, "unknown")
    end

    # Return the value of map key k if it is present with type typ, else nil.
    def field(m, k, typ)
      m.pairs.each do |key, val|
        if key.is_a?(Naalp::CBOR::U) && key.v == k
          return val.is_a?(typ) ? val : nil
        end
      end
      nil
    end

    # Reconstruct a PaymentImport from its body bytes alone. Does NOT validate the format against the
    # closed set (that is verify_payment_import's job), so an import carrying an unknown format can be
    # represented (then rejected). Fail-closed on a malformed shape or a non-canonical encoding.
    def parse_payment_import(b)
      begin
        v = Naalp::CBOR.decode(b) # the strict decoder rejects a non-canonical body (NonCanonical)
      rescue Naalp::CBOR::NonCanonical => e
        raise PayError.new("PayMalformed", "non-canonical payment-import body: #{e}")
      end
      raise PayError.new("PayMalformed", "payment import is not a map") unless v.is_a?(Naalp::CBOR::M)
      fmt = field(v, 1, Naalp::CBOR::U)
      amt = field(v, 2, Naalp::CBOR::U)
      cur = field(v, 3, Naalp::CBOR::T)
      payee = field(v, 4, Naalp::CBOR::B)
      na = field(v, 5, Naalp::CBOR::U)
      foreign = field(v, 6, Naalp::CBOR::B)
      if [fmt, amt, cur, payee, na, foreign].any?(&:nil?)
        raise PayError.new("PayMalformed", "object is not a well-formed N-AALP payment-import body")
      end
      PaymentImport.new(fmt.v, amt.v, cur.v, payee.v, na.v, foreign.v)
    end

    # The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int).
    def protected_header(alg)
      Naalp::CBOR.encode(Naalp::CBOR::M.new([[Naalp::CBOR::U.new(1), Naalp::CBOR::N.new(alg)]]))
    end

    # Read the alg (label 1) value from an encoded protected header.
    def alg_from_protected(prot)
      v = Naalp::CBOR.decode(prot)
      raise PayError.new("PayMalformed", "protected header is not a map") unless v.is_a?(Naalp::CBOR::M)
      v.pairs.each do |k, val|
        if k.is_a?(Naalp::CBOR::U) && k.v == 1 && (val.is_a?(Naalp::CBOR::N) || val.is_a?(Naalp::CBOR::U))
          return val.v
        end
      end
      raise PayError.new("PayMalformed", "protected header has no alg")
    end

    # Produce the tagged COSE_Sign1 object over the PaymentImport body with a real deterministic ML-DSA
    # key derived from seed.
    def sign_payment_import(p, alg, seed)
      prot = protected_header(alg)
      payload = p.bytes
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      sig = Naalp::COSE.mldsa_sign(alg, seed, tbs)
      Naalp::COSE.assemble_sign1_raw(prot, payload, sig)
    end

    # Verify the import's full signature under the profile, reconstruct it from the signed body bytes,
    # and validate the format against the closed registry. Check order (fail-closed): PayMalformed ->
    # UnknownAlg -> ProfileDowngrade -> KeyAlgMismatch -> BadSignature -> parse -> UnknownPaymentFormat.
    # Returns the PaymentImport on success.
    def verify_payment_import(obj, profile, alg, pubkey)
      begin
        prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj)
      rescue StandardError => e
        raise PayError.new("PayMalformed", "not a tagged COSE_Sign1: #{e}")
      end
      halg = alg_from_protected(prot)
      level, known = Naalp::COSE.alg_level(halg)
      raise PayError.new("UnknownAlg", "algorithm id not in the N-AALP registry") unless known
      raise PayError.new("ProfileDowngrade", "signature level below the profile minimum") if level < Naalp::COSE.profile_min_level(profile)
      raise PayError.new("KeyAlgMismatch", "key algorithm does not match object header") if halg != alg
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      raise PayError.new("BadSignature", "signature verification failed") unless Naalp::COSE.cose_verify1_raw(halg, pubkey, tbs, sig)
      p = parse_payment_import(payload)
      unless registered_format?(p.format)
        raise PayError.new("UnknownPaymentFormat", "payment import selects a format outside the closed payment-format registry")
      end
      p
    end

    # ---- the per-charge approval gate (reuses §7 approval + consume ledger) ---------------------

    # AuthorizeCharge enforces the value-bearing rule for an imported payment, reusing the §7 approval
    # and single-use consume ledger UNCHANGED (Naalp::Approval), exactly as impl/go/payment.go:241
    # AuthorizeCharge. The approval MUST bind the EXACT charge binding content id (format + amount +
    # currency + payee + expiry + foreign_id) -- so it satisfies neither a different
    # amount/payee/currency nor a substituted foreign payload (ApprovalMismatch, from
    # Naalp::Approval.verify_approval) -- its granted effect must cover the charge's CHARGE_EFFECT (a
    # non_idempotent_write), it must be unexpired at `now`, and it is consumed single-use by `by`
    # through the §7 ledger. Precedence and fail-closed behaviour mirror the spine: an unknown format
    # denies UnknownPaymentFormat before any approval check and appends nothing; a non-matching or
    # under-granting approval denies with no ledger append; an already-spent approval denies
    # AlreadyConsumed; the consume (the single state change) happens only when every check holds.
    # Returns the ledger entry (Naalp::Approval::LedgerEntry) on success.
    def authorize_charge(p, appr, approver_alg, approver_pubkey, appr_sig, by, now, ledger)
      unless registered_format?(p.format)
        raise PayError.new("UnknownPaymentFormat", "payment import selects a format outside the closed payment-format registry")
      end
      charge_cid = p.charge_binding.content_id
      # ApprovalMismatch (wrong amount/payee/currency/payload) / ApprovalExpired / BadSignature --
      # the EXISTING §7 errors, reused unchanged (raised by Naalp::Approval.verify_approval).
      Naalp::Approval.verify_approval(appr, approver_alg, approver_pubkey, appr_sig, charge_cid, now)
      unless Naalp::Policy.authorizes(appr.grant, CHARGE_EFFECT)
        raise Naalp::Approval::ApprovalError.new("ApprovalRequired", "the approval's granted effect does not cover the charge")
      end
      ledger.consume(appr.id, by) # AlreadyConsumed on replay -- single-use, no double-spend
    end
  end
end
