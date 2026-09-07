# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C21 (5B.1) NAALP-PAY payment-import conformance for the Ruby SDK (design.md §24; R-PAY-1..6),
# graded against the shared independent corpus vectors/payment/cases.json (NOT produced by this
# code): the closed payment-format registry, the byte-exact PaymentImport body/head/content-id (incl.
# the oversized >2^53 amount and the minimal import), the foreign-payload content id (carriage
# binding), the byte-exact ChargeBinding body/head/content-id, the parse round-trip, the fail-closed
# edge cases (non-canonical -> NonCanonical / PayMalformed, absent mandatory field -> PayMalformed, a
# bstr-currency look-alike -> PayMalformed, empty vs populated foreign distinct by content-id), and
# the mismatch content-ids (a wrong amount, wrong payee, or substituted foreign payload yields a
# DIFFERENT charge content-id, so a §7 approval bound to the original no longer matches).
#
# The PaymentImport SIGNATURE is real deterministic ML-DSA-65 via a bare-{1:alg} COSE_Sign1 (as the
# reference's cose.Sign1); the corpus carries no signed vector for this channel, so sign/verify is
# demonstrated in isolation only -- stated honestly, not corpus-graded (skips LOUDLY where the
# platform lacks deterministic ML-DSA).
#
# AuthorizeCharge (design.md §24) composes the EXISTING §7 approval object + single-use consume
# ledger (Naalp::Approval, ported in this SDK) UNCHANGED, exactly as impl/go/payment.AuthorizeCharge
# (authority: impl/go/payment/payment.go:241 + payment_test.go TestChargeSingleUseAndBinding). It is
# demonstrated in isolation (the corpus carries no signed/consume vector for this surface); the
# value-bearing binding property IT ENFORCES is corpus-graded via the mismatch content-ids
# (test_charge_binding_mismatch_ids) that its approval binding rejects. All four fail-closed deny
# paths (UnknownPaymentFormat, ApprovalMismatch/ApprovalExpired/BadSignature, ApprovalRequired,
# AlreadyConsumed) and the success-consumes-exactly-once property are exercised in
# test_authorize_charge_single_use_and_binding below.
#
# Written test-first; the module is absent until ported, so this fails RED on require until
# impl/ruby/lib/naalp/payment.rb lands, and a mutation forcing the ChargeBinding amount field to a
# constant flips test_charge_binding_ids_match_oracle.
#
# Run:  ruby -Ilib -Itest test/test_payment.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def payment_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "payment", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/payment/cases.json not found"
end

def hb(hex)
  [hex].pack("H*")
end

ALG = Naalp::COSE::ALG_MLDSA65
SEED = ("\x00" * 32).b

class PaymentConformance < Minitest::Test
  C = payment_vectors

  def pk
    Naalp::COSE.mldsa_keygen("ML-DSA-65", SEED)
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  def import_from(iv)
    Naalp::Payment::PaymentImport.new(
      iv["format"], iv["amount"], iv["currency"], hb(iv["payee_hex"]),
      iv["not_after"], hb(iv["foreign_hex"])
    )
  end

  # ---- closed payment-format registry (design §24) --------------------------------------

  def test_format_vocabulary
    C["format_vocabulary"].each do |fv|
      assert Naalp::Payment.registered_format?(fv["code"]), fv["name"]
      assert_equal fv["name"], Naalp::Payment.format_name(fv["code"])
    end
    refute Naalp::Payment.registered_format?(C["unknown_format"])
    assert_equal "unknown", Naalp::Payment.format_name(C["unknown_format"])
  end

  def test_charge_effect
    assert_equal C["charge_effect"], Naalp::Payment::CHARGE_EFFECT
    assert_equal Naalp::Policy::NON_IDEMPOTENT_WRITE, Naalp::Payment::CHARGE_EFFECT
  end

  # ---- PaymentImport byte parity (design §24) -------------------------------------------

  def test_import_bodies_match_oracle
    %w[ap2 acp x402].each do |name|
      iv = C["imports"][name]
      p = import_from(iv)
      assert_equal iv["body_hex"], p.bytes.unpack1("H*"), name
      assert_equal iv["head_hex"], p.head.unpack1("H*"), name
      assert_equal iv["id_hex"], p.id.unpack1("H*"), name
      assert_equal iv["foreign_id_hex"], p.foreign_id.unpack1("H*"), name
    end
  end

  # THIS is the mutation-target assertion: the exact charge value a §7 approval binds.
  def test_charge_binding_ids_match_oracle
    %w[ap2 acp x402].each do |name|
      iv = C["imports"][name]
      cb = import_from(iv).charge_binding
      assert_equal iv["charge_binding"]["body_hex"], cb.bytes.unpack1("H*"), name
      assert_equal iv["charge_binding"]["head_hex"], cb.head.unpack1("H*"), name
      assert_equal iv["charge_binding"]["id_hex"], cb.content_id.unpack1("H*"), name
    end
  end

  def test_big_amount_over_2_53_round_trips
    bv = C["big_amount"]
    amount = bv["amount_str"].to_i # 72623859790382856 > 2^53, exact (Ruby bigint)
    assert amount > 2**53
    p = Naalp::Payment::PaymentImport.new(bv["format"], amount, bv["currency"], hb(bv["payee_hex"]),
                                          bv["not_after"], hb(bv["foreign_hex"]))
    assert_equal bv["body_hex"], p.bytes.unpack1("H*")
    assert_equal bv["head_hex"], p.head.unpack1("H*")
    assert_equal bv["id_hex"], p.id.unpack1("H*")
    assert_equal bv["charge_binding"]["id_hex"], p.charge_binding.content_id.unpack1("H*")
    # and the parsed amount round-trips byte-exact through the strict decoder
    rp = Naalp::Payment.parse_payment_import(hb(bv["body_hex"]))
    assert_equal amount, rp.amount
  end

  def test_minimal_import
    m = C["minimal"]
    p = Naalp::Payment::PaymentImport.new(m["format"], m["amount"], m["currency"], hb(m["payee_hex"]),
                                          m["not_after"], hb(m["foreign_hex"]))
    assert_equal m["body_hex"], p.bytes.unpack1("H*")
    assert_equal m["head_hex"], p.head.unpack1("H*")
    assert_equal m["id_hex"], p.id.unpack1("H*")
  end

  # ---- parse round-trip + fail-closed edges (design §24, §15) ---------------------------

  def test_parse_roundtrips
    %w[ap2 acp x402].each do |name|
      iv = C["imports"][name]
      p = Naalp::Payment.parse_payment_import(hb(iv["body_hex"]))
      assert_equal iv["format"], p.format, name
      assert_equal iv["amount"], p.amount, name
      assert_equal iv["currency"], p.currency, name
      assert_equal hb(iv["payee_hex"]), p.payee, name
      assert_equal iv["not_after"], p.not_after, name
      assert_equal hb(iv["foreign_hex"]), p.foreign, name
    end
  end

  def test_noncanonical_body_rejected
    ec = C["edge_cases"]["keys_out_of_order"]
    assert_raises(Naalp::CBOR::NonCanonical) { Naalp::CBOR.decode(hb(ec["noncanonical_body_hex"])) }
    err = assert_raises(Naalp::Payment::PayError) { Naalp::Payment.parse_payment_import(hb(ec["noncanonical_body_hex"])) }
    assert_equal "PayMalformed", err.kind # the corpus 'reject' family
    # the canonical form of the same content parses
    p = Naalp::Payment.parse_payment_import(hb(ec["canonical_body_hex"]))
    assert_equal ec["format"], p.format
  end

  def test_empty_vs_absent_foreign
    ev = C["edge_cases"]["empty_vs_absent"]
    empty = Naalp::Payment.parse_payment_import(hb(ev["empty_foreign"]["body_hex"]))
    assert_equal "".b, empty.foreign
    assert_equal ev["empty_foreign"]["id_hex"], empty.id.unpack1("H*")
    assert_equal ev["empty_foreign"]["foreign_id_hex"], empty.foreign_id.unpack1("H*")
    populated = Naalp::Payment.parse_payment_import(hb(ev["populated_foreign"]["body_hex"]))
    assert_equal ev["populated_foreign"]["id_hex"], populated.id.unpack1("H*")
    assert_equal ev["populated_foreign"]["foreign_id_hex"], populated.foreign_id.unpack1("H*")
    # an empty foreign payload is present and valid, distinct by content-id from a populated one
    refute_equal empty.id, populated.id
    refute_equal empty.foreign_id, populated.foreign_id
    # field 6 (foreign) is mandatory: a body missing it is rejected fail-closed
    err = assert_raises(Naalp::Payment::PayError) { Naalp::Payment.parse_payment_import(hb(ev["absent_field"]["body_hex"])) }
    assert_equal ev["absent_field"]["reject"], err.kind # PayMalformed
  end

  def test_look_alike_rejected
    la = C["edge_cases"]["look_alike"]
    err = assert_raises(Naalp::Payment::PayError) { Naalp::Payment.parse_payment_import(hb(la["body_hex"])) }
    assert_equal la["reject"], err.kind # PayMalformed (currency as bstr)
  end

  # ---- the binding property: a changed charge is a different content-id -----------------

  def test_charge_binding_mismatch_ids
    base_iv = C["imports"]["ap2"]
    base = import_from(base_iv)
    base_id = base.charge_binding.content_id
    assert_equal base_iv["charge_binding"]["id_hex"], base_id.unpack1("H*")
    mm = C["mismatch"]

    wrong_amount = Naalp::Payment::PaymentImport.new(base.format, base.amount + 8000, base.currency,
                                                     base.payee, base.not_after, base.foreign)
    assert_equal mm["wrong_amount_charge_id_hex"], wrong_amount.charge_binding.content_id.unpack1("H*")

    wrong_payee = Naalp::Payment::PaymentImport.new(base.format, base.amount, base.currency,
                                                    "merchant:evil-store".b, base.not_after, base.foreign)
    assert_equal mm["wrong_payee_charge_id_hex"], wrong_payee.charge_binding.content_id.unpack1("H*")

    substituted = Naalp::Payment::PaymentImport.new(base.format, base.amount, base.currency, base.payee,
                                                    base.not_after, hb(mm["substituted_foreign_hex"]))
    assert_equal mm["substituted_foreign_id_hex"], substituted.foreign_id.unpack1("H*")
    assert_equal mm["substituted_charge_id_hex"], substituted.charge_binding.content_id.unpack1("H*")

    [mm["wrong_amount_charge_id_hex"], mm["wrong_payee_charge_id_hex"], mm["substituted_charge_id_hex"]].each do |other|
      refute_equal base_id.unpack1("H*"), other, "a changed charge must not match the bound one"
    end
  end

  # ---- signed import round-trip in isolation (design §24) -------------------------------

  def test_sign_verify_import_in_isolation
    key = pk
    iv = C["imports"]["ap2"]
    p = import_from(iv)
    obj = Naalp::Payment.sign_payment_import(p, ALG, SEED)
    got = Naalp::Payment.verify_payment_import(obj, Naalp::COSE::PROFILE_PUBLIC, ALG, key)
    assert_equal [p.format, p.amount, p.currency, p.payee, p.not_after, p.foreign],
                 [got.format, got.amount, got.currency, got.payee, got.not_after, got.foreign]
    # tampered signature -> BadSignature
    bad = obj.dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
    err = assert_raises(Naalp::Payment::PayError) { Naalp::Payment.verify_payment_import(bad, Naalp::COSE::PROFILE_PUBLIC, ALG, key) }
    assert_equal "BadSignature", err.kind
    # an unknown imported format is not chargeable -> UnknownPaymentFormat
    bad_fmt = Naalp::Payment::PaymentImport.new(C["unknown_format"], 1, "USD", "x".b, 1, "".b)
    bad_obj = Naalp::Payment.sign_payment_import(bad_fmt, ALG, SEED)
    err = assert_raises(Naalp::Payment::PayError) { Naalp::Payment.verify_payment_import(bad_obj, Naalp::COSE::PROFILE_PUBLIC, ALG, key) }
    assert_equal "UnknownPaymentFormat", err.kind
  end

  # ---- AuthorizeCharge: the §7 approval + single-use consume ledger gate (design §24) ----------
  #
  # Authority: impl/go/payment/payment.go:241 (AuthorizeCharge) + payment_test.go
  # TestChargeSingleUseAndBinding. AuthorizeCharge composes Naalp::Approval.verify_approval (binds the
  # EXACT charge content id), Naalp::Policy.authorizes (the approval's granted effect covers the
  # charge), and Naalp::Approval::Ledger#consume (single-use spend, AlreadyConsumed on replay) --
  # reusing the §7 approval + consume ledger UNCHANGED, exactly as the Go reference.

  APPROVER_SEED = ("\x11" * 32).b # the approver's key (isolation; not corpus-graded)
  FOREIGN_SEED  = ("\x22" * 32).b # a key that never authenticates the approval

  def approver_key
    Naalp::COSE.mldsa_keygen("ML-DSA-65", APPROVER_SEED)
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  def foreign_key
    Naalp::COSE.mldsa_keygen("ML-DSA-65", FOREIGN_SEED)
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  # Build and sign a §7 approval binding a charge content id at grant `grant`.
  def mk_approval(charge_cid, approver, grant, nonce_byte, not_after, seed = APPROVER_SEED)
    n = (nonce_byte.chr * 16).b
    a = Naalp::Approval::ApprovalRecord.new(charge_cid, approver, grant, n, not_after)
    sig = Naalp::Approval.sign_approval(a, ALG, seed)
    [a, sig]
  end

  # A fresh WAL-backed ledger in its own temp dir, closed (and the dir cleaned up) before returning --
  # mirrors the Go test's freshLedger(t) (a fresh t.TempDir() ledger per deny-path assertion), safe on
  # Windows because the file handle is released before Dir.mktmpdir removes the directory.
  def fresh_ledger
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "fresh.wal"))
      begin
        yield led
      ensure
        led.close
      end
    end
  end

  # THE C21 payment checkpoint: an imported payment is spent SINGLE-USE through the §7 ledger (a
  # replay is AlreadyConsumed) and is bound to the exact charge (a wrong amount, wrong payee, or
  # substituted foreign payload fails its approval binding); an unauthenticated signer is
  # BadSignature; an expired approval is ApprovalExpired; an under-granting approval is
  # ApprovalRequired; an unregistered format is UnknownPaymentFormat. Mutation target: neutering any
  # one of these checks in Naalp::Payment.authorize_charge flips the corresponding assertion below.
  def test_authorize_charge_single_use_and_binding
    vkey = approver_key
    fkey = foreign_key
    pi = import_from(C["imports"]["ap2"])
    charge_cid = pi.charge_binding.content_id
    appr, appr_sig = mk_approval(charge_cid, "approver-A", Naalp::Payment::CHARGE_EFFECT, 0x01, pi.not_after)
    mm = C["mismatch"]

    # First charge: authorized and consumed exactly once.
    Dir.mktmpdir do |d|
      ledger = Naalp::Approval.open_ledger(File.join(d, "charge.wal"))
      begin
        entry = Naalp::Payment.authorize_charge(pi, appr, ALG, vkey, appr_sig, "payer-1", pi.not_after, ledger)
        refute_nil entry
        assert_equal 0, entry.seq, "first charge must consume at seq 0"

        # Replay: the same approval is rejected by the ledger, no second spend, no state change.
        err = assert_raises(Naalp::Approval::ApprovalError) do
          Naalp::Payment.authorize_charge(pi, appr, ALG, vkey, appr_sig, "payer-1", pi.not_after, ledger)
        end
        assert_equal "AlreadyConsumed", err.kind
        assert_equal 1, ledger.count, "no double-spend: exactly one ledger entry after replay"
      ensure
        ledger.close
      end
    end

    # A wrong-amount charge yields a different charge content-id, so the approval no longer matches.
    wrong_amount = Naalp::Payment::PaymentImport.new(pi.format, pi.amount + 8000, pi.currency, pi.payee, pi.not_after, pi.foreign)
    assert_equal mm["wrong_amount_charge_id_hex"], wrong_amount.charge_binding.content_id.unpack1("H*")
    fresh_ledger do |l|
      err = assert_raises(Naalp::Approval::ApprovalError) do
        Naalp::Payment.authorize_charge(wrong_amount, appr, ALG, vkey, appr_sig, "payer-1", pi.not_after, l)
      end
      assert_equal "ApprovalMismatch", err.kind
    end

    # A wrong-payee charge likewise fails the binding.
    wrong_payee = Naalp::Payment::PaymentImport.new(pi.format, pi.amount, pi.currency, "merchant:evil-store".b, pi.not_after, pi.foreign)
    assert_equal mm["wrong_payee_charge_id_hex"], wrong_payee.charge_binding.content_id.unpack1("H*")
    fresh_ledger do |l|
      err = assert_raises(Naalp::Approval::ApprovalError) do
        Naalp::Payment.authorize_charge(wrong_payee, appr, ALG, vkey, appr_sig, "payer-1", pi.not_after, l)
      end
      assert_equal "ApprovalMismatch", err.kind
    end

    # A substituted foreign payload changes the foreign content-id, hence the charge binding.
    substituted = Naalp::Payment::PaymentImport.new(pi.format, pi.amount, pi.currency, pi.payee, pi.not_after, hb(mm["substituted_foreign_hex"]))
    assert_equal mm["substituted_foreign_id_hex"], substituted.foreign_id.unpack1("H*")
    assert_equal mm["substituted_charge_id_hex"], substituted.charge_binding.content_id.unpack1("H*")
    fresh_ledger do |l|
      err = assert_raises(Naalp::Approval::ApprovalError) do
        Naalp::Payment.authorize_charge(substituted, appr, ALG, vkey, appr_sig, "payer-1", pi.not_after, l)
      end
      assert_equal "ApprovalMismatch", err.kind
    end

    # A foreign key never authenticates the approval.
    fresh_ledger do |l|
      err = assert_raises(Naalp::Approval::ApprovalError) do
        Naalp::Payment.authorize_charge(pi, appr, ALG, fkey, appr_sig, "payer-1", pi.not_after, l)
      end
      assert_equal "BadSignature", err.kind
    end

    # An expired charge is rejected.
    fresh_ledger do |l|
      err = assert_raises(Naalp::Approval::ApprovalError) do
        Naalp::Payment.authorize_charge(pi, appr, ALG, vkey, appr_sig, "payer-1", pi.not_after + 1, l)
      end
      assert_equal "ApprovalExpired", err.kind
    end

    # An under-granting approval (read_only cannot authorize a non_idempotent_write charge) is denied.
    under_cid = pi.charge_binding.content_id
    under_appr, under_sig = mk_approval(under_cid, "approver-A", Naalp::Policy::READ_ONLY, 0x03, pi.not_after)
    fresh_ledger do |l|
      err = assert_raises(Naalp::Approval::ApprovalError) do
        Naalp::Payment.authorize_charge(pi, under_appr, ALG, vkey, under_sig, "payer-1", pi.not_after, l)
      end
      assert_equal "ApprovalRequired", err.kind
    end

    # An unknown imported format is not chargeable.
    unk = Naalp::Payment::PaymentImport.new(C["unknown_format"], pi.amount, pi.currency, pi.payee, pi.not_after, pi.foreign)
    fresh_ledger do |l|
      err = assert_raises(Naalp::Payment::PayError) do
        Naalp::Payment.authorize_charge(unk, appr, ALG, vkey, appr_sig, "payer-1", pi.not_after, l)
      end
      assert_equal "UnknownPaymentFormat", err.kind
    end
  end
end
