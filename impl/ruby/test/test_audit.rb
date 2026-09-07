# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C7 audit conformance for the Ruby SDK (design.md §8; R-8.1..8.6, R-12.2, R-12.3), graded against
# the shared independent corpus vectors/audit/cases.json (NOT produced by this code): the
# hash-chained signed receipt body + head, offline chain verification (ChainBroken /
# ReceiptUnsigned), equivocation detection, the draft-01 fork-proof preimage (signatures elided),
# and the offline causal graph (valid topo order, cycle rejection, future-cause rejection).
#
# The receipt/fork-proof SIGNATURES are real deterministic ML-DSA-65 (OpenSSL >= 3.5, rnd=0), but
# the corpus carries no signature vector for this channel (signatures are graded by the shared cose
# byte-parity elsewhere), so the sign/verify round-trips here are demonstrated in isolation with a
# fixed local seed -- stated honestly, not corpus-graded. Every byte-exact assertion
# (body/head/preimage/topo) IS corpus-graded. Where deterministic ML-DSA is unavailable the
# signature tests skip LOUDLY -- never a false green.
#
# Written test-first; the module is absent until ported, so this fails RED on require until
# impl/ruby/lib/naalp/audit.rb lands, and a mutation to the equivocation object-difference check
# flips test_equivocation_detected.
#
# Run:  ruby -Ilib -Itest test/test_audit.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

# Walk up from this test dir to the repository's shared corpus (the independent oracle).
def audit_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "audit", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/audit/cases.json not found"
end

def hb(hex)
  [hex].pack("H*")
end

ALG = Naalp::COSE::ALG_MLDSA65
SEED = ("\x00" * 32).b

class AuditConformance < Minitest::Test
  C = audit_vectors

  # The authority's real ML-DSA-65 public key, or a loud skip where the platform lacks it.
  def pk
    Naalp::COSE.mldsa_keygen("ML-DSA-65", SEED)
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  # ---- signed hash-chained receipt (design §8.1) ----------------------------------------

  # Ruby encoding == the non-circular oracle, byte-for-byte, for every receipt body/head, and each
  # prev links to the previous head. Corpus-graded (no signature needed).
  def test_chain_receipts_match_oracle
    head = hb(C["chain"]["genesis_prev_hex"])
    assert_equal Naalp::Audit::HEAD_SIZE, head.bytesize
    C["chain"]["receipts"].each do |rv|
      r = Naalp::Audit::Receipt.new(hb(rv["prev_hex"]), hb(rv["obj_hex"]), rv["seq"], rv["at"])
      assert_equal rv["body_hex"], r.bytes.unpack1("H*"), "receipt body seq=#{rv['seq']}"
      assert_equal rv["head_after_hex"], r.head.unpack1("H*"), "receipt head seq=#{rv['seq']}"
      assert_equal head.unpack1("H*"), r.prev.unpack1("H*"), "prev links to previous head seq=#{rv['seq']}"
      head = r.head
    end
    assert_equal C["chain"]["final_head_hex"], head.unpack1("H*")
  end

  # A fresh authority appending the same object ids at the same anchors reproduces the byte-exact
  # corpus chain, and the resulting real-ML-DSA-signed chain verifies offline.
  def test_authority_reproduces_chain_and_verifies
    key = pk
    a = Naalp::Audit::Authority.new(ALG, SEED)
    receipts = []
    sigs = []
    C["chain"]["receipts"].each do |rv|
      r, sig = a.append(hb(rv["obj_hex"]), rv["at"])
      assert_equal rv["body_hex"], r.bytes.unpack1("H*"), "append body seq=#{rv['seq']}"
      receipts << r
      sigs << sig
    end
    assert_nil Naalp::Audit.verify_chain(receipts, sigs, ALG, key)
  end

  def test_verify_chain_detects_broken_prev_link
    key = pk
    cb = C["chain_broken"]
    receipts = []
    sigs = []
    cb["receipts"].each do |rv|
      r = Naalp::Audit::Receipt.new(hb(rv["prev_hex"]), hb(rv["obj_hex"]), rv["seq"], rv["at"])
      assert_equal rv["body_hex"], r.bytes.unpack1("H*")
      receipts << r
      sigs << Naalp::COSE.mldsa_sign(ALG, SEED, r.bytes) # real sig so the BREAK, not a bad sig, fires
    end
    err = assert_raises(Naalp::Audit::AuditError) { Naalp::Audit.verify_chain(receipts, sigs, ALG, key) }
    assert_equal cb["expect"], err.kind # ChainBroken
  end

  def test_verify_chain_detects_tampered_signature
    key = pk
    rv = C["chain"]["receipts"][0]
    r = Naalp::Audit::Receipt.new(hb(C["chain"]["genesis_prev_hex"]), hb(rv["obj_hex"]), 0, rv["at"])
    good = Naalp::COSE.mldsa_sign(ALG, SEED, r.bytes)
    bad = good.dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
    err = assert_raises(Naalp::Audit::AuditError) { Naalp::Audit.verify_chain([r], [bad], ALG, key) }
    assert_equal "ReceiptUnsigned", err.kind
  end

  def test_consistent_with_anchor
    assert Naalp::Audit.consistent_with_anchor(100, 100)
    assert Naalp::Audit.consistent_with_anchor(99, 100)
    refute Naalp::Audit.consistent_with_anchor(101, 100) # created after ordered
  end

  # ---- equivocation detection (design §8.5) ---------------------------------------------

  def fork_receipts
    f = C["fork_proof"]
    ra = Naalp::Audit::Receipt.new(hb(f["prev_hex"]), hb(f["obj_a_hex"]), f["seq"], f["at"])
    rb = Naalp::Audit::Receipt.new(hb(f["prev_hex"]), hb(f["obj_b_hex"]), f["seq"], f["at"])
    [f, ra, rb]
  end

  def test_equivocation_receipts_match_oracle
    f, ra, rb = fork_receipts
    assert_equal f["body_a_hex"], ra.bytes.unpack1("H*")
    assert_equal f["body_b_hex"], rb.bytes.unpack1("H*")
    eq = C["equivocation"]
    assert_equal eq["receipt_a"]["body_hex"], ra.bytes.unpack1("H*")
    assert_equal eq["receipt_b"]["body_hex"], rb.bytes.unpack1("H*")
  end

  # Two validly-signed receipts by ONE authority at one seq naming DIFFERENT objects: the auditor
  # mints a fork proof. A benign first observe returns nil. THIS is the mutation-target assertion.
  def test_equivocation_detected
    key = pk
    f, ra, rb = fork_receipts
    sig_a = Naalp::COSE.mldsa_sign(ALG, SEED, ra.bytes)
    sig_b = Naalp::COSE.mldsa_sign(ALG, SEED, rb.bytes)
    auditor = Naalp::Audit::Auditor.new(ALG, key, hb(f["signer_hex"]), f["ext_counter"])
    assert_nil auditor.observe(ra, sig_a), "first observe is benign"
    fp = auditor.observe(rb, sig_b)
    refute_nil fp, "a genuine fork at one seq must be detected"
    assert_nil fp.verify(ALG, key), "the minted proof verifies against the accused key"
    assert_equal "Equivocation", C["equivocation"]["expect"]
  end

  def test_benign_duplicate_is_not_equivocation
    key = pk
    f, ra, = fork_receipts
    sig_a = Naalp::COSE.mldsa_sign(ALG, SEED, ra.bytes)
    auditor = Naalp::Audit::Auditor.new(ALG, key, hb(f["signer_hex"]), f["ext_counter"])
    assert_nil auditor.observe(ra, sig_a)
    assert_nil auditor.observe(ra, sig_a), "an exact duplicate is not a fork"
  end

  def test_observe_rejects_unsigned
    key = pk
    f, ra, = fork_receipts
    auditor = Naalp::Audit::Auditor.new(ALG, key, hb(f["signer_hex"]), f["ext_counter"])
    err = assert_raises(Naalp::Audit::AuditError) { auditor.observe(ra, ("\x00" * 8).b) }
    assert_equal "ReceiptUnsigned", err.kind
  end

  # ---- fork proof (draft-01 §8.5) -------------------------------------------------------

  # The framing witness (both signatures elided to empty) is reproduced byte-for-byte from the
  # corpus, independent of the signature bytes. Corpus-graded.
  def test_fork_proof_preimage_matches_oracle
    f, ra, rb = fork_receipts
    fp = Naalp::Audit.new_fork_proof(hb(f["signer_hex"]), ra, "".b, rb, "".b, f["ext_counter"])
    assert_equal f["preimage_hex"], fp.preimage.unpack1("H*")
  end

  def test_fork_proof_verify_accepts_and_fails_closed
    key = pk
    f, ra, rb = fork_receipts
    sig_a = Naalp::COSE.mldsa_sign(ALG, SEED, ra.bytes)
    sig_b = Naalp::COSE.mldsa_sign(ALG, SEED, rb.bytes)
    signer = hb(f["signer_hex"])

    good = Naalp::Audit.new_fork_proof(signer, ra, sig_a, rb, sig_b, f["ext_counter"])
    assert_nil good.verify(ALG, key) # a valid, non-repudiable proof

    # same object named twice -> not equivocation -> ForkProofInvalid (fail-closed)
    same = Naalp::Audit.new_fork_proof(signer, ra, sig_a, ra, sig_a, f["ext_counter"])
    err = assert_raises(Naalp::Audit::AuditError) { same.verify(ALG, key) }
    assert_equal "ForkProofInvalid", err.kind

    # unnamed accused -> ForkProofInvalid
    unnamed = Naalp::Audit.new_fork_proof("".b, ra, sig_a, rb, sig_b, f["ext_counter"])
    err = assert_raises(Naalp::Audit::AuditError) { unnamed.verify(ALG, key) }
    assert_equal "ForkProofInvalid", err.kind

    # seq mismatch -> ForkProofInvalid
    rb_seq = Naalp::Audit::Receipt.new(rb.prev, rb.obj, rb.seq + 1, rb.at)
    sig_b2 = Naalp::COSE.mldsa_sign(ALG, SEED, rb_seq.bytes)
    mism = Naalp::Audit.new_fork_proof(signer, ra, sig_a, rb_seq, sig_b2, f["ext_counter"])
    err = assert_raises(Naalp::Audit::AuditError) { mism.verify(ALG, key) }
    assert_equal "ForkProofInvalid", err.kind

    # tampered signature -> ReceiptUnsigned
    bad = sig_b.dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
    tampered = Naalp::Audit.new_fork_proof(signer, ra, sig_a, rb, bad, f["ext_counter"])
    err = assert_raises(Naalp::Audit::AuditError) { tampered.verify(ALG, key) }
    assert_equal "ReceiptUnsigned", err.kind
  end

  # ---- offline causal graph (design §8.2-§8.3) ------------------------------------------

  def nodes_for(key)
    C[key]["nodes"].map do |n|
      Naalp::Audit::CausalNode.new(hb(n["id_hex"]), n["causes_hex"].map { |c| hb(c) }, n["position"])
    end
  end

  def test_causal_valid_topo_order_matches_oracle
    nodes = nodes_for("causal_valid")
    assert_nil Naalp::Audit.verify_causal(nodes)
    order = Naalp::Audit.topo_order(nodes)
    assert_equal C["causal_valid"]["topo_order_hex"], order.map { |o| o.unpack1("H*") }
  end

  def test_causal_cycle_rejected
    err = assert_raises(Naalp::Graph::CausalViolation) { Naalp::Audit.verify_causal(nodes_for("causal_cycle")) }
    assert_equal C["causal_cycle"]["expect"], err.kind
  end

  def test_causal_future_cause_rejected
    err = assert_raises(Naalp::Graph::CausalViolation) { Naalp::Audit.verify_causal(nodes_for("causal_future")) }
    assert_equal C["causal_future"]["expect"], err.kind
  end
end
