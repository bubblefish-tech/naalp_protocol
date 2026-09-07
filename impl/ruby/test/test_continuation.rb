# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C17 N-AALP-CONT flow-continuation conformance for the Ruby SDK (design.md §20; R-CONT-1..7),
# graded against the shared independent corpus vectors/continuation/cases.json (NOT produced by this
# code): the FlowOpen body/head/content-id (incl. the minimal and empty-vs-populated-approvals
# forms), the cheap Continuation body/head hash-chain (incl. the >2^53 seq carried as a JSON
# string), the Checkpoint and FlowCommit bodies, the whole-chain verify_chain final head, the
# AboveCeiling escalation refusal, the GapDetected checkpoint (dropped link + the u64::MAX overflow),
# the WrongFlow replay refusal, the RangeError out-of-lattice refusal, the NonCanonical decode
# refusal, and the look-alike shape refusal (a 2-field FlowCommit fed to the 3-field Checkpoint
# parser).
#
# The FlowOpen / FlowCommit full ML-DSA-65 signatures are real (OpenSSL >= 3.5, rnd=0) but not
# corpus-graded (the corpus carries no signed vector), so sign/verify is demonstrated in isolation
# only -- stated honestly. Where deterministic ML-DSA is unavailable the signature test skips LOUDLY.
# test_above_ceiling_rejected is the mutation target: making the cheap path skip the effect-ceiling
# check (an escalation past the one full signature + approval) flips it.
#
# Written test-first; the Continuation module is absent until ported, so this fails RED (uninitialized
# constant Naalp::Continuation) until impl/ruby/lib/naalp/continuation.rb lands and naalp.rb requires
# it.
#
# Run:  ruby -Ilib -Itest test/test_continuation.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def continuation_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "continuation", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/continuation/cases.json not found"
end

def hb(hex)
  [hex].pack("H*")
end

ALG = Naalp::COSE::ALG_MLDSA65
SEED = ("\x00" * 32).b

class ContinuationConformance < Minitest::Test
  C = continuation_vectors

  def flow_open_from(fo)
    Naalp::Continuation::FlowOpen.new(
      hb(fo["flow_id_hex"]), fo["effect_ceiling"], fo["approvals_hex"].map { |a| hb(a) })
  end

  def cont_from(cv, flow_open_id)
    Naalp::Continuation::Continuation.new(
      flow_open_id, cv["seq"], cv["effect"], hb(cv["payload_id_hex"]), hb(cv["prev_hex"]))
  end

  # ---- FlowOpen byte parity (design §20.2) ----------------------------------------------

  # Ruby encoding == the non-circular oracle, byte-for-byte, for the FlowOpen body/head/content-id;
  # parse round-trips from the body bytes ALONE (the bearer-authority property). Corpus-graded.
  def test_flow_open_bytes_match_oracle
    fo = C["flow_open"]
    o = flow_open_from(fo)
    assert_equal fo["body_hex"], o.bytes.unpack1("H*")
    assert_equal fo["head_hex"], o.head.unpack1("H*")
    assert_equal fo["id_hex"], o.id.unpack1("H*")
    p = Naalp::Continuation.parse_flow_open(hb(fo["body_hex"]))
    assert_equal hb(fo["flow_id_hex"]), p.flow_id
    assert_equal fo["effect_ceiling"], p.effect_ceiling
    assert_equal fo["approvals_hex"].map { |a| hb(a) }, p.approvals
  end

  def test_flow_open_minimal_and_empty_vs_nonempty
    m = C["minimal"]
    o = Naalp::Continuation::FlowOpen.new(hb(m["flow_id_hex"]), m["effect_ceiling"],
                                          m["approvals_hex"].map { |a| hb(a) })
    assert_equal m["body_hex"], o.bytes.unpack1("H*")
    assert_equal m["head_hex"], o.head.unpack1("H*")
    assert_equal m["id_hex"], o.id.unpack1("H*")

    ev = C["empty_vs_nonempty"]
    empty = Naalp::Continuation.parse_flow_open(hb(ev["empty_approvals"]["body_hex"]))
    assert_equal ev["empty_approvals"]["id_hex"], empty.id.unpack1("H*")
    assert_equal [], empty.approvals
    one = Naalp::Continuation.parse_flow_open(hb(ev["one_approval"]["body_hex"]))
    assert_equal ev["one_approval"]["id_hex"], one.id.unpack1("H*")
    assert_equal 1, one.approvals.length
    refute_equal empty.id, one.id # distinct on the wire and by content-id
  end

  # ---- Continuation cheap hash-chain byte parity (design §20.3) --------------------------

  def test_continuation_bytes_match_oracle
    fid = flow_open_from(C["flow_open"]).id
    C["continuations"].each do |cv|
      c = cont_from(cv, fid)
      assert_equal cv["body_hex"], c.bytes.unpack1("H*"), "seq #{cv['seq']} body"
      assert_equal cv["head_hex"], c.head.unpack1("H*"), "seq #{cv['seq']} head"
    end
  end

  # A seq beyond 2^53 (0x0102030405060708) MUST round-trip byte-exact -- carried in the corpus as a
  # JSON string, decoded with Ruby's arbitrary-precision Integer (never a lossy float64).
  def test_big_seq_round_trips
    bs = C["big_seq"]
    seq = bs["seq_str"].to_i
    assert seq > 2**53
    fid = flow_open_from(C["flow_open"]).id
    c = Naalp::Continuation::Continuation.new(fid, seq, bs["effect"], hb(bs["payload_id_hex"]), hb(bs["prev_hex"]))
    assert_equal bs["body_hex"], c.bytes.unpack1("H*")
    assert_equal bs["head_hex"], c.head.unpack1("H*")
    rp = Naalp::Continuation.parse_continuation(hb(bs["body_hex"]))
    assert_equal seq, rp.seq
  end

  # ---- whole-chain verification -> final head (design §20.3) -----------------------------

  def test_verify_chain_final_head
    open_ = flow_open_from(C["flow_open"])
    conts = C["continuations"].map { |cv| cont_from(cv, open_.id) }
    final = Naalp::Continuation.verify_chain(open_, conts)
    assert_equal C["final_head_hex"], final.unpack1("H*")
  end

  # ---- Checkpoint + FlowCommit bodies + confirm prefix (design §20.4, §20.5) -------------

  def test_checkpoint_body_and_verify
    cp = C["checkpoint"]
    open_ = flow_open_from(C["flow_open"])
    obj = Naalp::Continuation::Checkpoint.new(open_.id, cp["through_seq"], hb(cp["head_hex"]))
    assert_equal cp["body_hex"], obj.bytes.unpack1("H*")
    prefix = C["continuations"][0..cp["through_seq"]].map { |cv| cont_from(cv, open_.id) }
    assert_nil Naalp::Continuation.verify_checkpoint(obj, open_, prefix) # contiguous prefix ok
  end

  def test_flow_commit_body
    fc = C["flow_commit"]
    open_ = flow_open_from(C["flow_open"])
    obj = Naalp::Continuation::FlowCommit.new(open_.id, hb(fc["final_head_hex"]))
    assert_equal fc["body_hex"], obj.bytes.unpack1("H*")
  end

  # ---- the cheap path can never escalate (AboveCeiling) -- MUTATION TARGET ----------------

  def test_above_ceiling_rejected
    ac = C["above_ceiling"]
    open_ = flow_open_from(C["flow_open"])
    c = Naalp::Continuation::Continuation.new(open_.id, ac["seq"], ac["effect"],
                                              hb(ac["payload_id_hex"]), hb(ac["prev_hex"]))
    assert_equal ac["body_hex"], c.bytes.unpack1("H*")
    assert_equal ac["head_hex"], c.head.unpack1("H*")
    err = assert_raises(Naalp::Continuation::ContError) do
      Naalp::Continuation.verify_continuation(c, open_.id, hb(ac["prev_hex"]), ac["seq"], ac["ceiling"])
    end
    assert_equal ac["reject"], err.kind # AboveCeiling
  end

  # ---- a dropped/reordered link is a GapDetected checkpoint (design §20.4) ----------------

  def test_gap_detected
    gap = C["gap"]
    open_ = flow_open_from(C["flow_open"])
    cs = C["continuations"]
    # non-contiguous prefix: seq0 then seq2 (seq1 dropped) claimed to cover through_seq=2.
    prefix = [cont_from(cs[0], open_.id), cont_from(cs[2], open_.id)]
    cp = Naalp::Continuation::Checkpoint.new(open_.id, gap["through_seq"], hb(gap["claimed_head_hex"]))
    err = assert_raises(Naalp::Continuation::ContError) do
      Naalp::Continuation.verify_checkpoint(cp, open_, prefix)
    end
    assert_equal gap["detect"], err.kind # GapDetected
  end

  def test_checkpoint_overflow_rejected
    co = C["checkpoint_overflow"]
    open_ = flow_open_from(C["flow_open"])
    through = co["through_seq_str"].to_i # u64::MAX
    cp = Naalp::Continuation::Checkpoint.new(open_.id, through, hb(co["head_hex"]))
    assert_equal co["body_hex"], cp.bytes.unpack1("H*")
    err = assert_raises(Naalp::Continuation::ContError) do
      Naalp::Continuation.verify_checkpoint(cp, open_, []) # prefix_len 0
    end
    assert_equal co["reject"], err.kind # GapDetected
  end

  # ---- a continuation replayed under a different FlowOpen fails WrongFlow -----------------

  def test_replay_wrong_flow
    rp = C["replay"]
    open_a = flow_open_from(C["flow_open"])
    open_b = Naalp::Continuation.parse_flow_open(hb(rp["flow_open_b_body_hex"]))
    assert_equal rp["flow_open_b_id_hex"], open_b.id.unpack1("H*")
    assert_equal rp["flow_open_b_head_hex"], open_b.head.unpack1("H*")
    cont0 = cont_from(C["continuations"][0], open_a.id) # carries flow_open_id = A
    err = assert_raises(Naalp::Continuation::ContError) do
      Naalp::Continuation.verify_continuation(cont0, open_b.id, open_b.head, 0, open_b.effect_ceiling)
    end
    assert_equal rp["detect"], err.kind # WrongFlow
  end

  # ---- out-of-lattice effect/ceiling is RangeError, never normalized ---------------------

  def test_range_reject
    rr = C["range_reject"]
    err = assert_raises(Naalp::Continuation::ContError) do
      Naalp::Continuation.parse_flow_open(hb(rr["flow_open_ceiling_body_hex"]))
    end
    assert_equal rr["reject"], err.kind # RangeError (ceiling=4)
    err = assert_raises(Naalp::Continuation::ContError) do
      Naalp::Continuation.parse_continuation(hb(rr["continuation_effect_body_hex"]))
    end
    assert_equal rr["reject"], err.kind # RangeError (effect=4)
  end

  # ---- fail-closed decode + shape refusals -----------------------------------------------

  def test_non_canonical_decode_rejected
    ko = C["keys_out_of_order"]
    assert_raises(Naalp::CBOR::NonCanonical) do
      Naalp::CBOR.decode(hb(ko["noncanonical_commit_body_hex"]))
    end
    # the canonical form of the same content decodes cleanly
    refute_nil Naalp::CBOR.decode(hb(ko["canonical_commit_body_hex"]))
  end

  def test_look_alike_shape_rejected
    la = C["look_alike"]
    # a 2-field FlowCommit body fed to the 3-field Checkpoint parser is malformed (fail-closed).
    err = assert_raises(Naalp::Continuation::ContError) do
      Naalp::Continuation.parse_checkpoint(hb(la["flow_commit_body_hex"]))
    end
    assert_equal "ContMalformed", err.kind
  end

  # ---- FlowOpen / FlowCommit full signature in isolation (design §20.2, §20.5) -----------

  def test_flow_open_sign_verify_isolation
    # NOT corpus-graded (no signed vector). Real deterministic ML-DSA-65 over a COSE_Sign1.
    key = begin
      Naalp::COSE.mldsa_keygen("ML-DSA-65", SEED)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    open_ = flow_open_from(C["flow_open"])
    obj = Naalp::Continuation.sign_flow_open(open_, ALG, SEED)
    got = Naalp::Continuation.verify_flow_open(obj, Naalp::COSE::PROFILE_PUBLIC, ALG, key)
    assert_equal open_.id, got.id
    bad = obj.dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
    err = assert_raises(Naalp::Continuation::ContError) do
      Naalp::Continuation.verify_flow_open(bad, Naalp::COSE::PROFILE_PUBLIC, ALG, key)
    end
    assert_equal "BadSignature", err.kind
  end
end
