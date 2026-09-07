# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C6 approval-object + single-use consume-ledger conformance for the Ruby SDK (design.md §7;
# R-7.1..7.4), graded against the shared independent corpus vectors/approval/cases.json (NOT
# produced by this code): the §7.1 approval body/content-id, the durable hash-chained consume
# ledger (genesis head, per-consume entry bytes + head_after, AlreadyConsumed on a replayed id,
# final head), the §7.3 expiry boundary, and the ApprovalMismatch binding property.
#
# The SECURITY-CRITICAL property is the atomic single-use consume: a consume succeeds EXACTLY ONCE,
# and every later consume of the same approval id is rejected AlreadyConsumed (fail-closed). The
# first-append-wins compare-and-set is serialised under ONE mutex (as the Go single-writer mutex),
# so a read-then-write TOCTOU cannot let two consumers spend one approval -- the replay skeleton key
# this capability exists to prevent. test_second_consume_rejected and test_consume_atomic_under_race
# are the mutation targets: making consume always-succeed / non-atomic flips both.
#
# The approval SIGNATURE is real deterministic ML-DSA-65 (OpenSSL >= 3.5, rnd=0) over the body bytes
# directly (as the reference cose.Signer.Sign -- NOT a COSE Sig_structure); the corpus carries no
# signed vector, so sign/verify is demonstrated in isolation only -- stated honestly, not
# corpus-graded. Where deterministic ML-DSA is unavailable the signature tests skip LOUDLY.
#
# NOT PORTED (out of scope, honest F2/F4): the T1.5 ledger-signed ConsumeReceipt / ConsumeFork /
# ReceiptSet double-spend-evidence surface (approval.go §7.5). It is graded by a SEPARATE corpus,
# vectors/consume_receipt/cases.json, not this port's grade target vectors/approval/cases.json, and
# is tracked as its own deliverable. The single-use replay guarantee this port DOES cover
# (AlreadyConsumed) is the core §7.2 property.
#
# Written test-first; the Approval module is absent until ported, so this fails RED (uninitialized
# constant Naalp::Approval) until impl/ruby/lib/naalp/approval.rb lands and naalp.rb requires it.
#
# Run:  ruby -Ilib -Itest test/test_approval.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'tmpdir'
require 'naalp'

# Walk up from this test dir to the repository's shared corpus (the independent oracle).
def approval_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "approval", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/approval/cases.json not found"
end

# T1.5 (NAALP-REQ-121) independent oracle: vectors/consume_receipt/cases.json.
def consume_receipt_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "consume_receipt", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/consume_receipt/cases.json not found"
end

# R-TDCS-3/4/5 (design.md §25, C22) independent oracle: vectors/trust_decision/cases.json.
def trust_decision_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "trust_decision", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/trust_decision/cases.json not found"
end

def hb(hex)
  [hex].pack("H*")
end

ALG = Naalp::COSE::ALG_MLDSA65
SEED = ("\x00" * 32).b # approver test key (isolation; signature not corpus-graded)

class ApprovalConformance < Minitest::Test
  C = approval_vectors
  CR = consume_receipt_vectors
  TDCS = trust_decision_vectors

  # The approver's real ML-DSA-65 public key, or a loud skip where the platform lacks it.
  def pk
    Naalp::COSE.mldsa_keygen("ML-DSA-65", SEED)
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  def record_from(av)
    Naalp::Approval::ApprovalRecord.new(
      hb(av["approves_hex"]), av["approver"], av["grant"], hb(av["nonce_hex"]), av["not_after"])
  end

  # ---- §7.1 approval body / content-id byte parity --------------------------------------

  # Ruby encoding == the non-circular oracle, byte-for-byte, for every approval body and content id.
  # A mutation to any Bytes() field (key, value, order) flips a *_hex assertion. Corpus-graded.
  def test_approval_bodies_match_oracle
    assert C["approvals"].length >= 2
    C["approvals"].each do |av|
      r = record_from(av)
      assert_equal av["record_hex"], r.bytes.unpack1("H*"), "#{av['name']} body"
      assert_equal av["approval_id_hex"], r.id.unpack1("H*"), "#{av['name']} content-id"
    end
  end

  # ---- §7.2 hash-chained consume ledger byte parity -------------------------------------

  def test_ledger_genesis_head
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "consume.log"))
      begin
        assert_equal C["ledger"]["genesis_head_hex"], led.head.unpack1("H*")
        assert_equal 0, led.count
      ensure
        led.close
      end
    end
  end

  # A fresh ledger consuming the corpus approval ids at the corpus consumers reproduces the byte-exact
  # entry bodies AND the byte-exact chain heads, ending at the corpus final head.
  def test_ledger_consume_chain_matches_oracle
    v = C["ledger"]
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "consume.log"))
      begin
        c0 = v["consumes"][0]
        e0 = led.consume(hb(c0["approval_id_hex"]), c0["by"])
        assert_equal c0["seq"], e0.seq
        assert_equal c0["entry_hex"], e0.bytes.unpack1("H*"), "consume 0 entry"
        assert_equal c0["head_after_hex"], led.head.unpack1("H*"), "head after 0"

        c1 = v["consumes"][1]
        e1 = led.consume(hb(c1["approval_id_hex"]), c1["by"])
        assert_equal c1["seq"], e1.seq
        assert_equal c1["entry_hex"], e1.bytes.unpack1("H*"), "consume 1 entry"
        assert_equal c1["head_after_hex"], led.head.unpack1("H*"), "head after 1"

        assert_equal v["final_head_hex"], led.head.unpack1("H*"), "final head"
        assert_equal 2, led.count
      ensure
        led.close
      end
    end
  end

  # ---- the atomic single-use property (SECURITY-CRITICAL, mutation target) ---------------

  # The corpus's third consume replays approval A's id under a DIFFERENT consumer and expects
  # AlreadyConsumed. THIS is a mutation-target assertion: making consume always-succeed flips it.
  def test_second_consume_rejected
    v = C["ledger"]
    c0 = v["consumes"][0]
    c2 = v["consumes"][2] # same approval id as c0, different consumer -> AlreadyConsumed
    assert_equal "AlreadyConsumed", c2["expect"]
    assert_equal c0["approval_id_hex"], c2["approval_id_hex"]
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "consume.log"))
      begin
        led.consume(hb(c0["approval_id_hex"]), c0["by"])
        assert led.consumed?(hb(c0["approval_id_hex"]))
        head_before = led.head
        err = assert_raises(Naalp::Approval::ApprovalError) do
          led.consume(hb(c2["approval_id_hex"]), c2["by"])
        end
        assert_equal "AlreadyConsumed", err.kind
        # fail-closed: a rejected consume appends nothing (head + count unchanged).
        assert_equal head_before, led.head
        assert_equal 1, led.count
      ensure
        led.close
      end
    end
  end

  # 16 threads race to consume the SAME approval id: exactly ONE wins the compare-and-set, every
  # other is rejected AlreadyConsumed, and exactly ONE entry lands. A non-atomic (mutex-less) consume
  # would let many win -- the replay skeleton key. A content-level barrier maximises contention.
  def test_consume_atomic_under_race
    aid = hb(C["ledger"]["consumes"][0]["approval_id_hex"])
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "consume.log"))
      begin
        n = 16
        wins = []
        rejects = []
        wl = Mutex.new
        bmu = Mutex.new
        bcv = ConditionVariable.new
        waiting = 0
        released = false

        ts = (0...n).map do |i|
          Thread.new do
            bmu.synchronize do
              waiting += 1
              bcv.broadcast if waiting == n
              bcv.wait(bmu) until released
            end
            begin
              led.consume(aid, "consumer-#{i}")
              wl.synchronize { wins << i }
            rescue Naalp::Approval::ApprovalError => e
              wl.synchronize { rejects << i } if e.kind == "AlreadyConsumed"
            end
          end
        end
        bmu.synchronize do
          bcv.wait(bmu) until waiting == n
          released = true
          bcv.broadcast
        end
        ts.each(&:join)

        assert_equal 1, wins.length, "exactly one consumer must win the compare-and-set"
        assert_equal n - 1, rejects.length, "every losing consumer must be AlreadyConsumed"
        assert_equal 1, led.count, "exactly one ledger entry for one approval id"
      ensure
        led.close
      end
    end
  end

  # ---- §7 verify: expiry + the ApprovalMismatch binding, fail-closed ---------------------

  def test_verify_approval_mismatch_and_expiry
    key = pk
    av = C["approvals"][0] # approval A
    r = record_from(av)
    sig = Naalp::Approval.sign_approval(r, ALG, SEED) # real ML-DSA-65 (isolation)
    args_id = hb(av["approves_hex"]) # the exact args this approval binds
    exp = C["expiry"]
    # valid at not_after (inclusive) -> ok (returns nil)
    assert_nil Naalp::Approval.verify_approval(r, ALG, key, sig, args_id, exp["valid_at"])
    # past not_after -> ApprovalExpired
    err = assert_raises(Naalp::Approval::ApprovalError) do
      Naalp::Approval.verify_approval(r, ALG, key, sig, args_id, exp["expired_at"])
    end
    assert_equal "ApprovalExpired", err.kind
    # a changed bound object (different args content id) no longer matches -> ApprovalMismatch
    wrong = hb(C["mismatch"]["wrong_args_id_hex"])
    refute_equal args_id, wrong
    err = assert_raises(Naalp::Approval::ApprovalError) do
      Naalp::Approval.verify_approval(r, ALG, key, sig, wrong, exp["valid_at"])
    end
    assert_equal "ApprovalMismatch", err.kind
  end

  def test_verify_approval_bad_signature_failclosed
    key = pk
    av = C["approvals"][0]
    r = record_from(av)
    sig = Naalp::Approval.sign_approval(r, ALG, SEED).dup
    sig.setbyte(sig.bytesize - 1, sig.getbyte(sig.bytesize - 1) ^ 1) # tamper one byte
    args_id = hb(av["approves_hex"])
    err = assert_raises(Naalp::Approval::ApprovalError) do
      Naalp::Approval.verify_approval(r, ALG, key, sig, args_id, av["not_after"])
    end
    assert_equal "BadSignature", err.kind
  end

  # The §7.4 held outcome is a distinct signed non-success result (never a silent success/denial).
  def test_held_result_signed_in_isolation
    key = pk
    av = C["approvals"][0]
    h = Naalp::Approval::HeldResult.new(hb(av["approves_hex"]), "awaiting approver")
    sig = Naalp::Approval.sign_held(h, ALG, SEED)
    assert Naalp::COSE.cose_verify1_raw(ALG, key, h.bytes, sig)
  end

  # ---- fail-closed ledger integrity (§7.2 durability) -----------------------------------

  # A WAL whose committed bytes were tampered does not hash-chain cleanly and is refused on replay
  # (LedgerCorrupt) rather than trusted -- the persist-before-ack chain is evidence, not decoration.
  def test_ledger_replay_detects_corruption_failclosed
    c0 = C["ledger"]["consumes"][0]
    Dir.mktmpdir do |d|
      p = File.join(d, "consume.log")
      led = Naalp::Approval.open_ledger(p)
      led.consume(hb(c0["approval_id_hex"]), c0["by"])
      led.close
      raw = File.binread(p).dup
      raw.setbyte(10, raw.getbyte(10) ^ 1) # flip a byte inside entry 0's prev (genesis) field
      File.binwrite(p, raw)
      err = assert_raises(Naalp::Approval::ApprovalError) { Naalp::Approval.open_ledger(p) }
      assert_equal "LedgerCorrupt", err.kind
    end
  end

  # ==== T1.5 (NAALP-REQ-121): ledger-signed consume receipt with forward-only position ==========
  #
  # Graded against the SEPARATE independent oracle vectors/consume_receipt/cases.json (non-circular,
  # F3 -- verdicts come from the oracle's from-scratch is_fork() model, NOT this code). Go and Rust
  # grade the same file, so Go == Rust == Ruby bytes.

  def receipt_from(rj)
    Naalp::Approval::ConsumeReceipt.new(hb(rj["ledger_hex"]), hb(rj["approval_id_hex"]), rj["position"])
  end

  def ledger_seed(byte)
    (byte.chr * 32).b
  end

  # The ledger's real ML-DSA-65 public key for a throwaway seed byte, or a loud skip.
  def ledger_pubkey(byte)
    Naalp::COSE.mldsa_keygen("ML-DSA-65", ledger_seed(byte))
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  # TestConsumeReceiptBytesMatchOracle: every consume-receipt body is byte-identical to the
  # independent oracle in this implementation. A field-ignoring or mis-framing encoder diverges here.
  def test_consume_receipt_bytes_match_oracle
    all = [CR["base"]] + CR["sequence"] + CR["forks"].flat_map { |f| [f["a"], f["b"]] }
    assert all.length > 0, "no consume-receipt cases"
    all.each do |rj|
      got = receipt_from(rj).bytes.unpack1("H*")
      assert_equal rj["body_hex"], got, "receipt body"
    end
  end

  # TestConsumeReceiptSignVerify: a ledger-signed receipt verifies under the ledger key (REQ-121); an
  # unnamed ledger, a tampered signature, and the wrong ledger key are each rejected fail-closed.
  def test_consume_receipt_sign_verify
    seed = ledger_seed(0x51)
    key = ledger_pubkey(0x51)
    r = receipt_from(CR["base"])

    sig = Naalp::Approval.sign_consume_receipt(r, ALG, seed)
    assert_nil Naalp::Approval.verify_consume_receipt(r, ALG, key, sig)

    # unnamed ordering authority (nil ledger id) is not evidence.
    unnamed = Naalp::Approval::ConsumeReceipt.new(nil, r.approval_id, r.position)
    err = assert_raises(Naalp::Approval::ApprovalError) { Naalp::Approval.verify_consume_receipt(unnamed, ALG, key, sig) }
    assert_equal "ConsumeReceiptUnsigned", err.kind

    # tampered signature.
    bad = sig.dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
    err = assert_raises(Naalp::Approval::ApprovalError) { Naalp::Approval.verify_consume_receipt(r, ALG, key, bad) }
    assert_equal "ConsumeReceiptUnsigned", err.kind

    # wrong ledger key.
    other_key = ledger_pubkey(0x52)
    err = assert_raises(Naalp::Approval::ApprovalError) { Naalp::Approval.verify_consume_receipt(r, ALG, other_key, sig) }
    assert_equal "ConsumeReceiptUnsigned", err.kind
  end

  # TestConsumeForkDetected (case a): two ledger-signed receipts for the SAME approval id with
  # DIFFERENT positions are detected as a fork, and the surfaced evidence carries BOTH positions and
  # verifies as a non-repudiable double-spend proof.
  def test_consume_fork_detected
    fk = CR["forks"].find { |f| f["name"] == "same_ledger_diff_position" }
    refute_nil fk, "same_ledger_diff_position case missing from oracle"
    assert_equal "fork", fk["expect"]

    seed = ledger_seed(0x41) # one ledger signs both conflicting positions (a partition)
    key = ledger_pubkey(0x41)
    ra = receipt_from(fk["a"])
    rb = receipt_from(fk["b"])
    sig_a = Naalp::Approval.sign_consume_receipt(ra, ALG, seed)
    sig_b = Naalp::Approval.sign_consume_receipt(rb, ALG, seed)

    resolve = ->(id) { id && id.b == ra.ledger.b ? [ALG, key] : nil }
    rs = Naalp::Approval.new_receipt_set(resolve)
    fe, err = rs.observe(ra, sig_a)
    assert_nil fe
    assert_nil err

    fe, err = rs.observe(rb, sig_b)
    refute_nil fe, "fork not detected on same approval id / different positions"
    assert_equal "ConsumeFork", err.kind
    refute_equal fe.a.position, fe.b.position, "fork evidence hides the position conflict"
    # the evidence is non-repudiable: both ledger signatures verify under the named key.
    assert_nil fe.verify(resolve)

    # a byte-identical re-emission is a benign duplicate, never flagged.
    rs2 = Naalp::Approval.new_receipt_set(resolve)
    rs2.observe(ra, sig_a)
    fe2, err2 = rs2.observe(ra, sig_a)
    assert_nil fe2, "benign duplicate flagged"
    assert_nil err2
  end

  # TestConsumeForkCrossLedger (case b): two DIFFERENT ledgers each sign a receipt for the SAME
  # approval id (a single-use approval spent twice). Observing both yields a provable contradiction --
  # concurrent execution of the two independent ledgers, then a comparison, surfaces the fork.
  def test_consume_fork_cross_ledger
    ledger_a_id = hb(CR["ledgers"]["a_hex"])
    ledger_b_id = hb(CR["ledgers"]["b_hex"])
    approval_x = hb(CR["approvals"]["x_hex"])
    seed_a = ledger_seed(0x41)
    seed_b = ledger_seed(0x42)
    key_a = ledger_pubkey(0x41)
    key_b = ledger_pubkey(0x42)

    Dir.mktmpdir do |d|
      l_a = Naalp::Approval.open_ledger_signed(File.join(d, "a.wal"), ledger_a_id, ALG, seed_a)
      l_b = Naalp::Approval.open_ledger_signed(File.join(d, "b.wal"), ledger_b_id, ALG, seed_b)
      begin
        # Two independent ordering authorities, run concurrently, each consuming approval X on its own
        # signed ledger. Each SUCCEEDS locally (they cannot see each other) -- the double spend is not
        # prevented, only made provable on comparison.
        results = []
        rl = Mutex.new
        ts = [l_a, l_b].map do |l|
          Thread.new do
            _e, r, sig = l.consume_with_receipt(approval_x, "requester")
            rl.synchronize { results << [r, sig] }
          end
        end
        ts.each(&:join)

        verifier_for = lambda do |id|
          if id.b == ledger_a_id.b
            [ALG, key_a]
          elsif id.b == ledger_b_id.b
            [ALG, key_b]
          end
        end
        rs = Naalp::Approval.new_receipt_set(verifier_for)
        fork_evidence = nil
        results.each do |r, sig|
          fe, err = rs.observe(r, sig)
          if fe
            assert_equal "ConsumeFork", err.kind
            fork_evidence = fe
          end
        end
        refute_nil fork_evidence, "cross-ledger double spend not detected"
        refute_equal fork_evidence.a.ledger, fork_evidence.b.ledger, "cross-ledger fork evidence names the same ledger twice"
        assert_nil fork_evidence.verify(verifier_for)
      ensure
        l_a.close
        l_b.close
      end
    end
  end

  # TestConsumeFirstAppendWinsCAS (case c) is the compare-and-set MUTATION anchor. On ONE honest
  # signed ledger, consuming the same approval id twice must yield exactly ONE ledger-signed receipt
  # (first-append-wins): the first consume returns a receipt at position 0, the second raises
  # AlreadyConsumed and signs nothing.
  def test_consume_first_append_wins_cas
    ledger_a_id = hb(CR["ledgers"]["a_hex"])
    approval_x = hb(CR["approvals"]["x_hex"])
    seed = ledger_seed(0x41)
    Dir.mktmpdir do |d|
      l = Naalp::Approval.open_ledger_signed(File.join(d, "cas.wal"), ledger_a_id, ALG, seed)
      begin
        e, r1, _sig1 = l.consume_with_receipt(approval_x, "requester")
        assert_equal 0, e.seq
        assert_equal 0, r1.position

        err = assert_raises(Naalp::Approval::ApprovalError) { l.consume_with_receipt(approval_x, "requester") }
        assert_equal "AlreadyConsumed", err.kind, "second consume must be first-append-wins"
        assert_equal 1, l.count, "ledger must have exactly one entry"
      ensure
        l.close
      end
    end
  end

  # TestConsumeReceiptExactlyOnceUnderRace: N threads call consume_with_receipt for the same approval
  # id concurrently on ONE signed ledger; exactly one wins and mints exactly one receipt, the rest get
  # AlreadyConsumed, and the fork detector sees no fork from the single winner.
  def test_consume_receipt_exactly_once_under_race
    ledger_a_id = hb(CR["ledgers"]["a_hex"])
    approval_x = hb(CR["approvals"]["x_hex"])
    seed = ledger_seed(0x41)
    key = ledger_pubkey(0x41)
    Dir.mktmpdir do |d|
      l = Naalp::Approval.open_ledger_signed(File.join(d, "race.wal"), ledger_a_id, ALG, seed)
      begin
        n = 16
        wins = []
        alreadys = []
        winner = nil
        wl = Mutex.new
        bmu = Mutex.new
        bcv = ConditionVariable.new
        waiting = 0
        released = false

        ts = (0...n).map do |i|
          Thread.new do
            bmu.synchronize do
              waiting += 1
              bcv.broadcast if waiting == n
              bcv.wait(bmu) until released
            end
            begin
              _e, r, sig = l.consume_with_receipt(approval_x, "requester")
              wl.synchronize { wins << i; winner = [r, sig] }
            rescue Naalp::Approval::ApprovalError => err
              wl.synchronize { alreadys << i } if err.kind == "AlreadyConsumed"
            end
          end
        end
        bmu.synchronize do
          bcv.wait(bmu) until waiting == n
          released = true
          bcv.broadcast
        end
        ts.each(&:join)

        assert_equal 1, wins.length, "exactly-once violated"
        assert_equal n - 1, alreadys.length
        assert_equal 1, l.count

        # the single minted receipt is not a fork with itself.
        rs = Naalp::Approval.new_receipt_set(->(id) { id && id.b == ledger_a_id.b ? [ALG, key] : nil })
        fe, err = rs.observe(*winner)
        assert_nil fe, "sole winning receipt flagged"
        assert_nil err
      ensure
        l.close
      end
    end
  end

  # TestConsumeReceiptWireCases covers the section-4 wire cases: keys out of order (rejected
  # NonCanonical at the CBOR layer, before any receipt rule), a position too large for a normal int
  # (64-bit uint round-trip), and empty-value vs absent-value (empty != absent; empty ledger id is
  # verify-rejected fail-closed).
  def test_consume_receipt_wire_cases
    w = CR["wire"]

    # keys out of order -> the strict decoder rejects NonCanonical.
    noncanon = hb(w["keys_out_of_order"]["payload_hex"])
    err = assert_raises(Naalp::CBOR::NonCanonical) { Naalp::CBOR.decode(noncanon) }
    assert_equal "NonCanonical", err.kind
    # the canonical variant of the same logical receipt decodes cleanly.
    assert Naalp::CBOR.decode(hb(w["keys_out_of_order"]["canonical_payload_hex"]))

    # position too large: a 64-bit uint position round-trips (encode == oracle, decode == value).
    ledger_x = hb(CR["base"]["ledger_hex"])
    approval_x = hb(CR["base"]["approval_id_hex"])
    w["position_too_large"].each do |big|
      # R12 (NAALP-01-03): a position above 2^53 is carried as a decimal string so a float64 decoder
      # cannot round it; parse it to an exact Integer (Ruby Integers are arbitrary precision).
      big_pos = big["position"].to_i
      r = Naalp::Approval::ConsumeReceipt.new(ledger_x, approval_x, big_pos)
      assert_equal big["body_hex"], r.bytes.unpack1("H*"), "#{big['name']} encode"
      v = Naalp::CBOR.decode(hb(big["body_hex"]))
      pos = nil
      v.pairs.each { |k, val| pos = val.v if k.is_a?(Naalp::CBOR::U) && k.v == 3 }
      assert_equal big_pos, pos, "#{big['name']} position round-trip"
    end

    # empty-ledger receipt: well-formed bytes (match oracle) but verify-rejected fail-closed, and its
    # bytes differ from the absent-ledger variant (empty != absent).
    el = w["empty_ledger"]
    empty = Naalp::Approval::ConsumeReceipt.new("".b, hb(el["approval_id_hex"]), el["position"])
    assert_equal el["body_hex"], empty.bytes.unpack1("H*")
    key = ledger_pubkey(0x41)
    err = assert_raises(Naalp::Approval::ApprovalError) do
      Naalp::Approval.verify_consume_receipt(empty, ALG, key, ("\x00" * Naalp::COSE::MLDSA65_SIG_SIZE).b)
    end
    assert_equal "ConsumeReceiptUnsigned", err.kind
    refute_equal el["body_hex"], w["absent_ledger"]["body_hex"], "empty-ledger and absent-ledger receipts must encode to distinct bytes (empty != absent)"
  end

  # ==== R-TDCS-5 / R-TDCS-3 / R-TDCS-4 (design.md §25, C22) =======================================
  #
  # Graded against the independent oracle vectors/trust_decision/cases.json.

  # R-TDCS-3: IsKnownRefusalOutcome is the closed set {denied, held, unverifiable}; anything else must
  # be reported UNKNOWN, never accepted. FAIL-CLOSED anchor / red-evidence mutation target.
  def test_is_known_refusal_outcome_closed_set
    assert Naalp::Approval.is_known_refusal_outcome(Naalp::Approval::REFUSAL_DENIED)
    assert Naalp::Approval.is_known_refusal_outcome(Naalp::Approval::REFUSAL_HELD)
    assert Naalp::Approval.is_known_refusal_outcome(Naalp::Approval::REFUSAL_UNVERIFIABLE)
    refute Naalp::Approval.is_known_refusal_outcome(3)
    refute Naalp::Approval.is_known_refusal_outcome(999)
  end

  # TestTDCS5AudienceByteParityAndCheck: R-TDCS-5. An approval carrying the OPTIONAL audience field
  # encodes byte-identically to the oracle, and a named audience is checked at use -- a mismatched
  # context is rejected, an absent audience passes any context, a matching one verifies.
  def test_tdcs5_audience_byte_parity_and_check
    a = TDCS["audience"]
    a["cases"].each do |tc|
      rec = Naalp::Approval::ApprovalRecord.new(
        hb(a["approves_hex"]), a["approver"], a["grant"], hb(a["nonce_hex"]), a["not_after"],
        tc["audience"].empty? ? nil : tc["audience"])
      assert_equal tc["record_hex"], rec.bytes.unpack1("H*"), "#{tc['name']}: approval bytes"
      assert_equal tc["approval_id_hex"], rec.id.unpack1("H*"), "#{tc['name']}: approval id"
    end

    # A named audience must equal the absent-audience bytes iff the audience is empty -- i.e. naming a
    # context changes the signed bytes, so a verdict cannot be silently moved to another context.
    present = Naalp::Approval::ApprovalRecord.new(hb(a["approves_hex"]), a["approver"], a["grant"], hb(a["nonce_hex"]), a["not_after"], a["use_context_match"])
    absent = Naalp::Approval::ApprovalRecord.new(hb(a["approves_hex"]), a["approver"], a["grant"], hb(a["nonce_hex"]), a["not_after"])
    refute_equal present.bytes, absent.bytes, "naming an audience must change the approval bytes"

    # The check: named audience must match the use context; absent audience passes any context.
    assert_nil Naalp::Approval.verify_audience(present, a["use_context_match"])
    err = assert_raises(Naalp::Approval::ApprovalError) { Naalp::Approval.verify_audience(present, a["use_context_mismatch"]) }
    assert_equal "AudienceMismatch", err.kind
    assert_nil Naalp::Approval.verify_audience(absent, a["use_context_mismatch"])
  end

  # TestTDCS3RefusalCoarseAndNoLeak: R-TDCS-3. RefusalFromRecord yields the exact oracle bytes for each
  # closed-set outcome, carries the full record's content id, and NEVER carries the record's
  # discriminating detail (the reason). ParseRefusal round-trips a conformant refusal and rejects every
  # non-conformant shape: an unknown outcome, an extra field, a missing/empty record id.
  def test_tdcs3_refusal_coarse_and_no_leak
    r = TDCS["refusal"]
    full_record = hb(r["full_record_hex"])
    record_id = hb(r["full_record_id_hex"])
    reason = r["leaked_reason"].b

    r["cases"].each do |tc|
      ref = Naalp::Approval.refusal_from_record(tc["outcome"], full_record)
      b = ref.bytes
      assert_equal tc["record_hex"], b.unpack1("H*"), "#{tc['name']}: refusal bytes"
      refute b.include?(reason), "#{tc['name']}: the record's reason LEAKED into the party-visible refusal"
      assert b.include?(record_id), "#{tc['name']}: refusal does not carry the full-record content id"

      # Round-trip: a conformant refusal parses back to the same outcome + record id.
      got = Naalp::Approval.parse_refusal(b)
      assert_equal tc["outcome"], got.outcome
      assert_equal record_id, got.record
    end

    # Non-conformant refusals a conformant parser MUST reject.
    err = assert_raises(Naalp::Approval::ApprovalError) { Naalp::Approval.parse_refusal(hb(r["reject"]["unknown_outcome_hex"])) }
    assert_equal "UnknownRefusalOutcome", err.kind

    { "extra field (leaked detail)" => r["reject"]["detail_leak_extra_field_hex"],
      "missing record id" => r["reject"]["missing_record_hex"],
      "empty record id" => r["reject"]["empty_record_hex"] }.each do |name, h|
      err = assert_raises(Naalp::Approval::ApprovalError) { Naalp::Approval.parse_refusal(hb(h)) }
      assert_equal "RefusalDetailLeak", err.kind, name
    end
  end

  # freshScenario builds a valid signed approval and a ledger-signed consume receipt for it, with the
  # approver, the ordering-authority ledger, and (returned separately) an authenticated-party id that
  # the caller chooses distinct or self-referential. pos_time is set at the approval's not_after
  # (still valid). ledger_id is the ordering authority's id; approver_id is the authenticated party's.
  def fresh_scenario
    approver_seed = ledger_seed(0x11) # the approver's key (the authenticated party)
    approver_key = Naalp::COSE.mldsa_keygen("ML-DSA-65", approver_seed)
    ledger_seed_ = ledger_seed(0x22)  # the ordering authority (ledger) -- a DISTINCT key
    ledger_key = Naalp::COSE.mldsa_keygen("ML-DSA-65", ledger_seed_)
    args_id = "the-exact-canonical-args-content-id".b
    approver_id = "approver-authenticated-party-id".b
    ledger_id = "ordering-authority-ledger-id".b
    a = Naalp::Approval::ApprovalRecord.new(args_id, "approver-authenticated-party-id", 1, "anti-replay-nonce".b, 1000)
    sig = Naalp::Approval.sign_approval(a, ALG, approver_seed)
    r = Naalp::Approval::ConsumeReceipt.new(ledger_id, a.id, 7)
    rsig = Naalp::Approval.sign_consume_receipt(r, ALG, ledger_seed_)
    [a, approver_key, sig, args_id, 1000, r, ledger_key, rsig, ledger_id, approver_id, ledger_seed_]
  end

  # TestTDCS4FreshnessIndependence: R-TDCS-4. When the ordering authority is distinct from the
  # authenticated party, an unexpired, correctly-signed approval with a valid ledger receipt verifies.
  # When the ordering authority IS the authenticated party (the party stamping its own freshness), it
  # is rejected FreshnessSelfAsserted -- the load-bearing distinctness the closure property requires.
  def test_tdcs4_freshness_independence
    pk # canary: skip loudly here too if deterministic ML-DSA is unavailable
    a, approver_key, a_sig, args_id, pos_time, r, ledger_key, r_sig, ledger_id, approver_id, ledger_seed_ =
      fresh_scenario

    # Distinct ordering authority (party != ledger): verifies.
    assert_nil Naalp::Approval.verify_fresh_independent(
      a, ALG, approver_key, a_sig, args_id, pos_time, r, ALG, ledger_key, r_sig, approver_id)

    # Self-asserted freshness (party == ledger): the party is the source of its own time -- rejected.
    err = assert_raises(Naalp::Approval::ApprovalError) do
      Naalp::Approval.verify_fresh_independent(
        a, ALG, approver_key, a_sig, args_id, pos_time, r, ALG, ledger_key, r_sig, ledger_id)
    end
    assert_equal "FreshnessSelfAsserted", err.kind

    # The distinctness check does not weaken the underlying checks: an expired approval still fails
    # closed, and a distinct authority does not rescue it.
    err = assert_raises(Naalp::Approval::ApprovalError) do
      Naalp::Approval.verify_fresh_independent(
        a, ALG, approver_key, a_sig, args_id, a.not_after + 1, r, ALG, ledger_key, r_sig, approver_id)
    end
    assert_equal "ApprovalExpired", err.kind

    # A receipt with no named ordering authority is not evidence, even with a distinct party id.
    empty = Naalp::Approval::ConsumeReceipt.new(nil, a.id, 7)
    empty_sig = Naalp::Approval.sign_consume_receipt(empty, ALG, ledger_seed(0x33))
    err = assert_raises(Naalp::Approval::ApprovalError) do
      Naalp::Approval.verify_fresh_independent(
        a, ALG, approver_key, a_sig, args_id, pos_time, empty, ALG, ledger_key, empty_sig, approver_id)
    end
    assert_equal "ConsumeReceiptUnsigned", err.kind
  end

  # ==== T20.1 (approval.state conformance op): consume_approval composed choke point ============
  #
  # Mirrors Go's TestConsumeApprovalPrecedence / Rust's consume_approval_precedence. Uses a
  # deterministic Ed25519 test key -- NOT ML-DSA -- because this is the same crypto convention the
  # approval.state adapter op uses (ruby skips deterministic ML-DSA on OpenSSL < 3.5, so Ed25519
  # keeps this test runnable everywhere). Exercises every reaction and both precedence rules
  # (mismatch over every cell; expiry over AlreadyConsumed), plus the effect-ceiling / grant-range /
  # bad-signature refusals, and asserts the ledger length so a mutant that returns the right Kind
  # but still appends is caught. Reactions are the draft's, not read off the code.
  ED_ALG = Naalp::COSE::ALG_ED25519
  ED_SEED = ("\x07" * 32).b

  def ed_pubkey(seed)
    OpenSSL::PKey.new_raw_private_key("ED25519", seed).raw_public_key
  end

  def mk_approval(args_cid, grant, not_after)
    a = Naalp::Approval::ApprovalRecord.new(args_cid, "approver-1", grant, "\x01\x02".b, not_after)
    sig = Naalp::COSE.ed25519_sign(ED_SEED, a.bytes)
    [a, sig]
  end

  def test_consume_approval_precedence
    ed_key = ed_pubkey(ED_SEED)
    args_cid = "args-content-id-A".b
    wrong_cid = "args-content-id-B".b

    # approved + consume -> consumed (len 1); a second consume -> AlreadyConsumed (len stays 1).
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "ca-consumed.log"))
      begin
        a, sig = mk_approval(args_cid, Naalp::Policy::DESTRUCTIVE, 1000)
        Naalp::Approval.consume_approval(a, ED_ALG, ed_key, sig, args_cid, 500, Naalp::Policy::READ_ONLY, led, "by")
        assert_equal 1, led.count
        err = assert_raises(Naalp::Approval::ApprovalError) do
          Naalp::Approval.consume_approval(a, ED_ALG, ed_key, sig, args_cid, 500, Naalp::Policy::READ_ONLY, led, "by")
        end
        assert_equal "AlreadyConsumed", err.kind
        assert_equal 1, led.count
      ensure
        led.close
      end
    end

    # expired + consume -> ApprovalExpired; nothing appended.
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "ca-expired.log"))
      begin
        a, sig = mk_approval(args_cid, Naalp::Policy::DESTRUCTIVE, 1000)
        err = assert_raises(Naalp::Approval::ApprovalError) do
          Naalp::Approval.consume_approval(a, ED_ALG, ed_key, sig, args_cid, 2000, Naalp::Policy::READ_ONLY, led, "by")
        end
        assert_equal "ApprovalExpired", err.kind
        assert_equal 0, led.count
      ensure
        led.close
      end
    end

    # expiry over consume: success, then a second past not_after -> ApprovalExpired (never
    # AlreadyConsumed), ledger untouched (len stays 1).
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "ca-eoc.log"))
      begin
        a, sig = mk_approval(args_cid, Naalp::Policy::DESTRUCTIVE, 1000)
        Naalp::Approval.consume_approval(a, ED_ALG, ed_key, sig, args_cid, 500, Naalp::Policy::READ_ONLY, led, "by")
        err = assert_raises(Naalp::Approval::ApprovalError) do
          Naalp::Approval.consume_approval(a, ED_ALG, ed_key, sig, args_cid, 2000, Naalp::Policy::READ_ONLY, led, "by")
        end
        assert_equal "ApprovalExpired", err.kind
        assert_equal 1, led.count
      ensure
        led.close
      end
    end

    # mismatch over every cell (fresh, and over an also-expired approval); no append.
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "ca-mismatch.log"))
      begin
        a, sig = mk_approval(args_cid, Naalp::Policy::DESTRUCTIVE, 1000)
        err = assert_raises(Naalp::Approval::ApprovalError) do
          Naalp::Approval.consume_approval(a, ED_ALG, ed_key, sig, wrong_cid, 500, Naalp::Policy::READ_ONLY, led, "by")
        end
        assert_equal "ApprovalMismatch", err.kind
        err2 = assert_raises(Naalp::Approval::ApprovalError) do
          Naalp::Approval.consume_approval(a, ED_ALG, ed_key, sig, wrong_cid, 2000, Naalp::Policy::READ_ONLY, led, "by")
        end
        assert_equal "ApprovalMismatch", err2.kind # mismatch before expiry
        assert_equal 0, led.count
      ensure
        led.close
      end
    end

    # a rejected mismatch leaves the ledger clean, so a later valid consume still succeeds.
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "ca-reject-then-valid.log"))
      begin
        a, sig = mk_approval(args_cid, Naalp::Policy::DESTRUCTIVE, 1000)
        assert_raises(Naalp::Approval::ApprovalError) do
          Naalp::Approval.consume_approval(a, ED_ALG, ed_key, sig, wrong_cid, 500, Naalp::Policy::READ_ONLY, led, "by")
        end
        assert_equal 0, led.count
        Naalp::Approval.consume_approval(a, ED_ALG, ed_key, sig, args_cid, 500, Naalp::Policy::READ_ONLY, led, "by")
        assert_equal 1, led.count
      ensure
        led.close
      end
    end

    # effect ceiling: granted effect below the action's required effect -> ApprovalRequired.
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "ca-under-grant.log"))
      begin
        a, sig = mk_approval(args_cid, Naalp::Policy::READ_ONLY, 1000)
        err = assert_raises(Naalp::Approval::ApprovalError) do
          Naalp::Approval.consume_approval(a, ED_ALG, ed_key, sig, args_cid, 500, Naalp::Policy::DESTRUCTIVE, led, "by")
        end
        assert_equal "ApprovalRequired", err.kind
        assert_equal 0, led.count
      ensure
        led.close
      end
    end

    # grant-range guard: a grant outside the closed 0..3 vocabulary authorizes nothing.
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "ca-malformed-grant.log"))
      begin
        a, sig = mk_approval(args_cid, 7, 1000)
        err = assert_raises(Naalp::Approval::ApprovalError) do
          Naalp::Approval.consume_approval(a, ED_ALG, ed_key, sig, args_cid, 500, Naalp::Policy::READ_ONLY, led, "by")
        end
        assert_equal "ApprovalRequired", err.kind
        assert_equal 0, led.count
      ensure
        led.close
      end
    end

    # bad signature (checked first) -> BadSignature.
    Dir.mktmpdir do |d|
      led = Naalp::Approval.open_ledger(File.join(d, "ca-bad-sig.log"))
      begin
        a, sig = mk_approval(args_cid, Naalp::Policy::DESTRUCTIVE, 1000)
        bad = sig.dup
        bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
        err = assert_raises(Naalp::Approval::ApprovalError) do
          Naalp::Approval.consume_approval(a, ED_ALG, ed_key, bad, args_cid, 500, Naalp::Policy::READ_ONLY, led, "by")
        end
        assert_equal "BadSignature", err.kind
        assert_equal 0, led.count
      ensure
        led.close
      end
    end
  end
end
