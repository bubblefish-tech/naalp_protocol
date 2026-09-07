# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# T1.3 recheck (the checkable-minimum field, RECHECK_KEY=13, NAALP-REQ-110/111) and T1.6 the
# per-signer forward-only counter + duplication detection (SIGNER_COUNTER_KEY=14, NAALP-REQ-120)
# known-answer tests for the Ruby SDK, graded against the independent oracles
# (tools/recheck_oracle.py -> vectors/recheck/cases.json, tools/signer_counter_oracle.py ->
# vectors/signer_counter/cases.json), i.e. Ruby == Go == Rust == oracle.
#
# Recheck (mirrors impl/go/envelope/envelope_test.go recheck section):
#   1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body
#      bytes; a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; and
#      the parsed recheck (present/id/critical) matches. Non-canonical bodies are rejected
#      NonCanonical at the codec.
#   2. REJECT PATH IS REAL [MUTATION ANCHOR] -- a CRITICAL recheck naming an UNKNOWN procedure id is
#      rejected UnknownCriticalExt; a known critical id and an unknown NON-critical id both verify,
#      proving the reject is specific to unknown-under-critical, not a blanket denial.
#   3. READER ROUND-TRIP -- set/get carry the id and criticality; cext (critical) takes precedence
#      over ext (non-critical) when both name the key.
#   4. IS_KNOWN_RECHECK_PROCEDURE BOUNDARIES -- the CLOSED registry is exactly {1,2,3,4}; 0 and 5
#      (immediately outside it) are unknown.
#
# Signer counter + duplication detection (mirrors impl/go/envelope/signer_counter_test.go):
#   5. MATCHES ORACLE -- byte parity + accept/reject verdict + accessor read-back, incl. counter
#      values up to 2^64-1 (no float64 rounding).
#   6. UNDER SIGNATURE -- the counter is folded into the SIGNER's signed body: splicing a different
#      counter into a signed object (keeping its id + signature) is rejected.
#   7. READER ROUND-TRIP -- set/get carries the value; the field is OPTIONAL; present is keyed on
#      the KEY being present, not the value (a present counter of 0 reads back present).
#   8. ABSENT VALIDATES -- an object with no counter signs and verifies.
#   9. DETECT MATCHES ORACLE -- every detection scenario reproduces the oracle's exact findings.
#  10. DETECT ONE SEQUENCE NOT FLAGGED [MUTATION ANCHOR] -- a single sequence (one object per value,
#      including an honest forward-only run) is never flagged; detection requires two conflicting
#      sequences to physically meet.
#  11. DETECT TWO CONFLICTING FLAGGED -- two distinct objects, same signer, same counter, presented
#      together -> flagged once, surfacing both content ids.
#  12. DETECT FORWARD-ONLY-CONSISTENT NOT FLAGGED -- different positions (one signer) and one
#      position (different signers) are both non-conflicts.
#
# Run:  ruby -Ilib -Itest test/test_recheck_signer_counter.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

include Naalp::CBOR

RC_ALG = Naalp::COSE::ALG_MLDSA65
SC_ALG = Naalp::COSE::ALG_MLDSA65
# LOCAL test signing seeds -- the byte-parity assertions reproduce the oracle's BODY bytes (pre-
# signature), so the seed choice does not affect them; the verdict assertions are a real
# sign+verify round-trip, not a reproduction of any oracle signature.
RC_SEED = (0...32).to_a.pack("C*")
SC_SEED = (0...32).to_a.pack("C*")

def rcsc_kind_ok
  ->(_ch, _k) { true }
end

def find_vector(name)
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", name, "cases.json")
    return p if File.file?(p)
    d = File.dirname(d)
  end
  nil
end

def rc_load
  p = find_vector("recheck")
  return nil unless p
  JSON.parse(File.read(p, encoding: "utf-8"))
end

def sc_load
  p = find_vector("signer_counter")
  return nil unless p
  JSON.parse(File.read(p, encoding: "utf-8"))
end

# --- recheck helpers -------------------------------------------------------------------------

# rc_base_object builds the shared base object (fields 2..10) from logical fields -- never from
# the oracle hex, so a constant/field-ignoring encoder diverges from the pinned body bytes.
def rc_base_object(corpus)
  base = corpus["base_object"]
  Naalp.object(
    kind: base["kind"], channel: base["channel"], tier: base["tier"],
    signer: [base["signer_hex"]].pack("H*"), created: base["created"], effect: base["effect"],
    causes: (base["causes_hex"] || []).map { |h| [h].pack("H*") },
    profile: base["profile"], body: T.new(base["body_str"]),
  )
end

# rc_apply_placement applies the case's recheck placement -- the ONLY variable per case.
def rc_apply_placement(o, tc)
  case tc["placement"]
  when "cext"
    o.set_recheck(tc["procedure_id"], true)
  when "ext"
    o.set_recheck(tc["procedure_id"], false)
  when "ext_empty"
    o.ext = M.new([]) # present but empty (no recheck) -- distinct bytes from absent
  when "absent"
    # no ext, no cext
  else
    raise "unknown placement #{tc["placement"].inspect}"
  end
end

# a plain base object for the vector-independent tests below (reject-path, reader round-trip),
# built from fixed logical fields matching the recheck corpus's base_object.
def rc_plain_object
  Naalp.object(
    kind: 2, channel: 4, tier: 0, signer: ["5349474e45525f41"].pack("H*"),
    created: 1785000000000, effect: 2, causes: [], profile: 1, body: T.new("hello"),
  )
end

# RecheckMatchesOracle grades recheck body bytes AND accept/reject verdicts against the
# independent oracle (tools/recheck_oracle.py): every body_no_id_hex/content_id_hex/full_hex is
# byte-identical, and every case verifies or fails with exactly the oracle's verdict over a REAL
# ML-DSA-65 signed object.
class RecheckMatchesOracle < Minitest::Test
  def test_matches_oracle
    corpus = rc_load
    skip "committed recheck vector not present (standalone install)" unless corpus
    assert_equal Naalp::Envelope::RECHECK_KEY, corpus["recheck_key"], "corpus key != impl key"
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", RC_SEED)

    corpus["cases"].each do |tc|
      o = rc_base_object(corpus)
      rc_apply_placement(o, tc)

      assert_equal tc["body_no_id_hex"], Naalp::CBOR.encode(o.body_map(false)).unpack1("H*"),
                   "body-no-id (#{tc["name"]})"
      cid = o.content_id
      assert_equal tc["content_id_hex"], cid.unpack1("H*"), "content-id (#{tc["name"]})"
      o.id = cid
      assert_equal tc["full_hex"], Naalp::CBOR.encode(o.body_map(true)).unpack1("H*"),
                   "full-body (#{tc["name"]})"

      o2 = rc_base_object(corpus)
      rc_apply_placement(o2, tc)
      signed = Naalp::Envelope.sign(o2, RC_ALG, RC_SEED)
      if tc["expect"] == "accept"
        got = Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, RC_ALG, pk, rcsc_kind_ok, signed)
        rid, present, critical = got.recheck
        assert_equal tc["present"], present, "present (#{tc["name"]})"
        if present
          assert_equal tc["procedure_id"], rid, "recheck id (#{tc["name"]})"
          assert_equal tc["critical"], critical, "recheck critical (#{tc["name"]})"
        end
      else
        err = assert_raises(Naalp::Envelope::EnvelopeError) do
          Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, RC_ALG, pk, rcsc_kind_ok, signed)
        end
        assert_equal tc["expect"], err.kind, "verdict error (#{tc["name"]})"
      end
    end

    # non-canonical recheck bodies (keys out of order) are rejected at the CBOR layer.
    (corpus["negatives"] || []).each do |neg|
      o = rc_base_object(corpus)
      prot = Naalp::Envelope.protected_header(RC_ALG, o.signer, o.profile)
      signed = Naalp::COSE.cose_sign1(RC_ALG, RC_SEED, prot, [neg["payload_hex"]].pack("H*"))
      err = assert_raises(StandardError) do
        Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, RC_ALG, pk, rcsc_kind_ok, signed)
      end
      kind = err.respond_to?(:kind) ? err.kind : nil
      assert_equal neg["expect"], kind, "negative verdict (#{neg["name"]})"
    end
  end
end

# RecheckRejectPathIsReal is the MUTATION ANCHOR for the reject path: a CRITICAL recheck naming an
# UNKNOWN procedure id MUST be rejected with UnknownCriticalExt. If the verify recheck branch is
# mutated to accept (e.g. dropping the is_known_recheck_procedure check), this test flips
# pass->fail. A known critical procedure and a non-critical unknown procedure both verify, proving
# the reject is specific to unknown-under-critical and not a blanket denial.
class RecheckRejectPathIsReal < Minitest::Test
  def test_reject_path_is_real
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", RC_SEED)

    critical_unknown = rc_plain_object
    critical_unknown.set_recheck(99, true) # unknown id, critical
    su = Naalp::Envelope.sign(critical_unknown, RC_ALG, RC_SEED)
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, RC_ALG, pk, rcsc_kind_ok, su)
    end
    assert_equal "UnknownCriticalExt", err.kind

    critical_known = rc_plain_object
    critical_known.set_recheck(Naalp::Envelope::RECHECK_WALK_CAUSES, true) # known id, critical
    sk = Naalp::Envelope.sign(critical_known, RC_ALG, RC_SEED)
    Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, RC_ALG, pk, rcsc_kind_ok, sk) # must not raise

    non_crit_unknown = rc_plain_object
    non_crit_unknown.set_recheck(99, false) # unknown id, non-critical -> ignored
    sn = Naalp::Envelope.sign(non_crit_unknown, RC_ALG, RC_SEED)
    Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, RC_ALG, pk, rcsc_kind_ok, sn) # must not raise
  end
end

# RecheckReaderRoundTrip proves recheck/set_recheck carry the id and criticality, and that cext
# (critical) takes precedence over ext (non-critical) when both name the key.
class RecheckReaderRoundTrip < Minitest::Test
  def test_reader_round_trip
    o = rc_plain_object
    _id, present, _critical = o.recheck
    refute present, "fresh object must have no recheck"

    o.set_recheck(Naalp::Envelope::RECHECK_VERIFY_COSE_SIGN1, false)
    id, present, critical = o.recheck
    assert present
    assert_equal Naalp::Envelope::RECHECK_VERIFY_COSE_SIGN1, id
    refute critical

    o.set_recheck(Naalp::Envelope::RECHECK_REPLAY_CONSUME_CHECK, true) # critical wins over the ext entry
    id, present, critical = o.recheck
    assert present
    assert_equal Naalp::Envelope::RECHECK_REPLAY_CONSUME_CHECK, id
    assert critical
  end
end

# IsKnownRecheckProcedureBoundaries proves the registry is exactly the CLOSED set {1,2,3,4}: the
# values immediately outside it (0 and 5) are unknown.
class IsKnownRecheckProcedureBoundaries < Minitest::Test
  def test_boundaries
    refute Naalp::Envelope.is_known_recheck_procedure(0), "0 is just below the registry"
    assert Naalp::Envelope.is_known_recheck_procedure(1)
    assert Naalp::Envelope.is_known_recheck_procedure(2)
    assert Naalp::Envelope.is_known_recheck_procedure(3)
    assert Naalp::Envelope.is_known_recheck_procedure(4)
    refute Naalp::Envelope.is_known_recheck_procedure(5), "5 is just above the registry top"
    refute Naalp::Envelope.is_known_recheck_procedure(99)
  end
end

# --- signer counter + duplication detection helpers -------------------------------------------

# sc_base_object builds the shared base object (fields 2..10) from logical fields, with an
# optional signer/body override -- never from the oracle hex, so a constant encoder diverges.
def sc_base_object(corpus, signer_hex = nil, body_str = nil)
  base = corpus["base_object"]
  Naalp.object(
    kind: base["kind"], channel: base["channel"], tier: base["tier"],
    signer: [(signer_hex || base["signer_hex"])].pack("H*"),
    created: base["created"], effect: base["effect"],
    causes: (base["causes_hex"] || []).map { |h| [h].pack("H*") },
    profile: base["profile"], body: T.new(body_str || base["body_str"]),
  )
end

# sc_u64 normalizes a corpus counter to Integer: a bare JSON number (<= 2^53) stays as-is, and a
# QUOTED decimal string (> 2^53, so a float64 JSON decoder cannot round it -- R12 / NAALP-01-03)
# is parsed to the exact Integer. nil passes through unchanged.
def sc_u64(v)
  v.is_a?(String) ? Integer(v, 10) : v
end

# sc_apply_placement applies the case's counter placement -- the ONLY variable per case.
def sc_apply_placement(o, tc)
  cnt = sc_u64(tc["counter"])
  case tc["placement"]
  when "ext"
    o.set_signer_counter(cnt)
  when "cext"
    # the counter placed in the CRITICAL map is an unrecognized critical extension.
    o.cext = M.new([[U.new(Naalp::Envelope::SIGNER_COUNTER_KEY), U.new(cnt)]])
  when "ext_empty"
    o.ext = M.new([]) # present but empty (no counter) -- distinct bytes from absent
  when "absent"
    # no ext, no cext
  else
    raise "unknown placement #{tc["placement"].inspect}"
  end
end

# sc_build_scenario_objects reconstructs a detection scenario's presented objects from their
# logical fields and cross-checks each recomputed content id against the oracle's (via `test`,
# the calling Minitest::Test instance, so a mismatch reports through the normal assertion path).
def sc_build_scenario_objects(test, corpus, objs)
  objs.map do |ro|
    o = sc_base_object(corpus, ro["signer_hex"], ro["body_str"])
    o.set_signer_counter(sc_u64(ro["counter"])) unless ro["counter"].nil?
    cid = o.content_id
    test.assert_equal ro["content_id_hex"], cid.unpack1("H*"), "scenario object content-id"
    o
  end
end

# SignerCounterMatchesOracle grades counter body bytes AND accept/reject verdicts against the
# independent oracle (tools/signer_counter_oracle.py): every body_no_id_hex/content_id_hex/
# full_hex is byte-identical, and every case verifies or fails with exactly the oracle's verdict
# over a REAL ML-DSA-65 signed object -- including counter values up to 2^64-1 (no float64
# rounding, since Ruby integers are arbitrary-precision).
class SignerCounterMatchesOracle < Minitest::Test
  def test_matches_oracle
    corpus = sc_load
    skip "committed signer_counter vector not present (standalone install)" unless corpus
    assert_equal Naalp::Envelope::SIGNER_COUNTER_KEY, corpus["counter_key"], "corpus key != impl key"
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", SC_SEED)

    corpus["cases"].each do |tc|
      o = sc_base_object(corpus, tc["signer_hex"], tc["body_str"])
      sc_apply_placement(o, tc)

      assert_equal tc["body_no_id_hex"], Naalp::CBOR.encode(o.body_map(false)).unpack1("H*"),
                   "body-no-id (#{tc["name"]})"
      cid = o.content_id
      assert_equal tc["content_id_hex"], cid.unpack1("H*"), "content-id (#{tc["name"]})"
      o.id = cid
      assert_equal tc["full_hex"], Naalp::CBOR.encode(o.body_map(true)).unpack1("H*"),
                   "full-body (#{tc["name"]})"

      o2 = sc_base_object(corpus, tc["signer_hex"], tc["body_str"])
      sc_apply_placement(o2, tc)
      signed = Naalp::Envelope.sign(o2, SC_ALG, SC_SEED)
      if tc["expect"] == "accept"
        got = Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, SC_ALG, pk, rcsc_kind_ok, signed)
        seq, present = got.signer_counter
        assert_equal tc["present"], present, "present (#{tc["name"]})"
        assert_equal sc_u64(tc["counter"]), seq, "counter value (#{tc["name"]})" if present
      else
        err = assert_raises(Naalp::Envelope::EnvelopeError) do
          Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, SC_ALG, pk, rcsc_kind_ok, signed)
        end
        assert_equal tc["expect"], err.kind, "verdict error (#{tc["name"]})"
      end
    end

    # non-canonical counter bodies (ext keys out of order) are rejected at the CBOR layer.
    (corpus["negatives"] || []).each do |neg|
      o = sc_base_object(corpus)
      prot = Naalp::Envelope.protected_header(SC_ALG, o.signer, o.profile)
      signed = Naalp::COSE.cose_sign1(SC_ALG, SC_SEED, prot, [neg["payload_hex"]].pack("H*"))
      err = assert_raises(StandardError) do
        Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, SC_ALG, pk, rcsc_kind_ok, signed)
      end
      kind = err.respond_to?(:kind) ? err.kind : nil
      assert_equal neg["expect"], kind, "negative verdict (#{neg["name"]})"
    end
  end
end

# SignerCounterUnderSignature proves the counter is folded into the SIGNER's COSE_Sign1 signed
# input (ext, field 11, is part of the signed body): flipping the counter value in a signed
# object's payload breaks verification. A signer-signed (not ledger-signed) counter is the whole
# point.
class SignerCounterUnderSignature < Minitest::Test
  def test_under_signature
    corpus = sc_load
    skip "committed signer_counter vector not present" unless corpus
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", SC_SEED)
    o = sc_base_object(corpus)
    o.set_signer_counter(5)
    signed = Naalp::Envelope.sign(o, SC_ALG, SC_SEED)
    # baseline: the signed object verifies and reads back counter 5.
    got = Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, SC_ALG, pk, rcsc_kind_ok, signed)
    seq, present = got.signer_counter
    assert present && seq == 5, "counter read-back"

    # tamper: change the counter to 6 and re-encode the body WITHOUT re-signing; the object must
    # be rejected (the content id no longer matches the signed body / the signature no longer
    # covers it).
    tampered = sc_base_object(corpus)
    tampered.set_signer_counter(6)
    tampered.id = o.id # keep the original (counter=5) content id -- a splice, not a re-sign
    payload = Naalp::CBOR.encode(tampered.body_map(true))
    prot, _payload, sig = Naalp::COSE.parse_sign1_raw(signed) # reuse the ORIGINAL signature bytes
    forged = Naalp::COSE.assemble_sign1_raw(prot, payload, sig)
    assert_raises(StandardError) do
      Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, SC_ALG, pk, rcsc_kind_ok, forged)
    end
  end
end

# SignerCounterReaderRoundTrip proves set_signer_counter/signer_counter carry the value, that the
# field is OPTIONAL (a fresh object has none), and that a present counter of value 0 reads back
# present (present is keyed on the key, not the value).
class SignerCounterReaderRoundTrip < Minitest::Test
  def test_reader_round_trip
    corpus = sc_load
    skip "committed signer_counter vector not present" unless corpus
    o = sc_base_object(corpus)
    _seq, present = o.signer_counter
    refute present, "fresh object must have no counter"

    o.set_signer_counter(42)
    seq, present = o.signer_counter
    assert present
    assert_equal 42, seq

    o.set_signer_counter(0) # present with value zero
    seq, present = o.signer_counter
    assert present, "present-zero counter must read back present"
    assert_equal 0, seq
  end
end

# SignerCounterAbsentValidates is the MUTATION ANCHOR for optionality: an object carrying NO
# counter Signs and Verifies. Making the field mandatory (e.g. adding a reject-if-absent check to
# verify) flips this test pass->fail.
class SignerCounterAbsentValidates < Minitest::Test
  def test_absent_validates
    corpus = sc_load
    skip "committed signer_counter vector not present" unless corpus
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", SC_SEED)
    o = sc_base_object(corpus)
    _seq, present = o.signer_counter
    refute present, "object built without a counter must have none"
    signed = Naalp::Envelope.sign(o, SC_ALG, SC_SEED)
    got = Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, SC_ALG, pk, rcsc_kind_ok, signed)
    _seq2, present2 = got.signer_counter
    refute present2, "verified object must report no counter"
  end
end

# DetectSignerDuplicationMatchesOracle grades detect_signer_duplication over every scenario in the
# independent oracle: the impl reconstructs the presented set and MUST reproduce the oracle's
# exact findings (signer, counter, and the SET of surfaced content ids, in order).
class DetectSignerDuplicationMatchesOracle < Minitest::Test
  def test_matches_oracle
    corpus = sc_load
    skip "committed signer_counter vector not present" unless corpus
    corpus["detection"]["scenarios"].each do |sc|
      objs = sc_build_scenario_objects(self, corpus, sc["objects"])
      findings = Naalp::Envelope.detect_signer_duplication(objs)
      assert_equal sc["expect"].length, findings.length, "findings count (#{sc["name"]})"
      sc["expect"].each_with_index do |want, i|
        got = findings[i]
        assert_equal want["signer_hex"], got.signer.unpack1("H*"), "finding #{i} signer (#{sc["name"]})"
        assert_equal sc_u64(want["counter"]), got.counter, "finding #{i} counter (#{sc["name"]})"
        assert_equal want["ids_hex"].length, got.ids.length, "finding #{i} ids count (#{sc["name"]})"
        want["ids_hex"].each_with_index do |id_hex, j|
          assert_equal id_hex, got.ids[j].unpack1("H*"), "finding #{i} id #{j} (#{sc["name"]})"
        end
      end
    end
  end
end

# DetectOneSequenceNotFlagged is case (a) and the MUTATION ANCHOR for the detection function: a
# single sequence (one object per value) MUST NOT be flagged -- detection requires two conflicting
# sequences to physically meet. Relaxing the `idset.size < 2` guard in detect_signer_duplication
# to `< 1` (flag from one) flips this test pass->fail; that is the whole detection-not-prevention
# line.
class DetectOneSequenceNotFlagged < Minitest::Test
  def test_one_sequence_not_flagged
    corpus = sc_load
    skip "committed signer_counter vector not present" unless corpus
    # one object alone at position 5.
    one = sc_base_object(corpus, nil, "holder")
    one.set_signer_counter(5)
    assert_equal 0, Naalp::Envelope.detect_signer_duplication([one]).length,
                 "one sequence alone must not be flagged"

    # a full honest forward-only sequence from one signer (1,2,3) is also one sequence -> not flagged.
    seq_objs = []
    ["s1", "s2", "s3"].each_with_index do |body, i|
      o = sc_base_object(corpus, nil, body)
      o.set_signer_counter(i + 1)
      seq_objs << o
    end
    assert_equal 0, Naalp::Envelope.detect_signer_duplication(seq_objs).length,
                 "an honest forward-only sequence must not be flagged"
  end
end

# DetectTwoConflictingFlagged is case (b): two DISTINCT objects, SAME signer id, SAME counter
# value, presented TOGETHER -> flagged once, surfacing BOTH content ids. This is the duplication
# fingerprint and it is only observable because both objects are present.
class DetectTwoConflictingFlagged < Minitest::Test
  def test_two_conflicting_flagged
    corpus = sc_load
    skip "committed signer_counter vector not present" unless corpus
    holder = sc_base_object(corpus, nil, "holder")
    holder.set_signer_counter(5)
    thief = sc_base_object(corpus, nil, "thief")
    thief.set_signer_counter(5)

    f = Naalp::Envelope.detect_signer_duplication([holder, thief])
    assert_equal 1, f.length, "two conflicting sequences must be flagged once"
    assert_equal 5, f[0].counter
    assert_equal 2, f[0].ids.length, "both conflicting content ids must be surfaced"
    surfaced = f[0].ids
    assert_includes surfaced, holder.content_id
    assert_includes surfaced, thief.content_id
  end
end

# DetectForwardOnlyConsistentNotFlagged is case (c): two objects from one signer at DIFFERENT
# (forward-only consistent) positions are not flagged; nor are two different signers at one
# position.
class DetectForwardOnlyConsistentNotFlagged < Minitest::Test
  def test_forward_only_consistent_not_flagged
    corpus = sc_load
    skip "committed signer_counter vector not present" unless corpus
    a5 = sc_base_object(corpus, nil, "holder")
    a5.set_signer_counter(5)
    a6 = sc_base_object(corpus, nil, "next")
    a6.set_signer_counter(6)
    assert_equal 0, Naalp::Envelope.detect_signer_duplication([a5, a6]).length,
                 "forward-only-consistent sequence must not be flagged"

    # per-signer: SIGNER_B at position 5 does not conflict with SIGNER_A at position 5.
    b5 = sc_base_object(corpus, "5349474e45525f42", "other")
    b5.set_signer_counter(5)
    assert_equal 0, Naalp::Envelope.detect_signer_duplication([a5, b5]).length,
                 "different signers at one value must not be flagged"
  end
end
