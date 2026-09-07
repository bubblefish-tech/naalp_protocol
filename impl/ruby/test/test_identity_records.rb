# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# The ENVELOPE-adjacent identity RECORD + THREAD surfaces (design.md §5.3/§5.4/§5.2, R-1.4) for the
# Ruby SDK: RevocationRecord, revoked_at, verify_revocation, ForeignLinkRecord, verify_foreign_link,
# RotationEvidence, Thread, Thread#attributable, resolve_thread -- graded against the independent,
# non-circular oracle (tools/identity_records_oracle.py -> vectors/identity_records/cases.json), i.e.
# Ruby == Go == Rust == oracle. Mirrors impl/go/identity/identity_records_oracle_test.go,
# impl/rust/src/identity.rs's identity_records_oracle section, and
# impl/csharp/test/IdentityRecordsKat.cs.
#
# SECURITY-CRITICAL fail-closed anchor: verify_revocation checks signer-id MEMBERSHIP (record.key OR
# a deployer-configured recovery id) BEFORE the signature. "recovery_key_not_configured_reject" is
# the mutation anchor -- a valid recovery-key signature presented against an EMPTY authorized-
# recovery-id set MUST be rejected SignerMismatch; dropping the membership guard (authorized := true
# unconditionally) flips it to accept.
#
# Run:  ruby -Ilib -Itest test/test_identity_records.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def irec_find_vector
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "identity_records", "cases.json")
    return p if File.file?(p)
    d = File.dirname(d)
  end
  nil
end

def irec_load
  p = irec_find_vector
  raise "identity_records vector not found" unless p
  JSON.parse(File.read(p, encoding: "utf-8"))
end

def irec_hex(s)
  [s].pack("H*")
end

class IdentityRecordsTest < Minitest::Test
  # ---- RevocationRecord#bytes (§5.3) ---------------------------------------------------------

  def test_revocation_record_bytes_matches_oracle
    c = irec_load
    cases = c["revocation"]["record_bytes"]
    refute_empty cases, "no revocation.record_bytes cases"
    cases.each do |tc|
      r = Naalp::Identity::RevocationRecord.new(tc["key"], tc["not_after"])
      got = r.bytes.unpack1("H*")
      assert_equal tc["bytes_hex"], got, tc["name"]
    end
  end

  # ---- revoked_at (§5.3) -- MUTATION ANCHOR: "at_boundary_still_valid" pins `>` vs `>=`. ------

  def test_revoked_at_matches_oracle
    c = irec_load
    scenarios = c["revocation"]["revoked_at"]
    refute_empty scenarios, "no revoked_at scenarios"
    scenarios.each do |sc|
      revoked = false
      not_after = 0
      sc["revocations"].each do |rv|
        next unless rv["key"] == sc["query_key"]
        rec = Naalp::Identity::RevocationRecord.new(rv["key"], rv["not_after"])
        if Naalp::Identity.revoked_at(rec, sc["query_position"])
          revoked = true
          not_after = rv["not_after"]
        end
      end
      assert_equal sc["expect_revoked"], revoked, sc["name"]
      assert_equal sc["expect_not_after"], not_after, sc["name"] if sc["expect_revoked"]
    end
  end

  # ---- verify_revocation (§5.3, §5.5) -- SECURITY-CRITICAL fail-closed authorization -----------
  # §5.3 permits a Revocation to be signed by the key it revokes OR by a deployer-configured
  # recovery key. verify_revocation takes the deployer's authorized recovery-id set and accepts a
  # signer iff its recomputed id equals record.key or is a member of that set, THEN verifies the
  # signature (membership BEFORE signature, fail-closed). MUTATION ANCHORS:
  # "recovery_key_not_configured_reject" (a valid recovery-key signature with an EMPTY authorized
  # set -> SignerMismatch) and "wrong_key_reject" -- dropping the membership guard flips both to
  # accept.

  def test_verify_revocation_matches_oracle
    c = irec_load
    cases = c["revocation"]["verify"]
    assert cases.length >= 7, "expected at least 7 revocation.verify cases, got #{cases.length}"
    cases.each do |tc|
      rec = Naalp::Identity::RevocationRecord.new(tc["record"]["key"], tc["record"]["not_after"])
      alg = tc["candidate_alg"]
      pub = irec_hex(tc["candidate_pubkey_hex"])
      sig = irec_hex(tc["sig_hex"])
      recovery_ids = tc["authorized_recovery_ids"] || []
      if tc["expect_valid"]
        Naalp::Identity.verify_revocation(rec, alg, pub, sig, recovery_ids) # must not raise
      else
        err = assert_raises(StandardError) do
          Naalp::Identity.verify_revocation(rec, alg, pub, sig, recovery_ids)
        end
        expect_kind = tc["expect_error_kind"]
        assert_equal expect_kind, err.kind, "#{tc['name']}: got #{err.kind}" if expect_kind && !expect_kind.empty?
      end
    end
  end

  # The fail-closed anchor, isolated: a VALID recovery-key signature presented against an EMPTY
  # authorized-recovery-id set MUST be rejected SignerMismatch (§5.5) -- the membership check runs
  # before the signature check and an unconfigured recovery key confers no authority. This is the
  # assertion the required mutation witness targets.

  def test_recovery_key_not_configured_is_rejected_fail_closed
    c = irec_load
    tc = c["revocation"]["verify"].find { |t| t["name"] == "recovery_key_not_configured_reject" }
    refute_nil tc, "recovery_key_not_configured_reject case not found in the corpus"
    rec = Naalp::Identity::RevocationRecord.new(tc["record"]["key"], tc["record"]["not_after"])
    alg = tc["candidate_alg"]
    pub = irec_hex(tc["candidate_pubkey_hex"])
    sig = irec_hex(tc["sig_hex"])
    recovery_ids = tc["authorized_recovery_ids"] || []
    assert_empty recovery_ids, "the anchor requires an EMPTY authorized set"
    err = assert_raises(Naalp::Identity::SignerMismatch) do
      Naalp::Identity.verify_revocation(rec, alg, pub, sig, recovery_ids)
    end
    assert_equal "SignerMismatch", err.kind
  end

  # ---- ForeignLinkRecord#bytes (§5.4) -- MUTATION ANCHOR: collapsing NFC/NFD to the same bytes
  #      would flip the not-equal assertion below. ----------------------------------------------

  def test_foreign_link_record_bytes_matches_oracle
    c = irec_load
    cases = c["foreign_link"]["record_bytes"]
    assert cases.length >= 2, "expected at least 2 foreign_link.record_bytes cases, got #{cases.length}"
    seen = {}
    cases.each do |tc|
      r = Naalp::Identity::ForeignLinkRecord.new(tc["controls"], tc["foreign_id"], tc["not_after"])
      got = r.bytes.unpack1("H*")
      assert_equal tc["bytes_hex"], got, tc["name"]
      seen[tc["name"]] = got
    end
    refute_equal seen["nfc_form"], seen["nfd_form_different_bytes"],
                 "NFC and NFD foreign_id forms must encode to different bytes"
  end

  # ---- verify_foreign_link (§5.4, §5.5) --------------------------------------------------------
  # Valid+unexpired, the not_after boundary (MUTATION ANCHOR for `now > not_after`), expiry
  # (ignored, no error), wrong-key (ignored, no error -- the SAME bucket as expiry per §5.5), and
  # non-NFC foreign_id (NonNFC, checked before expiry/signature).

  def test_verify_foreign_link_matches_oracle
    c = irec_load
    cases = c["foreign_link"]["verify"]
    refute_empty cases, "no foreign_link.verify cases"
    cases.each do |tc|
      rec = Naalp::Identity::ForeignLinkRecord.new(
        tc["record"]["controls"], tc["record"]["foreign_id"], tc["record"]["not_after"])
      alg = tc["candidate_alg"]
      pub = irec_hex(tc["candidate_pubkey_hex"])
      sig = irec_hex(tc["sig_hex"])
      now = tc["now"]
      expect_kind = tc["expect_error_kind"]
      if expect_kind && !expect_kind.empty?
        err = assert_raises(StandardError) { Naalp::Identity.verify_foreign_link(rec, alg, pub, sig, now) }
        assert_equal expect_kind, err.kind, "#{tc['name']}: got #{err.kind}"
        next
      end
      linked = Naalp::Identity.verify_foreign_link(rec, alg, pub, sig, now)
      assert_equal tc["expect_linked"], linked, tc["name"]
      if tc["expect_linked"]
        assert_equal tc["expect_controls"], rec.controls, tc["name"]
        assert_equal tc["expect_foreign_id"], rec.foreign_id, tc["name"]
      end
    end
  end

  # ---- RotationEvidence / Thread / resolve_thread (§5.2, R-1.4) ---------------------------------

  def irec_build_evidence(evs_json)
    evs_json.map do |e|
      rec = Naalp::Identity::RotationRecord.new(e["old"], e["new"], e["not_before"])
      got = rec.bytes.unpack1("H*")
      assert_equal e["record_bytes_hex"], got, "RotationRecord#bytes (RotationEvidence input)"
      Naalp::Identity::RotationEvidence.new(
        rec, e["old_alg"], irec_hex(e["old_pubkey_hex"]),
        e["new_alg"], irec_hex(e["new_pubkey_hex"]),
        irec_hex(e["old_sig_hex"]), irec_hex(e["new_sig_hex"]))
    end
  end

  # resolve_thread: empty chain, single link, a 3-link contiguous chain, and TWO distinct
  # broken-chain shapes -- "broken_link_old_mismatch" pins the CONTIGUITY guard, and
  # "broken_link_forged_old_signature" pins the per-link CO-SIGNATURE guard (verify_rotation),
  # isolating one guard from the other. MUTATION ANCHORS.

  def test_resolve_thread_matches_oracle
    c = irec_load
    cases = c["thread"]["resolve"]
    refute_empty cases, "no thread.resolve cases"
    cases.each do |tc|
      evs = irec_build_evidence(tc["evidence"])
      expect_error = tc["expect_error"]
      if expect_error && !expect_error.empty?
        err = assert_raises(StandardError) { Naalp::Identity.resolve_thread(evs) }
        assert_equal expect_error, err.kind, "#{tc['name']}: got #{err.kind}"
        next
      end
      th = Naalp::Identity.resolve_thread(evs)
      want = tc["expect_thread"]
      refute_nil want, "#{tc['name']}: oracle declared no expected thread but impl accepted"
      assert_equal want["root"], th.root, tc["name"]
      assert_equal want["current"], th.current, tc["name"]
      assert_equal want["chain"], th.chain, tc["name"]
    end
  end

  # Thread#attributable: root/intermediate/current keys are attributable; an unrelated key is
  # not. "unrelated_key_not_attributable" is the MUTATION ANCHOR (an always-true stub flips it).

  def test_thread_attributable_matches_oracle
    c = irec_load
    cases = c["thread"]["attributable"]
    refute_empty cases, "no thread.attributable cases"
    cases.each do |tc|
      th_json = tc["thread"]
      th = Naalp::Identity::Thread.new(th_json["root"], th_json["current"], th_json["chain"])
      assert_equal tc["expect"], th.attributable(tc["query"]), tc["name"]
    end
  end
end
