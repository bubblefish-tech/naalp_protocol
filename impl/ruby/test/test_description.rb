# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C18 signed description / directory / import conformance for the Ruby SDK (design.md §21;
# R-DESC-1..8), graded against the shared independent corpus vectors/description/cases.json (NOT
# produced by this code): the Operation / Description / Directory / Import body-head-id bytes, the
# foreign-id binding, the fork-detection first-differing position (fork, length-fork, different-version,
# duplicate), and the closed foreign-format rejection.
#
# The offline-verification property (authority in the SIGNED bytes, not the serving host), the directory
# fork proof, and the confused-deputy import rule (the wrapping signer is the sole authorization
# identity, a foreign identity never becomes one) are real behaviour demonstrated in isolation with REAL
# deterministic ML-DSA-65 (the corpus carries no signed-object vector, stated honestly, so those are NOT
# corpus-graded). Where deterministic ML-DSA is unavailable those tests skip LOUDLY (never a false green).
#
# Written test-first; the Description module is absent until ported, so this fails RED (uninitialized
# constant Naalp::Description) until impl/ruby/lib/naalp/description.rb lands and naalp.rb requires it.
# THE mutation target is test_operation_bodies_match_oracle: forcing the operation effect field to a
# constant flips it on its assertion.
#
# Run:  ruby -Ilib -Itest test/test_description.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def description_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "description", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/description/cases.json not found"
end

def hb(hex)
  [hex].pack("H*")
end

ALG = Naalp::COSE::ALG_MLDSA65
PROFILE = Naalp::COSE::PROFILE_PUBLIC

DescKey = Struct.new(:seed, :pk, :id)

def ops_from(op_dicts)
  op_dicts.map { |o| Naalp::Description::Operation.new(o["name"], o["effect"], o["requires_approval"]) }
end

class DescriptionConformance < Minitest::Test
  C = description_vectors

  def mk_key(n)
    seed = ([n & 0xFF].pack("C") * 32).b
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
    DescKey.new(seed, pk, Naalp::Identity.signer_id(ALG, pk))
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  def dir_a
    dv = C["directory"]
    Naalp::Description::Directory.new(hb(dv["directory_hex"]), dv["version"],
                                      dv["members_a_hex"].map { |m| hb(m) })
  end

  # ---- Operation body bytes (THE mutation target) ---------------------------------------

  # Each operation encodes {1:name,2:effect,3:requires_approval} byte-for-byte the oracle; the effect
  # accessor normalizes fail-closed and the approval flag reads the uint 1/0. Forcing the effect field
  # to a constant flips a body_hex assertion.
  def test_operation_bodies_match_oracle
    ops = C["description"]["operations"]
    assert ops.length >= 2
    ops.each do |o|
      op = Naalp::Description::Operation.new(o["name"], o["effect"], o["requires_approval"])
      assert_equal o["body_hex"], op.bytes.unpack1("H*"), o["name"]
      assert_equal Naalp::Policy.normalize_effect(o["effect"]), op.effect_class, o["name"]
      assert_equal (o["requires_approval"] == 1), op.requires_approval_flag, o["name"]
    end
  end

  # ---- Description body / head / id ------------------------------------------------------

  def test_description_body_matches_oracle
    dv = C["description"]
    d = Naalp::Description::Description.new(hb(dv["service_hex"]), ops_from(dv["operations"]))
    assert_equal dv["body_hex"], d.bytes.unpack1("H*")
    assert_equal dv["head_hex"], d.head.unpack1("H*")
    assert_equal dv["id_hex"], d.id.unpack1("H*")
    # the operation table reconstructs from the body bytes ALONE (offline-verifiable)
    parsed = Naalp::Description.parse_description(d.bytes)
    op, ok = parsed.operation("write_record")
    assert ok
    assert_equal Naalp::Policy::NON_IDEMPOTENT_WRITE, op.effect_class
    assert op.requires_approval_flag
  end

  def test_malformed_approval_flag_rejected
    # requires_approval outside {0,1} is rejected (no CBOR boolean), never defaulted.
    m = Naalp::CBOR::M.new([[Naalp::CBOR::U.new(1), Naalp::CBOR::T.new("x")],
                            [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(0)],
                            [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(2)]])
    err = assert_raises(Naalp::Description::DescriptionError) do
      Naalp::Description.operation_from_value(m)
    end
    assert_equal "MalformedApprovalFlag", err.kind
  end

  # ---- Directory body / head / id + fork detection ---------------------------------------

  def test_directory_bodies_match_oracle
    dv = C["directory"]
    a = dir_a
    assert_equal dv["a"]["body_hex"], a.bytes.unpack1("H*")
    assert_equal dv["a"]["head_hex"], a.head.unpack1("H*")
    assert_equal dv["a"]["id_hex"], a.id.unpack1("H*")
    b = Naalp::Description::Directory.new(hb(dv["directory_hex"]), dv["version"],
                                          dv["fork"]["members_b_hex"].map { |m| hb(m) })
    assert_equal dv["fork"]["b"]["body_hex"], b.bytes.unpack1("H*")
    assert_equal dv["fork"]["b"]["id_hex"], b.id.unpack1("H*")
  end

  def test_fork_detection_matches_oracle
    dv = C["directory"]
    a = dir_a
    b = Naalp::Description::Directory.new(hb(dv["directory_hex"]), dv["version"],
                                          dv["fork"]["members_b_hex"].map { |m| hb(m) })
    pos, fork = Naalp::Description.detect_fork(a, b)
    assert fork
    assert_equal dv["fork"]["first_differing_position"], pos

    # a truncated member list forks at the length of the shorter list.
    short = Naalp::Description::Directory.new(hb(dv["directory_hex"]), dv["version"],
                                              dv["length_fork"]["members_short_hex"].map { |m| hb(m) })
    pos2, fork2 = Naalp::Description.detect_fork(a, short)
    assert fork2
    assert_equal dv["length_fork"]["first_differing_position"], pos2

    # a different version is a legitimate succession, not a fork.
    other_ver = Naalp::Description::Directory.new(hb(dv["directory_hex"]),
                                                  dv["different_version"]["version"], a.members)
    assert_equal [0, false], Naalp::Description.detect_fork(a, other_ver)

    # identical directories are a benign duplicate (no fork) -- corpus records position -1.
    assert_equal [0, false], Naalp::Description.detect_fork(a, dir_a)
  end

  # ---- Import body / head / id / foreign-id + closed foreign-format -----------------------

  def test_import_body_matches_oracle
    iv = C["import"]
    im = Naalp::Description::Import.new(hb(iv["importer_hex"]), iv["format"],
                                        hb(iv["foreign_hex"]), ops_from(iv["operations"]))
    assert_equal iv["body_hex"], im.bytes.unpack1("H*")
    assert_equal iv["head_hex"], im.head.unpack1("H*")
    assert_equal iv["id_hex"], im.id.unpack1("H*")
    assert_equal iv["foreign_id_hex"], im.foreign_id.unpack1("H*")
  end

  def test_unknown_format_rejected
    uf = C["import"]["unknown_format"]
    err = assert_raises(Naalp::Description::DescriptionError) do
      Naalp::Description.parse_import(hb(uf["body_hex"]))
    end
    assert_equal "UnknownDescriptionFormat", err.kind
  end

  # ---- offline verification, in isolation (NOT corpus-graded) ----------------------------

  def test_offline_verification_roundtrip
    signer = mk_key(21)
    dv = C["description"]
    d = Naalp::Description::Description.new(hb(dv["service_hex"]), ops_from(dv["operations"]))
    signed = Naalp::Description.sign_description(d, ALG, signer.seed)
    # the SAME signed bytes verify identically no matter who serves them (authority = signature)
    got = Naalp::Description.verify_description(signed, PROFILE, ALG, signer.pk)
    assert_equal d.bytes, got.bytes
    op, ok = got.operation("purge")
    assert ok
    assert_equal Naalp::Policy::DESTRUCTIVE, op.effect_class
    # a tampered copy is rejected BadSignature (the bytes are the authority)
    bad = signed.dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
    err = assert_raises(Naalp::Description::DescriptionError) do
      Naalp::Description.verify_description(bad, PROFILE, ALG, signer.pk)
    end
    assert_equal "BadSignature", err.kind
  end

  def test_directory_fork_proof_in_isolation
    signer = mk_key(22)
    dv = C["directory"]
    a = dir_a
    b = Naalp::Description::Directory.new(hb(dv["directory_hex"]), dv["version"],
                                          dv["fork"]["members_b_hex"].map { |m| hb(m) })
    sa = Naalp::Description.sign_directory(a, ALG, signer.seed)
    sb = Naalp::Description.sign_directory(b, ALG, signer.seed)
    fp = Naalp::Description::DirectoryForkProof.new(signer.id, sa, sb)
    pos = fp.verify(PROFILE, ALG, signer.pk)
    assert_equal dv["fork"]["first_differing_position"], pos
    # a "fork proof" of one directory against itself is not evidence of equivocation.
    fp_same = Naalp::Description::DirectoryForkProof.new(signer.id, sa, sa)
    err = assert_raises(Naalp::Description::DescriptionError) do
      fp_same.verify(PROFILE, ALG, signer.pk)
    end
    assert_equal "DirForkProofInvalid", err.kind
  end

  def test_import_confused_deputy_in_isolation
    # The importer (the wrapping signer, recomputed from the verifying key) is the SOLE authority; a
    # foreign identity in the carried bytes never becomes one (R-14.6).
    signer = mk_key(23)
    iv = C["import"]
    foreign = hb(iv["foreign_hex"])
    im = Naalp::Description::Import.new(signer.id, Naalp::Description::FORMAT_ANP_DESCRIPTION, foreign,
                                        ops_from(iv["operations"]))
    signed = Naalp::Description.sign_import(im, ALG, signer.seed)
    r = Naalp::Description.verify_import(signed, PROFILE, ALG, signer.pk)
    assert_equal signer.id, r.authority_id # recomputed from the key
    assert_equal Naalp::Description.content_id(foreign), r.foreign_id
    # a signer that names a DIFFERENT importer than its own key id imports as nobody -> rejected.
    forged = Naalp::Description::Import.new("SOMEONE_ELSE".b, Naalp::Description::FORMAT_ANP_DESCRIPTION,
                                            foreign, ops_from(iv["operations"]))
    signed_forged = Naalp::Description.sign_import(forged, ALG, signer.seed)
    err = assert_raises(Naalp::Description::DescriptionError) do
      Naalp::Description.verify_import(signed_forged, PROFILE, ALG, signer.pk)
    end
    assert_equal "ImporterMismatch", err.kind
  end
end
