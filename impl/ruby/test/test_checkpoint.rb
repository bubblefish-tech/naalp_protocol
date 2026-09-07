# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# S3 naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof conformance for the Ruby
# SDK, graded against the shared independent corpus vectors/checkpoint/cases.json (NOT produced by
# this code): RFC 9162-profiled Merkle math (leaf hash, interior node hash, empty-tree KAT),
# byte-exact checkpoint/witness-cosign/inclusion-proof body/head/content-id, fork evidence,
# inclusion-proof verification against the resolved checkpoint's own size/root, and the named
# negative rejections (witness-root mismatch, wrong index, wrong path, descending-key body,
# missing mandatory field).
#
# Mirrors impl/python/tests/test_checkpoint.py and impl/go/gateway/checkpoint_test.go.
#
# Run:  ruby -Ilib -Itest test/test_checkpoint.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def checkpoint_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "checkpoint", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/checkpoint/cases.json not found"
end

def hbc(hex)
  [hex].pack("H*")
end

class CheckpointConformance < Minitest::Test
  C = checkpoint_vectors

  def cp_from(cv)
    Naalp::Gateway::CheckpointRoot.new(hbc(cv["log_hex"]), cv["size"], hbc(cv["root_hex"]), hbc(cv["prev_hex"]), Integer(cv["at_str"]))
  end

  def wc_from(wv)
    Naalp::Gateway::WitnessCosign.new(hbc(wv["witness_hex"]), hbc(wv["root_hex"]), Integer(wv["at_str"]))
  end

  def test_checkpoint_bodies_match_oracle
    assert_equal C["genesis"]["prev_hex"], Naalp::Gateway.genesis_prev.unpack1("H*")
    C["checkpoints"].each do |name, cv|
      c = cp_from(cv)
      assert_equal cv["body_hex"], c.bytes.unpack1("H*"), name
      assert_equal cv["head_hex"], c.head.unpack1("H*"), name
      assert_equal cv["id_hex"], c.id.unpack1("H*"), name
      parsed = Naalp::Gateway.parse_checkpoint_root(c.bytes)
      assert_equal cv["body_hex"], parsed.bytes.unpack1("H*"), name
    end
  end

  def test_witness_cosign_byte_parity
    C["witness_cosigns"].each do |name, wv|
      w = wc_from(wv)
      assert_equal wv["body_hex"], w.bytes.unpack1("H*"), name
      assert_equal wv["head_hex"], w.head.unpack1("H*"), name
      assert_equal wv["id_hex"], w.id.unpack1("H*"), name
    end
  end

  def test_fork_evidence
    fe = C["fork_evidence"]
    refute_equal fe["checkpoint_a"]["root_hex"], fe["checkpoint_b"]["root_hex"]
    refute_equal fe["checkpoint_a"]["id_hex"], fe["checkpoint_b"]["id_hex"]

    wc_a = wc_from(fe["checkpoint_a"]["witness_cosign"])
    wc_b = wc_from(fe["checkpoint_b"]["witness_cosign"])
    assert_equal fe["checkpoint_a"]["witness_cosign"]["body_hex"], wc_a.bytes.unpack1("H*")
    assert_equal fe["checkpoint_b"]["witness_cosign"]["body_hex"], wc_b.bytes.unpack1("H*")

    id_a = hbc(fe["checkpoint_a"]["id_hex"])
    id_b = hbc(fe["checkpoint_b"]["id_hex"])
    Naalp::Gateway.validate_witness_cosign(wc_a, id_a) # no raise
    Naalp::Gateway.validate_witness_cosign(wc_b, id_b) # no raise
    err = assert_raises(Naalp::Gateway::WitnessRootMismatch) { Naalp::Gateway.validate_witness_cosign(wc_a, id_b) }
    assert_equal "WitnessRootMismatch", err.kind
    err2 = assert_raises(Naalp::Gateway::WitnessRootMismatch) { Naalp::Gateway.validate_witness_cosign(wc_b, id_a) }
    assert_equal "WitnessRootMismatch", err2.kind
  end

  def test_inclusion_proof_byte_parity_and_verify
    checkpoint_for = {
      "leaf3_of7" => "checkpoint0_size7",
      "leaf7_of8_newly_appended" => "checkpoint1_size8",
      "single_leaf_tree_empty_path" => "checkpoint_single_leaf",
    }
    C["inclusion_proofs"].each do |name, iv|
      cp_name = checkpoint_for.fetch(name)
      cp = C["checkpoints"][cp_name]
      resolved_id = cp_from(cp).id
      assert_equal iv["root_hex"], resolved_id.unpack1("H*"), name

      p = Naalp::Gateway::InclusionProof.new(hbc(iv["root_hex"]), hbc(iv["leaf_hex"]), iv["index"], iv["path_hex"].map { |h| hbc(h) })
      assert_equal iv["body_hex"], p.bytes.unpack1("H*"), name
      assert_equal iv["head_hex"], p.head.unpack1("H*"), name
      assert_equal iv["id_hex"], p.id.unpack1("H*"), name
      parsed = Naalp::Gateway.parse_inclusion_proof(p.bytes)
      Naalp::Gateway.verify_inclusion_proof(parsed.leaf, parsed.index, cp["size"], parsed.path, hbc(cp["root_hex"])) # no raise
    end
  end

  def test_inclusion_proof_negative
    cp0 = C["checkpoints"]["checkpoint0_size7"]
    root0 = hbc(cp0["root_hex"])

    wi = C["negative"]["inclusion_wrong_index"]
    err = assert_raises(Naalp::Gateway::InclusionProofInvalid) do
      Naalp::Gateway.verify_inclusion_proof(hbc(wi["leaf_hex"]), wi["claimed_index"], cp0["size"], wi["path_hex"].map { |h| hbc(h) }, root0)
    end
    assert_equal "InclusionProofInvalid", err.kind

    wp = C["negative"]["inclusion_wrong_path"]
    err2 = assert_raises(Naalp::Gateway::InclusionProofInvalid) do
      Naalp::Gateway.verify_inclusion_proof(hbc(wp["leaf_hex"]), wp["index"], cp0["size"], wp["path_hex"].map { |h| hbc(h) }, root0)
    end
    assert_equal "InclusionProofInvalid", err2.kind
  end

  def test_witness_root_mismatch
    wm = C["negative"]["witness_root_mismatch"]
    w = Naalp::Gateway.parse_witness_cosign(hbc(wm["cosign_body_hex"]))
    assert_equal wm["cosign_names_root_hex"], w.root.unpack1("H*")
    err = assert_raises(Naalp::Gateway::WitnessRootMismatch) do
      Naalp::Gateway.validate_witness_cosign(w, hbc(wm["checkpoint_accompanied_id_hex"]))
    end
    assert_equal wm["reject"], err.kind
  end

  def test_checkpoint_negative
    koo = C["negative"]["checkpoint_keys_out_of_order"]
    Naalp::Gateway.parse_checkpoint_root(hbc(koo["canonical_body_hex"])) # should parse
    assert_raises(Naalp::CBOR::NonCanonical) { Naalp::CBOR.decode(hbc(koo["noncanonical_body_hex"])) }
    err = assert_raises(Naalp::Gateway::CheckpointMalformed) { Naalp::Gateway.parse_checkpoint_root(hbc(koo["noncanonical_body_hex"])) }
    assert_equal "CheckpointMalformed", err.kind

    mf = C["negative"]["checkpoint_missing_field"]
    err2 = assert_raises(Naalp::Gateway::CheckpointMalformed) { Naalp::Gateway.parse_checkpoint_root(hbc(mf["body_hex"])) }
    assert_equal mf["reject"], err2.kind
  end

  def test_empty_tree_kat
    want = C["empty_tree_kat"]["root_hex"]
    assert_equal want, Naalp::Gateway.merkle_root(nil).unpack1("H*")
    assert_equal want, Naalp::Gateway.merkle_root([]).unpack1("H*")
  end

  def test_rfc9162_self_fidelity
    # Independently re-derives the oracle's own claimed property using Ruby's OWN Merkle
    # construction over synthetic leaves -- never the oracle's numbers -- so this test would catch
    # an algorithmic defect the byte-parity vectors above (which only exercise n in {1,7,8}) do not
    # reach.
    total = 0
    (1..12).each do |n|
      leaves = (0...n).map { |i| "synthetic-leaf-#{i}".b }
      root = Naalp::Gateway.merkle_root(leaves)
      (0...n).each do |m|
        path = Naalp::Gateway.generate_inclusion_proof_path(leaves, m)
        Naalp::Gateway.verify_inclusion_proof(leaves[m], m, n, path, root) # no raise
        total += 1
      end
    end
    assert_equal 78, total # sum(1..12) == 78, matching the oracle's own count

    # A tampered leaf must NOT verify against the untouched root.
    leaves = (0...5).map { |i| "synthetic-leaf-#{i}".b }
    root = Naalp::Gateway.merkle_root(leaves)
    path = Naalp::Gateway.generate_inclusion_proof_path(leaves, 2)
    err = assert_raises(Naalp::Gateway::InclusionProofInvalid) do
      Naalp::Gateway.verify_inclusion_proof("tampered-leaf".b, 2, 5, path, root)
    end
    assert_equal "InclusionProofInvalid", err.kind
  end

  def test_sign_verify_checkpoint_in_isolation
    # NOT corpus-graded (the corpus carries no signed COSE vector): demonstrates
    # sign/verify_checkpoint_root round-tripping in isolation with a local seed.
    cv = C["checkpoints"]["checkpoint0_size7"]
    c = cp_from(cv)
    seed = ("\x11" * 32).b
    alg = Naalp::COSE::ALG_MLDSA65
    begin
      pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    obj = Naalp::Gateway.sign_checkpoint_root(c, alg, seed)
    prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj)
    assert Naalp::COSE.cose_verify1_raw(alg, pk, Naalp::COSE.to_be_signed_raw(prot, payload), sig)
    assert_equal c.bytes, payload
  end
end
