# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# Federation higher-tier conformance for the Ruby SDK (design.md §8.4; design-channels.md §7;
# R-8.6), graded against the shared independent corpus vectors/federation/cases.json (NOT
# produced by this code). Reconcile is the deterministic linearization of the union causal DAG,
# tie-broken among causally-concurrent objects by content id (bytewise ascending): it MUST equal
# the oracle order, be causally valid, and beat the naive content-id sort (which is NOT causally
# valid). The tier-1 Reconcile record MUST encode to the oracle bytes. Written test-first; the
# module is absent until ported, so this fails RED on require until
# impl/ruby/lib/naalp/federation.rb lands, and a mutation that ignores the causal graph flips
# test_reconcile_matches_oracle.
#
# Run:  ruby -Ilib -Itest test/test_federation.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def federation_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "federation", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/federation/cases.json not found"
end

def bin(hex)
  [hex].pack("H*")
end

class FederationConformance < Minitest::Test
  C = federation_vectors

  def nodes
    C["nodes"].map do |n|
      Naalp::Federation::CausalNode.new(bin(n["id_hex"]), n["causes_hex"].map { |h| bin(h) })
    end
  end

  def test_reconcile_matches_oracle
    order = Naalp::Federation.reconcile(nodes)
    got = order.map { |id| id.unpack1("H*") }
    assert_equal C["reconcile_order_hex"], got, "reconcile order must equal the independent oracle"
  end

  def test_reconcile_order_is_causally_valid
    ns = nodes
    order = Naalp::Federation.reconcile(ns)
    assert Naalp::Federation.causally_valid(order, ns), "reconcile order must be causally valid"
  end

  def test_naive_sort_fails_causality
    ns = nodes
    naive = C["naive_content_id_sort_hex"].map { |h| bin(h) }
    assert_equal C["naive_causally_valid"],
                 Naalp::Federation.causally_valid(naive, ns),
                 "naive content-id sort's causal validity must match the oracle"
    refute C["naive_causally_valid"],
           "this graph's naive sort must violate causality (the mutation baseline)"
  end

  def test_reconcile_record_matches_oracle
    order = Naalp::Federation.reconcile(nodes)
    rec = Naalp::Federation::ReconcileRecord.new(C["authorities"], order)
    assert_equal C["record_hex"], rec.bytes.unpack1("H*"),
                 "the tier-1 Reconcile record must encode to the oracle bytes"
  end

  # R-8.6: the reconcile order depends only on the causal graph, not on how objects are split
  # across authorities' scopes. Any input permutation reconciles identically.
  def test_scope_independence
    base = Naalp::Federation.reconcile(nodes)
    reversed = Naalp::Federation.reconcile(nodes.reverse)
    assert_equal base.map { |x| x.unpack1("H*") }, reversed.map { |x| x.unpack1("H*") },
                 "reconcile must not depend on input (scope) order"
  end

  # An out-of-lattice cycle is rejected fail-closed (the causal partial order must hold).
  def test_cycle_rejected
    a = bin("2030" + ("aa" * 48))
    b = bin("2030" + ("bb" * 48))
    cyclic = [
      Naalp::Federation::CausalNode.new(a, [b]),
      Naalp::Federation::CausalNode.new(b, [a]),
    ]
    assert_raises(Naalp::Graph::CausalViolation) { Naalp::Federation.reconcile(cyclic) }
  end

  # The tier-1 ordering authority signs the Reconcile record; the raw signature verifies under
  # its key. (Skips loudly where deterministic ML-DSA is unavailable -- never a false green.)
  def test_sign_reconcile_roundtrip
    seed = ("\x2a" * 32).b
    begin
      pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    rec = Naalp::Federation::ReconcileRecord.new(C["authorities"], Naalp::Federation.reconcile(nodes))
    sig = Naalp::Federation.sign_reconcile(rec, Naalp::COSE::ALG_MLDSA65, seed)
    assert Naalp::Federation.verify_reconcile(rec, Naalp::COSE::ALG_MLDSA65, pk, sig),
           "a Reconcile record signed by the authority must verify under its key"
    # a tampered record must not verify under the same signature
    tampered = Naalp::Federation::ReconcileRecord.new(["bauthority-z"], rec.order)
    refute Naalp::Federation.verify_reconcile(tampered, Naalp::COSE::ALG_MLDSA65, pk, sig),
           "a tampered Reconcile record must not verify"
  end
end

# Mutation-surviving unit tests for Federation.verify_reconcile_order -- the verify-event choke
# point of the Reconcile state machine (draft "## Reconcile state machine"). Mirrors Go's
# TestVerifyReconcileOrder (impl/go/federation/verify_reconcile_test.go). Two causally-INDEPENDENT
# byte-id nodes id_a=[0x01], id_b=[0x02] (concurrent -> the one deterministic order is [id_a,
# id_b], since reconcile ties break by content id, bytewise ascending). The mutation that neuters
# the order comparison (always returns nil) flips test_mismatch and test_mismatch_length RED.
class VerifyReconcileOrderTest < Minitest::Test
  ID_A = "\x01".b
  ID_B = "\x02".b

  def concurrent_nodes
    [
      Naalp::Federation::CausalNode.new(ID_A, []),
      Naalp::Federation::CausalNode.new(ID_B, []),
    ]
  end

  # verify agrees: the claimed order IS the deterministic order -> verified (no raise, nil).
  def test_agrees
    rec = Naalp::Federation::ReconcileRecord.new(["auth-1"], [ID_A, ID_B])
    assert_nil Naalp::Federation.verify_reconcile_order(rec, concurrent_nodes)
  end

  # ReconcileMismatch: a causally-VALID-but-different order (the two objects are concurrent, so
  # [id_b, id_a] is causally valid) is not the deterministic order -> ReconcileMismatch.
  def test_mismatch
    rec = Naalp::Federation::ReconcileRecord.new(["auth-1"], [ID_B, ID_A])
    err = assert_raises(Naalp::Federation::ReconcileMismatch) do
      Naalp::Federation.verify_reconcile_order(rec, concurrent_nodes)
    end
    assert_equal "ReconcileMismatch", err.kind
  end

  # A wrong-length claim (drops or adds an element) -> ReconcileMismatch.
  def test_mismatch_length
    rec = Naalp::Federation::ReconcileRecord.new(["auth-1"], [ID_A])
    err = assert_raises(Naalp::Federation::ReconcileMismatch) do
      Naalp::Federation.verify_reconcile_order(rec, concurrent_nodes)
    end
    assert_equal "ReconcileMismatch", err.kind
  end

  # CausalViolation: a cyclic node set is not a valid partial order; the recomputation rejects it
  # before any order comparison, so the record is rejected under the graph fault, fail-closed.
  def test_causal_violation
    id_c = "\x03".b
    id_d = "\x04".b
    cyclic = [
      Naalp::Federation::CausalNode.new(id_c, [id_d]),
      Naalp::Federation::CausalNode.new(id_d, [id_c]),
    ]
    rec = Naalp::Federation::ReconcileRecord.new(["auth-1"], [id_c, id_d])
    err = assert_raises(Naalp::Graph::CausalViolation) do
      Naalp::Federation.verify_reconcile_order(rec, cyclic)
    end
    assert_equal "CausalViolation", err.kind
  end
end
