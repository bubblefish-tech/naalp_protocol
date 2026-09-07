# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP Federation higher tier (tier 1) for the Ruby SDK -- federated ordering by a
# deterministic reconcile-merge over the shared causal graph (design.md §8.4;
# design-channels.md §7; R-8.6, R-15A.2, R-15A.3).
#
# The baseline tier is a single ordering authority's monotonic receipt chain (C7). The higher
# tier lets multiple independent authorities each order their own scope and reconcile over the
# shared causal graph -- the partial order every authority already signs over (§8.2). Reconcile
# is a DETERMINISTIC linearization of the union causal DAG: a topological sort whose tie-break
# among causally-concurrent objects is the object content id (bytewise ascending). Because it
# depends only on the causal graph (not on how scopes are split), any split of the same objects
# reconciles to the same order -- so moving from single-authority to federated ordering requires
# no envelope or object change (R-8.6). An independent transcription of the design, graded against
# the shared vectors/federation/cases.json. The causal partial order is checked by the shared
# Naalp::Graph (the C7/audit foundation), exactly as the reference reuses the audit layer.
require 'openssl'
require_relative 'cbor'
require_relative 'cose'
require_relative 'graph'

module Naalp
  module Federation
    # ReconcileMismatch (error code 61) is the verify-event reject of the Reconcile state machine
    # (draft "## Reconcile state machine"): an independent recomputation of the deterministic
    # linearization disagrees with the total order a Reconcile record claims, so the record is
    # rejected whole. Emitted by verify_reconcile_order.
    class ReconcileMismatch < StandardError
      def kind; "ReconcileMismatch"; end
    end

    # A node's place in the shared causal graph: its content id and the content ids of its causes
    # (envelope field 8). The federated tier reconciles by these causal edges and the content-id
    # tie-break; the single-authority future-cause position check lives in the baseline tier.
    CausalNode = Struct.new(:id, :causes)

    # The tier-1 Reconcile object body (design-channels.md §7): the authorities reconciled and the
    # resulting deterministic total order (object content ids). Signed with the C2 crypto over its
    # deterministic-CBOR bytes; it orders the identical signed objects the baseline already
    # produced (no envelope change).
    ReconcileRecord = Struct.new(:authorities, :order) do
      # Deterministic-CBOR encoding {1: [authorities], 2: [order content-ids]}.
      def bytes
        auth = Naalp::CBOR::A.new(authorities.map { |a| Naalp::CBOR::T.new(a) })
        ordr = Naalp::CBOR::A.new(order.map { |o| Naalp::CBOR::B.new(o) })
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), auth],
          [Naalp::CBOR::U.new(2), ordr],
        ]))
      end
    end

    module_function

    # Reconcile deterministically merges the objects of a shared causal graph into one total order
    # (design.md §8.4). It first verifies the graph is a valid partial order (acyclic, no
    # future-cause) via the shared Naalp::Graph, then linearizes it with Kahn's algorithm, breaking
    # ties among ready nodes by content id (bytewise ascending). The result is causally consistent
    # and deterministic. A duplicate object id (scope overlap) is ordered once (resolved).
    def reconcile(nodes)
      Naalp::Graph.verify_causal(nodes.map { |n| [n.id, n.causes, 0] })
      ids = nodes.map(&:id)
      present = {}
      ids.each { |id| present[id] = true }
      causes = nodes.map { |n| n.causes.select { |c| present[c] } }
      indeg = causes.map(&:length)
      done = Array.new(nodes.length, false)
      order = []
      while order.length < nodes.length
        pick = -1
        nodes.each_index do |i|
          next if done[i] || indeg[i] != 0
          pick = i if pick == -1 || (ids[i] <=> ids[pick]) < 0
        end
        # unreachable after verify_causal, but fail-closed rather than loop forever
        raise Naalp::Graph::CausalViolation, "no ready node" if pick == -1
        done[pick] = true
        order << ids[pick]
        nodes.each_index do |j|
          indeg[j] -= 1 if !done[j] && causes[j].include?(ids[pick])
        end
      end
      order
    end

    # Reports whether an order places every object's (present) causes before it.
    def causally_valid(order, nodes)
      pos = {}
      order.each_with_index { |id, k| pos[id] = k }
      nodes.each do |n|
        np = pos[n.id]
        next if np.nil?
        n.causes.each do |c|
          cp = pos[c]
          return false if !cp.nil? && cp > np
        end
      end
      true
    end

    # Sign a Reconcile record with a tier-1 ordering authority's ML-DSA key: a raw deterministic
    # signature over the record's deterministic-CBOR bytes.
    def sign_reconcile(record, alg, seed)
      Naalp::COSE.mldsa_sign(alg, seed, record.bytes)
    end

    # Verify a raw Reconcile-record signature under the authority's public key.
    def verify_reconcile(record, alg, pubkey, sig)
      Naalp::COSE.mldsa_verify(alg, pubkey, record.bytes, sig)
    end

    # verify_reconcile_order is the verify-event choke point of the Reconcile state machine (draft
    # "## Reconcile state machine"). A verifier independently re-runs the deterministic
    # linearization over the identical causal graph and rejects the record whole
    # (ReconcileMismatch) if the recomputed total order differs from the one the record claims. It
    # MUST recompute via `reconcile` -- the content-id tie-break -- and NEVER
    # Naalp::Audit.topo_order, whose (position, input-index) tie-break would spuriously disagree on
    # causally-concurrent objects. A node set that is not a valid partial order is rejected under
    # that fault (Naalp::Graph::CausalViolation), fail-closed. Returns nil only when the record's
    # claimed order is byte-for-byte the deterministic order (verified).
    #
    # This is distinct from the signature-verify verify_reconcile(record, alg, pubkey, sig), which
    # checks the COSE signature over the record bytes; verify_reconcile_order verifies the ORDER,
    # not the signature. Named ...Order uniformly across all ten ports so one parity token cannot
    # collide with the signature-verify name.
    def verify_reconcile_order(record, nodes)
      recomputed = reconcile(nodes) # CausalViolation propagates fail-closed
      if recomputed.length != record.order.length
        raise ReconcileMismatch, "independent linearization disagrees with the reconcile record's claimed order"
      end
      recomputed.each_index do |i|
        if recomputed[i] != record.order[i]
          raise ReconcileMismatch, "independent linearization disagrees with the reconcile record's claimed order"
        end
      end
      nil # the claimed order is the deterministic order
    end
  end
end
