# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP causal graph (C7, §8.2-§8.3) and federation reconcile (T13, §8.6) for the Ruby SDK.
#
# verify_causal enforces no-future-cause (a present cause may not sit at a later position than
# its effect) and acyclicity. reconcile is the deterministic merge: a topological linearization
# of the union causal DAG, ties broken by content id (bytewise), scope-independent (R-8.6).
require_relative 'cbor'

module Naalp
  module Graph
    class CausalViolation < StandardError
      def kind; "CausalViolation"; end
    end

    module_function

    # nodes: array of [id (binary str), causes (array of binary str), position (int)].
    def verify_causal(nodes)
      idx = {}
      nodes.each_with_index { |(nid, _causes, _pos), i| idx[nid] = i }

      # no future cause
      nodes.each do |_nid, causes, pos|
        causes.each do |c|
          j = idx[c]
          if !j.nil? && nodes[j][2] > pos
            raise CausalViolation, "cause at a later position than its effect"
          end
        end
      end

      # acyclic (3-colour DFS over effect -> cause edges)
      white, gray, black = 0, 1, 2
      color = Array.new(nodes.length, white)

      has_cycle = lambda do |i|
        color[i] = gray
        nodes[i][1].each do |c|
          j = idx[c]
          next if j.nil?
          return true if color[j] == gray
          return true if color[j] == white && has_cycle.call(j)
        end
        color[i] = black
        false
      end

      nodes.each_index do |i|
        if color[i] == white && has_cycle.call(i)
          raise CausalViolation, "causal graph contains a cycle"
        end
      end
      nil
    end

    # Deterministic topological merge over the union causal DAG; ties break by content id.
    def reconcile(nodes)
      verify_causal(nodes)
      ids = nodes.map { |nid, _c, _p| nid }
      present = {}
      ids.each { |id| present[id] = true }
      causes = nodes.map { |_nid, cs, _p| cs.select { |c| present[c] } }
      indeg = causes.map(&:length)
      done = Array.new(nodes.length, false)
      order = []
      while order.length < nodes.length
        pick = -1
        nodes.each_index do |i|
          next if done[i] || indeg[i] != 0
          pick = i if pick == -1 || (ids[i] <=> ids[pick]) < 0
        end
        raise CausalViolation, "no ready node (unreachable after verify_causal)" if pick == -1
        done[pick] = true
        order << ids[pick]
        nodes.each_index do |j|
          if !done[j] && causes[j].include?(ids[pick])
            indeg[j] -= 1
          end
        end
      end
      order
    end

    # The tier-1 Reconcile body {1: [authorities], 2: [order content-ids]}.
    def reconcile_record(authorities, order)
      auth = Naalp::CBOR::A.new(authorities.map { |a| Naalp::CBOR::T.new(a) })
      ordr = Naalp::CBOR::A.new(order.map { |o| Naalp::CBOR::B.new(o) })
      Naalp::CBOR.encode(
        Naalp::CBOR::M.new([[Naalp::CBOR::U.new(1), auth], [Naalp::CBOR::U.new(2), ordr]])
      )
    end
  end
end
