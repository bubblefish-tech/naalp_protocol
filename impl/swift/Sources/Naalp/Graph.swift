// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP causal graph (C7, §8.2-§8.3) and federation reconcile (T13, §8.6) for the Swift SDK.
//
// verifyCausal enforces no-future-cause (a present cause may not sit at a later position than
// its effect) and acyclicity. reconcile is the deterministic merge: a topological linearization
// of the union causal DAG, ties broken by content id (bytewise), scope-independent (R-8.6).

import Foundation

public enum Graph {

    public struct Node {
        public let id: [UInt8]
        public let causes: [[UInt8]]
        public let position: Int
        public init(id: [UInt8], causes: [[UInt8]], position: Int) {
            self.id = id
            self.causes = causes
            self.position = position
        }
    }

    /// Enforce no-future-cause and acyclicity, or throw CausalViolation.
    public static func verifyCausal(_ nodes: [Node]) throws {
        // Index id -> position in `nodes`; on duplicate ids the last occurrence wins
        // (matching the Python dict-comprehension semantics).
        var idx: [[UInt8]: Int] = [:]
        for (i, node) in nodes.enumerated() {
            idx[node.id] = i
        }

        // no future cause
        for node in nodes {
            for c in node.causes {
                if let j = idx[c], nodes[j].position > node.position {
                    throw NaalpError("CausalViolation", "cause at a later position than its effect")
                }
            }
        }

        // acyclic (3-colour DFS over effect -> cause edges)
        let WHITE = 0, GRAY = 1, BLACK = 2
        var color = [Int](repeating: WHITE, count: nodes.count)

        func hasCycle(_ i: Int) -> Bool {
            color[i] = GRAY
            for c in nodes[i].causes {
                guard let j = idx[c] else { continue }
                if color[j] == GRAY { return true }
                if color[j] == WHITE && hasCycle(j) { return true }
            }
            color[i] = BLACK
            return false
        }

        for i in 0..<nodes.count {
            if color[i] == WHITE && hasCycle(i) {
                throw NaalpError("CausalViolation", "causal graph contains a cycle")
            }
        }
    }

    /// Deterministic topological merge over the union causal DAG; ties break by content id.
    public static func reconcile(_ nodes: [Node]) throws -> [[UInt8]] {
        try verifyCausal(nodes)
        let ids = nodes.map { $0.id }
        var present = Set<[UInt8]>()
        for id in ids { present.insert(id) }
        let causes: [[[UInt8]]] = nodes.map { node in
            node.causes.filter { present.contains($0) }
        }
        var indeg = causes.map { $0.count }
        var done = [Bool](repeating: false, count: nodes.count)
        var order: [[UInt8]] = []

        while order.count < nodes.count {
            var pick = -1
            for i in 0..<nodes.count {
                if done[i] || indeg[i] != 0 { continue }
                if pick == -1 || Cbor.lexLess(ids[i], ids[pick]) {
                    pick = i
                }
            }
            if pick == -1 {
                throw NaalpError("CausalViolation", "no ready node (unreachable after verifyCausal)")
            }
            done[pick] = true
            order.append(ids[pick])
            for j in 0..<nodes.count where !done[j] {
                if causes[j].contains(ids[pick]) {
                    indeg[j] -= 1
                }
            }
        }
        return order
    }

    /// The tier-1 Reconcile body {1: [authorities], 2: [order content-ids]}.
    public static func reconcileRecord(_ authorities: [String], _ order: [[UInt8]]) throws -> [UInt8] {
        let auth = CborValue.a(authorities.map { .t($0) })
        let ordr = CborValue.a(order.map { .b($0) })
        return try Cbor.encode(.m([
            (.u(1), auth),
            (.u(2), ordr),
        ]))
    }
}
