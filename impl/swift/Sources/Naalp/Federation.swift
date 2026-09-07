// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP Federation higher tier (tier 1) for the Swift SDK — federated ordering by a deterministic
// reconcile-merge over the shared causal graph (design.md §8.4; design-channels.md §7; R-8.6,
// R-15A.2, R-15A.3).
//
// The baseline tier is a single ordering authority's monotonic receipt chain (C7). The higher tier
// lets multiple independent authorities each order their own scope and reconcile over the shared
// causal graph — the partial order every authority already signs over (§8.2). Reconcile is a
// DETERMINISTIC linearization of the union causal DAG: a topological sort whose tie-break among
// causally-concurrent objects is the object content id (bytewise ascending). Because it depends
// only on the causal graph (not on how scopes are split), any split of the same objects reconciles
// to the same order — so moving from single-authority to federated ordering requires no envelope or
// object change (R-8.6). A higher tier adds capability without changing the baseline
// envelope/effect/identity/audit (R-15A.2).
//
// An independent transcription of impl/go/federation, graded against the shared
// vectors/federation/cases.json. The causal partial order is checked by the shared Naalp.Graph (the
// C7/audit foundation), exactly as the reference reuses the audit layer.
//
// CRYPTO SCOPE (PURE-ONLY): Swift cannot deterministically sign or verify ML-DSA (FIPS 204) with
// SwiftDilithium 3.6.0, so the reference's ML-DSA Reconcile-record signature is provided here as an
// Ed25519 (RFC 8032) signing DEMONSTRATION (signReconcile / verifyReconcile via swift-crypto) —
// exercised in isolation, NOT corpus-graded. The corpus-graded deliverable is the pure reconcile /
// causal-validity / record-bytes logic.

import Foundation

public enum Federation {

    /// A node's place in the shared causal graph: its content id and the content ids of its causes
    /// (envelope field 8). The federated tier reconciles by these causal edges and the content-id
    /// tie-break; the single-authority future-cause position check lives in the baseline tier.
    public struct CausalNode {
        public let id: [UInt8]
        public let causes: [[UInt8]]
        public init(id: [UInt8], causes: [[UInt8]]) {
            self.id = id
            self.causes = causes
        }
    }

    /// The tier-1 Reconcile object body (design-channels.md §7): the authorities reconciled and the
    /// resulting deterministic total order (object content ids). Signed with the C2 crypto over its
    /// deterministic-CBOR bytes; it orders the identical signed objects the baseline already
    /// produced (no envelope change).
    public struct ReconcileRecord {
        public let authorities: [String]
        public let order: [[UInt8]]
        public init(authorities: [String], order: [[UInt8]]) {
            self.authorities = authorities
            self.order = order
        }

        /// Deterministic-CBOR encoding {1: [authorities], 2: [order content-ids]}.
        public func bytes() throws -> [UInt8] {
            let auth = CborValue.a(authorities.map { .t($0) })
            let ordr = CborValue.a(order.map { .b($0) })
            return try Cbor.encode(.m([
                (.u(1), auth),
                (.u(2), ordr),
            ]))
        }
    }

    /// Reconcile deterministically merges the objects of a shared causal graph into one total order
    /// (design.md §8.4). It first verifies the graph is a valid partial order (acyclic, no
    /// future-cause) via the shared Naalp.Graph, then linearizes it with Kahn's algorithm, breaking
    /// ties among ready nodes by content id (bytewise ascending). The result is causally consistent
    /// and deterministic. A duplicate object id (scope overlap) is ordered once (resolved).
    public static func reconcile(_ nodes: [CausalNode]) throws -> [[UInt8]] {
        // Verify the shared partial order via the C7/audit foundation. The federated tier
        // reconciles by causal edges alone (position 0), so it is the acyclicity that matters here;
        // the single-authority future-cause position check belongs to the baseline tier.
        try Graph.verifyCausal(nodes.map { Graph.Node(id: $0.id, causes: $0.causes, position: 0) })

        let ids = nodes.map { $0.id }
        var present = Set<[UInt8]>()
        for id in ids { present.insert(id) }
        // keep only causes that are present in this graph (a cause outside the scope is not an edge).
        let causes: [[[UInt8]]] = nodes.map { n in n.causes.filter { present.contains($0) } }
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
                // unreachable after verifyCausal, but fail-closed rather than loop forever.
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

    /// Reports whether an order places every object's (present) causes before it.
    public static func causallyValid(_ order: [[UInt8]], _ nodes: [CausalNode]) -> Bool {
        var pos: [[UInt8]: Int] = [:]
        for (k, id) in order.enumerated() {
            pos[id] = k
        }
        for n in nodes {
            guard let np = pos[n.id] else { continue }
            for c in n.causes {
                if let cp = pos[c], cp > np {
                    return false
                }
            }
        }
        return true
    }

    /// Ed25519 signing DEMONSTRATION (isolation, NOT corpus-graded): a tier-1 ordering authority
    /// signs a Reconcile record with a deterministic Ed25519 (RFC 8032) signature over the record's
    /// deterministic-CBOR bytes. Swift is PURE-ONLY for ML-DSA, so this stands in for the
    /// reference's ML-DSA signature to exercise the signing binding end-to-end.
    public static func signReconcile(_ record: ReconcileRecord, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.ed25519Sign(seed, try record.bytes())
    }

    /// Verify a raw Ed25519 Reconcile-record signature under the authority's public key.
    public static func verifyReconcile(_ record: ReconcileRecord, _ pubkey: [UInt8], _ sig: [UInt8]) throws -> Bool {
        return Cose.ed25519Verify(pubkey, try record.bytes(), sig)
    }

    /// verifyReconcileOrder is the verify-event choke point of the Reconcile state machine (draft "##
    /// Reconcile state machine", error code 61). A verifier independently re-runs the deterministic
    /// linearization over the identical causal graph and rejects the record whole (ReconcileMismatch)
    /// if the recomputed total order differs from the one the record claims. It MUST recompute via
    /// `reconcile(_:)` — the content-id tie-break — and NEVER a position-tie-broken topological sort
    /// (Naalp.Graph.topoOrder / Audit.topoOrder), which would spuriously disagree on
    /// causally-concurrent objects. A node set that is not a valid partial order is rejected under
    /// that fault (CausalViolation), fail-closed, propagated unchanged. Returns normally only when
    /// the record's claimed order is byte-for-byte the deterministic order (verified).
    ///
    /// This is distinct from the per-port signature-verify `verifyReconcile(record, pubkey, sig)`,
    /// which checks the Ed25519 signature over the record bytes; `verifyReconcileOrder` verifies the
    /// ORDER, not the signature. Named ...Order uniformly across all ten ports so one parity token
    /// cannot collide with the signature-verify name.
    public static func verifyReconcileOrder(_ record: ReconcileRecord, _ nodes: [CausalNode]) throws {
        let recomputed = try reconcile(nodes) // CausalViolation propagates: the graph is not a valid partial order
        if recomputed.count != record.order.count {
            throw NaalpError("ReconcileMismatch", "independent linearization disagrees with the reconcile record's claimed order")
        }
        for i in 0..<recomputed.count {
            if recomputed[i] != record.order[i] {
                throw NaalpError("ReconcileMismatch", "independent linearization disagrees with the reconcile record's claimed order")
            }
        }
        // the claimed order is the deterministic order: return normally (verified).
    }
}
