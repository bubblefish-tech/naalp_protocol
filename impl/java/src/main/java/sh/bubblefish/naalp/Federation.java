// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * N-AALP Federation higher tier (tier 1) for the Java SDK — federated ordering by a deterministic
 * reconcile-merge over the shared causal graph (design.md §8.4; design-channels.md §7; R-8.6,
 * R-15A.2, R-15A.3).
 *
 * <p>The baseline tier is a single ordering authority's monotonic receipt chain (C7). The higher tier
 * lets multiple independent authorities each order their own scope and reconcile over the shared
 * causal graph — the partial order every authority already signs over (§8.2). Reconcile is a
 * DETERMINISTIC linearization of the union causal DAG: a topological sort whose tie-break among
 * causally-concurrent objects is the object content id (bytewise ascending). Because it depends only
 * on the causal graph (not on how scopes are split), any split of the same objects reconciles to the
 * same order — so moving from single-authority to federated ordering requires no envelope or object
 * change (R-8.6). An independent transcription of impl/go/federation, graded against the shared
 * vectors/federation/cases.json. The causal partial order is checked by the shared {@link Graph} (the
 * C7/audit foundation), exactly as the reference federation package reuses the audit layer.
 */
public final class Federation {
    private Federation() {}

    /**
     * A node's place in the shared causal graph: its content id and the content ids of its causes
     * (envelope field 8). The federated tier reconciles by these causal edges and the content-id
     * tie-break; the single-authority future-cause position check lives in the baseline tier.
     */
    public static final class CausalNode {
        public final byte[] id;
        public final List<byte[]> causes;

        public CausalNode(byte[] id, List<byte[]> causes) {
            this.id = id;
            this.causes = new ArrayList<>(causes);
        }
    }

    /**
     * The tier-1 Reconcile object body (design-channels.md §7): the authorities reconciled and the
     * resulting deterministic total order (object content ids). Signed with the C2 crypto over its
     * deterministic-CBOR bytes; it orders the identical signed objects the baseline already produced
     * (no envelope change).
     */
    public static final class ReconcileRecord {
        public final List<String> authorities;
        public final List<byte[]> order;

        public ReconcileRecord(List<String> authorities, List<byte[]> order) {
            this.authorities = new ArrayList<>(authorities);
            this.order = new ArrayList<>(order);
        }

        /** Deterministic-CBOR encoding {1: [authorities], 2: [order content-ids]}. */
        public byte[] bytes() {
            List<Cbor.Value> auth = new ArrayList<>(authorities.size());
            for (String a : authorities) {
                auth.add(new Cbor.T(a));
            }
            List<Cbor.Value> ordr = new ArrayList<>(order.size());
            for (byte[] o : order) {
                ordr.add(new Cbor.B(o));
            }
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.A(auth)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.A(ordr)))));
        }
    }

    /**
     * Reconcile deterministically merges the objects of a shared causal graph into one total order
     * (design.md §8.4). It first verifies the graph is a valid partial order (acyclic, no future-cause)
     * via the shared {@link Graph}, then linearizes it with Kahn's algorithm, breaking ties among ready
     * nodes by content id (bytewise ascending). The result is causally consistent and deterministic. A
     * duplicate object id (scope overlap) is ordered once (resolved).
     */
    public static List<byte[]> reconcile(List<CausalNode> nodes) {
        List<Graph.Node> gnodes = new ArrayList<>(nodes.size());
        for (CausalNode n : nodes) {
            gnodes.add(new Graph.Node(n.id, n.causes, 0));
        }
        Graph.verifyCausal(gnodes); // acyclic + no-future-cause, fail-closed (CausalViolation)

        int n = nodes.size();
        List<byte[]> ids = new ArrayList<>(n);
        for (CausalNode node : nodes) {
            ids.add(node.id);
        }
        Set<String> present = new HashSet<>();
        for (byte[] id : ids) {
            present.add(Hex.encode(id));
        }
        List<List<byte[]>> causes = new ArrayList<>(n);
        for (CausalNode node : nodes) {
            List<byte[]> filtered = new ArrayList<>();
            for (byte[] c : node.causes) {
                if (present.contains(Hex.encode(c))) {
                    filtered.add(c);
                }
            }
            causes.add(filtered);
        }
        int[] indeg = new int[n];
        for (int i = 0; i < n; i++) {
            indeg[i] = causes.get(i).size();
        }
        boolean[] done = new boolean[n];
        List<byte[]> order = new ArrayList<>(n);
        while (order.size() < n) {
            int pick = -1;
            for (int i = 0; i < n; i++) {
                if (done[i] || indeg[i] != 0) {
                    continue;
                }
                if (pick == -1 || Cbor.compareBytes(ids.get(i), ids.get(pick)) < 0) {
                    pick = i;
                }
            }
            if (pick == -1) {
                // unreachable after verifyCausal, but fail-closed rather than loop forever
                throw new NaalpException("CausalViolation", "no ready node");
            }
            done[pick] = true;
            order.add(ids.get(pick));
            for (int j = 0; j < n; j++) {
                if (!done[j]) {
                    for (byte[] c : causes.get(j)) {
                        if (Cbor.compareBytes(c, ids.get(pick)) == 0) {
                            indeg[j]--;
                            break;
                        }
                    }
                }
            }
        }
        return order;
    }

    /** Reports whether an order places every object's (present) causes before it. */
    public static boolean causallyValid(List<byte[]> order, List<CausalNode> nodes) {
        java.util.Map<String, Integer> pos = new java.util.HashMap<>();
        for (int k = 0; k < order.size(); k++) {
            pos.put(Hex.encode(order.get(k)), k);
        }
        for (CausalNode n : nodes) {
            Integer np = pos.get(Hex.encode(n.id));
            if (np == null) {
                continue;
            }
            for (byte[] c : n.causes) {
                Integer cp = pos.get(Hex.encode(c));
                if (cp != null && cp > np) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Sign a Reconcile record with a tier-1 ordering authority's ML-DSA key: a deterministic FIPS-204
     * signature over the record's deterministic-CBOR bytes.
     */
    public static byte[] signReconcile(ReconcileRecord record, int alg, byte[] seed) {
        return Cose.mldsaSign(alg, seed, record.bytes());
    }

    /** Verify a raw Reconcile-record signature under the authority's public key. */
    public static boolean verifyReconcile(ReconcileRecord record, int alg, byte[] pubkey, byte[] sig) {
        return Cose.mldsaVerify(alg, pubkey, record.bytes(), sig);
    }

    private static NaalpException reconcileMismatch() {
        return new NaalpException("ReconcileMismatch",
                "independent linearization disagrees with the reconcile record's claimed order");
    }

    /**
     * The Reconcile state machine's verify event (ietf/draft-bubblefish-naalp-01.md "## Reconcile
     * state machine"): independently recompute the deterministic reconcile order from the shared
     * causal graph and check it against {@code record}'s claimed order. Recomputes via {@link
     * #reconcile} — the content-id tie-break — NEVER a position/index tie-break, which would
     * spuriously disagree on causally-concurrent objects that {@link #reconcile} orders identically
     * either way. A causal-graph fault (a cycle or a future cause) propagates fail-closed as
     * CausalViolation from {@link #reconcile}; a length or element mismatch between the recomputed
     * and claimed orders is {@code ReconcileMismatch}. Returns normally (no error) when the claimed
     * order IS the deterministic order — the record is verified.
     */
    public static void verifyReconcileOrder(ReconcileRecord record, List<CausalNode> nodes) {
        List<byte[]> recomputed = reconcile(nodes); // CausalViolation propagates fail-closed
        if (recomputed.size() != record.order.size()) {
            throw reconcileMismatch();
        }
        for (int i = 0; i < recomputed.size(); i++) {
            if (!Arrays.equals(recomputed.get(i), record.order.get(i))) {
                throw reconcileMismatch();
            }
        }
    }
}
