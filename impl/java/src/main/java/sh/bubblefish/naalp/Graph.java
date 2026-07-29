// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * N-AALP causal graph (C7, §8.2-§8.3) and federation reconcile (T13, §8.6) for the Java SDK.
 *
 * <p>verifyCausal enforces no-future-cause (a present cause may not sit at a later position than its
 * effect) and acyclicity. reconcile is the deterministic merge: a topological linearization of the
 * union causal DAG, ties broken by content id (bytewise), scope-independent (R-8.6).
 */
public final class Graph {
    private Graph() {}

    /** A causal node: content id, the ids it directly depends on, and its ordering position. */
    public static final class Node {
        public final byte[] id;
        public final List<byte[]> causes;
        public final long position;
        public Node(byte[] id, List<byte[]> causes, long position) {
            this.id = id;
            this.causes = causes;
            this.position = position;
        }
    }

    private static String key(byte[] b) {
        return Hex.encode(b);
    }

    public static void verifyCausal(List<Node> nodes) {
        Map<String, Integer> idx = new HashMap<>();
        for (int i = 0; i < nodes.size(); i++) {
            idx.put(key(nodes.get(i).id), i);
        }
        // no future cause
        for (Node n : nodes) {
            for (byte[] c : n.causes) {
                Integer j = idx.get(key(c));
                if (j != null && nodes.get(j).position > n.position) {
                    throw new NaalpException("CausalViolation", "cause at a later position than its effect");
                }
            }
        }
        // acyclic (3-colour DFS over effect -> cause edges)
        int[] color = new int[nodes.size()]; // 0 white, 1 gray, 2 black
        for (int i = 0; i < nodes.size(); i++) {
            if (color[i] == 0 && hasCycle(i, nodes, idx, color)) {
                throw new NaalpException("CausalViolation", "causal graph contains a cycle");
            }
        }
    }

    private static boolean hasCycle(int i, List<Node> nodes, Map<String, Integer> idx, int[] color) {
        color[i] = 1;
        for (byte[] c : nodes.get(i).causes) {
            Integer j = idx.get(key(c));
            if (j == null) {
                continue;
            }
            if (color[j] == 1) {
                return true;
            }
            if (color[j] == 0 && hasCycle(j, nodes, idx, color)) {
                return true;
            }
        }
        color[i] = 2;
        return false;
    }

    /** Deterministic topological merge over the union causal DAG; ties break by content id. */
    public static List<byte[]> reconcile(List<Node> nodes) {
        verifyCausal(nodes);
        int n = nodes.size();
        List<byte[]> ids = new ArrayList<>(n);
        for (Node node : nodes) {
            ids.add(node.id);
        }
        java.util.Set<String> present = new java.util.HashSet<>();
        for (byte[] id : ids) {
            present.add(key(id));
        }
        List<List<byte[]>> causes = new ArrayList<>(n);
        for (Node node : nodes) {
            List<byte[]> filtered = new ArrayList<>();
            for (byte[] c : node.causes) {
                if (present.contains(key(c))) {
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
                throw new NaalpException("CausalViolation", "no ready node (unreachable after verifyCausal)");
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

    /** The tier-1 Reconcile body {1: [authorities], 2: [order content-ids]}. */
    public static byte[] reconcileRecord(List<String> authorities, List<byte[]> order) {
        List<Cbor.Value> auth = new ArrayList<>();
        for (String a : authorities) {
            auth.add(new Cbor.T(a));
        }
        List<Cbor.Value> ordr = new ArrayList<>();
        for (byte[] o : order) {
            ordr.add(new Cbor.B(o));
        }
        return Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.A(auth)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.A(ordr)))));
    }
}
