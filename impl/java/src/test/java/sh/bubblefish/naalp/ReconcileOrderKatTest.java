// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.List;

/**
 * VerifyReconcileOrder known-answer test for the Java SDK (ietf/draft-bubblefish-naalp-01.md
 * "## Reconcile state machine"; design.md §8.4, design-channels.md §7) — the verify-event choke
 * point of the Reconcile state machine, mirroring impl/go/federation/verify_reconcile_test.go's
 * TestVerifyReconcileOrder exactly (synthetic byte ids, not corpus-graded; the Reconcile state
 * machine's byte-level cases are graded by the shared harness against vectors/reconcile_state via
 * the conformance adapter's {@code reconcile.state} op).
 *
 * <p>Named with the {@code KatTest} suffix its sibling KATs (FederationKatTest, AuditKatTest) carry
 * so the parity gate's test-corpus indexer (which keys on "test"/"spec" in the filename) sees it.
 *
 * <p>Two causally-INDEPENDENT byte-id nodes (id_a=[0x01], id_b=[0x02]; concurrent, so the one
 * deterministic order is [id_a, id_b] by content-id bytewise-ascending). Four subtests, each
 * mutation-surviving:
 * <ol>
 *   <li>agrees — the claimed order IS the deterministic order -&gt; verified (no error).</li>
 *   <li>mismatch [MUTATION ANCHOR] — a causally-valid but non-deterministic order -&gt;
 *       ReconcileMismatch.</li>
 *   <li>mismatch-length — a claim that drops an element -&gt; ReconcileMismatch.</li>
 *   <li>causal-violation — a cyclic node set is rejected before any order comparison -&gt;
 *       CausalViolation (fail-closed, propagated from {@link Federation#reconcile}).</li>
 * </ol>
 *
 * <p>Written test-first: {@link Federation#verifyReconcileOrder} is absent until this task lands,
 * so this fails RED with a javac "cannot find symbol verifyReconcileOrder"; the recorded mutation
 * (dropping the order comparison so verifyReconcileOrder always returns normally) flips the
 * "mismatch" and "mismatch-length" subtests from the expected ReconcileMismatch to no-error.
 *
 * <p>Run (from the repo root, on Windows the classpath separator is ';'):
 * <pre>
 * javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d impl/java/tout \
 *     impl/java/src/main/java/sh/bubblefish/naalp/*.java \
 *     impl/java/src/test/java/sh/bubblefish/naalp/ReconcileOrderKatTest.java
 * java -cp "impl/java/tout;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" sh.bubblefish.naalp.ReconcileOrderKatTest
 * </pre>
 */
public final class ReconcileOrderKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    /** The named kind thrown by verifyReconcileOrder, or "no-error". */
    private static String verify(Federation.ReconcileRecord record, List<Federation.CausalNode> nodes) {
        try {
            Federation.verifyReconcileOrder(record, nodes);
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    public static void main(String[] args) {
        byte[] idA = {0x01};
        byte[] idB = {0x02};
        List<Federation.CausalNode> concurrent = List.of(
                new Federation.CausalNode(idA, List.of()),
                new Federation.CausalNode(idB, List.of()));

        // 1. agrees: the claimed order IS the deterministic order -> verified.
        check("agrees",
                verify(new Federation.ReconcileRecord(List.of("auth-1"), List.of(idA, idB)), concurrent),
                "no-error");

        // 2. mismatch [MUTATION ANCHOR]: idA and idB are causally concurrent, so [idB, idA] is
        //    causally VALID but is not the deterministic (content-id ascending) order.
        check("mismatch",
                verify(new Federation.ReconcileRecord(List.of("auth-1"), List.of(idB, idA)), concurrent),
                "ReconcileMismatch");

        // 3. mismatch-length: a claim that drops an element.
        check("mismatch-length",
                verify(new Federation.ReconcileRecord(List.of("auth-1"), List.of(idA)), concurrent),
                "ReconcileMismatch");

        // 4. causal-violation: a cyclic node set is not a valid partial order; the recomputation
        //    rejects it before any order comparison, so the record is rejected under the graph
        //    fault, fail-closed -- regardless of what the record claims.
        byte[] idC = {0x03};
        byte[] idD = {0x04};
        List<Federation.CausalNode> cyclic = List.of(
                new Federation.CausalNode(idC, List.of(idD)),
                new Federation.CausalNode(idD, List.of(idC)));
        check("causal-violation",
                verify(new Federation.ReconcileRecord(List.of("auth-1"), List.of(idC, idD)), cyclic),
                "CausalViolation");

        System.out.println(fails == 0 ? "ReconcileOrderKatTest: PASS" : "ReconcileOrderKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
