// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Federation higher-tier (tier 1) known-answer test for the Java SDK (design.md §8.4;
 * design-channels.md §7; R-8.6), graded against the shared independent corpus
 * vectors/federation/cases.json (NOT produced by this code). Reconcile is the deterministic
 * linearization of the union causal DAG, tie-broken among causally-concurrent objects by content id
 * (bytewise ascending): it MUST equal the oracle order, be causally valid, and beat the naive
 * content-id sort (which is NOT causally valid here). The tier-1 Reconcile record MUST encode to the
 * oracle bytes, and reconcile MUST be scope-independent (R-8.6).
 *
 * <p>CORPUS-GRADED (pure): reconcile order, causal validity, naive-sort baseline, record bytes, scope
 * independence, cycle rejection. ML-DSA-DEMONSTRATED (isolation, real FIPS-204 via BouncyCastle, NOT
 * corpus-graded — the corpus carries no federation signature): the tier-1 authority's deterministic
 * ML-DSA signature over the record, and rejection of a tampered record.
 *
 * <p>KAT convention (a standalone {@code main} that exits non-zero on any failure); named "…KatTest"
 * so the filename carries the "test" token the ten-language-parity gate indexes. Written test-first:
 * {@link Federation} is absent until Federation.java lands, so this fails RED with a javac "cannot
 * find symbol Federation"; a mutation that ignores the causal graph flips "reconcile order == oracle".
 */
public final class FederationKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    // ---- minimal regex JSON access (Java has no JSON library) ----

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("federation").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/federation/cases.json not found from " + System.getProperty("user.dir"));
    }

    private static String str(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        if (!m.find()) {
            throw new AssertionError("string key not found: " + key);
        }
        return m.group(1);
    }

    private static boolean bool(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(true|false)").matcher(json);
        if (!m.find()) {
            throw new AssertionError("boolean key not found: " + key);
        }
        return "true".equals(m.group(1));
    }

    /** Every lowercase-hex token quoted inside a JSON segment, decoded to bytes, in document order. */
    private static List<byte[]> hexTokens(String segment) {
        List<byte[]> out = new ArrayList<>();
        Matcher m = Pattern.compile("\"([0-9a-f]+)\"").matcher(segment);
        while (m.find()) {
            out.add(Hex.decode(m.group(1)));
        }
        return out;
    }

    /** The decoded hex strings of the array named {@code key} (no nested arrays inside). */
    private static List<byte[]> hexArray(String json, String key) {
        Matcher a = Pattern.compile("\"" + key + "\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL).matcher(json);
        if (!a.find()) {
            throw new AssertionError("array key not found: " + key);
        }
        return hexTokens(a.group(1));
    }

    /** The string elements of the array named {@code key}. */
    private static List<String> stringArray(String json, String key) {
        Matcher a = Pattern.compile("\"" + key + "\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL).matcher(json);
        if (!a.find()) {
            throw new AssertionError("array key not found: " + key);
        }
        List<String> out = new ArrayList<>();
        Matcher m = Pattern.compile("\"([^\"]*)\"").matcher(a.group(1));
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }

    /**
     * The corpus nodes as CausalNode[]. The federation corpus's only brace-pairs are the node objects
     * (each flat: name, id_hex, a causes_hex array of hex strings, no nested object), so matching every
     * innermost {@code {...}} yields exactly the nodes in document order.
     */
    private static List<Federation.CausalNode> corpusNodes(String json) {
        List<Federation.CausalNode> out = new ArrayList<>();
        Matcher nb = Pattern.compile("\\{([^{}]*)\\}", Pattern.DOTALL).matcher(json);
        while (nb.find()) {
            String block = nb.group(1);
            byte[] id = Hex.decode(str(block, "id_hex"));
            Matcher ce = Pattern.compile("\"causes_hex\"\\s*:\\s*\\[([^\\]]*)\\]", Pattern.DOTALL).matcher(block);
            List<byte[]> causes = ce.find() ? hexTokens(ce.group(1)) : new ArrayList<>();
            out.add(new Federation.CausalNode(id, causes));
        }
        return out;
    }

    private static String hexJoin(List<byte[]> bins) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bins.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(Hex.encode(bins.get(i)));
        }
        return sb.toString();
    }

    // ---- checks ----

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);
        List<Federation.CausalNode> nodes = corpusNodes(json);
        check("node count", Integer.toString(nodes.size()),
                Integer.toString(hexArray(json, "reconcile_order_hex").size()));

        // 1. reconcile == the independent oracle order (the load-bearing property; the mutation target).
        List<byte[]> order = Federation.reconcile(nodes);
        check("reconcile order == oracle", hexJoin(order), hexJoin(hexArray(json, "reconcile_order_hex")));

        // 2. the reconcile order is causally valid (every present cause precedes its effect).
        check("reconcile order causally valid",
                Boolean.toString(Federation.causallyValid(order, nodes)),
                Boolean.toString(bool(json, "reconcile_order_causally_valid")));

        // 3. the naive content-id sort's causal validity matches the oracle — and here it is NOT valid,
        //    so it is the mutation baseline: a reconcile that degrades to the naive sort is caught.
        List<byte[]> naive = hexArray(json, "naive_content_id_sort_hex");
        check("naive content-id sort causally valid == oracle",
                Boolean.toString(Federation.causallyValid(naive, nodes)),
                Boolean.toString(bool(json, "naive_causally_valid")));

        // 4. the tier-1 Reconcile record encodes to the oracle bytes {1:[authorities], 2:[order]}.
        List<String> authorities = stringArray(json, "authorities");
        Federation.ReconcileRecord rec = new Federation.ReconcileRecord(authorities, order);
        check("reconcile record bytes == oracle", Hex.encode(rec.bytes()), str(json, "record_hex"));

        // 5. R-8.6: reconcile depends only on the causal graph, not on input (scope) order — reversing
        //    the input reconciles identically.
        List<Federation.CausalNode> reversed = new ArrayList<>(nodes);
        java.util.Collections.reverse(reversed);
        check("scope independence (reversed input)", hexJoin(Federation.reconcile(reversed)), hexJoin(order));

        // 6. an out-of-lattice cycle is rejected fail-closed (CausalViolation).
        byte[] a = Hex.decode("2030" + "aa".repeat(48));
        byte[] b = Hex.decode("2030" + "bb".repeat(48));
        List<Federation.CausalNode> cyclic = List.of(
                new Federation.CausalNode(a, List.of(b)),
                new Federation.CausalNode(b, List.of(a)));
        String got = "no-error";
        try {
            Federation.reconcile(cyclic);
        } catch (NaalpException e) {
            got = e.kind;
        }
        check("cycle rejected", got, "CausalViolation");

        // 7. ML-DSA-DEMONSTRATED (isolation, real FIPS-204): a tier-1 authority signs the Reconcile
        //    record deterministically; the raw signature verifies under its key, and a tampered record
        //    does NOT verify. This exercises the signing binding in isolation (NOT corpus-graded).
        byte[] seed = new byte[32];
        java.util.Arrays.fill(seed, (byte) 0x2a);
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", seed);
        byte[] sig = Federation.signReconcile(rec, Cose.ALG_MLDSA65, seed);
        check("ml-dsa reconcile-record sign/verify",
                Boolean.toString(Federation.verifyReconcile(rec, Cose.ALG_MLDSA65, pk, sig)), "true");
        Federation.ReconcileRecord tampered =
                new Federation.ReconcileRecord(List.of("bauthority-z"), rec.order);
        check("ml-dsa tampered record rejected",
                Boolean.toString(Federation.verifyReconcile(tampered, Cose.ALG_MLDSA65, pk, sig)), "false");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("federation conformance (Java) — graded vs vectors/federation/cases.json");
        run();
        System.out.println(fails == 0 ? "FederationKatTest: PASS" : "FederationKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
