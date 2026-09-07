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
 * C7 audit known-answer test for the Java SDK (design.md §8; R-8.1..8.6), graded against the shared
 * independent corpus vectors/audit/cases.json (NOT produced by this code): the hash-chained signed
 * receipt body + head, offline chain verification (ChainBroken / ReceiptUnsigned), equivocation
 * detection, the draft-01 fork-proof preimage (signatures elided), and the offline causal graph
 * (valid topo order, cycle rejection, future-cause rejection).
 *
 * <p>CORPUS-GRADED (pure bytes / verdicts): every receipt body/head, the final chain head, the
 * fork-proof framing preimage, and the causal topo order / rejections — all reproduced byte-for-byte
 * or verdict-for-verdict from the corpus. CRYPTO-DEMONSTRATED IN ISOLATION (real FIPS-204 ML-DSA-65
 * via BouncyCastle, NOT corpus-graded because the corpus carries no signature vector for this
 * channel): the {@link Audit.Authority} appends a chain whose real signatures verify offline; a
 * broken prev-link is ChainBroken and a tampered signature is ReceiptUnsigned; the auditor mints a
 * fork proof whose two real signatures verify against the accused key; the fork proof fails closed.
 *
 * <p>KAT convention (a standalone {@code main} exiting non-zero on any failure); named "…KatTest" so
 * the filename carries the "test" token the ten-language-parity gate indexes. Written test-first:
 * {@link Audit} is absent until Audit.java lands, so this fails RED with a javac "cannot find symbol
 * Audit"; the recorded mutation forces the encoded receipt {@code seq} field to a constant, which
 * flips "chain body seq=1 == oracle".
 */
public final class AuditKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    // ---- nesting-aware JSON access (Java has no JSON library; the corpus has nested objects,
    //      nested arrays, and braces inside string values, so the matcher skips quoted strings) ----

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("audit").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/audit/cases.json not found from " + System.getProperty("user.dir"));
    }

    /** Index just past the '{'/'[' at {@code open}'s match, skipping over double-quoted strings. */
    private static int matchClose(String s, int open) {
        char oc = s.charAt(open);
        char cc = oc == '{' ? '}' : ']';
        int depth = 0;
        boolean inStr = false;
        for (int i = open; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (inStr) {
                if (ch == '\\') {
                    i++;
                } else if (ch == '"') {
                    inStr = false;
                }
                continue;
            }
            if (ch == '"') {
                inStr = true;
            } else if (ch == oc) {
                depth++;
            } else if (ch == cc && --depth == 0) {
                return i + 1;
            }
        }
        throw new AssertionError("unbalanced from " + open);
    }

    private static int afterKey(String s, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:").matcher(s);
        if (!m.find()) {
            throw new AssertionError("key not found: " + key);
        }
        return m.end();
    }

    /** The inner content (braces stripped) of the object value that follows "key":. */
    private static String objBlock(String s, String key) {
        int open = s.indexOf('{', afterKey(s, key));
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
    }

    /** The inner content (brackets stripped) of the array value that follows "key":. */
    private static String arrayBlock(String s, String key) {
        int open = s.indexOf('[', afterKey(s, key));
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
    }

    /** The top-level {@code { ... }} object blocks (inner content) inside an array body. */
    private static List<String> splitObjects(String arrayInner) {
        List<String> out = new ArrayList<>();
        int i = 0;
        while (true) {
            int open = arrayInner.indexOf('{', i);
            if (open < 0) {
                return out;
            }
            int close = matchClose(arrayInner, open);
            out.add(arrayInner.substring(open + 1, close - 1));
            i = close;
        }
    }

    /** The top-level quoted strings inside an array body (e.g. a hex-string list). */
    private static List<String> topStrings(String arrayInner) {
        List<String> out = new ArrayList<>();
        Matcher m = Pattern.compile("\"([^\"]*)\"").matcher(arrayInner);
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }

    private static String field(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("string key not found: " + key);
        }
        return m.group(1);
    }

    private static long intField(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("int key not found: " + key);
        }
        return Long.parseLong(m.group(1));
    }

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    /** The named kind thrown by {@code r}, or "no-error". */
    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    // ---- checks ----

    private static final int ALG = Cose.ALG_MLDSA65;

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);
        byte[] zeroSeed = new byte[32];
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", zeroSeed);

        // 1. the hash-chained receipt bodies/heads reproduce the oracle; prev links to the prior head.
        String chain = objBlock(json, "chain");
        byte[] head = Hex.decode(field(chain, "genesis_prev_hex"));
        check("genesis prev width", Integer.toString(head.length), Integer.toString(Audit.HEAD_SIZE));
        List<String> receiptBlocks = splitObjects(arrayBlock(chain, "receipts"));
        for (String rb : receiptBlocks) {
            long sq = intField(rb, "seq");
            Audit.Receipt r = new Audit.Receipt(
                    Hex.decode(field(rb, "prev_hex")), Hex.decode(field(rb, "obj_hex")), sq, intField(rb, "at"));
            check("chain body seq=" + sq + " == oracle", Hex.encode(r.bytes()), field(rb, "body_hex"));
            check("chain head seq=" + sq + " == oracle", Hex.encode(r.head()), field(rb, "head_after_hex"));
            check("chain prev seq=" + sq + " links prior head", Hex.encode(r.prev), Hex.encode(head));
            head = r.head();
        }
        check("final chain head == oracle", Hex.encode(head), field(chain, "final_head_hex"));

        // 2. a fresh authority appending the same object ids at the same anchors reproduces the
        //    byte-exact corpus chain, and the resulting real-ML-DSA-signed chain verifies offline.
        Audit.Authority auth = new Audit.Authority(ALG, zeroSeed);
        List<Audit.Receipt> rs = new ArrayList<>();
        List<byte[]> sigs = new ArrayList<>();
        for (String rb : receiptBlocks) {
            Audit.Signed s = auth.append(Hex.decode(field(rb, "obj_hex")), intField(rb, "at"));
            check("append body seq=" + intField(rb, "seq") + " == oracle", Hex.encode(s.receipt.bytes()), field(rb, "body_hex"));
            rs.add(s.receipt);
            sigs.add(s.sig);
        }
        check("appended chain verifies offline",
                errKind(() -> Audit.verifyChain(rs, sigs, ALG, pk)), "no-error");

        // 3. a broken prev-link is ChainBroken (each body signed with a real key so the break, not a
        //    bad signature, is what fires).
        String cb = objBlock(json, "chain_broken");
        List<Audit.Receipt> brs = new ArrayList<>();
        List<byte[]> bsigs = new ArrayList<>();
        for (String rb : splitObjects(arrayBlock(cb, "receipts"))) {
            Audit.Receipt r = new Audit.Receipt(
                    Hex.decode(field(rb, "prev_hex")), Hex.decode(field(rb, "obj_hex")),
                    intField(rb, "seq"), intField(rb, "at"));
            check("chain_broken body seq=" + intField(rb, "seq") + " == oracle", Hex.encode(r.bytes()), field(rb, "body_hex"));
            brs.add(r);
            bsigs.add(Cose.mldsaSign(ALG, zeroSeed, r.bytes()));
        }
        check("broken prev-link rejected", errKind(() -> Audit.verifyChain(brs, bsigs, ALG, pk)), field(cb, "expect"));

        // 4. a validly-chained receipt with a corrupted signature is ReceiptUnsigned.
        String r0 = receiptBlocks.get(0);
        Audit.Receipt genesis = new Audit.Receipt(
                Hex.decode(field(chain, "genesis_prev_hex")), Hex.decode(field(r0, "obj_hex")), 0, intField(r0, "at"));
        byte[] goodSig = Cose.mldsaSign(ALG, zeroSeed, genesis.bytes());
        byte[] badSig = goodSig.clone();
        badSig[badSig.length - 1] ^= 1;
        check("tampered signature rejected",
                errKind(() -> Audit.verifyChain(List.of(genesis), List.of(badSig), ALG, pk)), "ReceiptUnsigned");

        // 5. consistent-with-anchor: created MUST NOT exceed the authority anchor (R-8.4).
        check("anchor created==at ok", Boolean.toString(Audit.consistentWithAnchor(100, 100)), "true");
        check("anchor created<at ok", Boolean.toString(Audit.consistentWithAnchor(99, 100)), "true");
        check("anchor created>at rejected", Boolean.toString(Audit.consistentWithAnchor(101, 100)), "false");

        // 6. equivocation receipts reproduce the oracle bodies (both fork_proof and equivocation views).
        String fp = objBlock(json, "fork_proof");
        long fseq = intField(fp, "seq");
        long fat = intField(fp, "at");
        byte[] fprev = Hex.decode(field(fp, "prev_hex"));
        Audit.Receipt ra = new Audit.Receipt(fprev, Hex.decode(field(fp, "obj_a_hex")), fseq, fat);
        Audit.Receipt rbb = new Audit.Receipt(fprev, Hex.decode(field(fp, "obj_b_hex")), fseq, fat);
        check("fork body_a == oracle", Hex.encode(ra.bytes()), field(fp, "body_a_hex"));
        check("fork body_b == oracle", Hex.encode(rbb.bytes()), field(fp, "body_b_hex"));
        String eq = objBlock(json, "equivocation");
        check("equivocation receipt_a body == oracle", Hex.encode(ra.bytes()), field(objBlock(eq, "receipt_a"), "body_hex"));
        check("equivocation receipt_b body == oracle", Hex.encode(rbb.bytes()), field(objBlock(eq, "receipt_b"), "body_hex"));

        // 7. the auditor detects a genuine one-seq fork and mints a proof that verifies; a benign first
        //    observe returns nothing; an exact duplicate is not a fork; an unsigned receipt is rejected.
        byte[] signerId = Hex.decode(field(fp, "signer_hex"));
        long extCounter = intField(fp, "ext_counter");
        byte[] sigA = Cose.mldsaSign(ALG, zeroSeed, ra.bytes());
        byte[] sigB = Cose.mldsaSign(ALG, zeroSeed, rbb.bytes());
        Audit.Auditor auditor = new Audit.Auditor(ALG, pk, signerId, extCounter);
        check("first observe is benign", Boolean.toString(auditor.observe(ra, sigA) == null), "true");
        Audit.ForkProof minted = auditor.observe(rbb, sigB);
        check("genuine fork detected", Boolean.toString(minted != null), "true");
        check("minted proof verifies", errKind(() -> minted.verify(ALG, pk)), "no-error");
        check("corpus equivocation verdict", field(eq, "expect"), "Equivocation");

        Audit.Auditor auditor2 = new Audit.Auditor(ALG, pk, signerId, extCounter);
        auditor2.observe(ra, sigA);
        check("benign duplicate is not a fork", Boolean.toString(auditor2.observe(ra, sigA) == null), "true");

        Audit.Auditor auditor3 = new Audit.Auditor(ALG, pk, signerId, extCounter);
        check("observe rejects unsigned", errKind(() -> auditor3.observe(ra, new byte[8])), "ReceiptUnsigned");

        // 8. the fork-proof framing preimage (both signatures elided) reproduces the oracle byte-for-byte.
        Audit.ForkProof preimageProof = Audit.newForkProof(signerId, ra, new byte[0], rbb, new byte[0], extCounter);
        check("fork-proof preimage == oracle", Hex.encode(preimageProof.preimage()), field(fp, "preimage_hex"));

        // 9. fork-proof Verify accepts a real proof and fails closed on same-object / unnamed / seq-
        //    mismatch (ForkProofInvalid) and on a tampered signature (ReceiptUnsigned).
        Audit.ForkProof good = Audit.newForkProof(signerId, ra, sigA, rbb, sigB, extCounter);
        check("valid fork proof accepted", errKind(() -> good.verify(ALG, pk)), "no-error");
        Audit.ForkProof same = Audit.newForkProof(signerId, ra, sigA, ra, sigA, extCounter);
        check("same-object proof rejected", errKind(() -> same.verify(ALG, pk)), "ForkProofInvalid");
        Audit.ForkProof unnamed = Audit.newForkProof(new byte[0], ra, sigA, rbb, sigB, extCounter);
        check("unnamed-accused proof rejected", errKind(() -> unnamed.verify(ALG, pk)), "ForkProofInvalid");
        Audit.Receipt rbSeq = new Audit.Receipt(rbb.prev, rbb.obj, rbb.seq + 1, rbb.at);
        byte[] sigBSeq = Cose.mldsaSign(ALG, zeroSeed, rbSeq.bytes());
        Audit.ForkProof mism = Audit.newForkProof(signerId, ra, sigA, rbSeq, sigBSeq, extCounter);
        check("seq-mismatch proof rejected", errKind(() -> mism.verify(ALG, pk)), "ForkProofInvalid");
        byte[] sigBBad = sigB.clone();
        sigBBad[sigBBad.length - 1] ^= 1;
        Audit.ForkProof tampered = Audit.newForkProof(signerId, ra, sigA, rbb, sigBBad, extCounter);
        check("tampered-sig proof rejected", errKind(() -> tampered.verify(ALG, pk)), "ReceiptUnsigned");

        // 10. the offline causal graph: a valid graph yields the oracle topo order; a cycle and a
        //     future cause are each CausalViolation.
        List<Audit.CausalNode> valid = nodesOf(objBlock(json, "causal_valid"));
        check("causal_valid verifies", errKind(() -> Audit.verifyCausal(valid)), "no-error");
        List<byte[]> order = Audit.topoOrder(valid);
        List<String> orderHex = new ArrayList<>();
        for (byte[] o : order) {
            orderHex.add(Hex.encode(o));
        }
        check("causal topo order == oracle",
                String.join(",", orderHex), String.join(",", topStrings(arrayBlock(objBlock(json, "causal_valid"), "topo_order_hex"))));

        String cycle = objBlock(json, "causal_cycle");
        check("causal cycle rejected", errKind(() -> Audit.verifyCausal(nodesOf(cycle))), field(cycle, "expect"));
        String future = objBlock(json, "causal_future");
        check("causal future-cause rejected", errKind(() -> Audit.verifyCausal(nodesOf(future))), field(future, "expect"));
    }

    private static List<Audit.CausalNode> nodesOf(String scope) {
        List<Audit.CausalNode> out = new ArrayList<>();
        for (String nb : splitObjects(arrayBlock(scope, "nodes"))) {
            List<byte[]> causes = new ArrayList<>();
            for (String c : topStrings(arrayBlock(nb, "causes_hex"))) {
                causes.add(Hex.decode(c));
            }
            out.add(new Audit.CausalNode(Hex.decode(field(nb, "id_hex")), causes, intField(nb, "position")));
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("audit conformance (Java) — graded vs vectors/audit/cases.json");
        run();
        System.out.println(fails == 0 ? "AuditKatTest: PASS" : "AuditKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
