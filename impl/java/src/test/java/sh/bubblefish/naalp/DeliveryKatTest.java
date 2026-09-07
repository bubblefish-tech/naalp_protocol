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
 * C8 delivery known-answer test for the Java SDK (design.md §9; R-9.1..9.4), graded against the
 * shared independent corpus vectors/delivery/cases.json (NOT produced by this code): the four
 * monotonic stage names, the byte-exact signed delivery.update body for each stage, and the T1
 * content-id framing.
 *
 * <p>CORPUS-GRADED (pure bytes): the stage vocabulary and the four delivery.update bodies. REAL
 * BEHAVIOUR DEMONSTRATED IN ISOLATION (NOT corpus-graded — the corpus carries no vector for these):
 * the persist-before-acknowledge WAL tracker (monotonic stages, StageOutOfOrder on regression,
 * idempotent re-report, durable recovery after reopen), the live full-duplex switchboard, and the
 * content-free relay whose retained C7 receipt chain over content ids verifies. The delivery.update
 * SIGNATURE is real deterministic ML-DSA-65 (BouncyCastle), also demonstrated in isolation.
 *
 * <p>Written test-first: {@link Delivery} is absent until Delivery.java lands, so this fails RED with
 * a javac "cannot find symbol Delivery"; the recorded mutation forces the encoded {@code stage} field
 * to a constant, which flips "update stage=1 body == oracle".
 */
public final class DeliveryKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("delivery").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/delivery/cases.json not found from " + System.getProperty("user.dir"));
    }

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

    private static String arrayBlock(String s, String key) {
        int open = s.indexOf('[', afterKey(s, key));
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
    }

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

    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static final int ALG = Cose.ALG_MLDSA65;

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);
        byte[] zeroSeed = new byte[32];
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", zeroSeed);

        // 1. the four monotonic stage names match the oracle; an out-of-set value is "unknown"; the
        //    four constants align with the corpus values in order.
        List<String> stageBlocks = splitObjects(arrayBlock(json, "stages"));
        long[] constants = {Delivery.STAGE_PERSISTED_ORIGIN, Delivery.STAGE_ACCEPTED_RELAY,
                Delivery.STAGE_PERSISTED_TARGET, Delivery.STAGE_PRESENTED};
        int i = 0;
        for (String sb : stageBlocks) {
            long value = intField(sb, "value");
            check("stage " + value + " name == oracle", Delivery.stageName(value), field(sb, "name"));
            check("stage constant[" + i + "] == oracle value", Long.toString(constants[i]), Long.toString(value));
            i++;
        }
        check("stage 99 is unknown", Delivery.stageName(99), "unknown");

        // 2. each of the four stages encodes a distinct byte-exact delivery.update body. (mutation target)
        byte[] obj = Hex.decode(field(json, "obj_content_id_hex"));
        for (String uv : splitObjects(arrayBlock(json, "updates"))) {
            long stage = intField(uv, "stage");
            Delivery.DeliveryUpdate u = new Delivery.DeliveryUpdate(obj, stage, intField(uv, "at"));
            check("update stage=" + stage + " body == oracle", Hex.encode(u.bytes()), field(uv, "body_hex"));
        }

        // 3. the delivery.update signature is real deterministic ML-DSA-65 (demonstrated in isolation).
        Delivery.DeliveryUpdate su = new Delivery.DeliveryUpdate(obj, Delivery.STAGE_PRESENTED, 103);
        byte[] sig = Delivery.signUpdate(su, ALG, zeroSeed);
        check("update signature verifies", Boolean.toString(Delivery.verifyUpdate(su, ALG, pk, sig)), "true");
        byte[] bad = sig.clone();
        bad[bad.length - 1] ^= 1;
        check("tampered update signature rejected", Boolean.toString(Delivery.verifyUpdate(su, ALG, pk, bad)), "false");

        // 4. the WAL tracker: monotonic stages, persist-before-ack, StageOutOfOrder on regression,
        //    idempotent re-report, and durable recovery after reopen (real behaviour in isolation).
        Path wal = Files.createTempFile("naalp-delivery-", ".wal");
        Files.delete(wal); // openTracker creates it
        try {
            Delivery.Tracker t = Delivery.openTracker(wal.toString());
            t.advance(obj, Delivery.STAGE_PERSISTED_ORIGIN, 100);
            t.advance(obj, Delivery.STAGE_PERSISTED_TARGET, 102); // skipping ahead is permitted
            check("regression rejected", errKind(() -> t.advance(obj, Delivery.STAGE_ACCEPTED_RELAY, 103)), "StageOutOfOrder");
            Delivery.DeliveryUpdate same = t.advance(obj, Delivery.STAGE_PERSISTED_TARGET, 104); // idempotent no-op
            check("idempotent re-report stage", Long.toString(same.stage), Long.toString(Delivery.STAGE_PERSISTED_TARGET));
            Delivery.StageResult sr = t.stage(obj);
            check("tracked stage after advances", sr.stage + "/" + sr.seen, Delivery.STAGE_PERSISTED_TARGET + "/true");
            t.close();
            Delivery.Tracker t2 = Delivery.openTracker(wal.toString());
            Delivery.StageResult sr2 = t2.stage(obj);
            check("stage recovered after reopen", sr2.stage + "/" + sr2.seen, Delivery.STAGE_PERSISTED_TARGET + "/true");
            Delivery.StageResult unseen = t2.stage("unseen".getBytes(StandardCharsets.UTF_8));
            check("unseen object stage", unseen.stage + "/" + unseen.seen, "0/false");
            t2.close();
        } finally {
            Files.deleteIfExists(wal);
        }

        // 5. the switchboard holds two connections open and relays both directions concurrently.
        Delivery.Switchboard sb = Delivery.newSwitchboard(4);
        try {
            sb.left().send("L->R".getBytes(StandardCharsets.UTF_8));
            sb.right().send("R->L".getBytes(StandardCharsets.UTF_8));
            check("switchboard left->right", new String(sb.right().recv(), StandardCharsets.UTF_8), "L->R");
            check("switchboard right->left", new String(sb.left().recv(), StandardCharsets.UTF_8), "R->L");
        } finally {
            sb.close();
        }

        // 6. the content-free relay retains only a C7 receipt chain over content ids (no payload); the
        //    receipt names the object's content id (T1 framing), and the retained trail verifies.
        Delivery.ContentFreeRelay relay = Delivery.newContentFreeRelay(ALG, zeroSeed);
        byte[] one = "object-one".getBytes(StandardCharsets.UTF_8);
        byte[] two = "object-two".getBytes(StandardCharsets.UTF_8);
        check("relay returns object for forwarding", new String(relay.route(one, 100), StandardCharsets.UTF_8), "object-one");
        relay.route(two, 101);
        Delivery.Trail trail = relay.auditTrail();
        check("relay retained two receipts", Integer.toString(trail.receipts.size()), "2");
        check("receipt names content id, not payload", Hex.encode(trail.receipts.get(0).obj), Hex.encode(Delivery.contentId(one)));
        check("content-id T1 framing prefix", Hex.encode(Delivery.contentId(one)).substring(0, 4), "2030");
        check("relay audit trail verifies",
                errKind(() -> Audit.verifyChain(trail.receipts, trail.sigs, ALG, pk)), "no-error");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("delivery conformance (Java) — graded vs vectors/delivery/cases.json");
        run();
        System.out.println(fails == 0 ? "DeliveryKatTest: PASS" : "DeliveryKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
