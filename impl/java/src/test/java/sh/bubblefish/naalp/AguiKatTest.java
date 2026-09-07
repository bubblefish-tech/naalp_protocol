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
 * C21 NAALP-AGUI UI-consent-binding known-answer test for the Java SDK (design.md §24; R-AGUI-1..6),
 * graded against the shared independent corpus vectors/agui/cases.json (NOT produced by this code): the
 * closed kind vocabulary, the receipt-chained UI-event bodies/heads/ids, the walked-chain final head,
 * the oversized-seq round-trip (&gt;2^53, carried as a string), the minimal event, the action content
 * ids, the omitted-shown-event hole position, and the malformed/non-canonical rejections.
 *
 * <p>CORPUS-GRADED (pure bytes / positions / verdicts): the kind vocabulary; every event body_hex /
 * head_hex / id_hex including the big-seq (0x0102030405060708) and minimal events; the walked-chain
 * final head; action_cid / substituted_cid; the hole position (1); the NonCanonical, UIMalformed and
 * absent-field rejections. SECURITY-CRITICAL, DEMONSTRATED IN ISOLATION (the corpus carries no signed
 * vector): the signed shown-chain (verifyShownChain rejects a tampered event BadSignature) and
 * verifyConsent — a human §7 approval binds the EXACT action shown+approved, and executing a SUBSTITUTED
 * action (different content id) is rejected ActionSubstituted, with a no-approved-event chain rejected
 * UINoConsent.
 *
 * <p>Written test-first: {@link Agui} is absent until Agui.java lands, so this fails RED with a javac
 * "cannot find symbol Agui"; the recorded mutation removes the ActionSubstituted check in
 * {@code Agui.verifyConsent}, which flips the named "executing a SUBSTITUTED action rejected
 * ActionSubstituted" check (the seam a lax UI profile would drop, letting an approved consent authorize
 * a different action).
 */
public final class AguiKatTest {
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
            Path p = d.resolve("vectors").resolve("agui").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/agui/cases.json not found from " + System.getProperty("user.dir"));
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

    private static String objBlock(String s, String key) {
        int open = s.indexOf('{', afterKey(s, key));
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
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
        byte[] session = Hex.decode(field(json, "session_hex"));

        // 1. the closed kind vocabulary (shown / args-shown / approved / rejected); an out-of-set code
        //    is not known and names "unknown".
        for (String kb : splitObjects(arrayBlock(json, "kind_vocabulary"))) {
            long code = intField(kb, "code");
            check("kind " + code + " known", Boolean.toString(Agui.isKnownKind(code)), "true");
            check("kind " + code + " name == oracle", Agui.kindName(code), field(kb, "name"));
        }
        long unknown = intField(json, "unknown_kind");
        check("unknown kind not known", Boolean.toString(Agui.isKnownKind(unknown)), "false");
        check("unknown kind names 'unknown'", Agui.kindName(unknown), "unknown");

        // 2. genesis is 48 zero octets.
        check("genesis == oracle", Hex.encode(Agui.genesis()), field(json, "genesis_hex"));
        check("genesis width == HEAD_SIZE", Integer.toString(Agui.genesis().length), Integer.toString(Agui.HEAD_SIZE));

        // 3. the receipt-chained shown chain: each event body/head/id reproduces the oracle, and
        //    walkShown returns a contiguous chain whose final head is the oracle final head.
        String chainScope = objBlock(json, "chain");
        List<String> evBlocks = splitObjects(arrayBlock(chainScope, "events"));
        List<Agui.UIEvent> chain = new ArrayList<>();
        for (String eb : evBlocks) {
            Agui.UIEvent e = new Agui.UIEvent(session, intField(eb, "kind"),
                    Hex.decode(field(eb, "action_hex")), intField(eb, "seq"), Hex.decode(field(eb, "prev_hex")));
            check("event seq=" + e.seq + " body == oracle", Hex.encode(e.bytes()), field(eb, "body_hex"));
            check("event seq=" + e.seq + " head == oracle", Hex.encode(e.head()), field(eb, "head_hex"));
            check("event seq=" + e.seq + " id == oracle", Hex.encode(e.id()), field(eb, "id_hex"));
            chain.add(e);
        }
        List<Agui.ShownEvent> shown = Agui.walkShown(chain);
        check("walkShown accepts the contiguous chain (3 events)", Integer.toString(shown.size()), "3");
        check("walkShown final head == oracle",
                Hex.encode(shown.get(shown.size() - 1).head), field(chainScope, "final_head_hex"));

        // 4. an oversized seq (>2^53) carried as a STRING round-trips byte-exact (no float64 rounding).
        String bigScope = objBlock(json, "big_seq");
        long bigSeq = Long.parseLong(field(bigScope, "seq_str"));
        Agui.UIEvent big = new Agui.UIEvent(session, intField(bigScope, "kind"),
                Hex.decode(field(bigScope, "action_hex")), bigSeq, Hex.decode(field(bigScope, "prev_hex")));
        check("big_seq body == oracle", Hex.encode(big.bytes()), field(bigScope, "body_hex"));
        check("big_seq head == oracle", Hex.encode(big.head()), field(bigScope, "head_hex"));
        check("big_seq id == oracle", Hex.encode(big.id()), field(bigScope, "id_hex"));

        // 5. the minimal event (empty session, empty action, seq 0, genesis prev).
        String minScope = objBlock(json, "minimal");
        Agui.UIEvent min = new Agui.UIEvent(Hex.decode(field(minScope, "session_hex")), intField(minScope, "kind"),
                Hex.decode(field(minScope, "action_hex")), intField(minScope, "seq"), Hex.decode(field(minScope, "prev_hex")));
        check("minimal body == oracle", Hex.encode(min.bytes()), field(minScope, "body_hex"));
        check("minimal head == oracle", Hex.encode(min.head()), field(minScope, "head_hex"));
        check("minimal id == oracle", Hex.encode(min.id()), field(minScope, "id_hex"));

        // 6. edge cases.
        String edge = objBlock(json, "edge_cases");
        String koo = objBlock(edge, "keys_out_of_order");
        check("edge keys_out_of_order canonical accepted (parseUIEvent)",
                errKind(() -> Agui.parseUIEvent(Hex.decode(field(koo, "canonical_body_hex")))), "no-error");
        check("edge keys_out_of_order noncanonical rejected NonCanonical",
                errKind(() -> Cbor.decode(Hex.decode(field(koo, "noncanonical_body_hex")))), field(koo, "reject"));

        String eva = objBlock(edge, "empty_vs_absent");
        String emptyAct = objBlock(eva, "empty_action");
        check("edge empty_action id == oracle",
                Hex.encode(Agui.parseUIEvent(Hex.decode(field(emptyAct, "body_hex"))).id()), field(emptyAct, "id_hex"));
        String popAct = objBlock(eva, "populated_action");
        check("edge populated_action id == oracle",
                Hex.encode(Agui.parseUIEvent(Hex.decode(field(popAct, "body_hex"))).id()), field(popAct, "id_hex"));
        String absentField = objBlock(eva, "absent_field");
        check("edge absent action field rejected " + field(absentField, "reject"),
                errKind(() -> Agui.parseUIEvent(Hex.decode(field(absentField, "body_hex")))), field(absentField, "reject"));

        String look = objBlock(edge, "look_alike");
        check("edge look_alike (no prev back-pointer) rejected " + field(look, "reject"),
                errKind(() -> Agui.parseUIEvent(Hex.decode(field(look, "body_hex")))), field(look, "reject"));

        // 7. the action content ids the shown chain and the human approval bind.
        byte[] actionBytes = Hex.decode(field(json, "action_bytes_hex"));
        byte[] substitutedBytes = Hex.decode(field(json, "substituted_bytes_hex"));
        check("action content id == oracle", Hex.encode(Agui.contentId(actionBytes)), field(json, "action_cid_hex"));
        check("substituted content id == oracle", Hex.encode(Agui.contentId(substitutedBytes)), field(json, "substituted_cid_hex"));
        check("substituted action has a DIFFERENT content id",
                Boolean.toString(!Hex.encode(Agui.contentId(substitutedBytes)).equals(field(json, "action_cid_hex"))), "true");

        // 8. an omitted shown-event leaves a detectable hole at its POSITION. Presenting [ev0, ev2]
        //    (ev1 omitted) breaks contiguity at position 1 (as the §8.5 fork proof reports a position).
        String holeScope = objBlock(json, "hole");
        List<Agui.UIEvent> gappy = new ArrayList<>();
        gappy.add(chain.get(0)); // ev0
        gappy.add(chain.get(2)); // ev2 (ev1 omitted)
        Agui.Hole hole = Agui.detectHole(gappy);
        check("omitted-shown-event hole detected", Boolean.toString(hole.isHole), "true");
        check("hole position == oracle", Integer.toString(hole.position), Long.toString(intField(holeScope, "position")));
        check("contiguous chain has no hole", Boolean.toString(Agui.detectHole(chain).isHole), "false");

        // the shown-and-approved action content id is the one a valid consent binds (ev2 is approved).
        byte[] approvedCid = Agui.approvedActionCID(shown);
        check("approvedActionCID == action_cid (ev2 approved)", Hex.encode(approvedCid), field(json, "action_cid_hex"));

        // 9. DEMONSTRATED IN ISOLATION — the signed shown-chain + consent binding with real ML-DSA-65.
        signedConsent(session, chain, actionBytes, substitutedBytes, Hex.decode(field(json, "action_cid_hex")));
    }

    private static void signedConsent(byte[] session, List<Agui.UIEvent> chain, byte[] actionBytes,
                                      byte[] substitutedBytes, byte[] actionCid) throws Exception {
        byte[] uiSeed = seed(0x55);
        byte[] approverSeed = seed(0x66);
        byte[] uiPk = Cose.mldsaKeygen("ML-DSA-65", uiSeed);
        byte[] approverPk = Cose.mldsaKeygen("ML-DSA-65", approverSeed);
        String approverId = Identity.signerId(ALG, approverPk);

        // sign the whole shown chain under the UI authority key; verifyShownChain accepts it, and a
        // tampered event is rejected BadSignature (real crypto).
        List<byte[]> signedChain = new ArrayList<>();
        for (Agui.UIEvent e : chain) {
            signedChain.add(Agui.signUIEvent(e, ALG, uiSeed));
        }
        check("verifyShownChain accepts the signed contiguous chain",
                errKind(() -> Agui.verifyShownChain(signedChain, Cose.PROFILE_PUBLIC, ALG, uiPk)), "no-error");
        List<byte[]> tamperedChain = new ArrayList<>(signedChain);
        byte[] t = signedChain.get(2).clone();
        t[t.length - 1] ^= 1;
        tamperedChain.set(2, t);
        check("verifyShownChain rejects a tampered event BadSignature",
                errKind(() -> Agui.verifyShownChain(tamperedChain, Cose.PROFILE_PUBLIC, ALG, uiPk)), "BadSignature");

        // a human §7 approval binds the EXACT shown+approved action content id.
        long notAfter = 1785000600000L;
        Approval.ApprovalRecord appr = new Approval.ApprovalRecord(
                actionCid, approverId, Policy.NON_IDEMPOTENT_WRITE, new byte[]{7, 7, 7, 7}, notAfter);
        byte[] apprSig = Approval.signApproval(appr, ALG, approverSeed);

        // executing the EXACT action shown+approved is authorized.
        check("verifyConsent authorizes the exact action shown+approved",
                errKind(() -> Agui.verifyConsent(chain, actionBytes, appr, ALG, approverPk, apprSig, 1785000100000L)),
                "no-error");
        // executing a SUBSTITUTED action (different content id) is rejected — the load-bearing seam.
        check("verifyConsent rejects a SUBSTITUTED action ActionSubstituted",
                errKind(() -> Agui.verifyConsent(chain, substitutedBytes, appr, ALG, approverPk, apprSig, 1785000100000L)),
                "ActionSubstituted");
        // an expired approval is rejected (real §7 expiry).
        check("verifyConsent rejects an expired approval ApprovalExpired",
                errKind(() -> Agui.verifyConsent(chain, actionBytes, appr, ALG, approverPk, apprSig, 1785000700000L)),
                "ApprovalExpired");

        // a chain with NO approved event has no consent to bind (UINoConsent): present only ev0+ev1.
        List<Agui.UIEvent> noApproval = new ArrayList<>();
        noApproval.add(chain.get(0)); // shown
        noApproval.add(chain.get(1)); // args-shown (no approved event)
        check("verifyConsent on a chain with no approved event rejected UINoConsent",
                errKind(() -> Agui.verifyConsent(noApproval, actionBytes, appr, ALG, approverPk, apprSig, 1785000100000L)),
                "UINoConsent");
    }

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("agui conformance (Java) — graded vs vectors/agui/cases.json");
        run();
        System.out.println(fails == 0 ? "AguiKatTest: PASS" : "AguiKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
