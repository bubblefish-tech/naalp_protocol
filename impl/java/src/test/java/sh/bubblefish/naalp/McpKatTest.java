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
 * NAALP-MCP binding-profile known-answer test for the Java SDK (design.md §19; Companion-Spec
 * Requirement 6.1), graded against the shared independent corpus vectors/mcp/cases.json (NOT produced
 * by this code): the annotation encoding, the published annotation-&gt;effect mapping table, the
 * tool-call bodies / content-ids, the call bindings (AC-6.1.2/6.1.3), the more-severe resolution
 * verdicts, and the malformed-annotation / edge-case rejections.
 *
 * <p>CORPUS-GRADED (pure bytes / verdicts): every annotations_hex round-trip and mapped_effect, every
 * tool-call body_hex/content_id_hex/tool_id_hex/args_id_hex/call_binding_hex/call_content_id_hex, every
 * resolution verdict + enforced + mismatch, the three malformed-annotation rejections, and the four
 * edge cases (non-canonical reject, empty-vs-absent annotations, minimal tool-call, look-alike
 * call-binding rejected). SECURITY-CRITICAL, DEMONSTRATED IN ISOLATION (the corpus carries no signed
 * vector): the full signed governance path — verifyToolCall verifies a real deterministic ML-DSA-65
 * McpToolCall, recomputes the annotation-derived effect independently, and enforces the MORE SEVERE
 * (accepting an over-declaration, rejecting an under-declaration EffectUnderDeclared); and authorizeCall
 * binds the EXACT call by content id through the just-landed §7 approval + single-use consume ledger
 * (a call with different args is ApprovalRequired; a replay is AlreadyConsumed).
 *
 * <p>Written test-first: {@link Mcp} is absent until Mcp.java lands, so this fails RED with a javac
 * "cannot find symbol Mcp"; the recorded mutation removes the EffectUnderDeclared guard in
 * {@code Mcp.resolveEnforcedEffect}, which flips the named "resolution under_declare_* verdict ==
 * EffectUnderDeclared" checks (a wrapper's declared effect may then sit below its own carried
 * annotations — the confused-deputy escalation the profile exists to stop).
 */
public final class McpKatTest {
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
            Path p = d.resolve("vectors").resolve("mcp").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/mcp/cases.json not found from " + System.getProperty("user.dir"));
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

    private static boolean boolField(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(true|false)").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("bool key not found: " + key);
        }
        return m.group(1).equals("true");
    }

    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static Mcp.Annotations annFromHex(String hex) {
        return Mcp.annotationsFromValue(Cbor.decode(Hex.decode(hex)));
    }

    private static final int ALG = Cose.ALG_MLDSA65;

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);

        // 1. every annotations_hex round-trips through the parser + encoder and maps to the oracle
        //    effect (the published annotation->effect table, MCP defaults applied to absent hints).
        for (String ab : splitObjects(arrayBlock(json, "annotations"))) {
            String name = field(ab, "name");
            String hex = field(ab, "annotations_hex");
            Mcp.Annotations a = annFromHex(hex);
            check("annotation " + name + " encode == oracle", Hex.encode(a.encode()), hex);
            check("annotation " + name + " mapped_effect == oracle",
                    Long.toString(Mcp.mapAnnotationsToEffect(a)), Long.toString(intField(ab, "mapped_effect")));
        }

        // 2. a malformed annotation set (hint value outside {0,1}, key outside {1,2,3,4}) is rejected
        //    MalformedAnnotation — never defaulted to benign (AC-6.1.2, fail-closed).
        for (String mb : splitObjects(arrayBlock(json, "malformed_annotations"))) {
            String name = field(mb, "name");
            String hex = field(mb, "annotations_hex");
            check("malformed annotation " + name + " rejected " + field(mb, "expect"),
                    errKind(() -> Mcp.annotationsFromValue(Cbor.decode(Hex.decode(hex)))), field(mb, "expect"));
        }

        // 3. each tool call: body bytes, content id, tool_id/args_id, the call binding bytes + content
        //    id, and the annotation-mapped effect all reproduce the oracle.
        for (String tb : splitObjects(arrayBlock(json, "tool_calls"))) {
            String name = field(tb, "name");
            byte[] tool = Hex.decode(field(tb, "tool_hex"));
            byte[] argv = Hex.decode(field(tb, "args_hex"));
            Mcp.Annotations a = annFromHex(field(tb, "annotations_hex"));
            Mcp.ToolCall tc = new Mcp.ToolCall(tool, argv, a);
            check("tool_call " + name + " body == oracle", Hex.encode(tc.bytes()), field(tb, "body_hex"));
            check("tool_call " + name + " content_id == oracle", Hex.encode(tc.contentId()), field(tb, "content_id_hex"));
            check("tool_call " + name + " annotation_mapped_effect == oracle",
                    Long.toString(Mcp.mapAnnotationsToEffect(a)), Long.toString(intField(tb, "annotation_mapped_effect")));
            Mcp.CallBinding cb = tc.callBinding();
            check("tool_call " + name + " tool_id == oracle", Hex.encode(cb.toolId), field(tb, "tool_id_hex"));
            check("tool_call " + name + " args_id == oracle", Hex.encode(cb.argsId), field(tb, "args_id_hex"));
            check("tool_call " + name + " call_binding == oracle", Hex.encode(cb.bytes()), field(tb, "call_binding_hex"));
            check("tool_call " + name + " call_content_id == oracle", Hex.encode(cb.contentId()), field(tb, "call_content_id_hex"));
        }

        // 4. the more-severe resolution (the good-regulator attenuator): accept => enforced+mismatch
        //    reproduce the oracle; an under-declaration below the tool's own annotations is
        //    EffectUnderDeclared. (mutation target: the EffectUnderDeclared guard.)
        for (String rb : splitObjects(arrayBlock(json, "resolution"))) {
            String name = field(rb, "name");
            long annMapped = intField(rb, "annotation_mapped");
            long declared = intField(rb, "declared");
            String verdict = field(rb, "verdict");
            if (verdict.equals("accept")) {
                Mcp.Resolution res = Mcp.resolveEnforcedEffect(annMapped, declared);
                check("resolution " + name + " enforced == oracle",
                        Long.toString(res.enforced), Long.toString(intField(rb, "enforced")));
                check("resolution " + name + " mismatch == oracle",
                        Boolean.toString(res.mismatch), Boolean.toString(boolField(rb, "mismatch")));
            } else {
                check("resolution " + name + " verdict == " + verdict,
                        errKind(() -> Mcp.resolveEnforcedEffect(annMapped, declared)), verdict);
            }
        }

        // 5. the approval binding names the EXACT call: a changed args body (AC-6.1.2) or a changed
        //    tool description (AC-6.1.3) yields a DIFFERENT call content id, so a prior approval no
        //    longer matches. The oracle carries the three distinct call content ids.
        List<String> apBlocks = splitObjects(arrayBlock(json, "approval_binding"));
        List<String> callCids = new ArrayList<>();
        for (String ap : apBlocks) {
            byte[] tool = Hex.decode(field(ap, "tool_hex"));
            byte[] argv = Hex.decode(field(ap, "args_hex"));
            Mcp.CallBinding cb = Mcp.newCallBinding(tool, argv);
            check("approval_binding " + field(ap, "name") + " call_binding == oracle",
                    Hex.encode(cb.bytes()), field(ap, "call_binding_hex"));
            String cid = Hex.encode(cb.contentId());
            check("approval_binding " + field(ap, "name") + " call_content_id == oracle",
                    cid, field(ap, "call_content_id_hex"));
            callCids.add(cid);
        }
        check("changed-args call content id differs from base (AC-6.1.2)",
                Boolean.toString(!callCids.get(1).equals(callCids.get(0))), "true");
        check("changed-tool-desc call content id differs from base (AC-6.1.3)",
                Boolean.toString(!callCids.get(2).equals(callCids.get(0))), "true");

        // 6. edge cases.
        String edge = objBlock(json, "edge_cases");
        String koo = objBlock(edge, "keys_out_of_order");
        check("edge keys_out_of_order canonical accepted (ToolCall parses)",
                errKind(() -> Mcp.toolCallFromBody(Cbor.decode(Hex.decode(field(koo, "canonical_body_hex"))))), "no-error");
        check("edge keys_out_of_order noncanonical rejected NonCanonical",
                errKind(() -> Cbor.decode(Hex.decode(field(koo, "noncanonical_body_hex")))), "NonCanonical");

        String eva = objBlock(edge, "empty_vs_absent");
        String empty = objBlock(eva, "empty_annotations");
        Mcp.ToolCall emptyTc = Mcp.toolCallFromBody(Cbor.decode(Hex.decode(field(empty, "body_hex"))));
        check("edge empty_annotations content_id == oracle", Hex.encode(emptyTc.contentId()), field(empty, "content_id_hex"));
        check("edge empty_annotations mapped_effect == oracle (destructive default)",
                Long.toString(Mcp.mapAnnotationsToEffect(emptyTc.annotations)), Long.toString(intField(empty, "mapped_effect")));
        String absent = objBlock(eva, "absent_annotations");
        check("edge absent_annotations rejected ToolCallMalformed",
                errKind(() -> Mcp.toolCallFromBody(Cbor.decode(Hex.decode(field(absent, "body_hex"))))), field(absent, "reject"));

        String minimal = objBlock(edge, "minimal");
        Mcp.ToolCall minTc = Mcp.toolCallFromBody(Cbor.decode(Hex.decode(field(minimal, "body_hex"))));
        check("edge minimal content_id == oracle", Hex.encode(minTc.contentId()), field(minimal, "content_id_hex"));
        check("edge minimal mapped_effect == oracle",
                Long.toString(Mcp.mapAnnotationsToEffect(minTc.annotations)), Long.toString(intField(minimal, "mapped_effect")));
        check("edge minimal body round-trips == oracle", Hex.encode(minTc.bytes()), field(minimal, "body_hex"));

        String look = objBlock(edge, "look_alike");
        check("edge look_alike 2-field call-binding rejected ToolCallMalformed",
                errKind(() -> Mcp.toolCallFromBody(Cbor.decode(Hex.decode(field(look, "call_binding_body_hex"))))), field(look, "reject"));

        // 7. DEMONSTRATED IN ISOLATION — the full signed governance path with real ML-DSA-65.
        signedGovernance();
    }

    /** The signed verifyToolCall + authorizeCall path, exercised with real deterministic ML-DSA-65
     *  keys and a real §7 consume ledger (the corpus carries no signed vector; the verdicts are the
     *  point). Uses the corpus delete_file_destructive tool bytes so the wrapper carries a real,
     *  meaningful annotation set. */
    private static void signedGovernance() throws Exception {
        byte[] signerSeed = seed(0x11);
        byte[] approverSeed = seed(0x22);
        byte[] signerPk = Cose.mldsaKeygen("ML-DSA-65", signerSeed);
        byte[] approverPk = Cose.mldsaKeygen("ML-DSA-65", approverSeed);
        String signerId = Identity.signerId(ALG, signerPk);
        String approverId = Identity.signerId(ALG, approverPk);

        byte[] tool = "{\"name\":\"delete_file\"}".getBytes(StandardCharsets.UTF_8);
        byte[] argv = "{\"path\":\"reports/q3.pdf\"}".getBytes(StandardCharsets.UTF_8);
        // destructive tool: readOnly=false, destructive=true -> annotation maps to destructive (3).
        Mcp.Annotations ann = new Mcp.Annotations(false, true, null, null);
        Mcp.ToolCall tc = new Mcp.ToolCall(tool, argv, ann);

        // signer agrees (declares destructive): verify -> enforced destructive, no mismatch.
        Envelope.Object obj = tc.envelopeObject(signerId.getBytes(StandardCharsets.UTF_8),
                1785000000000L, Cose.PROFILE_PUBLIC, Policy.DESTRUCTIVE, null);
        byte[] signed = Mcp.signToolCall(obj, ALG, signerSeed);
        Mcp.Resolved r = Mcp.verifyToolCall(Cose.PROFILE_PUBLIC, ALG, signerPk, signed);
        check("verifyToolCall enforced == destructive", Long.toString(r.enforced), Long.toString(Policy.DESTRUCTIVE));
        check("verifyToolCall no mismatch when signer agrees", Boolean.toString(r.mismatch), "false");
        check("verifyToolCall signer id round-trips", new String(r.signer, StandardCharsets.UTF_8), signerId);

        // a lying tool (annotation read_only) with an accountable signer that declares destructive:
        // enforced = destructive (the more severe), mismatch = true, attributable to the signer.
        Mcp.ToolCall lying = new Mcp.ToolCall(tool, argv, new Mcp.Annotations(true, null, null, null));
        Envelope.Object lyObj = lying.envelopeObject(signerId.getBytes(StandardCharsets.UTF_8),
                1785000000000L, Cose.PROFILE_PUBLIC, Policy.DESTRUCTIVE, null);
        Mcp.Resolved lr = Mcp.verifyToolCall(Cose.PROFILE_PUBLIC, ALG, signerPk, Mcp.signToolCall(lyObj, ALG, signerSeed));
        check("lying-tool enforced == destructive (more severe wins)", Long.toString(lr.enforced), Long.toString(Policy.DESTRUCTIVE));
        check("lying-tool mismatch attributable to signer", Boolean.toString(lr.mismatch), "true");

        // an under-declaring signer (destructive annotation, declares read_only) is rejected at the
        // enforcement point EffectUnderDeclared (the signed, attributable inconsistency). The object is
        // buildable (under-declaration is a signed claim, not blocked at build), but verify rejects it.
        Envelope.Object udObj = tc.envelopeObject(signerId.getBytes(StandardCharsets.UTF_8),
                1785000000000L, Cose.PROFILE_PUBLIC, Policy.READ_ONLY, null);
        byte[] udSigned = Mcp.signToolCall(udObj, ALG, signerSeed);
        check("under-declared wrapper rejected EffectUnderDeclared",
                errKind(() -> Mcp.verifyToolCall(Cose.PROFILE_PUBLIC, ALG, signerPk, udSigned)), "EffectUnderDeclared");

        // a tampered signed object is rejected BadSignature (real crypto).
        byte[] tampered = signed.clone();
        tampered[tampered.length - 1] ^= 1;
        check("tampered McpToolCall rejected BadSignature",
                errKind(() -> Mcp.verifyToolCall(Cose.PROFILE_PUBLIC, ALG, signerPk, tampered)), "BadSignature");

        // the per-call approval gate binds the EXACT call and is single-use through the §7 ledger.
        byte[] callCid = r.toolCall.callBinding().contentId();
        long notAfter = 1785000600000L;
        Approval.ApprovalRecord appr = new Approval.ApprovalRecord(
                callCid, approverId, Policy.DESTRUCTIVE, new byte[]{9, 9, 9, 9}, notAfter);
        byte[] apprSig = Approval.signApproval(appr, ALG, approverSeed);

        Path walPath = Files.createTempFile("naalp-mcp-waveC-", ".wal");
        Files.deleteIfExists(walPath);
        Approval.Ledger ledger = Approval.Ledger.open(walPath);
        try {
            check("authorizeCall grants the matching, unexpired, approved call",
                    errKind(() -> Mcp.authorizeCall(r, appr, ALG, approverPk, apprSig, "runner-1", 1785000100000L, ledger)),
                    "no-error");
            check("authorizeCall replay rejected AlreadyConsumed (single-use §7 ledger)",
                    errKind(() -> Mcp.authorizeCall(r, appr, ALG, approverPk, apprSig, "runner-2", 1785000100000L, ledger)),
                    "AlreadyConsumed");
        } finally {
            ledger.close();
            Files.deleteIfExists(walPath);
        }

        // an approval bound to a DIFFERENT call (different args) does not authorize this call: the
        // mismatch on the exact call bytes is a held outcome surfaced as ApprovalRequired (§7.3/§7.4).
        Mcp.ToolCall other = new Mcp.ToolCall(tool, "{\"path\":\"reports/q4.pdf\"}".getBytes(StandardCharsets.UTF_8), ann);
        byte[] otherCid = other.callBinding().contentId();
        Approval.ApprovalRecord otherAppr = new Approval.ApprovalRecord(
                otherCid, approverId, Policy.DESTRUCTIVE, new byte[]{1, 2, 3, 4}, notAfter);
        byte[] otherSig = Approval.signApproval(otherAppr, ALG, approverSeed);
        Path wal2 = Files.createTempFile("naalp-mcp-waveC2-", ".wal");
        Files.deleteIfExists(wal2);
        Approval.Ledger ledger2 = Approval.Ledger.open(wal2);
        try {
            check("approval for a different call rejected ApprovalRequired (binds the exact call)",
                    errKind(() -> Mcp.authorizeCall(r, otherAppr, ALG, approverPk, otherSig, "runner-3", 1785000100000L, ledger2)),
                    "ApprovalRequired");
        } finally {
            ledger2.close();
            Files.deleteIfExists(wal2);
        }

        // a baseline-only endpoint (channels validator alone) rejects an McpToolCall as UnknownKind;
        // the composed validator accepts it.
        check("composed kind validator accepts Bridge McpToolCall",
                Boolean.toString(Mcp.composedKindValidator(Mcp.CHANNEL_BRIDGE, Mcp.KIND_MCP_TOOL_CALL)), "true");
        check("mcp kind validator rejects baseline Carriage (kind 0)",
                Boolean.toString(Mcp.kindValidator(Mcp.CHANNEL_BRIDGE, 0)), "false");
    }

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("mcp conformance (Java) — graded vs vectors/mcp/cases.json");
        run();
        System.out.println(fails == 0 ? "McpKatTest: PASS" : "McpKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
