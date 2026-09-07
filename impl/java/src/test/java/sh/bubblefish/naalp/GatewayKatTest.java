// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * C21 portable gateway-decision known-answer test for the Java SDK (design.md §24; R-GW-1..6), graded
 * against the shared independent corpus vectors/gateway/cases.json (NOT produced by this code).
 *
 * <p>CORPUS-GRADED (pure): the deterministic body/head/content-id of the three decisions, the closed
 * decision vocabulary, and the strict-decoder rejections (keys-out-of-order NonCanonical, empty-vs-
 * absent policy, minimal decision, ui-event look-alike). CRYPTO-GRADED (real FIPS-204 ML-DSA-65 via
 * BouncyCastle — Java is NOT pure-only): the third-party re-serve property (sign → verify → identical
 * re-verify), foreign-key rejection, unknown-decision rejection, and the cross-language pinned signed-
 * decision SHA-384 that Go and Rust both pin (an independent Go+Rust authority for the signed bytes).
 *
 * <p>KAT convention (a standalone {@code main} exiting non-zero on any failure); named "…KatTest" so
 * the filename carries the "test" token the ten-language-parity gate indexes. Written test-first:
 * {@link Gateway} is absent until Gateway.java lands, so this fails RED with a javac "cannot find
 * symbol Gateway"; a mutation to the field-presence guard flips "look-alike rejected" / "absent policy
 * rejected", and a mutation to Bytes() flips "deny body == oracle".
 */
public final class GatewayKatTest {
    private static int fails = 0;

    // The cross-language pinned SHA-384 of the deterministic COSE_Sign1 object obtained by signing the
    // DENY decision body with the shared all-0x11 32-byte ML-DSA-65 seed. Go and Rust both pin it, so it
    // is an independent (non-circular) authority for the signed bytes; Java must reproduce it exactly.
    private static final String PIN_SIGNED_DENY_SHA384 =
            "774047d87f11f688c57d985e9cab632ea66d0abc8b9ec3d48d1c3063c54ef5df0f761ce8239cbf68302d547097f01047";

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
            Path p = d.resolve("vectors").resolve("gateway").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/gateway/cases.json not found from " + System.getProperty("user.dir"));
    }

    /** The string value of a "key": "value" pair inside {@code scope} (value may be empty). */
    private static String field(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("string key not found: " + key);
        }
        return m.group(1);
    }

    /** The integer value of a "key": <number> pair inside {@code scope}. */
    private static long intField(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("int key not found: " + key);
        }
        return Long.parseLong(m.group(1));
    }

    /** The flat inner {@code { ... }} block of the object-valued field named {@code key} (no nesting). */
    private static String subObject(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\\{([^{}]*)\\}", Pattern.DOTALL).matcher(json);
        if (!m.find()) {
            throw new AssertionError("object key not found: " + key);
        }
        return m.group(1);
    }

    /**
     * The {@code body_hex} value that immediately opens the object named {@code key}. Used for
     * look_alike, whose {@code note} carries a literal "{1:bstr,...}" that would break the flat
     * brace-free {@link #subObject} matcher; body_hex is the object's first field, before the note.
     */
    private static String openingBodyHex(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\\{\\s*\"body_hex\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        if (!m.find()) {
            throw new AssertionError("opening body_hex not found for: " + key);
        }
        return m.group(1);
    }

    /** The flat object blocks of the array named {@code arrayKey}. */
    private static List<String> objectBlocks(String json, String arrayKey) {
        Matcher a = Pattern.compile("\"" + arrayKey + "\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL).matcher(json);
        if (!a.find()) {
            throw new AssertionError("array key not found: " + arrayKey);
        }
        List<String> out = new ArrayList<>();
        Matcher o = Pattern.compile("\\{([^{}]*)\\}", Pattern.DOTALL).matcher(a.group(1));
        while (o.find()) {
            out.add(o.group(1));
        }
        return out;
    }

    // ---- nesting-aware JSON access (for the S1/S3/E6.3 evidence-record corpora, which nest
    //      objects inside objects -- e.g. records{}, checkpoints{}.witness_cosign{}, edge_cases{}.
    //      empty_vs_absent{}.empty_audience{} -- beyond the flat [^{}]* helpers above) ----

    /** Locates vectors/{@code subdir}/cases.json by walking up from the working directory (mirrors
     * {@link #findVector}, generalized to the S1/S3/E6.3 corpora decision_record/checkpoint/
     * egress_attestation/). */
    private static Path findVectorNamed(String subdir) {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve(subdir).resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/" + subdir + "/cases.json not found from " + System.getProperty("user.dir"));
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
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:").matcher(s);
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

    /** Returns {@code name -> innerContent} for a JSON object whose values are themselves objects,
     * given the flattened outer content of that object (as returned by {@link #objBlock}); each
     * inner content is itself returned braces-stripped, exactly as {@link #objBlock} would return
     * it. Scalar sibling keys (whose value is not an object) are skipped naturally, since the
     * matcher requires the next non-whitespace token after the colon to be a literal '{'. */
    private static LinkedHashMap<String, String> namedObjectBlocks(String outerBlockContent) {
        LinkedHashMap<String, String> out = new LinkedHashMap<>();
        Matcher km = Pattern.compile("\"([^\"]*)\"\\s*:\\s*\\{").matcher(outerBlockContent);
        int i = 0;
        while (km.find(i)) {
            String name = km.group(1);
            int open = km.end() - 1; // position of the matched '{'
            int close = matchClose(outerBlockContent, open);
            out.put(name, outerBlockContent.substring(open + 1, close - 1));
            i = close;
        }
        return out;
    }

    /** All double-quoted hex-looking tokens in a flattened JSON array body (e.g. governing_hex[],
     * path_hex[]), in order. */
    private static List<String> hexStringArray(String arrInner) {
        List<String> out = new ArrayList<>();
        String trimmed = arrInner.trim();
        if (trimmed.isEmpty()) {
            return out;
        }
        Matcher m = Pattern.compile("\"([0-9a-fA-F]*)\"").matcher(trimmed);
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }

    /** The decoded byte-string array named {@code key} inside {@code scope}. */
    private static List<byte[]> hexArrayField(String scope, String key) {
        List<byte[]> out = new ArrayList<>();
        for (String h : hexStringArray(arrayBlock(scope, key))) {
            out.add(Hex.decode(h));
        }
        return out;
    }

    /** An unsigned-64-bit integer field, via {@link Long#parseUnsignedLong} -- {@code at_str} in the
     * checkpoint/egress-attestation corpora ranges up to 2^64-1, beyond {@link Long#parseLong}'s
     * signed range; carried as a decimal STRING so no float64 decoder anywhere can round it. */
    private static long longField(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"?(\\d+)\"?").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("int key not found: " + key);
        }
        return Long.parseUnsignedLong(m.group(1));
    }

    /** {@code consume_hex} may be a JSON string, {@code null}, or absent; the mandatory-quote {@link
     * #field} matcher only matches an actual quoted string, so {@code null}/absent both fall through
     * to the empty (absent) byte string -- exactly the DecisionRecord.consume "absent" convention. */
    private static byte[] consumeHexField(String scope) {
        Matcher m = Pattern.compile("\"consume_hex\"\\s*:\\s*\"([0-9a-fA-F]*)\"").matcher(scope);
        if (m.find()) {
            return Hex.decode(m.group(1));
        }
        return new byte[0];
    }

    /** The named kind thrown by {@code r}, or "no-error" -- the {@link Runnable} idiom lets a
     * lambda over any {@code void}-returning Gateway call share this file's PASS/FAIL convention. */
    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static String sha384Hex(byte[] b) throws Exception {
        return Hex.encode(MessageDigest.getInstance("SHA-384").digest(b));
    }

    /** A GatewayDecision built from a corpus block carrying decision/effect/action_hex/policy_hex. */
    private static Gateway.GatewayDecision decFrom(String block) {
        return new Gateway.GatewayDecision(
                intField(block, "decision"),
                Hex.decode(field(block, "action_hex")),
                Hex.decode(field(block, "policy_hex")),
                intField(block, "effect"));
    }

    /** The named kind thrown by parseDecision on {@code body}, or "no-error". */
    private static String parseKind(byte[] body) {
        try {
            Gateway.parseDecision(body);
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    // ---- checks ----

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);

        // 1. the closed decision vocabulary is registered; an out-of-set code is not known.
        for (String vb : objectBlocks(json, "decision_vocabulary")) {
            String name = field(vb, "name");
            long code = intField(vb, "code");
            check("vocab " + name + " known", Boolean.toString(Gateway.isKnownDecision(code)), "true");
            check("vocab " + name + " name", Gateway.decisionName(code), name);
        }
        long unknown = intField(json, "unknown_decision");
        check("unknown decision not known", Boolean.toString(Gateway.isKnownDecision(unknown)), "false");

        // 2. each decision body/head/id == the non-circular oracle, byte-for-byte.
        for (String dn : new String[]{"allow", "deny", "hold"}) {
            String block = subObject(json, dn);
            Gateway.GatewayDecision d = decFrom(block);
            check(dn + " body == oracle", Hex.encode(d.bytes()), field(block, "body_hex"));
            check(dn + " head == oracle", Hex.encode(d.head()), field(block, "head_hex"));
            check(dn + " id == oracle", Hex.encode(d.id()), field(block, "id_hex"));
        }

        // 3. edge #1: a canonical body encodes to the oracle and parses; a DESCENDING-key body is
        //    rejected NonCanonical by the strict decoder and GwMalformed by parseDecision.
        String koo = subObject(json, "keys_out_of_order");
        Gateway.GatewayDecision kd = decFrom(koo);
        check("keys-out-of-order canonical body == oracle", Hex.encode(kd.bytes()), field(koo, "canonical_body_hex"));
        byte[] canon = Hex.decode(field(koo, "canonical_body_hex"));
        byte[] noncanon = Hex.decode(field(koo, "noncanonical_body_hex"));
        check("canonical body parses", parseKind(canon), "no-error");
        String cborKind;
        try {
            Cbor.decode(noncanon);
            cborKind = "decoded";
        } catch (NaalpException e) {
            cborKind = e.kind;
        }
        check("descending-key body cbor-rejected", cborKind, "NonCanonical");
        check("descending-key body parseDecision-rejected", parseKind(noncanon), "GwMalformed");

        // 4. edge #2: an EMPTY policy identity is present, valid, and distinct by content-id from a
        //    populated one; both differ from a body whose policy field is ABSENT (rejected GwMalformed).
        byte[] actionCid = Hex.decode(field(json, "action_cid_hex"));
        String emptyB = subObject(json, "empty_policy");
        String popB = subObject(json, "populated_policy");
        String absB = subObject(json, "absent_field");
        Gateway.GatewayDecision empty =
                new Gateway.GatewayDecision(Gateway.DECISION_ALLOW, actionCid, new byte[0], 1);
        Gateway.GatewayDecision populated = new Gateway.GatewayDecision(
                Gateway.DECISION_ALLOW, actionCid, Hex.decode(field(popB, "policy_hex")), 1);
        check("empty-policy body == oracle", Hex.encode(empty.bytes()), field(emptyB, "body_hex"));
        check("empty-policy id == oracle", Hex.encode(empty.id()), field(emptyB, "id_hex"));
        check("populated-policy body == oracle", Hex.encode(populated.bytes()), field(popB, "body_hex"));
        check("populated-policy id == oracle", Hex.encode(populated.id()), field(popB, "id_hex"));
        check("empty vs populated ids distinct",
                Boolean.toString(!Hex.encode(empty.id()).equals(Hex.encode(populated.id()))), "true");
        check("empty policy parses", parseKind(empty.bytes()), "no-error");
        check("populated policy parses", parseKind(populated.bytes()), "no-error");
        check("absent policy field rejected", parseKind(Hex.decode(field(absB, "body_hex"))), "GwMalformed");

        // 5. edge #4: the minimal decision (allow, empty action, empty policy, read_only) encodes to the
        //    oracle bytes, has a stable content-id, parses, and verifies end-to-end (allow is known).
        String minB = subObject(json, "minimal");
        Gateway.GatewayDecision minimal = decFrom(minB);
        check("minimal body == oracle", Hex.encode(minimal.bytes()), field(minB, "body_hex"));
        check("minimal id == oracle", Hex.encode(minimal.id()), field(minB, "id_hex"));
        check("minimal parses", parseKind(minimal.bytes()), "no-error");

        // 6. edge #5: a ui-event look-alike {1:bstr,2:uint,3:bstr,4:uint,5:bstr} — field 1 a bstr where
        //    the decision uint is required — is rejected GwMalformed.
        check("ui-event look-alike rejected", parseKind(Hex.decode(openingBodyHex(json, "look_alike"))),
                "GwMalformed");

        // 7. CRYPTO-GRADED (real ML-DSA-65): the third-party re-serve property. A signed decision
        //    verifies offline and RE-VERIFIES IDENTICALLY (VerifyDecision takes no serving-party
        //    identity); a foreign key never verifies it; an unknown-code decision is rejected.
        Gateway.GatewayDecision deny = decFrom(subObject(json, "deny"));
        byte[] gwSeed = seed(0x51);
        byte[] gwPk = Cose.mldsaKeygen("ML-DSA-65", gwSeed);
        byte[] obj = Gateway.signDecision(deny, Cose.ALG_MLDSA65, gwSeed);
        Gateway.ResolvedDecision byGateway = Gateway.verifyDecision(obj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk);
        Gateway.ResolvedDecision byThirdParty = Gateway.verifyDecision(obj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk);
        check("verify resolves deny", Long.toString(byGateway.decision), Long.toString(Gateway.DECISION_DENY));
        check("resolved action == oracle action cid", Hex.encode(byThirdParty.action), field(json, "action_cid_hex"));
        boolean reServeIdentical = byGateway.decision == byThirdParty.decision
                && java.util.Arrays.equals(byGateway.action, byThirdParty.action)
                && java.util.Arrays.equals(byGateway.policy, byThirdParty.policy)
                && byGateway.effect == byThirdParty.effect;
        check("third-party re-serve identical", Boolean.toString(reServeIdentical), "true");

        byte[] foreignPk = Cose.mldsaKeygen("ML-DSA-65", seed(0x52));
        String foreignKind = "no-error";
        try {
            Gateway.verifyDecision(obj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, foreignPk);
        } catch (NaalpException e) {
            foreignKind = e.kind;
        }
        check("foreign key rejected", foreignKind, "BadSignature");

        Gateway.GatewayDecision bad =
                new Gateway.GatewayDecision(unknown, actionCid, Hex.decode(field(json, "policy_hex")), 0);
        byte[] badObj = Gateway.signDecision(bad, Cose.ALG_MLDSA65, gwSeed);
        String unknownKind = "no-error";
        try {
            Gateway.verifyDecision(badObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk);
        } catch (NaalpException e) {
            unknownKind = e.kind;
        }
        check("unknown-code decision rejected", unknownKind, "UnknownGatewayDecision");

        // 8. the minimal decision verifies end-to-end (allow is known) with a fresh gateway key.
        byte[] mSeed = seed(0x53);
        byte[] mPk = Cose.mldsaKeygen("ML-DSA-65", mSeed);
        byte[] mObj = Gateway.signDecision(minimal, Cose.ALG_MLDSA65, mSeed);
        String minVerify = "ok";
        try {
            Gateway.verifyDecision(mObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, mPk);
        } catch (NaalpException e) {
            minVerify = e.kind;
        }
        check("minimal verifies end-to-end", minVerify, "ok");

        // 9. CROSS-LANGUAGE PIN: the signed DENY object (seed=0x11*32) has the SHA-384 Go and Rust pin —
        //    proving the two independent ML-DSA stacks emit byte-identical signed gateway-decision objects.
        byte[] pinObj = Gateway.signDecision(deny, Cose.ALG_MLDSA65, seed(0x11));
        check("cross-language signed-deny SHA-384 pin", sha384Hex(pinObj), PIN_SIGNED_DENY_SHA384);

        // 10. R1 ordering (field 5) + R8 foreign-profile (field 6), graded against this SAME
        //     corpus's optional_fields{} block (mirrors gateway_test.go's optional-fields section).
        runOptionalFields(json);
    }

    // =================================================================================================
    // Evidence-record family: S1 naalp-decision-record, S3 naalp-checkpoint-root/witness-cosign/
    // inclusion-proof, E6.3 naalp-egress-attestation. Each graded against its OWN independent corpus
    // (vectors/{decision_record,checkpoint,egress_attestation}/cases.json), mirroring
    // impl/go/gateway/{decision_record,checkpoint,egress_attestation}_test.go and
    // impl/python/tests/test_{decision_record,checkpoint,egress_attestation}.py.
    // =================================================================================================

    // ---- R1/R8 GatewayDecision optional fields (vectors/gateway/cases.json optional_fields{}) ------

    private static void runOptionalFields(String json) throws Exception {
        String of = objBlock(json, "optional_fields");

        // with_ordering: field 5 present (single-boundary), field 6 absent.
        String wo = objBlock(of, "with_ordering");
        String woOrd = objBlock(wo, "ordering");
        Gateway.OrderingDisclosure ordWo = new Gateway.OrderingDisclosure(
                intField(woOrd, "basis"), Hex.decode(field(woOrd, "boundary_hex")), new byte[0], new byte[0]);
        Gateway.GatewayDecision dWo = new Gateway.GatewayDecision(
                intField(wo, "decision"), Hex.decode(field(wo, "action_hex")), Hex.decode(field(wo, "policy_hex")),
                intField(wo, "effect"), ordWo, null);
        check("with_ordering body == oracle", Hex.encode(dWo.bytes()), field(wo, "body_hex"));
        check("with_ordering id == oracle", Hex.encode(dWo.id()), field(wo, "id_hex"));
        Gateway.GatewayDecision parsedWo = Gateway.parseDecision(Hex.decode(field(wo, "body_hex")));
        check("with_ordering parsed has ordering", Boolean.toString(parsedWo.ordering != null), "true");
        check("with_ordering parsed has no foreign profile", Boolean.toString(parsedWo.foreignProfile == null), "true");
        check("with_ordering basis", Long.toString(parsedWo.ordering.basis), Long.toString(intField(woOrd, "basis")));
        check("with_ordering boundary", Hex.encode(parsedWo.ordering.boundary), field(woOrd, "boundary_hex"));
        parsedWo.ordering.validate(); // no throw

        // with_foreign_profile: field 6 present, field 5 absent.
        String wf = objBlock(of, "with_foreign_profile");
        String wfFp = objBlock(wf, "foreign_profile");
        Gateway.ForeignProfilePin fpWf = new Gateway.ForeignProfilePin(field(wfFp, "id"), field(wfFp, "revision"));
        Gateway.GatewayDecision dWf = new Gateway.GatewayDecision(
                intField(wf, "decision"), Hex.decode(field(wf, "action_hex")), Hex.decode(field(wf, "policy_hex")),
                intField(wf, "effect"), null, fpWf);
        check("with_foreign_profile body == oracle", Hex.encode(dWf.bytes()), field(wf, "body_hex"));
        check("with_foreign_profile id == oracle", Hex.encode(dWf.id()), field(wf, "id_hex"));
        Gateway.GatewayDecision parsedWf = Gateway.parseDecision(Hex.decode(field(wf, "body_hex")));
        check("with_foreign_profile parsed has no ordering", Boolean.toString(parsedWf.ordering == null), "true");
        check("with_foreign_profile parsed has foreign profile", Boolean.toString(parsedWf.foreignProfile != null), "true");
        check("with_foreign_profile id field", parsedWf.foreignProfile.id, field(wfFp, "id"));
        check("with_foreign_profile revision field", parsedWf.foreignProfile.revision, field(wfFp, "revision"));
        parsedWf.foreignProfile.validate(); // no throw

        // with_both: field 5 (external-mechanism, with relation) AND field 6 both present.
        String wb = objBlock(of, "with_both");
        String wbOrd = objBlock(wb, "ordering");
        String wbFp = objBlock(wb, "foreign_profile");
        Gateway.OrderingDisclosure ordWb = new Gateway.OrderingDisclosure(
                intField(wbOrd, "basis"), new byte[0], Hex.decode(field(wbOrd, "mechanism_hex")), Hex.decode(field(wbOrd, "relation_hex")));
        Gateway.ForeignProfilePin fpWb = new Gateway.ForeignProfilePin(field(wbFp, "id"), field(wbFp, "revision"));
        Gateway.GatewayDecision dWb = new Gateway.GatewayDecision(
                intField(wb, "decision"), Hex.decode(field(wb, "action_hex")), Hex.decode(field(wb, "policy_hex")),
                intField(wb, "effect"), ordWb, fpWb);
        check("with_both body == oracle", Hex.encode(dWb.bytes()), field(wb, "body_hex"));
        check("with_both id == oracle", Hex.encode(dWb.id()), field(wb, "id_hex"));
        Gateway.GatewayDecision parsedWb = Gateway.parseDecision(Hex.decode(field(wb, "body_hex")));
        check("with_both parsed has ordering", Boolean.toString(parsedWb.ordering != null), "true");
        check("with_both parsed has foreign profile", Boolean.toString(parsedWb.foreignProfile != null), "true");
        parsedWb.ordering.validate();
        parsedWb.foreignProfile.validate();
        byte[] seedWb = seed(0x71);
        byte[] pkWb = Cose.mldsaKeygen("ML-DSA-65", seedWb);
        byte[] objWb = Gateway.signDecision(dWb, Cose.ALG_MLDSA65, seedWb);
        check("with_both verifies end-to-end", errKind(() -> Gateway.verifyDecision(objWb, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pkWb)), "no-error");

        // foreign_profile_malformed: field 6 present but omits key 2 (revision). parseDecision
        // decodes it structurally fine; ForeignProfilePin.validate()/verifyDecision reject it.
        String fpm = objBlock(of, "foreign_profile_malformed");
        byte[] fpmBody = Hex.decode(field(fpm, "body_hex"));
        Gateway.GatewayDecision parsedFpm = Gateway.parseDecision(fpmBody);
        check("foreign_profile_malformed parsed has foreign profile", Boolean.toString(parsedFpm.foreignProfile != null), "true");
        check("foreign_profile_malformed validate rejected", errKind(parsedFpm.foreignProfile::validate), "ForeignProfileMalformed");
        byte[] seedFpm = seed(0x72);
        byte[] pkFpm = Cose.mldsaKeygen("ML-DSA-65", seedFpm);
        byte[] objFpm = Cose.coseSign1(Cose.ALG_MLDSA65, seedFpm, Gateway.gatewayProtectedHeader(Cose.ALG_MLDSA65), fpmBody);
        check("foreign_profile_malformed verify rejected",
                errKind(() -> Gateway.verifyDecision(objFpm, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pkFpm)), "ForeignProfileMalformed");

        // ordering_malformed: field 5 basis=external-mechanism but key 2 (boundary) is ALSO present.
        String om = objBlock(of, "ordering_malformed");
        byte[] omBody = Hex.decode(field(om, "body_hex"));
        Gateway.GatewayDecision parsedOm = Gateway.parseDecision(omBody);
        check("ordering_malformed parsed has ordering", Boolean.toString(parsedOm.ordering != null), "true");
        check("ordering_malformed validate rejected", errKind(parsedOm.ordering::validate), "OrderingDisclosureMalformed");
        byte[] seedOm = seed(0x73);
        byte[] pkOm = Cose.mldsaKeygen("ML-DSA-65", seedOm);
        byte[] objOm = Cose.coseSign1(Cose.ALG_MLDSA65, seedOm, Gateway.gatewayProtectedHeader(Cose.ALG_MLDSA65), omBody);
        check("ordering_malformed verify rejected",
                errKind(() -> Gateway.verifyDecision(objOm, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pkOm)), "OrderingDisclosureMalformed");

        // ForeignProfilePin.validate() direct unit tests (no oracle vector needed).
        check("fp both present validates", errKind(new Gateway.ForeignProfilePin("https://example.test/p", "1")::validate), "no-error");
        check("fp missing id rejected", errKind(new Gateway.ForeignProfilePin("", "1")::validate), "ForeignProfileMalformed");
        check("fp missing revision rejected", errKind(new Gateway.ForeignProfilePin("https://example.test/p", "")::validate), "ForeignProfileMalformed");
        check("fp both empty rejected", errKind(new Gateway.ForeignProfilePin("", "")::validate), "ForeignProfileMalformed");

        // foreign profile extra key rejected: a field-6 map carrying a THIRD key (3) beyond {1,2}
        // decodes structurally (the extra key does not fail decode) but fails validate().
        Cbor.M fpExtra = new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.T("https://example-registry.test/profiles/acme")),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T("2026-01")),
                new Cbor.Pair(new Cbor.U(3), new Cbor.T("unexpected"))));
        Cbor.M mExtra = new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(Gateway.DECISION_ALLOW)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(Hex.decode(field(json, "action_cid_hex")))),
                new Cbor.Pair(new Cbor.U(3), new Cbor.B(Hex.decode(field(json, "policy_hex")))),
                new Cbor.Pair(new Cbor.U(4), new Cbor.U(1)),
                new Cbor.Pair(new Cbor.U(6), fpExtra)));
        byte[] extraBody = Cbor.encode(mExtra);
        Gateway.GatewayDecision parsedExtra = Gateway.parseDecision(extraBody);
        check("fp extra key parsed has foreign profile", Boolean.toString(parsedExtra.foreignProfile != null), "true");
        check("fp extra key id field", parsedExtra.foreignProfile.id, "https://example-registry.test/profiles/acme");
        check("fp extra key revision field", parsedExtra.foreignProfile.revision, "2026-01");
        check("fp extra key validate rejected", errKind(parsedExtra.foreignProfile::validate), "ForeignProfileMalformed");
    }

    // ---- S1 naalp-decision-record (vectors/decision_record/cases.json) ----------------------------

    /** Reconstructs a records{}/ordering_examples{} case with its exact ordering/terms/enforcement
     * fixture, mirroring decision_record_test.go's build() switch / test_decision_record.py's
     * _build() exactly. */
    private static Gateway.DecisionRecord buildRecord(String name, String rv) {
        byte[] action = Hex.decode(field(rv, "action_hex"));
        List<byte[]> governing = hexArrayField(rv, "governing_hex");
        long outcome = intField(rv, "outcome");
        byte[] consume = consumeHexField(rv);
        Gateway.OrderingDisclosure ordering;
        Map<Long, Gateway.TermDisposition> terms = new HashMap<>();
        long enforcement = 0;
        switch (name) {
            case "allow_consuming":
            case "allow_no_consume":
            case "minimal":
            case "correspondence_only":
                ordering = Gateway.correspondenceOnly();
                break;
            case "deny_two_governing":
                ordering = new Gateway.OrderingDisclosure(Gateway.ORDERING_SINGLE_BOUNDARY,
                        "boundary-signer-X".getBytes(StandardCharsets.UTF_8), new byte[0], new byte[0]);
                break;
            case "hold_empty_governing":
            case "external_mechanism":
                ordering = new Gateway.OrderingDisclosure(Gateway.ORDERING_EXTERNAL_MECHANISM, new byte[0],
                        "external-log:acme-transparency-v1".getBytes(StandardCharsets.UTF_8),
                        Hex.decode("2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56"));
                break;
            case "single_boundary":
                ordering = new Gateway.OrderingDisclosure(Gateway.ORDERING_SINGLE_BOUNDARY,
                        "SIGNER_B-boundary".getBytes(StandardCharsets.UTF_8), new byte[0], new byte[0]);
                break;
            case "external_mechanism_no_relation":
                ordering = new Gateway.OrderingDisclosure(Gateway.ORDERING_EXTERNAL_MECHANISM, new byte[0],
                        "external-log:acme-transparency-v1".getBytes(StandardCharsets.UTF_8), new byte[0]);
                break;
            case "terms_valid":
                ordering = Gateway.correspondenceOnly();
                terms.put(1L, new Gateway.TermDisposition(Gateway.TERM_OBSERVED));
                terms.put(4L, new Gateway.TermDisposition(Gateway.TERM_REPORTED, "boundary:relay-partner-3".getBytes(StandardCharsets.UTF_8)));
                break;
            case "enforcement_enforced":
                ordering = Gateway.correspondenceOnly();
                enforcement = Gateway.ENFORCEMENT_ENFORCED;
                break;
            case "enforcement_advised":
                ordering = Gateway.correspondenceOnly();
                enforcement = Gateway.ENFORCEMENT_ADVISED;
                break;
            default:
                throw new AssertionError("unhandled record name " + name + " -- add its ordering/terms/enforcement fixture");
        }
        return new Gateway.DecisionRecord(action, governing, outcome, ordering, consume, terms, enforcement);
    }

    /** The named kind thrown by parseDecisionRecord/validateDecisionRecord on {@code body}, or "". */
    private static String drRejectKind(byte[] body) {
        try {
            Gateway.DecisionRecord d = Gateway.parseDecisionRecord(body);
            try {
                Gateway.validateDecisionRecord(d);
            } catch (NaalpException e) {
                return e.kind;
            }
            return "";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static void runDecisionRecord() throws Exception {
        String json = Files.readString(findVectorNamed("decision_record"), StandardCharsets.UTF_8);

        // 1. the closed outcome vocabulary (reuses Gateway's gw-decision accessors) + ordering-basis
        //    vocabulary are registered.
        for (String vb : objectBlocks(json, "outcome_vocabulary")) {
            String name = field(vb, "name");
            long code = intField(vb, "code");
            check("dr outcome vocab " + name + " known", Boolean.toString(Gateway.isKnownDecision(code)), "true");
            check("dr outcome vocab " + name + " name", Gateway.decisionName(code), name);
        }
        for (String vb : objectBlocks(json, "ordering_basis_vocabulary")) {
            String name = field(vb, "name");
            long code = intField(vb, "code");
            check("dr ordering vocab " + name + " known", Boolean.toString(Gateway.isKnownOrderingBasis(code)), "true");
            check("dr ordering vocab " + name + " name", Gateway.orderingBasisName(code), name);
        }
        check("dr unknown ordering basis 99 not known", Boolean.toString(Gateway.isKnownOrderingBasis(99)), "false");

        // 2. every records{}/ordering_examples{} case: body/head/id == oracle, byte-for-byte; the
        //    parse round-trip re-encodes to the SAME canonical bytes; every case is POSITIVE.
        String recordsBlock = objBlock(json, "records");
        String orderingExamplesBlock = objBlock(json, "ordering_examples");
        LinkedHashMap<String, String> records = namedObjectBlocks(recordsBlock);
        LinkedHashMap<String, String> orderingExamples = namedObjectBlocks(orderingExamplesBlock);
        LinkedHashMap<String, String> allCases = new LinkedHashMap<>();
        allCases.putAll(records);
        allCases.putAll(orderingExamples);
        check("dr records/ordering_examples no name collision",
                Integer.toString(allCases.size()), Integer.toString(records.size() + orderingExamples.size()));
        for (Map.Entry<String, String> e : allCases.entrySet()) {
            String name = e.getKey();
            String rv = e.getValue();
            Gateway.DecisionRecord d = buildRecord(name, rv);
            check("dr " + name + " body == oracle", Hex.encode(d.bytes()), field(rv, "body_hex"));
            check("dr " + name + " head == oracle", Hex.encode(d.head()), field(rv, "head_hex"));
            check("dr " + name + " id == oracle", Hex.encode(d.id()), field(rv, "id_hex"));
            Gateway.DecisionRecord parsed = Gateway.parseDecisionRecord(d.bytes());
            check("dr " + name + " round-trip", Hex.encode(parsed.bytes()), field(rv, "body_hex"));
            Gateway.validateDecisionRecord(parsed); // every records/ordering_examples case is POSITIVE
        }

        // 3. minimal, built directly (mandatory-field-only shell).
        String minB = records.get("minimal");
        Gateway.DecisionRecord minimal = new Gateway.DecisionRecord(
                Hex.decode(field(minB, "action_hex")), hexArrayField(minB, "governing_hex"), intField(minB, "outcome"),
                Gateway.correspondenceOnly());
        check("dr minimal direct body == oracle", Hex.encode(minimal.bytes()), field(minB, "body_hex"));
        check("dr minimal direct id == oracle", Hex.encode(minimal.id()), field(minB, "id_hex"));
        Gateway.validateDecisionRecord(Gateway.parseDecisionRecord(minimal.bytes()));

        // 4. named negative rejections.
        String neg = objBlock(json, "negative");
        for (String name : new String[]{"deny_with_consume_rejected", "hold_with_consume_rejected",
                "terms_key_outside_field_set_rejected", "unknown_outcome_rejected", "look_alike"}) {
            String c = objBlock(neg, name);
            check("dr negative " + name, drRejectKind(Hex.decode(field(c, "body_hex"))), field(c, "reject"));
        }
        for (Map.Entry<String, String> e : namedObjectBlocks(objBlock(neg, "ordering_malformed")).entrySet()) {
            check("dr ordering_malformed." + e.getKey(), drRejectKind(Hex.decode(field(e.getValue(), "body_hex"))), field(e.getValue(), "reject"));
        }

        // keys_out_of_order: canonical decodes+validates cleanly; the descending-key body is
        // rejected at the CBOR layer (NonCanonical) before parseDecisionRecord's own checks run.
        String koo = objBlock(neg, "keys_out_of_order");
        Gateway.validateDecisionRecord(Gateway.parseDecisionRecord(Hex.decode(field(koo, "canonical_body_hex"))));
        String cborKind;
        try {
            Cbor.decode(Hex.decode(field(koo, "noncanonical_body_hex")));
            cborKind = "decoded";
        } catch (NaalpException e) {
            cborKind = e.kind;
        }
        check("dr keys_out_of_order cbor-rejected", cborKind, "NonCanonical");
        check("dr keys_out_of_order parse-rejected", drRejectKind(Hex.decode(field(koo, "noncanonical_body_hex"))), "DecisionMalformed");

        // 5. third-party re-serve, using allow_consuming.
        String allowConsuming = records.get("allow_consuming");
        Gateway.DecisionRecord acRecord = buildRecord("allow_consuming", allowConsuming);
        check("dr allow_consuming body == oracle (re-check)", Hex.encode(acRecord.bytes()), field(allowConsuming, "body_hex"));
        byte[] seedProducer = seed(0x71);
        byte[] seedForeign = seed(0x72);
        byte[] producerPk = Cose.mldsaKeygen("ML-DSA-65", seedProducer);
        byte[] foreignPk = Cose.mldsaKeygen("ML-DSA-65", seedForeign);
        byte[] drObj = Gateway.signDecisionRecord(acRecord, Cose.ALG_MLDSA65, seedProducer);
        Gateway.ResolvedDecisionRecord byProducer = Gateway.verifyDecisionRecord(drObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, producerPk);
        Gateway.ResolvedDecisionRecord byThirdParty = Gateway.verifyDecisionRecord(drObj.clone(), Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, producerPk);
        check("dr third-party action match", Hex.encode(byProducer.action), Hex.encode(byThirdParty.action));
        check("dr third-party outcome allow", Long.toString(byThirdParty.outcome), Long.toString(Gateway.DECISION_ALLOW));
        check("dr third-party consume == oracle", Hex.encode(byThirdParty.consume), field(allowConsuming, "consume_hex"));
        check("dr foreign key rejected", errKind(() -> Gateway.verifyDecisionRecord(drObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, foreignPk)), "BadSignature");

        // 6. sign/verify terms_valid end-to-end, exercising the terms map on the round trip.
        String termsValid = records.get("terms_valid");
        Gateway.DecisionRecord tvRecord = buildRecord("terms_valid", termsValid);
        byte[] tvSeed = seed(0x11);
        byte[] tvPk = Cose.mldsaKeygen("ML-DSA-65", tvSeed);
        byte[] tvObj = Gateway.signDecisionRecord(tvRecord, Cose.ALG_MLDSA65, tvSeed);
        Gateway.ResolvedDecisionRecord tvResolved = Gateway.verifyDecisionRecord(tvObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, tvPk);
        check("dr terms_valid resolved terms[1].kind", Long.toString(tvResolved.terms.get(1L).kind), Long.toString(Gateway.TERM_OBSERVED));
        check("dr terms_valid resolved terms[4].kind", Long.toString(tvResolved.terms.get(4L).kind), Long.toString(Gateway.TERM_REPORTED));
        check("dr terms_valid resolved terms[4].source", new String(tvResolved.terms.get(4L).source, StandardCharsets.UTF_8), "boundary:relay-partner-3");
    }

    // ---- S3 naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof -------------------

    private static Gateway.CheckpointRoot cpFrom(String cv) {
        return new Gateway.CheckpointRoot(
                Hex.decode(field(cv, "log_hex")), intField(cv, "size"), Hex.decode(field(cv, "root_hex")),
                Hex.decode(field(cv, "prev_hex")), longField(cv, "at_str"));
    }

    private static Gateway.WitnessCosign wcFrom(String wv) {
        return new Gateway.WitnessCosign(Hex.decode(field(wv, "witness_hex")), Hex.decode(field(wv, "root_hex")), longField(wv, "at_str"));
    }

    private static String cpRejectKind(byte[] body) {
        try {
            Gateway.parseCheckpointRoot(body);
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static void runCheckpoint() throws Exception {
        String json = Files.readString(findVectorNamed("checkpoint"), StandardCharsets.UTF_8);

        check("cp genesisPrev == oracle", Hex.encode(Gateway.genesisPrev()), field(objBlock(json, "genesis"), "prev_hex"));

        String checkpointsBlock = objBlock(json, "checkpoints");
        LinkedHashMap<String, String> checkpoints = namedObjectBlocks(checkpointsBlock);
        for (Map.Entry<String, String> e : checkpoints.entrySet()) {
            String name = e.getKey();
            String cv = e.getValue();
            Gateway.CheckpointRoot c = cpFrom(cv);
            check("cp " + name + " body == oracle", Hex.encode(c.bytes()), field(cv, "body_hex"));
            check("cp " + name + " head == oracle", Hex.encode(c.head()), field(cv, "head_hex"));
            check("cp " + name + " id == oracle", Hex.encode(c.id()), field(cv, "id_hex"));
            check("cp " + name + " round-trip", Hex.encode(Gateway.parseCheckpointRoot(c.bytes()).bytes()), field(cv, "body_hex"));
        }

        LinkedHashMap<String, String> witnesses = namedObjectBlocks(objBlock(json, "witness_cosigns"));
        for (Map.Entry<String, String> e : witnesses.entrySet()) {
            String name = e.getKey();
            String wv = e.getValue();
            Gateway.WitnessCosign w = wcFrom(wv);
            check("wc " + name + " body == oracle", Hex.encode(w.bytes()), field(wv, "body_hex"));
            check("wc " + name + " head == oracle", Hex.encode(w.head()), field(wv, "head_hex"));
            check("wc " + name + " id == oracle", Hex.encode(w.id()), field(wv, "id_hex"));
        }

        // fork evidence: two witness-cosigned roots at the SAME (log, size) carrying DIFFERENT root
        // values -- the log has signed two incompatible histories, and both signatures are the proof.
        String fe = objBlock(json, "fork_evidence");
        String cpABlock = objBlock(fe, "checkpoint_a");
        String cpBBlock = objBlock(fe, "checkpoint_b");
        check("fork roots distinct", Boolean.toString(!field(cpABlock, "root_hex").equals(field(cpBBlock, "root_hex"))), "true");
        check("fork ids distinct", Boolean.toString(!field(cpABlock, "id_hex").equals(field(cpBBlock, "id_hex"))), "true");
        String wcABlock = objBlock(cpABlock, "witness_cosign");
        String wcBBlock = objBlock(cpBBlock, "witness_cosign");
        Gateway.WitnessCosign wcA = wcFrom(wcABlock);
        Gateway.WitnessCosign wcB = wcFrom(wcBBlock);
        check("fork wcA body == oracle", Hex.encode(wcA.bytes()), field(wcABlock, "body_hex"));
        check("fork wcB body == oracle", Hex.encode(wcB.bytes()), field(wcBBlock, "body_hex"));
        byte[] idA = Hex.decode(field(cpABlock, "id_hex"));
        byte[] idB = Hex.decode(field(cpBBlock, "id_hex"));
        check("fork wcA validates against A", errKind(() -> Gateway.validateWitnessCosign(wcA, idA)), "no-error");
        check("fork wcB validates against B", errKind(() -> Gateway.validateWitnessCosign(wcB, idB)), "no-error");
        check("fork wcA rejected against B", errKind(() -> Gateway.validateWitnessCosign(wcA, idB)), "WitnessRootMismatch");
        check("fork wcB rejected against A", errKind(() -> Gateway.validateWitnessCosign(wcB, idA)), "WitnessRootMismatch");

        // inclusion proofs, each checked against its named checkpoint's resolved id/size/root.
        Map<String, String> checkpointFor = Map.of(
                "leaf3_of7", "checkpoint0_size7",
                "leaf7_of8_newly_appended", "checkpoint1_size8",
                "single_leaf_tree_empty_path", "checkpoint_single_leaf");
        LinkedHashMap<String, String> inclusionProofs = namedObjectBlocks(objBlock(json, "inclusion_proofs"));
        for (Map.Entry<String, String> e : inclusionProofs.entrySet()) {
            String name = e.getKey();
            String iv = e.getValue();
            String cp = checkpoints.get(checkpointFor.get(name));
            check("ip " + name + " root matches checkpoint id", Hex.encode(cpFrom(cp).id()), field(iv, "root_hex"));

            Gateway.InclusionProof p = new Gateway.InclusionProof(
                    Hex.decode(field(iv, "root_hex")), Hex.decode(field(iv, "leaf_hex")), intField(iv, "index"), hexArrayField(iv, "path_hex"));
            check("ip " + name + " body == oracle", Hex.encode(p.bytes()), field(iv, "body_hex"));
            check("ip " + name + " head == oracle", Hex.encode(p.head()), field(iv, "head_hex"));
            check("ip " + name + " id == oracle", Hex.encode(p.id()), field(iv, "id_hex"));
            Gateway.InclusionProof parsed = Gateway.parseInclusionProof(p.bytes());
            long cpSize = intField(cp, "size");
            byte[] cpRoot = Hex.decode(field(cp, "root_hex"));
            check("ip " + name + " verify", errKind(() -> Gateway.verifyInclusionProof(parsed.leaf, parsed.index, cpSize, parsed.path, cpRoot)), "no-error");
        }

        // negative: wrong index / wrong path / witness-root-mismatch / checkpoint malformed.
        String neg = objBlock(json, "negative");
        String cp0 = checkpoints.get("checkpoint0_size7");
        byte[] root0 = Hex.decode(field(cp0, "root_hex"));
        long size0 = intField(cp0, "size");

        String wi = objBlock(neg, "inclusion_wrong_index");
        List<byte[]> wiPath = hexArrayField(wi, "path_hex");
        byte[] wiLeaf = Hex.decode(field(wi, "leaf_hex"));
        long wiIndex = intField(wi, "claimed_index");
        check("cp wrong index rejected", errKind(() -> Gateway.verifyInclusionProof(wiLeaf, wiIndex, size0, wiPath, root0)), "InclusionProofInvalid");

        String wp = objBlock(neg, "inclusion_wrong_path");
        List<byte[]> wpPath = hexArrayField(wp, "path_hex");
        byte[] wpLeaf = Hex.decode(field(wp, "leaf_hex"));
        long wpIndex = intField(wp, "index");
        check("cp wrong path rejected", errKind(() -> Gateway.verifyInclusionProof(wpLeaf, wpIndex, size0, wpPath, root0)), "InclusionProofInvalid");

        String wm = objBlock(neg, "witness_root_mismatch");
        Gateway.WitnessCosign wParsed = Gateway.parseWitnessCosign(Hex.decode(field(wm, "cosign_body_hex")));
        check("wm cosign root == oracle", Hex.encode(wParsed.root), field(wm, "cosign_names_root_hex"));
        byte[] wmAccompaniedId = Hex.decode(field(wm, "checkpoint_accompanied_id_hex"));
        check("wm rejected", errKind(() -> Gateway.validateWitnessCosign(wParsed, wmAccompaniedId)), field(wm, "reject"));

        String ckoo = objBlock(neg, "checkpoint_keys_out_of_order");
        Gateway.parseCheckpointRoot(Hex.decode(field(ckoo, "canonical_body_hex"))); // should parse
        String cborKind;
        try {
            Cbor.decode(Hex.decode(field(ckoo, "noncanonical_body_hex")));
            cborKind = "decoded";
        } catch (NaalpException e) {
            cborKind = e.kind;
        }
        check("cp keys_out_of_order cbor-rejected", cborKind, "NonCanonical");
        check("cp keys_out_of_order parse-rejected", cpRejectKind(Hex.decode(field(ckoo, "noncanonical_body_hex"))), "CheckpointMalformed");

        String cmf = objBlock(neg, "checkpoint_missing_field");
        check("cp missing field rejected", cpRejectKind(Hex.decode(field(cmf, "body_hex"))), field(cmf, "reject"));

        // MTH({}) = HASH() -- the empty-list base case.
        String etk = objBlock(json, "empty_tree_kat");
        check("cp merkleRoot(null) == oracle", Hex.encode(Gateway.merkleRoot(null)), field(etk, "root_hex"));
        check("cp merkleRoot([]) == oracle", Hex.encode(Gateway.merkleRoot(new ArrayList<>())), field(etk, "root_hex"));

        // RFC 9162 self-fidelity: independently re-derives PATH()/recompute over SYNTHETIC leaves
        // (never the oracle's own numbers), catching an algorithmic defect the n in {1,7,8} byte-
        // parity vectors above do not reach.
        int total = 0;
        for (int n = 1; n <= 12; n++) {
            List<byte[]> leaves = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                leaves.add(("synthetic-leaf-" + i).getBytes(StandardCharsets.UTF_8));
            }
            byte[] root = Gateway.merkleRoot(leaves);
            for (int m = 0; m < n; m++) {
                List<byte[]> path = Gateway.generateInclusionProofPath(leaves, m);
                Gateway.verifyInclusionProof(leaves.get(m), m, n, path, root); // no throw
                total++;
            }
        }
        check("cp rfc9162 self-fidelity total (sum 1..12)", Integer.toString(total), "78");

        List<byte[]> leaves5 = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            leaves5.add(("synthetic-leaf-" + i).getBytes(StandardCharsets.UTF_8));
        }
        byte[] root5 = Gateway.merkleRoot(leaves5);
        List<byte[]> path2 = Gateway.generateInclusionProofPath(leaves5, 2);
        check("cp tampered leaf rejected", errKind(() -> Gateway.verifyInclusionProof(
                "tampered-leaf".getBytes(StandardCharsets.UTF_8), 2, 5, path2, root5)), "InclusionProofInvalid");

        // sign/verify in isolation (NOT corpus-graded: the corpus carries no signed COSE vector).
        Gateway.CheckpointRoot cp0Obj = cpFrom(cp0);
        byte[] cpSeed = seed(0x11);
        byte[] cpPk = Cose.mldsaKeygen("ML-DSA-65", cpSeed);
        byte[] cpObj = Gateway.signCheckpointRoot(cp0Obj, Cose.ALG_MLDSA65, cpSeed);
        byte[][] cpParts = Cose.parseSign1Raw(cpObj);
        check("cp sign/verify in isolation", Boolean.toString(Cose.coseVerify1Raw(Cose.ALG_MLDSA65, cpPk, Cose.toBeSignedRaw(cpParts[0], cpParts[1]), cpParts[2])), "true");
        check("cp sign payload == body", Hex.encode(cpParts[1]), Hex.encode(cp0Obj.bytes()));
    }

    // ---- E6.3 naalp-egress-attestation -------------------------------------------------------------

    private static Gateway.EgressAttestation attFrom(String av) {
        return new Gateway.EgressAttestation(
                intField(av, "binding"), Hex.decode(field(av, "digest_hex")), intField(av, "effect"),
                Hex.decode(field(av, "audience_hex")), longField(av, "at_str"));
    }

    private static String egRejectKind(byte[] body) {
        try {
            Gateway.EgressAttestation a = Gateway.parseEgressAttestation(body);
            try {
                Gateway.validateEgressAttestation(a);
            } catch (NaalpException e) {
                return e.kind;
            }
            return "";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    /** Mirrors TestEgressVendorOnlyMutation: the honest verifyEgressAttestation takes NO
     * serving-party identity, so a mutant "vendor-only" verifier that additionally requires
     * servingParty == gatewayId wrongly rejects a third party re-serving the identical bytes. */
    private static void mutantVerify(byte[] obj, byte[] gwPk, byte[] gatewayId, byte[] servingParty) {
        Gateway.verifyEgressAttestation(obj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk);
        if (!java.util.Arrays.equals(servingParty, gatewayId)) {
            throw new NaalpException("EgMalformed", "stands in for a not-served-by-vendor rejection");
        }
    }

    private static void runEgressAttestation() throws Exception {
        String json = Files.readString(findVectorNamed("egress_attestation"), StandardCharsets.UTF_8);

        LinkedHashMap<String, String> attestations = namedObjectBlocks(objBlock(json, "attestations"));
        for (Map.Entry<String, String> e : attestations.entrySet()) {
            String name = e.getKey();
            String av = e.getValue();
            Gateway.EgressAttestation a = attFrom(av);
            check("eg " + name + " body == oracle", Hex.encode(a.bytes()), field(av, "body_hex"));
            check("eg " + name + " head == oracle", Hex.encode(a.head()), field(av, "head_hex"));
            check("eg " + name + " id == oracle", Hex.encode(a.id()), field(av, "id_hex"));
        }
        for (String vb : objectBlocks(json, "binding_vocabulary")) {
            String name = field(vb, "name");
            long code = intField(vb, "code");
            check("eg binding vocab " + name + " known", Boolean.toString(Gateway.isKnownBinding(code)), "true");
            check("eg binding vocab " + name + " name", Gateway.bindingName(code), name);
        }
        long unknownBinding = intField(json, "unknown_binding");
        check("eg unknown binding not known", Boolean.toString(Gateway.isKnownBinding(unknownBinding)), "false");

        // oversized counter: at = 2^64-1, carried as a decimal string so no float64 decoder rounds it.
        String ec = objBlock(json, "edge_cases");
        String ov = objBlock(ec, "oversized_counter");
        check("eg oversized at_str", field(ov, "at_str"), "18446744073709551615");
        Gateway.EgressAttestation oversized = attFrom(ov);
        check("eg oversized at == 2^64-1", Long.toUnsignedString(oversized.at), "18446744073709551615");
        check("eg oversized body == oracle", Hex.encode(oversized.bytes()), field(ov, "body_hex"));
        check("eg oversized parsed at", Long.toUnsignedString(Gateway.parseEgressAttestation(oversized.bytes()).at), Long.toUnsignedString(oversized.at));

        // third-party re-serve.
        byte[] seedGw = seed(0x61);
        byte[] seedForeign = seed(0x62);
        byte[] gwPk = Cose.mldsaKeygen("ML-DSA-65", seedGw);
        byte[] foreignPk = Cose.mldsaKeygen("ML-DSA-65", seedForeign);
        Gateway.EgressAttestation cb = attFrom(attestations.get("content_bound"));
        byte[] egObj = Gateway.signEgressAttestation(cb, Cose.ALG_MLDSA65, seedGw);
        Gateway.ResolvedEgressAttestation byGateway = Gateway.verifyEgressAttestation(egObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk);
        Gateway.ResolvedEgressAttestation byThirdParty = Gateway.verifyEgressAttestation(egObj.clone(), Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk);
        check("eg re-serve binding match", Long.toString(byGateway.binding), Long.toString(byThirdParty.binding));
        check("eg re-serve digest match", Hex.encode(byGateway.digest), Hex.encode(byThirdParty.digest));
        check("eg re-serve effect match", Long.toString(byGateway.effect), Long.toString(byThirdParty.effect));
        check("eg re-serve audience match", Hex.encode(byGateway.audience), Hex.encode(byThirdParty.audience));
        check("eg re-serve at match", Long.toUnsignedString(byGateway.at), Long.toUnsignedString(byThirdParty.at));
        check("eg re-serve binding content_bound", Long.toString(byThirdParty.binding), Long.toString(Gateway.BINDING_CONTENT_BOUND));
        check("eg re-serve digest == object cid", Hex.encode(byThirdParty.digest), field(json, "object_cid_hex"));
        check("eg foreign key rejected", errKind(() -> Gateway.verifyEgressAttestation(egObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, foreignPk)), "BadSignature");

        Gateway.EgressAttestation bad = new Gateway.EgressAttestation(
                unknownBinding, Hex.decode(field(json, "object_cid_hex")), 0, Hex.decode(field(json, "audience_hex")), 0);
        byte[] badObj = Gateway.signEgressAttestation(bad, Cose.ALG_MLDSA65, seedGw);
        check("eg unknown binding rejected", errKind(() -> Gateway.verifyEgressAttestation(badObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk)), "UnknownEgressBinding");

        // vendor-only mutation.
        byte[] gatewayId = "gateway-id-0x61".getBytes(StandardCharsets.UTF_8);
        byte[] thirdPartyId = "did:example:mirror-cache".getBytes(StandardCharsets.UTF_8);
        Gateway.EgressAttestation cf = attFrom(attestations.get("content_free"));
        byte[] cfObj = Gateway.signEgressAttestation(cf, Cose.ALG_MLDSA65, seedGw);
        Gateway.verifyEgressAttestation(cfObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk); // honest: no throw
        check("eg vendor-only mutant accepts vendor", errKind(() -> mutantVerify(cfObj, gwPk, gatewayId, gatewayId)), "no-error");
        check("eg vendor-only mutant rejects third party", errKind(() -> mutantVerify(cfObj, gwPk, gatewayId, thirdPartyId)), "EgMalformed");

        // content_free commitment open/verify pair.
        String co = objBlock(json, "commitment_open");
        Gateway.EgressAttestation cfForCommit = attFrom(attestations.get("content_free"));
        check("eg commitment digest == oracle", Hex.encode(cfForCommit.digest), field(co, "commitment_hex"));
        byte[] objectCid = Hex.decode(field(co, "object_cid_hex"));
        byte[] wrongObjectCid = Hex.decode(field(co, "wrong_object_cid_hex"));
        byte[] salt = Hex.decode(field(co, "salt_hex"));
        byte[] wrongSalt = Hex.decode(field(co, "wrong_salt_hex"));
        check("eg egressCommit == oracle", Hex.encode(Gateway.egressCommit(objectCid, salt)), field(co, "commitment_hex"));
        check("eg open commitment true", Boolean.toString(Gateway.openEgressCommitment(cfForCommit, objectCid, salt)), "true");
        check("eg open commitment wrong salt false", Boolean.toString(Gateway.openEgressCommitment(cfForCommit, objectCid, wrongSalt)), "false");
        check("eg open commitment wrong cid false", Boolean.toString(Gateway.openEgressCommitment(cfForCommit, wrongObjectCid, salt)), "false");
        check("eg open commitment wrong both false", Boolean.toString(Gateway.openEgressCommitment(cfForCommit, wrongObjectCid, wrongSalt)), "false");
        Gateway.EgressAttestation cbForCommit = attFrom(attestations.get("content_bound"));
        check("eg content_bound never opens", Boolean.toString(Gateway.openEgressCommitment(cbForCommit, objectCid, salt)), "false");

        // keys_out_of_order.
        String koo = objBlock(ec, "keys_out_of_order");
        Gateway.EgressAttestation kooAtt = attFrom(koo);
        check("eg koo body == oracle", Hex.encode(kooAtt.bytes()), field(koo, "canonical_body_hex"));
        byte[] canon = Hex.decode(field(koo, "canonical_body_hex"));
        byte[] noncanon = Hex.decode(field(koo, "noncanonical_body_hex"));
        Cbor.decode(canon); // should decode
        Gateway.parseEgressAttestation(canon); // should parse
        String cborKind;
        try {
            Cbor.decode(noncanon);
            cborKind = "decoded";
        } catch (NaalpException e) {
            cborKind = e.kind;
        }
        check("eg koo cbor-rejected", cborKind, "NonCanonical");
        check("eg koo parse-rejected", egRejectKind(noncanon), "EgMalformed");

        // empty-vs-absent audience.
        String eva = objBlock(ec, "empty_vs_absent");
        byte[] objectCidBytes = Hex.decode(field(json, "object_cid_hex"));
        String emptyAudBlock = objBlock(eva, "empty_audience");
        String populatedAudBlock = objBlock(eva, "populated_audience");
        Gateway.EgressAttestation emptyAud = new Gateway.EgressAttestation(
                Gateway.BINDING_CONTENT_BOUND, objectCidBytes, 1, new byte[0], 1735689600000L);
        Gateway.EgressAttestation populatedAud = new Gateway.EgressAttestation(
                Gateway.BINDING_CONTENT_BOUND, objectCidBytes, 1, Hex.decode(field(populatedAudBlock, "audience_hex")), 1735689600000L);
        check("eg empty audience body == oracle", Hex.encode(emptyAud.bytes()), field(emptyAudBlock, "body_hex"));
        check("eg populated audience body == oracle", Hex.encode(populatedAud.bytes()), field(populatedAudBlock, "body_hex"));
        check("eg empty vs populated ids distinct", Boolean.toString(!Hex.encode(emptyAud.id()).equals(Hex.encode(populatedAud.id()))), "true");
        check("eg empty audience id == oracle", Hex.encode(emptyAud.id()), field(emptyAudBlock, "id_hex"));
        Gateway.parseEgressAttestation(emptyAud.bytes());
        Gateway.parseEgressAttestation(populatedAud.bytes());
        String absentFieldBlock = objBlock(eva, "absent_field");
        check("eg absent audience field rejected", egRejectKind(Hex.decode(field(absentFieldBlock, "body_hex"))), "EgMalformed");

        // minimal.
        String minB = objBlock(ec, "minimal");
        Gateway.EgressAttestation minimal = attFrom(minB);
        check("eg minimal body == oracle", Hex.encode(minimal.bytes()), field(minB, "body_hex"));
        check("eg minimal id == oracle", Hex.encode(minimal.id()), field(minB, "id_hex"));
        Gateway.parseEgressAttestation(minimal.bytes());
        byte[] minSeed = seed(0x63);
        byte[] minPk = Cose.mldsaKeygen("ML-DSA-65", minSeed);
        byte[] minObj = Gateway.signEgressAttestation(minimal, Cose.ALG_MLDSA65, minSeed);
        check("eg minimal verifies end-to-end", errKind(() -> Gateway.verifyEgressAttestation(minObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, minPk)), "no-error");

        // look_alike.
        String la = objBlock(ec, "look_alike");
        check("eg look_alike rejected", egRejectKind(Hex.decode(field(la, "body_hex"))), field(la, "reject"));

        // ordering byte parity.
        for (String vb : objectBlocks(json, "ordering_basis_vocabulary")) {
            String name = field(vb, "name");
            long code = intField(vb, "code");
            check("eg ordering vocab " + name + " known", Boolean.toString(Gateway.isKnownOrderingBasis(code)), "true");
            check("eg ordering vocab " + name + " name", Gateway.orderingBasisName(code), name);
        }
        LinkedHashMap<String, String> attestationsWithOrdering = namedObjectBlocks(objBlock(json, "attestations_with_ordering"));
        for (Map.Entry<String, String> e : attestationsWithOrdering.entrySet()) {
            String name = e.getKey();
            String av = e.getValue();
            Gateway.EgressAttestation base = attFrom(av);
            Gateway.OrderingDisclosure ord;
            switch (name) {
                case "correspondence_only":
                    ord = Gateway.correspondenceOnly();
                    break;
                case "single_boundary":
                    ord = new Gateway.OrderingDisclosure(Gateway.ORDERING_SINGLE_BOUNDARY,
                            "boundary-signer-X".getBytes(StandardCharsets.UTF_8), new byte[0], new byte[0]);
                    break;
                case "external_mechanism":
                    ord = new Gateway.OrderingDisclosure(Gateway.ORDERING_EXTERNAL_MECHANISM, new byte[0],
                            "external-log:acme-transparency-v1".getBytes(StandardCharsets.UTF_8),
                            Hex.decode("2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56"));
                    break;
                default:
                    throw new AssertionError("unhandled attestations_with_ordering name " + name);
            }
            Gateway.EgressAttestation withOrd = new Gateway.EgressAttestation(base.binding, base.digest, base.effect, base.audience, base.at, ord);
            check("eg " + name + " body == oracle", Hex.encode(withOrd.bytes()), field(av, "body_hex"));
            check("eg " + name + " head == oracle", Hex.encode(withOrd.head()), field(av, "head_hex"));
            check("eg " + name + " id == oracle", Hex.encode(withOrd.id()), field(av, "id_hex"));
            Gateway.EgressAttestation parsed = Gateway.parseEgressAttestation(withOrd.bytes());
            check("eg " + name + " parsed has ordering", Boolean.toString(parsed.ordering != null), "true");
            check("eg " + name + " round-trip", Hex.encode(parsed.bytes()), field(av, "body_hex"));
            Gateway.validateEgressAttestation(parsed); // no throw
        }
        Gateway.EgressAttestation plain = Gateway.parseEgressAttestation(attFrom(attestations.get("content_bound")).bytes());
        check("eg plain has no ordering", Boolean.toString(plain.ordering == null), "true");

        // ordering negative.
        String negOrd = objBlock(json, "negative_ordering");
        String sbwm = objBlock(negOrd, "ordering_malformed_single_boundary_with_mechanism");
        check("eg ordering malformed sbwm", egRejectKind(Hex.decode(field(sbwm, "body_hex"))), field(sbwm, "reject"));
        String uob = objBlock(negOrd, "unknown_ordering_basis");
        check("eg unknown ordering basis", egRejectKind(Hex.decode(field(uob, "body_hex"))), field(uob, "reject"));

        // missing at (field 5) -- fields 1-4 correctly typed, field 5 absent.
        Cbor.M missingAt = new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(Gateway.BINDING_CONTENT_BOUND)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(new byte[]{0x20, 0x30})),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(1)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(new byte[0]))));
        check("eg missing at field rejected", egRejectKind(Cbor.encode(missingAt)), "EgMalformed");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("gateway conformance (Java) — graded vs vectors/gateway/cases.json");
        run();
        System.out.println("decision-record conformance (Java) — graded vs vectors/decision_record/cases.json");
        runDecisionRecord();
        System.out.println("checkpoint conformance (Java) — graded vs vectors/checkpoint/cases.json");
        runCheckpoint();
        System.out.println("egress-attestation conformance (Java) — graded vs vectors/egress_attestation/cases.json");
        runEgressAttestation();
        System.out.println(fails == 0 ? "GatewayKatTest: PASS" : "GatewayKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
