// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * C15 multi-hop agent-delegation known-answer test for the Java SDK (design.md §18; R-DEL-1..8),
 * graded against the shared independent corpus vectors/delegation/cases.json (NOT produced by this
 * code): the DelegationGrant wire body + content id, the D2 scope-containment path-prefix rule, and
 * the 12-step leaf→root chain verifier's verdict for every scenario (authorized / GrantExpired /
 * GrantRevoked / CapExceedsParent / DelegationDepthExceeded / UntrustedChainRoot / ChainBroken /
 * EffectNotAuthorized).
 *
 * <p>CORPUS-GRADED (pure bytes / verdicts): every grant body and id, every scope-containment verdict,
 * and every chain-verification verdict — reproduced byte-for-byte or verdict-for-verdict from the
 * corpus. The chain scenarios are abstract (issuer/subject with index-referenced causes), exactly as
 * the reference verdict tests build them; each scenario grant is assigned a distinct synthetic
 * envelope content id, and the verdict is invariant to the specific id bytes (only equality and
 * uniqueness matter). WIRING DEMONSTRATED IN ISOLATION: the D4 two-gate composition
 * ({@code authorizeDestructive}) wires a valid delegation chain onto a real §7 approval consumed
 * single-use through {@link Approval.Ledger} — a destructive action authorizes once and denies
 * AlreadyConsumed on replay.
 *
 * <p>Section 5 (STEP-2 ten-port parity wave) exercises the envelope-integration layer in isolation over
 * real ML-DSA-65 signed objects: {@link Delegation#composedKindValidator}, {@link
 * Delegation.Grant#envelopeObject}, and {@link Delegation#verifyGrantObject} — using the SAME grant
 * field values the corpus grades (section 1 above), so the round-tripped grant body still reproduces
 * the oracle bytes through the envelope path, not just the bare {@link Delegation.Grant#bytes} path.
 *
 * <p>Written test-first: {@link Delegation} is absent until Delegation.java lands, so this fails RED
 * with a javac "cannot find symbol Delegation"; the recorded mutation drops the effect-attenuation
 * check (step 6 CapExceedsParent) in {@code verifyChain}, which flips the named "effect_exceeds_leaf"
 * scenario (a leaf could then act above its granted effect_cap — a privilege escalation).
 */
public final class DelegationKatTest {
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
            Path p = d.resolve("vectors").resolve("delegation").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/delegation/cases.json not found from " + System.getProperty("user.dir"));
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

    private static List<String> topStrings(String arrayInner) {
        List<String> out = new ArrayList<>();
        Matcher m = Pattern.compile("\"([^\"]*)\"").matcher(arrayInner);
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }

    private static List<Integer> intList(String scope, String key) {
        List<Integer> out = new ArrayList<>();
        Matcher m = Pattern.compile("-?\\d+").matcher(arrayBlock(scope, key));
        while (m.find()) {
            out.add(Integer.parseInt(m.group()));
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

    /** A distinct synthetic envelope content id per scenario grant index (the verdict is invariant to
     * the specific bytes; only per-index distinctness and consistent cross-reference matter). */
    private static byte[] scenarioCid(int i) {
        return Cbor.contentId(("naalp-deleg-grant-" + i).getBytes(StandardCharsets.UTF_8));
    }

    private static final int ALG = Cose.ALG_MLDSA65;

    private static Delegation.Grant grantOf(String gb) {
        return new Delegation.Grant(field(gb, "subject"), intField(gb, "effect_cap"), intField(gb, "max_depth"),
                intField(gb, "not_before"), intField(gb, "not_after"), field(gb, "scope"));
    }

    private static String grantBlockNamed(String json, String name) {
        for (String gb : splitObjects(arrayBlock(json, "grants"))) {
            if (field(gb, "name").equals(name)) {
                return gb;
            }
        }
        throw new AssertionError("grant not found: " + name);
    }

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);

        // 1. the DelegationGrant wire body + content id reproduce the oracle for every named grant, and
        //    grantFromBody round-trips the decoded body back to the same fields (the decode direction).
        for (String gb : splitObjects(arrayBlock(json, "grants"))) {
            Delegation.Grant g = grantOf(gb);
            String name = field(gb, "name");
            check("grant " + name + " body == oracle", Hex.encode(g.bytes()), field(gb, "body_hex"));
            check("grant " + name + " content id == oracle", Hex.encode(g.contentId()), field(gb, "content_id_hex"));
            Delegation.Grant back = Delegation.grantFromBody(Cbor.decode(g.bytes()));
            check("grant " + name + " round-trips through grantFromBody", Hex.encode(back.bytes()), field(gb, "body_hex"));
        }
        // a malformed grant body (effect_cap out of the closed lattice) is rejected ChainBroken.
        byte[] badBody = Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.T("x")),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(4)), // effect_cap 4 > destructive
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(0)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.U(0)),
                new Cbor.Pair(new Cbor.U(5), new Cbor.U(0)))));
        check("grantFromBody(effect_cap=4) rejected ChainBroken",
                errKind(() -> Delegation.grantFromBody(Cbor.decode(badBody))), "ChainBroken");

        // 2. the D2 scope-containment path-prefix rule reproduces the oracle for every pair.
        for (String cb : splitObjects(arrayBlock(json, "scope_containment"))) {
            String child = field(cb, "child");
            String parent = field(cb, "parent");
            boolean want = boolField(cb, "contained");
            check("scope_contained(\"" + child + "\", \"" + parent + "\")",
                    Boolean.toString(Delegation.scopeContained(child, parent)), Boolean.toString(want));
        }

        // 3. the 12-step leaf->root chain verifier reproduces the oracle verdict for every scenario.
        for (String sb : splitObjects(arrayBlock(json, "scenarios"))) {
            String name = field(sb, "name");
            List<String> gblocks = splitObjects(arrayBlock(sb, "grants"));
            List<byte[]> cids = new ArrayList<>();
            for (int i = 0; i < gblocks.size(); i++) {
                cids.add(scenarioCid(i));
            }
            Map<String, Delegation.Resolved> gs = new HashMap<>();
            for (int i = 0; i < gblocks.size(); i++) {
                String gb = gblocks.get(i);
                List<byte[]> causes = new ArrayList<>();
                for (int idx : intList(gb, "causes")) {
                    causes.add(cids.get(idx));
                }
                Delegation.Resolved r = new Delegation.Resolved(cids.get(i), field(gb, "issuer"), grantOf(gb), causes);
                gs.put(Hex.encode(cids.get(i)), r);
            }
            String ab = objBlock(sb, "action");
            List<byte[]> acauses = new ArrayList<>();
            for (int idx : intList(ab, "causes")) {
                acauses.add(cids.get(idx));
            }
            Delegation.Action action = new Delegation.Action(
                    field(ab, "signer"), intField(ab, "effect"), field(ab, "scope"), acauses);
            Set<String> anchors = new HashSet<>(topStrings(arrayBlock(sb, "anchors")));
            Map<String, Long> revoked = new HashMap<>();
            for (String rb : splitObjects(arrayBlock(sb, "revoked"))) {
                revoked.put(Hex.encode(cids.get((int) intField(rb, "grant"))), intField(rb, "pos"));
            }
            long now = intField(sb, "now");
            String expect = field(sb, "expect");
            String want = expect.equals("authorized") ? "no-error" : expect;
            check("scenario " + name + " -> " + expect,
                    errKind(() -> Delegation.verifyChain(action, gs, anchors, revoked, now)), want);
        }

        // 4. D4 wiring demonstrated in isolation: a destructive action gated by BOTH a valid delegation
        //    chain AND a real §7 approval consumed single-use — authorizes once, denies AlreadyConsumed.
        byte[] argsId = Cbor.contentId("destructive-op-args".getBytes(StandardCharsets.UTF_8));
        byte[] approverSeed = new byte[32];
        java.util.Arrays.fill(approverSeed, (byte) 7);
        byte[] approverPk = Cose.mldsaKeygen("ML-DSA-65", approverSeed);
        byte[] nonce = new byte[16];
        Approval.ApprovalRecord appr = new Approval.ApprovalRecord(argsId, "A", Policy.DESTRUCTIVE, nonce, 100000);
        byte[] apprSig = Approval.signApproval(appr, ALG, approverSeed);

        byte[] rootCid = scenarioCid(0);
        Delegation.Grant chainGrant = new Delegation.Grant("B", Policy.DESTRUCTIVE, 0, 100, 900, "");
        Delegation.Resolved rootGrant = new Delegation.Resolved(rootCid, "A", chainGrant, List.of());
        Map<String, Delegation.Resolved> d4grants = new HashMap<>();
        d4grants.put(Hex.encode(rootCid), rootGrant);
        Delegation.Action d4action = new Delegation.Action("B", Policy.DESTRUCTIVE, "", List.of(rootCid));
        Set<String> d4anchors = new HashSet<>(List.of("A"));

        Path wal = Files.createTempFile("naalp-deleg-waveB-", ".wal");
        wal.toFile().deleteOnExit();
        Files.deleteIfExists(wal);
        Approval.Ledger ledger = Approval.Ledger.open(wal);
        check("D4 destructive action authorized (chain + fresh approval)",
                errKind(() -> Delegation.authorizeDestructive(d4action, d4grants, d4anchors, new HashMap<>(), 500,
                        appr, ALG, approverPk, apprSig, argsId, ledger)), "no-error");
        check("D4 approval consumed single-use (replay denied AlreadyConsumed)",
                errKind(() -> Delegation.authorizeDestructive(d4action, d4grants, d4anchors, new HashMap<>(), 500,
                        appr, ALG, approverPk, apprSig, argsId, ledger)), "AlreadyConsumed");
        ledger.close();

        // a broken chain denies with its D3 error even when a valid approval is present (precedence).
        Delegation.Action untrusted = new Delegation.Action("B", Policy.DESTRUCTIVE, "", List.of(rootCid));
        Path wal2 = Files.createTempFile("naalp-deleg-waveB2-", ".wal");
        wal2.toFile().deleteOnExit();
        Files.deleteIfExists(wal2);
        Approval.Ledger ledger2 = Approval.Ledger.open(wal2);
        check("D4 broken chain denies with the D3 error (untrusted root), approval untouched",
                errKind(() -> Delegation.authorizeDestructive(untrusted, d4grants, new HashSet<>(List.of("Z")),
                        new HashMap<>(), 500, appr, ALG, approverPk, apprSig, argsId, ledger2)), "UntrustedChainRoot");
        check("D4 approval NOT consumed on a denied action", Integer.toString(ledger2.len()), "0");
        ledger2.close();

        // 5. the envelope-integration layer (D3 step 3), demonstrated in isolation over real ML-DSA-65
        //    signed objects: composedKindValidator, Grant.envelopeObject, verifyGrantObject. Uses the
        //    SAME grant field values graded in section 1, so the round-tripped body still reproduces
        //    the oracle bytes through the envelope path.
        check("composedKindValidator accepts tier-1 DelegationGrant",
                Boolean.toString(Delegation.composedKindValidator(Delegation.CHANNEL_CAPABILITY, Delegation.KIND_DELEGATION_GRANT)),
                "true");
        check("composedKindValidator accepts the frozen baseline (CapIssue)",
                Boolean.toString(Delegation.composedKindValidator(Delegation.CHANNEL_CAPABILITY, 0)), "true");
        check("composedKindValidator rejects an unregistered kind on Capability",
                Boolean.toString(Delegation.composedKindValidator(Delegation.CHANNEL_CAPABILITY, 99)), "false");
        check("composedKindValidator rejects an unregistered channel",
                Boolean.toString(Delegation.composedKindValidator(0x0099, Delegation.KIND_DELEGATION_GRANT)), "false");
        check("kindValidator alone rejects the frozen baseline (tier separation)",
                Boolean.toString(Delegation.kindValidator(Delegation.CHANNEL_CAPABILITY, 0)), "false");

        byte[] issuerSeed = new byte[32];
        java.util.Arrays.fill(issuerSeed, (byte) 0x30);
        byte[] issuerPk = Cose.mldsaKeygen("ML-DSA-65", issuerSeed);
        String issuerId = Identity.signerId(ALG, issuerPk);
        byte[] foreignEnvSeed = new byte[32];
        java.util.Arrays.fill(foreignEnvSeed, (byte) 0x31);
        byte[] foreignEnvPk = Cose.mldsaKeygen("ML-DSA-65", foreignEnvSeed);

        String fullScopeGb = grantBlockNamed(json, "full_scope");
        Delegation.Grant fullScopeGrant = grantOf(fullScopeGb);
        Envelope.Object rootObj = fullScopeGrant.envelopeObject(issuerId.getBytes(StandardCharsets.UTF_8), 1234, Cose.PROFILE_PUBLIC, List.of());
        byte[] rootSigned = Envelope.sign(rootObj, ALG, issuerSeed);
        Delegation.Resolved resolvedRoot = Delegation.verifyGrantObject(Cose.PROFILE_PUBLIC, ALG, issuerPk, rootSigned);
        check("verifyGrantObject issuer == the authenticated signer id", resolvedRoot.issuer, issuerId);
        check("verifyGrantObject grant body == oracle (through the envelope path)",
                Hex.encode(resolvedRoot.grant.bytes()), field(fullScopeGb, "body_hex"));
        check("verifyGrantObject content id == the signed envelope's own content id",
                Hex.encode(resolvedRoot.contentID), Hex.encode(rootObj.id));
        check("verifyGrantObject causes empty for a root grant", Integer.toString(resolvedRoot.causes.size()), "0");

        // a chained (non-root) grant: causes names the parent envelope content id.
        List<byte[]> childCauses = List.of(rootObj.id);
        Envelope.Object childObj = fullScopeGrant.envelopeObject(issuerId.getBytes(StandardCharsets.UTF_8), 1235, Cose.PROFILE_PUBLIC, childCauses);
        byte[] childSigned = Envelope.sign(childObj, ALG, issuerSeed);
        Delegation.Resolved resolvedChild = Delegation.verifyGrantObject(Cose.PROFILE_PUBLIC, ALG, issuerPk, childSigned);
        check("verifyGrantObject preserves causes (parent content id)",
                Hex.encode(resolvedChild.causes.get(0)), Hex.encode(rootObj.id));

        // a wrong verifying key never authenticates the signed grant (BadSignature, propagated from
        // envelope.verify — the signature check itself fails before the issuer-binding check runs).
        check("verifyGrantObject wrong key denied BadSignature",
                errKind(() -> Delegation.verifyGrantObject(Cose.PROFILE_PUBLIC, ALG, foreignEnvPk, rootSigned)), "BadSignature");

        // a self-asserted issuer that does not derive from the authenticated key confers nothing
        // (R-DEL-3/R-5.1): the object is internally consistent and the real key signs it, but the
        // claimed signer id is not what the verifying key resolves to.
        Envelope.Object spoofedObj = fullScopeGrant.envelopeObject("attacker-claimed-id".getBytes(StandardCharsets.UTF_8), 1234, Cose.PROFILE_PUBLIC, List.of());
        byte[] spoofedSigned = Envelope.sign(spoofedObj, ALG, issuerSeed);
        check("verifyGrantObject self-asserted issuer denied SignerMismatch",
                errKind(() -> Delegation.verifyGrantObject(Cose.PROFILE_PUBLIC, ALG, issuerPk, spoofedSigned)), "SignerMismatch");

        // a baseline (non-DelegationGrant) kind on the Capability channel is a known kind (composed
        // validator accepts it) but is not a tier-1 DelegationGrant — ChainBroken, fail-closed.
        Envelope.Object wrongKindObj = fullScopeGrant.envelopeObject(issuerId.getBytes(StandardCharsets.UTF_8), 1234, Cose.PROFILE_PUBLIC, List.of());
        wrongKindObj.kind = 0; // CapIssue — known via the frozen baseline, but not DelegationGrant
        byte[] wrongKindSigned = Envelope.sign(wrongKindObj, ALG, issuerSeed);
        check("verifyGrantObject wrong kind denied ChainBroken",
                errKind(() -> Delegation.verifyGrantObject(Cose.PROFILE_PUBLIC, ALG, issuerPk, wrongKindSigned)), "ChainBroken");

        // a DelegationGrant object declaring an effect other than non_idempotent_write — ChainBroken.
        Envelope.Object wrongEffectObj = fullScopeGrant.envelopeObject(issuerId.getBytes(StandardCharsets.UTF_8), 1234, Cose.PROFILE_PUBLIC, List.of());
        wrongEffectObj.effect = Policy.READ_ONLY;
        byte[] wrongEffectSigned = Envelope.sign(wrongEffectObj, ALG, issuerSeed);
        check("verifyGrantObject wrong own-effect denied ChainBroken",
                errKind(() -> Delegation.verifyGrantObject(Cose.PROFILE_PUBLIC, ALG, issuerPk, wrongEffectSigned)), "ChainBroken");

        // Grant.envelopeObject's own fail-closed checks: a non-NFC subject and an out-of-lattice
        // effect_cap are rejected before any signing is attempted.
        Delegation.Grant nonNfcGrant = new Delegation.Grant("é", 0, 0, 0, 1000, "");
        check("envelopeObject rejects a non-NFC subject NonNFC",
                errKind(() -> nonNfcGrant.envelopeObject(issuerId.getBytes(StandardCharsets.UTF_8), 1234, Cose.PROFILE_PUBLIC, List.of())),
                "NonNFC");
        Delegation.Grant badCapGrant = new Delegation.Grant("agent:x", 4, 0, 0, 1000, "");
        check("envelopeObject rejects effect_cap=4 GrantMalformed",
                errKind(() -> badCapGrant.envelopeObject(issuerId.getBytes(StandardCharsets.UTF_8), 1234, Cose.PROFILE_PUBLIC, List.of())),
                "GrantMalformed");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("delegation conformance (Java) — graded vs vectors/delegation/cases.json");
        run();
        System.out.println(fails == 0 ? "DelegationKatTest: PASS" : "DelegationKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
