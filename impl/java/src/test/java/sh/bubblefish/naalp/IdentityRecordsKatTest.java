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
 * Identity RECORD + THREAD surfaces known-answer test for the Java SDK (design.md
 * §5.2/§5.3/§5.4/§5.5, R-1.4/R-5.2/R-5.3/R-5.4), graded against the shared independent corpus
 * vectors/identity_records/cases.json (tools/identity_records_oracle.py; NOT produced by this
 * code): {@link Identity.RevocationRecord}, {@link Identity#revokedAt}, {@link
 * Identity#verifyRevocation}, {@link Identity.ForeignLinkRecord}, {@link
 * Identity#verifyForeignLink}, {@link Identity.RotationEvidence}, {@link Identity.Thread}, {@link
 * Identity.Thread#attributable}, {@link Identity#resolveThread}. Go (impl/go/identity) and Rust
 * (impl/rust/src/identity.rs) MUST reproduce every *_hex byte and every expect_valid /
 * expect_linked / expect_error / expect_revoked / expect_thread / expect verdict; this test grades
 * the Java port against the SAME oracle bytes and verdicts.
 *
 * <p>SECURITY-CRITICAL: {@link Identity#verifyRevocation} is fail-closed -- a candidate signer
 * that recomputes to neither the revoked key nor a member of the deployer's configured
 * recovery-id set is rejected SignerMismatch BEFORE the signature is even checked. The
 * "recovery_key_not_configured_reject" case is the mutation anchor: a valid K_R signature over an
 * EMPTY authorized-recovery-ids set MUST reject; dropping the membership guard (authorized :=
 * true unconditionally) flips it to accept.
 *
 * <p>KAT convention (a standalone {@code main} that exits non-zero on any failure); named
 * "…KatTest" so the filename carries the "test" token the ten-language-parity gate indexes.
 * Compile alongside the SDK sources and RotationKatTest's sibling tests, then run with the
 * bcprov-jdk18on jar on the classpath (see RotationKatTest's javadoc for the exact commands).
 */
public final class IdentityRecordsKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    // ---- nesting-aware JSON access (Java has no JSON library; mirrors PolicyKatTest/FederationKatTest) ----

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("identity_records").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/identity_records/cases.json not found from " + System.getProperty("user.dir"));
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
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("string key not found: " + key);
        }
        return m.group(1);
    }

    private static long intField(String scope, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+)").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("int key not found: " + key);
        }
        return Long.parseLong(m.group(1));
    }

    private static boolean boolField(String scope, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(true|false)").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("bool key not found: " + key);
        }
        return m.group(1).equals("true");
    }

    /** The string elements of the array named {@code key} (also fine for an empty {@code []}). */
    private static List<String> stringArray(String scope, String key) {
        Matcher a = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL).matcher(scope);
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

    private static byte[] hexField(String scope, String key) {
        return Hex.decode(field(scope, key));
    }

    /** {@code errKind}-style runner: "no-error" on success, else the NaalpException.kind, else the
     * exception class name. */
    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        } catch (Throwable t) {
            return t.getClass().getSimpleName();
        }
    }

    // ---- revocation ----

    private static void runRevocation(String json) {
        String rev = objBlock(json, "revocation");

        // RevocationRecord.bytes() reproduces the oracle's deterministic-CBOR body.
        for (String tc : splitObjects(arrayBlock(rev, "record_bytes"))) {
            String name = field(tc, "name");
            Identity.RevocationRecord r = new Identity.RevocationRecord(field(tc, "key"), intField(tc, "not_after"));
            check("revocation.record_bytes " + name, Hex.encode(r.bytes()), field(tc, "bytes_hex"));
        }

        // RevokedAt: `posTime > notAfter`, selecting only the scenario's revocation for query_key
        // (mirrors the Go/Rust oracle test's thin selection loop over a per-key revocation set).
        for (String sc : splitObjects(arrayBlock(rev, "revoked_at"))) {
            String name = field(sc, "name");
            String queryKey = field(sc, "query_key");
            long queryPosition = intField(sc, "query_position");
            boolean expectRevoked = boolField(sc, "expect_revoked");
            boolean revoked = false;
            long notAfter = 0L;
            for (String rv : splitObjects(arrayBlock(sc, "revocations"))) {
                String key = field(rv, "key");
                if (!key.equals(queryKey)) {
                    continue;
                }
                long na = intField(rv, "not_after");
                Identity.RevocationRecord rec = new Identity.RevocationRecord(key, na);
                if (Identity.revokedAt(rec, queryPosition)) {
                    revoked = true;
                    notAfter = na;
                }
            }
            check("revocation.revoked_at " + name, Boolean.toString(revoked), Boolean.toString(expectRevoked));
            if (expectRevoked) {
                check("revocation.revoked_at " + name + " not_after", Long.toString(notAfter),
                        Long.toString(intField(sc, "expect_not_after")));
            }
        }

        // VerifyRevocation (§5.3, §5.5) -- fail-closed membership-before-signature. The mutation
        // anchor is "recovery_key_not_configured_reject": a valid K_R signature over an EMPTY
        // authorized_recovery_ids set MUST reject SignerMismatch.
        List<String> verifyCases = splitObjects(arrayBlock(rev, "verify"));
        check("revocation.verify has >= 7 cases", Boolean.toString(verifyCases.size() >= 7), "true");
        for (String tc : verifyCases) {
            String name = field(tc, "name");
            String recordScope = objBlock(tc, "record");
            Identity.RevocationRecord r = new Identity.RevocationRecord(field(recordScope, "key"), intField(recordScope, "not_after"));
            int alg = (int) intField(tc, "candidate_alg");
            byte[] pub = hexField(tc, "candidate_pubkey_hex");
            byte[] sig = hexField(tc, "sig_hex");
            List<String> recoveryIds = stringArray(tc, "authorized_recovery_ids");
            boolean expectValid = boolField(tc, "expect_valid");
            String expectKind = field(tc, "expect_error_kind");
            String got = errKind(() -> Identity.verifyRevocation(r, alg, pub, sig, recoveryIds));
            if (expectValid) {
                check("revocation.verify " + name, got, "no-error");
            } else if (!expectKind.isEmpty()) {
                check("revocation.verify " + name, got, expectKind);
            } else {
                check("revocation.verify " + name + " rejected", Boolean.toString(!got.equals("no-error")), "true");
            }
        }
    }

    // ---- foreign link ----

    private static void runForeignLink(String json) {
        String fl = objBlock(json, "foreign_link");

        // ForeignLinkRecord.bytes() reproduces the oracle's deterministic-CBOR body, and NFC/NFD
        // forms of the SAME logical foreign_id encode to DIFFERENT bytes (the mutation anchor: a
        // normalizer that collapses NFC/NFD would flip this not-equal assertion).
        String nfcBytes = null, nfdBytes = null;
        for (String tc : splitObjects(arrayBlock(fl, "record_bytes"))) {
            String name = field(tc, "name");
            Identity.ForeignLinkRecord r = new Identity.ForeignLinkRecord(
                    field(tc, "controls"), field(tc, "foreign_id"), intField(tc, "not_after"));
            String got = Hex.encode(r.bytes());
            check("foreign_link.record_bytes " + name, got, field(tc, "bytes_hex"));
            if (name.equals("nfc_form")) {
                nfcBytes = got;
            } else if (name.equals("nfd_form_different_bytes")) {
                nfdBytes = got;
            }
        }
        if (nfcBytes != null && nfdBytes != null) {
            check("foreign_link NFC/NFD encode to different bytes", Boolean.toString(!nfcBytes.equals(nfdBytes)), "true");
        }

        // VerifyForeignLink (§5.4, §5.5): valid+unexpired, the not_after boundary, expiry (ignored,
        // no error), wrong-key (ignored, no error -- same bucket as expiry), non-NFC foreign_id
        // (NonNFC, checked before expiry/signature).
        for (String tc : splitObjects(arrayBlock(fl, "verify"))) {
            String name = field(tc, "name");
            String recordScope = objBlock(tc, "record");
            Identity.ForeignLinkRecord r = new Identity.ForeignLinkRecord(
                    field(recordScope, "controls"), field(recordScope, "foreign_id"), intField(recordScope, "not_after"));
            int alg = (int) intField(tc, "candidate_alg");
            byte[] pub = hexField(tc, "candidate_pubkey_hex");
            byte[] sig = hexField(tc, "sig_hex");
            long now = intField(tc, "now");
            String expectKind = field(tc, "expect_error_kind");
            if (!expectKind.isEmpty()) {
                check("foreign_link.verify " + name, errKind(() -> Identity.verifyForeignLink(r, alg, pub, sig, now)), expectKind);
                continue;
            }
            boolean expectLinked = boolField(tc, "expect_linked");
            boolean linked;
            try {
                linked = Identity.verifyForeignLink(r, alg, pub, sig, now);
            } catch (NaalpException e) {
                fails++;
                System.out.println("  FAIL " + name + " unexpected exception " + e.kind);
                continue;
            }
            check("foreign_link.verify " + name, Boolean.toString(linked), Boolean.toString(expectLinked));
            if (expectLinked) {
                check("foreign_link.verify " + name + " controls", r.controls, field(tc, "expect_controls"));
                check("foreign_link.verify " + name + " foreign_id", r.foreignId, field(tc, "expect_foreign_id"));
            }
        }
    }

    // ---- rotation evidence / thread / resolveThread ----

    private static List<Identity.RotationEvidence> buildEvidence(List<String> evScopes) {
        List<Identity.RotationEvidence> out = new ArrayList<>();
        for (String e : evScopes) {
            Identity.RotationRecord rec = new Identity.RotationRecord(field(e, "old"), field(e, "new"), intField(e, "not_before"));
            check("thread evidence record bytes (RotationEvidence input)", Hex.encode(rec.bytes()), field(e, "record_bytes_hex"));
            out.add(new Identity.RotationEvidence(
                    rec,
                    (int) intField(e, "old_alg"), hexField(e, "old_pubkey_hex"),
                    (int) intField(e, "new_alg"), hexField(e, "new_pubkey_hex"),
                    hexField(e, "old_sig_hex"), hexField(e, "new_sig_hex")));
        }
        return out;
    }

    private static void runThread(String json) {
        String th = objBlock(json, "thread");

        // ResolveThread: empty chain, single link, a 3-link contiguous chain, and two distinct
        // broken-chain shapes -- "broken_link_old_mismatch" pins the CONTIGUITY guard and
        // "broken_link_forged_old_signature" pins the per-link CO-SIGNATURE guard, isolating one
        // guard from the other.
        for (String tc : splitObjects(arrayBlock(th, "resolve"))) {
            String name = field(tc, "name");
            List<String> evScopes = splitObjects(arrayBlock(tc, "evidence"));
            List<Identity.RotationEvidence> evs = buildEvidence(evScopes);
            String expectError = field(tc, "expect_error");
            if (!expectError.isEmpty()) {
                check("thread.resolve " + name, errKind(() -> Identity.resolveThread(evs)), expectError);
                continue;
            }
            Identity.Thread t;
            try {
                t = Identity.resolveThread(evs);
            } catch (NaalpException e) {
                fails++;
                System.out.println("  FAIL " + name + " unexpected exception " + e.kind);
                continue;
            }
            String wantScope = objBlock(tc, "expect_thread");
            check("thread.resolve " + name + " root", t.root, field(wantScope, "root"));
            check("thread.resolve " + name + " current", t.current, field(wantScope, "current"));
            check("thread.resolve " + name + " chain", String.join(",", t.chain), String.join(",", stringArray(wantScope, "chain")));
        }

        // Thread.attributable: root/intermediate/current keys are attributable; an unrelated key is
        // not ("unrelated_key_not_attributable" is the mutation anchor -- an always-true stub flips it).
        for (String tc : splitObjects(arrayBlock(th, "attributable"))) {
            String name = field(tc, "name");
            String thScope = objBlock(tc, "thread");
            Identity.Thread t = new Identity.Thread(field(thScope, "root"), field(thScope, "current"), stringArray(thScope, "chain"));
            String query = field(tc, "query");
            boolean expect = boolField(tc, "expect");
            check("thread.attributable " + name, Boolean.toString(t.attributable(query)), Boolean.toString(expect));
        }
    }

    public static void main(String[] args) throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);
        runRevocation(json);
        runForeignLink(json);
        runThread(json);
        System.out.println(fails == 0 ? "PASS" : "FAIL (" + fails + ")");
        if (fails != 0) {
            System.exit(1);
        }
    }
}
