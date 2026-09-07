// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * C5 §6 authorization conformance for the Java SDK, graded against the shared independent corpus
 * vectors/effect/cases.json (NOT produced by this code): the granted×effect authorization matrix
 * (R-6.3), the signature-only authorization-principal rule (R-6.5), and the strict optional
 * safety-label extraction (R-6.4). Fail-closed throughout.
 *
 * <p>KAT convention (a standalone {@code main} exiting non-zero on any failure); named "…KatTest" so
 * the filename carries the "test" token the ten-language-parity gate indexes. The recorded mutation
 * forces {@link Policy.Grant#authorizeObject} to skip the ceiling check, which flips the denied
 * authorization-matrix rows on their EffectNotAuthorized assertion.
 */
public final class PolicyKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

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

    // ---- nesting-aware JSON access (Java has no JSON library) ------------------------------

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("effect").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/effect/cases.json not found from " + System.getProperty("user.dir"));
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

    // Locate the object block for a key whose value is an object ("key": { ... }). Unlike objBlock,
    // this anchors on the '{' immediately after the colon, so it skips a same-named STRING field
    // elsewhere (e.g. bridge_mapping's "safety_label": "..." vs the top-level "safety_label": {...}).
    private static String objBlockStrict(String s, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\\{").matcher(s);
        if (!m.find()) {
            throw new AssertionError("object key not found: " + key);
        }
        int open = m.end() - 1; // the '{'
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
    }

    private static String arrayBlock(String s, String key) {
        int open = s.indexOf('[', afterKey(s, key));
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
    }

    private static List<String> splitObjects(String arrayInner) {
        List<String> out = new java.util.ArrayList<>();
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
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(-?\\d+)").matcher(scope);
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

    private static Policy.PrincipalSource srcOf(String s) {
        switch (s) {
            case "signature": return Policy.PrincipalSource.SIGNATURE;
            case "transport_metadata": return Policy.PrincipalSource.TRANSPORT_METADATA;
            case "foreign_header": return Policy.PrincipalSource.FOREIGN_HEADER;
            case "client_name": return Policy.PrincipalSource.CLIENT_NAME;
            default: throw new AssertionError("unknown source " + s);
        }
    }

    public static void main(String[] args) throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);

        // 1. R-6.3 — the granted x effect authorization matrix: a matched signature principal is
        //    authorized iff the object effect is within the grant's ceiling, else EffectNotAuthorized.
        List<String> matrix = splitObjects(arrayBlock(json, "authorization_matrix"));
        check("matrix has 16 cells", Integer.toString(matrix.size()), "16");
        int allows = 0, denies = 0;
        for (String r : matrix) {
            long granted = intField(r, "granted");
            long effect = intField(r, "effect");
            boolean allow = boolField(r, "allow");
            Policy.Grant g = new Policy.Grant("pA", granted);
            if (allow) {
                allows++;
                check("granted=" + granted + " effect=" + effect + " allowed",
                        errKind(() -> g.authorizeObject(Policy.PrincipalSource.SIGNATURE, "pA", effect)), "no-error");
            } else {
                denies++;
                check("granted=" + granted + " effect=" + effect + " denied (EffectNotAuthorized)",
                        errKind(() -> g.authorizeObject(Policy.PrincipalSource.SIGNATURE, "pA", effect)), "EffectNotAuthorized");
            }
            check("lattice authorizes(granted=" + granted + ", norm(effect=" + effect + "))",
                    Policy.authorizes(granted, Policy.normalizeEffect(effect)) ? "yes" : "no", allow ? "yes" : "no");
        }
        check("matrix exercises both allow and deny", (allows > 0 && denies > 0) ? "yes" : "no", "yes");

        // 2. R-6.5 — only a signature-derived identity is an authorization principal; a
        //    transport/foreign/client source is refused UnauthenticatedPrincipal (even for read_only).
        Policy.Grant g = new Policy.Grant("pA", Policy.DESTRUCTIVE); // maximally permissive
        for (String ps : splitObjects(arrayBlock(json, "principal_sources"))) {
            Policy.PrincipalSource src = srcOf(field(ps, "source"));
            boolean accepted = boolField(ps, "accepted");
            String src2 = field(ps, "source");
            if (accepted) {
                check("source " + src2 + " accepted", errKind(() -> Policy.resolveAuthPrincipal(src, "pA")), "no-error");
                check("source " + src2 + " authorizes read_only",
                        errKind(() -> g.authorizeObject(src, "pA", Policy.READ_ONLY)), "no-error");
            } else {
                check("source " + src2 + " refused (UnauthenticatedPrincipal)",
                        errKind(() -> Policy.resolveAuthPrincipal(src, "pA")), "UnauthenticatedPrincipal");
                check("source " + src2 + " denies read_only (UnauthenticatedPrincipal)",
                        errKind(() -> g.authorizeObject(src, "pA", Policy.READ_ONLY)), "UnauthenticatedPrincipal");
            }
        }

        // 3. R-6.4 — safetyLabelFromExt extracts a well-formed {1:tstr,2:tstr} label (matching the
        //    independently-hex-pinned oracle bytes), reports absence, and rejects malformed/incomplete.
        String sl = objBlockStrict(json, "safety_label");
        String risk = field(sl, "risk");
        String scope = field(sl, "scope");
        long extKey = intField(sl, "ext_key");
        String cborHex = field(sl, "cbor_hex");

        Cbor.M ext = new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(extKey),
                new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(1), new Cbor.T(risk)),
                        new Cbor.Pair(new Cbor.U(2), new Cbor.T(scope)))))));
        Policy.LabelResult lr = Policy.safetyLabelFromExt(ext);
        check("safety label present", lr.present ? "yes" : "no", "yes");
        check("safety label risk == oracle", lr.label.risk, risk);
        check("safety label scope == oracle", lr.label.scope, scope);
        check("safety label body == oracle hex", Hex.encode(Policy.safetyLabelBytes(risk, scope)), cborHex);

        Policy.LabelResult absent = Policy.safetyLabelFromExt(new Cbor.M(List.of()));
        check("absent ext -> not present", (absent.label == null && !absent.present) ? "yes" : "no", "yes");

        Cbor.M badNonMap = new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(extKey), new Cbor.U(9))));
        check("malformed (non-map) rejected (MalformedSafetyLabel)",
                errKind(() -> Policy.safetyLabelFromExt(badNonMap)), "MalformedSafetyLabel");

        Cbor.M badIncomplete = new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(extKey),
                new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(1), new Cbor.T("x")))))));
        check("incomplete (missing scope) rejected (MalformedSafetyLabel)",
                errKind(() -> Policy.safetyLabelFromExt(badIncomplete)), "MalformedSafetyLabel");

        System.out.println(fails == 0 ? "PASS" : "FAIL (" + fails + ")");
        if (fails != 0) {
            System.exit(1);
        }
    }
}
