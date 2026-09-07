// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Manufacturing Add-ons Component F (naalp-hazard) known-answer test for the Java SDK (design.md
 * addendum; requirements F1-F5), graded against the independent, non-circular oracle
 * {@code vectors/hazard/cases.json}
 * ({@code tools/hazard_oracle.py}) — mirroring {@code impl/rust/naalp-hazard/src/lib.rs}'s test
 * module and {@code impl/csharp/test/HazardKatTest.cs}, i.e. Java == Rust == C# == oracle.
 *
 * <p>CORPUS-GRADED: {@code from_code} (F2 fail-closed class decode), {@code bodies} (the claim/
 * authorization CBOR body + content id, and round-trip decode), and {@code coverage} (F3 grant
 * containment authorization verdicts). NON-ORACLE, direct: the absent-claim distinct-error
 * behavior, structural malformation, and the two containment truth tables — mirroring the
 * Rust/C# non-oracle assertions verbatim.
 *
 * <p>Run: {@code cd impl/java && javac -cp ../../harness/adapters/java/lib/bcprov-jdk18on-1.85.jar
 * -d build/hazard src/main/java/sh/bubblefish/naalp/*.java
 * src/test/java/sh/bubblefish/naalp/HazardKatTest.java && java -cp
 * "build/hazard;../../harness/adapters/java/lib/bcprov-jdk18on-1.85.jar"
 * sh.bubblefish.naalp.HazardKatTest}
 */
public final class HazardKatTest {
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
            Path p = d.resolve("vectors").resolve("hazard").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/hazard/cases.json not found from " + System.getProperty("user.dir"));
    }

    // ---- minimal hand-rolled JSON navigation (same convention as the sibling KAT tests) --------

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

    /** Decode the standard JSON string escapes (including {@code \\uXXXX}, needed by the
     * {@code unicode_frame} row's non-ASCII {@code frame} value) — a plain regex substring capture
     * would leave the literal 6-character escape sequence in place and silently diverge from the
     * oracle's real Unicode text, breaking both the NFC check and the byte-exact body comparison. */
    private static String jsonUnescape(String raw) {
        StringBuilder out = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\' && i + 1 < raw.length()) {
                char n = raw.charAt(++i);
                switch (n) {
                    case '"': out.append('"'); break;
                    case '\\': out.append('\\'); break;
                    case '/': out.append('/'); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    case 'u':
                        out.append((char) Integer.parseInt(raw.substring(i + 1, i + 5), 16));
                        i += 4;
                        break;
                    default: out.append(n);
                }
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static String field(String scope, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"")
                .matcher(scope);
        if (!m.find()) {
            throw new AssertionError("string key not found: " + key);
        }
        return jsonUnescape(m.group(1));
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

    /** A {@code code}/{@code claim_class_code}/{@code grant_class_code} cell: {@code null}, a plain
     * JSON number, or (for the {@code > 2^63-1} case) a decimal string — never through a float64
     * decoder anywhere, so the exact 64-bit code survives, matching the C# {@code GetNullableULong}
     * / Rust {@code as_u64} handling of the same corpus field. */
    private static Long nullableCode(String scope, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(null|\\d+|\"\\d+\")").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("code key not found: " + key);
        }
        String v = m.group(1);
        if (v.equals("null")) {
            return null;
        }
        if (v.startsWith("\"")) {
            v = v.substring(1, v.length() - 1);
        }
        return Long.parseUnsignedLong(v);
    }

    private static List<Hazard.Axis> axesFrom(String scope, String key) {
        String block = arrayBlock(scope, key);
        List<Hazard.Axis> out = new ArrayList<>();
        Matcher m = Pattern.compile("\\[\\s*(-?\\d+)\\s*,\\s*(-?\\d+)\\s*]").matcher(block);
        while (m.find()) {
            out.add(new Hazard.Axis(Long.parseLong(m.group(1)), Long.parseLong(m.group(2))));
        }
        return out;
    }

    private static Hazard.HazardEnvelope envFrom(String o) {
        return new Hazard.HazardEnvelope(
                new Hazard.SpatialBounds(field(o, "frame"), axesFrom(o, "axes")),
                intField(o, "speed_bound_mm_s"),
                new Hazard.HazardWindow(intField(o, "not_before"), intField(o, "not_after")));
    }

    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static void run() throws Exception {
        String json = Files.readString(findVector(), java.nio.charset.StandardCharsets.UTF_8);

        // ---- F2: fail-closed class decode (mutation anchor: a constant HazardClass.NONE return
        // would pass none of the non-zero cases; a constant MOTION_IN_SHARED_SPACE would fail the
        // exact 0..3 cases). ------------------------------------------------------------------
        for (String row : splitObjects(arrayBlock(json, "from_code"))) {
            Long input = nullableCode(row, "code");
            long want = intField(row, "class");
            check("from_code(" + input + ")", Long.toString(Hazard.fromCode(input).code), Long.toString(want));
        }
        // Explicit oracle-independent assertions of the two named fail-closed cases (F2).
        check("from_code(null) -> highest class",
                Hazard.fromCode(null).name(), "MOTION_IN_SHARED_SPACE");
        check("from_code(9) -> highest class",
                Hazard.fromCode(9L).name(), "MOTION_IN_SHARED_SPACE");
        check("from_code(u64::MAX) -> highest class, no throw/wrap",
                Hazard.fromCode(-1L).name(), "MOTION_IN_SHARED_SPACE"); // -1L == 0xFFFF...FFFF unsigned
        // The five in-range codes decode to themselves, never collapsing to the default.
        for (long code = 0; code <= 4; code++) {
            check("from_code(" + code + ") round-trips its own code",
                    Long.toString(Hazard.fromCode(code).code), Long.toString(code));
        }

        // ---- byte-level: encode matches the independent oracle (=> Java == Rust == C# once
        // graded). ---------------------------------------------------------------------------
        for (String row : splitObjects(arrayBlock(json, "bodies"))) {
            String name = field(row, "name");
            Hazard.HazardClass cls = Hazard.fromCode(intField(row, "class"));
            Hazard.HazardEnvelope e = envFrom(row);
            Hazard.HazardClaim claim = new Hazard.HazardClaim(cls, e);
            Hazard.HazardAuthorization auth = new Hazard.HazardAuthorization(cls, e);
            String want = field(row, "body_hex");
            check("claim " + name + " body == oracle", Hex.encode(claim.bytes()), want);
            check("authorization " + name + " body == oracle (same shape as claim)", Hex.encode(auth.bytes()), want);
            check("claim " + name + " content id == oracle", Hex.encode(claim.contentId()), field(row, "content_id_hex"));

            // Round-trip: fromValue(decode(bytes())) reproduces the same body bytes.
            Hazard.HazardClaim got = Hazard.HazardClaim.fromValue(Cbor.decode(claim.bytes()));
            check("claim " + name + " round-trips through fromValue", Hex.encode(got.bytes()), want);
        }

        // ---- F3: coverage matrix (mutation anchor: a constant "always authorized" fails the deny
        // rows; a constant "always denied" fails the allow rows). -------------------------------
        List<String> coverageRows = splitObjects(arrayBlock(json, "coverage"));
        int allows = 0;
        int denies = 0;
        for (String row : coverageRows) {
            String name = field(row, "name");
            Hazard.HazardClaim claim = new Hazard.HazardClaim(
                    Hazard.fromCode(nullableCode(row, "claim_class_code")),
                    envFrom(objBlock(row, "claim_envelope")));
            Hazard.HazardAuthorization grant = new Hazard.HazardAuthorization(
                    Hazard.fromCode(nullableCode(row, "grant_class_code")),
                    envFrom(objBlock(row, "grant_envelope")));
            boolean wantOk = boolField(row, "authorized");
            if (wantOk) {
                allows++;
                check("coverage " + name + " -> authorized", errKind(() -> Hazard.hazardAuthorized(claim, grant)), "no-error");
            } else {
                denies++;
                check("coverage " + name + " -> HazardNotCovered", errKind(() -> Hazard.hazardAuthorized(claim, grant)), "HazardNotCovered");
            }
        }
        check("coverage matrix has both allows and denies", Boolean.toString(allows > 0 && denies > 0), "true");

        // ---- F2/F4's "absent hazard" behavioural vector, at the OBJECT level (no claim at all):
        // distinct from an in-range-but-mismatched class, and distinct from an unrecognized class
        // byte inside a present claim (covered by the coverage matrix's normalized rows). --------
        Hazard.HazardAuthorization absGrant = new Hazard.HazardAuthorization(
                Hazard.HazardClass.TOOL_ACTUATION,
                new Hazard.HazardEnvelope(
                        new Hazard.SpatialBounds("cell-7/world", List.of(
                                new Hazard.Axis(0, 1000), new Hazard.Axis(0, 1000), new Hazard.Axis(0, 500))),
                        500, new Hazard.HazardWindow(0, 1000)));
        check("absent claim denied HazardUnknown",
                errKind(() -> Hazard.hazardAuthorizedOptional(null, absGrant)), "HazardUnknown");
        Hazard.HazardClaim absClaim = new Hazard.HazardClaim(
                Hazard.HazardClass.TOOL_ACTUATION,
                new Hazard.HazardEnvelope(
                        new Hazard.SpatialBounds("cell-7/world", List.of(
                                new Hazard.Axis(100, 200), new Hazard.Axis(100, 200), new Hazard.Axis(0, 100))),
                        100, new Hazard.HazardWindow(10, 900)));
        check("a present, well-covered claim still authorizes through the same entry point",
                errKind(() -> Hazard.hazardAuthorizedOptional(absClaim, absGrant)), "no-error");

        // ---- structural malformation (fail-closed, never partially valid) ---------------------
        Hazard.SpatialBounds emptyAxes = new Hazard.SpatialBounds("f", List.of());
        check("empty axes is not well-formed", Boolean.toString(emptyAxes.isWellFormed()), "false");
        check("empty axes rejected on decode HazardMalformed",
                errKind(() -> Hazard.SpatialBounds.fromValue(emptyAxes.toValue())), "HazardMalformed");

        Hazard.SpatialBounds minGtMax = new Hazard.SpatialBounds("f", List.of(new Hazard.Axis(10, -10)));
        check("min > max is not well-formed", Boolean.toString(minGtMax.isWellFormed()), "false");

        Hazard.SpatialBounds nonNfc = new Hazard.SpatialBounds("e\u0301", List.of(new Hazard.Axis(0, 1))); // NFD, not NFC
        check("non-NFC frame is not well-formed", Boolean.toString(nonNfc.isWellFormed()), "false");

        check("wrong shape entirely (not a map) rejected HazardMalformed",
                errKind(() -> Hazard.HazardClaim.fromValue(new Cbor.U(0))), "HazardMalformed");

        Cbor.M partial = new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(1), new Cbor.U(1))));
        check("class present, envelope missing rejected HazardMalformed",
                errKind(() -> Hazard.HazardClaim.fromValue(partial)), "HazardMalformed");

        // an explicit out-of-range class ON THE WIRE (not "absent") is malformed, not silently
        // normalized -- see Hazard.hazardBodyFromValue's doc comment.
        Hazard.HazardEnvelope goodEnv = new Hazard.HazardEnvelope(
                new Hazard.SpatialBounds("f", List.of(new Hazard.Axis(0, 1))), 1, new Hazard.HazardWindow(0, 1));
        Cbor.M outOfRange = new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(99)),
                new Cbor.Pair(new Cbor.U(2), goodEnv.toValue())));
        check("out-of-range class on the wire rejected HazardMalformed",
                errKind(() -> Hazard.HazardClaim.fromValue(outOfRange)), "HazardMalformed");

        // ---- containment truth table (independent of the oracle file, direct assertions) ------
        Hazard.SpatialBounds grantSb = new Hazard.SpatialBounds("f", List.of(new Hazard.Axis(0, 100), new Hazard.Axis(0, 100)));
        Hazard.SpatialBounds inside = new Hazard.SpatialBounds("f", List.of(new Hazard.Axis(10, 90), new Hazard.Axis(10, 90)));
        check("fully inside -> contained", Boolean.toString(Hazard.spatialContained(inside, grantSb)), "true");
        Hazard.SpatialBounds equal = new Hazard.SpatialBounds("f", List.of(new Hazard.Axis(0, 100), new Hazard.Axis(0, 100)));
        check("equal bounds -> contained (closed interval)", Boolean.toString(Hazard.spatialContained(equal, grantSb)), "true");
        Hazard.SpatialBounds outside = new Hazard.SpatialBounds("f", List.of(new Hazard.Axis(10, 90), new Hazard.Axis(10, 101)));
        check("one axis pokes outside -> not contained", Boolean.toString(Hazard.spatialContained(outside, grantSb)), "false");
        Hazard.SpatialBounds wrongFrame = new Hazard.SpatialBounds("g", List.of(new Hazard.Axis(10, 90), new Hazard.Axis(10, 90)));
        check("different frame -> never contained regardless of numeric bounds",
                Boolean.toString(Hazard.spatialContained(wrongFrame, grantSb)), "false");
        Hazard.SpatialBounds fewer = new Hazard.SpatialBounds("f", List.of(new Hazard.Axis(10, 90)));
        check("fewer axes -> never contained", Boolean.toString(Hazard.spatialContained(fewer, grantSb)), "false");

        Hazard.HazardEnvelope envGrant = mkEnv(0, 100, 500, 100, 900);
        Hazard.HazardEnvelope envOk = mkEnv(0, 100, 500, 100, 900); // exact edges, closed interval
        check("exact edges -> contained", Boolean.toString(Hazard.envelopeContained(envOk, envGrant)), "true");
        Hazard.HazardEnvelope speedOver = mkEnv(0, 100, 501, 100, 900);
        check("speed over bound -> not contained", Boolean.toString(Hazard.envelopeContained(speedOver, envGrant)), "false");
        Hazard.HazardEnvelope startsEarly = mkEnv(0, 100, 500, 99, 900);
        check("window starts before grant -> not contained", Boolean.toString(Hazard.envelopeContained(startsEarly, envGrant)), "false");
        Hazard.HazardEnvelope endsLate = mkEnv(0, 100, 500, 100, 901);
        check("window ends after grant -> not contained", Boolean.toString(Hazard.envelopeContained(endsLate, envGrant)), "false");
    }

    private static String objBlock(String scope, String key) {
        int open = scope.indexOf('{', afterKey(scope, key));
        int close = matchClose(scope, open);
        return scope.substring(open + 1, close - 1);
    }

    private static Hazard.HazardEnvelope mkEnv(long lo, long hi, long speed, long nb, long na) {
        return new Hazard.HazardEnvelope(
                new Hazard.SpatialBounds("f", List.of(new Hazard.Axis(lo, hi))), speed, new Hazard.HazardWindow(nb, na));
    }

    public static void main(String[] args) throws Exception {
        System.out.println("hazard conformance (Java) — graded vs vectors/hazard/cases.json");
        run();
        System.out.println(fails == 0 ? "HazardKatTest: PASS" : "HazardKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
