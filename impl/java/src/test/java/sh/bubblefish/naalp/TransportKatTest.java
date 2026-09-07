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
 * C11 transport-binding known-answer test for the Java SDK, graded against the shared independent
 * corpus vectors/transport/cases.json (NOT produced by this code): the media type, the four
 * bindings' confidentiality/peer-auth guarantees, the framing round-trip, and the §12.3/§12.4
 * emit-boundary matrix. Every property here is a PURE deterministic assertion (no crypto), so all of
 * transport is corpus-graded on the Java port.
 *
 * <p>KAT convention (a standalone {@code main} that runs checks and exits non-zero on any failure,
 * mirroring {@link WorkedExampleKat}); named "…KatTest" so the filename carries the "test" token the
 * ten-language-parity gate indexes as test evidence. Written test-first: the {@link Transport} class
 * is absent until Transport.java lands, so this fails RED with a javac "cannot find symbol Transport";
 * a mutation to the emit boundary flips the "emit websocket+ws sensitive=true peer=false" check.
 *
 * <p>Run (from the repo root; on Windows the classpath separator is ';'):
 * <pre>
 * javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d impl/java/tout \
 *     impl/java/src/main/java/sh/bubblefish/naalp/*.java impl/java/src/test/java/sh/bubblefish/naalp/*.java
 * java -cp "impl/java/tout;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" sh.bubblefish.naalp.TransportKatTest
 * </pre>
 */
public final class TransportKatTest {
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
            Path p = d.resolve("vectors").resolve("transport").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/transport/cases.json not found from " + System.getProperty("user.dir"));
    }

    /** The string value of a top-level or in-block "key": "value" pair (value may be empty). */
    private static String str(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        if (!m.find()) {
            throw new AssertionError("string key not found: " + key);
        }
        return m.group(1);
    }

    /** The boolean value of a "key": true|false pair. */
    private static boolean bool(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(true|false)").matcher(json);
        if (!m.find()) {
            throw new AssertionError("boolean key not found: " + key);
        }
        return "true".equals(m.group(1));
    }

    /**
     * The flat {@code { ... }} object blocks of the array named {@code arrayKey}. The transports and
     * emit_matrix arrays contain only flat objects (no nested braces), so a brace-balanced-free split
     * on innermost {@code {...}} within the array body is exact.
     */
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

    // ---- checks ----

    private static final byte[] OBJ = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);

        // 1. media type is the one-object-per-representation N-AALP type (§12.1).
        check("media type", Transport.MEDIA_TYPE, str(json, "media_type"));

        // 2. every transport variant's confidentiality/peer-auth guarantees == the oracle.
        for (String b : objectBlocks(json, "transports")) {
            String name = str(b, "name");
            Transport t = Transport.byName(name);
            check("variant present: " + name, t == null ? "absent" : "present", "present");
            if (t != null) {
                String got = (t.confidential ? "1" : "0") + (t.peerAuthenticated ? "1" : "0");
                String want = (bool(b, "confidential") ? "1" : "0") + (bool(b, "peer_authenticated") ? "1" : "0");
                check("variant guarantees: " + name, got, want);
            }
        }

        // 3. framing round-trips the object bytes verbatim; the media type is the N-AALP type (R-13.2).
        Transport np = Transport.byName("npamp");
        Transport.MessageUnit mu = Transport.frame(np, new byte[]{1, 2, 3});
        check("frame media type", mu.mediaType, Transport.MEDIA_TYPE);
        check("frame roundtrip object", Hex.encode(mu.object()), "010203");

        // 4. a message unit with a wrong media type is rejected Malformed (fail-closed).
        String badKind = "no-error";
        try {
            new Transport.MessageUnit("npamp", "application/json", new byte[]{9}).object();
        } catch (NaalpException e) {
            badKind = e.kind;
        }
        check("wrong media type rejected", badKind, "Malformed");

        // 5. the §12.3 confidentiality / §12.4 peer-auth emit-boundary matrix == the oracle, row by row.
        for (String c : objectBlocks(json, "emit_matrix")) {
            String tn = str(c, "transport");
            boolean sensitive = bool(c, "sensitive");
            boolean requirePeerAuth = bool(c, "require_peer_auth");
            String want = str(c, "result");
            Transport t = Transport.byName(tn);
            String result;
            if (t == null) {
                result = "unknown-transport";
            } else {
                try {
                    Transport.MessageUnit emitted = Transport.emit(t, OBJ, sensitive, requirePeerAuth);
                    result = java.util.Arrays.equals(emitted.object(), OBJ) ? "ok" : "framed-wrong-bytes";
                } catch (NaalpException e) {
                    result = e.kind;
                }
            }
            check("emit " + tn + " sensitive=" + (sensitive ? "1" : "0") + " peer=" + (requirePeerAuth ? "1" : "0"),
                    result, want);
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("transport conformance (Java) — graded vs vectors/transport/cases.json");
        run();
        System.out.println(fails == 0 ? "TransportKatTest: PASS" : "TransportKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
