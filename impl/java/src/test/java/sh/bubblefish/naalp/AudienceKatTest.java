// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The object-audience (field 13, §2.5.3) known-answer + gate test for the Java SDK, in the same
 * plain-{@code main()} KAT style as {@link WorkedExampleKatTest} (runs via javac + java, no JUnit).
 *
 * <p>Three properties, all mutation-surviving:
 * <ol>
 *   <li>BYTE MATCH -- an audience-bearing object's content id (over the body WITH the audience)
 *       reproduces the independent oracle's {@code object_with_audience.content_id_hex}, and a
 *       NO-audience object reproduces the base {@code object.content_id_hex} -- proving
 *       omit-when-empty additivity byte-for-byte (Java == Go == Rust == ... == the oracle).
 *       {@code contentId()} runs the impl's own bodyMap-with-audience.</li>
 *   <li>checkAudience -- the three-branch point-of-use gate.</li>
 *   <li>consumeObject -- enforced at the consume choke point BEFORE the compare-and-set:
 *       wrong/absent -> WrongAudience with no append; unnamed ledger -> LedgerUnsigned;
 *       correct -> consumes once (second -> AlreadyConsumed).</li>
 * </ol>
 *
 * <p>Run (from the repo root, on Windows the classpath separator is ';'):
 * <pre>
 * javac -cp "&lt;bcprov-jdk18on.jar&gt;" -d tout impl/java/src/main/java/sh/bubblefish/naalp/*.java \
 *     impl/java/src/test/java/sh/bubblefish/naalp/AudienceKatTest.java
 * java -cp "tout;&lt;bcprov-jdk18on.jar&gt;" sh.bubblefish.naalp.AudienceKatTest
 * </pre>
 */
public final class AudienceKatTest {
    private static final byte[] SIGNER = Hex.decode("5349474e45525f41"); // "SIGNER_A"
    private static final String AUDIENCE = "consuming-authority-xyz";

    private static Envelope.Object audienceObject() {
        Envelope.Object o = new Envelope.Object(
                2, 4, 0, SIGNER, 1785000000000L, 2, 1, new Cbor.T("hello"), null, null, null);
        o.audience = AUDIENCE;
        return o;
    }

    private static Envelope.Object plainObject() {
        return new Envelope.Object(
                2, 4, 0, SIGNER, 1785000000000L, 2, 1, new Cbor.T("hello"), null, null, null);
    }

    private static Envelope.Object gateObject(String aud) {
        Envelope.Object o = new Envelope.Object(
                2, 4, 0, SIGNER, 0, 0, 1, new Cbor.T("x"), null, null, null);
        o.audience = aud;
        return o;
    }

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("envelope").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        return null;
    }

    /** content_id_hex for the base object (audience=false) or the object_with_audience block (true). */
    private static String contentIdIn(String json, boolean audience) {
        int split = json.indexOf("object_with_audience");
        String region = audience ? json.substring(split) : json.substring(0, split);
        Matcher m = Pattern.compile("\"content_id_hex\"\\s*:\\s*\"([0-9a-f]+)\"").matcher(region);
        return m.find() ? m.group(1) : null;
    }

    private static void eq(String what, String want, String got) {
        if (!want.equals(got)) {
            throw new AssertionError(what + " mismatch\n  want=" + want + "\n  got =" + got);
        }
    }

    private static void expectWrongAudience(String what, Runnable fn) {
        expectKind(what, fn, "WrongAudience");
    }

    private static void expectKind(String what, Runnable fn, String wantKind) {
        try {
            fn.run();
            throw new AssertionError(what + ": expected " + wantKind + ", no exception thrown");
        } catch (NaalpException e) {
            eq(what + ".kind", wantKind, e.kind);
        }
    }

    private static byte[] aid() {
        byte[] a = new byte[50];
        for (int i = 0; i < 50; i++) {
            a[i] = (byte) i;
        }
        return a;
    }

    private static void testByteMatch() throws IOException {
        Path p = findVector();
        if (p == null) {
            System.out.println("  SKIP byte-match (vectors/envelope/cases.json not found)");
            return;
        }
        String json = Files.readString(p, StandardCharsets.UTF_8);
        eq("audience content_id", contentIdIn(json, true), Hex.encode(audienceObject().contentId()));
        eq("plain content_id (additive)", contentIdIn(json, false), Hex.encode(plainObject().contentId()));
        if (Hex.encode(audienceObject().contentId()).equals(Hex.encode(plainObject().contentId()))) {
            throw new AssertionError("audience and no-audience content ids must differ");
        }
    }

    private static void testCheckAudience() {
        Envelope.checkAudience(gateObject("authority-A"), "authority-A", true);   // pass
        Envelope.checkAudience(gateObject(""), "authority-A", false);             // pass
        Envelope.checkAudience(gateObject("authority-A"), "authority-A", false);  // pass
        expectWrongAudience("consume-once foreign", () -> Envelope.checkAudience(gateObject("authority-B"), "authority-A", true));
        expectWrongAudience("consume-once absent", () -> Envelope.checkAudience(gateObject(""), "authority-A", true));
        expectWrongAudience("foreign unrestricted", () -> Envelope.checkAudience(gateObject("authority-B"), "authority-A", false));
    }

    private static void testConsumeObject() throws IOException {
        // wrong audience -> WrongAudience, no append
        Path p1 = Files.createTempFile("naalp-audience-", ".wal");
        Approval.Ledger led1 = Approval.Ledger.open(p1, "authority-A");
        expectWrongAudience("consumeObject wrong", () -> led1.consumeObject(gateObject("authority-B"), aid(), "consumer"));
        if (led1.len() != 0) {
            throw new AssertionError("wrong audience must not append (len=" + led1.len() + ")");
        }
        led1.close();
        Files.deleteIfExists(p1);

        // absent audience -> WrongAudience, no append
        Path p2 = Files.createTempFile("naalp-audience-", ".wal");
        Approval.Ledger led2 = Approval.Ledger.open(p2, "authority-A");
        expectWrongAudience("consumeObject absent", () -> led2.consumeObject(gateObject(""), aid(), "consumer"));
        if (led2.len() != 0) {
            throw new AssertionError("absent audience must not append (len=" + led2.len() + ")");
        }
        led2.close();
        Files.deleteIfExists(p2);

        // correct audience -> consumes once; second -> AlreadyConsumed
        Path p3 = Files.createTempFile("naalp-audience-", ".wal");
        Approval.Ledger led3 = Approval.Ledger.open(p3, "authority-A");
        led3.consumeObject(gateObject("authority-A"), aid(), "consumer");
        if (led3.len() != 1) {
            throw new AssertionError("correct audience must consume once (len=" + led3.len() + ")");
        }
        expectKind("consumeObject second", () -> led3.consumeObject(gateObject("authority-A"), aid(), "consumer"), "AlreadyConsumed");
        led3.close();
        Files.deleteIfExists(p3);

        // unnamed ledger -> LedgerUnsigned
        Path p4 = Files.createTempFile("naalp-audience-", ".wal");
        Approval.Ledger led4 = Approval.Ledger.open(p4, "");
        expectKind("consumeObject unnamed", () -> led4.consumeObject(gateObject("authority-A"), aid(), "consumer"), "LedgerUnsigned");
        led4.close();
        Files.deleteIfExists(p4);
    }

    public static void main(String[] args) throws Exception {
        testByteMatch();
        System.out.println("  ok  byte-match vs oracle (audience + additive plain content ids)");
        testCheckAudience();
        System.out.println("  ok  checkAudience three branches (6 cases)");
        testConsumeObject();
        System.out.println("  ok  consumeObject choke point (wrong/absent/correct/unnamed)");
        System.out.println("AudienceKatTest: PASS");
    }
}
