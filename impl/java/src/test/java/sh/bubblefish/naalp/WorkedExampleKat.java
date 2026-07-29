// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The full-object known-answer test: the reference worked object (fixed seed 0x2a*32, ML-DSA-65,
 * a Governance Approval object) MUST be reproduced byte-for-byte, and the resulting object MUST
 * verify and reject tampering. The self-contained anchors below (signer id, content id) are
 * checked always; when the committed vector (vectors/worked/example.json) is found, the exact
 * {@code signed_object_hex} is compared byte-for-byte.
 *
 * <p>Run (from the repo root, on Windows the classpath separator is ';'):
 * <pre>
 * javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d impl/java/tout \
 *     impl/java/src/main/java/sh/bubblefish/naalp/*.java impl/java/src/test/java/sh/bubblefish/naalp/*.java
 * java -cp "impl/java/tout;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" sh.bubblefish.naalp.WorkedExampleKat
 * </pre>
 */
public final class WorkedExampleKat {
    private static final byte[] SEED = seed(0x2a);
    private static final int ALG = Cose.ALG_MLDSA65;
    private static final String SIGNER_ID = "bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua";
    private static final String CONTENT_ID_HEX =
            "2030192922f9be80623bea1c689ddfe91dc15303abc851c8811b86cf9e53b837b5cc99d9c17e3acf95279f55e48203f79134";
    private static final String ARGS_ID_HEX =
            "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff";

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    private static Envelope.Object workedObject() {
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", SEED);
        String signerId = Identity.signerId(ALG, pk);
        Cbor.M body = new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(Hex.decode(ARGS_ID_HEX))),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T(signerId)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(2)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(new byte[]{1, 2, 3, 4, 5, 6, 7, 8})),
                new Cbor.Pair(new Cbor.U(5), new Cbor.U(1785000000000L))));
        return new Envelope.Object(
                1, 4, 0, signerId.getBytes(StandardCharsets.UTF_8),
                1785000000000L, 2, Cose.PROFILE_PUBLIC, body, null, null, null);
    }

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("worked").resolve("example.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        return null;
    }

    private static String field(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([0-9a-f]+)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    // ---- checks ----

    private static void testSignerAndContentId() {
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", SEED);
        String signerId = Identity.signerId(ALG, pk);
        eq("signer_id", SIGNER_ID, signerId);
        eq("content_id", CONTENT_ID_HEX, Hex.encode(workedObject().contentId()));
    }

    private static void testSignVerifyRoundtrip() {
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", SEED);
        byte[] signed = Envelope.sign(workedObject(), ALG, SEED);
        Envelope.Object got = Envelope.verify(
                Cose.PROFILE_PUBLIC, ALG, pk, (c, k) -> c == 4 && k == 1, signed, null);
        if (!(got.kind == 1 && got.channel == 4 && got.effect == 2)) {
            throw new AssertionError("roundtrip: unexpected decoded object");
        }
    }

    private static void testTamperRejected() {
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", SEED);
        byte[] signed = Envelope.sign(workedObject(), ALG, SEED).clone();
        signed[signed.length - 1] ^= 1;
        try {
            Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, (c, k) -> true, signed, null);
            throw new AssertionError("tamper: expected BadSignature, verify succeeded");
        } catch (NaalpException e) {
            eq("tamper.kind", "BadSignature", e.kind);
        }
    }

    private static void testByteExactVsCommittedVector() throws IOException {
        Path p = findVector();
        if (p == null) {
            System.out.println("  SKIP byte-exact vector compare (vectors/worked/example.json not found)");
            return;
        }
        String json = Files.readString(p, StandardCharsets.UTF_8);
        String wantSigned = field(json, "signed_object_hex");
        String wantContentId = field(json, "content_id_hex");
        byte[] signed = Envelope.sign(workedObject(), ALG, SEED);
        eq("vector.content_id_hex", wantContentId, Hex.encode(workedObject().contentId()));
        eq("vector.signed_object_hex", wantSigned, Hex.encode(signed));
    }

    private static void eq(String what, String want, String got) {
        if (!want.equals(got)) {
            throw new AssertionError(what + " mismatch\n  want=" + want + "\n  got =" + got);
        }
    }

    public static void main(String[] args) throws Exception {
        testSignerAndContentId();
        System.out.println("  ok  signer id + content id");
        testSignVerifyRoundtrip();
        System.out.println("  ok  sign -> verify roundtrip");
        testTamperRejected();
        System.out.println("  ok  tamper -> BadSignature");
        testByteExactVsCommittedVector();
        System.out.println("  ok  byte-exact vs committed worked vector");
        System.out.println("WorkedExampleKat: PASS");
    }
}
