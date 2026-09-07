// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.security.MessageDigest;
import java.util.List;

/**
 * §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) known-answer + fail-closed tests
 * for the Java SDK.
 *
 * <p>Mutation-surviving properties: (1) BYTE PARITY -- {@link Envelope#signRotationObject} over the
 * fixed worked fixture reproduces the Go/Rust/oracle bytes: the SHA-256 of the 6798-byte tag-98
 * object is pinned and equals the Go rotation.sign reference (Java == Go == Rust == Python ==
 * oracle on the whole two-leg object). (2) Round-trip -- {@link Envelope#verifyRotationObject}
 * accepts a co-signed rotation (both legs, old then new). (3) Fail-closed reject family -- a tag-18
 * single-signature rotation, a dropped old leg, a wrong-key old leg, a tag-98 object on a
 * non-rotation (channel,kind), and a Sovereign verifier over a rotation whose OLD key is below the
 * profile floor are ALL rejected with the named kind.
 *
 * <p>Run (main()-driven, no test framework, mirrors WorkedExampleKat): compile the SDK sources plus
 * this file into a jar, then
 * <pre>
 * javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d impl/java/tout \
 *     impl/java/src/main/java/sh/bubblefish/naalp/*.java impl/java/src/test/java/sh/bubblefish/naalp/RotationKatTest.java
 * java -cp "impl/java/tout;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" sh.bubblefish.naalp.RotationKatTest
 * </pre>
 */
public final class RotationKatTest {
    private static final byte[] OLD_SEED = seed((byte) 0x0B);        // old ML-DSA-65 key
    private static final byte[] NEW_SEED = seed((byte) 0x16);        // new ML-DSA-65 key (go-forward)
    private static final byte[] FLOOR_OLD_SEED = seed((byte) 0x21);  // below-floor old ML-DSA-65 key (33)
    private static final byte[] FLOOR_NEW_SEED = seed((byte) 0x2C);  // go-forward ML-DSA-87 key (44)
    // SHA-256 of the 6798-byte tag-98 rotation object for the fixed worked fixture; byte-identical to
    // the Go rotation.sign reference and tools/rotation_oracle.py (a cross-language, non-circular
    // anchor, not a Java-only self-check).
    private static final String OBJECT_SHA256 =
            "298d5d5bac8a0bf556541784f3090ac7300897858e883dc3ab6e7625bc418194";

    private static final byte[] SIGNER = "SIGNER_NEW".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final long NOT_BEFORE = 1785000000000L;

    private static byte[] seed(byte b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, b);
        return s;
    }

    private static Cbor.M rotationRecord() {
        // field-10 naalp-rotation body {1: old_id, 2: new_id, 3: not_before}
        return new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.T("signer-old")),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T("signer-new")),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(NOT_BEFORE))));
    }

    private static Envelope.Object workedObject(long profile) {
        return new Envelope.Object(0, 3, 0, SIGNER, NOT_BEFORE, 2, profile, rotationRecord(), null, null, null);
    }

    private static Envelope.Object workedObject() {
        return workedObject(Cose.PROFILE_PUBLIC);
    }

    private static boolean kindOk(long ch, long k) {
        return ch == 3 && k == 0;
    }

    private static String sha256Hex(byte[] b) {
        try {
            return Hex.encode(MessageDigest.getInstance("SHA-256").digest(b));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    // ---- checks ----

    private static void testObjectByteParityWithReference() {
        byte[] obj = Envelope.signRotationObject(workedObject(), Cose.ALG_MLDSA65, OLD_SEED, Cose.ALG_MLDSA65, NEW_SEED);
        eq("object length", 6798, obj.length);
        eq("object sha256", OBJECT_SHA256, sha256Hex(obj));
    }

    private static void testRoundtripAccept() {
        byte[] oldPk = Cose.mldsaKeygen("ML-DSA-65", OLD_SEED);
        byte[] newPk = Cose.mldsaKeygen("ML-DSA-65", NEW_SEED);
        byte[] obj = Envelope.signRotationObject(workedObject(), Cose.ALG_MLDSA65, OLD_SEED, Cose.ALG_MLDSA65, NEW_SEED);
        Envelope.Object o = Envelope.verifyRotationObject(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk,
                Cose.ALG_MLDSA65, newPk, RotationKatTest::kindOk, obj, null);
        if (o.channel != 3 || o.kind != 0) {
            throw new AssertionError("roundtrip: unexpected decoded object channel=" + o.channel + " kind=" + o.kind);
        }
    }

    private static void testTag18SingleSigRejected() {
        // a channel-3/kind-0 object signed as a normal single-signature COSE_Sign1 (tag 18) is a
        // rotation missing the old-key co-signature -> the general verify() rejects RotationUnauthorized.
        byte[] newPk = Cose.mldsaKeygen("ML-DSA-65", NEW_SEED);
        byte[] obj = Envelope.sign(workedObject(), Cose.ALG_MLDSA65, NEW_SEED); // tag-18
        try {
            Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, newPk, RotationKatTest::kindOk, obj, null);
            throw new AssertionError("tag18: expected RotationUnauthorized, verify succeeded");
        } catch (NaalpException e) {
            eq("tag18.kind", "RotationUnauthorized", e.kind);
        }
    }

    private static void testOldLegDropped() {
        // the mutation anchor: dropping the old leg (one leg) MUST be rejected RotationUnauthorized.
        // Disabling the exactly-two-legs check in verifyRotationObject flips this test.
        byte[] oldPk = Cose.mldsaKeygen("ML-DSA-65", OLD_SEED);
        byte[] newPk = Cose.mldsaKeygen("ML-DSA-65", NEW_SEED);
        byte[] obj = Envelope.signRotationObject(workedObject(), Cose.ALG_MLDSA65, OLD_SEED, Cose.ALG_MLDSA65, NEW_SEED);
        Cose.RotationParse rp = Cose.parseSignRaw(obj);
        byte[] oneLeg = Cose.assembleSignRaw(rp.bodyProt, rp.payload,
                java.util.Collections.singletonList(rp.legs.get(1))); // keep only the new leg
        try {
            Envelope.verifyRotationObject(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA65, newPk,
                    RotationKatTest::kindOk, oneLeg, null);
            throw new AssertionError("oldLegDropped: expected RotationUnauthorized, verify succeeded");
        } catch (NaalpException e) {
            eq("oldLegDropped.kind", "RotationUnauthorized", e.kind);
        }
    }

    private static void testOldLegWrongKey() {
        // both legs signed by the NEW key -> the trusted old key cannot verify slot 0.
        byte[] oldPk = Cose.mldsaKeygen("ML-DSA-65", OLD_SEED);
        byte[] newPk = Cose.mldsaKeygen("ML-DSA-65", NEW_SEED);
        byte[] obj = Envelope.signRotationObject(workedObject(), Cose.ALG_MLDSA65, NEW_SEED, Cose.ALG_MLDSA65, NEW_SEED);
        try {
            Envelope.verifyRotationObject(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA65, newPk,
                    RotationKatTest::kindOk, obj, null);
            throw new AssertionError("oldLegWrongKey: expected RotationUnauthorized, verify succeeded");
        } catch (NaalpException e) {
            eq("oldLegWrongKey.kind", "RotationUnauthorized", e.kind);
        }
    }

    private static void testNonRotationKind() {
        // a tag-98 object built over a non-rotation (channel 4, kind 2) is UnknownKind.
        byte[] oldPk = Cose.mldsaKeygen("ML-DSA-65", OLD_SEED);
        byte[] newPk = Cose.mldsaKeygen("ML-DSA-65", NEW_SEED);
        Envelope.Object o = new Envelope.Object(2, 4, 0, SIGNER, NOT_BEFORE, 2, Cose.PROFILE_PUBLIC,
                new Cbor.T("hello"), null, null, null);
        // sign() is only used here to obtain a valid (protected-header, payload) pair for this
        // object's fields -- protectedHeader() is private, so a real tag-18 object over the same
        // fields is parsed back with parseSign1Raw to recover the identical bytes
        // signatureLeg()/assembleSignRaw() need. The tag-18 signature itself is discarded.
        byte[] signed = Envelope.sign(o, Cose.ALG_MLDSA65, NEW_SEED);
        byte[][] parts = Cose.parseSign1Raw(signed);
        byte[] bodyProt = parts[0];
        byte[] payload = parts[1];
        byte[][] oldLeg = Cose.signatureLeg(bodyProt, Cose.ALG_MLDSA65, OLD_SEED, payload);
        byte[][] newLeg = Cose.signatureLeg(bodyProt, Cose.ALG_MLDSA65, NEW_SEED, payload);
        byte[] obj = Cose.assembleSignRaw(bodyProt, payload, List.of(oldLeg, newLeg));
        try {
            Envelope.verifyRotationObject(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA65, newPk,
                    (c, k) -> true, obj, null);
            throw new AssertionError("nonRotationKind: expected UnknownKind, verify succeeded");
        } catch (NaalpException e) {
            eq("nonRotationKind.kind", "UnknownKind", e.kind);
        }
    }

    private static void testSovereignOldLegFloor() {
        // old=ML-DSA-65 (level 3), new=ML-DSA-87 (level 5), Sovereign floor 5 -> the sub-floor OLD
        // leg yields ProfileDowngrade under the ratified fail-closed default.
        byte[] oldPk = Cose.mldsaKeygen("ML-DSA-65", FLOOR_OLD_SEED);
        byte[] newPk = Cose.mldsaKeygen("ML-DSA-87", FLOOR_NEW_SEED);
        byte[] obj = Envelope.signRotationObject(workedObject(Cose.PROFILE_SOVEREIGN), Cose.ALG_MLDSA65,
                FLOOR_OLD_SEED, Cose.ALG_MLDSA87, FLOOR_NEW_SEED);
        try {
            Envelope.verifyRotationObject(Cose.PROFILE_SOVEREIGN, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA87, newPk,
                    RotationKatTest::kindOk, obj, null);
            throw new AssertionError("sovereignOldLegFloor: expected ProfileDowngrade, verify succeeded");
        } catch (NaalpException e) {
            eq("sovereignOldLegFloor.kind", "ProfileDowngrade", e.kind);
        }
    }

    private static void eq(String what, Object want, Object got) {
        if (!want.equals(got)) {
            throw new AssertionError(what + " mismatch\n  want=" + want + "\n  got =" + got);
        }
    }

    public static void main(String[] args) {
        testObjectByteParityWithReference();
        System.out.println("  ok  object byte parity with reference");
        testRoundtripAccept();
        System.out.println("  ok  roundtrip accept");
        testTag18SingleSigRejected();
        System.out.println("  ok  tag-18 single-sig -> RotationUnauthorized");
        testOldLegDropped();
        System.out.println("  ok  old leg dropped -> RotationUnauthorized");
        testOldLegWrongKey();
        System.out.println("  ok  old leg wrong key -> RotationUnauthorized");
        testNonRotationKind();
        System.out.println("  ok  non-rotation kind -> UnknownKind");
        testSovereignOldLegFloor();
        System.out.println("  ok  sovereign old leg floor -> ProfileDowngrade");
        System.out.println("RotationKatTest: PASS");
    }
}
