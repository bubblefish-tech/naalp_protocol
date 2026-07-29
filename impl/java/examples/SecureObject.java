// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// examples/SecureObject.java — build, sign, verify, and tamper-check a full N-AALP object.
//
// Compile (from the repo root, on Windows the classpath separator is ';'):
//   javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" \
//       -d impl/java/out impl/java/src/main/java/sh/bubblefish/naalp/*.java impl/java/examples/SecureObject.java
// Run:
//   java -cp "impl/java/out;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" SecureObject
// Expected output:
//   signer   bciq...
//   signed   <N> bytes, verifies=true
//   tampered rejected: BadSignature

import java.nio.charset.StandardCharsets;
import java.util.List;

import sh.bubblefish.naalp.Cbor;
import sh.bubblefish.naalp.Cose;
import sh.bubblefish.naalp.Envelope;
import sh.bubblefish.naalp.Identity;
import sh.bubblefish.naalp.NaalpException;

public final class SecureObject {
    public static void main(String[] args) {
        // a deterministic 32-byte key seed (use a real random seed in production)
        byte[] seed = new byte[32];
        java.util.Arrays.fill(seed, (byte) 0x2a);
        int alg = Cose.ALG_MLDSA65;
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", seed);
        String signerId = Identity.signerId(alg, pk);
        System.out.println("signer   " + signerId);

        // a Governance Approval object (channel 0x0004, kind 1) on the Public profile.
        // args_id is the content id of the object the approval authorizes.
        byte[] argsId = new Envelope.Object(
                0, 0, new byte[0], 0, 0,
                new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(1), new Cbor.T("the-args"))))).contentId();
        Cbor.M approval = new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(argsId)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T(signerId)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(2)),                                  // granted effect
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(new byte[]{1, 2, 3, 4, 5, 6, 7, 8})), // nonce
                new Cbor.Pair(new Cbor.U(5), new Cbor.U(1785000000000L))));                   // not_after (ms)
        Envelope.Object obj = new Envelope.Object(
                1, 4, 0, signerId.getBytes(StandardCharsets.UTF_8),
                1785000000000L, 2, Cose.PROFILE_PUBLIC, approval, null, null, null);

        byte[] signed = Envelope.sign(obj, alg, seed);
        Envelope.Object got = Envelope.verify(
                Cose.PROFILE_PUBLIC, alg, pk, (c, k) -> c == 4 && k == 1, signed, null);
        boolean verifies = got.kind == 1 && got.channel == 4;
        System.out.println("signed   " + signed.length + " bytes, verifies=" + verifies);

        byte[] tampered = signed.clone();
        tampered[tampered.length - 1] ^= 1;
        try {
            Envelope.verify(Cose.PROFILE_PUBLIC, alg, pk, (c, k) -> true, tampered, null);
            System.out.println("tampered NOT rejected (bug)");
        } catch (NaalpException e) {
            System.out.println("tampered rejected: " + e.kind);
        }
    }
}
