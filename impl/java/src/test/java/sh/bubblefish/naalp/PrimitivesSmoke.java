// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

/**
 * Self-contained conformance smoke tests over the SDK primitives, anchored to independent
 * standards vectors (FIPS 180-4 SHA-384, RFC 8949 canonical CBOR, the multiformats signer id, the
 * §6.1 effect lattice, the twenty-channel registry). The authoritative cross-language grading is
 * the naalp-conform harness against the 239-case corpus; these keep the SDK independently
 * checkable without the harness.
 *
 * <p>Run: {@code java -cp "impl/java/tout;.../bcprov-jdk18on-1.85.jar" sh.bubblefish.naalp.PrimitivesSmoke}
 */
public final class PrimitivesSmoke {

    private static byte[] sha384(byte[] b) throws Exception {
        return MessageDigest.getInstance("SHA-384").digest(b);
    }

    private static void testSha384Kat() throws Exception {
        eq("sha384(abc)",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                        + "8086072ba1e7cc2358baeca134c825a7",
                Hex.encode(sha384("abc".getBytes(StandardCharsets.UTF_8))));
    }

    private static void testCborCanonicalEncodeAndContentId() {
        // canonical map: keys emitted in bytewise-ascending order regardless of input order
        Cbor.M m = new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(4)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(0))));
        eq("canonical map encode", "a2020003 04".replace(" ", ""), Hex.encode(Cbor.encode(m)));
        byte[] cid = Cbor.contentId(Cbor.encode(m));
        if (!(cid[0] == 0x20 && cid[1] == 0x30)) {
            throw new AssertionError("content id multihash prefix");
        }
        if (cid.length != 2 + 48) {
            throw new AssertionError("content id length != 50");
        }
    }

    private static void testCborRejectsNonCanonical() {
        // out-of-order / non-shortest / indefinite / duplicate-key
        for (String bad : new String[]{"a202000100", "1800", "9f00ff", "a201000101"}) {
            boolean rejected = false;
            try {
                Cbor.decode(Hex.decode(bad));
            } catch (NaalpException e) {
                rejected = "NonCanonical".equals(e.kind);
            }
            if (!rejected) {
                throw new AssertionError("expected NonCanonical rejection for " + bad);
            }
        }
    }

    private static void testCoseToBeSignedRfc9052() {
        byte[] tbs = Cose.toBeSignedRaw(Hex.decode("a1013830"), Hex.decode("a10700"));
        // ["Signature1", ...]  ->  84 6a 5369676e6174757265 31
        String want = "846a5369676e617475726531";
        if (!Hex.encode(tbs).startsWith(want)) {
            throw new AssertionError("Sig_structure prefix");
        }
    }

    private static void testSignerIdForm() {
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", new byte[32]);
        String sid = Identity.signerId(Cose.ALG_MLDSA65, pk);
        if (!sid.startsWith("b")) {
            throw new AssertionError("signer id multibase base32 prefix");
        }
    }

    private static void testEffectLattice() {
        eq("normalize 99 -> destructive", Policy.DESTRUCTIVE, Policy.normalizeEffect(99));
        if (!Policy.authorizes(Policy.NON_IDEMPOTENT_WRITE, Policy.IDEMPOTENT_WRITE)) {
            throw new AssertionError("NIW should authorize IW");
        }
        if (Policy.authorizes(Policy.READ_ONLY, Policy.DESTRUCTIVE)) {
            throw new AssertionError("RO must not authorize DE");
        }
    }

    private static void testChannelsRegistry() {
        Channels.KindSpec ks = Channels.lookup(0x0004, 1); // Governance.Approval
        eq("channel 0x0004 kind 1 name", "Approval", ks.name);
        eq("channel 0x0004 kind 1 effect", (long) Policy.NON_IDEMPOTENT_WRITE, (long) ks.effect);
        boolean rejected = false;
        try {
            Channels.lookup(0x0000, 9999);
        } catch (NaalpException e) {
            rejected = "UnknownKind".equals(e.kind);
        }
        if (!rejected) {
            throw new AssertionError("unknown kind must raise UnknownKind");
        }
    }

    private static void testRecordsDeterministic() throws Exception {
        byte[] body = Records.receiptBody(new byte[48], Hex.decode("2030" + "00".repeat(48)), 0, 100);
        eq("receipt head == sha384(body)", Hex.encode(sha384(body)), Hex.encode(Records.receiptHead(body)));
    }

    private static void testAlgLevelAndProfileFloor() {
        eq("ML-DSA-87 level", 5L, (long) Cose.algLevel(Cose.ALG_MLDSA87).level);
        eq("ML-DSA-65 level", 3L, (long) Cose.algLevel(Cose.ALG_MLDSA65).level);
        if (Cose.algLevel(999).known) {
            throw new AssertionError("unregistered alg must be unknown");
        }
        eq("sovereign floor", 5L, (long) Cose.profileMinLevel(Cose.PROFILE_SOVEREIGN));
        eq("public floor", 3L, (long) Cose.profileMinLevel(Cose.PROFILE_PUBLIC));
    }

    private static void eq(String what, String want, String got) {
        if (!want.equals(got)) {
            throw new AssertionError(what + " mismatch\n  want=" + want + "\n  got =" + got);
        }
    }

    private static void eq(String what, long want, long got) {
        if (want != got) {
            throw new AssertionError(what + " mismatch: want=" + want + " got=" + got);
        }
    }

    public static void main(String[] args) throws Exception {
        testSha384Kat();
        System.out.println("  ok  SHA-384 KAT (FIPS 180-4)");
        testCborCanonicalEncodeAndContentId();
        System.out.println("  ok  canonical CBOR encode + content id (RFC 8949)");
        testCborRejectsNonCanonical();
        System.out.println("  ok  strict decoder rejects non-canonical");
        testCoseToBeSignedRfc9052();
        System.out.println("  ok  COSE ToBeSigned (RFC 9052 Sig_structure)");
        testSignerIdForm();
        System.out.println("  ok  self-certifying signer id (multiformats)");
        testEffectLattice();
        System.out.println("  ok  effect lattice (§6.1)");
        testChannelsRegistry();
        System.out.println("  ok  twenty-channel registry");
        testRecordsDeterministic();
        System.out.println("  ok  deterministic record bodies");
        testAlgLevelAndProfileFloor();
        System.out.println("  ok  alg level + profile floor");
        System.out.println("PrimitivesSmoke: PASS");
    }
}
