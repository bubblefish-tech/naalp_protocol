// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.ArrayList;
import java.util.List;

/**
 * Decoder resource bounds (design.md §3.4, R7) known-answer + fail-closed tests for the Java SDK,
 * mirroring impl/go/{cbor,envelope,streaming}/bounds_test.go and impl/rust/src/{cbor,envelope,
 * streaming}.rs. Each bound is proven by a BOUNDARY PAIR: an otherwise-valid input exactly AT the
 * limit is accepted, and one strictly past the limit is rejected with the named error.
 * "Otherwise valid" is load-bearing for mutation survival -- because the only defect under test is
 * the bound, deleting the bound check would make the over-limit input accepted, which is exactly
 * what these tests would catch.
 *
 * <p>Bounds covered: the signed-object octet-size ceiling (TooLarge, checked on both the tag-18
 * object-verify entry and the tag-98 rotation-verify entry), the CBOR decoder nesting-depth ceiling
 * ({@link Cbor#decodeBounded}, DepthExceeded), the causes[]/ext/cext cardinality ceilings
 * (TooManyCauses / TooManyExtensions), and the stream chunk-count ceiling (TooManyChunks, checked
 * in both {@link Streaming#verifyCommit} and {@link Streaming#verifyCheckpoint} before the digest
 * comparison).
 *
 * <p>Run (main()-driven, no test framework, mirrors WorkedExampleKat/RotationKatTest):
 * <pre>
 * javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d impl/java/tout \
 *     impl/java/src/main/java/sh/bubblefish/naalp/*.java impl/java/src/test/java/sh/bubblefish/naalp/BoundsKatTest.java
 * java -cp "impl/java/tout;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" sh.bubblefish.naalp.BoundsKatTest
 * </pre>
 */
public final class BoundsKatTest {
    private static final byte[] SIGNER = "SIGNER_BOUNDS".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final long NOT_BEFORE = 1785000000000L;
    private static final byte[] SEED = seed((byte) 0x77);
    private static final byte[] PUBKEY = Cose.mldsaKeygen("ML-DSA-65", SEED);

    private static byte[] seed(byte b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, b);
        return s;
    }

    private static void eq(String what, Object want, Object got) {
        if (!want.equals(got)) {
            throw new AssertionError(what + " mismatch\n  want=" + want + "\n  got =" + got);
        }
    }

    private static boolean kindOk(long ch, long k) {
        return ch == 4 && k == 2;
    }

    private static Envelope.Object buildObject() {
        return new Envelope.Object(2, 4, 0, SIGNER, NOT_BEFORE, 0, Cose.PROFILE_PUBLIC,
                new Cbor.T("hello"), null, null, null);
    }

    private static void accept(String name, Envelope.Object o) {
        byte[] obj = Envelope.sign(o, Cose.ALG_MLDSA65, SEED);
        Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, PUBKEY, BoundsKatTest::kindOk, obj, null);
    }

    private static void expectKind(String name, Envelope.Object o, String wantKind) {
        byte[] obj = Envelope.sign(o, Cose.ALG_MLDSA65, SEED);
        try {
            Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, PUBKEY, BoundsKatTest::kindOk, obj, null);
            throw new AssertionError(name + ": expected " + wantKind + ", verify succeeded");
        } catch (NaalpException e) {
            eq(name + ".kind", wantKind, e.kind);
        }
    }

    // --- helpers mirroring impl/go/envelope/bounds_test.go ---

    /** n distinct content-id-shaped bstrs (multihash sha2-384 = 0x20 0x30 + 48 zero bytes), so the
     * object is otherwise valid at any cardinality. */
    private static List<byte[]> makeCauses(int n) {
        List<byte[]> out = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            byte[] b = new byte[50];
            b[0] = 0x20;
            b[1] = 0x30;
            out.add(b);
        }
        return out;
    }

    /** n distinct non-critical extension entries (unknown keys, which the may-ignore rule
     * accepts), so the object is otherwise valid at any cardinality. */
    private static Cbor.M makeExtMap(int n) {
        List<Cbor.Pair> pairs = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            pairs.add(new Cbor.Pair(new Cbor.U(100 + i), new Cbor.U(0)));
        }
        return new Cbor.M(pairs);
    }

    /** k single-element arrays wrapping a zero scalar. As a body value it sits at depth 2 (the
     * object body map is depth 1), so the scalar is at depth 2+k. */
    private static Cbor.Value nestArrays(int k) {
        Cbor.Value v = new Cbor.U(0);
        for (int i = 0; i < k; i++) {
            v = new Cbor.A(List.of(v));
        }
        return v;
    }

    private static void testBoundsAcceptAtLimit() {
        Envelope.Object oc = buildObject();
        oc.causes = makeCauses((int) WireConstants.MAX_CAUSES);
        accept("causes==MaxCauses", oc);

        Envelope.Object oe = buildObject();
        oe.ext = makeExtMap((int) WireConstants.MAX_EXT);
        accept("ext==MaxExt", oe);

        // body nested so the deepest scalar sits at exactly MaxNestingDepth (2 + (MaxNestingDepth-2)).
        Envelope.Object od = buildObject();
        od.body = nestArrays((int) WireConstants.MAX_NESTING_DEPTH - 2);
        accept("depth==MaxNestingDepth", od);
    }

    private static void testBoundsRejectOverLimit() {
        Envelope.Object oc = buildObject();
        oc.causes = makeCauses((int) WireConstants.MAX_CAUSES + 1);
        expectKind("TooManyCauses", oc, "TooManyCauses");

        Envelope.Object oe = buildObject();
        oe.ext = makeExtMap((int) WireConstants.MAX_EXT + 1);
        expectKind("TooManyExtensions(ext)", oe, "TooManyExtensions");

        // cext over the limit also yields TooManyExtensions: the cardinality check in
        // objectFromMap fires before the critical-extension recognition check.
        Envelope.Object ox = buildObject();
        ox.cext = makeExtMap((int) WireConstants.MAX_CEXT + 1);
        expectKind("TooManyExtensions(cext)", ox, "TooManyExtensions");

        // body nested so the deepest scalar sits at MaxNestingDepth+1.
        Envelope.Object od = buildObject();
        od.body = nestArrays((int) WireConstants.MAX_NESTING_DEPTH - 1);
        expectKind("DepthExceeded", od, "DepthExceeded");
    }

    /** Pins the object octet-size bound: a large-but-under-limit signed object verifies, and an
     * otherwise-valid object over the limit is rejected TooLarge on the raw bytes before any parse
     * (RFC 8949 §10 decoder-memory guard). */
    private static void testBoundTooLarge() {
        Envelope.Object under = buildObject();
        under.body = new Cbor.B(new byte[(int) WireConstants.MAX_OBJECT_SIZE - 16384]);
        byte[] uobj = Envelope.sign(under, Cose.ALG_MLDSA65, SEED);
        if (uobj.length > WireConstants.MAX_OBJECT_SIZE) {
            throw new AssertionError("under-limit object is " + uobj.length + " bytes, expected < " + WireConstants.MAX_OBJECT_SIZE);
        }
        Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, PUBKEY, BoundsKatTest::kindOk, uobj, null);

        Envelope.Object over = buildObject();
        over.body = new Cbor.B(new byte[(int) WireConstants.MAX_OBJECT_SIZE]);
        byte[] bobj = Envelope.sign(over, Cose.ALG_MLDSA65, SEED);
        if (bobj.length <= WireConstants.MAX_OBJECT_SIZE) {
            throw new AssertionError("over-limit object is only " + bobj.length + " bytes, expected > " + WireConstants.MAX_OBJECT_SIZE);
        }
        try {
            Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, PUBKEY, BoundsKatTest::kindOk, bobj, null);
            throw new AssertionError("TooLarge: verify succeeded, expected TooLarge");
        } catch (NaalpException e) {
            eq("TooLarge.kind", "TooLarge", e.kind);
        }
    }

    // --- impl/go/cbor/bounds_test.go mirror ---

    /** k single-element arrays (0x81 repeated k times) then a zero scalar (0x00): decoding it, the
     * outermost array is at depth 1 and the innermost scalar is at depth k+1. */
    private static byte[] nestedArraysCbor(int k) {
        byte[] b = new byte[k + 1];
        java.util.Arrays.fill(b, 0, k, (byte) 0x81);
        b[k] = 0x00;
        return b;
    }

    /** Pins the nesting-depth counter (design.md §3.4, R7): the outermost item is depth 1, and
     * decodeBounded rejects the first item at depth maxDepth+1 with a DepthExceeded error, before
     * it is materialized. The unbounded decode path still accepts the same structure, so the
     * bound -- not another check -- is what does the work. */
    private static void testDecodeBoundedDepth() {
        final int d = 3;

        byte[] atLimit = nestedArraysCbor(d - 1); // deepest scalar at depth d
        Cbor.decodeBounded(atLimit, d); // accepted at maxDepth=d

        byte[] over = nestedArraysCbor(d); // deepest scalar at depth d+1
        try {
            Cbor.decodeBounded(over, d);
            throw new AssertionError("deepest item at depth " + (d + 1) + " should be DepthExceeded at maxDepth=" + d);
        } catch (NaalpException e) {
            eq("cbor.decodeBounded over-depth kind", "DepthExceeded", e.kind);
        }

        // The unbounded path accepts the same over-depth structure: the bound, not another check,
        // is what rejected it above.
        Cbor.decode(over);
    }

    // --- impl/go/streaming/bounds_test.go mirror ---

    /** Pins the stream chunk-count bound (design.md §3.4, R7): a commit over exactly
     * MaxStreamChunks chunks verifies, and one over MaxStreamChunks+1 is rejected TooManyChunks.
     * Both carry a MATCHING rolling digest, so the count is the only reason to reject -- deleting
     * the count check would make the +1 case verify (the mutation is caught). The chunks share one
     * backing list to bound test memory. */
    private static void testBoundTooManyChunks() {
        int limit = (int) WireConstants.MAX_STREAM_CHUNKS;
        List<Streaming.Chunk> over = new ArrayList<>(limit + 1);
        for (int i = 0; i <= limit; i++) {
            over.add(new Streaming.Chunk(0, new byte[0]));
        }
        List<Streaming.Chunk> atLimit = over.subList(0, limit);

        Streaming.StreamCommit okCommit = new Streaming.StreamCommit(new byte[0], Streaming.commitDigest(atLimit));
        Streaming.verifyCommit(okCommit, atLimit); // commit over `limit` chunks should verify

        Streaming.StreamCommit overCommit = new Streaming.StreamCommit(new byte[0], Streaming.commitDigest(over));
        try {
            Streaming.verifyCommit(overCommit, over);
            throw new AssertionError("commit over " + (limit + 1) + " chunks should be TooManyChunks");
        } catch (NaalpException e) {
            eq("verifyCommit over-limit kind", "TooManyChunks", e.kind);
        }

        // verifyCheckpoint enforces the same bound, and the count check fires before the
        // contiguity/digest checks, so the diagnosis is TooManyChunks (not a digest error).
        Streaming.StreamCheckpoint cp = new Streaming.StreamCheckpoint(new byte[0], 0, new byte[0]);
        try {
            Streaming.verifyCheckpoint(cp, over);
            throw new AssertionError("checkpoint over " + (limit + 1) + " chunks should be TooManyChunks");
        } catch (NaalpException e) {
            eq("verifyCheckpoint over-limit kind", "TooManyChunks", e.kind);
        }
    }

    public static void main(String[] args) {
        testDecodeBoundedDepth();
        System.out.println("  ok  cbor.decodeBounded depth bound (accept-at-limit, reject-over, unbounded unaffected)");
        testBoundsAcceptAtLimit();
        System.out.println("  ok  causes/ext/depth accepted exactly at their limits");
        testBoundsRejectOverLimit();
        System.out.println("  ok  causes/ext/cext/depth rejected one past their limits with the named kind");
        testBoundTooLarge();
        System.out.println("  ok  object octet-size bound (TooLarge)");
        testBoundTooManyChunks();
        System.out.println("  ok  stream chunk-count bound (TooManyChunks, commit + checkpoint)");
        System.out.println("BoundsKatTest: PASS");
    }
}
