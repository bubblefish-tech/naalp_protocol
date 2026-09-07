// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * NA-IETF-1 producing-boundary disclosure (the OPTIONAL, self-asserted ext key 15, §2.5.4)
 * known-answer tests for the Java SDK, graded against the independent oracle
 * (tools/producing_boundary_oracle.py -&gt; vectors/producing_boundary/cases.json), i.e. Java ==
 * Go == Rust == Python == oracle. Runs via javac + java (no test framework), in the same plain
 * {@code main()} KAT style as {@link WorkedExampleKatTest} and {@link RotationKatTest}.
 *
 * <p>Five properties, mirroring impl/go/envelope/producing_boundary_test.go and
 * impl/python/tests/test_producing_boundary.py, all mutation-surviving:
 * <ol>
 *   <li>MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body
 *       bytes; a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; and
 *       the parsed disclosure (present/kind/boundary/reporting) matches. Non-canonical sub-map
 *       bytes are rejected NonCanonical at the codec.</li>
 *   <li>UNDER SIGNATURE -- the disclosure is folded into the SIGNER's signed body: splicing a
 *       different boundary into a signed object (keeping its id + signature) is rejected.</li>
 *   <li>READER ROUND-TRIP -- set/get carries the value; the field is OPTIONAL; the setter DROPS a
 *       reporting-boundary under observed (an observer relays from no one).</li>
 *   <li>MALFORMED IGNORED [MUTATION ANCHOR] -- a well-formed object carrying a MALFORMED disclosure
 *       (reporting under observed) in the non-critical ext map still verifies and is NOT surfaced.</li>
 *   <li>CEXT REJECTED [MUTATION ANCHOR] -- the disclosure in the CRITICAL cext map is
 *       UnknownCriticalExt.</li>
 * </ol>
 *
 * <p>Run (from the repo root, on Windows the classpath separator is ';'):
 * <pre>
 * javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d impl/java/tout \
 *     impl/java/src/main/java/sh/bubblefish/naalp/*.java harness/adapters/java/Json.java \
 *     impl/java/src/test/java/sh/bubblefish/naalp/ProducingBoundaryKatTest.java
 * java -cp "impl/java/tout;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" sh.bubblefish.naalp.ProducingBoundaryKatTest
 * </pre>
 */
public final class ProducingBoundaryKatTest {
    private static final int ALG = Cose.ALG_MLDSA65;
    // a LOCAL test signing seed -- the verdict is a sign+verify round-trip, not a reproduction of
    // the oracle's signature (full_hex is the object BODY, not a signed COSE object, so byte-parity
    // needs no signing).
    private static final byte[] SEED = seedRange32();

    private static byte[] seedRange32() {
        byte[] s = new byte[32];
        for (int i = 0; i < 32; i++) {
            s[i] = (byte) i;
        }
        return s;
    }

    private static boolean kindOk(long ch, long k) {
        return true;
    }

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("producing_boundary").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadCorpus() throws IOException {
        Path p = findVector();
        if (p == null) {
            return null;
        }
        String json = Files.readString(p, StandardCharsets.UTF_8);
        return (Map<String, Object>) Json.parse(json);
    }

    // base object built from the corpus's LOGICAL fields (never the oracle hex), so a constant
    // encoder diverges from the pinned bytes.
    @SuppressWarnings("unchecked")
    private static Envelope.Object baseObject(Map<String, Object> corpus) {
        Map<String, Object> base = (Map<String, Object>) corpus.get("base_object");
        long kind = (Long) base.get("kind");
        long channel = (Long) base.get("channel");
        long tier = (Long) base.get("tier");
        byte[] signer = Hex.decode((String) base.get("signer_hex"));
        long created = (Long) base.get("created");
        long effect = (Long) base.get("effect");
        List<Object> causesHex = (List<Object>) base.get("causes_hex");
        List<byte[]> causes = new ArrayList<>(causesHex.size());
        for (Object h : causesHex) {
            causes.add(Hex.decode((String) h));
        }
        long profile = (Long) base.get("profile");
        String bodyStr = (String) base.get("body_str");
        return new Envelope.Object(kind, channel, tier, signer, created, effect, profile,
                new Cbor.T(bodyStr), causes, null, null);
    }

    // Build the ext[15]/cext[15] sub-map DIRECTLY from the case's logical fields (the ONLY variable
    // per case), reproducing the oracle bytes for well-formed AND malformed values -- the malformed
    // cases cannot be built via setProducingBoundary by design, so they are constructed here.
    private static void applyPlacement(Envelope.Object o, Map<String, Object> tc) {
        String placement = (String) tc.get("placement");
        if ("absent".equals(placement)) {
            return;
        }
        List<Cbor.Pair> sub = new ArrayList<>();
        Object boundaryHex = tc.get("boundary_hex");
        if (boundaryHex != null) {
            sub.add(new Cbor.Pair(new Cbor.U(Envelope.PB_FIELD_BOUNDARY), new Cbor.B(Hex.decode((String) boundaryHex))));
        }
        Object kindV = tc.get("kind");
        if (kindV != null) {
            sub.add(new Cbor.Pair(new Cbor.U(Envelope.PB_FIELD_KIND), new Cbor.U((Long) kindV)));
        }
        Object reportingHex = tc.get("reporting_hex");
        if (reportingHex != null) {
            sub.add(new Cbor.Pair(new Cbor.U(Envelope.PB_FIELD_REPORTING), new Cbor.B(Hex.decode((String) reportingHex))));
        }
        Cbor.M ext = new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(Envelope.PRODUCING_BOUNDARY_KEY), new Cbor.M(sub))));
        if ("ext".equals(placement)) {
            o.ext = ext;
        } else if ("cext".equals(placement)) {
            o.cext = ext;
        } else {
            throw new AssertionError("unknown placement " + placement);
        }
    }

    // ---- checks ----

    /**
     * Grades disclosure body bytes, accept/reject verdicts, AND the parsed disclosure
     * (present/kind/boundary/reporting) against the independent oracle
     * (tools/producing_boundary_oracle.py): every body_no_id_hex/content_id_hex/full_hex is
     * byte-identical, and every case verifies or fails with exactly the oracle's verdict over a
     * REAL ML-DSA-65 signed object. knownCext is null throughout -- the disclosure is enforced by
     * the envelope's existing rules, not the caller's critical-extension set.
     */
    @SuppressWarnings("unchecked")
    private static void testMatchesOracle(Map<String, Object> corpus) {
        long corpusKey = (Long) corpus.get("producing_boundary_key");
        if (corpusKey != Envelope.PRODUCING_BOUNDARY_KEY) {
            throw new AssertionError("producing_boundary_key: corpus " + corpusKey + " != impl " + Envelope.PRODUCING_BOUNDARY_KEY);
        }
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", SEED);
        List<Object> cases = (List<Object>) corpus.get("cases");
        for (Object co : cases) {
            Map<String, Object> tc = (Map<String, Object>) co;
            String name = (String) tc.get("name");

            Envelope.Object o = baseObject(corpus);
            applyPlacement(o, tc);

            // byte parity: body-without-id, content id, full body (all pre-signature).
            eq(name + ".body_no_id", tc.get("body_no_id_hex"), Hex.encode(Cbor.encode(o.bodyMap(false))));
            byte[] cid = o.contentId();
            eq(name + ".content_id", tc.get("content_id_hex"), Hex.encode(cid));
            o.id = cid;
            eq(name + ".full_body", tc.get("full_hex"), Hex.encode(Cbor.encode(o.bodyMap(true))));

            // verdict: sign for real and verify offline; assert accept vs the named error.
            Envelope.Object o2 = baseObject(corpus);
            applyPlacement(o2, tc);
            byte[] signed = Envelope.sign(o2, ALG, SEED);
            String expect = (String) tc.get("expect");
            if ("accept".equals(expect)) {
                Envelope.Object got = Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, ProducingBoundaryKatTest::kindOk, signed, null);
                Envelope.ProducingBoundary pb = got.producingBoundary();
                boolean present = pb != null;
                boolean wantPresent = (Boolean) tc.get("present");
                if (present != wantPresent) {
                    throw new AssertionError(name + ".present: got " + present + " want " + wantPresent);
                }
                if (present) {
                    Map<String, Object> surfaced = (Map<String, Object>) tc.get("surfaced");
                    if (surfaced == null) {
                        throw new AssertionError(name + ": corpus marks present but carries no surfaced disclosure");
                    }
                    long wantKind = (Long) surfaced.get("kind");
                    if (pb.kind != wantKind) {
                        throw new AssertionError(name + ".kind: got " + pb.kind + " want " + wantKind);
                    }
                    eq(name + ".boundary", surfaced.get("boundary_hex"), Hex.encode(pb.boundary));
                    String wantReporting = surfaced.get("reporting_hex") == null ? "" : (String) surfaced.get("reporting_hex");
                    String gotReporting = pb.reporting == null ? "" : Hex.encode(pb.reporting);
                    eq(name + ".reporting", wantReporting, gotReporting);
                }
            } else {
                try {
                    Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, ProducingBoundaryKatTest::kindOk, signed, null);
                    throw new AssertionError(name + ": expected " + expect + ", verify succeeded");
                } catch (NaalpException e) {
                    eq(name + ".verdict", expect, e.kind);
                }
            }
        }

        // non-canonical disclosure bodies (sub-map keys out of order) are rejected at the CBOR layer.
        List<Object> negatives = (List<Object>) corpus.getOrDefault("negatives", List.of());
        byte[] baseSigned = Envelope.sign(baseObject(corpus), ALG, SEED);
        byte[] negProt = Cose.parseSign1Raw(baseSigned)[0];
        for (Object no : negatives) {
            Map<String, Object> neg = (Map<String, Object>) no;
            String name = "negative_" + neg.get("name");
            byte[] payload = Hex.decode((String) neg.get("payload_hex"));
            byte[] negSigned = Cose.coseSign1(ALG, SEED, negProt, payload);
            try {
                Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, ProducingBoundaryKatTest::kindOk, negSigned, null);
                throw new AssertionError(name + ": expected " + neg.get("expect") + ", verify succeeded");
            } catch (NaalpException e) {
                eq(name + ".verdict", neg.get("expect"), e.kind);
            }
        }
    }

    /**
     * Proves the disclosure is folded into the SIGNER's COSE_Sign1 signed input (ext, field 11, is
     * part of the signed body): changing the boundary in a signed object's payload without
     * re-signing breaks verification. A self-asserted disclosure that is NOT under the signer's
     * signature would be forgeable, defeating attributability.
     */
    private static void testUnderSignature(Map<String, Object> corpus) {
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", SEED);
        Envelope.Object o = baseObject(corpus);
        o.setProducingBoundary(new Envelope.ProducingBoundary(Hex.decode("424f554e444152595f58"), Envelope.PRODUCING_BOUNDARY_OBSERVED));
        byte[] signed = Envelope.sign(o, ALG, SEED);
        // baseline: the signed object verifies and reads back the disclosure.
        Envelope.Object got = Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, ProducingBoundaryKatTest::kindOk, signed, null);
        Envelope.ProducingBoundary pb = got.producingBoundary();
        if (pb == null || pb.kind != Envelope.PRODUCING_BOUNDARY_OBSERVED) {
            throw new AssertionError("disclosure read-back failed: " + pb);
        }

        // tamper: change the boundary and re-encode the body WITHOUT re-signing; keep the original
        // id and reuse the original signature bytes -- a real forgery attempt that MUST be rejected.
        Envelope.Object tampered = baseObject(corpus);
        tampered.setProducingBoundary(new Envelope.ProducingBoundary(Hex.decode("4f524947494e5f59"), Envelope.PRODUCING_BOUNDARY_OBSERVED));
        tampered.id = o.id; // keep original content id -- a splice, not a re-sign
        byte[] payload = Cbor.encode(tampered.bodyMap(true));
        byte[][] parts = Cose.parseSign1Raw(signed);
        byte[] forged = Cose.assembleSign1Raw(parts[0], payload, parts[2]);
        try {
            Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, ProducingBoundaryKatTest::kindOk, forged, null);
            throw new AssertionError("tampered producing-boundary must be rejected (it is under signature), got accept");
        } catch (NaalpException e) {
            // expected -- any rejection kind is acceptable, the object is a forged splice.
        }
    }

    /**
     * Proves setProducingBoundary/producingBoundary carry the value, that the field is OPTIONAL (a
     * fresh object has none), that a reported disclosure carries its reporting-boundary, and that
     * the setter DROPS a reporting-boundary under observed (an observer relays from no one) so a
     * caller cannot accidentally build a malformed disclosure.
     */
    private static void testReaderRoundTrip(Map<String, Object> corpus) {
        Envelope.Object o = baseObject(corpus);
        if (o.producingBoundary() != null) {
            throw new AssertionError("fresh object must have no producing-boundary disclosure");
        }
        byte[] x = Hex.decode("424f554e444152595f58");
        byte[] y = Hex.decode("4f524947494e5f59");

        o.setProducingBoundary(new Envelope.ProducingBoundary(x, Envelope.PRODUCING_BOUNDARY_REPORTED, y));
        Envelope.ProducingBoundary pb = o.producingBoundary();
        if (pb == null || pb.kind != Envelope.PRODUCING_BOUNDARY_REPORTED
                || !Hex.encode(pb.boundary).equals("424f554e444152595f58")
                || pb.reporting == null || !Hex.encode(pb.reporting).equals("4f524947494e5f59")) {
            throw new AssertionError("reported disclosure round-trip wrong: " + (pb == null ? "null" : Hex.encode(pb.boundary)));
        }

        // the setter drops a reporting-boundary under observed: read-back has no reporting.
        o.setProducingBoundary(new Envelope.ProducingBoundary(x, Envelope.PRODUCING_BOUNDARY_OBSERVED, y));
        pb = o.producingBoundary();
        if (pb == null || pb.kind != Envelope.PRODUCING_BOUNDARY_OBSERVED || pb.reporting != null) {
            throw new AssertionError("observed disclosure must drop reporting");
        }
    }

    /**
     * MUTATION ANCHOR: dropping the reporting-under-observed check in producingBoundary() flips
     * present false-&gt;true and this test pass-&gt;fail; that check is the
     * observer-relays-from-no-one invariant. A well-formed object carrying a MALFORMED
     * producing-boundary in the non-critical ext map (a reporting-boundary under observed) still
     * Signs and Verifies, and the disclosure is NOT surfaced.
     */
    private static void testMalformedIgnored(Map<String, Object> corpus) {
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", SEED);
        Envelope.Object o = baseObject(corpus);
        // build the malformed ext[15] = {1:X, 2:observed, 3:Y} directly (the setter refuses to build it).
        o.ext = new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(Envelope.PRODUCING_BOUNDARY_KEY), new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(Envelope.PB_FIELD_BOUNDARY), new Cbor.B(Hex.decode("424f554e444152595f58"))),
                new Cbor.Pair(new Cbor.U(Envelope.PB_FIELD_KIND), new Cbor.U(Envelope.PRODUCING_BOUNDARY_OBSERVED)),
                new Cbor.Pair(new Cbor.U(Envelope.PB_FIELD_REPORTING), new Cbor.B(Hex.decode("4f524947494e5f59"))))))));
        byte[] signed = Envelope.sign(o, ALG, SEED);
        Envelope.Object got = Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, ProducingBoundaryKatTest::kindOk, signed, null);
        if (got.producingBoundary() != null) {
            throw new AssertionError("a malformed disclosure (reporting under observed) must NOT be surfaced");
        }
    }

    /**
     * MUTATION ANCHOR: the disclosure placed in the CRITICAL cext map (field 12) is an unrecognized
     * critical extension -&gt; UnknownCriticalExt, fail-closed. A disclosure must never masquerade
     * as a must-understand gate.
     */
    private static void testCextRejected(Map<String, Object> corpus) {
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", SEED);
        Envelope.Object o = baseObject(corpus);
        o.cext = new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(Envelope.PRODUCING_BOUNDARY_KEY), new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(Envelope.PB_FIELD_BOUNDARY), new Cbor.B(Hex.decode("424f554e444152595f58"))),
                new Cbor.Pair(new Cbor.U(Envelope.PB_FIELD_KIND), new Cbor.U(Envelope.PRODUCING_BOUNDARY_OBSERVED)))))));
        byte[] signed = Envelope.sign(o, ALG, SEED);
        try {
            Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, ProducingBoundaryKatTest::kindOk, signed, null);
            throw new AssertionError("cext producing-boundary must be rejected UnknownCriticalExt, got accept");
        } catch (NaalpException e) {
            eq("cext.verdict", "UnknownCriticalExt", e.kind);
        }
    }

    private static void eq(String what, Object want, Object got) {
        if (!want.equals(got)) {
            throw new AssertionError(what + " mismatch\n  want=" + want + "\n  got =" + got);
        }
    }

    public static void main(String[] args) throws Exception {
        Map<String, Object> corpus = loadCorpus();
        if (corpus == null) {
            System.out.println("SKIP: vectors/producing_boundary/cases.json not found");
            return;
        }
        testMatchesOracle(corpus);
        System.out.println("  ok  matches oracle (8 cases + 1 negative: byte parity + verdict + surfaced disclosure)");
        testUnderSignature(corpus);
        System.out.println("  ok  disclosure under signature (splice rejected)");
        testReaderRoundTrip(corpus);
        System.out.println("  ok  reader round-trip (optional; setter drops reporting under observed)");
        testMalformedIgnored(corpus);
        System.out.println("  ok  malformed disclosure ignored (may-ignore, not surfaced)");
        testCextRejected(corpus);
        System.out.println("  ok  cext placement -> UnknownCriticalExt");
        System.out.println("ProducingBoundaryKatTest: PASS");
    }
}
