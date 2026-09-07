// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * T1.3 recheck procedure (ext/cext key 13, §2.5.1) and T1.6 per-signer forward-only counter +
 * duplication detection (ext key 14, §2.5.2) known-answer tests for the Java SDK.
 *
 * <p>The signer-counter surface is ORACLE-GRADED against the independent oracle
 * (tools/signer_counter_oracle.py -&gt; vectors/signer_counter/cases.json), i.e. Java == Go ==
 * Rust == oracle for every body_no_id_hex / content_id_hex / full_hex byte and every accept/reject
 * verdict, plus every {@code DetectSignerDuplication} scenario finding. The recheck surface has no
 * shared corpus (it is a pure ext/cext accessor + a closed registry, design.md §2.5), so it is
 * graded here with structural KATs mirroring impl/go/envelope/envelope.go's own doc comments.
 *
 * <p>Runs via javac + java (no test framework), in the same plain {@code main()} KAT style as
 * {@link ProducingBoundaryKatTest} and {@link WorkedExampleKatTest}.
 *
 * <p>Run (from the repo root, on Windows the classpath separator is ';'):
 * <pre>
 * javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d impl/java/tout \
 *     impl/java/src/main/java/sh/bubblefish/naalp/*.java harness/adapters/java/Json.java \
 *     impl/java/src/test/java/sh/bubblefish/naalp/RecheckSignerCounterKatTest.java
 * java -cp "impl/java/tout;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" sh.bubblefish.naalp.RecheckSignerCounterKatTest
 * </pre>
 */
public final class RecheckSignerCounterKatTest {
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
            Path p = d.resolve("vectors").resolve("signer_counter").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        return null;
    }

    // base object built from the corpus's LOGICAL fields (never the oracle hex), so a constant
    // encoder diverges from the pinned bytes. signerHexOverride/bodyStrOverride win over the base
    // object's own fields when non-empty (matching impl/go/envelope/signer_counter_test.go's
    // baseCounterObject); pass null/"" for both to use the shared base object unmodified.
    @SuppressWarnings("unchecked")
    private static Envelope.Object baseObject(Map<String, Object> corpus, String signerHexOverride, String bodyStrOverride) {
        Map<String, Object> base = (Map<String, Object>) corpus.get("base_object");
        long kind = (Long) base.get("kind");
        long channel = (Long) base.get("channel");
        long tier = (Long) base.get("tier");
        String signerHex = (signerHexOverride != null && !signerHexOverride.isEmpty())
                ? signerHexOverride : (String) base.get("signer_hex");
        byte[] signer = Hex.decode(signerHex);
        long created = (Long) base.get("created");
        long effect = (Long) base.get("effect");
        List<Object> causesHex = (List<Object>) base.get("causes_hex");
        List<byte[]> causes = new ArrayList<>(causesHex.size());
        for (Object h : causesHex) {
            causes.add(Hex.decode((String) h));
        }
        long profile = (Long) base.get("profile");
        String bodyStr = (bodyStrOverride != null && !bodyStrOverride.isEmpty())
                ? bodyStrOverride : (String) base.get("body_str");
        return new Envelope.Object(kind, channel, tier, signer, created, effect, profile,
                new Cbor.T(bodyStr), causes, null, null);
    }

    /**
     * Extracts the raw JSON integer literal following the first {@code "counter":} key inside the
     * named case's object in the corpus's RAW text, as the exact 64-bit two's-complement bit
     * pattern ({@link BigInteger#longValue()} wraps modulo 2^64 -- matching Go's {@code uint64}
     * decode). {@code Json}'s parser falls back to {@code Double} for an integer literal beyond
     * {@code Long.MAX_VALUE} (the corpus's {@code counter_uint64_max} case is 2^64-1), which would
     * silently round to 2^64 and then clamp on a lossy double-to-long cast; reading the exact digit
     * run from the source text sidesteps that loss entirely.
     */
    private static long rawCounterLong(String rawJson, String caseName) {
        String needle = "\"name\": \"" + caseName + "\"";
        int nameIdx = rawJson.indexOf(needle);
        if (nameIdx < 0) {
            throw new AssertionError("case not found in raw JSON: " + caseName);
        }
        int counterKeyIdx = rawJson.indexOf("\"counter\":", nameIdx);
        if (counterKeyIdx < 0) {
            throw new AssertionError("no counter field after case " + caseName);
        }
        int p = counterKeyIdx + "\"counter\":".length();
        while (Character.isWhitespace(rawJson.charAt(p))) {
            p++;
        }
        int start = p;
        // R12 (NAALP-01-03): a counter above 2^53 is carried as a QUOTED decimal string so a float64
        // decoder cannot round it; skip the opening quote so the digit scan reads the exact literal
        // (the closing quote, being a non-digit, stops the scan).
        if (rawJson.charAt(p) == '"') {
            p++;
            start = p;
        }
        if (rawJson.charAt(p) == '-') {
            p++;
        }
        while (p < rawJson.length() && Character.isDigit(rawJson.charAt(p))) {
            p++;
        }
        String digits = rawJson.substring(start, p);
        if (digits.isEmpty() || "-".equals(digits)) {
            throw new AssertionError("counter field after case " + caseName + " is not an integer literal");
        }
        return new BigInteger(digits).longValue();
    }

    // applyPlacement applies the case's counter placement -- the ONLY variable per case. The "ext"
    // placement uses the real setSignerCounter() accessor under test; "cext"/"ext_empty" are built
    // directly (the accessor never places the counter there by construction).
    private static void applyPlacement(Envelope.Object o, Map<String, Object> tc, String rawJson) {
        String placement = (String) tc.get("placement");
        String name = (String) tc.get("name");
        switch (placement) {
            case "ext":
                o.setSignerCounter(rawCounterLong(rawJson, name));
                break;
            case "cext":
                o.cext = new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(Envelope.SIGNER_COUNTER_KEY),
                        new Cbor.U(rawCounterLong(rawJson, name)))));
                break;
            case "ext_empty":
                o.ext = new Cbor.M(List.of()); // present but empty (no key 14) -- distinct bytes from absent
                break;
            case "absent":
                break; // no ext, no cext
            default:
                throw new AssertionError("unknown placement " + placement);
        }
    }

    // ---- signer-counter: oracle-graded checks ----

    /**
     * Grades counter body bytes AND accept/reject verdicts against the independent oracle
     * (tools/signer_counter_oracle.py): every body_no_id_hex/content_id_hex/full_hex is
     * byte-identical, and every case verifies or fails with exactly the oracle's verdict over a REAL
     * ML-DSA-65 signed object. knownCext is null throughout -- the counter is enforced by the
     * envelope's existing rules, not the caller's critical-extension set.
     */
    @SuppressWarnings("unchecked")
    private static void testMatchesOracle(Map<String, Object> corpus, String rawJson) {
        long corpusKey = (Long) corpus.get("counter_key");
        if (corpusKey != Envelope.SIGNER_COUNTER_KEY) {
            throw new AssertionError("counter_key: corpus " + corpusKey + " != impl " + Envelope.SIGNER_COUNTER_KEY);
        }
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", SEED);
        List<Object> cases = (List<Object>) corpus.get("cases");
        for (Object co : cases) {
            Map<String, Object> tc = (Map<String, Object>) co;
            String name = (String) tc.get("name");
            String signerHex = (String) tc.get("signer_hex");
            String bodyStr = (String) tc.get("body_str");

            Envelope.Object o = baseObject(corpus, signerHex, bodyStr);
            applyPlacement(o, tc, rawJson);

            // byte parity: body-without-id, content id, full body (all pre-signature).
            eq(name + ".body_no_id", tc.get("body_no_id_hex"), Hex.encode(Cbor.encode(o.bodyMap(false))));
            byte[] cid = o.contentId();
            eq(name + ".content_id", tc.get("content_id_hex"), Hex.encode(cid));
            o.id = cid;
            eq(name + ".full_body", tc.get("full_hex"), Hex.encode(Cbor.encode(o.bodyMap(true))));

            // verdict: sign for real and verify offline; assert accept vs the named error.
            Envelope.Object o2 = baseObject(corpus, signerHex, bodyStr);
            applyPlacement(o2, tc, rawJson);
            byte[] signed = Envelope.sign(o2, ALG, SEED);
            String expect = (String) tc.get("expect");
            if ("accept".equals(expect)) {
                Envelope.Object got = Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, RecheckSignerCounterKatTest::kindOk, signed, null);
                Long seq = got.signerCounter();
                boolean present = seq != null;
                boolean wantPresent = (Boolean) tc.get("present");
                if (present != wantPresent) {
                    throw new AssertionError(name + ".present: got " + present + " want " + wantPresent);
                }
                if (present) {
                    long wantSeq = rawCounterLong(rawJson, name);
                    if (seq != wantSeq) {
                        throw new AssertionError(name + ".counter: got " + seq + " want " + wantSeq);
                    }
                }
            } else {
                try {
                    Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, RecheckSignerCounterKatTest::kindOk, signed, null);
                    throw new AssertionError(name + ": expected " + expect + ", verify succeeded");
                } catch (NaalpException e) {
                    eq(name + ".verdict", expect, e.kind);
                }
            }
        }

        // non-canonical counter bodies (ext keys out of order) are rejected at the CBOR layer.
        List<Object> negatives = (List<Object>) corpus.getOrDefault("negatives", List.of());
        byte[] baseSigned = Envelope.sign(baseObject(corpus, null, null), ALG, SEED);
        byte[] negProt = Cose.parseSign1Raw(baseSigned)[0];
        for (Object no : negatives) {
            Map<String, Object> neg = (Map<String, Object>) no;
            String name = "negative_" + neg.get("name");
            byte[] payload = Hex.decode((String) neg.get("payload_hex"));
            byte[] negSigned = Cose.coseSign1(ALG, SEED, negProt, payload);
            try {
                Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, RecheckSignerCounterKatTest::kindOk, negSigned, null);
                throw new AssertionError(name + ": expected " + neg.get("expect") + ", verify succeeded");
            } catch (NaalpException e) {
                eq(name + ".verdict", neg.get("expect"), e.kind);
            }
        }
    }

    /**
     * Proves the counter is folded into the SIGNER's COSE_Sign1 signed input (ext, field 11, is part
     * of the signed body): flipping the counter value in a signed object's payload without re-signing
     * breaks verification. A signer-signed (not ledger-signed) counter is the whole point.
     */
    private static void testUnderSignature(Map<String, Object> corpus) {
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", SEED);
        Envelope.Object o = baseObject(corpus, null, null);
        o.setSignerCounter(5);
        byte[] signed = Envelope.sign(o, ALG, SEED);
        // baseline: the signed object verifies and reads back counter 5.
        Envelope.Object got = Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, RecheckSignerCounterKatTest::kindOk, signed, null);
        Long seq = got.signerCounter();
        if (seq == null || seq != 5) {
            throw new AssertionError("counter read-back: got " + seq + " want 5");
        }
        // tamper: change the counter to 6 and re-encode the body WITHOUT re-signing; keep the
        // original id and reuse the original signature bytes (a real forgery attempt).
        Envelope.Object tampered = baseObject(corpus, null, null);
        tampered.setSignerCounter(6);
        tampered.id = o.id; // keep the original (counter=5) content id -- a splice, not a re-sign
        byte[] payload = Cbor.encode(tampered.bodyMap(true));
        byte[][] parts = Cose.parseSign1Raw(signed);
        byte[] forged = Cose.assembleSign1Raw(parts[0], payload, parts[2]);
        try {
            Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, RecheckSignerCounterKatTest::kindOk, forged, null);
            throw new AssertionError("tampered counter must be rejected (the counter is under signature), got accept");
        } catch (NaalpException e) {
            // expected -- any rejection kind is acceptable, the object is a forged splice.
        }
    }

    /**
     * Proves setSignerCounter/signerCounter carry the value, that the field is OPTIONAL (a fresh
     * object has none), and that a present counter of value 0 reads back present (present is keyed
     * on the key, not the value).
     */
    private static void testReaderRoundTrip(Map<String, Object> corpus) {
        Envelope.Object o = baseObject(corpus, null, null);
        if (o.signerCounter() != null) {
            throw new AssertionError("fresh object must have no counter");
        }
        o.setSignerCounter(42);
        Long seq = o.signerCounter();
        if (seq == null || seq != 42) {
            throw new AssertionError("counter read back wrong: " + seq);
        }
        o.setSignerCounter(0); // present with value zero
        seq = o.signerCounter();
        if (seq == null || seq != 0) {
            throw new AssertionError("present-zero counter must read back present: " + seq);
        }
    }

    /**
     * MUTATION ANCHOR for optionality: an object carrying NO counter Signs and Verifies. Making the
     * field mandatory (e.g. adding a reject-if-absent check to Envelope.verify) flips this test
     * pass-&gt;fail.
     */
    private static void testAbsentValidates(Map<String, Object> corpus) {
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", SEED);
        Envelope.Object o = baseObject(corpus, null, null);
        if (o.signerCounter() != null) {
            throw new AssertionError("object built without a counter must have none");
        }
        byte[] signed = Envelope.sign(o, ALG, SEED);
        Envelope.Object got = Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, RecheckSignerCounterKatTest::kindOk, signed, null);
        if (got.signerCounter() != null) {
            throw new AssertionError("verified object must report no counter");
        }
    }

    // ---- DetectSignerDuplication: oracle-graded + structural checks ----

    // Reconstructs a detection scenario's presented objects from their logical fields and
    // cross-checks each recomputed content id against the oracle's.
    @SuppressWarnings("unchecked")
    private static List<Envelope.Object> buildScenarioObjects(Map<String, Object> corpus, List<Object> objsRaw) {
        List<Envelope.Object> out = new ArrayList<>(objsRaw.size());
        for (Object oo : objsRaw) {
            Map<String, Object> ro = (Map<String, Object>) oo;
            String signerHex = (String) ro.get("signer_hex");
            String bodyStr = (String) ro.get("body_str");
            Envelope.Object o = baseObject(corpus, signerHex, bodyStr);
            Object counterV = ro.get("counter");
            if (counterV != null) {
                o.setSignerCounter((Long) counterV);
            }
            byte[] id = o.contentId();
            String want = (String) ro.get("content_id_hex");
            if (!Hex.encode(id).equals(want)) {
                throw new AssertionError("scenario object content-id\n got " + Hex.encode(id) + "\nwant " + want);
            }
            out.add(o);
        }
        return out;
    }

    /**
     * Grades DetectSignerDuplication over every scenario in the independent oracle: the impl MUST
     * reproduce the oracle's exact findings (signer, counter, and the SET of surfaced content ids).
     */
    @SuppressWarnings("unchecked")
    private static void testDetectMatchesOracle(Map<String, Object> corpus) {
        Map<String, Object> detection = (Map<String, Object>) corpus.get("detection");
        List<Object> scenarios = (List<Object>) detection.get("scenarios");
        for (Object so : scenarios) {
            Map<String, Object> sc = (Map<String, Object>) so;
            String name = (String) sc.get("name");
            List<Envelope.Object> objs = buildScenarioObjects(corpus, (List<Object>) sc.get("objects"));
            List<Envelope.DuplicationFinding> findings = Envelope.detectSignerDuplication(objs);
            List<Object> expect = (List<Object>) sc.get("expect");
            if (findings.size() != expect.size()) {
                throw new AssertionError(name + " findings count: got " + findings.size() + " want " + expect.size());
            }
            for (int i = 0; i < expect.size(); i++) {
                Map<String, Object> want = (Map<String, Object>) expect.get(i);
                Envelope.DuplicationFinding got = findings.get(i);
                String wantSignerHex = (String) want.get("signer_hex");
                if (!Hex.encode(got.signer).equals(wantSignerHex)) {
                    throw new AssertionError(name + " finding " + i + " signer: got " + Hex.encode(got.signer) + " want " + wantSignerHex);
                }
                long wantCounter = (Long) want.get("counter");
                if (got.counter != wantCounter) {
                    throw new AssertionError(name + " finding " + i + " counter: got " + got.counter + " want " + wantCounter);
                }
                List<Object> idsHex = (List<Object>) want.get("ids_hex");
                if (got.ids.size() != idsHex.size()) {
                    throw new AssertionError(name + " finding " + i + " ids count: got " + got.ids.size() + " want " + idsHex.size());
                }
                for (int j = 0; j < idsHex.size(); j++) {
                    String wantIdHex = (String) idsHex.get(j);
                    if (!Hex.encode(got.ids.get(j)).equals(wantIdHex)) {
                        throw new AssertionError(name + " finding " + i + " id " + j + ": got " + Hex.encode(got.ids.get(j)) + " want " + wantIdHex);
                    }
                }
            }
        }
    }

    // case (a): a single sequence (one object per value) MUST NOT be flagged -- detection requires
    // two conflicting sequences to physically meet.
    private static void testDetectOneSequenceNotFlagged(Map<String, Object> corpus) {
        Envelope.Object one = baseObject(corpus, null, "holder");
        one.setSignerCounter(5);
        List<Envelope.DuplicationFinding> f = Envelope.detectSignerDuplication(List.of(one));
        if (!f.isEmpty()) {
            throw new AssertionError("one sequence alone must not be flagged, got " + f.size() + " finding(s)");
        }
        List<Envelope.Object> seqObjs = new ArrayList<>();
        String[] bodies = {"s1", "s2", "s3"};
        for (int i = 0; i < bodies.length; i++) {
            Envelope.Object o = baseObject(corpus, null, bodies[i]);
            o.setSignerCounter(i + 1);
            seqObjs.add(o);
        }
        f = Envelope.detectSignerDuplication(seqObjs);
        if (!f.isEmpty()) {
            throw new AssertionError("an honest forward-only sequence must not be flagged, got " + f.size() + " finding(s)");
        }
    }

    /**
     * MUTATION ANCHOR: case (b) -- two DISTINCT objects, SAME signer id, SAME counter value,
     * presented TOGETHER -&gt; flagged once, surfacing BOTH content ids. Widening the {@code
     * idset.size() &lt; 2} guard in {@code Envelope.detectSignerDuplication} so it is always true
     * (never flags) neuters detection entirely and flips this test pass-&gt;fail.
     */
    private static void testDetectTwoConflictingFlagged(Map<String, Object> corpus) {
        Envelope.Object holder = baseObject(corpus, null, "holder");
        holder.setSignerCounter(5);
        Envelope.Object thief = baseObject(corpus, null, "thief");
        thief.setSignerCounter(5);

        List<Envelope.DuplicationFinding> f = Envelope.detectSignerDuplication(List.of(holder, thief));
        if (f.size() != 1) {
            throw new AssertionError("two conflicting sequences must be flagged once, got " + f.size());
        }
        if (f.get(0).counter != 5) {
            throw new AssertionError("finding counter: got " + f.get(0).counter + " want 5");
        }
        if (f.get(0).ids.size() != 2) {
            throw new AssertionError("both conflicting content ids must be surfaced, got " + f.get(0).ids.size());
        }
        byte[] hid = holder.contentId();
        byte[] tid = thief.contentId();
        boolean sawHolder = false;
        boolean sawThief = false;
        for (byte[] id : f.get(0).ids) {
            if (java.util.Arrays.equals(id, hid)) {
                sawHolder = true;
            }
            if (java.util.Arrays.equals(id, tid)) {
                sawThief = true;
            }
        }
        if (!sawHolder || !sawThief) {
            throw new AssertionError("the finding must surface both the holder's and the thief's content ids");
        }
    }

    // case (c): two objects from one signer at DIFFERENT (forward-only consistent) positions are not
    // flagged; nor are two different signers at one position.
    private static void testDetectForwardOnlyConsistentNotFlagged(Map<String, Object> corpus) {
        Envelope.Object a5 = baseObject(corpus, null, "holder");
        a5.setSignerCounter(5);
        Envelope.Object a6 = baseObject(corpus, null, "next");
        a6.setSignerCounter(6);
        List<Envelope.DuplicationFinding> f = Envelope.detectSignerDuplication(List.of(a5, a6));
        if (!f.isEmpty()) {
            throw new AssertionError("forward-only-consistent sequence must not be flagged, got " + f.size());
        }

        // per-signer: SIGNER_B at position 5 does not conflict with SIGNER_A at position 5.
        Envelope.Object b5 = baseObject(corpus, "5349474e45525f42", "other");
        b5.setSignerCounter(5);
        f = Envelope.detectSignerDuplication(List.of(a5, b5));
        if (!f.isEmpty()) {
            throw new AssertionError("different signers at one value must not be flagged, got " + f.size());
        }
    }

    // ---- recheck: structural checks (no shared corpus -- a pure ext/cext accessor + registry) ----

    private static boolean hasEntry(Cbor.M m, int key, long value) {
        if (m == null) {
            return false;
        }
        for (Cbor.Pair pr : m.pairs) {
            if (pr.k instanceof Cbor.U u && u.v == key && pr.val instanceof Cbor.U v && v.v == value) {
                return true;
            }
        }
        return false;
    }

    /**
     * Proves setRecheck/recheck carry the value, that the field is OPTIONAL, that non-critical places
     * the entry literally in ext (field 11) and critical literally in cext (field 12), that cext
     * takes precedence when both carry the key, and that a second setRecheck on the same target
     * REPLACES rather than duplicates the entry.
     */
    private static void testRecheckRoundTripAndPlacement(Map<String, Object> corpus) {
        Envelope.Object o = baseObject(corpus, null, null);
        Envelope.RecheckInfo r = o.recheck();
        if (r.present) {
            throw new AssertionError("fresh object must have no recheck procedure named");
        }

        // non-critical placement -> ext (field 11, may-ignore).
        o.setRecheck(Envelope.RECHECK_WALK_CAUSES, false);
        r = o.recheck();
        if (!r.present || r.critical || r.id != Envelope.RECHECK_WALK_CAUSES) {
            throw new AssertionError("non-critical recheck round-trip wrong: present=" + r.present + " critical=" + r.critical + " id=" + r.id);
        }
        if (!hasEntry(o.ext, Envelope.RECHECK_KEY, Envelope.RECHECK_WALK_CAUSES)) {
            throw new AssertionError("non-critical recheck entry must be literally present in ext (field 11)");
        }
        if (o.cext != null) {
            throw new AssertionError("non-critical setRecheck must not touch cext");
        }

        // critical placement -> cext (field 12, must-understand); cext takes precedence over the
        // still-present ext entry set above (SetRecheck writes only its own target map).
        o.setRecheck(Envelope.RECHECK_VERIFY_COSE_SIGN1, true);
        r = o.recheck();
        if (!r.present || !r.critical || r.id != Envelope.RECHECK_VERIFY_COSE_SIGN1) {
            throw new AssertionError("critical recheck round-trip wrong (cext must take precedence): present=" + r.present + " critical=" + r.critical + " id=" + r.id);
        }
        if (!hasEntry(o.cext, Envelope.RECHECK_KEY, Envelope.RECHECK_VERIFY_COSE_SIGN1)) {
            throw new AssertionError("critical recheck entry must be literally present in cext (field 12)");
        }
        if (!hasEntry(o.ext, Envelope.RECHECK_KEY, Envelope.RECHECK_WALK_CAUSES)) {
            throw new AssertionError("the earlier ext entry must remain untouched");
        }

        // replace-not-append: setting critical again replaces the existing cext entry, not append.
        o.setRecheck(Envelope.RECHECK_REPLAY_CONSUME_CHECK, true);
        int cextCount = 0;
        for (Cbor.Pair pr : o.cext.pairs) {
            if (pr.k instanceof Cbor.U u && u.v == Envelope.RECHECK_KEY) {
                cextCount++;
            }
        }
        if (cextCount != 1) {
            throw new AssertionError("setRecheck must replace an existing entry, not append a duplicate; found " + cextCount);
        }
        r = o.recheck();
        if (r.id != Envelope.RECHECK_REPLAY_CONSUME_CHECK) {
            throw new AssertionError("replaced recheck id wrong: got " + r.id);
        }
    }

    /**
     * The closed re-check procedure registry is {1,2,3,4} (design.md §2.5); 0, 5, and a huge
     * wrapped-negative uint64 (2^64-1) are outside it.
     */
    private static void testIsKnownRecheckProcedureBoundaries() {
        long[] known = {Envelope.RECHECK_RECOMPUTE_CONTENT_ID, Envelope.RECHECK_VERIFY_COSE_SIGN1,
                Envelope.RECHECK_WALK_CAUSES, Envelope.RECHECK_REPLAY_CONSUME_CHECK};
        for (long id : known) {
            if (!Envelope.isKnownRecheckProcedure(id)) {
                throw new AssertionError("id " + id + " must be a known recheck procedure");
            }
        }
        long[] unknown = {0L, 5L, -1L}; // -1L is the uint64 bit pattern for 2^64-1
        for (long id : unknown) {
            if (Envelope.isKnownRecheckProcedure(id)) {
                throw new AssertionError("id " + id + " must NOT be a known recheck procedure");
            }
        }
    }

    private static void eq(String what, Object want, Object got) {
        if (!want.equals(got)) {
            throw new AssertionError(what + " mismatch\n  want=" + want + "\n  got =" + got);
        }
    }

    public static void main(String[] args) throws IOException {
        Path p = findVector();
        if (p == null) {
            System.out.println("SKIP: vectors/signer_counter/cases.json not found");
            return;
        }
        String rawJson = Files.readString(p, StandardCharsets.UTF_8);
        @SuppressWarnings("unchecked")
        Map<String, Object> corpus = (Map<String, Object>) Json.parse(rawJson);

        testMatchesOracle(corpus, rawJson);
        System.out.println("  ok  signer-counter matches oracle (7 cases + 1 negative: byte parity + verdict + read-back)");
        testUnderSignature(corpus);
        System.out.println("  ok  signer-counter under signature (splice rejected)");
        testReaderRoundTrip(corpus);
        System.out.println("  ok  signer-counter reader round-trip (optional; present-zero distinct from absent)");
        testAbsentValidates(corpus);
        System.out.println("  ok  signer-counter absent validates");
        testDetectMatchesOracle(corpus);
        System.out.println("  ok  DetectSignerDuplication matches oracle (8 scenarios)");
        testDetectOneSequenceNotFlagged(corpus);
        System.out.println("  ok  one sequence alone / honest forward-only sequence not flagged");
        testDetectTwoConflictingFlagged(corpus);
        System.out.println("  ok  two conflicting sequences flagged once, both ids surfaced [mutation anchor]");
        testDetectForwardOnlyConsistentNotFlagged(corpus);
        System.out.println("  ok  forward-only-consistent / cross-signer not flagged");
        testRecheckRoundTripAndPlacement(corpus);
        System.out.println("  ok  recheck round-trip (ext/cext placement, cext precedence, replace-not-append)");
        testIsKnownRecheckProcedureBoundaries();
        System.out.println("  ok  isKnownRecheckProcedure boundaries (1..4 known; 0, 5, uint64-max unknown)");
        System.out.println("RecheckSignerCounterKatTest: PASS");
    }
}
