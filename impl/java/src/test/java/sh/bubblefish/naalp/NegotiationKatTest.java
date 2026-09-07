// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * C20 governed-negotiation + advisory-risk-label + trust-reference conformance for the Java SDK
 * (design.md §23), graded against the shared independent corpus vectors/negotiation/cases.json (NOT
 * produced by this code): the offer/counter/accept and risk-label/labeled-object/trust-ref body,
 * head and content-id byte parity; the causally-linked descent check (an accept descends from its
 * offer along the causes DAG, a non-descended accept is rejected); the closed pre-registered profile
 * set (unknown profile/role rejected); the load-bearing invariant that carrying a risk label NEVER
 * changes an object's effect class (the closed C5 lattice is untouched); the R-2.5 critical-extension
 * rule (unknown critical rejected, unknown non-critical ignored); the checkable-but-never-weighed
 * trust reference (content-id recompute over the external record); and the wire-format edge cases
 * (keys-out-of-order NonCanonical, empty-vs-absent field, minimal, look-alike cross-parse).
 *
 * <p>CORPUS-GRADED (pure bytes / verdicts): every message/label/labeled-object/trust-ref body/head/id,
 * the recognized-set and rejected-set verdicts, the descent verdicts, the effect-class-unchanged
 * table, the edge cases. CRYPTO-DEMONSTRATED IN ISOLATION with real FIPS-204 ML-DSA-65 (via
 * BouncyCastle): the message/labeled-object/trust-ref signature verification, the foreign-key
 * rejection, and the trust-ref end-to-end verify. The three CROSS-LANGUAGE PINS (SHA-384 of the
 * seq-0x11 signed offer, signed read_only-with-labels labeled object, and signed trust-ref A) are the
 * Go+Rust reference constants; asserting them proves Java == Go == Rust byte-identical signed objects.
 *
 * <p>KAT convention (a standalone {@code main} exiting non-zero on any failure); named "…KatTest" so
 * the filename carries the "test" token the ten-language-parity gate indexes. Written test-first:
 * {@link Negotiation} is absent until Negotiation.java lands, so this fails RED with a javac "cannot
 * find symbol Negotiation"; the recorded mutation forces {@link Negotiation#Descends} to return a
 * constant true, which flips the named "non-descended accept rejected NotDescended" check on its
 * assertion.
 */
public final class NegotiationKatTest {
    private static int fails = 0;

    // The Go + Rust reference pins for the deterministic signed offer / labeled / trust-ref (seed=0x11*32).
    private static final String PIN_SIGNED_OFFER_SHA384 =
            "28b5c4e082cfae270bcc0317ef95c88c451f5af7c0d984b2120496afad4870964845b699fe501bb8cd6fab99298729fd";
    private static final String PIN_SIGNED_LABELED_SHA384 =
            "c6f4ba4c897f2f34f075ec504cd8329da7b138764cac5f4b7dcd120348b15d36fab9bf55bb5302dd024f1b077ecc1a0c";
    private static final String PIN_SIGNED_TRUSTREF_SHA384 =
            "80a7d8302bdb01d0fec577a28a4cb0e37c540f80c4d588a8be8324d9e80229fbf3f6a850c6c50d24ca1991e03b84699f";

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    // ---- nesting-aware JSON access (Java has no JSON library) ------------------------------

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("negotiation").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/negotiation/cases.json not found from " + System.getProperty("user.dir"));
    }

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

    // objBlock/arrayBlock anchor on the '{' / '[' that FOLLOWS the key, so a same-named key whose value
    // is a scalar (e.g. "offer": 0 inside the roles sub-map) is skipped and only the object/array value
    // is matched.
    private static String objBlock(String s, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\\{").matcher(s);
        if (!m.find()) {
            throw new AssertionError("obj key not found: " + key);
        }
        int open = m.end() - 1;
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
    }

    private static String arrayBlock(String s, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\\[").matcher(s);
        if (!m.find()) {
            throw new AssertionError("array key not found: " + key);
        }
        int open = m.end() - 1;
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

    private static List<String> topStrings(String arrayInner) {
        List<String> out = new ArrayList<>();
        Matcher m = Pattern.compile("\"([^\"]*)\"").matcher(arrayInner);
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }

    private static List<Long> intList(String arrayInner) {
        List<Long> out = new ArrayList<>();
        Matcher m = Pattern.compile("(\\d+)").matcher(arrayInner);
        while (m.find()) {
            out.add(Long.parseLong(m.group(1)));
        }
        return out;
    }

    private static String field(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("string key not found: " + key);
        }
        return m.group(1);
    }

    private static long intField(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("int key not found: " + key);
        }
        return Long.parseLong(m.group(1));
    }

    private static byte[] hb(String s) {
        return Hex.decode(s);
    }

    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static final int ALG = Cose.ALG_MLDSA65;
    private static final int PROFILE = Cose.PROFILE_PUBLIC;

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    private static String sha384Hex(byte[] b) throws Exception {
        return Hex.encode(MessageDigest.getInstance("SHA-384").digest(b));
    }

    // ---- corpus scopes --------------------------------------------------------------------

    private static String negScope;
    private static String riskScope;
    private static String trustScope;
    private static String edgeScope;
    private static byte[] negId;

    private static List<byte[]> causesOf(String scope) {
        List<byte[]> out = new ArrayList<>();
        for (String h : topStrings(arrayBlock(scope, "causes_hex"))) {
            out.add(hb(h));
        }
        return out;
    }

    private static Negotiation.Message messageFrom(String scope) {
        return new Negotiation.Message(negId, intField(scope, "role"), intField(scope, "profile"), causesOf(scope));
    }

    private static List<Negotiation.RiskLabel> carriedLabels() {
        List<Negotiation.RiskLabel> out = new ArrayList<>();
        for (String c : splitObjects(arrayBlock(riskScope, "carried_on_labeled_objects"))) {
            out.add(new Negotiation.RiskLabel(intField(c, "code"), intField(c, "critical")));
        }
        return out;
    }

    private static List<Negotiation.RiskLabel> labelsFrom(String arrayKey, String scope) {
        List<Negotiation.RiskLabel> out = new ArrayList<>();
        for (String c : splitObjects(arrayBlock(scope, arrayKey))) {
            out.add(new Negotiation.RiskLabel(intField(c, "code"), intField(c, "critical")));
        }
        return out;
    }

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);
        negScope = objBlock(json, "negotiation");
        riskScope = objBlock(json, "risk");
        trustScope = objBlock(json, "trust");
        edgeScope = objBlock(json, "edge_cases");
        negId = hb(field(negScope, "negotiation_hex"));

        byteParity();
        descend();                 // contains the mutation-target assertion
        riskEffectUnchanged();
        criticalExtensionRule();
        trustRef();
        crossLangPins();
        keysOutOfOrder();
        emptyVsAbsentCauses();
        emptyVsAbsentLabels();
        minimal();
        lookAlike();
    }

    // ---- byte parity (design §23) ---------------------------------------------------------

    private static void byteParity() {
        for (String key : new String[]{"offer", "counter", "accept", "offer2", "accept_not_descended",
                "unknown_profile_offer", "unknown_role_message"}) {
            String s = objBlock(negScope, key);
            Negotiation.Message m = messageFrom(s);
            check(key + ".bytes == oracle", Hex.encode(m.bytes()), field(s, "body_hex"));
            check(key + ".head == oracle", Hex.encode(m.head()), field(s, "head_hex"));
            check(key + ".id == oracle", Hex.encode(m.id()), field(s, "id_hex"));
        }

        List<Negotiation.RiskLabel> carried = carriedLabels();
        List<String> los = splitObjects(arrayBlock(riskScope, "labeled_objects"));
        check("labeled_objects count == 4", Integer.toString(los.size()), "4");
        for (String lo : los) {
            long effect = intField(lo, "effect");
            String with = objBlock(lo, "with_labels");
            String without = objBlock(lo, "without_labels");
            Negotiation.LabeledObject wl = new Negotiation.LabeledObject(effect, carried);
            check("labeled[" + effect + "] with-labels body == oracle", Hex.encode(wl.bytes()), field(with, "body_hex"));
            check("labeled[" + effect + "] with-labels head == oracle", Hex.encode(wl.head()), field(with, "head_hex"));
            check("labeled[" + effect + "] with-labels id == oracle", Hex.encode(wl.id()), field(with, "id_hex"));
            Negotiation.LabeledObject nl = new Negotiation.LabeledObject(effect, new ArrayList<>());
            check("labeled[" + effect + "] without-labels body == oracle", Hex.encode(nl.bytes()), field(without, "body_hex"));
        }

        String refA = objBlock(trustScope, "ref_a");
        Negotiation.TrustRef ta = new Negotiation.TrustRef(hb(field(trustScope, "registry_a_hex")),
                hb(field(trustScope, "reference_hex")), hb(field(trustScope, "subject_hex")));
        check("trust ref A body == oracle", Hex.encode(ta.bytes()), field(refA, "body_hex"));
        check("trust ref A head == oracle", Hex.encode(ta.head()), field(refA, "head_hex"));
        check("trust ref A id == oracle", Hex.encode(ta.id()), field(refA, "id_hex"));
        String refB = objBlock(trustScope, "ref_b");
        Negotiation.TrustRef tb = new Negotiation.TrustRef(hb(field(trustScope, "registry_b_hex")),
                hb(field(trustScope, "reference_hex")), hb(field(trustScope, "subject_hex")));
        check("trust ref B body == oracle", Hex.encode(tb.bytes()), field(refB, "body_hex"));
    }

    // ---- governed negotiation: descent + closed profile/role sets (mutation target) -------

    private static void descend() {
        byte[] seed = seed(0x11);
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", seed);
        byte[] fpk = Cose.mldsaKeygen("ML-DSA-65", seed(0x22));

        Negotiation.Message offer = messageFrom(objBlock(negScope, "offer"));
        Negotiation.Message counter = messageFrom(objBlock(negScope, "counter"));
        Negotiation.Message accept = messageFrom(objBlock(negScope, "accept"));
        Negotiation.Message offer2 = messageFrom(objBlock(negScope, "offer2"));
        Negotiation.Message acceptBad = messageFrom(objBlock(negScope, "accept_not_descended"));

        // The causes wiring reproduces the oracle: counter -> offer, accept -> counter, acceptBad -> offer2.
        check("counter chains onto the offer", Hex.encode(counter.causes.get(0)), Hex.encode(offer.id()));
        check("accept chains onto the counter", Hex.encode(accept.causes.get(0)), Hex.encode(counter.id()));
        check("acceptBad chains onto offer2", Hex.encode(acceptBad.causes.get(0)), Hex.encode(offer2.id()));

        // Sign & verify every message under the real key; the foreign key is rejected BadSignature.
        List<Negotiation.Message> all = List.of(offer, counter, accept, offer2, acceptBad);
        List<Negotiation.Message> verified = new ArrayList<>();
        for (Negotiation.Message m : all) {
            byte[] obj = Negotiation.signMessage(m, ALG, seed);
            Negotiation.Message vm = Negotiation.verifyMessage(obj, PROFILE, ALG, pk);
            check("verified " + Negotiation.roleName(m.role) + " id round-trips", Hex.encode(vm.id()), Hex.encode(m.id()));
            check("foreign key rejects " + Negotiation.roleName(m.role),
                    errKind(() -> Negotiation.verifyMessage(obj, PROFILE, ALG, fpk)), "BadSignature");
            verified.add(vm);
        }
        java.util.Map<String, Negotiation.Message> byId = Negotiation.indexById(verified);

        // The honest accept descends from the offer and yields the agreed pre-registered profile.
        check("Descends(accept, offer)", Boolean.toString(Negotiation.Descends(accept, offer, byId)),
                objBlock(negScope, "descends").contains("\"accept_from_offer\": true") ? "true" : "false");
        check("VerifyAccept agreed profile == oracle",
                Long.toString(Negotiation.verifyAccept(accept, offer, byId)), Long.toString(intField(negScope, "agreed_profile")));

        // The bad accept does NOT descend and is rejected NotDescended.  <<< MUTATION TARGET >>>
        check("Descends(acceptBad, offer)", Boolean.toString(Negotiation.Descends(acceptBad, offer, byId)),
                objBlock(negScope, "descends").contains("\"accept_bad_from_offer\": true") ? "true" : "false");
        check("non-descended accept rejected NotDescended",
                errKind(() -> Negotiation.verifyAccept(acceptBad, offer, byId)), "NotDescended");

        // An unknown profile and an unknown role are rejected at verify time.
        byte[] unkProf = Negotiation.signMessage(messageFrom(objBlock(negScope, "unknown_profile_offer")), ALG, seed);
        check("unknown profile rejected UnknownProfile",
                errKind(() -> Negotiation.verifyMessage(unkProf, PROFILE, ALG, pk)), "UnknownProfile");
        byte[] unkRole = Negotiation.signMessage(messageFrom(objBlock(negScope, "unknown_role_message")), ALG, seed);
        check("unknown role rejected UnknownRole",
                errKind(() -> Negotiation.verifyMessage(unkRole, PROFILE, ALG, pk)), "UnknownRole");

        // Presenting a non-offer as the offer, or a non-accept as the accept, is rejected fail-closed.
        check("non-offer-as-offer rejected NotOffer",
                errKind(() -> Negotiation.verifyAccept(accept, counter, byId)), "NotOffer");
        check("non-accept-as-accept rejected NotAccept",
                errKind(() -> Negotiation.verifyAccept(counter, offer, byId)), "NotAccept");

        // The closed pre-registered profile set: an unregistered code is not accepted.
        check("unregistered profile code not accepted",
                Boolean.toString(Negotiation.isRegisteredProfile(intField(negScope, "unknown_profile"))), "false");
        check("baseline registered", Boolean.toString(Negotiation.isRegisteredProfile(Negotiation.PROFILE_BASELINE)), "true");
        check("streaming registered", Boolean.toString(Negotiation.isRegisteredProfile(Negotiation.PROFILE_STREAMING)), "true");
        check("batch registered", Boolean.toString(Negotiation.isRegisteredProfile(Negotiation.PROFILE_BATCH)), "true");
    }

    // ---- the load-bearing C20 invariant: a risk label never changes the effect class ------

    private static void riskEffectUnchanged() {
        List<Negotiation.RiskLabel> labels = carriedLabels();
        boolean sawGating = false;
        for (Negotiation.RiskLabel l : labels) {
            Negotiation.RiskClassResult c = Negotiation.riskClassOf(l.code);
            if (c.known && c.riskClass == Negotiation.CLASS_GATING) {
                sawGating = true;
            }
        }
        check("corpus carries a gating label (mutation seam real)", Boolean.toString(sawGating), "true");

        for (String lo : splitObjects(arrayBlock(riskScope, "labeled_objects"))) {
            long effect = intField(lo, "effect");
            long effectClass = intField(lo, "effect_class");
            Negotiation.LabeledObject with = new Negotiation.LabeledObject(effect, labels);
            Negotiation.LabeledObject without = new Negotiation.LabeledObject(effect, new ArrayList<>());
            long want = Policy.normalizeEffect(effect);
            check("effect " + effect + " with-labels class == normalized", Long.toString(with.effectClass()), Long.toString(want));
            check("effect " + effect + " without-labels class == normalized", Long.toString(without.effectClass()), Long.toString(want));
            check("effect " + effect + " labels do not change class",
                    Long.toString(with.effectClass()), Long.toString(without.effectClass()));
            check("effect " + effect + " class == oracle", Long.toString(with.effectClass()), Long.toString(effectClass));
        }
        // Concretely: a read_only object carrying the gating "sensitive" (critical) label is still read_only.
        Negotiation.LabeledObject sensitive = new Negotiation.LabeledObject(Policy.READ_ONLY,
                List.of(new Negotiation.RiskLabel(Negotiation.RISK_SENSITIVE, 1)));
        check("read_only + sensitive stays read_only", Long.toString(sensitive.effectClass()), Long.toString(Policy.READ_ONLY));
    }

    // ---- the R-2.5 critical-extension rule over risk labels -------------------------------

    private static void criticalExtensionRule() {
        for (String e : splitObjects(arrayBlock(riskScope, "vocabulary"))) {
            long code = intField(e, "code");
            Negotiation.RiskClassResult c = Negotiation.riskClassOf(code);
            check("vocab code " + code + " registered", Boolean.toString(c.known), "true");
            check("vocab code " + code + " class name == oracle", Negotiation.riskClassName(c.riskClass), field(e, "class"));
        }
        check("extensible range start == oracle", Long.toString(Negotiation.EXTENSIBLE_RANGE_START),
                Long.toString(intField(riskScope, "extensible_range_start")));

        String validate = objBlock(riskScope, "validate");
        String recSet = objBlock(validate, "recognized_set");
        List<Negotiation.RiskLabel> carried = labelsFrom("carried", recSet);
        List<Negotiation.RiskLabel> got = Negotiation.validateLabels(carried);
        List<Long> wantCodes = intList(arrayBlock(recSet, "recognized_codes"));
        check("recognized-set size == oracle", Integer.toString(got.size()), Integer.toString(wantCodes.size()));
        for (int i = 0; i < got.size(); i++) {
            check("recognized[" + i + "] code == oracle", Long.toString(got.get(i).code), Long.toString(wantCodes.get(i)));
            check("recognized[" + i + "] is a standard label", Boolean.toString(Negotiation.isRegisteredRisk(got.get(i).code)), "true");
        }

        String critRej = objBlock(validate, "unknown_critical_rejected");
        List<Negotiation.RiskLabel> critSet = labelsFrom("carried", critRej);
        check("unknown critical label rejected UnknownCriticalRisk",
                errKind(() -> Negotiation.validateLabels(critSet)), "UnknownCriticalRisk");

        // A malformed critical flag (outside {0,1}) is rejected at parse time (no CBOR boolean).
        Negotiation.LabeledObject badFlag = new Negotiation.LabeledObject(0,
                List.of(new Negotiation.RiskLabel(Negotiation.RISK_SENSITIVE, 2)));
        check("malformed critical flag rejected MalformedCriticalFlag",
                errKind(() -> Negotiation.parseLabeledObject(badFlag.bytes())), "MalformedCriticalFlag");
    }

    // ---- trust reference: checkable by content-id recompute, never weighed ----------------

    private static void trustRef() {
        byte[] seed = seed(0x11);
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", seed);
        byte[] fpk = Cose.mldsaKeygen("ML-DSA-65", seed(0x22));
        byte[] record = hb(field(trustScope, "external_record_hex"));
        byte[] reference = hb(field(trustScope, "reference_hex"));
        byte[] tampered = hb(field(trustScope, "tampered_record_hex"));

        Negotiation.TrustRef refA = new Negotiation.TrustRef(hb(field(trustScope, "registry_a_hex")), reference, hb(field(trustScope, "subject_hex")));
        check("trust ref binds the external record", Boolean.toString(refA.bindsRecord(record)), "true");
        check("trust ref does not bind a tampered record", Boolean.toString(refA.bindsRecord(tampered)), "false");

        byte[] obj = Negotiation.signTrustRef(refA, ALG, seed);
        Negotiation.ResolvedTrustRef r = Negotiation.verifyTrustRef(obj, PROFILE, ALG, pk, record);
        check("resolved reference == carried content-id", Hex.encode(r.reference), Hex.encode(reference));
        check("tampered record rejected ReferenceMismatch",
                errKind(() -> Negotiation.verifyTrustRef(obj, PROFILE, ALG, pk, tampered)), "ReferenceMismatch");
        check("foreign key rejects trust ref BadSignature",
                errKind(() -> Negotiation.verifyTrustRef(obj, PROFILE, ALG, fpk, record)), "BadSignature");

        // Two DIFFERENT registries referencing the SAME record both verify — the wire weighs neither.
        Negotiation.TrustRef refB = new Negotiation.TrustRef(hb(field(trustScope, "registry_b_hex")), reference, hb(field(trustScope, "subject_hex")));
        byte[] objB = Negotiation.signTrustRef(refB, ALG, seed);
        Negotiation.ResolvedTrustRef rB = Negotiation.verifyTrustRef(objB, PROFILE, ALG, pk, record);
        check("two registries resolve the same reference", Hex.encode(r.reference), Hex.encode(rB.reference));
        check("the two registries differ (symmetry fixture)",
                Boolean.toString(java.util.Arrays.equals(r.registry, rB.registry)), "false");
    }

    // ---- cross-language signed-object byte parity (Java == Go == Rust) --------------------

    private static void crossLangPins() throws Exception {
        byte[] seed = seed(0x11);
        Negotiation.Message offer = messageFrom(objBlock(negScope, "offer"));
        check("cross-lang signed offer pin (SHA-384)", sha384Hex(Negotiation.signMessage(offer, ALG, seed)), PIN_SIGNED_OFFER_SHA384);

        String lo0 = splitObjects(arrayBlock(riskScope, "labeled_objects")).get(0);
        Negotiation.LabeledObject labeled = new Negotiation.LabeledObject(intField(lo0, "effect"), carriedLabels());
        check("cross-lang signed labeled pin (SHA-384)", sha384Hex(Negotiation.signLabeledObject(labeled, ALG, seed)), PIN_SIGNED_LABELED_SHA384);

        Negotiation.TrustRef tref = new Negotiation.TrustRef(hb(field(trustScope, "registry_a_hex")),
                hb(field(trustScope, "reference_hex")), hb(field(trustScope, "subject_hex")));
        check("cross-lang signed trust-ref pin (SHA-384)", sha384Hex(Negotiation.signTrustRef(tref, ALG, seed)), PIN_SIGNED_TRUSTREF_SHA384);
    }

    // ---- wire-format edge cases -----------------------------------------------------------

    private static void keysOutOfOrder() {
        String koo = objBlock(edgeScope, "keys_out_of_order");
        Negotiation.Message offer = new Negotiation.Message("neg-0001".getBytes(StandardCharsets.UTF_8),
                Negotiation.ROLE_OFFER, Negotiation.PROFILE_BASELINE, new ArrayList<>());
        check("canonical offer body == oracle", Hex.encode(offer.bytes()), field(koo, "canonical_offer_body_hex"));
        check("canonical offer body decodes", errKind(() -> Cbor.decode(hb(field(koo, "canonical_offer_body_hex")))), "no-error");
        check("descending-key body rejected NonCanonical",
                errKind(() -> Cbor.decode(hb(field(koo, "noncanonical_offer_body_hex")))), "NonCanonical");
        check("descending-key body ParseMessage NegMalformed",
                errKind(() -> Negotiation.parseMessage(hb(field(koo, "noncanonical_offer_body_hex")))), "NegMalformed");
    }

    private static void emptyVsAbsentCauses() {
        String c = objBlock(objBlock(edgeScope, "empty_vs_absent"), "causes");
        byte[] neg = "neg-0001".getBytes(StandardCharsets.UTF_8);
        Negotiation.Message empty = new Negotiation.Message(neg, Negotiation.ROLE_OFFER, Negotiation.PROFILE_BASELINE, new ArrayList<>());
        String oneCause = objBlock(c, "one_cause");
        List<byte[]> one = new ArrayList<>();
        one.add(hb(field(oneCause, "cause_hex")));
        Negotiation.Message onem = new Negotiation.Message(neg, Negotiation.ROLE_OFFER, Negotiation.PROFILE_BASELINE, one);
        check("empty-causes body == oracle", Hex.encode(empty.bytes()), field(objBlock(c, "empty_present"), "body_hex"));
        check("one-cause body == oracle", Hex.encode(onem.bytes()), field(oneCause, "body_hex"));
        check("empty and one-cause ids differ", Boolean.toString(java.util.Arrays.equals(empty.id(), onem.id())), "false");
        check("empty-causes id == oracle", Hex.encode(empty.id()), field(objBlock(c, "empty_present"), "id_hex"));
        check("absent causes field rejected NegMalformed",
                errKind(() -> Negotiation.parseMessage(hb(field(objBlock(c, "absent_field"), "body_hex")))), "NegMalformed");
    }

    private static void emptyVsAbsentLabels() {
        String l = objBlock(objBlock(edgeScope, "empty_vs_absent"), "labels");
        Negotiation.LabeledObject empty = new Negotiation.LabeledObject(0, new ArrayList<>());
        String oneLabel = objBlock(l, "one_label");
        Negotiation.LabeledObject onel = new Negotiation.LabeledObject(0,
                List.of(new Negotiation.RiskLabel(intField(oneLabel, "code"), intField(oneLabel, "critical"))));
        check("empty-labels body == oracle", Hex.encode(empty.bytes()), field(objBlock(l, "empty_present"), "body_hex"));
        check("one-label body == oracle", Hex.encode(onel.bytes()), field(oneLabel, "body_hex"));
        check("empty and one-label ids differ", Boolean.toString(java.util.Arrays.equals(empty.id(), onel.id())), "false");
        check("empty-labels id == oracle", Hex.encode(empty.id()), field(objBlock(l, "empty_present"), "id_hex"));
        check("absent labels field rejected NegMalformed",
                errKind(() -> Negotiation.parseLabeledObject(hb(field(objBlock(l, "absent_field"), "body_hex")))), "NegMalformed");
    }

    private static void minimal() {
        String m = objBlock(edgeScope, "minimal");
        String mo = objBlock(m, "offer");
        Negotiation.Message offer = new Negotiation.Message(hb(field(mo, "negotiation_hex")),
                intField(mo, "role"), intField(mo, "profile"), new ArrayList<>());
        check("minimal offer body == oracle", Hex.encode(offer.bytes()), field(mo, "body_hex"));
        check("minimal offer id == oracle", Hex.encode(offer.id()), field(mo, "id_hex"));
        check("minimal offer round-trips", Boolean.toString(Negotiation.parseMessage(offer.bytes()) != null), "true");

        String ml = objBlock(m, "labeled_object");
        Negotiation.LabeledObject lo = new Negotiation.LabeledObject(intField(ml, "effect"), new ArrayList<>());
        check("minimal labeled-object body == oracle", Hex.encode(lo.bytes()), field(ml, "body_hex"));
        check("minimal labeled-object id == oracle", Hex.encode(lo.id()), field(ml, "id_hex"));

        String mt = objBlock(m, "trust_ref");
        Negotiation.TrustRef tr = new Negotiation.TrustRef(new byte[0], new byte[0], new byte[0]);
        check("minimal trust-ref body == oracle", Hex.encode(tr.bytes()), field(mt, "body_hex"));
        check("minimal trust-ref id == oracle", Hex.encode(tr.id()), field(mt, "id_hex"));
        check("minimal trust-ref round-trips", Boolean.toString(Negotiation.parseTrustRef(tr.bytes()) != null), "true");
    }

    private static void lookAlike() {
        String la = objBlock(edgeScope, "look_alike");
        check("trust-ref body fed to parseMessage NegMalformed",
                errKind(() -> Negotiation.parseMessage(hb(field(objBlock(la, "trust_ref_as_message"), "body_hex")))), "NegMalformed");
        check("message body fed to parseTrustRef NegMalformed",
                errKind(() -> Negotiation.parseTrustRef(hb(field(objBlock(la, "message_as_trust_ref"), "body_hex")))), "NegMalformed");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("negotiation conformance (Java) — graded vs vectors/negotiation/cases.json");
        run();
        System.out.println(fails == 0 ? "NegotiationKatTest: PASS" : "NegotiationKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
