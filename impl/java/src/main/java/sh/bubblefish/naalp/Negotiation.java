// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * C20 — governed negotiation, advisory risk labels, and trust references for the Java SDK
 * (design.md §23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4).
 *
 * <p>C20 adds three signed surfaces carried on N-AALP's own signed object. It introduces NO new
 * envelope, encoding, signature, identity, or audit mechanism (R-11.3): each object is an ordinary
 * signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice ({@link Policy}), the T1
 * content-id framing (§2.3), and the §8.2 causal partial order (the {@code causes} field) UNCHANGED.
 *
 * <p>Task 5.1 — governed negotiation: a {@link Message} {1:negotiation,2:role,3:profile,4:causes[]}
 * is one signed step — an OFFER, a COUNTER, or an ACCEPT — CAUSALLY LINKED to its predecessor by
 * content-id in {@code causes}. Each step SELECTS a profile from a CLOSED, pre-registered set: the
 * negotiation selects a pre-registered profile, it never negotiates free-form runtime behaviour
 * (§23.9). An ACCEPT MUST DESCEND from its offer — walking the {@code causes} DAG from the accept must
 * reach the offer's content-id ({@link #verifyAccept}), or it is rejected (NotDescended). An unknown
 * profile is rejected (UnknownProfile); an unknown role is rejected (UnknownRole).
 *
 * <p>Task 5.2 — advisory risk labels: a {@link RiskLabel} {1:code,2:critical} is one carried advisory
 * label; a {@link LabeledObject} {1:effect,2:labels[]} carries an effect together with a set of risk
 * labels. The critical-extension rule (R-2.5) applies: an unknown CRITICAL label is rejected
 * (UnknownCriticalRisk); an unknown NON-critical label is ignored. The load-bearing invariant: adding
 * or carrying a risk label NEVER changes an object's effect class — {@link LabeledObject#effectClass}
 * derives from field 1 (the effect) ALONE (via {@link Policy#normalizeEffect}), so the closed C5
 * lattice is untouched. Risk labels are an advisory dimension, not a fifth effect.
 *
 * <p>Task 5.3 — trust references: a {@link TrustRef} {1:registry,2:reference,3:subject} carries a
 * third-party trust statement as a CHECKABLE signed object — {@code reference} is the T1 content-id of
 * an external registry record. {@link #verifyTrustRef} checks the signature and, given the external
 * bytes, confirms the reference by RECOMPUTING that content-id ({@link TrustRef#bindsRecord}). But NO
 * wire field WEIGHS the statement: there is no score, rank, or ordering on the wire, and this class
 * provides NO scoring function (§23.7).
 *
 * <p>An independent transcription of impl/go/negotiation (cross-checked against
 * impl/python/naalp/negotiation). The byte surfaces are graded against vectors/negotiation/cases.json;
 * the signed-object verifiers run over REAL deterministic ML-DSA-65 COSE_Sign1 objects (via
 * {@link Cose#coseSign1}); the three cross-language pins (SHA-384 of the seed-0x11 signed offer,
 * labeled object, and trust-ref A) prove Java == Go == Rust byte-identical signed objects. Every
 * check is fail-closed (§15): a failing object is rejected whole, returns its named error, and causes
 * no state change.
 */
public final class Negotiation {
    /** The width of a head / content-id digest (SHA-384 = 48 bytes). */
    public static final int HEAD_SIZE = 48;

    private Negotiation() {}

    private static byte[] head(byte[] b) {
        try {
            return java.security.MessageDigest.getInstance("SHA-384").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    /** T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets). */
    private static byte[] contentId(byte[] b) {
        byte[] h = head(b);
        byte[] out = new byte[2 + h.length];
        out[0] = 0x20;
        out[1] = 0x30;
        System.arraycopy(h, 0, out, 2, h.length);
        return out;
    }

    // ---- the COSE_Sign1 signing/verification helpers (reuse the C2 layer, R-11.3) ----------------

    private static byte[] protectedHeader(int alg) {
        return Cbor.encode(new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)))));
    }

    private static int algFromProtected(byte[] prot) {
        Cbor.Value v = Cbor.decode(prot);
        if (v instanceof Cbor.M m) {
            for (Cbor.Pair p : m.pairs) {
                if (p.k instanceof Cbor.U u && u.v == 1) {
                    if (p.val instanceof Cbor.N n) {
                        return (int) n.v;
                    }
                    if (p.val instanceof Cbor.U pu) {
                        return (int) pu.v;
                    }
                }
            }
        }
        throw new NaalpException("NegMalformed", "protected header has no alg");
    }

    /** Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the
     * payload. Check order (mirroring cose.Verify1): alg registry -> profile floor -> key-alg match ->
     * signature. Fail-closed with a named error. */
    private static byte[] verifySign1(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[][] parts = Cose.parseSign1Raw(obj);
        byte[] prot = parts[0];
        byte[] payload = parts[1];
        byte[] sig = parts[2];
        int halg = algFromProtected(prot);
        Cose.AlgLevel al = Cose.algLevel(halg);
        if (!al.known) {
            throw new NaalpException("UnknownAlg", "unregistered alg " + halg);
        }
        if (al.level < Cose.profileMinLevel(profile)) {
            throw new NaalpException("ProfileDowngrade", "signature level below the profile minimum");
        }
        if (halg != alg) {
            throw new NaalpException("KeyAlgMismatch", "alg " + halg + " does not match the verifier key alg " + alg);
        }
        byte[] tbs = Cose.toBeSignedRaw(prot, payload);
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, sig)) {
            throw new NaalpException("BadSignature", "signature does not verify");
        }
        return payload;
    }

    // ==== Task 5.1 — governed negotiation =========================================================

    /** Negotiation message roles (closed set). */
    public static final long ROLE_OFFER = 0;   // the initiating offer (the root of a negotiation; no causes)
    public static final long ROLE_COUNTER = 1;  // a counter-offer chaining onto the offer or a prior counter
    public static final long ROLE_ACCEPT = 2;   // the accept; it MUST descend from its offer

    /** Pre-registered negotiation profiles (the closed set). */
    public static final long PROFILE_BASELINE = 0;   // the baseline capability profile
    public static final long PROFILE_STREAMING = 1;  // the native-streaming capability profile (C9)
    public static final long PROFILE_BATCH = 2;      // the batched-delivery capability profile

    /** The role name ("offer"/"counter"/"accept"), or "unknown" for an out-of-range code. */
    public static String roleName(long r) {
        if (r == ROLE_OFFER) return "offer";
        if (r == ROLE_COUNTER) return "counter";
        if (r == ROLE_ACCEPT) return "accept";
        return "unknown";
    }

    /** Whether r is one of the three defined roles. */
    public static boolean knownRole(long r) {
        return r == ROLE_OFFER || r == ROLE_COUNTER || r == ROLE_ACCEPT;
    }

    /** The profile name, or "unknown" for an unregistered code. */
    public static String profileName(long p) {
        if (p == PROFILE_BASELINE) return "baseline";
        if (p == PROFILE_STREAMING) return "streaming";
        if (p == PROFILE_BATCH) return "batch";
        return "unknown";
    }

    /** Whether p is one of the pre-registered profiles (the closed set). */
    public static boolean isRegisteredProfile(long p) {
        return p == PROFILE_BASELINE || p == PROFILE_STREAMING || p == PROFILE_BATCH;
    }

    /** One signed step of a governed negotiation, causally linked to its predecessor(s) by content-id
     * in {@code causes} (empty for an offer), selecting a pre-registered {@code profile}. */
    public static final class Message {
        public final byte[] negotiation; // opaque negotiation id (ties the exchange together)
        public final long role;          // offer / counter / accept (closed set)
        public final long profile;       // the selected pre-registered profile (closed set)
        public final List<byte[]> causes; // content-ids of predecessor messages (empty for an offer)

        public Message(byte[] negotiation, long role, long profile, List<byte[]> causes) {
            this.negotiation = negotiation.clone();
            this.role = role;
            this.profile = profile;
            this.causes = new ArrayList<>();
            for (byte[] c : causes) {
                this.causes.add(c.clone());
            }
        }

        /** Deterministic-CBOR encoding {1:negotiation,2:role,3:profile,4:causes[]}. */
        public byte[] bytes() {
            List<Cbor.Value> arr = new ArrayList<>(causes.size());
            for (byte[] c : causes) {
                arr.add(new Cbor.B(c));
            }
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(negotiation)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(role)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(profile)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.A(arr)))));
        }

        /** The message's SHA-384 head (48 octets). */
        public byte[] head() {
            return Negotiation.head(bytes());
        }

        /** The message's T1 content-id (50 octets) — the id a successor names in its causes. */
        public byte[] id() {
            return contentId(bytes());
        }
    }

    /** Reconstruct a Message from its body bytes alone. It does NOT validate role/profile against the
     * closed sets (that is {@link #verifyMessage}'s job). A malformed shape is NegMalformed. */
    public static Message parseMessage(byte[] b) {
        Cbor.M m = decodeMap(b);
        byte[] neg = bstrField(m, 1);
        Long role = uintField(m, 2);
        Long prof = uintField(m, 3);
        Cbor.Value causesV = field(m, 4);
        if (neg == null || role == null || prof == null || !(causesV instanceof Cbor.A arr)) {
            throw new NaalpException("NegMalformed", "body is not a well-formed negotiation message");
        }
        List<byte[]> causes = new ArrayList<>(arr.items.size());
        for (Cbor.Value e : arr.items) {
            if (!(e instanceof Cbor.B bs)) {
                throw new NaalpException("NegMalformed", "a cause is not a byte string");
            }
            causes.add(bs.v);
        }
        return new Message(neg, role, prof, causes);
    }

    /** Produce the tagged COSE_Sign1 object over the Message body (real deterministic ML-DSA). */
    public static byte[] signMessage(Message m, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), m.bytes());
    }

    /** Verify the Message's full signature under the profile, reconstruct it from the signed body
     * bytes, and validate against the closed sets: the role MUST be offer/counter/accept
     * (UnknownRole) and the profile MUST be pre-registered (UnknownProfile). A bad signature is
     * BadSignature. Fail-closed. */
    public static Message verifyMessage(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[] payload = verifySign1(obj, profile, alg, pubkey);
        Message m = parseMessage(payload);
        if (!knownRole(m.role)) {
            throw new NaalpException("UnknownRole", "message role is not offer/counter/accept");
        }
        if (!isRegisteredProfile(m.profile)) {
            throw new NaalpException("UnknownProfile", "message selects a profile outside the closed pre-registered set");
        }
        return m;
    }

    /** Build the content-id (hex) -> Message index the descent walk resolves predecessors through. */
    public static Map<String, Message> indexById(List<Message> msgs) {
        Map<String, Message> byId = new HashMap<>(msgs.size() * 2);
        for (Message m : msgs) {
            byId.put(Hex.encode(m.id()), m);
        }
        return byId;
    }

    /** Reachability walk: whether {@code from} reaches {@code targetId} by following causes edges
     * resolved through {@code byId}. An unresolved cause cannot extend the chain through it, so a
     * forged pointer to an id the verifier never saw does not manufacture descent. Fail-closed. */
    private static boolean descends(Message from, byte[] targetId, Map<String, Message> byId) {
        String target = Hex.encode(targetId);
        Set<String> seen = new HashSet<>();
        List<byte[]> stack = new ArrayList<>(from.causes);
        while (!stack.isEmpty()) {
            byte[] id = stack.remove(stack.size() - 1);
            String k = Hex.encode(id);
            if (k.equals(target)) {
                return true;
            }
            if (!seen.add(k)) {
                continue;
            }
            Message pred = byId.get(k);
            if (pred == null) {
                continue; // an unresolved cause: the chain cannot be walked through it
            }
            stack.addAll(pred.causes);
        }
        return false;
    }

    /** Whether {@code accept} descends from {@code offer} by walking the causes DAG through
     * {@code byId} (a counter or a chain of counters between them is traversed). It is the graph
     * predicate underlying {@link #verifyAccept}; it performs no signature check. */
    public static boolean Descends(Message accept, Message offer, Map<String, Message> byId) {
        return descends(accept, offer.id(), byId);
    }

    /** Check an accept against its offer over a set of verified messages, fail-closed: (1) offer must
     * be a genuine offer selecting a pre-registered profile (NotOffer / UnknownProfile); (2) accept
     * must be an accept selecting a pre-registered profile (NotAccept / UnknownProfile); (3) accept
     * must DESCEND from the offer (NotDescended otherwise). Returns the AGREED profile (the accept's
     * selected pre-registered profile). It authorizes nothing; it accepts or rejects. */
    public static long verifyAccept(Message accept, Message offer, Map<String, Message> byId) {
        if (offer.role != ROLE_OFFER) {
            throw new NaalpException("NotOffer", "the object presented as the offer is not an offer role");
        }
        if (!isRegisteredProfile(offer.profile)) {
            throw new NaalpException("UnknownProfile", "offer selects an unregistered profile");
        }
        if (accept.role != ROLE_ACCEPT) {
            throw new NaalpException("NotAccept", "the object presented as the accept is not an accept role");
        }
        if (!isRegisteredProfile(accept.profile)) {
            throw new NaalpException("UnknownProfile", "accept selects an unregistered profile");
        }
        if (!Descends(accept, offer, byId)) {
            throw new NaalpException("NotDescended", "accept does not descend from its offer along the causes chain");
        }
        return accept.profile;
    }

    // ==== Task 5.2 — advisory risk labels =========================================================

    /** Risk-label advisory classes (a registry attribute of the label code, distinct from critical). */
    public static final long CLASS_INFORMING = 0; // purely informational
    public static final long CLASS_GATING = 1;    // a policy MAY require an additional gate when present

    /** The class name ("gating"/"informing"), or "" for an out-of-range value. */
    public static String riskClassName(long c) {
        if (c == CLASS_INFORMING) return "informing";
        if (c == CLASS_GATING) return "gating";
        return "";
    }

    /** The closed standard risk-label vocabulary codes. */
    public static final long RISK_SENSITIVE = 1;  // gating: the object touches sensitive material
    public static final long RISK_EGRESS = 2;     // gating: the object causes data egress
    public static final long RISK_REVERSIBLE = 3; // informing: the object's effect is reversible

    /** The first code of the private/experimental extensible range (unknown to a lacking verifier). */
    public static final long EXTENSIBLE_RANGE_START = 0x1000;

    /** The result of a vocabulary lookup: the class, and whether the code is a registered standard label. */
    public static final class RiskClassResult {
        public final long riskClass;
        public final boolean known;

        public RiskClassResult(long riskClass, boolean known) {
            this.riskClass = riskClass;
            this.known = known;
        }
    }

    /** Look up a code's vocabulary class and whether it is registered. */
    public static RiskClassResult riskClassOf(long code) {
        if (code == RISK_SENSITIVE) return new RiskClassResult(CLASS_GATING, true);
        if (code == RISK_EGRESS) return new RiskClassResult(CLASS_GATING, true);
        if (code == RISK_REVERSIBLE) return new RiskClassResult(CLASS_INFORMING, true);
        return new RiskClassResult(0, false);
    }

    /** Whether code is in the closed standard vocabulary. */
    public static boolean isRegisteredRisk(long code) {
        return riskClassOf(code).known;
    }

    /** Whether code lies in the private/experimental extensible range. */
    public static boolean inExtensibleRange(long code) {
        return code >= EXTENSIBLE_RANGE_START;
    }

    /** One advisory risk label carried on an object: {@code code} plus the per-carriage must-understand
     * flag {@code critical} (uint 1/0 — the spine carries no CBOR boolean, §3.1). */
    public static final class RiskLabel {
        public final long code;
        public final long critical;

        public RiskLabel(long code, long critical) {
            this.code = code;
            this.critical = critical;
        }

        /** Whether the label is carried critical (must-understand). */
        public boolean isCritical() {
            return critical == 1;
        }

        /** The label's CBOR map {1:code,2:critical}. */
        Cbor.M toMap() {
            return new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(code)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(critical))));
        }

        /** Deterministic-CBOR encoding of the risk-label body. */
        public byte[] bytes() {
            return Cbor.encode(toMap());
        }
    }

    /** Parse one risk-label map, rejecting a malformed shape (NegMalformed) or a critical flag outside
     * {0,1} (MalformedCriticalFlag). Fail-closed. */
    private static RiskLabel riskLabelFromValue(Cbor.Value v) {
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("NegMalformed", "risk label is not a map");
        }
        Long code = uintField(m, 1);
        Long crit = uintField(m, 2);
        if (code == null || crit == null) {
            throw new NaalpException("NegMalformed", "risk label is missing code or critical");
        }
        if (crit > 1) {
            throw new NaalpException("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}");
        }
        return new RiskLabel(code, crit);
    }

    /** Apply the critical-extension rule (R-2.5): return the RECOGNIZED (standard-vocabulary) labels,
     * DROP unknown non-critical labels, and REJECT an unknown CRITICAL label (UnknownCriticalRisk). A
     * critical flag outside {0,1} is MalformedCriticalFlag. It NEVER inspects or returns an effect —
     * risk labels are an advisory dimension, never a fifth effect. Fail-closed. */
    public static List<RiskLabel> validateLabels(List<RiskLabel> labels) {
        List<RiskLabel> recognized = new ArrayList<>(labels.size());
        for (RiskLabel l : labels) {
            if (l.critical > 1) {
                throw new NaalpException("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}");
            }
            if (isRegisteredRisk(l.code)) {
                recognized.add(l);
                continue;
            }
            if (l.isCritical()) {
                throw new NaalpException("UnknownCriticalRisk", "an unknown risk label carried critical is rejected (R-2.5)");
            }
            // unknown non-critical: ignored (dropped from the recognized set)
        }
        return recognized;
    }

    /** A minimal N-AALP object carrying an effect (field 1, C5) and a set of advisory risk labels. It
     * demonstrates — provably, in isolation — the invariant that carrying a risk label NEVER changes
     * the object's effect class. */
    public static final class LabeledObject {
        public final long effect;
        public final List<RiskLabel> labels;

        public LabeledObject(long effect, List<RiskLabel> labels) {
            this.effect = effect;
            this.labels = new ArrayList<>(labels);
        }

        /** Deterministic-CBOR encoding {1:effect,2:labels[]}. */
        public byte[] bytes() {
            List<Cbor.Value> arr = new ArrayList<>(labels.size());
            for (RiskLabel l : labels) {
                arr.add(l.toMap());
            }
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(effect)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.A(arr)))));
        }

        /** The object's SHA-384 head (48 octets). */
        public byte[] head() {
            return Negotiation.head(bytes());
        }

        /** The object's T1 content-id (50 octets). */
        public byte[] id() {
            return contentId(bytes());
        }

        /** The object's C5 effect class, derived from the effect field ALONE and normalized fail-closed
         * (unknown -> destructive, R-6.2). It DELIBERATELY does not consult the risk labels: a risk
         * label is an advisory dimension, never a fifth effect, so the closed lattice is untouched by
         * any label the object carries. This is the load-bearing C20 invariant. */
        public long effectClass() {
            return Policy.normalizeEffect(effect);
        }

        /** Apply the critical-extension rule to the object's carried labels. */
        public List<RiskLabel> validateLabels() {
            return Negotiation.validateLabels(labels);
        }
    }

    /** Reconstruct a LabeledObject from its body bytes alone. A malformed shape is NegMalformed; a bad
     * critical flag propagates MalformedCriticalFlag. */
    public static LabeledObject parseLabeledObject(byte[] b) {
        Cbor.M m = decodeMap(b);
        Long eff = uintField(m, 1);
        Cbor.Value labelsV = field(m, 2);
        if (eff == null || !(labelsV instanceof Cbor.A arr)) {
            throw new NaalpException("NegMalformed", "body is not a well-formed labeled object");
        }
        List<RiskLabel> labels = new ArrayList<>(arr.items.size());
        for (Cbor.Value e : arr.items) {
            labels.add(riskLabelFromValue(e));
        }
        return new LabeledObject(eff, labels);
    }

    /** Produce the tagged COSE_Sign1 object over the LabeledObject body. */
    public static byte[] signLabeledObject(LabeledObject o, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), o.bytes());
    }

    /** Verify the signature under the profile, reconstruct the object, and apply the critical-extension
     * rule to its labels (an unknown critical label is rejected). Returns the verified object; its
     * effectClass is unchanged by any label. Fail-closed. */
    public static LabeledObject verifyLabeledObject(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[] payload = verifySign1(obj, profile, alg, pubkey);
        LabeledObject o = parseLabeledObject(payload);
        validateLabels(o.labels);
        return o;
    }

    // ==== Task 5.3 — trust references (checkable, never weighed) ==================================

    /** Carries a third-party trust statement as a CHECKABLE signed object. {@code registry} is an
     * opaque external-registry identifier; {@code reference} is the T1 content-id of the referenced
     * external record; {@code subject} is the opaque id the statement is about. The wire CARRIES the
     * reference; NO field weighs it. */
    public static final class TrustRef {
        public final byte[] registry;
        public final byte[] reference;
        public final byte[] subject;

        public TrustRef(byte[] registry, byte[] reference, byte[] subject) {
            this.registry = registry.clone();
            this.reference = reference.clone();
            this.subject = subject.clone();
        }

        /** Deterministic-CBOR encoding {1:registry,2:reference,3:subject}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(registry)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(reference)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(subject)))));
        }

        /** The TrustRef's SHA-384 head (48 octets). */
        public byte[] head() {
            return Negotiation.head(bytes());
        }

        /** The TrustRef's own T1 content-id (50 octets). */
        public byte[] id() {
            return contentId(bytes());
        }

        /** Whether the carried {@code reference} is the T1 content-id of {@code record} — i.e. the
         * reference recomputes over the presented external bytes. This is the CHECK a relying party
         * runs to confirm the reference names those exact external bytes; it computes NO score. A
         * changed record yields a different content-id, so this returns false. */
        public boolean bindsRecord(byte[] record) {
            return Arrays.equals(reference, contentId(record));
        }
    }

    /** Reconstruct a TrustRef from its body bytes alone. A malformed shape is NegMalformed. */
    public static TrustRef parseTrustRef(byte[] b) {
        Cbor.M m = decodeMap(b);
        byte[] reg = bstrField(m, 1);
        byte[] ref = bstrField(m, 2);
        byte[] subj = bstrField(m, 3);
        if (reg == null || ref == null || subj == null) {
            throw new NaalpException("NegMalformed", "body is not a well-formed trust ref");
        }
        return new TrustRef(reg, ref, subj);
    }

    /** Produce the tagged COSE_Sign1 object over the TrustRef body. */
    public static byte[] signTrustRef(TrustRef r, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), r.bytes());
    }

    /** A TrustRef that has passed signature verification and (given the external record) the content-id
     * recompute. It carries NO score, rank, or trust weight — the protocol does not weigh trust. */
    public static final class ResolvedTrustRef {
        public final byte[] registry;
        public final byte[] reference;
        public final byte[] subject;

        public ResolvedTrustRef(byte[] registry, byte[] reference, byte[] subject) {
            this.registry = registry.clone();
            this.reference = reference.clone();
            this.subject = subject.clone();
        }
    }

    /** Verify a trust reference end-to-end: (1) verify the signed object under the profile with real
     * crypto; (2) reconstruct it from the signed bytes; and (3) confirm the reference by RECOMPUTING
     * the external record's content-id and requiring it to equal the carried reference
     * (ReferenceMismatch otherwise). Returns the resolved reference — and NOTHING that scores it. Any
     * failure returns its named error and resolves nothing (fail-closed). */
    public static ResolvedTrustRef verifyTrustRef(byte[] obj, int profile, int alg, byte[] pubkey, byte[] externalRecord) {
        byte[] payload = verifySign1(obj, profile, alg, pubkey);
        TrustRef r = parseTrustRef(payload);
        if (!r.bindsRecord(externalRecord)) {
            throw new NaalpException("ReferenceMismatch", "trust-ref reference does not recompute over the presented record");
        }
        return new ResolvedTrustRef(r.registry, r.reference, r.subject);
    }

    // ---- small deterministic-CBOR field accessors (strict decode; NonCanonical propagates) ---------

    private static Cbor.M decodeMap(byte[] b) {
        // The strict decoder throws NonCanonical on a non-canonical body; the negotiation parse layer
        // normalizes any structural decode failure to its own NegMalformed kind (mirroring the Go
        // reference's decodeMap, which returns ok=false — hence ErrMalformed — on any cbor.Decode error).
        Cbor.Value v;
        try {
            v = Cbor.decode(b);
        } catch (NaalpException e) {
            throw new NaalpException("NegMalformed", "body does not decode canonically");
        }
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("NegMalformed", "body is not a map");
        }
        return m;
    }

    private static Cbor.Value field(Cbor.M m, long k) {
        for (Cbor.Pair p : m.pairs) {
            if (p.k instanceof Cbor.U u && u.v == k) {
                return p.val;
            }
        }
        return null;
    }

    private static byte[] bstrField(Cbor.M m, long k) {
        Cbor.Value v = field(m, k);
        return v instanceof Cbor.B b ? b.v : null;
    }

    private static Long uintField(Cbor.M m, long k) {
        Cbor.Value v = field(m, k);
        return v instanceof Cbor.U u ? u.v : null;
    }
}
