// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * N-AALP C21 portable gateway-decision object for the Java SDK (design.md §24; R-GW-1..6).
 *
 * <p>A GatewayDecision is a SIGNED decision object an enforcement gateway of ANY vendor emits as
 * PORTABLE EVIDENCE that it decided about an action. Its load-bearing property, exactly as the C18
 * signed description, is that authority lives in the SIGNED BYTES, never in the connection or the host
 * that served them: {@link #verifyDecision} takes NO serving-party/connection identity, so the same
 * signed decision RE-VERIFIES IDENTICALLY when a party OTHER than the gateway serves it (the
 * third-party re-serve property). It introduces NO new envelope, encoding, signature, identity, or
 * audit mechanism: the object is an ordinary signed N-AALP body (COSE_Sign1), reusing the closed C5
 * effect lattice and the T1 content-id framing unchanged. This is the EVIDENCE FORMAT ONLY — never a
 * policy language. Every check is fail-closed: a failing object is rejected whole, throws its named
 * error, and causes no state change. An independent transcription of impl/go/gateway, graded against
 * the shared vectors/gateway/cases.json.
 *
 * <p>CRYPTO SCOPE: Java signs and verifies with real deterministic FIPS-204 ML-DSA-65 (BouncyCastle),
 * so {@link #signDecision}/{@link #verifyDecision} are the full crypto surface — the signed object is
 * byte-identical to the Go and Rust references, and the third-party re-serve property is demonstrated
 * with real signatures rather than a pure-only stand-in.
 */
public final class Gateway {
    /** The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain. */
    public static final int HEAD_SIZE = 48;

    /** The closed set a gateway may emit; a code outside the set is rejected (UnknownGatewayDecision). */
    public static final long DECISION_ALLOW = 0; // the gateway allows the action
    public static final long DECISION_DENY = 1;  // the gateway denies the action
    public static final long DECISION_HOLD = 2;  // the gateway holds the action pending a further step

    /** decision code -> name (diagnostics); an unknown code has no entry. */
    private static final Map<Long, String> DECISION_NAMES = Map.of(
            DECISION_ALLOW, "allow", DECISION_DENY, "deny", DECISION_HOLD, "hold");

    private Gateway() {}

    /** Reports whether {@code code} is one of the closed decision codes. */
    public static boolean isKnownDecision(long code) {
        return DECISION_NAMES.containsKey(code);
    }

    /** The decision name, or "unknown". */
    public static String decisionName(long code) {
        return DECISION_NAMES.getOrDefault(code, "unknown");
    }

    // ---- ordering-disclosure embeddable group (design.md section 26.3) ------------------------
    //
    // `ordering-disclosure` states what, if anything, establishes decision->effect / record->event
    // ORDER, and from which observational domain. It is carried as a field inside naalp-decision-
    // record (mandatory, field 5), naalp-egress-attestation (optional, field 6), and naalp-gateway-
    // decision (optional, field 5) -- never as a top-level object of its own, so it has no
    // head()/id() of its own; it is embedded directly as a nested CBOR map value.

    /** Ordering-basis codes -- the closed set (design.md section 26.3). */
    public static final long ORDERING_CORRESPONDENCE_ONLY = 0; // the record orders only its own two-party construction (the weakest claim)
    public static final long ORDERING_SINGLE_BOUNDARY = 1;     // one boundary observed both terms and is named
    public static final long ORDERING_EXTERNAL_MECHANISM = 2;  // an external sequencing mechanism is named

    private static final Map<Long, String> ORDERING_BASIS_NAMES = Map.of(
            ORDERING_CORRESPONDENCE_ONLY, "correspondence-only",
            ORDERING_SINGLE_BOUNDARY, "single-boundary",
            ORDERING_EXTERNAL_MECHANISM, "external-mechanism");

    /** Reports whether {@code code} is one of the closed ordering-basis codes. */
    public static boolean isKnownOrderingBasis(long code) {
        return ORDERING_BASIS_NAMES.containsKey(code);
    }

    /** The ordering-basis name, or "unknown". */
    public static String orderingBasisName(long code) {
        return ORDERING_BASIS_NAMES.getOrDefault(code, "unknown");
    }

    /** Enforcement-disposition codes -- the closed set (design.md section 26.4). */
    public static final long ENFORCEMENT_ENFORCED = 1; // the producer states it actually enforces this outcome
    public static final long ENFORCEMENT_ADVISED = 2;  // the producer's own unverifiable self-account that it only advises

    /** Term-disposition kind codes -- reused unchanged from the section 2.5.4 producing-boundary kind vocabulary. */
    public static final long TERM_OBSERVED = 1; // the term was observed first-hand
    public static final long TERM_REPORTED = 2; // the term was reported, relayed from a named source

    /**
     * The embeddable group {1: basis, ?2: boundary, ?3: mechanism, ?4: relation} (design.md section
     * 26.3). It is never a top-level signed object; it is always a field inside another record. The
     * zero value (basis=correspondence-only, no boundary/mechanism/relation) is the weakest claim and
     * is exactly what an ABSENT optional ordering-disclosure field reads as.
     */
    public static final class OrderingDisclosure {
        public final long basis;
        public final byte[] boundary;  // present iff basis == ORDERING_SINGLE_BOUNDARY
        public final byte[] mechanism; // present iff basis == ORDERING_EXTERNAL_MECHANISM
        public final byte[] relation;  // present ONLY when basis == ORDERING_EXTERNAL_MECHANISM (optional even then)

        public OrderingDisclosure(long basis) {
            this(basis, new byte[0], new byte[0], new byte[0]);
        }

        public OrderingDisclosure(long basis, byte[] boundary, byte[] mechanism, byte[] relation) {
            this.basis = basis;
            this.boundary = boundary.clone();
            this.mechanism = mechanism.clone();
            this.relation = relation.clone();
        }

        /** Returns self as a nested CBOR map VALUE (never top-level -- always embedded as a field
         * inside its carrying record, so it has no bytes()/head()/id() of its own). */
        Cbor.M toCbor() {
            List<Cbor.Pair> pairs = new ArrayList<>();
            pairs.add(new Cbor.Pair(new Cbor.U(1), new Cbor.U(basis)));
            if (boundary.length > 0) {
                pairs.add(new Cbor.Pair(new Cbor.U(2), new Cbor.B(boundary)));
            }
            if (mechanism.length > 0) {
                pairs.add(new Cbor.Pair(new Cbor.U(3), new Cbor.B(mechanism)));
            }
            if (relation.length > 0) {
                pairs.add(new Cbor.Pair(new Cbor.U(4), new Cbor.B(relation)));
            }
            return new Cbor.M(pairs);
        }

        /**
         * Checks (a) basis is in the closed set (UnknownOrderingBasis) and (b) the basis-conditioned
         * field well-formedness rule (design.md section 26.3, native and fail-closed -- any violation
         * rejects the whole carrying record, OrderingDisclosureMalformed). UnknownOrderingBasis is
         * checked and thrown FIRST: an out-of-set basis is never additionally reported as malformed.
         */
        public void validate() {
            if (!isKnownOrderingBasis(basis)) {
                throw new NaalpException("UnknownOrderingBasis",
                        "ordering-disclosure basis is outside the closed set correspondence-only/single-boundary/external-mechanism");
            }
            if (basis == ORDERING_CORRESPONDENCE_ONLY) {
                if (boundary.length > 0 || mechanism.length > 0 || relation.length > 0) {
                    throw new NaalpException("OrderingDisclosureMalformed", "correspondence-only requires keys 2/3/4 absent");
                }
            } else if (basis == ORDERING_SINGLE_BOUNDARY) {
                if (boundary.length == 0 || mechanism.length > 0 || relation.length > 0) {
                    throw new NaalpException("OrderingDisclosureMalformed", "single-boundary requires key 2 present, keys 3/4 absent");
                }
            } else if (basis == ORDERING_EXTERNAL_MECHANISM) {
                if (boundary.length > 0 || mechanism.length == 0) {
                    throw new NaalpException("OrderingDisclosureMalformed", "external-mechanism requires key 2 absent, key 3 present");
                }
            }
        }
    }

    /** The weakest ordering-disclosure claim, exactly what a verifier reads for an absent optional
     * ordering-disclosure field. */
    public static OrderingDisclosure correspondenceOnly() {
        return new OrderingDisclosure(ORDERING_CORRESPONDENCE_ONLY);
    }

    /** Decodes a nested ordering-disclosure map value. Returns null on any wrong shape, including an
     * optional key present under the WRONG CBOR type (never silently treated as absent). */
    private static OrderingDisclosure orderingFromCbor(Cbor.Value v) {
        if (!(v instanceof Cbor.M m)) {
            return null;
        }
        Map<Long, Cbor.Value> f = fieldsOf(m);
        Cbor.Value basisV = f.get(1L);
        if (!(basisV instanceof Cbor.U bu)) {
            return null;
        }
        byte[] boundary = new byte[0];
        byte[] mechanism = new byte[0];
        byte[] relation = new byte[0];
        if (f.containsKey(2L)) {
            if (!(f.get(2L) instanceof Cbor.B b)) {
                return null;
            }
            boundary = b.v;
        }
        if (f.containsKey(3L)) {
            if (!(f.get(3L) instanceof Cbor.B b)) {
                return null;
            }
            mechanism = b.v;
        }
        if (f.containsKey(4L)) {
            if (!(f.get(4L) instanceof Cbor.B b)) {
                return null;
            }
            relation = b.v;
        }
        return new OrderingDisclosure(bu.v, boundary, mechanism, relation);
    }

    /** The embeddable group {1: kind, ?2: source} (design.md section 26.4). {@code kind} is carried
     * as a plain uint on the wire (the CDDL does not close its value set the way ordering-basis
     * does), so TermDisposition itself validates no closed set -- only naalp-decision-record's own
     * field-6 key set (the record's own field numbers) is fail-closed (TermDispositionMalformed). */
    public static final class TermDisposition {
        public final long kind;
        public final byte[] source; // present iff kind == TERM_REPORTED

        public TermDisposition(long kind) {
            this(kind, new byte[0]);
        }

        public TermDisposition(long kind, byte[] source) {
            this.kind = kind;
            this.source = source.clone();
        }

        Cbor.M toCbor() {
            List<Cbor.Pair> pairs = new ArrayList<>();
            pairs.add(new Cbor.Pair(new Cbor.U(1), new Cbor.U(kind)));
            if (source.length > 0) {
                pairs.add(new Cbor.Pair(new Cbor.U(2), new Cbor.B(source)));
            }
            return new Cbor.M(pairs);
        }
    }

    private static TermDisposition termDispositionFromCbor(Cbor.Value v) {
        if (!(v instanceof Cbor.M m)) {
            return null;
        }
        Map<Long, Cbor.Value> f = fieldsOf(m);
        Cbor.Value kindV = f.get(1L);
        if (!(kindV instanceof Cbor.U ku)) {
            return null;
        }
        byte[] source = new byte[0];
        if (f.containsKey(2L)) {
            if (!(f.get(2L) instanceof Cbor.B b)) {
                return null;
            }
            source = b.v;
        }
        return new TermDisposition(ku.v, source);
    }

    // ---- ForeignProfilePin: GatewayDecision field 6, R8 -----------------------------------------

    /** The embeddable group {1: id, 2: revision} (naalp-foreign-profile-pin, R8). Present on
     * GatewayDecision field 6 iff the decision was over foreign-protocol evidence: it pins the
     * foreign evidence profile's identifier (an absolute URI) AND the revision pinned at decision
     * time -- binding the reference, not just the class. Both fields are mandatory tstr; the group
     * carries no other keys. It is never a top-level signed object -- always embedded as field 6 of
     * its carrying naalp-gateway-decision, so it has no head()/id() of its own (mirroring
     * OrderingDisclosure). */
    public static final class ForeignProfilePin {
        public final String id;
        public final String revision;
        private final boolean unknownField; // an unrecognized key besides 1/2 was present in the decoded CBOR map

        public ForeignProfilePin(String id, String revision) {
            this(id, revision, false);
        }

        private ForeignProfilePin(String id, String revision, boolean unknownField) {
            this.id = id;
            this.revision = revision;
            this.unknownField = unknownField;
        }

        /** Returns self as a nested CBOR map VALUE {1: tstr(id), 2: tstr(revision)}. */
        Cbor.M toCbor() {
            return new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(id)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(revision))));
        }

        /** Checks the foreign-profile-pin's own well-formedness (R8): both id and revision are
         * mandatory non-empty tstr, and no key besides 1/2 may be present. A missing, empty, or
         * extra field rejects the WHOLE carrying naalp-gateway-decision (ForeignProfileMalformed). */
        public void validate() {
            if (id.isEmpty() || revision.isEmpty() || unknownField) {
                throw new NaalpException("ForeignProfileMalformed",
                        "foreign-profile-pin is not well-formed (id and revision are mandatory tstr, no other keys)");
            }
        }
    }

    /** Decodes a nested foreign-profile-pin map value. Decode is STRUCTURAL only, mirroring
     * orderingFromCbor: a key present under the WRONG CBOR type fails decode (returns null, never
     * silently treated as absent); a key that is simply ABSENT decodes to the empty string, leaving
     * the mandatory-presence check to validate(). A key besides 1/2 marks the group's unknown-field
     * flag, also caught by validate() -- the closed 2-key set is enforced semantically, not by
     * refusing to decode a map that merely carries an extra key. */
    private static ForeignProfilePin foreignProfileFromCbor(Cbor.Value v) {
        if (!(v instanceof Cbor.M m)) {
            return null;
        }
        String id = "";
        String revision = "";
        boolean unknown = false;
        for (Cbor.Pair p : m.pairs) {
            if (p.k instanceof Cbor.U u && u.v == 1L) {
                if (!(p.val instanceof Cbor.T t)) {
                    return null;
                }
                id = t.v;
            } else if (p.k instanceof Cbor.U u && u.v == 2L) {
                if (!(p.val instanceof Cbor.T t)) {
                    return null;
                }
                revision = t.v;
            } else {
                unknown = true;
            }
        }
        return new ForeignProfilePin(id, revision, unknown);
    }

    /**
     * A signed decision an enforcement gateway emits as portable evidence. {@code decision} is the
     * closed-set outcome; {@code action} is the content id of the action decided about; {@code policy}
     * is the opaque deciding-policy identity (a name, not a program); {@code effect} is the action's C5
     * class. {@code ordering} (field 5, R1) and {@code foreignProfile} (field 6, R8) are OPTIONAL:
     * {@code null} reads exactly as an absent field (correspondence-only ordering / no
     * foreign-profile pin) -- never a stronger claim inferred from silence.
     */
    public static final class GatewayDecision {
        public final long decision;
        public final byte[] action;
        public final byte[] policy;
        public final long effect;
        public final OrderingDisclosure ordering;         // OPTIONAL field 5 (R1); null == absent (reads correspondence-only)
        public final ForeignProfilePin foreignProfile;     // OPTIONAL field 6 (R8); non-null iff decided over foreign-protocol evidence

        public GatewayDecision(long decision, byte[] action, byte[] policy, long effect) {
            this(decision, action, policy, effect, null, null);
        }

        public GatewayDecision(long decision, byte[] action, byte[] policy, long effect,
                                OrderingDisclosure ordering, ForeignProfilePin foreignProfile) {
            this.decision = decision;
            this.action = action.clone();
            this.policy = policy.clone();
            this.effect = effect;
            this.ordering = ordering;
            this.foreignProfile = foreignProfile;
        }

        /** Deterministic-CBOR encoding {1: decision, 2: action, 3: policy, 4: effect, ?5: ordering,
         * ?6: foreign-profile}. Fields 5/6 are OMITTED entirely when null (the same omit-when-absent
         * precedent as naalp-decision-record's optional fields 3/6/7). */
        public byte[] bytes() {
            List<Cbor.Pair> pairs = new ArrayList<>(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(decision)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(action)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(policy)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.U(effect))));
            if (ordering != null) {
                pairs.add(new Cbor.Pair(new Cbor.U(5), ordering.toCbor()));
            }
            if (foreignProfile != null) {
                pairs.add(new Cbor.Pair(new Cbor.U(6), foreignProfile.toCbor()));
            }
            return Cbor.encode(new Cbor.M(pairs));
        }

        /** The decision's SHA-384 head (48 octets). */
        public byte[] head() {
            return sha384(bytes());
        }

        /** The decision's T1 content-id: multihash(0x20, 0x30 [48]) || SHA-384(body) (50 octets). */
        public byte[] id() {
            return Cbor.contentId(bytes());
        }

        /** The C5 effect class, normalized fail-closed: an unrecognized value is destructive (R-6.2). */
        public long effectClass() {
            return Policy.normalizeEffect(effect);
        }
    }

    /**
     * A GatewayDecision that has passed signature verification. It carries NOTHING about who served the
     * bytes — the authority is the signature, so the resolved evidence is identical regardless of the
     * serving party (the third-party re-serve property).
     */
    public static final class ResolvedDecision {
        public final long decision;
        public final byte[] action;
        public final byte[] policy;
        public final long effect;

        public ResolvedDecision(long decision, byte[] action, byte[] policy, long effect) {
            this.decision = decision;
            this.action = action;
            this.policy = policy;
            this.effect = effect;
        }
    }

    /**
     * Reconstruct a GatewayDecision from its body bytes alone. It does NOT validate the decision code
     * against the closed set — that is {@link #verifyDecision}'s job — so a decision carrying an unknown
     * code can be represented (and then rejected). Fail-closed on a malformed shape: a non-canonical
     * body, a non-map, or an absent/wrong-typed field 1-4 throws GwMalformed.
     */
    public static GatewayDecision parseDecision(byte[] b) {
        Cbor.Value v;
        try {
            v = Cbor.decode(b);
        } catch (NaalpException e) {
            throw new NaalpException("GwMalformed", "decision body is not well-formed deterministic CBOR");
        }
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("GwMalformed", "decision body is not a map");
        }
        Map<Long, Cbor.Value> fields = fieldsOf(m);
        Cbor.Value dec = fields.get(1L);
        Cbor.Value action = fields.get(2L);
        Cbor.Value pol = fields.get(3L);
        Cbor.Value eff = fields.get(4L);
        if (!(dec instanceof Cbor.U du) || !(action instanceof Cbor.B ab)
                || !(pol instanceof Cbor.B pb) || !(eff instanceof Cbor.U eu)) {
            throw new NaalpException("GwMalformed", "decision body missing or wrong-typed field 1-4");
        }
        OrderingDisclosure ordering = null;
        if (fields.containsKey(5L)) {
            ordering = orderingFromCbor(fields.get(5L));
            if (ordering == null) {
                throw new NaalpException("GwMalformed", "field 5 (ordering) is present but malformed");
            }
        }
        ForeignProfilePin foreignProfile = null;
        if (fields.containsKey(6L)) {
            foreignProfile = foreignProfileFromCbor(fields.get(6L));
            if (foreignProfile == null) {
                throw new NaalpException("GwMalformed", "field 6 (foreign-profile) is present but malformed");
            }
        }
        return new GatewayDecision(du.v, ab.v, pb.v, eu.v, ordering, foreignProfile);
    }

    /** Builds a {@code key -> value} map from a decoded CBOR map's pairs, keyed by the integer value
     * of any {@link Cbor.U} key (mirroring the Go/Python/Rust embedded-field accessor field(m, k): a
     * key that is not a {@link Cbor.U} simply does not match -- it never causes rejection here). The
     * strict canonical decoder has already ruled out duplicate keys, so this is a safe 1:1 mapping. */
    private static Map<Long, Cbor.Value> fieldsOf(Cbor.M m) {
        Map<Long, Cbor.Value> fields = new HashMap<>();
        for (Cbor.Pair p : m.pairs) {
            if (p.k instanceof Cbor.U u) {
                fields.put(u.v, p.val);
            }
        }
        return fields;
    }

    /** The bare {1: alg} COSE_Sign1 protected header (§4), as the reference's cose.Sign1 emits. */
    public static byte[] gatewayProtectedHeader(int alg) {
        return Cbor.encode(new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)))));
    }

    /**
     * Produce the tagged COSE_Sign1 object over the decision body, signed by the gateway with a real
     * deterministic FIPS-204 ML-DSA key derived from {@code seed}.
     */
    public static byte[] signDecision(GatewayDecision d, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), d.bytes());
    }

    /** Read the alg (label 1) value from an encoded protected header. */
    private static int algFromProtected(byte[] prot) {
        Cbor.Value v = Cbor.decode(prot);
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("GwMalformed", "protected header is not a map");
        }
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
        throw new NaalpException("GwMalformed", "protected header has no alg");
    }

    /**
     * Verify a gateway decision end-to-end and return the resolved evidence. It (1) verifies the signed
     * object under the profile with real crypto (signature, alg registry, profile floor) against the
     * gateway's key; (2) reconstructs it from the signed bytes; and (3) validates the decision code
     * against the closed set (UnknownGatewayDecision). It takes NO serving-party or connection identity:
     * the authority is the signature over the bytes, so the same {@code obj} yields an identical
     * ResolvedDecision whether the gateway or an unrelated third party served it. Any failure throws its
     * named error and resolves nothing (fail-closed).
     */
    public static ResolvedDecision verifyDecision(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[][] parts = Cose.parseSign1Raw(obj); // [protected, payload, signature]
        int halg = algFromProtected(parts[0]);
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
        byte[] tbs = Cose.toBeSignedRaw(parts[0], parts[1]);
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, parts[2])) {
            throw new NaalpException("BadSignature", "signature does not verify");
        }
        GatewayDecision d = parseDecision(parts[1]);
        if (!isKnownDecision(d.decision)) {
            throw new NaalpException("UnknownGatewayDecision", "decision code " + d.decision + " outside the closed set");
        }
        if (d.ordering != null) {
            d.ordering.validate();
        }
        if (d.foreignProfile != null) {
            d.foreignProfile.validate();
        }
        return new ResolvedDecision(d.decision, d.action.clone(), d.policy.clone(), Policy.normalizeEffect(d.effect));
    }

    private static byte[] sha384(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    // =================================================================================================
    // Evidence-record family (E6.3 egress-attestation + S1 decision-record + S3 checkpoint), ported
    // from impl/go/gateway/{decision_record,checkpoint,egress_attestation}.go; graded against the
    // shared vectors/{decision_record,checkpoint,egress_attestation}/cases.json plus gateway/
    // cases.json's optional_fields{} block (the ordering-disclosure/term-disposition/foreign-profile-
    // pin groups above already carry R1/R8).
    // =================================================================================================

    // ---- naalp-decision-record: S1, the full governed-decision accountability record -------------
    //
    // A DecisionRecord is the SIGNED record a governed decision point emits that it decided about an
    // action under a CLOSED, uniquely-selected condition set. It carries the T/T+n accountability
    // triple (section 26.1): UNIQUE SELECTION (field 2, the governing set in the clear as content
    // ids); GOVERNED-AT-T (field 3, the naalp-consume-receipt spent at decision time); BINDING-FIXED-
    // BY-T (established off-record by inclusion under a witnessed naalp-checkpoint-root). The record
    // is deliberately CLOCK-FREE: it carries no claimed timestamp anywhere in its own body; both time
    // properties are POSITIONAL, never a self-asserted timestamp.

    /** The governed-decision accountability record (design.md section 26.4). {@code action} is the
     * content id of the action decided about; {@code governing} is the closed governing condition
     * set, content ids, in the clear (may be empty); {@code consume} is OPTIONAL field 3 (content id
     * of the consume-receipt spent at decision time; empty == absent); {@code outcome} is field 4
     * (allow/deny/hold, reuses the closed gw-decision set); {@code ordering} is field 5, MANDATORY
     * (no silent default -- every record states its ordering basis); {@code terms} is OPTIONAL field
     * 6 (per-term observed/reported, keyed by this record's OWN field numbers 1..5; empty == absent);
     * {@code enforcement} is OPTIONAL field 7 (enforced(1)/advised(2); 0 == absent). */
    public static final class DecisionRecord {
        public final byte[] action;
        public final List<byte[]> governing;
        public final byte[] consume;
        public final long outcome;
        public final OrderingDisclosure ordering;
        public final Map<Long, TermDisposition> terms;
        public final long enforcement;

        public DecisionRecord(byte[] action, List<byte[]> governing, long outcome, OrderingDisclosure ordering) {
            this(action, governing, outcome, ordering, new byte[0], Map.of(), 0L);
        }

        public DecisionRecord(byte[] action, List<byte[]> governing, long outcome, OrderingDisclosure ordering,
                               byte[] consume, Map<Long, TermDisposition> terms, long enforcement) {
            this.action = action.clone();
            this.governing = new ArrayList<>();
            for (byte[] g : governing) {
                this.governing.add(g.clone());
            }
            this.consume = consume.clone();
            this.outcome = outcome;
            this.ordering = ordering;
            this.terms = new HashMap<>(terms);
            this.enforcement = enforcement;
        }

        /** Deterministic-CBOR encoding {1:action, 2:governing[], ?3:consume, 4:outcome, 5:ordering,
         * ?6:terms, ?7:enforcement}. Fields 3/6/7 are OMITTED when absent (consume empty, terms
         * empty, enforcement zero) -- the omit-when-absent precedent (naalp-approval ?6:audience). */
        public byte[] bytes() {
            List<Cbor.Pair> pairs = new ArrayList<>();
            pairs.add(new Cbor.Pair(new Cbor.U(1), new Cbor.B(action)));
            List<Cbor.Value> govItems = new ArrayList<>();
            for (byte[] g : governing) {
                govItems.add(new Cbor.B(g));
            }
            pairs.add(new Cbor.Pair(new Cbor.U(2), new Cbor.A(govItems)));
            if (consume.length > 0) {
                pairs.add(new Cbor.Pair(new Cbor.U(3), new Cbor.B(consume)));
            }
            pairs.add(new Cbor.Pair(new Cbor.U(4), new Cbor.U(outcome)));
            pairs.add(new Cbor.Pair(new Cbor.U(5), ordering.toCbor()));
            if (!terms.isEmpty()) {
                List<Cbor.Pair> tpairs = new ArrayList<>();
                for (Map.Entry<Long, TermDisposition> e : terms.entrySet()) {
                    tpairs.add(new Cbor.Pair(new Cbor.U(e.getKey()), e.getValue().toCbor()));
                }
                pairs.add(new Cbor.Pair(new Cbor.U(6), new Cbor.M(tpairs)));
            }
            if (enforcement != 0) {
                pairs.add(new Cbor.Pair(new Cbor.U(7), new Cbor.U(enforcement)));
            }
            return Cbor.encode(new Cbor.M(pairs));
        }

        /** The record's SHA-384 head (48 octets). */
        public byte[] head() {
            return sha384(bytes());
        }

        /** The record's T1 content-id (50 octets). */
        public byte[] id() {
            return Cbor.contentId(bytes());
        }
    }

    /**
     * Reconstruct a DecisionRecord from its body bytes alone. It performs ONLY structural checks
     * (mandatory-field presence and CBOR type); it does NOT validate the outcome against the closed
     * gw-decision set, the ordering disclosure's basis-conditioned well-formedness, the deny/hold-
     * with-consume rule, or the terms key set -- see {@link #validateDecisionRecord}. Fail-closed on
     * any malformed shape (DecisionMalformed).
     */
    public static DecisionRecord parseDecisionRecord(byte[] b) {
        Cbor.Value v;
        try {
            v = Cbor.decode(b);
        } catch (NaalpException e) {
            throw new NaalpException("DecisionMalformed", "decision-record body is not well-formed deterministic CBOR");
        }
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("DecisionMalformed", "decision-record body is not a map");
        }
        Map<Long, Cbor.Value> fields = fieldsOf(m);
        Cbor.Value actionV = fields.get(1L);
        Cbor.Value govV = fields.get(2L);
        if (!(actionV instanceof Cbor.B ab) || !(govV instanceof Cbor.A ga)) {
            throw new NaalpException("DecisionMalformed", "missing or wrong-typed field 1/2");
        }
        List<byte[]> governing = new ArrayList<>();
        for (Cbor.Value item : ga.items) {
            if (!(item instanceof Cbor.B gb)) {
                throw new NaalpException("DecisionMalformed", "governing array element not a bstr");
            }
            governing.add(gb.v);
        }
        byte[] consume = new byte[0];
        if (fields.containsKey(3L)) {
            if (!(fields.get(3L) instanceof Cbor.B cb)) {
                throw new NaalpException("DecisionMalformed", "field 3 (consume) wrong type");
            }
            consume = cb.v;
        }
        Cbor.Value outcomeV = fields.get(4L);
        if (!(outcomeV instanceof Cbor.U ou)) {
            throw new NaalpException("DecisionMalformed", "missing or wrong-typed field 4 (outcome)");
        }
        if (!fields.containsKey(5L)) {
            throw new NaalpException("DecisionMalformed", "missing mandatory field 5 (ordering)");
        }
        OrderingDisclosure ordering = orderingFromCbor(fields.get(5L));
        if (ordering == null) {
            throw new NaalpException("DecisionMalformed", "field 5 (ordering) malformed");
        }
        Map<Long, TermDisposition> terms = new HashMap<>();
        if (fields.containsKey(6L)) {
            if (!(fields.get(6L) instanceof Cbor.M tm)) {
                throw new NaalpException("DecisionMalformed", "field 6 (terms) wrong type");
            }
            for (Cbor.Pair p : tm.pairs) {
                if (!(p.k instanceof Cbor.U ku)) {
                    throw new NaalpException("DecisionMalformed", "terms map key not a uint");
                }
                TermDisposition td = termDispositionFromCbor(p.val);
                if (td == null) {
                    throw new NaalpException("DecisionMalformed", "terms map value malformed");
                }
                terms.put(ku.v, td);
            }
        }
        long enforcement = 0;
        if (fields.containsKey(7L)) {
            if (!(fields.get(7L) instanceof Cbor.U eu)) {
                throw new NaalpException("DecisionMalformed", "field 7 (enforcement) wrong type");
            }
            enforcement = eu.v;
        }
        return new DecisionRecord(ab.v, governing, ou.v, ordering, consume, terms, enforcement);
    }

    /** Reports whether {@code k} is one of the record's own field numbers 1..5 -- the only valid keys
     * for the field-6 terms map (design.md section 26.4; TermDispositionMalformed otherwise). */
    private static boolean validDecisionRecordTermKey(long k) {
        return k >= 1 && k <= 5;
    }

    /**
     * Performs the semantic, closed-set, and native well-formedness checks {@link
     * #parseDecisionRecord} deliberately does not (mirroring {@link #verifyDecision}'s parse/verify
     * split):
     * <ol>
     *   <li>Outcome must be in the closed gw-decision set (UnknownGatewayDecision).</li>
     *   <li>Ordering must satisfy its basis-conditioned well-formedness rule (UnknownOrderingBasis /
     *       OrderingDisclosureMalformed) -- checked BEFORE the deny/hold-consume rule so a record
     *       whose ordering is itself malformed is never additionally reported as a consume
     *       violation.</li>
     *   <li>A deny/hold outcome carrying a field-3 consume reference is rejected in full
     *       (DecisionMalformed) -- nothing was consumed, so a value here would assert authority
     *       spent for an action the record's own outcome says was not taken.</li>
     *   <li>Every terms map key must be one of the record's own field numbers 1..5
     *       (TermDispositionMalformed).</li>
     * </ol>
     */
    public static void validateDecisionRecord(DecisionRecord d) {
        if (!isKnownDecision(d.outcome)) {
            throw new NaalpException("UnknownGatewayDecision", "decision-record outcome " + d.outcome + " outside the closed set");
        }
        d.ordering.validate();
        if (d.outcome != DECISION_ALLOW && d.consume.length > 0) {
            throw new NaalpException("DecisionMalformed", "a deny/hold outcome must not carry a field-3 consume reference");
        }
        for (Long k : d.terms.keySet()) {
            if (!validDecisionRecordTermKey(k)) {
                throw new NaalpException("TermDispositionMalformed", "a terms map key is outside the record's own field set 1..5");
            }
        }
    }

    /** Produce the tagged COSE_Sign1 object over the record body, signed by the governed decision point. */
    public static byte[] signDecisionRecord(DecisionRecord d, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), d.bytes());
    }

    /** A DecisionRecord that has passed signature verification and full semantic validation. */
    public static final class ResolvedDecisionRecord {
        public final byte[] action;
        public final List<byte[]> governing;
        public final byte[] consume;
        public final long outcome;
        public final OrderingDisclosure ordering;
        public final Map<Long, TermDisposition> terms;
        public final long enforcement;

        public ResolvedDecisionRecord(byte[] action, List<byte[]> governing, byte[] consume, long outcome,
                                       OrderingDisclosure ordering, Map<Long, TermDisposition> terms, long enforcement) {
            this.action = action;
            this.governing = governing;
            this.consume = consume;
            this.outcome = outcome;
            this.ordering = ordering;
            this.terms = terms;
            this.enforcement = enforcement;
        }
    }

    /**
     * Verify a decision record end-to-end: (1) the signed object under the profile with real crypto;
     * (2) structural reconstruction ({@link #parseDecisionRecord}); and (3) full semantic validation
     * ({@link #validateDecisionRecord}). It takes no serving-party or connection identity -- the
     * authority is the signature over the bytes, mirroring {@link #verifyDecision}. Any failure
     * throws its named error and resolves nothing (fail-closed).
     */
    public static ResolvedDecisionRecord verifyDecisionRecord(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[][] parts = Cose.parseSign1Raw(obj);
        int halg = algFromProtected(parts[0]);
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
        byte[] tbs = Cose.toBeSignedRaw(parts[0], parts[1]);
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, parts[2])) {
            throw new NaalpException("BadSignature", "signature does not verify");
        }
        DecisionRecord d = parseDecisionRecord(parts[1]);
        validateDecisionRecord(d);
        return new ResolvedDecisionRecord(d.action.clone(), new ArrayList<>(d.governing), d.consume.clone(),
                d.outcome, d.ordering, d.terms, d.enforcement);
    }

    // ---- naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof: S3 -----------------
    //
    // S3 is the neither-party anchor for the BINDING-FIXED-BY-T leg of the accountability triple
    // (design.md section 26.5). Tree construction follows RFC 9162
    // (https://www.rfc-editor.org/rfc/rfc9162.html) section 2.1 EXACTLY, SHA-384-profiled: leaf hash
    // = HASH(0x00 || leaf); interior node hash = HASH(0x01 || left || right); MTH({}) = HASH() (the
    // empty hash); MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the
    // largest power of two k < n. Section 2.1.2's PATH(m, D[n]) recursion (leaf-to-root sibling
    // order) generates the audit path; section 2.1.3.1's inverse recursion recomputes the root from
    // (leaf, index, size, path) and compares against the named root (InclusionProofInvalid on
    // mismatch, fail-closed).

    /** The width of a head/content-id digest for {@link #genesisPrev}. */
    public static byte[] genesisPrev() {
        return new byte[HEAD_SIZE];
    }

    /** A log operator's signed Merkle tree head over a leaf set of record content ids (design.md
     * section 26.5). */
    public static final class CheckpointRoot {
        public final byte[] log;
        public final long size;
        public final byte[] root;
        public final byte[] prev;
        public final long at;

        public CheckpointRoot(byte[] log, long size, byte[] root, byte[] prev, long at) {
            this.log = log.clone();
            this.size = size;
            this.root = root.clone();
            this.prev = prev.clone();
            this.at = at;
        }

        /** Deterministic-CBOR encoding {1:log, 2:size, 3:root, 4:prev, 5:at}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(log)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(size)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(root)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(prev)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(at)))));
        }

        /** The checkpoint's SHA-384 head (48 octets) -- the {@code prev} the NEXT checkpoint chains from. */
        public byte[] head() {
            return sha384(bytes());
        }

        /** The checkpoint's T1 content-id (50 octets) -- what an inclusion proof's {@code root} field
         * and a witness-cosign's {@code root} field both name. */
        public byte[] id() {
            return Cbor.contentId(bytes());
        }
    }

    /** Reconstruct a CheckpointRoot from its body bytes alone. Fail-closed on any malformed shape
     * (CheckpointMalformed): every one of the five fields is mandatory. */
    public static CheckpointRoot parseCheckpointRoot(byte[] b) {
        Cbor.Value v;
        try {
            v = Cbor.decode(b);
        } catch (NaalpException e) {
            throw new NaalpException("CheckpointMalformed", "checkpoint-root body is not well-formed deterministic CBOR");
        }
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("CheckpointMalformed", "checkpoint-root body is not a map");
        }
        Map<Long, Cbor.Value> f = fieldsOf(m);
        Cbor.Value log = f.get(1L);
        Cbor.Value size = f.get(2L);
        Cbor.Value root = f.get(3L);
        Cbor.Value prev = f.get(4L);
        Cbor.Value at = f.get(5L);
        if (!(log instanceof Cbor.B lb) || !(size instanceof Cbor.U su) || !(root instanceof Cbor.B rb)
                || !(prev instanceof Cbor.B pb) || !(at instanceof Cbor.U au)) {
            throw new NaalpException("CheckpointMalformed", "missing or wrong-typed field 1-5");
        }
        return new CheckpointRoot(lb.v, su.v, rb.v, pb.v, au.v);
    }

    /** Produce the tagged COSE_Sign1 object over the checkpoint body, signed by the log operator. */
    public static byte[] signCheckpointRoot(CheckpointRoot c, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), c.bytes());
    }

    /** A witness's countersignature over one exact checkpoint by content id (design.md section
     * 26.5). Whether the witness's observational domain is genuinely distinct from both parties to
     * the decisions the checkpoint covers is a structural deployment fact checkable in substance at
     * T+n -- the wire supplies the hook; it does not manufacture the independence itself. */
    public static final class WitnessCosign {
        public final byte[] witness;
        public final byte[] root;
        public final long at;

        public WitnessCosign(byte[] witness, byte[] root, long at) {
            this.witness = witness.clone();
            this.root = root.clone();
            this.at = at;
        }

        /** Deterministic-CBOR encoding {1:witness, 2:root, 3:at}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(witness)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(root)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(at)))));
        }

        /** The cosign's SHA-384 head (48 octets). */
        public byte[] head() {
            return sha384(bytes());
        }

        /** The cosign's T1 content-id (50 octets). */
        public byte[] id() {
            return Cbor.contentId(bytes());
        }
    }

    /** Reconstruct a WitnessCosign from its body bytes alone. Fail-closed on any malformed shape:
     * every one of the three fields is mandatory. */
    public static WitnessCosign parseWitnessCosign(byte[] b) {
        Cbor.Value v;
        try {
            v = Cbor.decode(b);
        } catch (NaalpException e) {
            throw new NaalpException("CheckpointMalformed", "witness-cosign body is not well-formed deterministic CBOR");
        }
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("CheckpointMalformed", "witness-cosign body is not a map");
        }
        Map<Long, Cbor.Value> f = fieldsOf(m);
        Cbor.Value witness = f.get(1L);
        Cbor.Value root = f.get(2L);
        Cbor.Value at = f.get(3L);
        if (!(witness instanceof Cbor.B wb) || !(root instanceof Cbor.B rb) || !(at instanceof Cbor.U au)) {
            throw new NaalpException("CheckpointMalformed", "missing or wrong-typed field 1-3");
        }
        return new WitnessCosign(wb.v, rb.v, au.v);
    }

    /** Produce the tagged COSE_Sign1 object over the cosign body, signed by the witness. */
    public static byte[] signWitnessCosign(WitnessCosign w, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), w.bytes());
    }

    /** Checks that {@code w} names the EXACT checkpoint it accompanies (WitnessRootMismatch, design.md
     * section 26.5): {@code w.root} must equal {@code accompaniedCheckpointId}, the content id of the
     * naalp-checkpoint-root object {@code w} claims to cosign. Fail-closed. */
    public static void validateWitnessCosign(WitnessCosign w, byte[] accompaniedCheckpointId) {
        if (!java.util.Arrays.equals(w.root, accompaniedCheckpointId)) {
            throw new NaalpException("WitnessRootMismatch",
                    "witness-cosign names a root content id that does not match the checkpoint it accompanies");
        }
    }

    /** Proves one record's content id existed as a leaf under a named checkpoint (design.md section
     * 26.5, RFC 9162 section 2.1.3.1). */
    public static final class InclusionProof {
        public final byte[] root;
        public final byte[] leaf;
        public final long index;
        public final List<byte[]> path;

        public InclusionProof(byte[] root, byte[] leaf, long index, List<byte[]> path) {
            this.root = root.clone();
            this.leaf = leaf.clone();
            this.index = index;
            this.path = new ArrayList<>();
            for (byte[] p : path) {
                this.path.add(p.clone());
            }
        }

        /** Deterministic-CBOR encoding {1:root, 2:leaf, 3:index, 4:path[]}. */
        public byte[] bytes() {
            List<Cbor.Value> pathItems = new ArrayList<>();
            for (byte[] p : path) {
                pathItems.add(new Cbor.B(p));
            }
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(root)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(leaf)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(index)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.A(pathItems)))));
        }

        /** The proof's SHA-384 head (48 octets). */
        public byte[] head() {
            return sha384(bytes());
        }

        /** The proof's T1 content-id (50 octets). */
        public byte[] id() {
            return Cbor.contentId(bytes());
        }
    }

    /** Reconstruct an InclusionProof from its body bytes alone. Fail-closed on any malformed shape:
     * every one of the four fields is mandatory. */
    public static InclusionProof parseInclusionProof(byte[] b) {
        Cbor.Value v;
        try {
            v = Cbor.decode(b);
        } catch (NaalpException e) {
            throw new NaalpException("CheckpointMalformed", "inclusion-proof body is not well-formed deterministic CBOR");
        }
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("CheckpointMalformed", "inclusion-proof body is not a map");
        }
        Map<Long, Cbor.Value> f = fieldsOf(m);
        Cbor.Value root = f.get(1L);
        Cbor.Value leaf = f.get(2L);
        Cbor.Value index = f.get(3L);
        Cbor.Value pathV = f.get(4L);
        if (!(root instanceof Cbor.B rb) || !(leaf instanceof Cbor.B lb) || !(index instanceof Cbor.U iu)
                || !(pathV instanceof Cbor.A pa)) {
            throw new NaalpException("CheckpointMalformed", "missing or wrong-typed field 1-4");
        }
        List<byte[]> path = new ArrayList<>();
        for (Cbor.Value item : pa.items) {
            if (!(item instanceof Cbor.B pb)) {
                throw new NaalpException("CheckpointMalformed", "path array element not a bstr");
            }
            path.add(pb.v);
        }
        return new InclusionProof(rb.v, lb.v, iu.v, path);
    }

    // ---- RFC 9162 section 2.1 Merkle tree math (SHA-384-profiled) ---------------------------------

    /** leaf_hash = HASH(0x00 || leaf) (RFC 9162 section 2.1's LEAF_HASH, leaf/interior domain separation). */
    private static byte[] leafHash(byte[] leaf) {
        byte[] b = new byte[1 + leaf.length];
        b[0] = 0x00;
        System.arraycopy(leaf, 0, b, 1, leaf.length);
        return sha384(b);
    }

    /** node_hash = HASH(0x01 || left || right) (RFC 9162 section 2.1's NODE_HASH). */
    private static byte[] nodeHash(byte[] l, byte[] r) {
        byte[] b = new byte[1 + l.length + r.length];
        b[0] = 0x01;
        System.arraycopy(l, 0, b, 1, l.length);
        System.arraycopy(r, 0, b, 1 + l.length, r.length);
        return sha384(b);
    }

    /** The largest power of two strictly less than n (n > 1), per RFC 9162 section 2.1's k = "the
     * largest power of two smaller than n". */
    private static int largestPowerOfTwoLessThan(int n) {
        int k = 1;
        while (2 * k < n) {
            k *= 2;
        }
        return k;
    }

    /** Computes MTH(leaves) per RFC 9162 section 2.1: MTH({}) = HASH() (SHA-384 of the empty string);
     * MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the largest
     * power of two k < n. leaves are raw leaf VALUES (record content ids); LEAF_HASH is applied
     * internally -- callers never hash a leaf before calling merkleRoot. {@code leaves == null} is
     * accepted as the empty list. */
    public static byte[] merkleRoot(List<byte[]> leaves) {
        int n = leaves == null ? 0 : leaves.size();
        if (n == 0) {
            return sha384(new byte[0]); // MTH({}) = HASH(""), the empty-list base case
        }
        if (n == 1) {
            return leafHash(leaves.get(0));
        }
        int k = largestPowerOfTwoLessThan(n);
        return nodeHash(merkleRoot(leaves.subList(0, k)), merkleRoot(leaves.subList(k, n)));
    }

    /** Internal sentinel: the recursive root recomputation ran out of path entries (or had entries
     * left over) before reaching the single-leaf base case. Always surfaced to callers as
     * InclusionProofInvalid -- never exported. */
    private static final class PathLengthMismatch extends RuntimeException {}

    /** Computes the RFC 9162 section 2.1.2 PATH(index, leaves) audit path (leaf-to-root sibling
     * order -- the list's FIRST entry is the leaf's immediate sibling, the LAST is closest to the
     * root, exactly the order naalp-inclusion-proof's {@code path} field carries). */
    public static List<byte[]> generateInclusionProofPath(List<byte[]> leaves, int index) {
        if (index < 0 || index >= leaves.size()) {
            throw new NaalpException("InclusionProofInvalid", "leaf index out of range");
        }
        return genPath(leaves, index);
    }

    private static List<byte[]> genPath(List<byte[]> leaves, int index) {
        int n = leaves.size();
        if (n <= 1) {
            return new ArrayList<>(); // PATH(0, {d0}) = {} -- the single-leaf base case
        }
        int k = largestPowerOfTwoLessThan(n);
        List<byte[]> out;
        if (index < k) {
            out = genPath(leaves.subList(0, k), index);
            out.add(merkleRoot(leaves.subList(k, n)));
        } else {
            out = genPath(leaves.subList(k, n), index - k);
            out.add(merkleRoot(leaves.subList(0, k)));
        }
        return out;
    }

    /** The exact structural inverse of {@link #genPath}: at each level it consumes the LAST
     * remaining path entry (closest to the root) as this level's sibling and recurses into the
     * appropriate half with the entries that remain. */
    private static byte[] recomputeRoot(byte[] leafH, int index, int size, List<byte[]> path) {
        if (size == 1) {
            if (!path.isEmpty()) {
                throw new PathLengthMismatch();
            }
            return leafH;
        }
        if (path.isEmpty()) {
            throw new PathLengthMismatch();
        }
        int k = largestPowerOfTwoLessThan(size);
        byte[] last = path.get(path.size() - 1);
        List<byte[]> rest = path.subList(0, path.size() - 1);
        if (index < k) {
            byte[] left = recomputeRoot(leafH, index, k, rest);
            return nodeHash(left, last);
        }
        byte[] right = recomputeRoot(leafH, index - k, size - k, rest);
        return nodeHash(last, right);
    }

    /**
     * Recomputes the audit path bottom-up (RFC 9162 section 2.1.3.1, the inverse of PATH()) from
     * (leaf, index, size, path) and compares the result against root. {@code size} is the tree size
     * the proof is checked against -- the resolved naalp-checkpoint-root's own {@code size} field,
     * NOT carried inside naalp-inclusion-proof itself. Fail-closed: any mismatch, out-of-range index,
     * or path-length mismatch is InclusionProofInvalid.
     */
    public static void verifyInclusionProof(byte[] leaf, long index, long size, List<byte[]> path, byte[] root) {
        if (size == 0 || index >= size) {
            throw new NaalpException("InclusionProofInvalid", "index out of range for the claimed tree size");
        }
        byte[] got;
        try {
            got = recomputeRoot(leafHash(leaf), (int) index, (int) size, new ArrayList<>(path));
        } catch (PathLengthMismatch e) {
            throw new NaalpException("InclusionProofInvalid", "inclusion path length does not match the claimed tree size");
        }
        if (!java.util.Arrays.equals(got, root)) {
            throw new NaalpException("InclusionProofInvalid", "inclusion audit path does not recompute to the named root");
        }
    }

    // ---- naalp-egress-attestation: E6.3 ------------------------------------------------------------
    //
    // A naalp-egress-attestation is a SIGNED attestation a gateway/sidecar emits that an object of a
    // given effect class, bound to a given audience, crossed an egress boundary at a given time --
    // third-party verifiable WITHOUT the payload. It is a near-clone of GatewayDecision: the gateway
    // is the SIGNER, and verifyEgressAttestation takes NO serving-party or connection identity -- the
    // authority is the signature over the bytes, so the identical attested evidence re-verifies
    // whether the gateway or an unrelated third party serves it. `binding` is a closed set
    // (content_bound/content_free); `digest` is either the T1 content-id of the crossed object
    // (content_bound) or a hiding commitment SHA-384(content_id||salt) (content_free) -- never both;
    // `effect` is the C5 effect class of the crossed object; `audience` is the bound destination
    // (empty-permitted); `at` is the crossing time in epoch milliseconds. Field 6 (`ordering`) is
    // OPTIONAL: ABSENT reads correspondence-only, never a stronger claim inferred from silence.
    //
    // The content_free binding lets a gateway attest an egress crossing WITHOUT disclosing which
    // object crossed. egressCommit/openEgressCommitment is the open/verify pair: the gateway (or
    // anyone it later discloses content-id+salt to) can PROVE which object a content_free
    // attestation names, without the attestation bytes themselves ever carrying the content-id.

    public static final long BINDING_CONTENT_BOUND = 0; // digest is the crossed object's T1 content-id
    public static final long BINDING_CONTENT_FREE = 1;  // digest is a hiding commitment SHA-384(content_id||salt)

    private static final Map<Long, String> BINDING_NAMES = Map.of(
            BINDING_CONTENT_BOUND, "content_bound", BINDING_CONTENT_FREE, "content_free");

    /** Reports whether {@code code} is one of the closed binding codes. */
    public static boolean isKnownBinding(long code) {
        return BINDING_NAMES.containsKey(code);
    }

    /** The binding name, or "unknown". */
    public static String bindingName(long code) {
        return BINDING_NAMES.getOrDefault(code, "unknown");
    }

    /** A signed attestation a gateway/sidecar emits that an object crossed an egress boundary.
     * {@code binding} selects how {@code digest} is interpreted (content_bound: the crossed object's
     * T1 content-id; content_free: a hiding commitment). {@code effect} is the crossed object's C5
     * effect class. {@code audience} is the bound destination (empty-permitted). {@code at} is the
     * crossing time, epoch ms. {@code ordering} is the OPTIONAL field 6: null == ABSENT (reads
     * correspondence-only). */
    public static final class EgressAttestation {
        public final long binding;
        public final byte[] digest;
        public final long effect;
        public final byte[] audience;
        public final long at;
        public final OrderingDisclosure ordering;

        public EgressAttestation(long binding, byte[] digest, long effect, byte[] audience, long at) {
            this(binding, digest, effect, audience, at, null);
        }

        public EgressAttestation(long binding, byte[] digest, long effect, byte[] audience, long at, OrderingDisclosure ordering) {
            this.binding = binding;
            this.digest = digest.clone();
            this.effect = effect;
            this.audience = audience.clone();
            this.at = at;
            this.ordering = ordering;
        }

        /** Deterministic-CBOR encoding {1: binding, 2: digest, 3: effect, 4: audience, 5: at,
         * ?6: ordering}. Field 6 is OMITTED when {@code ordering} is null. */
        public byte[] bytes() {
            List<Cbor.Pair> pairs = new ArrayList<>(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(binding)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(digest)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(effect)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(audience)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(at))));
            if (ordering != null) {
                pairs.add(new Cbor.Pair(new Cbor.U(6), ordering.toCbor()));
            }
            return Cbor.encode(new Cbor.M(pairs));
        }

        /** The attestation's SHA-384 head (48 octets). */
        public byte[] head() {
            return sha384(bytes());
        }

        /** The attestation's T1 content-id (50 octets). */
        public byte[] id() {
            return Cbor.contentId(bytes());
        }

        /** The attestation's C5 effect class, normalized fail-closed: a value the evaluator does not
         * recognize is treated as destructive, never as a weaker class. */
        public long effectClass() {
            return Policy.normalizeEffect(effect);
        }
    }

    /**
     * Reconstruct an EgressAttestation from its body bytes alone. It does NOT validate the binding
     * code against the closed set -- that is {@link #verifyEgressAttestation}'s job -- so an
     * attestation carrying an unknown binding can be represented (and then rejected). Fail-closed on
     * a malformed shape: every one of the five mandatory fields is required, and a present-but-wrong-
     * typed field 6 fails here too.
     */
    public static EgressAttestation parseEgressAttestation(byte[] b) {
        Cbor.Value v;
        try {
            v = Cbor.decode(b);
        } catch (NaalpException e) {
            throw new NaalpException("EgMalformed", "egress-attestation body is not well-formed deterministic CBOR");
        }
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("EgMalformed", "egress-attestation body is not a map");
        }
        Map<Long, Cbor.Value> f = fieldsOf(m);
        Cbor.Value binding = f.get(1L);
        Cbor.Value digest = f.get(2L);
        Cbor.Value effect = f.get(3L);
        Cbor.Value audience = f.get(4L);
        Cbor.Value at = f.get(5L);
        if (!(binding instanceof Cbor.U bu) || !(digest instanceof Cbor.B db) || !(effect instanceof Cbor.U eu)
                || !(audience instanceof Cbor.B aub) || !(at instanceof Cbor.U atu)) {
            throw new NaalpException("EgMalformed", "missing or wrong-typed field 1-5");
        }
        OrderingDisclosure ordering = null;
        if (f.containsKey(6L)) {
            ordering = orderingFromCbor(f.get(6L));
            if (ordering == null) {
                throw new NaalpException("EgMalformed", "field 6 (ordering) is present but malformed");
            }
        }
        return new EgressAttestation(bu.v, db.v, eu.v, aub.v, atu.v, ordering);
    }

    /** Produce the tagged COSE_Sign1 object over the attestation body, signed by the gateway. */
    public static byte[] signEgressAttestation(EgressAttestation a, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), a.bytes());
    }

    /** An EgressAttestation that has passed signature verification. It carries NOTHING about WHO
     * served the bytes -- the authority is the signature, so the resolved evidence is identical
     * regardless of the serving party (the third-party re-serve property). */
    public static final class ResolvedEgressAttestation {
        public final long binding;
        public final byte[] digest;
        public final long effect;
        public final byte[] audience;
        public final long at;
        public final OrderingDisclosure ordering;

        public ResolvedEgressAttestation(long binding, byte[] digest, long effect, byte[] audience, long at, OrderingDisclosure ordering) {
            this.binding = binding;
            this.digest = digest;
            this.effect = effect;
            this.audience = audience;
            this.at = at;
            this.ordering = ordering;
        }
    }

    /** Performs the semantic, closed-set checks {@link #parseEgressAttestation} deliberately does
     * not (mirroring {@link #verifyDecision}'s parse/verify split): the binding must be in the closed
     * set (UnknownEgressBinding), and -- if present -- the field-6 ordering disclosure must satisfy
     * its basis-conditioned well-formedness rule (UnknownOrderingBasis/OrderingDisclosureMalformed). */
    public static void validateEgressAttestation(EgressAttestation a) {
        if (!isKnownBinding(a.binding)) {
            throw new NaalpException("UnknownEgressBinding",
                    "egress attestation binding code is outside the closed set content_bound/content_free");
        }
        if (a.ordering != null) {
            a.ordering.validate();
        }
    }

    /**
     * Verifies an egress attestation end-to-end and returns the resolved evidence. It (1) verifies
     * the signed object under the profile with real crypto against the GATEWAY's key; (2)
     * reconstructs it from the signed bytes; and (3) validates the binding code against the closed
     * set (UnknownEgressBinding), and the ordering disclosure if present. It takes NO serving-party
     * or connection identity: the authority is the signature over the bytes, so the same {@code obj}
     * yields an identical ResolvedEgressAttestation whether the gateway or an unrelated third party
     * served it (the third-party re-serve property). Any failure throws its named error and resolves
     * nothing (fail-closed).
     */
    public static ResolvedEgressAttestation verifyEgressAttestation(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[][] parts = Cose.parseSign1Raw(obj);
        int halg = algFromProtected(parts[0]);
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
        byte[] tbs = Cose.toBeSignedRaw(parts[0], parts[1]);
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, parts[2])) {
            throw new NaalpException("BadSignature", "signature does not verify");
        }
        EgressAttestation a = parseEgressAttestation(parts[1]);
        validateEgressAttestation(a);
        return new ResolvedEgressAttestation(a.binding, a.digest.clone(), Policy.normalizeEffect(a.effect),
                a.audience.clone(), a.at, a.ordering);
    }

    // ---- content_free commitment open/verify pair -------------------------------------------------

    /** The content_free hiding commitment over an object's T1 content-id and a salt:
     * SHA-384(objectCid || salt) (48 octets). The commitment reveals nothing about objectCid without
     * the salt; a gateway builds it once to populate a content_free attestation's {@code digest}
     * field, and retains objectCid+salt to later prove which object crossed via
     * {@link #openEgressCommitment}. */
    public static byte[] egressCommit(byte[] objectCid, byte[] salt) {
        byte[] b = new byte[objectCid.length + salt.length];
        System.arraycopy(objectCid, 0, b, 0, objectCid.length);
        System.arraycopy(salt, 0, b, objectCid.length, salt.length);
        return sha384(b);
    }

    /** Proves which object crossed under a content_free attestation. It recomputes
     * egressCommit(objectCid, salt) and compares it, in constant time, against {@code a.digest}.
     * Returns true iff {@code a} is a content_free attestation AND the recomputed commitment
     * matches: a wrong salt or a wrong objectCid both fail to open (return false), and a
     * content_bound attestation never opens (its digest is not a commitment). */
    public static boolean openEgressCommitment(EgressAttestation a, byte[] objectCid, byte[] salt) {
        if (a.binding != BINDING_CONTENT_FREE) {
            return false;
        }
        byte[] want = egressCommit(objectCid, salt);
        if (want.length != a.digest.length) {
            return false;
        }
        return MessageDigest.isEqual(want, a.digest);
    }
}
