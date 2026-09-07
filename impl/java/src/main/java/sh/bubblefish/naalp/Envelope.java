// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static sh.bubblefish.naalp.WireConstants.FIELD_ID;
import static sh.bubblefish.naalp.WireConstants.FIELD_KIND;
import static sh.bubblefish.naalp.WireConstants.FIELD_CHANNEL;
import static sh.bubblefish.naalp.WireConstants.FIELD_TIER;
import static sh.bubblefish.naalp.WireConstants.FIELD_SIGNER;
import static sh.bubblefish.naalp.WireConstants.FIELD_CREATED;
import static sh.bubblefish.naalp.WireConstants.FIELD_EFFECT;
import static sh.bubblefish.naalp.WireConstants.FIELD_CAUSES;
import static sh.bubblefish.naalp.WireConstants.FIELD_PROFILE;
import static sh.bubblefish.naalp.WireConstants.FIELD_BODY;
import static sh.bubblefish.naalp.WireConstants.FIELD_EXT;
import static sh.bubblefish.naalp.WireConstants.FIELD_CEXT;
import static sh.bubblefish.naalp.WireConstants.FIELD_AUDIENCE;
import static sh.bubblefish.naalp.WireConstants.FIELD_SUITE;
import static sh.bubblefish.naalp.WireConstants.NAALP_VERSION;
import static sh.bubblefish.naalp.WireConstants.HEADER_LABEL;

/**
 * N-AALP C3 object envelope for the Java SDK — the full signed object and its offline verify
 * (design.md §2). This is the ergonomic surface a developer uses: build an {@link Object} (its
 * channel/kind/effect/body and the rest), sign it with a seed, and get a single self-describing,
 * offline-verifiable byte string; verify one from the object + key + spec alone.
 *
 * <p>The object body is a deterministic-CBOR map (fields 1..12) carried as the COSE_Sign1 payload;
 * field 1 is the content id {@code multihash(0x20, 0x30, SHA-384(canonical-body-without-field-1))}
 * (§2.3). The COSE protected header carries the signature algorithm plus a routing copy of the
 * signer, profile and naalp-version (§2.1, §2.5). The bytes are byte-identical to the Go, Rust and
 * Python reference implementations — {@code vectors/worked/example.json} is the byte-level
 * known-answer for this module.
 */
public final class Envelope {
    // Field numbers (§2.1), the naalp-version (§2.5) and the COSE header label are generated from
    // spec/wire-constants.csv into WireConstants and static-imported above, so they are authored
    // once and cannot be re-typed and drift (scripts/gen_wire_constants.py).

    private Envelope() {}

    /**
     * The signed suite id carried in field 14 for the opt-in ML-DSA-65 + Ed25519 composite signature
     * (§4.2); present iff the object is signed by a composite alg, so a pure object encodes
     * byte-identically to a draft-00 object.
     */
    public static final int SUITE_MLDSA65_ED25519 = 1;

    /**
     * Whether (channel, kind) is a recognized surface kind. The envelope owns the fail-closed
     * dispatch ({@code UnknownKind}); the per-channel kind tables are the surface layer's content
     * ({@link Channels}). A {@code null} validator rejects every kind.
     */
    @FunctionalInterface
    public interface KindValidator {
        boolean isKnown(long channel, long kind);
    }

    // --- §2.5.1 recheck procedure (ext/cext key 13, NAALP-REQ-111(c)) -----------------------------

    /**
     * The ext/cext extension key under which an object NAMES the re-check procedure for the claim
     * in its body (design.md §2.5, NAALP-REQ-111(c) -- the "checkable minimum"). The value is a
     * procedure id into the closed registry below. In the non-critical ext map (field 11) it is
     * may-ignore; in the critical cext map (field 12) it is must-understand and an unknown procedure
     * id is rejected fail-closed (UnknownCriticalExt), the same C3 critical-extension rule reaching
     * the procedure it names. 13 does not collide with the safety-label ext key 1 (§6.4), the
     * signer-counter ext key 14 (§2.5.2), nor the producing-boundary ext key 15 (§2.5.4).
     * Byte-identical to impl/go and impl/rust.
     */
    public static final int RECHECK_KEY = 13;

    // The closed re-check procedure registry (design.md §2.5; T1.3); mirrors the spec
    // recheck-procedure production and vectors/registry/recheck.csv.
    public static final long RECHECK_RECOMPUTE_CONTENT_ID = 1; // recompute the content id from the body (§2.3)
    public static final long RECHECK_VERIFY_COSE_SIGN1 = 2;    // verify the COSE_Sign1 signature under the signer key (§4)
    public static final long RECHECK_WALK_CAUSES = 3;          // walk the signed causal partial order offline (§8.2)
    public static final long RECHECK_REPLAY_CONSUME_CHECK = 4; // replay the single-use consume ledger for the approval (§7.2)

    /**
     * Reports whether id is a recognized re-check procedure. The registry is CLOSED: an id outside
     * it is unknown, and an unknown id under the critical map is rejected (§2.5). Compared as an
     * unsigned 64-bit magnitude ({@link Long#compareUnsigned}) so a Java long representing a huge
     * uint64 (wrapped negative) is correctly reported outside the small closed registry.
     */
    public static boolean isKnownRecheckProcedure(long id) {
        return Long.compareUnsigned(id, RECHECK_RECOMPUTE_CONTENT_ID) >= 0
                && Long.compareUnsigned(id, RECHECK_REPLAY_CONSUME_CHECK) <= 0;
    }

    /**
     * A decoded re-check disclosure ({@link #RECHECK_KEY}, §2.5): {@code id} is the named procedure,
     * {@code present} is true when a procedure is named, and {@code critical} is true iff it is
     * named in the cext map (field 12, must-understand) rather than the ext map (field 11,
     * may-ignore). When no procedure is named the claim is attributable-only (NAALP-REQ-111).
     */
    public static final class RecheckInfo {
        public final long id;
        public final boolean present;
        public final boolean critical;

        public RecheckInfo(long id, boolean present, boolean critical) {
            this.id = id;
            this.present = present;
            this.critical = critical;
        }
    }

    /**
     * Returns the uint value under key in a CBOR map (ext or cext), or {@code null} when the key is
     * absent or present under a non-uint value. Shared by {@link Object#recheck} and {@link
     * Object#signerCounter}.
     */
    private static Long extGetUintKey(Cbor.M m, int key) {
        if (m == null) {
            return null;
        }
        for (Cbor.Pair pr : m.pairs) {
            if (pr.k instanceof Cbor.U u && u.v == key) {
                if (pr.val instanceof Cbor.U v) {
                    return v.v;
                }
                return null;
            }
        }
        return null;
    }

    /**
     * Returns a NEW map with entry upserted under key (replace-or-append); m may be {@code null}.
     * Append order is irrelevant to the encoded bytes -- {@link Cbor#encode} always emits canonical
     * key order.
     */
    private static Cbor.M upsertUintEntry(Cbor.M m, int key, Cbor.Pair entry) {
        if (m == null) {
            return new Cbor.M(List.of(entry));
        }
        List<Cbor.Pair> newPairs = new ArrayList<>();
        boolean replaced = false;
        for (Cbor.Pair pr : m.pairs) {
            if (pr.k instanceof Cbor.U u && u.v == key) {
                newPairs.add(entry);
                replaced = true;
            } else {
                newPairs.add(pr);
            }
        }
        if (!replaced) {
            newPairs.add(entry);
        }
        return new Cbor.M(newPairs);
    }

    // --- §2.5.2 per-signer forward-only counter (ext key 14, NAALP-REQ-120) -----------------------

    /**
     * The ext extension key under which an object OPTIONALLY carries a forward-only per-signer
     * counter (design.md §2.5.2, NAALP-REQ-120 -- the per-signer counter). The value is a
     * forward-only position (a uint) the signer increments on each object. It lives in the
     * NON-CRITICAL ext map (field 11): a verifier that does not perform duplication-detection
     * ignores it and the object still verifies (may-ignore). Because ext (field 11) is part of the
     * signed body/payload, the counter is covered by the SIGNER's own COSE_Sign1 signature -- the
     * deliberate contrast with the T1.5 consume-receipt position, which is signed by the LEDGER key.
     * 14 does not collide with the safety-label ext key 1 (§6.4), the recheck ext/cext key 13
     * (§2.5.1), or the producing-boundary ext key 15 (§2.5.4). Byte-identical to impl/go and
     * impl/rust.
     *
     * <p>The counter is DETECTION, not prevention (NAALP-REQ-120; # Security Considerations): a
     * single self-authored sequence proves nothing. It is a NON-CRITICAL field only -- placing it in
     * the critical cext map (field 12) is an unrecognized critical extension and is rejected
     * fail-closed (UnknownCriticalExt), because a detection aid is never a must-understand
     * verification gate.
     */
    public static final int SIGNER_COUNTER_KEY = 14;

    /**
     * One detected per-signer counter conflict: two or more DISTINCT objects (distinct content ids)
     * from the SAME signer id that carry the SAME forward-only counter value. A forward-only counter
     * binds each value to at most one object, so a value bound to &gt;= 2 distinct objects is the
     * observable fingerprint of the key incrementing in two places (key duplication). The finding
     * surfaces BOTH sides of the contradiction: the reused counter value and every conflicting
     * content id (ascending by bytes) -- never a single flag with the evidence hidden.
     */
    public static final class DuplicationFinding {
        public final byte[] signer;
        public final long counter;
        public final List<byte[]> ids; // >= 2 conflicting content ids, ascending by bytes

        public DuplicationFinding(byte[] signer, long counter, List<byte[]> ids) {
            this.signer = signer.clone();
            this.counter = counter;
            this.ids = new ArrayList<>(ids);
        }
    }

    /**
     * Scans a SET of PRESENTED objects for per-signer counter reuse. This is the whole point of the
     * field, and it is DETECTION, not prevention (NAALP-REQ-120): it flags a signer id ONLY when two
     * conflicting sequences from that signer physically MEET in the presented set -- a counter value
     * bound to &gt;= 2 distinct content ids by one signer. Given only ONE object per value (one
     * sequence) it returns no findings; the second conflicting object must be present, unsuppressed,
     * for the duplication to become provable. Objects with no counter do not participate. Output is
     * deterministic (findings ordered by signer id then counter; ids within a finding ascending).
     *
     * <p>It operates over the SET, never per object: a per-object boolean could never express "these
     * two distinct objects reuse one position," and a single self-authored counter proves nothing on
     * its own.
     */
    public static List<DuplicationFinding> detectSignerDuplication(List<Object> objs) {
        // signerKeyHex -> counter -> (contentIdHex -> contentIdBytes), a set that de-dups a
        // byte-identical re-presentation (one content id twice) so it is NOT a conflict.
        java.util.LinkedHashMap<String, byte[]> signerBytes = new java.util.LinkedHashMap<>();
        java.util.LinkedHashMap<String, java.util.LinkedHashMap<Long, java.util.LinkedHashMap<String, byte[]>>> groups =
                new java.util.LinkedHashMap<>();
        for (Object o : objs) {
            Long seq = o.signerCounter();
            if (seq == null) {
                continue; // a counter-less object does not participate in detection
            }
            byte[] id;
            try {
                id = o.contentId();
            } catch (RuntimeException e) {
                continue; // a body that cannot be canonically encoded cannot be a presented object
            }
            String sk = Hex.encode(o.signer);
            signerBytes.putIfAbsent(sk, o.signer);
            groups.computeIfAbsent(sk, k -> new java.util.LinkedHashMap<>())
                    .computeIfAbsent(seq, k -> new java.util.LinkedHashMap<>())
                    .put(Hex.encode(id), id);
        }

        List<String> signers = new ArrayList<>(groups.keySet());
        java.util.Collections.sort(signers);

        List<DuplicationFinding> findings = new ArrayList<>();
        for (String sk : signers) {
            java.util.LinkedHashMap<Long, java.util.LinkedHashMap<String, byte[]>> byCounter = groups.get(sk);
            List<Long> counters = new ArrayList<>(byCounter.keySet());
            counters.sort(Long::compareUnsigned);
            for (Long c : counters) {
                java.util.LinkedHashMap<String, byte[]> idset = byCounter.get(c);
                // A (signer, counter) that binds two-or-more DISTINCT content ids is a detected
                // duplication. The >= 2 requirement is the detection-requires-both invariant: relax
                // it to >= 1 and a single sequence would flag (prevention theatre) -- the mutation
                // the "one sequence alone -> not flagged" test is built to catch.
                if (idset.size() < 2) {
                    continue;
                }
                List<byte[]> ids = new ArrayList<>(idset.values());
                ids.sort(Cbor::compareBytes);
                findings.add(new DuplicationFinding(signerBytes.get(sk), c, ids));
            }
        }
        return findings;
    }

    // --- NA-IETF-1 producing-boundary disclosure (OPTIONAL, self-asserted ext key 15, §2.5.4) -----

    /**
     * The ext extension key under which an object OPTIONALLY carries a per-object producing-boundary
     * disclosure (design.md §2.5.4, NA-IETF-1): the trust boundary that emitted the object and
     * whether that boundary OBSERVED the event it describes first-hand or is RELAYING a report of
     * it. It rides the NON-CRITICAL ext map (field 11): a verifier that does not understand it, or
     * that reads a malformed value, IGNORES the entry and the object still verifies (may-ignore).
     * Because ext is part of the signed body/payload, the disclosure is covered by the SIGNER's own
     * COSE_Sign1 signature -- a SELF-ASSERTED claim. 15 collides with neither the safety-label ext
     * key 1 (§6.4), the recheck ext/cext key 13 (§2.5.1), nor the signer-counter ext key 14 (§2.5.2).
     * Byte-identical to impl/go, impl/rust, and impl/python.
     */
    public static final int PRODUCING_BOUNDARY_KEY = 15;

    /** This boundary witnessed the event directly (first-hand), §2.5.4. */
    public static final long PRODUCING_BOUNDARY_OBSERVED = 1;
    /** This boundary is relaying a report it did not witness, §2.5.4. */
    public static final long PRODUCING_BOUNDARY_REPORTED = 2;

    // The producing-boundary value sub-map wire keys (§2.5.4).
    static final int PB_FIELD_BOUNDARY = 1;   // bstr -- the emitting trust boundary (party id)
    static final int PB_FIELD_KIND = 2;       // 1 observed / 2 reported
    static final int PB_FIELD_REPORTING = 3;  // bstr -- report origin; present iff kind == reported

    /**
     * A decoded producing-boundary disclosure ({@link #PRODUCING_BOUNDARY_KEY}, §2.5.4). {@code
     * boundary} is the emitting trust boundary (the same bstr party-id form as {@link
     * Object#signer}). {@code kind} is {@link #PRODUCING_BOUNDARY_OBSERVED} or {@link
     * #PRODUCING_BOUNDARY_REPORTED}. {@code reporting} names the report origin and is non-null ONLY
     * when kind is PRODUCING_BOUNDARY_REPORTED (an observer relays from no one).
     */
    public static final class ProducingBoundary {
        public final byte[] boundary;
        public final long kind;
        public final byte[] reporting;

        public ProducingBoundary(byte[] boundary, long kind, byte[] reporting) {
            this.boundary = boundary.clone();
            this.kind = kind;
            this.reporting = reporting == null ? null : reporting.clone();
        }

        public ProducingBoundary(byte[] boundary, long kind) {
            this(boundary, kind, null);
        }
    }

    /** A decoded N-AALP object body. {@code id} is set by {@link #sign} (content id §2.3). */
    public static final class Object {
        public byte[] id;            // set by sign(): the content id
        public long kind;
        public long channel;
        public long tier;
        public byte[] signer;
        public long created;
        public long effect;
        public List<byte[]> causes;
        public long profile;
        public Cbor.Value body;      // e.g. a Cbor.M
        public Cbor.M ext;           // field 11, non-critical; null = absent
        public Cbor.M cext;          // field 12, critical; null = absent
        // field 13 (§2.5.3): the single-use consume binding. Omit-when-empty -- a no-audience object
        // encodes byte-identically to a draft-00 object (additivity). Anchors version 2. Java has no
        // default ctor args, so audience is a public field defaulting to "" (set directly like ext/cext).
        public String audience = "";
        // field 14 (§4.2): the signed suite declaration, present (value 1) iff a composite alg signs
        // this object; 0 = absent, so a pure object stays byte-identical to draft-00. Public field
        // (like audience), set by signComposite / objectFromMap.
        public long suite = 0;

        /** The common case: Public profile, tier 0, no causes/extensions. */
        public Object(long kind, long channel, byte[] signer, long created, long effect, Cbor.Value body) {
            this(kind, channel, 0, signer, created, effect, Cose.PROFILE_PUBLIC, body, null, null, null);
        }

        /** The full object: every field, with {@code causes}/{@code ext}/{@code cext} nullable. */
        public Object(long kind, long channel, long tier, byte[] signer, long created, long effect,
                      long profile, Cbor.Value body, List<byte[]> causes, Cbor.M ext, Cbor.M cext) {
            this.kind = kind;
            this.channel = channel;
            this.tier = tier;
            this.signer = signer.clone();
            this.created = created;
            this.effect = effect;
            this.profile = profile;
            this.body = body;
            this.causes = causes == null ? new ArrayList<>() : new ArrayList<>(causes);
            this.ext = ext;
            this.cext = cext;
        }

        // Package-private (not private): the NA-IETF-1 producing-boundary KAT (ProducingBoundaryKat,
        // §2.5.4) grades the pre-signature body bytes directly, the same way the Go/Rust/Python
        // reference tests read bodyMap()/_body_map() in their own package/module.
        Cbor.M bodyMap(boolean includeId) {
            List<Cbor.Pair> pairs = new ArrayList<>(12);
            if (includeId) {
                pairs.add(new Cbor.Pair(new Cbor.U(FIELD_ID), new Cbor.B(id)));
            }
            pairs.add(new Cbor.Pair(new Cbor.U(FIELD_KIND), new Cbor.U(kind)));
            pairs.add(new Cbor.Pair(new Cbor.U(FIELD_CHANNEL), new Cbor.U(channel)));
            pairs.add(new Cbor.Pair(new Cbor.U(FIELD_TIER), new Cbor.U(tier)));
            pairs.add(new Cbor.Pair(new Cbor.U(FIELD_SIGNER), new Cbor.B(signer)));
            pairs.add(new Cbor.Pair(new Cbor.U(FIELD_CREATED), new Cbor.U(created)));
            pairs.add(new Cbor.Pair(new Cbor.U(FIELD_EFFECT), new Cbor.U(effect)));
            List<Cbor.Value> cs = new ArrayList<>(causes.size());
            for (byte[] c : causes) {
                cs.add(new Cbor.B(c));
            }
            pairs.add(new Cbor.Pair(new Cbor.U(FIELD_CAUSES), new Cbor.A(cs)));
            pairs.add(new Cbor.Pair(new Cbor.U(FIELD_PROFILE), new Cbor.U(profile)));
            pairs.add(new Cbor.Pair(new Cbor.U(FIELD_BODY), body));
            if (ext != null) {
                pairs.add(new Cbor.Pair(new Cbor.U(FIELD_EXT), ext));
            }
            if (cext != null) {
                pairs.add(new Cbor.Pair(new Cbor.U(FIELD_CEXT), cext));
            }
            if (audience != null && !audience.isEmpty()) {
                pairs.add(new Cbor.Pair(new Cbor.U(FIELD_AUDIENCE), new Cbor.T(audience)));
            }
            if (suite != 0) {
                pairs.add(new Cbor.Pair(new Cbor.U(FIELD_SUITE), new Cbor.U(suite)));
            }
            return new Cbor.M(pairs);
        }

        /** The object content id over the body without field 1 (§2.3). */
        public byte[] contentId() {
            return Cbor.contentId(Cbor.encode(bodyMap(false)));
        }

        /**
         * Returns the re-check procedure this object names ({@link #RECHECK_KEY}, §2.5): {@code
         * present} is true when a procedure is named, and {@code critical} is true iff it is named
         * in the cext map (field 12, must-understand) rather than the ext map (field 11,
         * may-ignore). cext takes precedence when both carry the key. When no procedure is named the
         * claim is attributable-only (NAALP-REQ-111).
         */
        public RecheckInfo recheck() {
            Long v = extGetUintKey(cext, RECHECK_KEY);
            if (v != null) {
                return new RecheckInfo(v, true, true);
            }
            v = extGetUintKey(ext, RECHECK_KEY);
            if (v != null) {
                return new RecheckInfo(v, true, false);
            }
            return new RecheckInfo(0, false, false);
        }

        /**
         * Names procId as this object's re-check procedure ({@link #RECHECK_KEY}, §2.5). {@code
         * critical} places it in the cext map (field 12, must-understand); otherwise the ext map
         * (field 11, may-ignore). Creates the carrier if absent and leaves any other extension
         * entries intact.
         */
        public void setRecheck(long procId, boolean critical) {
            Cbor.Pair entry = new Cbor.Pair(new Cbor.U(RECHECK_KEY), new Cbor.U(procId));
            if (critical) {
                cext = upsertUintEntry(cext, RECHECK_KEY, entry);
            } else {
                ext = upsertUintEntry(ext, RECHECK_KEY, entry);
            }
        }

        /**
         * Returns the forward-only per-signer position this object names ({@link
         * #SIGNER_COUNTER_KEY}, §2.5.2), or {@code null} if absent. The field is OPTIONAL -- present
         * is keyed on the KEY being present in the non-critical ext map (field 11), not on the
         * value: a present counter of 0 returns non-null {@code 0L}.
         */
        public Long signerCounter() {
            return extGetUintKey(ext, SIGNER_COUNTER_KEY);
        }

        /**
         * Names seq as this object's forward-only per-signer position in the NON-CRITICAL ext map
         * (field 11, {@link #SIGNER_COUNTER_KEY}), covered by the signer's COSE_Sign1 signature.
         * Creates the ext carrier if absent and leaves any other extension entries intact. The
         * counter is deliberately never placed in the critical cext map (it is detection, not a
         * verification gate).
         */
        public void setSignerCounter(long seq) {
            Cbor.Pair entry = new Cbor.Pair(new Cbor.U(SIGNER_COUNTER_KEY), new Cbor.U(seq));
            ext = upsertUintEntry(ext, SIGNER_COUNTER_KEY, entry);
        }

        /**
         * Return the producing-boundary disclosure this object carries (§2.5.4, {@link
         * #PRODUCING_BOUNDARY_KEY}), or {@code null} if absent OR malformed (may-ignore -- never
         * throws). Well-formed requires a non-empty boundary (sub-key 1), a kind (sub-key 2) in
         * {@link #PRODUCING_BOUNDARY_OBSERVED}/{@link #PRODUCING_BOUNDARY_REPORTED}, and a
         * reporting-boundary (sub-key 3) absent unless the kind is reported. An unrecognized sub-key is
         * ignored and does not by itself make an otherwise well-formed value malformed.
         */
        public ProducingBoundary producingBoundary() {
            if (ext == null) {
                return null;
            }
            Cbor.M val = null;
            boolean found = false;
            for (Cbor.Pair pr : ext.pairs) {
                if (pr.k instanceof Cbor.U u && u.v == PRODUCING_BOUNDARY_KEY) {
                    found = true;
                    if (pr.val instanceof Cbor.M m) {
                        val = m;
                    }
                    break;
                }
            }
            if (!found || val == null) {
                return null;
            }
            byte[] boundary = null;
            Long kind = null;
            byte[] reporting = null;
            boolean haveReporting = false;
            for (Cbor.Pair pr : val.pairs) {
                if (!(pr.k instanceof Cbor.U k)) {
                    return null;
                }
                if (k.v == PB_FIELD_BOUNDARY) {
                    if (!(pr.val instanceof Cbor.B b)) {
                        return null;
                    }
                    boundary = b.v;
                } else if (k.v == PB_FIELD_KIND) {
                    if (!(pr.val instanceof Cbor.U u)) {
                        return null;
                    }
                    kind = u.v;
                } else if (k.v == PB_FIELD_REPORTING) {
                    if (!(pr.val instanceof Cbor.B b)) {
                        return null;
                    }
                    reporting = b.v;
                    haveReporting = true;
                }
                // else: an unrecognized sub-key -- may-ignore.
            }
            // well-formedness (§2.5.4). Any failure returns null (may-ignore), never an error.
            if (boundary == null || boundary.length == 0) {
                return null; // no boundary named
            }
            if (kind == null || (kind != PRODUCING_BOUNDARY_OBSERVED && kind != PRODUCING_BOUNDARY_REPORTED)) {
                return null; // absent or out-of-enum kind
            }
            if (haveReporting && kind != PRODUCING_BOUNDARY_REPORTED) {
                return null; // a reporting-boundary under observed: an observer relays from no one
            }
            return new ProducingBoundary(boundary, kind, haveReporting ? reporting : null);
        }

        /**
         * Name {@code pb} as this object's producing-boundary disclosure in the NON-CRITICAL ext map
         * (field 11, {@link #PRODUCING_BOUNDARY_KEY}), covered by the signer's COSE_Sign1 signature.
         * Creates the ext carrier if absent and leaves any other extension entries intact. The
         * reporting-boundary is emitted ONLY when non-null AND the kind is reported, so a caller cannot
         * accidentally emit a malformed observed-with-reporting disclosure (an observer relays from no
         * one).
         */
        public void setProducingBoundary(ProducingBoundary pb) {
            List<Cbor.Pair> sub = new ArrayList<>();
            sub.add(new Cbor.Pair(new Cbor.U(PB_FIELD_BOUNDARY), new Cbor.B(pb.boundary)));
            sub.add(new Cbor.Pair(new Cbor.U(PB_FIELD_KIND), new Cbor.U(pb.kind)));
            if (pb.reporting != null && pb.kind == PRODUCING_BOUNDARY_REPORTED) {
                sub.add(new Cbor.Pair(new Cbor.U(PB_FIELD_REPORTING), new Cbor.B(pb.reporting)));
            }
            Cbor.Pair entry = new Cbor.Pair(new Cbor.U(PRODUCING_BOUNDARY_KEY), new Cbor.M(sub));
            if (ext == null) {
                ext = new Cbor.M(List.of(entry));
                return;
            }
            List<Cbor.Pair> newPairs = new ArrayList<>();
            boolean replaced = false;
            for (Cbor.Pair pr : ext.pairs) {
                if (pr.k instanceof Cbor.U u && u.v == PRODUCING_BOUNDARY_KEY) {
                    newPairs.add(entry);
                    replaced = true;
                } else {
                    newPairs.add(pr);
                }
            }
            if (!replaced) {
                newPairs.add(entry);
            }
            ext = new Cbor.M(newPairs);
        }
    }

    private static byte[] protectedHeader(int alg, byte[] signer, long profile) {
        Cbor.M naalp = new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(signer)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(profile)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(NAALP_VERSION))));
        Cbor.M hdr = new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)),
                new Cbor.Pair(new Cbor.T(HEADER_LABEL), naalp)));
        return Cbor.encode(hdr);
    }

    /**
     * Assemble, content-id-bind, and deterministically sign a full N-AALP object with an ML-DSA key
     * derived from {@code seed}. Returns the tagged COSE_Sign1 object bytes. The signer's algorithm
     * and the object's signer/profile fields populate the protected-header copies.
     */
    public static byte[] sign(Object obj, int alg, byte[] seed) {
        obj.id = obj.contentId();
        byte[] payload = Cbor.encode(obj.bodyMap(true));
        byte[] prot = protectedHeader(alg, obj.signer, obj.profile);
        byte[] tbs = Cose.toBeSignedRaw(prot, payload);
        byte[] sig = Cose.mldsaSign(alg, seed, tbs);
        return Cose.assembleSign1Raw(prot, payload, sig);
    }

    /**
     * Assemble, content-id-bind, and sign a full N-AALP object with the opt-in LAMPS composite
     * signature (alg -65537, §4.2). Sets the signed suite field (14) present (value 1) BEFORE the
     * content id so the id covers it; the composite value is deterministic in both legs (ML-DSA-65
     * with ctx=Label, Ed25519 with no ctx). Returns the tagged COSE_Sign1 object bytes.
     */
    public static byte[] signComposite(Object obj, byte[] mldsaSeed, byte[] edSeed) {
        obj.suite = SUITE_MLDSA65_ED25519;
        obj.id = obj.contentId();
        byte[] payload = Cbor.encode(obj.bodyMap(true));
        byte[] prot = protectedHeader(Cose.ALG_COMPOSITE_65_ED25519, obj.signer, obj.profile);
        byte[] tbs = Cose.toBeSignedRaw(prot, payload);
        byte[] sig = Cose.compositeSign(mldsaSeed, edSeed, tbs);
        return Cose.assembleSign1Raw(prot, payload, sig);
    }

    /** Parsed protected-header routing fields: {@code {1: alg}, "naalp": {1,2,3}}. */
    private static final class Protected {
        int alg;
        byte[] signer;
        long profile;
        long version;
    }

    private static Protected parseProtected(byte[] prot) {
        // §3.1.1 (R5): the empty protected header is pinned to 0x40; a byte string wrapping an
        // empty CBOR map (the 0x41A0 form — its unwrapped content is the single byte 0xA0) MUST
        // be rejected as NonCanonical before the header is interpreted.
        if (prot.length == 1 && (prot[0] & 0xFF) == 0xA0) {
            throw new NaalpException("NonCanonical", "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)");
        }
        Cbor.Value v = Cbor.decode(prot);
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("Malformed", "protected header not a map");
        }
        Protected p = new Protected();
        boolean haveAlg = false;
        boolean haveNaalp = false;
        Integer profile = null;
        Long version = null;
        byte[] signer = null;
        for (Cbor.Pair pr : m.pairs) {
            if (pr.k instanceof Cbor.U u && u.v == 1 && pr.val instanceof Cbor.N n) {
                p.alg = (int) n.v;
                haveAlg = true;
            } else if (pr.k instanceof Cbor.T t && t.v.equals(HEADER_LABEL) && pr.val instanceof Cbor.M nm) {
                for (Cbor.Pair np : nm.pairs) {
                    if (!(np.k instanceof Cbor.U nk)) {
                        continue;
                    }
                    if (nk.v == 1 && np.val instanceof Cbor.B b) {
                        signer = b.v;
                    } else if (nk.v == 2 && np.val instanceof Cbor.U pu) {
                        profile = (int) pu.v;
                    } else if (nk.v == 3 && np.val instanceof Cbor.U vu) {
                        version = vu.v;
                    }
                }
                haveNaalp = true;
            }
        }
        if (!haveAlg || !haveNaalp || signer == null || profile == null || version == null) {
            throw new NaalpException("Malformed", "protected header missing routing fields");
        }
        p.signer = signer;
        p.profile = profile;
        p.version = version;
        return p;
    }

    private static Object objectFromMap(Cbor.M m) {
        Map<Long, Cbor.Value> fields = new java.util.HashMap<>();
        for (Cbor.Pair pr : m.pairs) {
            if (!(pr.k instanceof Cbor.U u)) {
                throw new NaalpException("Malformed", "non-uint body key");
            }
            fields.put(u.v, pr.val);
        }
        long kind = needU(fields, FIELD_KIND);
        long channel = needU(fields, FIELD_CHANNEL);
        long tier = needU(fields, FIELD_TIER);
        byte[] signer = needB(fields, FIELD_SIGNER);
        long created = needU(fields, FIELD_CREATED);
        long effect = needU(fields, FIELD_EFFECT);
        long profile = needU(fields, FIELD_PROFILE);
        Cbor.Value body = fields.get((long) FIELD_BODY);
        if (body == null) {
            throw new NaalpException("Malformed", "field 10 absent");
        }
        Cbor.Value causesV = fields.get((long) FIELD_CAUSES);
        if (!(causesV instanceof Cbor.A ca)) {
            throw new NaalpException("Malformed", "field 8 wrong type/absent");
        }
        if (ca.items.size() > WireConstants.MAX_CAUSES) { // causal fan-in bound (§3.4, R7)
            throw new NaalpException("TooManyCauses", "causes[] exceeds the maximum count (§3.4, R7)");
        }
        List<byte[]> causes = new ArrayList<>(ca.items.size());
        for (Cbor.Value c : ca.items) {
            if (!(c instanceof Cbor.B cb)) {
                throw new NaalpException("Malformed", "cause not a bstr");
            }
            causes.add(cb.v);
        }
        Cbor.Value extV = fields.get((long) FIELD_EXT);
        Cbor.Value cextV = fields.get((long) FIELD_CEXT);
        if (extV != null && !(extV instanceof Cbor.M)) {
            throw new NaalpException("Malformed", "ext not a map");
        }
        if (extV instanceof Cbor.M em && em.pairs.size() > WireConstants.MAX_EXT) { // ext cardinality bound (§3.4, R7)
            throw new NaalpException("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)");
        }
        if (cextV != null && !(cextV instanceof Cbor.M)) {
            throw new NaalpException("Malformed", "cext not a map");
        }
        if (cextV instanceof Cbor.M cm && cm.pairs.size() > WireConstants.MAX_CEXT) { // cext cardinality bound (§3.4, R7)
            throw new NaalpException("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)");
        }
        Cbor.Value audV = fields.get((long) FIELD_AUDIENCE);
        if (audV != null && !(audV instanceof Cbor.T)) {
            throw new NaalpException("Malformed", "audience not a tstr");
        }
        Cbor.Value suiteV = fields.get((long) FIELD_SUITE);
        if (suiteV != null && !(suiteV instanceof Cbor.U)) {
            throw new NaalpException("Malformed", "suite not a uint");
        }
        Object o = new Object(kind, channel, tier, signer, created, effect, profile, body, causes,
                (Cbor.M) extV, (Cbor.M) cextV);
        if (audV instanceof Cbor.T at) {
            o.audience = at.v;
        }
        if (suiteV instanceof Cbor.U su) {
            o.suite = su.v;
        }
        Cbor.Value idV = fields.get((long) FIELD_ID);
        if (idV instanceof Cbor.B ib) {
            o.id = ib.v;
        }
        return o;
    }

    /**
     * The single-use consume binding gate (§2.5.3), checked at the point of use -- before the consume
     * logic (the CAS append) -- NEVER inside verify(). An in-transit relay, ordering authority, or
     * auditor legitimately verifies objects addressed to some OTHER authority; only the authority
     * about to CONSUME an object enforces that the object is addressed to it. Three branches: (a)
     * absent audience on a consume-once object -&gt; WrongAudience; (b) an audience present but not
     * this authority -&gt; WrongAudience; (c) a non-consume-once object with no audience -&gt; pass.
     * Throws {@link NaalpException} with kind {@code "WrongAudience"} on rejection.
     */
    public static void checkAudience(Object o, String selfAuthority, boolean consumeOnce) {
        if (o.audience == null || o.audience.isEmpty()) {
            if (consumeOnce) {
                throw new NaalpException("WrongAudience", "consume-once object has no audience");
            }
            return;
        }
        if (!o.audience.equals(selfAuthority)) {
            throw new NaalpException("WrongAudience", "object audience is not this consuming authority");
        }
    }

    private static long needU(Map<Long, Cbor.Value> fields, int fnum) {
        Cbor.Value v = fields.get((long) fnum);
        if (!(v instanceof Cbor.U u)) {
            throw new NaalpException("Malformed", "field " + fnum + " wrong type/absent");
        }
        return u.v;
    }

    private static byte[] needB(Map<Long, Cbor.Value> fields, int fnum) {
        Cbor.Value v = fields.get((long) fnum);
        if (!(v instanceof Cbor.B b)) {
            throw new NaalpException("Malformed", "field " + fnum + " wrong type/absent");
        }
        return b.v;
    }

    /**
     * Verify a signed N-AALP object end-to-end, offline (R-2.4). Returns the {@link Object} on
     * success; throws a {@link NaalpException} with a stable {@code kind} on the first named failure.
     * Check order (fail-closed): decode -&gt; content-id -&gt; field ranges -&gt; header/body copies
     * + version -&gt; critical extensions -&gt; kind dispatch -&gt; profile floor -&gt; signature.
     *
     * @param knownCext the recognized critical-extension keys (may be {@code null} = none known)
     */
    public static Object verify(int profile, int alg, byte[] pubkey, KindValidator kindValidator,
                                byte[] objBytes, Map<Long, Boolean> knownCext) {
        // Object octet-size bound (§3.4, R7): reject an oversized signed object on the raw bytes,
        // before any parse (RFC 8949 §10 decoder-memory guard).
        if (objBytes.length > WireConstants.MAX_OBJECT_SIZE) {
            throw new NaalpException("TooLarge", "object exceeds the maximum octet size (§3.4, R7)");
        }
        byte[][] parts = Cose.parseSign1Raw(objBytes);
        byte[] prot = parts[0];
        byte[] payload = parts[1];
        byte[] sig = parts[2];

        // non-canonical -> NonCanonical (§2.6); over-nested -> DepthExceeded (§3.4, R7).
        Cbor.Value bv = Cbor.decodeBounded(payload, WireConstants.MAX_NESTING_DEPTH);
        if (!(bv instanceof Cbor.M bm)) {
            throw new NaalpException("Malformed", "body not a map");
        }

        // content-id: recompute over the body without field 1, compare to the claimed id.
        byte[] claimed = null;
        List<Cbor.Pair> without = new ArrayList<>(bm.pairs.size());
        for (Cbor.Pair pr : bm.pairs) {
            if (pr.k instanceof Cbor.U u && u.v == FIELD_ID) {
                if (!(pr.val instanceof Cbor.B b)) {
                    throw new NaalpException("Malformed", "id not a bstr");
                }
                claimed = b.v;
                continue;
            }
            without.add(pr);
        }
        if (claimed == null) {
            throw new NaalpException("Malformed", "no content id");
        }
        byte[] recomputed = Cbor.contentId(Cbor.encode(new Cbor.M(without)));
        if (!java.util.Arrays.equals(recomputed, claimed)) {
            throw new NaalpException("ContentIdMismatch", "recomputed id differs");
        }

        Object o = objectFromMap(bm);

        // A (channel 3, kind 0) Rotation object MUST be a tag-98 COSE_Sign co-signed by the old AND
        // new key (§5.2); a single-signature (tag-18) rotation is missing the old-key co-signature and
        // is rejected RotationUnauthorized (the single-Sign1 rotation-gap fix).
        if (isRotationObject(o.channel, o.kind)) {
            throw new NaalpException("RotationUnauthorized", "single-signature rotation missing the old-key co-signature");
        }

        // field ranges (§3.3): channel 0..19, effect 0..3, profile 1..3.
        if (o.channel > 19 || o.effect > 3 || o.profile < 1 || o.profile > 3) {
            throw new NaalpException("RangeError", "field out of range");
        }

        // protected-header copies vs body (HeaderBodyMismatch, §2.1) + version.
        Protected hp = parseProtected(prot);
        if (hp.version != NAALP_VERSION) {
            throw new NaalpException("UnsupportedVersion", "bad naalp-version");
        }
        if (!java.util.Arrays.equals(hp.signer, o.signer) || hp.profile != o.profile) {
            throw new NaalpException("HeaderBodyMismatch", "protected header disagrees with body");
        }

        // critical extensions: any unrecognized key rejects (§2.5, R-2.5).
        if (o.cext != null) {
            for (Cbor.Pair pr : o.cext.pairs) {
                boolean known = pr.k instanceof Cbor.U u && knownCext != null
                        && Boolean.TRUE.equals(knownCext.get(u.v));
                if (!known) {
                    throw new NaalpException("UnknownCriticalExt", "unrecognized critical extension");
                }
            }
        }

        // kind/channel surface dispatch (UnknownKind, §2.6).
        if (kindValidator == null || !kindValidator.isKnown(o.channel, o.kind)) {
            throw new NaalpException("UnknownKind", "kind/channel not a registered surface");
        }

        byte[] tbs = Cose.toBeSignedRaw(prot, payload);
        if (hp.alg == Cose.ALG_COMPOSITE_65_ED25519) {
            // Opt-in composite path (§4.2/§4.4/§4.5): CompositeRefused (Sovereign floors at level 5,
            // the composite ML-DSA-65 leg is level 3) -> SuiteMismatch (field 14 must declare the
            // matching suite) -> both-legs signature. Verifying key = mldsaPub || ed25519Pub.
            if (profile == Cose.PROFILE_SOVEREIGN) {
                throw new NaalpException("CompositeRefused", "composite refused on the Sovereign profile");
            }
            if (o.suite != SUITE_MLDSA65_ED25519) {
                throw new NaalpException("SuiteMismatch", "field 14 does not declare the composite suite");
            }
            byte[] mldsaPub = java.util.Arrays.copyOfRange(pubkey, 0, Cose.MLDSA65_PUB_SIZE);
            byte[] edPub = java.util.Arrays.copyOfRange(pubkey, Cose.MLDSA65_PUB_SIZE, pubkey.length);
            if (edPub.length != 32 || !Cose.compositeVerify(mldsaPub, edPub, tbs, sig)) {
                throw new NaalpException("BadSignature", "composite signature does not verify");
            }
            return o;
        }
        // pure path: a non-composite alg MUST NOT carry the signed suite field (§4.2).
        if (o.suite != 0) {
            throw new NaalpException("SuiteMismatch", "pure object carries a composite suite field");
        }
        // profile floor + COSE signature (reuse the C2 registry + verifier).
        Cose.AlgLevel al = Cose.algLevel(hp.alg);
        if (!al.known) {
            throw new NaalpException("UnknownAlg", "unregistered alg");
        }
        if (al.level < Cose.profileMinLevel(profile)) {
            throw new NaalpException("ProfileDowngrade", "signature level below the profile minimum");
        }
        if (!Cose.coseVerify1Raw(hp.alg, pubkey, tbs, sig)) {
            throw new NaalpException("BadSignature", "signature does not verify");
        }
        return o;
    }

    // --- §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) ---

    // The OPEN-DECISION toggle (design.md §4.4 profile floor applied to a rotation): a Sovereign/High
    // verifier gates the OLD (authorizing) leg by the profile floor too (DEFAULT, fail-closed) rather
    // than only the NEW leg. Ratified default = true (matches impl/go rotationOldLegFloorApplies).
    public static final boolean ROTATION_OLD_LEG_FLOOR_APPLIES = true;

    private static boolean isRotationObject(long channel, long kind) {
        return channel == 3 && kind == 0;
    }

    private static boolean isCompositeAlg(int alg) {
        return alg == Cose.ALG_COMPOSITE_65_ED25519 || alg == Cose.ALG_COMPOSITE_44_ED25519;
    }

    /**
     * Build a §5.2 Rotation object as a tag-98 COSE_Sign co-signed by the OLD then the NEW key in
     * fixed order; the body protected header names the NEW (go-forward) key. Permitted ONLY for the
     * Identity Rotation object (channel 3, kind 0); a composite leg is rejected fail-closed. Bytes are
     * byte-identical to the Go/Rust/Python/TypeScript/Ruby/PHP/C# reference implementations.
     */
    public static byte[] signRotationObject(Object o, int oldAlg, byte[] oldSeed, int newAlg, byte[] newSeed) {
        if (!isRotationObject(o.channel, o.kind)) {
            throw new NaalpException("UnknownKind", "tag-98 permitted only for the Identity Rotation object");
        }
        if (isCompositeAlg(oldAlg) || isCompositeAlg(newAlg)) {
            throw new NaalpException("Malformed", "composite-inside-rotation is undecided");
        }
        o.suite = 0; // a rotation object is never composite
        o.id = o.contentId();
        byte[] payload = Cbor.encode(o.bodyMap(true));
        byte[] bodyProt = protectedHeader(newAlg, o.signer, o.profile);
        byte[][] oldLeg = Cose.signatureLeg(bodyProt, oldAlg, oldSeed, payload);
        byte[][] newLeg = Cose.signatureLeg(bodyProt, newAlg, newSeed, payload);
        return Cose.assembleSignRaw(bodyProt, payload, List.of(oldLeg, newLeg));
    }

    /**
     * Verify a tag-98 Rotation object (§5.2): the same object-body checks as verify(), then EXACTLY
     * two legs in fixed order (old-key then new-key) BOTH verifying. Any missing/wrong/bad old leg is
     * RotationUnauthorized. Permitted ONLY for (channel 3, kind 0).
     */
    public static Object verifyRotationObject(int profile, int oldAlg, byte[] oldPk, int newAlg, byte[] newPk,
                                              KindValidator kindValidator, byte[] objBytes, Map<Long, Boolean> knownCext) {
        // Object octet-size bound (§3.4, R7): the tag-98 rotation object is a top-level signed
        // object too, so it is size-checked on raw bytes before any parse.
        if (objBytes.length > WireConstants.MAX_OBJECT_SIZE) {
            throw new NaalpException("TooLarge", "object exceeds the maximum octet size (§3.4, R7)");
        }
        Cose.RotationParse rp;
        try {
            rp = Cose.parseSignRaw(objBytes);
        } catch (NaalpException e) {
            throw new NaalpException("Malformed", "not a COSE_Sign object");
        }
        byte[] bodyProt = rp.bodyProt;
        byte[] payload = rp.payload;
        List<byte[][]> legs = rp.legs;

        Cbor.Value bv = Cbor.decodeBounded(payload, WireConstants.MAX_NESTING_DEPTH);
        if (!(bv instanceof Cbor.M bm)) {
            throw new NaalpException("Malformed", "body not a map");
        }

        byte[] claimed = null;
        List<Cbor.Pair> without = new ArrayList<>(bm.pairs.size());
        for (Cbor.Pair pr : bm.pairs) {
            if (pr.k instanceof Cbor.U u && u.v == FIELD_ID) {
                if (!(pr.val instanceof Cbor.B b)) {
                    throw new NaalpException("Malformed", "id not a bstr");
                }
                claimed = b.v;
                continue;
            }
            without.add(pr);
        }
        if (claimed == null) {
            throw new NaalpException("Malformed", "no content id");
        }
        if (!java.util.Arrays.equals(Cbor.contentId(Cbor.encode(new Cbor.M(without))), claimed)) {
            throw new NaalpException("ContentIdMismatch", "recomputed id differs");
        }

        Object o = objectFromMap(bm);
        if (o.channel > 19 || o.effect > 3 || o.profile < 1 || o.profile > 3) {
            throw new NaalpException("RangeError", "field out of range");
        }

        Protected hp = parseProtected(bodyProt);
        if (hp.version != NAALP_VERSION) {
            throw new NaalpException("UnsupportedVersion", "bad naalp-version");
        }
        if (!java.util.Arrays.equals(hp.signer, o.signer) || hp.profile != o.profile) {
            throw new NaalpException("HeaderBodyMismatch", "protected header disagrees with body");
        }
        if (o.cext != null) {
            for (Cbor.Pair pr : o.cext.pairs) {
                boolean known = pr.k instanceof Cbor.U u && knownCext != null && Boolean.TRUE.equals(knownCext.get(u.v));
                if (!known) {
                    throw new NaalpException("UnknownCriticalExt", "unrecognized critical extension");
                }
            }
        }

        // tag-98 is permitted ONLY for the Identity-channel Rotation object (channel 3, kind 0).
        if (!isRotationObject(o.channel, o.kind)) {
            throw new NaalpException("UnknownKind", "tag-98 permitted only for the Identity Rotation object");
        }
        if (kindValidator == null || !kindValidator.isKnown(o.channel, o.kind)) {
            throw new NaalpException("UnknownKind", "kind/channel not a registered surface");
        }
        if (isCompositeAlg(hp.alg)) {
            throw new NaalpException("Malformed", "composite-inside-rotation is undecided");
        }
        if (hp.alg != newAlg) {
            throw new NaalpException("KeyAlgMismatch", "body header alg is not the new key alg");
        }

        // EXACTLY two legs, fixed order (old, new). A missing/lone leg IS "old leg dropped".
        if (legs.size() != 2) {
            throw new NaalpException("RotationUnauthorized", "rotation must carry exactly two legs");
        }
        int oldLegAlg = Cose.algFromProtected(legs.get(0)[0]);
        int newLegAlg = Cose.algFromProtected(legs.get(1)[0]);
        if (isCompositeAlg(oldLegAlg) || isCompositeAlg(newLegAlg)) {
            throw new NaalpException("Malformed", "composite leg in a rotation");
        }
        if (oldLegAlg != oldAlg || newLegAlg != newAlg) {
            throw new NaalpException("RotationUnauthorized", "legs not in (old, new) order");
        }

        // profile floor: the NEW (go-forward) leg always; the OLD leg iff the fail-closed toggle applies.
        Cose.AlgLevel nl = Cose.algLevel(newLegAlg);
        if (!nl.known) {
            throw new NaalpException("UnknownAlg", "unregistered alg");
        }
        if (nl.level < Cose.profileMinLevel(profile)) {
            throw new NaalpException("ProfileDowngrade", "new-leg level below the profile minimum");
        }
        if (ROTATION_OLD_LEG_FLOOR_APPLIES) {
            Cose.AlgLevel ol = Cose.algLevel(oldLegAlg);
            if (!ol.known) {
                throw new NaalpException("UnknownAlg", "unregistered alg");
            }
            if (ol.level < Cose.profileMinLevel(profile)) {
                throw new NaalpException("ProfileDowngrade", "old-leg level below the profile minimum");
            }
        }

        // both legs MUST verify over their per-signer ToBeSigned.
        byte[] oldTbs = Cose.signatureToBeSigned(bodyProt, oldLegAlg, payload);
        if (!Cose.coseVerify1Raw(oldLegAlg, oldPk, oldTbs, legs.get(0)[1])) {
            throw new NaalpException("RotationUnauthorized", "old leg does not verify");
        }
        byte[] newTbs = Cose.signatureToBeSigned(bodyProt, newLegAlg, payload);
        if (!Cose.coseVerify1Raw(newLegAlg, newPk, newTbs, legs.get(1)[1])) {
            throw new NaalpException("RotationUnauthorized", "new leg does not verify");
        }
        return o;
    }
}
