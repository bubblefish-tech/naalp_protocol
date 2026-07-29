// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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
    // object body field numbers (§2.1)
    public static final int FIELD_ID = 1;
    public static final int FIELD_KIND = 2;
    public static final int FIELD_CHANNEL = 3;
    public static final int FIELD_TIER = 4;
    public static final int FIELD_SIGNER = 5;
    public static final int FIELD_CREATED = 6;
    public static final int FIELD_EFFECT = 7;
    public static final int FIELD_CAUSES = 8;
    public static final int FIELD_PROFILE = 9;
    public static final int FIELD_BODY = 10;
    public static final int FIELD_EXT = 11;
    public static final int FIELD_CEXT = 12;

    /** The protected-header naalp-version (§2.5). */
    public static final long NAALP_VERSION = 1;

    /**
     * The COSE protected-header parameter (a text-string label, which cannot collide with any
     * integer-labeled standard COSE parameter, RFC 9052 §3.1) under which N-AALP carries its
     * routing copies {@code {1:signer, 2:profile, 3:version}}.
     */
    private static final String HEADER_LABEL = "naalp";

    private Envelope() {}

    /**
     * Whether (channel, kind) is a recognized surface kind. The envelope owns the fail-closed
     * dispatch ({@code UnknownKind}); the per-channel kind tables are the surface layer's content
     * ({@link Channels}). A {@code null} validator rejects every kind.
     */
    @FunctionalInterface
    public interface KindValidator {
        boolean isKnown(long channel, long kind);
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

        private Cbor.M bodyMap(boolean includeId) {
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
            return new Cbor.M(pairs);
        }

        /** The object content id over the body without field 1 (§2.3). */
        public byte[] contentId() {
            return Cbor.contentId(Cbor.encode(bodyMap(false)));
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

    /** Parsed protected-header routing fields: {@code {1: alg}, "naalp": {1,2,3}}. */
    private static final class Protected {
        int alg;
        byte[] signer;
        long profile;
        long version;
    }

    private static Protected parseProtected(byte[] prot) {
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
        if (cextV != null && !(cextV instanceof Cbor.M)) {
            throw new NaalpException("Malformed", "cext not a map");
        }
        Object o = new Object(kind, channel, tier, signer, created, effect, profile, body, causes,
                (Cbor.M) extV, (Cbor.M) cextV);
        Cbor.Value idV = fields.get((long) FIELD_ID);
        if (idV instanceof Cbor.B ib) {
            o.id = ib.v;
        }
        return o;
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
        byte[][] parts = Cose.parseSign1Raw(objBytes);
        byte[] prot = parts[0];
        byte[] payload = parts[1];
        byte[] sig = parts[2];

        Cbor.Value bv = Cbor.decode(payload); // rejects non-canonical CBOR (NonCanonical, §2.6)
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

        // profile floor + COSE signature (reuse the C2 registry + verifier).
        Cose.AlgLevel al = Cose.algLevel(hp.alg);
        if (!al.known) {
            throw new NaalpException("UnknownAlg", "unregistered alg");
        }
        if (al.level < Cose.profileMinLevel(profile)) {
            throw new NaalpException("ProfileDowngrade", "signature level below the profile minimum");
        }
        byte[] tbs = Cose.toBeSignedRaw(prot, payload);
        if (!Cose.coseVerify1Raw(hp.alg, pubkey, tbs, sig)) {
            throw new NaalpException("BadSignature", "signature does not verify");
        }
        return o;
    }
}
