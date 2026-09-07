// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * C18 — the signed description / directory / import primitive for the Java SDK (design.md §21;
 * R-DESC-1..8).
 *
 * <p>C18 is a signed, OFFLINE-VERIFIABLE description and discovery layer carried on N-AALP's own signed
 * object. Its load-bearing property is that authority lives in the SIGNED BYTES, never in the
 * connection or the host that served them: the same signed Description re-verifies byte-identically
 * when an unrelated host serves it, because the signature (not a TLS-fetch origin) is the authority. It
 * introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3): each object
 * is an ordinary signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice
 * ({@link Policy}) and the T1 content-id framing (§2.3) unchanged.
 *
 * <p>Three wire objects: a {@code Description} (this class, {1: service, 2: operations[]}) listing a
 * service's operations; a {@link Directory} ({1: directory, 2: version, 3: members[]}) whose two
 * conflicting versions from ONE signer are a FORK detected at the first-differing member position; and
 * an {@link Import} ({1: importer, 2: format, 3: foreign, 4: operations[]}) carrying a foreign
 * description format octet-for-octet (carriage, not adoption) whose IMPORTER — recomputed
 * self-certifyingly from the verifying key — is the SOLE authorization identity (R-14.6).
 *
 * <p>Every check is fail-closed (§15). An independent transcription of impl/go/description (cross-
 * checked against impl/python/naalp/description): the byte surface (bodies, heads, content ids,
 * foreign-id binding, fork position, closed-format rejection) is graded against
 * vectors/description/cases.json; the offline-verification, fork-proof, and confused-deputy paths use
 * real deterministic ML-DSA-65 and are demonstrated in isolation (the corpus carries no signed vector).
 *
 * <p>Deviation from the Go reference, honest F4 note: Go's VerifyImport carries an
 * {@code ErrVerifierKeyMismatch} guard because it takes BOTH an (alg, pubkey) pair AND a separate
 * {@code cose.Verifier}, and must bind them before deriving the authority id. This Java idiom (as
 * {@link Gateway}/{@link Delegation} do) verifies with a single (alg, pubkey) pair, so the authority id
 * is ALWAYS derived from exactly the key that verified the signature — the mismatch the Go guard
 * prevents is structurally impossible here, so there is no VerifierKeyMismatch surface to port. It is
 * not silently dropped; it is absent because the vulnerability it guards cannot arise in this signature
 * (identical to the impl/python deviation).
 */
public final class Description {
    /** The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain. */
    public static final int HEAD_SIZE = 48;

    // Foreign description format codes (design §21; the closed naalp-description-format registry).
    public static final long FORMAT_A2A_CARD = 1;         // A2A Agent Card
    public static final long FORMAT_ANP_DESCRIPTION = 2;  // ANP Agent Description
    public static final long FORMAT_AGNTCY_BADGE = 3;     // AGNTCY Agent Badge

    public final byte[] service;                 // opaque service id
    public final List<Operation> operations;     // the listed operations

    public Description(byte[] service, List<Operation> operations) {
        this.service = service.clone();
        this.operations = new ArrayList<>(operations);
    }

    private static byte[] sha384(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    /** SHA-384 over a body — a 48-octet digest (the same construction as the C7 receipt head). */
    private static byte[] head(byte[] b) {
        return sha384(b);
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

    private static boolean isKnownFormat(long fmt) {
        return fmt == FORMAT_A2A_CARD || fmt == FORMAT_ANP_DESCRIPTION || fmt == FORMAT_AGNTCY_BADGE;
    }

    // ---- Operation: one listed operation with its effect + approval declaration (design §21.2) ----

    /** One entry of a Description or Import mapping: a named operation, its C5 effect class, and whether
     * it requires an approval. {@code requiresApproval} is the uint 1 (yes) / 0 (no) — no CBOR boolean
     * (design §3.1). */
    public static final class Operation {
        public final String name;
        public final long effect;
        public final long requiresApproval;

        public Operation(String name, long effect, long requiresApproval) {
            this.name = name;
            this.effect = effect;
            this.requiresApproval = requiresApproval;
        }

        Cbor.M toMap() {
            return new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(name)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(effect)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(requiresApproval))));
        }

        /** Deterministic-CBOR encoding of the operation body {1:name,2:effect,3:requires_approval}. */
        public byte[] bytes() {
            return Cbor.encode(toMap());
        }

        /** The per-operation effect, normalized fail-closed: an unrecognized value is destructive. */
        public long effectClass() {
            return Policy.normalizeEffect(effect);
        }

        /** True iff the operation declares that it requires an approval. */
        public boolean requiresApprovalFlag() {
            return requiresApproval == 1;
        }
    }

    private static Operation operationFromValue(Cbor.Value v) {
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("DescMalformed", "operation is not a map");
        }
        String name = null;
        Long effect = null;
        Long req = null;
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U ku)) {
                throw new NaalpException("DescMalformed", "non-uint operation key");
            }
            if (ku.v == 1 && p.val instanceof Cbor.T t) {
                name = t.v;
            } else if (ku.v == 2 && p.val instanceof Cbor.U u) {
                effect = u.v;
            } else if (ku.v == 3 && p.val instanceof Cbor.U u) {
                req = u.v;
            }
        }
        if (name == null || effect == null || req == null) {
            throw new NaalpException("DescMalformed", "operation missing a mandatory field");
        }
        if (req > 1) {
            throw new NaalpException("MalformedApprovalFlag", "requires_approval is outside {0,1}");
        }
        return new Operation(name, effect, req);
    }

    private static List<Operation> operationsFromValue(Cbor.Value v) {
        if (!(v instanceof Cbor.A a)) {
            throw new NaalpException("DescMalformed", "operations is not an array");
        }
        List<Operation> ops = new ArrayList<>(a.items.size());
        for (Cbor.Value e : a.items) {
            ops.add(operationFromValue(e));
        }
        return ops;
    }

    private static Cbor.A operationsValue(List<Operation> ops) {
        List<Cbor.Value> items = new ArrayList<>(ops.size());
        for (Operation op : ops) {
            items.add(op.toMap());
        }
        return new Cbor.A(items);
    }

    private static Operation findOperation(List<Operation> ops, String name) {
        for (Operation op : ops) {
            if (op.name.equals(name)) {
                return op;
            }
        }
        return null;
    }

    // ---- Description body / offline verification (design §21.2) -----------------------------------

    /** Deterministic-CBOR encoding {1: service, 2: operations[]}. */
    public byte[] bytes() {
        return Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(service)),
                new Cbor.Pair(new Cbor.U(2), operationsValue(operations)))));
    }

    /** The Description's SHA-384 head (48 octets). */
    public byte[] head() {
        return head(bytes());
    }

    /** The Description's T1 content id (50 octets). */
    public byte[] id() {
        return contentId(bytes());
    }

    /** The named operation, or {@code null} if not listed. */
    public Operation operation(String name) {
        return findOperation(operations, name);
    }

    /** Reconstruct a Description from its body bytes ALONE — the offline-verifiable property. */
    public static Description parseDescription(byte[] b) {
        Cbor.M m = decodeMap(b);
        byte[] svc = bstrField(m, 1);
        Cbor.Value opsV = field(m, 2);
        if (svc == null || opsV == null) {
            throw new NaalpException("DescMalformed", "description missing service or operations");
        }
        return new Description(svc, operationsFromValue(opsV));
    }

    /** Produce the tagged COSE_Sign1 object over the Description body. */
    public static byte[] signDescription(Description d, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), d.bytes());
    }

    /** Verify the Description's full signature under the profile, then reconstruct the operation table
     * from the signed body bytes. Because the authority is the signature over the bytes, this returns
     * the identical Description regardless of which host served {@code obj} (R-DESC-1). Fail-closed. */
    public static Description verifyDescription(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[] payload = verifySign1(obj, profile, alg, pubkey);
        return parseDescription(payload);
    }

    // ---- Directory: a signed collection of content ids, with fork detection (design §21.3) --------

    /** A signed collection object whose members are content ids. It carries a monotonic per-signer
     * version so two versions can be compared for equivocation. */
    public static final class Directory {
        public final byte[] directory;      // opaque directory id
        public final long version;          // monotonic per-signer version
        public final List<byte[]> members;  // content ids of the member objects

        public Directory(byte[] directory, long version, List<byte[]> members) {
            this.directory = directory.clone();
            this.version = version;
            this.members = new ArrayList<>();
            for (byte[] m : members) {
                this.members.add(m.clone());
            }
        }

        /** Deterministic-CBOR encoding {1: directory, 2: version, 3: members[]}. */
        public byte[] bytes() {
            List<Cbor.Value> arr = new ArrayList<>(members.size());
            for (byte[] m : members) {
                arr.add(new Cbor.B(m));
            }
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(directory)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(version)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.A(arr)))));
        }

        public byte[] head() {
            return Description.head(bytes());
        }

        public byte[] id() {
            return contentId(bytes());
        }
    }

    /** Reconstruct a Directory from its body bytes alone. */
    public static Directory parseDirectory(byte[] b) {
        Cbor.M m = decodeMap(b);
        byte[] did = bstrField(m, 1);
        Long ver = uintField(m, 2);
        Cbor.Value memV = field(m, 3);
        if (did == null || ver == null || !(memV instanceof Cbor.A a)) {
            throw new NaalpException("DescMalformed", "directory missing or malformed field");
        }
        List<byte[]> members = new ArrayList<>(a.items.size());
        for (Cbor.Value e : a.items) {
            if (!(e instanceof Cbor.B mb)) {
                throw new NaalpException("DescMalformed", "member is not a bstr");
            }
            members.add(mb.v);
        }
        return new Directory(did, ver, members);
    }

    /** Produce the tagged COSE_Sign1 object over the Directory body. */
    public static byte[] signDirectory(Directory d, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), d.bytes());
    }

    /** Verify the Directory's full signature under the profile, then reconstruct it from the signed
     * body bytes. Fail-closed. */
    public static Directory verifyDirectory(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[] payload = verifySign1(obj, profile, alg, pubkey);
        return parseDirectory(payload);
    }

    /** The result of a fork comparison: the first-differing member position and whether it is a fork. */
    public static final class Fork {
        public final int position;
        public final boolean isFork;

        Fork(int position, boolean isFork) {
            this.position = position;
            this.isFork = isFork;
        }
    }

    /** The first index at which two member lists differ, and whether they differ at all. If the lists
     * share a common prefix and one is longer, the difference is reported at the length of the shorter
     * list. Identical lists return (0, false). */
    static Fork firstMemberDifference(List<byte[]> a, List<byte[]> b) {
        int n = Math.min(a.size(), b.size());
        for (int i = 0; i < n; i++) {
            if (!Arrays.equals(a.get(i), b.get(i))) {
                return new Fork(i, true);
            }
        }
        if (a.size() != b.size()) {
            return new Fork(n, true);
        }
        return new Fork(0, false);
    }

    /** Compare two directory versions from ONE signer and report whether they equivocate — the SAME
     * directory id and version but DIFFERENT members — and, if so, the FIRST-DIFFERING member POSITION
     * (as the §8.5 audit fork-proof reports the position of an equivocation). A different directory id
     * or version is a legitimate distinct object/succession, not a fork; identical members are a benign
     * duplicate. In both non-fork cases returns (0, false). The caller establishes the 'one signer'
     * precondition by verifying both objects under the same key. */
    public static Fork detectFork(Directory a, Directory b) {
        if (!Arrays.equals(a.directory, b.directory) || a.version != b.version) {
            return new Fork(0, false);
        }
        return firstMemberDifference(a.members, b.members);
    }

    /** Non-repudiable evidence of a directory fork: two validly-signed Directory objects by ONE signer
     * at the SAME (directory, version) listing DIFFERENT members, carried as the accused signer's OWN
     * two signed objects. Because a single verifier checks BOTH signed objects, the proof is
     * self-contained. */
    public static final class DirectoryForkProof {
        public final byte[] signer;    // accused signer id (both signed objects verify under its key)
        public final byte[] signedA;   // the accused's first signed Directory (tagged COSE_Sign1)
        public final byte[] signedB;   // the accused's second signed Directory at the same (directory, version)

        public DirectoryForkProof(byte[] signer, byte[] signedA, byte[] signedB) {
            this.signer = signer.clone();
            this.signedA = signedA.clone();
            this.signedB = signedB.clone();
        }

        /** Check that this is a genuine directory fork by the signer whose key is (alg, pubkey), and
         * return the FIRST-DIFFERING member POSITION. Accepts iff ALL hold: (1) the signer id is
         * present; (2) BOTH signed objects verify under the key (which, because a single verifier checks
         * both, proves one signer); (3) the two directories share one directory id and version; and (4)
         * their member lists differ. Any failure rejects the whole proof (fail-closed): an unnamed
         * signer, a different directory/version, or identical members is DirForkProofInvalid; a
         * signature that does not verify propagates BadSignature. */
        public int verify(int profile, int alg, byte[] pubkey) {
            if (signer.length == 0) {
                throw new NaalpException("DirForkProofInvalid", "an unnamed accused is not evidence");
            }
            Directory a = verifyDirectory(signedA, profile, alg, pubkey);
            Directory b = verifyDirectory(signedB, profile, alg, pubkey);
            Fork f = detectFork(a, b);
            if (!f.isFork) {
                throw new NaalpException("DirForkProofInvalid",
                        "same directory+version identical members, or not the same versioned directory");
            }
            return f.position;
        }
    }

    // ---- Import: foreign description carried as a signed attestation (design §21.4) ---------------

    /** Carries a foreign description format octet-for-octet (carriage, not adoption) as a signed N-AALP
     * attestation. {@code importer} is the wrapping signer id (the sole authorization identity);
     * {@code foreign} is the foreign bytes verbatim; {@code operations} is the N-AALP effect mapping the
     * importer attests. The foreign bytes' content id is bound by {@link #foreignId}. */
    public static final class Import {
        public final byte[] importer;
        public final long format;
        public final byte[] foreign;
        public final List<Operation> operations;

        public Import(byte[] importer, long format, byte[] foreign, List<Operation> operations) {
            this.importer = importer.clone();
            this.format = format;
            this.foreign = foreign.clone();
            this.operations = new ArrayList<>(operations);
        }

        /** Deterministic-CBOR encoding {1: importer, 2: format, 3: foreign, 4: operations[]}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(importer)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(format)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(foreign)),
                    new Cbor.Pair(new Cbor.U(4), operationsValue(operations)))));
        }

        public byte[] head() {
            return Description.head(bytes());
        }

        public byte[] id() {
            return contentId(bytes());
        }

        /** The T1 content id of the carried foreign bytes — the hash the attestation binds. A changed
         * foreign document yields a different foreign_id, so an attestation binds the exact bytes. */
        public byte[] foreignId() {
            return contentId(foreign);
        }

        public Operation operation(String name) {
            return findOperation(operations, name);
        }
    }

    /** Reconstruct an Import from its body bytes alone. A format code outside the closed
     * naalp-description-format set {1,2,3} is rejected on decode (UnknownDescriptionFormat), never
     * carried as an unknown format. Fail-closed. */
    public static Import parseImport(byte[] b) {
        Cbor.M m = decodeMap(b);
        byte[] imp = bstrField(m, 1);
        Long fmt = uintField(m, 2);
        byte[] foreign = bstrField(m, 3);
        Cbor.Value opsV = field(m, 4);
        if (imp == null || fmt == null || foreign == null || opsV == null) {
            throw new NaalpException("DescMalformed", "import missing a mandatory field");
        }
        if (!isKnownFormat(fmt)) {
            throw new NaalpException("UnknownDescriptionFormat",
                    "import format " + fmt + " is outside the closed set {1,2,3}");
        }
        return new Import(imp, fmt, foreign, operationsFromValue(opsV));
    }

    /** Produce the tagged COSE_Sign1 object over the Import body. */
    public static byte[] signImport(Import im, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), im.bytes());
    }

    /** An Import that has passed signature verification and the confused-deputy check. {@code
     * authorityId} is the self-certifying signer id RECOMPUTED from the verifying key — the wrapping
     * signer, and the only authorization identity. It is never any identity parsed from the foreign
     * bytes. */
    public static final class ResolvedImport {
        public final String authorityId;
        public final long format;
        public final byte[] foreignId;
        public final List<Operation> operations;

        ResolvedImport(String authorityId, long format, byte[] foreignId, List<Operation> operations) {
            this.authorityId = authorityId;
            this.format = format;
            this.foreignId = foreignId.clone();
            this.operations = operations;
        }
    }

    /** Verify a foreign-description import end-to-end and enforce the confused-deputy rule normatively.
     * It (1) verifies the signed object under the profile with real crypto; (2) recomputes the wrapping
     * signer's SELF-CERTIFYING id from the verifying key ({@link Identity#signerId}); and (3) requires
     * the attestation's {@code importer} field to equal that recomputed id (ImporterMismatch otherwise).
     * The returned {@code authorityId} is that recomputed key id — the wrapping signer — so no field
     * inside the carried foreign bytes, including any foreign identity claim, can ever become the N-AALP
     * authorization identity (R-14.6). Any failure returns its named error and authorizes nothing. */
    public static ResolvedImport verifyImport(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[] payload = verifySign1(obj, profile, alg, pubkey);
        Import im = parseImport(payload);
        String keyId = Identity.signerId(alg, pubkey);
        // The authorization identity is the wrapping key's own id. The attestation's declared importer
        // MUST match it: a signer can only ever import AS ITSELF, never as a foreign identity it names.
        if (!new String(im.importer, java.nio.charset.StandardCharsets.UTF_8).equals(keyId)) {
            throw new NaalpException("ImporterMismatch", "the attested importer is not the verifying key's signer id");
        }
        return new ResolvedImport(keyId, im.format, im.foreignId(), im.operations);
    }

    // ---- signing / verification helpers (COSE_Sign1 with the bare {1: alg} header) ----------------

    /** The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits. */
    private static byte[] protectedHeader(int alg) {
        return Cbor.encode(new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)))));
    }

    /** Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the
     * payload. Checks: alg registry, profile floor, key-alg match, signature. Fail-closed with a named
     * DescriptionError kind. */
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
        throw new NaalpException("DescMalformed", "protected header has no alg");
    }

    // ---- small deterministic-CBOR field accessors ------------------------------------------------

    private static Cbor.M decodeMap(byte[] b) {
        Cbor.Value v = Cbor.decode(b); // strict decoder: throws NonCanonical on a non-canonical body
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("DescMalformed", "body is not a map");
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
