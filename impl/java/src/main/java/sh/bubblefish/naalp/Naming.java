// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * C19 — name bindings and the signed A2A task-state profile for the Java SDK (design.md §22;
 * R-NAME-1..6, R-A2A-1..7).
 *
 * <p>C19 is two receipt-CHAINED, signed, OFFLINE-WALKABLE surfaces carried on N-AALP's own signed
 * object. Both reuse the C7 audit receipt-chain construction (§8.1) unchanged — head = SHA-384(body),
 * genesis prev = 48 zero bytes, a monotonic seq, the prior head carried in the body so editing or
 * omitting a record breaks the next record's linkage — and they add NO new envelope, encoding,
 * signature, identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP body
 * (COSE_Sign1, §4), reusing the T1 content-id framing (§2.3) and the C7 chain.
 *
 * <p>Task 4.1 — name bindings: a {@link NameBinding} {1:name,2:signer,3:seq,4:prev} maps a name to a
 * signer id and CHAINS onto the prior binding for that name (prev = the prior binding's head; genesis
 * prev is zero). A key rotation is a NEW binding at the next seq naming the new signer. A binding is
 * DATED BY its chain position (seq); the envelope's {@code created} field is advisory only. A name's
 * history is WALKABLE offline ({@link #walkHistory}), a deleted/omitted binding leaves a detectable
 * HOLE at the first-broken position ({@link #detectHole}), and two bindings by ONE authority at the
 * SAME (name, seq) naming DIFFERENT signers are a FORK reported at that seq ({@link #detectFork} /
 * {@link NameForkProof}).
 *
 * <p>Task 4.2 — the signed A2A task-state profile: {@link TaskState} is the IMPORTED A2A (Agent2Agent)
 * TaskState vocabulary (carriage, not adoption): the eight states submitted, working, input-required,
 * auth-required, completed, canceled, failed, rejected (A2A §4.1.3: start = submitted; terminal =
 * completed/canceled/failed/rejected; interrupted = input-required/auth-required). A {@link Transition}
 * {1:task,2:card,3:from,4:to,5:seq,6:prev} is one receipt-CHAINED signed state transition. The
 * legal-edge table is DERIVED from those documented A2A category rules; {@link #verifyTransition}
 * rejects an illegal edge, and {@link #verifyTaskChain} walks a task's transition chain enforcing the
 * start state, contiguity, the legal-edge table, prev/seq linkage, the card binding, and the
 * signatures. {@code card} is the content-id of the A2A Agent Card attestation (a C18
 * naalp-description-import, {@link Description.Import}) that binds the profile to an agent/operation; a
 * transition carrying a foreign card is rejected.
 *
 * <p>An independent transcription of impl/go/naming (cross-checked against impl/python/naalp/naming).
 * The byte surfaces (binding/transition body/head/id, card import body/id, legal-edge table, the
 * >2^53 seq round-trip, the minimal/canonical/look-alike cases) are graded against
 * vectors/naming/cases.json; the chain verifiers run over REAL deterministic ML-DSA-65 signed
 * COSE_Sign1 objects (via {@link Cose#coseSign1}), and the two cross-language pins (SHA-384 of the
 * seq-0 signed binding and transition, seed = 0x11*32) prove Java == Go == Rust == Python byte-identical
 * signed objects. Every check is fail-closed (§15): a failing object is rejected whole, returns its
 * named error, and causes no state change.
 */
public final class Naming {
    /** The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. */
    public static final int HEAD_SIZE = 48;

    private Naming() {}

    private static byte[] sha384(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    /** A fresh 48-octet zero prev — the empty-chain link (the C7 chain genesis). */
    public static byte[] genesis() {
        return new byte[HEAD_SIZE];
    }

    /** SHA-384 over a body — a 48-octet digest (the same construction as audit.Receipt.head). */
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

    // ---- the COSE_Sign1 signing/verification helpers (reuse the C2 layer, R-11.3) ----------------

    /** The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits. */
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
        throw new NaalpException("NameMalformed", "protected header has no alg");
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

    // ==== Task 4.1 — name bindings ================================================================

    /** Maps a name to a signer id at a chain position. It chains onto the prior binding for the same
     * name: {@code prev} is the prior binding's head (genesis for seq 0). A key rotation is a new
     * binding at the next seq naming the new signer. The binding is DATED BY seq; the envelope's
     * {@code created} is advisory. */
    public static final class NameBinding {
        public final String name;   // the name being bound (a durable, human-readable name)
        public final byte[] signer; // the signer id this binding maps the name to (opaque bytes; §5.1)
        public final long seq;      // monotonic per-name chain position; seq 0 is the genesis binding
        public final byte[] prev;   // the prior binding's head (HEAD_SIZE bytes; genesis is zero)

        public NameBinding(String name, byte[] signer, long seq, byte[] prev) {
            this.name = name;
            this.signer = signer.clone();
            this.seq = seq;
            this.prev = prev.clone();
        }

        /** Deterministic-CBOR encoding {1:name,2:signer,3:seq,4:prev}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(name)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(signer)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(seq)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(prev)))));
        }

        /** The chain head after this binding: SHA-384 of the binding body (48 octets). */
        public byte[] head() {
            return Naming.head(bytes());
        }

        /** The binding's T1 content-id (50 octets). */
        public byte[] id() {
            return contentId(bytes());
        }
    }

    /** Reconstruct a NameBinding from its body bytes alone. A body that is not exactly the {1,2,3,4}
     * map with the right value types is NameMalformed (fail-closed). */
    public static NameBinding parseNameBinding(byte[] b) {
        Cbor.M m = decodeMap(b);
        String name = tstrField(m, 1);
        byte[] signer = bstrField(m, 2);
        Long seq = uintField(m, 3);
        byte[] prev = bstrField(m, 4);
        if (name == null || signer == null || seq == null || prev == null) {
            throw new NaalpException("NameMalformed", "body is not a well-formed name binding");
        }
        return new NameBinding(name, signer, seq, prev);
    }

    /** Produce the tagged COSE_Sign1 object over the binding body (real deterministic ML-DSA). */
    public static byte[] signBinding(NameBinding nb, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), nb.bytes());
    }

    /** Verify the binding's full signature under the profile, then reconstruct it from the signed body
     * bytes. A bad signature is BadSignature; a malformed body is NameMalformed. Fail-closed. */
    public static NameBinding verifyBinding(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[] payload = verifySign1(obj, profile, alg, pubkey);
        return parseNameBinding(payload);
    }

    /** A naming authority that appends monotonic signed bindings for ONE name (mirroring the C7 audit
     * authority). Each append records a name -> signer mapping at the next chain position; a rotation is
     * simply an append naming the new signer. Signs with a real deterministic ML-DSA key from {@code seed}. */
    public static final class Registrar {
        private final String name;
        private final int alg;
        private final byte[] seed;
        private byte[] chainHead;
        private long seq;

        public Registrar(String name, int alg, byte[] seed) {
            this.name = name;
            this.alg = alg;
            this.seed = seed.clone();
            this.chainHead = genesis();
            this.seq = 0;
        }

        /** Record a binding of the registrar's name to {@code subject} at the next chain position,
         * returning the binding and its tagged COSE_Sign1 object. Seq increases by one per append; the
         * head advances. */
        public SignedBinding append(byte[] subject) {
            NameBinding nb = new NameBinding(name, subject, seq, chainHead);
            byte[] obj = signBinding(nb, alg, seed);
            chainHead = nb.head();
            seq++;
            return new SignedBinding(nb, obj);
        }
    }

    /** The (binding, tagged COSE_Sign1 object) pair a {@link Registrar#append} returns. */
    public static final class SignedBinding {
        public final NameBinding binding;
        public final byte[] obj;

        public SignedBinding(NameBinding binding, byte[] obj) {
            this.binding = binding;
            this.obj = obj;
        }
    }

    /** One step of a walked name history: the chain position and the signer the name mapped to at that
     * position, with the chain head after it. */
    public static final class NameEvent {
        public final long seq;
        public final byte[] signer;
        public final byte[] head;

        public NameEvent(long seq, byte[] signer, byte[] head) {
            this.seq = seq;
            this.signer = signer.clone();
            this.head = head.clone();
        }
    }

    /** Verify a name-binding chain's structural continuity OFFLINE (no signatures) and return the
     * ordered signer succession. Requires every binding to name the SAME name, seq i to equal its index,
     * and prev to link to the previous binding's head (genesis zero for seq 0). A gap, reorder, omitted
     * binding, or a name change is NameChainBroken (fail-closed). The CURRENT signer is the last event's
     * signer. */
    public static List<NameEvent> walkHistory(List<NameBinding> bindings) {
        List<NameEvent> events = new ArrayList<>(bindings.size());
        byte[] h = genesis();
        String name = null;
        for (int i = 0; i < bindings.size(); i++) {
            NameBinding nb = bindings.get(i);
            if (i == 0) {
                name = nb.name;
            } else if (!nb.name.equals(name)) {
                throw new NaalpException("NameChainBroken", "a chain is for exactly one name");
            }
            if (nb.seq != i || !Arrays.equals(nb.prev, h)) {
                throw new NaalpException("NameChainBroken", "prev/seq does not chain to the previous binding");
            }
            h = nb.head();
            events.add(new NameEvent(nb.seq, nb.signer, h));
        }
        return events;
    }

    /** Check a name-binding chain offline against the authority's key. Each element is the tagged
     * COSE_Sign1 object for one binding. Verifies every signature under the profile (verifyBinding),
     * then enforces structural continuity — every binding names the SAME name, seq i equals its index,
     * prev links to the previous head — returning the verified, ordered bindings. A bad signature is
     * BadSignature; a broken link, a seq gap, or a name change is NameChainBroken. Fail-closed. */
    public static List<NameBinding> verifyChain(List<byte[]> objs, int profile, int alg, byte[] pubkey) {
        byte[] h = genesis();
        String name = null;
        List<NameBinding> out = new ArrayList<>(objs.size());
        for (int i = 0; i < objs.size(); i++) {
            NameBinding nb = verifyBinding(objs.get(i), profile, alg, pubkey);
            if (i == 0) {
                name = nb.name;
            } else if (!nb.name.equals(name)) {
                throw new NaalpException("NameChainBroken", "a chain is for exactly one name");
            }
            if (nb.seq != i || !Arrays.equals(nb.prev, h)) {
                throw new NaalpException("NameChainBroken", "prev/seq does not chain to the previous binding");
            }
            h = nb.head();
            out.add(nb);
        }
        return out;
    }

    /** The result of a hole/gap detection: the first-broken position and whether a break was found. */
    public static final class Break {
        public final int position;
        public final boolean broken;

        public Break(int position, boolean broken) {
            this.position = position;
            this.broken = broken;
        }
    }

    /** Report whether a presented (possibly gappy) binding list breaks contiguity — a deleted/omitted
     * binding — and, if so, the FIRST-BROKEN position: the index i where the i-th presented binding's
     * seq is not i or its prev does not link to the previous binding's head. A contiguous list returns
     * (0, false). */
    public static Break detectHole(List<NameBinding> bindings) {
        byte[] h = genesis();
        for (int i = 0; i < bindings.size(); i++) {
            NameBinding nb = bindings.get(i);
            if (nb.seq != i || !Arrays.equals(nb.prev, h)) {
                return new Break(i, true);
            }
            h = nb.head();
        }
        return new Break(0, false);
    }

    /** Compare two bindings for the SAME name and report whether they equivocate — the SAME name and
     * seq but DIFFERENT bodies (a different signer or prev) — and, if so, the seq position at which they
     * conflict. A different name or seq is a legitimate distinct binding; byte-identical bindings are a
     * benign duplicate. Both non-fork cases return (0, false). */
    public static Break detectFork(NameBinding a, NameBinding b) {
        if (!a.name.equals(b.name) || a.seq != b.seq) {
            return new Break(0, false);
        }
        if (Arrays.equals(a.bytes(), b.bytes())) {
            return new Break(0, false);
        }
        return new Break((int) a.seq, true);
    }

    /** Non-repudiable evidence of a name fork: two validly-signed NameBinding objects by ONE authority
     * at the SAME (name, seq) naming DIFFERENT signers, carried as the accused authority's OWN two signed
     * objects (the tagged COSE_Sign1 bytes). Because a single verifier checks BOTH signed objects, the
     * proof is self-contained — any third party confirms both signatures against the accused key. */
    public static final class NameForkProof {
        public final byte[] signer;  // accused authority signer id (both objects verify under its key)
        public final byte[] signedA;
        public final byte[] signedB;

        public NameForkProof(byte[] signer, byte[] signedA, byte[] signedB) {
            this.signer = signer.clone();
            this.signedA = signedA.clone();
            this.signedB = signedB.clone();
        }

        /** Accept iff ALL hold: (1) the signer id is present; (2) BOTH signed objects verify under the
         * key (which, because a single verifier checks both, proves one authority); (3) the two bindings
         * share one name and seq; and (4) their bodies differ. Returns the seq position at which it
         * forks. An unnamed signer, a different name/seq, or identical bodies is NameForkProofInvalid; a
         * signature that does not verify is BadSignature. Fail-closed. */
        public int verify(int profile, int alg, byte[] pubkey) {
            if (signer.length == 0) {
                throw new NaalpException("NameForkProofInvalid", "an unnamed accused is not evidence");
            }
            NameBinding a = verifyBinding(signedA, profile, alg, pubkey);
            NameBinding b = verifyBinding(signedB, profile, alg, pubkey);
            Break f = detectFork(a, b);
            if (!f.broken) {
                throw new NaalpException("NameForkProofInvalid", "not the same (name, seq) or identical bodies");
            }
            return f.position;
        }
    }

    // ==== Task 4.2 — the signed A2A task-state profile ============================================

    /** TaskState codes (stable N-AALP wire codes for the imported A2A vocabulary; A2A §4.1.3). */
    public static final long STATE_SUBMITTED = 0;       // acknowledged, not yet started (the start state)
    public static final long STATE_WORKING = 1;         // actively processed
    public static final long STATE_INPUT_REQUIRED = 2;  // interrupted, awaiting client input
    public static final long STATE_AUTH_REQUIRED = 3;   // interrupted, awaiting authentication
    public static final long STATE_COMPLETED = 4;       // terminal success
    public static final long STATE_CANCELED = 5;        // terminal, canceled before completion
    public static final long STATE_FAILED = 6;          // terminal, finished with an error
    public static final long STATE_REJECTED = 7;        // terminal, the agent declined the task

    /** The A2A lifecycle start state (submitted). */
    public static final long START_STATE = STATE_SUBMITTED;

    private static final long[] TERMINAL = {STATE_COMPLETED, STATE_CANCELED, STATE_FAILED, STATE_REJECTED};
    private static final long[] INTERRUPTED = {STATE_INPUT_REQUIRED, STATE_AUTH_REQUIRED};

    /** The A2A state name, or "unknown" for an out-of-range code. */
    public static String stateName(long s) {
        if (s == STATE_SUBMITTED) return "submitted";
        if (s == STATE_WORKING) return "working";
        if (s == STATE_INPUT_REQUIRED) return "input-required";
        if (s == STATE_AUTH_REQUIRED) return "auth-required";
        if (s == STATE_COMPLETED) return "completed";
        if (s == STATE_CANCELED) return "canceled";
        if (s == STATE_FAILED) return "failed";
        if (s == STATE_REJECTED) return "rejected";
        return "unknown";
    }

    /** Whether s is one of the eight defined A2A states. */
    public static boolean isState(long s) {
        return s >= STATE_SUBMITTED && s <= STATE_REJECTED;
    }

    /** Whether s is a terminal state (completed/canceled/failed/rejected). */
    public static boolean isTerminal(long s) {
        for (long t : TERMINAL) {
            if (s == t) {
                return true;
            }
        }
        return false;
    }

    /** Whether s is an interrupted state (input-required/auth-required). */
    public static boolean isInterrupted(long s) {
        return s == STATE_INPUT_REQUIRED || s == STATE_AUTH_REQUIRED;
    }

    private static long edgeKey(long from, long to) {
        return (from << 8) | to;
    }

    /** The explicit A2A transition table: the legal (from, to) edges derived from the A2A category
     * rules (design §22.3). It is the authoritative source both {@link #legalEdge} and
     * {@link #verifyTaskChain} consult. */
    private static final Set<Long> LEGAL_EDGES = buildLegalEdges();

    private static Set<Long> buildLegalEdges() {
        long[] active = {STATE_SUBMITTED, STATE_WORKING};
        Set<Long> m = new HashSet<>();
        m.add(edgeKey(STATE_SUBMITTED, STATE_WORKING)); // begin processing (the only active->active edge)
        for (long s : active) {                          // active -> interrupted
            for (long t : INTERRUPTED) {
                m.add(edgeKey(s, t));
            }
        }
        for (long s : active) {                          // active -> terminal
            for (long t : TERMINAL) {
                m.add(edgeKey(s, t));
            }
        }
        for (long s : INTERRUPTED) {                     // interrupted -> working (client acted)
            m.add(edgeKey(s, STATE_WORKING));
        }
        for (long s : INTERRUPTED) {                     // interrupted -> terminal
            for (long t : TERMINAL) {
                m.add(edgeKey(s, t));
            }
        }
        return m;
    }

    /** Whether (from -> to) is a legal A2A transition edge per the table. A self-loop, an edge out of a
     * terminal state, an edge touching an undefined state, and any edge not in the table are all false. */
    public static boolean legalEdge(long from, long to) {
        if (!isState(from) || !isState(to)) {
            return false;
        }
        return LEGAL_EDGES.contains(edgeKey(from, to));
    }

    /** A copy of the legal transition table as a sorted list of {from, to} pairs. */
    public static List<long[]> legalEdges() {
        List<long[]> out = new ArrayList<>(LEGAL_EDGES.size());
        for (long k : LEGAL_EDGES) {
            out.add(new long[]{k >> 8, k & 0xFF});
        }
        out.sort((x, y) -> x[0] != y[0] ? Long.compare(x[0], y[0]) : Long.compare(x[1], y[1]));
        return out;
    }

    /** The edge-legality gate: returns normally iff (from -> to) is a legal A2A edge, else throws
     * IllegalTransition. Fail-closed. */
    public static void verifyTransition(long from, long to) {
        if (!legalEdge(from, to)) {
            throw new NaalpException("IllegalTransition", "not a legal A2A transition edge");
        }
    }

    /** One signed, receipt-CHAINED A2A task state transition (design §22.4). It chains onto the prior
     * transition of the same task: {@code prev} is the prior transition's head (genesis for seq 0).
     * Dated by seq. {@code card} is the content-id of the A2A Agent Card attestation (a C18 import) that
     * binds this profile to an agent/operation. */
    public static final class Transition {
        public final byte[] task;   // the task id (opaque bytes)
        public final byte[] card;   // content-id of the bound A2A Agent Card attestation (the C18 import)
        public final long from;     // the source state
        public final long to;       // the target state
        public final long seq;      // monotonic per-task chain position; seq 0's from MUST be the start state
        public final byte[] prev;   // the prior transition's head (HEAD_SIZE bytes; genesis is zero)

        public Transition(byte[] task, byte[] card, long from, long to, long seq, byte[] prev) {
            this.task = task.clone();
            this.card = card.clone();
            this.from = from;
            this.to = to;
            this.seq = seq;
            this.prev = prev.clone();
        }

        /** Deterministic-CBOR encoding {1:task,2:card,3:from,4:to,5:seq,6:prev}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(task)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(card)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(from)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.U(to)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(seq)),
                    new Cbor.Pair(new Cbor.U(6), new Cbor.B(prev)))));
        }

        /** The chain head after this transition: SHA-384 of the transition body (48 octets). */
        public byte[] head() {
            return Naming.head(bytes());
        }

        /** The transition's T1 content-id (50 octets). */
        public byte[] id() {
            return contentId(bytes());
        }
    }

    /** Reconstruct a Transition from its body bytes alone. A body that is not exactly the {1,2,3,4,5,6}
     * map with the right value types is NameMalformed (fail-closed). */
    public static Transition parseTransition(byte[] b) {
        Cbor.M m = decodeMap(b);
        byte[] task = bstrField(m, 1);
        byte[] card = bstrField(m, 2);
        Long from = uintField(m, 3);
        Long to = uintField(m, 4);
        Long seq = uintField(m, 5);
        byte[] prev = bstrField(m, 6);
        if (task == null || card == null || from == null || to == null || seq == null || prev == null) {
            throw new NaalpException("NameMalformed", "body is not a well-formed task transition");
        }
        return new Transition(task, card, from, to, seq, prev);
    }

    /** Produce the tagged COSE_Sign1 object over the transition body (real deterministic ML-DSA). */
    public static byte[] signTransition(Transition t, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), t.bytes());
    }

    /** Verify a transition's full signature under the profile, reconstruct it from the signed body
     * bytes, AND check that its edge is legal. A bad signature is BadSignature; an illegal edge is
     * IllegalTransition. Fail-closed. */
    public static Transition verifyTransitionObject(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[] payload = verifySign1(obj, profile, alg, pubkey);
        Transition t = parseTransition(payload);
        verifyTransition(t.from, t.to);
        return t;
    }

    /** Walk a task's transition chain offline against the authority's key and the bound card
     * attestation. Enforces, in order and fail-closed: (1) the SIGNATURE of every transition
     * (BadSignature otherwise); (2) prev/seq linkage (each prev links to the prior head, genesis zero for
     * seq 0; seq i == index) — a gap/reorder is TaskChainBroken; (3) the CARD BINDING (every transition's
     * card equals {@code card}) — ForeignCard otherwise; and (4) the START STATE (seq-0's from is
     * START_STATE), CONTIGUITY (each from == the prior to), and the LEGAL-EDGE TABLE at every step
     * (including the terminal-cannot-continue rule) — IllegalTransition otherwise. Returns the verified,
     * ordered transitions. It never authorizes; it accepts or rejects. */
    public static List<Transition> verifyTaskChain(List<byte[]> objs, byte[] card, int profile, int alg, byte[] pubkey) {
        byte[] h = genesis();
        long prevTo = 0;
        List<Transition> out = new ArrayList<>(objs.size());
        for (int i = 0; i < objs.size(); i++) {
            byte[] payload = verifySign1(objs.get(i), profile, alg, pubkey); // BadSignature (foreign/tampered)
            Transition t = parseTransition(payload);
            if (t.seq != i || !Arrays.equals(t.prev, h)) {
                throw new NaalpException("TaskChainBroken", "prev/seq does not chain to the previous transition");
            }
            if (!Arrays.equals(t.card, card)) {
                throw new NaalpException("ForeignCard", "transition binds a card other than the profile's bound card");
            }
            if (i == 0) {
                if (t.from != START_STATE) {
                    throw new NaalpException("IllegalTransition", "the first transition must leave the start state");
                }
            } else if (t.from != prevTo) {
                throw new NaalpException("IllegalTransition", "non-contiguous: this from must equal the prior to");
            }
            verifyTransition(t.from, t.to); // an illegal edge (incl. a from-terminal edge)
            h = t.head();
            prevTo = t.to;
            out.add(t);
        }
        return out;
    }

    /** Report whether a presented (possibly gappy) transition list breaks contiguity — a
     * deleted/omitted or reordered transition — and, if so, the FIRST-BROKEN position. A contiguous list
     * returns (0, false). */
    public static Break detectTaskGap(List<Transition> transitions) {
        byte[] h = genesis();
        for (int i = 0; i < transitions.size(); i++) {
            Transition t = transitions.get(i);
            if (t.seq != i || !Arrays.equals(t.prev, h)) {
                return new Break(i, true);
            }
            h = t.head();
        }
        return new Break(0, false);
    }

    // ---- small deterministic-CBOR field accessors (strict decode; NonCanonical propagates) ---------

    private static Cbor.M decodeMap(byte[] b) {
        Cbor.Value v = Cbor.decode(b); // strict decoder: throws NonCanonical on a non-canonical body
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("NameMalformed", "body is not a map");
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

    private static String tstrField(Cbor.M m, long k) {
        Cbor.Value v = field(m, k);
        return v instanceof Cbor.T t ? t.v : null;
    }

    private static Long uintField(Cbor.M m, long k) {
        Cbor.Value v = field(m, k);
        return v instanceof Cbor.U u ? u.v : null;
    }

    /** Decode a UTF-8 byte payload to a String. */
    static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }
}
