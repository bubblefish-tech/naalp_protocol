// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * N-AALP C17 flow continuation (N-AALP-CONT) for the Java SDK (design.md §20; R-CONT-1..7).
 *
 * <p>N-AALP-CONT generalizes native streaming (one signed StreamOpen, cheap per-chunk data, one signed
 * StreamCommit over a rolling digest) into a domain-agnostic flow:
 *
 * <ul>
 *   <li>{@link FlowOpen} is the ONE full ML-DSA signature that fixes the flow's authority: its
 *       flow_id, its effect ceiling, and the content-ids of the approvals that authorize it up to that
 *       ceiling. The authority is reconstructable from the FlowOpen bytes ALONE ({@link #parseFlowOpen}).
 *   <li>A {@code Continuation} (this outer type) is a CHEAP object: no per-object signature, only a
 *       SHA-384 hash-chain link. Each link's head is SHA-384(link body); its {@code prev} is the
 *       previous link's head; the genesis prev is the FlowOpen's head. A link carries its own effect,
 *       which MUST stay at or below the ceiling (AboveCeiling otherwise — the cheap path can never
 *       escalate past the one full signature + approval).
 *   <li>{@link Checkpoint} confirms a contiguous prefix and DETECTS A GAP (GapDetected).
 *   <li>{@link FlowCommit} is a second full ML-DSA signature binding the whole ordered sequence with
 *       ONE signature regardless of the number of continuations.
 * </ul>
 *
 * <p>Domain separation is structural: FlowOpen (3 fields), Continuation (5 fields), Checkpoint (3
 * fields, a bstr head at 3) and FlowCommit (2 fields) are each a distinct deterministic-CBOR shape.
 * An independent transcription of impl/go/continuation (cross-checked against
 * impl/python/naalp/continuation); byte surfaces graded against vectors/continuation/cases.json. The
 * FlowOpen / FlowCommit signatures are real deterministic ML-DSA-65 (COSE_Sign1), demonstrated in
 * isolation (the corpus carries no signature vector for this channel).
 *
 * <p>Java-nesting note: Go's package-level type {@code Continuation} is rendered here as this outer
 * class (the cheap link), with the flow-level types nested; the package functions ParseFlowOpen /
 * VerifyChain / … are the static methods of the same names.
 */
public final class Continuation {
    /** The width of a chain head / prev link (SHA-384 = 48 bytes). A FlowOpen head anchors a chain. */
    public static final int HEAD_SIZE = 48;

    // ---- the cheap Continuation link (design §20.3) — the outer instance type --------------------

    public final byte[] flowOpenID; // the originating FlowOpen's content-id (WrongFlow if it mismatches)
    public final long seq;          // 0-based position in the chain
    public final long effect;       // this step's effect; MUST be <= the FlowOpen ceiling (AboveCeiling otherwise)
    public final byte[] payloadID;  // content-id of this step's payload
    public final byte[] prev;       // the previous link's head (the FlowOpen head for seq 0)

    public Continuation(byte[] flowOpenID, long seq, long effect, byte[] payloadID, byte[] prev) {
        this.flowOpenID = flowOpenID.clone();
        this.seq = seq;
        this.effect = effect;
        this.payloadID = payloadID.clone();
        this.prev = prev.clone();
    }

    /** Deterministic-CBOR encoding {1: flow_open_id, 2: seq, 3: effect, 4: payload_id, 5: prev}. */
    public byte[] bytes() {
        return Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(flowOpenID)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(seq)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(effect)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(payloadID)),
                new Cbor.Pair(new Cbor.U(5), new Cbor.B(prev)))));
    }

    /** This link's SHA-384 head — the prev of the next link. */
    public byte[] head() {
        return head(bytes());
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private static byte[] head(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    /** Whether {@code v} is a value of the closed C5 effect lattice (0..3). An out-of-lattice value is
     * rejected RangeError, NEVER normalized to destructive — normalizing a CEILING to destructive would
     * silently make an out-of-range ceiling the MOST-permissive one (a fail-open). */
    private static boolean inLattice(long v) {
        return v >= 0 && v <= Policy.DESTRUCTIVE;
    }

    private static NaalpException wrongFlow() {
        return new NaalpException("WrongFlow", "object's flow_open_id does not match the FlowOpen");
    }

    private static NaalpException malformed() {
        return new NaalpException("ContMalformed", "object is not a well-formed N-AALP-CONT body");
    }

    private static NaalpException range() {
        return new NaalpException("RangeError", "effect or effect_ceiling is outside the closed 0..3 lattice");
    }

    // ---- FlowOpen: the one full signature fixing the flow's authority (design §20.2) --------------

    /** Fixes a flow's identity, effect ceiling, and approval bindings. Signed with one full ML-DSA
     * signature; its authority is reconstructable from its bytes alone. */
    public static final class FlowOpen {
        public final byte[] flowID;
        public final long effectCeiling;
        public final List<byte[]> approvals;

        public FlowOpen(byte[] flowID, long effectCeiling, List<byte[]> approvals) {
            this.flowID = flowID.clone();
            this.effectCeiling = effectCeiling;
            this.approvals = new ArrayList<>();
            for (byte[] a : approvals) {
                this.approvals.add(a.clone());
            }
        }

        /** Deterministic-CBOR encoding {1: flow_id, 2: effect_ceiling, 3: approvals[]}. */
        public byte[] bytes() {
            List<Cbor.Value> arr = new ArrayList<>(approvals.size());
            for (byte[] a : approvals) {
                arr.add(new Cbor.B(a));
            }
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(flowID)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(effectCeiling)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.A(arr)))));
        }

        /** The FlowOpen's SHA-384 head — the genesis prev that anchors the continuation chain. */
        public byte[] head() {
            return Continuation.head(bytes());
        }

        /** The FlowOpen's content-id — carried by every child object. */
        public byte[] id() {
            return Cbor.contentId(bytes());
        }
    }

    /** Reconstruct a FlowOpen from its body bytes ALONE (the bearer-authority property). An
     * out-of-lattice effect_ceiling is rejected RangeError on decode, never normalized. Fail-closed
     * (ContMalformed) on any malformed shape. */
    public static FlowOpen parseFlowOpen(byte[] b) {
        Cbor.M m = decodeMap(b);
        byte[] fid = bstrField(m, 1);
        Long ceil = uintField(m, 2);
        Cbor.Value appsV = field(m, 3);
        if (fid == null || ceil == null || !(appsV instanceof Cbor.A arr)) {
            throw malformed();
        }
        if (!inLattice(ceil)) {
            throw range();
        }
        List<byte[]> apps = new ArrayList<>(arr.items.size());
        for (Cbor.Value e : arr.items) {
            if (!(e instanceof Cbor.B bs)) {
                throw malformed();
            }
            apps.add(bs.v);
        }
        return new FlowOpen(fid, ceil, apps);
    }

    // ---- Continuation decode / verify (design §20.3) ---------------------------------------------

    /** The single audited decode path for untrusted Continuation wire bytes. Reconstructs the 5-field
     * body and range-checks the effect against the closed lattice (0..3): an out-of-lattice effect is
     * rejected RangeError, never carried as an unknown value. Fail-closed (ContMalformed). */
    public static Continuation parseContinuation(byte[] b) {
        Cbor.M m = decodeMap(b);
        byte[] fid = bstrField(m, 1);
        Long seq = uintField(m, 2);
        Long effect = uintField(m, 3);
        byte[] pid = bstrField(m, 4);
        byte[] prev = bstrField(m, 5);
        if (fid == null || seq == null || effect == null || pid == null || prev == null) {
            throw malformed();
        }
        if (!inLattice(effect)) {
            throw range();
        }
        return new Continuation(fid, seq, effect, pid, prev);
    }

    /** The CHEAP-path check of a single link against the flow's fixed authority: same flow (WrongFlow),
     * next seq (SeqGap), effect within the ceiling (AboveCeiling), and prev chaining to the previous
     * head (ChainBroken). Performs no signature verification — that is what makes it cheap. Both the
     * ceiling and the link effect are closed effects; an out-of-lattice value is RangeError, never
     * normalized (fail-closed). */
    public static void verifyContinuation(Continuation c, byte[] flowOpenID, byte[] prevHead,
                                          long expectedSeq, long ceiling) {
        if (!inLattice(ceiling)) {
            throw range();
        }
        if (!inLattice(c.effect)) {
            throw range();
        }
        if (!Arrays.equals(c.flowOpenID, flowOpenID)) {
            throw wrongFlow();
        }
        if (c.seq != expectedSeq) {
            throw new NaalpException("SeqGap", "continuation seq is not the next expected value");
        }
        if (!Policy.authorizes(ceiling, c.effect)) {
            throw new NaalpException("AboveCeiling", "continuation effect exceeds the FlowOpen effect ceiling");
        }
        if (!Arrays.equals(c.prev, prevHead)) {
            throw new NaalpException("ChainBroken", "continuation prev does not chain to the previous head");
        }
    }

    /** Verify a whole ordered continuation sequence starting from the FlowOpen and return the final
     * chain head. The ceiling comes from the FlowOpen, so the cheap path can never exceed what the one
     * full signature authorized. */
    public static byte[] verifyChain(FlowOpen open, List<Continuation> conts) {
        if (!inLattice(open.effectCeiling)) {
            throw range();
        }
        byte[] id = open.id();
        byte[] prev = open.head();
        long ceiling = open.effectCeiling;
        for (int i = 0; i < conts.size(); i++) {
            verifyContinuation(conts.get(i), id, prev, i, ceiling);
            prev = conts.get(i).head();
        }
        return prev;
    }

    // ---- Checkpoint: confirm a prefix, detect a gap (design §20.4) --------------------------------

    /** Asserts the chain head after a contiguous prefix of continuations (seq 0..throughSeq). */
    public static final class Checkpoint {
        public final byte[] flowOpenID;
        public final long throughSeq;
        public final byte[] head;

        public Checkpoint(byte[] flowOpenID, long throughSeq, byte[] head) {
            this.flowOpenID = flowOpenID.clone();
            this.throughSeq = throughSeq;
            this.head = head.clone();
        }

        /** Deterministic-CBOR encoding {1: flow_open_id, 2: through_seq, 3: head}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(flowOpenID)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(throughSeq)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(head)))));
        }
    }

    /** The single audited decode path for untrusted Checkpoint wire bytes: the 3-field body (field 3 a
     * bstr head). A 2-field FlowCommit look-alike is rejected here (missing field 3). Fail-closed
     * (ContMalformed). */
    public static Checkpoint parseCheckpoint(byte[] b) {
        Cbor.M m = decodeMap(b);
        byte[] fid = bstrField(m, 1);
        Long through = uintField(m, 2);
        byte[] h = bstrField(m, 3);
        if (fid == null || through == null || h == null) {
            throw malformed();
        }
        return new Checkpoint(fid, through, h);
    }

    /** Confirm the prefix is exactly the contiguous sequence seq 0..throughSeq and that its recomputed
     * head matches the checkpoint. A dropped or reordered link — a missing seq, a broken prev, or the
     * wrong count — is reported GapDetected. */
    public static void verifyCheckpoint(Checkpoint cp, FlowOpen open, List<Continuation> prefix) {
        if (!Arrays.equals(cp.flowOpenID, open.id())) {
            throw wrongFlow();
        }
        // throughSeq is a 0-based index, so the prefix length is throughSeq+1. At throughSeq == u64::MAX
        // that addition would wrap and false-accept an EMPTY prefix as covering the whole counter space —
        // reject it as a gap instead (there can be no MAX+1 contiguous links).
        NaalpException gap = new NaalpException("GapDetected", "checkpoint reveals a dropped or reordered continuation");
        if (cp.throughSeq == 0xFFFFFFFFFFFFFFFFL) { // u64::MAX
            throw gap;
        }
        if (Long.compareUnsigned((long) prefix.size(), cp.throughSeq + 1) != 0) {
            throw gap; // wrong count: a link is missing or extra
        }
        byte[] h;
        try {
            h = verifyChain(open, prefix);
        } catch (NaalpException e) {
            throw gap; // a seq/prev break inside the prefix is a gap
        }
        if (!Arrays.equals(cp.head, h)) {
            throw gap;
        }
    }

    // ---- FlowCommit: the second full signature binding the whole sequence (design §20.5) ----------

    /** Binds a completed flow's final chain head under one full ML-DSA signature. */
    public static final class FlowCommit {
        public final byte[] flowOpenID;
        public final byte[] finalHead;

        public FlowCommit(byte[] flowOpenID, byte[] finalHead) {
            this.flowOpenID = flowOpenID.clone();
            this.finalHead = finalHead.clone();
        }

        /** Deterministic-CBOR encoding {1: flow_open_id, 2: final_head} — the 2-field shape that
         * distinguishes it from the 3-field Checkpoint. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(flowOpenID)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(finalHead)))));
        }
    }

    // ---- full-signature helpers (FlowOpen / FlowCommit) — real ML-DSA, isolation ------------------

    /** The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int). */
    private static byte[] protectedHeader(int alg) {
        return Cbor.encode(new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)))));
    }

    /** The tagged COSE_Sign1 over the FlowOpen body (the one full signature that opens the flow). */
    public static byte[] signFlowOpen(FlowOpen o, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), o.bytes());
    }

    /** The tagged COSE_Sign1 over the FlowCommit body. */
    public static byte[] signFlowCommit(FlowCommit c, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), c.bytes());
    }

    /** Verify the FlowOpen's full signature, then reconstruct the authority from the signed body bytes
     * (fail-closed BadSignature). This is the expensive path measured against the cheap one. */
    public static FlowOpen verifyFlowOpen(byte[] obj, int profile, int alg, byte[] pk) {
        byte[][] parts = Cose.parseSign1Raw(obj);
        byte[] tbs = Cose.toBeSignedRaw(parts[0], parts[1]);
        if (!Cose.coseVerify1Raw(alg, pk, tbs, parts[2])) {
            throw new NaalpException("BadSignature", "flow-open signature does not verify");
        }
        return parseFlowOpen(parts[1]);
    }

    /** Verify the FlowCommit's full signature, that it binds this FlowOpen, and that its final_head
     * equals the chain recomputed over the delivered continuations (CommitMismatch otherwise). */
    public static FlowCommit verifyFlowCommit(byte[] obj, int profile, int alg, byte[] pk,
                                              FlowOpen open, List<Continuation> conts) {
        byte[][] parts = Cose.parseSign1Raw(obj);
        byte[] tbs = Cose.toBeSignedRaw(parts[0], parts[1]);
        if (!Cose.coseVerify1Raw(alg, pk, tbs, parts[2])) {
            throw new NaalpException("BadSignature", "flow-commit signature does not verify");
        }
        Cbor.M m = decodeMap(parts[1]);
        byte[] fid = bstrField(m, 1);
        byte[] fh = bstrField(m, 2);
        if (fid == null || fh == null) {
            throw malformed();
        }
        if (!Arrays.equals(fid, open.id())) {
            throw wrongFlow();
        }
        byte[] finalHead = verifyChain(open, conts);
        if (!Arrays.equals(fh, finalHead)) {
            throw new NaalpException("CommitMismatch", "flow commit final_head does not match the recomputed chain");
        }
        return new FlowCommit(fid, fh);
    }

    // ---- small deterministic-CBOR field accessors ------------------------------------------------

    private static Cbor.M decodeMap(byte[] b) {
        Cbor.Value v = Cbor.decode(b); // strict decoder: throws NonCanonical on a non-canonical body
        if (!(v instanceof Cbor.M m)) {
            throw malformed();
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
