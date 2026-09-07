// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * N-AALP C7 audit for the Java SDK — the signed hash-chained receipt (the baseline single-authority
 * ordering tier), the equivocation auditor and its non-repudiable fork proof, and the
 * offline-checkable causal graph (design.md §8; R-8.1..8.6, R-12.2, R-12.3).
 *
 * <p>An ordering authority records each accepted object by appending a signed Receipt
 * {1: prev, 2: obj, 3: seq, 4: at}; the chain is tamper-evident because reordering, omission, or
 * substitution breaks a {@code prev} link or a {@code seq} (§8.1). The authority never mutates the
 * origin object to order it — ordering is an outer signed layer. The causal graph is the
 * authority-independent foundation: an edge "A causes B" is proven by B's signature over A's content
 * id and is checkable offline; a total order is a policy layered over this partial order (§8.2). A
 * cause an effect could not have seen (later position, or a cycle) is rejected (CausalViolation,
 * §8.3). An auditor detects equivocation — two receipts by one authority at one seq naming different
 * objects — from the signed receipts alone (§8.5), and mints a non-repudiable ForkProof carrying BOTH
 * of the accused's signatures and an external monotonic counter (draft-01 finding #70).
 *
 * <p>An independent transcription of impl/go/audit (cross-checked against impl/python/naalp/audit).
 * Receipt / fork-proof signatures are a RAW deterministic ML-DSA signature over the record body
 * ({@link Cose#mldsaSign}/{@link Cose#mldsaVerify}), exactly as the Go {@code cose.Signer} signs the
 * receipt body directly. Byte surfaces are graded against vectors/audit/cases.json; the signatures
 * are demonstrated in isolation with real crypto (the corpus carries no signature vector).
 */
public final class Audit {
    /** The width of a chain head / prev link (SHA-384 = 48 bytes). Genesis is zero. */
    public static final int HEAD_SIZE = 48;

    private Audit() {}

    private static byte[] sha384(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    // ---- Receipt: one signed append to an ordering authority's chain (design §8.1) --------------

    /** One signed append to an ordering authority's chain. */
    public static final class Receipt {
        public final byte[] prev; // hash of the previous receipt body (HEAD_SIZE bytes; genesis is zero)
        public final byte[] obj;  // content id of the accepted object (never the object itself — §8.2)
        public final long seq;    // monotonic sequence position within this authority's chain
        public final long at;     // the authority's time anchor, epoch ms (independent of the signer's clock)

        public Receipt(byte[] prev, byte[] obj, long seq, long at) {
            this.prev = prev.clone();
            this.obj = obj.clone();
            this.seq = seq;
            this.at = at;
        }

        /** Deterministic-CBOR encoding of the receipt body {1: prev, 2: obj, 3: seq, 4: at}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(prev)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(obj)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(seq)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.U(at)))));
        }

        /** The chain head after this receipt: SHA-384 of the receipt body. Because the body carries
         * prev, editing any receipt breaks the next receipt's linkage. */
        public byte[] head() {
            return sha384(bytes());
        }
    }

    /** The (receipt, signature) pair an {@link Authority#append} returns. */
    public static final class Signed {
        public final Receipt receipt;
        public final byte[] sig;

        public Signed(Receipt receipt, byte[] sig) {
            this.receipt = receipt;
            this.sig = sig;
        }
    }

    // ---- Authority: the baseline single ordering authority (§8.4) --------------------------------

    /** A baseline single ordering authority (§8.4). It appends monotonic signed receipts over object
     * content ids; it holds no object bodies and mutates none. Signs with a real deterministic ML-DSA
     * key derived from {@code seed} (a RAW signature over each receipt body). */
    public static final class Authority {
        private final int alg;
        private final byte[] seed;
        private byte[] head;
        private long seq;

        public Authority(int alg, byte[] seed) {
            this.alg = alg;
            this.seed = seed.clone();
            this.head = new byte[HEAD_SIZE];
            this.seq = 0;
        }

        /** Record acceptance of the object named by content id {@code obj} at time {@code at},
         * returning the signed receipt and its signature. Seq increases by one per append. */
        public Signed append(byte[] obj, long at) {
            Receipt r = new Receipt(head, obj, seq, at);
            byte[] sig = Cose.mldsaSign(alg, seed, r.bytes());
            head = r.head();
            seq++;
            return new Signed(r, sig);
        }
    }

    // ---- named, fail-closed errors (design §8.6) ------------------------------------------------

    private static NaalpException chainBroken() {
        return new NaalpException("ChainBroken", "receipt prev/seq does not chain to the previous receipt");
    }

    private static NaalpException receiptUnsigned() {
        return new NaalpException("ReceiptUnsigned", "receipt signature does not verify");
    }

    private static NaalpException forkProofInvalid(String why) {
        return new NaalpException("ForkProofInvalid", why);
    }

    private static NaalpException causalViolation() {
        return new NaalpException("CausalViolation", "causal graph has a cycle or a future cause");
    }

    /**
     * Check a receipt chain offline against the authority's key: each receipt's seq is the next
     * expected value, its prev links to the previous receipt's head (genesis is zero), and its raw
     * signature verifies. A broken link or a seq gap is ChainBroken; a bad signature is
     * ReceiptUnsigned. Detects any reorder, omission, or substitution (§8.1).
     */
    public static void verifyChain(List<Receipt> receipts, List<byte[]> sigs, int alg, byte[] pk) {
        if (receipts.size() != sigs.size()) {
            throw chainBroken();
        }
        byte[] head = new byte[HEAD_SIZE];
        for (int i = 0; i < receipts.size(); i++) {
            Receipt r = receipts.get(i);
            if (r.seq != i || !Arrays.equals(r.prev, head)) {
                throw chainBroken();
            }
            if (!Cose.mldsaVerify(alg, pk, r.bytes(), sigs.get(i))) {
                throw receiptUnsigned();
            }
            head = r.head();
        }
    }

    /** An object cannot be created after the authority ordered it, so created MUST NOT exceed at
     * (R-8.4). The receipt's {@code at} is signed and chained, so it is evidence a verifier checks
     * independently of the signer's clock. */
    public static boolean consistentWithAnchor(long created, long at) {
        return created <= at;
    }

    // ---- ForkProof: non-repudiable evidence of equivocation (draft-01 §8.5, R-8.3) --------------

    /** Non-repudiable evidence of equivocation: two validly-signed receipts by ONE authority at the
     * SAME seq naming DIFFERENT objects, with the accused's OWN two signatures and an external
     * monotonic counter — self-contained, so any third party verifies both signatures against the
     * accused key with no further evidence and no repudiation. */
    public static final class ForkProof {
        public final byte[] signer;   // accused authority signer id; both sigs verify under its key
        public final long extCounter; // external monotonic counter bound into the proof
        public final Receipt a;       // first receipt (a.bytes() is the signed input for sigA)
        public final byte[] sigA;     // the accused authority's signature over a.bytes()
        public final Receipt b;       // second receipt at the same seq naming a different object
        public final byte[] sigB;     // the accused authority's signature over b.bytes()

        public ForkProof(byte[] signer, long extCounter, Receipt a, byte[] sigA, Receipt b, byte[] sigB) {
            this.signer = signer.clone();
            this.extCounter = extCounter;
            this.a = a;
            this.sigA = sigA.clone();
            this.b = b;
            this.sigB = sigB.clone();
        }

        /** Deterministic-CBOR fork-proof body {1: signer, 2: ext_counter, 3: body_a, 4: sig_a,
         * 5: body_b, 6: sig_b}. The two receipt bodies are embedded as the exact bytes each signature
         * covers. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(signer)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(extCounter)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(a.bytes())),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(sigA)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.B(b.bytes())),
                    new Cbor.Pair(new Cbor.U(6), new Cbor.B(sigB)))));
        }

        /** The deterministic-CBOR framing witness: the fork-proof body with the two signature
         * byte-strings elided to empty. It is the structural authority the independent oracle
         * reproduces byte-for-byte; the two ML-DSA signatures are graded by cross-implementation
         * byte-parity elsewhere. This is not a wire object; it exists only to grade the framing. */
        public byte[] preimage() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(signer)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(extCounter)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(a.bytes())),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(new byte[0])),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.B(b.bytes())),
                    new Cbor.Pair(new Cbor.U(6), new Cbor.B(new byte[0])))));
        }

        /** Accept iff ALL hold: (1) the signer id is present; (2) the two receipts share one seq;
         * (3) they name DIFFERENT objects; and (4) BOTH signatures verify under the accused key. Any
         * failure rejects the whole proof (fail-closed): a same-object / seq-mismatch / unnamed-signer
         * proof is ForkProofInvalid, and a signature that does not verify is ReceiptUnsigned. */
        public void verify(int alg, byte[] pk) {
            if (signer.length == 0) {
                throw forkProofInvalid("an unnamed accused is not evidence");
            }
            if (a.seq != b.seq) {
                throw forkProofInvalid("receipts at different sequence positions");
            }
            if (Arrays.equals(a.obj, b.obj)) {
                throw forkProofInvalid("same object named twice — no equivocation");
            }
            if (!Cose.mldsaVerify(alg, pk, a.bytes(), sigA) || !Cose.mldsaVerify(alg, pk, b.bytes(), sigB)) {
                throw receiptUnsigned();
            }
        }
    }

    /** Assemble a fork proof from two conflicting signed receipts, the accused signer id, and an
     * external monotonic counter. Performs no checks — verify is the fail-closed gate; this is the
     * pure constructor (A9). Copies the byte slices so the proof owns its evidence. */
    public static ForkProof newForkProof(byte[] signer, Receipt a, byte[] sigA, Receipt b, byte[] sigB, long extCounter) {
        return new ForkProof(signer, extCounter, a, sigA, b, sigB);
    }

    // ---- Auditor: observes an authority and detects equivocation (§8.5) -------------------------

    private static final class Seen {
        final Receipt r;
        final byte[] sig;

        Seen(Receipt r, byte[] sig) {
            this.r = r;
            this.sig = sig;
        }
    }

    /** Observes an authority's receipts and detects equivocation from the signed receipts alone
     * (§8.5). On a conflict it mints a non-repudiable ForkProof carrying the accused signer id, both
     * conflicting signatures, and an external monotonic counter. */
    public static final class Auditor {
        private final int alg;
        private final byte[] pk;
        private final byte[] signer;
        private long extCounter;
        private final Map<Long, Seen> seen = new HashMap<>();

        public Auditor(int alg, byte[] pk, byte[] signer) {
            this(alg, pk, signer, 0);
        }

        public Auditor(int alg, byte[] pk, byte[] signer, long extBase) {
            this.alg = alg;
            this.pk = pk.clone();
            this.signer = signer.clone();
            this.extCounter = extBase;
        }

        /** Record a signed receipt. Throws ReceiptUnsigned on a bad signature. Returns a ForkProof
         * (Equivocation) if a previously-seen receipt at the same seq named a different object — the
         * proof carries the accused signer id, both signatures, and the auditor's current external
         * counter, which then advances. Returns null otherwise (including a benign exact duplicate). */
        public ForkProof observe(Receipt r, byte[] sig) {
            if (!Cose.mldsaVerify(alg, pk, r.bytes(), sig)) {
                throw receiptUnsigned();
            }
            Seen prev = seen.get(r.seq);
            if (prev != null) {
                if (!Arrays.equals(prev.r.obj, r.obj)) {
                    ForkProof fp = newForkProof(signer, prev.r, prev.sig, r, sig, extCounter);
                    extCounter++;
                    return fp;
                }
                return null;
            }
            seen.put(r.seq, new Seen(r, sig.clone()));
            return null;
        }
    }

    // ---- causal graph: the authority-independent partial order (§8.2, §8.3) ---------------------

    /** An object's place in the causal graph: its content id, the content ids of its causes
     * (envelope field 8), and its ordering position (authority seq, or {@code created} absent a
     * receipt). */
    public static final class CausalNode {
        public final byte[] id;
        public final List<byte[]> causes;
        public final long position;

        public CausalNode(byte[] id, List<byte[]> causes, long position) {
            this.id = id.clone();
            this.causes = new ArrayList<>(causes);
            this.position = position;
        }
    }

    private static String key(byte[] b) {
        return Hex.encode(b);
    }

    /** Check the signed partial order (§8.2, §8.3): no object names a present cause whose position
     * exceeds its own (a future cause it could not have seen), and the graph is acyclic. Either fault
     * is CausalViolation. Edges to causes not present in the set are ignored (external references).
     * Runs with no ordering authority present (R-8.5). */
    public static void verifyCausal(List<CausalNode> nodes) {
        Map<String, Integer> idx = new HashMap<>();
        for (int i = 0; i < nodes.size(); i++) {
            idx.put(key(nodes.get(i).id), i);
        }
        // No future cause: a present cause must not sit at a later position than its effect.
        for (CausalNode n : nodes) {
            for (byte[] c : n.causes) {
                Integer j = idx.get(key(c));
                if (j != null && nodes.get(j).position > n.position) {
                    throw causalViolation();
                }
            }
        }
        // Acyclic: 3-colour DFS over depends-on edges (effect -> cause).
        int[] color = new int[nodes.size()]; // 0 white, 1 gray, 2 black
        for (int i = 0; i < nodes.size(); i++) {
            if (color[i] == 0 && hasCycle(nodes, idx, color, i)) {
                throw causalViolation();
            }
        }
    }

    private static boolean hasCycle(List<CausalNode> nodes, Map<String, Integer> idx, int[] color, int i) {
        color[i] = 1;
        for (byte[] c : nodes.get(i).causes) {
            Integer j = idx.get(key(c));
            if (j == null) {
                continue;
            }
            if (color[j] == 1) {
                return true;
            }
            if (color[j] == 0 && hasCycle(nodes, idx, color, j)) {
                return true;
            }
        }
        color[i] = 2;
        return false;
    }

    /** Return the causal nodes' content ids in a deterministic topological order (a cause before its
     * effects). Ties among ready nodes break by (position, input index), so the order is reproducible.
     * Throws CausalViolation if the graph does not verify. NOTE: the audit tie-break is by POSITION —
     * distinct from the federation reconcile, whose tie-break is the content id. */
    public static List<byte[]> topoOrder(List<CausalNode> nodes) {
        verifyCausal(nodes);
        Map<String, Integer> idx = new HashMap<>();
        for (int i = 0; i < nodes.size(); i++) {
            idx.put(key(nodes.get(i).id), i);
        }
        int[] indeg = new int[nodes.size()];
        List<List<Integer>> effects = new ArrayList<>();
        for (int i = 0; i < nodes.size(); i++) {
            effects.add(new ArrayList<>());
        }
        for (int i = 0; i < nodes.size(); i++) {
            for (byte[] c : nodes.get(i).causes) {
                Integer j = idx.get(key(c));
                if (j != null) {
                    effects.get(j).add(i);
                    indeg[i]++;
                }
            }
        }
        boolean[] done = new boolean[nodes.size()];
        List<byte[]> order = new ArrayList<>(nodes.size());
        while (order.size() < nodes.size()) {
            int pick = -1;
            for (int i = 0; i < nodes.size(); i++) {
                if (done[i] || indeg[i] != 0) {
                    continue;
                }
                if (pick == -1 || nodes.get(i).position < nodes.get(pick).position) {
                    pick = i; // lowest position wins; equal positions keep the lower index (first seen)
                }
            }
            if (pick == -1) {
                throw causalViolation(); // unreachable after verifyCausal, but fail-closed
            }
            done[pick] = true;
            order.add(nodes.get(pick).id.clone());
            for (int e : effects.get(pick)) {
                indeg[e]--;
            }
        }
        return order;
    }
}
