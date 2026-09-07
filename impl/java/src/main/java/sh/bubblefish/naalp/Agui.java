// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * C21 NAALP-AGUI UI-consent binding for the Java SDK (design.md §24; R-AGUI-1..6).
 *
 * <p>NAALP-AGUI binds a human-in-the-loop approval, captured in a user-interface event stream (the
 * AG-UI tool-lifecycle events an agent shows a user), to the EXACT action bytes by content id, and
 * RECEIPT-CHAINS the shown events so the shown sequence is provable offline. It introduces NO new
 * envelope, encoding, signature, identity, or audit mechanism (R-11.3): a UI event is an ordinary
 * signed N-AALP body (COSE_Sign1, §4), and the surface reuses the C7 audit receipt-chain construction
 * (§8.1) unchanged — head = SHA-384(body), genesis prev = 48 zero bytes, a monotonic seq, the prior
 * head carried in {@code prev} so editing or omitting an event breaks the next event's linkage — and
 * the §7 approval binding ({@link Approval}) UNCHANGED.
 *
 * <p>{@link UIEvent} {1: session, 2: kind, 3: action, 4: seq, 5: prev} is one shown tool-lifecycle
 * event. {@code kind} is a closed set (shown / args-shown / approved / rejected); {@code action} is the
 * T1 content id of the action bytes shown to the user at this step; the chain is receipt-chained by
 * prev/seq.
 *
 * <p>The load-bearing properties, graded across implementations:
 * <ul>
 *   <li>A UI approval verifies ONLY against the EXACT action shown. {@link #verifyConsent} walks the
 *       shown chain, takes the action content id from the shown-and-approved event, and requires the
 *       action actually being executed to hash to THAT content id (ActionSubstituted otherwise) AND the
 *       human approval to bind it (the §7 approval, ApprovalMismatch otherwise). A substituted action
 *       has a different content id and is rejected.
 *   <li>A removed/omitted shown-event is detected with its POSITION. {@link #walkShown} enforces
 *       contiguity and returns UIChainBroken on a gap; {@link #detectHole} reports the first-broken
 *       position.
 * </ul>
 *
 * <p>Every check is fail-closed (§15). An independent transcription of impl/go/agui (cross-checked
 * against impl/python/naalp/agui): the byte surface (kind vocabulary, event bodies/heads/ids, action
 * content ids, the shown-chain walk, hole position, rejections) is graded against vectors/agui/cases.json;
 * the signed shown-chain and the consent binding use real deterministic ML-DSA-65 and are demonstrated
 * in isolation (the corpus carries no signed vector).
 */
public final class Agui {
    /** The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. */
    public static final int HEAD_SIZE = 48;

    // UI event kinds — the closed AG-UI tool-lifecycle set. A kind outside the set is rejected.
    public static final long KIND_SHOWN = 0;        // the action / tool call was shown (rendered) to the user
    public static final long KIND_ARGS_SHOWN = 1;   // the arguments were shown to the user
    public static final long KIND_APPROVED = 2;     // the user approved the shown action
    public static final long KIND_REJECTED = 3;     // the user rejected the shown action

    private static final Map<Long, String> KIND_NAMES = new LinkedHashMap<>();

    static {
        KIND_NAMES.put(KIND_SHOWN, "shown");
        KIND_NAMES.put(KIND_ARGS_SHOWN, "args-shown");
        KIND_NAMES.put(KIND_APPROVED, "approved");
        KIND_NAMES.put(KIND_REJECTED, "rejected");
    }

    private Agui() {}

    /** Whether {@code code} is one of the closed UI-event kinds. */
    public static boolean isKnownKind(long code) {
        return KIND_NAMES.containsKey(code);
    }

    /** The kind name, or "unknown". */
    public static String kindName(long code) {
        return KIND_NAMES.getOrDefault(code, "unknown");
    }

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

    private static byte[] head(byte[] b) {
        return sha384(b);
    }

    /** T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets). The content
     * id of an ACTION, which a UI event names in field 3 and a human approval binds. */
    public static byte[] contentId(byte[] b) {
        byte[] h = head(b);
        byte[] out = new byte[2 + h.length];
        out[0] = 0x20;
        out[1] = 0x30;
        System.arraycopy(h, 0, out, 2, h.length);
        return out;
    }

    // ---- UIEvent: one receipt-chained shown tool-lifecycle event (design §24) ---------------------

    /** One shown tool-lifecycle event in a UI session's event stream. It chains onto the prior event:
     * {@code prev} is the prior event's head (genesis for seq 0). {@code action} is the content id of
     * the exact action bytes shown to the user at this step. */
    public static final class UIEvent {
        public final byte[] session;
        public final long kind;
        public final byte[] action;
        public final long seq;
        public final byte[] prev;

        public UIEvent(byte[] session, long kind, byte[] action, long seq, byte[] prev) {
            this.session = session.clone();
            this.kind = kind;
            this.action = action.clone();
            this.seq = seq;
            this.prev = prev.clone();
        }

        /** Deterministic-CBOR encoding {1: session, 2: kind, 3: action, 4: seq, 5: prev}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(session)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(kind)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(action)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.U(seq)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.B(prev)))));
        }

        /** The chain head after this event: SHA-384 of the event body (48 octets). Because the body
         * carries prev, editing any event breaks the next event's linkage. */
        public byte[] head() {
            return Agui.head(bytes());
        }

        /** The event's T1 content id (50 octets). */
        public byte[] id() {
            return contentId(bytes());
        }
    }

    /** Reconstruct a UIEvent from its body bytes alone. A non-canonical body, a non-map, a non-uint
     * key, a mistyped field, or an absent mandatory field {1,2,3,4,5} is UIMalformed. Fail-closed. */
    public static UIEvent parseUIEvent(byte[] b) {
        Cbor.Value v;
        try {
            v = Cbor.decode(b); // strict decoder; a non-canonical body throws NonCanonical
        } catch (NaalpException e) {
            throw new NaalpException("UIMalformed", "ui-event body is not well-formed deterministic CBOR");
        }
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("UIMalformed", "ui-event body is not a map");
        }
        byte[] sess = null;
        Long kind = null;
        byte[] action = null;
        Long seq = null;
        byte[] prev = null;
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U ku)) {
                throw new NaalpException("UIMalformed", "non-uint ui-event key");
            }
            long k = ku.v;
            if (k == 1 && p.val instanceof Cbor.B b1) {
                sess = b1.v;
            } else if (k == 2 && p.val instanceof Cbor.U u2) {
                kind = u2.v;
            } else if (k == 3 && p.val instanceof Cbor.B b3) {
                action = b3.v;
            } else if (k == 4 && p.val instanceof Cbor.U u4) {
                seq = u4.v;
            } else if (k == 5 && p.val instanceof Cbor.B b5) {
                prev = b5.v;
            } else {
                throw new NaalpException("UIMalformed", "unknown or mistyped ui-event field " + k);
            }
        }
        if (sess == null || kind == null || action == null || seq == null || prev == null) {
            throw new NaalpException("UIMalformed", "ui-event body missing a mandatory field");
        }
        return new UIEvent(sess, kind, action, seq, prev);
    }

    /** Produce the tagged COSE_Sign1 object over the event body (real deterministic ML-DSA). */
    public static byte[] signUIEvent(UIEvent e, int alg, byte[] seed) {
        return Cose.coseSign1(alg, seed, protectedHeader(alg), e.bytes());
    }

    /** Verify the event's full signature under the profile, reconstruct it from the signed body bytes,
     * and validate the kind against the closed set (UnknownUIEventKind). A bad signature propagates
     * BadSignature. Fail-closed. */
    public static UIEvent verifyUIEvent(byte[] obj, int profile, int alg, byte[] pubkey) {
        byte[] payload = verifySign1(obj, profile, alg, pubkey);
        UIEvent e = parseUIEvent(payload);
        if (!isKnownKind(e.kind)) {
            throw new NaalpException("UnknownUIEventKind", "ui-event kind is outside the closed set");
        }
        return e;
    }

    // ---- the shown chain: contiguity, walk, hole detection (mirrors the C7 chain) -----------------

    /** One step of a walked shown chain: the chain position, the event kind, the action content id
     * shown, and the chain head after it. */
    public static final class ShownEvent {
        public final long seq;
        public final long kind;
        public final byte[] action;
        public final byte[] head;

        ShownEvent(long seq, long kind, byte[] action, byte[] head) {
            this.seq = seq;
            this.kind = kind;
            this.action = action.clone();
            this.head = head.clone();
        }
    }

    /** Verify a UI event chain's structural continuity OFFLINE (no signatures) and return the ordered
     * shown events. It requires every event to name the SAME session, seq i to equal its index, each
     * kind to be in the closed set, and prev to link to the previous event's head (genesis for seq 0).
     * A gap, reorder, omitted event, or a session change is UIChainBroken (fail-closed); an unknown kind
     * is UnknownUIEventKind. */
    public static List<ShownEvent> walkShown(List<UIEvent> events) {
        List<ShownEvent> out = new ArrayList<>(events.size());
        byte[] h = genesis();
        byte[] session = null;
        for (int i = 0; i < events.size(); i++) {
            UIEvent e = events.get(i);
            if (i == 0) {
                session = e.session;
            } else if (!Arrays.equals(e.session, session)) {
                throw new NaalpException("UIChainBroken", "a chain is for exactly one session");
            }
            if (!isKnownKind(e.kind)) {
                throw new NaalpException("UnknownUIEventKind", "ui-event kind is outside the closed set");
            }
            if (e.seq != i || !Arrays.equals(e.prev, h)) {
                throw new NaalpException("UIChainBroken", "ui-event prev/seq does not chain to the previous event");
            }
            h = e.head();
            out.add(new ShownEvent(e.seq, e.kind, e.action, h));
        }
        return out;
    }

    /** Check a UI event chain offline against the UI authority's key. Each element is the tagged
     * COSE_Sign1 object for one event; verify every signature under the profile ({@link #verifyUIEvent}),
     * then enforce the same structural continuity as {@link #walkShown}. A bad signature propagates
     * BadSignature; a broken link, seq gap, or session change is UIChainBroken. Detects any reorder,
     * omission, or substitution of a shown event (§8.1). Fail-closed. */
    public static List<UIEvent> verifyShownChain(List<byte[]> objs, int profile, int alg, byte[] pubkey) {
        byte[] h = genesis();
        byte[] session = null;
        List<UIEvent> out = new ArrayList<>(objs.size());
        for (int i = 0; i < objs.size(); i++) {
            UIEvent e = verifyUIEvent(objs.get(i), profile, alg, pubkey);
            if (i == 0) {
                session = e.session;
            } else if (!Arrays.equals(e.session, session)) {
                throw new NaalpException("UIChainBroken", "a chain is for exactly one session");
            }
            if (e.seq != i || !Arrays.equals(e.prev, h)) {
                throw new NaalpException("UIChainBroken", "ui-event prev/seq does not chain to the previous event");
            }
            h = e.head();
            out.add(e);
        }
        return out;
    }

    /** The result of hole detection: the first-broken position and whether the list has a hole. */
    public static final class Hole {
        public final int position;
        public final boolean isHole;

        Hole(int position, boolean isHole) {
            this.position = position;
            this.isHole = isHole;
        }
    }

    /** Report whether a presented (possibly gappy) event list breaks contiguity — a deleted/omitted
     * shown-event — and, if so, the FIRST-BROKEN POSITION: the index i where the i-th presented event's
     * seq is not i or its prev does not link to the previous event's head. A contiguous list returns
     * (0, false). */
    public static Hole detectHole(List<UIEvent> events) {
        byte[] h = genesis();
        for (int i = 0; i < events.size(); i++) {
            UIEvent e = events.get(i);
            if (e.seq != i || !Arrays.equals(e.prev, h)) {
                return new Hole(i, true);
            }
            h = e.head();
        }
        return new Hole(0, false);
    }

    // ---- the UI consent binding (reuses the §7 approval) ------------------------------------------

    /** The content id of the action shown-and-approved in a walked chain, or {@code null} if no approved
     * event is present. It is the content id a valid consent binds; a chain with no approved event has
     * no consent to bind. */
    public static byte[] approvedActionCID(List<ShownEvent> shown) {
        for (ShownEvent ev : shown) {
            if (ev.kind == KIND_APPROVED) {
                return ev.action.clone();
            }
        }
        return null;
    }

    /** Bind a human-in-the-loop approval to the EXACT action shown in a UI event stream. It (1) walks
     * the shown chain, rejecting any gap/reorder/omission (UIChainBroken); (2) takes the action content
     * id from the shown-and-approved event (UINoConsent if there is none); (3) verifies the human §7
     * approval binds THAT shown content id and has not expired (ApprovalMismatch / ApprovalExpired /
     * BadSignature); and (4) requires the action actually being executed ({@code actionBytes}) to hash
     * to the shown-and-approved content id — a SUBSTITUTED action has a different content id and is
     * rejected (ActionSubstituted). Every failure returns its named error and authorizes nothing
     * (fail-closed). On success the caller may execute exactly {@code actionBytes}. */
    public static void verifyConsent(List<UIEvent> chain, byte[] actionBytes, Approval.ApprovalRecord appr,
                                     int approverAlg, byte[] approverPubkey, byte[] apprSig, long now) {
        List<ShownEvent> shown = walkShown(chain); // UIChainBroken / UnknownUIEventKind on a hole
        byte[] shownCid = approvedActionCID(shown);
        if (shownCid == null) {
            throw new NaalpException("UINoConsent", "the shown chain carries no approved event");
        }
        // The human approval must be a valid signature binding the shown-and-approved action content id.
        Approval.verifyApproval(appr, approverAlg, approverPubkey, apprSig, shownCid, now);
        // The action actually being executed MUST be the exact one shown and approved: a substitution
        // has a different content id and is rejected. This is the seam a lax UI profile would drop.
        if (!Arrays.equals(contentId(actionBytes), shownCid)) {
            throw new NaalpException("ActionSubstituted", "the executed action is not the exact action shown+approved");
        }
    }

    // ---- signing / verification helpers (COSE_Sign1 with the bare {1: alg} header) ----------------

    /** The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits. */
    private static byte[] protectedHeader(int alg) {
        return Cbor.encode(new Cbor.M(List.of(new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)))));
    }

    /** Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the
     * payload. Checks: alg registry, profile floor, key-alg match, signature. Fail-closed. */
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
        throw new NaalpException("UIMalformed", "protected header has no alg");
    }
}
