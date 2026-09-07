// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Collaboration / rooms membership for the Java SDK (feature #64): a Phase-3 ADDITIVE higher tier
 * (tier 1) over the frozen draft-00 spine (design.md §2..§10; design-channels.md §21). It introduces
 * NO new envelope, encoding, signature, identity, or audit mechanism — it reuses the spine unchanged
 * (R-11.3, R-15A.2) — and adds only tier-1 object kinds on the Governance channel (0x0004; membership
 * ops) and the Identity channel (0x0003; the principal registry). A frozen baseline verifier that has
 * not licensed the tier rejects a room kind as UnknownKind, fail-closed; that is honest, not a defect.
 *
 * <p>It builds three recorded maintainer decisions:
 *
 * <ul>
 *   <li>#4a Membership carriage — every membership change (create, add_member, remove_member,
 *       change_role, add_owner) is a first-class SIGNED object (a normal N-AALP envelope object, §2),
 *       CURSOR-OCCUPYING (a real ordered position in the per-room log), RECEIPT-CHAINED (the room log
 *       IS the append-only signed audit/receipt chain of §8.1, one {@link Audit.Receipt} per accepted
 *       op over the op's content id), and EPOCH-BUMPING (each accepted op increments the room's
 *       membership epoch; an op built against a superseded epoch is rejected StaleEpoch — serialising
 *       concurrent membership changes so a stale view cannot win).
 *   <li>#4b O2 ownership — multi-owner, ADD-ONLY: a room may have many owners; add_owner adds one; an
 *       owner is NEVER removed (remove_member refuses an owner) nor demoted (change_role refuses to
 *       lower an owner). Create seeds exactly one owner, add_owner only grows the set, so the owner
 *       count is monotonically &gt;= 1 — a room can never become ownerless.
 *   <li>#3 Delivery Model B — {@link PrincipalRegistry} maps a stable semantic principal id to a
 *       durable Handle (the current signer id), resolved at send time. The binding survives key
 *       rotation (a rebind is authorised only by a verified {@link Identity.RotationRecord} from the
 *       current handle, R-1.4), so the semantic id is a durable layer above the connection-scoped
 *       handle; a hijack to an unrelated key is refused (RebindUnauthorized).
 * </ul>
 *
 * <p>An independent transcription of impl/go/rooms (cross-checked against impl/python/naalp/rooms).
 * The RoomOp / Binding wire bodies are graded byte-for-byte against vectors/rooms/cases.json; the room
 * state machine + Delivery-Model-B registry are behaviour-graded, exercised with REAL ML-DSA-65 signed
 * objects and a REAL co-signed key rotation. Every check is fail-closed (§15): an op that fails any
 * check is rejected whole, returns its named error, and causes no state change.
 */
public final class Rooms {
    // Channel bindings (R-1.2) and the tier for this higher-tier surface.
    public static final long CHANNEL_GOVERNANCE = 0x0004; // membership ops (who is authorised in the room)
    public static final long CHANNEL_IDENTITY = 0x0003;   // the principal registry (durable naming, R-1.4)
    public static final long TIER = 1;                    // a named higher tier over the frozen baseline (tier 0)

    // Room membership operation codes (naalp-room-op field 2).
    public static final long OP_CREATE = 0;
    public static final long OP_ADD_MEMBER = 1;
    public static final long OP_REMOVE_MEMBER = 2;
    public static final long OP_CHANGE_ROLE = 3;
    public static final long OP_ADD_OWNER = 4;

    // Role codes (naalp-room-op field 5). A role is the collaboration role that gates membership ops —
    // NOT an effect and NOT a capability ceiling.
    public static final long ROLE_MEMBER = 0;
    public static final long ROLE_ADMIN = 1;
    public static final long ROLE_OWNER = 2;

    // Tier-1 kind codes. Governance (0x0004) carries the five membership ops; Identity (0x0003) carries
    // the principal binding. They start at 16 to sit clear of the frozen baseline kinds.
    public static final long KIND_ROOM_CREATE = 16;
    public static final long KIND_ROOM_ADD_MEMBER = 17;
    public static final long KIND_ROOM_REMOVE_MEMBER = 18;
    public static final long KIND_ROOM_CHANGE_ROLE = 19;
    public static final long KIND_ROOM_ADD_OWNER = 20;
    public static final long KIND_PRINCIPAL_BIND = 16; // on the Identity channel

    private Rooms() {}

    private static byte[] sha384(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    // ---- the membership op (the first-class signed object's body) -------------------------

    /** One membership operation body carried in envelope field 10. Its content id (multihash(0x20,
     * SHA-384(body))) is what the room log orders (the cursor position), so the op is content-addressed
     * and its ordering is tamper-evident. */
    public static final class RoomOp {
        public final byte[] room;    // room id (bstr)
        public final long op;        // 0 create | 1 add_member | 2 remove_member | 3 change_role | 4 add_owner
        public final long epoch;     // the membership epoch this op is built against (bumps on accept)
        public final String subject; // the affected member's signer id (the creator, for create); MUST be NFC
        public final long role;      // 0 member | 1 admin | 2 owner

        public RoomOp(byte[] room, long op, long epoch, String subject, long role) {
            this.room = room.clone();
            this.op = op;
            this.epoch = epoch;
            this.subject = subject;
            this.role = role;
        }

        private Cbor.M toMap() {
            return new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(room)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(op)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(epoch)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.T(subject)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(role))));
        }

        /** Deterministic-CBOR encoding {1:room,2:op,3:epoch,4:subject,5:role}. */
        public byte[] bytes() {
            return Cbor.encode(toMap());
        }

        /** The op's content id in the T1 framing (design §2.3): multihash(0x20, SHA-384(body)). */
        public byte[] contentId() {
            return Cbor.contentId(bytes());
        }

        /** Build the (unsigned) N-AALP envelope object that carries this op: tier 1, Governance channel,
         * the op's kind and declared effect, the op body as field 10. The caller signs it with
         * {@link Envelope#sign} to produce the first-class signed membership object. A non-NFC subject or
         * an unknown op is rejected fail-closed. */
        public Envelope.Object envelopeObject(byte[] signer, long created, long profile, List<byte[]> causes) {
            KindEffect ke = kindForOp(op);
            if (!ke.ok) {
                throw new NaalpException("OpUnknown", "unknown room op code");
            }
            Identity.requireNfc(subject);
            return new Envelope.Object(ke.kind, CHANNEL_GOVERNANCE, TIER, signer, created, ke.effect,
                    profile, toMap(), causes, null, null);
        }
    }

    /** Parse an envelope object body (field 10) back into a RoomOp. A body that is not exactly the
     * {1,2,3,4,5} map with the right value types is RoomOpMismatch (fail-closed). */
    public static RoomOp roomOpFromBody(Cbor.Value v) {
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("RoomOpMismatch", "op body is not a map");
        }
        byte[] room = null;
        Long op = null;
        Long epoch = null;
        String subject = null;
        Long role = null;
        boolean[] seen = new boolean[6];
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U ku) || ku.v < 1 || ku.v > 5) {
                throw new NaalpException("RoomOpMismatch", "op body has an out-of-range field");
            }
            long k = ku.v;
            if (k == 1) {
                if (!(p.val instanceof Cbor.B b)) {
                    throw new NaalpException("RoomOpMismatch", "room is not a bstr");
                }
                room = b.v;
            } else if (k == 2) {
                if (!(p.val instanceof Cbor.U u)) {
                    throw new NaalpException("RoomOpMismatch", "op is not a uint");
                }
                op = u.v;
            } else if (k == 3) {
                if (!(p.val instanceof Cbor.U u)) {
                    throw new NaalpException("RoomOpMismatch", "epoch is not a uint");
                }
                epoch = u.v;
            } else if (k == 4) {
                if (!(p.val instanceof Cbor.T t)) {
                    throw new NaalpException("RoomOpMismatch", "subject is not a tstr");
                }
                subject = t.v;
            } else {
                if (!(p.val instanceof Cbor.U u)) {
                    throw new NaalpException("RoomOpMismatch", "role is not a uint");
                }
                role = u.v;
            }
            seen[(int) k] = true;
        }
        if (!(seen[1] && seen[2] && seen[3] && seen[4] && seen[5])) {
            throw new NaalpException("RoomOpMismatch", "op body is missing a mandatory field");
        }
        return new RoomOp(room, op, epoch, subject, role);
    }

    /** The (kind, effect) an op code maps to, and whether the op code is known. */
    public static final class KindEffect {
        public final long kind;
        public final long effect;
        public final boolean ok;

        KindEffect(long kind, long effect, boolean ok) {
            this.kind = kind;
            this.effect = effect;
            this.ok = ok;
        }
    }

    /** Map an op code to its tier-1 Governance kind and its declared effect (design-channels.md §21).
     * remove_member is destructive; the rest are non_idempotent_write. */
    public static KindEffect kindForOp(long op) {
        if (op == OP_CREATE) {
            return new KindEffect(KIND_ROOM_CREATE, Policy.NON_IDEMPOTENT_WRITE, true);
        }
        if (op == OP_ADD_MEMBER) {
            return new KindEffect(KIND_ROOM_ADD_MEMBER, Policy.NON_IDEMPOTENT_WRITE, true);
        }
        if (op == OP_REMOVE_MEMBER) {
            return new KindEffect(KIND_ROOM_REMOVE_MEMBER, Policy.DESTRUCTIVE, true);
        }
        if (op == OP_CHANGE_ROLE) {
            return new KindEffect(KIND_ROOM_CHANGE_ROLE, Policy.NON_IDEMPOTENT_WRITE, true);
        }
        if (op == OP_ADD_OWNER) {
            return new KindEffect(KIND_ROOM_ADD_OWNER, Policy.NON_IDEMPOTENT_WRITE, true);
        }
        return new KindEffect(0, 0, false);
    }

    // ---- kind validation (composes with the frozen baseline) ------------------------------

    /** Accept exactly this surface's tier-1 kinds: the five Governance membership kinds and the
     * Identity principal-bind kind. Nothing else. */
    public static boolean kindValidator(long channel, long kind) {
        if (channel == CHANNEL_GOVERNANCE) {
            return kind >= KIND_ROOM_CREATE && kind <= KIND_ROOM_ADD_OWNER;
        }
        if (channel == CHANNEL_IDENTITY) {
            return kind == KIND_PRINCIPAL_BIND;
        }
        return false;
    }

    private static boolean baselineKindValidator(long channel, long kind) {
        try {
            Channels.lookup(channel, kind);
            return true;
        } catch (NaalpException e) {
            return false;
        }
    }

    /** Accept the frozen baseline kinds OR this surface's tier-1 kinds — the validator a rooms-aware
     * endpoint passes to {@link Envelope#verify}. A baseline-only endpoint using the baseline validator
     * alone correctly rejects a room kind as UnknownKind (fail-closed). */
    public static boolean composedKindValidator(long channel, long kind) {
        return baselineKindValidator(channel, kind) || kindValidator(channel, kind);
    }

    // ---- the room state machine (per-room membership + the receipt-chained log) ------------

    /** A subject's role and whether it is a member. */
    public static final class RoleResult {
        public final long role;
        public final boolean member;

        RoleResult(long role, boolean member) {
            this.role = role;
            this.member = member;
        }
    }

    /** The (receipt, cursor) an {@link Room#apply} returns. */
    public static final class Applied {
        public final Audit.Receipt receipt;
        public final long cursor;

        Applied(Audit.Receipt receipt, long cursor) {
            this.receipt = receipt;
            this.cursor = cursor;
        }
    }

    /** The (room, receipt, cursor) {@link #createRoom} returns. */
    public static final class Created {
        public final Room room;
        public final Audit.Receipt receipt;
        public final long cursor;

        Created(Room room, Audit.Receipt receipt, long cursor) {
            this.room = room;
            this.receipt = receipt;
            this.cursor = cursor;
        }
    }

    /** A collaboration room's live membership state and its signed, append-only log. The log is an
     * audit receipt chain (§8.1): each accepted op is ordered at a cursor (the receipt seq) over the
     * op's content id, weaving membership into the tamper-evident chain. */
    public static final class Room {
        private final byte[] id;
        private long epoch;
        private final Map<String, Long> members = new LinkedHashMap<>();
        private final Map<String, Boolean> owners = new LinkedHashMap<>();
        private final Audit.Authority auth;
        private final List<Audit.Receipt> receipts = new ArrayList<>();
        private final List<byte[]> sigs = new ArrayList<>();

        Room(byte[] id, Audit.Authority auth) {
            this.id = id.clone();
            this.auth = auth;
        }

        public byte[] id() {
            return id.clone();
        }

        /** The room's current membership epoch (the epoch the next op must carry). */
        public long epoch() {
            return epoch;
        }

        /** Returns the subject's role and whether it is a member. */
        public RoleResult roleOf(String subject) {
            Long role = members.get(subject);
            return role == null ? new RoleResult(0, false) : new RoleResult(role, true);
        }

        public boolean isOwner(String subject) {
            return Boolean.TRUE.equals(owners.get(subject));
        }

        /** The number of owners; the add-only invariant keeps this &gt;= 1 after createRoom. */
        public int ownerCount() {
            return owners.size();
        }

        /** The owner ids in sorted order. */
        public List<String> owners() {
            return new ArrayList<>(new TreeSet<>(owners.keySet()));
        }

        /** The members and their roles (a sorted copy). */
        public Map<String, Long> members() {
            return new TreeMap<>(members);
        }

        /** The room log's receipts and their signatures (its persistent state); verifies offline with
         * {@link Audit#verifyChain} against the ordering authority's key. */
        public List<Audit.Receipt> receipts() {
            return new ArrayList<>(receipts);
        }

        public List<byte[]> sigs() {
            return new ArrayList<>(sigs);
        }

        /** Validate and apply one membership op (add_member, remove_member, change_role, add_owner) by an
         * owner {@code actor}, order it into the room log, and bump the epoch. Check order is fail-closed
         * throughout: room match -> epoch -> subject well-formed -> authorization -> per-op semantics ->
         * order -> mutate -> bump. Any failure throws a named error and leaves the room unchanged. */
        public Applied apply(RoomOp op, String actor, long at) {
            if (!Arrays.equals(op.room, id) || op.op == OP_CREATE) {
                throw new NaalpException("RoomOpMismatch", "op room id, kind, or op code does not match this room");
            }
            if (op.epoch != epoch) {
                throw new NaalpException("StaleEpoch", "op epoch does not match the room's current membership epoch");
            }
            if (op.subject.isEmpty()) {
                throw new NaalpException("RoomOpMismatch", "empty subject");
            }
            Identity.requireNfc(op.subject);
            if (!Boolean.TRUE.equals(owners.get(actor))) { // only an owner may change membership (R-6.5)
                throw new NaalpException("Unauthorized", "actor is not an owner of the room");
            }

            // Per-op semantic validation — NO mutation yet (so a rejection is a true no-op).
            if (op.op == OP_ADD_MEMBER) {
                if (op.role != ROLE_MEMBER && op.role != ROLE_ADMIN) {
                    throw new NaalpException("RoleInvalid", "owners are added via add_owner only");
                }
                if (members.containsKey(op.subject)) {
                    throw new NaalpException("MemberExists", "subject is already a member");
                }
            } else if (op.op == OP_ADD_OWNER) {
                if (op.role != ROLE_OWNER) {
                    throw new NaalpException("RoleInvalid", "add_owner must carry the owner role");
                }
                if (Boolean.TRUE.equals(owners.get(op.subject))) {
                    throw new NaalpException("OwnerExists", "subject is already an owner");
                }
            } else if (op.op == OP_REMOVE_MEMBER) {
                if (!members.containsKey(op.subject)) {
                    throw new NaalpException("MemberUnknown", "subject is not a member of the room");
                }
                if (Boolean.TRUE.equals(owners.get(op.subject))) {
                    throw new NaalpException("OwnerImmutable", "an owner cannot be removed (ownership is add-only)");
                }
            } else if (op.op == OP_CHANGE_ROLE) {
                if (!members.containsKey(op.subject)) {
                    throw new NaalpException("MemberUnknown", "subject is not a member of the room");
                }
                if (op.role != ROLE_MEMBER && op.role != ROLE_ADMIN) {
                    throw new NaalpException("RoleInvalid", "promote to owner via add_owner only");
                }
                if (members.get(op.subject) == ROLE_OWNER) {
                    throw new NaalpException("OwnerImmutable", "an owner cannot be demoted");
                }
            } else {
                throw new NaalpException("OpUnknown", "unknown room op code");
            }

            // Order the op into the log first; if ordering fails there is no state change.
            Audit.Signed s = auth.append(op.contentId(), at);
            if (op.op == OP_ADD_MEMBER) {
                members.put(op.subject, op.role);
            } else if (op.op == OP_ADD_OWNER) {
                members.put(op.subject, ROLE_OWNER);
                owners.put(op.subject, true);
            } else if (op.op == OP_REMOVE_MEMBER) {
                members.remove(op.subject);
            } else if (op.op == OP_CHANGE_ROLE) {
                members.put(op.subject, op.role);
            }
            receipts.add(s.receipt);
            sigs.add(s.sig);
            epoch++;
            return new Applied(s.receipt, s.receipt.seq);
        }

        /** The behavioural end-to-end path: verify a signed membership object with real crypto
         * ({@link Envelope#verify} against the composed rooms validator), bind the claimed signer id to
         * the verifying key (a self-asserted id that does not derive from the authenticated key confers
         * no authority, R-1.3/R-5.1), confirm the object is a tier-1 Governance room op whose kind and
         * effect match its op code, then apply it with the authenticated signer id as the actor. */
        public Applied applySigned(int profile, int alg, byte[] pubkey, byte[] signedObj, long at) {
            Envelope.Object o = Envelope.verify(profile, alg, pubkey, Rooms::composedKindValidator, signedObj, null);
            if (o.channel != CHANNEL_GOVERNANCE || o.tier != TIER) {
                throw new NaalpException("RoomOpMismatch", "object is not a tier-1 Governance room op");
            }
            String actor = Identity.signerId(alg, pubkey);
            if (!Arrays.equals(o.signer, actor.getBytes(StandardCharsets.UTF_8))) {
                throw new NaalpException("SignerMismatch", "signer id does not derive from the verifying key");
            }
            RoomOp op = roomOpFromBody(o.body);
            KindEffect ke = kindForOp(op.op);
            if (!ke.ok || o.kind != ke.kind || o.effect != ke.effect) {
                throw new NaalpException("RoomOpMismatch", "op kind/effect does not match its op code");
            }
            return apply(op, actor, at);
        }
    }

    /** Build a room from a verified create op signed by the creator. The creator (the op subject)
     * becomes the first and, at creation, only owner+member. The create op occupies cursor 0 in the log;
     * the room advances to epoch 1. {@code auth} is the room's ordering authority. A non-create op, a
     * non-zero epoch, an empty/non-NFC subject, or an actor that is not the subject is rejected
     * fail-closed. */
    public static Created createRoom(RoomOp op, String actor, Audit.Authority auth, long at) {
        if (op.op != OP_CREATE) {
            throw new NaalpException("RoomOpMismatch", "createRoom requires a create op");
        }
        if (op.epoch != 0) {
            throw new NaalpException("StaleEpoch", "a create op must be built against epoch 0");
        }
        if (op.subject.isEmpty()) {
            throw new NaalpException("RoomOpMismatch", "empty subject");
        }
        Identity.requireNfc(op.subject);
        if (!actor.equals(op.subject)) { // the creator seeds itself as the first owner
            throw new NaalpException("Unauthorized", "the create actor must be the seeded owner (the subject)");
        }
        Room r = new Room(op.room, auth);
        r.members.put(op.subject, ROLE_OWNER);
        r.owners.put(op.subject, true);
        Audit.Signed s = auth.append(op.contentId(), at);
        r.receipts.add(s.receipt);
        r.sigs.add(s.sig);
        r.epoch = 1;
        return new Created(r, s.receipt, s.receipt.seq);
    }

    // ---- Delivery Model B: the principal registry (semantic id -> durable Handle, R-1.4) ---

    /** One principal-registry record: a semantic principal id bound to a durable Handle at a monotonic
     * per-principal epoch, chained to the prior binding's head. Signed as an Identity-channel (0x0003)
     * tier-1 object; here it is the wire body (byte-graded) and the registry below is the policy
     * (behaviour-graded). */
    public static final class Binding {
        public final String principal; // the stable semantic principal id (MUST be NFC)
        public final String handle;    // the current durable Handle (a signer id)
        public final long epoch;       // monotonic per-principal binding epoch (0 for the first bind)
        public final byte[] prev;      // prior binding chain head (48 bytes; genesis = zero)

        public Binding(String principal, String handle, long epoch, byte[] prev) {
            this.principal = principal;
            this.handle = handle;
            this.epoch = epoch;
            this.prev = prev.clone();
        }

        /** Deterministic-CBOR encoding {1:principal,2:handle,3:epoch,4:prev}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(principal)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(handle)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(epoch)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(prev)))));
        }

        /** The per-principal chain head after this binding: SHA-384(binding body). Because the body
         * carries the prior head, editing any binding breaks the next binding's linkage. */
        public byte[] head() {
            return sha384(bytes());
        }
    }

    /** The empty per-principal chain head (48 zero bytes). */
    public static byte[] genesisHead() {
        return new byte[Audit.HEAD_SIZE];
    }

    /** The durable semantic-naming layer of Delivery Model B: it maps each semantic principal id to its
     * current durable Handle, keeping a per-principal signed binding chain. A delivery addresses a
     * semantic id and {@link #resolve} returns the Handle at send time. */
    public static final class PrincipalRegistry {
        private final Map<String, List<Binding>> chain = new LinkedHashMap<>();
        private final Map<String, byte[]> head = new LinkedHashMap<>();
        private final Map<String, String> current = new LinkedHashMap<>();
        private final Map<String, Long> epoch = new LinkedHashMap<>();

        /** Create the FIRST binding for a principal (epoch 0, prev = genesis). A principal already bound
         * is PrincipalExists (use rebind); an empty or non-NFC principal/handle is rejected. */
        public Binding bind(String principal, String handle) {
            if (principal.isEmpty() || handle.isEmpty()) {
                throw new NaalpException("RoomOpMismatch", "empty principal or handle");
            }
            Identity.requireNfc(principal);
            Identity.requireNfc(handle);
            if (current.containsKey(principal)) {
                throw new NaalpException("PrincipalExists", "principal already bound; use rebind");
            }
            Binding b = new Binding(principal, handle, 0, genesisHead());
            chain.put(principal, new ArrayList<>(List.of(b)));
            head.put(principal, b.head());
            current.put(principal, handle);
            epoch.put(principal, 0L);
            return b;
        }

        /** Update a principal to a new durable Handle, REQUIRING a verified rotation from the current
         * handle to the new handle (R-1.4): the semantic id survives key rotation, but a rebind to a key
         * not proven continuous with the current handle is refused (RebindUnauthorized). The binding
         * epoch bumps and the chain links to the prior head. */
        public Binding rebind(String principal, String newHandle, Identity.RotationRecord rot,
                              int oldAlg, byte[] oldPub, int newAlg, byte[] newPub, byte[] oldSig, byte[] newSig) {
            if (!current.containsKey(principal)) {
                throw new NaalpException("PrincipalUnknown", "no binding for the semantic principal id");
            }
            String cur = current.get(principal);
            if (newHandle.isEmpty()) {
                throw new NaalpException("RoomOpMismatch", "empty new handle");
            }
            Identity.requireNfc(newHandle);
            // The rotation MUST carry the current handle as old and the new handle as new, and it MUST be
            // a valid co-signed rotation (both keys derive their ids and both signatures verify).
            if (!rot.oldId.equals(cur) || !rot.newId.equals(newHandle)) {
                throw new NaalpException("RebindUnauthorized",
                        "a rebind requires a verified rotation from the current handle");
            }
            try {
                Identity.verifyRotation(rot, oldAlg, oldPub, newAlg, newPub, oldSig, newSig);
            } catch (NaalpException e) {
                throw new NaalpException("RebindUnauthorized",
                        "a rebind requires a verified rotation from the current handle");
            }
            long ep = epoch.get(principal) + 1;
            Binding b = new Binding(principal, newHandle, ep, head.get(principal));
            chain.get(principal).add(b);
            head.put(principal, b.head());
            current.put(principal, newHandle);
            epoch.put(principal, ep);
            return b;
        }

        /** Return the current durable Handle for a semantic principal id (Delivery Model B). An unknown
         * principal is PrincipalUnknown (fail-closed — never a silent empty handle). */
        public String resolve(String principal) {
            String h = current.get(principal);
            if (h == null) {
                throw new NaalpException("PrincipalUnknown", "no binding for the semantic principal id");
            }
            return h;
        }

        /** A principal's ordered binding chain (its persistent state) for offline audit, or null. */
        public List<Binding> chain(String principal) {
            List<Binding> c = chain.get(principal);
            return c == null ? null : Collections.unmodifiableList(c);
        }
    }
}
