// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

/**
 * Collaboration / rooms membership for the Kotlin SDK (feature #64): a Phase-3 ADDITIVE higher tier
 * (tier 1) over the frozen draft-00 spine (design.md 2..10; design-channels.md 21). It introduces NO
 * new envelope, encoding, signature, identity, or audit mechanism - it reuses the spine unchanged
 * (R-11.3, R-15A.2) - and adds only tier-1 object kinds on the Governance channel (0x0004; membership
 * ops) and the Identity channel (0x0003; the principal registry). A frozen baseline verifier that has
 * not licensed the tier rejects a room kind as UnknownKind, fail-closed; that is honest, not a defect.
 *
 * It builds three recorded maintainer decisions:
 *
 *   - #4a Membership carriage - every membership change (create, add_member, remove_member,
 *     change_role, add_owner) is a first-class SIGNED object (a normal N-AALP envelope object, 2),
 *     CURSOR-OCCUPYING (a real ordered position in the per-room log), RECEIPT-CHAINED (the room log IS
 *     the append-only signed audit/receipt chain of 8.1, one [Audit.Receipt] per accepted op over the
 *     op's content id), and EPOCH-BUMPING (each accepted op increments the room's membership epoch; an
 *     op built against a superseded epoch is rejected StaleEpoch - serialising concurrent membership
 *     changes so a stale view cannot win).
 *   - #4b O2 ownership - multi-owner, ADD-ONLY: a room may have many owners; add_owner adds one; an
 *     owner is NEVER removed (remove_member refuses an owner) nor demoted (change_role refuses to lower
 *     an owner). Create seeds exactly one owner, add_owner only grows the set, so the owner count is
 *     monotonically >= 1 - a room can never become ownerless.
 *   - #3 Delivery Model B - [PrincipalRegistry] maps a stable semantic principal id to a durable Handle
 *     (the current signer id), resolved at send time. The binding survives key rotation (a rebind is
 *     authorised only by a verified [Identity.RotationRecord] from the current handle, R-1.4), so the
 *     semantic id is a durable layer above the connection-scoped handle; a hijack to an unrelated key is
 *     refused (RebindUnauthorized).
 *
 * An independent transcription of impl/go/rooms (cross-checked against impl/python/naalp/rooms and
 * impl/java). The RoomOp / Binding wire bodies are graded byte-for-byte against vectors/rooms/cases.json;
 * the room state machine + Delivery-Model-B registry are behaviour-graded, exercised with REAL ML-DSA-65
 * signed objects and a REAL co-signed key rotation. Every check is fail-closed (15): an op that fails any
 * check is rejected whole, returns its named error, and causes no state change.
 */
object Rooms {
    // Channel bindings (R-1.2) and the tier for this higher-tier surface.
    const val CHANNEL_GOVERNANCE = 0x0004L // membership ops (who is authorised in the room)
    const val CHANNEL_IDENTITY = 0x0003L   // the principal registry (durable naming, R-1.4)
    const val TIER = 1L                     // a named higher tier over the frozen baseline (tier 0)

    // Room membership operation codes (naalp-room-op field 2).
    const val OP_CREATE = 0L
    const val OP_ADD_MEMBER = 1L
    const val OP_REMOVE_MEMBER = 2L
    const val OP_CHANGE_ROLE = 3L
    const val OP_ADD_OWNER = 4L

    // Role codes (naalp-room-op field 5). A role is the collaboration role that gates membership ops -
    // NOT an effect and NOT a capability ceiling.
    const val ROLE_MEMBER = 0L
    const val ROLE_ADMIN = 1L
    const val ROLE_OWNER = 2L

    // Tier-1 kind codes. Governance (0x0004) carries the five membership ops; Identity (0x0003) carries
    // the principal binding. They start at 16 to sit clear of the frozen baseline kinds.
    const val KIND_ROOM_CREATE = 16L
    const val KIND_ROOM_ADD_MEMBER = 17L
    const val KIND_ROOM_REMOVE_MEMBER = 18L
    const val KIND_ROOM_CHANGE_ROLE = 19L
    const val KIND_ROOM_ADD_OWNER = 20L
    const val KIND_PRINCIPAL_BIND = 16L // on the Identity channel

    private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

    // ---- the membership op (the first-class signed object's body) -------------------------

    /**
     * One membership operation body carried in envelope field 10. Its content id (multihash(0x20,
     * SHA-384(body))) is what the room log orders (the cursor position), so the op is content-addressed
     * and its ordering is tamper-evident.
     */
    class RoomOp(room: ByteArray, val op: Long, val epoch: Long, val subject: String, val role: Long) {
        val room: ByteArray = room.copyOf()

        private fun toMap(): Cbor.M = Cbor.M(
            listOf(
                Cbor.Pair(Cbor.U(1), Cbor.B(room)),
                Cbor.Pair(Cbor.U(2), Cbor.U(op)),
                Cbor.Pair(Cbor.U(3), Cbor.U(epoch)),
                Cbor.Pair(Cbor.U(4), Cbor.T(subject)),
                Cbor.Pair(Cbor.U(5), Cbor.U(role)),
            )
        )

        /** Deterministic-CBOR encoding {1:room,2:op,3:epoch,4:subject,5:role}. */
        fun bytes(): ByteArray = Cbor.encode(toMap())

        /** The op's content id in the T1 framing (design 2.3): multihash(0x20, SHA-384(body)). */
        fun contentId(): ByteArray = Cbor.contentId(bytes())

        /**
         * Build the (unsigned) N-AALP envelope object that carries this op: tier 1, Governance channel,
         * the op's kind and declared effect, the op body as field 10. The caller signs it with
         * [Envelope.sign] to produce the first-class signed membership object. A non-NFC subject or an
         * unknown op is rejected fail-closed.
         */
        fun envelopeObject(signer: ByteArray, created: Long, profile: Long, causes: List<ByteArray>): Envelope.Object {
            val ke = kindForOp(op)
            if (!ke.ok) throw NaalpException("OpUnknown", "unknown room op code")
            Identity.requireNfc(subject)
            return Envelope.Object(
                kind = ke.kind, channel = CHANNEL_GOVERNANCE, signer = signer, created = created,
                effect = ke.effect, body = toMap(), tier = TIER, profile = profile, causes = causes,
            )
        }
    }

    /**
     * Parse an envelope object body (field 10) back into a RoomOp. A body that is not exactly the
     * {1,2,3,4,5} map with the right value types is RoomOpMismatch (fail-closed).
     */
    fun roomOpFromBody(v: Cbor.Value): RoomOp {
        if (v !is Cbor.M) throw NaalpException("RoomOpMismatch", "op body is not a map")
        var room: ByteArray? = null
        var op: Long? = null
        var epoch: Long? = null
        var subject: String? = null
        var role: Long? = null
        val seen = BooleanArray(6)
        for (p in v.pairs) {
            val k = p.k
            if (k !is Cbor.U || k.v < 1 || k.v > 5) throw NaalpException("RoomOpMismatch", "op body has an out-of-range field")
            when (k.v) {
                1L -> { val b = p.v; if (b !is Cbor.B) throw NaalpException("RoomOpMismatch", "room is not a bstr"); room = b.v }
                2L -> { val u = p.v; if (u !is Cbor.U) throw NaalpException("RoomOpMismatch", "op is not a uint"); op = u.v }
                3L -> { val u = p.v; if (u !is Cbor.U) throw NaalpException("RoomOpMismatch", "epoch is not a uint"); epoch = u.v }
                4L -> { val t = p.v; if (t !is Cbor.T) throw NaalpException("RoomOpMismatch", "subject is not a tstr"); subject = t.v }
                5L -> { val u = p.v; if (u !is Cbor.U) throw NaalpException("RoomOpMismatch", "role is not a uint"); role = u.v }
            }
            seen[k.v.toInt()] = true
        }
        if (!(seen[1] && seen[2] && seen[3] && seen[4] && seen[5])) {
            throw NaalpException("RoomOpMismatch", "op body is missing a mandatory field")
        }
        return RoomOp(room!!, op!!, epoch!!, subject!!, role!!)
    }

    /** The (kind, effect) an op code maps to, and whether the op code is known. */
    class KindEffect(val kind: Long, val effect: Long, val ok: Boolean)

    /**
     * Map an op code to its tier-1 Governance kind and its declared effect (design-channels.md 21).
     * remove_member is destructive; the rest are non_idempotent_write.
     */
    fun kindForOp(op: Long): KindEffect = when (op) {
        OP_CREATE -> KindEffect(KIND_ROOM_CREATE, Policy.NON_IDEMPOTENT_WRITE, true)
        OP_ADD_MEMBER -> KindEffect(KIND_ROOM_ADD_MEMBER, Policy.NON_IDEMPOTENT_WRITE, true)
        OP_REMOVE_MEMBER -> KindEffect(KIND_ROOM_REMOVE_MEMBER, Policy.DESTRUCTIVE, true)
        OP_CHANGE_ROLE -> KindEffect(KIND_ROOM_CHANGE_ROLE, Policy.NON_IDEMPOTENT_WRITE, true)
        OP_ADD_OWNER -> KindEffect(KIND_ROOM_ADD_OWNER, Policy.NON_IDEMPOTENT_WRITE, true)
        else -> KindEffect(0, 0, false)
    }

    // ---- kind validation (composes with the frozen baseline) ------------------------------

    /**
     * Accept exactly this surface's tier-1 kinds: the five Governance membership kinds and the Identity
     * principal-bind kind. Nothing else.
     */
    fun kindValidator(channel: Long, kind: Long): Boolean = when (channel) {
        CHANNEL_GOVERNANCE -> kind in KIND_ROOM_CREATE..KIND_ROOM_ADD_OWNER
        CHANNEL_IDENTITY -> kind == KIND_PRINCIPAL_BIND
        else -> false
    }

    private fun baselineKindValidator(channel: Long, kind: Long): Boolean = try {
        Channels.lookup(channel, kind); true
    } catch (e: NaalpException) {
        false
    }

    /**
     * Accept the frozen baseline kinds OR this surface's tier-1 kinds - the validator a rooms-aware
     * endpoint passes to [Envelope.verify]. A baseline-only endpoint using the baseline validator alone
     * correctly rejects a room kind as UnknownKind (fail-closed).
     */
    fun composedKindValidator(channel: Long, kind: Long): Boolean =
        baselineKindValidator(channel, kind) || kindValidator(channel, kind)

    // ---- the room state machine (per-room membership + the receipt-chained log) ------------

    /** A subject's role and whether it is a member. */
    class RoleResult(val role: Long, val member: Boolean)

    /** The (receipt, cursor) a [Room.apply] returns. */
    class Applied(val receipt: Audit.Receipt, val cursor: Long)

    /** The (room, receipt, cursor) [createRoom] returns. */
    class Created(val room: Room, val receipt: Audit.Receipt, val cursor: Long)

    /**
     * A collaboration room's live membership state and its signed, append-only log. The log is an audit
     * receipt chain (8.1): each accepted op is ordered at a cursor (the receipt seq) over the op's content
     * id, weaving membership into the tamper-evident chain.
     */
    class Room internal constructor(id: ByteArray, private val auth: Audit.Authority) {
        private val id: ByteArray = id.copyOf()
        internal var epochState: Long = 0
        internal val members = LinkedHashMap<String, Long>()
        internal val owners = LinkedHashMap<String, Boolean>()
        internal val receiptList = ArrayList<Audit.Receipt>()
        internal val sigList = ArrayList<ByteArray>()

        fun id(): ByteArray = id.copyOf()

        /** The room's current membership epoch (the epoch the next op must carry). */
        fun epoch(): Long = epochState

        /** Returns the subject's role and whether it is a member. */
        fun roleOf(subject: String): RoleResult {
            val role = members[subject]
            return if (role == null) RoleResult(0, false) else RoleResult(role, true)
        }

        fun isOwner(subject: String): Boolean = owners[subject] == true

        /** The number of owners; the add-only invariant keeps this >= 1 after createRoom. */
        fun ownerCount(): Int = owners.size

        /** The owner ids in sorted order. */
        fun owners(): List<String> = owners.keys.sorted()

        /** The members and their roles (a sorted copy). */
        fun members(): Map<String, Long> = members.toSortedMap()

        /**
         * The room log's receipts and their signatures (its persistent state); verifies offline with
         * [Audit.verifyChain] against the ordering authority's key.
         */
        fun receipts(): List<Audit.Receipt> = ArrayList(receiptList)

        fun sigs(): List<ByteArray> = ArrayList(sigList)

        /**
         * Validate and apply one membership op (add_member, remove_member, change_role, add_owner) by an
         * owner [actor], order it into the room log, and bump the epoch. Check order is fail-closed
         * throughout: room match -> epoch -> subject well-formed -> authorization -> per-op semantics ->
         * order -> mutate -> bump. Any failure throws a named error and leaves the room unchanged.
         */
        fun apply(op: RoomOp, actor: String, at: Long): Applied {
            if (!op.room.contentEquals(id) || op.op == OP_CREATE) {
                throw NaalpException("RoomOpMismatch", "op room id, kind, or op code does not match this room")
            }
            if (op.epoch != epochState) {
                throw NaalpException("StaleEpoch", "op epoch does not match the room's current membership epoch")
            }
            if (op.subject.isEmpty()) throw NaalpException("RoomOpMismatch", "empty subject")
            Identity.requireNfc(op.subject)
            if (owners[actor] != true) { // only an owner may change membership (R-6.5)
                throw NaalpException("Unauthorized", "actor is not an owner of the room")
            }

            // Per-op semantic validation - NO mutation yet (so a rejection is a true no-op).
            when (op.op) {
                OP_ADD_MEMBER -> {
                    if (op.role != ROLE_MEMBER && op.role != ROLE_ADMIN) throw NaalpException("RoleInvalid", "owners are added via add_owner only")
                    if (members.containsKey(op.subject)) throw NaalpException("MemberExists", "subject is already a member")
                }
                OP_ADD_OWNER -> {
                    if (op.role != ROLE_OWNER) throw NaalpException("RoleInvalid", "add_owner must carry the owner role")
                    if (owners[op.subject] == true) throw NaalpException("OwnerExists", "subject is already an owner")
                }
                OP_REMOVE_MEMBER -> {
                    if (!members.containsKey(op.subject)) throw NaalpException("MemberUnknown", "subject is not a member of the room")
                    if (owners[op.subject] == true) throw NaalpException("OwnerImmutable", "an owner cannot be removed (ownership is add-only)")
                }
                OP_CHANGE_ROLE -> {
                    if (!members.containsKey(op.subject)) throw NaalpException("MemberUnknown", "subject is not a member of the room")
                    if (op.role != ROLE_MEMBER && op.role != ROLE_ADMIN) throw NaalpException("RoleInvalid", "promote to owner via add_owner only")
                    if (members[op.subject] == ROLE_OWNER) throw NaalpException("OwnerImmutable", "an owner cannot be demoted")
                }
                else -> throw NaalpException("OpUnknown", "unknown room op code")
            }

            // Order the op into the log first; if ordering fails there is no state change.
            val (rec, sig) = auth.append(op.contentId(), at)
            when (op.op) {
                OP_ADD_MEMBER -> members[op.subject] = op.role
                OP_ADD_OWNER -> { members[op.subject] = ROLE_OWNER; owners[op.subject] = true }
                OP_REMOVE_MEMBER -> members.remove(op.subject)
                OP_CHANGE_ROLE -> members[op.subject] = op.role
            }
            receiptList.add(rec)
            sigList.add(sig)
            epochState++
            return Applied(rec, rec.seq)
        }

        /**
         * The behavioural end-to-end path: verify a signed membership object with real crypto
         * ([Envelope.verify] against the composed rooms validator), bind the claimed signer id to the
         * verifying key (a self-asserted id that does not derive from the authenticated key confers no
         * authority, R-1.3/R-5.1), confirm the object is a tier-1 Governance room op whose kind and effect
         * match its op code, then apply it with the authenticated signer id as the actor.
         */
        fun applySigned(profile: Long, alg: Int, pubkey: ByteArray, signedObj: ByteArray, at: Long): Applied {
            val o = Envelope.verify(profile, alg, pubkey, Envelope.KindValidator { ch, k -> composedKindValidator(ch, k) }, signedObj)
            if (o.channel != CHANNEL_GOVERNANCE || o.tier != TIER) {
                throw NaalpException("RoomOpMismatch", "object is not a tier-1 Governance room op")
            }
            val actor = Identity.signerId(alg, pubkey)
            if (!o.signer.contentEquals(actor.toByteArray(Charsets.UTF_8))) {
                throw NaalpException("SignerMismatch", "signer id does not derive from the verifying key")
            }
            val op = roomOpFromBody(o.body)
            val ke = kindForOp(op.op)
            if (!ke.ok || o.kind != ke.kind || o.effect != ke.effect) {
                throw NaalpException("RoomOpMismatch", "op kind/effect does not match its op code")
            }
            return apply(op, actor, at)
        }
    }

    /**
     * Build a room from a verified create op signed by the creator. The creator (the op subject) becomes
     * the first and, at creation, only owner+member. The create op occupies cursor 0 in the log; the room
     * advances to epoch 1. [auth] is the room's ordering authority. A non-create op, a non-zero epoch, an
     * empty/non-NFC subject, or an actor that is not the subject is rejected fail-closed.
     */
    fun createRoom(op: RoomOp, actor: String, auth: Audit.Authority, at: Long): Created {
        if (op.op != OP_CREATE) throw NaalpException("RoomOpMismatch", "createRoom requires a create op")
        if (op.epoch != 0L) throw NaalpException("StaleEpoch", "a create op must be built against epoch 0")
        if (op.subject.isEmpty()) throw NaalpException("RoomOpMismatch", "empty subject")
        Identity.requireNfc(op.subject)
        if (actor != op.subject) throw NaalpException("Unauthorized", "the create actor must be the seeded owner (the subject)")
        val r = Room(op.room, auth)
        r.members[op.subject] = ROLE_OWNER
        r.owners[op.subject] = true
        val (rec, sig) = auth.append(op.contentId(), at)
        r.receiptList.add(rec)
        r.sigList.add(sig)
        r.epochState = 1
        return Created(r, rec, rec.seq)
    }

    // ---- Delivery Model B: the principal registry (semantic id -> durable Handle, R-1.4) ---

    /**
     * One principal-registry record: a semantic principal id bound to a durable Handle at a monotonic
     * per-principal epoch, chained to the prior binding's head. Signed as an Identity-channel (0x0003)
     * tier-1 object; here it is the wire body (byte-graded) and the registry below is the policy
     * (behaviour-graded).
     */
    class Binding(val principal: String, val handle: String, val epoch: Long, prev: ByteArray) {
        val prev: ByteArray = prev.copyOf()

        /** Deterministic-CBOR encoding {1:principal,2:handle,3:epoch,4:prev}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.T(principal)),
                    Cbor.Pair(Cbor.U(2), Cbor.T(handle)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(epoch)),
                    Cbor.Pair(Cbor.U(4), Cbor.B(prev)),
                )
            )
        )

        /**
         * The per-principal chain head after this binding: SHA-384(binding body). Because the body carries
         * the prior head, editing any binding breaks the next binding's linkage.
         */
        fun head(): ByteArray = sha384(bytes())
    }

    /** The empty per-principal chain head (48 zero bytes). */
    fun genesisHead(): ByteArray = ByteArray(Audit.HEAD_SIZE)

    /**
     * The durable semantic-naming layer of Delivery Model B: it maps each semantic principal id to its
     * current durable Handle, keeping a per-principal signed binding chain. A delivery addresses a
     * semantic id and [resolve] returns the Handle at send time.
     */
    class PrincipalRegistry {
        private val chain = LinkedHashMap<String, ArrayList<Binding>>()
        private val head = LinkedHashMap<String, ByteArray>()
        private val current = LinkedHashMap<String, String>()
        private val epoch = LinkedHashMap<String, Long>()

        /**
         * Create the FIRST binding for a principal (epoch 0, prev = genesis). A principal already bound is
         * PrincipalExists (use rebind); an empty or non-NFC principal/handle is rejected.
         */
        fun bind(principal: String, handle: String): Binding {
            if (principal.isEmpty() || handle.isEmpty()) throw NaalpException("RoomOpMismatch", "empty principal or handle")
            Identity.requireNfc(principal)
            Identity.requireNfc(handle)
            if (current.containsKey(principal)) throw NaalpException("PrincipalExists", "principal already bound; use rebind")
            val b = Binding(principal, handle, 0, genesisHead())
            chain[principal] = arrayListOf(b)
            head[principal] = b.head()
            current[principal] = handle
            epoch[principal] = 0
            return b
        }

        /**
         * Update a principal to a new durable Handle, REQUIRING a verified rotation from the current handle
         * to the new handle (R-1.4): the semantic id survives key rotation, but a rebind to a key not
         * proven continuous with the current handle is refused (RebindUnauthorized). The binding epoch
         * bumps and the chain links to the prior head.
         */
        fun rebind(
            principal: String, newHandle: String, rot: Identity.RotationRecord,
            oldAlg: Int, oldPub: ByteArray, newAlg: Int, newPub: ByteArray, oldSig: ByteArray, newSig: ByteArray,
        ): Binding {
            val cur = current[principal] ?: throw NaalpException("PrincipalUnknown", "no binding for the semantic principal id")
            if (newHandle.isEmpty()) throw NaalpException("RoomOpMismatch", "empty new handle")
            Identity.requireNfc(newHandle)
            // The rotation MUST carry the current handle as old and the new handle as new, and it MUST be a
            // valid co-signed rotation (both keys derive their ids and both signatures verify).
            if (rot.oldId != cur || rot.newId != newHandle) {
                throw NaalpException("RebindUnauthorized", "a rebind requires a verified rotation from the current handle")
            }
            try {
                Identity.verifyRotation(rot, oldAlg, oldPub, newAlg, newPub, oldSig, newSig)
            } catch (e: NaalpException) {
                throw NaalpException("RebindUnauthorized", "a rebind requires a verified rotation from the current handle")
            }
            val ep = epoch[principal]!! + 1
            val b = Binding(principal, newHandle, ep, head[principal]!!)
            chain[principal]!!.add(b)
            head[principal] = b.head()
            current[principal] = newHandle
            epoch[principal] = ep
            return b
        }

        /**
         * Return the current durable Handle for a semantic principal id (Delivery Model B). An unknown
         * principal is PrincipalUnknown (fail-closed - never a silent empty handle).
         */
        fun resolve(principal: String): String =
            current[principal] ?: throw NaalpException("PrincipalUnknown", "no binding for the semantic principal id")

        /** A principal's ordered binding chain (its persistent state) for offline audit, or null. */
        fun chain(principal: String): List<Binding>? = chain[principal]
    }
}
