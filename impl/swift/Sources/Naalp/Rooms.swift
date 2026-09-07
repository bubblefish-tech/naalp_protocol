// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP collaboration / rooms membership for the Swift SDK (feature #64): a Phase-3 ADDITIVE higher
// tier (tier 1) over the frozen draft-00 spine (design.md §2..§10; design-channels.md §21). It
// introduces NO new envelope, encoding, signature, identity, or audit mechanism — it reuses the spine
// unchanged (R-11.3, R-15A.2) — and adds only tier-1 object kinds on the Governance channel (0x0004;
// membership ops) and the Identity channel (0x0003; the principal registry). A frozen baseline
// verifier that has not licensed the tier rejects a room kind as UnknownKind, fail-closed.
//
// It builds three recorded maintainer decisions:
//
//   - #4a Membership carriage — every membership change (create, add_member, remove_member,
//     change_role, add_owner) is a first-class SIGNED object (a normal N-AALP envelope object, §2),
//     CURSOR-OCCUPYING (a real ordered position in the per-room log), RECEIPT-CHAINED (the room log IS
//     the C7 append-only signed audit/receipt chain of §8.1 — this port reuses Naalp.Audit.Authority /
//     Audit.Receipt unchanged, one Receipt per accepted op over the op's content id), and EPOCH-BUMPING
//     (each accepted op increments the room's membership epoch; an op built against a superseded epoch
//     is rejected StaleEpoch — serialising concurrent changes so a stale view cannot win).
//   - #4b O2 ownership — multi-owner, ADD-ONLY: a room may have many owners; add_owner adds one; an
//     owner is NEVER removed (remove_member refuses an owner) nor demoted (change_role refuses to lower
//     an owner). Create seeds exactly one owner and add_owner only grows the set, so the owner count is
//     monotonically >= 1 — a room can never become ownerless.
//   - #3  Delivery Model B — PrincipalRegistry maps a stable semantic principal id to a durable Handle
//     (the current signer id), resolved at send time. The binding survives key rotation (a rebind is
//     authorised only by a verified co-signed rotation from the current handle, R-1.4 — this port
//     composes on the C4 Identity.signRotation/verifyRotation primitive added additively to
//     Identity.swift), so the semantic id is a durable layer above the connection-scoped handle while a
//     hijack to an unrelated key is refused RebindUnauthorized.
//
// An independent transcription of impl/go/rooms (cross-read against impl/python/naalp/rooms.py and
// impl/php/src/Rooms.php), graded against the shared vectors/rooms/cases.json. Every check is
// fail-closed (§15): an op that fails any check is rejected whole, returns its named error, and causes
// no state change.
//
// CRYPTO SCOPE (PURE-ONLY): Swift has no deterministic-from-seed ML-DSA (FIPS 204) signer
// (SwiftDilithium 3.6.0). The corpus-graded surfaces — op bodies/content-ids, the receipt-chained
// room-log bodies/heads/objs, the cursor/epoch progression, the final membership/ownership state, and
// the principal-binding bodies/heads — are all signature-independent and pure. The room-log ordering
// authority signs each receipt with a real Ed25519 (RFC 8032) key (Audit.Authority, the pure-tier
// stand-in for the reference's ML-DSA authority) and the log verifies offline; the rebind rotation is a
// real co-signed Ed25519 rotation. The signed membership object's END-TO-END apply (#4a) composes on
// the spine Envelope.verify, which SKIP-TRACKS the ML-DSA signature (Unavailable) in this pure tier, so
// its post-verification authorization+apply half is exercised directly (applyVerifiedObject); the
// reference's ML-DSA cross-language signed pins are NOT reproducible here and are NOT fabricated
// (honest F2/F4, mirroring the PHP + Delegation ports).

import Crypto
import Foundation

public enum Rooms {
    // Channel bindings (R-1.2) and the tier for this higher-tier surface.
    public static let CHANNEL_GOVERNANCE: UInt64 = 0x0004 // membership ops (who is authorised in the room)
    public static let CHANNEL_IDENTITY: UInt64 = 0x0003   // the principal registry (durable naming, R-1.4)
    public static let TIER: UInt64 = 1                     // a named higher tier over the frozen baseline (tier 0)

    // Room membership operation codes (naalp-room-op field 2).
    public static let OP_CREATE: UInt64 = 0
    public static let OP_ADD_MEMBER: UInt64 = 1
    public static let OP_REMOVE_MEMBER: UInt64 = 2
    public static let OP_CHANGE_ROLE: UInt64 = 3
    public static let OP_ADD_OWNER: UInt64 = 4

    // Role codes (naalp-room-op field 5) — the collaboration role that gates membership ops; NOT an
    // effect and NOT a capability ceiling.
    public static let ROLE_MEMBER: UInt64 = 0
    public static let ROLE_ADMIN: UInt64 = 1
    public static let ROLE_OWNER: UInt64 = 2

    // Tier-1 kind codes. Governance (0x0004) carries the five membership ops; Identity (0x0003) carries
    // the principal binding. They start at 16 to sit clear of the frozen baseline kinds.
    public static let KIND_ROOM_CREATE: UInt64 = 16
    public static let KIND_ROOM_ADD_MEMBER: UInt64 = 17
    public static let KIND_ROOM_REMOVE_MEMBER: UInt64 = 18
    public static let KIND_ROOM_CHANGE_ROLE: UInt64 = 19
    public static let KIND_ROOM_ADD_OWNER: UInt64 = 20
    public static let KIND_PRINCIPAL_BIND: UInt64 = 16 // on the Identity channel

    // ---- the membership op (the first-class signed object's body) -------------------------

    /// One membership operation body carried in envelope field 10. Its content id (multihash(0x20,
    /// SHA-384(body))) is what the room log orders (the cursor position), so the op is content-addressed
    /// and its ordering is tamper-evident.
    public struct RoomOp {
        public let room: [UInt8]   // room id (bstr)
        public let op: UInt64      // 0 create | 1 add_member | 2 remove_member | 3 change_role | 4 add_owner
        public let epoch: UInt64   // the membership epoch this op is built against (bumps on accept)
        public let subject: String // the affected member's signer id (the creator, for create); MUST be NFC
        public let role: UInt64    // 0 member | 1 admin | 2 owner

        public init(room: [UInt8], op: UInt64, epoch: UInt64, subject: String, role: UInt64) {
            self.room = room
            self.op = op
            self.epoch = epoch
            self.subject = subject
            self.role = role
        }

        func toMap() -> CborValue {
            return .m([
                (.u(1), .b(room)),
                (.u(2), .u(op)),
                (.u(3), .u(epoch)),
                (.u(4), .t(subject)),
                (.u(5), .u(role)),
            ])
        }

        /// Deterministic-CBOR encoding of the op body {1:room,2:op,3:epoch,4:subject,5:role}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(toMap())
        }

        /// The op's content id in the T1 framing (design §2.3): multihash(0x20, SHA-384(body)).
        public func contentId() throws -> [UInt8] {
            return Cbor.contentId(try bytes())
        }

        /// Build the (unsigned) N-AALP envelope object that carries this op: tier 1, Governance channel,
        /// the op's kind and declared effect, the op body as field 10. The caller signs it to produce the
        /// first-class signed membership object. A non-NFC subject or an unknown op is rejected
        /// fail-closed.
        public func envelopeObject(_ signer: [UInt8], _ created: UInt64, _ profile: UInt64, _ causes: [[UInt8]]) throws -> Envelope.Object {
            let (kind, eff, ok) = Rooms.kindForOp(op)
            if !ok {
                throw NaalpError("OpUnknown", "unknown room op code")
            }
            try Identity.requireNFC(subject) // throws NonNFC
            return Envelope.Object(
                kind: kind, channel: Rooms.CHANNEL_GOVERNANCE, signer: signer, created: created,
                effect: UInt64(eff), body: toMap(), tier: Rooms.TIER, profile: profile, causes: causes)
        }
    }

    /// Map an op code to its tier-1 Governance kind and its declared effect (design-channels.md §21).
    /// remove_member is destructive; the rest are non_idempotent_write. Returns (kind, effect, ok).
    public static func kindForOp(_ op: UInt64) -> (kind: UInt64, effect: Int, ok: Bool) {
        switch op {
        case OP_CREATE:        return (KIND_ROOM_CREATE, Policy.NON_IDEMPOTENT_WRITE, true)
        case OP_ADD_MEMBER:    return (KIND_ROOM_ADD_MEMBER, Policy.NON_IDEMPOTENT_WRITE, true)
        case OP_REMOVE_MEMBER: return (KIND_ROOM_REMOVE_MEMBER, Policy.DESTRUCTIVE, true)
        case OP_CHANGE_ROLE:   return (KIND_ROOM_CHANGE_ROLE, Policy.NON_IDEMPOTENT_WRITE, true)
        case OP_ADD_OWNER:     return (KIND_ROOM_ADD_OWNER, Policy.NON_IDEMPOTENT_WRITE, true)
        default:               return (0, 0, false)
        }
    }

    /// Parse an envelope object body (field 10) back into a RoomOp. A body that is not exactly the
    /// {1,2,3,4,5} map with the right value types is RoomOpMismatch (fail-closed).
    public static func roomOpFromBody(_ v: CborValue) throws -> RoomOp {
        guard case let .m(pairs) = v else {
            throw NaalpError("RoomOpMismatch", "op body is not a map")
        }
        var room: [UInt8]? = nil, op: UInt64? = nil, epoch: UInt64? = nil
        var subject: String? = nil, role: UInt64? = nil
        var seen = Set<UInt64>()
        for (k, val) in pairs {
            guard case let .u(kk) = k, kk >= 1, kk <= 5 else {
                throw NaalpError("RoomOpMismatch", "op body has an out-of-range field")
            }
            switch kk {
            case 1:
                guard case let .b(b) = val else { throw NaalpError("RoomOpMismatch", "room is not a bstr") }
                room = b
            case 2:
                guard case let .u(u) = val else { throw NaalpError("RoomOpMismatch", "op is not a uint") }
                op = u
            case 3:
                guard case let .u(u) = val else { throw NaalpError("RoomOpMismatch", "epoch is not a uint") }
                epoch = u
            case 4:
                guard case let .t(s) = val else { throw NaalpError("RoomOpMismatch", "subject is not a tstr") }
                subject = s
            case 5:
                guard case let .u(u) = val else { throw NaalpError("RoomOpMismatch", "role is not a uint") }
                role = u
            default:
                break
            }
            seen.insert(kk)
        }
        guard seen.isSuperset(of: [1, 2, 3, 4, 5]),
              let rm = room, let o = op, let e = epoch, let sub = subject, let rl = role else {
            throw NaalpError("RoomOpMismatch", "op body is missing a mandatory field")
        }
        return RoomOp(room: rm, op: o, epoch: e, subject: sub, role: rl)
    }

    // ---- kind validation (composes with the frozen baseline) ------------------------------

    /// Accept exactly this surface's tier-1 kinds: the five Governance membership kinds and the Identity
    /// principal-bind kind. Nothing else.
    public static func kindValidator(_ channel: UInt64, _ kind: UInt64) -> Bool {
        if channel == CHANNEL_GOVERNANCE {
            return kind >= KIND_ROOM_CREATE && kind <= KIND_ROOM_ADD_OWNER
        }
        if channel == CHANNEL_IDENTITY {
            return kind == KIND_PRINCIPAL_BIND
        }
        return false
    }

    static func baselineKindValidator(_ channel: UInt64, _ kind: UInt64) -> Bool {
        return (try? Channels.lookup(Int(channel), Int(kind))) != nil
    }

    /// Accept the frozen baseline kinds OR this surface's tier-1 kinds — the validator a rooms-aware
    /// endpoint passes to Envelope.verify. A baseline-only endpoint using the baseline validator alone
    /// correctly rejects a room kind as UnknownKind (fail-closed).
    public static func composedKindValidator(_ channel: UInt64, _ kind: UInt64) -> Bool {
        return baselineKindValidator(channel, kind) || kindValidator(channel, kind)
    }

    /// The empty per-principal chain head (48 zero bytes) — the C7 chain genesis width.
    public static func genesisHead() -> [UInt8] {
        return [UInt8](repeating: 0, count: Audit.HEAD_SIZE)
    }

    /// Build a room from a verified create op signed by the creator (see Room.create). Returns
    /// (Room, Receipt, cursor).
    public static func createRoom(_ op: RoomOp, _ actor: String, _ auth: Audit.Authority, _ at: UInt64) throws -> (Room, Audit.Receipt, UInt64) {
        return try Room.create(op, actor, auth, at)
    }

    // ---- the room state machine (per-room membership + the receipt-chained log) ------------

    /// A collaboration room's live membership state and its signed, append-only log. The log is a C7
    /// audit receipt chain (Audit.Authority): each accepted op is ordered at a cursor (the receipt seq)
    /// over the op's content id, weaving membership into the tamper-evident chain.
    public final class Room {
        private let roomId: [UInt8]
        private var epochVal: UInt64
        private var memberRoles: [String: UInt64]
        private var ownerSet: Set<String>
        private let auth: Audit.Authority
        private var receipts: [Audit.Receipt]
        private var sigs: [[UInt8]]

        init(id: [UInt8], auth: Audit.Authority) {
            self.roomId = id
            self.epochVal = 0
            self.memberRoles = [:]
            self.ownerSet = []
            self.auth = auth
            self.receipts = []
            self.sigs = []
        }

        /// Build a room from a verified create op signed by the creator. The creator (the op subject)
        /// becomes the first and, at creation, only owner+member. The create op occupies cursor 0 in the
        /// log; the room advances to epoch 1. A non-create op, a non-zero epoch, an empty/non-NFC
        /// subject, or an actor that is not the subject is rejected fail-closed. Returns (Room, Receipt,
        /// cursor).
        static func create(_ op: RoomOp, _ actor: String, _ auth: Audit.Authority, _ at: UInt64) throws -> (Room, Audit.Receipt, UInt64) {
            if op.op != Rooms.OP_CREATE {
                throw NaalpError("RoomOpMismatch", "create requires a create op")
            }
            if op.epoch != 0 {
                throw NaalpError("StaleEpoch", "a create op must be built against epoch 0")
            }
            if op.subject.isEmpty {
                throw NaalpError("RoomOpMismatch", "empty subject")
            }
            try Identity.requireNFC(op.subject) // throws NonNFC
            if actor != op.subject { // the creator seeds itself as the first owner
                throw NaalpError("Unauthorized", "the create actor must be the seeded owner (the subject)")
            }
            let r = Room(id: op.room, auth: auth)
            r.memberRoles[op.subject] = Rooms.ROLE_OWNER
            r.ownerSet.insert(op.subject)
            let (rec, sig) = try auth.append(try op.contentId(), at)
            r.receipts.append(rec)
            r.sigs.append(sig)
            r.epochVal = 1
            return (r, rec, rec.seq)
        }

        /// Validate and apply one membership op (add_member, remove_member, change_role, add_owner) by an
        /// owner `actor`, order it into the room log, and bump the epoch. Check order is fail-closed
        /// throughout: room match -> epoch -> subject well-formed -> authorization -> per-op semantics ->
        /// order -> mutate -> bump. Any failure throws a named error and leaves the room unchanged.
        /// Returns (Receipt, cursor).
        public func apply(_ op: RoomOp, _ actor: String, _ at: UInt64) throws -> (Audit.Receipt, UInt64) {
            if op.room != roomId || op.op == Rooms.OP_CREATE {
                throw NaalpError("RoomOpMismatch", "op room id or op code does not match this room/operation")
            }
            if op.epoch != epochVal {
                throw NaalpError("StaleEpoch", "op epoch does not match the room's current membership epoch")
            }
            if op.subject.isEmpty {
                throw NaalpError("RoomOpMismatch", "empty subject")
            }
            try Identity.requireNFC(op.subject) // throws NonNFC
            if !ownerSet.contains(actor) { // only an owner may change membership (R-6.5)
                throw NaalpError("Unauthorized", "actor is not an owner of the room")
            }
            // Per-op semantic validation — NO mutation yet (so a rejection is a true no-op).
            switch op.op {
            case Rooms.OP_ADD_MEMBER:
                if op.role != Rooms.ROLE_MEMBER && op.role != Rooms.ROLE_ADMIN {
                    throw NaalpError("RoleInvalid", "owners are added via add_owner only")
                }
                if memberRoles[op.subject] != nil {
                    throw NaalpError("MemberExists", "subject is already a member")
                }
            case Rooms.OP_ADD_OWNER:
                if op.role != Rooms.ROLE_OWNER {
                    throw NaalpError("RoleInvalid", "add_owner must carry the owner role")
                }
                if ownerSet.contains(op.subject) {
                    throw NaalpError("OwnerExists", "subject is already an owner")
                }
            case Rooms.OP_REMOVE_MEMBER:
                if memberRoles[op.subject] == nil {
                    throw NaalpError("MemberUnknown", "subject is not a member of the room")
                }
                if ownerSet.contains(op.subject) {
                    throw NaalpError("OwnerImmutable", "an owner cannot be removed (ownership is add-only)")
                }
            case Rooms.OP_CHANGE_ROLE:
                guard let cur = memberRoles[op.subject] else {
                    throw NaalpError("MemberUnknown", "subject is not a member of the room")
                }
                if op.role != Rooms.ROLE_MEMBER && op.role != Rooms.ROLE_ADMIN {
                    throw NaalpError("RoleInvalid", "promote to owner via add_owner only")
                }
                if cur == Rooms.ROLE_OWNER {
                    throw NaalpError("OwnerImmutable", "an owner cannot be demoted")
                }
            default:
                throw NaalpError("OpUnknown", "unknown room op code")
            }
            // Order the op into the log first; if ordering fails there is no state change.
            let (rec, sig) = try auth.append(try op.contentId(), at)
            switch op.op {
            case Rooms.OP_ADD_MEMBER:
                memberRoles[op.subject] = op.role
            case Rooms.OP_ADD_OWNER:
                memberRoles[op.subject] = Rooms.ROLE_OWNER
                ownerSet.insert(op.subject)
            case Rooms.OP_REMOVE_MEMBER:
                memberRoles[op.subject] = nil
            case Rooms.OP_CHANGE_ROLE:
                memberRoles[op.subject] = op.role
            default:
                break
            }
            receipts.append(rec)
            sigs.append(sig)
            epochVal += 1
            return (rec, rec.seq)
        }

        /// Bind a spine-verified envelope object to the authenticated key and apply it as a membership
        /// op: the object MUST be a tier-1 Governance room op, its signer field MUST equal the signer id
        /// derived from the verifying key (a self-asserted id that does not derive from the authenticated
        /// key confers no authority, R-1.3/R-5.1), and its kind+effect MUST match its op code; then apply
        /// with the authenticated signer id as the actor. This is the post-verification half of
        /// applySigned — exercised directly in the pure Swift tier because Envelope.verify skip-tracks the
        /// ML-DSA signature (Unavailable), so the full applySigned cannot COMPLETE here for an ML-DSA
        /// object. Returns (Receipt, cursor).
        public func applyVerifiedObject(_ o: Envelope.Object, _ alg: Int, _ pubkey: [UInt8], _ at: UInt64) throws -> (Audit.Receipt, UInt64) {
            if o.channel != Rooms.CHANNEL_GOVERNANCE || o.tier != Rooms.TIER {
                throw NaalpError("RoomOpMismatch", "object is not a tier-1 Governance room op")
            }
            let actor = try Identity.signerId(alg, pubkey)
            if o.signer != Array(actor.utf8) { // the object's signer field must be the authenticated id
                throw NaalpError("SignerMismatch", "signer id does not derive from the verifying key")
            }
            let op = try Rooms.roomOpFromBody(o.body)
            let (wantKind, wantEff, ok) = Rooms.kindForOp(op.op)
            if !ok || o.kind != wantKind || o.effect != UInt64(wantEff) {
                throw NaalpError("RoomOpMismatch", "op kind/effect does not match its op code")
            }
            return try apply(op, actor, at)
        }

        /// The behavioural end-to-end path: verify a signed membership object through the spine
        /// (Envelope.verify against the composed rooms validator) and apply the verified object
        /// (applyVerifiedObject). PURE-ONLY Swift: Envelope.verify skip-tracks the ML-DSA signature
        /// (Unavailable), so for an ML-DSA object this path surfaces Unavailable rather than completing —
        /// never a false green (the ML-DSA signature is the one un-exercised leg). Returns (Receipt,
        /// cursor).
        public func applySigned(_ profile: Int, _ alg: Int, _ pubkey: [UInt8], _ signedObj: [UInt8], _ at: UInt64) throws -> (Audit.Receipt, UInt64) {
            let o = try Envelope.verify(profile, alg, pubkey, Rooms.composedKindValidator, signedObj)
            return try applyVerifiedObject(o, alg, pubkey, at)
        }

        /// The room id.
        public func id() -> [UInt8] { return roomId }

        /// The room's current membership epoch (the epoch the next op must carry).
        public func epoch() -> UInt64 { return epochVal }

        /// A subject's role and whether it is a member.
        public func roleOf(_ subject: String) -> (UInt64, Bool) {
            if let r = memberRoles[subject] { return (r, true) }
            return (0, false)
        }

        /// Whether a subject is an owner of the room.
        public func isOwner(_ subject: String) -> Bool { return ownerSet.contains(subject) }

        /// The number of owners; the add-only invariant keeps this >= 1 after create.
        public func ownerCount() -> Int { return ownerSet.count }

        /// The owner ids in sorted order.
        public func owners() -> [String] { return ownerSet.sorted() }

        /// The members and their roles (a copy).
        public func members() -> [String: UInt64] { return memberRoles }

        /// The room log's receipts and their signatures (its persistent state); verifies offline with
        /// Audit.verifyChain against the ordering authority's key.
        public func log() -> ([Audit.Receipt], [[UInt8]]) { return (receipts, sigs) }
    }

    // ---- Delivery Model B: the principal registry (semantic id -> durable Handle, R-1.4) ---

    /// One principal-registry record: a semantic principal id bound to a durable Handle at a monotonic
    /// per-principal epoch, chained to the prior binding's head (SHA-384). Signed as an Identity-channel
    /// (0x0003) tier-1 object; here it is the wire body (byte-graded) and the PrincipalRegistry below is
    /// the policy (behaviour-graded).
    public struct Binding {
        public let principal: String // the stable semantic principal id (MUST be NFC)
        public let handle: String    // the current durable Handle (a signer id) this principal resolves to
        public let epoch: UInt64     // monotonic per-principal binding epoch (0 for the first bind)
        public let prev: [UInt8]     // prior binding chain head (48 bytes; genesis = zero)

        public init(principal: String, handle: String, epoch: UInt64, prev: [UInt8]) {
            self.principal = principal
            self.handle = handle
            self.epoch = epoch
            self.prev = prev
        }

        func toMap() -> CborValue {
            return .m([
                (.u(1), .t(principal)),
                (.u(2), .t(handle)),
                (.u(3), .u(epoch)),
                (.u(4), .b(prev)),
            ])
        }

        /// Deterministic-CBOR encoding {1:principal,2:handle,3:epoch,4:prev}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(toMap())
        }

        /// The per-principal chain head after this binding: SHA-384(binding body). Because the body
        /// carries the prior head, editing any binding breaks the next binding's linkage.
        public func head() throws -> [UInt8] {
            return Array(SHA384.hash(data: Data(try bytes())))
        }
    }

    /// The durable semantic-naming layer of Delivery Model B (R-1.4): it maps each semantic principal id
    /// to its current durable Handle, keeping a per-principal signed binding chain. A delivery addresses
    /// a semantic id and resolve returns the Handle at send time. A rebind is authorised ONLY by a
    /// verified co-signed rotation from the current handle (Identity.verifyRotation).
    public final class PrincipalRegistry {
        private var chains: [String: [Binding]]
        private var heads: [String: [UInt8]]
        private var current: [String: String]
        private var epochs: [String: UInt64]

        public init() {
            chains = [:]
            heads = [:]
            current = [:]
            epochs = [:]
        }

        /// Create the FIRST binding for a principal (epoch 0, prev = genesis). A principal already bound
        /// is PrincipalExists (use rebind); an empty or non-NFC principal/handle is rejected.
        @discardableResult
        public func bind(_ principal: String, _ handle: String) throws -> Binding {
            if principal.isEmpty || handle.isEmpty {
                throw NaalpError("RoomOpMismatch", "empty principal or handle")
            }
            try Identity.requireNFC(principal) // throws NonNFC
            try Identity.requireNFC(handle)
            if current[principal] != nil {
                throw NaalpError("PrincipalExists", "principal already bound; use rebind")
            }
            let b = Binding(principal: principal, handle: handle, epoch: 0, prev: Rooms.genesisHead())
            chains[principal] = [b]
            heads[principal] = try b.head()
            current[principal] = handle
            epochs[principal] = 0
            return b
        }

        /// Update a principal to a new durable Handle, REQUIRING a verified rotation from the current
        /// handle to the new handle (R-1.4): the semantic id survives key rotation, but a rebind to a key
        /// not proven continuous with the current handle is refused (RebindUnauthorized). The binding
        /// epoch bumps and the chain links to the prior head. `rot` is the co-signed rotation record and
        /// the two keys' algs/pubkeys/signatures (Identity.verifyRotation).
        @discardableResult
        public func rebind(_ principal: String, _ newHandle: String, _ rot: Identity.RotationRecord,
                           _ oldAlg: Int, _ oldPub: [UInt8], _ newAlg: Int, _ newPub: [UInt8],
                           _ oldSig: [UInt8], _ newSig: [UInt8]) throws -> Binding {
            guard let cur = current[principal] else {
                throw NaalpError("PrincipalUnknown", "no binding for the semantic principal id")
            }
            if newHandle.isEmpty {
                throw NaalpError("RoomOpMismatch", "empty new handle")
            }
            try Identity.requireNFC(newHandle) // throws NonNFC
            // The rotation MUST carry the current handle as old and the new handle as new, and it MUST be
            // a valid co-signed rotation (both keys derive their ids and both signatures verify).
            if rot.old != cur || rot.new != newHandle {
                throw NaalpError("RebindUnauthorized", "a rebind requires a verified rotation from the current handle")
            }
            do {
                try Identity.verifyRotation(rot, oldAlg, oldPub, newAlg, newPub, oldSig, newSig)
            } catch {
                throw NaalpError("RebindUnauthorized", "a rebind requires a verified rotation from the current handle")
            }
            let ep = (epochs[principal] ?? 0) + 1
            let b = Binding(principal: principal, handle: newHandle, epoch: ep, prev: heads[principal] ?? Rooms.genesisHead())
            chains[principal, default: []].append(b)
            heads[principal] = try b.head()
            current[principal] = newHandle
            epochs[principal] = ep
            return b
        }

        /// Return the current durable Handle for a semantic principal id (Delivery Model B). An unknown
        /// principal is PrincipalUnknown (fail-closed — never a silent empty handle).
        public func resolve(_ principal: String) throws -> String {
            guard let h = current[principal] else {
                throw NaalpError("PrincipalUnknown", "no binding for the semantic principal id")
            }
            return h
        }

        /// A principal's ordered binding chain (its persistent state) for offline audit, or nil.
        public func chain(_ principal: String) -> [Binding]? {
            return chains[principal]
        }
    }
}
