// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Naalp
{
    /// <summary>
    /// Collaboration / rooms membership for the C# SDK (feature #64): a Phase-3 ADDITIVE higher tier
    /// (tier 1) over the frozen draft-00 spine (design.md §2..§10; design-channels.md §21), ported from
    /// impl/go/rooms and cross-checked against impl/python/naalp/rooms.py. It introduces NO new
    /// envelope, encoding, signature, identity, or audit mechanism — it reuses the spine unchanged
    /// (R-11.3, R-15A.2) — and adds only tier-1 object kinds on the Governance channel (0x0004;
    /// membership ops) and the Identity channel (0x0003; the principal registry). A frozen baseline
    /// verifier that has not licensed the tier rejects a room kind as UnknownKind, fail-closed.
    ///
    /// <para>It builds three recorded maintainer decisions: (#4a) every membership change is a
    /// first-class SIGNED object, CURSOR-OCCUPYING, RECEIPT-CHAINED (the room log IS the §8.1 audit
    /// chain over op content ids), and EPOCH-BUMPING (a superseded epoch is StaleEpoch); (#4b) O2
    /// ownership is multi-owner ADD-ONLY (an owner is never removed nor demoted, so the owner count is
    /// monotonically >= 1 — a room can never become ownerless); (#3) Delivery Model B — a semantic
    /// principal id resolves to a durable Handle, and a rebind is authorised ONLY by a verified
    /// rotation from the current handle (R-1.4), composing on the ADDITIVE C4 identity-rotation
    /// primitive (<see cref="Identity.RotationRecord"/> / <see cref="Identity.VerifyRotation"/>), so the
    /// semantic id survives key rotation while a hijack to an unrelated key is refused
    /// RebindUnauthorized.</para>
    ///
    /// <para>Every check is fail-closed (§15): an op that fails any check is rejected whole, throws its
    /// named error, and causes no state change. Graded against vectors/rooms/cases.json.</para>
    /// </summary>
    public static class Rooms
    {
        // Channel bindings (R-1.2) and the tier for this higher-tier surface.
        public const long ChannelGovernance = 0x0004; // membership ops (who is authorised in the room)
        public const long ChannelIdentity = 0x0003;   // the principal registry (durable naming, R-1.4)
        public const long Tier = 1;                    // a named higher tier over the frozen baseline (tier 0)

        // Room membership operation codes (naalp-room-op field 2).
        public const long OpCreate = 0;
        public const long OpAddMember = 1;
        public const long OpRemoveMember = 2;
        public const long OpChangeRole = 3;
        public const long OpAddOwner = 4;

        // Role codes (naalp-room-op field 5). A role is the collaboration role that gates membership
        // ops — NOT an effect and NOT a capability ceiling.
        public const long RoleMember = 0;
        public const long RoleAdmin = 1;
        public const long RoleOwner = 2;

        // Tier-1 kind codes. Governance (0x0004) carries the five membership ops; Identity (0x0003)
        // carries the principal binding. They start at 16 to sit clear of the frozen baseline kinds.
        public const long KindRoomCreate = 16;
        public const long KindRoomAddMember = 17;
        public const long KindRoomRemoveMember = 18;
        public const long KindRoomChangeRole = 19;
        public const long KindRoomAddOwner = 20;
        public const long KindPrincipalBind = 16; // on the Identity channel

        private static NaalpException Err(string kind, string msg) => new NaalpException(kind, msg);

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }

        // ---- the membership op (the first-class signed object's body) -------------------------

        /// <summary>One membership operation body carried in envelope field 10. Its content id
        /// (multihash(0x20, SHA-384(body))) is what the room log orders (the cursor position), so the op
        /// is content-addressed and its ordering is tamper-evident.</summary>
        public sealed class RoomOp
        {
            public readonly byte[] Room;    // room id (bstr)
            public readonly long Op;        // 0 create | 1 add_member | 2 remove_member | 3 change_role | 4 add_owner
            public readonly long Epoch;     // the membership epoch this op is built against (bumps on accept)
            public readonly string Subject; // the affected member's signer id (the creator, for create); MUST be NFC
            public readonly long Role;      // 0 member | 1 admin | 2 owner

            public RoomOp(byte[] room, long op, long epoch, string subject, long role)
            {
                Room = (byte[])room.Clone();
                Op = op;
                Epoch = epoch;
                Subject = subject;
                Role = role;
            }

            internal Cbor.M ToMap()
            {
                return new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Room)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(Op)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(Epoch)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.T(Subject)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(Role)),
                });
            }

            /// <summary>Deterministic-CBOR encoding {1:room,2:op,3:epoch,4:subject,5:role}.</summary>
            public byte[] Bytes() => Cbor.Encode(ToMap());

            /// <summary>The op's content id in the T1 framing (§2.3): multihash(0x20, SHA-384(body)).</summary>
            public byte[] ContentId() => Cbor.ContentId(Bytes());

            /// <summary>Build the (unsigned) N-AALP envelope object that carries this op: tier 1,
            /// Governance channel, the op's kind and declared effect, the op body as field 10. The caller
            /// signs it with <see cref="Envelope.Sign"/> to produce the first-class signed membership
            /// object. An unknown op or a non-NFC subject is rejected fail-closed.</summary>
            public Envelope.Object EnvelopeObject(byte[] signer, long created, long profile, List<byte[]>? causes)
            {
                (long kind, long eff, bool ok) = KindForOp(Op);
                if (!ok)
                {
                    throw Err("OpUnknown", "unknown room op code");
                }
                Identity.RequireNfc(Subject); // throws NonNFC (§3.1, R-3.3)
                return new Envelope.Object(
                    kind: kind, channel: ChannelGovernance, signer: signer, created: created, effect: eff,
                    body: ToMap(), tier: Tier, profile: profile, causes: causes);
            }
        }

        /// <summary>Parse an envelope object body (field 10) back into a RoomOp. A body that is not
        /// exactly the {1,2,3,4,5} map with the right value types is RoomOpMismatch (fail-closed).</summary>
        public static RoomOp RoomOpFromBody(Cbor.Value v)
        {
            if (!(v is Cbor.M m))
            {
                throw Err("RoomOpMismatch", "op body is not a map");
            }
            byte[]? room = null;
            long? op = null, epoch = null, role = null;
            string? subject = null;
            var seen = new HashSet<long>();
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku) || ku.V < 1 || ku.V > 5)
                {
                    throw Err("RoomOpMismatch", "op body has an out-of-range field");
                }
                switch (ku.V)
                {
                    case 1:
                        if (!(p.Val is Cbor.B b)) throw Err("RoomOpMismatch", "room is not a bstr");
                        room = b.V;
                        break;
                    case 2:
                        if (!(p.Val is Cbor.U u2)) throw Err("RoomOpMismatch", "op is not a uint");
                        op = u2.V;
                        break;
                    case 3:
                        if (!(p.Val is Cbor.U u3)) throw Err("RoomOpMismatch", "epoch is not a uint");
                        epoch = u3.V;
                        break;
                    case 4:
                        if (!(p.Val is Cbor.T t)) throw Err("RoomOpMismatch", "subject is not a tstr");
                        subject = t.V;
                        break;
                    case 5:
                        if (!(p.Val is Cbor.U u5)) throw Err("RoomOpMismatch", "role is not a uint");
                        role = u5.V;
                        break;
                }
                seen.Add(ku.V);
            }
            if (!(seen.Contains(1) && seen.Contains(2) && seen.Contains(3) && seen.Contains(4) && seen.Contains(5)))
            {
                throw Err("RoomOpMismatch", "op body is missing a mandatory field");
            }
            return new RoomOp(room!, op!.Value, epoch!.Value, subject!, role!.Value);
        }

        /// <summary>Map an op code to its tier-1 Governance kind and its declared effect
        /// (design-channels.md §21). remove_member is destructive; the rest are non_idempotent_write.</summary>
        public static (long Kind, long Effect, bool Ok) KindForOp(long op)
        {
            switch (op)
            {
                case OpCreate: return (KindRoomCreate, Policy.NON_IDEMPOTENT_WRITE, true);
                case OpAddMember: return (KindRoomAddMember, Policy.NON_IDEMPOTENT_WRITE, true);
                case OpRemoveMember: return (KindRoomRemoveMember, Policy.DESTRUCTIVE, true);
                case OpChangeRole: return (KindRoomChangeRole, Policy.NON_IDEMPOTENT_WRITE, true);
                case OpAddOwner: return (KindRoomAddOwner, Policy.NON_IDEMPOTENT_WRITE, true);
                default: return (0, 0, false);
            }
        }

        // ---- kind validation (composes with the frozen baseline) ------------------------------

        /// <summary>Accept exactly this surface's tier-1 kinds: the five Governance membership kinds and
        /// the Identity principal-bind kind. Nothing else.</summary>
        public static bool KindValidator(long channel, long kind)
        {
            if (channel == ChannelGovernance)
            {
                return kind >= KindRoomCreate && kind <= KindRoomAddOwner;
            }
            if (channel == ChannelIdentity)
            {
                return kind == KindPrincipalBind;
            }
            return false;
        }

        private static bool BaselineKind(long channel, long kind)
        {
            try
            {
                Channels.Lookup(channel, kind);
                return true;
            }
            catch (NaalpException)
            {
                return false;
            }
        }

        /// <summary>Accept the frozen baseline kinds OR this surface's tier-1 kinds — the validator a
        /// rooms-aware endpoint passes to <see cref="Envelope.Verify"/>. A baseline-only endpoint using
        /// the baseline validator alone correctly rejects a room kind as UnknownKind (fail-closed).</summary>
        public static bool ComposedKindValidator(long channel, long kind)
            => BaselineKind(channel, kind) || KindValidator(channel, kind);

        // ---- the room state machine (per-room membership + the receipt-chained log) ------------

        /// <summary>A collaboration room's live membership state and its signed, append-only log. The
        /// log is a C7 audit receipt chain (§8.1): each accepted op is ordered at a cursor (the receipt
        /// seq) over the op's content id, weaving membership into the tamper-evident chain.</summary>
        public sealed class Room
        {
            private readonly byte[] _id;
            private long _epoch;
            private readonly Dictionary<string, long> _members;
            private readonly HashSet<string> _owners;
            private readonly Audit.Authority _auth;
            private readonly List<Audit.Receipt> _receipts;
            private readonly List<byte[]> _sigs;

            private Room(byte[] id, Audit.Authority auth)
            {
                _id = (byte[])id.Clone();
                _epoch = 0;
                _members = new Dictionary<string, long>();
                _owners = new HashSet<string>();
                _auth = auth;
                _receipts = new List<Audit.Receipt>();
                _sigs = new List<byte[]>();
            }

            /// <summary>Build a room from a verified create op signed by the creator. The creator (the op
            /// subject) becomes the first and, at creation, only owner+member. The create op occupies
            /// cursor 0 in the log; the room advances to epoch 1. A non-create op, a non-zero epoch, an
            /// empty/non-NFC subject, or an actor that is not the subject is rejected fail-closed.</summary>
            public static (Room Room, Audit.Receipt Receipt, long Cursor) Create(RoomOp op, string actor, Audit.Authority auth, long at)
            {
                if (op.Op != OpCreate)
                {
                    throw Err("RoomOpMismatch", "create requires a create op");
                }
                if (op.Epoch != 0)
                {
                    throw Err("StaleEpoch", "a create op must be built against epoch 0");
                }
                if (op.Subject == "")
                {
                    throw Err("RoomOpMismatch", "empty subject");
                }
                Identity.RequireNfc(op.Subject); // throws NonNFC
                if (actor != op.Subject) // the creator seeds itself as the first owner
                {
                    throw Err("Unauthorized", "the create actor must be the seeded owner (the subject)");
                }
                var r = new Room(op.Room, auth);
                r._members[op.Subject] = RoleOwner;
                r._owners.Add(op.Subject);
                (Audit.Receipt rec, byte[] sig) = auth.Append(op.ContentId(), at);
                r._receipts.Add(rec);
                r._sigs.Add(sig);
                r._epoch = 1;
                return (r, rec, rec.Seq);
            }

            /// <summary>Validate and apply one membership op (add_member, remove_member, change_role,
            /// add_owner) by an owner <paramref name="actor"/>, order it into the room log, and bump the
            /// epoch. Check order is fail-closed throughout: room match -> epoch -> subject well-formed
            /// -> authorization -> per-op semantics -> order -> mutate -> bump. Any failure throws a
            /// named error and leaves the room unchanged. Returns (receipt, cursor).</summary>
            public (Audit.Receipt Receipt, long Cursor) Apply(RoomOp op, string actor, long at)
            {
                if (!BytesEqual(op.Room, _id) || op.Op == OpCreate)
                {
                    throw Err("RoomOpMismatch", "op room id, kind, or op code does not match this room");
                }
                if (op.Epoch != _epoch)
                {
                    throw Err("StaleEpoch", "op epoch does not match the room's current membership epoch");
                }
                if (op.Subject == "")
                {
                    throw Err("RoomOpMismatch", "empty subject");
                }
                Identity.RequireNfc(op.Subject); // throws NonNFC
                if (!_owners.Contains(actor)) // only an owner may change membership (R-6.5)
                {
                    throw Err("Unauthorized", "actor is not an owner of the room");
                }

                // Per-op semantic validation — NO mutation yet (so a rejection is a true no-op).
                switch (op.Op)
                {
                    case OpAddMember:
                        if (op.Role != RoleMember && op.Role != RoleAdmin)
                        {
                            throw Err("RoleInvalid", "owners are added via add_owner only");
                        }
                        if (_members.ContainsKey(op.Subject))
                        {
                            throw Err("MemberExists", "subject is already a member");
                        }
                        break;
                    case OpAddOwner:
                        if (op.Role != RoleOwner)
                        {
                            throw Err("RoleInvalid", "add_owner must carry the owner role");
                        }
                        if (_owners.Contains(op.Subject))
                        {
                            throw Err("OwnerExists", "subject is already an owner");
                        }
                        break;
                    case OpRemoveMember:
                        if (!_members.ContainsKey(op.Subject))
                        {
                            throw Err("MemberUnknown", "subject is not a member of the room");
                        }
                        if (_owners.Contains(op.Subject))
                        {
                            throw Err("OwnerImmutable", "an owner cannot be removed (ownership is add-only)");
                        }
                        break;
                    case OpChangeRole:
                        if (!_members.ContainsKey(op.Subject))
                        {
                            throw Err("MemberUnknown", "subject is not a member of the room");
                        }
                        if (op.Role != RoleMember && op.Role != RoleAdmin)
                        {
                            throw Err("RoleInvalid", "promote to owner via add_owner only");
                        }
                        if (_members[op.Subject] == RoleOwner)
                        {
                            throw Err("OwnerImmutable", "an owner cannot be demoted");
                        }
                        break;
                    default:
                        throw Err("OpUnknown", "unknown room op code");
                }

                // Order the op into the log first; if ordering fails there is no state change.
                (Audit.Receipt rec, byte[] sig) = _auth.Append(op.ContentId(), at);
                switch (op.Op)
                {
                    case OpAddMember:
                        _members[op.Subject] = op.Role;
                        break;
                    case OpAddOwner:
                        _members[op.Subject] = RoleOwner;
                        _owners.Add(op.Subject);
                        break;
                    case OpRemoveMember:
                        _members.Remove(op.Subject);
                        break;
                    case OpChangeRole:
                        _members[op.Subject] = op.Role;
                        break;
                }
                _receipts.Add(rec);
                _sigs.Add(sig);
                _epoch++;
                return (rec, rec.Seq);
            }

            /// <summary>The behavioural end-to-end path: verify a signed membership object with real
            /// crypto (<see cref="Envelope.Verify"/> against the composed rooms validator), bind the
            /// claimed signer id to the verifying key (a self-asserted id that does not derive from the
            /// authenticated key confers no authority, R-1.3/R-5.1), confirm the object is a tier-1
            /// Governance room op whose kind and effect match its op code, then apply it with the
            /// authenticated signer id as the actor.</summary>
            public (Audit.Receipt Receipt, long Cursor) ApplySigned(int profile, int alg, byte[] pubkey, byte[] signedObj, long at)
            {
                Envelope.Object o = Envelope.Verify(profile, alg, pubkey, ComposedKindValidator, signedObj);
                if (o.Channel != ChannelGovernance || o.Tier != Tier)
                {
                    throw Err("RoomOpMismatch", "object is not a tier-1 Governance room op");
                }
                string actor = Identity.SignerId(alg, pubkey);
                if (Identity.Utf8(o.Signer) != actor) // the object's signer field must be the authenticated id
                {
                    throw new NaalpException("SignerMismatch", "signer id does not derive from the verifying key");
                }
                RoomOp op = RoomOpFromBody(o.Body);
                (long wantKind, long wantEff, bool ok) = KindForOp(op.Op);
                if (!ok || o.Kind != wantKind || o.Effect != wantEff)
                {
                    throw Err("RoomOpMismatch", "op kind/effect does not match its op code");
                }
                return Apply(op, actor, at);
            }

            /// <summary>The room id.</summary>
            public byte[] Id() => (byte[])_id.Clone();

            /// <summary>The room's current membership epoch (the epoch the next op must carry).</summary>
            public long Epoch() => _epoch;

            /// <summary>A subject's role and whether it is a member.</summary>
            public (long Role, bool Ok) RoleOf(string subject)
                => _members.TryGetValue(subject, out long role) ? (role, true) : (0, false);

            /// <summary>Whether a subject is an owner of the room.</summary>
            public bool IsOwner(string subject) => _owners.Contains(subject);

            /// <summary>The number of owners; the add-only invariant keeps this >= 1 after Create.</summary>
            public int OwnerCount() => _owners.Count;

            /// <summary>The owner ids in sorted order.</summary>
            public List<string> Owners()
            {
                var outp = new List<string>(_owners);
                outp.Sort(StringComparer.Ordinal);
                return outp;
            }

            /// <summary>The members and their roles (a copy).</summary>
            public Dictionary<string, long> Members() => new Dictionary<string, long>(_members);

            /// <summary>The room log's receipts and their signatures (its persistent state); verifies
            /// offline with <see cref="Audit.VerifyChain"/> against the ordering authority's key.</summary>
            public (IReadOnlyList<Audit.Receipt> Receipts, IReadOnlyList<byte[]> Sigs) Log() => (_receipts, _sigs);
        }

        /// <summary>Build a room from a verified create op signed by the creator (see
        /// <see cref="Room.Create"/>). Returns (room, receipt, cursor).</summary>
        public static (Room Room, Audit.Receipt Receipt, long Cursor) CreateRoom(RoomOp op, string actor, Audit.Authority auth, long at)
            => Room.Create(op, actor, auth, at);

        // ---- Delivery Model B: the principal registry (semantic id -> durable Handle, R-1.4) ---

        /// <summary>One principal-registry record: a semantic principal id bound to a durable Handle at
        /// a monotonic per-principal epoch, chained to the prior binding's head. Here it is the wire
        /// body (byte-graded); the registry below is the policy (behaviour-graded).</summary>
        public sealed class Binding
        {
            public readonly string Principal; // the stable semantic principal id (MUST be NFC)
            public readonly string Handle;    // the current durable Handle (a signer id)
            public readonly long Epoch;       // monotonic per-principal binding epoch (0 for the first bind)
            public readonly byte[] Prev;      // prior binding chain head (48 bytes; genesis = zero)

            public Binding(string principal, string handle, long epoch, byte[] prev)
            {
                Principal = principal;
                Handle = handle;
                Epoch = epoch;
                Prev = (byte[])prev.Clone();
            }

            /// <summary>Deterministic-CBOR encoding {1:principal,2:handle,3:epoch,4:prev}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(Principal)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(Handle)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(Epoch)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(Prev)),
                }));
            }

            /// <summary>The per-principal chain head after this binding: SHA-384(binding body). Because
            /// the body carries the prior head, editing any binding breaks the next binding's linkage.</summary>
            public byte[] Head() => SHA384.HashData(Bytes());
        }

        /// <summary>The empty per-principal chain head (48 zero bytes).</summary>
        public static byte[] GenesisHead() => new byte[Audit.HeadSize];

        /// <summary>The durable semantic-naming layer of Delivery Model B: it maps each semantic
        /// principal id to its current durable Handle, keeping a per-principal signed binding chain. A
        /// delivery addresses a semantic id and Resolve returns the Handle at send time.</summary>
        public sealed class PrincipalRegistry
        {
            private readonly Dictionary<string, List<Binding>> _chain = new Dictionary<string, List<Binding>>();
            private readonly Dictionary<string, byte[]> _head = new Dictionary<string, byte[]>();
            private readonly Dictionary<string, string> _current = new Dictionary<string, string>();
            private readonly Dictionary<string, long> _epoch = new Dictionary<string, long>();

            /// <summary>Create the FIRST binding for a principal (epoch 0, prev = genesis). A principal
            /// already bound is PrincipalExists (use Rebind); an empty or non-NFC principal/handle is
            /// rejected.</summary>
            public Binding Bind(string principal, string handle)
            {
                if (principal == "" || handle == "")
                {
                    throw Err("RoomOpMismatch", "empty principal or handle");
                }
                Identity.RequireNfc(principal);
                Identity.RequireNfc(handle);
                if (_current.ContainsKey(principal))
                {
                    throw Err("PrincipalExists", "principal already bound; use Rebind");
                }
                var b = new Binding(principal, handle, 0, GenesisHead());
                _chain[principal] = new List<Binding> { b };
                _head[principal] = b.Head();
                _current[principal] = handle;
                _epoch[principal] = 0;
                return b;
            }

            /// <summary>Update a principal to a new durable Handle, REQUIRING a verified rotation from
            /// the current handle to the new handle (R-1.4): the semantic id survives key rotation, but a
            /// rebind to a key not proven continuous with the current handle is refused
            /// (RebindUnauthorized). The binding epoch bumps and the chain links to the prior head. The
            /// rotation MUST carry the current handle as old and the new handle as new, AND be a valid
            /// co-signed rotation (both keys derive their ids and both signatures verify).</summary>
            public Binding Rebind(string principal, string newHandle, Identity.RotationRecord rot,
                int oldAlg, byte[] oldPub, int newAlg, byte[] newPub, byte[] oldSig, byte[] newSig)
            {
                if (!_current.TryGetValue(principal, out string? cur))
                {
                    throw Err("PrincipalUnknown", "no binding for the semantic principal id");
                }
                if (newHandle == "")
                {
                    throw Err("RoomOpMismatch", "empty new handle");
                }
                Identity.RequireNfc(newHandle);
                if (rot.Old != cur || rot.New != newHandle)
                {
                    throw Err("RebindUnauthorized", "a rebind requires a verified rotation from the current handle");
                }
                try
                {
                    Identity.VerifyRotation(rot, oldAlg, oldPub, newAlg, newPub, oldSig, newSig);
                }
                catch (NaalpException e) when (e.Kind == "RotationUnauthorized")
                {
                    throw Err("RebindUnauthorized", "a rebind requires a verified rotation from the current handle");
                }
                long ep = _epoch[principal] + 1;
                var b = new Binding(principal, newHandle, ep, _head[principal]);
                _chain[principal].Add(b);
                _head[principal] = b.Head();
                _current[principal] = newHandle;
                _epoch[principal] = ep;
                return b;
            }

            /// <summary>Return the current durable Handle for a semantic principal id (Delivery Model B).
            /// An unknown principal is PrincipalUnknown (fail-closed — never a silent empty handle).</summary>
            public string Resolve(string principal)
            {
                if (!_current.TryGetValue(principal, out string? h))
                {
                    throw Err("PrincipalUnknown", "no binding for the semantic principal id");
                }
                return h;
            }

            /// <summary>A principal's ordered binding chain (its persistent state) for offline audit, or
            /// null.</summary>
            public List<Binding>? Chain(string principal)
                => _chain.TryGetValue(principal, out List<Binding>? c) ? c : null;
        }
    }
}
