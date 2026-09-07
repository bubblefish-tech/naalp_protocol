# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Collaboration / rooms membership for the Python SDK (feature #64): a Phase-3 ADDITIVE higher
tier (tier 1) over the frozen draft-00 spine (design.md §2..§10; design-channels.md §21). It
introduces NO new envelope, encoding, signature, identity, or audit mechanism -- it reuses the
spine unchanged (R-11.3, R-15A.2) -- and adds only tier-1 object kinds on the Governance channel
(0x0004; membership ops) and the Identity channel (0x0003; the principal registry). A frozen
baseline verifier that has not licensed the tier rejects a room kind as UnknownKind, fail-closed.

It builds three recorded maintainer decisions:

  - #4a Membership carriage -- every membership change (create, add_member, remove_member,
    change_role, add_owner) is a first-class SIGNED object (a normal N-AALP envelope object, §2),
    CURSOR-OCCUPYING (a real ordered position in the per-room log), RECEIPT-CHAINED (the room log IS
    the append-only signed audit/receipt chain of §8.1, one Receipt per accepted op over the op's
    content id), and EPOCH-BUMPING (each accepted op increments the room's membership epoch; an op
    built against a superseded epoch is rejected StaleEpoch -- serialising concurrent changes).
  - #4b O2 ownership -- multi-owner, ADD-ONLY: a room may have many owners; add_owner adds one; an
    owner is NEVER removed (remove_member refuses an owner) nor demoted (change_role refuses to lower
    an owner). Create seeds exactly one owner, add_owner only grows the set, so the owner count is
    monotonically >= 1 -- a room can never become ownerless.
  - #3  Delivery Model B -- PrincipalRegistry maps a stable semantic principal id to a durable
    Handle (the current signer id), resolved at send time. The binding survives key rotation (a
    rebind is authorised only by a verified rotation from the current handle, R-1.4), so the semantic
    id is a durable layer above the connection-scoped handle; a hijack is refused RebindUnauthorized.

Every check is fail-closed (§15): an op that fails any check is rejected whole, returns its named
error, and causes no state change. Ported from impl/go/rooms; graded against vectors/rooms/cases.json.
"""
from . import audit, cbor, channels, cose, envelope, identity, policy
from .cbor import U, T, B, M

# Channel bindings (R-1.2) and the tier for this higher-tier surface.
CHANNEL_GOVERNANCE = 0x0004     # membership ops (who is authorised in the room)
CHANNEL_IDENTITY = 0x0003       # the principal registry (durable naming, R-1.4)
TIER = 1                        # a named higher tier over the frozen baseline (tier 0)

# Room membership operation codes (naalp-room-op field 2).
OP_CREATE = 0
OP_ADD_MEMBER = 1
OP_REMOVE_MEMBER = 2
OP_CHANGE_ROLE = 3
OP_ADD_OWNER = 4

# Role codes (naalp-room-op field 5). A role is the collaboration role that gates membership ops --
# NOT an effect and NOT a capability ceiling.
ROLE_MEMBER = 0
ROLE_ADMIN = 1
ROLE_OWNER = 2

# Tier-1 kind codes. Governance (0x0004) carries the five membership ops; Identity (0x0003) carries
# the principal binding. They start at 16 to sit clear of the frozen baseline kinds.
KIND_ROOM_CREATE = 16
KIND_ROOM_ADD_MEMBER = 17
KIND_ROOM_REMOVE_MEMBER = 18
KIND_ROOM_CHANGE_ROLE = 19
KIND_ROOM_ADD_OWNER = 20
KIND_PRINCIPAL_BIND = 16        # on the Identity channel


class RoomsError(ValueError):
    """A named, fail-closed rooms error; .kind is the stable error kind (§15). Kinds reused from
    other layers (SignerMismatch, NonNFC) carry those exact strings so a verifier's verdict is
    identical to the Go reference."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


# ---- the membership op (the first-class signed object's body) -------------------------

class RoomOp:
    """One membership operation body carried in envelope field 10. Its content id (multihash(0x20,
    SHA-384(body))) is what the room log orders (the cursor position), so the op is content-addressed
    and its ordering is tamper-evident."""

    __slots__ = ("room", "op", "epoch", "subject", "role")

    def __init__(self, room, op, epoch, subject, role):
        self.room = bytes(room)         # room id (bstr)
        self.op = int(op)               # 0 create | 1 add_member | 2 remove_member | 3 change_role | 4 add_owner
        self.epoch = int(epoch)         # the membership epoch this op is built against (bumps on accept)
        self.subject = subject          # the affected member's signer id (the creator, for create); MUST be NFC
        self.role = int(role)           # 0 member | 1 admin | 2 owner

    def _to_map(self):
        return M([
            (U(1), B(self.room)),
            (U(2), U(self.op)),
            (U(3), U(self.epoch)),
            (U(4), T(self.subject)),
            (U(5), U(self.role)),
        ])

    def bytes(self):
        """Deterministic-CBOR encoding {1:room,2:op,3:epoch,4:subject,5:role}."""
        return cbor.encode(self._to_map())

    def content_id(self):
        """The op's content id in the T1 framing (design §2.3): multihash(0x20, SHA-384(body))."""
        return cbor.content_id(self.bytes())

    def envelope_object(self, signer, created, profile, causes):
        """Build the (unsigned) N-AALP envelope object that carries this op: tier 1, Governance
        channel, the op's kind and declared effect, the op body as field 10. The caller signs it with
        envelope.sign to produce the first-class signed membership object. A non-NFC subject or an
        unknown op is rejected fail-closed."""
        kind, eff, ok = kind_for_op(self.op)
        if not ok:
            raise RoomsError("OpUnknown", "unknown room op code")
        try:
            identity.require_nfc(self.subject)
        except identity.NonNFC:
            raise RoomsError("NonNFC", "subject/principal string is not Unicode NFC")
        return envelope.Object(
            kind=kind, channel=CHANNEL_GOVERNANCE, tier=TIER,
            signer=bytes(signer), created=created, effect=int(eff),
            causes=list(causes or []), profile=profile, body=self._to_map())


def room_op_from_body(v):
    """Parse an envelope object body (field 10) back into a RoomOp. A body that is not exactly the
    {1,2,3,4,5} map with the right value types is RoomOpMismatch (fail-closed)."""
    if not isinstance(v, M):
        raise RoomsError("RoomOpMismatch", "op body is not a map")
    room = op = epoch = subject = role = None
    seen = set()
    for k, val in v.pairs:
        if not isinstance(k, U) or k.v < 1 or k.v > 5:
            raise RoomsError("RoomOpMismatch", "op body has an out-of-range field")
        if k.v == 1:
            if not isinstance(val, B):
                raise RoomsError("RoomOpMismatch", "room is not a bstr")
            room = val.v
        elif k.v == 2:
            if not isinstance(val, U):
                raise RoomsError("RoomOpMismatch", "op is not a uint")
            op = val.v
        elif k.v == 3:
            if not isinstance(val, U):
                raise RoomsError("RoomOpMismatch", "epoch is not a uint")
            epoch = val.v
        elif k.v == 4:
            if not isinstance(val, T):
                raise RoomsError("RoomOpMismatch", "subject is not a tstr")
            subject = val.v
        elif k.v == 5:
            if not isinstance(val, U):
                raise RoomsError("RoomOpMismatch", "role is not a uint")
            role = val.v
        seen.add(k.v)
    if not {1, 2, 3, 4, 5}.issubset(seen):
        raise RoomsError("RoomOpMismatch", "op body is missing a mandatory field")
    return RoomOp(room, op, epoch, subject, role)


def kind_for_op(op):
    """Map an op code to its tier-1 Governance kind and its declared effect (design-channels.md §21).
    remove_member is destructive; the rest are non_idempotent_write. Returns (kind, effect, ok)."""
    if op == OP_CREATE:
        return KIND_ROOM_CREATE, policy.NON_IDEMPOTENT_WRITE, True
    if op == OP_ADD_MEMBER:
        return KIND_ROOM_ADD_MEMBER, policy.NON_IDEMPOTENT_WRITE, True
    if op == OP_REMOVE_MEMBER:
        return KIND_ROOM_REMOVE_MEMBER, policy.DESTRUCTIVE, True
    if op == OP_CHANGE_ROLE:
        return KIND_ROOM_CHANGE_ROLE, policy.NON_IDEMPOTENT_WRITE, True
    if op == OP_ADD_OWNER:
        return KIND_ROOM_ADD_OWNER, policy.NON_IDEMPOTENT_WRITE, True
    return 0, 0, False


# ---- kind validation (composes with the frozen baseline) ------------------------------

def kind_validator(channel, kind):
    """Accept exactly this surface's tier-1 kinds: the five Governance membership kinds and the
    Identity principal-bind kind. Nothing else."""
    if channel == CHANNEL_GOVERNANCE:
        return KIND_ROOM_CREATE <= kind <= KIND_ROOM_ADD_OWNER
    if channel == CHANNEL_IDENTITY:
        return kind == KIND_PRINCIPAL_BIND
    return False


def _baseline_kind_validator(channel, kind):
    try:
        channels.lookup(channel, kind)
        return True
    except channels.UnknownKind:
        return False


def composed_kind_validator(channel, kind):
    """Accept the frozen baseline kinds OR this surface's tier-1 kinds -- the validator a rooms-aware
    endpoint passes to envelope.verify. A baseline-only endpoint using the baseline validator alone
    correctly rejects a room kind as UnknownKind (fail-closed)."""
    return _baseline_kind_validator(channel, kind) or kind_validator(channel, kind)


# ---- the room state machine (per-room membership + the receipt-chained log) ------------

class Room:
    """A collaboration room's live membership state and its signed, append-only log. The log is an
    audit receipt chain (§8.1): each accepted op is ordered at a cursor (the receipt seq) over the
    op's content id, weaving membership into the tamper-evident chain."""

    __slots__ = ("_id", "_epoch", "_members", "_owners", "_auth", "_receipts", "_sigs")

    def __init__(self, room_id, auth):
        self._id = bytes(room_id)
        self._epoch = 0
        self._members = {}
        self._owners = {}
        self._auth = auth
        self._receipts = []
        self._sigs = []

    def id(self):
        return bytes(self._id)

    def epoch(self):
        """The room's current membership epoch (the epoch the next op must carry)."""
        return self._epoch

    def role_of(self, subject):
        """Returns (role, is_member)."""
        if subject in self._members:
            return self._members[subject], True
        return 0, False

    def is_owner(self, subject):
        return bool(self._owners.get(subject))

    def owner_count(self):
        """The number of owners; the add-only invariant keeps this >= 1 after create_room."""
        return len(self._owners)

    def owners(self):
        """The owner ids in sorted order."""
        return sorted(self._owners.keys())

    def members(self):
        """The members and their roles (a copy)."""
        return dict(self._members)

    def log(self):
        """The room log's receipts and their signatures (its persistent state); verifies offline with
        audit.verify_chain against the ordering authority's key."""
        return self._receipts, self._sigs

    def apply(self, op, actor, at):
        """Validate and apply one membership op (add_member, remove_member, change_role, add_owner) by
        an owner `actor`, order it into the room log, and bump the epoch. Check order is fail-closed
        throughout: room match -> epoch -> subject well-formed -> authorization -> per-op semantics ->
        order -> mutate -> bump. Any failure raises a named error and leaves the room unchanged.
        Returns (receipt, cursor)."""
        if op.room != self._id or op.op == OP_CREATE:
            raise RoomsError("RoomOpMismatch", "op room id, kind, or op code does not match this room")
        if op.epoch != self._epoch:
            raise RoomsError("StaleEpoch", "op epoch does not match the room's current membership epoch")
        if op.subject == "":
            raise RoomsError("RoomOpMismatch", "empty subject")
        try:
            identity.require_nfc(op.subject)
        except identity.NonNFC:
            raise RoomsError("NonNFC", "subject/principal string is not Unicode NFC")
        if not self._owners.get(actor):     # only an owner may change membership (R-6.5)
            raise RoomsError("Unauthorized", "actor is not an owner of the room")

        # Per-op semantic validation -- NO mutation yet (so a rejection is a true no-op).
        if op.op == OP_ADD_MEMBER:
            if op.role != ROLE_MEMBER and op.role != ROLE_ADMIN:
                raise RoomsError("RoleInvalid", "owners are added via add_owner only")
            if op.subject in self._members:
                raise RoomsError("MemberExists", "subject is already a member")
        elif op.op == OP_ADD_OWNER:
            if op.role != ROLE_OWNER:
                raise RoomsError("RoleInvalid", "add_owner must carry the owner role")
            if self._owners.get(op.subject):
                raise RoomsError("OwnerExists", "subject is already an owner")
        elif op.op == OP_REMOVE_MEMBER:
            if op.subject not in self._members:
                raise RoomsError("MemberUnknown", "subject is not a member of the room")
            if self._owners.get(op.subject):
                raise RoomsError("OwnerImmutable", "an owner cannot be removed (ownership is add-only)")
        elif op.op == OP_CHANGE_ROLE:
            if op.subject not in self._members:
                raise RoomsError("MemberUnknown", "subject is not a member of the room")
            if op.role != ROLE_MEMBER and op.role != ROLE_ADMIN:
                raise RoomsError("RoleInvalid", "promote to owner via add_owner only")
            if self._members[op.subject] == ROLE_OWNER:
                raise RoomsError("OwnerImmutable", "an owner cannot be demoted")
        else:
            raise RoomsError("OpUnknown", "unknown room op code")

        # Order the op into the log first; if ordering fails there is no state change.
        rec, sig = self._auth.append(op.content_id(), at)
        if op.op == OP_ADD_MEMBER:
            self._members[op.subject] = op.role
        elif op.op == OP_ADD_OWNER:
            self._members[op.subject] = ROLE_OWNER
            self._owners[op.subject] = True
        elif op.op == OP_REMOVE_MEMBER:
            del self._members[op.subject]
        elif op.op == OP_CHANGE_ROLE:
            self._members[op.subject] = op.role
        self._receipts.append(rec)
        self._sigs.append(sig)
        self._epoch += 1
        return rec, rec.seq

    def apply_signed(self, profile, alg, pubkey, signed_obj, at):
        """The behavioural end-to-end path: verify a signed membership object with real crypto
        (envelope.verify against the composed rooms validator), bind the claimed signer id to the
        verifying key (a self-asserted id that does not derive from the authenticated key confers no
        authority, R-1.3/R-5.1), confirm the object is a tier-1 Governance room op whose kind and
        effect match its op code, then apply it with the authenticated signer id as the actor."""
        o = envelope.verify(profile, alg, pubkey, composed_kind_validator, signed_obj)
        if o.channel != CHANNEL_GOVERNANCE or o.tier != TIER:
            raise RoomsError("RoomOpMismatch", "object is not a tier-1 Governance room op")
        actor = identity.signer_id(alg, pubkey)
        if o.signer != actor.encode():       # the object's signer field must be the authenticated id
            raise identity.SignerMismatch("signer id does not derive from the verifying key")
        op = room_op_from_body(o.body)
        want_kind, want_eff, ok = kind_for_op(op.op)
        if not ok or o.kind != want_kind or o.effect != int(want_eff):
            raise RoomsError("RoomOpMismatch", "op kind/effect does not match its op code")
        return self.apply(op, actor, at)


def create_room(op, actor, auth, at):
    """Build a room from a verified create op signed by the creator. The creator (the op subject)
    becomes the first and, at creation, only owner+member. The create op occupies cursor 0 in the
    log; the room advances to epoch 1. `auth` is the room's ordering authority. A non-create op, a
    non-zero epoch, an empty/non-NFC subject, or an actor that is not the subject is rejected
    fail-closed. Returns (room, receipt, cursor)."""
    if op.op != OP_CREATE:
        raise RoomsError("RoomOpMismatch", "create_room requires a create op")
    if op.epoch != 0:
        raise RoomsError("StaleEpoch", "a create op must be built against epoch 0")
    if op.subject == "":
        raise RoomsError("RoomOpMismatch", "empty subject")
    try:
        identity.require_nfc(op.subject)
    except identity.NonNFC:
        raise RoomsError("NonNFC", "subject/principal string is not Unicode NFC")
    if actor != op.subject:              # the creator seeds itself as the first owner
        raise RoomsError("Unauthorized", "the create actor must be the seeded owner (the subject)")
    r = Room(op.room, auth)
    r._members[op.subject] = ROLE_OWNER
    r._owners[op.subject] = True
    rec, sig = auth.append(op.content_id(), at)
    r._receipts.append(rec)
    r._sigs.append(sig)
    r._epoch = 1
    return r, rec, rec.seq


# ---- Delivery Model B: the principal registry (semantic id -> durable Handle, R-1.4) ---

class Binding:
    """One principal-registry record: a semantic principal id bound to a durable Handle at a
    monotonic per-principal epoch, chained to the prior binding's head. Signed as an Identity-channel
    (0x0003) tier-1 object; here it is the wire body (byte-graded) and the registry below is the
    policy (behaviour-graded)."""

    __slots__ = ("principal", "handle", "epoch", "prev")

    def __init__(self, principal, handle, epoch, prev):
        self.principal = principal      # the stable semantic principal id (MUST be NFC)
        self.handle = handle            # the current durable Handle (a signer id)
        self.epoch = int(epoch)         # monotonic per-principal binding epoch (0 for the first bind)
        self.prev = bytes(prev)         # prior binding chain head (48 bytes; genesis = zero)

    def _to_map(self):
        return M([
            (U(1), T(self.principal)),
            (U(2), T(self.handle)),
            (U(3), U(self.epoch)),
            (U(4), B(self.prev)),
        ])

    def bytes(self):
        """Deterministic-CBOR encoding {1:principal,2:handle,3:epoch,4:prev}."""
        return cbor.encode(self._to_map())

    def head(self):
        """The per-principal chain head after this binding: SHA-384(binding body). Because the body
        carries the prior head, editing any binding breaks the next binding's linkage."""
        import hashlib
        return hashlib.sha384(self.bytes()).digest()


def genesis_head():
    """The empty per-principal chain head (48 zero bytes)."""
    return bytes(audit.HEAD_SIZE)


class PrincipalRegistry:
    """The durable semantic-naming layer of Delivery Model B: it maps each semantic principal id to
    its current durable Handle, keeping a per-principal signed binding chain. A delivery addresses a
    semantic id and resolve returns the Handle at send time."""

    __slots__ = ("_chain", "_head", "_current", "_epoch")

    def __init__(self):
        self._chain = {}
        self._head = {}
        self._current = {}
        self._epoch = {}

    def bind(self, principal, handle):
        """Create the FIRST binding for a principal (epoch 0, prev = genesis). A principal already
        bound is PrincipalExists (use rebind); an empty or non-NFC principal/handle is rejected."""
        if principal == "" or handle == "":
            raise RoomsError("RoomOpMismatch", "empty principal or handle")
        try:
            identity.require_nfc(principal)
            identity.require_nfc(handle)
        except identity.NonNFC:
            raise RoomsError("NonNFC", "subject/principal string is not Unicode NFC")
        if principal in self._current:
            raise RoomsError("PrincipalExists", "principal already bound; use rebind")
        b = Binding(principal, handle, 0, genesis_head())
        self._chain[principal] = [b]
        self._head[principal] = b.head()
        self._current[principal] = handle
        self._epoch[principal] = 0
        return b

    def rebind(self, principal, new_handle, rot, old_alg, old_pub, new_alg, new_pub, old_sig, new_sig):
        """Update a principal to a new durable Handle, REQUIRING a verified rotation from the current
        handle to the new handle (R-1.4): the semantic id survives key rotation, but a rebind to a key
        not proven continuous with the current handle is refused (RebindUnauthorized). The binding
        epoch bumps and the chain links to the prior head."""
        if principal not in self._current:
            raise RoomsError("PrincipalUnknown", "no binding for the semantic principal id")
        cur = self._current[principal]
        if new_handle == "":
            raise RoomsError("RoomOpMismatch", "empty new handle")
        try:
            identity.require_nfc(new_handle)
        except identity.NonNFC:
            raise RoomsError("NonNFC", "subject/principal string is not Unicode NFC")
        # The rotation MUST carry the current handle as old and the new handle as new, and it MUST be
        # a valid co-signed rotation (both keys derive their ids and both signatures verify).
        if rot.old != cur or rot.new != new_handle:
            raise RoomsError("RebindUnauthorized",
                             "a rebind requires a verified rotation from the current handle")
        try:
            identity.verify_rotation(rot, old_alg, old_pub, new_alg, new_pub, old_sig, new_sig)
        except identity.RotationUnauthorized:
            raise RoomsError("RebindUnauthorized",
                             "a rebind requires a verified rotation from the current handle")
        ep = self._epoch[principal] + 1
        b = Binding(principal, new_handle, ep, self._head[principal])
        self._chain[principal].append(b)
        self._head[principal] = b.head()
        self._current[principal] = new_handle
        self._epoch[principal] = ep
        return b

    def resolve(self, principal):
        """Return the current durable Handle for a semantic principal id (Delivery Model B). An
        unknown principal is PrincipalUnknown (fail-closed -- never a silent empty handle)."""
        if principal not in self._current:
            raise RoomsError("PrincipalUnknown", "no binding for the semantic principal id")
        return self._current[principal]

    def chain(self, principal):
        """A principal's ordered binding chain (its persistent state) for offline audit, or None."""
        return self._chain.get(principal)
