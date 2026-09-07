# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP collaboration/rooms membership for the Ruby SDK (feature #64): a Phase-3 ADDITIVE higher tier
# (tier 1) over the frozen draft-00 spine (design.md §2..§10; design-channels.md §21). It introduces NO
# new envelope, encoding, signature, identity, or audit mechanism -- it reuses the spine unchanged
# (R-11.3, R-15A.2) -- and adds only tier-1 object kinds on the Governance channel (0x0004; membership
# ops) and the Identity channel (0x0003; the principal registry). A frozen baseline verifier that has
# not licensed the tier rejects a room kind as UnknownKind, fail-closed.
#
# It builds three recorded maintainer decisions:
#
#   - #4a Membership carriage -- every membership change (create, add_member, remove_member, change_role,
#     add_owner) is a first-class SIGNED object (a normal N-AALP envelope object, §2), CURSOR-OCCUPYING
#     (a real ordered position in the per-room log), RECEIPT-CHAINED (the room log IS the append-only
#     signed audit/receipt chain of §8.1, one Receipt per accepted op over the op's content id), and
#     EPOCH-BUMPING (each accepted op increments the room's membership epoch; an op built against a
#     superseded epoch is rejected StaleEpoch -- serialising concurrent changes).
#   - #4b O2 ownership -- multi-owner, ADD-ONLY: a room may have many owners; add_owner adds one; an
#     owner is NEVER removed (remove_member refuses an owner) nor demoted (change_role refuses to lower
#     an owner). Create seeds exactly one owner, add_owner only grows the set, so the owner count is
#     monotonically >= 1 -- a room can never become ownerless.
#   - #3  Delivery Model B -- PrincipalRegistry maps a stable semantic principal id to a durable Handle
#     (the current signer id), resolved at send time. The binding survives key rotation (a rebind is
#     authorised only by a verified rotation from the current handle, R-1.4), so the semantic id is a
#     durable layer above the connection-scoped handle; a hijack is refused RebindUnauthorized.
#
# Every check is fail-closed (§15): an op that fails any check is rejected whole, returns its named
# error, and causes no state change. Ported from impl/go/rooms (cross-read against
# impl/python/naalp/rooms.py); graded against vectors/rooms/cases.json. The rebind composes on the C4
# identity rotation primitive (Naalp::Identity.verify_rotation), added additively to identity.rb where
# the Go reference places it.
require_relative 'cbor'
require_relative 'cose'
require_relative 'channels'
require_relative 'envelope'
require_relative 'identity'
require_relative 'policy'
require_relative 'audit'

module Naalp
  module Rooms
    U = Naalp::CBOR::U
    T = Naalp::CBOR::T
    B = Naalp::CBOR::B
    M = Naalp::CBOR::M

    # Channel bindings (R-1.2) and the tier for this higher-tier surface.
    CHANNEL_GOVERNANCE = 0x0004    # membership ops (who is authorised in the room)
    CHANNEL_IDENTITY = 0x0003      # the principal registry (durable naming, R-1.4)
    TIER = 1                       # a named higher tier over the frozen baseline (tier 0)

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
    KIND_PRINCIPAL_BIND = 16       # on the Identity channel

    # A named, fail-closed rooms error; #kind is the stable error kind (§15). Kinds reused from other
    # layers (SignerMismatch, NonNFC) carry those exact strings so a verifier's verdict is identical to
    # the Go/Python reference.
    class RoomsError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # ---- the membership op (the first-class signed object's body) -------------------------

    # One membership operation body carried in envelope field 10. Its content id (multihash(0x20,
    # SHA-384(body))) is what the room log orders (the cursor position), so the op is content-addressed
    # and its ordering is tamper-evident.
    class RoomOp
      attr_reader :room, :op, :epoch, :subject, :role

      def initialize(room, op, epoch, subject, role)
        @room = room.dup.force_encoding(Encoding::BINARY)  # room id (bstr)
        @op = op.to_i                                      # 0 create | 1 add_member | 2 remove_member | 3 change_role | 4 add_owner
        @epoch = epoch.to_i                                # the membership epoch this op is built against (bumps on accept)
        @subject = subject.to_s                            # the affected member's signer id (the creator, for create); MUST be NFC
        @role = role.to_i                                  # 0 member | 1 admin | 2 owner
      end

      def to_map
        M.new([
          [U.new(1), B.new(@room)],
          [U.new(2), U.new(@op)],
          [U.new(3), U.new(@epoch)],
          [U.new(4), T.new(@subject)],
          [U.new(5), U.new(@role)],
        ])
      end

      # Deterministic-CBOR encoding {1:room,2:op,3:epoch,4:subject,5:role}.
      def bytes
        Naalp::CBOR.encode(to_map)
      end

      # The op's content id in the T1 framing (design §2.3): multihash(0x20, SHA-384(body)).
      def content_id
        Naalp::CBOR.content_id(bytes)
      end

      # Build the (unsigned) N-AALP envelope object that carries this op: tier 1, Governance channel, the
      # op's kind and declared effect, the op body as field 10. The caller signs it with envelope.sign to
      # produce the first-class signed membership object. A non-NFC subject or an unknown op is rejected
      # fail-closed.
      def envelope_object(signer, created, profile, causes)
        kind, eff, ok = Naalp::Rooms.kind_for_op(@op)
        raise RoomsError.new("OpUnknown", "unknown room op code") unless ok
        begin
          Naalp::Identity.require_nfc(@subject)
        rescue Naalp::Identity::NonNFC
          raise RoomsError.new("NonNFC", "subject/principal string is not Unicode NFC")
        end
        Naalp::Envelope::Object.new(
          kind: kind, channel: CHANNEL_GOVERNANCE, tier: TIER,
          signer: signer, created: created, effect: eff,
          causes: causes, profile: profile, body: to_map)
      end
    end

    # ---- the room state machine (per-room membership + the receipt-chained log) ------------

    # A collaboration room's live membership state and its signed, append-only log. The log is an audit
    # receipt chain (§8.1): each accepted op is ordered at a cursor (the receipt seq) over the op's
    # content id, weaving membership into the tamper-evident chain.
    class Room
      def initialize(room_id, auth)
        @id = room_id.dup.force_encoding(Encoding::BINARY)
        @epoch = 0
        @members = {}
        @owners = {}
        @auth = auth
        @receipts = []
        @sigs = []
      end

      # The room id (a copy).
      def id
        @id.dup
      end

      # The room's current membership epoch (the epoch the next op must carry).
      def epoch
        @epoch
      end

      # Returns [role, is_member].
      def role_of(subject)
        return [@members[subject], true] if @members.key?(subject)
        [0, false]
      end

      def is_owner?(subject)
        @owners.fetch(subject, false) == true
      end

      # The number of owners; the add-only invariant keeps this >= 1 after create_room.
      def owner_count
        @owners.length
      end

      # The owner ids in sorted order.
      def owners
        @owners.keys.sort
      end

      # The members and their roles (a copy).
      def members
        @members.dup
      end

      # The room log's receipts and their signatures (its persistent state); verifies offline with
      # audit.verify_chain against the ordering authority's key.
      def log
        [@receipts, @sigs]
      end

      # Seed the first owner+member and order the create op at cursor 0 (called only by create_room).
      # Not part of the public op path -- the state machine's only public mutator is #apply.
      def seed_create(op, at)
        @members[op.subject] = ROLE_OWNER
        @owners[op.subject] = true
        rec, sig = @auth.append(op.content_id, at)
        @receipts << rec
        @sigs << sig
        @epoch = 1
        [rec, rec.seq]
      end

      # Validate and apply one membership op (add_member, remove_member, change_role, add_owner) by an
      # owner `actor`, order it into the room log, and bump the epoch. Check order is fail-closed
      # throughout: room match -> epoch -> subject well-formed -> authorization -> per-op semantics ->
      # order -> mutate -> bump. Any failure raises a named error and leaves the room unchanged. Returns
      # [receipt, cursor].
      def apply(op, actor, at)
        if op.room.b != @id || op.op == OP_CREATE
          raise RoomsError.new("RoomOpMismatch", "op room id, kind, or op code does not match this room")
        end
        if op.epoch != @epoch
          raise RoomsError.new("StaleEpoch", "op epoch does not match the room's current membership epoch")
        end
        if op.subject == ""
          raise RoomsError.new("RoomOpMismatch", "empty subject")
        end
        begin
          Naalp::Identity.require_nfc(op.subject)
        rescue Naalp::Identity::NonNFC
          raise RoomsError.new("NonNFC", "subject/principal string is not Unicode NFC")
        end
        unless @owners.fetch(actor, false) # only an owner may change membership (R-6.5)
          raise RoomsError.new("Unauthorized", "actor is not an owner of the room")
        end

        # Per-op semantic validation -- NO mutation yet (so a rejection is a true no-op).
        case op.op
        when OP_ADD_MEMBER
          if op.role != ROLE_MEMBER && op.role != ROLE_ADMIN
            raise RoomsError.new("RoleInvalid", "owners are added via add_owner only")
          end
          raise RoomsError.new("MemberExists", "subject is already a member") if @members.key?(op.subject)
        when OP_ADD_OWNER
          raise RoomsError.new("RoleInvalid", "add_owner must carry the owner role") if op.role != ROLE_OWNER
          raise RoomsError.new("OwnerExists", "subject is already an owner") if @owners.fetch(op.subject, false)
        when OP_REMOVE_MEMBER
          raise RoomsError.new("MemberUnknown", "subject is not a member of the room") unless @members.key?(op.subject)
          raise RoomsError.new("OwnerImmutable", "an owner cannot be removed (ownership is add-only)") if @owners.fetch(op.subject, false)
        when OP_CHANGE_ROLE
          raise RoomsError.new("MemberUnknown", "subject is not a member of the room") unless @members.key?(op.subject)
          if op.role != ROLE_MEMBER && op.role != ROLE_ADMIN
            raise RoomsError.new("RoleInvalid", "promote to owner via add_owner only")
          end
          raise RoomsError.new("OwnerImmutable", "an owner cannot be demoted") if @members[op.subject] == ROLE_OWNER
        else
          raise RoomsError.new("OpUnknown", "unknown room op code")
        end

        # Order the op into the log first; if ordering fails there is no state change.
        rec, sig = @auth.append(op.content_id, at)
        case op.op
        when OP_ADD_MEMBER
          @members[op.subject] = op.role
        when OP_ADD_OWNER
          @members[op.subject] = ROLE_OWNER
          @owners[op.subject] = true
        when OP_REMOVE_MEMBER
          @members.delete(op.subject)
        when OP_CHANGE_ROLE
          @members[op.subject] = op.role
        end
        @receipts << rec
        @sigs << sig
        @epoch += 1
        [rec, rec.seq]
      end

      # The behavioural end-to-end path: verify a signed membership object with real crypto
      # (envelope.verify against the composed rooms validator), bind the claimed signer id to the
      # verifying key (a self-asserted id that does not derive from the authenticated key confers no
      # authority, R-1.3/R-5.1), confirm the object is a tier-1 Governance room op whose kind and effect
      # match its op code, then apply it with the authenticated signer id as the actor.
      def apply_signed(profile, alg, pubkey, signed_obj, at)
        validator = ->(ch, k) { Naalp::Rooms.composed_kind_validator(ch, k) }
        o = Naalp::Envelope.verify(profile, alg, pubkey, validator, signed_obj)
        if o.channel != CHANNEL_GOVERNANCE || o.tier != TIER
          raise RoomsError.new("RoomOpMismatch", "object is not a tier-1 Governance room op")
        end
        actor = Naalp::Identity.signer_id(alg, pubkey)
        unless o.signer.b == actor.b   # the object's signer field must be the authenticated id
          raise Naalp::Identity::SignerMismatch, "signer id does not derive from the verifying key"
        end
        op = Naalp::Rooms.room_op_from_body(o.body)
        want_kind, want_eff, ok = Naalp::Rooms.kind_for_op(op.op)
        if !ok || o.kind != want_kind || o.effect != want_eff
          raise RoomsError.new("RoomOpMismatch", "op kind/effect does not match its op code")
        end
        apply(op, actor, at)
      end
    end

    # ---- Delivery Model B: the principal registry (semantic id -> durable Handle, R-1.4) ---

    # One principal-registry record: a semantic principal id bound to a durable Handle at a monotonic
    # per-principal epoch, chained to the prior binding's head. Signed as an Identity-channel (0x0003)
    # tier-1 object; here it is the wire body (byte-graded) and the registry below is the policy
    # (behaviour-graded).
    class Binding
      attr_reader :principal, :handle, :epoch, :prev

      def initialize(principal, handle, epoch, prev)
        @principal = principal.to_s                        # the stable semantic principal id (MUST be NFC)
        @handle = handle.to_s                              # the current durable Handle (a signer id)
        @epoch = epoch.to_i                                # monotonic per-principal binding epoch (0 for the first bind)
        @prev = prev.dup.force_encoding(Encoding::BINARY)  # prior binding chain head (48 bytes; genesis = zero)
      end

      def to_map
        M.new([
          [U.new(1), T.new(@principal)],
          [U.new(2), T.new(@handle)],
          [U.new(3), U.new(@epoch)],
          [U.new(4), B.new(@prev)],
        ])
      end

      # Deterministic-CBOR encoding {1:principal,2:handle,3:epoch,4:prev}.
      def bytes
        Naalp::CBOR.encode(to_map)
      end

      # The per-principal chain head after this binding: SHA-384(binding body). Because the body carries
      # the prior head, editing any binding breaks the next binding's linkage.
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end
    end

    # The durable semantic-naming layer of Delivery Model B: it maps each semantic principal id to its
    # current durable Handle, keeping a per-principal signed binding chain. A delivery addresses a
    # semantic id and resolve returns the Handle at send time.
    class PrincipalRegistry
      def initialize
        @chain = {}
        @head = {}
        @current = {}
        @epoch = {}
      end

      # Create the FIRST binding for a principal (epoch 0, prev = genesis). A principal already bound is
      # PrincipalExists (use rebind); an empty or non-NFC principal/handle is rejected.
      def bind(principal, handle)
        if principal == "" || handle == ""
          raise RoomsError.new("RoomOpMismatch", "empty principal or handle")
        end
        begin
          Naalp::Identity.require_nfc(principal)
          Naalp::Identity.require_nfc(handle)
        rescue Naalp::Identity::NonNFC
          raise RoomsError.new("NonNFC", "subject/principal string is not Unicode NFC")
        end
        raise RoomsError.new("PrincipalExists", "principal already bound; use rebind") if @current.key?(principal)
        b = Binding.new(principal, handle, 0, Naalp::Rooms.genesis_head)
        @chain[principal] = [b]
        @head[principal] = b.head
        @current[principal] = handle
        @epoch[principal] = 0
        b
      end

      # Update a principal to a new durable Handle, REQUIRING a verified rotation from the current handle
      # to the new handle (R-1.4): the semantic id survives key rotation, but a rebind to a key not
      # proven continuous with the current handle is refused (RebindUnauthorized). The binding epoch
      # bumps and the chain links to the prior head.
      def rebind(principal, new_handle, rot, old_alg, old_pub, new_alg, new_pub, old_sig, new_sig)
        raise RoomsError.new("PrincipalUnknown", "no binding for the semantic principal id") unless @current.key?(principal)
        cur = @current[principal]
        raise RoomsError.new("RoomOpMismatch", "empty new handle") if new_handle == ""
        begin
          Naalp::Identity.require_nfc(new_handle)
        rescue Naalp::Identity::NonNFC
          raise RoomsError.new("NonNFC", "subject/principal string is not Unicode NFC")
        end
        # The rotation MUST carry the current handle as old and the new handle as new, and it MUST be a
        # valid co-signed rotation (both keys derive their ids and both signatures verify).
        if rot.old != cur || rot.new != new_handle
          raise RoomsError.new("RebindUnauthorized", "a rebind requires a verified rotation from the current handle")
        end
        begin
          Naalp::Identity.verify_rotation(rot, old_alg, old_pub, new_alg, new_pub, old_sig, new_sig)
        rescue Naalp::Identity::RotationUnauthorized
          raise RoomsError.new("RebindUnauthorized", "a rebind requires a verified rotation from the current handle")
        end
        ep = @epoch[principal] + 1
        b = Binding.new(principal, new_handle, ep, @head[principal])
        @chain[principal] << b
        @head[principal] = b.head
        @current[principal] = new_handle
        @epoch[principal] = ep
        b
      end

      # Return the current durable Handle for a semantic principal id (Delivery Model B). An unknown
      # principal is PrincipalUnknown (fail-closed -- never a silent empty handle).
      def resolve(principal)
        raise RoomsError.new("PrincipalUnknown", "no binding for the semantic principal id") unless @current.key?(principal)
        @current[principal]
      end

      # A principal's ordered binding chain (its persistent state) for offline audit, or nil.
      def chain(principal)
        @chain[principal]
      end
    end

    module_function

    # Map an op code to its tier-1 Governance kind and its declared effect (design-channels.md §21).
    # remove_member is destructive; the rest are non_idempotent_write. Returns [kind, effect, ok].
    def kind_for_op(op)
      case op
      when OP_CREATE then [KIND_ROOM_CREATE, Naalp::Policy::NON_IDEMPOTENT_WRITE, true]
      when OP_ADD_MEMBER then [KIND_ROOM_ADD_MEMBER, Naalp::Policy::NON_IDEMPOTENT_WRITE, true]
      when OP_REMOVE_MEMBER then [KIND_ROOM_REMOVE_MEMBER, Naalp::Policy::DESTRUCTIVE, true]
      when OP_CHANGE_ROLE then [KIND_ROOM_CHANGE_ROLE, Naalp::Policy::NON_IDEMPOTENT_WRITE, true]
      when OP_ADD_OWNER then [KIND_ROOM_ADD_OWNER, Naalp::Policy::NON_IDEMPOTENT_WRITE, true]
      else [0, 0, false]
      end
    end

    # Parse an envelope object body (field 10) back into a RoomOp. A body that is not exactly the
    # {1,2,3,4,5} map with the right value types is RoomOpMismatch (fail-closed).
    def room_op_from_body(v)
      raise RoomsError.new("RoomOpMismatch", "op body is not a map") unless v.is_a?(M)
      room = op = epoch = subject = role = nil
      seen = {}
      v.pairs.each do |k, val|
        unless k.is_a?(U) && k.v >= 1 && k.v <= 5
          raise RoomsError.new("RoomOpMismatch", "op body has an out-of-range field")
        end
        case k.v
        when 1
          raise RoomsError.new("RoomOpMismatch", "room is not a bstr") unless val.is_a?(B)
          room = val.v
        when 2
          raise RoomsError.new("RoomOpMismatch", "op is not a uint") unless val.is_a?(U)
          op = val.v
        when 3
          raise RoomsError.new("RoomOpMismatch", "epoch is not a uint") unless val.is_a?(U)
          epoch = val.v
        when 4
          raise RoomsError.new("RoomOpMismatch", "subject is not a tstr") unless val.is_a?(T)
          subject = val.v
        when 5
          raise RoomsError.new("RoomOpMismatch", "role is not a uint") unless val.is_a?(U)
          role = val.v
        end
        seen[k.v] = true
      end
      unless [1, 2, 3, 4, 5].all? { |n| seen[n] }
        raise RoomsError.new("RoomOpMismatch", "op body is missing a mandatory field")
      end
      RoomOp.new(room, op, epoch, subject, role)
    end

    # Accept exactly this surface's tier-1 kinds: the five Governance membership kinds and the Identity
    # principal-bind kind. Nothing else.
    def kind_validator?(channel, kind)
      case channel
      when CHANNEL_GOVERNANCE
        kind >= KIND_ROOM_CREATE && kind <= KIND_ROOM_ADD_OWNER
      when CHANNEL_IDENTITY
        kind == KIND_PRINCIPAL_BIND
      else
        false
      end
    end

    def baseline_kind_validator?(channel, kind)
      Naalp::Channels.lookup(channel, kind)
      true
    rescue Naalp::Channels::UnknownKind
      false
    end

    # Accept the frozen baseline kinds OR this surface's tier-1 kinds -- the validator a rooms-aware
    # endpoint passes to envelope.verify. A baseline-only endpoint using the baseline validator alone
    # correctly rejects a room kind as UnknownKind (fail-closed).
    def composed_kind_validator(channel, kind)
      baseline_kind_validator?(channel, kind) || kind_validator?(channel, kind)
    end

    # Build a room from a verified create op signed by the creator. The creator (the op subject) becomes
    # the first and, at creation, only owner+member. The create op occupies cursor 0 in the log; the room
    # advances to epoch 1. `auth` is the room's ordering authority. A non-create op, a non-zero epoch, an
    # empty/non-NFC subject, or an actor that is not the subject is rejected fail-closed. Returns
    # [room, receipt, cursor].
    def create_room(op, actor, auth, at)
      raise RoomsError.new("RoomOpMismatch", "create_room requires a create op") if op.op != OP_CREATE
      raise RoomsError.new("StaleEpoch", "a create op must be built against epoch 0") if op.epoch != 0
      raise RoomsError.new("RoomOpMismatch", "empty subject") if op.subject == ""
      begin
        Naalp::Identity.require_nfc(op.subject)
      rescue Naalp::Identity::NonNFC
        raise RoomsError.new("NonNFC", "subject/principal string is not Unicode NFC")
      end
      if actor != op.subject # the creator seeds itself as the first owner
        raise RoomsError.new("Unauthorized", "the create actor must be the seeded owner (the subject)")
      end
      r = Room.new(op.room, auth)
      rec, cursor = r.seed_create(op, at)
      [r, rec, cursor]
    end

    # The empty per-principal chain head (48 zero bytes).
    def genesis_head
      ("\x00" * Naalp::Audit::HEAD_SIZE).b
    end
  end
end
