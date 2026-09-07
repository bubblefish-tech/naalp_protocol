# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# Collaboration/rooms membership conformance for the Ruby SDK (feature #64; design.md §2..§10,
# design-channels.md §21), graded against the shared independent corpus vectors/rooms/cases.json (NOT
# produced by this code): the membership op body/content-id byte parity, the receipt-chained room log
# (bodies + heads via the C7 audit authority) with the epoch progression and final membership/ownership
# state, the principal-binding wire bodies + per-principal chain heads, and the fail-closed behavioural
# surface (StaleEpoch, Unauthorized, OwnerImmutable, add-only ownership, RebindUnauthorized) exercised
# with REAL ML-DSA-65 signed objects and a REAL co-signed key rotation.
#
# Two graded surfaces: the RoomOp / Binding wire bodies (byte-graded == oracle) and the room state
# machine + Delivery-Model-B principal registry (behaviour-graded). Every check is fail-closed (§15):
# an op that fails any check is rejected whole, returns its named error, and causes no state change.
# Ported from impl/go/rooms (cross-read against impl/python/naalp/rooms.py).
#
# The membership object path is a REAL signed N-AALP envelope (tier-1 Governance, real ML-DSA-65 verify
# + signer-id binding), and the rebind path is a REAL co-signed identity rotation (no stand-ins).
# test_stale_epoch_rejected is the mutation target: disabling the epoch-match check lets a stale-view op
# replay, so the StaleEpoch assertion flips.
#
# Written test-first; the Rooms module is absent until ported, so this fails RED (uninitialized constant
# Naalp::Rooms) until impl/ruby/lib/naalp/rooms.rb lands and naalp.rb requires it.
#
# Run:  ruby -Ilib -Itest test/test_rooms.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'openssl'
require 'naalp'

def rooms_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "rooms", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/rooms/cases.json not found"
end

RALG = Naalp::COSE::ALG_MLDSA65
RPROFILE = Naalp::COSE::PROFILE_PUBLIC

RKey = Struct.new(:seed, :pk, :id)

# A real ML-DSA-65 keypair from an all-<seed_byte> 32-byte seed; returns RKey(seed, pk, signer_id).
def rooms_key(seed_byte)
  seed = ([seed_byte] * 32).pack("C*").b
  pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
  RKey.new(seed, pk, Naalp::Identity.signer_id(RALG, pk))
end

class RoomsConformance < Minitest::Test
  C = rooms_vectors

  def hb(s)
    [s].pack("H*")
  end

  def ml_dsa_or_skip
    rooms_key(0x5A)
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  # ---- membership op body / content-id byte parity (design §2.3) ------------------------

  def test_op_bodies_match_oracle
    rj = C["rooms"]
    room = hb(rj["room_id_hex"])
    assert rj["ops"].any?
    rj["ops"].each do |oj|
      op = Naalp::Rooms::RoomOp.new(room, oj["op"], oj["epoch_at_build"], oj["subject"], oj["role"])
      assert_equal oj["body_hex"], op.bytes.unpack1("H*"), oj["op_name"]
      assert_equal oj["op_content_id_hex"], op.content_id.unpack1("H*"), oj["op_name"]
    end
  end

  # ---- the full run: receipt-chained log + state machine (byte + value) ------------------

  def test_room_run_matches_oracle
    ml_dsa_or_skip
    rj = C["rooms"]
    room = hb(rj["room_id_hex"])
    ak = rooms_key(90)                  # the room's ordering authority
    auth = Naalp::Audit::Authority.new(RALG, ak.seed)
    ops, log = rj["ops"], rj["room_log"]

    create = ops[0]
    cop = Naalp::Rooms::RoomOp.new(room, create["op"], create["epoch_at_build"], create["subject"], create["role"])
    rm, rec0, cursor0 = Naalp::Rooms.create_room(cop, create["subject"], auth, log[0]["at"])
    assert_equal 0, cursor0
    assert_equal 1, rm.epoch
    check_receipt(rec0, log[0])

    (1...ops.length).each do |i|
      oj = ops[i]
      op = Naalp::Rooms::RoomOp.new(room, oj["op"], oj["epoch_at_build"], oj["subject"], oj["role"])
      assert_equal rm.epoch, oj["epoch_at_build"], "built epoch tracks room epoch"
      rec, cursor = rm.apply(op, create["subject"], log[i]["at"])
      assert_equal oj["seq"], cursor, "cursor == oracle seq"
      assert_equal oj["epoch_after"], rm.epoch, "epoch bumped"
      check_receipt(rec, log[i])
    end

    assert_equal rj["final_epoch"], rm.epoch
    assert_equal rj["final_owners"], rm.owners
    rj["final_members"].each do |m|
      role, ok = rm.role_of(m["subject"])
      assert ok, m["subject"]
      assert_equal m["role"], role, m["subject"]
    end
    receipts, sigs = rm.log
    assert_nil Naalp::Audit.verify_chain(receipts, sigs, RALG, ak.pk)
    assert_equal rj["final_log_head_hex"], receipts[-1].head.unpack1("H*")
  end

  def check_receipt(rec, want)
    assert_equal want["body_hex"], rec.bytes.unpack1("H*"), "receipt body seq=#{want['seq']}"
    assert_equal want["head_after_hex"], rec.head.unpack1("H*"), "receipt head seq=#{want['seq']}"
    assert_equal want["obj_hex"], rec.obj.unpack1("H*"), "receipt obj seq=#{want['seq']}"
  end

  # ---- signed membership end-to-end (REAL ML-DSA-65 through the spine) --------------------

  def test_signed_membership_end_to_end
    ml_dsa_or_skip
    room = [0x20, 0x30, 1, 2, 3, 4].pack("C*").b
    owner = rooms_key(50)
    bob = rooms_key(51)
    ak = rooms_key(91)
    auth = Naalp::Audit::Authority.new(RALG, ak.seed)

    create = Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_CREATE, 0, owner.id, Naalp::Rooms::ROLE_OWNER)
    rm, = Naalp::Rooms.create_room(create, owner.id, auth, 1000)

    add = Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_ADD_MEMBER, rm.epoch, bob.id, Naalp::Rooms::ROLE_MEMBER)
    obj = add.envelope_object(owner.id.b, 1001, RPROFILE, [])
    signed = Naalp::Envelope.sign(obj, RALG, owner.seed)
    rec, cursor = rm.apply_signed(RPROFILE, RALG, owner.pk, signed, 1001)
    assert_equal 1, cursor
    role, ok = rm.role_of(bob.id)
    assert ok
    assert_equal Naalp::Rooms::ROLE_MEMBER, role

    # A baseline-only verifier (no tier licensed) rejects the tier-1 room kind as UnknownKind.
    baseline = lambda do |ch, k|
      Naalp::Channels.lookup(ch, k)
      true
    rescue Naalp::Channels::UnknownKind
      false
    end
    err = assert_raises(Naalp::Envelope::EnvelopeError) { Naalp::Envelope.verify(RPROFILE, RALG, owner.pk, baseline, signed) }
    assert_equal "UnknownKind", err.kind
  end

  # ---- EPOCH-BUMPING: StaleEpoch (THIS is the mutation-target assertion) ------------------

  def test_stale_epoch_rejected
    ml_dsa_or_skip
    room = [9, 9, 9].pack("C*").b
    owner = rooms_key(52)
    bob = rooms_key(53)
    carol = rooms_key(54)
    ak = rooms_key(92)
    auth = Naalp::Audit::Authority.new(RALG, ak.seed)
    rm, = Naalp::Rooms.create_room(
      Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_CREATE, 0, owner.id, Naalp::Rooms::ROLE_OWNER), owner.id, auth, 1)
    e = rm.epoch                                    # both ops build against this epoch
    rm.apply(Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_ADD_MEMBER, e, bob.id, Naalp::Rooms::ROLE_MEMBER), owner.id, 2)
    err = assert_raises(Naalp::Rooms::RoomsError) do
      rm.apply(Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_ADD_MEMBER, e, carol.id, Naalp::Rooms::ROLE_MEMBER), owner.id, 3)
    end
    assert_equal "StaleEpoch", err.kind
    refute rm.role_of(carol.id)[1], "no state change on a rejected stale-epoch op"
    # The same op rebuilt against the CURRENT epoch is accepted.
    rm.apply(Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_ADD_MEMBER, rm.epoch, carol.id, Naalp::Rooms::ROLE_MEMBER), owner.id, 4)
    assert rm.role_of(carol.id)[1]
  end

  # ---- only an owner may change membership (fail-closed) ---------------------------------

  def test_unauthorized_actor_rejected
    ml_dsa_or_skip
    room = [7, 7].pack("C*").b
    owner = rooms_key(55)
    bob = rooms_key(56)
    mallory = rooms_key(57)
    ak = rooms_key(93)
    auth = Naalp::Audit::Authority.new(RALG, ak.seed)
    rm, = Naalp::Rooms.create_room(
      Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_CREATE, 0, owner.id, Naalp::Rooms::ROLE_OWNER), owner.id, auth, 1)
    rm.apply(Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_ADD_MEMBER, rm.epoch, bob.id, Naalp::Rooms::ROLE_MEMBER), owner.id, 2)
    # mallory (not even a member) tries to add themselves as owner.
    err = assert_raises(Naalp::Rooms::RoomsError) do
      rm.apply(Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_ADD_OWNER, rm.epoch, mallory.id, Naalp::Rooms::ROLE_OWNER), mallory.id, 3)
    end
    assert_equal "Unauthorized", err.kind
    # bob (a member, not an owner) also cannot add a member.
    assert_raises(Naalp::Rooms::RoomsError) do
      rm.apply(Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_ADD_MEMBER, rm.epoch, mallory.id, Naalp::Rooms::ROLE_MEMBER), bob.id, 4)
    end
    assert_equal 1, rm.owner_count, "owner count unchanged on rejected ops"
  end

  # ---- O2: add-only ownership, never ownerless -------------------------------------------

  def test_add_only_ownership_no_ownerless
    ml_dsa_or_skip
    room = [5].pack("C*").b
    alice = rooms_key(58)
    bob = rooms_key(59)
    ak = rooms_key(94)
    auth = Naalp::Audit::Authority.new(RALG, ak.seed)
    rm, = Naalp::Rooms.create_room(
      Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_CREATE, 0, alice.id, Naalp::Rooms::ROLE_OWNER), alice.id, auth, 1)
    assert_equal 1, rm.owner_count
    rm.apply(Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_ADD_OWNER, rm.epoch, bob.id, Naalp::Rooms::ROLE_OWNER), alice.id, 2)
    assert_equal 2, rm.owner_count
    assert rm.is_owner?(bob.id)
    # remove_member(alice) -- an owner -- is refused OwnerImmutable.
    err = assert_raises(Naalp::Rooms::RoomsError) do
      rm.apply(Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_REMOVE_MEMBER, rm.epoch, alice.id, Naalp::Rooms::ROLE_MEMBER), bob.id, 3)
    end
    assert_equal "OwnerImmutable", err.kind
    # change_role(alice -> member) -- demoting an owner -- is refused OwnerImmutable.
    err = assert_raises(Naalp::Rooms::RoomsError) do
      rm.apply(Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_CHANGE_ROLE, rm.epoch, alice.id, Naalp::Rooms::ROLE_MEMBER), bob.id, 4)
    end
    assert_equal "OwnerImmutable", err.kind
    # re-add of an existing owner is refused OwnerExists.
    err = assert_raises(Naalp::Rooms::RoomsError) do
      rm.apply(Naalp::Rooms::RoomOp.new(room, Naalp::Rooms::OP_ADD_OWNER, rm.epoch, bob.id, Naalp::Rooms::ROLE_OWNER), alice.id, 5)
    end
    assert_equal "OwnerExists", err.kind
    assert_operator rm.owner_count, :>=, 1
  end

  # ---- Delivery Model B: principal-binding wire bytes (byte parity) ----------------------

  def test_binding_bytes_match_oracle
    C["registry"]["bindings"].each do |bj|
      b = Naalp::Rooms::Binding.new(bj["principal"], bj["handle"], bj["epoch"], hb(bj["prev_hex"]))
      assert_equal bj["body_hex"], b.bytes.unpack1("H*"), "#{bj['principal']}@#{bj['epoch']} body"
      assert_equal bj["head_after_hex"], b.head.unpack1("H*"), "#{bj['principal']}@#{bj['epoch']} head"
    end
  end

  # ---- Delivery Model B: rebind-on-rotation (REAL co-signed rotation) ---------------------

  def test_principal_registry_rebind_on_rotation
    ml_dsa_or_skip
    v1 = rooms_key(60)   # alice v1
    v2 = rooms_key(61)   # alice v2 (rotated-to)
    evil = rooms_key(62)

    pr = Naalp::Rooms::PrincipalRegistry.new
    pr.bind("agent:alice", v1.id)
    assert_equal v1.id, pr.resolve("agent:alice")

    # A valid co-signed rotation v1 -> v2 authorises the rebind; the semantic id survives.
    rot = Naalp::Identity::RotationRecord.new(v1.id, v2.id, 100)
    old_sig, new_sig = Naalp::Identity.sign_rotation(rot, RALG, v1.seed, v2.seed)
    pr.rebind("agent:alice", v2.id, rot, RALG, v1.pk, RALG, v2.pk, old_sig, new_sig)
    assert_equal v2.id, pr.resolve("agent:alice")

    # A hijack: a rotation to an unrelated key not proven continuous with the current handle is refused
    # (old leg signed by the WRONG key), and the registry is unchanged.
    bad = Naalp::Identity::RotationRecord.new(v2.id, evil.id, 200)
    bo, bn = Naalp::Identity.sign_rotation(bad, RALG, v1.seed, v2.seed) # old leg signed by v1, not v2
    err = assert_raises(Naalp::Rooms::RoomsError) do
      pr.rebind("agent:alice", evil.id, bad, RALG, v1.pk, RALG, v2.pk, bo, bn)
    end
    assert_equal "RebindUnauthorized", err.kind
    assert_equal v2.id, pr.resolve("agent:alice")

    # An unknown principal resolves fail-closed.
    err = assert_raises(Naalp::Rooms::RoomsError) { pr.resolve("agent:nobody") }
    assert_equal "PrincipalUnknown", err.kind
  end

  # ---- double-bind refused; first binding is genesis (prev == zero) ----------------------

  def test_bind_duplicate_and_genesis
    a = rooms_key(63)
    pr = Naalp::Rooms::PrincipalRegistry.new
    b = pr.bind("agent:alice", a.id)
    assert_equal 0, b.epoch
    assert_equal Naalp::Rooms.genesis_head, b.prev
    err = assert_raises(Naalp::Rooms::RoomsError) { pr.bind("agent:alice", a.id) }
    assert_equal "PrincipalExists", err.kind
  end
end
