// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Collaboration/rooms membership conformance for the TypeScript SDK (feature #64), graded against
// the shared independent corpus vectors/rooms/cases.json (NOT produced by this code): the membership
// op body/content-id byte parity, the receipt-chained room log (bodies + heads via the C7 audit
// authority) with the epoch progression and final membership/ownership state, the principal-binding
// wire bodies + per-principal chain heads, and the fail-closed behavioural surface (StaleEpoch,
// Unauthorized, OwnerImmutable, add-only ownership, RebindUnauthorized) exercised with REAL
// deterministic ML-DSA-65 signed objects and a REAL co-signed key rotation.
//
// Two graded surfaces: the RoomOp / Binding wire bodies (byte-graded == oracle) and the room state
// machine + Delivery-Model-B principal registry (behaviour-graded). Every check is fail-closed (§15):
// an op that fails any check is rejected whole, throws its named error, and causes no state change.
// Ported from impl/go/rooms (with impl/python/naalp/rooms.py as a second reference).
//
// Written test-first; the rooms module is absent until ported, so this fails RED on import
// (ERR_MODULE_NOT_FOUND) until impl/typescript/naalp/rooms.mjs lands. The mutation "disable the
// epoch-bump check (accept any epoch)" flips 'rooms stale-epoch op is rejected' on its assertion.
//
// Run:  node --test test/rooms.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cose from '../naalp/cose.mjs';
import * as audit from '../naalp/audit.mjs';
import * as channels from '../naalp/channels.mjs';
import * as envelope from '../naalp/envelope.mjs';
import * as identity from '../naalp/identity.mjs';
import * as rooms from '../naalp/rooms.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'rooms', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/rooms/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);
const ALG = cose.ALG_MLDSA65;
const PROFILE = cose.PROFILE_PUBLIC;

// A deterministic ML-DSA-65 key: a 32-byte all-<seedByte> seed, its public key, and its signer id.
function mkKey(seedByte) {
  const seed = new Uint8Array(32).fill(seedByte);
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const id = identity.signerId(ALG, pk);
  return { seed, pk, id };
}

// ---- membership op body / content-id byte parity (design §2.3) --------------------------

test('rooms op bodies + content ids match the oracle byte-for-byte', () => {
  // Mutation target: if RoomOp.bytes() ignored a field, the hex (and the multihash content id over
  // it) diverges from the pinned oracle.
  const rj = C.rooms;
  const room = hexToBytes(rj.room_id_hex);
  assert.ok(rj.ops.length > 0);
  for (const oj of rj.ops) {
    const op = new rooms.RoomOp(room, oj.op, oj.epoch_at_build, oj.subject, oj.role);
    assert.equal(bytesToHex(op.bytes()), oj.body_hex, `op ${oj.seq} (${oj.op_name}) body`);
    assert.equal(bytesToHex(op.contentId()), oj.op_content_id_hex, `op ${oj.seq} (${oj.op_name}) content id`);
  }
});

// ---- the full run: receipt-chained log + state machine (byte + value) --------------------

test('rooms room run reproduces the oracle receipt-chained log + state', () => {
  const rj = C.rooms;
  const room = hexToBytes(rj.room_id_hex);
  const authSeed = new Uint8Array(32).fill(90); // the room's ordering authority
  const authPk = cose.mldsaKeygen('ML-DSA-65', authSeed);
  const auth = new audit.Authority(ALG, authSeed);
  const ops = rj.ops;
  const log = rj.room_log;

  const create = ops[0];
  const cop = new rooms.RoomOp(room, create.op, create.epoch_at_build, create.subject, create.role);
  const [rm, rec0, cursor0] = rooms.createRoom(cop, create.subject, auth, log[0].at);
  assert.equal(Number(cursor0), 0, 'create occupies cursor 0');
  assert.equal(Number(rm.epoch()), 1, 'room advances to epoch 1 after create');
  checkReceipt(rec0, log[0]);

  for (let i = 1; i < ops.length; i++) {
    const oj = ops[i];
    const op = new rooms.RoomOp(room, oj.op, oj.epoch_at_build, oj.subject, oj.role);
    assert.equal(oj.epoch_at_build, Number(rm.epoch()), 'built epoch tracks room epoch');
    const [rec, cursor] = rm.apply(op, create.subject, log[i].at);
    assert.equal(Number(cursor), oj.seq, `op ${i} cursor == oracle seq`);
    assert.equal(Number(rm.epoch()), oj.epoch_after, `op ${i} epoch bumped`);
    checkReceipt(rec, log[i]);
  }

  assert.equal(Number(rm.epoch()), rj.final_epoch, 'final epoch');
  assert.deepEqual(rm.owners(), rj.final_owners, 'final owners (sorted)');
  for (const m of rj.final_members) {
    const [role, ok] = rm.roleOf(m.subject);
    assert.ok(ok, `${m.subject} is a member`);
    assert.equal(Number(role), m.role, `${m.subject} role`);
  }
  // The whole log verifies offline against the authority key, and the final head matches the oracle.
  const [receipts, sigs] = rm.log();
  assert.equal(audit.verifyChain(receipts, sigs, ALG, authPk), null, 'room log chain verifies offline');
  assert.equal(bytesToHex(receipts[receipts.length - 1].head()), rj.final_log_head_hex, 'final log head');
});

function checkReceipt(rec, want) {
  assert.equal(bytesToHex(rec.bytes()), want.body_hex, `receipt body seq=${want.seq}`);
  assert.equal(bytesToHex(rec.head()), want.head_after_hex, `receipt head seq=${want.seq}`);
  assert.equal(bytesToHex(rec.obj), want.obj_hex, `receipt obj seq=${want.seq}`);
}

// ---- signed membership end-to-end (REAL ML-DSA-65 through the spine) ---------------------

test('rooms signed membership verifies end-to-end (real crypto) and baseline rejects the tier', () => {
  const room = Uint8Array.from([0x20, 0x30, 1, 2, 3, 4]);
  const owner = mkKey(50);
  const bob = mkKey(51);
  const authSeed = new Uint8Array(32).fill(91);
  const auth = new audit.Authority(ALG, authSeed);

  const createOp = new rooms.RoomOp(room, rooms.OP_CREATE, 0, owner.id, rooms.ROLE_OWNER);
  const [rm] = rooms.createRoom(createOp, owner.id, auth, 1000);

  const addOp = new rooms.RoomOp(room, rooms.OP_ADD_MEMBER, rm.epoch(), bob.id, rooms.ROLE_MEMBER);
  const obj = addOp.envelopeObject(enc(owner.id), 1001, PROFILE, []);
  const signed = envelope.sign(obj, ALG, owner.seed);
  const [, cursor] = rm.applySigned(PROFILE, ALG, owner.pk, signed, 1001);
  assert.equal(Number(cursor), 1, 'the signed add is ordered at cursor 1');
  const [role, ok] = rm.roleOf(bob.id);
  assert.ok(ok && Number(role) === rooms.ROLE_MEMBER, 'bob added as a member via the signed path');

  // A baseline-only verifier (no tier licensed) rejects the tier-1 room kind as UnknownKind.
  const baseline = (ch, k) => { try { channels.lookup(ch, k); return true; } catch { return false; } };
  assert.throws(() => envelope.verify(PROFILE, ALG, owner.pk, baseline, signed), (e) => e.kind === 'UnknownKind');
});

// ---- EPOCH-BUMPING: StaleEpoch (THIS is the mutation-target assertion) -------------------

test('rooms stale-epoch op is rejected (epoch-bump serialization)', () => {
  // MUTATION: disabling the epoch check in Room.apply lets a stale-view op replay, flipping this
  // test's StaleEpoch assertion. Two ops built against the same epoch cannot both apply.
  const room = Uint8Array.from([9, 9, 9]);
  const owner = mkKey(52);
  const bob = mkKey(53);
  const carol = mkKey(54);
  const auth = new audit.Authority(ALG, new Uint8Array(32).fill(92));
  const [rm] = rooms.createRoom(new rooms.RoomOp(room, rooms.OP_CREATE, 0, owner.id, rooms.ROLE_OWNER), owner.id, auth, 1);

  const e = rm.epoch(); // both ops build against this epoch
  rm.apply(new rooms.RoomOp(room, rooms.OP_ADD_MEMBER, e, bob.id, rooms.ROLE_MEMBER), owner.id, 2);
  assert.throws(
    () => rm.apply(new rooms.RoomOp(room, rooms.OP_ADD_MEMBER, e, carol.id, rooms.ROLE_MEMBER), owner.id, 3),
    (er) => er.kind === 'StaleEpoch');
  assert.equal(rm.roleOf(carol.id)[1], false, 'no state change on a rejected stale-epoch op');
  // The same op rebuilt against the CURRENT epoch is accepted.
  rm.apply(new rooms.RoomOp(room, rooms.OP_ADD_MEMBER, rm.epoch(), carol.id, rooms.ROLE_MEMBER), owner.id, 4);
  assert.equal(rm.roleOf(carol.id)[1], true, 'the current-epoch op is accepted');
});

// ---- only an owner may change membership (fail-closed) -----------------------------------

test('rooms unauthorized actor is refused (only an owner may change membership)', () => {
  const room = Uint8Array.from([7, 7]);
  const owner = mkKey(55);
  const bob = mkKey(56);
  const mallory = mkKey(57);
  const auth = new audit.Authority(ALG, new Uint8Array(32).fill(93));
  const [rm] = rooms.createRoom(new rooms.RoomOp(room, rooms.OP_CREATE, 0, owner.id, rooms.ROLE_OWNER), owner.id, auth, 1);
  rm.apply(new rooms.RoomOp(room, rooms.OP_ADD_MEMBER, rm.epoch(), bob.id, rooms.ROLE_MEMBER), owner.id, 2);
  // mallory (not even a member) tries to add themselves as owner.
  assert.throws(
    () => rm.apply(new rooms.RoomOp(room, rooms.OP_ADD_OWNER, rm.epoch(), mallory.id, rooms.ROLE_OWNER), mallory.id, 3),
    (e) => e.kind === 'Unauthorized');
  // bob (a member, not an owner) also cannot add a member.
  assert.throws(
    () => rm.apply(new rooms.RoomOp(room, rooms.OP_ADD_MEMBER, rm.epoch(), mallory.id, rooms.ROLE_MEMBER), bob.id, 4),
    (e) => e.kind === 'Unauthorized');
  assert.equal(rm.ownerCount(), 1, 'owner count unchanged on rejected ops');
});

// ---- O2: add-only ownership, never ownerless --------------------------------------------

test('rooms ownership is add-only and never ownerless (O2)', () => {
  const room = Uint8Array.from([5]);
  const alice = mkKey(58);
  const bob = mkKey(59);
  const auth = new audit.Authority(ALG, new Uint8Array(32).fill(94));
  const [rm] = rooms.createRoom(new rooms.RoomOp(room, rooms.OP_CREATE, 0, alice.id, rooms.ROLE_OWNER), alice.id, auth, 1);
  assert.equal(rm.ownerCount(), 1, 'fresh room has exactly one owner');
  rm.apply(new rooms.RoomOp(room, rooms.OP_ADD_OWNER, rm.epoch(), bob.id, rooms.ROLE_OWNER), alice.id, 2);
  assert.equal(rm.ownerCount(), 2, 'add_owner grows the owner set');
  assert.equal(rm.isOwner(bob.id), true);
  // remove_member(alice) — an owner — is refused OwnerImmutable.
  assert.throws(
    () => rm.apply(new rooms.RoomOp(room, rooms.OP_REMOVE_MEMBER, rm.epoch(), alice.id, rooms.ROLE_MEMBER), bob.id, 3),
    (e) => e.kind === 'OwnerImmutable');
  // change_role(alice -> member) — demoting an owner — is refused OwnerImmutable.
  assert.throws(
    () => rm.apply(new rooms.RoomOp(room, rooms.OP_CHANGE_ROLE, rm.epoch(), alice.id, rooms.ROLE_MEMBER), bob.id, 4),
    (e) => e.kind === 'OwnerImmutable');
  // re-add of an existing owner is refused OwnerExists.
  assert.throws(
    () => rm.apply(new rooms.RoomOp(room, rooms.OP_ADD_OWNER, rm.epoch(), bob.id, rooms.ROLE_OWNER), alice.id, 5),
    (e) => e.kind === 'OwnerExists');
  assert.ok(rm.ownerCount() >= 1, 'owner count never falls below 1');
});

// ---- Delivery Model B: principal-binding wire bytes (byte parity) ------------------------

test('rooms principal-binding bodies + chain heads match the oracle byte-for-byte', () => {
  for (const bj of C.registry.bindings) {
    const b = new rooms.Binding(bj.principal, bj.handle, bj.epoch, hexToBytes(bj.prev_hex));
    assert.equal(bytesToHex(b.bytes()), bj.body_hex, `${bj.principal}@${bj.epoch} body`);
    assert.equal(bytesToHex(b.head()), bj.head_after_hex, `${bj.principal}@${bj.epoch} head`);
  }
});

// ---- Delivery Model B: rebind-on-rotation (REAL co-signed rotation, the C4 primitive) ----

test('rooms principal registry rebind survives a real key rotation; a hijack is refused', () => {
  // MUTATION: if Rebind skipped the rotation verification, the hijack would succeed, flipping the
  // RebindUnauthorized assertion. The semantic id is a durable layer above the connection handle.
  const v1 = mkKey(60); // alice v1
  const v2 = mkKey(61); // alice v2 (rotated-to)
  const evil = mkKey(62);

  const pr = new rooms.PrincipalRegistry();
  pr.bind('agent:alice', v1.id);
  assert.equal(pr.resolve('agent:alice'), v1.id, 'resolves to v1 before rotation');

  // A valid co-signed rotation v1 -> v2 authorises the rebind; the semantic id survives.
  const rot = new identity.RotationRecord(v1.id, v2.id, 100);
  const [oldSig, newSig] = identity.signRotation(rot, ALG, v1.seed, v2.seed);
  pr.rebind('agent:alice', v2.id, rot, ALG, v1.pk, ALG, v2.pk, oldSig, newSig);
  assert.equal(pr.resolve('agent:alice'), v2.id, 'durable Handle follows the rotation');

  // A hijack: a rotation to an unrelated key not proven continuous with the current handle is refused
  // (the old leg here is signed by v1, but the record names v2 as the old id), and the registry is
  // unchanged.
  const bad = new identity.RotationRecord(v2.id, evil.id, 200);
  const [bo, bn] = identity.signRotation(bad, ALG, v1.seed, v2.seed);
  assert.throws(
    () => pr.rebind('agent:alice', evil.id, bad, ALG, v1.pk, ALG, v2.pk, bo, bn),
    (e) => e.kind === 'RebindUnauthorized');
  assert.equal(pr.resolve('agent:alice'), v2.id, 'the refused hijack left the binding unchanged');

  // An unknown principal resolves fail-closed.
  assert.throws(() => pr.resolve('agent:nobody'), (e) => e.kind === 'PrincipalUnknown');
});

// ---- double-bind refused; first binding is genesis (prev == zero) ------------------------

test('rooms double-bind is refused and the first binding is genesis', () => {
  const a = mkKey(63);
  const pr = new rooms.PrincipalRegistry();
  const b = pr.bind('agent:alice', a.id);
  assert.equal(Number(b.epoch), 0, 'first binding epoch is 0');
  assert.equal(bytesToHex(b.prev), bytesToHex(rooms.genesisHead()), 'first binding prev is genesis (48 zero bytes)');
  assert.throws(() => pr.bind('agent:alice', a.id), (e) => e.kind === 'PrincipalExists');
});
