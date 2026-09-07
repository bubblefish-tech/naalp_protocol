// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Collaboration / rooms membership for the TypeScript SDK (feature #64): a Phase-3 ADDITIVE higher
// tier (tier 1) over the frozen draft-00 spine (design.md §2..§10; design-channels.md §21). It
// introduces NO new envelope, encoding, signature, identity, or audit mechanism -- it reuses the spine
// unchanged (R-11.3, R-15A.2) -- and adds only tier-1 object kinds on the Governance channel (0x0004;
// membership ops) and the Identity channel (0x0003; the principal registry). A frozen baseline verifier
// that has not licensed the tier rejects a room kind as UnknownKind, fail-closed; that is honest, not a
// defect.
//
// It builds three recorded maintainer decisions:
//
//   - #4a Membership carriage -- every membership change (create, add_member, remove_member,
//     change_role, add_owner) is a first-class SIGNED object (a normal N-AALP envelope object, §2),
//     CURSOR-OCCUPYING (a real ordered position in the per-room log), RECEIPT-CHAINED (the room log IS
//     the append-only signed audit/receipt chain of §8.1, one Receipt per accepted op over the op's
//     content id), and EPOCH-BUMPING (each accepted op increments the room's membership epoch; an op
//     built against a superseded epoch is rejected StaleEpoch -- serialising concurrent changes).
//   - #4b O2 ownership -- multi-owner, ADD-ONLY: a room may have many owners; add_owner adds one; an
//     owner is NEVER removed (remove_member refuses an owner) nor demoted (change_role refuses to lower
//     an owner). Create seeds exactly one owner, add_owner only grows the set, so the owner count is
//     monotonically >= 1 -- a room can never become ownerless.
//   - #3  Delivery Model B -- PrincipalRegistry maps a stable semantic principal id to a durable Handle
//     (the current signer id), resolved at send time. The binding survives key rotation (a rebind is
//     authorised only by a verified co-signed rotation from the current handle, R-1.4), so the semantic
//     id is a durable layer above the connection handle; a hijack is refused RebindUnauthorized.
//
// Every check is fail-closed (§15): an op that fails any check is rejected whole, throws its named
// error, and causes no state change. Ported from impl/go/rooms (with impl/python/naalp/rooms.py as a
// second reference); graded against vectors/rooms/cases.json (values from the corpus, never this code).
// The rooms.Rebind rotation-authorised rebind composes on the C4 identity rotation primitive, added
// additively to naalp/identity.mjs (identity.RotationRecord / verifyRotation), mirroring the Python
// port -- see the flagged deviation in that module.

import { U, B, T, M } from './cbor.mjs';
import * as cbor from './cbor.mjs';
import { sha384 } from '@noble/hashes/sha2.js';
import * as policy from './policy.mjs';
import * as channels from './channels.mjs';
import * as envelope from './envelope.mjs';
import * as identity from './identity.mjs';

// Channel bindings (R-1.2) and the tier for this higher-tier surface.
export const CHANNEL_GOVERNANCE = 0x0004; // membership ops (who is authorised in the room)
export const CHANNEL_IDENTITY = 0x0003;   // the principal registry (durable naming, R-1.4)
export const TIER = 1;                     // a named higher tier over the frozen baseline (tier 0)

// Room membership operation codes (naalp-room-op field 2).
export const OP_CREATE = 0;
export const OP_ADD_MEMBER = 1;
export const OP_REMOVE_MEMBER = 2;
export const OP_CHANGE_ROLE = 3;
export const OP_ADD_OWNER = 4;

// Role codes (naalp-room-op field 5). A role is the collaboration role that gates membership ops --
// NOT an effect and NOT a capability ceiling.
export const ROLE_MEMBER = 0;
export const ROLE_ADMIN = 1;
export const ROLE_OWNER = 2;

// Tier-1 kind codes. Governance (0x0004) carries the five membership ops; Identity (0x0003) carries the
// principal binding. They start at 16 to sit clear of the frozen baseline kinds.
export const KIND_ROOM_CREATE = 16;
export const KIND_ROOM_ADD_MEMBER = 17;
export const KIND_ROOM_REMOVE_MEMBER = 18;
export const KIND_ROOM_CHANGE_ROLE = 19;
export const KIND_ROOM_ADD_OWNER = 20;
export const KIND_PRINCIPAL_BIND = 16; // on the Identity channel

// The width of a per-principal chain head (SHA-384 = 48 bytes); genesis is zero.
const HEAD_SIZE = 48;

// A named, fail-closed rooms error; .kind is the stable error kind (§15). Kinds reused from other
// layers (SignerMismatch, NonNFC) carry those exact strings so a verifier's verdict is identical to the
// Go/Python reference.
export class RoomsError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ---- the membership op (the first-class signed object's body) -------------------------

// One membership operation body carried in envelope field 10. Its content id (multihash(0x20,
// SHA-384(body))) is what the room log orders (the cursor position), so the op is content-addressed and
// its ordering is tamper-evident.
export class RoomOp {
  constructor(room, op, epoch, subject, role) {
    this.room = Uint8Array.from(room);  // room id (bstr)
    this.op = Number(op);               // 0 create | 1 add_member | 2 remove_member | 3 change_role | 4 add_owner
    this.epoch = Number(epoch);         // the membership epoch this op is built against (bumps on accept)
    this.subject = String(subject);     // the affected member's signer id (the creator, for create); MUST be NFC
    this.role = Number(role);           // 0 member | 1 admin | 2 owner
  }

  toMap() {
    return new M([
      [new U(1), new B(this.room)],
      [new U(2), new U(this.op)],
      [new U(3), new U(this.epoch)],
      [new U(4), new T(this.subject)],
      [new U(5), new U(this.role)],
    ]);
  }

  // Deterministic-CBOR encoding {1:room,2:op,3:epoch,4:subject,5:role}.
  bytes() {
    return cbor.encode(this.toMap());
  }

  // The op's content id in the T1 framing (design §2.3): multihash(0x20, SHA-384(body)).
  contentId() {
    return cbor.contentId(this.bytes());
  }

  // Build the (unsigned) N-AALP envelope object that carries this op: tier 1, Governance channel, the
  // op's kind and declared effect, the op body as field 10. The caller signs it with envelope.sign to
  // produce the first-class signed membership object. A non-NFC subject or an unknown op is rejected.
  envelopeObject(signer, created, profile, causes) {
    const [kind, eff, ok] = kindForOp(this.op);
    if (!ok) throw new RoomsError('OpUnknown', 'unknown room op code');
    try {
      identity.requireNFC(this.subject);
    } catch (e) {
      throw new RoomsError('NonNFC', 'subject/principal string is not Unicode NFC');
    }
    return new envelope.Object({
      kind, channel: CHANNEL_GOVERNANCE, tier: TIER,
      signer, created, effect: eff, causes, profile, body: this.toMap(),
    });
  }
}

// Parse an envelope object body (field 10) back into a RoomOp. A body that is not exactly the
// {1,2,3,4,5} map with the right value types is RoomOpMismatch (fail-closed).
export function roomOpFromBody(v) {
  if (!(v instanceof M)) throw new RoomsError('RoomOpMismatch', 'op body is not a map');
  let room = null;
  let op = null;
  let epoch = null;
  let subject = null;
  let role = null;
  const seen = new Set();
  for (const [k, val] of v.pairs) {
    if (!(k instanceof U) || k.v < 1n || k.v > 5n) {
      throw new RoomsError('RoomOpMismatch', 'op body has an out-of-range field');
    }
    const kv = Number(k.v);
    if (kv === 1) {
      if (!(val instanceof B)) throw new RoomsError('RoomOpMismatch', 'room is not a bstr');
      room = val.v;
    } else if (kv === 2) {
      if (!(val instanceof U)) throw new RoomsError('RoomOpMismatch', 'op is not a uint');
      op = val.v;
    } else if (kv === 3) {
      if (!(val instanceof U)) throw new RoomsError('RoomOpMismatch', 'epoch is not a uint');
      epoch = val.v;
    } else if (kv === 4) {
      if (!(val instanceof T)) throw new RoomsError('RoomOpMismatch', 'subject is not a tstr');
      subject = val.v;
    } else if (kv === 5) {
      if (!(val instanceof U)) throw new RoomsError('RoomOpMismatch', 'role is not a uint');
      role = val.v;
    }
    seen.add(kv);
  }
  if (!(seen.has(1) && seen.has(2) && seen.has(3) && seen.has(4) && seen.has(5))) {
    throw new RoomsError('RoomOpMismatch', 'op body is missing a mandatory field');
  }
  return new RoomOp(room, op, epoch, subject, role);
}

// Map an op code to its tier-1 Governance kind and its declared effect (design-channels.md §21).
// remove_member is destructive; the rest are non_idempotent_write. Returns [kind, effect, ok].
export function kindForOp(op) {
  switch (Number(op)) {
    case OP_CREATE: return [KIND_ROOM_CREATE, policy.NON_IDEMPOTENT_WRITE, true];
    case OP_ADD_MEMBER: return [KIND_ROOM_ADD_MEMBER, policy.NON_IDEMPOTENT_WRITE, true];
    case OP_REMOVE_MEMBER: return [KIND_ROOM_REMOVE_MEMBER, policy.DESTRUCTIVE, true];
    case OP_CHANGE_ROLE: return [KIND_ROOM_CHANGE_ROLE, policy.NON_IDEMPOTENT_WRITE, true];
    case OP_ADD_OWNER: return [KIND_ROOM_ADD_OWNER, policy.NON_IDEMPOTENT_WRITE, true];
    default: return [0, 0, false];
  }
}

// ---- kind validation (composes with the frozen baseline) ------------------------------

// Accept exactly this surface's tier-1 kinds: the five Governance membership kinds and the Identity
// principal-bind kind. Nothing else.
export function kindValidator(channel, kind) {
  const ch = Number(channel);
  const k = Number(kind);
  if (ch === CHANNEL_GOVERNANCE) return k >= KIND_ROOM_CREATE && k <= KIND_ROOM_ADD_OWNER;
  if (ch === CHANNEL_IDENTITY) return k === KIND_PRINCIPAL_BIND;
  return false;
}

function baselineKindValidator(channel, kind) {
  try {
    channels.lookup(channel, kind);
    return true;
  } catch (e) {
    return false;
  }
}

// Accept the frozen baseline kinds OR this surface's tier-1 kinds -- the validator a rooms-aware
// endpoint passes to envelope.verify. A baseline-only endpoint using the baseline validator alone
// correctly rejects a room kind as UnknownKind (fail-closed).
export function composedKindValidator(channel, kind) {
  return baselineKindValidator(channel, kind) || kindValidator(channel, kind);
}

// ---- the room state machine (per-room membership + the receipt-chained log) ------------

// A collaboration room's live membership state and its signed, append-only log. The log is an audit
// receipt chain (§8.1): each accepted op is ordered at a cursor (the receipt seq) over the op's content
// id, weaving membership into the tamper-evident chain.
export class Room {
  constructor(roomId, auth) {
    this._id = Uint8Array.from(roomId);
    this._epoch = 0;
    this._members = new Map(); // subject -> role
    this._owners = new Map();  // subject -> true
    this._auth = auth;
    this._receipts = [];
    this._sigs = [];
  }

  id() { return Uint8Array.from(this._id); }

  // The room's current membership epoch (the epoch the next op must carry).
  epoch() { return this._epoch; }

  // Returns [role, isMember].
  roleOf(subject) {
    if (this._members.has(subject)) return [this._members.get(subject), true];
    return [0, false];
  }

  isOwner(subject) { return this._owners.get(subject) === true; }

  // The number of owners; the add-only invariant keeps this >= 1 after createRoom.
  ownerCount() { return this._owners.size; }

  // The owner ids in sorted order.
  owners() { return [...this._owners.keys()].sort(); }

  // The members and their roles (a copy).
  members() { return new Map(this._members); }

  // The room log's receipts and their signatures (its persistent state); verifies offline with
  // audit.verifyChain against the ordering authority's key.
  log() { return [this._receipts, this._sigs]; }

  // Validate and apply one membership op (add_member, remove_member, change_role, add_owner) by an owner
  // `actor`, order it into the room log, and bump the epoch. Check order is fail-closed throughout: room
  // match -> epoch -> subject well-formed -> authorization -> per-op semantics -> order -> mutate ->
  // bump. Any failure throws a named error and leaves the room unchanged. Returns [receipt, cursor].
  apply(op, actor, at) {
    if (!bytesEqual(op.room, this._id) || op.op === OP_CREATE) {
      throw new RoomsError('RoomOpMismatch', 'op room id, kind, or op code does not match this room');
    }
    if (op.epoch !== this._epoch) {
      throw new RoomsError('StaleEpoch', 'op epoch does not match the room\'s current membership epoch');
    }
    if (op.subject === '') {
      throw new RoomsError('RoomOpMismatch', 'empty subject');
    }
    try {
      identity.requireNFC(op.subject);
    } catch (e) {
      throw new RoomsError('NonNFC', 'subject/principal string is not Unicode NFC');
    }
    if (this._owners.get(actor) !== true) { // only an owner may change membership (R-6.5)
      throw new RoomsError('Unauthorized', 'actor is not an owner of the room');
    }

    // Per-op semantic validation -- NO mutation yet (so a rejection is a true no-op).
    switch (op.op) {
      case OP_ADD_MEMBER:
        if (op.role !== ROLE_MEMBER && op.role !== ROLE_ADMIN) {
          throw new RoomsError('RoleInvalid', 'owners are added via add_owner only');
        }
        if (this._members.has(op.subject)) throw new RoomsError('MemberExists', 'subject is already a member');
        break;
      case OP_ADD_OWNER:
        if (op.role !== ROLE_OWNER) throw new RoomsError('RoleInvalid', 'add_owner must carry the owner role');
        if (this._owners.get(op.subject) === true) throw new RoomsError('OwnerExists', 'subject is already an owner');
        break;
      case OP_REMOVE_MEMBER:
        if (!this._members.has(op.subject)) throw new RoomsError('MemberUnknown', 'subject is not a member of the room');
        if (this._owners.get(op.subject) === true) throw new RoomsError('OwnerImmutable', 'an owner cannot be removed (ownership is add-only)');
        break;
      case OP_CHANGE_ROLE:
        if (!this._members.has(op.subject)) throw new RoomsError('MemberUnknown', 'subject is not a member of the room');
        if (op.role !== ROLE_MEMBER && op.role !== ROLE_ADMIN) throw new RoomsError('RoleInvalid', 'promote to owner via add_owner only');
        if (this._members.get(op.subject) === ROLE_OWNER) throw new RoomsError('OwnerImmutable', 'an owner cannot be demoted');
        break;
      default:
        throw new RoomsError('OpUnknown', 'unknown room op code');
    }

    // Order the op into the log first; if ordering fails there is no state change.
    const [rec, sig] = this._auth.append(op.contentId(), at);
    switch (op.op) {
      case OP_ADD_MEMBER: this._members.set(op.subject, op.role); break;
      case OP_ADD_OWNER: this._members.set(op.subject, ROLE_OWNER); this._owners.set(op.subject, true); break;
      case OP_REMOVE_MEMBER: this._members.delete(op.subject); break;
      case OP_CHANGE_ROLE: this._members.set(op.subject, op.role); break;
    }
    this._receipts.push(rec);
    this._sigs.push(sig);
    this._epoch += 1;
    return [rec, rec.seq];
  }

  // The behavioural end-to-end path: verify a signed membership object with real crypto (envelope.verify
  // against the composed rooms validator), bind the claimed signer id to the verifying key (a
  // self-asserted id that does not derive from the authenticated key confers no authority, R-1.3/R-5.1),
  // confirm the object is a tier-1 Governance room op whose kind and effect match its op code, then apply
  // it with the authenticated signer id as the actor. Returns [receipt, cursor].
  applySigned(profile, alg, pubkey, signedObj, at) {
    const o = envelope.verify(profile, alg, pubkey, composedKindValidator, signedObj);
    if (Number(o.channel) !== CHANNEL_GOVERNANCE || Number(o.tier) !== TIER) {
      throw new RoomsError('RoomOpMismatch', 'object is not a tier-1 Governance room op');
    }
    const actor = identity.signerId(alg, pubkey);
    if (new TextDecoder().decode(o.signer) !== actor) { // the object's signer field must be the authenticated id
      throw new identity.SignerMismatch('signer id does not derive from the verifying key');
    }
    const op = roomOpFromBody(o.body);
    const [wantKind, wantEff, ok] = kindForOp(op.op);
    if (!ok || Number(o.kind) !== wantKind || Number(o.effect) !== wantEff) {
      throw new RoomsError('RoomOpMismatch', 'op kind/effect does not match its op code');
    }
    return this.apply(op, actor, at);
  }
}

// Build a room from a verified create op signed by the creator. The creator (the op subject) becomes the
// first and, at creation, only owner+member. The create op occupies cursor 0 in the log; the room
// advances to epoch 1. `auth` is the room's ordering authority. A non-create op, a non-zero epoch, an
// empty/non-NFC subject, or an actor that is not the subject is rejected fail-closed. Returns
// [room, receipt, cursor].
export function createRoom(op, actor, auth, at) {
  if (op.op !== OP_CREATE) throw new RoomsError('RoomOpMismatch', 'createRoom requires a create op');
  if (op.epoch !== 0) throw new RoomsError('StaleEpoch', 'a create op must be built against epoch 0');
  if (op.subject === '') throw new RoomsError('RoomOpMismatch', 'empty subject');
  try {
    identity.requireNFC(op.subject);
  } catch (e) {
    throw new RoomsError('NonNFC', 'subject/principal string is not Unicode NFC');
  }
  if (actor !== op.subject) throw new RoomsError('Unauthorized', 'the create actor must be the seeded owner (the subject)');
  const r = new Room(op.room, auth);
  r._members.set(op.subject, ROLE_OWNER);
  r._owners.set(op.subject, true);
  const [rec, sig] = auth.append(op.contentId(), at);
  r._receipts.push(rec);
  r._sigs.push(sig);
  r._epoch = 1;
  return [r, rec, rec.seq];
}

// ---- Delivery Model B: the principal registry (semantic id -> durable Handle, R-1.4) ---

// One principal-registry record: a semantic principal id bound to a durable Handle at a monotonic
// per-principal epoch, chained to the prior binding's head. Signed as an Identity-channel (0x0003)
// tier-1 object; here it is the wire body (byte-graded) and the registry below is the policy
// (behaviour-graded).
export class Binding {
  constructor(principal, handle, epoch, prev) {
    this.principal = String(principal); // the stable semantic principal id (MUST be NFC)
    this.handle = String(handle);       // the current durable Handle (a signer id)
    this.epoch = Number(epoch);         // monotonic per-principal binding epoch (0 for the first bind)
    this.prev = Uint8Array.from(prev);  // prior binding chain head (48 bytes; genesis = zero)
  }

  toMap() {
    return new M([
      [new U(1), new T(this.principal)],
      [new U(2), new T(this.handle)],
      [new U(3), new U(this.epoch)],
      [new U(4), new B(this.prev)],
    ]);
  }

  // Deterministic-CBOR encoding {1:principal,2:handle,3:epoch,4:prev}.
  bytes() {
    return cbor.encode(this.toMap());
  }

  // The per-principal chain head after this binding: SHA-384(binding body). Because the body carries the
  // prior head, editing any binding breaks the next binding's linkage.
  head() {
    return sha384(this.bytes());
  }
}

// The empty per-principal chain head (48 zero bytes).
export function genesisHead() {
  return new Uint8Array(HEAD_SIZE);
}

// The durable semantic-naming layer of Delivery Model B: it maps each semantic principal id to its
// current durable Handle, keeping a per-principal signed binding chain. A delivery addresses a semantic
// id and resolve returns the Handle at send time.
export class PrincipalRegistry {
  constructor() {
    this._chain = new Map();   // principal -> [Binding, ...]
    this._head = new Map();    // principal -> chain head (Uint8Array)
    this._current = new Map(); // principal -> current handle
    this._epoch = new Map();   // principal -> current epoch
  }

  // Create the FIRST binding for a principal (epoch 0, prev = genesis). A principal already bound is
  // PrincipalExists (use rebind); an empty or non-NFC principal/handle is rejected.
  bind(principal, handle) {
    if (principal === '' || handle === '') throw new RoomsError('RoomOpMismatch', 'empty principal or handle');
    try {
      identity.requireNFC(principal);
      identity.requireNFC(handle);
    } catch (e) {
      throw new RoomsError('NonNFC', 'subject/principal string is not Unicode NFC');
    }
    if (this._current.has(principal)) throw new RoomsError('PrincipalExists', 'principal already bound; use rebind');
    const b = new Binding(principal, handle, 0, genesisHead());
    this._chain.set(principal, [b]);
    this._head.set(principal, b.head());
    this._current.set(principal, handle);
    this._epoch.set(principal, 0);
    return b;
  }

  // Update a principal to a new durable Handle, REQUIRING a verified rotation from the current handle to
  // the new handle (R-1.4): the semantic id survives key rotation, but a rebind to a key not proven
  // continuous with the current handle is refused (RebindUnauthorized). The binding epoch bumps and the
  // chain links to the prior head.
  rebind(principal, newHandle, rot, oldAlg, oldPub, newAlg, newPub, oldSig, newSig) {
    if (!this._current.has(principal)) throw new RoomsError('PrincipalUnknown', 'no binding for the semantic principal id');
    const cur = this._current.get(principal);
    if (newHandle === '') throw new RoomsError('RoomOpMismatch', 'empty new handle');
    try {
      identity.requireNFC(newHandle);
    } catch (e) {
      throw new RoomsError('NonNFC', 'subject/principal string is not Unicode NFC');
    }
    // The rotation MUST carry the current handle as old and the new handle as new, and it MUST be a valid
    // co-signed rotation (both keys derive their ids and both signatures verify).
    if (rot.old !== cur || rot.new !== newHandle) {
      throw new RoomsError('RebindUnauthorized', 'a rebind requires a verified rotation from the current handle');
    }
    try {
      identity.verifyRotation(rot, oldAlg, oldPub, newAlg, newPub, oldSig, newSig);
    } catch (e) {
      throw new RoomsError('RebindUnauthorized', 'a rebind requires a verified rotation from the current handle');
    }
    const ep = this._epoch.get(principal) + 1;
    const b = new Binding(principal, newHandle, ep, this._head.get(principal));
    this._chain.get(principal).push(b);
    this._head.set(principal, b.head());
    this._current.set(principal, newHandle);
    this._epoch.set(principal, ep);
    return b;
  }

  // Return the current durable Handle for a semantic principal id (Delivery Model B). An unknown
  // principal is PrincipalUnknown (fail-closed -- never a silent empty handle).
  resolve(principal) {
    if (!this._current.has(principal)) throw new RoomsError('PrincipalUnknown', 'no binding for the semantic principal id');
    return this._current.get(principal);
  }

  // A principal's ordered binding chain (its persistent state) for offline audit, or null.
  chain(principal) {
    return this._chain.get(principal) ?? null;
  }
}
