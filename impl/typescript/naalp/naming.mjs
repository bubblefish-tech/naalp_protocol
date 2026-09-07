// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C19 name bindings and the signed A2A task-state profile for the TypeScript SDK (design.md §22;
// R-NAME-1..6, R-A2A-1..7).
//
// C19 is two receipt-CHAINED, signed, OFFLINE-WALKABLE surfaces carried on N-AALP's own signed object.
// Both reuse the C7 audit receipt-chain construction (§8.1) unchanged -- head = SHA-384(body), genesis
// prev = 48 zero bytes, a monotonic seq, the prior head carried in the body so editing or omitting a
// record breaks the next record's linkage -- and they add NO new envelope, encoding, signature,
// identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP body (COSE_Sign1, §4),
// reusing the T1 content-id framing (§2.3) and the C7 chain.
//
// Task 4.1 -- name bindings: NameBinding {1:name,2:signer,3:seq,4:prev} maps a name to a signer id and
// CHAINS onto the prior binding for that name (prev = the prior binding's head; genesis prev is zero). A
// key rotation is a NEW binding at the next seq naming the new signer. A binding is DATED BY its chain
// position (seq); the envelope's `created` field is advisory only. A name's history is WALKABLE offline
// (walkHistory), a deleted/omitted binding leaves a detectable HOLE at the first-broken position
// (detectHole), and two bindings by ONE authority at the SAME (name, seq) naming DIFFERENT signers are a
// FORK reported at that seq (detectFork / NameForkProof).
//
// Task 4.2 -- the signed A2A task-state profile: TaskState is the IMPORTED A2A (Agent2Agent) TaskState
// vocabulary (carriage, not adoption): the eight states submitted, working, input-required,
// auth-required, completed, canceled, failed, rejected (A2A §4.1.3: start = submitted; terminal =
// completed/canceled/failed/rejected; interrupted = input-required/auth-required). A Transition
// {1:task,2:card,3:from,4:to,5:seq,6:prev} is one receipt-CHAINED signed state transition. The
// legal-edge table is DERIVED from those documented A2A category rules; verifyTransition rejects an
// illegal edge, and verifyTaskChain walks a task's transition chain enforcing the start state,
// contiguity, the legal-edge table, prev/seq linkage, the card binding, and the signatures. `card` is
// the content-id of the A2A Agent Card attestation (a C18 naalp-description-import) that binds the
// profile to an agent/operation; a transition carrying a foreign card is rejected.
//
// Every check is fail-closed (§15): a failing object is rejected whole, throws its named error, and
// causes no state change. Ported from impl/go/naming (with impl/python/naalp/naming.py as a second
// reference); graded against vectors/naming/cases.json (expected values from the corpus, never this
// code). Signatures are real deterministic ML-DSA-65 over the body bytes (cose.coseSign1 / rnd=0), and
// the two cross-language pins prove the signed objects are byte-identical to Go/Rust/Python. Any seq
// (name-binding or task-transition) is carried as a BigInt so a value > 2^53 round-trips byte-exact.

import { sha384 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, N, B, T, M } from './cbor.mjs';
import * as cose from './cose.mjs';

// The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. Genesis is
// zero.
export const HEAD_SIZE = 48;

// A named, fail-closed C19 error; .kind is the stable error kind (§15). The signature kinds
// (BadSignature, UnknownAlg, ProfileDowngrade, KeyAlgMismatch) are reused from the C2 cose layer so a
// verifier's verdict is identical to the Go reference.
export class NamingError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// A fresh 48-octet zero prev -- the empty-chain link (the C7 chain genesis).
export function genesis() {
  return new Uint8Array(HEAD_SIZE);
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// SHA-384 over a body -- a 48-octet digest (the same construction as the C7 receipt head).
function headOf(b) {
  return sha384(Uint8Array.from(b));
}

// T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
function contentIdOf(b) {
  return cbor.contentId(Uint8Array.from(b));
}

// ---- the COSE_Sign1 signing/verification helpers (reuse the C2 layer, R-11.3) ------------------

// The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits.
function protectedHeader(alg) {
  return cbor.encode(new M([[new U(1), new N(alg)]]));
}

function algFromProtected(prot) {
  const v = cbor.decode(prot);
  if (v instanceof M) {
    for (const [k, val] of v.pairs) {
      if (k instanceof U && k.v === 1n && (val instanceof N || val instanceof U)) return Number(val.v);
    }
  }
  throw new NamingError('NameMalformed', 'protected header has no alg');
}

// Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the payload.
// Check order (mirroring cose.Verify1): alg registry -> profile floor -> key-alg match -> signature.
// Fail-closed with a named error.
function verifySign1(obj, profile, alg, pubkey) {
  const [prot, payload, sig] = cose.parseSign1Raw(obj);
  const halg = algFromProtected(prot);
  const [level, known] = cose.algLevel(halg);
  if (!known) throw new NamingError('UnknownAlg', 'unregistered alg ' + halg);
  if (level < cose.profileMinLevel(profile)) {
    throw new NamingError('ProfileDowngrade', 'signature level below the profile minimum');
  }
  if (halg !== Number(alg)) {
    throw new NamingError('KeyAlgMismatch', 'alg ' + halg + ' does not match the verifier key alg ' + alg);
  }
  const tbs = cose.toBeSignedRaw(prot, payload);
  if (!cose.coseVerify1Raw(halg, pubkey, tbs, sig)) {
    throw new NamingError('BadSignature', 'signature does not verify');
  }
  return payload;
}

// ==== Task 4.1 -- name bindings ===============================================================

// Maps a name to a signer id at a chain position. It chains onto the prior binding for the same name:
// prev is the prior binding's head (genesis for seq 0). A key rotation is a new binding at the next seq
// naming the new signer. The binding is DATED BY seq; the envelope's `created` is advisory. `seq` is a
// BigInt so a value > 2^53 round-trips byte-exact (no float64 truncation).
export class NameBinding {
  constructor(name, signer, seq, prev) {
    this.name = String(name);           // the name being bound (a durable, human-readable name)
    this.signer = Uint8Array.from(signer); // the signer id this binding maps the name to (opaque bytes)
    this.seq = BigInt(seq);             // monotonic per-name chain position; seq 0 is the genesis binding
    this.prev = Uint8Array.from(prev);  // the prior binding's head (HEAD_SIZE bytes; genesis is zero)
  }

  // Deterministic-CBOR encoding {1:name,2:signer,3:seq,4:prev}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new T(this.name)],
      [new U(2), new B(this.signer)],
      [new U(3), new U(this.seq)],
      [new U(4), new B(this.prev)],
    ]));
  }

  // The chain head after this binding: SHA-384 of the binding body (48 octets).
  head() {
    return headOf(this.bytes());
  }

  // The binding's T1 content-id (50 octets).
  id() {
    return contentIdOf(this.bytes());
  }
}

// Reconstruct a NameBinding from its body bytes alone. A body that is not exactly the {1,2,3,4} map with
// the right value types is NameMalformed (fail-closed).
export function parseNameBinding(b) {
  const m = decodeMap(b);
  if (m === null) throw new NamingError('NameMalformed', 'body is not a well-formed name binding');
  const name = tstrField(m, 1);
  const signer = bstrField(m, 2);
  const seq = uintField(m, 3);
  const prev = bstrField(m, 4);
  if (name === null || signer === null || seq === null || prev === null) {
    throw new NamingError('NameMalformed', 'body is not a well-formed name binding');
  }
  return new NameBinding(name, signer, seq, prev);
}

// Produce the tagged COSE_Sign1 object over the binding body (real deterministic ML-DSA-65).
export function signBinding(nb, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), nb.bytes());
}

// Verify the binding's full signature under the profile, then reconstruct it from the signed body bytes.
// A bad signature is BadSignature; a malformed body is NameMalformed. Fail-closed.
export function verifyBinding(obj, profile, alg, pubkey) {
  const payload = verifySign1(obj, profile, alg, pubkey);
  return parseNameBinding(payload);
}

// A naming authority that appends monotonic signed bindings for ONE name (mirroring the C7 audit
// authority). Each append records a name -> signer mapping at the next chain position; a rotation is
// simply an append naming the new signer. Signs with a real deterministic ML-DSA key from `seed`.
export class Registrar {
  constructor(name, alg, seed) {
    this._name = String(name);
    this._alg = alg;
    this._seed = Uint8Array.from(seed);
    this._head = genesis();
    this._seq = 0n;
  }

  // Record a binding of the registrar's name to `subject` at the next chain position, returning
  // [binding, tagged COSE_Sign1 object]. Seq increases by one per append; the head advances.
  append(subject) {
    const nb = new NameBinding(this._name, subject, this._seq, this._head);
    const obj = signBinding(nb, this._alg, this._seed);
    this._head = nb.head();
    this._seq += 1n;
    return [nb, obj];
  }
}

// One step of a walked name history: the chain position and the signer the name mapped to at that
// position, with the chain head after it.
export class NameEvent {
  constructor(seq, signer, head) {
    this.seq = BigInt(seq);
    this.signer = Uint8Array.from(signer);
    this.head = Uint8Array.from(head);
  }
}

// Verify a name-binding chain's structural continuity OFFLINE (no signatures) and return the ordered
// signer succession. Requires every binding to name the SAME name, seq i to equal its index, and prev to
// link to the previous binding's head (genesis zero for seq 0). A gap, reorder, omitted binding, or a
// name change is NameChainBroken (fail-closed). The CURRENT signer is the last event's signer.
export function walkHistory(bindings) {
  const events = [];
  let h = genesis();
  let name;
  for (let i = 0; i < bindings.length; i++) {
    const nb = bindings[i];
    if (i === 0) name = nb.name;
    else if (nb.name !== name) throw new NamingError('NameChainBroken', 'a chain is for exactly one name');
    if (nb.seq !== BigInt(i) || !bytesEqual(nb.prev, h)) {
      throw new NamingError('NameChainBroken', 'prev/seq does not chain to the previous binding');
    }
    h = nb.head();
    events.push(new NameEvent(nb.seq, nb.signer, h));
  }
  return events;
}

// Check a name-binding chain offline against the authority's key. Each element is the tagged COSE_Sign1
// object for one binding. Verifies every signature under the profile (verifyBinding), then enforces
// structural continuity -- every binding names the SAME name, seq i equals its index, prev links to the
// previous head -- returning the verified, ordered bindings. A bad signature is BadSignature; a broken
// link, a seq gap, or a name change is NameChainBroken. Fail-closed.
export function verifyChain(objs, profile, alg, pubkey) {
  let h = genesis();
  let name;
  const out = [];
  for (let i = 0; i < objs.length; i++) {
    const nb = verifyBinding(objs[i], profile, alg, pubkey);
    if (i === 0) name = nb.name;
    else if (nb.name !== name) throw new NamingError('NameChainBroken', 'a chain is for exactly one name');
    if (nb.seq !== BigInt(i) || !bytesEqual(nb.prev, h)) {
      throw new NamingError('NameChainBroken', 'prev/seq does not chain to the previous binding');
    }
    h = nb.head();
    out.push(nb);
  }
  return out;
}

// Report whether a presented (possibly gappy) binding list breaks contiguity -- a deleted/omitted
// binding -- and, if so, the FIRST-BROKEN position: the index i where the i-th presented binding's seq
// is not i or its prev does not link to the previous binding's head. A contiguous list returns
// [0, false].
export function detectHole(bindings) {
  let h = genesis();
  for (let i = 0; i < bindings.length; i++) {
    const nb = bindings[i];
    if (nb.seq !== BigInt(i) || !bytesEqual(nb.prev, h)) return [i, true];
    h = nb.head();
  }
  return [0, false];
}

// Compare two bindings for the SAME name and report whether they equivocate -- the SAME name and seq but
// DIFFERENT bodies (a different signer or prev) -- and, if so, the seq position at which they conflict. A
// different name or seq is a legitimate distinct binding; byte-identical bindings are a benign
// duplicate. Both non-fork cases return [0, false].
export function detectFork(a, b) {
  if (a.name !== b.name || a.seq !== b.seq) return [0, false];
  if (bytesEqual(a.bytes(), b.bytes())) return [0, false];
  return [Number(a.seq), true];
}

// Non-repudiable evidence of a name fork: two validly-signed NameBinding objects by ONE authority at the
// SAME (name, seq) naming DIFFERENT signers, carried as the accused authority's OWN two signed objects
// (the tagged COSE_Sign1 bytes). Because a single verifier checks BOTH signed objects, the proof is
// self-contained -- any third party confirms both signatures against the accused key.
export class NameForkProof {
  constructor(signer, signedA, signedB) {
    this.signer = Uint8Array.from(signer);   // accused authority signer id (both objects verify under its key)
    this.signedA = Uint8Array.from(signedA);
    this.signedB = Uint8Array.from(signedB);
  }

  // Accept iff ALL hold: (1) the signer id is present; (2) BOTH signed objects verify under the key
  // (which, because a single verifier checks both, proves one authority); (3) the two bindings share one
  // name and seq; and (4) their bodies differ. Returns the seq position at which it forks. An unnamed
  // signer, a different name/seq, or identical bodies is NameForkProofInvalid; a signature that does not
  // verify is BadSignature. Fail-closed.
  verify(profile, alg, pubkey) {
    if (this.signer.length === 0) throw new NamingError('NameForkProofInvalid', 'an unnamed accused is not evidence');
    const a = verifyBinding(this.signedA, profile, alg, pubkey);
    const b = verifyBinding(this.signedB, profile, alg, pubkey);
    const [pos, fork] = detectFork(a, b);
    if (!fork) throw new NamingError('NameForkProofInvalid', 'not the same (name, seq) or identical bodies');
    return pos;
  }
}

// ==== Task 4.2 -- the signed A2A task-state profile ===========================================

// TaskState codes (stable N-AALP wire codes for the imported A2A vocabulary; A2A §4.1.3).
export const STATE_SUBMITTED = 0;       // acknowledged, not yet started (the start state)
export const STATE_WORKING = 1;         // actively processed
export const STATE_INPUT_REQUIRED = 2;  // interrupted, awaiting client input
export const STATE_AUTH_REQUIRED = 3;   // interrupted, awaiting authentication
export const STATE_COMPLETED = 4;       // terminal success
export const STATE_CANCELED = 5;        // terminal, canceled before completion
export const STATE_FAILED = 6;          // terminal, finished with an error
export const STATE_REJECTED = 7;        // terminal, the agent declined the task

export const START_STATE = STATE_SUBMITTED;

const STATE_NAMES = new Map([
  [STATE_SUBMITTED, 'submitted'], [STATE_WORKING, 'working'], [STATE_INPUT_REQUIRED, 'input-required'],
  [STATE_AUTH_REQUIRED, 'auth-required'], [STATE_COMPLETED, 'completed'], [STATE_CANCELED, 'canceled'],
  [STATE_FAILED, 'failed'], [STATE_REJECTED, 'rejected'],
]);
const TERMINAL = [STATE_COMPLETED, STATE_CANCELED, STATE_FAILED, STATE_REJECTED];
const INTERRUPTED = [STATE_INPUT_REQUIRED, STATE_AUTH_REQUIRED];

export function stateName(s) {
  return STATE_NAMES.get(Number(s)) ?? 'unknown';
}

export function isState(s) {
  return STATE_NAMES.has(Number(s));
}

export function isTerminal(s) {
  return TERMINAL.includes(Number(s));
}

export function isInterrupted(s) {
  return INTERRUPTED.includes(Number(s));
}

// The explicit A2A transition table: the set of legal (from, to) edges derived from the A2A category
// rules (design §22.3). It is the authoritative source both the boolean legalEdge check and
// verifyTaskChain consult. Encoded as (from*16 + to) since every state code is < 8.
const edgeKey = (f, t) => f * 16 + t;
const LEGAL_EDGES = (() => {
  const active = [STATE_SUBMITTED, STATE_WORKING];
  const m = new Set();
  m.add(edgeKey(STATE_SUBMITTED, STATE_WORKING)); // begin processing (the only active->active edge)
  for (const s of active) for (const t of INTERRUPTED) m.add(edgeKey(s, t)); // active -> interrupted
  for (const s of active) for (const t of TERMINAL) m.add(edgeKey(s, t));    // active -> terminal
  for (const s of INTERRUPTED) m.add(edgeKey(s, STATE_WORKING));             // interrupted -> working (client acted)
  for (const s of INTERRUPTED) for (const t of TERMINAL) m.add(edgeKey(s, t)); // interrupted -> terminal
  return m;
})();

// Whether (from -> to) is a legal A2A transition edge per the table. A self-loop, an edge out of a
// terminal state, an edge touching an undefined state, and any edge not in the table are all false.
export function legalEdge(from, to) {
  if (!isState(from) || !isState(to)) return false;
  return LEGAL_EDGES.has(edgeKey(Number(from), Number(to)));
}

// A copy of the legal transition table as a sorted array of [from, to] pairs (by from then to).
export function legalEdges() {
  const out = [];
  for (const key of LEGAL_EDGES) out.push([Math.floor(key / 16), key % 16]);
  out.sort((a, b) => (a[0] !== b[0] ? a[0] - b[0] : a[1] - b[1]));
  return out;
}

// The edge-legality gate: returns null iff (from -> to) is a legal A2A edge, else throws
// NamingError(IllegalTransition). Fail-closed.
export function verifyTransition(from, to) {
  if (!legalEdge(from, to)) throw new NamingError('IllegalTransition', 'not a legal A2A transition edge');
  return null;
}

// One signed, receipt-CHAINED A2A task state transition (design §22.4). It chains onto the prior
// transition of the same task: prev is the prior transition's head (genesis for seq 0). Dated by seq.
// card is the content-id of the A2A Agent Card attestation (a C18 import) that binds this profile to an
// agent/operation. `seq` is a BigInt so a value > 2^53 round-trips byte-exact.
export class Transition {
  constructor(task, card, from, to, seq, prev) {
    this.task = Uint8Array.from(task);   // the task id (opaque bytes)
    this.card = Uint8Array.from(card);   // content-id of the bound A2A Agent Card attestation (the C18 import)
    this.from = Number(from);            // the source state
    this.to = Number(to);                // the target state
    this.seq = BigInt(seq);              // monotonic per-task chain position; seq 0's from MUST be the start state
    this.prev = Uint8Array.from(prev);   // the prior transition's head (HEAD_SIZE bytes; genesis is zero)
  }

  // Deterministic-CBOR encoding {1:task,2:card,3:from,4:to,5:seq,6:prev}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.task)],
      [new U(2), new B(this.card)],
      [new U(3), new U(this.from)],
      [new U(4), new U(this.to)],
      [new U(5), new U(this.seq)],
      [new U(6), new B(this.prev)],
    ]));
  }

  // The chain head after this transition: SHA-384 of the transition body (48 octets).
  head() {
    return headOf(this.bytes());
  }

  // The transition's T1 content-id (50 octets).
  id() {
    return contentIdOf(this.bytes());
  }
}

// Reconstruct a Transition from its body bytes alone. A body that is not exactly the {1,2,3,4,5,6} map
// with the right value types is NameMalformed (fail-closed).
export function parseTransition(b) {
  const m = decodeMap(b);
  if (m === null) throw new NamingError('NameMalformed', 'body is not a well-formed task transition');
  const task = bstrField(m, 1);
  const card = bstrField(m, 2);
  const from = uintField(m, 3);
  const to = uintField(m, 4);
  const seq = uintField(m, 5);
  const prev = bstrField(m, 6);
  if (task === null || card === null || from === null || to === null || seq === null || prev === null) {
    throw new NamingError('NameMalformed', 'body is not a well-formed task transition');
  }
  return new Transition(task, card, from, to, seq, prev);
}

// Produce the tagged COSE_Sign1 object over the transition body (real deterministic ML-DSA-65).
export function signTransition(t, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), t.bytes());
}

// Verify a transition's full signature under the profile, reconstruct it from the signed body bytes, AND
// check that its edge is legal. A bad signature is BadSignature; an illegal edge is IllegalTransition.
// Fail-closed.
export function verifyTransitionObject(obj, profile, alg, pubkey) {
  const payload = verifySign1(obj, profile, alg, pubkey);
  const t = parseTransition(payload);
  verifyTransition(t.from, t.to);
  return t;
}

// Walk a task's transition chain offline against the authority's key and the bound card attestation.
// Enforces, in order and fail-closed: (1) the SIGNATURE of every transition (BadSignature otherwise);
// (2) prev/seq linkage (each prev links to the prior head, genesis zero for seq 0; seq i == index) -- a
// gap/reorder is TaskChainBroken; (3) the CARD BINDING (every transition's card equals `card`) --
// ForeignCard otherwise; and (4) the START STATE (seq-0's from is START_STATE), CONTIGUITY (each from ==
// the prior to), and the LEGAL-EDGE TABLE at every step (including the terminal-cannot-continue rule) --
// IllegalTransition otherwise. Returns the verified, ordered transitions. It never authorizes; it
// accepts or rejects.
export function verifyTaskChain(objs, card, profile, alg, pubkey) {
  let h = genesis();
  let prevTo;
  const cardBytes = Uint8Array.from(card);
  const out = [];
  for (let i = 0; i < objs.length; i++) {
    const payload = verifySign1(objs[i], profile, alg, pubkey); // BadSignature (foreign/tampered)
    const t = parseTransition(payload);
    if (t.seq !== BigInt(i) || !bytesEqual(t.prev, h)) {
      throw new NamingError('TaskChainBroken', 'prev/seq does not chain to the previous transition');
    }
    if (!bytesEqual(t.card, cardBytes)) {
      throw new NamingError('ForeignCard', 'transition binds a card other than the profile\'s bound card');
    }
    if (i === 0) {
      if (t.from !== START_STATE) throw new NamingError('IllegalTransition', 'the first transition must leave the start state');
    } else if (t.from !== prevTo) {
      throw new NamingError('IllegalTransition', 'non-contiguous: this from must equal the prior to');
    }
    verifyTransition(t.from, t.to); // an illegal edge (incl. from-terminal)
    h = t.head();
    prevTo = t.to;
    out.push(t);
  }
  return out;
}

// Report whether a presented (possibly gappy) transition list breaks contiguity -- a deleted/omitted or
// reordered transition -- and, if so, the FIRST-BROKEN position. A contiguous list returns [0, false].
// (The gap-evident detector for the task chain, mirroring detectHole.)
export function detectTaskGap(transitions) {
  let h = genesis();
  for (let i = 0; i < transitions.length; i++) {
    const t = transitions[i];
    if (t.seq !== BigInt(i) || !bytesEqual(t.prev, h)) return [i, true];
    h = t.head();
  }
  return [0, false];
}

// ---- small deterministic-CBOR field accessors (strict decode; a non-canonical body is malformed) ----

function decodeMap(b) {
  let v;
  try {
    v = cbor.decode(Uint8Array.from(b));
  } catch (e) {
    return null; // NonCanonical or any decode failure => malformed
  }
  return v instanceof M ? v : null;
}

function field(m, k) {
  for (const [key, val] of m.pairs) {
    if (key instanceof U && key.v === BigInt(k)) return val;
  }
  return null;
}

function bstrField(m, k) {
  const v = field(m, k);
  return v instanceof B ? v.v : null;
}

function tstrField(m, k) {
  const v = field(m, k);
  return v instanceof T ? v.v : null;
}

function uintField(m, k) {
  const v = field(m, k);
  return v instanceof U ? v.v : null;
}
