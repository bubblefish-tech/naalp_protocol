// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C21 NAALP-AGUI UI-consent binding for the TypeScript SDK (design.md §24; R-AGUI-1..6).
//
// NAALP-AGUI binds a human-in-the-loop approval, captured in a user-interface event stream (the AG-UI
// tool-lifecycle events an agent shows a user), to the EXACT action bytes by content id, and
// RECEIPT-CHAINS the shown events so the shown sequence is provable offline. It introduces NO new
// envelope, encoding, signature, identity, or audit mechanism (R-11.3): a UI event is an ordinary signed
// N-AALP body (COSE_Sign1, §4), and the surface reuses the C7 audit receipt-chain construction (§8.1)
// unchanged -- head = SHA-384(body), genesis prev = 48 zero bytes, a monotonic seq, the prior head
// carried in `prev` so editing or omitting an event breaks the next event's linkage -- and the §7
// approval binding (module approval) UNCHANGED.
//
//   - UIEvent {1: session, 2: kind, 3: action, 4: seq, 5: prev} is one shown tool-lifecycle event.
//     `kind` is a closed set (shown / args-shown / approved / rejected); `action` is the T1 content id
//     of the action bytes shown to the user at this step; the chain is receipt-chained by prev/seq.
//
// The load-bearing properties, graded across implementations:
//
//   - A UI approval verifies ONLY against the EXACT action shown. verifyConsent walks the shown chain,
//     takes the action content id from the shown-and-approved event, and requires the action actually
//     being executed to hash to THAT content id (ActionSubstituted otherwise) AND the human approval to
//     bind it (the §7 approval, ApprovalMismatch otherwise). A substituted action has a different content
//     id and is rejected.
//   - A removed/omitted shown-event is detected with its POSITION. walkShown enforces contiguity and
//     returns UIChainBroken on a gap; detectHole reports the first-broken position.
//
// Every check is fail-closed (§15). Ported from impl/go/agui (with impl/python/naalp/agui.py as a second
// reference); the byte surface (kind vocabulary, event bodies/heads/ids, action content ids, the
// shown-chain walk, hole position, rejections) is graded against vectors/agui/cases.json; the signed
// shown-chain and the consent binding use real deterministic ML-DSA-65 and are demonstrated in isolation
// (the corpus carries no signed vector). The ui-event seq is carried as a BigInt so an oversized
// (>2^53) seq round-trips byte-exact.

import { sha384 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, N, B, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import * as approval from './approval.mjs';

// The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. Genesis is
// zero.
export const HEAD_SIZE = 48;

// UI event kinds -- the closed AG-UI tool-lifecycle set. A kind outside the set is rejected
// (UnknownUIEventKind).
export const KIND_SHOWN = 0;       // the action / tool call was shown (rendered) to the user
export const KIND_ARGS_SHOWN = 1;  // the arguments were shown to the user
export const KIND_APPROVED = 2;    // the user approved the shown action
export const KIND_REJECTED = 3;    // the user rejected the shown action

const KIND_NAMES = new Map([
  [KIND_SHOWN, 'shown'], [KIND_ARGS_SHOWN, 'args-shown'],
  [KIND_APPROVED, 'approved'], [KIND_REJECTED, 'rejected'],
]);

// A named, fail-closed AGUI error; .kind is the stable error kind (mirroring the Go/Rust/Python kinds
// UIMalformed, UIChainBroken, UnknownUIEventKind, ActionSubstituted, UINoConsent, plus the reused §7
// approval + cose kinds ApprovalMismatch / ApprovalExpired / BadSignature).
export class AguiError extends Error {
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

// Whether code is one of the closed UI-event kinds.
export function isKnownKind(code) {
  return KIND_NAMES.has(Number(code));
}

// The kind name, or 'unknown'.
export function kindName(code) {
  return KIND_NAMES.get(Number(code)) ?? 'unknown';
}

// A fresh 48-octet zero prev -- the empty-chain link (the C7 chain genesis).
export function genesis() {
  return new Uint8Array(HEAD_SIZE);
}

function headOf(b) {
  return sha384(Uint8Array.from(b));
}

// T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets). The content id of
// an ACTION, which a UI event names in field 3 and a human approval binds.
export function contentId(b) {
  return cbor.contentId(Uint8Array.from(b));
}

// ---- UIEvent: one receipt-chained shown tool-lifecycle event (design §24) ---------------------

// One shown tool-lifecycle event in a UI session's event stream. It chains onto the prior event: `prev`
// is the prior event's head (genesis for seq 0). `action` is the content id of the exact action bytes
// shown to the user at this step. `seq` is carried as a BigInt (an oversized >2^53 seq must round-trip
// byte-exact -- a float64 would round its low octets).
export class UIEvent {
  constructor(session, kind, action, seq, prev) {
    this.session = Uint8Array.from(session);
    this.kind = BigInt(kind);
    this.action = Uint8Array.from(action);
    this.seq = BigInt(seq);
    this.prev = Uint8Array.from(prev);
  }

  // Deterministic-CBOR encoding {1: session, 2: kind, 3: action, 4: seq, 5: prev}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.session)],
      [new U(2), new U(this.kind)],
      [new U(3), new B(this.action)],
      [new U(4), new U(this.seq)],
      [new U(5), new B(this.prev)],
    ]));
  }

  // The chain head after this event: SHA-384 of the event body (48 octets). Because the body carries
  // prev, editing any event breaks the next event's linkage.
  head() {
    return headOf(this.bytes());
  }

  // The event's T1 content id (50 octets).
  id() {
    return contentId(this.bytes());
  }
}

// Reconstruct a UIEvent from its body bytes alone. A non-canonical body, a non-map, a non-uint key, a
// mistyped field, or an absent mandatory field {1,2,3,4,5} is UIMalformed. Fail-closed.
export function parseUIEvent(b) {
  let v;
  try {
    v = cbor.decode(Uint8Array.from(b));
  } catch (e) {
    if (e instanceof cbor.NonCanonical) throw new AguiError('UIMalformed', 'ui-event body is not well-formed deterministic CBOR');
    throw e;
  }
  if (!(v instanceof M)) throw new AguiError('UIMalformed', 'ui-event body is not a map');
  let sess = null;
  let kind = null;
  let action = null;
  let seq = null;
  let prev = null;
  for (const [k, val] of v.pairs) {
    if (!(k instanceof U)) throw new AguiError('UIMalformed', 'non-uint ui-event key');
    if (k.v === 1n && val instanceof B) sess = val.v;
    else if (k.v === 2n && val instanceof U) kind = val.v;
    else if (k.v === 3n && val instanceof B) action = val.v;
    else if (k.v === 4n && val instanceof U) seq = val.v;
    else if (k.v === 5n && val instanceof B) prev = val.v;
    else throw new AguiError('UIMalformed', 'unknown or mistyped ui-event field');
  }
  if (sess === null || kind === null || action === null || seq === null || prev === null) {
    throw new AguiError('UIMalformed', 'ui-event body missing a mandatory field');
  }
  return new UIEvent(sess, kind, action, seq, prev);
}

// Produce the tagged COSE_Sign1 object over the event body (real deterministic ML-DSA).
export function signUIEvent(e, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), e.bytes());
}

// Verify the event's full signature under the profile, reconstruct it from the signed body bytes, and
// validate the kind against the closed set (UnknownUIEventKind). A bad signature propagates BadSignature.
// Fail-closed.
export function verifyUIEvent(obj, profile, alg, pubkey) {
  const payload = verifySign1(obj, profile, alg, pubkey);
  const e = parseUIEvent(payload);
  if (!isKnownKind(e.kind)) throw new AguiError('UnknownUIEventKind', 'ui-event kind is outside the closed set');
  return e;
}

// ---- the shown chain: contiguity, walk, hole detection (mirrors the C7 chain) -----------------

// One step of a walked shown chain: the chain position, the event kind, the action content id shown, and
// the chain head after it.
export class ShownEvent {
  constructor(seq, kind, action, head) {
    this.seq = seq;
    this.kind = kind;
    this.action = Uint8Array.from(action);
    this.head = Uint8Array.from(head);
  }
}

// Verify a UI event chain's structural continuity OFFLINE (no signatures) and return the ordered shown
// events. It requires every event to name the SAME session, seq i to equal its index, each kind to be in
// the closed set, and prev to link to the previous event's head (genesis for seq 0). A gap, reorder,
// omitted event, or a session change is UIChainBroken (fail-closed); an unknown kind is
// UnknownUIEventKind.
export function walkShown(events) {
  const out = [];
  let h = genesis();
  let session = null;
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (i === 0) session = e.session;
    else if (!bytesEqual(e.session, session)) throw new AguiError('UIChainBroken', 'a chain is for exactly one session');
    if (!isKnownKind(e.kind)) throw new AguiError('UnknownUIEventKind', 'ui-event kind is outside the closed set');
    if (e.seq !== BigInt(i) || !bytesEqual(e.prev, h)) {
      throw new AguiError('UIChainBroken', 'ui-event prev/seq does not chain to the previous event');
    }
    h = e.head();
    out.push(new ShownEvent(e.seq, e.kind, e.action, h));
  }
  return out;
}

// Check a UI event chain offline against the UI authority's key. Each element is the tagged COSE_Sign1
// object for one event; verify every signature under the profile (verifyUIEvent), then enforce the same
// structural continuity as walkShown. A bad signature propagates BadSignature; a broken link, seq gap, or
// session change is UIChainBroken. Detects any reorder, omission, or substitution of a shown event
// (§8.1). Fail-closed.
export function verifyShownChain(objs, profile, alg, pubkey) {
  let h = genesis();
  let session = null;
  const out = [];
  for (let i = 0; i < objs.length; i++) {
    const e = verifyUIEvent(objs[i], profile, alg, pubkey);
    if (i === 0) session = e.session;
    else if (!bytesEqual(e.session, session)) throw new AguiError('UIChainBroken', 'a chain is for exactly one session');
    if (e.seq !== BigInt(i) || !bytesEqual(e.prev, h)) {
      throw new AguiError('UIChainBroken', 'ui-event prev/seq does not chain to the previous event');
    }
    h = e.head();
    out.push(e);
  }
  return out;
}

// Report whether a presented (possibly gappy) event list breaks contiguity -- a deleted/omitted
// shown-event -- and, if so, the FIRST-BROKEN POSITION: the index i where the i-th presented event's seq
// is not i or its prev does not link to the previous event's head. A contiguous list returns [0, false].
export function detectHole(events) {
  let h = genesis();
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (e.seq !== BigInt(i) || !bytesEqual(e.prev, h)) return [i, true];
    h = e.head();
  }
  return [0, false];
}

// ---- the UI consent binding (reuses the §7 approval) ------------------------------------------

// The content id of the action shown-and-approved in a walked chain, and whether an approved event is
// present. It is the content id a valid consent binds; a chain with no approved event has no consent to
// bind.
export function approvedActionCID(shown) {
  for (const ev of shown) {
    if (Number(ev.kind) === KIND_APPROVED) return [Uint8Array.from(ev.action), true];
  }
  return [null, false];
}

// Bind a human-in-the-loop approval to the EXACT action shown in a UI event stream. It (1) walks the
// shown chain, rejecting any gap/reorder/omission (UIChainBroken); (2) takes the action content id from
// the shown-and-approved event (UINoConsent if there is none); (3) verifies the human §7 approval binds
// THAT shown content id and has not expired (ApprovalMismatch / ApprovalExpired / BadSignature, from
// modules approval and cose); and (4) requires the action actually being executed (`actionBytes`) to
// hash to the shown-and-approved content id -- a SUBSTITUTED action has a different content id and is
// rejected (ActionSubstituted). Every failure returns its named error and authorizes nothing
// (fail-closed). On success the caller may execute exactly `actionBytes`. Returns null on authorization.
export function verifyConsent(chain, actionBytes, appr, approverAlg, approverPubkey, apprSig, now) {
  const shown = walkShown(chain); // UIChainBroken / UnknownUIEventKind on a hole
  const [shownCID, ok] = approvedActionCID(shown);
  if (!ok) throw new AguiError('UINoConsent', 'the shown chain carries no approved event');
  // The human approval must be a valid signature binding the shown-and-approved action content id.
  approval.verifyApproval(appr, approverAlg, approverPubkey, apprSig, shownCID, now);
  // The action actually being executed MUST be the exact one shown and approved: a substitution has a
  // different content id and is rejected. This is the seam a lax UI profile would drop.
  if (!bytesEqual(contentId(actionBytes), shownCID)) {
    throw new AguiError('ActionSubstituted', 'the executed action is not the exact action shown+approved');
  }
  return null;
}

// ---- signing / verification helpers (COSE_Sign1 with the bare {1: alg} header) ------------------

// The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits.
function protectedHeader(alg) {
  return cbor.encode(new M([[new U(1), new N(alg)]]));
}

// Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the payload.
// Mirrors the shared verify: alg registry, profile floor, key-alg match, signature. Fail-closed with a
// named AguiError.
function verifySign1(obj, profile, alg, pubkey) {
  const [prot, payload, sig] = cose.parseSign1Raw(obj);
  const halg = algFromProtected(prot);
  const [level, known] = cose.algLevel(halg);
  if (!known) throw new AguiError('UnknownAlg', 'unregistered alg ' + halg);
  if (level < cose.profileMinLevel(profile)) {
    throw new AguiError('ProfileDowngrade', 'signature level below the profile minimum');
  }
  if (halg !== Number(alg)) {
    throw new AguiError('KeyAlgMismatch', 'alg ' + halg + ' does not match the verifier key alg ' + alg);
  }
  const tbs = cose.toBeSignedRaw(prot, payload);
  if (!cose.coseVerify1Raw(halg, pubkey, tbs, sig)) {
    throw new AguiError('BadSignature', 'signature does not verify');
  }
  return payload;
}

function algFromProtected(prot) {
  const v = cbor.decode(prot);
  if (v instanceof M) {
    for (const [k, val] of v.pairs) {
      if (k instanceof U && k.v === 1n && (val instanceof N || val instanceof U)) return Number(val.v);
    }
  }
  throw new AguiError('UIMalformed', 'protected header has no alg');
}
