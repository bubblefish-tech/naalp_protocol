// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C20 governed negotiation, advisory risk labels, and trust references for the TypeScript SDK
// (design.md §23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4).
//
// C20 adds three signed surfaces carried on N-AALP's own signed object; it introduces NO new envelope,
// encoding, signature, identity, or audit mechanism (R-11.3). Each object is an ordinary signed N-AALP
// body (COSE_Sign1, §4), reusing the closed C5 effect lattice (policy), the T1 content-id framing
// (§2.3), and the §8.2 causal partial order (the `causes` field) UNCHANGED.
//
//   - Governed negotiation: a Message {1:negotiation, 2:role, 3:profile, 4:causes[]} is one signed
//     step -- an OFFER, a COUNTER, or an ACCEPT -- CAUSALLY LINKED to its predecessor(s) by content-id
//     in `causes` (empty for an offer) and SELECTING a profile from a CLOSED pre-registered set (no
//     free-form/runtime capability on the wire, §23.9). An ACCEPT MUST DESCEND from its offer: walking
//     the causes DAG from the accept must reach the offer's content-id (verifyAccept), else it is
//     rejected (NotDescended). An unknown role/profile is rejected.
//   - Advisory risk labels: a RiskLabel {1:code, 2:critical} + a LabeledObject {1:effect, 2:labels[]}.
//     The R-2.5 critical-extension rule applies (an unknown CRITICAL label is rejected, an unknown
//     non-critical one is ignored). LOAD-BEARING invariant: carrying a risk label NEVER changes an
//     object's effect class -- effectClass derives from the effect field ALONE, so the closed C5
//     lattice is untouched. Risk labels are an advisory dimension, never a fifth effect.
//   - Trust references: a TrustRef {1:registry, 2:reference, 3:subject} carries a third-party trust
//     statement as a CHECKABLE signed object -- verifyTrustRef recomputes the referenced content-id
//     over the external record (bindsRecord). NO wire field weighs it: there is no score, rank, or
//     ordering, and this module provides no scoring function, by design (§23.7).
//
// Every check is fail-closed (§15). Ported from impl/go/negotiation (with impl/python/naalp/negotiation
// as a second reference); graded against the shared vectors/negotiation/cases.json. The Message /
// LabeledObject / TrustRef signatures are real deterministic ML-DSA-65 (COSE_Sign1) but not
// corpus-graded.

import { sha384 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, B, A, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import * as policy from './policy.mjs';

// The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
export const HEAD_SIZE = 48;

// A named, fail-closed C20 error; .kind is the stable error kind mirroring the Go/Rust/Python/Ruby
// kinds (NegMalformed, UnknownRole, UnknownProfile, NotDescended, NotOffer, NotAccept,
// MalformedCriticalFlag, UnknownCriticalRisk, ReferenceMismatch, BadSignature, UnknownAlg,
// ProfileDowngrade, KeyAlgMismatch).
export class NegotiationError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// SHA-384 over a body -- a 48-octet head (the same construction as the C7 audit head).
function headOf(b) { return sha384(Uint8Array.from(b)); }

// T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
export function contentId(b) { return cbor.contentId(Uint8Array.from(b)); }

const hexOf = (b) => Buffer.from(b).toString('hex');

// ==== governed negotiation =====================================================================

export const ROLE_OFFER = 0;   // the initiating offer (root of a negotiation; no causes)
export const ROLE_COUNTER = 1; // a counter-offer chaining onto the offer or a prior counter
export const ROLE_ACCEPT = 2;  // the accept; it MUST descend from its offer

const ROLE_NAMES = new Map([[ROLE_OFFER, 'offer'], [ROLE_COUNTER, 'counter'], [ROLE_ACCEPT, 'accept']]);

// Whether r is one of the three defined negotiation roles.
export function knownRole(r) { return ROLE_NAMES.has(Number(r)); }

// The role name, or 'unknown' for an out-of-range code.
export function roleName(r) { return ROLE_NAMES.get(Number(r)) ?? 'unknown'; }

export const PROFILE_BASELINE = 0;  // the baseline capability profile
export const PROFILE_STREAMING = 1; // the native-streaming capability profile (C9)
export const PROFILE_BATCH = 2;     // the batched-delivery capability profile

const PROFILE_NAMES = new Map([[PROFILE_BASELINE, 'baseline'], [PROFILE_STREAMING, 'streaming'], [PROFILE_BATCH, 'batch']]);

// Whether p is one of the pre-registered profiles (the closed set).
export function isRegisteredProfile(p) { return PROFILE_NAMES.has(Number(p)); }

// The profile name, or 'unknown' for an unregistered code.
export function profileName(p) { return PROFILE_NAMES.get(Number(p)) ?? 'unknown'; }

// One signed step of a governed negotiation: an offer, a counter, or an accept. It is causally linked
// to its predecessor(s) by content-id in `causes` (empty for an offer) and SELECTS a pre-registered
// profile.
export class Message {
  constructor(negotiation, role, profile, causes = []) {
    this.negotiation = Uint8Array.from(negotiation);
    this.role = role;
    this.profile = profile;
    this.causes = causes.map((c) => Uint8Array.from(c));
  }

  // Deterministic-CBOR encoding {1: negotiation, 2: role, 3: profile, 4: causes[]}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.negotiation)],
      [new U(2), new U(this.role)],
      [new U(3), new U(this.profile)],
      [new U(4), new A(this.causes.map((c) => new B(c)))],
    ]));
  }

  // The Message's SHA-384 head (48 octets).
  head() { return headOf(this.bytes()); }

  // The Message's T1 content-id (50 octets) -- the id a successor names in its causes.
  id() { return contentId(this.bytes()); }
}

// Build an offer (the root of a negotiation): role offer, no causes.
export function newOffer(negotiation, profile) {
  return new Message(negotiation, ROLE_OFFER, profile, []);
}

// Build a counter chaining onto the predecessor named by predecessorId.
export function newCounter(negotiation, profile, predecessorId) {
  return new Message(negotiation, ROLE_COUNTER, profile, [predecessorId]);
}

// Build an accept chaining onto the predecessor named by predecessorId.
export function newAccept(negotiation, profile, predecessorId) {
  return new Message(negotiation, ROLE_ACCEPT, profile, [predecessorId]);
}

// Reconstruct a Message from its body bytes alone. It does NOT validate the role or profile against
// the closed sets (that is verifyMessage's job), so a message carrying an unknown role or profile can
// be represented (and then rejected). Fail-closed (NegMalformed) on a malformed shape, a non-canonical
// body, or a mistyped field.
export function parseMessage(b) {
  const m = decodeMap(b);
  if (m === null) throw new NegotiationError('NegMalformed', 'object is not a well-formed negotiation body');
  const neg = bstrField(m, 1);
  const role = uintField(m, 2);
  const prof = uintField(m, 3);
  const causesV = field(m, 4);
  if (neg === undefined || role === undefined || prof === undefined || causesV === undefined || !(causesV instanceof A)) {
    throw new NegotiationError('NegMalformed', 'object is not a well-formed negotiation body');
  }
  const causes = [];
  for (const e of causesV.items) {
    if (!(e instanceof B)) throw new NegotiationError('NegMalformed', 'cause is not a bstr');
    causes.push(e.v);
  }
  return new Message(neg, role, prof, causes);
}

// The tagged COSE_Sign1 over the Message body (real deterministic ML-DSA).
export function signMessage(m, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), m.bytes());
}

// Verify the Message's full signature under the profile, reconstruct it from the signed body bytes,
// and validate it against the closed sets: the role MUST be offer/counter/accept (UnknownRole) and the
// selected profile MUST be pre-registered (UnknownProfile). Fail-closed.
export function verifyMessage(obj, profile, alg, pubkey) {
  const payload = verifyCoseBody(obj, profile, alg, pubkey);
  const msg = parseMessage(payload);
  if (!knownRole(msg.role)) throw new NegotiationError('UnknownRole', 'negotiation message role is not offer/counter/accept');
  if (!isRegisteredProfile(msg.profile)) throw new NegotiationError('UnknownProfile', 'negotiation selects a profile outside the closed set');
  return msg;
}

// Build the content-id(hex) -> Message index the descent walk resolves predecessors through.
export function indexById(msgs) {
  const byId = new Map();
  for (const m of msgs) byId.set(hexOf(m.id()), m);
  return byId;
}

// Whether `from` reaches targetId by following causes edges resolved through byId: a real reachability
// walk over the causal DAG. A cause that cannot be resolved through byId cannot extend the chain, so a
// forged causes pointer to an id the verifier never saw does not manufacture descent. Fail-closed.
function reaches(from, targetId, byId) {
  const target = hexOf(targetId);
  const seen = new Set();
  const stack = from.causes.map((c) => hexOf(c));
  while (stack.length) {
    const cid = stack.pop();
    if (cid === target) return true;
    if (seen.has(cid)) continue;
    seen.add(cid);
    const pred = byId.get(cid);
    if (pred === undefined) continue; // an unresolved cause: the chain cannot be walked through it
    for (const c of pred.causes) stack.push(hexOf(c));
  }
  return false;
}

// Whether `accept` descends from `offer` by walking the causes DAG through byId (a counter or a chain
// of counters between them is traversed). Performs no signature check.
export function descends(accept, offer, byId) {
  return reaches(accept, offer.id(), byId);
}

// Check an accept against its offer over a set of verified messages, fail-closed. It requires `offer`
// to be a genuine offer selecting a pre-registered profile (NotOffer / UnknownProfile), `accept` to be
// an accept selecting a pre-registered profile (NotAccept / UnknownProfile), and the accept to DESCEND
// from the offer (NotDescended). Returns the AGREED profile. It authorizes nothing; it accepts or
// rejects.
export function verifyAccept(accept, offer, byId) {
  if (Number(offer.role) !== ROLE_OFFER) throw new NegotiationError('NotOffer', 'the object presented as the offer is not an offer role');
  if (!isRegisteredProfile(offer.profile)) throw new NegotiationError('UnknownProfile', 'offer selects a profile outside the closed set');
  if (Number(accept.role) !== ROLE_ACCEPT) throw new NegotiationError('NotAccept', 'the object presented as the accept is not an accept role');
  if (!isRegisteredProfile(accept.profile)) throw new NegotiationError('UnknownProfile', 'accept selects a profile outside the closed set');
  if (!descends(accept, offer, byId)) throw new NegotiationError('NotDescended', 'accept does not descend from its offer along the causes chain');
  return accept.profile;
}

// ==== advisory risk labels =====================================================================

export const CLASS_INFORMING = 0; // purely informational
export const CLASS_GATING = 1;    // a policy MAY require an additional gate when this label is present

const RISK_CLASS_NAMES = new Map([[CLASS_INFORMING, 'informing'], [CLASS_GATING, 'gating']]);

// The class name ('gating'/'informing'), or '' for an out-of-range value.
export function riskClassName(c) { return RISK_CLASS_NAMES.get(Number(c)) ?? ''; }

export const RISK_SENSITIVE = 1;  // gating: the object touches sensitive material
export const RISK_EGRESS = 2;     // gating: the object causes data egress
export const RISK_REVERSIBLE = 3; // informing: the object's effect is reversible

// The first code of the private/experimental extensible range. A code at or above it is unknown to a
// verifier that lacks it: carried critical it is rejected (R-2.5), carried non-critical it is ignored.
export const EXTENSIBLE_RANGE_START = 0x1000;

// The closed standard risk-label vocabulary: code -> class.
const RISK_VOCAB = new Map([
  [RISK_SENSITIVE, CLASS_GATING],
  [RISK_EGRESS, CLASS_GATING],
  [RISK_REVERSIBLE, CLASS_INFORMING],
]);

// A code's vocabulary class and whether the code is a registered standard label: [class, ok].
export function riskClassOf(code) {
  const c = Number(code);
  return RISK_VOCAB.has(c) ? [RISK_VOCAB.get(c), true] : [CLASS_INFORMING, false];
}

// Whether code is in the closed standard vocabulary.
export function isRegisteredRisk(code) { return RISK_VOCAB.has(Number(code)); }

// Whether code lies in the private/experimental extensible range.
export function inExtensibleRange(code) { return Number(code) >= EXTENSIBLE_RANGE_START; }

// One advisory risk label carried on an object. `code` is the label code; `critical` is the
// per-carriage must-understand flag (1 = critical, 0 = advisory) -- the uint 1/0, no CBOR boolean.
export class RiskLabel {
  constructor(code, critical) {
    this.code = code;
    this.critical = critical;
  }

  // Whether the label is carried critical (must-understand).
  isCritical() { return Number(this.critical) === 1; }

  // The label's CBOR map {1: code, 2: critical}.
  toMap() {
    return new M([[new U(1), new U(this.code)], [new U(2), new U(this.critical)]]);
  }

  // Deterministic-CBOR encoding of the risk-label body.
  bytes() { return cbor.encode(this.toMap()); }
}

// Parse one risk-label map, rejecting a malformed shape (NegMalformed) or a critical flag outside
// {0,1} (MalformedCriticalFlag). Fail-closed.
function riskLabelFromValue(v) {
  if (!(v instanceof M)) throw new NegotiationError('NegMalformed', 'risk label is not a map');
  const code = uintField(v, 1);
  const crit = uintField(v, 2);
  if (code === undefined || crit === undefined) throw new NegotiationError('NegMalformed', 'risk label missing a field');
  if (crit > 1n) throw new NegotiationError('MalformedCriticalFlag', 'risk-label critical flag is outside {0,1}');
  return new RiskLabel(code, crit);
}

// Apply the critical-extension rule (R-2.5) to a set of carried risk labels: return the RECOGNIZED
// (standard-vocabulary) labels, DROP unknown non-critical labels, and REJECT an unknown CRITICAL label
// (UnknownCriticalRisk). A critical flag outside {0,1} is MalformedCriticalFlag. It NEVER inspects or
// returns an effect -- risk labels are an advisory dimension, never a fifth effect. Fail-closed.
export function validateLabels(labels) {
  const recognized = [];
  for (const l of labels) {
    if (Number(l.critical) > 1) throw new NegotiationError('MalformedCriticalFlag', 'risk-label critical flag is outside {0,1}');
    if (isRegisteredRisk(l.code)) { recognized.push(l); continue; }
    if (l.isCritical()) throw new NegotiationError('UnknownCriticalRisk', 'an unknown critical risk label is rejected (R-2.5)');
    // unknown non-critical: ignored (dropped from the recognized set)
  }
  return recognized;
}

// A minimal N-AALP object carrying an effect (field 1, C5) and a set of advisory risk labels. It
// demonstrates -- provably, in isolation -- the load-bearing invariant that carrying a risk label
// NEVER changes the object's effect class.
export class LabeledObject {
  constructor(effect, labels = []) {
    this.effect = effect;
    this.labels = Array.from(labels);
  }

  // Deterministic-CBOR encoding {1: effect, 2: labels[]}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new U(this.effect)],
      [new U(2), new A(this.labels.map((l) => l.toMap()))],
    ]));
  }

  // The LabeledObject's SHA-384 head (48 octets).
  head() { return headOf(this.bytes()); }

  // The LabeledObject's T1 content-id (50 octets).
  id() { return contentId(this.bytes()); }

  // The C5 effect class, derived from the effect field (field 1) ALONE and normalized fail-closed
  // (unknown -> destructive, R-6.2). It DELIBERATELY does not consult the risk labels: a risk label is
  // an advisory dimension, never a fifth effect, so the closed lattice is untouched by any label the
  // object carries. This is the load-bearing C20 invariant.
  effectClass() { return policy.normalizeEffect(this.effect); }

  // Apply the critical-extension rule to the object's carried labels.
  validateLabels() { return validateLabels(this.labels); }
}

// Reconstruct a LabeledObject from its body bytes alone. Fail-closed (NegMalformed) on a malformed
// shape; a critical flag outside {0,1} is MalformedCriticalFlag.
export function parseLabeledObject(b) {
  const m = decodeMap(b);
  if (m === null) throw new NegotiationError('NegMalformed', 'object is not a well-formed labeled-object body');
  const eff = uintField(m, 1);
  const labelsV = field(m, 2);
  if (eff === undefined || labelsV === undefined || !(labelsV instanceof A)) {
    throw new NegotiationError('NegMalformed', 'object is not a well-formed labeled-object body');
  }
  const labels = labelsV.items.map(riskLabelFromValue);
  return new LabeledObject(eff, labels);
}

// The tagged COSE_Sign1 over the LabeledObject body (real deterministic ML-DSA).
export function signLabeledObject(o, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), o.bytes());
}

// Verify the signature, reconstruct the object, and apply the critical-extension rule to its labels
// (an unknown critical label is rejected). Returns [object, recognizedLabels]. The returned object's
// effectClass is unchanged by any label. Fail-closed.
export function verifyLabeledObject(obj, profile, alg, pubkey) {
  const payload = verifyCoseBody(obj, profile, alg, pubkey);
  const o = parseLabeledObject(payload);
  const recognized = validateLabels(o.labels);
  return [o, recognized];
}

// ==== trust references (checkable, never weighed) ==============================================

// A third-party trust statement carried as a CHECKABLE signed object. `registry` is an opaque
// external-registry identifier (an ERC-8004-style reputation/identity registry -- a name, not a URL
// the wire resolves); `reference` is the T1 content-id of the referenced external record; `subject` is
// the opaque id the statement is about. The wire CARRIES the reference; NO field here weighs it --
// there is no score, rank, or ordering.
export class TrustRef {
  constructor(registry, reference, subject) {
    this.registry = Uint8Array.from(registry);
    this.reference = Uint8Array.from(reference);
    this.subject = Uint8Array.from(subject);
  }

  // Deterministic-CBOR encoding {1: registry, 2: reference, 3: subject}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.registry)],
      [new U(2), new B(this.reference)],
      [new U(3), new B(this.subject)],
    ]));
  }

  // The TrustRef's SHA-384 head (48 octets).
  head() { return headOf(this.bytes()); }

  // The TrustRef's own T1 content-id (50 octets).
  id() { return contentId(this.bytes()); }

  // The content-id the trust ref binds (the carried external-record reference).
  referenceId() { return Uint8Array.from(this.reference); }

  // Whether the carried reference is the T1 content-id of `record` -- i.e. the reference recomputes
  // over the presented external bytes. This is the CHECK a relying party runs to confirm the reference
  // names those exact external bytes; it computes NO score. A changed record yields a different
  // content-id, so bindsRecord returns false.
  bindsRecord(record) {
    const want = contentId(record);
    if (want.length !== this.reference.length) return false;
    for (let i = 0; i < want.length; i++) if (want[i] !== this.reference[i]) return false;
    return true;
  }
}

// Reconstruct a TrustRef from its body bytes alone. Fail-closed (NegMalformed).
export function parseTrustRef(b) {
  const m = decodeMap(b);
  if (m === null) throw new NegotiationError('NegMalformed', 'object is not a well-formed trust-ref body');
  const reg = bstrField(m, 1);
  const ref = bstrField(m, 2);
  const subj = bstrField(m, 3);
  if (reg === undefined || ref === undefined || subj === undefined) {
    throw new NegotiationError('NegMalformed', 'object is not a well-formed trust-ref body');
  }
  return new TrustRef(reg, ref, subj);
}

// The tagged COSE_Sign1 over the TrustRef body (real deterministic ML-DSA).
export function signTrustRef(r, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), r.bytes());
}

// A TrustRef that has passed signature verification and (given the external record) the content-id
// recompute. It carries NO score, rank, or trust weight -- the protocol does not weigh trust; which
// statement to believe is left to the relying party.
export class ResolvedTrustRef {
  constructor(registry, reference, subject) {
    this.registry = Uint8Array.from(registry);
    this.reference = Uint8Array.from(reference);
    this.subject = Uint8Array.from(subject);
  }
}

// Verify a trust reference end-to-end: (1) verify the signed object with real crypto (BadSignature);
// (2) reconstruct it from the signed bytes; and (3) confirm the reference by RECOMPUTING the external
// record's content-id and requiring it to equal the carried reference (ReferenceMismatch otherwise).
// Returns the resolved reference -- and NOTHING that scores it: this module has no trust-weighting
// function, by design. Fail-closed.
export function verifyTrustRef(obj, profile, alg, pubkey, externalRecord) {
  const payload = verifyCoseBody(obj, profile, alg, pubkey);
  const r = parseTrustRef(payload);
  if (!r.bindsRecord(externalRecord)) throw new NegotiationError('ReferenceMismatch', 'trust-ref reference does not recompute over the record');
  return new ResolvedTrustRef(r.registry, r.reference, r.subject);
}

// ---- full-signature helpers (real ML-DSA COSE_Sign1, demonstrated in isolation) ---------------

// The bare {1: alg} COSE_Sign1 protected header (§4).
function protectedHeader(alg) {
  return cbor.encode(new M([[new U(1), new cbor.N(alg)]]));
}

// Read the alg (label 1) value from an encoded protected header.
function algFromProtected(prot) {
  const v = cbor.decode(prot);
  if (!(v instanceof M)) throw new NegotiationError('NegMalformed', 'protected header is not a map');
  for (const [k, val] of v.pairs) {
    if (k instanceof U && k.v === 1n && (val instanceof cbor.N || val instanceof U)) return Number(val.v);
  }
  throw new NegotiationError('NegMalformed', 'protected header has no alg');
}

// Verify a tagged COSE_Sign1 object's full signature under the profile and return its signed payload
// bytes. Mirrors the C21 gateway verify prologue: alg registry, profile floor, key-alg match, and the
// real signature check. Fail-closed (UnknownAlg / ProfileDowngrade / KeyAlgMismatch / BadSignature).
function verifyCoseBody(obj, profile, alg, pubkey) {
  const [prot, payload, sig] = cose.parseSign1Raw(obj);
  const halg = algFromProtected(prot);
  const [level, known] = cose.algLevel(halg);
  if (!known) throw new NegotiationError('UnknownAlg', 'unregistered alg ' + halg);
  if (level < cose.profileMinLevel(profile)) throw new NegotiationError('ProfileDowngrade', 'signature level below the profile minimum');
  if (halg !== Number(alg)) throw new NegotiationError('KeyAlgMismatch', 'alg ' + halg + ' does not match the verifier key alg ' + alg);
  const tbs = cose.toBeSignedRaw(prot, payload);
  if (!cose.coseVerify1Raw(halg, pubkey, tbs, sig)) throw new NegotiationError('BadSignature', 'signature does not verify');
  return payload;
}

// ---- small deterministic-CBOR field accessors ------------------------------------------------

function decodeMap(b) {
  let v;
  try { v = cbor.decode(b); }
  catch (e) { if (e instanceof cbor.NonCanonical) return null; throw e; }
  return (v instanceof M) ? v : null;
}

function field(m, k) {
  for (const [key, val] of m.pairs) {
    if (key instanceof U && key.v === BigInt(k)) return val;
  }
  return undefined;
}

function bstrField(m, k) { const v = field(m, k); return v instanceof B ? v.v : undefined; }

function uintField(m, k) { const v = field(m, k); return v instanceof U ? v.v : undefined; }
