// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C21 portable gateway-decision object for the TypeScript SDK (design.md §24; R-GW-1..6).
//
// A GatewayDecision is a SIGNED decision object an enforcement gateway of ANY vendor emits as
// PORTABLE EVIDENCE that it decided about an action. Its load-bearing property, exactly as the C18
// signed description, is that authority lives in the SIGNED BYTES, never in the connection or the
// host that served them: verifyDecision takes NO serving-party/connection identity, so the same
// signed decision RE-VERIFIES IDENTICALLY when a party OTHER than the gateway serves it (the
// third-party re-serve property). It introduces NO new envelope, encoding, signature, identity, or
// audit mechanism: the object is an ordinary signed N-AALP body (COSE_Sign1), reusing the closed C5
// effect lattice and the T1 content-id framing unchanged. This is the EVIDENCE FORMAT ONLY -- never
// a policy language. Every check is fail-closed: a failing object is rejected whole, returns its
// named error, and causes no state change.
//
// Ported from impl/go/gateway; graded against the shared vectors/gateway/cases.json.

import { sha384 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, N, B, T, A, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import * as policy from './policy.mjs';

// The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
export const HEAD_SIZE = 48;

// The closed set a gateway may emit; a code outside the set is rejected (UnknownGatewayDecision).
export const DECISION_ALLOW = 0; // the gateway allows the action
export const DECISION_DENY = 1;  // the gateway denies the action
export const DECISION_HOLD = 2;  // the gateway holds the action pending a further step

// decision code -> name (diagnostics); an unknown code has no entry.
const DECISION_NAMES = new Map([[DECISION_ALLOW, 'allow'], [DECISION_DENY, 'deny'], [DECISION_HOLD, 'hold']]);

// A named, fail-closed gateway error; .kind is a stable string mirroring the Go/Rust/Python/Ruby
// error kinds (GwMalformed, UnknownGatewayDecision, BadSignature, UnknownAlg, ProfileDowngrade,
// KeyAlgMismatch).
export class GatewayError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// Reports whether code is one of the closed decision codes.
export function isKnownDecision(code) {
  return DECISION_NAMES.has(Number(code));
}

// The decision name, or 'unknown'.
export function decisionName(code) {
  return DECISION_NAMES.get(Number(code)) ?? 'unknown';
}

// A signed decision an enforcement gateway emits as portable evidence. `decision` is the closed-set
// outcome; `action` is the content id of the action decided about; `policy` is the opaque
// deciding-policy identity (a name, not a program); `effect` is the action's C5 class. `ordering`
// (field 5, R1) and `foreignProfile` (field 6, R8) are OPTIONAL: null reads exactly as an absent
// field (correspondence-only ordering / no foreign-profile pin) -- never a stronger claim inferred
// from silence.
export class GatewayDecision {
  constructor(decision, action, policy, effect, ordering = null, foreignProfile = null) {
    this.decision = decision;
    this.action = Uint8Array.from(action);
    this.policy = Uint8Array.from(policy);
    this.effect = effect;
    this.ordering = ordering;
    this.foreignProfile = foreignProfile;
  }

  // Deterministic-CBOR encoding {1: decision, 2: action, 3: policy, 4: effect, ?5: ordering,
  // ?6: foreign-profile}. Fields 5/6 are OMITTED entirely when null (the same omit-when-absent
  // precedent as naalp-decision-record's optional fields 3/6/7).
  bytes() {
    const pairs = [
      [new U(1), new U(this.decision)],
      [new U(2), new B(this.action)],
      [new U(3), new B(this.policy)],
      [new U(4), new U(this.effect)],
    ];
    if (this.ordering !== null) pairs.push([new U(5), this.ordering.toCbor()]);
    if (this.foreignProfile !== null) pairs.push([new U(6), this.foreignProfile.toCbor()]);
    return cbor.encode(new M(pairs));
  }

  // The decision's SHA-384 head (48 octets).
  head() {
    return sha384(this.bytes());
  }

  // The decision's T1 content-id: multihash(0x20, 0x30 [48]) || SHA-384(body) (50 octets).
  id() {
    return cbor.contentId(this.bytes());
  }

  // The C5 effect class, normalized fail-closed: an unrecognized value is destructive.
  effectClass() {
    return policy.normalizeEffect(this.effect);
  }
}

// A GatewayDecision that has passed signature verification. It carries NOTHING about who served the
// bytes -- the authority is the signature, so the resolved evidence is identical regardless of the
// serving party (the third-party re-serve property).
export class ResolvedDecision {
  constructor(decision, action, policy, effect) {
    this.decision = decision;
    this.action = Uint8Array.from(action);
    this.policy = Uint8Array.from(policy);
    this.effect = effect;
  }
}

// Reconstruct a GatewayDecision from its body bytes alone. It does NOT validate the decision code
// against the closed set -- that is verifyDecision's job -- so a decision carrying an unknown code
// can be represented (and then rejected). Fail-closed on a malformed shape: a non-canonical body, a
// non-map, or an absent/wrong-typed field 1-4 is GwMalformed.
export function parseDecision(b) {
  let v;
  try {
    v = cbor.decode(b);
  } catch (e) {
    if (e instanceof cbor.NonCanonical) {
      throw new GatewayError('GwMalformed', 'decision body is not well-formed deterministic CBOR');
    }
    throw e;
  }
  if (!(v instanceof M)) throw new GatewayError('GwMalformed', 'decision body is not a map');
  const fields = new Map();
  for (const [k, val] of v.pairs) {
    if (k instanceof U) fields.set(k.v, val);
  }
  const dec = fields.get(1n);
  const action = fields.get(2n);
  const pol = fields.get(3n);
  const eff = fields.get(4n);
  if (!(dec instanceof U) || !(action instanceof B) || !(pol instanceof B) || !(eff instanceof U)) {
    throw new GatewayError('GwMalformed', 'decision body missing or wrong-typed field 1-4');
  }
  const gd = new GatewayDecision(dec.v, action.v, pol.v, eff.v);
  const ordV = fields.get(5n);
  if (ordV !== undefined) {
    const ordering = orderingFromCbor(ordV);
    if (ordering === null) throw new GatewayError('GwMalformed', 'field 5 (ordering) is present but malformed');
    gd.ordering = ordering;
  }
  const fpV = fields.get(6n);
  if (fpV !== undefined) {
    const fp = foreignProfileFromCbor(fpV);
    if (fp === null) throw new GatewayError('GwMalformed', 'field 6 (foreign-profile) is present but malformed');
    gd.foreignProfile = fp;
  }
  return gd;
}

// The bare {1: alg} COSE_Sign1 protected header (§4), as the reference's cose.Sign1 emits.
export function gatewayProtectedHeader(alg) {
  return cbor.encode(new M([[new U(1), new N(alg)]]));
}

// Produce the tagged COSE_Sign1 object over the decision body, signed by the gateway.
export function signDecision(d, alg, seed) {
  return cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), d.bytes());
}

// Read the alg (label 1) value from an encoded protected header.
export function algFromProtected(prot) {
  const v = cbor.decode(prot);
  if (!(v instanceof M)) throw new GatewayError('GwMalformed', 'protected header is not a map');
  for (const [k, val] of v.pairs) {
    if (k instanceof U && k.v === 1n && (val instanceof N || val instanceof U)) return Number(val.v);
  }
  throw new GatewayError('GwMalformed', 'protected header has no alg');
}

// Verify a gateway decision end-to-end and return the resolved evidence. It (1) verifies the signed
// object under the profile with real crypto (signature, alg registry, profile floor) against the
// gateway's key; (2) reconstructs it from the signed bytes; and (3) validates the decision code
// against the closed set (UnknownGatewayDecision). It takes NO serving-party or connection identity:
// the authority is the signature over the bytes, so the same obj yields an identical
// ResolvedDecision whether the gateway or an unrelated third party served it. Any failure returns
// its named error and resolves nothing (fail-closed).
export function verifyDecision(obj, profile, alg, pubkey) {
  const [prot, payload, sig] = cose.parseSign1Raw(obj);
  const halg = algFromProtected(prot);
  const [level, known] = cose.algLevel(halg);
  if (!known) throw new GatewayError('UnknownAlg', 'unregistered alg ' + halg);
  if (level < cose.profileMinLevel(profile)) {
    throw new GatewayError('ProfileDowngrade', 'signature level below the profile minimum');
  }
  if (halg !== Number(alg)) {
    throw new GatewayError('KeyAlgMismatch', 'alg ' + halg + ' does not match the verifier key alg ' + alg);
  }
  const tbs = cose.toBeSignedRaw(prot, payload);
  if (!cose.coseVerify1Raw(halg, pubkey, tbs, sig)) {
    throw new GatewayError('BadSignature', 'signature does not verify');
  }
  const d = parseDecision(payload);
  if (!isKnownDecision(d.decision)) {
    throw new GatewayError('UnknownGatewayDecision', 'decision code ' + d.decision + ' outside the closed set');
  }
  if (d.ordering !== null) d.ordering.validate();
  if (d.foreignProfile !== null) d.foreignProfile.validate();
  return new ResolvedDecision(d.decision, d.action, d.policy, policy.normalizeEffect(d.effect));
}

// =================================================================================================
// Evidence-record family (E6.3 egress-attestation + S1 decision-record + S3 checkpoint + R1/R8
// ordering-disclosure / foreign-profile-pin), ported from impl/go/gateway/{ordering,decision_record,
// checkpoint,egress_attestation}.go via the byte-verified impl/python template; graded against the
// shared vectors/{decision_record,checkpoint,egress_attestation}/cases.json plus gateway/cases.json's
// optional_fields{} block.
// =================================================================================================

// Return the CBOR value for integer key k in a decoded map's pairs list, or undefined if absent.
// Mirrors the Go embedded-field accessor field(m, k) / python _mfield: a key that is not a matching
// cbor.U simply does not match -- it never causes the whole map to be rejected.
function mfield(pairs, k) {
  const kk = BigInt(k);
  for (const [key, val] of pairs) {
    if (key instanceof U && key.v === kk) return val;
  }
  return undefined;
}

function concatBytes(...chunks) {
  let len = 0;
  for (const c of chunks) len += c.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

// Constant-time byte-array equality (mirrors python's hmac.compare_digest usage here); also used as
// the plain equality check for witness-root / inclusion-proof-root comparisons, where constant time
// is harmless and consistent.
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---- ordering-disclosure embeddable group (design.md section 26.3) ----------------------------
//
// `ordering-disclosure` states what, if anything, establishes decision->effect / record->event
// ORDER, and from which observational domain, rather than leaving the reader to assume more than
// the bytes support. It is carried as a field inside naalp-decision-record (mandatory, field 5),
// naalp-egress-attestation (optional, field 6), and naalp-gateway-decision (optional, field 5) --
// never as a top-level object of its own, so it has no head()/id() of its own; it is embedded
// directly as a nested CBOR map value inside its carrying record.
//
// correspondence-only (0) is the weakest claim and the value a verifier MUST read when the field is
// ABSENT on an optional carrier -- never a stronger claim inferred from silence. single-boundary (1)
// names one covering boundary. external-mechanism (2) names an external sequencing mechanism and,
// optionally, the log relation binding the record under it.
//
// Well-formedness is fail-closed and NATIVE: correspondence-only requires keys 2/3/4 absent;
// single-boundary requires key 2 present and 3/4 absent; external-mechanism requires key 3 present
// (4 optional) and key 2 absent. Any violation rejects the WHOLE carrying record
// (OrderingDisclosureMalformed).

export const ORDERING_CORRESPONDENCE_ONLY = 0; // the record orders only its own two-party construction (the weakest claim)
export const ORDERING_SINGLE_BOUNDARY = 1;     // one boundary observed both terms and is named
export const ORDERING_EXTERNAL_MECHANISM = 2;  // an external sequencing mechanism is named

const ORDERING_BASIS_NAMES = new Map([
  [ORDERING_CORRESPONDENCE_ONLY, 'correspondence-only'],
  [ORDERING_SINGLE_BOUNDARY, 'single-boundary'],
  [ORDERING_EXTERNAL_MECHANISM, 'external-mechanism'],
]);

// Reports whether code is one of the closed ordering-basis codes.
export function isKnownOrderingBasis(code) {
  return ORDERING_BASIS_NAMES.has(Number(code));
}

// The ordering-basis name, or 'unknown'.
export function orderingBasisName(code) {
  return ORDERING_BASIS_NAMES.get(Number(code)) ?? 'unknown';
}

// Enforcement-disposition codes -- the closed set (design.md section 26.4).
export const ENFORCEMENT_ENFORCED = 1; // the producer states it actually enforces this outcome
export const ENFORCEMENT_ADVISED = 2;  // the producer's own unverifiable self-account that it only advises

// Term-disposition kind codes -- reused unchanged from the section 2.5.4 producing-boundary kind
// vocabulary.
export const TERM_OBSERVED = 1; // the term was observed first-hand
export const TERM_REPORTED = 2; // the term was reported, relayed from a named source

const EMPTY = new Uint8Array(0);

// The embeddable group {1: basis, ?2: boundary, ?3: mechanism, ?4: relation} (design.md section
// 26.3). It is never a top-level signed object; it is always a field inside another record. The
// zero value (basis=correspondence-only, no boundary/mechanism/relation) is the weakest claim and
// is exactly what an ABSENT optional ordering-disclosure field reads as.
export class OrderingDisclosure {
  constructor(basis, boundary = EMPTY, mechanism = EMPTY, relation = EMPTY) {
    this.basis = basis;
    this.boundary = Uint8Array.from(boundary);
    this.mechanism = Uint8Array.from(mechanism);
    this.relation = Uint8Array.from(relation);
  }

  // Return self as a nested CBOR map VALUE (never top-level bytes -- self is always embedded as a
  // field inside its carrying record).
  toCbor() {
    const pairs = [[new U(1), new U(this.basis)]];
    if (this.boundary.length) pairs.push([new U(2), new B(this.boundary)]);
    if (this.mechanism.length) pairs.push([new U(3), new B(this.mechanism)]);
    if (this.relation.length) pairs.push([new U(4), new B(this.relation)]);
    return new M(pairs);
  }

  // Checks (a) basis is in the closed set (UnknownOrderingBasis) and (b) the basis-conditioned
  // field well-formedness rule (design.md section 26.3, native and fail-closed -- any violation
  // rejects the whole carrying record, OrderingDisclosureMalformed). UnknownOrderingBasis is
  // checked and raised FIRST: an out-of-set basis is never additionally reported as malformed.
  validate() {
    const basis = Number(this.basis);
    if (!isKnownOrderingBasis(basis)) {
      throw new GatewayError('UnknownOrderingBasis',
        'ordering-disclosure basis is outside the closed set correspondence-only/single-boundary/external-mechanism');
    }
    if (basis === ORDERING_CORRESPONDENCE_ONLY) {
      if (this.boundary.length || this.mechanism.length || this.relation.length) {
        throw new GatewayError('OrderingDisclosureMalformed', 'correspondence-only requires keys 2/3/4 absent');
      }
    } else if (basis === ORDERING_SINGLE_BOUNDARY) {
      if (!this.boundary.length || this.mechanism.length || this.relation.length) {
        throw new GatewayError('OrderingDisclosureMalformed', 'single-boundary requires key 2 present, keys 3/4 absent');
      }
    } else if (basis === ORDERING_EXTERNAL_MECHANISM) {
      if (this.boundary.length || !this.mechanism.length) {
        throw new GatewayError('OrderingDisclosureMalformed', 'external-mechanism requires key 2 absent, key 3 present');
      }
    }
  }
}

// The weakest ordering-disclosure claim, exactly what a verifier reads for an absent optional
// ordering-disclosure field.
export function correspondenceOnly() {
  return new OrderingDisclosure(ORDERING_CORRESPONDENCE_ONLY);
}

// Decode a nested ordering-disclosure map value. Returns null on any wrong shape, including an
// optional key present under the WRONG CBOR type (never silently treated as absent).
function orderingFromCbor(v) {
  if (!(v instanceof M)) return null;
  const basisV = mfield(v.pairs, 1);
  if (!(basisV instanceof U)) return null;
  let boundary = EMPTY, mechanism = EMPTY, relation = EMPTY;
  const v2 = mfield(v.pairs, 2);
  if (v2 !== undefined) { if (!(v2 instanceof B)) return null; boundary = v2.v; }
  const v3 = mfield(v.pairs, 3);
  if (v3 !== undefined) { if (!(v3 instanceof B)) return null; mechanism = v3.v; }
  const v4 = mfield(v.pairs, 4);
  if (v4 !== undefined) { if (!(v4 instanceof B)) return null; relation = v4.v; }
  return new OrderingDisclosure(basisV.v, boundary, mechanism, relation);
}

// The embeddable group {1: kind, ?2: source} (design.md section 26.4). `kind` is carried as a
// plain uint on the wire (the CDDL does not close its value set the way ordering-basis does), so
// TermDisposition itself validates no closed set -- only naalp-decision-record's own field-6 key
// set (the record's own field numbers) is fail-closed (TermDispositionMalformed).
export class TermDisposition {
  constructor(kind, source = EMPTY) {
    this.kind = kind;
    this.source = Uint8Array.from(source);
  }

  toCbor() {
    const pairs = [[new U(1), new U(this.kind)]];
    if (this.source.length) pairs.push([new U(2), new B(this.source)]);
    return new M(pairs);
  }
}

// Decode a nested term-disposition map value. Returns null on any wrong shape.
function termDispositionFromCbor(v) {
  if (!(v instanceof M)) return null;
  const kindV = mfield(v.pairs, 1);
  if (!(kindV instanceof U)) return null;
  let source = EMPTY;
  const v2 = mfield(v.pairs, 2);
  if (v2 !== undefined) { if (!(v2 instanceof B)) return null; source = v2.v; }
  return new TermDisposition(kindV.v, source);
}

// ---- ForeignProfilePin: GatewayDecision field 6, R8 --------------------------------------------

// The embeddable group {1: id, 2: revision} (naalp-foreign-profile-pin, R8). Present on
// GatewayDecision field 6 iff the decision was over foreign-protocol evidence: it pins the foreign
// evidence profile's identifier (an absolute URI) AND the revision pinned at decision time --
// binding the reference, not just the class. Both fields are mandatory tstr; the group carries no
// other keys. It is never a top-level signed object -- always embedded as field 6 of its carrying
// naalp-gateway-decision, so it has no head()/id() of its own (mirroring OrderingDisclosure).
export class ForeignProfilePin {
  constructor(id = '', revision = '', unknownField = false) {
    this.id = id;
    this.revision = revision;
    this._unknownField = unknownField;
  }

  // Return self as a nested CBOR map VALUE {1: tstr(id), 2: tstr(revision)}.
  toCbor() {
    return new M([[new U(1), new T(this.id)], [new U(2), new T(this.revision)]]);
  }

  // Checks the foreign-profile-pin's own well-formedness (R8): both id and revision are mandatory
  // non-empty tstr, and no key besides 1/2 may be present. A missing, empty, or extra field
  // rejects the WHOLE carrying naalp-gateway-decision (ForeignProfileMalformed).
  validate() {
    if (!this.id || !this.revision || this._unknownField) {
      throw new GatewayError('ForeignProfileMalformed',
        'foreign-profile-pin is not well-formed (id and revision are mandatory tstr, no other keys)');
    }
  }
}

// Decode a nested foreign-profile-pin map value. Decode is STRUCTURAL only, mirroring
// orderingFromCbor: a key present under the WRONG CBOR type fails decode (returns null, never
// silently treated as absent); a key that is simply ABSENT decodes to the empty string, leaving the
// mandatory-presence check to validate() (mirroring OrderingDisclosure's own decode/validate
// split). A key besides 1/2 marks the group's unknown-field flag, also caught by validate() -- the
// closed 2-key set is enforced semantically, not by refusing to decode a map that merely carries an
// extra key.
function foreignProfileFromCbor(v) {
  if (!(v instanceof M)) return null;
  let id = '';
  const v1 = mfield(v.pairs, 1);
  if (v1 !== undefined) { if (!(v1 instanceof T)) return null; id = v1.v; }
  let revision = '';
  const v2 = mfield(v.pairs, 2);
  if (v2 !== undefined) { if (!(v2 instanceof T)) return null; revision = v2.v; }
  let unknown = false;
  for (const [k] of v.pairs) {
    if (!(k instanceof U && (k.v === 1n || k.v === 2n))) { unknown = true; break; }
  }
  return new ForeignProfilePin(id, revision, unknown);
}

// ---- naalp-decision-record: S1, the full governed-decision accountability record --------------
//
// A DecisionRecord is the SIGNED record a governed decision point emits that it decided about an
// action under a CLOSED, uniquely-selected condition set. It carries the T/T+n accountability
// triple (section 26.1): UNIQUE SELECTION (field 2, the governing set in the clear as content ids);
// GOVERNED-AT-T (field 3, the naalp-consume-receipt spent at decision time); BINDING-FIXED-BY-T
// (established off-record by inclusion under a witnessed naalp-checkpoint-root). The record is
// deliberately CLOCK-FREE: it carries no claimed timestamp anywhere in its own body; both time
// properties are POSITIONAL, never a self-asserted timestamp. It introduces no new envelope,
// encoding, signature, or identity mechanism: an ordinary N-AALP signed body (COSE_Sign1), reusing
// the closed gw-decision outcome vocabulary unchanged.
//
// Following parseDecision/verifyDecision's split: parseDecisionRecord reconstructs the record from
// its body bytes ALONE and performs only STRUCTURAL checks (field presence and CBOR type); it does
// NOT validate the outcome against the closed gw-decision set, the ordering disclosure's
// well-formedness, the deny/hold-with-consume rule, or the terms key set -- those are
// validateDecisionRecord's job.

// The governed-decision accountability record (design.md section 26.4). `action` is the content id
// of the action decided about; `governing` is the closed governing condition set, content ids, in
// the clear (may be empty); `consume` is OPTIONAL field 3 (content id of the consume-receipt spent
// at decision time; empty == absent); `outcome` is field 4 (allow/deny/hold, reuses the closed
// gw-decision set); `ordering` is field 5, MANDATORY (no silent default -- every record states its
// ordering basis); `terms` is OPTIONAL field 6 (per-term observed/reported, keyed by this record's
// OWN field numbers 1..5 as a Map<number, TermDisposition>; empty == absent); `enforcement` is
// OPTIONAL field 7 (enforced(1)/advised(2); 0 == absent).
export class DecisionRecord {
  constructor(action, governing, outcome, ordering, consume = EMPTY, terms = null, enforcement = 0) {
    this.action = Uint8Array.from(action);
    this.governing = governing.map((g) => Uint8Array.from(g));
    this.consume = Uint8Array.from(consume);
    this.outcome = outcome;
    this.ordering = ordering;
    this.terms = terms ? new Map(terms) : new Map();
    this.enforcement = enforcement;
  }

  // Deterministic-CBOR encoding {1:action, 2:governing[], ?3:consume, 4:outcome, 5:ordering,
  // ?6:terms, ?7:enforcement}. Fields 3/6/7 are OMITTED when absent (consume empty, terms empty,
  // enforcement zero) -- the omit-when-absent precedent (naalp-approval ?6:audience).
  bytes() {
    const pairs = [
      [new U(1), new B(this.action)],
      [new U(2), new A(this.governing.map((g) => new B(g)))],
    ];
    if (this.consume.length) pairs.push([new U(3), new B(this.consume)]);
    pairs.push([new U(4), new U(this.outcome)]);
    pairs.push([new U(5), this.ordering.toCbor()]);
    if (this.terms.size) {
      const termPairs = [];
      for (const [k, td] of this.terms) termPairs.push([new U(k), td.toCbor()]);
      pairs.push([new U(6), new M(termPairs)]);
    }
    if (this.enforcement) pairs.push([new U(7), new U(this.enforcement)]);
    return cbor.encode(new M(pairs));
  }

  // The record's SHA-384 head (48 octets).
  head() { return sha384(this.bytes()); }

  // The record's T1 content-id (50 octets).
  id() { return cbor.contentId(this.bytes()); }
}

// Reconstruct a DecisionRecord from its body bytes alone. It performs ONLY structural checks
// (mandatory-field presence and CBOR type); it does NOT validate the outcome against the closed
// gw-decision set, the ordering disclosure's basis-conditioned well-formedness, the
// deny/hold-with-consume rule, or the terms key set -- see validateDecisionRecord. Fail-closed on
// any malformed shape (DecisionMalformed).
export function parseDecisionRecord(b) {
  let v;
  try {
    v = cbor.decode(b);
  } catch (e) {
    if (e instanceof cbor.NonCanonical) {
      throw new GatewayError('DecisionMalformed', 'decision-record body is not well-formed deterministic CBOR');
    }
    throw e;
  }
  if (!(v instanceof M)) throw new GatewayError('DecisionMalformed', 'decision-record body is not a map');
  const action = mfield(v.pairs, 1);
  const govV = mfield(v.pairs, 2);
  if (!(action instanceof B) || !(govV instanceof A)) {
    throw new GatewayError('DecisionMalformed', 'missing or wrong-typed field 1/2');
  }
  const governing = [];
  for (const e of govV.items) {
    if (!(e instanceof B)) throw new GatewayError('DecisionMalformed', 'governing array element not a bstr');
    governing.push(e.v);
  }
  let consume = EMPTY;
  const consumeV = mfield(v.pairs, 3);
  if (consumeV !== undefined) {
    if (!(consumeV instanceof B)) throw new GatewayError('DecisionMalformed', 'field 3 (consume) wrong type');
    consume = consumeV.v;
  }
  const outcomeV = mfield(v.pairs, 4);
  if (!(outcomeV instanceof U)) throw new GatewayError('DecisionMalformed', 'missing or wrong-typed field 4 (outcome)');
  const ordV = mfield(v.pairs, 5);
  if (ordV === undefined) throw new GatewayError('DecisionMalformed', 'missing mandatory field 5 (ordering)');
  const ordering = orderingFromCbor(ordV);
  if (ordering === null) throw new GatewayError('DecisionMalformed', 'field 5 (ordering) malformed');
  const terms = new Map();
  const termsV = mfield(v.pairs, 6);
  if (termsV !== undefined) {
    if (!(termsV instanceof M)) throw new GatewayError('DecisionMalformed', 'field 6 (terms) wrong type');
    for (const [k, val] of termsV.pairs) {
      if (!(k instanceof U)) throw new GatewayError('DecisionMalformed', 'terms map key not a uint');
      const td = termDispositionFromCbor(val);
      if (td === null) throw new GatewayError('DecisionMalformed', 'terms map value malformed');
      terms.set(Number(k.v), td);
    }
  }
  let enforcement = 0;
  const enfV = mfield(v.pairs, 7);
  if (enfV !== undefined) {
    if (!(enfV instanceof U)) throw new GatewayError('DecisionMalformed', 'field 7 (enforcement) wrong type');
    enforcement = enfV.v;
  }
  return new DecisionRecord(action.v, governing, outcomeV.v, ordering, consume, terms, enforcement);
}

// Reports whether k is one of the record's own field numbers 1..5 -- the only valid keys for the
// field-6 terms map (design.md section 26.4; TermDispositionMalformed otherwise).
function isValidDecisionRecordTermKey(k) {
  const kk = Number(k);
  return kk >= 1 && kk <= 5;
}

// Performs the semantic, closed-set, and native well-formedness checks parseDecisionRecord
// deliberately does not (mirroring verifyDecision's parse/validate split):
//
// 1. Outcome must be in the closed gw-decision set (UnknownGatewayDecision).
// 2. Ordering must satisfy its basis-conditioned well-formedness rule (UnknownOrderingBasis /
//    OrderingDisclosureMalformed) -- checked BEFORE the deny/hold-consume rule so a record whose
//    ordering is itself malformed is never additionally reported as a consume violation.
// 3. A deny/hold outcome carrying a field-3 consume reference is rejected in full
//    (DecisionMalformed) -- nothing was consumed, so a value here would assert authority spent for
//    an action the record's own outcome says was not taken.
// 4. Every terms map key must be one of the record's own field numbers 1..5
//    (TermDispositionMalformed).
export function validateDecisionRecord(d) {
  if (!isKnownDecision(d.outcome)) {
    throw new GatewayError('UnknownGatewayDecision', 'decision-record outcome ' + d.outcome + ' outside the closed set');
  }
  d.ordering.validate();
  if (Number(d.outcome) !== DECISION_ALLOW && d.consume.length) {
    throw new GatewayError('DecisionMalformed', 'a deny/hold outcome must not carry a field-3 consume reference');
  }
  for (const k of d.terms.keys()) {
    if (!isValidDecisionRecordTermKey(k)) {
      throw new GatewayError('TermDispositionMalformed', "a terms map key is outside the record's own field set 1..5");
    }
  }
}

// Produce the tagged COSE_Sign1 object over the record body, signed by the governed decision point.
export function signDecisionRecord(d, alg, seed) {
  return cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), d.bytes());
}

// A DecisionRecord that has passed signature verification and full semantic validation.
export class ResolvedDecisionRecord {
  constructor(action, governing, consume, outcome, ordering, terms, enforcement) {
    this.action = Uint8Array.from(action);
    this.governing = governing.map((g) => Uint8Array.from(g));
    this.consume = Uint8Array.from(consume);
    this.outcome = outcome;
    this.ordering = ordering;
    this.terms = new Map(terms);
    this.enforcement = enforcement;
  }
}

// Verify a decision record end-to-end: (1) the signed object under the profile with real crypto;
// (2) structural reconstruction (parseDecisionRecord); and (3) full semantic validation
// (validateDecisionRecord). It takes no serving-party or connection identity -- the authority is
// the signature over the bytes, mirroring verifyDecision. Any failure throws its named error and
// resolves nothing (fail-closed).
export function verifyDecisionRecord(obj, profile, alg, pubkey) {
  const [prot, payload, sig] = cose.parseSign1Raw(obj);
  const halg = algFromProtected(prot);
  const [level, known] = cose.algLevel(halg);
  if (!known) throw new GatewayError('UnknownAlg', 'unregistered alg ' + halg);
  if (level < cose.profileMinLevel(profile)) {
    throw new GatewayError('ProfileDowngrade', 'signature level below the profile minimum');
  }
  if (halg !== Number(alg)) {
    throw new GatewayError('KeyAlgMismatch', 'alg ' + halg + ' does not match the verifier key alg ' + alg);
  }
  const tbs = cose.toBeSignedRaw(prot, payload);
  if (!cose.coseVerify1Raw(halg, pubkey, tbs, sig)) {
    throw new GatewayError('BadSignature', 'signature does not verify');
  }
  const d = parseDecisionRecord(payload);
  validateDecisionRecord(d);
  return new ResolvedDecisionRecord(d.action, d.governing, d.consume, d.outcome, d.ordering, d.terms, d.enforcement);
}

// ---- naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof: S3 -------------------
//
// S3 is the neither-party anchor for the BINDING-FIXED-BY-T leg of the accountability triple
// (design.md section 26.5). Tree construction follows RFC 9162
// (https://www.rfc-editor.org/rfc/rfc9162.html) section 2.1 EXACTLY, SHA-384-profiled: leaf hash =
// HASH(0x00 || leaf); interior node hash = HASH(0x01 || left || right); MTH({}) = HASH() (the empty
// hash); MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the largest
// power of two k < n. Section 2.1.2's PATH(m, D[n]) recursion (leaf-to-root sibling order) generates
// the audit path; section 2.1.3.1's inverse recursion recomputes the root from (leaf, index, size,
// path) and compares against the named root (InclusionProofInvalid on mismatch, fail-closed).
//
// naalp-checkpoint-root is a log operator's signed Merkle tree head over a leaf set of record
// content ids, chaining by `prev` (genesis = HEAD_SIZE zero bytes). naalp-witness-cosign carries the
// wire hook for an independent countersignature over one exact checkpoint by content id;
// naalp-inclusion-proof proves one record's content id was a leaf under a named checkpoint. Two
// witness-cosigned roots at one (log, size) carrying different root values are fork evidence.

// A log operator's signed Merkle tree head over a leaf set of record content ids (design.md
// section 26.5).
export class CheckpointRoot {
  constructor(log, size, root, prev, at) {
    this.log = Uint8Array.from(log);
    this.size = Number(size);
    this.root = Uint8Array.from(root);
    this.prev = Uint8Array.from(prev);
    this.at = BigInt(at);
  }

  // Deterministic-CBOR encoding {1:log, 2:size, 3:root, 4:prev, 5:at}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.log)],
      [new U(2), new U(this.size)],
      [new U(3), new B(this.root)],
      [new U(4), new B(this.prev)],
      [new U(5), new U(this.at)],
    ]));
  }

  // The checkpoint's SHA-384 head (48 octets) -- the `prev` the NEXT checkpoint chains from.
  head() { return sha384(this.bytes()); }

  // The checkpoint's T1 content-id (50 octets) -- what an inclusion proof's `root` field and a
  // witness-cosign's `root` field both name.
  id() { return cbor.contentId(this.bytes()); }
}

// The HEAD_SIZE all-zero prev value a log's first checkpoint chains from.
export function genesisPrev() {
  return new Uint8Array(HEAD_SIZE);
}

// Reconstruct a CheckpointRoot from its body bytes alone. Fail-closed on any malformed shape
// (CheckpointMalformed): every one of the five fields is mandatory.
export function parseCheckpointRoot(b) {
  let v;
  try {
    v = cbor.decode(b);
  } catch (e) {
    if (e instanceof cbor.NonCanonical) {
      throw new GatewayError('CheckpointMalformed', 'checkpoint-root body is not well-formed deterministic CBOR');
    }
    throw e;
  }
  if (!(v instanceof M)) throw new GatewayError('CheckpointMalformed', 'checkpoint-root body is not a map');
  const log = mfield(v.pairs, 1);
  const size = mfield(v.pairs, 2);
  const root = mfield(v.pairs, 3);
  const prev = mfield(v.pairs, 4);
  const at = mfield(v.pairs, 5);
  if (!(log instanceof B) || !(size instanceof U) || !(root instanceof B) || !(prev instanceof B) || !(at instanceof U)) {
    throw new GatewayError('CheckpointMalformed', 'missing or wrong-typed field 1-5');
  }
  return new CheckpointRoot(log.v, size.v, root.v, prev.v, at.v);
}

// Produce the tagged COSE_Sign1 object over the checkpoint body, signed by the log operator.
export function signCheckpointRoot(c, alg, seed) {
  return cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), c.bytes());
}

// A witness's countersignature over one exact checkpoint by content id (design.md section 26.5).
// Whether the witness's observational domain is genuinely distinct from both parties to the
// decisions the checkpoint covers is a structural deployment fact checkable in substance at T+n --
// the wire supplies the hook; it does not manufacture the independence itself.
export class WitnessCosign {
  constructor(witness, root, at) {
    this.witness = Uint8Array.from(witness);
    this.root = Uint8Array.from(root);
    this.at = BigInt(at);
  }

  // Deterministic-CBOR encoding {1:witness, 2:root, 3:at}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.witness)],
      [new U(2), new B(this.root)],
      [new U(3), new U(this.at)],
    ]));
  }

  // The cosign's SHA-384 head (48 octets).
  head() { return sha384(this.bytes()); }

  // The cosign's T1 content-id (50 octets).
  id() { return cbor.contentId(this.bytes()); }
}

// Reconstruct a WitnessCosign from its body bytes alone. Fail-closed on any malformed shape: every
// one of the three fields is mandatory.
export function parseWitnessCosign(b) {
  let v;
  try {
    v = cbor.decode(b);
  } catch (e) {
    if (e instanceof cbor.NonCanonical) {
      throw new GatewayError('CheckpointMalformed', 'witness-cosign body is not well-formed deterministic CBOR');
    }
    throw e;
  }
  if (!(v instanceof M)) throw new GatewayError('CheckpointMalformed', 'witness-cosign body is not a map');
  const witness = mfield(v.pairs, 1);
  const root = mfield(v.pairs, 2);
  const at = mfield(v.pairs, 3);
  if (!(witness instanceof B) || !(root instanceof B) || !(at instanceof U)) {
    throw new GatewayError('CheckpointMalformed', 'missing or wrong-typed field 1-3');
  }
  return new WitnessCosign(witness.v, root.v, at.v);
}

// Produce the tagged COSE_Sign1 object over the cosign body, signed by the witness.
export function signWitnessCosign(w, alg, seed) {
  return cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), w.bytes());
}

// Checks that w names the EXACT checkpoint it accompanies (WitnessRootMismatch, design.md section
// 26.5): w.root must equal accompaniedCheckpointId, the content id of the naalp-checkpoint-root
// object w claims to cosign. Fail-closed.
export function validateWitnessCosign(w, accompaniedCheckpointId) {
  if (!constantTimeEqual(w.root, accompaniedCheckpointId)) {
    throw new GatewayError('WitnessRootMismatch',
      'witness-cosign names a root content id that does not match the checkpoint it accompanies');
  }
}

// Proves one record's content id existed as a leaf under a named checkpoint (design.md section
// 26.5, RFC 9162 section 2.1.3.1).
export class InclusionProof {
  constructor(root, leaf, index, path) {
    this.root = Uint8Array.from(root);
    this.leaf = Uint8Array.from(leaf);
    this.index = Number(index);
    this.path = path.map((p) => Uint8Array.from(p));
  }

  // Deterministic-CBOR encoding {1:root, 2:leaf, 3:index, 4:path[]}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.root)],
      [new U(2), new B(this.leaf)],
      [new U(3), new U(this.index)],
      [new U(4), new A(this.path.map((p) => new B(p)))],
    ]));
  }

  // The proof's SHA-384 head (48 octets).
  head() { return sha384(this.bytes()); }

  // The proof's T1 content-id (50 octets).
  id() { return cbor.contentId(this.bytes()); }
}

// Reconstruct an InclusionProof from its body bytes alone. Fail-closed on any malformed shape:
// every one of the four fields is mandatory.
export function parseInclusionProof(b) {
  let v;
  try {
    v = cbor.decode(b);
  } catch (e) {
    if (e instanceof cbor.NonCanonical) {
      throw new GatewayError('CheckpointMalformed', 'inclusion-proof body is not well-formed deterministic CBOR');
    }
    throw e;
  }
  if (!(v instanceof M)) throw new GatewayError('CheckpointMalformed', 'inclusion-proof body is not a map');
  const root = mfield(v.pairs, 1);
  const leaf = mfield(v.pairs, 2);
  const index = mfield(v.pairs, 3);
  const pathV = mfield(v.pairs, 4);
  if (!(root instanceof B) || !(leaf instanceof B) || !(index instanceof U) || !(pathV instanceof A)) {
    throw new GatewayError('CheckpointMalformed', 'missing or wrong-typed field 1-4');
  }
  const path = [];
  for (const e of pathV.items) {
    if (!(e instanceof B)) throw new GatewayError('CheckpointMalformed', 'path array element not a bstr');
    path.push(e.v);
  }
  return new InclusionProof(root.v, leaf.v, index.v, path);
}

// ---- RFC 9162 section 2.1 Merkle tree math (SHA-384-profiled) ----------------------------------

// leafHash = HASH(0x00 || leaf) (RFC 9162 section 2.1's LEAF_HASH, leaf/interior domain
// separation).
function leafHash(leaf) {
  return sha384(concatBytes(Uint8Array.of(0x00), Uint8Array.from(leaf)));
}

// nodeHash = HASH(0x01 || left || right) (RFC 9162 section 2.1's NODE_HASH).
function nodeHash(l, r) {
  return sha384(concatBytes(Uint8Array.of(0x01), Uint8Array.from(l), Uint8Array.from(r)));
}

// The largest power of two strictly less than n (n > 1), per RFC 9162 section 2.1's k = "the
// largest power of two smaller than n".
function largestPowerOfTwoLessThan(n) {
  let k = 1;
  while (2 * k < n) k *= 2;
  return k;
}

// Computes MTH(leaves) per RFC 9162 section 2.1: MTH({}) = HASH() (SHA-384 of the empty string);
// MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the largest power
// of two k < n. leaves are raw leaf VALUES (record content ids); LEAF_HASH is applied internally --
// callers never hash a leaf before calling merkleRoot. `leaves=null` is accepted as the empty list
// (mirroring Go's nil-slice-len-0 semantics for MerkleRoot(nil)).
export function merkleRoot(leaves) {
  const n = leaves == null ? 0 : leaves.length;
  if (n === 0) return sha384(EMPTY); // MTH({}) = HASH(""), the empty-list base case
  if (n === 1) return leafHash(leaves[0]);
  const k = largestPowerOfTwoLessThan(n);
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

// Internal sentinel: the recursive root recomputation ran out of path entries (or had entries left
// over) before reaching the single-leaf base case. Always surfaced to callers as
// InclusionProofInvalid -- never exported.
class PathLengthMismatch extends Error {}

// Computes the RFC 9162 section 2.1.2 PATH(index, leaves) audit path (leaf-to-root sibling order --
// the list's FIRST entry is the leaf's immediate sibling, the LAST is closest to the root, exactly
// the order naalp-inclusion-proof's `path` field carries).
export function generateInclusionProofPath(leaves, index) {
  if (index < 0 || index >= leaves.length) {
    throw new GatewayError('InclusionProofInvalid', 'leaf index out of range');
  }
  return genPath(leaves, index);
}

function genPath(leaves, index) {
  const n = leaves.length;
  if (n <= 1) return []; // PATH(0, {d0}) = {} -- the single-leaf base case
  const k = largestPowerOfTwoLessThan(n);
  if (index < k) {
    const sub = genPath(leaves.slice(0, k), index);
    return [...sub, merkleRoot(leaves.slice(k))];
  }
  const sub = genPath(leaves.slice(k), index - k);
  return [...sub, merkleRoot(leaves.slice(0, k))];
}

// The exact structural inverse of genPath: at each level it consumes the LAST remaining path entry
// (closest to the root) as this level's sibling and recurses into the appropriate half with the
// entries that remain.
function recomputeRoot(leafH, index, size, path) {
  if (size === 1) {
    if (path.length !== 0) throw new PathLengthMismatch();
    return leafH;
  }
  if (path.length === 0) throw new PathLengthMismatch();
  const k = largestPowerOfTwoLessThan(size);
  const last = path[path.length - 1];
  const rest = path.slice(0, -1);
  if (index < k) {
    const left = recomputeRoot(leafH, index, k, rest);
    return nodeHash(left, last);
  }
  const right = recomputeRoot(leafH, index - k, size - k, rest);
  return nodeHash(last, right);
}

// Recomputes the audit path bottom-up (RFC 9162 section 2.1.3.1, the inverse of PATH()) from
// (leaf, index, size, path) and compares the result against root. `size` is the tree size the
// proof is checked against -- the resolved naalp-checkpoint-root's own `size` field, NOT carried
// inside naalp-inclusion-proof itself (the proof names the checkpoint by content id; the verifier
// is expected to already hold the resolved checkpoint to learn its size). Fail-closed: any
// mismatch, out-of-range index, or path-length mismatch is InclusionProofInvalid.
export function verifyInclusionProof(leaf, index, size, path, root) {
  if (size === 0 || index >= size) {
    throw new GatewayError('InclusionProofInvalid', 'index out of range for the claimed tree size');
  }
  let got;
  try {
    got = recomputeRoot(leafHash(leaf), index, size, Array.from(path));
  } catch (e) {
    if (e instanceof PathLengthMismatch) {
      throw new GatewayError('InclusionProofInvalid', 'inclusion path length does not match the claimed tree size');
    }
    throw e;
  }
  if (!constantTimeEqual(got, Uint8Array.from(root))) {
    throw new GatewayError('InclusionProofInvalid', 'inclusion audit path does not recompute to the named root');
  }
}

// ---- naalp-egress-attestation: E6.3 --------------------------------------------------------------
//
// A naalp-egress-attestation is a SIGNED attestation a gateway/sidecar emits that an object of a
// given effect class, bound to a given audience, crossed an egress boundary at a given time --
// third-party verifiable WITHOUT the payload. It is a near-clone of GatewayDecision: the gateway is
// the SIGNER, and verifyEgressAttestation takes NO serving-party or connection identity -- the
// authority is the signature over the bytes, so the identical attested evidence re-verifies whether
// the gateway or an unrelated third party serves it. `binding` is a closed set
// (content_bound/content_free); `digest` is either the T1 content-id of the crossed object
// (content_bound) or a hiding commitment SHA-384(content_id||salt) (content_free) -- never both;
// `effect` is the C5 effect class of the crossed object; `audience` is the bound destination
// (empty-permitted); `at` is the crossing time in epoch milliseconds. Field 6 (`ordering`) is
// OPTIONAL: ABSENT reads correspondence-only, never a stronger claim inferred from silence.
//
// The content_free binding lets a gateway attest an egress crossing WITHOUT disclosing which object
// crossed. egressCommit/openEgressCommitment is the open/verify pair: the gateway (or anyone it
// later discloses content-id+salt to) can PROVE which object a content_free attestation names,
// without the attestation bytes themselves ever carrying the content-id.

export const BINDING_CONTENT_BOUND = 0; // digest is the crossed object's T1 content-id
export const BINDING_CONTENT_FREE = 1;  // digest is a hiding commitment SHA-384(content_id||salt)

const BINDING_NAMES = new Map([[BINDING_CONTENT_BOUND, 'content_bound'], [BINDING_CONTENT_FREE, 'content_free']]);

// Reports whether code is one of the closed binding codes.
export function isKnownBinding(code) {
  return BINDING_NAMES.has(Number(code));
}

// The binding name, or 'unknown'.
export function bindingName(code) {
  return BINDING_NAMES.get(Number(code)) ?? 'unknown';
}

// A signed attestation a gateway/sidecar emits that an object crossed an egress boundary.
// `binding` selects how `digest` is interpreted (content_bound: the crossed object's T1
// content-id; content_free: a hiding commitment). `effect` is the crossed object's C5 effect
// class. `audience` is the bound destination (empty-permitted). `at` is the crossing time, epoch
// ms. `ordering` is the OPTIONAL field 6: null == ABSENT (reads correspondence-only).
export class EgressAttestation {
  constructor(binding, digest, effect, audience, at, ordering = null) {
    this.binding = binding;
    this.digest = Uint8Array.from(digest);
    this.effect = effect;
    this.audience = Uint8Array.from(audience);
    this.at = BigInt(at);
    this.ordering = ordering;
  }

  // Deterministic-CBOR encoding {1:binding, 2:digest, 3:effect, 4:audience, 5:at, ?6:ordering}.
  // Field 6 is OMITTED when `ordering` is null.
  bytes() {
    const pairs = [
      [new U(1), new U(this.binding)],
      [new U(2), new B(this.digest)],
      [new U(3), new U(this.effect)],
      [new U(4), new B(this.audience)],
      [new U(5), new U(this.at)],
    ];
    if (this.ordering !== null) pairs.push([new U(6), this.ordering.toCbor()]);
    return cbor.encode(new M(pairs));
  }

  // The attestation's SHA-384 head (48 octets).
  head() { return sha384(this.bytes()); }

  // The attestation's T1 content-id (50 octets).
  id() { return cbor.contentId(this.bytes()); }

  // The attestation's C5 effect class, normalized fail-closed: a value the evaluator does not
  // recognize is treated as destructive, never as a weaker class.
  effectClass() { return policy.normalizeEffect(this.effect); }
}

// Reconstruct an EgressAttestation from its body bytes alone. It does NOT validate the binding
// code against the closed set -- that is verifyEgressAttestation's job -- so an attestation
// carrying an unknown binding can be represented (and then rejected). Fail-closed on a malformed
// shape: every one of the five mandatory fields is required, and a present-but-wrong-typed field
// 6 fails here too.
export function parseEgressAttestation(b) {
  let v;
  try {
    v = cbor.decode(b);
  } catch (e) {
    if (e instanceof cbor.NonCanonical) {
      throw new GatewayError('EgMalformed', 'egress-attestation body is not well-formed deterministic CBOR');
    }
    throw e;
  }
  if (!(v instanceof M)) throw new GatewayError('EgMalformed', 'egress-attestation body is not a map');
  const binding = mfield(v.pairs, 1);
  const digest = mfield(v.pairs, 2);
  const effect = mfield(v.pairs, 3);
  const audience = mfield(v.pairs, 4);
  const at = mfield(v.pairs, 5);
  if (!(binding instanceof U) || !(digest instanceof B) || !(effect instanceof U)
      || !(audience instanceof B) || !(at instanceof U)) {
    throw new GatewayError('EgMalformed', 'missing or wrong-typed field 1-5');
  }
  let ordering = null;
  const ordV = mfield(v.pairs, 6);
  if (ordV !== undefined) {
    ordering = orderingFromCbor(ordV);
    if (ordering === null) throw new GatewayError('EgMalformed', 'field 6 (ordering) is present but malformed');
  }
  return new EgressAttestation(binding.v, digest.v, effect.v, audience.v, at.v, ordering);
}

// Produce the tagged COSE_Sign1 object over the attestation body, signed by the gateway.
export function signEgressAttestation(a, alg, seed) {
  return cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), a.bytes());
}

// An EgressAttestation that has passed signature verification. It carries NOTHING about WHO served
// the bytes -- the authority is the signature, so the resolved evidence is identical regardless of
// the serving party (the third-party re-serve property).
export class ResolvedEgressAttestation {
  constructor(binding, digest, effect, audience, at, ordering) {
    this.binding = binding;
    this.digest = Uint8Array.from(digest);
    this.effect = effect;
    this.audience = Uint8Array.from(audience);
    this.at = BigInt(at);
    this.ordering = ordering;
  }
}

// Performs the semantic, closed-set checks parseEgressAttestation deliberately does not: the
// binding must be in the closed set (UnknownEgressBinding), and -- if present -- the field-6
// ordering disclosure must satisfy its basis-conditioned well-formedness rule
// (UnknownOrderingBasis/OrderingDisclosureMalformed).
export function validateEgressAttestation(a) {
  if (!isKnownBinding(a.binding)) {
    throw new GatewayError('UnknownEgressBinding',
      'egress attestation binding code is outside the closed set content_bound/content_free');
  }
  if (a.ordering !== null) a.ordering.validate();
}

// Verifies an egress attestation end-to-end and returns the resolved evidence. It (1) verifies the
// signed object under the profile with real crypto against the GATEWAY's key; (2) reconstructs it
// from the signed bytes; and (3) validates the binding code against the closed set
// (UnknownEgressBinding), and the ordering disclosure if present. It takes NO serving-party or
// connection identity: the authority is the signature over the bytes, so the same `obj` yields an
// identical ResolvedEgressAttestation whether the gateway or an unrelated third party served it
// (the third-party re-serve property). Any failure throws its named error and resolves nothing
// (fail-closed).
export function verifyEgressAttestation(obj, profile, alg, pubkey) {
  const [prot, payload, sig] = cose.parseSign1Raw(obj);
  const halg = algFromProtected(prot);
  const [level, known] = cose.algLevel(halg);
  if (!known) throw new GatewayError('UnknownAlg', 'unregistered alg ' + halg);
  if (level < cose.profileMinLevel(profile)) {
    throw new GatewayError('ProfileDowngrade', 'signature level below the profile minimum');
  }
  if (halg !== Number(alg)) {
    throw new GatewayError('KeyAlgMismatch', 'alg ' + halg + ' does not match the verifier key alg ' + alg);
  }
  const tbs = cose.toBeSignedRaw(prot, payload);
  if (!cose.coseVerify1Raw(halg, pubkey, tbs, sig)) {
    throw new GatewayError('BadSignature', 'signature does not verify');
  }
  const a = parseEgressAttestation(payload);
  validateEgressAttestation(a);
  return new ResolvedEgressAttestation(a.binding, a.digest, policy.normalizeEffect(a.effect), a.audience, a.at, a.ordering);
}

// ---- content_free commitment open/verify pair --------------------------------------------------

// The content_free hiding commitment over an object's T1 content-id and a salt:
// SHA-384(object_cid || salt) (48 octets). The commitment reveals nothing about object_cid without
// the salt; a gateway builds it once to populate a content_free attestation's `digest` field, and
// retains object_cid+salt to later prove which object crossed via openEgressCommitment.
export function egressCommit(objectCid, salt) {
  return sha384(concatBytes(Uint8Array.from(objectCid), Uint8Array.from(salt)));
}

// Proves which object crossed under a content_free attestation. It recomputes
// egressCommit(objectCid, salt) and compares it, in constant time, against `a.digest`. Returns true
// iff `a` is a content_free attestation AND the recomputed commitment matches: a wrong salt or a
// wrong objectCid both fail to open (return false), and a content_bound attestation never opens
// (its digest is not a commitment).
export function openEgressCommitment(a, objectCid, salt) {
  if (Number(a.binding) !== BINDING_CONTENT_FREE) return false;
  const want = egressCommit(objectCid, salt);
  if (want.length !== a.digest.length) return false;
  return constantTimeEqual(want, a.digest);
}
