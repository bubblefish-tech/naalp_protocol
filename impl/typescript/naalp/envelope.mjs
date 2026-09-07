// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C3 object envelope for the TypeScript SDK — the full signed object and its offline verify.
//
// This is the ergonomic surface a developer uses: build an Object (its channel/kind/effect/body and
// the rest), sign it with a signer, and get a single self-describing, offline-verifiable byte string;
// verify one from the object + key + spec alone. The bytes are byte-identical to the Go, Rust and
// Python reference implementations (the worked example in vectors/worked/example.json is the
// byte-level known-answer for this module).

import * as cbor from './cbor.mjs';
import { U, N, B, T, A, M, Tag } from './cbor.mjs';
import * as cose from './cose.mjs';

// The object body field numbers, the protected-header NAALP_VERSION, and HEADER_LABEL are
// GENERATED from spec/wire-constants.csv into wire_constants_gen.mjs so the ten ports cannot
// drift on the wire. Change the CSV and run scripts/gen_wire_constants.py; never edit here.
// Imported for local use here; the originally-public names are re-exported (HEADER_LABEL stays
// module-private, as before).
import {
  FIELD_ID, FIELD_KIND, FIELD_CHANNEL, FIELD_TIER, FIELD_SIGNER, FIELD_CREATED,
  FIELD_EFFECT, FIELD_CAUSES, FIELD_PROFILE, FIELD_BODY, FIELD_EXT, FIELD_CEXT,
  FIELD_AUDIENCE, FIELD_SUITE, NAALP_VERSION, HEADER_LABEL,
  MAX_OBJECT_SIZE, MAX_CAUSES, MAX_EXT, MAX_CEXT, MAX_NESTING_DEPTH,
} from './wire_constants_gen.mjs';
export {
  FIELD_ID, FIELD_KIND, FIELD_CHANNEL, FIELD_TIER, FIELD_SIGNER, FIELD_CREATED,
  FIELD_EFFECT, FIELD_CAUSES, FIELD_PROFILE, FIELD_BODY, FIELD_EXT, FIELD_CEXT,
  FIELD_AUDIENCE, FIELD_SUITE, NAALP_VERSION,
  MAX_OBJECT_SIZE, MAX_CAUSES, MAX_EXT, MAX_CEXT, MAX_NESTING_DEPTH,
};

// The signed suite id carried in field 14 for the opt-in ML-DSA-65 + Ed25519 composite signature
// (§4.2); present iff the object is signed by a composite alg, so a pure object encodes
// byte-identically to a draft-00 object.
export const SUITE_MLDSA65_ED25519 = 1;

// --- T1.3 recheck (the checkable-minimum field, NAALP-REQ-110/111, §2.5) ----------------------

// RECHECK_KEY is the ext/cext extension key under which an object NAMES the re-check procedure for
// the claim in its body (§2.5, NAALP-REQ-111(c)). In the non-critical ext map (field 11) it is
// may-ignore; in the critical cext map (field 12) it is must-understand and an unknown procedure id
// is rejected fail-closed (UnknownCriticalExt), the same C3 critical-extension rule reaching the
// procedure it names. 13 does not collide with the safety-label ext key 1 (§6.4). Byte-identical to
// impl/go, impl/rust and impl/python.
export const RECHECK_KEY = 13n;

// The closed re-check procedure registry (design.md §2.5; T1.3); mirrors the spec
// recheck-procedure production and vectors/registry/recheck.csv.
export const RECHECK_RECOMPUTE_CONTENT_ID = 1n; // recompute the content id from the body and compare (§2.3)
export const RECHECK_VERIFY_COSE_SIGN1 = 2n;    // verify the COSE_Sign1 signature under the signer key (§4)
export const RECHECK_WALK_CAUSES = 3n;          // walk the signed causal partial order offline (§8.2)
export const RECHECK_REPLAY_CONSUME_CHECK = 4n; // replay the single-use consume ledger for the approval (§7.2)

// isKnownRecheckProcedure reports whether id is a recognized re-check procedure. The registry is
// CLOSED: an id outside it is unknown, and an unknown id under the critical map is rejected (§2.5).
export function isKnownRecheckProcedure(id) {
  const v = asBigInt(id);
  return v >= RECHECK_RECOMPUTE_CONTENT_ID && v <= RECHECK_REPLAY_CONSUME_CHECK;
}

// --- T1.6 per-signer forward-only counter (the OPTIONAL detection field, NAALP-REQ-120) --------

// SIGNER_COUNTER_KEY is the ext extension key under which an object OPTIONALLY carries a
// forward-only per-signer counter (§2.5.2). The value is a forward-only position (a uint) the
// signer increments on each object. It lives in the NON-CRITICAL ext map (field 11): a verifier
// that does not perform duplication-detection ignores it and the object still verifies
// (may-ignore). Because ext (field 11) is part of the signed body/payload, the counter is covered
// by the SIGNER's own COSE_Sign1 signature -- the deliberate contrast with the T1.5 consume-receipt
// position, which is signed by the LEDGER key. 14 does not collide with the safety-label ext key 1
// (§6.4) or the recheck ext/cext key 13 (T1.3). Byte-identical to impl/go, impl/rust and impl/python.
//
// The counter is DETECTION, not prevention (NAALP-REQ-120): a single self-authored sequence proves
// nothing. It is a NON-CRITICAL field only -- placing it in the critical cext map (field 12) is an
// unrecognized critical extension and is rejected fail-closed (UnknownCriticalExt), because a
// detection aid is never a must-understand verification gate.
export const SIGNER_COUNTER_KEY = 14n;

// cextGetUint mirrors impl/go's cextGetUint / impl/python's _cext_get_uint: the uint value under
// key in a CBOR map (ext or cext, or null for an absent carrier), reporting present only when the
// key exists AND its value is a uint.
function cextGetUint(m, key) {
  if (m === null) return [0n, false];
  for (const [k, v] of m.pairs) {
    if (k instanceof U && k.v === key) {
      if (v instanceof U) return [v.v, true];
      return [0n, false];
    }
  }
  return [0n, false];
}

// setExtCextUint places {key: U(value)} into o[field] ('ext' or 'cext'), replacing an existing
// entry under that key in place or appending; creates the carrier map if absent. Shared placement
// idiom for setRecheck/setSignerCounter (mirrors impl/go SetRecheck/SetSignerCounter).
function setExtCextUint(o, field, key, value) {
  const entry = [new U(key), new U(value)];
  const cur = o[field];
  if (cur === null) {
    o[field] = new M([entry]);
    return;
  }
  const newPairs = [];
  let replaced = false;
  for (const [k, v] of cur.pairs) {
    if (k instanceof U && k.v === key) {
      newPairs.push(entry);
      replaced = true;
    } else {
      newPairs.push([k, v]);
    }
  }
  if (!replaced) newPairs.push(entry);
  o[field] = new M(newPairs);
}

export class EnvelopeError extends Error {
  constructor(kind, msg = '') {
    super(kind + ': ' + msg);
    this.kind = kind;
  }
}

function asBigInt(v) {
  return typeof v === 'bigint' ? v : BigInt(v);
}

export class Object_ {
  /**
   * A decoded N-AALP object body. `id` is set by sign() (content id §2.3).
   * @param {object} fields
   * @param {bigint|number} fields.kind object kind (§2.1)
   * @param {bigint|number} fields.channel channel id (§2.1)
   * @param {Uint8Array|number[]} fields.signer signer-id bytes
   * @param {bigint|number} fields.created creation time, epoch ms
   * @param {bigint|number} fields.effect closed effect label (§6)
   * @param {*} fields.body a CBOR value (e.g. new M([...]))
   * @param {bigint|number} [fields.tier] tier (default 0)
   * @param {bigint|number} [fields.profile] profile (default Public)
   * @param {Array<Uint8Array|number[]>|null} [fields.causes] causal parents
   * @param {*} [fields.ext] non-critical extensions map (field 11) or null
   * @param {*} [fields.cext] critical extensions map (field 12) or null
   * @param {string} [fields.audience] single-use consume binding (field 13); '' = absent
   */
  constructor({ kind, channel, signer, created, effect, body,
    tier = 0, profile = cose.PROFILE_PUBLIC, causes = null, ext = null, cext = null,
    audience = '', suite = 0 } = {}) {
    this.id = null;
    this.kind = asBigInt(kind);
    this.channel = asBigInt(channel);
    this.tier = asBigInt(tier);
    this.signer = Uint8Array.from(signer);
    this.created = asBigInt(created);
    this.effect = asBigInt(effect);
    this.causes = (causes || []).map((c) => Uint8Array.from(c));
    this.profile = asBigInt(profile);
    this.body = body;   // a cbor Value (e.g. new M([...]))
    this.ext = ext;     // M or null (field 11, non-critical)
    this.cext = cext;   // M or null (field 12, critical)
    // field 13 (§2.5.3): the single-use consume binding. Omit-when-empty -- a no-audience object
    // encodes byte-identically to a draft-00 object (additivity). Anchors version 2.
    this.audience = audience;
    // field 14 (§4.2): the signed suite declaration, present (value 1) iff a composite alg signs
    // this object; 0 = absent, so a pure object stays byte-identical to draft-00.
    this.suite = asBigInt(suite);
  }

  bodyMap(includeId) {
    const pairs = [];
    if (includeId) pairs.push([new U(FIELD_ID), new B(this.id)]);
    pairs.push(
      [new U(FIELD_KIND), new U(this.kind)],
      [new U(FIELD_CHANNEL), new U(this.channel)],
      [new U(FIELD_TIER), new U(this.tier)],
      [new U(FIELD_SIGNER), new B(this.signer)],
      [new U(FIELD_CREATED), new U(this.created)],
      [new U(FIELD_EFFECT), new U(this.effect)],
      [new U(FIELD_CAUSES), new A(this.causes.map((c) => new B(c)))],
      [new U(FIELD_PROFILE), new U(this.profile)],
      [new U(FIELD_BODY), this.body],
    );
    if (this.ext !== null) pairs.push([new U(FIELD_EXT), this.ext]);
    if (this.cext !== null) pairs.push([new U(FIELD_CEXT), this.cext]);
    if (this.audience) pairs.push([new U(FIELD_AUDIENCE), new T(this.audience)]);
    if (this.suite) pairs.push([new U(FIELD_SUITE), new U(this.suite)]);
    return new M(pairs);
  }

  contentId() {
    // The object content id over the body without field 1 (§2.3).
    return cbor.contentId(this.bodyMap(false));
  }

  recheck() {
    // Return [id, present, critical]: the re-check procedure named in RECHECK_KEY (§2.5). present
    // is true iff a procedure is named; critical is true iff it is named in the cext map (field 12,
    // must-understand) rather than the ext map (field 11, may-ignore). cext takes precedence when
    // both carry the key. When no procedure is named the claim is attributable-only (NAALP-REQ-111).
    let [v, ok] = cextGetUint(this.cext, RECHECK_KEY);
    if (ok) return [v, true, true];
    [v, ok] = cextGetUint(this.ext, RECHECK_KEY);
    if (ok) return [v, true, false];
    return [0n, false, false];
  }

  setRecheck(procId, critical) {
    // Name procId as the body claim's re-check procedure. critical places it in the cext map
    // (field 12, must-understand); otherwise the ext map (field 11, may-ignore). Creates the
    // carrier if absent, replaces an existing RECHECK_KEY entry in place, and leaves any other
    // extension entries intact.
    setExtCextUint(this, critical ? 'cext' : 'ext', RECHECK_KEY, asBigInt(procId));
  }

  signerCounter() {
    // Return [seq, present]: the forward-only per-signer position named in SIGNER_COUNTER_KEY
    // (§2.5.2), read from the non-critical ext map (field 11) only. The field is OPTIONAL -- absent
    // (present === false) is valid. present is keyed on the KEY being present, not on the value: a
    // present counter of value 0 returns [0n, true].
    return cextGetUint(this.ext, SIGNER_COUNTER_KEY);
  }

  setSignerCounter(seq) {
    // Name seq as this object's forward-only per-signer position in the NON-CRITICAL ext map
    // (field 11), covered by the signer's COSE_Sign1 signature. Creates the ext carrier if absent,
    // replaces an existing SIGNER_COUNTER_KEY entry in place, and leaves any other extension
    // entries intact. Deliberately never placed in cext (detection, not a verification gate).
    setExtCextUint(this, 'ext', SIGNER_COUNTER_KEY, asBigInt(seq));
  }
}

// DuplicationFinding surfaces one detected per-signer counter conflict: two or more DISTINCT
// objects (distinct content ids) from the SAME signer id that carry the SAME forward-only counter
// value (§2.5.2, NAALP-REQ-120). A forward-only counter binds each value to at most one object, so
// a value bound to >= 2 distinct objects is the observable fingerprint of the key incrementing in
// two places (key duplication). The finding surfaces BOTH sides of the contradiction: the reused
// counter value and every conflicting content id (ascending by bytes) -- never a single flag with
// the evidence hidden.
export class DuplicationFinding {
  /**
   * @param {Uint8Array|number[]} signer the signer id whose forward-only counter was reused
   * @param {bigint|number} counter the reused forward-only counter value
   * @param {Array<Uint8Array|number[]>} ids the content ids of the >= 2 conflicting objects, ascending
   */
  constructor(signer, counter, ids) {
    this.signer = Uint8Array.from(signer);
    this.counter = asBigInt(counter);
    this.ids = ids.map((id) => Uint8Array.from(id));
  }
}

function hexKey(b) {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

function bytesCompare(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

export function detectSignerDuplication(objs) {
  // Scan a SET of PRESENTED objects for per-signer counter reuse (§2.5.2, NAALP-REQ-120). This is
  // the whole point of the field, and it is DETECTION, not prevention: it flags a signer id ONLY
  // when two conflicting sequences from that signer physically MEET in the presented set -- a
  // counter value bound to >= 2 distinct content ids by one signer. Given only ONE object per value
  // (one sequence) it returns no findings; the second conflicting object must be present,
  // unsuppressed, for the duplication to become provable. Objects with no counter do not
  // participate. Output is deterministic (findings ordered by signer id bytes then counter; ids
  // within a finding ascending by bytes).
  //
  // It operates over the SET, never per object: a per-object boolean could never express "these two
  // distinct objects reuse one position," and a single self-authored counter proves nothing alone.
  const groups = new Map();         // signerHexKey -> Map<counterString, Map<idHexKey, Uint8Array>>
  const signerBytesByKey = new Map(); // signerHexKey -> Uint8Array (a de-dup'd, real signer id)

  for (const o of objs) {
    const [seq, present] = o.signerCounter();
    if (!present) continue; // a counter-less object does not participate in detection
    let id;
    try {
      id = o.contentId();
    } catch {
      continue; // a body that cannot be canonically encoded cannot be a presented object
    }
    const sk = hexKey(o.signer);
    if (!signerBytesByKey.has(sk)) signerBytesByKey.set(sk, o.signer);
    if (!groups.has(sk)) groups.set(sk, new Map());
    const byCounter = groups.get(sk);
    const ck = seq.toString();
    if (!byCounter.has(ck)) byCounter.set(ck, new Map());
    byCounter.get(ck).set(hexKey(id), id); // a set that de-dups a byte-identical re-presentation
  }

  const signerKeys = Array.from(signerBytesByKey.keys())
    .sort((a, b) => bytesCompare(signerBytesByKey.get(a), signerBytesByKey.get(b)));

  const findings = [];
  for (const sk of signerKeys) {
    const byCounter = groups.get(sk);
    const counters = Array.from(byCounter.keys())
      .map((s) => BigInt(s))
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    for (const c of counters) {
      const idset = byCounter.get(c.toString());
      // A (signer, counter) that binds two-or-more DISTINCT content ids is a detected duplication.
      // The >= 2 requirement is the detection-requires-both invariant: relax it to >= 1 and a
      // single sequence would flag (prevention theatre) -- the mutation the "one sequence alone ->
      // not flagged" test is built to catch.
      if (idset.size < 2) continue;
      const ids = Array.from(idset.values()).sort(bytesCompare);
      findings.push(new DuplicationFinding(signerBytesByKey.get(sk), c, ids));
    }
  }
  return findings;
}

function protectedHeader(alg, signer, profile) {
  const naalp = new M([
    [new U(1), new B(signer)],
    [new U(2), new U(profile)],
    [new U(3), new U(NAALP_VERSION)],
  ]);
  return cbor.encode(new M([[new U(1), new N(alg)], [new T(HEADER_LABEL), naalp]]));
}

export function sign(obj, alg, seed) {
  // Assemble, content-id-bind, and deterministically sign a full N-AALP object with an ML-DSA key
  // derived from `seed`. Returns the tagged COSE_Sign1 object bytes.
  obj.id = obj.contentId();
  const payload = cbor.encode(obj.bodyMap(true));
  const prot = protectedHeader(alg, obj.signer, obj.profile);
  const tbs = cose.toBeSignedRaw(prot, payload);
  const sig = cose.mldsaSign(alg, seed, tbs);
  return cose.assembleSign1Raw(prot, payload, sig);
}

export function signComposite(obj, mldsaSeed, edSeed) {
  // Assemble, content-id-bind, and sign a full N-AALP object with the opt-in LAMPS composite
  // signature (alg -65537, §4.2). Sets the signed suite field (14) present (value 1) BEFORE the
  // content id so the id covers it; the composite value is deterministic in both legs (ML-DSA-65
  // with ctx=Label, Ed25519 with no ctx). Returns the tagged COSE_Sign1 object bytes.
  obj.suite = BigInt(SUITE_MLDSA65_ED25519);
  obj.id = obj.contentId();
  const payload = cbor.encode(obj.bodyMap(true));
  const prot = protectedHeader(cose.ALG_COMPOSITE_65_ED25519, obj.signer, obj.profile);
  const tbs = cose.toBeSignedRaw(prot, payload);
  const sig = cose.compositeSign(mldsaSeed, edSeed, tbs);
  return cose.assembleSign1Raw(prot, payload, sig);
}

function parseProtected(prot) {
  // §3.1.1 (R5): the empty protected header is pinned to 0x40; a byte string wrapping an
  // empty CBOR map (the 0x41A0 form -- its unwrapped content is the single byte 0xA0) MUST be
  // rejected as NonCanonical before the header is interpreted as a map.
  if (prot.length === 1 && prot[0] === 0xA0) {
    throw new EnvelopeError('NonCanonical', 'empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)');
  }
  const v = cbor.decode(prot);
  if (!(v instanceof M)) throw new EnvelopeError('Malformed', 'protected header not a map');
  let alg = null, signer = null, profile = null, version = null;
  for (const [k, val] of v.pairs) {
    if (k instanceof U && k.v === 1n && val instanceof N) {
      alg = val.v;
    } else if (k instanceof T && k.v === HEADER_LABEL && val instanceof M) {
      for (const [kk, vv] of val.pairs) {
        if (kk instanceof U && kk.v === 1n && vv instanceof B) signer = vv.v;
        else if (kk instanceof U && kk.v === 2n && vv instanceof U) profile = vv.v;
        else if (kk instanceof U && kk.v === 3n && vv instanceof U) version = vv.v;
      }
    }
  }
  if (alg === null || signer === null || profile === null || version === null) {
    throw new EnvelopeError('Malformed', 'protected header missing routing fields');
  }
  return [alg, signer, profile, version];
}

const BODY_TYPES = [U, N, B, T, A, M, Tag];

function objectFromMap(m) {
  const fields = new Map();
  for (const [k, v] of m.pairs) {
    if (!(k instanceof U)) throw new EnvelopeError('Malformed', 'non-uint body key');
    fields.set(k.v, v);
  }

  const need = (fnum, types) => {
    const v = fields.get(BigInt(fnum));
    if (v === undefined || !types.some((t) => v instanceof t)) {
      throw new EnvelopeError('Malformed', 'field ' + fnum + ' wrong type/absent');
    }
    return v;
  };

  const signer = need(FIELD_SIGNER, [B]).v;
  const causesV = need(FIELD_CAUSES, [A]);
  if (causesV.items.length > MAX_CAUSES) { // causal fan-in bound (§3.4, R7)
    throw new EnvelopeError('TooManyCauses', 'causes[] exceeds the maximum count (§3.4, R7)');
  }
  const causes = [];
  for (const c of causesV.items) {
    if (!(c instanceof B)) throw new EnvelopeError('Malformed', 'cause not a bstr');
    causes.push(c.v);
  }
  const ext = fields.get(BigInt(FIELD_EXT)) ?? null;
  const cext = fields.get(BigInt(FIELD_CEXT)) ?? null;
  if (ext !== null && !(ext instanceof M)) throw new EnvelopeError('Malformed', 'ext not a map');
  if (ext !== null && ext.pairs.length > MAX_EXT) { // ext cardinality bound (§3.4, R7)
    throw new EnvelopeError('TooManyExtensions', 'ext/cext exceeds the maximum cardinality (§3.4, R7)');
  }
  if (cext !== null && !(cext instanceof M)) throw new EnvelopeError('Malformed', 'cext not a map');
  if (cext !== null && cext.pairs.length > MAX_CEXT) { // cext cardinality bound (§3.4, R7)
    throw new EnvelopeError('TooManyExtensions', 'ext/cext exceeds the maximum cardinality (§3.4, R7)');
  }
  const audV = fields.get(BigInt(FIELD_AUDIENCE)) ?? null;
  if (audV !== null && !(audV instanceof T)) throw new EnvelopeError('Malformed', 'audience not a tstr');
  const suiteV = fields.get(BigInt(FIELD_SUITE)) ?? null;
  if (suiteV !== null && !(suiteV instanceof U)) throw new EnvelopeError('Malformed', 'suite not a uint');

  const o = new Object_({
    kind: need(FIELD_KIND, [U]).v,
    channel: need(FIELD_CHANNEL, [U]).v,
    signer,
    created: need(FIELD_CREATED, [U]).v,
    effect: need(FIELD_EFFECT, [U]).v,
    body: need(FIELD_BODY, BODY_TYPES),
    tier: need(FIELD_TIER, [U]).v,
    profile: need(FIELD_PROFILE, [U]).v,
    causes,
    ext,
    cext,
    audience: audV !== null ? audV.v : '',
    suite: suiteV !== null ? suiteV.v : 0,
  });
  const idv = fields.get(BigInt(FIELD_ID));
  o.id = idv instanceof B ? idv.v : null;
  return o;
}

// The single-use consume binding gate (§2.5.3), checked at the point of use -- before the consume
// logic (the CAS append) -- NEVER inside verify(). An in-transit relay, ordering authority, or
// auditor legitimately verifies objects addressed to some OTHER authority; only the authority about
// to CONSUME an object enforces that the object is addressed to it. Three branches: (a) absent
// audience on a consume-once object -> WrongAudience; (b) an audience present but not this authority
// -> WrongAudience; (c) a non-consume-once object with no audience -> pass. Throws
// EnvelopeError('WrongAudience') on rejection.
export function checkAudience(o, selfAuthority, consumeOnce) {
  if (!o.audience) {
    if (consumeOnce) throw new EnvelopeError('WrongAudience', 'consume-once object has no audience');
    return;
  }
  if (o.audience !== selfAuthority) {
    throw new EnvelopeError('WrongAudience', 'object audience is not this consuming authority');
  }
}

export function verify(profile, alg, pubkey, kindValidator, objBytes, knownCext = null) {
  // Verify a signed N-AALP object end-to-end, offline (R-2.4). Returns the Object on success; throws
  // EnvelopeError (or a cose/cbor error) with a stable .kind on the first named failure. Check order
  // (fail-closed): object octet size -> decode (bounded depth) -> content-id -> field ranges ->
  // header/body copies + version -> critical extensions -> kind dispatch -> profile floor -> signature.

  // Object octet-size bound (§3.4, R7): reject an oversized signed object on the raw bytes, before
  // any parse (RFC 8949 §10 decoder-memory guard).
  if (objBytes.length > MAX_OBJECT_SIZE) {
    throw new EnvelopeError('TooLarge', 'object exceeds the maximum octet size (§3.4, R7)');
  }
  const known = knownCext || {};
  const [prot, payload, sig] = cose.parseSign1Raw(objBytes);
  // non-canonical -> NonCanonical (§2.6); over-nested -> DepthExceeded (§3.4, R7)
  const bv = cbor.decodeBounded(payload, MAX_NESTING_DEPTH);
  if (!(bv instanceof M)) throw new EnvelopeError('Malformed', 'body not a map');

  // content-id: recompute over the body without field 1, compare to the claimed id
  let claimed = null;
  const without = [];
  for (const [k, v] of bv.pairs) {
    if (k instanceof U && k.v === BigInt(FIELD_ID)) {
      if (!(v instanceof B)) throw new EnvelopeError('Malformed', 'id not a bstr');
      claimed = v.v;
      continue;
    }
    without.push([k, v]);
  }
  if (claimed === null) throw new EnvelopeError('Malformed', 'no content id');
  const recomputed = cbor.contentId(new M(without));
  if (!bytesEqual(recomputed, claimed)) throw new EnvelopeError('ContentIdMismatch', 'recomputed id differs');

  const o = objectFromMap(bv);

  // A (channel 3, kind 0) Rotation object MUST be a tag-98 COSE_Sign co-signed by the old AND new
  // key (§5.2); a single-signature (tag-18) rotation is missing the old-key co-signature and is
  // rejected RotationUnauthorized (the single-Sign1 rotation-gap fix).
  if (isRotationObject(o.channel, o.kind)) {
    throw new EnvelopeError('RotationUnauthorized', 'single-signature rotation missing the old-key co-signature');
  }

  // field ranges (§3.3): channel 0..19, effect 0..3, profile 1..3
  if (o.channel > 19n || o.effect > 3n || o.profile < 1n || o.profile > 3n) {
    throw new EnvelopeError('RangeError', 'field out of range');
  }

  const [halg, hsigner, hprofile, hversion] = parseProtected(prot);
  if (hversion !== BigInt(NAALP_VERSION)) throw new EnvelopeError('UnsupportedVersion', 'bad naalp-version');
  if (!bytesEqual(hsigner, o.signer) || hprofile !== o.profile) {
    throw new EnvelopeError('HeaderBodyMismatch', 'protected header disagrees with body');
  }

  if (o.cext !== null) {
    for (const [k, v] of o.cext.pairs) {
      if (!(k instanceof U)) {
        throw new EnvelopeError('UnknownCriticalExt', 'unrecognized critical extension');
      }
      // RECHECK_KEY (13) is an envelope-recognized critical key: a critical recheck naming an
      // UNKNOWN procedure id is rejected fail-closed (the critical-extension rule reaching the
      // procedure it names, T1.3); a known procedure id is recognized. A NON-critical recheck
      // (ext, field 11) is never rejected here -- an unknown non-critical procedure is ignored
      // per the may-ignore rule (handled below in the plain lookup, since it is never critical).
      if (k.v === RECHECK_KEY) {
        if (!(v instanceof U)) throw new EnvelopeError('Malformed', 'recheck procedure id not a uint');
        if (!isKnownRecheckProcedure(v.v)) {
          throw new EnvelopeError('UnknownCriticalExt', 'unrecognized critical extension');
        }
        continue;
      }
      if (!Object.prototype.hasOwnProperty.call(known, String(k.v))) {
        throw new EnvelopeError('UnknownCriticalExt', 'unrecognized critical extension');
      }
    }
  }

  if (kindValidator === null || !kindValidator(o.channel, o.kind)) {
    throw new EnvelopeError('UnknownKind', 'kind/channel not a registered surface');
  }

  const tbs = cose.toBeSignedRaw(prot, payload);
  if (Number(halg) === cose.ALG_COMPOSITE_65_ED25519) {
    // Opt-in composite path (§4.2/§4.4/§4.5). Check order: CompositeRefused (Sovereign floors at
    // level 5, the composite ML-DSA-65 leg is level 3) -> SuiteMismatch (field 14 must declare the
    // matching suite) -> both-legs signature. The verifying key is mldsaPub || ed25519Pub.
    if (Number(profile) === cose.PROFILE_SOVEREIGN) {
      throw new EnvelopeError('CompositeRefused', 'composite refused on the Sovereign profile');
    }
    if (o.suite !== BigInt(SUITE_MLDSA65_ED25519)) {
      throw new EnvelopeError('SuiteMismatch', 'field 14 does not declare the composite suite');
    }
    const mldsaPub = pubkey.slice(0, cose.MLDSA65_PUB_SIZE);
    const edPub = pubkey.slice(cose.MLDSA65_PUB_SIZE);
    if (edPub.length !== 32 || !cose.compositeVerify(mldsaPub, edPub, tbs, sig)) {
      throw new EnvelopeError('BadSignature', 'composite signature does not verify');
    }
    return o;
  }
  // pure path: a non-composite alg MUST NOT carry the signed suite field (§4.2).
  if (o.suite !== 0n) throw new EnvelopeError('SuiteMismatch', 'pure object carries a composite suite field');
  const [level, algKnown] = cose.algLevel(halg);
  if (!algKnown) throw new EnvelopeError('UnknownAlg', 'unregistered alg');
  if (level < cose.profileMinLevel(profile)) {
    throw new EnvelopeError('ProfileDowngrade', 'signature level below the profile minimum');
  }
  if (!cose.coseVerify1Raw(halg, pubkey, tbs, sig)) {
    throw new EnvelopeError('BadSignature', 'signature does not verify');
  }
  return o;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// --- §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) --------------------------

// The OPEN-DECISION toggle (design.md §4.4 profile floor applied to a rotation): a Sovereign/High
// verifier gates the OLD (authorizing) leg by the profile floor too (DEFAULT, fail-closed) rather
// than only the NEW leg. Ratified default = true (matches impl/go rotationOldLegFloorApplies).
const ROTATION_OLD_LEG_FLOOR_APPLIES = true;

function isRotationObject(channel, kind) {
  return Number(channel) === 3 && Number(kind) === 0;
}

function isCompositeAlg(alg) {
  const a = Number(alg);
  return a === cose.ALG_COMPOSITE_65_ED25519 || a === cose.ALG_COMPOSITE_44_ED25519;
}

export function signRotationObject(o, oldAlg, oldSeed, newAlg, newSeed) {
  // Build a §5.2 Rotation object as a tag-98 COSE_Sign co-signed by the OLD then the NEW key in
  // fixed order; the body protected header names the NEW (go-forward) key. Permitted ONLY for the
  // Identity Rotation object (channel 3, kind 0); a composite leg is rejected fail-closed. Bytes are
  // byte-identical to the Go, Rust and Python reference implementations.
  if (!isRotationObject(o.channel, o.kind)) {
    throw new EnvelopeError('UnknownKind', 'tag-98 permitted only for the Identity Rotation object');
  }
  if (isCompositeAlg(oldAlg) || isCompositeAlg(newAlg)) {
    throw new EnvelopeError('Malformed', 'composite-inside-rotation is undecided');
  }
  o.suite = 0n; // a rotation object is never composite
  o.id = o.contentId();
  const payload = cbor.encode(o.bodyMap(true));
  const bodyProt = protectedHeader(newAlg, o.signer, o.profile);
  const oldLeg = cose.signatureLeg(bodyProt, oldAlg, oldSeed, payload);
  const newLeg = cose.signatureLeg(bodyProt, newAlg, newSeed, payload);
  return cose.assembleSignRaw(bodyProt, payload, [oldLeg, newLeg]);
}

export function verifyRotationObject(profile, oldAlg, oldPk, newAlg, newPk, kindValidator, objBytes, knownCext = null) {
  // Verify a tag-98 Rotation object (§5.2): the same object-body checks as verify(), then EXACTLY
  // two legs in fixed order (old-key then new-key) BOTH verifying. Any missing/wrong/bad old leg is
  // RotationUnauthorized. Permitted ONLY for (channel 3, kind 0).

  // Object octet-size bound (§3.4, R7): the tag-98 rotation object is a top-level signed object
  // too, so it is size-checked on raw bytes before any parse.
  if (objBytes.length > MAX_OBJECT_SIZE) {
    throw new EnvelopeError('TooLarge', 'object exceeds the maximum octet size (§3.4, R7)');
  }
  const known = knownCext || {};
  const [bodyProt, payload, legs] = cose.parseSignRaw(objBytes);
  const bv = cbor.decodeBounded(payload, MAX_NESTING_DEPTH);
  if (!(bv instanceof M)) throw new EnvelopeError('Malformed', 'body not a map');

  let claimed = null;
  const without = [];
  for (const [k, v] of bv.pairs) {
    if (k instanceof U && k.v === BigInt(FIELD_ID)) {
      if (!(v instanceof B)) throw new EnvelopeError('Malformed', 'id not a bstr');
      claimed = v.v;
      continue;
    }
    without.push([k, v]);
  }
  if (claimed === null) throw new EnvelopeError('Malformed', 'no content id');
  if (!bytesEqual(cbor.contentId(new M(without)), claimed)) {
    throw new EnvelopeError('ContentIdMismatch', 'recomputed id differs');
  }

  const o = objectFromMap(bv);
  if (o.channel > 19n || o.effect > 3n || o.profile < 1n || o.profile > 3n) {
    throw new EnvelopeError('RangeError', 'field out of range');
  }

  const [halg, hsigner, hprofile, hversion] = parseProtected(bodyProt);
  if (hversion !== BigInt(NAALP_VERSION)) throw new EnvelopeError('UnsupportedVersion', 'bad naalp-version');
  if (!bytesEqual(hsigner, o.signer) || hprofile !== o.profile) {
    throw new EnvelopeError('HeaderBodyMismatch', 'protected header disagrees with body');
  }
  if (o.cext !== null) {
    for (const [k, v] of o.cext.pairs) {
      if (!(k instanceof U)) {
        throw new EnvelopeError('UnknownCriticalExt', 'unrecognized critical extension');
      }
      // RECHECK_KEY (13) is an envelope-recognized critical key: a critical recheck naming an
      // UNKNOWN procedure id is rejected fail-closed (the critical-extension rule reaching the
      // procedure it names, T1.3); a known procedure id is recognized. A NON-critical recheck
      // (ext, field 11) is never rejected here -- an unknown non-critical procedure is ignored
      // per the may-ignore rule (handled below in the plain lookup, since it is never critical).
      if (k.v === RECHECK_KEY) {
        if (!(v instanceof U)) throw new EnvelopeError('Malformed', 'recheck procedure id not a uint');
        if (!isKnownRecheckProcedure(v.v)) {
          throw new EnvelopeError('UnknownCriticalExt', 'unrecognized critical extension');
        }
        continue;
      }
      if (!Object.prototype.hasOwnProperty.call(known, String(k.v))) {
        throw new EnvelopeError('UnknownCriticalExt', 'unrecognized critical extension');
      }
    }
  }

  // tag-98 is permitted ONLY for the Identity-channel Rotation object (channel 3, kind 0).
  if (!isRotationObject(o.channel, o.kind)) {
    throw new EnvelopeError('UnknownKind', 'tag-98 permitted only for the Identity Rotation object');
  }
  if (kindValidator === null || !kindValidator(o.channel, o.kind)) {
    throw new EnvelopeError('UnknownKind', 'kind/channel not a registered surface');
  }
  if (isCompositeAlg(halg)) throw new EnvelopeError('Malformed', 'composite-inside-rotation is undecided');
  if (Number(halg) !== Number(newAlg)) throw new EnvelopeError('KeyAlgMismatch', 'body header alg is not the new key alg');

  // EXACTLY two legs, fixed order (old, new). A missing/lone leg IS "old leg dropped".
  if (legs.length !== 2) throw new EnvelopeError('RotationUnauthorized', 'rotation must carry exactly two legs');
  const oldLegAlg = cose.algFromProtected(legs[0][0]);
  const newLegAlg = cose.algFromProtected(legs[1][0]);
  if (isCompositeAlg(oldLegAlg) || isCompositeAlg(newLegAlg)) throw new EnvelopeError('Malformed', 'composite leg in a rotation');
  if (Number(oldLegAlg) !== Number(oldAlg) || Number(newLegAlg) !== Number(newAlg)) {
    throw new EnvelopeError('RotationUnauthorized', 'legs not in (old, new) order');
  }

  // profile floor: the NEW (go-forward) leg always; the OLD leg iff the fail-closed toggle applies.
  const [newLevel, nknown] = cose.algLevel(newLegAlg);
  if (!nknown) throw new EnvelopeError('UnknownAlg', 'unregistered alg');
  if (newLevel < cose.profileMinLevel(profile)) {
    throw new EnvelopeError('ProfileDowngrade', 'new-leg level below the profile minimum');
  }
  if (ROTATION_OLD_LEG_FLOOR_APPLIES) {
    const [oldLevel, oknown] = cose.algLevel(oldLegAlg);
    if (!oknown) throw new EnvelopeError('UnknownAlg', 'unregistered alg');
    if (oldLevel < cose.profileMinLevel(profile)) {
      throw new EnvelopeError('ProfileDowngrade', 'old-leg level below the profile minimum');
    }
  }

  // both legs MUST verify over their per-signer ToBeSigned.
  const oldTbs = cose.signatureToBeSigned(bodyProt, oldLegAlg, payload);
  if (!cose.coseVerify1Raw(oldLegAlg, oldPk, oldTbs, legs[0][1])) {
    throw new EnvelopeError('RotationUnauthorized', 'old leg does not verify');
  }
  const newTbs = cose.signatureToBeSigned(bodyProt, newLegAlg, payload);
  if (!cose.coseVerify1Raw(newLegAlg, newPk, newTbs, legs[1][1])) {
    throw new EnvelopeError('RotationUnauthorized', 'new leg does not verify');
  }
  return o;
}

// --- NA-IETF-1 producing-boundary disclosure (OPTIONAL, self-asserted ext key 15, §2.5.4) -------

// The ext extension key under which an object OPTIONALLY carries a per-object producing-boundary
// disclosure (design.md §2.5.4, NA-IETF-1): the trust boundary that emitted the object and whether
// that boundary OBSERVED the event it describes first-hand or is RELAYING a report of it. It rides
// the NON-CRITICAL ext map (field 11): a verifier that does not understand it, or that reads a
// malformed value, IGNORES the entry and the object still verifies (may-ignore). Because ext is part
// of the signed body/payload, the disclosure is covered by the SIGNER's own COSE_Sign1 signature --
// a SELF-ASSERTED claim. 15 collides with neither the safety-label ext key 1 (§6.4), the recheck
// ext/cext key 13 (§2.5.1), nor the signer-counter ext key 14 (§2.5.2). Byte-identical to impl/go,
// impl/rust and impl/python.
export const PRODUCING_BOUNDARY_KEY = 15n;

// The producing-boundary kind (§2.5.4): a closed enum naming whether the emitting boundary witnessed
// the event directly or is relaying a report of it.
export const PRODUCING_BOUNDARY_OBSERVED = 1n; // this boundary witnessed the event directly (first-hand)
export const PRODUCING_BOUNDARY_REPORTED = 2n; // this boundary is relaying a report it did not witness

// The producing-boundary value sub-map keys (§2.5.4).
const PB_FIELD_BOUNDARY = 1n;  // bstr -- the emitting trust boundary (party id)
const PB_FIELD_KIND = 2n;      // 1 observed / 2 reported
const PB_FIELD_REPORTING = 3n; // bstr -- report origin; present iff kind == reported

export class ProducingBoundary {
  /**
   * A decoded producing-boundary disclosure (PRODUCING_BOUNDARY_KEY, §2.5.4). `boundary` is the
   * emitting trust boundary (the same bstr party-id form as Object.signer). `kind` is
   * PRODUCING_BOUNDARY_OBSERVED or PRODUCING_BOUNDARY_REPORTED. `reporting` names the report origin
   * and is non-null ONLY when kind is PRODUCING_BOUNDARY_REPORTED (an observer relays from no one).
   * @param {Uint8Array|number[]} boundary
   * @param {bigint|number} kind
   * @param {Uint8Array|number[]|null} [reporting]
   */
  constructor(boundary, kind, reporting = null) {
    this.boundary = Uint8Array.from(boundary);
    this.kind = asBigInt(kind);
    this.reporting = reporting === null ? null : Uint8Array.from(reporting);
  }
}

export function producingBoundary(o) {
  // Return [ProducingBoundary, true] iff `o` carries a WELL-FORMED producing-boundary disclosure in
  // the non-critical ext map (field 11, PRODUCING_BOUNDARY_KEY): a non-empty boundary (key 1), a
  // kind (key 2) in {observed, reported}, and a reporting-boundary (key 3) absent unless the kind is
  // reported. A malformed value is IGNORED -- returns [null, false], NEVER throwing (may-ignore). An
  // absent disclosure returns [null, false]. An unrecognized sub-key is ignored and does not by
  // itself make an otherwise well-formed value malformed.
  if (o.ext === null) return [null, false];
  let val = null;
  let found = false;
  for (const [k, v] of o.ext.pairs) {
    if (k instanceof U && k.v === PRODUCING_BOUNDARY_KEY) {
      val = v;
      found = true;
      break;
    }
  }
  if (!found || !(val instanceof M)) return [null, false];
  let boundary = null;
  let kind = null;
  let reporting = null;
  let haveReporting = false;
  for (const [k, v] of val.pairs) {
    if (!(k instanceof U)) return [null, false];
    if (k.v === PB_FIELD_BOUNDARY) {
      if (!(v instanceof B)) return [null, false];
      boundary = v.v;
    } else if (k.v === PB_FIELD_KIND) {
      if (!(v instanceof U)) return [null, false];
      kind = v.v;
    } else if (k.v === PB_FIELD_REPORTING) {
      if (!(v instanceof B)) return [null, false];
      reporting = v.v;
      haveReporting = true;
    }
    // else: an unrecognized sub-key -- may-ignore.
  }
  // well-formedness (§2.5.4). Any failure returns [null, false] (may-ignore), never an error.
  if (boundary === null || boundary.length === 0) return [null, false]; // no boundary named
  if (kind !== PRODUCING_BOUNDARY_OBSERVED && kind !== PRODUCING_BOUNDARY_REPORTED) {
    return [null, false]; // absent or out-of-enum kind
  }
  if (haveReporting && kind !== PRODUCING_BOUNDARY_REPORTED) {
    return [null, false]; // a reporting-boundary under observed: an observer relays from no one
  }
  return [new ProducingBoundary(boundary, kind, haveReporting ? reporting : null), true];
}

export function setProducingBoundary(o, pb) {
  // Name `pb` as `o`'s producing-boundary disclosure in the NON-CRITICAL ext map (field 11), covered
  // by the signer's COSE_Sign1 signature. Creates the ext carrier if absent and leaves any other
  // extension entries intact. The reporting-boundary is emitted ONLY when non-null AND the kind is
  // reported, so a caller cannot accidentally emit a malformed observed-with-reporting disclosure (an
  // observer relays from no one). Sub-map keys are appended in ascending order; encode emits
  // canonical CBOR regardless, so the object stays deterministic.
  const sub = [[new U(PB_FIELD_BOUNDARY), new B(pb.boundary)], [new U(PB_FIELD_KIND), new U(pb.kind)]];
  if (pb.reporting !== null && pb.kind === PRODUCING_BOUNDARY_REPORTED) {
    sub.push([new U(PB_FIELD_REPORTING), new B(pb.reporting)]);
  }
  const entry = [new U(PRODUCING_BOUNDARY_KEY), new M(sub)];
  if (o.ext === null) {
    o.ext = new M([entry]);
    return;
  }
  const newPairs = [];
  let replaced = false;
  for (const [k, v] of o.ext.pairs) {
    if (k instanceof U && k.v === PRODUCING_BOUNDARY_KEY) {
      newPairs.push(entry);
      replaced = true;
    } else {
      newPairs.push([k, v]);
    }
  }
  if (!replaced) newPairs.push(entry);
  o.ext = new M(newPairs);
}

// `Object` is the ergonomic name (mirrors the Python/Go/Rust `Object`); the class is declared as
// `Object_` because `Object` is a reserved global identifier for a class declaration.
export { Object_ as Object };
