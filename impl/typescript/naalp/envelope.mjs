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

// object body field numbers (§2.1)
export const FIELD_ID = 1;
export const FIELD_KIND = 2;
export const FIELD_CHANNEL = 3;
export const FIELD_TIER = 4;
export const FIELD_SIGNER = 5;
export const FIELD_CREATED = 6;
export const FIELD_EFFECT = 7;
export const FIELD_CAUSES = 8;
export const FIELD_PROFILE = 9;
export const FIELD_BODY = 10;
export const FIELD_EXT = 11;
export const FIELD_CEXT = 12;

export const NAALP_VERSION = 1;
const HEADER_LABEL = 'naalp';

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
   */
  constructor({ kind, channel, signer, created, effect, body,
    tier = 0, profile = cose.PROFILE_PUBLIC, causes = null, ext = null, cext = null } = {}) {
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
    return new M(pairs);
  }

  contentId() {
    // The object content id over the body without field 1 (§2.3).
    return cbor.contentId(this.bodyMap(false));
  }
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

function parseProtected(prot) {
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
  const causes = [];
  for (const c of causesV.items) {
    if (!(c instanceof B)) throw new EnvelopeError('Malformed', 'cause not a bstr');
    causes.push(c.v);
  }
  const ext = fields.get(BigInt(FIELD_EXT)) ?? null;
  const cext = fields.get(BigInt(FIELD_CEXT)) ?? null;
  if (ext !== null && !(ext instanceof M)) throw new EnvelopeError('Malformed', 'ext not a map');
  if (cext !== null && !(cext instanceof M)) throw new EnvelopeError('Malformed', 'cext not a map');

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
  });
  const idv = fields.get(BigInt(FIELD_ID));
  o.id = idv instanceof B ? idv.v : null;
  return o;
}

export function verify(profile, alg, pubkey, kindValidator, objBytes, knownCext = null) {
  // Verify a signed N-AALP object end-to-end, offline (R-2.4). Returns the Object on success; throws
  // EnvelopeError (or a cose/cbor error) with a stable .kind on the first named failure. Check order
  // (fail-closed): decode -> content-id -> field ranges -> header/body copies + version -> critical
  // extensions -> kind dispatch -> profile floor -> signature.
  const known = knownCext || {};
  const [prot, payload, sig] = cose.parseSign1Raw(objBytes);
  const bv = cbor.decode(payload); // throws NonCanonical on a non-canonical body
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
    for (const [k] of o.cext.pairs) {
      if (!(k instanceof U && Object.prototype.hasOwnProperty.call(known, String(k.v)))) {
        throw new EnvelopeError('UnknownCriticalExt', 'unrecognized critical extension');
      }
    }
  }

  if (kindValidator === null || !kindValidator(o.channel, o.kind)) {
    throw new EnvelopeError('UnknownKind', 'kind/channel not a registered surface');
  }

  const [level, algKnown] = cose.algLevel(halg);
  if (!algKnown) throw new EnvelopeError('UnknownAlg', 'unregistered alg');
  if (level < cose.profileMinLevel(profile)) {
    throw new EnvelopeError('ProfileDowngrade', 'signature level below the profile minimum');
  }
  const tbs = cose.toBeSignedRaw(prot, payload);
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

// `Object` is the ergonomic name (mirrors the Python/Go/Rust `Object`); the class is declared as
// `Object_` because `Object` is a reserved global identifier for a class declaration.
export { Object_ as Object };
