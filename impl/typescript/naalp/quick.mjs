// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP ergonomic sign/verify layer for the TypeScript SDK.
//
// A thin convenience surface over the raw SDK primitives (`cose`, `identity`, `channels`,
// `envelope`). It collapses the common paths to one well-named call each:
//
//   const a = new Signer(seed);                       // derives the public key + signer id
//   const bytes = a.sign(channel, kind, body);        // -> a signed N-AALP object (Uint8Array)
//   const obj = verify(a.publicKey, bytes);           // -> the decoded Object, or throws
//
// It delegates every cryptographic and encoding operation to the SDK — ML-DSA keygen/sign/verify
// (`cose`), the self-certifying signer id (`identity`), the deterministic object envelope and its
// offline verify (`envelope`), and the frozen twenty-channel registry (`channels`). It introduces
// no new wire format and no new cryptography; the bytes it produces are the same conformance-graded
// bytes the raw `envelope.sign` produces. Its only additions are ergonomic: it derives the signer id
// for you, fills the object's effect from the channel registry (so the declared effect is
// correct-by-construction), and validates a received object against the real registry instead of a
// hand-written kind predicate.

import * as cbor from './cbor.mjs';
import { U, N, B, T, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import * as identity from './identity.mjs';
import * as channels from './channels.mjs';
import * as envelope from './envelope.mjs';

const TEXT = new TextEncoder();
const UTF8 = new TextDecoder();

/** Map a COSE ML-DSA algorithm id to the `@noble/post-quantum` parameter name used by keygen. */
function mldsaParam(alg) {
  if (alg === cose.ALG_MLDSA87) return 'ML-DSA-87';
  if (alg === cose.ALG_MLDSA65) return 'ML-DSA-65';
  throw new envelope.EnvelopeError('UnknownAlg', 'quick.Signer supports ML-DSA-65 / ML-DSA-87 only');
}

/**
 * Return `true` iff (channel, kind) is a registered N-AALP surface, using the real twenty-channel
 * registry (`channels.lookup`). This is the kind validator the ergonomic `verify` uses in place of a
 * hand-written predicate — a received object on an unregistered surface is rejected fail-closed.
 * @param {bigint|number} channel
 * @param {bigint|number} kind
 * @returns {boolean}
 */
export function registeredKind(channel, kind) {
  try {
    channels.lookup(channel, kind);
    return true;
  } catch {
    return false;
  }
}

/**
 * A signing identity: a 32-byte ML-DSA seed plus its derived public key and self-certifying signer
 * id. Construction runs the real `cose.mldsaKeygen` and `identity.signerId`; there is no stored
 * secret beyond the seed.
 */
export class Signer {
  /**
   * @param {Uint8Array|number[]} seed a 32-byte ML-DSA key seed (NIST ACVP keyGen)
   * @param {object} [opts]
   * @param {number} [opts.alg] COSE algorithm id (default `cose.ALG_MLDSA65`)
   */
  constructor(seed, { alg = cose.ALG_MLDSA65 } = {}) {
    this.alg = alg;
    this.seed = Uint8Array.from(seed);
    /** @type {Uint8Array} the ML-DSA public key bytes */
    this.publicKey = cose.mldsaKeygen(mldsaParam(alg), this.seed);
    /** @type {string} the self-certifying signer id (§5.1) */
    this.signerId = identity.signerId(alg, this.publicKey);
  }

  /**
   * Build, content-id-bind, and deterministically sign one N-AALP object, and return its signed
   * bytes. The object's effect defaults to the channel registry's declared effect for (channel,
   * kind) and is checked against the registry (`channels.checkEffect`) before signing, so an object
   * can never carry an effect its kind does not declare. Delegates the actual signing to
   * `envelope.sign`.
   *
   * @param {bigint|number} channel channel id (§2.1), e.g. `0x000F` (Interaction)
   * @param {bigint|number} kind object kind within the channel
   * @param {*} body a CBOR value for the object body (e.g. `new M([[new U(1), new T('hi')]])`)
   * @param {object} [opts]
   * @param {number} [opts.effect] override the effect (only valid for variable-effect kinds; a
   *   fixed-effect kind still rejects a wrong effect via `channels.checkEffect`)
   * @param {bigint|number} [opts.profile] COSE profile (default `cose.PROFILE_PUBLIC`)
   * @param {bigint|number} [opts.tier] tier (default 0)
   * @param {bigint|number} [opts.created] creation time, epoch ms (default `Date.now()`)
   * @param {Array<Uint8Array|number[]>|null} [opts.causes] causal-parent content ids
   * @returns {Uint8Array} the tagged COSE_Sign1 object bytes
   */
  sign(channel, kind, body, {
    effect = undefined, profile = cose.PROFILE_PUBLIC, tier = 0, created = Date.now(), causes = null,
  } = {}) {
    const [, declared] = channels.lookup(channel, kind);   // throws UnknownKind — fail-closed
    const eff = effect === undefined ? declared : effect;
    channels.checkEffect(channel, kind, eff);              // throws EffectDeclarationMismatch — fail-closed
    const obj = new envelope.Object({
      kind, channel, tier, signer: TEXT.encode(this.signerId),
      created, effect: eff, profile, body, causes,
    });
    return envelope.sign(obj, this.alg, this.seed);
  }
}

/** Read the COSE algorithm id from a signed object's protected header (self-describing). */
function headerAlg(objBytes) {
  const [prot] = cose.parseSign1Raw(objBytes);
  const m = cbor.decode(prot);
  if (!(m instanceof M)) throw new envelope.EnvelopeError('Malformed', 'protected header not a map');
  for (const [k, v] of m.pairs) {
    if (k instanceof U && k.v === 1n && v instanceof N) return Number(v.v);
  }
  throw new envelope.EnvelopeError('Malformed', 'protected header has no alg');
}

/**
 * Verify a signed N-AALP object offline against a public key, and return the decoded Object. The
 * algorithm is read from the object's self-describing protected header; the (channel, kind) is
 * validated against the real twenty-channel registry; and the whole verify — decode, content-id
 * recompute, field ranges, header/body agreement, critical extensions, profile floor, and signature
 * — is performed by `envelope.verify`, fail-closed: any failure throws an `EnvelopeError` with a
 * stable `.kind` and yields no object.
 *
 * @param {Uint8Array} publicKey the signer's public key bytes
 * @param {Uint8Array} objBytes the signed object bytes
 * @param {object} [opts]
 * @param {bigint|number} [opts.acceptProfile] the minimum profile the verifier accepts (the floor
 *   passed to `envelope.verify`; default `cose.PROFILE_PUBLIC`)
 * @param {object|null} [opts.knownCext] recognized critical-extension labels
 * @returns {envelope.Object} the verified object
 */
export function verify(publicKey, objBytes, { acceptProfile = cose.PROFILE_PUBLIC, knownCext = null } = {}) {
  const alg = headerAlg(objBytes);
  return envelope.verify(acceptProfile, alg, publicKey, registeredKind, objBytes, knownCext);
}

/**
 * A human-readable description of a verified object: its channel/kind names (from the registry), the
 * effect, the signer id, and the object's content id (hex). Intended for logging and CLI output; it
 * does not perform verification.
 * @param {envelope.Object} obj a verified Object (e.g. the return of `verify`)
 * @returns {{channel: string, kind: string, effect: number, signer: string, contentId: string}}
 */
export function describe(obj) {
  const [kindName] = channels.lookup(obj.channel, obj.kind);
  return {
    channel: `0x${Number(obj.channel).toString(16).padStart(4, '0')} ${channels.channelName(obj.channel)}`,
    kind: `${Number(obj.kind)} ${kindName}`,
    effect: Number(obj.effect),
    signer: UTF8.decode(obj.signer),
    contentId: obj.id ? Buffer.from(obj.id).toString('hex') : '',
  };
}
