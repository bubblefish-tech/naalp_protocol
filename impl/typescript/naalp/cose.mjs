// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C2 signing layer for the TypeScript SDK: the COSE_Sign1 (RFC 9052) signing-input and
// object assembly, plus deterministic ML-DSA (FIPS 204, rnd=0) and Ed25519 (RFC 8032).
//
// The deterministic ML-DSA path (@noble/post-quantum ml_dsa.sign(msg, sk, {extraEntropy:false}),
// which sets the FIPS 204 rnd to 32 zero bytes) produces signatures byte-identical to the Go
// (CIRCL), Rust (fips204) and Python (dilithium-py) reference implementations — verified against
// the shared conformance corpus and the NIST ACVP keyGen vectors.

import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import * as cbor from './cbor.mjs';
import { U, B, T, A, M, Tag } from './cbor.mjs';

export const ALG_MLDSA65 = -49;
export const ALG_MLDSA87 = -50;
export const ALG_ED25519 = -19;

export const PROFILE_PUBLIC = 1;
export const PROFILE_ENTERPRISE = 2;
export const PROFILE_SOVEREIGN = 3;

export const TAG_SIGN1 = 18;

export function algLevel(alg) {
  // NIST security level of a registered alg, and whether it is registered. Ed25519 is
  // classical (level 0), valid only as a hybrid leg. Returns [level, known].
  const lvl = { [ALG_MLDSA87]: 5, [ALG_MLDSA65]: 3, [ALG_ED25519]: 0 };
  const a = Number(alg);
  return [lvl[a] ?? 0, a === ALG_MLDSA87 || a === ALG_MLDSA65 || a === ALG_ED25519];
}

export function profileMinLevel(profile) {
  // Minimum signature level a profile accepts (Sovereign floors at level 5; else 3).
  return Number(profile) === PROFILE_SOVEREIGN ? 5 : 3;
}

export function toBeSignedRaw(protectedHdr, payload) {
  // RFC 9052 §4.4 Sig_structure for a COSE_Sign1 over an already-serialized header.
  return cbor.encode(new A([new T('Signature1'), new B(protectedHdr), new B(new Uint8Array(0)), new B(payload)]));
}

export function assembleSign1Raw(protectedHdr, payload, sig) {
  // The tagged COSE_Sign1 object: 18([protected, {}, payload, signature]).
  return cbor.encode(new Tag(TAG_SIGN1, new A([new B(protectedHdr), new M([]), new B(payload), new B(sig)])));
}

export function parseSign1Raw(obj) {
  const v = cbor.decode(obj);
  if (!(v instanceof Tag) || v.n !== BigInt(TAG_SIGN1) || !(v.content instanceof A)) {
    throw new Error('not a tagged COSE_Sign1');
  }
  const arr = v.content.items;
  if (arr.length !== 4 || !(arr[0] instanceof B) || !(arr[2] instanceof B) || !(arr[3] instanceof B)) {
    throw new Error('malformed COSE_Sign1 array');
  }
  return [arr[0].v, arr[2].v, arr[3].v];
}

// --- ML-DSA (FIPS 204) via @noble/post-quantum ---

function mldsaFor(alg) {
  if (alg === ALG_MLDSA65) return ml_dsa65;
  if (alg === ALG_MLDSA87) return ml_dsa87;
  throw new Error('alg ' + alg + ' is not an ML-DSA algorithm');
}

export function mldsaKeygen(param, seed) {
  // Derive the public key from a 32-byte seed (NIST ACVP keyGen); returns pk bytes.
  const M_ = param === 'ML-DSA-87' ? ml_dsa87 : ml_dsa65;
  return M_.keygen(Uint8Array.from(seed)).publicKey;
}

export function mldsaSign(alg, seed, tbs) {
  // Deterministic (rnd=0) ML-DSA signature over tbs with the key derived from seed.
  const M_ = mldsaFor(alg);
  const { secretKey } = M_.keygen(Uint8Array.from(seed));
  return M_.sign(Uint8Array.from(tbs), secretKey, { extraEntropy: false });
}

export function mldsaVerify(alg, pk, tbs, sig) {
  const M_ = mldsaFor(alg);
  // @noble/post-quantum verify order is (signature, message, publicKey).
  return Boolean(M_.verify(Uint8Array.from(sig), Uint8Array.from(tbs), Uint8Array.from(pk)));
}

// --- Ed25519 (RFC 8032) via @noble/curves ---

export function ed25519Sign(seed, msg) {
  if (seed.length !== 32) throw new Error('ed25519 secret key must be a 32-byte seed');
  return ed25519.sign(Uint8Array.from(msg), Uint8Array.from(seed));
}

export function ed25519Verify(pk, msg, sig) {
  try {
    return Boolean(ed25519.verify(Uint8Array.from(sig), Uint8Array.from(msg), Uint8Array.from(pk)));
  } catch (e) {
    return false;
  }
}

export function coseSign1(alg, seed, protectedHdr, payload) {
  const tbs = toBeSignedRaw(protectedHdr, payload);
  const sig = mldsaSign(alg, seed, tbs);
  return assembleSign1Raw(protectedHdr, payload, sig);
}

export function coseVerify1Raw(alg, pk, tbs, sig) {
  // Verify a raw signature over already-assembled ToBeSigned bytes, dispatching by alg.
  const a = Number(alg);
  if (a === ALG_MLDSA65 || a === ALG_MLDSA87) return mldsaVerify(a, pk, tbs, sig);
  if (a === ALG_ED25519) return ed25519Verify(pk, tbs, sig);
  throw new Error('unknown alg ' + alg);
}

export function coseVerify1(alg, pk, obj) {
  const [protectedHdr, payload, sig] = parseSign1Raw(obj);
  const tbs = toBeSignedRaw(protectedHdr, payload);
  return coseVerify1Raw(alg, pk, tbs, sig);
}
