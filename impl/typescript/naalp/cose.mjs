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
import { sha512 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, N, B, T, A, M, Tag } from './cbor.mjs';

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

// --- COSE_Sign (tag 98) multi-signature support: the §5.2 Rotation object co-signature ---

export const TAG_SIGN = 98;

export function legProtected(alg) {
  // One COSE_Signature protected header: {1: alg} (RFC 9052 §4).
  return cbor.encode(new M([[new U(1), new N(alg)]]));
}

export function signatureToBeSigned(bodyProt, signerAlg, payload) {
  // The per-signer COSE_Signature signing input for a COSE_Sign (RFC 9052 §4.4):
  // det-CBOR(["Signature", body_protected, sign_protected, external_aad(empty), payload]). Note the
  // five-element "Signature" structure (with the per-leg sign_protected) vs the four-element
  // "Signature1" of a COSE_Sign1.
  return cbor.encode(new A([
    new T('Signature'), new B(bodyProt), new B(legProtected(signerAlg)), new B(new Uint8Array(0)), new B(payload),
  ]));
}

export function signatureLeg(bodyProt, alg, seed, payload) {
  // Build one COSE_Signature leg: (leg_protected_bytes, signature_bytes).
  const sprot = legProtected(alg);
  const sig = mldsaSign(alg, seed, signatureToBeSigned(bodyProt, alg, payload));
  return [sprot, sig];
}

export function assembleSignRaw(bodyProt, payload, legs) {
  // The tagged COSE_Sign object: 98([body_prot, {}, payload, [[sprot, {}, sig], ...]]).
  const sigArr = new A(legs.map(([sprot, sig]) => new A([new B(sprot), new M([]), new B(sig)])));
  return cbor.encode(new Tag(TAG_SIGN, new A([new B(bodyProt), new M([]), new B(payload), sigArr])));
}

export function parseSignRaw(obj) {
  const v = cbor.decode(obj);
  if (!(v instanceof Tag) || v.n !== BigInt(TAG_SIGN) || !(v.content instanceof A)) {
    throw new Error('not a tagged COSE_Sign');
  }
  const arr = v.content.items;
  if (arr.length !== 4 || !(arr[0] instanceof B) || !(arr[2] instanceof B) || !(arr[3] instanceof A)) {
    throw new Error('malformed COSE_Sign array');
  }
  const legs = [];
  for (const e of arr[3].items) {
    if (!(e instanceof A) || e.items.length !== 3 || !(e.items[0] instanceof B) || !(e.items[2] instanceof B)) {
      throw new Error('malformed COSE_Signature leg');
    }
    legs.push([e.items[0].v, e.items[2].v]);
  }
  return [arr[0].v, arr[2].v, legs];
}

export function algFromProtected(prot) {
  // §3.1.1 (R5): reject the redundant 0x41A0 encoding of an empty protected header (a bstr
  // wrapping an empty map; its unwrapped content is the single byte 0xA0) as NonCanonical,
  // before interpreting the header -- the empty protected header is pinned to 0x40.
  if (prot.length === 1 && prot[0] === 0xA0) {
    throw new cbor.NonCanonical('empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)');
  }
  // Extract the alg (label 1) value from a serialized leg protected header {1: alg}.
  const v = cbor.decode(prot);
  if (!(v instanceof M)) throw new Error('protected header not a map');
  for (const [k, val] of v.pairs) {
    if (k instanceof U && k.v === 1n && val instanceof N) return val.v;
  }
  throw new Error('no alg in protected header');
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

// --- LAMPS opt-in composite signature (alg -65537, design.md §4.2) ---

export const ALG_COMPOSITE_65_ED25519 = -65537; // COMPSIG-MLDSA65-Ed25519-SHA512 (Public/Enterprise)
export const ALG_COMPOSITE_44_ED25519 = -65538; // COMPSIG-MLDSA44-Ed25519-SHA512 (edge; RESERVED)
const COMPOSITE_PREFIX = new TextEncoder().encode('CompositeAlgorithmSignatures2025');
const COMPOSITE_LABEL_MLDSA65_ED25519 = new TextEncoder().encode('COMPSIG-MLDSA65-Ed25519-SHA512');
const MLDSA65_SIG_SIZE = 3309;         // FIPS 204 ML-DSA-65 signature size
export const MLDSA65_PUB_SIZE = 1952;  // FIPS 204 ML-DSA-65 public-key size (composite split point)

export function computeMprime(label, ctx, m) {
  // M' = Prefix || Label || len(ctx) || ctx || SHA-512(M) (design.md §4.2). len(ctx) is a single
  // length octet; PH is SHA-512; the N-AALP composite context ctx is empty, so the octet is 0x00.
  if (ctx.length > 255) throw new Error('composite context exceeds one length octet');
  const h = sha512(Uint8Array.from(m));
  const out = new Uint8Array(COMPOSITE_PREFIX.length + label.length + 1 + ctx.length + h.length);
  let o = 0;
  out.set(COMPOSITE_PREFIX, o); o += COMPOSITE_PREFIX.length;
  out.set(label, o); o += label.length;
  out[o] = ctx.length; o += 1;         // len(ctx) as a single length octet
  out.set(ctx, o); o += ctx.length;
  out.set(h, o);
  return out;
}

export function compositeSign(mldsaSeed, edSeed, tbs) {
  // LAMPS composite value over the COSE ToBeSigned tbs: mldsaSig || tradSig (ML-DSA-65 first, raw
  // concatenation; design.md §4.2). The ML-DSA leg is deterministic (extraEntropy:false => rnd=0)
  // with context = the suite Label octets; the Ed25519 leg signs M' with no context.
  const mprime = computeMprime(COMPOSITE_LABEL_MLDSA65_ED25519, new Uint8Array(0), tbs);
  const { secretKey } = ml_dsa65.keygen(Uint8Array.from(mldsaSeed));
  const mldsaSig = ml_dsa65.sign(mprime, secretKey, { context: COMPOSITE_LABEL_MLDSA65_ED25519, extraEntropy: false });
  const tradSig = ed25519Sign(edSeed, mprime);
  const out = new Uint8Array(mldsaSig.length + tradSig.length);
  out.set(mldsaSig, 0);                 // ML-DSA first (LAMPS order)
  out.set(tradSig, mldsaSig.length);
  return out;
}

export function compositeVerify(mldsaPk, edPk, m, sig) {
  // Valid IFF BOTH the ML-DSA-65 leg (context = Label) and the Ed25519 leg (no context) validate
  // over M'. A value of the wrong length is malformed and rejected. A stripped or re-interpreted
  // lone leg has no valid composite because M' binds both components (RFC 9955; §4.2/§4.5).
  if (sig.length !== MLDSA65_SIG_SIZE + 64) return false;
  const mprime = computeMprime(COMPOSITE_LABEL_MLDSA65_ED25519, new Uint8Array(0), m);
  const mldsaOk = Boolean(ml_dsa65.verify(
    sig.slice(0, MLDSA65_SIG_SIZE), mprime, Uint8Array.from(mldsaPk),
    { context: COMPOSITE_LABEL_MLDSA65_ED25519 }));
  const edOk = ed25519Verify(edPk, mprime, sig.slice(MLDSA65_SIG_SIZE));
  return mldsaOk && edOk;
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
