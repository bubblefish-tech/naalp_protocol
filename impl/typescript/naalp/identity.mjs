// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C4 identity for the TypeScript SDK: the self-certifying signer id (§5.1) and the NFC rule.
//
// signer id = multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))),
// identical in form to the N-PAMP PeerHandle. Multicodec codes are from the multiformats registry:
// ed25519-pub 0xed, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212; multihash sha2-256 0x12.

import { sha256 } from '@noble/hashes/sha2.js';
import { ALG_ED25519, ALG_MLDSA65, ALG_MLDSA87 } from './cose.mjs';

const MULTICODEC = new Map([
  [ALG_ED25519, 0xed],
  [ALG_MLDSA65, 0x1211],
  [ALG_MLDSA87, 0x1212],
]);
const MH_SHA256 = 0x12;

// RFC 4648 base32 lowercase alphabet (no padding).
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

export class UnknownAlg extends Error { constructor(m) { super(m); this.kind = 'UnknownAlg'; } }
export class SignerMismatch extends Error { constructor(m) { super(m); this.kind = 'SignerMismatch'; } }
export class NonNFC extends Error { constructor(m) { super(m); this.kind = 'NonNFC'; } }

function uvarint(n) {
  const out = [];
  for (;;) {
    let b = n & 0x7f;
    n >>>= 7;
    if (n) { out.push(b | 0x80); } else { out.push(b); return Uint8Array.from(out); }
  }
}

function base32NoPad(data) {
  let bits = 0, value = 0, out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}

export function signerId(alg, pubkey) {
  const mc = MULTICODEC.get(alg);
  if (mc === undefined) throw new UnknownAlg('no multicodec for alg ' + alg);
  const tagged = concat(uvarint(mc), Uint8Array.from(pubkey));
  const digest = sha256(tagged);
  const mh = concat(concat(uvarint(MH_SHA256), uvarint(digest.length)), digest);
  return 'b' + base32NoPad(mh);
}

export function compositeSignerId(mldsaAlg, mldsaPub, edPub) {
  // Self-certifying signer id for a composite key pair (§5.1). The SHA-256 preimage is the
  // multicodec-tagged ML-DSA public key concatenated with the multicodec-tagged Ed25519 public key
  // -- using only existing official multicodecs (no minted composite code) -- so stripping or
  // substituting either leg changes the id (=> SignerMismatch before verify). Downgrade-resistant.
  if (mldsaAlg !== ALG_MLDSA65 && mldsaAlg !== ALG_MLDSA87) {
    throw new UnknownAlg('composite signer id requires an ML-DSA alg, got ' + mldsaAlg);
  }
  const preimage = concat(
    concat(uvarint(MULTICODEC.get(mldsaAlg)), Uint8Array.from(mldsaPub)),
    concat(uvarint(MULTICODEC.get(ALG_ED25519)), Uint8Array.from(edPub)));
  const digest = sha256(preimage);
  const mh = concat(concat(uvarint(MH_SHA256), uvarint(digest.length)), digest);
  return 'b' + base32NoPad(mh);
}

export function checkSigner(claimed, alg, pubkey) {
  if (signerId(alg, pubkey) !== claimed) throw new SignerMismatch('signer id does not recompute from the key');
}

export function requireNFC(s) {
  // Reject an identity/scope string that is not Unicode NFC (§3.1, R-3.3).
  if (s.normalize('NFC') !== s) throw new NonNFC('string is not Unicode NFC');
}

// ---- key rotation (design §5.2): the co-signed old->new link (ADDITIVE, wave-D) --------------
//
// The self-certifying signer id survives a key rotation: a RotationRecord binds the old id to the new
// id from a not_before position, co-signed by BOTH keys, so attribution to the durable identity is
// preserved across rotation (R-1.4). This is the C4 primitive the Delivery-Model-B principal registry
// (naalp/rooms) composes on for a rotation-authorised rebind. Added additively (new exports only, no
// edit to the existing surface above) exactly as impl/python/naalp/identity.py added it; the import
// declarations below are ESM-hoisted, so appending them here leaves the original file byte-for-byte.
import * as cbor from './cbor.mjs';
import { U, T, M } from './cbor.mjs';
import { mldsaSign as _mldsaSign, coseVerify1Raw as _coseVerify1Raw } from './cose.mjs';

export class RotationUnauthorized extends Error {
  constructor(m) { super(m); this.kind = 'RotationUnauthorized'; }
}

// Links an old signer id to a new one from notBefore (§5.2). Its signed bytes are the
// deterministic-CBOR map {1: old, 2: new, 3: not_before}.
export class RotationRecord {
  constructor(oldId, newId, notBefore) {
    this.old = String(oldId);
    this.new = String(newId);
    this.notBefore = notBefore;
  }

  bytes() {
    return cbor.encode(new M([
      [new U(1), new T(this.old)],
      [new U(2), new T(this.new)],
      [new U(3), new U(this.notBefore)],
    ]));
  }
}

// Co-sign a rotation with BOTH the old and new keys (§5.2): each leg is a raw deterministic ML-DSA
// signature over the rotation body. Returns [oldSig, newSig].
export function signRotation(r, alg, oldSeed, newSeed) {
  const m = r.bytes();
  return [_mldsaSign(alg, oldSeed, m), _mldsaSign(alg, newSeed, m)];
}

// Confirm a rotation is authorized (§5.2, §5.5): the old and new keys derive the ids in the record AND
// both signatures verify. Any failure -- an id that does not recompute from its key, an unregistered
// alg, or a signature that does not verify -- is RotationUnauthorized (fail-closed). A substitution not
// co-signed by the old key cannot pass, so the durable id cannot be hijacked to an unrelated key.
// Returns null on success.
export function verifyRotation(r, oldAlg, oldPub, newAlg, newPub, oldSig, newSig) {
  let oldComputed, newComputed;
  try {
    oldComputed = signerId(oldAlg, oldPub);
    newComputed = signerId(newAlg, newPub);
  } catch (e) {
    throw new RotationUnauthorized('rotation names an unregistered algorithm');
  }
  if (oldComputed !== r.old || newComputed !== r.new) {
    throw new RotationUnauthorized('a key does not derive its id in the rotation record');
  }
  const m = r.bytes();
  if (!_coseVerify1Raw(oldAlg, oldPub, m, oldSig) || !_coseVerify1Raw(newAlg, newPub, m, newSig)) {
    throw new RotationUnauthorized('a rotation signature does not verify under its key');
  }
  return null;
}

// ---- key revocation (design §5.3): distinct from rotation (ADDITIVE, RECORD+THREAD wave) --------
//
// A RevocationRecord marks a key dead from notAfter (§5.3), signed either by the key it revokes or
// by a deployer-configured recovery key. Ported from impl/go/identity/identity.go and
// impl/rust/src/identity.rs (design.md §5.3/§5.4/§5.5, R-1.4), which this file matches exactly:
// same field numbers, same fail-closed membership-before-signature order, same error kinds.

export class BadSignature extends Error {
  constructor(m) { super(m); this.kind = 'BadSignature'; }
}

// Marks a key dead from notAfter (§5.3). Signed bytes: deterministic-CBOR map {1: key, 2: not_after}.
export class RevocationRecord {
  constructor(key, notAfter) {
    this.key = String(key);
    this.notAfter = notAfter;
  }

  bytes() {
    return cbor.encode(new M([
      [new U(1), new T(this.key)],
      [new U(2), new U(this.notAfter)],
    ]));
  }
}

// Confirms a revocation is validly signed (§5.3): by the key it revokes, or by a deployer-configured
// recovery key. recoveryIds is the deployer's set of authorized recovery-key signer ids; a
// revocation whose signer is neither r.key nor a member of recoveryIds is rejected SignerMismatch
// (§5.5), fail-closed -- an empty recoveryIds admits only the revoked key itself. The signer id is
// recomputed from the presented key and checked BEFORE the signature (membership before signature).
// An UnknownAlg from the id recompute propagates unchanged. Throws on rejection; returns undefined
// on success.
export function verifyRevocation(r, alg, pubkey, sig, recoveryIds) {
  const id = signerId(alg, pubkey); // UnknownAlg propagates unchanged
  let authorized = id === r.key;
  if (!authorized) {
    for (const rid of (recoveryIds || [])) {
      if (rid === id) { authorized = true; break; }
    }
  }
  if (!authorized) {
    throw new SignerMismatch('signer id is neither the revoked key nor an authorized recovery key');
  }
  if (!_coseVerify1Raw(alg, pubkey, r.bytes(), sig)) {
    throw new BadSignature('revocation signature does not verify under its key');
  }
}

// Reports whether an object fixed at authoritative position `posTime` is after the revocation
// (revoked); objects fixed at or before notAfter stay valid (§5.3).
export function revokedAt(r, posTime) {
  return posTime > r.notAfter;
}

// ---- foreign-identity linkage (design §5.4): cross-signed attestation (ADDITIVE) -----------------
//
// Cross-signs a foreign identity to a signer id (§5.4). Signed bytes:
// {1: controls, 2: foreign_id, 3: not_after}. It is signed by the FOREIGN identity's key.
export class ForeignLinkRecord {
  constructor(controls, foreignId, notAfter) {
    this.controls = String(controls);
    this.foreignId = String(foreignId);
    this.notAfter = notAfter;
  }

  bytes() {
    return cbor.encode(new M([
      [new U(1), new T(this.controls)],
      [new U(2), new T(this.foreignId)],
      [new U(3), new U(this.notAfter)],
    ]));
  }
}

// Reports whether a foreign-identity link confers linkage at time `now`. A non-NFC foreignId is
// rejected (NonNFC), checked BEFORE expiry/signature. An expired link or a bad cross-signature
// confers NO linkage but is NOT itself an error -- it simply does not link (the object remains valid
// on its own signature, §5.4/§5.5). It NEVER overrides the key-derived id. Returns a boolean.
export function verifyForeignLink(r, foreignAlg, foreignPub, sig, now) {
  requireNFC(r.foreignId); // throws NonNFC
  if (now > r.notAfter) return false; // expired: confers no authority (ignored)
  if (!_coseVerify1Raw(foreignAlg, foreignPub, r.bytes(), sig)) return false; // bad/absent cross-sig
  return true;
}

// ---- durable identity thread (rotation-surviving attribution, R-1.4) (ADDITIVE) ------------------
//
// One verified rotation step: the record plus the two keys' algs/pubkeys and their co-signatures.
export class RotationEvidence {
  constructor(record, oldAlg, oldPub, newAlg, newPub, oldSig, newSig) {
    this.record = record;
    this.oldAlg = oldAlg;
    this.oldPub = oldPub;
    this.newAlg = newAlg;
    this.newPub = newPub;
    this.oldSig = oldSig;
    this.newSig = newSig;
  }
}

// A durable identity: a root signer id continued by a chain of rotations.
export class Thread {
  constructor(root, current, chain) {
    this.root = root;
    this.current = current;
    this.chain = chain;
  }

  // Reports whether an object whose body signer id is `signer` belongs to this durable thread (any
  // id in the chain, including a pre-rotation key, R-1.4).
  attributable(signer) {
    return this.chain.includes(signer);
  }
}

// Verifies an ordered rotation chain and returns the durable identity thread. Each rotation must be
// authorized (co-signed) and link the previous `new` to the next `old`; a break yields
// RotationUnauthorized. A receipt signed under any id in Thread.chain is attributable to Root, so it
// stays attributable after rotation (R-1.4).
export function resolveThread(evs) {
  if (!evs || evs.length === 0) throw new RotationUnauthorized('empty rotation evidence chain');
  const root = evs[0].record.old;
  const chain = [root];
  let prevNew = root;
  for (const e of evs) {
    if (e.record.old !== prevNew) {
      throw new RotationUnauthorized('rotation chain is not contiguous'); // contiguity guard
    }
    verifyRotation(e.record, e.oldAlg, e.oldPub, e.newAlg, e.newPub, e.oldSig, e.newSig); // co-sig guard
    chain.push(e.record.new);
    prevNew = e.record.new;
  }
  return new Thread(root, prevNew, chain);
}
