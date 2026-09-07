// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) known-answer + fail-closed tests
// for the TypeScript SDK.
//
// Mutation-surviving properties:
//   1. BYTE PARITY -- signRotationObject over the fixed worked fixture reproduces the Go/Rust/
//      oracle bytes: the SHA-256 of the 6798-byte tag-98 object is pinned and equals the Go
//      rotation.sign reference (TypeScript == Go == Rust == Python == oracle on the whole
//      two-leg object).
//   2. Round-trip -- verifyRotationObject accepts a co-signed rotation (both legs, old then new).
//   3. Fail-closed reject family -- a tag-18 single-signature rotation, a dropped old leg, a
//      wrong-key old leg, a tag-98 object on a non-rotation (channel,kind), and a Sovereign
//      verifier over a rotation whose OLD key is below the profile floor are ALL rejected with
//      the named kind.
//
// Run:  node --test test/rotation.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { cose, envelope } from '../naalp/index.mjs';
import { U, T, M } from '../naalp/cbor.mjs';

const OLD_SEED = new Uint8Array(32).fill(0x0b);        // old ML-DSA-65 key
const NEW_SEED = new Uint8Array(32).fill(0x16);         // new ML-DSA-65 key (go-forward)
const FLOOR_OLD_SEED = new Uint8Array(32).fill(0x21);   // below-floor old ML-DSA-65 key (33)
const FLOOR_NEW_SEED = new Uint8Array(32).fill(0x2c);   // go-forward ML-DSA-87 key (44)
// SHA-256 of the 6798-byte tag-98 rotation object for the fixed worked fixture; byte-identical to
// the Go rotation.sign reference and tools/rotation_oracle.py (a cross-language, non-circular
// anchor, not a TypeScript-only self-check).
const OBJECT_SHA256 = '298d5d5bac8a0bf556541784f3090ac7300897858e883dc3ab6e7625bc418194';

const SIGNER = new TextEncoder().encode('SIGNER_NEW');
const NOT_BEFORE = 1785000000000n;

function rotationRecord() {
  // field-10 naalp-rotation body {1: old_id, 2: new_id, 3: not_before}
  return new M([
    [new U(1), new T('signer-old')],
    [new U(2), new T('signer-new')],
    [new U(3), new U(NOT_BEFORE)],
  ]);
}

function workedObject(profile = cose.PROFILE_PUBLIC) {
  return new envelope.Object({
    kind: 0, channel: 3, signer: SIGNER, created: NOT_BEFORE, effect: 2,
    body: rotationRecord(), tier: 0, profile,
  });
}

function kindOk(ch, k) { return Number(ch) === 3 && Number(k) === 0; }

function sha256Hex(b) { return createHash('sha256').update(b).digest('hex'); }

function expectRejects(fn, expectedKind) {
  assert.throws(fn, (err) => err instanceof envelope.EnvelopeError && err.kind === expectedKind);
}

test('rotation object byte parity with the Go/Rust/oracle reference', () => {
  const obj = envelope.signRotationObject(workedObject(), cose.ALG_MLDSA65, OLD_SEED, cose.ALG_MLDSA65, NEW_SEED);
  assert.equal(obj.length, 6798);
  assert.equal(sha256Hex(obj), OBJECT_SHA256,
    'rotation object diverged from the Go/Rust/oracle reference bytes');
});

test('rotation roundtrip accept', () => {
  const oldPk = cose.mldsaKeygen('ML-DSA-65', OLD_SEED);
  const newPk = cose.mldsaKeygen('ML-DSA-65', NEW_SEED);
  const obj = envelope.signRotationObject(workedObject(), cose.ALG_MLDSA65, OLD_SEED, cose.ALG_MLDSA65, NEW_SEED);
  const o = envelope.verifyRotationObject(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, oldPk, cose.ALG_MLDSA65, newPk, kindOk, obj);
  assert.equal(o.channel, 3n);
  assert.equal(o.kind, 0n);
});

test('a tag-18 single-signature rotation is rejected RotationUnauthorized', () => {
  // a channel-3/kind-0 object signed as a normal single-signature COSE_Sign1 (tag 18) is a
  // rotation missing the old-key co-signature -> the general verify rejects RotationUnauthorized.
  const newPk = cose.mldsaKeygen('ML-DSA-65', NEW_SEED);
  const obj = envelope.sign(workedObject(), cose.ALG_MLDSA65, NEW_SEED); // tag-18
  expectRejects(
    () => envelope.verify(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, newPk, kindOk, obj),
    'RotationUnauthorized',
  );
});

test('rotation with the old leg dropped is rejected RotationUnauthorized', () => {
  // the mutation anchor: dropping the old leg (one leg) MUST be rejected RotationUnauthorized.
  // Disabling the exactly-two-legs check in verifyRotationObject flips this test.
  const oldPk = cose.mldsaKeygen('ML-DSA-65', OLD_SEED);
  const newPk = cose.mldsaKeygen('ML-DSA-65', NEW_SEED);
  const obj = envelope.signRotationObject(workedObject(), cose.ALG_MLDSA65, OLD_SEED, cose.ALG_MLDSA65, NEW_SEED);
  const [bodyProt, payload, legs] = cose.parseSignRaw(obj);
  const oneLeg = cose.assembleSignRaw(bodyProt, payload, [legs[1]]); // keep only the new leg
  expectRejects(
    () => envelope.verifyRotationObject(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, oldPk, cose.ALG_MLDSA65, newPk, kindOk, oneLeg),
    'RotationUnauthorized',
  );
});

test('rotation with the old leg signed by the wrong (new) key is rejected RotationUnauthorized', () => {
  // both legs signed by the NEW key -> the trusted old key cannot verify slot 0.
  const oldPk = cose.mldsaKeygen('ML-DSA-65', OLD_SEED);
  const newPk = cose.mldsaKeygen('ML-DSA-65', NEW_SEED);
  const obj = envelope.signRotationObject(workedObject(), cose.ALG_MLDSA65, NEW_SEED, cose.ALG_MLDSA65, NEW_SEED);
  expectRejects(
    () => envelope.verifyRotationObject(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, oldPk, cose.ALG_MLDSA65, newPk, kindOk, obj),
    'RotationUnauthorized',
  );
});

test('a tag-98 object built over a non-rotation kind is rejected UnknownKind', () => {
  // a tag-98 object over (channel 4, kind 2) is not the Identity Rotation object.
  const oldPk = cose.mldsaKeygen('ML-DSA-65', OLD_SEED);
  const newPk = cose.mldsaKeygen('ML-DSA-65', NEW_SEED);
  const o = new envelope.Object({
    kind: 2, channel: 4, signer: SIGNER, created: NOT_BEFORE, effect: 2,
    body: new T('hello'), tier: 0, profile: cose.PROFILE_PUBLIC,
  });
  // sign() is only used here to obtain a valid (protected-header, payload) pair for this object's
  // fields -- protectedHeader() is module-private, so a real tag-18 object over the same fields is
  // parsed back with parseSign1Raw to recover the identical bytes signatureLeg()/assembleSignRaw()
  // need. The tag-18 signature itself is discarded.
  const signed = envelope.sign(o, cose.ALG_MLDSA65, NEW_SEED);
  const [bodyProt, payload] = cose.parseSign1Raw(signed);
  const oldLeg = cose.signatureLeg(bodyProt, cose.ALG_MLDSA65, OLD_SEED, payload);
  const newLeg = cose.signatureLeg(bodyProt, cose.ALG_MLDSA65, NEW_SEED, payload);
  const obj = cose.assembleSignRaw(bodyProt, payload, [oldLeg, newLeg]);
  expectRejects(
    () => envelope.verifyRotationObject(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, oldPk, cose.ALG_MLDSA65, newPk, () => true, obj),
    'UnknownKind',
  );
});

test('a Sovereign verifier rejects an old leg below the profile floor with ProfileDowngrade', () => {
  // old=ML-DSA-65 (level 3), new=ML-DSA-87 (level 5), Sovereign floor 5 -> the sub-floor OLD
  // leg yields ProfileDowngrade under the ratified fail-closed default.
  const oldPk = cose.mldsaKeygen('ML-DSA-65', FLOOR_OLD_SEED);
  const newPk = cose.mldsaKeygen('ML-DSA-87', FLOOR_NEW_SEED);
  const obj = envelope.signRotationObject(workedObject(cose.PROFILE_SOVEREIGN), cose.ALG_MLDSA65,
    FLOOR_OLD_SEED, cose.ALG_MLDSA87, FLOOR_NEW_SEED);
  expectRejects(
    () => envelope.verifyRotationObject(cose.PROFILE_SOVEREIGN, cose.ALG_MLDSA65, oldPk, cose.ALG_MLDSA87, newPk, kindOk, obj),
    'ProfileDowngrade',
  );
});
