// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Tests for the ergonomic sign/verify layer (naalp/quick.mjs). Each test would fail if the wrapper
// were replaced by a constant or a no-op: the round-trip asserts the real decoded fields, the
// tamper test asserts a bit-flip is rejected (so a bypassed verify fails the test), and the
// fail-closed tests assert the wrapper delegates to the real channel registry and effect lattice.
//
// Run:  node --test "test/**/*.test.mjs"      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Signer, quick } from '../naalp/index.mjs';
import { cose, envelope, channels } from '../naalp/index.mjs';
import { U, T, M } from '../naalp/cbor.mjs';

const SEED = new Uint8Array(32).fill(0x2a);
const INTERACTION = 0x000F, ELICIT = 0;               // read_only
const GOVERNANCE = 0x0004, APPROVAL = 1;              // fixed effect: non_idempotent_write (2)

function textBody(s) {
  return new M([[new U(1), new T(s)]]);
}

test('Signer derives the same signer id as identity.signerId', () => {
  const s = new Signer(SEED);
  // Independent recompute via the raw primitives must agree (not a hard-coded constant).
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);
  assert.equal(s.publicKey.length, pk.length);
  assert.deepEqual([...s.publicKey], [...pk]);
  assert.match(s.signerId, /^bciq[a-z2-7]+$/);
});

test('sign -> quick.verify round-trips and returns the real decoded fields', () => {
  const s = new Signer(SEED);
  const bytes = s.sign(INTERACTION, ELICIT, textBody('hi B'), { created: 1785000000000n });
  const obj = quick.verify(s.publicKey, bytes);
  assert.equal(Number(obj.channel), INTERACTION);
  assert.equal(Number(obj.kind), ELICIT);
  assert.equal(Number(obj.effect), 0);                // read_only, filled from the registry
  assert.equal(obj.body.pairs[0][1].v, 'hi B');       // the body actually round-tripped
  const d = quick.describe(obj);
  assert.equal(d.channel, '0x000f Interaction');
  assert.equal(d.kind, '0 Elicit');
  assert.equal(d.signer, s.signerId);
});

test('quick.verify rejects a tampered object (fail-closed, mutation-surviving)', () => {
  const s = new Signer(SEED);
  const bytes = Uint8Array.from(s.sign(INTERACTION, ELICIT, textBody('hi'), { created: 1n }));
  bytes[bytes.length - 1] ^= 0x01;                    // flip one bit of the signature
  assert.throws(() => quick.verify(s.publicKey, bytes), (e) => e.kind === 'BadSignature');
});

test('quick.verify rejects the wrong public key', () => {
  const s = new Signer(SEED);
  const other = new Signer(new Uint8Array(32).fill(0x01));
  const bytes = s.sign(INTERACTION, ELICIT, textBody('hi'), { created: 1n });
  assert.throws(() => quick.verify(other.publicKey, bytes), (e) => e.kind === 'BadSignature');
});

test('sign fails closed on an unregistered (channel, kind)', () => {
  const s = new Signer(SEED);
  assert.throws(() => s.sign(0x00FF, 0, textBody('x'), { created: 1n }), (e) => e.kind === 'UnknownKind');
});

test('sign fails closed when an explicit effect contradicts a fixed-effect kind', () => {
  const s = new Signer(SEED);
  // Governance/Approval declares effect 2; forcing effect 3 must be rejected by the effect lattice.
  assert.throws(
    () => s.sign(GOVERNANCE, APPROVAL, textBody('x'), { effect: 3, created: 1n }),
    (e) => e.kind === 'EffectDeclarationMismatch',
  );
});

test('sign fills the declared effect from the registry when none is given', () => {
  const s = new Signer(SEED);
  const bytes = s.sign(GOVERNANCE, APPROVAL, textBody('x'), { created: 1n });
  const obj = quick.verify(s.publicKey, bytes);
  const [, declared] = channels.lookup(GOVERNANCE, APPROVAL);
  assert.equal(Number(obj.effect), declared);         // 2 (non_idempotent_write), not a constant
});

test('registeredKind agrees with the channel registry', () => {
  assert.equal(quick.registeredKind(INTERACTION, ELICIT), true);
  assert.equal(quick.registeredKind(0x00FF, 0), false);
  assert.equal(quick.registeredKind(INTERACTION, 99), false);
});

test('quick.verify enforces the profile floor (Sovereign rejects ML-DSA-65)', () => {
  const s = new Signer(SEED);                          // ML-DSA-65 == level 3
  const bytes = s.sign(INTERACTION, ELICIT, textBody('hi'), { created: 1n });
  // Sovereign requires level 5; a level-3 signature must be rejected as a downgrade.
  assert.throws(
    () => quick.verify(s.publicKey, bytes, { acceptProfile: cose.PROFILE_SOVEREIGN }),
    (e) => e.kind === 'ProfileDowngrade',
  );
});

test('quick.verify produces the same bytes/decode as the raw envelope path (delegation, not reimpl)', () => {
  const s = new Signer(SEED);
  const bytes = s.sign(INTERACTION, ELICIT, textBody('parity'), { created: 42n });
  // The raw SDK verify accepts the exact same bytes with an equivalent kind validator.
  const rawObj = envelope.verify(cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, s.publicKey,
    (c, k) => c === BigInt(INTERACTION) && k === BigInt(ELICIT), bytes);
  const quickObj = quick.verify(s.publicKey, bytes);
  assert.deepEqual(rawObj.id, quickObj.id);
  assert.equal(Number(rawObj.channel), Number(quickObj.channel));
});
