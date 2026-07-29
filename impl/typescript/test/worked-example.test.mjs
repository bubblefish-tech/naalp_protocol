// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The full-object known-answer test: the reference worked object (fixed seed 0x2a*32) MUST be
// reproduced byte-for-byte, and the resulting object MUST verify and reject tampering. When the
// repository's committed vector (vectors/worked/example.json) is present the exact bytes are
// compared; standalone (after `npm install`) the crypto round-trip is still checked self-contained.
//
// Run:  node --test "test/**/*.test.mjs"      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { cose, identity, envelope } from '../naalp/index.mjs';
import { U, B, T, M } from '../naalp/cbor.mjs';

const SEED = new Uint8Array(32).fill(0x2a);
const ALG = cose.ALG_MLDSA65;
// short, self-contained KAT anchors (from vectors/worked/example.json)
const SIGNER_ID = 'bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua';
const CONTENT_ID_HEX = '2030192922f9be80623bea1c689ddfe91dc15303abc851c8811b86cf9e53b837b5cc99d9c17e3acf95279f55e48203f79134';
const ARGS_ID_HEX = '20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff';

const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

function workedObject() {
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);
  const signerId = identity.signerId(ALG, pk);
  const body = new M([
    [new U(1), new B(hexToBytes(ARGS_ID_HEX))],
    [new U(2), new T(signerId)],
    [new U(3), new U(2)],
    [new U(4), new B(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8))],
    [new U(5), new U(1785000000000n)],
  ]);
  const obj = new envelope.Object({
    kind: 1, channel: 4, tier: 0, signer: new TextEncoder().encode(signerId),
    created: 1785000000000n, effect: 2, profile: cose.PROFILE_PUBLIC, body,
  });
  return { pk, signerId, obj };
}

function findVector() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'worked', 'example.json');
    if (existsSync(p)) return p;
    d = dirname(d);
  }
  return null;
}

test('signer id and content id reproduce the KAT anchors', () => {
  const { signerId, obj } = workedObject();
  assert.equal(signerId, SIGNER_ID);
  assert.equal(bytesToHex(obj.contentId()), CONTENT_ID_HEX);
});

test('sign/verify round-trips a full object', () => {
  const { pk, obj } = workedObject();
  const signed = envelope.sign(obj, ALG, SEED);
  const got = envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, (c, k) => c === 4n && k === 1n, signed);
  assert.deepEqual([got.kind, got.channel, got.effect], [1n, 4n, 2n]);
});

test('a tampered object is rejected with BadSignature', () => {
  const { pk, obj } = workedObject();
  const signed = Uint8Array.from(envelope.sign(obj, ALG, SEED));
  signed[signed.length - 1] ^= 1;
  assert.throws(
    () => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, () => true, signed),
    (e) => e.kind === 'BadSignature',
  );
});

test('the signed object reproduces the committed worked-example bytes', () => {
  const p = findVector();
  if (!p) { console.log('  (committed vector not present — standalone install; skipping byte-exact check)'); return; }
  const want = JSON.parse(readFileSync(p, 'utf-8'));
  const { obj } = workedObject();
  const signed = envelope.sign(obj, ALG, SEED);
  assert.equal(bytesToHex(signed), want.signed_object_hex);
  assert.equal(bytesToHex(obj.contentId()), want.content_id_hex);
});
