// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C8 delivery conformance for the TypeScript SDK, graded against the shared independent corpus
// vectors/delivery/cases.json (NOT produced by this code): the four monotonic stage names, the
// byte-exact signed delivery.update body for each stage, and the T1 content-id framing.
//
// The remaining C8 substance -- the persist-before-acknowledge WAL tracker, the live full-duplex
// switchboard, and the content-free relay (whose audit trail is a real C7 chain over content ids) --
// is real behaviour demonstrated in isolation (a tempfile WAL, async pumps, and the shared
// naalp/audit chain); the corpus carries no vector for those, so they are NOT corpus-graded (stated
// honestly). The delivery.update SIGNATURE is real deterministic ML-DSA-65, also in isolation.
//
// Written test-first; the delivery module is absent until ported, so this fails RED on import until
// impl/typescript/naalp/delivery.mjs lands, and a mutation forcing the encoded stage field to a
// constant flips 'delivery update bodies match the oracle byte-for-byte'.
//
// Run:  node --test test/delivery.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import * as cose from '../naalp/cose.mjs';
import * as audit from '../naalp/audit.mjs';
import * as delivery from '../naalp/delivery.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'delivery', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/delivery/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

const ALG = cose.ALG_MLDSA65;
const SEED = new Uint8Array(32);
const PK = cose.mldsaKeygen('ML-DSA-65', SEED);

test('delivery stage vocabulary', () => {
  for (const s of C.stages) {
    assert.equal(delivery.stageName(s.value), s.name, JSON.stringify(s));
  }
  assert.equal(delivery.stageName(99), 'unknown');
  // the four stage constants align with the corpus values, monotonic in order
  assert.deepEqual(
    [delivery.STAGE_PERSISTED_ORIGIN, delivery.STAGE_ACCEPTED_RELAY,
      delivery.STAGE_PERSISTED_TARGET, delivery.STAGE_PRESENTED],
    C.stages.map((s) => s.value),
  );
});

test('delivery update bodies match the oracle byte-for-byte', () => {
  // THIS is the mutation-target assertion: each of the four stages encodes a distinct body.
  const obj = hexToBytes(C.obj_content_id_hex);
  for (const uv of C.updates) {
    const u = new delivery.DeliveryUpdate(obj, uv.stage, uv.at);
    assert.equal(bytesToHex(u.bytes()), uv.body_hex, `update stage=${uv.stage}`);
  }
});

test('delivery sign/verify update in isolation', () => {
  // NOT corpus-graded (no signature vector). Real deterministic ML-DSA round-trip.
  const obj = hexToBytes(C.obj_content_id_hex);
  const u = new delivery.DeliveryUpdate(obj, delivery.STAGE_PRESENTED, 103);
  const sig = delivery.signUpdate(u, ALG, SEED);
  assert.equal(delivery.verifyUpdate(u, ALG, PK, sig), true);
  const bad = Uint8Array.from(sig);
  bad[bad.length - 1] ^= 1;
  assert.equal(delivery.verifyUpdate(u, ALG, PK, bad), false);
});

test('delivery tracker monotonic persist and replay', () => {
  // Real WAL behaviour in isolation: monotonic stages, persist-before-ack, StageOutOfOrder on
  // regression, idempotent re-report, and durable recovery after reopen.
  const obj = hexToBytes(C.obj_content_id_hex);
  const dir = mkdtempSync(join(tmpdir(), 'naalp-delivery-'));
  const path = join(dir, 'tracker.wal');
  try {
    const t = delivery.openTracker(path);
    t.advance(obj, delivery.STAGE_PERSISTED_ORIGIN, 100);
    t.advance(obj, delivery.STAGE_PERSISTED_TARGET, 102); // skipping ahead is permitted
    assert.throws(() => t.advance(obj, delivery.STAGE_ACCEPTED_RELAY, 103), // regression rejected
      (e) => e.kind === 'StageOutOfOrder');
    // re-reporting the current stage is an idempotent no-op that still returns the update
    const same = t.advance(obj, delivery.STAGE_PERSISTED_TARGET, 104);
    assert.equal(Number(same.stage), delivery.STAGE_PERSISTED_TARGET);
    assert.deepEqual(t.stage(obj), [delivery.STAGE_PERSISTED_TARGET, true]);
    t.close();
    // reopen -> replay recovers the last durable stage
    const t2 = delivery.openTracker(path);
    assert.deepEqual(t2.stage(obj), [delivery.STAGE_PERSISTED_TARGET, true]);
    assert.deepEqual(t2.stage(new TextEncoder().encode('unseen')), [0, false]);
    t2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('delivery switchboard full-duplex', async () => {
  // Two connections held open, objects relayed through both directions concurrently.
  const sb = new delivery.Switchboard(4);
  try {
    const left = sb.left();
    const right = sb.right();
    left.send(Uint8Array.from(Buffer.from('L->R')));
    right.send(Uint8Array.from(Buffer.from('R->L')));
    assert.equal(Buffer.from(await right.recv()).toString(), 'L->R');
    assert.equal(Buffer.from(await left.recv()).toString(), 'R->L');
  } finally {
    sb.close();
  }
});

test('delivery content-free relay audit trail verifies', () => {
  // A relay retains only a C7 receipt chain over content ids (no payload). The retained trail
  // verifies as a valid chain, and the content-id framing matches the shared T1 framing.
  const relay = new delivery.ContentFreeRelay(ALG, SEED);
  const one = relay.route(Uint8Array.from(Buffer.from('object-one')), 100);
  const two = relay.route(Uint8Array.from(Buffer.from('object-two')), 101);
  assert.equal(Buffer.from(one).toString(), 'object-one'); // returned for immediate forwarding
  assert.equal(Buffer.from(two).toString(), 'object-two');
  const [receipts, sigs] = relay.auditTrail();
  assert.equal(receipts.length, 2);
  // the receipt names the object's content id, not the payload
  assert.equal(bytesToHex(receipts[0].obj), bytesToHex(delivery.contentId(Uint8Array.from(Buffer.from('object-one')))));
  assert.equal(bytesToHex(delivery.contentId(Uint8Array.from(Buffer.from('object-one'))).slice(0, 2)), '2030'); // T1 framing prefix
  assert.equal(audit.verifyChain(receipts, sigs, ALG, PK), null);
});
