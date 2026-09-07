// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Federation higher-tier (tier 1) conformance for the TypeScript SDK, graded against the shared
// independent corpus vectors/federation/cases.json (NOT produced by this code): the deterministic
// reconcile order over the shared causal DAG, the causal validity of that order, the fact that a
// naive content-id sort is NOT causally valid (which is what distinguishes reconcile from a plain
// sort), and the byte-exact ReconcileRecord encoding (record_hex).
//
// The sign/verifyReconcile round-trip is demonstrated in isolation only: the corpus carries no
// signing seed or signature vector, so it is NOT corpus-graded here (stated honestly).
//
// Written test-first; the federation module is absent until ported, so this fails RED on import
// until impl/typescript/naalp/federation.mjs lands, and a mutation to the reconcile ready-node
// guard flips 'federation reconcile matches the oracle order'.
//
// Run:  node --test test/federation.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cose from '../naalp/cose.mjs';
import * as federation from '../naalp/federation.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'federation', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/federation/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');
const nodes = () => C.nodes.map((n) => new federation.CausalNode(hexToBytes(n.id_hex), n.causes_hex.map(hexToBytes)));

test('federation reconcile matches the oracle order', () => {
  const order = federation.reconcile(nodes());
  assert.deepEqual(order.map(bytesToHex), C.reconcile_order_hex);
});

test('federation reconcile order is causally valid', () => {
  const order = C.reconcile_order_hex.map(hexToBytes);
  assert.equal(federation.causallyValid(order, nodes()), C.reconcile_order_causally_valid);
});

test('federation naive content-id sort is NOT causally valid', () => {
  // The distinguishing property: a plain bytewise content-id sort violates causality; the
  // deterministic reconcile does not. If these agreed, reconcile could be a mere sort.
  const naive = C.naive_content_id_sort_hex.map(hexToBytes);
  assert.equal(federation.causallyValid(naive, nodes()), C.naive_causally_valid);
  assert.equal(C.naive_causally_valid, false);
});

test('federation ReconcileRecord bytes match the oracle', () => {
  const order = C.reconcile_order_hex.map(hexToBytes);
  const rec = new federation.ReconcileRecord(C.authorities, order);
  assert.equal(bytesToHex(rec.bytes()), C.record_hex);
});

// verifyReconcileOrder is the verify-event choke point of the Reconcile state machine (draft "##
// Reconcile state machine"). Mirrors impl/go/federation/verify_reconcile_test.go
// TestVerifyReconcileOrder: two causally-INDEPENDENT byte-id nodes (idA=[0x01] < idB=[0x02]) so the
// one deterministic order is [idA, idB]; a mutation that neuters the order comparison (e.g. an early
// `return null` right after reconcile()) flips the 'mismatch' and 'mismatch-length' subtests RED.
test('federation verifyReconcileOrder agrees / mismatch / mismatch-length / causal-violation', async (t) => {
  const idA = Uint8Array.of(0x01);
  const idB = Uint8Array.of(0x02);
  const concurrent = [new federation.CausalNode(idA, []), new federation.CausalNode(idB, [])];

  await t.test('agrees: the claimed order IS the deterministic order -> verified', () => {
    const rec = new federation.ReconcileRecord(['auth-1'], [idA, idB]);
    assert.equal(federation.verifyReconcileOrder(rec, concurrent), null);
  });

  await t.test('mismatch: a causally-valid but non-deterministic order -> ReconcileMismatch', () => {
    const rec = new federation.ReconcileRecord(['auth-1'], [idB, idA]);
    assert.throws(() => federation.verifyReconcileOrder(rec, concurrent),
      (e) => e.kind === 'ReconcileMismatch');
  });

  await t.test('mismatch-length: a claim that drops an element -> ReconcileMismatch', () => {
    const rec = new federation.ReconcileRecord(['auth-1'], [idA]);
    assert.throws(() => federation.verifyReconcileOrder(rec, concurrent),
      (e) => e.kind === 'ReconcileMismatch');
  });

  await t.test('causal-violation: a cyclic node set is rejected before any order comparison', () => {
    const idC = Uint8Array.of(0x03);
    const idD = Uint8Array.of(0x04);
    const cyclic = [new federation.CausalNode(idC, [idD]), new federation.CausalNode(idD, [idC])];
    const rec = new federation.ReconcileRecord(['auth-1'], [idC, idD]);
    assert.throws(() => federation.verifyReconcileOrder(rec, cyclic),
      (e) => e.kind === 'CausalViolation');
  });
});

test('federation sign/verify reconcile round-trips in isolation (not corpus-graded)', () => {
  // NOT corpus-graded: the federation corpus has no signing seed or signature vector. This
  // demonstrates the sign/verifyReconcile surface in isolation with a fixed local seed.
  const order = C.reconcile_order_hex.map(hexToBytes);
  const rec = new federation.ReconcileRecord(C.authorities, order);
  const seed = new Uint8Array(32);
  const alg = cose.ALG_MLDSA65;
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const sig = federation.signReconcile(rec, alg, seed);
  assert.equal(federation.verifyReconcile(rec, alg, pk, sig), true);
  const tampered = new federation.ReconcileRecord(['bauthority-z'], order);
  assert.equal(federation.verifyReconcile(tampered, alg, pk, sig), false);
});
