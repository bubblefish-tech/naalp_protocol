// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C21 portable gateway-decision conformance for the TypeScript SDK, graded against the shared
// independent corpus vectors/gateway/cases.json (NOT produced by this code): the closed decision
// vocabulary, the byte-exact decision body/head/content-id for allow/deny/hold, the parse
// round-trip, and the fail-closed edge cases (non-canonical body -> NonCanonical/GwMalformed,
// absent mandatory field -> GwMalformed, a look-alike object -> GwMalformed, empty vs populated
// policy distinct by content-id, and the minimal decision).
//
// The sign/verifyDecision round-trip and the third-party re-serve property are demonstrated in
// isolation only: the corpus carries no signed COSE_Sign1 vector, seed, or public key, so those are
// NOT corpus-graded here (stated honestly). What the corpus grades is the evidence-object bytes.
//
// Written test-first; the gateway module is absent until ported, so this fails RED on import until
// impl/typescript/naalp/gateway.mjs lands, and a mutation forcing the decision field to a constant
// flips 'gateway decision bodies match the oracle byte-for-byte'.
//
// Run:  node --test test/gateway.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as policy from '../naalp/policy.mjs';
import * as gateway from '../naalp/gateway.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'gateway', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/gateway/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

test('gateway decision vocabulary is the closed set', () => {
  for (const d of C.decision_vocabulary) {
    assert.equal(gateway.isKnownDecision(d.code), true, d.name);
    assert.equal(gateway.decisionName(d.code), d.name);
  }
  assert.equal(gateway.isKnownDecision(C.unknown_decision), false);
  assert.equal(gateway.decisionName(C.unknown_decision), 'unknown');
});

test('gateway decision bodies match the oracle byte-for-byte', () => {
  for (const [name, d] of Object.entries(C.decisions)) {
    const gd = new gateway.GatewayDecision(d.decision, hexToBytes(d.action_hex), hexToBytes(d.policy_hex), d.effect);
    assert.equal(bytesToHex(gd.bytes()), d.body_hex, name);
    assert.equal(bytesToHex(gd.head()), d.head_hex, name);
    assert.equal(bytesToHex(gd.id()), d.id_hex, name);
    assert.equal(gd.effectClass(), policy.normalizeEffect(d.effect), name);
  }
});

test('gateway parseDecision round-trips the oracle bodies', () => {
  for (const [name, d] of Object.entries(C.decisions)) {
    const gd = gateway.parseDecision(hexToBytes(d.body_hex));
    assert.equal(Number(gd.decision), d.decision, name);
    assert.equal(bytesToHex(gd.action), d.action_hex, name);
    assert.equal(bytesToHex(gd.policy), d.policy_hex, name);
    assert.equal(Number(gd.effect), d.effect, name);
  }
});

test('gateway rejects a non-canonical body fail-closed', () => {
  const ec = C.edge_cases.keys_out_of_order;
  // the strict decoder rejects the descending-key body (the corpus 'reject' value)
  assert.throws(() => cbor.decode(hexToBytes(ec.noncanonical_body_hex)), (e) => e.kind === 'NonCanonical');
  // parseDecision fails closed to GwMalformed
  assert.throws(() => gateway.parseDecision(hexToBytes(ec.noncanonical_body_hex)), (e) => e.kind === 'GwMalformed');
  // the canonical form of the same content parses
  const gd = gateway.parseDecision(hexToBytes(ec.canonical_body_hex));
  assert.equal(Number(gd.decision), ec.decision);
});

test('gateway distinguishes empty from absent policy', () => {
  const ev = C.edge_cases.empty_vs_absent;
  const empty = gateway.parseDecision(hexToBytes(ev.empty_policy.body_hex));
  assert.equal(bytesToHex(empty.policy), '');
  assert.equal(bytesToHex(empty.id()), ev.empty_policy.id_hex);
  const populated = gateway.parseDecision(hexToBytes(ev.populated_policy.body_hex));
  assert.equal(bytesToHex(populated.id()), ev.populated_policy.id_hex);
  // an empty policy identity is present and valid, distinct by content-id from a populated one
  assert.notEqual(bytesToHex(empty.id()), bytesToHex(populated.id()));
  // field 3 (policy) is mandatory: a body missing it is rejected fail-closed
  assert.throws(() => gateway.parseDecision(hexToBytes(ev.absent_field.body_hex)), (e) => e.kind === 'GwMalformed');
});

test('gateway minimal decision matches the oracle', () => {
  const m = C.edge_cases.minimal;
  const gd = new gateway.GatewayDecision(m.decision, hexToBytes(m.action_hex), hexToBytes(m.policy_hex), m.effect);
  assert.equal(bytesToHex(gd.bytes()), m.body_hex);
  assert.equal(bytesToHex(gd.id()), m.id_hex);
});

test('gateway rejects a look-alike object', () => {
  const la = C.edge_cases.look_alike;
  assert.throws(() => gateway.parseDecision(hexToBytes(la.body_hex)), (e) => e.kind === la.reject);
});

test('gateway sign/verify and third-party re-serve in isolation (not corpus-graded)', () => {
  // NOT corpus-graded: the gateway corpus has no signed COSE vector or key. This demonstrates
  // sign/verifyDecision and the third-party re-serve property in isolation with a local seed.
  const d = C.decisions.deny;
  const gd = new gateway.GatewayDecision(d.decision, hexToBytes(d.action_hex), hexToBytes(d.policy_hex), d.effect);
  const seed = new Uint8Array(32);
  const alg = cose.ALG_MLDSA65;
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const obj = gateway.signDecision(gd, alg, seed);
  const resolved = gateway.verifyDecision(obj, cose.PROFILE_PUBLIC, alg, pk);
  assert.equal(Number(resolved.decision), d.decision);
  assert.equal(bytesToHex(resolved.action), d.action_hex);
  assert.equal(bytesToHex(resolved.policy), d.policy_hex);
  assert.equal(resolved.effect, policy.normalizeEffect(d.effect));
  // third-party re-serve: verifyDecision takes NO serving-party identity, so the identical bytes
  // verify identically regardless of who served them.
  const resolved2 = gateway.verifyDecision(Uint8Array.from(obj), cose.PROFILE_PUBLIC, alg, pk);
  assert.deepEqual([Number(resolved2.decision), resolved2.effect], [Number(resolved.decision), resolved.effect]);
  // tampered signature -> BadSignature
  const tampered = Uint8Array.from(obj);
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => gateway.verifyDecision(tampered, cose.PROFILE_PUBLIC, alg, pk), (e) => e.kind === 'BadSignature');
  // an out-of-set decision code -> UnknownGatewayDecision (closed-set enforcement)
  const bad = new gateway.GatewayDecision(C.unknown_decision, new Uint8Array(0), new Uint8Array(0), 0);
  const badObj = gateway.signDecision(bad, alg, seed);
  assert.throws(() => gateway.verifyDecision(badObj, cose.PROFILE_PUBLIC, alg, pk), (e) => e.kind === 'UnknownGatewayDecision');
});
