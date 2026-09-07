// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// R1 ordering (field 5) + R8 foreign-profile (field 6) conformance for the TypeScript SDK's
// naalp-gateway-decision, graded against the optional_fields{} block of the shared independent
// corpus vectors/gateway/cases.json (NOT produced by this code). Mirrors
// impl/python/tests/test_gateway.py's GatewayOptionalFieldsConformance (itself mirroring
// impl/go/gateway/gateway_test.go's optional-fields section).
//
// Written test-first against the ported gateway.mjs; a mutation forcing OrderingDisclosure.validate
// or ForeignProfilePin.validate to a no-op flips the malformed-rejection tests below.
//
// Run:  node --test test/gateway.optional.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import { U, B, T, M } from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
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

test('existing decision bodies unchanged by adding optional fields 5/6 (non-regression)', () => {
  // Pins the allow/deny/hold body_hex values as they stood BEFORE this change, independent of the
  // vector file's own drift.
  const pinnedAllow = 'a401000258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330401';
  const pinnedDeny = 'a401010258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330403';
  const pinnedHold = 'a401020258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330402';
  assert.equal(C.decisions.allow.body_hex, pinnedAllow);
  assert.equal(C.decisions.deny.body_hex, pinnedDeny);
  assert.equal(C.decisions.hold.body_hex, pinnedHold);
  for (const [name, dv] of Object.entries(C.decisions)) {
    const gd = new gateway.GatewayDecision(dv.decision, hexToBytes(dv.action_hex), hexToBytes(dv.policy_hex), dv.effect);
    assert.equal(bytesToHex(gd.bytes()), dv.body_hex, name);
  }
});

test('optional fields 5/6 round-trip byte-exact against the oracle', () => {
  const of = C.optional_fields;

  const wo = of.with_ordering;
  {
    const d = new gateway.GatewayDecision(
      wo.decision, hexToBytes(wo.action_hex), hexToBytes(wo.policy_hex), wo.effect,
      new gateway.OrderingDisclosure(wo.ordering.basis, hexToBytes(wo.ordering.boundary_hex)));
    assert.equal(bytesToHex(d.bytes()), wo.body_hex, 'with_ordering');
    assert.equal(bytesToHex(d.id()), wo.id_hex, 'with_ordering');
    const parsed = gateway.parseDecision(hexToBytes(wo.body_hex));
    assert.notEqual(parsed.ordering, null);
    assert.equal(parsed.foreignProfile, null);
    assert.equal(Number(parsed.ordering.basis), wo.ordering.basis);
    assert.equal(bytesToHex(parsed.ordering.boundary), wo.ordering.boundary_hex);
    parsed.ordering.validate(); // no throw
  }

  const wf = of.with_foreign_profile;
  {
    const d = new gateway.GatewayDecision(
      wf.decision, hexToBytes(wf.action_hex), hexToBytes(wf.policy_hex), wf.effect, null,
      new gateway.ForeignProfilePin(wf.foreign_profile.id, wf.foreign_profile.revision));
    assert.equal(bytesToHex(d.bytes()), wf.body_hex, 'with_foreign_profile');
    assert.equal(bytesToHex(d.id()), wf.id_hex, 'with_foreign_profile');
    const parsed = gateway.parseDecision(hexToBytes(wf.body_hex));
    assert.equal(parsed.ordering, null);
    assert.notEqual(parsed.foreignProfile, null);
    assert.equal(parsed.foreignProfile.id, wf.foreign_profile.id);
    assert.equal(parsed.foreignProfile.revision, wf.foreign_profile.revision);
    parsed.foreignProfile.validate(); // no throw
  }

  const wb = of.with_both;
  {
    const d = new gateway.GatewayDecision(
      wb.decision, hexToBytes(wb.action_hex), hexToBytes(wb.policy_hex), wb.effect,
      new gateway.OrderingDisclosure(wb.ordering.basis, undefined, hexToBytes(wb.ordering.mechanism_hex), hexToBytes(wb.ordering.relation_hex)),
      new gateway.ForeignProfilePin(wb.foreign_profile.id, wb.foreign_profile.revision));
    assert.equal(bytesToHex(d.bytes()), wb.body_hex, 'with_both');
    assert.equal(bytesToHex(d.id()), wb.id_hex, 'with_both');
    const parsed = gateway.parseDecision(hexToBytes(wb.body_hex));
    assert.notEqual(parsed.ordering, null);
    assert.notEqual(parsed.foreignProfile, null);
    parsed.ordering.validate();
    parsed.foreignProfile.validate();
    // Full end-to-end: signs and verifies with both optional fields present.
    const seed = new Uint8Array(32).fill(0x71);
    const alg = cose.ALG_MLDSA65;
    const pk = cose.mldsaKeygen('ML-DSA-65', seed);
    const obj = gateway.signDecision(d, alg, seed);
    gateway.verifyDecision(obj, cose.PROFILE_PUBLIC, alg, pk); // no throw
  }
});

test('foreign-profile-pin missing revision is structurally decodable but validate() rejects it', () => {
  const fm = C.optional_fields.foreign_profile_malformed;
  const body = hexToBytes(fm.body_hex);
  const parsed = gateway.parseDecision(body);
  assert.notEqual(parsed.foreignProfile, null);
  assert.throws(() => parsed.foreignProfile.validate(), (e) => e.kind === 'ForeignProfileMalformed');

  const seed = new Uint8Array(32).fill(0x72);
  const alg = cose.ALG_MLDSA65;
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const obj = cose.coseSign1(alg, seed, gateway.gatewayProtectedHeader(alg), body);
  assert.throws(() => gateway.verifyDecision(obj, cose.PROFILE_PUBLIC, alg, pk), (e) => e.kind === 'ForeignProfileMalformed');
});

test('ordering-disclosure external-mechanism with a boundary present is structurally decodable but validate() rejects it', () => {
  const om = C.optional_fields.ordering_malformed;
  const body = hexToBytes(om.body_hex);
  const parsed = gateway.parseDecision(body);
  assert.notEqual(parsed.ordering, null);
  assert.throws(() => parsed.ordering.validate(), (e) => e.kind === 'OrderingDisclosureMalformed');

  const seed = new Uint8Array(32).fill(0x73);
  const alg = cose.ALG_MLDSA65;
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const obj = cose.coseSign1(alg, seed, gateway.gatewayProtectedHeader(alg), body);
  assert.throws(() => gateway.verifyDecision(obj, cose.PROFILE_PUBLIC, alg, pk), (e) => e.kind === 'OrderingDisclosureMalformed');
});

test('ForeignProfilePin.validate direct unit coverage (no oracle vector needed)', () => {
  const cases = [
    ['both present', new gateway.ForeignProfilePin('https://example.test/p', '1'), false],
    ['missing id', new gateway.ForeignProfilePin('', '1'), true],
    ['missing revision', new gateway.ForeignProfilePin('https://example.test/p', ''), true],
    ['both empty', new gateway.ForeignProfilePin('', ''), true],
  ];
  for (const [name, pin, wantErr] of cases) {
    if (wantErr) {
      assert.throws(() => pin.validate(), (e) => e.kind === 'ForeignProfileMalformed', name);
    } else {
      pin.validate(); // no throw
    }
  }
});

test('a foreign-profile-pin carrying a third key beyond {1,2} decodes structurally but fails validate()', () => {
  const fp = new M([
    [new U(1), new T('https://example-registry.test/profiles/acme')],
    [new U(2), new T('2026-01')],
    [new U(3), new T('unexpected')],
  ]);
  const m = new M([
    [new U(1), new U(gateway.DECISION_ALLOW)],
    [new U(2), new B(hexToBytes(C.action_cid_hex))],
    [new U(3), new B(hexToBytes(C.policy_hex))],
    [new U(4), new U(1)],
    [new U(6), fp],
  ]);
  const body = cbor.encode(m);
  const parsed = gateway.parseDecision(body);
  assert.notEqual(parsed.foreignProfile, null);
  assert.equal(parsed.foreignProfile.id, 'https://example-registry.test/profiles/acme');
  assert.equal(parsed.foreignProfile.revision, '2026-01');
  assert.throws(() => parsed.foreignProfile.validate(), (e) => e.kind === 'ForeignProfileMalformed');
});
