// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The object-audience (field 13, §2.5.3) known-answer + gate tests for the TypeScript SDK.
//
// Three properties, all mutation-surviving:
//   1. BYTE MATCH -- an audience-bearing object reproduces the independent oracle's content id,
//      payload, protected header, and to-be-signed bytes (vectors/envelope/cases.json
//      object_with_audience), i.e. TS == Go == Rust == Python == tools/envelope_oracle.py.
//   2. checkAudience -- the three-branch point-of-use gate (absent+consume-once -> WrongAudience;
//      present+foreign -> WrongAudience; else pass).
//   3. consumeObject -- the gate is enforced at the consume choke point BEFORE the compare-and-set:
//      a wrong/absent audience is rejected WrongAudience with NO ledger append; an unnamed ledger
//      refuses LedgerUnsigned; a correct audience consumes exactly once (second -> AlreadyConsumed).
//
// Run:  node --test "test/**/*.test.mjs"      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as envelope from '../naalp/envelope.mjs';
import * as approval from '../naalp/approval.mjs';
import { U, N, B, T, M } from '../naalp/cbor.mjs';
import { HEADER_LABEL, NAALP_VERSION } from '../naalp/wire_constants_gen.mjs';

const ALG = cose.ALG_MLDSA65;   // -49
const SIGNER = Uint8Array.from(Buffer.from('5349474e45525f41', 'hex')); // "SIGNER_A" (oracle's fixed synthetic signer)
const AUDIENCE = 'consuming-authority-xyz';
const bytesToHex = (b) => Buffer.from(b).toString('hex');

function audienceObject() {
  return new envelope.Object({
    kind: 2, channel: 4, tier: 0, signer: SIGNER, created: 1785000000000n,
    effect: 2, profile: 1, body: new T('hello'), audience: AUDIENCE,
  });
}

// The protected header (invariant of audience); reconstructed here because envelope.protectedHeader
// is module-private -- same construction as envelope.sign.
function protectedHeader() {
  const naalp = new M([
    [new U(1), new B(SIGNER)],
    [new U(2), new U(1n)],                    // profile 1
    [new U(3), new U(BigInt(NAALP_VERSION))], // version 2
  ]);
  return cbor.encode(new M([[new U(1), new N(ALG)], [new T(HEADER_LABEL), naalp]]));
}

function findVector() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'envelope', 'cases.json');
    if (existsSync(p)) return p;
    d = dirname(d);
  }
  return null;
}

test('audience object reproduces the oracle bytes (content id, payload, protected, tobesigned)', () => {
  const p = findVector();
  if (!p) { return; } // committed oracle vector not present (standalone install)
  const want = JSON.parse(readFileSync(p, 'utf8')).object_with_audience;
  const o = audienceObject();
  o.id = o.contentId();
  const payload = cbor.encode(o.bodyMap(true));
  const prot = protectedHeader();
  const tbs = cose.toBeSignedRaw(prot, payload);
  assert.equal(bytesToHex(o.contentId()), want.content_id_hex, 'content id');
  assert.equal(bytesToHex(payload), want.payload_hex, 'payload');
  assert.equal(bytesToHex(prot), want.protected_hex, 'protected header');
  assert.equal(bytesToHex(tbs), want.tobesigned_hex, 'to-be-signed');
});

test('omit-when-empty is additive: a no-audience object carries no field 13', () => {
  const o = new envelope.Object({
    kind: 2, channel: 4, tier: 0, signer: SIGNER, created: 1785000000000n,
    effect: 2, profile: 1, body: new T('hello'),
  });
  const bodyHex = bytesToHex(cbor.encode(o.bodyMap(false)));
  assert.ok(!bodyHex.slice(-8).includes('0d'), 'no-audience body must not carry field 13 (0x0d)');
  const oa = audienceObject();
  assert.ok(cbor.encode(oa.bodyMap(false)).length > cbor.encode(o.bodyMap(false)).length);
});

function gateObj(aud) {
  return new envelope.Object({ kind: 2, channel: 4, signer: SIGNER, created: 0, effect: 0, body: new T('x'), audience: aud });
}
function expectWrongAudience(fn) {
  assert.throws(fn, (e) => e instanceof envelope.EnvelopeError && e.kind === 'WrongAudience');
}

test('checkAudience: consume-once accepts the matching authority', () => {
  assert.equal(envelope.checkAudience(gateObj('authority-A'), 'authority-A', true), undefined);
});
test('checkAudience: consume-once rejects a foreign audience', () => {
  expectWrongAudience(() => envelope.checkAudience(gateObj('authority-B'), 'authority-A', true));
});
test('checkAudience: consume-once rejects an absent audience', () => {
  expectWrongAudience(() => envelope.checkAudience(gateObj(''), 'authority-A', true));
});
test('checkAudience: unrestricted accepts an absent audience', () => {
  assert.equal(envelope.checkAudience(gateObj(''), 'authority-A', false), undefined);
});
test('checkAudience: unrestricted accepts the matching authority', () => {
  assert.equal(envelope.checkAudience(gateObj('authority-A'), 'authority-A', false), undefined);
});
test('checkAudience: a foreign audience is rejected even for a non-consume-once object', () => {
  expectWrongAudience(() => envelope.checkAudience(gateObj('authority-B'), 'authority-A', false));
});

function withLedger(authority, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'naalp-audience-'));
  const path = join(dir, 'ledger.wal');
  const led = approval.openLedger(path, authority);
  try { fn(led); } finally { led.close(); rmSync(dir, { recursive: true, force: true }); }
}
const aid = () => Uint8Array.from(Array.from({ length: 50 }, (_, i) => i));

test('consumeObject: a wrong audience is rejected WrongAudience with no ledger append', () => {
  withLedger('authority-A', (led) => {
    expectWrongAudience(() => led.consumeObject(gateObj('authority-B'), aid(), 'consumer'));
    assert.equal(led.len(), 0, 'a rejected consume MUST NOT append a ledger entry');
  });
});
test('consumeObject: an absent audience is rejected WrongAudience with no ledger append', () => {
  withLedger('authority-A', (led) => {
    expectWrongAudience(() => led.consumeObject(gateObj(''), aid(), 'consumer'));
    assert.equal(led.len(), 0);
  });
});
test('consumeObject: a correct audience consumes exactly once', () => {
  withLedger('authority-A', (led) => {
    led.consumeObject(gateObj('authority-A'), aid(), 'consumer');
    assert.equal(led.len(), 1);
    assert.throws(() => led.consumeObject(gateObj('authority-A'), aid(), 'consumer'),
      (e) => e instanceof approval.ApprovalError && e.kind === 'AlreadyConsumed');
  });
});
test('consumeObject: an unnamed ledger refuses LedgerUnsigned', () => {
  withLedger('', (led) => {
    assert.throws(() => led.consumeObject(gateObj('authority-A'), aid(), 'consumer'),
      (e) => e instanceof approval.ApprovalError && e.kind === 'LedgerUnsigned');
  });
});
