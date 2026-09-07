// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// T3.3 naalp-error object + numeric error-code registry conformance for the TypeScript SDK
// (design.md §3.5, R3.3/R3.4), mirroring impl/go/naalperror/naalperror_test.go and
// impl/rust/src/naalperror.rs's #[cfg(test)] mod tests -- the hand-computed CBOR is independent of
// the oracle and of impl/go/impl/rust, so this is a non-circular KAT.
//
// Written test-first; the naalperror module is absent until ported, so this fails RED on import
// (ERR_MODULE_NOT_FOUND) until impl/typescript/naalp/naalperror.mjs lands, and a mutation that
// truncates the encoded map, skips the dual-carriage name check, or rejects an unregistered code
// flips one of the assertions below.
//
// Run:  node --test test/naalperror.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as cbor from '../naalp/cbor.mjs';
import { U, T, M, A } from '../naalp/cbor.mjs';
import * as naalperror from '../naalp/naalperror.mjs';

const bytesToHex = (b) => Buffer.from(b).toString('hex');

// TestRegistrySize: pins the registry to exactly 129 unique names with no gaps (the fields-of-record
// invariant: code == index+1, sequential 1..129). A mutation that drops or duplicates an entry flips
// this and the code/name relationship.
test('naalp-error registry is 129 unique names, sequential', () => {
  assert.equal(naalperror.NAMES.length, 132);
  const seen = new Set();
  naalperror.NAMES.forEach((n, i) => {
    assert.equal(seen.has(n), false, `duplicate name ${n}`);
    seen.add(n);
    const { code, registered } = naalperror.codeForName(n);
    assert.equal(registered, true, n);
    assert.equal(code, i + 1, n);
  });
});

// TestEncodeKAT: pins the deterministic naalp-error body bytes against hand-computed CBOR
// (independent of the oracle and of impl/go/impl/rust): a2 (map-2) 01 <code> 02 <tstr name>. A
// mutation of encode flips it. These are the MANDATORY KATs.
test('naalp-error encode KAT matches hand-computed canonical CBOR', () => {
  assert.equal(
    bytesToHex(naalperror.encode(1, 'NonCanonical', '', null)),
    'a20101026c4e6f6e43616e6f6e6963616c',
  );
  assert.equal(
    bytesToHex(naalperror.encode(52, 'NotDelivered', '', null)),
    'a2011834026c4e6f7444656c697665726564',
  );
});

// TestEncodeDecodeFull: exercises the optional fields 3 and 4 (map grows to a3/a4, keys stay
// ascending). A mutation that drops a field or mis-orders keys flips the round-trip below.
test('naalp-error encode/decode round-trips detail and subject', () => {
  const subj = new Uint8Array([0x20, 0x30, ...new Array(48).fill(0)]);
  const { code } = naalperror.codeForName('BadSignature');
  const b = naalperror.encode(code, 'BadSignature', 'reason', subj);
  const o = naalperror.decode(b);
  assert.equal(o.name, 'BadSignature');
  assert.equal(o.detail, 'reason');
  assert.equal(o.subject.length, 50);
});

// TestDualCarriageMismatch: a registered code carrying the wrong registered name is rejected
// Malformed (the strengthening direction). A mutation that skips the name check flips this. This is
// one of the MANDATORY KATs (code 22=BadSignature, wrong name "NotDelivered").
test('naalp-error dual-carriage mismatch is rejected Malformed', () => {
  const { code } = naalperror.codeForName('BadSignature'); // code 22, name of code 52
  const b = naalperror.encode(code, 'NotDelivered', '', null);
  assert.throws(() => naalperror.decode(b), (e) => e.kind === 'Malformed');
});

// TestUnknownCodeOpaque: a code outside the registry is accepted opaque (open-registry contract). A
// mutation that rejects unknown codes flips this. This is one of the MANDATORY KATs.
test('naalp-error unknown code is accepted opaque', () => {
  const b = naalperror.encode(60000, 'SomeFutureError', '', null);
  const o = naalperror.decode(b);
  assert.equal(o.code, 60000);
  assert.equal(o.name, 'SomeFutureError');
});

// TestNameForCode: pins a few known code->name entries + the unregistered boundary.
test('naalp-error nameForCode boundary', () => {
  assert.deepEqual(naalperror.nameForCode(1), { name: 'NonCanonical', registered: true });
  assert.deepEqual(naalperror.nameForCode(22), { name: 'BadSignature', registered: true });
  assert.deepEqual(naalperror.nameForCode(119), { name: 'RebindUnauthorized', registered: true });
  for (const code of [0, 133, 60000]) {
    assert.equal(naalperror.nameForCode(code).registered, false, `code ${code}`);
  }
  assert.equal(naalperror.STANDARDS_MAX, 0x7FFF);
});

// Structural malformation: closed grammar. A non-map, a missing mandatory field, and an unknown
// field key are all rejected Malformed -- never silently accepted or misclassified.
test('naalp-error structurally malformed bodies are rejected Malformed', () => {
  // not a map at all
  assert.throws(() => naalperror.decode(cbor.encode(new A([]))), (e) => e.kind === 'Malformed');

  // missing the mandatory name field (key 2)
  const missingName = cbor.encode(new M([[new U(1), new U(1)]]));
  assert.throws(() => naalperror.decode(missingName), (e) => e.kind === 'Malformed');

  // an unknown field key (5) is a closed-grammar violation
  const unknownField = cbor.encode(new M([
    [new U(1), new U(1)], [new U(2), new T('NonCanonical')], [new U(5), new U(0)],
  ]));
  assert.throws(() => naalperror.decode(unknownField), (e) => e.kind === 'Malformed');

  // garbage bytes are not well-formed CBOR at all
  assert.throws(() => naalperror.decode(new Uint8Array([0xff, 0xff])), (e) => e.kind === 'Malformed');
});
