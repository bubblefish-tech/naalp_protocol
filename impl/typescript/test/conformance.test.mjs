// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Self-contained conformance smoke tests over the SDK primitives, anchored to independent standards
// vectors (FIPS 180-4 SHA-384, RFC 8949 canonical CBOR, the multiformats signer-id, the §6.1 effect
// lattice). The authoritative cross-language grading is the naalp-conform harness against the
// 239-case corpus; these keep the published package independently checkable.
//
// Run:  node --test "test/**/*.test.mjs"      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { cbor, cose, identity, policy, records, channels } from '../naalp/index.mjs';
import { U, M, NonCanonical } from '../naalp/cbor.mjs';

const bytesToHex = (b) => Buffer.from(b).toString('hex');
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));

test('SHA-384 matches the FIPS 180-4 "abc" KAT', () => {
  assert.equal(
    createHash('sha384').update('abc').digest('hex'),
    'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
  );
});

test('CBOR canonicalizes map keys and the content id carries the sha2-384 multihash prefix', () => {
  // canonical map: keys emitted in bytewise-ascending order regardless of input order
  const m = new M([[new U(3), new U(4)], [new U(2), new U(0)]]);
  assert.equal(bytesToHex(cbor.encode(m)), 'a202000304');
  const cid = cbor.contentId(cbor.encode(m));
  assert.deepEqual(Array.from(cid.slice(0, 2)), [0x20, 0x30]); // multihash sha2-384 prefix
  assert.equal(cid.length, 2 + 48);
});

test('CBOR decode rejects non-canonical inputs', () => {
  for (const bad of ['a202000100', '1800', '9f00ff', 'a201000101']) { // out-of-order/non-shortest/indefinite/dup
    assert.throws(() => cbor.decode(hexToBytes(bad)), NonCanonical);
  }
});

test('COSE ToBeSigned is the RFC 9052 Sig_structure', () => {
  const tbs = cose.toBeSignedRaw(hexToBytes('a1013830'), hexToBytes('a10700'));
  assert.equal(bytesToHex(tbs).startsWith('846a5369676e617475726531'), true); // ["Signature1", ...]
});

test('signer id is a multibase base32 string', () => {
  const pk = cose.mldsaKeygen('ML-DSA-65', new Uint8Array(32));
  const sid = identity.signerId(cose.ALG_MLDSA65, pk);
  assert.equal(sid.startsWith('b'), true); // multibase base32 prefix
});

test('the effect lattice fails closed and honors the §6.1 ceiling', () => {
  assert.equal(policy.normalizeEffect(99), policy.DESTRUCTIVE); // unknown -> destructive
  assert.equal(policy.authorizes(policy.NON_IDEMPOTENT_WRITE, policy.IDEMPOTENT_WRITE), true);
  assert.equal(policy.authorizes(policy.READ_ONLY, policy.DESTRUCTIVE), false);
});

test('the channel registry resolves Governance.Approval and rejects an unknown kind', () => {
  const [name, effect, variable] = channels.lookup(0x0004, 1); // Governance.Approval
  assert.deepEqual([name, effect, variable], ['Approval', policy.NON_IDEMPOTENT_WRITE, false]);
  assert.throws(() => channels.lookup(0x0000, 9999), (e) => e.kind === 'UnknownKind');
});

test('a receipt body is deterministic and its head is SHA-384 of it', () => {
  const body = records.receiptBody(new Uint8Array(48), hexToBytes('2030' + '00'.repeat(48)), 0, 100);
  assert.equal(bytesToHex(records.receiptHead(body)), createHash('sha384').update(Buffer.from(body)).digest('hex'));
});

test('the profile floor exposes the NIST security levels the envelope enforces', () => {
  const [lvl, known] = cose.algLevel(cose.ALG_MLDSA65);
  assert.deepEqual([lvl, known], [3, true]);
  assert.equal(cose.algLevel(0)[1], false); // unregistered alg
  assert.equal(cose.profileMinLevel(cose.PROFILE_SOVEREIGN), 5);
  assert.equal(cose.profileMinLevel(cose.PROFILE_PUBLIC), 3);
});
