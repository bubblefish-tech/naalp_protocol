// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C12 foreign-carriage-by-class conformance for the TypeScript SDK, graded against the shared
// independent PER-CLASS corpus vectors/carriage/<class>/cases.json (NOT produced by this code) -- each
// of the six carriage classes (JSONRPC, HTTP, MSG, STREAM, DOC, OPAQUE) has its own oracle subdirectory.
// The corpus grades: the byte-exact carriage body {1:protocol_id,2:class,3:content_type,4:correlation,
// 5:method,6:foreign} for each class, and the round-trip identity -- the foreign message is recovered
// OCTET-FOR-OCTET (R-14.4) and re-encoding is byte-identical (round-trip identity is the independent
// authority, R-14.7). The fail-closed edges (unknown class -> MappingError, non-map / missing foreign
// -> Malformed), the protocol-id ranges, the honest delivery report (R-14.8) and the signer-is-authority
// rule (R-14.6) are demonstrated in isolation.
//
// Written test-first; the carriage module is absent until ported, so this fails RED on import
// (ERR_MODULE_NOT_FOUND) until impl/typescript/naalp/carriage.mjs lands, and a mutation truncating the
// carried foreign field flips 'carriage bodies match the per-class oracle byte-for-byte'.
//
// Run:  node --test test/carriage.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as carriage from '../naalp/carriage.mjs';

function carriageVectors(cls) {
  // PER-CLASS oracle: each carriage class grades against its own vectors/carriage/<class>/cases.json.
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'carriage', cls, 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/carriage/' + cls + '/cases.json not found');
}

const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

// subdirectory name -> class code, and the ClassName the code resolves to.
const CLASSES = [
  ['jsonrpc', carriage.CLASS_JSONRPC, 'JSONRPC'],
  ['http', carriage.CLASS_HTTP, 'HTTP'],
  ['msg', carriage.CLASS_MSG, 'MSG'],
  ['stream', carriage.CLASS_STREAM, 'STREAM'],
  ['doc', carriage.CLASS_DOC, 'DOC'],
  ['opaque', carriage.CLASS_OPAQUE, 'OPAQUE'],
];

test('carriage class vocabulary is the closed set', () => {
  for (const [name, code, cname] of CLASSES) {
    assert.equal(carriage.className(code), cname, name);
    assert.equal(carriage.validateClass(code), null, name);
  }
  assert.equal(carriage.className(6), 'unknown');
  assert.throws(() => carriage.validateClass(6), (e) => e.kind === 'MappingError');
});

test('carriage bodies match the per-class oracle byte-for-byte', () => {
  // THIS is the mutation-target assertion: each class encodes its body distinctly and the foreign
  // field is carried verbatim; truncating the foreign field flips this against every class oracle.
  for (const [name, code] of CLASSES) {
    const v = carriageVectors(name);
    assert.equal(v.class, code, `${name} subdir class code`);
    const cb = carriage.carry(v.protocol_id, v.class, v.content_type, hexToBytes(v.correlation_hex), v.method, hexToBytes(v.foreign_hex));
    assert.equal(bytesToHex(cb.bytes()), v.body_hex, `${name} body`);
  }
});

test('carriage round-trips each class body, recovering the foreign message octet-for-octet', () => {
  for (const [name] of CLASSES) {
    const v = carriageVectors(name);
    const parsed = carriage.carriageFromValue(cbor.decode(hexToBytes(v.body_hex)));
    assert.equal(Number(parsed.protocolId), v.protocol_id, name);
    assert.equal(Number(parsed.klass), v.class, name);
    assert.equal(Number(parsed.contentType), v.content_type, name);
    assert.equal(bytesToHex(parsed.correlation), v.correlation_hex, name);
    assert.equal(parsed.method, v.method, name);
    // R-14.4 / R-14.7: the foreign field is recovered VERBATIM, and re-encoding is byte-identical.
    assert.equal(bytesToHex(parsed.foreign), v.foreign_hex, `${name} foreign octet-for-octet`);
    assert.equal(bytesToHex(parsed.bytes()), v.body_hex, `${name} round-trip identity`);
  }
});

test('carriage parsing is fail-closed', () => {
  // an unknown class code is a MappingError, never a silent drop (R-14.8).
  assert.throws(() => carriage.carry(0x10, 6, 0, new Uint8Array(0), '', new Uint8Array(0)), (e) => e.kind === 'MappingError');
  // a non-map body is Malformed (80 = array(0)).
  assert.throws(() => carriage.carriageFromValue(cbor.decode(hexToBytes('80'))), (e) => e.kind === 'Malformed');
  // a body missing the mandatory foreign field (key 6) is Malformed.
  const noForeign = cbor.encode(new cbor.M([[new cbor.U(1), new cbor.U(1)], [new cbor.U(2), new cbor.U(0)]]));
  assert.throws(() => carriage.carriageFromValue(cbor.decode(noForeign)), (e) => e.kind === 'Malformed');
});

test('carriage protocol-id ranges match the design', () => {
  assert.equal(carriage.protocolRange(0x00), 'reserved');
  assert.equal(carriage.protocolRange(0x01), 'standards');
  assert.equal(carriage.protocolRange(0x0F), 'standards');
  assert.equal(carriage.protocolRange(0x10), 'experimental');
  assert.equal(carriage.protocolRange(0x7F), 'experimental');
  assert.equal(carriage.protocolRange(0x80), 'private');
  assert.equal(carriage.protocolRange(0xFF), 'private');
  assert.equal(carriage.protocolRange(0x100), 'invalid');
});

test('carriage delivery report is honest and authority is the N-AALP signer, never a foreign principal', () => {
  assert.equal(carriage.report(true).delivered, true);
  assert.throws(() => carriage.report(false), (e) => e.kind === 'NotDelivered');
  // R-14.6: the authorizing principal is the N-AALP signer of the carriage object, never a foreign
  // principal named inside the foreign bytes.
  const signer = Uint8Array.from(Buffer.from('agent-n-aalp-signer'));
  assert.equal(bytesToHex(carriage.carriageAuthority({ signer })), bytesToHex(signer));
});
