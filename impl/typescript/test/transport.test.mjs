// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C11 transport-binding conformance for the TypeScript SDK, graded against the shared independent
// corpus vectors/transport/cases.json (NOT produced by this code): the media type, the four
// bindings' confidentiality/peer-auth guarantees, the framing round-trip, and the §12.3/§12.4 emit
// boundary matrix. Written test-first; the transport module is absent until ported, so this fails
// RED on import until impl/typescript/naalp/transport.mjs lands, and a mutation to the emit boundary
// or a transport flag flips a named assertion.
//
// Run:  node --test test/transport.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as transport from '../naalp/transport.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'transport', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/transport/cases.json not found');
}

const C = vectors();

test('transport media type matches the corpus', () => {
  assert.equal(transport.MEDIA_TYPE, C.media_type);
});

test('transport variants match the corpus guarantees', () => {
  for (const t of C.transports) {
    const [got, ok] = transport.byName(t.name);
    assert.ok(ok, `unknown transport ${t.name}`);
    assert.equal(got.confidential, t.confidential, `confidential mismatch for ${t.name}`);
    assert.equal(got.peerAuthenticated, t.peer_authenticated, `peer-auth mismatch for ${t.name}`);
  }
});

test('transport frame round-trips the object bytes unchanged', () => {
  const [t] = transport.byName('npamp');
  const mu = transport.frame(t, Uint8Array.of(1, 2, 3));
  assert.equal(mu.mediaType, transport.MEDIA_TYPE);
  assert.deepEqual(mu.object(), Uint8Array.of(1, 2, 3));
});

test('transport object() rejects a wrong media type as Malformed', () => {
  const mu = new transport.MessageUnit('npamp', 'application/json', Uint8Array.of(0x78));
  assert.throws(() => mu.object(), (e) => e.kind === 'Malformed');
});

test('transport emit boundary matrix matches the corpus', () => {
  const obj = new TextEncoder().encode('obj');
  for (const c of C.emit_matrix) {
    const [t, ok] = transport.byName(c.transport);
    assert.ok(ok, `unknown transport ${c.transport}`);
    if (c.result === 'ok') {
      const mu = transport.emit(t, obj, c.sensitive, c.require_peer_auth);
      assert.deepEqual(mu.object(), obj, JSON.stringify(c));
    } else {
      assert.throws(
        () => transport.emit(t, obj, c.sensitive, c.require_peer_auth),
        (e) => e.kind === c.result,
        JSON.stringify(c),
      );
    }
  }
});
