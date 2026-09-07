// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C5 authorization conformance for the TypeScript SDK (design §6.3, §6.5), graded against the shared
// independent corpus vectors/effect/cases.json (NOT produced by this code): the authorization_matrix
// (Grant.authorizeObject's accept/deny lattice -- action <= ceiling), principal_sources (only a
// signature-derived identity is ever an authorization principal, R-6.5 -- checked both directly via
// resolveAuthPrincipal and end-to-end via a maximally-permissive Grant presenting a read_only
// object), and safety_label (SafetyLabelFromExt: present / absent / malformed / incomplete, fail-
// closed -- a malformed label is REJECTED, never silently accepted).
//
// MUTATION TARGET: forcing Grant.authorizeObject to unconditionally return (bypassing both the
// principal-match check and the ceiling check) flips 'policy authorization_matrix matches the oracle
// lattice (accept iff allow)' on every denied row (allow:false), which would then wrongly pass.
//
// Run:  node --test test/policy.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { U, T, M } from '../naalp/cbor.mjs';
import * as policy from '../naalp/policy.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'effect', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/effect/cases.json not found');
}

const C = vectors();

const SOURCE_BY_NAME = {
  signature: policy.SOURCE_SIGNATURE,
  transport_metadata: policy.SOURCE_TRANSPORT_METADATA,
  foreign_header: policy.SOURCE_FOREIGN_HEADER,
  client_name: policy.SOURCE_CLIENT_NAME,
};

// ---- authorization_matrix: Grant.authorizeObject accept/deny lattice ----------------------------

test('policy authorization_matrix matches the oracle lattice (accept iff allow)', () => {
  const rows = C.authorization_matrix;
  assert.equal(rows.length, 16, 'oracle carries all 16 granted x effect combinations');
  for (const row of rows) {
    const grant = new policy.Grant('pA', row.granted);
    if (row.allow) {
      assert.doesNotThrow(
        () => grant.authorizeObject(policy.SOURCE_SIGNATURE, 'pA', row.effect),
        `granted=${row.granted} effect=${row.effect} should authorize`,
      );
    } else {
      assert.throws(
        () => grant.authorizeObject(policy.SOURCE_SIGNATURE, 'pA', row.effect),
        (e) => e.kind === 'EffectNotAuthorized',
        `granted=${row.granted} effect=${row.effect} should deny EffectNotAuthorized`,
      );
    }
  }
});

test('policy authorizeObject denies a mismatched principal even under a sufficient ceiling', () => {
  // who != grant.principal is EffectNotAuthorized regardless of how permissive maxEffect is.
  const grant = new policy.Grant('pA', policy.DESTRUCTIVE);
  assert.throws(
    () => grant.authorizeObject(policy.SOURCE_SIGNATURE, 'pB', policy.READ_ONLY),
    (e) => e.kind === 'EffectNotAuthorized',
  );
});

// ---- principal_sources: only a signature-derived identity is an authorization principal ---------

test('policy principal_sources: only a signature-derived identity is an authorization principal', () => {
  const rows = C.principal_sources;
  assert.equal(rows.length, 4, 'oracle carries all 4 principal sources');
  for (const row of rows) {
    const src = SOURCE_BY_NAME[row.source];
    assert.ok(src !== undefined, `unknown source ${row.source}`);

    if (row.accepted) {
      assert.equal(policy.resolveAuthPrincipal(src, 'pA'), 'pA', `${row.source} should resolve`);
    } else {
      assert.throws(
        () => policy.resolveAuthPrincipal(src, 'pA'),
        (e) => e.kind === 'UnauthenticatedPrincipal',
        `${row.source} should be refused UnauthenticatedPrincipal`,
      );
    }

    // Even a maximally-permissive grant, presenting a read_only object, is denied from a
    // non-signature source: a transport/foreign/client identity is never an authz identity, no
    // matter how permissive the grant or how harmless the object's declared effect.
    const grant = new policy.Grant('pA', policy.DESTRUCTIVE);
    if (row.accepted) {
      assert.doesNotThrow(() => grant.authorizeObject(src, 'pA', policy.READ_ONLY));
    } else {
      assert.throws(
        () => grant.authorizeObject(src, 'pA', policy.READ_ONLY),
        (e) => e.kind === 'UnauthenticatedPrincipal',
        `${row.source} + read_only should still be refused UnauthenticatedPrincipal`,
      );
    }
  }
});

test('policy resolveAuthPrincipal refuses an empty signature-derived id', () => {
  assert.throws(
    () => policy.resolveAuthPrincipal(policy.SOURCE_SIGNATURE, ''),
    (e) => e.kind === 'UnauthenticatedPrincipal',
  );
});

// ---- safety_label: present / absent / malformed / incomplete, fail-closed -----------------------

test('policy safety label: present, absent, malformed, incomplete', () => {
  const sl = C.safety_label;

  // Present: ext = {1: {1: risk, 2: scope}}.
  const present = new M([
    [new U(sl.ext_key), new M([[new U(1), new T(sl.risk)], [new U(2), new T(sl.scope)]])],
  ]);
  const got = policy.safetyLabelFromExt(present);
  assert.equal(got.present, true);
  assert.equal(got.label.risk, sl.risk);
  assert.equal(got.label.scope, sl.scope);

  // The oracle's cbor_hex is the {1:risk,2:scope} inner-map body bytes -- an independent byte check
  // that this port's encoder produces the same bytes for the same risk/scope.
  const bodyHex = Buffer.from(policy.safetyLabelBytes(sl.risk, sl.scope)).toString('hex');
  assert.equal(bodyHex, sl.cbor_hex, 'safety-label body bytes match the oracle');

  // Absent: an ext map with no key-1 entry -- not present, no error.
  const absent = new M([]);
  const abs = policy.safetyLabelFromExt(absent);
  assert.equal(abs.present, false);
  assert.equal(abs.label, null);

  // Malformed: ext[1]'s value is not itself a map.
  const malformed = new M([[new U(1), new U(9)]]);
  assert.throws(
    () => policy.safetyLabelFromExt(malformed),
    (e) => e.kind === 'MalformedSafetyLabel',
  );

  // Incomplete: ext[1] is a map but is missing scope (key 2).
  const incomplete = new M([[new U(1), new M([[new U(1), new T('x')]])]]);
  assert.throws(
    () => policy.safetyLabelFromExt(incomplete),
    (e) => e.kind === 'MalformedSafetyLabel',
  );

  // Also incomplete the other way: missing risk (key 1).
  const incomplete2 = new M([[new U(1), new M([[new U(2), new T('y')]])]]);
  assert.throws(
    () => policy.safetyLabelFromExt(incomplete2),
    (e) => e.kind === 'MalformedSafetyLabel',
  );

  // Malformed: a non-uint key inside the inner map.
  const badKey = new M([[new U(1), new M([[new T('1'), new T('x')], [new U(2), new T('y')]])]]);
  assert.throws(
    () => policy.safetyLabelFromExt(badKey),
    (e) => e.kind === 'MalformedSafetyLabel',
  );

  // Malformed: a non-tstr value inside the inner map.
  const badVal = new M([[new U(1), new M([[new U(1), new U(7)], [new U(2), new T('y')]])]]);
  assert.throws(
    () => policy.safetyLabelFromExt(badVal),
    (e) => e.kind === 'MalformedSafetyLabel',
  );
});
