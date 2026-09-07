// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Manufacturing Add-ons Component F, naalp-hazard KAT for the TypeScript SDK, graded against the
// shared independent corpus vectors/hazard/cases.json (NOT produced by this code, frozen
// 2026-09-01): the F2 fail-closed hazard-class decode (including the >2^32 and >2^63-1 oracle
// values carried through BigInt with no float64 rounding), byte-exact claim/authorization/
// envelope encoding (including the unicode_frame and negative_only_axis edge cases), the F3
// grant-coverage containment matrix (both allow and deny rows), the F2/F4 absent-claim
// distinct-error behaviour, and structural malformation rejection.
//
// Mirrors impl/rust/naalp-hazard/src/lib.rs (the frozen reference), impl/csharp/Hazard.cs,
// impl/java/.../Hazard.java, impl/php/src/Hazard.php and impl/ruby/lib/naalp/hazard.rb.
//
// Run:  node --test test/hazard.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import { U, M } from '../naalp/cbor.mjs';
import * as hazard from '../naalp/hazard.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'hazard', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/hazard/cases.json not found');
}

const C = vectors();
const bytesToHex = (b) => Buffer.from(b).toString('hex');

function envFrom(o) {
  const axes = o.axes.map(([min, max]) => [min, max]);
  const spatial = new hazard.SpatialBounds(o.frame, axes);
  const window = new hazard.HazardWindow(o.not_before, o.not_after);
  return new hazard.HazardEnvelope(spatial, o.speed_bound_mm_s, window);
}

// ---- F2: fail-closed class decode (mutation anchor: a constant CLASS_NONE return would pass
// none of the non-zero cases; a constant CLASS_MOTION_IN_SHARED_SPACE would fail the exact 0..3
// cases). ------------------------------------------------------------------------------------
test('from_code fail-closed matches oracle', () => {
  for (const row of C.from_code) {
    const got = hazard.classFromCode(row.code);
    assert.equal(got, row.class, `from_code(${JSON.stringify(row.code)})`);
  }
  // Explicit oracle-independent assertions of the named fail-closed cases (F2).
  assert.equal(hazard.classFromCode(null), hazard.CLASS_MOTION_IN_SHARED_SPACE,
    'absent must normalize to the highest class');
  assert.equal(hazard.classFromCode(undefined), hazard.CLASS_MOTION_IN_SHARED_SPACE,
    'undefined must normalize to the highest class');
  assert.equal(hazard.classFromCode(9), hazard.CLASS_MOTION_IN_SHARED_SPACE,
    'unknown code must normalize to the highest class');
  assert.equal(hazard.classFromCode((1n << 64n) - 1n), hazard.CLASS_MOTION_IN_SHARED_SPACE,
    'an out-of-range BigInt code must still normalize, never throw');
  assert.equal(hazard.classFromCode('9223372036854775808'), hazard.CLASS_MOTION_IN_SHARED_SPACE,
    'a >2^63-1 decimal string must normalize losslessly through BigInt, no float64 rounding');
  // The five in-range codes decode to themselves, never collapsing to the default.
  for (let code = 0; code <= 4; code++) {
    assert.equal(hazard.classFromCode(code), code);
  }
});

// ---- byte-level: encode matches the independent oracle (TS == Go == Rust == oracle). --------
test('claim and authorization bytes match oracle', () => {
  for (const row of C.bodies) {
    const cls = hazard.classFromCode(row.class);
    const e = envFrom(row);
    const claim = new hazard.HazardClaim(cls, e);
    const auth = new hazard.HazardAuthorization(cls, e);
    assert.equal(bytesToHex(claim.bytes()), row.body_hex, `claim ${row.name}`);
    assert.equal(bytesToHex(auth.bytes()), row.body_hex, `authorization ${row.name} (same shape as claim)`);
    assert.equal(bytesToHex(claim.contentId()), row.content_id_hex, `claim ${row.name} content-id`);
  }
});

// Round-trip: from_value(to_value(x)) == x for every oracle body.
test('round-trip matches oracle', () => {
  for (const row of C.bodies) {
    const e = envFrom(row);
    const claim = new hazard.HazardClaim(hazard.classFromCode(row.class), e);
    const got = hazard.HazardClaim.fromValue(claim.toValue());
    assert.equal(got.class, claim.class, `round-trip ${row.name}`);
    assert.equal(got.envelope.spatial.frame, claim.envelope.spatial.frame, `round-trip ${row.name}`);
    assert.deepEqual(got.envelope.spatial.axes, claim.envelope.spatial.axes, `round-trip ${row.name}`);
    assert.equal(got.envelope.speedBoundMmS, claim.envelope.speedBoundMmS, `round-trip ${row.name}`);
    assert.equal(got.envelope.window.notBefore, claim.envelope.window.notBefore, `round-trip ${row.name}`);
    assert.equal(got.envelope.window.notAfter, claim.envelope.window.notAfter, `round-trip ${row.name}`);
  }
});

// ---- F3: coverage matrix (mutation anchor: a constant "always allow" would pass none of the
// deny rows; a constant "always deny" would fail all the allow rows). -------------------------
test('coverage matches oracle', () => {
  const rows = C.coverage;
  assert.ok(rows.length > 0);
  let allows = 0;
  let denies = 0;
  for (const row of rows) {
    const claim = new hazard.HazardClaim(hazard.classFromCode(row.claim_class_code), envFrom(row.claim_envelope));
    const grant = new hazard.HazardAuthorization(hazard.classFromCode(row.grant_class_code), envFrom(row.grant_envelope));
    if (row.authorized) {
      allows++;
      assert.doesNotThrow(() => hazard.hazardAuthorized(claim, grant), `${row.name}: want authorized`);
    } else {
      denies++;
      assert.throws(
        () => hazard.hazardAuthorized(claim, grant),
        (e) => e.kind === 'HazardNotCovered',
        row.name,
      );
    }
  }
  assert.equal(allows, 6, 'oracle coverage matrix must carry exactly 6 allow rows');
  assert.equal(denies, 9, 'oracle coverage matrix must carry exactly 9 deny rows');
  assert.ok(allows > 0 && denies > 0, 'matrix needs both allows and denies');
});

// F2/F4's "absent hazard" behavioural vector, at the OBJECT level (no claim at all): distinct
// from an in-range-but-mismatched class, and distinct from an unrecognized class byte inside a
// present claim (covered by the coverage-matches-oracle normalized rows).
test('absent claim denies with distinct error', () => {
  const grant = new hazard.HazardAuthorization(
    hazard.CLASS_TOOL_ACTUATION,
    envFrom({ frame: 'cell-7/world', axes: [[0, 1000], [0, 1000], [0, 500]], speed_bound_mm_s: 500, not_before: 0, not_after: 1000 }),
  );
  assert.throws(() => hazard.hazardAuthorizedOptional(null, grant), (e) => e.kind === 'HazardUnknown');
  assert.throws(() => hazard.hazardAuthorizedOptional(undefined, grant), (e) => e.kind === 'HazardUnknown');

  // A present, well-covered claim still authorizes through the same entry point.
  const claim = new hazard.HazardClaim(
    hazard.CLASS_TOOL_ACTUATION,
    envFrom({ frame: 'cell-7/world', axes: [[100, 200], [100, 200], [0, 100]], speed_bound_mm_s: 100, not_before: 10, not_after: 900 }),
  );
  assert.doesNotThrow(() => hazard.hazardAuthorizedOptional(claim, grant));
});

// ---- structural malformation (fail-closed, never partially valid) ---------------------------
test('malformed bodies rejected', () => {
  // empty axes
  const bad = new hazard.SpatialBounds('f', []);
  assert.equal(bad.isWellFormed(), false);
  assert.throws(() => hazard.SpatialBounds.fromValue(bad.toValue()), (e) => e.kind === 'HazardMalformed');

  // min > max
  const bad2 = new hazard.SpatialBounds('f', [[10, -10]]);
  assert.equal(bad2.isWellFormed(), false);

  // non-NFC frame ('e' + combining acute, NFD not NFC)
  const bad3 = new hazard.SpatialBounds('é', [[0, 1]]);
  assert.equal(bad3.isWellFormed(), false);

  // wrong shape entirely (not a map)
  assert.throws(() => hazard.HazardClaim.fromValue(new U(0)), (e) => e.kind === 'HazardMalformed');

  // class present, envelope missing
  const partial = new M([[new U(1), new U(1)]]);
  assert.throws(() => hazard.HazardClaim.fromValue(partial), (e) => e.kind === 'HazardMalformed');

  // an explicit out-of-range class ON THE WIRE (not "absent") is malformed, not silently
  // normalized -- see bodyFromValue's doc comment in naalp/hazard.mjs.
  const goodEnv = envFrom({ frame: 'f', axes: [[0, 1]], speed_bound_mm_s: 1, not_before: 0, not_after: 1 }).toValue();
  const outOfRange = new M([
    [new U(1), new U(99)],
    [new U(2), goodEnv],
  ]);
  assert.throws(() => hazard.HazardClaim.fromValue(outOfRange), (e) => e.kind === 'HazardMalformed');
});

// ---- containment truth table (independent of the oracle file, direct assertions) ------------
test('spatial_contained truth table', () => {
  const grant = new hazard.SpatialBounds('f', [[0, 100], [0, 100]]);
  // fully inside -> contained
  const inside = new hazard.SpatialBounds('f', [[10, 90], [10, 90]]);
  assert.equal(hazard.spatialContained(inside, grant), true);
  // equal bounds -> contained (closed interval)
  const equal = new hazard.SpatialBounds('f', [[0, 100], [0, 100]]);
  assert.equal(hazard.spatialContained(equal, grant), true);
  // one axis pokes outside -> not contained
  const outside = new hazard.SpatialBounds('f', [[10, 90], [10, 101]]);
  assert.equal(hazard.spatialContained(outside, grant), false);
  // different frame -> never contained regardless of numeric bounds
  const wrongFrame = new hazard.SpatialBounds('g', [[10, 90], [10, 90]]);
  assert.equal(hazard.spatialContained(wrongFrame, grant), false);
  // fewer axes -> never contained
  const fewer = new hazard.SpatialBounds('f', [[10, 90]]);
  assert.equal(hazard.spatialContained(fewer, grant), false);
});

test('envelope_contained window and speed', () => {
  const mk = (axes, speed, w) => envFrom({ frame: 'f', axes, speed_bound_mm_s: speed, not_before: w[0], not_after: w[1] });
  const grant = mk([[0, 100]], 500, [100, 900]);
  const ok = mk([[0, 100]], 500, [100, 900]); // exact edges, closed interval
  assert.equal(hazard.envelopeContained(ok, grant), true);
  const speedOver = mk([[0, 100]], 501, [100, 900]);
  assert.equal(hazard.envelopeContained(speedOver, grant), false);
  const startsEarly = mk([[0, 100]], 500, [99, 900]);
  assert.equal(hazard.envelopeContained(startsEarly, grant), false);
  const endsLate = mk([[0, 100]], 500, [100, 901]);
  assert.equal(hazard.envelopeContained(endsLate, grant), false);
});

// unicode_frame body row: JSON.parse already resolves the é escape to the correct UTF-8
// codepoint; confirmed directly (no manual unescape helper needed).
test('unicode_frame row decodes and NFC-checks correctly', () => {
  const row = C.bodies.find((r) => r.name === 'unicode_frame');
  assert.ok(row, 'unicode_frame row must exist in the oracle');
  assert.equal(row.frame, 'cellule-café/monde');
  const sb = new hazard.SpatialBounds(row.frame, row.axes);
  assert.equal(sb.isWellFormed(), true);
  const e = envFrom(row);
  const claim = new hazard.HazardClaim(hazard.classFromCode(row.class), e);
  assert.equal(bytesToHex(claim.bytes()), row.body_hex);
  const decoded = cbor.decode(claim.bytes());
  const back = hazard.HazardClaim.fromValue(decoded);
  assert.equal(back.envelope.spatial.frame, row.frame);
});
