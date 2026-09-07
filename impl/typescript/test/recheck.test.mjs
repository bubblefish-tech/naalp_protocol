// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// T1.3 recheck (the checkable-minimum field, NAALP-REQ-110/111, §2.5) known-answer tests for the
// TypeScript SDK, graded against the independent oracle (tools/recheck_oracle.py ->
// vectors/recheck/cases.json), i.e. TypeScript == Go == Rust == Python == oracle.
//
// Four properties, mirroring impl/go/envelope/envelope_test.go and impl/python/tests, all
// mutation-surviving:
//   1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body
//      bytes; a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; and
//      the parsed recheck (present/id/critical) matches. Non-canonical cext bytes are rejected
//      NonCanonical at the codec.
//   2. REJECT PATH IS REAL [MUTATION ANCHOR] -- a CRITICAL recheck naming an UNKNOWN procedure id
//      is rejected UnknownCriticalExt; a known critical procedure and a non-critical unknown
//      procedure both verify, proving the reject is specific to unknown-under-critical.
//   3. READER ROUND TRIP -- set/get carries the id and criticality; cext (critical) takes
//      precedence over ext (non-critical) when both name the key.
//
// Run:  node --test test/recheck.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as envelope from '../naalp/envelope.mjs';
import { T } from '../naalp/cbor.mjs';
import { HEADER_LABEL, NAALP_VERSION } from '../naalp/wire_constants_gen.mjs';

const ALG = cose.ALG_MLDSA65;               // -49
const SEED = Uint8Array.from({ length: 32 }, (_, i) => i); // a LOCAL test signing seed -- the
// verdict is a sign+verify round-trip, not a reproduction of the oracle's signature.

const bytesToHex = (b) => Buffer.from(b).toString('hex');
const hexToBytes = (h) => Uint8Array.from(Buffer.from(h, 'hex'));

function kindOk(_ch, _k) { return true; }

function findVector() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'recheck', 'cases.json');
    if (existsSync(p)) return p;
    d = dirname(d);
  }
  return null;
}

function loadCorpus() {
  const p = findVector();
  if (!p) return null;
  return JSON.parse(readFileSync(p, 'utf8'));
}

function baseObject(corpus, signerHex, bodyStr) {
  const b = corpus.base_object;
  return new envelope.Object({
    kind: b.kind, channel: b.channel, tier: b.tier,
    signer: hexToBytes(signerHex || b.signer_hex), created: b.created, effect: b.effect,
    causes: b.causes_hex.map(hexToBytes), profile: b.profile,
    body: new T(bodyStr || b.body_str),
  });
}

// applyPlacement applies the case's recheck placement -- the ONLY variable per case. setRecheck has
// no validation, so it builds even the deliberately-unknown-procedure-id cases directly.
function applyPlacement(o, tc) {
  switch (tc.placement) {
    case 'cext':
      o.setRecheck(BigInt(tc.procedure_id), true);
      break;
    case 'ext':
      o.setRecheck(BigInt(tc.procedure_id), false);
      break;
    case 'ext_empty':
      o.ext = new cbor.M([]); // present but empty (no key 13)
      break;
    case 'absent':
      break;
    default:
      throw new Error('unknown placement ' + tc.placement);
  }
}

test('recheck matches the independent oracle (bytes, verdict, parsed procedure)', () => {
  const corpus = loadCorpus();
  if (!corpus) return; // committed oracle vector not present (standalone install)
  assert.equal(BigInt(corpus.recheck_key), envelope.RECHECK_KEY, 'corpus key != impl key');
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);

  for (const tc of corpus.cases) {
    // byte parity: body-without-id, content id, full body (all pre-signature).
    const o = baseObject(corpus);
    applyPlacement(o, tc);
    assert.equal(bytesToHex(cbor.encode(o.bodyMap(false))), tc.body_no_id_hex, `${tc.name}: body-no-id`);
    const cid = o.contentId();
    assert.equal(bytesToHex(cid), tc.content_id_hex, `${tc.name}: content-id`);
    o.id = cid;
    assert.equal(bytesToHex(cbor.encode(o.bodyMap(true))), tc.full_hex, `${tc.name}: full-body`);

    // verdict: sign for real + verify offline; assert accept vs the named error.
    const o2 = baseObject(corpus);
    applyPlacement(o2, tc);
    const signed = envelope.sign(o2, ALG, SEED);
    if (tc.expect === 'accept') {
      const got = envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed);
      const [rid, present, critical] = got.recheck();
      assert.equal(present, tc.present, `${tc.name}: present`);
      if (present) {
        assert.equal(rid, BigInt(tc.procedure_id), `${tc.name}: procedure id`);
        assert.equal(critical, tc.critical, `${tc.name}: critical`);
      }
    } else {
      assert.throws(
        () => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed),
        (e) => e instanceof envelope.EnvelopeError && e.kind === tc.expect,
        `${tc.name}: expected ${tc.expect}`,
      );
    }
  }

  // non-canonical recheck bodies (keys out of order) are rejected at the CBOR layer.
  for (const neg of corpus.negatives || []) {
    const o = baseObject(corpus);
    const prot = protectedHeaderFor(o.signer, o.profile);
    const signed = cose.coseSign1(ALG, SEED, prot, hexToBytes(neg.payload_hex));
    assert.throws(
      () => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed),
      (e) => (e && e.kind) === neg.expect,
      `negative ${neg.name}: expected ${neg.expect}`,
    );
  }
});

// The protected header (module-private in envelope.mjs); reconstructed here the same way
// producing_boundary.test.mjs / audience.test.mjs / rotation.test.mjs do, for the negative
// (non-canonical payload) case.
function protectedHeaderFor(signer, profile) {
  const naalp = new cbor.M([
    [new cbor.U(1), new cbor.B(signer)],
    [new cbor.U(2), new cbor.U(profile)],
    [new cbor.U(3), new cbor.U(BigInt(NAALP_VERSION))],
  ]);
  return cbor.encode(new cbor.M([[new cbor.U(1), new cbor.N(ALG)], [new cbor.T(HEADER_LABEL), naalp]]));
}

test('recheck reject path is real: critical-unknown rejected, critical-known and noncritical-unknown accept [MUTATION ANCHOR]', () => {
  // MUTATION ANCHOR: dropping the isKnownRecheckProcedure check in verify()'s cext loop (accepting
  // an unknown critical procedure id) flips this test pass->fail on the criticalUnknown assertion.
  const corpus = loadCorpus();
  if (!corpus) return;
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);

  const criticalUnknown = baseObject(corpus);
  criticalUnknown.setRecheck(99n, true); // unknown id, critical
  const su = envelope.sign(criticalUnknown, ALG, SEED);
  assert.throws(
    () => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, su),
    (e) => e instanceof envelope.EnvelopeError && e.kind === 'UnknownCriticalExt',
    'critical unknown recheck must be rejected',
  );

  const criticalKnown = baseObject(corpus);
  criticalKnown.setRecheck(envelope.RECHECK_WALK_CAUSES, true); // known id, critical
  const sk = envelope.sign(criticalKnown, ALG, SEED);
  assert.doesNotThrow(() => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, sk), 'known critical recheck must verify');

  const nonCritUnknown = baseObject(corpus);
  nonCritUnknown.setRecheck(99n, false); // unknown id, non-critical -> ignored
  const sn = envelope.sign(nonCritUnknown, ALG, SEED);
  assert.doesNotThrow(() => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, sn), 'unknown non-critical recheck must be ignored');
});

test('recheck reader round-trip: optional, set/get, cext takes precedence over ext', () => {
  const corpus = loadCorpus();
  if (!corpus) return;
  const o = baseObject(corpus);
  let [, present] = o.recheck();
  assert.equal(present, false, 'fresh object must have no recheck');

  o.setRecheck(envelope.RECHECK_VERIFY_COSE_SIGN1, false);
  let [id, pres, crit] = o.recheck();
  assert.equal(pres, true);
  assert.equal(id, envelope.RECHECK_VERIFY_COSE_SIGN1);
  assert.equal(crit, false, 'non-critical recheck read back wrong');

  o.setRecheck(envelope.RECHECK_REPLAY_CONSUME_CHECK, true); // critical wins over the ext entry
  [id, pres, crit] = o.recheck();
  assert.equal(pres, true);
  assert.equal(id, envelope.RECHECK_REPLAY_CONSUME_CHECK);
  assert.equal(crit, true, 'critical recheck must take precedence');
});

test('isKnownRecheckProcedure is closed to exactly {1,2,3,4} [MUTATION ANCHOR]', () => {
  // MUTATION ANCHOR: making isKnownRecheckProcedure return true unconditionally (or widening the
  // range) flips this test pass->fail on the boundary assertions.
  assert.equal(envelope.isKnownRecheckProcedure(0n), false);
  assert.equal(envelope.isKnownRecheckProcedure(1n), true);
  assert.equal(envelope.isKnownRecheckProcedure(2n), true);
  assert.equal(envelope.isKnownRecheckProcedure(3n), true);
  assert.equal(envelope.isKnownRecheckProcedure(4n), true);
  assert.equal(envelope.isKnownRecheckProcedure(5n), false);
  assert.equal(envelope.isKnownRecheckProcedure(4294967296n), false); // 2^32, well beyond the registry
});
