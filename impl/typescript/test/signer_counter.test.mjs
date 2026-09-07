// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// T1.6 per-signer forward-only counter (the OPTIONAL detection field, NAALP-REQ-120) known-answer
// tests for the TypeScript SDK, graded against the independent oracle
// (tools/signer_counter_oracle.py -> vectors/signer_counter/cases.json), i.e.
// TypeScript == Go == Rust == Python == oracle.
//
// Five properties, mirroring impl/go/envelope/signer_counter_test.go and impl/python/tests, all
// mutation-surviving:
//   1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body
//      bytes; a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; and
//      the parsed counter (present/value) matches. Non-canonical ext bytes are rejected
//      NonCanonical at the codec.
//   2. UNDER SIGNATURE -- the counter is folded into the SIGNER's signed body: splicing a
//      different counter into a signed object (keeping its id + signature) is rejected.
//   3. READER ROUND TRIP -- set/get carries the value; the field is OPTIONAL; a present-zero
//      counter reads back present.
//   4. ABSENT VALIDATES [MUTATION ANCHOR] -- an object carrying NO counter signs and verifies.
//   5. DETECT DUPLICATION -- detectSignerDuplication matches the independent oracle's findings over
//      every scenario, including the ONE-SEQUENCE-NOT-FLAGGED and TWO-CONFLICTING-FLAGGED
//      [MUTATION ANCHOR]s that are the whole point of the detection-not-prevention field.
//
// Run:  node --test test/signer_counter.test.mjs      (from impl/typescript/)

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
    const p = join(d, 'vectors', 'signer_counter', 'cases.json');
    if (existsSync(p)) return p;
    d = dirname(d);
  }
  return null;
}

// Quote every bare `"counter": <int>` literal before JSON.parse so a 64-bit forward-only position
// (up to 2^64-1, beyond Number.MAX_SAFE_INTEGER = 2^53-1) round-trips EXACTLY as a string -> BigInt,
// never a precision-losing float64 (JS's JSON.parse always converts bare numbers to float64, which
// cannot represent 2^64-1 exactly). "counter_key" is a distinct key name and is untouched; a JSON
// `null` (the counter-absent cases) does not match the digit pattern and also passes through
// untouched.
function loadCorpus() {
  const p = findVector();
  if (!p) return null;
  const text = readFileSync(p, 'utf8');
  const patched = text.replace(/"counter":\s*(-?\d+)/g, '"counter":"$1"');
  return JSON.parse(patched);
}

// counterBig converts a corpus counter field (a digit string after loadCorpus's patch, or null) to
// a BigInt, or null.
function counterBig(v) {
  return v === null || v === undefined ? null : BigInt(v);
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

// applyPlacement applies the case's counter placement -- the ONLY variable per case.
function applyPlacement(o, tc) {
  const counter = counterBig(tc.counter);
  switch (tc.placement) {
    case 'ext':
      o.setSignerCounter(counter);
      break;
    case 'cext':
      // the counter placed in the CRITICAL map is an unrecognized critical extension.
      o.cext = new cbor.M([[new cbor.U(envelope.SIGNER_COUNTER_KEY), new cbor.U(counter)]]);
      break;
    case 'ext_empty':
      o.ext = new cbor.M([]); // present but empty (no counter) -- distinct bytes from absent
      break;
    case 'absent':
      break;
    default:
      throw new Error('unknown placement ' + tc.placement);
  }
}

function protectedHeaderFor(signer, profile) {
  const naalp = new cbor.M([
    [new cbor.U(1), new cbor.B(signer)],
    [new cbor.U(2), new cbor.U(profile)],
    [new cbor.U(3), new cbor.U(BigInt(NAALP_VERSION))],
  ]);
  return cbor.encode(new cbor.M([[new cbor.U(1), new cbor.N(ALG)], [new cbor.T(HEADER_LABEL), naalp]]));
}

test('signer-counter matches the independent oracle (bytes, verdict, reader)', () => {
  const corpus = loadCorpus();
  if (!corpus) return; // committed oracle vector not present (standalone install)
  assert.equal(BigInt(corpus.counter_key), envelope.SIGNER_COUNTER_KEY, 'corpus key != impl key');
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);

  for (const tc of corpus.cases) {
    // byte parity: body-without-id, content id, full body (all pre-signature).
    const o = baseObject(corpus, tc.signer_hex, tc.body_str);
    applyPlacement(o, tc);
    assert.equal(bytesToHex(cbor.encode(o.bodyMap(false))), tc.body_no_id_hex, `${tc.name}: body-no-id`);
    const cid = o.contentId();
    assert.equal(bytesToHex(cid), tc.content_id_hex, `${tc.name}: content-id`);
    o.id = cid;
    assert.equal(bytesToHex(cbor.encode(o.bodyMap(true))), tc.full_hex, `${tc.name}: full-body`);

    // verdict: sign for real + verify offline; assert accept vs the named error.
    const o2 = baseObject(corpus, tc.signer_hex, tc.body_str);
    applyPlacement(o2, tc);
    const signed = envelope.sign(o2, ALG, SEED);
    if (tc.expect === 'accept') {
      const got = envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed);
      const [seq, present] = got.signerCounter();
      assert.equal(present, tc.present, `${tc.name}: present`);
      if (present) {
        assert.equal(seq, counterBig(tc.counter), `${tc.name}: counter value`);
      }
    } else {
      assert.throws(
        () => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed),
        (e) => e instanceof envelope.EnvelopeError && e.kind === tc.expect,
        `${tc.name}: expected ${tc.expect}`,
      );
    }
  }

  // non-canonical counter bodies (ext keys out of order) are rejected at the CBOR layer.
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

test('signer-counter is folded under the signer signature (splice rejected)', () => {
  const corpus = loadCorpus();
  if (!corpus) return;
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);

  const o = baseObject(corpus);
  o.setSignerCounter(5n);
  const signed = envelope.sign(o, ALG, SEED);
  // baseline: the signed object verifies and reads back counter 5.
  const got = envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed);
  const [seq0, present0] = got.signerCounter();
  assert.ok(present0 && seq0 === 5n, 'counter read-back');

  // tamper: change the counter to 6 and re-encode the body WITHOUT re-signing; the object must be
  // rejected (the content id no longer matches the signed body / the signature no longer covers it).
  const tampered = baseObject(corpus);
  tampered.setSignerCounter(6n);
  tampered.id = o.id; // keep the original (counter=5) content id -- a splice, not a re-sign
  const payload = cbor.encode(tampered.bodyMap(true));
  const [prot, , origSig] = cose.parseSign1Raw(signed);
  const forged = cose.assembleSign1Raw(prot, payload, origSig);
  assert.throws(
    () => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, forged),
    undefined,
    'tampered counter must be rejected (the counter is under signature)',
  );
});

test('signer-counter reader round-trip: optional, set/get, present-zero reads back present', () => {
  const corpus = loadCorpus();
  if (!corpus) return;
  const o = baseObject(corpus);
  let [, present] = o.signerCounter();
  assert.equal(present, false, 'fresh object must have no counter');

  o.setSignerCounter(42n);
  let [seq, pres] = o.signerCounter();
  assert.equal(pres, true);
  assert.equal(seq, 42n, 'counter read back wrong');

  o.setSignerCounter(0n); // present with value zero
  [seq, pres] = o.signerCounter();
  assert.equal(pres, true, 'present-zero counter must read back present');
  assert.equal(seq, 0n);
});

test('signer-counter absent validates [MUTATION ANCHOR]', () => {
  // MUTATION ANCHOR: making the field mandatory (e.g. adding a reject-if-absent check to verify)
  // flips this test pass->fail.
  const corpus = loadCorpus();
  if (!corpus) return;
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);
  const o = baseObject(corpus);
  let [, present] = o.signerCounter();
  assert.equal(present, false, 'object built without a counter must have none');
  const signed = envelope.sign(o, ALG, SEED);
  const got = envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed);
  [, present] = got.signerCounter();
  assert.equal(present, false, 'verified object must report no counter');
});

// buildScenarioObjects reconstructs a detection scenario's presented objects from their logical
// fields and cross-checks each recomputed content id against the oracle's.
function buildScenarioObjects(corpus, objs) {
  return objs.map((ro) => {
    const o = baseObject(corpus, ro.signer_hex, ro.body_str);
    const c = counterBig(ro.counter);
    if (c !== null) o.setSignerCounter(c);
    const id = o.contentId();
    assert.equal(bytesToHex(id), ro.content_id_hex, 'scenario object content-id');
    return o;
  });
}

test('detectSignerDuplication matches the independent oracle over every scenario', () => {
  const corpus = loadCorpus();
  if (!corpus) return;
  for (const sc of corpus.detection.scenarios) {
    const objs = buildScenarioObjects(corpus, sc.objects);
    const findings = envelope.detectSignerDuplication(objs);
    assert.equal(findings.length, sc.expect.length, `${sc.name}: findings count`);
    sc.expect.forEach((want, i) => {
      const got = findings[i];
      assert.equal(bytesToHex(got.signer), want.signer_hex, `${sc.name}: finding ${i} signer`);
      assert.equal(got.counter, counterBig(want.counter), `${sc.name}: finding ${i} counter`);
      assert.equal(got.ids.length, want.ids_hex.length, `${sc.name}: finding ${i} ids count`);
      want.ids_hex.forEach((idHex, j) => {
        assert.equal(bytesToHex(got.ids[j]), idHex, `${sc.name}: finding ${i} id ${j}`);
      });
    });
  }
});

test('one sequence alone is never flagged; an honest forward-only sequence is never flagged [MUTATION ANCHOR]', () => {
  // MUTATION ANCHOR: relaxing the >= 2 guard in detectSignerDuplication to >= 1 (flag from one)
  // flips this test pass->fail; that is the whole detection-not-prevention line.
  const corpus = loadCorpus();
  if (!corpus) return;
  const one = baseObject(corpus, '', 'holder');
  one.setSignerCounter(5n);
  assert.equal(envelope.detectSignerDuplication([one]).length, 0, 'one sequence alone must not be flagged');

  const seqObjs = ['s1', 's2', 's3'].map((body, i) => {
    const o = baseObject(corpus, '', body);
    o.setSignerCounter(BigInt(i + 1));
    return o;
  });
  assert.equal(envelope.detectSignerDuplication(seqObjs).length, 0, 'an honest forward-only sequence must not be flagged');
});

test('two conflicting sequences are flagged once, surfacing both content ids [MUTATION ANCHOR]', () => {
  const corpus = loadCorpus();
  if (!corpus) return;
  const holder = baseObject(corpus, '', 'holder');
  holder.setSignerCounter(5n);
  const thief = baseObject(corpus, '', 'thief');
  thief.setSignerCounter(5n);

  const f = envelope.detectSignerDuplication([holder, thief]);
  assert.equal(f.length, 1, 'two conflicting sequences must be flagged once');
  assert.equal(f[0].counter, 5n);
  assert.equal(f[0].ids.length, 2, 'both conflicting content ids must be surfaced');
  const hid = holder.contentId();
  const tid = thief.contentId();
  const surfaced = new Set(f[0].ids.map(bytesToHex));
  assert.ok(surfaced.has(bytesToHex(hid)) && surfaced.has(bytesToHex(tid)));
});

test('forward-only-consistent and cross-signer positions are never flagged', () => {
  const corpus = loadCorpus();
  if (!corpus) return;
  const a5 = baseObject(corpus, '', 'holder');
  a5.setSignerCounter(5n);
  const a6 = baseObject(corpus, '', 'next');
  a6.setSignerCounter(6n);
  assert.equal(envelope.detectSignerDuplication([a5, a6]).length, 0, 'forward-only-consistent sequence must not be flagged');

  // per-signer: SIGNER_B at position 5 does not conflict with SIGNER_A at position 5.
  const b5 = baseObject(corpus, '5349474e45525f42', 'other');
  b5.setSignerCounter(5n);
  assert.equal(envelope.detectSignerDuplication([a5, b5]).length, 0, 'different signers at one value must not be flagged');
});
