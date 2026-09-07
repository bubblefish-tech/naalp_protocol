// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// NA-IETF-1 producing-boundary disclosure (the OPTIONAL, self-asserted ext key 15, §2.5.4)
// known-answer tests for the TypeScript SDK, graded against the independent oracle
// (tools/producing_boundary_oracle.py -> vectors/producing_boundary/cases.json), i.e.
// TypeScript == Go == Rust == Python == oracle.
//
// Five properties, mirroring impl/go/envelope/producing_boundary_test.go and
// impl/python/tests/test_producing_boundary.py, all mutation-surviving:
//   1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body
//      bytes; a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; and
//      the parsed disclosure (present/kind/boundary/reporting) matches. Non-canonical sub-map
//      bytes are rejected NonCanonical at the codec.
//   2. UNDER SIGNATURE -- the disclosure is folded into the SIGNER's signed body: splicing a
//      different boundary into a signed object (keeping its id + signature) is rejected.
//   3. READER ROUND-TRIP -- set/get carries the value; the field is OPTIONAL; the setter DROPS a
//      reporting-boundary under observed (an observer relays from no one).
//   4. MALFORMED IGNORED [MUTATION ANCHOR] -- a well-formed object carrying a MALFORMED disclosure
//      (reporting under observed) in the non-critical ext map still verifies and is NOT surfaced.
//   5. CEXT REJECTED [MUTATION ANCHOR] -- the disclosure in the CRITICAL cext map is
//      UnknownCriticalExt.
//
// Run:  node --test test/producing_boundary.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as envelope from '../naalp/envelope.mjs';
import { U, N, B, T, M } from '../naalp/cbor.mjs';
import { HEADER_LABEL, NAALP_VERSION } from '../naalp/wire_constants_gen.mjs';

const ALG = cose.ALG_MLDSA65;               // -49
const SEED = Uint8Array.from({ length: 32 }, (_, i) => i); // a LOCAL test signing seed -- the
// verdict is a sign+verify round-trip, not a reproduction of the oracle's signature (full_hex is
// the object BODY, not a signed COSE object, so byte-parity needs no signing).

// the producing-boundary value sub-map WIRE keys (§2.5.4), used to build ext/cext DIRECTLY so the
// test grades the impl against the oracle's independent wire layout, not the impl's own private
// constants.
const K_BOUNDARY = 1n;
const K_KIND = 2n;
const K_REPORTING = 3n;

const BOUNDARY_X_HEX = '424f554e444152595f58';
const ORIGIN_Y_HEX = '4f524947494e5f59';

const bytesToHex = (b) => Buffer.from(b).toString('hex');
const hexToBytes = (h) => Uint8Array.from(Buffer.from(h, 'hex'));

function kindOk(_ch, _k) { return true; }

function findVector() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'producing_boundary', 'cases.json');
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

function baseObject(corpus) {
  const b = corpus.base_object;
  return new envelope.Object({
    kind: b.kind, channel: b.channel, tier: b.tier,
    signer: hexToBytes(b.signer_hex), created: b.created, effect: b.effect,
    causes: b.causes_hex.map(hexToBytes), profile: b.profile,
    body: new T(b.body_str),
  });
}

// Build the ext[15]/cext[15] sub-map DIRECTLY from the case's logical fields (the ONLY variable
// per case), reproducing the oracle bytes for well-formed AND malformed values -- the malformed
// cases cannot be built via setProducingBoundary by design, so they are constructed here.
function applyPlacement(o, tc) {
  if (tc.placement === 'absent') return;
  const sub = [];
  if (tc.boundary_hex !== null) sub.push([new U(K_BOUNDARY), new B(hexToBytes(tc.boundary_hex))]);
  if (tc.kind !== null) sub.push([new U(K_KIND), new U(tc.kind)]);
  if (tc.reporting_hex !== null) sub.push([new U(K_REPORTING), new B(hexToBytes(tc.reporting_hex))]);
  const ext = new M([[new U(envelope.PRODUCING_BOUNDARY_KEY), new M(sub)]]);
  if (tc.placement === 'ext') {
    o.ext = ext;
  } else if (tc.placement === 'cext') {
    o.cext = ext;
  } else {
    throw new Error('unknown placement ' + tc.placement);
  }
}

// The protected header (module-private in envelope.mjs); reconstructed here the same way
// audience.test.mjs and rotation.test.mjs do, for the negative (non-canonical payload) case.
function protectedHeader(alg, signer, profile) {
  const naalp = new M([
    [new U(1), new B(signer)],
    [new U(2), new U(profile)],
    [new U(3), new U(BigInt(NAALP_VERSION))],
  ]);
  return cbor.encode(new M([[new U(1), new N(alg)], [new T(HEADER_LABEL), naalp]]));
}

test('producing-boundary matches the independent oracle (bytes, verdict, parsed disclosure)', () => {
  const corpus = loadCorpus();
  if (!corpus) return; // committed oracle vector not present (standalone install)
  assert.equal(BigInt(corpus.producing_boundary_key), envelope.PRODUCING_BOUNDARY_KEY, 'corpus key != impl key');
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
      const [pb, present] = envelope.producingBoundary(got);
      assert.equal(present, tc.present, `${tc.name}: present`);
      if (present) {
        const s = tc.surfaced;
        assert.equal(pb.kind, BigInt(s.kind), `${tc.name}: kind`);
        assert.equal(bytesToHex(pb.boundary), s.boundary_hex, `${tc.name}: boundary`);
        const wantRep = s.reporting_hex || '';
        assert.equal(bytesToHex(pb.reporting || new Uint8Array(0)), wantRep, `${tc.name}: reporting`);
      }
    } else {
      assert.throws(
        () => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed),
        (e) => e instanceof envelope.EnvelopeError && e.kind === tc.expect,
        `${tc.name}: expected ${tc.expect}`,
      );
    }
  }

  // non-canonical disclosure bodies (sub-map keys out of order) are rejected at the CBOR layer.
  for (const neg of corpus.negatives || []) {
    const o = baseObject(corpus);
    const prot = protectedHeader(ALG, o.signer, o.profile);
    const signed = cose.coseSign1(ALG, SEED, prot, hexToBytes(neg.payload_hex));
    assert.throws(
      () => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed),
      (e) => (e && e.kind) === neg.expect,
      `negative ${neg.name}: expected ${neg.expect}`,
    );
  }
});

test('producing-boundary disclosure is folded under the signer signature (splice rejected)', () => {
  const corpus = loadCorpus();
  if (!corpus) return;
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);

  const o = baseObject(corpus);
  envelope.setProducingBoundary(
    o, new envelope.ProducingBoundary(hexToBytes(BOUNDARY_X_HEX), envelope.PRODUCING_BOUNDARY_OBSERVED));
  const signed = envelope.sign(o, ALG, SEED);
  const got = envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed);
  const [pb, present] = envelope.producingBoundary(got);
  assert.ok(present && pb.kind === envelope.PRODUCING_BOUNDARY_OBSERVED, 'read-back');

  // tamper: change boundary, keep the original id, reuse the original signature (a splice).
  const tampered = baseObject(corpus);
  envelope.setProducingBoundary(
    tampered, new envelope.ProducingBoundary(hexToBytes(ORIGIN_Y_HEX), envelope.PRODUCING_BOUNDARY_OBSERVED));
  tampered.id = o.id; // keep original content id -- a splice, not a re-sign
  const payload = cbor.encode(tampered.bodyMap(true));
  const [prot, , sig] = cose.parseSign1Raw(signed);
  const forged = cose.assembleSign1Raw(prot, payload, sig);
  assert.throws(() => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, forged));
});

test('producing-boundary reader round-trip: optional, set/get, observed drops reporting', () => {
  const corpus = loadCorpus();
  if (!corpus) return;
  const o = baseObject(corpus);
  let [, present] = envelope.producingBoundary(o);
  assert.equal(present, false, 'fresh object must have no producing-boundary disclosure');

  const x = hexToBytes(BOUNDARY_X_HEX);
  const y = hexToBytes(ORIGIN_Y_HEX);

  envelope.setProducingBoundary(o, new envelope.ProducingBoundary(x, envelope.PRODUCING_BOUNDARY_REPORTED, y));
  let pb;
  [pb, present] = envelope.producingBoundary(o);
  assert.ok(present);
  assert.equal(pb.kind, envelope.PRODUCING_BOUNDARY_REPORTED);
  assert.equal(bytesToHex(pb.boundary), bytesToHex(x));
  assert.equal(bytesToHex(pb.reporting), bytesToHex(y));

  // the setter drops a reporting-boundary under observed: read-back has no reporting.
  envelope.setProducingBoundary(o, new envelope.ProducingBoundary(x, envelope.PRODUCING_BOUNDARY_OBSERVED, y));
  [pb, present] = envelope.producingBoundary(o);
  assert.ok(present);
  assert.equal(pb.kind, envelope.PRODUCING_BOUNDARY_OBSERVED);
  assert.equal(pb.reporting, null, 'observed disclosure must drop reporting');
});

test('a malformed disclosure (reporting under observed) is ignored, not surfaced [MUTATION ANCHOR]', () => {
  // MUTATION ANCHOR: dropping the reporting-under-observed check in producingBoundary() flips
  // present false->true and this test pass->fail; that check is the observer-relays-from-no-one
  // invariant.
  const corpus = loadCorpus();
  if (!corpus) return;
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);
  const o = baseObject(corpus);
  // malformed ext[15] = {1:X, 2:observed, 3:Y} built directly (the setter refuses to build it).
  o.ext = new M([[new U(envelope.PRODUCING_BOUNDARY_KEY), new M([
    [new U(K_BOUNDARY), new B(hexToBytes(BOUNDARY_X_HEX))],
    [new U(K_KIND), new U(envelope.PRODUCING_BOUNDARY_OBSERVED)],
    [new U(K_REPORTING), new B(hexToBytes(ORIGIN_Y_HEX))],
  ])]]);
  const signed = envelope.sign(o, ALG, SEED);
  const got = envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed); // must NOT throw (may-ignore)
  const [, present] = envelope.producingBoundary(got);
  assert.equal(present, false, 'a malformed disclosure (reporting under observed) must NOT be surfaced');
});

test('the disclosure placed in the critical cext map is rejected UnknownCriticalExt [MUTATION ANCHOR]', () => {
  // MUTATION ANCHOR: the disclosure in the CRITICAL cext map (field 12) is an unrecognized critical
  // extension -> UnknownCriticalExt, fail-closed. A disclosure must never masquerade as a
  // must-understand gate.
  const corpus = loadCorpus();
  if (!corpus) return;
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);
  const o = baseObject(corpus);
  o.cext = new M([[new U(envelope.PRODUCING_BOUNDARY_KEY), new M([
    [new U(K_BOUNDARY), new B(hexToBytes(BOUNDARY_X_HEX))],
    [new U(K_KIND), new U(envelope.PRODUCING_BOUNDARY_OBSERVED)],
  ])]]);
  const signed = envelope.sign(o, ALG, SEED);
  assert.throws(
    () => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed),
    (e) => e instanceof envelope.EnvelopeError && e.kind === 'UnknownCriticalExt',
  );
});
