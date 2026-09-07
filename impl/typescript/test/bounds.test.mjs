// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Decoder resource bounds (design.md §3.4, R7) for the TypeScript SDK -- mirrors
// impl/go/{cbor,envelope,streaming}/bounds_test.go and impl/rust/src/{cbor,envelope,streaming}.rs.
//
// Every count, length, and nesting depth a decoder materializes BEFORE an object is authenticated
// carries a MUST-level maximum, rejected fail-closed with a named error. Each bound is proven by a
// BOUNDARY PAIR: an otherwise-valid input exactly AT the limit is accepted, and one just past the
// limit is rejected with its exact error kind. "Otherwise valid" is load-bearing for mutation
// survival -- because the only defect is the bound, deleting the bound check makes the over-limit
// case verify, so a constant-return mutation is caught.
//
// Run:  node --test test/bounds.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as cbor from '../naalp/cbor.mjs';
import { U, A, M, T, B } from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as envelope from '../naalp/envelope.mjs';
import * as streaming from '../naalp/streaming.mjs';
import {
  MAX_OBJECT_SIZE, MAX_CAUSES, MAX_EXT, MAX_CEXT, MAX_NESTING_DEPTH, MAX_STREAM_CHUNKS,
} from '../naalp/wire_constants_gen.mjs';

function expectRejects(fn, expectedKind) {
  assert.throws(fn, (err) => Boolean(err) && err.kind === expectedKind, `expected ${expectedKind}`);
}

// ---- cbor.decodeBounded: nesting-depth counter (design.md §3.4, R7) ---------------------------

// nestedArraysCBOR returns canonical CBOR for k single-element arrays wrapping a zero scalar:
// 0x81 (array of one) repeated k times, then 0x00. Decoding it, the outermost array is at depth 1
// and the innermost scalar is at depth k+1.
function nestedArraysCBOR(k) {
  const out = new Uint8Array(k + 1);
  out.fill(0x81, 0, k);
  out[k] = 0x00;
  return out;
}

test('cbor.decodeBounded pins the nesting-depth counter [MUTATION ANCHOR]', () => {
  const d = 3;

  // deepest scalar at depth d (k = d-1): accepted at maxDepth=d.
  const atLimit = nestedArraysCBOR(d - 1);
  assert.doesNotThrow(() => cbor.decodeBounded(atLimit, d), `depth ${d} should decode at maxDepth=${d}`);

  // deepest scalar at depth d+1 (k = d): rejected DepthExceeded at maxDepth=d.
  const over = nestedArraysCBOR(d);
  expectRejects(() => cbor.decodeBounded(over, d), 'DepthExceeded');

  // The unbounded path accepts the same over-depth structure: the bound, not another check, is
  // what rejected it above.
  assert.doesNotThrow(() => cbor.decode(over), 'unbounded decode should accept the deeper structure');
});

// ---- envelope bounds: object size, causes/ext/cext cardinality, nesting depth ------------------

const SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1); // mirrors impl/go testSigner
const ALG = cose.ALG_MLDSA65;
const SIGNER = new TextEncoder().encode('SIGNER_A');
const CREATED = 1785000000000n;

function kindOk(ch, k) { return Number(ch) === 4 && Number(k) === 2; }

function baseFields(overrides = {}) {
  return {
    kind: 2, channel: 4, tier: 0, signer: SIGNER, created: CREATED, effect: 2,
    profile: cose.PROFILE_PUBLIC, body: new T('hello'),
    ...overrides,
  };
}

// makeCauses builds n content-id-shaped bstrs (multihash sha2-384 prefix 0x20 0x30 + 48 zero
// bytes), so the object is otherwise valid at any causes[] cardinality.
function makeCauses(n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const b = new Uint8Array(50);
    b[0] = 0x20; b[1] = 0x30;
    out.push(b);
  }
  return out;
}

// makeExtMap builds n distinct extension entries (unknown keys, which the may-ignore rule
// accepts for ext and which are simply not RECHECK_KEY for cext), so the object is otherwise
// valid at any cardinality.
function makeExtMap(n) {
  const pairs = [];
  for (let i = 0; i < n; i++) pairs.push([new U(100 + i), new U(0)]);
  return new M(pairs);
}

// nestArrays returns k single-element arrays wrapping a zero scalar. As a body value it sits at
// depth 2 (the object body map is depth 1), so the scalar is at depth 2+k.
function nestArrays(k) {
  let v = new U(0);
  for (let i = 0; i < k; i++) v = new A([v]);
  return v;
}

function signAndVerify(fields) {
  const obj = new envelope.Object(fields);
  const signed = envelope.sign(obj, ALG, SEED);
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);
  return envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, signed);
}

test('envelope bounds accept AT each limit [causes/ext/depth]', () => {
  assert.doesNotThrow(
    () => signAndVerify(baseFields({ causes: makeCauses(MAX_CAUSES) })),
    'causes==MAX_CAUSES should verify',
  );
  assert.doesNotThrow(
    () => signAndVerify(baseFields({ ext: makeExtMap(MAX_EXT) })),
    'ext==MAX_EXT should verify',
  );
  assert.doesNotThrow(
    () => signAndVerify(baseFields({ body: nestArrays(MAX_NESTING_DEPTH - 2) })),
    'depth==MAX_NESTING_DEPTH should verify',
  );
});

test('envelope bounds reject one PAST each limit with the exact Kind [MUTATION ANCHOR]', () => {
  expectRejects(
    () => signAndVerify(baseFields({ causes: makeCauses(MAX_CAUSES + 1) })),
    'TooManyCauses',
  );
  expectRejects(
    () => signAndVerify(baseFields({ ext: makeExtMap(MAX_EXT + 1) })),
    'TooManyExtensions',
  );
  // cext over the limit also yields TooManyExtensions: the cardinality check fires before the
  // critical-extension recognition check.
  expectRejects(
    () => signAndVerify(baseFields({ cext: makeExtMap(MAX_CEXT + 1) })),
    'TooManyExtensions',
  );
  expectRejects(
    () => signAndVerify(baseFields({ body: nestArrays(MAX_NESTING_DEPTH - 1) })),
    'DepthExceeded',
  );
});

test('envelope object octet-size bound: boundary pair [MUTATION ANCHOR]', () => {
  const pk = cose.mldsaKeygen('ML-DSA-65', SEED);

  const under = new envelope.Object(baseFields({ body: new B(new Uint8Array(MAX_OBJECT_SIZE - 16384)) }));
  const uobj = envelope.sign(under, ALG, SEED);
  assert.ok(uobj.length < MAX_OBJECT_SIZE, `under-limit object is ${uobj.length} bytes, expected < ${MAX_OBJECT_SIZE}`);
  assert.doesNotThrow(() => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, uobj), 'verify under-limit');

  const over = new envelope.Object(baseFields({ body: new B(new Uint8Array(MAX_OBJECT_SIZE)) }));
  const bobj = envelope.sign(over, ALG, SEED);
  assert.ok(bobj.length > MAX_OBJECT_SIZE, `over-limit object is only ${bobj.length} bytes, expected > ${MAX_OBJECT_SIZE}`);
  expectRejects(() => envelope.verify(cose.PROFILE_PUBLIC, ALG, pk, kindOk, bobj), 'TooLarge');
});

// The tag-98 rotation-verify entry is size-guarded identically (#154 gave every port a rotation
// verify path). Build a minimal rotation object over-size and confirm TooLarge fires before any
// parse -- an object so oversized it is not even valid COSE_Sign structure would still be
// rejected TooLarge, proving the check runs first.
test('rotation-verify entry is also size-guarded [MUTATION ANCHOR]', () => {
  const oversized = new Uint8Array(MAX_OBJECT_SIZE + 1);
  expectRejects(
    () => envelope.verifyRotationObject(
      cose.PROFILE_PUBLIC, ALG, new Uint8Array(0), ALG, new Uint8Array(0), () => true, oversized,
    ),
    'TooLarge',
  );
});

// ---- streaming bounds: chunk-count (design.md §3.4, R7) ----------------------------------------

// makeChunks builds n zero-offset, zero-length chunks so building/hashing/sorting at
// MAX_STREAM_CHUNKS stays cheap; contiguity and digest still hold trivially at offset 0.
function makeChunks(n) {
  const out = new Array(n);
  const empty = new Uint8Array(0);
  for (let i = 0; i < n; i++) out[i] = new streaming.Chunk(0, empty);
  return out;
}

test('stream chunk-count bound: boundary pair, digest matches so count is the only reject reason [MUTATION ANCHOR]', () => {
  const over = makeChunks(MAX_STREAM_CHUNKS + 1);
  const atLimit = over.slice(0, MAX_STREAM_CHUNKS);

  const okCommit = new streaming.StreamCommit(new Uint8Array(0), streaming.commitDigest(atLimit));
  assert.doesNotThrow(
    () => streaming.verifyCommit(okCommit, atLimit),
    `commit over ${MAX_STREAM_CHUNKS} chunks should verify`,
  );

  const overCommit = new streaming.StreamCommit(new Uint8Array(0), streaming.commitDigest(over));
  expectRejects(() => streaming.verifyCommit(overCommit, over), 'TooManyChunks');

  // verifyCheckpoint enforces the same bound, and the count check fires before the
  // contiguity/digest checks, so the diagnosis is TooManyChunks (not a digest error).
  const cp = new streaming.StreamCheckpoint(new Uint8Array(0), 0, new Uint8Array(0));
  expectRejects(() => streaming.verifyCheckpoint(cp, over), 'TooManyChunks');
});
