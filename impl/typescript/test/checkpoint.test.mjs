// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// S3 naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof conformance for the
// TypeScript SDK, graded against the shared independent corpus vectors/checkpoint/cases.json (NOT
// produced by this code): RFC 9162-profiled Merkle math (leaf hash, interior node hash, empty-tree
// KAT), byte-exact checkpoint/witness-cosign/inclusion-proof body/head/content-id, fork evidence,
// inclusion-proof verification against the resolved checkpoint's own size/root, and the named
// negative rejections (witness-root mismatch, wrong index, wrong path, descending-key body, missing
// mandatory field).
//
// Mirrors impl/go/gateway/checkpoint_test.go via the byte-verified impl/python template
// (test_checkpoint.py). Written test-first: a mutation forcing merkleRoot to a constant flips
// 'RFC 9162 self-fidelity over synthetic leaves'.
//
// Run:  node --test test/checkpoint.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as gateway from '../naalp/gateway.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'checkpoint', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/checkpoint/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

function cpFrom(cv) {
  return new gateway.CheckpointRoot(hexToBytes(cv.log_hex), cv.size, hexToBytes(cv.root_hex), hexToBytes(cv.prev_hex), BigInt(cv.at_str));
}

function wcFrom(wv) {
  return new gateway.WitnessCosign(hexToBytes(wv.witness_hex), hexToBytes(wv.root_hex), BigInt(wv.at_str));
}

test('checkpoint bodies match the oracle byte-for-byte', () => {
  assert.equal(bytesToHex(gateway.genesisPrev()), C.genesis.prev_hex);
  for (const [name, cv] of Object.entries(C.checkpoints)) {
    const c = cpFrom(cv);
    assert.equal(bytesToHex(c.bytes()), cv.body_hex, name);
    assert.equal(bytesToHex(c.head()), cv.head_hex, name);
    assert.equal(bytesToHex(c.id()), cv.id_hex, name);
    const parsed = gateway.parseCheckpointRoot(c.bytes());
    assert.equal(bytesToHex(parsed.bytes()), cv.body_hex, name);
  }
});

test('witness-cosign byte parity', () => {
  for (const [name, wv] of Object.entries(C.witness_cosigns)) {
    const w = wcFrom(wv);
    assert.equal(bytesToHex(w.bytes()), wv.body_hex, name);
    assert.equal(bytesToHex(w.head()), wv.head_hex, name);
    assert.equal(bytesToHex(w.id()), wv.id_hex, name);
  }
});

test('fork evidence: two witness-cosigned roots at one (log, size) with different roots', () => {
  const fe = C.fork_evidence;
  assert.notEqual(fe.checkpoint_a.root_hex, fe.checkpoint_b.root_hex);
  assert.notEqual(fe.checkpoint_a.id_hex, fe.checkpoint_b.id_hex);

  const wcA = wcFrom(fe.checkpoint_a.witness_cosign);
  const wcB = wcFrom(fe.checkpoint_b.witness_cosign);
  assert.equal(bytesToHex(wcA.bytes()), fe.checkpoint_a.witness_cosign.body_hex);
  assert.equal(bytesToHex(wcB.bytes()), fe.checkpoint_b.witness_cosign.body_hex);

  const idA = hexToBytes(fe.checkpoint_a.id_hex);
  const idB = hexToBytes(fe.checkpoint_b.id_hex);
  gateway.validateWitnessCosign(wcA, idA); // no throw
  gateway.validateWitnessCosign(wcB, idB); // no throw
  assert.throws(() => gateway.validateWitnessCosign(wcA, idB), (e) => e.kind === 'WitnessRootMismatch');
  assert.throws(() => gateway.validateWitnessCosign(wcB, idA), (e) => e.kind === 'WitnessRootMismatch');
});

test('inclusion-proof byte parity and verification against the resolved checkpoint', () => {
  const checkpointFor = {
    leaf3_of7: 'checkpoint0_size7',
    leaf7_of8_newly_appended: 'checkpoint1_size8',
    single_leaf_tree_empty_path: 'checkpoint_single_leaf',
  };
  for (const [name, iv] of Object.entries(C.inclusion_proofs)) {
    const cpName = checkpointFor[name];
    const cp = C.checkpoints[cpName];
    const resolvedId = cpFrom(cp).id();
    assert.equal(bytesToHex(resolvedId), iv.root_hex, name);

    const p = new gateway.InclusionProof(hexToBytes(iv.root_hex), hexToBytes(iv.leaf_hex), iv.index, iv.path_hex.map(hexToBytes));
    assert.equal(bytesToHex(p.bytes()), iv.body_hex, name);
    assert.equal(bytesToHex(p.head()), iv.head_hex, name);
    assert.equal(bytesToHex(p.id()), iv.id_hex, name);
    const parsed = gateway.parseInclusionProof(p.bytes());
    gateway.verifyInclusionProof(parsed.leaf, parsed.index, cp.size, parsed.path, hexToBytes(cp.root_hex)); // no throw
  }
});

test('inclusion-proof negative: wrong index and wrong path', () => {
  const cp0 = C.checkpoints.checkpoint0_size7;
  const root0 = hexToBytes(cp0.root_hex);

  const wi = C.negative.inclusion_wrong_index;
  assert.throws(
    () => gateway.verifyInclusionProof(hexToBytes(wi.leaf_hex), wi.claimed_index, cp0.size, wi.path_hex.map(hexToBytes), root0),
    (e) => e.kind === 'InclusionProofInvalid');

  const wp = C.negative.inclusion_wrong_path;
  assert.throws(
    () => gateway.verifyInclusionProof(hexToBytes(wp.leaf_hex), wp.index, cp0.size, wp.path_hex.map(hexToBytes), root0),
    (e) => e.kind === 'InclusionProofInvalid');
});

test('witness-root mismatch', () => {
  const wm = C.negative.witness_root_mismatch;
  const w = gateway.parseWitnessCosign(hexToBytes(wm.cosign_body_hex));
  assert.equal(bytesToHex(w.root), wm.cosign_names_root_hex);
  assert.throws(() => gateway.validateWitnessCosign(w, hexToBytes(wm.checkpoint_accompanied_id_hex)), (e) => e.kind === wm.reject);
});

test('checkpoint negative: descending-key body and missing mandatory field', () => {
  const koo = C.negative.checkpoint_keys_out_of_order;
  gateway.parseCheckpointRoot(hexToBytes(koo.canonical_body_hex)); // should parse
  assert.throws(() => cbor.decode(hexToBytes(koo.noncanonical_body_hex)), (e) => e.kind === 'NonCanonical');
  assert.throws(() => gateway.parseCheckpointRoot(hexToBytes(koo.noncanonical_body_hex)), (e) => e.kind === 'CheckpointMalformed');

  const mf = C.negative.checkpoint_missing_field;
  assert.throws(() => gateway.parseCheckpointRoot(hexToBytes(mf.body_hex)), (e) => e.kind === mf.reject);
});

test('empty-tree KAT: MTH({}) = HASH()', () => {
  const want = C.empty_tree_kat.root_hex;
  assert.equal(bytesToHex(gateway.merkleRoot(null)), want);
  assert.equal(bytesToHex(gateway.merkleRoot([])), want);
});

test('RFC 9162 self-fidelity over synthetic leaves (independent of the oracle vectors)', () => {
  // Independently re-derives the RFC's own claimed property using this module's OWN Merkle
  // construction over synthetic leaves -- never the oracle's numbers -- so this test would catch an
  // algorithmic defect the byte-parity vectors above (which only exercise n in {1,7,8}) do not reach.
  let total = 0;
  for (let n = 1; n <= 12; n++) {
    const leaves = [];
    for (let i = 0; i < n; i++) leaves.push(new TextEncoder().encode(`synthetic-leaf-${i}`));
    const root = gateway.merkleRoot(leaves);
    for (let m = 0; m < n; m++) {
      const path = gateway.generateInclusionProofPath(leaves, m);
      gateway.verifyInclusionProof(leaves[m], m, n, path, root); // no throw
      total += 1;
    }
  }
  assert.equal(total, 78); // sum(1..12) == 78, matching the oracle's own count

  // A tampered leaf must NOT verify against the untouched root.
  const leaves = [];
  for (let i = 0; i < 5; i++) leaves.push(new TextEncoder().encode(`synthetic-leaf-${i}`));
  const root = gateway.merkleRoot(leaves);
  const path = gateway.generateInclusionProofPath(leaves, 2);
  assert.throws(
    () => gateway.verifyInclusionProof(new TextEncoder().encode('tampered-leaf'), 2, 5, path, root),
    (e) => e.kind === 'InclusionProofInvalid');
});

test('sign/verify checkpoint in isolation (not corpus-graded)', () => {
  // NOT corpus-graded (the corpus carries no signed COSE vector): demonstrates
  // sign/verifyCheckpointRoot round-tripping in isolation with a local seed.
  const cv = C.checkpoints.checkpoint0_size7;
  const c = cpFrom(cv);
  const seed = new Uint8Array(32).fill(0x11);
  const alg = cose.ALG_MLDSA65;
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const obj = gateway.signCheckpointRoot(c, alg, seed);
  const [prot, payload, sig] = cose.parseSign1Raw(obj);
  assert.equal(cose.coseVerify1Raw(alg, pk, cose.toBeSignedRaw(prot, payload), sig), true);
  assert.deepEqual(payload, c.bytes());
});
