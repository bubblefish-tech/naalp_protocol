// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C7 audit conformance for the TypeScript SDK, graded against the shared independent corpus
// vectors/audit/cases.json (NOT produced by this code): the hash-chained signed receipt body +
// head, offline chain verification (ChainBroken / ReceiptUnsigned), equivocation detection, the
// draft-01 fork-proof preimage (signatures elided), and the offline causal graph (valid topo
// order, cycle rejection, future-cause rejection).
//
// The receipt/fork-proof SIGNATURES are real deterministic ML-DSA-65 (@noble/post-quantum, rnd=0),
// but the corpus carries no signature vector for this channel (signatures are graded by the shared
// cose byte-parity elsewhere), so the sign/verify round-trips here are demonstrated in isolation
// with a fixed local seed -- stated honestly, not corpus-graded. Every byte-exact assertion
// (body/head/preimage/topo) IS corpus-graded.
//
// Written test-first; the audit module is absent until ported, so this fails RED on import until
// impl/typescript/naalp/audit.mjs lands, and a mutation forcing the encoded receipt seq field to a
// constant flips 'audit receipt chain matches the oracle byte-for-byte'.
//
// Run:  node --test test/audit.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cose from '../naalp/cose.mjs';
import * as audit from '../naalp/audit.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'audit', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/audit/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

const ALG = cose.ALG_MLDSA65;
const SEED = new Uint8Array(32);
const PK = cose.mldsaKeygen('ML-DSA-65', SEED);

// ---- signed hash-chained receipt (design §8.1) ----------------------------------------

test('audit receipt chain matches the oracle byte-for-byte', () => {
  // THIS is the mutation-target assertion: each receipt encodes its own seq/prev/obj/at.
  let head = hexToBytes(C.chain.genesis_prev_hex);
  assert.equal(head.length, audit.HEAD_SIZE);
  for (const rv of C.chain.receipts) {
    const r = new audit.Receipt(hexToBytes(rv.prev_hex), hexToBytes(rv.obj_hex), rv.seq, rv.at);
    assert.equal(bytesToHex(r.bytes()), rv.body_hex, `receipt body seq=${rv.seq}`);
    assert.equal(bytesToHex(r.head()), rv.head_after_hex, `receipt head seq=${rv.seq}`);
    assert.equal(bytesToHex(r.prev), bytesToHex(head), `prev links to previous head seq=${rv.seq}`);
    head = r.head();
  }
  assert.equal(bytesToHex(head), C.chain.final_head_hex);
});

test('audit authority reproduces the chain and verifies in isolation', () => {
  // A fresh authority appending the same object ids at the same anchors reproduces the byte-exact
  // corpus chain (corpus-graded), and the resulting real-ML-DSA-signed chain verifies offline
  // (NOT corpus-graded: the corpus has no signature vector).
  const a = new audit.Authority(ALG, SEED);
  const receipts = [];
  const sigs = [];
  for (const rv of C.chain.receipts) {
    const [r, sig] = a.append(hexToBytes(rv.obj_hex), rv.at);
    assert.equal(bytesToHex(r.bytes()), rv.body_hex, `append body seq=${rv.seq}`);
    receipts.push(r);
    sigs.push(sig);
  }
  assert.equal(audit.verifyChain(receipts, sigs, ALG, PK), null);
});

test('audit verifyChain detects a broken prev link', () => {
  // Sign each body with a real key so the break, not a bad signature, is what fires.
  const cb = C.chain_broken;
  const receipts = [];
  const sigs = [];
  for (const rv of cb.receipts) {
    const r = new audit.Receipt(hexToBytes(rv.prev_hex), hexToBytes(rv.obj_hex), rv.seq, rv.at);
    assert.equal(bytesToHex(r.bytes()), rv.body_hex);
    receipts.push(r);
    sigs.push(cose.mldsaSign(ALG, SEED, r.bytes()));
  }
  assert.throws(() => audit.verifyChain(receipts, sigs, ALG, PK), (e) => e.kind === cb.expect);
});

test('audit verifyChain detects a tampered signature', () => {
  // Isolation: a validly-chained receipt with a corrupted signature is ReceiptUnsigned.
  const rv0 = C.chain.receipts[0];
  const r = new audit.Receipt(hexToBytes(C.chain.genesis_prev_hex), hexToBytes(rv0.obj_hex), 0, rv0.at);
  const bad = Uint8Array.from(cose.mldsaSign(ALG, SEED, r.bytes()));
  bad[bad.length - 1] ^= 1;
  assert.throws(() => audit.verifyChain([r], [bad], ALG, PK), (e) => e.kind === 'ReceiptUnsigned');
});

test('audit consistentWithAnchor', () => {
  assert.equal(audit.consistentWithAnchor(100, 100), true);
  assert.equal(audit.consistentWithAnchor(99, 100), true);
  assert.equal(audit.consistentWithAnchor(101, 100), false); // created after ordered
});

// ---- equivocation detection (design §8.5) ---------------------------------------------

function forkReceipts() {
  const f = C.fork_proof;
  const ra = new audit.Receipt(hexToBytes(f.prev_hex), hexToBytes(f.obj_a_hex), f.seq, f.at);
  const rb = new audit.Receipt(hexToBytes(f.prev_hex), hexToBytes(f.obj_b_hex), f.seq, f.at);
  return [f, ra, rb];
}

test('audit equivocation receipts match the oracle', () => {
  const [f, ra, rb] = forkReceipts();
  assert.equal(bytesToHex(ra.bytes()), f.body_a_hex);
  assert.equal(bytesToHex(rb.bytes()), f.body_b_hex);
  // cross-check against the corpus equivocation section (same seq-1 conflict)
  const eq = C.equivocation;
  assert.equal(bytesToHex(ra.bytes()), eq.receipt_a.body_hex);
  assert.equal(bytesToHex(rb.bytes()), eq.receipt_b.body_hex);
});

test('audit equivocation is detected', () => {
  // Two validly-signed receipts by ONE authority at one seq naming DIFFERENT objects: the auditor
  // mints a fork proof (corpus expect == "Equivocation"). A benign first observe returns null.
  const [f, ra, rb] = forkReceipts();
  const sigA = cose.mldsaSign(ALG, SEED, ra.bytes());
  const sigB = cose.mldsaSign(ALG, SEED, rb.bytes());
  const auditor = new audit.Auditor(ALG, PK, hexToBytes(f.signer_hex), f.ext_counter);
  assert.equal(auditor.observe(ra, sigA), null, 'first observe is benign');
  const fp = auditor.observe(rb, sigB);
  assert.notEqual(fp, null, 'a genuine fork at one seq must be detected');
  assert.equal(fp.verify(ALG, PK), null, 'the minted proof verifies against the accused key');
  assert.equal(C.equivocation.expect, 'Equivocation');
});

test('audit benign duplicate is not equivocation', () => {
  const [f, ra] = forkReceipts();
  const sigA = cose.mldsaSign(ALG, SEED, ra.bytes());
  const auditor = new audit.Auditor(ALG, PK, hexToBytes(f.signer_hex), f.ext_counter);
  assert.equal(auditor.observe(ra, sigA), null);
  assert.equal(auditor.observe(ra, sigA), null, 'an exact duplicate is not a fork');
});

test('audit observe rejects an unsigned receipt', () => {
  const [f, ra] = forkReceipts();
  const auditor = new audit.Auditor(ALG, PK, hexToBytes(f.signer_hex), f.ext_counter);
  assert.throws(() => auditor.observe(ra, new Uint8Array(8)), (e) => e.kind === 'ReceiptUnsigned');
});

// ---- fork proof (draft-01 §8.5) -------------------------------------------------------

test('audit fork-proof preimage matches the oracle', () => {
  // The framing witness (both signatures elided to empty) is reproduced byte-for-byte from the
  // corpus, independent of the signature bytes. Corpus-graded.
  const [f, ra, rb] = forkReceipts();
  const fp = audit.newForkProof(hexToBytes(f.signer_hex), ra, new Uint8Array(0), rb, new Uint8Array(0), f.ext_counter);
  assert.equal(bytesToHex(fp.preimage()), f.preimage_hex);
});

test('audit fork-proof verify accepts and fails closed', () => {
  const [f, ra, rb] = forkReceipts();
  const sigA = cose.mldsaSign(ALG, SEED, ra.bytes());
  const sigB = cose.mldsaSign(ALG, SEED, rb.bytes());
  const signer = hexToBytes(f.signer_hex);
  const good = audit.newForkProof(signer, ra, sigA, rb, sigB, f.ext_counter);
  assert.equal(good.verify(ALG, PK), null); // a valid, non-repudiable proof

  // same object named twice -> not equivocation -> ForkProofInvalid (fail-closed)
  const same = audit.newForkProof(signer, ra, sigA, ra, sigA, f.ext_counter);
  assert.throws(() => same.verify(ALG, PK), (e) => e.kind === 'ForkProofInvalid');

  // unnamed accused -> ForkProofInvalid
  const unnamed = audit.newForkProof(new Uint8Array(0), ra, sigA, rb, sigB, f.ext_counter);
  assert.throws(() => unnamed.verify(ALG, PK), (e) => e.kind === 'ForkProofInvalid');

  // seq mismatch -> ForkProofInvalid
  const rbSeq = new audit.Receipt(rb.prev, rb.obj, Number(rb.seq) + 1, rb.at);
  const sigB2 = cose.mldsaSign(ALG, SEED, rbSeq.bytes());
  const mism = audit.newForkProof(signer, ra, sigA, rbSeq, sigB2, f.ext_counter);
  assert.throws(() => mism.verify(ALG, PK), (e) => e.kind === 'ForkProofInvalid');

  // tampered signature -> ReceiptUnsigned
  const badSig = Uint8Array.from(sigB);
  badSig[badSig.length - 1] ^= 1;
  const tampered = audit.newForkProof(signer, ra, sigA, rb, badSig, f.ext_counter);
  assert.throws(() => tampered.verify(ALG, PK), (e) => e.kind === 'ReceiptUnsigned');
});

// ---- offline causal graph (design §8.2-§8.3) ------------------------------------------

function nodesFor(key) {
  return C[key].nodes.map((n) => new audit.CausalNode(
    hexToBytes(n.id_hex), n.causes_hex.map(hexToBytes), n.position));
}

test('audit causal valid topo order matches the oracle', () => {
  const nodes = nodesFor('causal_valid');
  assert.equal(audit.verifyCausal(nodes), null);
  const order = audit.topoOrder(nodes);
  assert.deepEqual(order.map(bytesToHex), C.causal_valid.topo_order_hex);
});

test('audit causal cycle rejected', () => {
  assert.throws(() => audit.verifyCausal(nodesFor('causal_cycle')), (e) => e.kind === C.causal_cycle.expect);
});

test('audit causal future-cause rejected', () => {
  assert.throws(() => audit.verifyCausal(nodesFor('causal_future')), (e) => e.kind === C.causal_future.expect);
});
