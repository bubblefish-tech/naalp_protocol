// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C17 N-AALP-CONT conformance for the TypeScript SDK, graded against the shared independent corpus
// vectors/continuation/cases.json (NOT produced by this code): the FlowOpen / Continuation /
// Checkpoint / FlowCommit body + head + content-id (byte-for-byte), the cheap-path hash-chain verify
// reaching the oracle final head, bearer-authority reconstruction from bytes alone, replay under a
// different FlowOpen (WrongFlow / ChainBroken), the effect-ceiling escalation guard (AboveCeiling),
// checkpoint gap detection, the closed-lattice range reject, the u64::MAX checkpoint-overflow guard,
// the >2^53 seq round-trip, minimal / empty-vs-nonempty distinctness, NonCanonical rejection, and
// look-alike sibling-parser rejection.
//
// FlowOpen / FlowCommit SIGNATURES are real deterministic ML-DSA-65 (@noble/post-quantum, rnd=0), but
// the corpus carries no signature vector, so sign/verify round-trips are demonstrated in isolation
// with fixed local seeds -- stated honestly, not corpus-graded. Every byte-exact assertion and every
// verdict IS corpus-graded.
//
// Written test-first; the continuation module is absent until ported, so this fails RED on import
// until impl/typescript/naalp/continuation.mjs lands, and the mutation "drop the effect-ceiling
// authorizes() check in verifyContinuation" flips 'continuation above-ceiling link is rejected'.
//
// Run:  node --test test/continuation.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as policy from '../naalp/policy.mjs';
import * as cont from '../naalp/continuation.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'continuation', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/continuation/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');
const ALG = cose.ALG_MLDSA65;

function openFrom() {
  return new cont.FlowOpen(
    hexToBytes(C.flow_open.flow_id_hex),
    C.flow_open.effect_ceiling,
    C.flow_open.approvals_hex.map(hexToBytes));
}

function contsFrom() {
  const id = hexToBytes(C.flow_open.id_hex);
  return C.continuations.map((c) => new cont.Continuation(
    id, c.seq, c.effect, hexToBytes(c.payload_id_hex), hexToBytes(c.prev_hex)));
}

// ---- byte parity against the independent oracle ---------------------------------------

test('continuation objects match the oracle byte-for-byte', () => {
  const open = openFrom();
  assert.equal(bytesToHex(open.bytes()), C.flow_open.body_hex, 'FlowOpen body');
  assert.equal(bytesToHex(open.head()), C.flow_open.head_hex, 'FlowOpen head');
  assert.equal(bytesToHex(open.id()), C.flow_open.id_hex, 'FlowOpen id');

  const conts = contsFrom();
  conts.forEach((c, i) => {
    assert.equal(bytesToHex(c.bytes()), C.continuations[i].body_hex, `Continuation[${i}] body`);
    assert.equal(bytesToHex(c.head()), C.continuations[i].head_hex, `Continuation[${i}] head`);
  });

  const cp = new cont.Checkpoint(open.id(), C.checkpoint.through_seq, hexToBytes(C.checkpoint.head_hex));
  assert.equal(bytesToHex(cp.bytes()), C.checkpoint.body_hex, 'Checkpoint body');

  const fc = new cont.FlowCommit(open.id(), hexToBytes(C.flow_commit.final_head_hex));
  assert.equal(bytesToHex(fc.bytes()), C.flow_commit.body_hex, 'FlowCommit body');
});

test('continuation verifyChain reaches the oracle final head', () => {
  const final = cont.verifyChain(openFrom(), contsFrom());
  assert.equal(bytesToHex(final), C.final_head_hex);
});

test('continuation FlowOpen reconstructs its authority from bytes alone (bearer authority)', () => {
  const open = openFrom();
  const got = cont.parseFlowOpen(open.bytes());
  assert.equal(Number(got.effectCeiling), C.flow_open.effect_ceiling);
  assert.equal(bytesToHex(got.flowId), C.flow_open.flow_id_hex);
  assert.equal(got.approvals.length, C.flow_open.approvals_hex.length);
  got.approvals.forEach((a, i) => assert.equal(bytesToHex(a), C.flow_open.approvals_hex[i]));
  assert.equal(bytesToHex(got.id()), bytesToHex(open.id()), 'reconstruct re-encodes to the same id');
});

test('continuation replayed under a different FlowOpen fails', () => {
  const openA = openFrom();
  const conts = contsFrom();
  const ceiling = C.flow_open.effect_ceiling;
  const openBID = hexToBytes(C.replay.flow_open_b_id_hex);
  const openBHead = hexToBytes(C.replay.flow_open_b_head_hex);

  // (a) As delivered: names flow A -> WrongFlow under B.
  assert.throws(() => cont.verifyContinuation(conts[0], openBID, openBHead, 0, ceiling),
    (e) => e.kind === 'WrongFlow');
  // (b) Attacker rewrites the id to B's: prev (head of A) no longer chains to B's head -> ChainBroken.
  const forged = new cont.Continuation(openBID, conts[0].seq, conts[0].effect, conts[0].payloadId, conts[0].prev);
  assert.throws(() => cont.verifyContinuation(forged, openBID, openBHead, 0, ceiling),
    (e) => e.kind === 'ChainBroken');
  // Positive control: verifies under its own FlowOpen A.
  assert.equal(cont.verifyContinuation(conts[0], openA.id(), openA.head(), 0, ceiling), null);
});

test('continuation above-ceiling link is rejected', () => {
  // The cheap path can never escalate past the one full signature + approval: a link whose effect
  // exceeds the ceiling is refused AboveCeiling. MUTATION: dropping the authorizes(ceiling,effect)
  // check in verifyContinuation flips this test on its AboveCeiling assertion.
  const open = openFrom();
  const ceiling = C.flow_open.effect_ceiling;
  const above = new cont.Continuation(
    open.id(), C.above_ceiling.seq, C.above_ceiling.effect,
    hexToBytes(C.above_ceiling.payload_id_hex), hexToBytes(C.above_ceiling.prev_hex));
  assert.equal(bytesToHex(above.bytes()), C.above_ceiling.body_hex, 'well-formed-but-forbidden body parity');
  assert.throws(
    () => cont.verifyContinuation(above, open.id(), hexToBytes(C.above_ceiling.prev_hex), C.above_ceiling.seq, ceiling),
    (e) => e.kind === 'AboveCeiling');
  // Positive control: a within-ceiling effect at the same position is accepted.
  const ok = new cont.Continuation(open.id(), C.above_ceiling.seq, policy.NON_IDEMPOTENT_WRITE,
    hexToBytes(C.above_ceiling.payload_id_hex), hexToBytes(C.above_ceiling.prev_hex));
  assert.equal(
    cont.verifyContinuation(ok, open.id(), hexToBytes(C.above_ceiling.prev_hex), C.above_ceiling.seq, ceiling),
    null);
});

test('continuation checkpoint detects a gap', () => {
  const open = openFrom();
  const conts = contsFrom();
  const through = C.checkpoint.through_seq;

  // Honest checkpoint over seq 0..through verifies.
  const cp = new cont.Checkpoint(open.id(), through, hexToBytes(C.checkpoint.head_hex));
  assert.equal(cont.verifyCheckpoint(cp, open, conts.slice(0, through + 1)), null);

  // Gap: claim through_seq 2 but deliver [seq0, seq2] (seq1 dropped).
  const gapCp = new cont.Checkpoint(open.id(), C.gap.through_seq, hexToBytes(C.final_head_hex));
  assert.throws(() => cont.verifyCheckpoint(gapCp, open, [conts[0], conts[2]]), (e) => e.kind === 'GapDetected');

  // Reorder: [seq1, seq0] with the right count is a gap (seq mismatch at index 0).
  const rcp = new cont.Checkpoint(open.id(), 1, hexToBytes(C.checkpoint.head_hex));
  assert.throws(() => cont.verifyCheckpoint(rcp, open, [conts[1], conts[0]]), (e) => e.kind === 'GapDetected');

  // Tampered head with the right prefix is also a gap.
  const badHead = hexToBytes(C.checkpoint.head_hex);
  badHead[0] ^= 0x01;
  const badCp = new cont.Checkpoint(open.id(), through, badHead);
  assert.throws(() => cont.verifyCheckpoint(badCp, open, conts.slice(0, through + 1)), (e) => e.kind === 'GapDetected');
});

// ---- full-signature paths (real ML-DSA, isolation) ------------------------------------

test('continuation FlowCommit full signature verifies and fails closed', () => {
  const open = openFrom();
  const conts = contsFrom();
  const seed = new Uint8Array(32).fill(0x11);
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const foreign = cose.mldsaKeygen('ML-DSA-65', new Uint8Array(32).fill(0x22));

  const fc = new cont.FlowCommit(open.id(), hexToBytes(C.final_head_hex));
  const obj = cont.signFlowOpen; // referenced to keep the API surface exercised below
  assert.equal(typeof obj, 'function');
  const signed = cont.signFlowCommit(fc, ALG, seed);
  assert.ok(cont.verifyFlowCommit(signed, cose.PROFILE_PUBLIC, ALG, pk, open, conts));

  // Foreign key -> bad signature.
  assert.throws(() => cont.verifyFlowCommit(signed, cose.PROFILE_PUBLIC, ALG, foreign, open, conts),
    (e) => e.kind === 'BadSignature');
  // Missing the last continuation -> recomputed final head differs -> CommitMismatch.
  assert.throws(() => cont.verifyFlowCommit(signed, cose.PROFILE_PUBLIC, ALG, pk, open, conts.slice(0, 2)),
    (e) => e.kind === 'CommitMismatch');
  // Tampered final_head in the signed body -> CommitMismatch.
  const badHead = hexToBytes(C.final_head_hex);
  badHead[0] ^= 0x01;
  const badSigned = cont.signFlowCommit(new cont.FlowCommit(open.id(), badHead), ALG, seed);
  assert.throws(() => cont.verifyFlowCommit(badSigned, cose.PROFILE_PUBLIC, ALG, pk, open, conts),
    (e) => e.kind === 'CommitMismatch');
});

test('continuation FlowOpen full signature is deterministic and reconstructs authority', () => {
  const open = openFrom();
  const seed = new Uint8Array(32).fill(0x11);
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const foreign = cose.mldsaKeygen('ML-DSA-65', new Uint8Array(32).fill(0x22));

  const obj1 = cont.signFlowOpen(open, ALG, seed);
  const obj2 = cont.signFlowOpen(open, ALG, seed);
  assert.equal(bytesToHex(obj1), bytesToHex(obj2), 'deterministic ML-DSA signing');
  const got = cont.verifyFlowOpen(obj1, cose.PROFILE_PUBLIC, ALG, pk);
  assert.equal(Number(got.effectCeiling), C.flow_open.effect_ceiling);
  assert.equal(bytesToHex(got.id()), bytesToHex(open.id()));
  assert.throws(() => cont.verifyFlowOpen(obj1, cose.PROFILE_PUBLIC, ALG, foreign), (e) => e.kind === 'BadSignature');
});

// ---- closed-lattice range reject (never normalize a ceiling to destructive) -----------

test('continuation out-of-lattice ceiling/effect is rejected RangeError (byte-parity + all paths)', () => {
  const bad = C.range_reject.out_of_lattice_value; // 4
  assert.ok(bad > policy.DESTRUCTIVE, 'fixture value is out of lattice');
  const open = openFrom();

  // (a) FlowOpen ceiling=4: byte parity, ParseFlowOpen and verifyChain both reject RangeError.
  const badOpen = new cont.FlowOpen(hexToBytes(C.flow_open.flow_id_hex), bad, open.approvals);
  assert.equal(bytesToHex(badOpen.bytes()), C.range_reject.flow_open_ceiling_body_hex);
  assert.throws(() => cont.parseFlowOpen(hexToBytes(C.range_reject.flow_open_ceiling_body_hex)), (e) => e.kind === 'RangeError');
  assert.throws(() => cont.verifyChain(badOpen, []), (e) => e.kind === 'RangeError');

  // (b) Continuation effect=4: byte parity, ParseContinuation and verifyContinuation reject RangeError.
  const badCont = new cont.Continuation(open.id(), 0, bad, hexToBytes(C.continuations[0].payload_id_hex), open.head());
  assert.equal(bytesToHex(badCont.bytes()), C.range_reject.continuation_effect_body_hex);
  assert.throws(() => cont.parseContinuation(hexToBytes(C.range_reject.continuation_effect_body_hex)), (e) => e.kind === 'RangeError');
  assert.throws(() => cont.verifyContinuation(badCont, open.id(), open.head(), 0, policy.DESTRUCTIVE), (e) => e.kind === 'RangeError');
  // An out-of-lattice CEILING passed to verifyContinuation is also RangeError (never the lattice top).
  const okCont = new cont.Continuation(open.id(), 0, 0, hexToBytes(C.continuations[0].payload_id_hex), open.head());
  assert.throws(() => cont.verifyContinuation(okCont, open.id(), open.head(), 0, bad), (e) => e.kind === 'RangeError');
});

test('continuation checkpoint overflow (through_seq = u64::MAX) is rejected GapDetected', () => {
  const open = openFrom();
  const through = BigInt(C.checkpoint_overflow.through_seq_str);
  assert.equal(through, (2n ** 64n) - 1n, 'fixture is u64::MAX');
  const cp = new cont.Checkpoint(open.id(), through, hexToBytes(C.checkpoint_overflow.head_hex));
  assert.equal(bytesToHex(cp.bytes()), C.checkpoint_overflow.body_hex, 'overflow checkpoint body parity');
  assert.throws(() => cont.verifyCheckpoint(cp, open, []), (e) => e.kind === 'GapDetected');
  // ParseCheckpoint round-trips the >2^53 counter byte-exact (no float corruption).
  const got = cont.parseCheckpoint(hexToBytes(C.checkpoint_overflow.body_hex));
  assert.equal(got.throughSeq, through);
});

test('continuation oversized seq (>2^53) round-trips byte-exact', () => {
  const open = openFrom();
  const seq = BigInt(C.big_seq.seq_str); // 0x0102030405060708 = 72623859790382856
  assert.ok(seq > (1n << 53n), 'fixture seq is > 2^53');
  const c = new cont.Continuation(open.id(), seq, C.big_seq.effect, hexToBytes(C.big_seq.payload_id_hex), hexToBytes(C.big_seq.prev_hex));
  assert.equal(bytesToHex(c.bytes()), C.big_seq.body_hex, 'big-seq body parity');
  assert.equal(bytesToHex(c.head()), C.big_seq.head_hex, 'big-seq head parity');
  const got = cont.parseContinuation(c.bytes());
  assert.equal(got.seq, seq, 'recovered seq is byte-exact (no float rounding)');
});

test('continuation minimal FlowOpen encodes and reconstructs', () => {
  const m = new cont.FlowOpen(hexToBytes(C.minimal.flow_id_hex), C.minimal.effect_ceiling, C.minimal.approvals_hex.map(hexToBytes));
  assert.equal(bytesToHex(m.bytes()), C.minimal.body_hex);
  assert.equal(bytesToHex(m.head()), C.minimal.head_hex);
  assert.equal(bytesToHex(m.id()), C.minimal.id_hex);
  assert.equal(bytesToHex(cont.parseFlowOpen(m.bytes()).id()), C.minimal.id_hex);
});

test('continuation empty vs nonempty approvals are distinct on the wire and by id', () => {
  const empty = new cont.FlowOpen(hexToBytes(C.flow_open.flow_id_hex), C.flow_open.effect_ceiling, []);
  const one = new cont.FlowOpen(hexToBytes(C.flow_open.flow_id_hex), C.flow_open.effect_ceiling, [hexToBytes(C.flow_open.approvals_hex[0])]);
  assert.equal(bytesToHex(empty.bytes()), C.empty_vs_nonempty.empty_approvals.body_hex);
  assert.equal(bytesToHex(one.bytes()), C.empty_vs_nonempty.one_approval.body_hex);
  assert.notEqual(bytesToHex(empty.id()), bytesToHex(one.id()));
  assert.equal(bytesToHex(empty.id()), C.empty_vs_nonempty.empty_approvals.id_hex);
});

test('continuation descending-key body is rejected NonCanonical by the strict decoder', () => {
  const canon = hexToBytes(C.keys_out_of_order.canonical_commit_body_hex);
  const noncanon = hexToBytes(C.keys_out_of_order.noncanonical_commit_body_hex);
  const open = openFrom();
  const fc = new cont.FlowCommit(open.id(), hexToBytes(C.final_head_hex));
  assert.equal(bytesToHex(fc.bytes()), C.keys_out_of_order.canonical_commit_body_hex, 'canonical encoder emits ascending keys');
  assert.doesNotThrow(() => cbor.decode(canon));
  assert.throws(() => cbor.decode(noncanon), (e) => e.kind === 'NonCanonical');
});

test('continuation a look-alike FlowCommit body is rejected by sibling parsers', () => {
  const commitBody = hexToBytes(C.look_alike.flow_commit_body_hex);
  assert.throws(() => cont.parseCheckpoint(commitBody), (e) => e.kind === 'ContMalformed');
  assert.throws(() => cont.parseContinuation(commitBody), (e) => e.kind === 'ContMalformed');
});
