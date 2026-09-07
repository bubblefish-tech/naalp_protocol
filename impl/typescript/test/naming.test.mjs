// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C19 name-bindings + signed A2A task-state profile conformance for the TypeScript SDK (design §22),
// graded against the shared independent corpus vectors/naming/cases.json (NOT produced by this code):
// the name-binding and task-transition body/head/content-id byte parity, the A2A Agent Card
// attestation content-id (a C18 naalp-description-import), the offline name-history walk, hole/fork
// detection with the non-repudiable NameForkProof, the A2A legal-edge table (every legal edge
// accepted, every illegal edge rejected), the signed task-chain verifier (illegal edge /
// non-contiguous / bad start / foreign card / gap / bad signature), the >2^53 seq round-trip, the
// minimal encodings, the strict canonical-key rejection, and the look-alike cross-parse rejection.
//
// The chain verifiers run over REAL deterministic ML-DSA-65 signed COSE_Sign1 objects
// (@noble/post-quantum, rnd=0). The two cross-language pins (SHA-384 of the seq-0 signed binding and
// transition, seed=0x11*32) are the Go + Rust + Python reference constants; asserting them proves the
// TypeScript signed objects are byte-identical to the other stacks. The A2A legal-edge table is the
// C19 mutation target: forcing legalEdge to accept every edge flips 'naming transition table matches
// the oracle' on the illegal-edge assertion.
//
// Written test-first; the naming module is absent until ported, so this fails RED on import
// (ERR_MODULE_NOT_FOUND) until impl/typescript/naalp/naming.mjs lands.
//
// Run:  node --test test/naming.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as policy from '../naalp/policy.mjs';
import * as identity from '../naalp/identity.mjs';
import * as description from '../naalp/description.mjs';
import * as naming from '../naalp/naming.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'naming', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/naming/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);
const ALG = cose.ALG_MLDSA65;
const PROFILE = cose.PROFILE_PUBLIC;

// The Go + Rust + Python reference pins for the deterministic signed seq-0 binding/transition
// (seed=0x11*32). Asserting them proves TypeScript == Go == Rust == Python byte-identical.
const PIN_SIGNED_BINDING_SHA384 = 'a9179b939fffb1bce6abb4cd594b20e08f9d855729047ce4cb287da191234c10fecc9b232f80be902f70a3da490bcb91';
const PIN_SIGNED_TRANSITION_SHA384 = '60a9902f51e3308149cf2ace5cb65cd4541b4cc7bd4ec5f9a120dd44f93560b6358dcb96cb04b0daedd4cbbdf31f5787';

import { sha384 } from '@noble/hashes/sha2.js';

// A deterministic ML-DSA-65 key: a 32-byte all-<seedByte> seed, its public key, and its signer id.
function mkKey(seedByte) {
  const seed = new Uint8Array(32).fill(seedByte);
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const id = identity.signerId(ALG, pk);
  return { seed, pk, id };
}

function bindings() {
  const n = C.name;
  return n.bindings.map((b) => new naming.NameBinding(n.name_utf8, hexToBytes(b.signer_hex), b.seq, hexToBytes(b.prev_hex)));
}

function transitions() {
  const a = C.a2a;
  const task = enc(a.task_utf8);
  const card = hexToBytes(a.card.card_id_hex);
  return a.transitions.map((t) => new naming.Transition(task, card, t.from, t.to, t.seq, hexToBytes(t.prev_hex)));
}

function cardImport() {
  const c = C.a2a.card;
  const ops = c.operations.map((o) => new description.Operation(o.name, o.effect, o.requires_approval));
  return new description.Import(hexToBytes(c.importer_hex), c.format, hexToBytes(c.foreign_hex), ops);
}

// ---- byte parity (design §22) ------------------------------------------------------------

test('naming binding + transition + card-import bodies/heads/ids match the oracle byte-for-byte', () => {
  const n = C.name;
  assert.equal(n.bindings.length, 3);
  const bs = bindings();
  for (let i = 0; i < bs.length; i++) {
    const bv = n.bindings[i];
    assert.equal(bytesToHex(bs[i].bytes()), bv.body_hex, `binding[${i}] body`);
    assert.equal(bytesToHex(bs[i].head()), bv.head_hex, `binding[${i}] head`);
    assert.equal(bytesToHex(bs[i].id()), bv.id_hex, `binding[${i}] id`);
  }
  // The fork sibling b' at seq 1 also encodes byte-identically to the oracle.
  const fp = n.fork.b_prime;
  const bp = new naming.NameBinding(n.name_utf8, hexToBytes(fp.signer_hex), fp.seq, hexToBytes(fp.prev_hex));
  assert.equal(bytesToHex(bp.bytes()), fp.body_hex, 'fork b\' body');

  const a = C.a2a;
  assert.equal(a.transitions.length, 4);
  const ts = transitions();
  for (let i = 0; i < ts.length; i++) {
    const tv = a.transitions[i];
    assert.equal(bytesToHex(ts[i].bytes()), tv.body_hex, `transition[${i}] body`);
    assert.equal(bytesToHex(ts[i].head()), tv.head_hex, `transition[${i}] head`);
    assert.equal(bytesToHex(ts[i].id()), tv.id_hex, `transition[${i}] id`);
  }

  // The A2A Agent Card attestation content-id (a C18 import) that the profile binds.
  const im = cardImport();
  assert.equal(bytesToHex(im.bytes()), a.card.import_body_hex, 'card import body');
  assert.equal(bytesToHex(im.id()), a.card.card_id_hex, 'card import id (the bound card)');
});

// ---- name-history walk -------------------------------------------------------------------

test('naming walk history reproduces the oracle signer succession', () => {
  const n = C.name;
  const bs = bindings();
  const events = naming.walkHistory(bs);
  assert.equal(events.length, n.walk.length);
  for (let i = 0; i < events.length; i++) {
    assert.equal(Number(events[i].seq), n.walk[i].seq, `event[${i}] seq`);
    assert.equal(bytesToHex(events[i].signer), n.walk[i].signer_hex, `event[${i}] signer`);
  }
  // The current signer is the last event's signer.
  assert.equal(bytesToHex(events[events.length - 1].signer), n.bindings[n.bindings.length - 1].signer_hex);
  // A name change mid-chain breaks the walk (one name per chain).
  const bad1 = new naming.NameBinding('other.name', bs[1].signer, bs[1].seq, bs[1].prev);
  assert.throws(() => naming.walkHistory([bs[0], bad1]), (e) => e.kind === 'NameChainBroken');
});

test('naming hole is detected at the oracle position', () => {
  const n = C.name;
  const bs = bindings();
  assert.equal(naming.detectHole(bs)[1], false, 'contiguous chain has no hole');
  const [pos, hole] = naming.detectHole([bs[0], bs[2]]); // seq 1 deleted
  assert.ok(hole);
  assert.equal(pos, n.hole.first_hole_position);
});

test('naming fork is detected with position and the signed proof is non-repudiable', () => {
  const n = C.name;
  const bs = bindings();
  const fp = n.fork.b_prime;
  const bp = new naming.NameBinding(n.name_utf8, hexToBytes(fp.signer_hex), fp.seq, hexToBytes(fp.prev_hex));
  const [pos, fork] = naming.detectFork(bs[1], bp);
  assert.ok(fork);
  assert.equal(pos, n.fork.position);
  // Identical bindings are a benign duplicate; a different seq is a distinct binding.
  assert.equal(naming.detectFork(bs[1], bs[1])[1], false, 'identical bindings are not a fork');
  assert.equal(naming.detectFork(bs[1], bs[2])[1], false, 'different-seq bindings are not a fork');

  // Signed non-repudiable proof: one authority signs BOTH conflicting bindings.
  const acc = mkKey(0x11);
  const foreign = mkKey(0x22);
  const signedA = naming.signBinding(bs[1], ALG, acc.seed);
  const signedB = naming.signBinding(bp, ALG, acc.seed);
  const proof = new naming.NameForkProof(enc(acc.id), signedA, signedB);
  assert.equal(proof.verify(PROFILE, ALG, acc.pk), n.fork.position, 'honest proof forks at the oracle seq');
  // A foreign key does not verify the accused's signatures.
  assert.throws(() => proof.verify(PROFILE, ALG, foreign.pk), (e) => e.kind === 'BadSignature');
  // An unnamed accused, and identical bodies, are NameForkProofInvalid.
  assert.throws(() => new naming.NameForkProof(new Uint8Array(0), signedA, signedB).verify(PROFILE, ALG, acc.pk),
    (e) => e.kind === 'NameForkProofInvalid');
  assert.throws(() => new naming.NameForkProof(enc(acc.id), signedA, signedA).verify(PROFILE, ALG, acc.pk),
    (e) => e.kind === 'NameForkProofInvalid');
});

test('naming chain verify is fail-closed (reorder, tamper, foreign key)', () => {
  const n = C.name;
  const acc = mkKey(0x11);
  const foreign = mkKey(0x22);
  // Build a signed chain via the Registrar (rotation A -> B -> C).
  const reg = new naming.Registrar(n.name_utf8, ALG, acc.seed);
  const bs = [];
  const objs = [];
  for (const bv of n.bindings) {
    const [nb, obj] = reg.append(hexToBytes(bv.signer_hex));
    bs.push(nb);
    objs.push(obj);
  }
  for (let i = 0; i < bs.length; i++) {
    assert.equal(bytesToHex(bs[i].bytes()), n.bindings[i].body_hex, `registrar reproduces oracle body ${i}`);
  }
  const verified = naming.verifyChain(objs, PROFILE, ALG, acc.pk);
  assert.equal(naming.walkHistory(verified).length, bs.length, 'verified chain walks to the full succession');
  // A reordered chain breaks the prev/seq linkage.
  assert.throws(() => naming.verifyChain([objs[0], objs[2], objs[1]], PROFILE, ALG, acc.pk), (e) => e.kind === 'NameChainBroken');
  // A tampered object fails its signature.
  const corrupt = Uint8Array.from(objs[1]);
  corrupt[corrupt.length - 1] ^= 0x01;
  assert.throws(() => naming.verifyChain([objs[0], corrupt, objs[2]], PROFILE, ALG, acc.pk), (e) => e.kind === 'BadSignature');
  // A foreign verifier authenticates none of the bindings.
  assert.throws(() => naming.verifyChain(objs, PROFILE, ALG, foreign.pk), (e) => e.kind === 'BadSignature');
  assert.throws(() => naming.verifyBinding(objs[0], PROFILE, ALG, foreign.pk), (e) => e.kind === 'BadSignature');
});

// ---- A2A legal-edge table (THIS is the mutation-target assertion) ------------------------

test('naming transition table matches the oracle (every legal accepted, every illegal rejected)', () => {
  // MUTATION: forcing legalEdge to a constant true flips the illegal-edge assertion; a constant false
  // flips the legal-edge assertion.
  const a = C.a2a;
  assert.equal(naming.legalEdges().length, a.legal_edges.length, 'legal-edge count matches the oracle');
  for (const e of a.legal_edges) {
    assert.ok(naming.legalEdge(e[0], e[1]), `legal edge ${e[0]}->${e[1]} accepted`);
    assert.equal(naming.verifyTransition(e[0], e[1]), null, `verifyTransition(${e[0]}->${e[1]}) ok`);
  }
  for (const e of a.illegal_edges) {
    assert.equal(naming.legalEdge(e[0], e[1]), false, `illegal edge ${e[0]}->${e[1]} rejected`);
    assert.throws(() => naming.verifyTransition(e[0], e[1]), (er) => er.kind === 'IllegalTransition');
  }
  // Categories match the oracle.
  assert.equal(naming.START_STATE, a.states.start);
  for (const s of a.states.terminal) assert.ok(naming.isTerminal(s), `state ${s} is terminal`);
  for (const s of a.states.interrupted) assert.ok(naming.isInterrupted(s), `state ${s} is interrupted`);
  // A terminal state has no legal out-edge.
  for (const s of a.states.terminal) {
    for (let to = 0; to < 8; to++) assert.equal(naming.legalEdge(s, to), false, `terminal ${s} has no out-edge to ${to}`);
  }
});

test('naming task chain verifies the legal lifecycle and rejects every fault', () => {
  const a = C.a2a;
  const acc = mkKey(0x11);
  const card = hexToBytes(a.card.card_id_hex);
  const task = enc(a.task_utf8);
  const trs = transitions();
  const objs = trs.map((t) => naming.signTransition(t, ALG, acc.seed));
  // LEGAL ordered lifecycle verifies.
  assert.equal(naming.verifyTaskChain(objs, card, PROFILE, ALG, acc.pk).length, 4);

  const chainErr = (list) => {
    try {
      naming.verifyTaskChain(list.map((t) => naming.signTransition(t, ALG, acc.seed)), card, PROFILE, ALG, acc.pk);
    } catch (e) { return e.kind; }
    return null;
  };

  const t0 = new naming.Transition(task, card, naming.STATE_SUBMITTED, naming.STATE_WORKING, 0, naming.genesis());
  // ILLEGAL edge inside a chain: working -> submitted.
  const illegal = new naming.Transition(task, card, naming.STATE_WORKING, naming.STATE_SUBMITTED, 1, t0.head());
  assert.equal(chainErr([t0, illegal]), 'IllegalTransition');
  // NON-CONTIGUOUS from: input-required -> working, but its `from` != t0.to (working).
  const nonContig = new naming.Transition(task, card, naming.STATE_INPUT_REQUIRED, naming.STATE_WORKING, 1, t0.head());
  assert.equal(chainErr([t0, nonContig]), 'IllegalTransition');
  // BAD START: seq-0 does not leave the start state.
  const badStart = new naming.Transition(task, card, naming.STATE_WORKING, naming.STATE_INPUT_REQUIRED, 0, naming.genesis());
  assert.equal(chainErr([badStart]), 'IllegalTransition');
  // FOREIGN CARD.
  const fc = new naming.Transition(task, hexToBytes(a.foreign_card_id_hex), naming.STATE_SUBMITTED, naming.STATE_WORKING, 0, naming.genesis());
  assert.equal(chainErr([fc]), 'ForeignCard');
  // GAP: present [t0, t2] (t1 omitted) — the seq/prev linkage breaks.
  assert.throws(() => naming.verifyTaskChain([objs[0], objs[2]], card, PROFILE, ALG, acc.pk), (e) => e.kind === 'TaskChainBroken');
  // BAD SIGNATURE: a tampered object at index 0.
  const corrupt = Uint8Array.from(objs[0]);
  corrupt[corrupt.length - 1] ^= 0x01;
  assert.throws(() => naming.verifyTaskChain([corrupt, objs[1], objs[2], objs[3]], card, PROFILE, ALG, acc.pk), (e) => e.kind === 'BadSignature');
});

test('naming task gap is detected at the oracle position', () => {
  const a = C.a2a;
  const trs = transitions();
  assert.equal(naming.detectTaskGap(trs)[1], false, 'contiguous chain has no gap');
  const [pos, gap] = naming.detectTaskGap([trs[0], trs[2]]);
  assert.ok(gap);
  assert.equal(pos, a.gap.first_gap_position);
});

test('naming card attestation binds the profile (C18 -> C19 link)', () => {
  const a = C.a2a;
  const acc = mkKey(0x11);
  const im = cardImport();
  const card = im.id();
  assert.equal(bytesToHex(card), a.card.card_id_hex);
  const [submit, ok] = im.operation('submit');
  assert.ok(ok);
  assert.equal(submit.effectClass(), policy.IDEMPOTENT_WRITE, 'the card attests submit -> idempotent_write');
  assert.equal(submit.requiresApprovalFlag(), true);
  // A chain bound to this card verifies.
  const objs = transitions().map((t) => naming.signTransition(t, ALG, acc.seed));
  assert.equal(naming.verifyTaskChain(objs, card, PROFILE, ALG, acc.pk).length, 4);
  // A different importer yields a different card id; a chain carrying it is refused ForeignCard.
  const other = new description.Import(enc('IMPORTER_ID_B'), im.format, im.foreign, im.operations);
  assert.notEqual(bytesToHex(other.id()), bytesToHex(card));
  const foreignT = new naming.Transition(enc(a.task_utf8), other.id(), naming.STATE_SUBMITTED, naming.STATE_WORKING, 0, naming.genesis());
  assert.throws(() => naming.verifyTaskChain([naming.signTransition(foreignT, ALG, acc.seed)], card, PROFILE, ALG, acc.pk),
    (e) => e.kind === 'ForeignCard');
});

test('naming malformed bodies are rejected NameMalformed', () => {
  assert.throws(() => naming.parseNameBinding(Uint8Array.from([0x80])), (e) => e.kind === 'NameMalformed'); // empty CBOR array
  assert.throws(() => naming.parseTransition(Uint8Array.from([0x00])), (e) => e.kind === 'NameMalformed');  // a bare uint 0
});

// ---- cross-language signed-object byte parity (TypeScript == Go == Rust == Python) --------

test('naming signed seq-0 binding is byte-identical to the Go/Rust/Python pin', () => {
  const nb = bindings()[0];
  const seed = new Uint8Array(32).fill(0x11);
  const obj = naming.signBinding(nb, ALG, seed);
  assert.equal(bytesToHex(sha384(obj)), PIN_SIGNED_BINDING_SHA384, 'signed name-binding digest matches the cross-lang pin');
});

test('naming signed seq-0 transition is byte-identical to the Go/Rust/Python pin', () => {
  const tr = transitions()[0];
  const seed = new Uint8Array(32).fill(0x11);
  const obj = naming.signTransition(tr, ALG, seed);
  assert.equal(bytesToHex(sha384(obj)), PIN_SIGNED_TRANSITION_SHA384, 'signed task-transition digest matches the cross-lang pin');
});

// ---- >2^53 seq round-trip, minimal, canonical-key, look-alike ----------------------------

test('naming >2^53 seq round-trips byte-exact (BigInt, no float truncation)', () => {
  const n = C.name;
  const a = C.a2a;
  const bseq = BigInt(n.big_seq.seq_str);
  assert.ok(bseq > (1n << 53n), 'oracle binding seq is > 2^53');
  const nb = new naming.NameBinding(n.name_utf8, hexToBytes(n.big_seq.signer_hex), bseq, hexToBytes(n.big_seq.prev_hex));
  assert.equal(bytesToHex(nb.bytes()), n.big_seq.body_hex, 'big-seq binding body');
  assert.equal(naming.parseNameBinding(nb.bytes()).seq, bseq, 'recovered binding seq is byte-exact');

  const tseq = BigInt(a.big_seq.seq_str);
  const tr = new naming.Transition(enc(a.task_utf8), hexToBytes(a.card.card_id_hex), a.big_seq.from, a.big_seq.to, tseq, hexToBytes(a.big_seq.prev_hex));
  assert.equal(bytesToHex(tr.bytes()), a.big_seq.body_hex, 'big-seq transition body');
  assert.equal(naming.parseTransition(tr.bytes()).seq, tseq, 'recovered transition seq is byte-exact');
});

test('naming minimal binding + transition encode, id, and reconstruct', () => {
  const n = C.name.minimal;
  const a = C.a2a.minimal;
  const nb = new naming.NameBinding(n.name_utf8, hexToBytes(n.signer_hex), n.seq, hexToBytes(n.prev_hex));
  assert.equal(bytesToHex(nb.bytes()), n.body_hex, 'minimal binding body');
  assert.equal(bytesToHex(nb.id()), n.id_hex, 'minimal binding id');
  assert.ok(naming.parseNameBinding(nb.bytes()));
  const tr = new naming.Transition(hexToBytes(a.task_hex), hexToBytes(a.card_hex), a.from, a.to, a.seq, hexToBytes(a.prev_hex));
  assert.equal(bytesToHex(tr.bytes()), a.body_hex, 'minimal transition body');
  assert.ok(naming.parseTransition(tr.bytes()));
});

test('naming rejects descending-key (non-canonical) binding bodies', () => {
  const koo = C.name.keys_out_of_order;
  const b0 = C.name.bindings[0];
  const nb = new naming.NameBinding(C.name.name_utf8, hexToBytes(b0.signer_hex), b0.seq, hexToBytes(b0.prev_hex));
  assert.equal(bytesToHex(nb.bytes()), koo.canonical_binding_body_hex, 'canonical body has ascending keys');
  assert.ok(cbor.decode(hexToBytes(koo.canonical_binding_body_hex)), 'canonical body decodes');
  assert.throws(() => cbor.decode(hexToBytes(koo.noncanonical_binding_body_hex)), (e) => e.kind === 'NonCanonical');
});

test('naming look-alike bodies are rejected by the sibling parser', () => {
  const la = C.name.look_alike;
  // A 4-field binding fed to parseTransition, and a 6-field transition fed to parseNameBinding, both reject.
  assert.throws(() => naming.parseTransition(hexToBytes(la.binding_body_hex)), (e) => e.kind === 'NameMalformed');
  assert.throws(() => naming.parseNameBinding(hexToBytes(la.transition_body_hex)), (e) => e.kind === 'NameMalformed');
});
