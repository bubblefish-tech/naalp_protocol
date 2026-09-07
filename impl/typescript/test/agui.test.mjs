// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C21 NAALP-AGUI UI-consent conformance for the TypeScript SDK, graded against the shared independent
// corpus vectors/agui/cases.json (NOT produced by this code): the closed kind vocabulary, the
// receipt-chained UIEvent bodies/heads/content-ids (incl. the oversized >2^53 seq carried losslessly as
// a string, and the minimal/empty-action forms), the shown-chain walk + final head, the gap-evident
// hole position, and the fail-closed rejections (NonCanonical / UIMalformed).
//
// The signed shown-chain and the human-consent binding (verifyConsent: ActionSubstituted / UINoConsent)
// use real deterministic ML-DSA-65 + the §7 approval and are demonstrated in isolation (the corpus
// carries no signed vector) -- stated honestly, not corpus-graded.
//
// Written test-first; the agui module is absent until ported, so this fails RED on import until
// impl/typescript/naalp/agui.mjs lands, and the mutation "detectHole never reports a gap" flips
// 'agui detects an omitted shown-event with its position (gap-evident)'.
//
// Run:  node --test test/agui.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as approval from '../naalp/approval.mjs';
import * as agui from '../naalp/agui.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'agui', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/agui/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

const ALG = cose.ALG_MLDSA65;
const SEED = new Uint8Array(32);
const PK = cose.mldsaKeygen('ML-DSA-65', SEED);

const SESSION = hexToBytes(C.session_hex);

// ---- the closed kind vocabulary + genesis + action content id (byte-graded) -----------

test('agui kind vocabulary + genesis + action content id match the oracle', () => {
  for (const k of C.kind_vocabulary) {
    assert.equal(agui.kindName(k.code), k.name, `kind ${k.code}`);
    assert.equal(agui.isKnownKind(k.code), true, `known ${k.code}`);
  }
  assert.equal(agui.kindName(C.unknown_kind), 'unknown');
  assert.equal(agui.isKnownKind(C.unknown_kind), false);
  assert.equal(bytesToHex(agui.genesis()), C.genesis_hex);
  // the action content id is the T1 framing over the exact action bytes.
  assert.equal(bytesToHex(agui.contentId(hexToBytes(C.action_bytes_hex))), C.action_cid_hex);
  assert.equal(bytesToHex(agui.contentId(hexToBytes(C.substituted_bytes_hex))), C.substituted_cid_hex);
  assert.notEqual(C.action_cid_hex, C.substituted_cid_hex);
});

// ---- the receipt-chained UIEvent bodies/heads/ids + the walked chain (byte-graded) ----

test('agui ui-event bodies + heads + ids + final chain head match the oracle byte-for-byte', () => {
  const events = [];
  for (const ev of C.chain.events) {
    const e = new agui.UIEvent(SESSION, ev.kind, hexToBytes(ev.action_hex), ev.seq, hexToBytes(ev.prev_hex));
    assert.equal(bytesToHex(e.bytes()), ev.body_hex, `event seq=${ev.seq} body`);
    assert.equal(bytesToHex(e.head()), ev.head_hex, `event seq=${ev.seq} head`);
    assert.equal(bytesToHex(e.id()), ev.id_hex, `event seq=${ev.seq} id`);
    events.push(e);
  }
  // walkShown enforces contiguity (same session, seq == index, prev links to prior head) and returns the
  // ordered shown events; the last head is the corpus final head.
  const shown = agui.walkShown(events);
  assert.equal(shown.length, C.chain.events.length);
  assert.equal(bytesToHex(shown[shown.length - 1].head), C.chain.final_head_hex);
  // the approved event names the action content id a consent binds.
  const [cid, ok] = agui.approvedActionCID(shown);
  assert.equal(ok, true);
  assert.equal(bytesToHex(cid), C.action_cid_hex);
});

test('agui oversized (>2^53) seq round-trips byte-exact (carried as a string / BigInt)', () => {
  // seq = 0x0102030405060708 exceeds 2^53; it MUST be carried losslessly (a float64 decode would round
  // the low octets). Constructed from the corpus string.
  const bs = C.big_seq;
  const e = new agui.UIEvent(SESSION, bs.kind, hexToBytes(bs.action_hex), BigInt(bs.seq_str), hexToBytes(bs.prev_hex));
  assert.equal(bytesToHex(e.bytes()), bs.body_hex, 'big-seq body');
  assert.equal(bytesToHex(e.head()), bs.head_hex, 'big-seq head');
  assert.equal(bytesToHex(e.id()), bs.id_hex, 'big-seq id');
  // and it survives a decode/re-encode round trip losslessly.
  const parsed = agui.parseUIEvent(hexToBytes(bs.body_hex));
  assert.equal(bytesToHex(parsed.bytes()), bs.body_hex, 'big-seq round-trip');
  assert.equal(parsed.seq.toString(), bs.seq_str, 'big-seq value preserved');
});

test('agui minimal ui-event matches the oracle byte-for-byte', () => {
  const m = C.minimal;
  const e = new agui.UIEvent(hexToBytes(m.session_hex), m.kind, hexToBytes(m.action_hex), m.seq, hexToBytes(m.prev_hex));
  assert.equal(bytesToHex(e.bytes()), m.body_hex, 'minimal body');
  assert.equal(bytesToHex(e.head()), m.head_hex, 'minimal head');
  assert.equal(bytesToHex(e.id()), m.id_hex, 'minimal id');
});

// ---- the gap-evident hole detector (byte/position-graded) -----------------------------

test('agui detects an omitted shown-event with its position (gap-evident)', () => {
  // THIS is the mutation-target assertion. Presenting ev0 then ev2 (ev1 omitted) breaks contiguity at
  // index 1 (ev2's seq is 2, not 1), which detectHole reports as the first-broken position -- exactly
  // where the missing shown-event should have been. MUTATION: making detectHole never report a gap
  // collapses this to (0,false), so the [position,true] assertion fails.
  const ev0 = new agui.UIEvent(SESSION, C.chain.events[0].kind, hexToBytes(C.chain.events[0].action_hex),
    C.chain.events[0].seq, hexToBytes(C.chain.events[0].prev_hex));
  const ev2 = new agui.UIEvent(SESSION, C.chain.events[2].kind, hexToBytes(C.chain.events[2].action_hex),
    C.chain.events[2].seq, hexToBytes(C.chain.events[2].prev_hex));
  assert.deepEqual(agui.detectHole([ev0, ev2]), [C.hole.position, true]);
  // a contiguous list has no hole.
  const full = C.chain.events.map((ev) => new agui.UIEvent(SESSION, ev.kind, hexToBytes(ev.action_hex), ev.seq, hexToBytes(ev.prev_hex)));
  assert.deepEqual(agui.detectHole(full), [0, false]);
});

// ---- fail-closed structural rejections (byte-graded) ----------------------------------

test('agui fail-closed: non-canonical, absent field, look-alike, unknown kind', () => {
  const ec = C.edge_cases;

  // keys out of order: the strict decoder rejects NonCanonical; parseUIEvent surfaces UIMalformed.
  assert.throws(() => cbor.decode(hexToBytes(ec.keys_out_of_order.noncanonical_body_hex)), (e) => e.kind === 'NonCanonical');
  assert.throws(() => agui.parseUIEvent(hexToBytes(ec.keys_out_of_order.noncanonical_body_hex)), (e) => e.kind === 'UIMalformed');
  // the canonical form parses.
  const canon = agui.parseUIEvent(hexToBytes(ec.keys_out_of_order.canonical_body_hex));
  assert.equal(bytesToHex(canon.bytes()), ec.keys_out_of_order.canonical_body_hex);

  // an empty action bstr is present and valid, distinct by content id from a populated one.
  const ea = ec.empty_vs_absent.empty_action;
  const emptyEv = new agui.UIEvent(SESSION, 0, new Uint8Array(0), 0, agui.genesis());
  assert.equal(bytesToHex(emptyEv.bytes()), ea.body_hex, 'empty-action body');
  assert.equal(bytesToHex(emptyEv.id()), ea.id_hex, 'empty-action id');
  const pop = ec.empty_vs_absent.populated_action;
  const popEv = new agui.UIEvent(SESSION, 0, hexToBytes(pop.action_hex), 0, agui.genesis());
  assert.equal(bytesToHex(popEv.id()), pop.id_hex, 'populated-action id');
  assert.notEqual(ea.id_hex, pop.id_hex);

  // a body whose mandatory action field is absent is rejected UIMalformed (distinct from empty).
  assert.throws(() => agui.parseUIEvent(hexToBytes(ec.empty_vs_absent.absent_field.body_hex)),
    (e) => e.kind === ec.empty_vs_absent.absent_field.reject);

  // a ui-event-shaped body lacking its field-5 chain back-pointer (prev) is rejected UIMalformed.
  assert.throws(() => agui.parseUIEvent(hexToBytes(ec.look_alike.body_hex)), (e) => e.kind === ec.look_alike.reject);

  // an event whose kind is outside the closed set is rejected when the chain is walked.
  const badKind = new agui.UIEvent(SESSION, C.unknown_kind, hexToBytes(C.action_cid_hex), 0, agui.genesis());
  assert.throws(() => agui.walkShown([badKind]), (e) => e.kind === 'UnknownUIEventKind');
});

// ---- the signed shown-chain + human-consent binding (real ML-DSA + §7, isolation) -----

test('agui verifyConsent binds the human approval to the EXACT action shown (isolation)', () => {
  const actionBytes = hexToBytes(C.action_bytes_hex);
  const actionCID = agui.contentId(actionBytes); // == C.action_cid_hex

  // a shown -> args-shown -> approved chain, all naming the action content id, signed by the UI authority.
  const g = agui.genesis();
  const eShown = new agui.UIEvent(SESSION, agui.KIND_SHOWN, actionCID, 0, g);
  const eArgs = new agui.UIEvent(SESSION, agui.KIND_ARGS_SHOWN, actionCID, 1, eShown.head());
  const eAppr = new agui.UIEvent(SESSION, agui.KIND_APPROVED, actionCID, 2, eArgs.head());
  const chain = [eShown, eArgs, eAppr];
  const objs = chain.map((e) => agui.signUIEvent(e, ALG, SEED));

  // every signed event verifies and the chain is structurally continuous.
  const verified = agui.verifyShownChain(objs, cose.PROFILE_PUBLIC, ALG, PK);
  assert.equal(verified.length, 3);
  // a tampered signature is rejected fail-closed (BadSignature).
  const badObjs = objs.map((o) => Uint8Array.from(o));
  badObjs[1][badObjs[1].length - 1] ^= 1;
  assert.throws(() => agui.verifyShownChain(badObjs, cose.PROFILE_PUBLIC, ALG, PK), (e) => e.kind === 'BadSignature');

  // the human §7 approval binds the shown action content id.
  const APPR_SEED = new Uint8Array(32).fill(9);
  const APPR_PK = cose.mldsaKeygen('ML-DSA-65', APPR_SEED);
  const now = 1000n;
  const appr = new approval.ApprovalRecord(actionCID, 'human', 0, new Uint8Array([1, 2]), 5000n);
  const apprSig = approval.signApproval(appr, ALG, APPR_SEED);

  // executing the EXACT action shown+approved is authorized.
  assert.equal(agui.verifyConsent(chain, actionBytes, appr, ALG, APPR_PK, apprSig, now), null);

  // a SUBSTITUTED action (different content id) is rejected -- the seam a lax UI profile would drop.
  const substituted = hexToBytes(C.substituted_bytes_hex);
  assert.throws(() => agui.verifyConsent(chain, substituted, appr, ALG, APPR_PK, apprSig, now),
    (e) => e.kind === 'ActionSubstituted');

  // a chain with no approved event has no consent to bind (UINoConsent).
  assert.throws(() => agui.verifyConsent([eShown, eArgs], actionBytes, appr, ALG, APPR_PK, apprSig, now),
    (e) => e.kind === 'UINoConsent');

  // an approval bound to a DIFFERENT action does not verify against the shown one (ApprovalMismatch).
  const apprOther = new approval.ApprovalRecord(agui.contentId(substituted), 'human', 0, new Uint8Array([3]), 5000n);
  const apprOtherSig = approval.signApproval(apprOther, ALG, APPR_SEED);
  assert.throws(() => agui.verifyConsent(chain, actionBytes, apprOther, ALG, APPR_PK, apprOtherSig, now),
    (e) => e.kind === 'ApprovalMismatch');
});
