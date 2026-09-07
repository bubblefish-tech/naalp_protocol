// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C15 multi-hop agent-delegation conformance for the TypeScript SDK, graded against the shared
// independent corpus vectors/delegation/cases.json (NOT produced by this code): the DelegationGrant
// wire body + content id (byte-for-byte, incl. the optional-scope omitted/present distinction), the
// D2 scope-containment truth table, and the 12-step leaf->root chain verifier's verdict for every
// oracle scenario -- authorized outcomes AND every named deny -- driven over REAL deterministic
// ML-DSA-65 signed grant chains (each grant a signed envelope object whose issuer is its verified
// signer, real envelope content ids wired into `causes`). Plus the dedicated behavioural deny paths
// (tampered signature, forged issuer, baseline-verifier kind rejection, non-NFC) and the D4 two-gate
// composition with the §7 single-use consume ledger.
//
// The signed chains use real ML-DSA-65 (deterministic, rnd=0); the grant BODY bytes and the chain
// VERDICTS are corpus-graded, while the signatures themselves (like the rest of the SDK) are graded
// by the shared cose byte-parity elsewhere -- here they are exercised end-to-end in isolation.
//
// Written test-first; the delegation module is absent until ported, so this fails RED on import until
// impl/typescript/naalp/delegation.mjs lands, and the mutation "drop the effect-cap attenuation check
// in verifyChain" flips 'delegation scenario effect_exceeds_leaf' (CapExceedsParent -> authorized).
//
// Run:  node --test test/delegation.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import { T } from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as policy from '../naalp/policy.mjs';
import * as channels from '../naalp/channels.mjs';
import * as envelope from '../naalp/envelope.mjs';
import * as identity from '../naalp/identity.mjs';
import * as approval from '../naalp/approval.mjs';
import * as del from '../naalp/delegation.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'delegation', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/delegation/cases.json not found');
}

const C = vectors();
const bytesToHex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const ALG = cose.ALG_MLDSA65;
const PROFILE = cose.PROFILE_PUBLIC;

// A deterministic ML-DSA-65 key: a 32-byte seed (all `seedByte`), its public key, and its signer id.
function mkKey(seedByte) {
  const seed = new Uint8Array(32).fill(seedByte);
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const id = identity.signerId(ALG, pk);
  return { seed, pk, id };
}

// contentIdOf: the T1 content-id framing over arbitrary bytes, to mint a stand-in "action args" id.
function contentIdOf(s) {
  return cbor.contentId(enc(s));
}

// Build, sign, and D3-step-3 verify a grant as its issuer; returns the Resolved (verified) grant.
function resolveGrant(issuerKey, grant, causes) {
  const obj = grant.envelopeObject(enc(issuerKey.id), 1, PROFILE, causes);
  const signed = del.signGrant(obj, ALG, issuerKey.seed);
  return del.verifyGrantObject(PROFILE, ALG, issuerKey.pk, signed);
}

// Build, SIGN, and VERIFY a real action object by its signer (grading R-DEL-2 / D3 step 1 with real
// crypto), then construct the Action from the verified object.
function buildAction(signerKey, effect, scope, causes) {
  const obj = new envelope.Object({
    kind: 2, channel: 1, tier: 0, signer: enc(signerKey.id), created: 1,
    effect, causes, profile: PROFILE, body: new T('action'),
  });
  const signed = envelope.sign(obj, ALG, signerKey.seed);
  const o = envelope.verify(PROFILE, ALG, signerKey.pk, del.composedKindValidator, signed);
  const gotSigner = dec(o.signer);
  assert.equal(gotSigner, signerKey.id, 'action signer must be the authenticated id');
  return new del.Action(gotSigner, Number(o.effect), scope, o.causes);
}

function withTemp(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'naalp-delegation-'));
  try {
    return fn(join(dir, 'consume.wal'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// A valid A -> M -> B two-hop chain (all in-window, effects/depths attenuating), with the pieces a
// tamper/compose test perturbs.
function buildValid2Hop(effect) {
  const a = mkKey(10); // trust anchor / root issuer
  const m = mkKey(11); // middle
  const b = mkKey(12); // actor
  const rootG = new del.Grant(m.id, policy.DESTRUCTIVE, 2, 0, 1000000, '');
  const rootRes = resolveGrant(a, rootG, []);
  const leafG = new del.Grant(b.id, policy.DESTRUCTIVE, 1, 0, 1000000, '');
  const leafObj = leafG.envelopeObject(enc(m.id), 1, PROFILE, [rootRes.contentId]);
  const leafSigned = del.signGrant(leafObj, ALG, m.seed);
  const leafRes = del.verifyGrantObject(PROFILE, ALG, m.pk, leafSigned);
  const set = new Map([
    [bytesToHex(rootRes.contentId), rootRes],
    [bytesToHex(leafRes.contentId), leafRes],
  ]);
  const action = buildAction(b, effect, '', [leafRes.contentId]);
  return { set, anchors: new Set([a.id]), action, leafSigned, leafKey: m, b };
}

// ---- byte + scope grading (== oracle) --------------------------------------------------

test('delegation grant body + content id match the oracle byte-for-byte', () => {
  assert.ok(C.grants.length > 0);
  for (const gj of C.grants) {
    const g = new del.Grant(gj.subject, gj.effect_cap, gj.max_depth, gj.not_before, gj.not_after, gj.scope);
    assert.equal(bytesToHex(g.bytes()), gj.body_hex, `grant ${gj.name} body`);
    assert.equal(bytesToHex(g.contentId()), gj.content_id_hex, `grant ${gj.name} content id`);
  }
});

test('delegation scope containment matches the oracle truth table', () => {
  assert.ok(C.scope_containment.length > 0);
  for (const r of C.scope_containment) {
    assert.equal(del.scopeContained(r.child, r.parent), r.contained,
      `ScopeContained(${JSON.stringify(r.child)}, ${JSON.stringify(r.parent)})`);
  }
});

// ---- the chain-verdict grading over REAL signed chains (one named test per scenario) --

function assignKeys(sc) {
  const m = new Map();
  let seed = 100;
  const assign = (label) => { if (!m.has(label)) { m.set(label, mkKey(seed)); seed += 1; } };
  for (const g of sc.grants) { assign(g.issuer); assign(g.subject); }
  assign(sc.action.signer);
  for (const a of sc.anchors) assign(a);
  return m;
}

for (const sc of C.scenarios) {
  test('delegation scenario ' + sc.name, () => {
    const keys = assignKeys(sc);
    const set = new Map();
    const grantCID = [];
    for (let i = 0; i < sc.grants.length; i++) {
      const gj = sc.grants[i];
      const g = new del.Grant(keys.get(gj.subject).id, gj.effect_cap, gj.max_depth, gj.not_before, gj.not_after, gj.scope);
      const causes = gj.causes.map((ci) => grantCID[ci]);
      const res = resolveGrant(keys.get(gj.issuer), g, causes);
      grantCID[i] = res.contentId;
      set.set(bytesToHex(res.contentId), res);
    }
    const actionCauses = sc.action.causes.map((ci) => grantCID[ci]);
    const action = buildAction(keys.get(sc.action.signer), sc.action.effect, sc.action.scope, actionCauses);
    const anchors = new Set(sc.anchors.map((a) => keys.get(a).id));
    const revoked = new Map();
    for (const r of sc.revoked) revoked.set(bytesToHex(grantCID[r.grant]), r.pos);

    if (sc.expect === 'authorized') {
      assert.equal(del.verifyChain(action, set, anchors, revoked, sc.now), null, `${sc.name}: want authorized`);
    } else {
      assert.throws(() => del.verifyChain(action, set, anchors, revoked, sc.now),
        (e) => e.kind === sc.expect, `${sc.name}: want ${sc.expect}`);
    }
  });
}

// ---- dedicated behavioural deny paths (real crypto) -----------------------------------

test('delegation valid 2-hop chain authorizes (real crypto, independent of the vector loop)', () => {
  const bc = buildValid2Hop(policy.NON_IDEMPOTENT_WRITE);
  assert.equal(del.verifyChain(bc.action, bc.set, bc.anchors, new Map(), 500), null);
});

test('delegation tampered grant signature is rejected (BadSignature)', () => {
  const bc = buildValid2Hop(policy.NON_IDEMPOTENT_WRITE);
  const tampered = Uint8Array.from(bc.leafSigned);
  tampered[tampered.length - 1] ^= 0x01;
  assert.throws(() => del.verifyGrantObject(PROFILE, ALG, bc.leafKey.pk, tampered), (e) => e.kind === 'BadSignature');
});

test('delegation forged issuer is rejected (SignerMismatch)', () => {
  const realKey = mkKey(20);
  const victim = mkKey(21); // the id the forger tries to impersonate
  const subject = mkKey(22);
  const g = new del.Grant(subject.id, policy.NON_IDEMPOTENT_WRITE, 1, 0, 1000000, '');
  // Claim the VICTIM as issuer but sign with realKey: envelope.verify passes (header/body agree), the
  // issuer-to-key binding must still reject.
  const obj = g.envelopeObject(enc(victim.id), 1, PROFILE, []);
  const signed = envelope.sign(obj, ALG, realKey.seed);
  assert.throws(() => del.verifyGrantObject(PROFILE, ALG, realKey.pk, signed), (e) => e.kind === 'SignerMismatch');
});

test('delegation baseline verifier rejects the tier-1 grant kind (UnknownKind)', () => {
  const issuer = mkKey(30);
  const subject = mkKey(31);
  const g = new del.Grant(subject.id, policy.NON_IDEMPOTENT_WRITE, 1, 0, 1000000, '');
  const signed = del.signGrant(g.envelopeObject(enc(issuer.id), 1, PROFILE, []), ALG, issuer.seed);
  // A frozen baseline validator (no tier licensed) rejects the tier-1 DelegationGrant as UnknownKind.
  const baselineValidator = (c, k) => {
    try { channels.lookup(c, k); return true; } catch { return false; }
  };
  assert.throws(() => envelope.verify(PROFILE, ALG, issuer.pk, baselineValidator, signed), (e) => e.kind === 'UnknownKind');
});

test('delegation non-NFC subject is rejected at build (NonNFC)', () => {
  const issuer = mkKey(40);
  const nonNFC = 'é'; // "é" as e + combining acute (NFD, not NFC)
  const g = new del.Grant(nonNFC, policy.READ_ONLY, 0, 0, 1, '');
  assert.throws(() => g.envelopeObject(enc(issuer.id), 1, PROFILE, []), (e) => e.kind === 'NonNFC');
});

// ---- D4 composition with the §7 single-use consume ledger (R-DEL-8) --------------------

function setupDestructive(path) {
  const bc = buildValid2Hop(policy.DESTRUCTIVE);
  const ledger = approval.openLedger(path);
  const approver = mkKey(50);
  const argsCID = contentIdOf('the exact canonical action args');
  const appr = new approval.ApprovalRecord(argsCID, approver.id, policy.DESTRUCTIVE, [1, 2, 3, 4], 1000000);
  const apprSig = approval.signApproval(appr, ALG, approver.seed);
  return { bc, ledger, appr, approverPk: approver.pk, apprSig, argsCID };
}

test('delegation D4 both gates authorize and consume the approval exactly once', () => {
  withTemp((path) => {
    const s = setupDestructive(path);
    try {
      assert.equal(
        del.authorizeDestructive(s.bc.action, s.bc.set, s.bc.anchors, new Map(), 500,
          s.appr, ALG, s.approverPk, s.apprSig, s.argsCID, s.ledger),
        null, 'both gates valid -> authorized');
      assert.equal(s.ledger.isConsumed(s.appr.id()), true, 'approval consumed after authorization');
    } finally {
      s.ledger.close();
    }
  });
});

test('delegation D4 valid chain without a matching approval denies ApprovalRequired (no consume)', () => {
  withTemp((path) => {
    const s = setupDestructive(path);
    try {
      const otherArgs = contentIdOf('some other args the approval does not bind');
      assert.throws(
        () => del.authorizeDestructive(s.bc.action, s.bc.set, s.bc.anchors, new Map(), 500,
          s.appr, ALG, s.approverPk, s.apprSig, otherArgs, s.ledger),
        (e) => e.kind === 'ApprovalRequired');
      assert.equal(s.ledger.len(), 0, 'no ledger append on a rejected action');
    } finally {
      s.ledger.close();
    }
  });
});

test('delegation D4 approval with a broken chain denies the D3 error first (no consume)', () => {
  withTemp((path) => {
    const s = setupDestructive(path);
    try {
      const noAnchors = new Set(); // the root is now untrusted
      assert.throws(
        () => del.authorizeDestructive(s.bc.action, s.bc.set, noAnchors, new Map(), 500,
          s.appr, ALG, s.approverPk, s.apprSig, s.argsCID, s.ledger),
        (e) => e.kind === 'UntrustedChainRoot');
      assert.equal(s.ledger.len(), 0, 'no ledger append when the chain gate fails');
    } finally {
      s.ledger.close();
    }
  });
});

test('delegation D4 approval replay is rejected AlreadyConsumed', () => {
  withTemp((path) => {
    const s = setupDestructive(path);
    try {
      assert.equal(
        del.authorizeDestructive(s.bc.action, s.bc.set, s.bc.anchors, new Map(), 500,
          s.appr, ALG, s.approverPk, s.apprSig, s.argsCID, s.ledger),
        null, 'first authorization succeeds');
      assert.throws(
        () => del.authorizeDestructive(s.bc.action, s.bc.set, s.bc.anchors, new Map(), 500,
          s.appr, ALG, s.approverPk, s.apprSig, s.argsCID, s.ledger),
        (e) => e.kind === 'AlreadyConsumed', 'a spent approval is not fresh authority');
    } finally {
      s.ledger.close();
    }
  });
});
