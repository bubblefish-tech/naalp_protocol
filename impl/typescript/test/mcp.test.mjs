// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// NAALP-MCP binding-profile conformance for the TypeScript SDK, graded against the shared independent
// corpus vectors/mcp/cases.json (NOT produced by this code): the naalp-mcp-annotations byte encoding,
// the published annotation->effect mapping table, the more-severe effect resolution + under-declaration
// rejection, the tool-call bodies/content-ids, the (tool_id, args_id) call binding an approval binds,
// and the fail-closed rejections (MalformedAnnotation / ToolCallMalformed / NonCanonical).
//
// The signed governance path (verifyToolCall / authorizeCall) is real deterministic ML-DSA-65 over the
// real envelope + §7 approval/consume ledger, demonstrated in isolation (the corpus carries no signed
// vector) -- stated honestly, not corpus-graded.
//
// Written test-first; the mcp module is absent until ported, so this fails RED on import until
// impl/typescript/naalp/mcp.mjs lands, and the mutation "drop the under-declaration guard in
// resolveEnforcedEffect" flips 'mcp effect resolution: more-severe, reject under-declaration'.
//
// Run:  node --test test/mcp.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as policy from '../naalp/policy.mjs';
import * as identity from '../naalp/identity.mjs';
import * as approval from '../naalp/approval.mjs';
import * as envelope from '../naalp/envelope.mjs';
import * as mcp from '../naalp/mcp.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'mcp', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/mcp/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

const ALG = cose.ALG_MLDSA65;
const SEED = new Uint8Array(32);
const PK = cose.mldsaKeygen('ML-DSA-65', SEED);

// Build an Annotations from a corpus `hints` object ({"1":1,"2":0,...}); an absent key is an absent
// hint (undefined), distinct on the wire from a present false.
function annFromHints(h) {
  const g = (k) => (k in h ? h[k] === 1 : undefined);
  return new mcp.Annotations(g('1'), g('2'), g('3'), g('4'));
}

// ---- §6.1 the naalp-mcp-annotations byte encoding (byte-graded) -----------------------

test('mcp annotation set encodes to the oracle bytes', () => {
  assert.ok(C.annotations.length >= 5, 'need several annotation vectors');
  for (const a of C.annotations) {
    const ann = annFromHints(a.hints);
    assert.equal(bytesToHex(ann.encode()), a.annotations_hex, `annotations ${a.name}`);
  }
});

// ---- §6.1 the published annotation -> effect mapping table (byte/verdict-graded) ------

test('mcp annotations map to the oracle effect (published table)', () => {
  for (const a of C.annotations) {
    const ann = annFromHints(a.hints);
    assert.equal(mcp.mapAnnotationsToEffect(ann), a.mapped_effect, `mapped ${a.name}`);
  }
});

// ---- a malformed annotation set is rejected fail-closed, never defaulted to benign ----

test('mcp malformed annotation sets are rejected (MalformedAnnotation)', () => {
  assert.ok(C.malformed_annotations.length >= 3);
  for (const m of C.malformed_annotations) {
    const v = cbor.decode(hexToBytes(m.annotations_hex));
    assert.throws(() => mcp.annotationsFromValue(v), (e) => e.kind === m.expect, `malformed ${m.name}`);
  }
});

// ---- the more-severe effect resolution (the good-regulator attenuator) ----------------

test('mcp effect resolution: more-severe, reject under-declaration', () => {
  // THIS is the mutation-target assertion. For an accept verdict the enforced effect is the more
  // severe (== declared) and mismatch is the corpus flag; an under-declaration THROWS
  // EffectUnderDeclared (a wrapper's declared effect can never sit under its own annotations' mapping).
  // MUTATION: dropping the `declared < annotationMapped` guard makes resolveEnforcedEffect return
  // [declared, ...] instead of throwing, so the assert.throws below fails.
  for (const r of C.resolution) {
    if (r.verdict === 'accept') {
      const [enforced, mismatch] = mcp.resolveEnforcedEffect(r.annotation_mapped, r.declared);
      assert.equal(enforced, r.enforced, `enforced ${r.name}`);
      assert.equal(mismatch, r.mismatch, `mismatch ${r.name}`);
    } else {
      assert.throws(() => mcp.resolveEnforcedEffect(r.annotation_mapped, r.declared),
        (e) => e.kind === r.verdict, `resolution ${r.name}`);
    }
  }
  // a declared value outside the closed lattice is EffectOutsideLattice
  assert.throws(() => mcp.resolveEnforcedEffect(policy.READ_ONLY, 4), (e) => e.kind === 'EffectOutsideLattice');
});

// ---- the tool-call body, content id, and the (tool_id, args_id) call binding (byte-graded) ----

test('mcp tool-call bodies + content ids + call bindings match the oracle byte-for-byte', () => {
  assert.ok(C.tool_calls.length >= 3);
  for (const tcv of C.tool_calls) {
    const tool = hexToBytes(tcv.tool_hex);
    const args = hexToBytes(tcv.args_hex);
    const ann = annFromHints(tcv.hints);
    const tc = new mcp.ToolCall(tool, args, ann);
    assert.equal(bytesToHex(ann.encode()), tcv.annotations_hex, `annotations ${tcv.name}`);
    assert.equal(bytesToHex(tc.bytes()), tcv.body_hex, `body ${tcv.name}`);
    assert.equal(bytesToHex(tc.contentId()), tcv.content_id_hex, `content id ${tcv.name}`);
    assert.equal(mcp.mapAnnotationsToEffect(tc.annotations), tcv.annotation_mapped_effect, `mapped ${tcv.name}`);

    const cb = mcp.newCallBinding(tool, args);
    assert.equal(bytesToHex(cb.toolId), tcv.tool_id_hex, `tool id ${tcv.name}`);
    assert.equal(bytesToHex(cb.argsId), tcv.args_id_hex, `args id ${tcv.name}`);
    assert.equal(bytesToHex(cb.bytes()), tcv.call_binding_hex, `call binding ${tcv.name}`);
    assert.equal(bytesToHex(cb.contentId()), tcv.call_content_id_hex, `call content id ${tcv.name}`);
    // the ToolCall's own call-binding accessor agrees with the free constructor
    assert.equal(bytesToHex(tc.callBinding().contentId()), tcv.call_content_id_hex, `tc.callBinding ${tcv.name}`);
  }
});

// ---- the approval binds the EXACT call: a changed arg OR a changed tool desc invalidates it ----

test('mcp call binding: changed args / changed tool desc yield a different call content id', () => {
  const byName = Object.fromEntries(C.approval_binding.map((b) => [b.name, b]));
  for (const b of C.approval_binding) {
    const cb = mcp.newCallBinding(hexToBytes(b.tool_hex), hexToBytes(b.args_hex));
    assert.equal(bytesToHex(cb.toolId), b.tool_id_hex, `tool id ${b.name}`);
    assert.equal(bytesToHex(cb.argsId), b.args_id_hex, `args id ${b.name}`);
    assert.equal(bytesToHex(cb.bytes()), b.call_binding_hex, `binding ${b.name}`);
    assert.equal(bytesToHex(cb.contentId()), b.call_content_id_hex, `call content id ${b.name}`);
  }
  // AC-6.1.2 / AC-6.1.3: the approved call's content id differs from both the changed-args and the
  // changed-tool-description calls -- so an approval bound to base_T_A satisfies neither.
  assert.notEqual(byName.base_T_A.call_content_id_hex, byName.changed_args_T_B.call_content_id_hex);
  assert.notEqual(byName.base_T_A.call_content_id_hex, byName.changed_tool_desc_T2_A.call_content_id_hex);
});

// ---- fail-closed edge cases (byte-graded) ---------------------------------------------

test('mcp edge cases: canonical vs non-canonical, empty vs absent annotations, minimal, look-alike', () => {
  const ec = C.edge_cases;

  // keys out of order: the strict decoder rejects NonCanonical; the canonical form round-trips.
  assert.throws(() => cbor.decode(hexToBytes(ec.keys_out_of_order.noncanonical_body_hex)),
    (e) => e.kind === 'NonCanonical');
  const canon = mcp.toolCallFromBody(cbor.decode(hexToBytes(ec.keys_out_of_order.canonical_body_hex)));
  assert.equal(bytesToHex(canon.bytes()), ec.keys_out_of_order.canonical_body_hex);

  // an empty annotations map is PRESENT and valid (all MCP defaults -> destructive).
  const ea = ec.empty_vs_absent.empty_annotations;
  const tcEmpty = mcp.toolCallFromBody(cbor.decode(hexToBytes(ea.body_hex)));
  assert.equal(bytesToHex(tcEmpty.bytes()), ea.body_hex);
  assert.equal(bytesToHex(tcEmpty.contentId()), ea.content_id_hex);
  assert.equal(mcp.mapAnnotationsToEffect(tcEmpty.annotations), ea.mapped_effect);

  // a tool-call whose annotations field is ABSENT is rejected ToolCallMalformed (distinct from empty).
  assert.throws(() => mcp.toolCallFromBody(cbor.decode(hexToBytes(ec.empty_vs_absent.absent_annotations.body_hex))),
    (e) => e.kind === ec.empty_vs_absent.absent_annotations.reject);

  // the smallest valid tool-call: empty tool, empty args, empty annotations (-> destructive default).
  const tcMin = mcp.toolCallFromBody(cbor.decode(hexToBytes(ec.minimal.body_hex)));
  assert.equal(bytesToHex(tcMin.bytes()), ec.minimal.body_hex);
  assert.equal(bytesToHex(tcMin.contentId()), ec.minimal.content_id_hex);
  assert.equal(mcp.mapAnnotationsToEffect(tcMin.annotations), ec.minimal.mapped_effect);

  // a 2-field call-binding fed to the tool-call parser is rejected (a tool-call is 3 fields).
  assert.throws(() => mcp.toolCallFromBody(cbor.decode(hexToBytes(ec.look_alike.call_binding_body_hex))),
    (e) => e.kind === ec.look_alike.reject);
});

// ---- the signed governance path: verify + resolve enforced effect (real ML-DSA, isolation) ----

test('mcp verifyToolCall resolves the enforced effect end-to-end (isolation)', () => {
  const signerBytes = new TextEncoder().encode(identity.signerId(ALG, PK));
  const tool = hexToBytes(C.tool_calls[0].tool_hex);
  const args = hexToBytes(C.tool_calls[0].args_hex);

  // agree: destructive annotations, declared destructive -> enforced destructive, no mismatch.
  const annDes = new mcp.Annotations(false, true); // ro=false, de=true
  const tcDes = new mcp.ToolCall(tool, args, annDes);
  const objDes = tcDes.envelopeObject(signerBytes, 1000, cose.PROFILE_PUBLIC, policy.DESTRUCTIVE, []);
  const rDes = mcp.verifyToolCall(cose.PROFILE_PUBLIC, ALG, PK, mcp.signToolCall(objDes, ALG, SEED));
  assert.equal(rDes.enforced, policy.DESTRUCTIVE);
  assert.equal(rDes.annotationMapped, policy.DESTRUCTIVE);
  assert.equal(rDes.declared, policy.DESTRUCTIVE);
  assert.equal(rDes.mismatch, false);

  // lying benign annotation (read_only -> 0) but the accountable signer declares destructive: enforced
  // = destructive (more severe), mismatch attributable to the signer.
  const annRO = new mcp.Annotations(true);
  const tcMis = new mcp.ToolCall(tool, args, annRO);
  const objMis = tcMis.envelopeObject(signerBytes, 1000, cose.PROFILE_PUBLIC, policy.DESTRUCTIVE, []);
  const rMis = mcp.verifyToolCall(cose.PROFILE_PUBLIC, ALG, PK, mcp.signToolCall(objMis, ALG, SEED));
  assert.equal(rMis.enforced, policy.DESTRUCTIVE);
  assert.equal(rMis.annotationMapped, policy.READ_ONLY);
  assert.equal(rMis.mismatch, true);

  // under-declaration: destructive annotations but the signer declares read_only -> EffectUnderDeclared.
  const tcUnder = new mcp.ToolCall(tool, args, annDes);
  const objUnder = tcUnder.envelopeObject(signerBytes, 1000, cose.PROFILE_PUBLIC, policy.READ_ONLY, []);
  assert.throws(() => mcp.verifyToolCall(cose.PROFILE_PUBLIC, ALG, PK, mcp.signToolCall(objUnder, ALG, SEED)),
    (e) => e.kind === 'EffectUnderDeclared');

  // a baseline-only endpoint (no MCP surface) rejects an McpToolCall as UnknownKind (fail-closed): the
  // McpToolCall kind is not in the frozen baseline registry, so a baseline-only validator refuses it.
  const signedDes = mcp.signToolCall(objDes, ALG, SEED);
  assert.throws(
    () => envelope.verify(cose.PROFILE_PUBLIC, ALG, PK, mcp.composedKindValidator, signedDes) &&
      envelope.verify(cose.PROFILE_PUBLIC, ALG, PK, (ch, k) => false, signedDes),
    (e) => e.kind === 'UnknownKind');
});

// ---- the per-call approval gate: bind exact call, cover effect, single-use (isolation) ----

test('mcp authorizeCall enforces the per-call approval gate exactly-once (isolation)', () => {
  const signerBytes = new TextEncoder().encode(identity.signerId(ALG, PK));
  const tool = hexToBytes(C.tool_calls[3].tool_hex); // delete_file_destructive
  const args = hexToBytes(C.tool_calls[3].args_hex);
  const ann = new mcp.Annotations(false, true);
  const tc = new mcp.ToolCall(tool, args, ann);
  const obj = tc.envelopeObject(signerBytes, 1000, cose.PROFILE_PUBLIC, policy.DESTRUCTIVE, []);
  const r = mcp.verifyToolCall(cose.PROFILE_PUBLIC, ALG, PK, mcp.signToolCall(obj, ALG, SEED));

  const callCID = tc.callBinding().contentId();
  const APPR_SEED = new Uint8Array(32).fill(7);
  const APPR_PK = cose.mldsaKeygen('ML-DSA-65', APPR_SEED);
  const now = 2000n;
  const appr = new approval.ApprovalRecord(callCID, 'approver', policy.DESTRUCTIVE, new Uint8Array([1, 2, 3]), 5000n);
  const apprSig = approval.signApproval(appr, ALG, APPR_SEED);

  const dir = mkdtempSync(join(tmpdir(), 'naalp-mcp-'));
  const path = join(dir, 'consume.wal');
  try {
    const ledger = approval.openLedger(path);
    try {
      // a valid, matching, covering, in-window, unspent approval authorizes exactly once.
      assert.equal(mcp.authorizeCall(r, appr, ALG, APPR_PK, apprSig, 'agent', now, ledger), null);
      // replay of the same approval is rejected AlreadyConsumed (no double-spend).
      assert.throws(() => mcp.authorizeCall(r, appr, ALG, APPR_PK, apprSig, 'thief', now, ledger),
        (e) => e.kind === 'AlreadyConsumed');
      // an approval that binds a DIFFERENT call (wrong args) does not satisfy this call -> ApprovalRequired.
      const otherCID = mcp.newCallBinding(tool, hexToBytes('7b2270617468223a226f746865722e747874227d')).contentId();
      const apprOther = new approval.ApprovalRecord(otherCID, 'approver', policy.DESTRUCTIVE, new Uint8Array([9]), 5000n);
      const apprOtherSig = approval.signApproval(apprOther, ALG, APPR_SEED);
      assert.throws(() => mcp.authorizeCall(r, apprOther, ALG, APPR_PK, apprOtherSig, 'agent', now, ledger),
        (e) => e.kind === 'ApprovalRequired');
    } finally {
      ledger.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
