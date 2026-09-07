// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C20 governed negotiation, advisory risk labels, and trust-reference conformance for the TypeScript
// SDK, graded against the shared independent corpus vectors/negotiation/cases.json (NOT produced by
// this code): the closed role/profile vocabularies, the byte-exact message/labeled-object/risk-
// label/trust-ref bodies + heads + content-ids, the accept-descends-from-offer causal-DAG walk, the
// R-2.5 critical-extension rule, the trust-ref content-id recompute, and the fail-closed edge cases
// (non-canonical body -> NonCanonical/NegMalformed, absent mandatory field -> NegMalformed, empty vs
// populated causes/labels distinct by content-id, the minimal bodies, and the look-alike cross-parse).
//
// The sign/verify round-trip (real deterministic ML-DSA-65 COSE_Sign1) is demonstrated in isolation:
// the corpus carries no signed COSE vector, seed, or public key, so it is NOT corpus-graded (stated
// honestly). What the corpus grades is the object bytes and the causal/advisory/trust invariants.
//
// Written test-first; the negotiation module is absent until ported, so this fails RED on import
// (ERR_MODULE_NOT_FOUND) until impl/typescript/naalp/negotiation.mjs lands, and a mutation forcing the
// encoded profile field to a constant flips 'negotiation message bodies match the oracle byte-for-byte'.
//
// Run:  node --test test/negotiation.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as policy from '../naalp/policy.mjs';
import * as negotiation from '../naalp/negotiation.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'negotiation', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/negotiation/cases.json not found');
}

const C = vectors();
const N = C.negotiation;
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');
const mkMsg = (c) => new negotiation.Message(hexToBytes(N.negotiation_hex), c.role, c.profile, c.causes_hex.map(hexToBytes));

test('negotiation role and profile vocabularies are the closed sets', () => {
  for (const [name, v] of Object.entries(N.roles)) {
    assert.equal(negotiation.knownRole(v), true, name);
    assert.equal(negotiation.roleName(v), name);
  }
  for (const [name, v] of Object.entries(N.profiles)) {
    assert.equal(negotiation.isRegisteredProfile(v), true, name);
    assert.equal(negotiation.profileName(v), name);
  }
  assert.equal(negotiation.isRegisteredProfile(N.unknown_profile), false);
  assert.equal(negotiation.profileName(N.unknown_profile), 'unknown');
  assert.equal(negotiation.knownRole(N.unknown_role_message.role), false);
  assert.equal(negotiation.roleName(N.unknown_role_message.role), 'unknown');
});

test('negotiation message bodies match the oracle byte-for-byte', () => {
  // THIS is the mutation-target assertion: each message encodes {1:neg,2:role,3:profile,4:causes}
  // distinctly; forcing the profile field to a constant flips at least the counter/accept/offer2 cases.
  for (const name of ['offer', 'counter', 'accept', 'offer2', 'accept_not_descended',
    'unknown_profile_offer', 'unknown_role_message']) {
    const c = N[name];
    const m = mkMsg(c);
    assert.equal(bytesToHex(m.bytes()), c.body_hex, `${name} body`);
    assert.equal(bytesToHex(m.head()), c.head_hex, `${name} head`);
    assert.equal(bytesToHex(m.id()), c.id_hex, `${name} id`);
  }
});

test('negotiation parseMessage round-trips the oracle bodies', () => {
  for (const name of ['offer', 'counter', 'accept', 'offer2']) {
    const c = N[name];
    const m = negotiation.parseMessage(hexToBytes(c.body_hex));
    assert.equal(Number(m.role), c.role, name);
    assert.equal(Number(m.profile), c.profile, name);
    assert.equal(bytesToHex(m.id()), c.id_hex, name);
  }
});

test('negotiation accept descends from its offer via the causes DAG', () => {
  const offer = mkMsg(N.offer);
  const counter = mkMsg(N.counter);
  const accept = mkMsg(N.accept);
  const offer2 = mkMsg(N.offer2);
  const acceptBad = mkMsg(N.accept_not_descended);
  // the causal chain the corpus asserts: counter names offer, accept names counter.
  assert.equal(bytesToHex(offer.id()), N.offer.id_hex);
  assert.equal(bytesToHex(counter.id()), N.counter.id_hex);
  assert.equal(bytesToHex(accept.id()), N.accept.id_hex);
  const byId = negotiation.indexById([offer, counter, accept, offer2, acceptBad]);
  assert.equal(negotiation.descends(accept, offer, byId), N.descends.accept_from_offer);
  assert.equal(negotiation.descends(acceptBad, offer, byId), N.descends.accept_bad_from_offer);
  // verifyAccept returns the AGREED profile, and rejects a non-descended accept fail-closed.
  assert.equal(Number(negotiation.verifyAccept(accept, offer, byId)), N.agreed_profile);
  assert.throws(() => negotiation.verifyAccept(acceptBad, offer, byId), (e) => e.kind === 'NotDescended');
});

test('negotiation risk-label vocabulary and label bodies match the oracle', () => {
  for (const v of C.risk.vocabulary) {
    assert.equal(negotiation.isRegisteredRisk(v.code), true, v.name);
    const [cls, ok] = negotiation.riskClassOf(v.code);
    assert.equal(ok, true, v.name);
    assert.equal(negotiation.riskClassName(cls), v.class, v.name);
  }
  assert.equal(negotiation.EXTENSIBLE_RANGE_START, C.risk.extensible_range_start);
  for (const [name, s] of Object.entries(C.risk.sample_labels)) {
    const l = new negotiation.RiskLabel(s.code, s.critical);
    assert.equal(bytesToHex(l.bytes()), s.body_hex, name);
  }
});

test('negotiation labeled-object bodies match the oracle and labels never change the effect class', () => {
  const carried = C.risk.carried_on_labeled_objects.map((l) => new negotiation.RiskLabel(l.code, l.critical));
  for (const lo of C.risk.labeled_objects) {
    const withL = new negotiation.LabeledObject(lo.effect, carried);
    assert.equal(bytesToHex(withL.bytes()), lo.with_labels.body_hex, `effect ${lo.effect} with labels`);
    assert.equal(bytesToHex(withL.head()), lo.with_labels.head_hex, `effect ${lo.effect} with labels head`);
    assert.equal(bytesToHex(withL.id()), lo.with_labels.id_hex, `effect ${lo.effect} with labels id`);
    const without = new negotiation.LabeledObject(lo.effect, []);
    assert.equal(bytesToHex(without.bytes()), lo.without_labels.body_hex, `effect ${lo.effect} without labels`);
    // LOAD-BEARING C20 invariant: carrying a risk label NEVER changes the C5 effect class.
    assert.equal(withL.effectClass(), lo.effect_class, `effect ${lo.effect} class unchanged by labels`);
    assert.equal(without.effectClass(), lo.effect_class);
    assert.equal(withL.effectClass(), policy.normalizeEffect(lo.effect));
  }
});

test('negotiation validateLabels applies the R-2.5 critical-extension rule', () => {
  const rs = C.risk.validate.recognized_set;
  const recognized = negotiation.validateLabels(rs.carried.map((l) => new negotiation.RiskLabel(l.code, l.critical)));
  assert.deepEqual(recognized.map((l) => Number(l.code)), rs.recognized_codes);
  assert.equal(rs.error, null);
  const uc = C.risk.validate.unknown_critical_rejected;
  assert.throws(
    () => negotiation.validateLabels(uc.carried.map((l) => new negotiation.RiskLabel(l.code, l.critical))),
    (e) => e.kind === uc.error, // UnknownCriticalRisk
  );
});

test('negotiation trust-ref bodies match the oracle and bind by content-id recompute', () => {
  const t = C.trust;
  const refA = new negotiation.TrustRef(hexToBytes(t.registry_a_hex), hexToBytes(t.reference_hex), hexToBytes(t.subject_hex));
  assert.equal(bytesToHex(refA.bytes()), t.ref_a.body_hex);
  assert.equal(bytesToHex(refA.head()), t.ref_a.head_hex);
  assert.equal(bytesToHex(refA.id()), t.ref_a.id_hex);
  const refB = new negotiation.TrustRef(hexToBytes(t.registry_b_hex), hexToBytes(t.reference_hex), hexToBytes(t.subject_hex));
  assert.equal(bytesToHex(refB.bytes()), t.ref_b.body_hex);
  assert.equal(bytesToHex(refB.id()), t.ref_b.id_hex);
  // the carried reference recomputes over the EXTERNAL record (the independent authority) --
  assert.equal(bytesToHex(negotiation.contentId(hexToBytes(t.external_record_hex))), t.reference_hex);
  assert.equal(refA.bindsRecord(hexToBytes(t.external_record_hex)), true);
  // a tampered record yields a different content-id -> the reference no longer binds.
  assert.equal(bytesToHex(negotiation.contentId(hexToBytes(t.tampered_record_hex))), t.tampered_reference_hex);
  assert.equal(refA.bindsRecord(hexToBytes(t.tampered_record_hex)), false);
  // two registries reference the same record and bind symmetrically -- the wire weighs neither.
  assert.equal(refB.bindsRecord(hexToBytes(t.external_record_hex)), true);
});

test('negotiation fail-closed edge cases', () => {
  const ec = C.edge_cases;
  // a descending-key body is rejected NonCanonical by the decoder and NegMalformed by parseMessage.
  assert.throws(() => cbor.decode(hexToBytes(ec.keys_out_of_order.noncanonical_offer_body_hex)), (e) => e.kind === ec.keys_out_of_order.reject);
  assert.throws(() => negotiation.parseMessage(hexToBytes(ec.keys_out_of_order.noncanonical_offer_body_hex)), (e) => e.kind === 'NegMalformed');
  assert.equal(Number(negotiation.parseMessage(hexToBytes(ec.keys_out_of_order.canonical_offer_body_hex)).role), 0);
  // empty vs absent -- causes: an empty causes[] is distinct by content-id from a populated one; an
  // absent causes field is rejected (mandatory).
  const ca = ec.empty_vs_absent.causes;
  assert.equal(bytesToHex(negotiation.parseMessage(hexToBytes(ca.empty_present.body_hex)).id()), ca.empty_present.id_hex);
  assert.equal(bytesToHex(negotiation.parseMessage(hexToBytes(ca.one_cause.body_hex)).id()), ca.one_cause.id_hex);
  assert.throws(() => negotiation.parseMessage(hexToBytes(ca.absent_field.body_hex)), (e) => e.kind === ca.absent_field.reject);
  // empty vs absent -- labels: same, for labeled objects.
  const la = ec.empty_vs_absent.labels;
  assert.equal(bytesToHex(negotiation.parseLabeledObject(hexToBytes(la.empty_present.body_hex)).id()), la.empty_present.id_hex);
  assert.equal(bytesToHex(negotiation.parseLabeledObject(hexToBytes(la.one_label.body_hex)).id()), la.one_label.id_hex);
  assert.throws(() => negotiation.parseLabeledObject(hexToBytes(la.absent_field.body_hex)), (e) => e.kind === la.absent_field.reject);
  // minimal bodies (smallest legal offer / labeled-object / trust-ref).
  const min = ec.minimal;
  const mo = new negotiation.Message(hexToBytes(min.offer.negotiation_hex), min.offer.role, min.offer.profile, []);
  assert.equal(bytesToHex(mo.bytes()), min.offer.body_hex);
  assert.equal(bytesToHex(mo.id()), min.offer.id_hex);
  const mlo = new negotiation.LabeledObject(min.labeled_object.effect, []);
  assert.equal(bytesToHex(mlo.bytes()), min.labeled_object.body_hex);
  assert.equal(bytesToHex(mlo.id()), min.labeled_object.id_hex);
  const mtr = new negotiation.TrustRef(new Uint8Array(0), new Uint8Array(0), new Uint8Array(0));
  assert.equal(bytesToHex(mtr.bytes()), min.trust_ref.body_hex);
  assert.equal(bytesToHex(mtr.id()), min.trust_ref.id_hex);
  // look-alike: a trust-ref fed to parseMessage and a message fed to parseTrustRef are both rejected.
  assert.throws(() => negotiation.parseMessage(hexToBytes(ec.look_alike.trust_ref_as_message.body_hex)), (e) => e.kind === ec.look_alike.trust_ref_as_message.reject);
  assert.throws(() => negotiation.parseTrustRef(hexToBytes(ec.look_alike.message_as_trust_ref.body_hex)), (e) => e.kind === ec.look_alike.message_as_trust_ref.reject);
});

test('negotiation sign/verify in isolation (real ML-DSA-65, not corpus-graded)', () => {
  const seed = new Uint8Array(32);
  const alg = cose.ALG_MLDSA65;
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  // a signed offer verifies and reconstructs to its pre-registered profile.
  const offer = mkMsg(N.offer);
  const obj = negotiation.signMessage(offer, alg, seed);
  const m = negotiation.verifyMessage(obj, cose.PROFILE_PUBLIC, alg, pk);
  assert.equal(Number(m.profile), N.offer.profile);
  // a tampered signature -> BadSignature (fail-closed).
  const bad = Uint8Array.from(obj); bad[bad.length - 1] ^= 1;
  assert.throws(() => negotiation.verifyMessage(bad, cose.PROFILE_PUBLIC, alg, pk), (e) => e.kind === 'BadSignature');
  // an unknown profile is rejected on verify (closed-set enforcement).
  const up = new negotiation.Message(hexToBytes(N.negotiation_hex), 0, N.unknown_profile, []);
  const upObj = negotiation.signMessage(up, alg, seed);
  assert.throws(() => negotiation.verifyMessage(upObj, cose.PROFILE_PUBLIC, alg, pk), (e) => e.kind === 'UnknownProfile');
  // a trust-ref verifies end-to-end against the external record, and mismatches a tampered one.
  const t = C.trust;
  const refA = new negotiation.TrustRef(hexToBytes(t.registry_a_hex), hexToBytes(t.reference_hex), hexToBytes(t.subject_hex));
  const tObj = negotiation.signTrustRef(refA, alg, seed);
  const resolved = negotiation.verifyTrustRef(tObj, cose.PROFILE_PUBLIC, alg, pk, hexToBytes(t.external_record_hex));
  assert.equal(bytesToHex(resolved.reference), t.reference_hex);
  assert.throws(() => negotiation.verifyTrustRef(tObj, cose.PROFILE_PUBLIC, alg, pk, hexToBytes(t.tampered_record_hex)), (e) => e.kind === 'ReferenceMismatch');
});
