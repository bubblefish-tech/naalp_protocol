// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// S1 naalp-decision-record conformance for the TypeScript SDK, graded against the shared
// independent corpus vectors/decision_record/cases.json (NOT produced by this code): the closed
// outcome/ordering-basis/enforcement-disposition/term-disposition-kind vocabularies, byte-exact
// record body/head/content-id for every records{} and ordering_examples{} case (each record
// reconstructed field-by-field, never routed through the decoder), the parse round-trip, full
// semantic validation, and every named negative rejection (deny/hold-with-consume,
// terms-key-outside-field-set, unknown outcome, every ordering_malformed variant, the
// descending-key body, and the gateway-decision look-alike).
//
// Mirrors impl/go/gateway/decision_record_test.go via the byte-verified impl/python template
// (test_decision_record.py). Written test-first: a mutation forcing the outcome field to a constant
// flips 'decision-record bodies match the oracle byte-for-byte'.
//
// Run:  node --test test/decision_record.test.mjs      (from impl/typescript/)

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
    const p = join(d, 'vectors', 'decision_record', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/decision_record/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');
const strBytes = (s) => new TextEncoder().encode(s);

function drFrom(rv) {
  const governing = rv.governing_hex.map(hexToBytes);
  const d = new gateway.DecisionRecord(hexToBytes(rv.action_hex), governing, rv.outcome, gateway.correspondenceOnly());
  if (rv.consume_hex) d.consume = hexToBytes(rv.consume_hex);
  return d;
}

// Reconstruct a records{}/ordering_examples{} case with its exact ordering/terms/enforcement
// fixture, mirroring decision_record_test.go's build() switch exactly.
function build(name, rv) {
  const d = drFrom(rv);
  if (['allow_consuming', 'allow_no_consume', 'minimal', 'correspondence_only'].includes(name)) {
    d.ordering = gateway.correspondenceOnly();
  } else if (name === 'deny_two_governing') {
    d.ordering = new gateway.OrderingDisclosure(gateway.ORDERING_SINGLE_BOUNDARY, strBytes('boundary-signer-X'));
  } else if (name === 'hold_empty_governing' || name === 'external_mechanism') {
    d.ordering = new gateway.OrderingDisclosure(
      gateway.ORDERING_EXTERNAL_MECHANISM, undefined,
      strBytes('external-log:acme-transparency-v1'),
      hexToBytes('2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56'));
  } else if (name === 'single_boundary') {
    d.ordering = new gateway.OrderingDisclosure(gateway.ORDERING_SINGLE_BOUNDARY, strBytes('SIGNER_B-boundary'));
  } else if (name === 'external_mechanism_no_relation') {
    d.ordering = new gateway.OrderingDisclosure(gateway.ORDERING_EXTERNAL_MECHANISM, undefined, strBytes('external-log:acme-transparency-v1'));
  } else if (name === 'terms_valid') {
    d.ordering = gateway.correspondenceOnly();
    d.terms = new Map([
      [1, new gateway.TermDisposition(gateway.TERM_OBSERVED)],
      [4, new gateway.TermDisposition(gateway.TERM_REPORTED, strBytes('boundary:relay-partner-3'))],
    ]);
  } else if (name === 'enforcement_enforced') {
    d.ordering = gateway.correspondenceOnly();
    d.enforcement = gateway.ENFORCEMENT_ENFORCED;
  } else if (name === 'enforcement_advised') {
    d.ordering = gateway.correspondenceOnly();
    d.enforcement = gateway.ENFORCEMENT_ADVISED;
  } else {
    throw new Error(`unhandled record name ${name} -- add its ordering/terms/enforcement fixture`);
  }
  return d;
}

test('decision-record outcome vocabulary is the closed set', () => {
  for (const e of C.outcome_vocabulary) {
    assert.equal(gateway.isKnownDecision(e.code), true, e.name);
    assert.equal(gateway.decisionName(e.code), e.name);
  }
});

test('ordering-basis vocabulary is the closed set', () => {
  for (const e of C.ordering_basis_vocabulary) {
    assert.equal(gateway.isKnownOrderingBasis(e.code), true, e.name);
    assert.equal(gateway.orderingBasisName(e.code), e.name);
  }
  assert.equal(gateway.isKnownOrderingBasis(99), false);
});

test('decision-record bodies match the oracle byte-for-byte', () => {
  const allCases = { ...C.records, ...C.ordering_examples };
  assert.equal(Object.keys(allCases).length, Object.keys(C.records).length + Object.keys(C.ordering_examples).length,
    'records/ordering_examples name collision');
  for (const [name, rv] of Object.entries(allCases)) {
    const d = build(name, rv);
    assert.equal(bytesToHex(d.bytes()), rv.body_hex, name);
    assert.equal(bytesToHex(d.head()), rv.head_hex, name);
    assert.equal(bytesToHex(d.id()), rv.id_hex, name);
    // Round-trip through the decoder and re-encode: the decoded record must re-encode to the SAME
    // canonical bytes.
    const parsed = gateway.parseDecisionRecord(d.bytes());
    assert.equal(bytesToHex(parsed.bytes()), rv.body_hex, name);
    gateway.validateDecisionRecord(parsed); // every records/ordering_examples case is POSITIVE
  }
});

test('decision-record minimal matches the oracle', () => {
  const m = C.records.minimal;
  const d = new gateway.DecisionRecord(hexToBytes(m.action_hex), [], m.outcome, gateway.correspondenceOnly());
  assert.equal(bytesToHex(d.bytes()), m.body_hex);
  assert.equal(bytesToHex(d.id()), m.id_hex);
  const parsed = gateway.parseDecisionRecord(d.bytes());
  gateway.validateDecisionRecord(parsed);
});

test('decision-record negative rejections', () => {
  const neg = C.negative;

  function kindOf(bodyHex) {
    let d;
    try {
      d = gateway.parseDecisionRecord(hexToBytes(bodyHex));
    } catch (e) {
      return e.kind;
    }
    try {
      gateway.validateDecisionRecord(d);
    } catch (e) {
      return e.kind;
    }
    return '';
  }

  const cases = {
    deny_with_consume_rejected: neg.deny_with_consume_rejected,
    hold_with_consume_rejected: neg.hold_with_consume_rejected,
    terms_key_outside_field_set_rejected: neg.terms_key_outside_field_set_rejected,
    unknown_outcome_rejected: neg.unknown_outcome_rejected,
    look_alike: neg.look_alike,
  };
  for (const [name, c] of Object.entries(cases)) {
    assert.equal(kindOf(c.body_hex), c.reject, name);
  }

  for (const [name, c] of Object.entries(neg.ordering_malformed)) {
    assert.equal(kindOf(c.body_hex), c.reject, 'ordering_malformed.' + name);
  }

  // keys_out_of_order: the canonical body decodes+validates cleanly; the descending-key body is
  // rejected at the CBOR layer (NonCanonical) before parseDecisionRecord's own checks ever run.
  const koo = neg.keys_out_of_order;
  const d = gateway.parseDecisionRecord(hexToBytes(koo.canonical_body_hex));
  gateway.validateDecisionRecord(d);
  assert.throws(() => cbor.decode(hexToBytes(koo.noncanonical_body_hex)), (e) => e.kind === 'NonCanonical');
  assert.throws(() => gateway.parseDecisionRecord(hexToBytes(koo.noncanonical_body_hex)), (e) => e.kind === 'DecisionMalformed');
});

test('decision-record third-party re-serve', () => {
  const rv = C.records.allow_consuming;
  const d = build('allow_consuming', rv);
  assert.equal(bytesToHex(d.bytes()), rv.body_hex);

  const seedProducer = new Uint8Array(32).fill(0x71);
  const seedForeign = new Uint8Array(32).fill(0x72);
  const alg = cose.ALG_MLDSA65;
  const producerPk = cose.mldsaKeygen('ML-DSA-65', seedProducer);
  const foreignPk = cose.mldsaKeygen('ML-DSA-65', seedForeign);

  const obj = gateway.signDecisionRecord(d, alg, seedProducer);
  const byProducer = gateway.verifyDecisionRecord(obj, cose.PROFILE_PUBLIC, alg, producerPk);
  const byThirdParty = gateway.verifyDecisionRecord(Uint8Array.from(obj), cose.PROFILE_PUBLIC, alg, producerPk);
  assert.deepEqual(byProducer.action, byThirdParty.action);
  assert.equal(Number(byProducer.outcome), Number(byThirdParty.outcome));
  assert.equal(Number(byThirdParty.outcome), gateway.DECISION_ALLOW);
  assert.equal(bytesToHex(byThirdParty.consume), rv.consume_hex);

  assert.throws(() => gateway.verifyDecisionRecord(obj, cose.PROFILE_PUBLIC, alg, foreignPk), (e) => e.kind === 'BadSignature');
});

test('decision-record sign/verify carries terms_valid through the full path (not corpus-pinned)', () => {
  // In isolation (no cross-lang pin claimed): terms_valid signs and verifies end-to-end, carrying
  // field 6 (terms) through the full signature-verification + semantic-validation path.
  const rv = C.records.terms_valid;
  const d = build('terms_valid', rv);
  assert.equal(bytesToHex(d.bytes()), rv.body_hex);
  const seed = new Uint8Array(32).fill(0x11);
  const alg = cose.ALG_MLDSA65;
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const obj = gateway.signDecisionRecord(d, alg, seed);
  const resolved = gateway.verifyDecisionRecord(obj, cose.PROFILE_PUBLIC, alg, pk);
  assert.equal(Number(resolved.terms.get(1).kind), gateway.TERM_OBSERVED);
  assert.equal(Number(resolved.terms.get(4).kind), gateway.TERM_REPORTED);
  assert.equal(bytesToHex(resolved.terms.get(4).source), bytesToHex(strBytes('boundary:relay-partner-3')));
});
