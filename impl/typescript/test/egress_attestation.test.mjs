// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// E6.3 naalp-egress-attestation conformance for the TypeScript SDK, graded against the shared
// independent corpus vectors/egress_attestation/cases.json (NOT produced by this code): the closed
// binding vocabulary, byte-exact attestation body/head/content-id (including the oversized 2^64-1
// counter and field-6 ordering-disclosure variants), the content_free commitment open/verify pair,
// the third-party re-serve property (and the vendor-only mutation it must survive), and every named
// edge case (descending-key body, empty-vs-absent audience, minimal, gateway-decision look-alike,
// missing mandatory `at`, ordering-malformed variants).
//
// Mirrors impl/go/gateway/egress_attestation_test.go via the byte-verified impl/python template
// (test_egress_attestation.py). Written test-first: a mutation forcing openEgressCommitment to
// always return true flips 'open-egress-commitment open/verify pair'.
//
// Run:  node --test test/egress_attestation.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import { U, B, M } from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as gateway from '../naalp/gateway.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'egress_attestation', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/egress_attestation/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

function attFrom(av) {
  return new gateway.EgressAttestation(av.binding, hexToBytes(av.digest_hex), av.effect, hexToBytes(av.audience_hex), BigInt(av.at_str));
}

test('byte parity against the oracle + binding vocabulary', () => {
  for (const [name, av] of Object.entries({ content_bound: C.attestations.content_bound, content_free: C.attestations.content_free })) {
    const a = attFrom(av);
    assert.equal(bytesToHex(a.bytes()), av.body_hex, name);
    assert.equal(bytesToHex(a.head()), av.head_hex, name);
    assert.equal(bytesToHex(a.id()), av.id_hex, name);
  }
  for (const e of C.binding_vocabulary) {
    assert.equal(gateway.isKnownBinding(e.code), true, e.name);
    assert.equal(gateway.bindingName(e.code), e.name);
  }
  assert.equal(gateway.isKnownBinding(C.unknown_binding), false);
});

test('oversized counter: at = 2^64-1 survives byte-exact (no float64 rounding)', () => {
  const e = C.edge_cases.oversized_counter;
  assert.equal(e.at_str, '18446744073709551615');
  const a = attFrom(e);
  assert.equal(a.at, (1n << 64n) - 1n);
  assert.equal(bytesToHex(a.bytes()), e.body_hex);
  const parsed = gateway.parseEgressAttestation(a.bytes());
  assert.equal(parsed.at, a.at);
});

test('third-party re-serve', () => {
  const seedGw = new Uint8Array(32).fill(0x61);
  const seedForeign = new Uint8Array(32).fill(0x62);
  const alg = cose.ALG_MLDSA65;
  const gwPk = cose.mldsaKeygen('ML-DSA-65', seedGw);
  const foreignPk = cose.mldsaKeygen('ML-DSA-65', seedForeign);

  const a = attFrom(C.attestations.content_bound);
  const obj = gateway.signEgressAttestation(a, alg, seedGw);

  const byGateway = gateway.verifyEgressAttestation(obj, cose.PROFILE_PUBLIC, alg, gwPk);
  const byThirdParty = gateway.verifyEgressAttestation(Uint8Array.from(obj), cose.PROFILE_PUBLIC, alg, gwPk);
  assert.equal(Number(byGateway.binding), Number(byThirdParty.binding));
  assert.deepEqual(byGateway.digest, byThirdParty.digest);
  assert.equal(Number(byGateway.effect), Number(byThirdParty.effect));
  assert.deepEqual(byGateway.audience, byThirdParty.audience);
  assert.equal(byGateway.at, byThirdParty.at);
  assert.equal(Number(byThirdParty.binding), gateway.BINDING_CONTENT_BOUND);
  assert.equal(bytesToHex(byThirdParty.digest), C.object_cid_hex);

  assert.throws(() => gateway.verifyEgressAttestation(obj, cose.PROFILE_PUBLIC, alg, foreignPk), (e) => e.kind === 'BadSignature');

  const bad = new gateway.EgressAttestation(C.unknown_binding, hexToBytes(C.object_cid_hex), 0, hexToBytes(C.audience_hex), 0n);
  const badObj = gateway.signEgressAttestation(bad, alg, seedGw);
  assert.throws(() => gateway.verifyEgressAttestation(badObj, cose.PROFILE_PUBLIC, alg, gwPk), (e) => e.kind === 'UnknownEgressBinding');
});

test('vendor-only mutation: the honest verifier takes no serving-party identity', () => {
  // Mirrors TestEgressVendorOnlyMutation: the honest verifyEgressAttestation takes NO serving-party
  // identity, so a mutant "vendor-only" verifier that additionally requires
  // servingParty === gatewayId wrongly rejects a third party re-serving the identical bytes.
  const seedGw = new Uint8Array(32).fill(0x61);
  const alg = cose.ALG_MLDSA65;
  const gwPk = cose.mldsaKeygen('ML-DSA-65', seedGw);
  const gatewayId = new TextEncoder().encode('gateway-id-0x61');
  const thirdParty = new TextEncoder().encode('did:example:mirror-cache');

  const a = attFrom(C.attestations.content_free);
  const obj = gateway.signEgressAttestation(a, alg, seedGw);
  gateway.verifyEgressAttestation(obj, cose.PROFILE_PUBLIC, alg, gwPk); // honest: no throw

  function mutantVerify(obj_, gwPk_, gatewayId_, servingParty) {
    gateway.verifyEgressAttestation(obj_, cose.PROFILE_PUBLIC, alg, gwPk_);
    if (bytesToHex(servingParty) !== bytesToHex(gatewayId_)) {
      throw new gateway.GatewayError('EgMalformed', 'stands in for a not-served-by-vendor rejection');
    }
  }

  mutantVerify(obj, gwPk, gatewayId, gatewayId); // accepts the vendor serving it
  assert.throws(() => mutantVerify(obj, gwPk, gatewayId, thirdParty)); // wrongly rejects the third party
});

test('open-egress-commitment open/verify pair', () => {
  const co = C.commitment_open;
  const a = attFrom(C.attestations.content_free);
  assert.equal(bytesToHex(a.digest), co.commitment_hex);

  const objectCid = hexToBytes(co.object_cid_hex);
  const wrongObjectCid = hexToBytes(co.wrong_object_cid_hex);
  const salt = hexToBytes(co.salt_hex);
  const wrongSalt = hexToBytes(co.wrong_salt_hex);

  assert.equal(bytesToHex(gateway.egressCommit(objectCid, salt)), co.commitment_hex);
  assert.equal(gateway.openEgressCommitment(a, objectCid, salt), true);
  assert.equal(gateway.openEgressCommitment(a, objectCid, wrongSalt), false);
  assert.equal(gateway.openEgressCommitment(a, wrongObjectCid, salt), false);
  assert.equal(gateway.openEgressCommitment(a, wrongObjectCid, wrongSalt), false);

  const bound = attFrom(C.attestations.content_bound);
  assert.equal(gateway.openEgressCommitment(bound, objectCid, salt), false);
});

test('keys-out-of-order body rejected fail-closed', () => {
  const e = C.edge_cases.keys_out_of_order;
  const a = new gateway.EgressAttestation(e.binding, hexToBytes(e.digest_hex), e.effect, hexToBytes(e.audience_hex), BigInt(e.at_str));
  assert.equal(bytesToHex(a.bytes()), e.canonical_body_hex);
  const canon = hexToBytes(e.canonical_body_hex);
  const noncanon = hexToBytes(e.noncanonical_body_hex);
  cbor.decode(canon); // should decode
  gateway.parseEgressAttestation(canon); // should parse
  assert.throws(() => cbor.decode(noncanon), (err) => err.kind === 'NonCanonical');
  assert.throws(() => gateway.parseEgressAttestation(noncanon), (err) => err.kind === 'EgMalformed');
});

test('empty vs absent audience', () => {
  const ea = C.edge_cases.empty_vs_absent;
  const objectCid = C.object_cid_hex;
  const empty = new gateway.EgressAttestation(gateway.BINDING_CONTENT_BOUND, hexToBytes(objectCid), 1, new Uint8Array(0), 1735689600000n);
  const populated = new gateway.EgressAttestation(
    gateway.BINDING_CONTENT_BOUND, hexToBytes(objectCid), 1, hexToBytes(ea.populated_audience.audience_hex), 1735689600000n);
  assert.equal(bytesToHex(empty.bytes()), ea.empty_audience.body_hex);
  assert.equal(bytesToHex(populated.bytes()), ea.populated_audience.body_hex);
  assert.notDeepEqual(empty.id(), populated.id());
  assert.equal(bytesToHex(empty.id()), ea.empty_audience.id_hex);
  gateway.parseEgressAttestation(empty.bytes());
  gateway.parseEgressAttestation(populated.bytes());
  assert.throws(() => gateway.parseEgressAttestation(hexToBytes(ea.absent_field.body_hex)), (e) => e.kind === 'EgMalformed');
});

test('minimal attestation matches the oracle', () => {
  const m = C.edge_cases.minimal;
  const a = new gateway.EgressAttestation(m.binding, hexToBytes(m.digest_hex), m.effect, hexToBytes(m.audience_hex), BigInt(m.at_str));
  assert.equal(bytesToHex(a.bytes()), m.body_hex);
  assert.equal(bytesToHex(a.id()), m.id_hex);
  gateway.parseEgressAttestation(a.bytes());
  const seed = new Uint8Array(32).fill(0x63);
  const alg = cose.ALG_MLDSA65;
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const obj = gateway.signEgressAttestation(a, alg, seed);
  gateway.verifyEgressAttestation(obj, cose.PROFILE_PUBLIC, alg, pk); // no throw
});

test('gateway-decision look-alike rejected', () => {
  const la = C.edge_cases.look_alike;
  assert.throws(() => gateway.parseEgressAttestation(hexToBytes(la.body_hex)), (e) => e.kind === la.reject);
});

test('field-6 ordering-disclosure byte parity', () => {
  for (const e of C.ordering_basis_vocabulary) {
    assert.equal(gateway.isKnownOrderingBasis(e.code), true, e.name);
    assert.equal(gateway.orderingBasisName(e.code), e.name);
  }

  function build(name, av) {
    const a = attFrom(av);
    if (name === 'correspondence_only') {
      a.ordering = gateway.correspondenceOnly();
    } else if (name === 'single_boundary') {
      a.ordering = new gateway.OrderingDisclosure(gateway.ORDERING_SINGLE_BOUNDARY, new TextEncoder().encode('boundary-signer-X'));
    } else if (name === 'external_mechanism') {
      a.ordering = new gateway.OrderingDisclosure(
        gateway.ORDERING_EXTERNAL_MECHANISM, undefined,
        new TextEncoder().encode('external-log:acme-transparency-v1'),
        hexToBytes('2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56'));
    } else {
      throw new Error(`unhandled attestations_with_ordering name ${name}`);
    }
    return a;
  }

  for (const [name, av] of Object.entries(C.attestations_with_ordering)) {
    const a = build(name, av);
    assert.equal(bytesToHex(a.bytes()), av.body_hex, name);
    assert.equal(bytesToHex(a.head()), av.head_hex, name);
    assert.equal(bytesToHex(a.id()), av.id_hex, name);
    const parsed = gateway.parseEgressAttestation(a.bytes());
    assert.notEqual(parsed.ordering, null, name);
    assert.equal(bytesToHex(parsed.bytes()), av.body_hex, name);
    gateway.validateEgressAttestation(parsed); // no throw
  }

  const plain = gateway.parseEgressAttestation(attFrom(C.attestations.content_bound).bytes());
  assert.equal(plain.ordering, null);
});

test('ordering negative rejections', () => {
  function kindOf(bodyHex) {
    let a;
    try {
      a = gateway.parseEgressAttestation(hexToBytes(bodyHex));
    } catch (e) {
      return e.kind;
    }
    try {
      gateway.validateEgressAttestation(a);
    } catch (e) {
      return e.kind;
    }
    return '';
  }

  const sbwm = C.negative_ordering.ordering_malformed_single_boundary_with_mechanism;
  assert.equal(kindOf(sbwm.body_hex), sbwm.reject);
  const uob = C.negative_ordering.unknown_ordering_basis;
  assert.equal(kindOf(uob.body_hex), uob.reject);
});

test('missing mandatory field 5 (at) rejected', () => {
  // Isolates the field-5 (`at`) mandatory check: fields 1-4 correctly typed, field 5 absent.
  const body = cbor.encode(new M([
    [new U(1), new U(gateway.BINDING_CONTENT_BOUND)],
    [new U(2), new B(Uint8Array.of(0x20, 0x30))],
    [new U(3), new U(1)],
    [new U(4), new B(new Uint8Array(0))],
  ]));
  assert.throws(() => gateway.parseEgressAttestation(body), (e) => e.kind === 'EgMalformed');
});
