// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// examples/sign-object.mjs — build, sign, and verify a full N-AALP object.
//
// Run:  node examples/sign-object.mjs
// Expected output:
//     signer   bciq...
//     signed   <N> bytes, verifies=true
//     tampered rejected: BadSignature

import { cose, identity, envelope } from '../naalp/index.mjs';
import { U, B, T, M } from '../naalp/cbor.mjs';

function main() {
  // a deterministic 32-byte key seed (use a real random seed in production)
  const seed = new Uint8Array(32).fill(0x2a);
  const alg = cose.ALG_MLDSA65;
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const signerId = identity.signerId(alg, pk);
  console.log('signer  ', signerId);

  // a Governance Approval object (channel 0x0004, kind 1) on the Public profile
  const argsId = new envelope.Object({
    kind: 0, channel: 0, signer: new Uint8Array(0), created: 0, effect: 0,
    body: new M([[new U(1), new T('the-args')]]),
  }).contentId();
  const approval = new M([
    [new U(1), new B(argsId)],
    [new U(2), new T(signerId)],
    [new U(3), new U(2)],                                  // granted effect: non_idempotent_write
    [new U(4), new B(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8))], // nonce
    [new U(5), new U(1785000000000n)],                    // not_after (epoch ms)
  ]);
  const obj = new envelope.Object({
    kind: 1, channel: 4, tier: 0, signer: new TextEncoder().encode(signerId),
    created: 1785000000000n, effect: 2, profile: cose.PROFILE_PUBLIC, body: approval,
  });

  const signed = envelope.sign(obj, alg, seed);
  const got = envelope.verify(cose.PROFILE_PUBLIC, alg, pk, (c, k) => c === 4n && k === 1n, signed);
  console.log('signed  ', signed.length, 'bytes, verifies=' + (got.kind === 1n && got.channel === 4n));

  const tampered = Uint8Array.from(signed);
  tampered[tampered.length - 1] ^= 1;
  try {
    envelope.verify(cose.PROFILE_PUBLIC, alg, pk, () => true, tampered);
    console.log('tampered NOT rejected (bug)');
  } catch (e) {
    console.log('tampered rejected:', e.kind || e.constructor.name);
  }
}

main();
