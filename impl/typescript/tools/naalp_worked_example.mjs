// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Emit the worked-example N-AALP object as one line of lowercase hex: the whole
// COSE_Sign1 the reference produces from the fixed 0x2a seed for the Governance
// Approval object (channel 0x0004, kind 1) -- the same construction the Go
// cmd/naalp-worked-example emitter and test/worked-example.test.mjs build.
// scripts/record_cross_port_objects.py runs this and records the bytes; the
// cross-port object gate compares them to vectors/worked/example.json. Prints ONLY
// the hex so the recorder reads it unambiguously.
//
//   node tools/naalp_worked_example.mjs        (from impl/typescript/)

import { cose, identity, envelope } from '../naalp/index.mjs';
import { U, B, T, M } from '../naalp/cbor.mjs';

const SEED = new Uint8Array(32).fill(0x2a);
const ALG = cose.ALG_MLDSA65;
const ARGS_ID_HEX =
  '20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff';
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

const pk = cose.mldsaKeygen('ML-DSA-65', SEED);
const signerId = identity.signerId(ALG, pk);
const body = new M([
  [new U(1), new B(hexToBytes(ARGS_ID_HEX))],
  [new U(2), new T(signerId)],
  [new U(3), new U(2)],
  [new U(4), new B(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8))],
  [new U(5), new U(1785000000000n)],
]);
const obj = new envelope.Object({
  kind: 1,
  channel: 4,
  tier: 0,
  signer: new TextEncoder().encode(signerId),
  created: 1785000000000n,
  effect: 2,
  profile: cose.PROFILE_PUBLIC,
  body,
});
process.stdout.write(bytesToHex(envelope.sign(obj, ALG, SEED)) + '\n');
