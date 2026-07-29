<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP TypeScript SDK

The TypeScript/ESM reference implementation of **N-AALP** (draft-bubblefish-naalp-00) — an
application-layer object protocol for autonomous agents. Every N-AALP object is a
deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.**

## What this SDK provides

- **The full object envelope** — `envelope.Object` + `envelope.sign` / `envelope.verify` (also
  re-exported at the top level as `Object` / `sign` / `verify`): build, content-id-bind,
  deterministically sign, and offline-verify a complete N-AALP object.
- **Post-quantum signatures** — deterministic ML-DSA-65/-87 (FIPS 204, rnd=0) and Ed25519
  (RFC 8032), in COSE_Sign1 (`cose`).
- **The byte-level primitives** — deterministic CBOR + content id (`cbor`), self-certifying signer
  id (`identity`), the effect lattice + authorization (`policy`), the spine record bodies — approval,
  receipt, delivery, stream, carriage, transport boundary (`records`), causal verify + federation
  reconcile (`graph`), and the twenty-channel registry (`channels`).

Every construction is **graded byte-for-byte** against the shared conformance corpus
(== Go == Rust == Python); the reference worked object is reproduced exactly
(`test/worked-example.test.mjs`).

## What this SDK does NOT provide

- A transport. N-AALP objects are transport-independent; carry them over N-PAMP, QUIC, WebSocket, or
  HTTP with your own client. The confidentiality boundary is `records.transportEmit`.
- Production key management. The `@noble/post-quantum` ML-DSA implementation is a correct,
  audited, from-scratch implementation ideal for reference/interop; use your organization's key
  custody and rotation policy for production key handling while keeping the same object bytes.

## Install

```sh
npm install naalp
```

Requires **Node.js >= 22** (ESM, `node:test`). Dependencies: `@noble/post-quantum` (deterministic
ML-DSA), `@noble/curves` (Ed25519), `@noble/hashes` (SHA-256/384). No native modules, no build step.

## Sign and verify an object

```js
import { cose, identity, envelope } from 'naalp';
import { U, B, T, M } from 'naalp/cbor';

const seed = new Uint8Array(32);                    // a real 32-byte key seed in production
const alg  = cose.ALG_MLDSA65;
const pk   = cose.mldsaKeygen('ML-DSA-65', seed);
const sid  = identity.signerId(alg, pk);

const body   = new M([[new U(1), new T('hello')]]);
const obj    = new envelope.Object({ kind: 1, channel: 4, signer: new TextEncoder().encode(sid),
                                     created: 1785000000000n, effect: 2, profile: cose.PROFILE_PUBLIC, body });
const signed = envelope.sign(obj, alg, seed);       // a self-describing signed object (Uint8Array)
const got    = envelope.verify(cose.PROFILE_PUBLIC, alg, pk, (c, k) => c === 4n && k === 1n, signed);
```

Byte fields are `Uint8Array`; integers are `BigInt` at the CBOR boundary. The SDK never accepts or
emits hex — hex framing lives in the conformance adapter.

## Run the example

```sh
npm run example        # (from impl/typescript/)
# signer   bciq...
# signed   <N> bytes, verifies=true
# tampered rejected: BadSignature
```

## Run the tests

```sh
npm test               # node --test "test/**/*.test.mjs"
```

`test/worked-example.test.mjs` reproduces the committed worked object byte-for-byte and checks the
sign / verify / tamper path; `test/conformance.test.mjs` is a standards-anchored primitives smoke
suite (FIPS 180-4 SHA-384, RFC 8949 canonical CBOR, the multiformats signer-id, the §6.1 effect
lattice).

Cross-language conformance (the authoritative grade) runs the adapter through the shared harness:

```sh
./harness/runner/naalp-conform run --testee "node harness/adapters/typescript/adapter.mjs"
# RESULT: PASS (239 graded, 0 unimplemented/skipped)
```

The adapter implements every op including the full crypto leg (`mldsa.keygen`, `ed25519.sign`,
`cose.sign1`, `cose.verify1`) — nothing is skipped.

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
