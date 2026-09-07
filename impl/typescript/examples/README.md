<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP TypeScript examples

Runnable examples for the N-AALP TypeScript/ESM reference SDK. Each uses the real SDK — real
ML-DSA keys, real COSE signatures, real offline verification — with no hand-rolled crypto.

## Prerequisites

- **Node.js ≥ 22** (the SDK is ESM and uses `node:test`).
- The SDK's dependencies installed. From `impl/typescript/`:

  ```sh
  npm install
  ```

## `two-agent-quickstart.mjs` — the core loop, end to end

Two agents, no shared connection or shared secret. **Agent A** generates an identity, builds and
signs an N-AALP object (a message on the Interaction surface), and hands **agent B** only the object
bytes and A's public key. Agent B verifies the object offline, reads it, and rejects a tampered copy
fail-closed.

Run it:

```sh
npm run quickstart
# or:  node examples/two-agent-quickstart.mjs
```

Expected output (the signer id and content id vary per run because the seed is random):

```
N-AALP two-agent quickstart (TypeScript SDK)

[1] Agent A generates a signing identity
  alg              ML-DSA-65 (COSE -49, FIPS 204)
  signer id        bciq...
  public key       1952 bytes

[2] Agent A builds and signs a message
  channel/kind     0x000f Interaction / 0 Elicit
  effect           0 (from the channel registry)
  signed object    ~3600 bytes (a single, self-describing COSE_Sign1)

[3] Over the wire, agent B receives only:
  object bytes     ~3600 bytes
  A's public key   1952 bytes

[4] Agent B verifies the object offline and reads it
  verified         true
  channel          0x000f Interaction
  kind             0 Elicit
  effect           0
  signer           bciq...
  content id       2030...
  message          Hello, agent B — this is agent A. | Please confirm you can verify this object offline.

[5] Agent B rejects a tampered object (fail-closed)
  tampered         rejected: BadSignature

Done: A signed, B verified and read the message, and the tampered copy was rejected.
```

The script exits `0` on success. It contains assertions (`node:assert`) that the tampered object is
rejected with `BadSignature`; if verification were bypassed, the tampered object would be accepted
and the script would exit non-zero, so a green run proves the fail-closed path really ran.

## `sign-object.mjs` — a single signed object (Governance/Approval)

Builds, signs, and verifies one full object using the lower-level `envelope` API, and shows a
tampered object being rejected.

```sh
npm run example
# or:  node examples/sign-object.mjs
```

## Where to go next

- The ergonomic surface used by the quickstart is `naalp/quick.mjs` (`Signer`, `verify`, `describe`).
- The command-line tool built on the same surface is `bin/naalp.mjs` — see [`../bin/README.md`](../bin/README.md).
- The byte-level primitives are `cbor`, `cose`, `identity`, `channels`, `envelope` — see the
  top-level [`../QUICKSTART.md`](../QUICKSTART.md).
