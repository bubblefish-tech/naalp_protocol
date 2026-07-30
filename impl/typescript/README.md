<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — TypeScript / JavaScript SDK

The TypeScript/ESM reference implementation of **N-AALP** (draft-bubblefish-naalp-00). Every N-AALP
object is a deterministically-encoded CBOR structure signed with COSE that carries, under one
signature, its content identity, its signer, a closed effect label, optional approval/audit
bindings, and its causal derivation — **verifiable offline, over any transport.**

The package ships type declarations (`naalp/*.d.mts`), so it is fully typed for TypeScript
consumers as well as usable from plain JavaScript (ESM).

## Install

```sh
npm install naalp
```

## Use

```ts
import { Object as NaalpObject, sign, verify } from "naalp";
import { cose, cbor, identity } from "naalp";
```

- `Object` / `sign` / `verify` — the ergonomic object envelope surface.
- `cbor`, `cose`, `identity`, `policy`, `records`, `graph`, `channels`, `envelope` — the byte-level
  primitives.

See [`QUICKSTART.md`](QUICKSTART.md) for a complete build → sign → verify example.

## API reference

Generate the full API reference with TypeDoc (config in `typedoc.json`):

```sh
npm run docs      # writes doc/api
```

## Requirements

Node.js ≥ 22. Crypto is `@noble/curves` (Ed25519), `@noble/hashes`, and `@noble/post-quantum`
(deterministic ML-DSA).

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
