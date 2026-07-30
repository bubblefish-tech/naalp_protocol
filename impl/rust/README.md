<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — Rust SDK

[![docs.rs](https://img.shields.io/docsrs/naalp)](https://docs.rs/naalp)

The Rust reference implementation of **N-AALP** (draft-bubblefish-naalp-00) — with Go, one of the two
primary references; the two produce **byte-identical** CBOR, signed input, signatures, and digests
for identical logical input. Every N-AALP object is a deterministically-encoded CBOR structure
signed with COSE that carries, under one signature, its content identity, its signer, a closed
effect label, optional approval/audit bindings, and its causal derivation — **verifiable offline,
over any transport.**

## Install

```sh
cargo add naalp
```

## API reference

Published on **docs.rs**: <https://docs.rs/naalp>

## Modules

| Module | What it provides |
|---|---|
| `envelope` | the full object — `Object` + `sign` / `verify` |
| `cose` | COSE_Sign1 + deterministic ML-DSA-65/-87 (FIPS 204) + Ed25519 |
| `cbor` | deterministic CBOR (RFC 8949 §4.2.1) + content id |
| `identity` | self-certifying signer id (multiformats) |
| `policy` | the closed effect vocabulary + authorization lattice |
| `approval` · `audit` · `delivery` · `streaming` · `carriage` | the spine record bodies + transport boundary |
| `federation` | causal verify + deterministic federation reconcile |
| `channels` | the frozen twenty-channel / 65-kind registry |

## Quickstart

See [`QUICKSTART.md`](QUICKSTART.md) for a complete build → sign → verify example, and run the
offline-verify example directly:

```sh
cargo run --example naalp_verify
```

## License

Apache-2.0 — see the repository `LICENSE` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
