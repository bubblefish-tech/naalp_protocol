<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — Rust SDK

[![docs.rs](https://img.shields.io/docsrs/naalp)](https://docs.rs/naalp)

The Rust reference implementation of **N-AALP** (draft-bubblefish-naalp-01) — with Go, one of the two
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
| `easy` | ergonomic sign/verify convenience layer — `Signer` + `verify` (delegates to the modules below) |
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

## Developer experience

Three ways in, from lowest to highest ceremony:

- **Ergonomic layer** — `naalp::easy`: `Signer::from_seed(seed).sign(channel, kind, body)` to
  produce a signed envelope, and `easy::verify(&verifier, &bytes)` to check one offline. It
  adds no crypto and no second encoding — it composes `cose` / `identity` / `envelope` /
  `channels`. See the rustdoc on each item.
- **Two-agent quickstart** — the core loop end to end (identity → sign → offline verify →
  fail-closed tamper rejection):

  ```sh
  cargo run --example naalp_quickstart
  ```

  Details and expected output: [`examples/README.md`](examples/README.md).
- **CLI** — `naalp sign` / `naalp verify` for shell round-trips (exit `0`/non-zero,
  fail-closed):

  ```sh
  cargo run --bin naalp -- sign   --seed <hex32> --channel 15 --kind 1 --message "hi" --pubkey-out pk.hex --out env.hex
  cargo run --bin naalp -- verify --pubkey-file pk.hex --envelope-file env.hex
  ```

  Full usage: [`CLI.md`](CLI.md).

## License

Apache-2.0 — see the repository `LICENSE` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
