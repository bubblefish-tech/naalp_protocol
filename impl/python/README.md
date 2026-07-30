<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — Python SDK

The Python reference implementation of **N-AALP** (draft-bubblefish-naalp-00). Every N-AALP object is
a deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.** Its bytes are byte-identical to the
Go and Rust references.

## Install

```sh
pip install naalp
```

Requires Python ≥ 3.9. Runtime dependencies: `dilithium-py` (deterministic ML-DSA, FIPS 204) and
`cryptography` (Ed25519, RFC 8032).

## Modules

| Module | What it provides |
|---|---|
| `naalp.envelope` | the full object — `Object` + `sign` / `verify` |
| `naalp.cose` | COSE_Sign1 + deterministic ML-DSA-65/-87 + Ed25519 |
| `naalp.cbor` | deterministic CBOR (RFC 8949 §4.2.1) + content id |
| `naalp.identity` | self-certifying signer id (multiformats) |
| `naalp.policy` | the closed effect vocabulary + authorization lattice |
| `naalp.channels` | the frozen twenty-channel / 65-kind registry |
| `naalp.graph` · `naalp.records` | causal graph + the spine record bodies |

## Quickstart

See [`QUICKSTART.md`](QUICKSTART.md) for a complete build → sign → verify example.

## Note on the reference crypto

`dilithium-py` is a correct but **not constant-time** ML-DSA implementation — appropriate for interop
and reference use, not for production key handling. Swap in a constant-time FIPS 204 provider and the
object bytes stay identical.

## License

Apache-2.0 — see the repository `LICENSE` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
