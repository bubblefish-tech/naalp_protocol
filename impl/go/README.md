<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/bubblefish-tech/naalp_protocol/impl/go.svg)](https://pkg.go.dev/github.com/bubblefish-tech/naalp_protocol/impl/go)

The Go reference implementation of **N-AALP** (draft-bubblefish-naalp-00) — the primary reference
against which every other SDK is byte-compared. Every N-AALP object is a deterministically-encoded
CBOR structure signed with COSE that carries, under one signature, its content identity, its signer,
a closed effect label, optional approval/audit bindings, and its causal derivation — **verifiable
offline, over any transport.**

## Install

```sh
go get github.com/bubblefish-tech/naalp_protocol/impl/go
```

## API reference

The full, per-package API reference is published automatically on **pkg.go.dev**:
<https://pkg.go.dev/github.com/bubblefish-tech/naalp_protocol/impl/go>

## Packages

| Package | What it provides |
|---|---|
| `envelope` | the full object — `Object` + `Sign` / `Verify` |
| `cose` | COSE_Sign1 + deterministic ML-DSA-65/-87 + Ed25519 |
| `cbor` | deterministic CBOR (RFC 8949 §4.2.1) + content id |
| `identity` | self-certifying signer id (multiformats) |
| `policy` | the closed effect vocabulary + authorization lattice |
| `approval` · `audit` · `delivery` · `streaming` · `carriage` | the spine record bodies + transport boundary |
| `federation` | causal verify + deterministic federation reconcile |
| `channels` | the frozen twenty-channel / 65-kind registry |

## Quickstart

See [`QUICKSTART.md`](QUICKSTART.md) for a complete build → sign → verify example, and the
repository root for the cross-language conformance harness.

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
