<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — Swift SDK

The Swift reference implementation of **N-AALP** (draft-bubblefish-naalp-00). Every N-AALP object is a
deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.**

## Install

Swift Package Manager (`Naalp` product), from a local checkout of this package directory:

```swift
// Package.swift
dependencies: [
  .package(path: "path/to/naalp_protocol/impl/swift"),
],
targets: [
  .target(name: "YourApp", dependencies: [.product(name: "Naalp", package: "swift")]),
]
```

Requires Swift ≥ 6. The classical leg (Ed25519) is Apple `swift-crypto`.

> **Pure-only:** no Swift ecosystem library offers deterministic ML-DSA seed-keygen yet, so this SDK
> implements every non-crypto operation plus Ed25519 and honestly **skip-tracks** the ML-DSA leg
> (never a false pass). It grades 235 conformance cases (4 ML-DSA cases skipped).

## Module

`Naalp` — `Envelope` (`Object` + `sign` / `verify`), `Cose`, `Cbor`, `Identity`, `Policy`,
`Channels`, `Records`, `Graph`.

## Quickstart

See [`QUICKSTART.md`](QUICKSTART.md).

## License

Apache-2.0 — see the repository `LICENSE` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
