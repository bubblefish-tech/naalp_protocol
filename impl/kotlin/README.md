<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — Kotlin SDK

The Kotlin reference implementation of **N-AALP** (draft-bubblefish-naalp-00). Every N-AALP object is
a deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.** Its bytes are byte-identical to the
Go and Rust references.

## Install

Requires a JVM toolchain ≥ 21. From Maven Central (`sh.bubblefish:naalp-kotlin`):

```kotlin
implementation("sh.bubblefish:naalp-kotlin:0.1.0")
```

The crypto leg (deterministic ML-DSA-65/-87 + Ed25519) is Bouncy Castle `bcprov-jdk18on`.

## Package

`sh.bubblefish.naalp` — `Naalp` / `Envelope` (`Object` + `sign` / `verify`), `Cose`, `Cbor`,
`Identity`, `Policy`, `Channels`, `Records`, `Graph`.

## Quickstart

See [`QUICKSTART.md`](QUICKSTART.md); build + run the byte-level worked-example KAT and the
primitives smoke suite with `./gradlew build`.

## License

Apache-2.0 — see the repository `LICENSE` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
