<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — Java SDK

The Java reference implementation of **N-AALP** (draft-bubblefish-naalp-00). Every N-AALP object is a
deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.** Its bytes are byte-identical to the
Go and Rust references.

## Install

Requires JDK ≥ 21. From Maven Central (`sh.bubblefish:naalp`):

```xml
<dependency>
  <groupId>sh.bubblefish</groupId>
  <artifactId>naalp</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle:

```kotlin
implementation("sh.bubblefish:naalp:0.1.0")
```

The crypto leg (deterministic ML-DSA-65/-87 + Ed25519) is Bouncy Castle `bcprov-jdk18on`.

## Package

`sh.bubblefish.naalp` — `Envelope` (`Object` + `sign` / `verify`), `Cose`, `Cbor`, `Identity`,
`Policy`, `Channels`, `Records`, `Graph`.

## Quickstart

See [`QUICKSTART.md`](QUICKSTART.md); build + run the KAT/smoke tests with `mvn verify`.

## License

Apache-2.0 — see the repository `LICENSE` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
