<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — PHP SDK

The PHP reference implementation of **N-AALP** (draft-bubblefish-naalp-00). Every N-AALP object is a
deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.**

## Install

Requires PHP ≥ 8.3 with the `sodium` and `intl` extensions. From Packagist:

```sh
composer require bubblefish/naalp
```

The classical leg (Ed25519) is `ext-sodium` (libsodium); NFC uses `ext-intl` (ICU).

> **Pure-only:** PHP has no deterministic ML-DSA seed-keygen path, so this SDK implements every
> non-crypto operation plus Ed25519 and honestly **skip-tracks** the ML-DSA leg (never a false
> pass). It grades 235 conformance cases (4 ML-DSA cases skipped).

## Classes

Namespace `Bubblefish\Naalp` — `Envelope` (`Object` + `sign` / `verify`), `Cose`, `Cbor`,
`Identity`, `Policy`, `Channels`, `Records`, `Graph`, `Naalp` (facade).

## Quickstart

See [`QUICKSTART.md`](QUICKSTART.md).

## License

Apache-2.0 — see the repository `LICENSE` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
