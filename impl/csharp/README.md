<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — C# SDK

The C# / .NET reference implementation of **N-AALP** (draft-bubblefish-naalp-00). Every N-AALP object
is a deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.** Its bytes are byte-identical to the
Go and Rust references.

## Install

Requires .NET ≥ 8. From NuGet:

```sh
dotnet add package Bubblefish.Naalp
```

The crypto leg (deterministic ML-DSA-65/-87 + Ed25519) is `BouncyCastle.Cryptography`.

> **Note:** the SDK requires real Unicode normalization (ICU) for the NFC identity rule; do **not**
> run under `InvariantGlobalization` (it disables ICU and the NFC check degrades to a no-op).

## Namespace

`Naalp` — `Envelope` (`Object` + `Sign` / `Verify`), `Cose`, `Cbor`, `Identity`, `Policy`,
`Channels`, `Records`, `Graph`.

## Quickstart

See [`QUICKSTART.md`](QUICKSTART.md).

## License

Apache-2.0 — see the repository `LICENSE` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
