<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — Ruby SDK

The Ruby reference implementation of **N-AALP** (draft-bubblefish-naalp-00). Every N-AALP object is a
deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.** Its bytes are byte-identical to the
Go and Rust references.

## Install

```sh
gem install naalp
```

The crypto leg uses Ruby's stdlib `openssl`. Deterministic ML-DSA (FIPS 204, rnd=0) needs the
platform OpenSSL ≥ 3.5; where OpenSSL is older, the ML-DSA leg is honestly skipped (Ed25519 and all
non-crypto operations still grade).

## Modules

`require "naalp"` — `Naalp::Envelope` (`Object` + `sign` / `verify`), `Naalp::Cose`, `Naalp::Cbor`,
`Naalp::Identity`, `Naalp::Policy`, `Naalp::Channels`, `Naalp::Records`, `Naalp::Graph`.

## Quickstart

See [`QUICKSTART.md`](QUICKSTART.md).

## License

Apache-2.0 — see the repository `LICENSE` and `NOTICE`. The Internet-Draft is additionally under
the IETF Trust's BCP 78.
