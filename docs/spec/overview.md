<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Specification overview

The normative wire authority is the CDDL module `spec/naalp-draft-00.cddl`; the prose
specification is the Internet-Draft (IETF Independent Submission stream). This page is an informative map.

## Three layers, never conflated

1. **The object** (self-secured, transport-independent): integrity, identity, non-repudiation,
   effect, and audit are always present regardless of transport.
2. **The transport** (N-PAMP, QUIC, WebSocket, HTTP): provides framing and, conditionally,
   confidentiality, forward secrecy, and connection authentication.
3. **The application**: the twenty channel surfaces, each a thin body over the one object model.

## The spine (C1–C9)

| # | Component | What it provides |
|---|---|---|
| C1 | Deterministic CBOR + content id | RFC 8949 §4.2.1 canonical encoding; `multihash(0x20, SHA-384)` content id |
| C2 | COSE_Sign1 + profiles | ML-DSA-65/87 (FIPS 204, deterministic) + optional Ed25519 hybrid; Public/Enterprise/Sovereign floors |
| C3 | Object envelope | the signed body, versioning, critical/non-critical extensions |
| C4 | Identity | self-certifying signer id; rotation, revocation, foreign-identity linkage |
| C5 | Effect + authorization | the closed effect set; effect is an authorization input; fail-closed |
| C6 | Approval + consume ledger | args bound by content id; single-use, durable, concurrent-safe |
| C7 | Audit + causal graph + ordering | signed receipt chain; offline causal graph; equivocation auditor |
| C8 | Delivery | four monotonic stages; persist-before-acknowledge; the switchboard |
| C9 | Streaming | one rolling-SHA-384 commitment per stream; checkpoints |

## Beyond the spine

- **C11 Transport bindings** — one object = one message unit over four transports; the
  confidentiality boundary refuses a sensitive object over cleartext.
- **C12 Foreign carriage** — a foreign protocol's message wrapped octet-for-octet, by class.
- **C10 Channel surfaces** — the twenty channels, baseline tier frozen.
- **Higher tiers** — federated ordering and per-channel escalations under the frozen envelope.

Continue to the [object model](object-model.md).
