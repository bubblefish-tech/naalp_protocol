<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — the Native Agentic Application Layer Protocol

N-AALP makes the **object, not the connection, the unit of security and governance** for
autonomous agents. Every N-AALP object is a deterministically encoded CBOR structure signed with
COSE, carrying under one signature its content identity, its originating signer, a closed effect
label that is an *authorization input rather than a hint*, optional approval and audit bindings,
and its causal derivation. The identical signed object is carried — with identical object-level
guarantees — over the N-PAMP substrate, QUIC, WebSocket, or HTTP.

## What N-AALP gives you

- **Post-quantum object security.** Every object is signed with ML-DSA (FIPS 204), with an
  optional Ed25519 hybrid. Long-lived records (receipts, approvals, audit chains) are safe against
  store-now-verify-later forgery.
- **Effect as authorization, not intent.** A closed four-value effect (read_only,
  idempotent_write, non_idempotent_write, destructive) is checked against a granted capability
  before any state change; an unrecognized effect fails closed to destructive.
- **Self-certifying identity.** The signer id is a pure function of the public key — no
  certificate authority — with key rotation, revocation, and attribution that survives rotation.
- **Single-use approvals.** An approval binds the exact arguments by content id and is consumed
  exactly once through a durable, hash-chained ledger, even under concurrency.
- **Tamper-evident audit + tiered ordering.** A signed hash-chained receipt chain, an
  offline-checkable causal graph, and a federated higher tier that reconciles multiple authorities
  with no wire change.
- **Native streaming, delivery, and carriage.** One signed commitment per stream; four monotonic
  delivery stages with persist-before-acknowledge; foreign protocols (MCP, A2A, HTTP, …) carried
  octet-for-octet under N-AALP governance.
- **Twenty tiered channel surfaces**, each a thin body over the one object model.

## Two independent implementations, byte-identical

N-AALP has reference implementations in **Go** and **Rust** from separate language runtimes. For
every construction carrying a security or interoperability claim, the two produce byte-identical
output and are cross-validated against an independent oracle whose expected values come from an
RFC, FIPS, or NIST vector or a from-scratch constructor — never from the implementation under
test. `bash harness/run.sh` grades the whole protocol.

## Where to go next

- [Specification overview](spec/overview.md) — the architecture and the object model.
- [The object model](spec/object-model.md) — the signed envelope, byte rules, and identity.
- [The twenty channels](spec/channels.md).
- [Conformance](conformance.md) — the harness and the non-circular oracles.
- [Implementations](implementations/index.md) — Go and Rust quickstarts.
- [Worked example](examples/worked-object.md) — a complete signed object, byte by byte.
- [Registries](registries.md) — the machine-readable code points.
- [Design decisions](adr/index.md).

!!! note "Status"
    N-AALP is an Independent Submission (`draft-bubblefish-naalp-00`). It does not represent IETF
    consensus and is not a standards-track document.
