# N-AALP™ — "Native Agentic Application Layer Protocol™"

`draft-bubblefish-naalp-00`

N-AALP™ is the universal, vendor-neutral application layer for autonomous agents and
their tools. It gives every application object a signed, deterministic, post-quantum,
offline-verifiable meaning — identity, effect, approval, and audit — on top of any
transport. It is carried by N-PAMP™, HTTP, WebSocket, or QUIC; it carries foreign agent
protocols (MCP, A2A, and more) by class inside a governed signed envelope; and it
presents one application surface for each of N-PAMP's twenty channels.

- Wire authority: `spec/naalp-draft-00.cddl`
- Reference implementations: `impl/go`, `impl/rust`
- Conformance: `harness/`, independent oracles in `tools/`, corpora in `vectors/`
- License: Apache-2.0 (`LICENSE`)

BubbleFish Substrate™: N-PAMP™ `draft-bubblefish-npamp-01`.
Copyright (c) 2026 BubbleFish Technologies™, Inc.
