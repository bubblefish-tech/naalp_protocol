# Changelog

All notable changes to the public N-AALP specification are recorded here.

Two independent counters apply (see the README "Versioning" section):

- the protocol **object major version** (the `1` carried in the object-envelope
  version field and in the `N-AALP/1/...` domain-separation label prefix); and
- the **Internet-Draft revision** (`-NN`), which advances with each published
  revision of the document.

N-AALP is an application-layer object protocol: it defines signed, deterministic,
offline-verifiable objects (identity, effect, approval, audit) carried over
N-PAMP or any other transport. Transport-layer concerns — the handshake, key
establishment, and AEAD record protection — belong to the substrate
(`draft-bubblefish-npamp-01`) and are not versioned here.

## draft-bubblefish-naalp-00 (2026-07-27)

Initial public Internet-Draft of N-AALP. Object major version 1;
domain-separation prefix `N-AALP/1`.

Specified in this revision:

- **Object model.** A single deterministic-CBOR object encoding (RFC 8949
  §4.2.1) for every application-layer meaning, with a `content-id` =
  `multihash(0x20, SHA-384(body))` and a `signer-id` in multiformats
  `PeerHandle` form. One encoding, one canonical byte form; a transport-
  independent object guarantee.
- **Cryptographic profiles.** COSE_Sign1 (RFC 9052) over the deterministic
  body; ML-DSA-65 and ML-DSA-87 (FIPS 204, deterministic `rnd = 0`) as the
  post-quantum signature suites; Ed25519 (RFC 8032) as the classical suite.
  No classical-only default; post-quantum first.
- **Identity.** The `signer-id` / `PeerHandle` construction, key binding, and
  the identity object that carries an agent's verifiable name.
- **Effect and authorization.** The effect object and the rule that effect *is*
  authorization — an object's declared effect is the unit an approver authorizes
  and an auditor verifies.
- **Approval.** The approval object: a single-use, independently-verifiable
  authorization bound to a specific effect and consumed exactly once.
- **Audit and federation.** The audit object, deterministic ordering, federated
  ordering across domains, and federation reconciliation.
- **Delivery.** The delivery surface and its receipts.
- **Streaming.** The streamed-object surface layered on N-PAMP's Stream channel.
- **Transport bindings.** Four bindings — N-PAMP, HTTP, WebSocket, and QUIC —
  each carrying the identical object bytes.
- **Carriage by class.** Foreign agent protocols (MCP, A2A, and more) are
  carried octet-exact by carriage **class** inside the governed signed envelope,
  with a carriage registry and an opaque class for unknown payloads.
- **Twenty channel surfaces** (`0x0000`-`0x0013`) and **65 kinds** — one
  application surface for each of N-PAMP's twenty channels, tiered from baseline
  to the higher tiers (including federated ordering and federation
  reconciliation).
- **Conformance.** The `naalp-conform` runner drives a 239-case op-replay corpus
  (assembled from independent, non-circular oracles anchored to RFC / FIPS / NIST
  vectors) through each SDK adapter; a cross-language deterministic-ML-DSA
  consensus gate; a machine-validated CDDL (RFC 8610); and a registry-drift gate.
- **Reference SDKs.** Ten languages. Go and Rust are the primary references and
  produce byte-identical CBOR, signed input, signatures, and digests. Python,
  TypeScript, Java, Kotlin, and Ruby carry full post-quantum crypto and grade
  239/239. PHP and Swift are pure-only (their ecosystems lack a deterministic
  ML-DSA seed-keygen path); they grade every non-crypto op plus Ed25519 and
  honestly skip-track the ML-DSA leg. C# is authored and graded in CI.
  Deterministic ML-DSA COSE_Sign1 is byte-identical across seven languages
  (Go, Rust, Python, TypeScript, Java, Kotlin, Ruby).
- **IANA Considerations.** Requests registration of the media type
  `application/naalp+cbor` (RFC 6838) and establishment of five N-AALP registries
  under Specification Required / Expert Review / Experimental / Private Use
  policies. The CDDL in `spec/naalp-draft-00.cddl` is the byte-level wire
  authority.

Submission track: IETF Independent Submission stream (ISE), Informational
category, pre-adoption. No working-group consensus is claimed at this revision.
