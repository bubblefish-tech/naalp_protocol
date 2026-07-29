# N-AALP object-version lineage

This file is the **public** narrative of how N-AALP reached
`draft-bubblefish-naalp-00`. It records what is publishable and orients a reader in the
version history; the authoritative rationale for each load-bearing choice lives in the linked
ADRs under `docs/adr/`. It is descriptive, not normative — where it and the spec or ADRs differ,
the spec (`ietf/draft-bubblefish-naalp-00.md`, `spec/naalp-draft-00.cddl`) and the ADRs govern.

## Where N-AALP sits (positioning)

N-AALP is an **application-layer object protocol**. Its unit of security is the *object*, not the
connection (**ADR-0002**): every application-layer meaning — identity, effect, approval, audit —
is a signed, deterministically-encoded, offline-verifiable object. The object security surface is
**deterministic CBOR** (RFC 8949 §4.2.1) + **COSE_Sign1** (RFC 9052) + **post-quantum signatures**
(ML-DSA-65/-87, FIPS 204, deterministic `rnd = 0`), with Ed25519 (RFC 8032) as the classical leg.

N-AALP is carried by **N-PAMP** (`draft-bubblefish-npamp-01`) or by HTTP, WebSocket, or QUIC; the
identical object bytes cross every binding. It carries foreign agent protocols (MCP, A2A, and more)
octet-exact **by carriage class** inside the governed signed envelope (**ADR-0005**), and presents
one application surface for each of N-PAMP's twenty channels.

## What this file does NOT contain (non-scope)

- **This is not the normative specification.** The byte-level authority is
  `spec/naalp-draft-00.cddl`; the prose authority is `ietf/draft-bubblefish-naalp-00.md`. This file
  narrates lineage only.
- **Transport-layer concerns are out of scope by layering, not by policy.** The 1.5-RTT handshake,
  hybrid key establishment, and AEAD record protection belong to the substrate
  (`draft-bubblefish-npamp-01`), not to N-AALP. N-AALP versions the *object*, not the connection.
- **There is no controlled, sealed, or privately-maintained cryptographic material.** N-AALP has no
  controlled edition and no controlled protocol generation. The **open edition is the full reference
  surface**: every construction (the object model, the COSE/ML-DSA/Ed25519 profiles, identity,
  effect, approval, audit, delivery, streaming, the transport bindings, carriage-by-class, and all
  twenty channel surfaces) and all ten reference SDKs are open under Apache-2.0. Nothing about
  N-AALP's cryptography is withheld from this repository; unlike a controlled/sealed model, there is
  no private delta to describe here because none exists.

## Public object-version identifiers

N-AALP carries an **object major version** in the object-envelope version field and in the
domain-separation label prefix `N-AALP/1` (used for every signed-input and digest domain string).
This is distinct from the substrate's ALPN wire identifier (`n-pamp/2`), which N-AALP does not
define — application-object versioning and transport-wire versioning are separate counters on
separate layers.

| Object major | Label prefix | Status |
|---|---|---|
| 1 | `N-AALP/1` | **Current** — defined by `draft-bubblefish-naalp-00` |

A future incompatible object model would take a new prefix (for example `N-AALP/2`); the
Internet-Draft revision (`-NN`) advances independently with each published document revision (see
`CHANGELOG.md`).

## Protocol generations

The public draft is the **first published** generation:

1. **draft-00 (`N-AALP/1`)** — the first published generation: `ietf/draft-bubblefish-naalp-00.md`
   + `spec/naalp-draft-00.cddl` + the reference implementations under `impl/`. Its public design
   decisions are indexed below.

There is **no deprecated predecessor** and **no controlled intermediate generation**. N-AALP was
authored directly to this published draft; the sequence above is the whole sequence.

## Public design decisions at draft-00 (index into `docs/adr/`)

Each item links to the ADR that records the full context, decision, and consequences:

- **The object, not the connection, is the unit of security.** Existing agent protocols secure the
  transport but leave the message un-signed and its authorization implicit; a message that crosses a
  relay, is stored, or is replayed loses its guarantees. N-AALP makes the object self-securing.
  **ADR-0002**.
- **Post-quantum-first signatures.** N-AALP objects (receipts, approvals, audit chains) are
  long-lived, non-repudiable records, so a classical-only signature is a latent forgery exposure.
  ML-DSA-65/-87 (FIPS 204, deterministic `rnd = 0`) are the post-quantum suites; Ed25519 is the
  classical leg; there is no classical-only default. **ADR-0003**.
- **Effect is an authorization input, not a hint.** Unlike an advisory intent label, an object's
  declared effect *is* the unit an approver authorizes and an auditor verifies — the effect is
  bound into the signed object and is not overridable by a downstream label. **ADR-0004**.
- **Foreign carriage by class, not by protocol.** Rather than a bespoke per-protocol mapping for
  every foreign protocol (a combinatorial, drift-prone burden), N-AALP carries foreign payloads
  octet-exact by carriage **class**, with a carriage registry and an **opaque** class for unknown
  payloads. **ADR-0005**.
- **Two independent implementations, byte-identical.** A spec proven by one implementation cannot
  demonstrate interoperability, and an implementation graded against its own output is a circular
  oracle. Go and Rust are independent references that MUST produce byte-identical CBOR, signed
  input, signatures, and digests, cross-validated against independent non-circular oracles anchored
  to RFC/FIPS/NIST vectors. **ADR-0006**.

The full ADR log (Nygard-style; **ADR-0001** records the decision-recording process itself) lives
in `docs/adr/`.

## Deprecations and supersessions (public)

- **None at this revision.** draft-00 is the first published generation of N-AALP; there is no prior
  object major version to deprecate and no superseded corpus or golden vector set.

## Honest conformance and SDK status

- **Ten reference SDKs.** Go and Rust are the primary byte-identical references. Python, TypeScript,
  Java, Kotlin, and Ruby carry full post-quantum crypto and grade 239/239. **PHP and Swift are
  pure-only** — their ecosystems lack a deterministic ML-DSA seed-keygen path, so they grade every
  non-crypto op plus Ed25519 and **honestly skip-track the ML-DSA leg** rather than fake it. C# is
  authored and graded in CI. Deterministic ML-DSA COSE_Sign1 is byte-identical across seven
  languages (Go, Rust, Python, TypeScript, Java, Kotlin, Ruby).
- **Non-circular grading.** The `naalp-conform` runner drives a 239-case op-replay corpus, assembled
  from independent oracles anchored to RFC/FIPS/NIST vectors (never from the code under test),
  through each SDK adapter, alongside a cross-language deterministic-ML-DSA consensus gate, a
  machine-validated CDDL (RFC 8610), and a registry-drift gate.

## Forward

Future revisions of the Internet-Draft advance the `-NN` counter and track the substrate as
`draft-bubblefish-npamp` evolves; a future incompatible object model would take a new `N-AALP/N`
prefix. Both counters, and their changes, are recorded in `CHANGELOG.md`.

## See also

- `docs/adr/` — the full ADR log (ADR-0001 records the decision-recording process itself).
- `README.md` — repository model and structure.
- `CHANGELOG.md` — the object-major-version and Internet-Draft-revision counters.
- `ietf/draft-bubblefish-naalp-00.md`, `spec/naalp-draft-00.cddl` — the normative protocol text and
  the byte-level wire authority.
