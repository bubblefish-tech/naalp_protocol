# N-AALP — Native Agentic Application Layer Protocol

**N-AALP gives every agentic application object a signed, deterministic, post-quantum, offline-verifiable meaning — identity, effect, approval, and audit — over any transport.** N-AALP sits *above* the transport and makes the **object, not the connection, the unit of security and governance**: every message is a deterministically encoded CBOR structure signed with COSE that carries, under one signature, its content identity, its originating signer, a closed effect label that is an *authorization input rather than a hint*, optional approval and audit bindings, and its causal derivation — verifiable offline, on any wire.

This repository is the **public reference home** of N-AALP: the byte-level CDDL wire authority, ten reference implementations, a language-agnostic conformance corpus assembled from independent (non-circular) oracles, a cross-implementation test harness, machine-readable code-point registries, and the Architecture Decision Records that capture the load-bearing design choices. The Internet-Draft itself is published through the IETF [Independent Submission stream](https://www.rfc-editor.org/about/independent/). N-AALP is developed as its **own artifact** — consuming products vendor a reference implementation and pin the conformance corpus from here; they do not fork the protocol.

| | |
|---|---|
| **Specification** | Internet-Draft `draft-bubblefish-naalp-00` (IETF Independent Submission stream, Informational); byte-level wire authority [`spec/naalp-draft-00.cddl`](spec/naalp-draft-00.cddl) |
| **License** | [Apache-2.0](LICENSE.md) (repository code + original content); the Internet-Draft additionally under IETF Trust BCP 78 |
| **Reference implementations** | 10 languages (Go, Rust, Python, TypeScript, C#, Swift, Java, Kotlin, PHP, Ruby) |
| **Conformance** | 239-case op-replay corpus (byte-identical Go == Rust == oracle) + a cross-language deterministic-ML-DSA consensus gate; every expected value anchored to an RFC / FIPS / NIST vector |

---

## Status

| Item | State |
|---|---|
| Specification | `draft-bubblefish-naalp-00` (Internet-Draft, Independent Submission stream, Informational) |
| Draft | draft-00 — pre-adoption, **no working-group consensus claimed** (Independent Submission, honest single-maintainer) |
| IETF stream | Independent Submission (ISE), Informational category |
| Substrate | N-PAMP (`draft-bubblefish-npamp-01`) — N-AALP is the application layer N-PAMP carries; N-AALP also rides QUIC, WebSocket, and HTTP |
| License | Apache-2.0 (code) + IETF Trust BCP 78 (draft) |

---

## Why you can trust this

N-AALP is not a whitepaper with aspirational code. Every claim in this repository is backed by an external authority, an executable gate, or a documented decision.

- **Deterministic bytes, not "canonical enough."** Every object is encoded with deterministic CBOR ([RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949)) and signed as a COSE_Sign1 ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)). The same logical object produces the same bytes on every implementation and every transport, so a signature made once verifies everywhere, forever.
- **Post-quantum by default.** Objects are signed with ML-DSA-65 / ML-DSA-87 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), deterministic `rnd = 0`), with an optional Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)) hybrid leg. Long-lived records — receipts, approvals, audit chains — are safe against store-now-verify-later forgery.
- **Offline-verifiable, self-certifying identity.** The signer id is a pure function of the public key (multiformats PeerHandle form); the content id is `multihash(0x20, SHA-384(body))`. No directory, no online lookup, no trusted intermediary is needed to verify an object.
- **Two implementations, byte-identical.** `impl/go` and `impl/rust` produce **byte-identical** deterministic CBOR, COSE signed input, signatures, and digests for identical logical input. The shared-corpus test asserts Go == Rust == oracle bytes — divergence fails CI (see [ADR-0006](docs/adr/0006-two-implementation-byte-parity.md)).
- **Test vectors anchored to outside authorities, not to ourselves.** The 239-case conformance corpus is assembled by independent Python oracles in [`tools/`](tools/); every expected value traces to an RFC / FIPS / NIST vector or a from-scratch byte constructor — **never** to an implementation under test (non-circular). Because the expected answers come from independent standards, a bug shared across implementations cannot silently pass.
- **Seven-language ML-DSA consensus.** Deterministic ML-DSA COSE_Sign1 is asserted byte-identical across **seven** languages (Go, Rust, Python, TypeScript, Java, Kotlin, Ruby) by a cross-language consensus gate ([`tools/crypto_consensus.py`](tools/crypto_consensus.py)). PHP and Swift, whose ecosystems lack a deterministic ML-DSA seed-keygen path, grade every non-crypto op plus Ed25519 and honestly skip-track the ML-DSA leg — recorded, never green-washed.
- **A documented decision history.** Six Architecture Decision Records in [`docs/adr/`](docs/adr/) record why the object — not the connection — is the unit of security, why the protocol is post-quantum-first, why the effect label is an authorization input, and why carriage is by class. Rationale is preserved, not lost.
- **CI that runs all of it on every push and pull request.** [`.github/workflows/conformance.yml`](.github/workflows/conformance.yml) grades the corpus through each SDK adapter, asserts Go == Rust byte parity, machine-validates the CDDL, runs the registry-drift gate, and asserts cross-language ML-DSA byte-parity.

Rigor and adoption-readiness in the same repository: the protocol is specified like a standard *and* shipped like a product.

---

## What N-AALP provides

- **A signed object envelope.** Every N-AALP object is a deterministic-CBOR structure carrying, under one COSE_Sign1 signature: its content id, its signer id, the channel and object `kind`, a `tier`, a closed **effect** label, and optional approval, audit, and causal-derivation bindings. The identical signed object is carried — with identical object-level guarantees — over N-PAMP, QUIC, WebSocket, or HTTP.
- **Effect as authorization, not intent.** A closed four-value effect — `read_only`, `idempotent_write`, `non_idempotent_write`, `destructive` — is checked against a granted capability **before** any state change; an unrecognized effect fails closed to `destructive`. Absence on a state-mutating carried request is treated as `destructive`.
- **Single-use approval and an append-only audit chain.** Approvals are content-addressed and consumed once through a single-use ledger append; receipts form an append-only chain an auditor can walk, with signed equivocation (fork) proofs.
- **Twenty application channels** (`0x0000`–`0x0013`), **65 object kinds** total — one application surface for each of N-PAMP's twenty channels, each a thin body over the one spine (envelope, encoding, crypto, identity, effect, approval, audit, delivery).
- **Foreign-protocol carriage by class.** N-AALP carries other agent protocols (MCP, A2A, and more) octet-exact by carriage **class** inside a governed signed envelope — six classes plus an OPAQUE catch-all — so a bridged payload inherits N-AALP's identity, effect, approval, and audit without re-encoding.
- **Tiered, baseline-frozen surfaces.** Every channel has a complete frozen baseline surface no edition may thin; higher tiers add capability under the same envelope, effect vocabulary, identity model, and audit chain. One codebase; editions license tiers.

N-AALP is deliberately scoped as an **application layer**. Transport concerns — the handshake, AEAD record layer, key establishment, and connection management — belong to N-PAMP (or QUIC / WebSocket / HTTP) beneath it, not to N-AALP.

### The 20 channels

Every channel is a thin surface over the one spine, adding only `kind` codes and their bodies. The code points are in [`vectors/registry/channels.csv`](vectors/registry/channels.csv); the design rationale is in the [Architecture Decision Records](docs/adr/).

| Code | Channel | Code | Channel |
|---|---|---|---|
| `0x0000` | Control | `0x000A` | Telemetry |
| `0x0001` | Memory | `0x000B` | Audit |
| `0x0002` | Capability | `0x000C` | Stream |
| `0x0003` | Identity | `0x000D` | Bridge |
| `0x0004` | Governance | `0x000E` | Commerce |
| `0x0005` | Immune | `0x000F` | Interaction |
| `0x0006` | Federation | `0x0010` | Discovery |
| `0x0007` | Settlement | `0x0011` | Workflow |
| `0x0008` | Compliance | `0x0012` | Knowledge |
| `0x0009` | Sensory | `0x0013` | Spatial |

---

## 1. Pick your language and go

Ten idiomatic reference implementations live under [`impl/`](impl/), co-located with the spec. Each SDK is the **open-protocol reference library**: the spine primitives (deterministic CBOR, content id, COSE ToBeSigned, signer id, effect, approval, audit, delivery, streaming, carriage, channels, federation) plus ML-DSA / Ed25519 where a conformant library exists, and a matching conformance adapter in the harness. **Go and Rust are the primary references and are byte-identical.**

| Language | Source | Quickstart | Crypto | Conformance adapter |
|---|---|---|---|---|
| Go *(primary reference)* | [`impl/go/`](impl/go/) | [Quickstart](docs/implementations/quickstart-go.md) | ML-DSA-65/-87 + Ed25519 | [`harness/adapters/go/`](harness/adapters/go/) |
| Rust *(primary reference)* | [`impl/rust/`](impl/rust/) | [Quickstart](docs/implementations/quickstart-rust.md) | ML-DSA-65/-87 + Ed25519 | [`harness/adapters/rust/`](harness/adapters/rust/) |
| Python | [`impl/python/`](impl/python/) | [QUICKSTART](impl/python/QUICKSTART.md) | ML-DSA-65/-87 + Ed25519 | [`harness/adapters/python/`](harness/adapters/python/) |
| TypeScript | [`impl/typescript/`](impl/typescript/) | [QUICKSTART](impl/typescript/QUICKSTART.md) | ML-DSA-65/-87 + Ed25519 | [`harness/adapters/typescript/`](harness/adapters/typescript/) |
| Java | [`impl/java/`](impl/java/) | [QUICKSTART](impl/java/QUICKSTART.md) | ML-DSA-65/-87 + Ed25519 | [`harness/adapters/java/`](harness/adapters/java/) |
| Kotlin | [`impl/kotlin/`](impl/kotlin/) | [source](impl/kotlin/) | ML-DSA-65/-87 + Ed25519 | [`harness/adapters/kotlin/`](harness/adapters/kotlin/) |
| Ruby | [`impl/ruby/`](impl/ruby/) | [QUICKSTART](impl/ruby/QUICKSTART.md) | ML-DSA-65/-87 + Ed25519 | [`harness/adapters/ruby/`](harness/adapters/ruby/) |
| C# | [`impl/csharp/`](impl/csharp/) | [source](impl/csharp/) | authored, CI-graded | [`harness/adapters/csharp/`](harness/adapters/csharp/) |
| PHP *(pure-only)* | [`impl/php/`](impl/php/) | [QUICKSTART](impl/php/QUICKSTART.md) | Ed25519 (ML-DSA skip-tracked) | [`harness/adapters/php/`](harness/adapters/php/) |
| Swift *(pure-only)* | [`impl/swift/`](impl/swift/) | [source](impl/swift/) | Ed25519 (ML-DSA skip-tracked) | [`harness/adapters/swift_adapter/`](harness/adapters/swift_adapter/) |

The Go module is `github.com/bubblefish-tech/naalp_protocol/impl/go`; the Rust crate is `naalp`. PHP and Swift are marked **pure-only**: their ecosystems lack a deterministic ML-DSA seed-keygen path, so they grade every non-crypto op plus Ed25519 and return an honest `skipped` for the ML-DSA ops (never a false green). The per-language ML-DSA library and its status are recorded in [`harness/adapters.json`](harness/adapters.json).

### What every SDK gives you

The exact symbol names differ per language (see each Quickstart), but every port implements the same spine, verified against the shared 239-case corpus in [`vectors/conformance/`](vectors/conformance/):

- **Deterministic CBOR codec** — canonical encode / decode with non-canonical rejection (RFC 8949 §4.2.1).
- **Object identity** — `content.id` = `multihash(0x20, SHA-384(body))`; `signer.id` in multiformats PeerHandle form (a pure function of the public key).
- **COSE signing** — the `Sig_structure` / ToBeSigned construction (RFC 9052) plus COSE_Sign1 sign / verify over ML-DSA and Ed25519.
- **Effect vocabulary** — the closed four-value effect, the §6.1 authorization lattice (`effect.authorize`), and safety-label encoding, with unknown effects failing closed to `destructive`.
- **Approval + audit** — content-addressed approval bodies, the single-use ledger entry, the receipt chain and its head, and causal-graph verification.
- **Delivery, streaming, carriage, channels, federation** — the delivery state body, rolling stream digest and stream open/commit/checkpoint, carriage-by-class bodies, channel/kind lookup and effect checks, and deterministic federation reconciliation.

Each SDK ships runnable examples and KAT tests in its directory. Transport, connection management, and RPC live in the *consuming* product that carries the SDK's objects — see each Quickstart's boundary note.

---

## 2. Prove your implementation conforms

Every implementation is graded against the **same** independent corpus by a single-binary, language-agnostic runner — so "it passes on my machine, in my language" means the same thing everywhere. The runner (`naalp-conform`) drives the corpus through **one adapter at a time**, launched as a child process, and grades each answer against the corpus's committed expected value — **including the negative cases an implementation MUST reject**, which is where real conformance bugs surface.

```sh
# Build the runner and the Go reference adapter, then grade the adapter:
( cd harness/runner       && GOWORK=off go build -o naalp-conform ./ )
( cd harness/adapters/go  && GOWORK=off go build -o naalp-adapter-go ./ )
./harness/runner/naalp-conform run \
  --testee "./harness/adapters/go/naalp-adapter-go"
```

A run prints a per-operation `Pass / Fail / Unimplemented` tally and **exits non-zero if any case fails** — so it drops into CI with no glue code. `naalp-conform vectors` dumps the embedded corpus.

### Two ways to use it

- **Tier A — vectors only.** Loop the corpus cases through your code directly: for `valid` cases your output must equal `expected`; for `invalid` cases you MUST reject the input.
- **Tier B — black-box adapter.** Write a small **adapter** ("testee") that wraps your implementation. The runner spawns it as a subprocess and drives it over a length-prefixed JSON-on-stdin/stdout contract (`4-byte little-endian length ‖ N bytes of JSON`; request `{op, in}` → response `{out | error | skipped}`). The adapter owns no test logic — it only translates each request into a call on your implementation, so it can be written in any language.

### Adapter starting points (one per language)

Copy a reference adapter from [`harness/adapters/`](harness/adapters/) and re-point it at your code. The Go and Rust adapters are the CI-exercised known-good references, graded on every push.

| | | | | |
|---|---|---|---|---|
| [`adapters/go/`](harness/adapters/go/) | [`adapters/rust/`](harness/adapters/rust/) | [`adapters/python/`](harness/adapters/python/) | [`adapters/typescript/`](harness/adapters/typescript/) | [`adapters/csharp/`](harness/adapters/csharp/) |
| [`adapters/swift_adapter/`](harness/adapters/swift_adapter/) | [`adapters/java/`](harness/adapters/java/) | [`adapters/kotlin/`](harness/adapters/kotlin/) | [`adapters/php/`](harness/adapters/php/) | [`adapters/ruby/`](harness/adapters/ruby/) |

The adapter contract covers 31 operations — the pure spine ops (deterministic CBOR, content id, COSE ToBeSigned, signer id, effect, approval, audit, delivery, streaming, carriage, channels, federation) and the crypto ops (`mldsa.keygen`, `ed25519.sign`, `cose.sign1`, `cose.verify1`). Any op the SDK genuinely cannot do returns `{"skipped": "..."}` and is reported **Unimplemented**, not Fail — so a pure-only SDK is still fully graded on every spine op. Full detail in [`harness/INSTRUCTIONS.md`](harness/INSTRUCTIONS.md).

---

## 3. Standards-anchored test vectors

The [`vectors/`](vectors/) tree is the **canonical** conformance oracle: the 239-case op-replay corpus is assembled by the independent Python oracles in [`tools/`](tools/) from per-family sources. Crucially, the vectors are derived from the underlying standards — **not** generated by the implementation they grade.

| Layer | What it pins | Standards anchor |
|---|---|---|
| Deterministic CBOR | canonical encode / decode + non-canonical reject | RFC 8949 §4.2.1 |
| Content + signer id | `multihash(0x20, SHA-384(body))`; PeerHandle signer id | FIPS 180-4 (SHA-384), multiformats |
| COSE ToBeSigned | the `Sig_structure` bytes | RFC 9052 |
| ML-DSA keygen / sign | seed → public key; deterministic signature | FIPS 204 (`rnd = 0`), NIST ACVP |
| Ed25519 | signature over a message | RFC 8032 |
| Effect / approval / audit / delivery / stream / carriage / channels / federation | the spine construction bodies | from-scratch byte constructors in `tools/*_oracle.py` |

Because every expected answer traces to an external standard or an independent byte constructor, no value is generated by an N-AALP implementation, and a shared implementation bug cannot pass the suite. The one exception — the deterministic ML-DSA signature, for which no external KAT gives the full COSE_Sign1 — is graded by the cross-language **consensus** gate ([`tools/crypto_consensus.py`](tools/crypto_consensus.py)), which asserts the seven crypto-capable SDKs agree byte-for-byte. Regenerate any oracle with `python tools/<name>_oracle.py`.

---

## 4. Machine-readable registries

Four CSV registries in [`vectors/registry/`](vectors/registry/) carry the public draft code points — parseable by tooling, one row per assignment. The registry-drift gate ([`scripts/registry_drift.py`](scripts/registry_drift.py)) asserts they stay in lockstep with the CDDL and the implementations.

| Registry | Contents |
|---|---|
| [`channels.csv`](vectors/registry/channels.csv) | The 20 channels and their 65 object kinds — channel id, kind code, kind name, effect, variable-effect flag |
| [`signatures.csv`](vectors/registry/signatures.csv) | COSE signature algorithms — `ML-DSA-65` (`-49`), `ML-DSA-87` (`-50`), `Ed25519` (`-19`), `SLH-DSA` (reserved) with NIST level and status |
| [`multicodec.csv`](vectors/registry/multicodec.csv) | Multicodec assignments for the multihash and signer-id key forms (`sha2-256`, `ed25519-pub`, `mldsa-65-pub`, `mldsa-87-pub`) |
| [`protocols.csv`](vectors/registry/protocols.csv) | Bridge protocol-id assignments and their carriage class — `MCP`, `A2A` (JSONRPC), `HTTP`, `WebSocket` (STREAM) |

---

## Bridging to the agent ecosystem

N-AALP's Bridge channel (`0x000D`) carries other agent protocols as first-class, octet-exact payloads inside the governed signed envelope, so a bridged payload inherits N-AALP's identity, effect, approval, and audit **without re-encoding**. Carriage is **by class**, not per-protocol: a payload travels over one of six carriage classes with a normative binding, and each mapped protocol names its class and a reserved `protocol_id` in [`vectors/registry/protocols.csv`](vectors/registry/protocols.csv).

| Carriage class | Carries |
|---|---|
| `JSONRPC` | JSON-RPC 2.0 request/response protocols (e.g. MCP, A2A) |
| `HTTP` | HTTP-semantics protocols |
| `MSG` | messaging / performative protocols |
| `STREAM` | streaming protocols (e.g. WebSocket) |
| `DOC` | capability & schema documents |
| `OPAQUE` | any payload whose bytes are carried verbatim under the envelope, with no class-specific binding |

The `OPAQUE` class is the catch-all: it lets N-AALP wrap a payload whose protocol has no dedicated class yet in the same signed, effect-labelled, auditable envelope, so nothing falls outside governance. Thin per-protocol mappings beyond the assigned four are added as registry entries, not new envelope machinery. The carriage-by-class rationale is recorded in [ADR-0005](docs/adr/0005-carriage-by-class.md); the Bridge channel code points are in [`vectors/registry/protocols.csv`](vectors/registry/protocols.csv).

---

## Repository map

| Path | Holds |
|------|-------|
| [`spec/naalp-draft-00.cddl`](spec/naalp-draft-00.cddl) | The byte-level wire authority (CDDL, RFC 8610) — machine-validated in CI. The prose specification is the Internet-Draft, published via the IETF Independent Submission stream. |
| [`impl/`](impl/) | 10 multi-language reference implementations (Go + Rust primary, byte-identical) |
| [`harness/`](harness/) | The cross-implementation conformance runner (`naalp-conform`) + 10 language adapters + the contract ([`INSTRUCTIONS.md`](harness/INSTRUCTIONS.md)) |
| [`tools/`](tools/) | The independent Python oracles that build the corpus + the cross-language ML-DSA consensus gate |
| [`vectors/`](vectors/) | The 239-case conformance corpus + per-family vectors |
| [`vectors/registry/`](vectors/registry/) | 4 machine-readable code-point registries (CSV) |
| [`scripts/`](scripts/) | Gate scripts: [`verify.sh`](scripts/verify.sh) / [`verify.ps1`](scripts/verify.ps1), [`cddl_check.sh`](scripts/cddl_check.sh), [`registry_drift.py`](scripts/registry_drift.py) |
| [`docs/`](docs/) | The MkDocs Material documentation site, including [`docs/adr/`](docs/adr/) — 6 Architecture Decision Records recording the load-bearing design rationale |
| [`.github/workflows/conformance.yml`](.github/workflows/conformance.yml) | The conformance CI workflow |

---

## Continuous integration

[`.github/workflows/conformance.yml`](.github/workflows/conformance.yml) runs on every push and pull request:

| Job | Gate |
|---|---|
| `conformance` | The full harness ([`harness/run.sh`](harness/run.sh)): the `naalp-conform` runner grades the 239-case corpus through the SDK adapters, the CDDL is machine-validated (Bormann `cddl` tool, RFC 8610), and the registry-drift gate runs. Any MUST failure exits non-zero. |
| `parity` | [`scripts/verify.sh`](scripts/verify.sh) asserts Go and Rust produce **byte-identical** COSE_Sign1 and object-envelope bytes for the same key + payload (R-16.2), and checks for vector drift. |
| `cross-language` | [`harness/cross_language.sh`](harness/cross_language.sh) builds every adapter whose toolchain is present, grades the corpus through each, and asserts deterministic ML-DSA COSE_Sign1 is byte-identical across the crypto-capable SDKs (a language without a deterministic ML-DSA library grades its pure ops and tracks the crypto leg as an honest SKIP). |

---

## Reading the specification

The normative prose specification is the Internet-Draft `draft-bubblefish-naalp-00`, published through the IETF [Independent Submission stream](https://www.rfc-editor.org/about/independent/) (Informational).

The byte-level wire authority is the CDDL in [`spec/naalp-draft-00.cddl`](spec/naalp-draft-00.cddl) — maintained with the reference implementations and machine-validated in CI (Bormann `cddl` tool, RFC 8610).

---

## Getting started

1. **Read the object model** — the wire grammar in [`spec/naalp-draft-00.cddl`](spec/naalp-draft-00.cddl) for the signed envelope, deterministic encoding, crypto profiles, and the effect vocabulary; the [ADRs](docs/adr/) for the rationale.
2. **Skim the channels** — the channel table above and [`vectors/registry/channels.csv`](vectors/registry/channels.csv) for the twenty application surfaces and their object kinds.
3. **Pick a language** — start from that implementation's Quickstart (table above); Go and Rust are the primary references.
4. **Prove conformance** — run your build against the `naalp-conform` harness with the corpus in [`vectors/conformance/`](vectors/conformance/).

---

## Scope

This repository is the **open** N-AALP reference surface: the spine (deterministic CBOR, content id, COSE signing, signer id, effect, approval, audit, delivery, streaming, carriage, channels, federation), the baseline surfaces of all twenty channels, the public draft registry code points, the conformance corpus, and the reference implementations. Every channel has a complete, frozen baseline surface here. Publishing a code point discloses an *identifier*, not an *implementation*: higher channel tiers and edition-licensed capability escalate under the identical frozen envelope, effect vocabulary, identity model, and audit chain, and their high-tier implementation material is maintained separately — out of scope for this open reference. Transport concerns (handshake, AEAD, key establishment) are **not** here: they belong to N-PAMP or the underlying QUIC / WebSocket / HTTP, beneath N-AALP.

---

## IANA registrations

The registrations are stated in the IANA Considerations of the Internet-Draft, and mirrored by the machine-readable registries in [`vectors/registry/`](vectors/registry/):

- **Media type `application/naalp+cbor`** ([RFC 6838](https://www.rfc-editor.org/rfc/rfc6838) / BCP 13) — the object encoding.
- **Five new N-AALP registries** — under Specification Required / Expert Review / Experimental / Private Use policies ([RFC 8126](https://www.rfc-editor.org/rfc/rfc8126)), with Designated-Expert guidance, mirrored by the machine-readable CSVs in [`vectors/registry/`](vectors/registry/).

---

## Versioning

- **Draft revision** — the `-NN` counter at the end of the draft name advances with every published revision (`draft-bubblefish-naalp-00`, `-01`, …). One annotated git tag marks each Datatracker revision, with `rfcdiff` for per-revision deltas.
- **Wire authority** — the CDDL in [`spec/naalp-draft-00.cddl`](spec/naalp-draft-00.cddl) is the byte-level source of truth; a wire-incompatible change is a new major and a new draft.
- **Substrate** — N-AALP tracks N-PAMP `draft-bubblefish-npamp-01` as its named substrate; the substrate version is independent of the N-AALP draft revision.

---

## License

The repository's code and original content are licensed under the [Apache License 2.0](LICENSE.md).

The Internet-Draft and any resulting RFC are additionally subject to the IETF Trust's Legal Provisions Relating to IETF Documents (BCP 78); see the IPR notice (`ipr: trust200902`) in the draft front matter and [`NOTICE`](NOTICE). Apache-2.0 does not override the IETF Trust terms on the draft text. Anyone may implement the protocol royalty-free. Trademark usage is covered by [`TRADEMARKS.md`](TRADEMARKS.md).

## Contributing and security

- Contribution guidelines: [CONTRIBUTING.md](CONTRIBUTING.md)
- Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Reporting a security issue: [SECURITY.md](SECURITY.md)
- How to cite this work: [CITATION.cff](CITATION.cff)

## Author

Shawn Sammartano, BubbleFish™ Technologies, Inc. — sole editor and lead maintainer, disclosed and intentional. This is a single-maintainer Independent Submission (ISE), pre-adoption: **no IETF working-group consensus is claimed**.

Contact: naalp-editor@bubblefish.sh

---

*N-AALP™ and BubbleFish™ are trademarks of BubbleFish Technologies, Inc.*
