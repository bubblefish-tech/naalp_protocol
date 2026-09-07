# Changelog

All notable changes to N-AALP — the specification and the reference SDKs — are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the reference
SDKs follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The SDKs are pre-1.0
(`0.y.z`): the public API may change between minor versions until `1.0.0` declares it stable. Two
protocol-level counters also apply (see the README "Versioning" section): the **object major
version** (the `1` carried in the object-envelope version field and the `N-AALP/1/…`
domain-separation prefix), and the **Internet-Draft revision** (`-NN`), which advances with each
published revision of the document. Transport-layer concerns (handshake, key establishment, AEAD
record protection) belong to the substrate (`draft-bubblefish-npamp-01`) and are not versioned here.

## [Unreleased]

### Added — draft-01 submission-ready wave (Phases 0–5)

- **Signed `audience` field (object-body field 13) with fail-closed `WrongAudience` verification.**
  An effecting object now names its intended recipient; a verifier rejects an object addressed to
  someone else. This is the anchor for `naalp-version` 2. (R1)
- **Non-decomposable LAMPS hybrid composite signature** — a single COSE_Sign1 (algorithm `-65537`,
  tag 18) combining the classical and post-quantum legs so neither can be stripped independently; a
  leg-removed object is proven to fail verification across all ten ports, with the RFC 9052
  deviation recorded normatively in the draft. (R2, Decision D7)
- **65-kind channel/effect table** enumerating every `(channel, kind_code, kind_name, effect)`
  tuple, and a **`naalp-error` object-kind** (channel `0x0000`, kind 3) carrying a 119-entry numeric
  error-code registry (`vectors/registry/error-codes.csv`) with defined dual-carriage rules for a
  registered-code-wrong-name mismatch (reject `Malformed`) versus an unknown code (opaque pass-through).
  (R3.1–R3.4)
- **Extension-key registry for `ext`/`cext`** (`vectors/registry/extension-keys.csv`): safety-label,
  recheck, signer-counter, and producing-boundary keys under an RFC-Required/FCFS policy. (R4)
- **Vendor-tree media type** `application/vnd.bubblefish.naalp+cbor` and an open
  **Carriage-Content-Types registry** (`vectors/registry/carriage-content-types.csv`). (R8, R11)
- **Multihash worked byte example** (`0x20 0x30` + the 48-byte SHA-384 digest) so the length octet
  cannot be mis-encoded as a two-field prefix, graded against an independent multiformats
  unsigned-varint encoder and the FIPS 180-4 SHA-384("abc") KAT, closing the shared-codebase
  independence gap. (R19, R9)
- **MUST-level decoder resource bounds** — object size (1 MiB), `|causes|` (1024), `ext`+`cext`
  cardinality (64), nesting depth (16), and stream chunk count (2^20) — as named wire constants
  enforced by all ten decoders, with named reject errors (`TooLarge`, `TooManyCauses`,
  `TooManyExtensions`, `DepthExceeded`, `TooManyChunks`). (R7)
- **Determinism hardening**: the canonical empty protected header (`0x41A0`) is pinned as a
  must-reject `NonCanonical` case ahead of map decode, floats are forbidden in body/ext/cext, and
  duplicate map keys are rejected by every strict decoder. (R5)
- **Every `>2^53` counter carried as a JSON string** across all conformance vector families, with an
  exact-integer comparator and a corpus-lint gate closing the class of float64-rounding defect.
  (R12)
- **Receive-side causal-application rule** with an explicit pending-cause hold/timeout state. (R13)
- **Consume-ledger receipt chain + single-writer, issuance-time-audience-bound semantics** for
  federated single-use consumption, with the multi-authority-consensus question explicitly scoped
  out and the boundary stated. (R14, Decision D6)
- **Reconcile base linearization pinned**, with the `naalp-reconcile` object (a signed record of a
  topological linearization of the union causal DAG) part of the inlined CDDL. (R15)
- **Streaming chunk-integrity model** stated: a chunk consumed before `StreamCommit` over a
  transport without N-PAMP per-frame authentication is unauthenticated; checkpoints are the bounding
  mechanism, and transport authentication is not conflated with object authentication. (R16)
- **Event×state tables for all four object state machines** — delivery, stream, approval, reconcile
  — each total with named errors, a timer block, an `not_after` clock-skew rule, an optional signed
  deadline, and cancel semantics requiring a real abort rather than a status flip. (R17)
- **Profile-vs-tier distinction** stated (public and enterprise profiles share the ML-DSA-65 floor;
  they differ in key management/policy, not cryptographic strength). (R18)
- **Deviant-trace + learned-model-diff conformance suites for all four object state machines.**
  Each machine (delivery: 18 cases, stream: 22, approval: 9, reconcile: 8) is graded from a
  non-circular F3 table oracle (`tools/<machine>_state_oracle.py`) through a dedicated corpus op
  (`<machine>.state`), driven through every one of the ten reference SDKs and CI-green
  (`stream.state` also closes the earlier state-machine gap tracked separately). Exhaustive
  total-table coverage is the completeness proof for these small, total machines. (R20.1)

### Changed — draft-01 submission-ready wave

- **Document renamed to `draft-bubblefish-naalp-01`**, with `naalp-version` stated normatively and
  reconciled across the document, the design, the CDDL, and all ten ports. (R6.1)
- **A single version-move rule** (the protected-header version moves only with the envelope
  grammar, never per-key) replaces the earlier contradictory per-key-bump text, and an unrecognized
  protected-header version is now a defined `UnsupportedVersion` reject across the draft, the CDDL,
  and all ten ports. (R6.2, R6.3)

### Fixed

- **Protected-header `naalp-version` aligned to `2` across all ten reference SDKs.** Seven ports
  (C#, Java, Kotlin, PHP, Python, Ruby, Swift) had lagged at `1` while the Go, Rust, and TypeScript
  references and the committed worked-example vector were at `2`; objects signed by the two sets
  were mutually unverifiable. All ten now declare `2`, so a base object is byte-identical across the
  ports. The change is to the protected-header version field only; the `N-AALP/1` domain-separation
  prefix and the object major version are unchanged. The recheck *extension* verify path
  (ext/cext key 13) remains reference-only — a version-2 port that does not recognize a critical
  recheck key rejects it fail-closed, and ignores a non-critical one — so version-2 base compliance
  holds without the extension. Porting the extension to the remaining ports is tracked separately.

### Changed

- **The normative CDDL is now inlined in Appendix A of the Internet-Draft.** The complete CDDL wire
  grammar is reproduced in the draft's `# Collected CDDL` appendix, which is authoritative;
  `spec/naalp-draft-01.cddl` is demoted to a byte-identical mirror, maintained with the reference
  implementation and machine-validated in CI. A `cddl-mirror` gate asserts the appendix and the file
  are the same bytes, so the two copies cannot silently drift. This makes the draft self-contained for
  submission (a reader needs no external file) and is a documentation/packaging change only — the wire
  grammar itself is unchanged.

### Added

- **Machine-readable wire-constant authority (`spec/wire-constants.csv`).** Beside the CDDL, this is
  the single statement of every wire-affecting envelope constant — the twelve object-body field
  numbers, the protected-header version, the header label, and the recheck extension key and
  procedure ids — each with its value and the identifier as spelled in each port. Two conformance
  gates read it: one compares every port's declared constant against the authority, and a meta-gate
  fails if any envelope constant is left uncompared, closing the class of defect the version split
  belonged to.
- **Mutation-evidence runner (`scripts/mutation_evidence.py` + `scripts/mutation_specs.json`).** A
  data-driven per-capability mutation gate: for each spec it runs the named test unmutated (must
  pass), applies a real compiling mutation, reruns (must fail on the *named assertion*, not a build
  error), reverts the source, verifies the hash, and only then records the proof in
  the recorded-mutation evidence ledger. It cannot fabricate evidence. Retires the plan's named debt with
  real, verified flips in both reference implementations: C15 delegation (rejecting a hop that
  raises its own effect ceiling), C17 continuation (the flow ceiling), and C19 naming (the A2A
  legal-edge table) — Go and Rust. This drops `red_evidence` from 69 unproven pairs to 63.
  Populating the remaining pairs is the ongoing mechanized activity (the runner locally where a
  toolchain exists, and in CI); Swift's 3 pairs record only where its toolchain is present.
- **Standing clean-room harness (`scripts/cleanroom.py`).** Grades
  whether the wire is reproducible from the spec + the independent oracles ALONE, with `impl/`
  reads DENIED: each oracle runs in a subprocess whose file access raises on any read under
  `impl/`, then the regenerated vectors must byte-match the committed corpus. The harness
  self-tests its denial (a probe reading `impl/` must be blocked, or the harness reports itself
  broken). Current grade: 26/26 oracles ran with `impl/` denied, vectors drift-free, 0 spec
  defects — proving the grading path does not secretly depend on the implementation. This is
  published beside the two-implementation grade in `docs/conformance.md`; it is explicitly NOT the
  same as "independent interoperability" (which needs an independently authored implementation,
  Plan I Task 8.3). The CDDL wire-validation leg runs in CI (Linux with ruby/cddl/python).
- **Cheapest-first verification ordering (normative) with a mismatch-flood test.** The draft now
  requires a verifier to reject on the cheapest failing check before it performs the signature
  verification, so a flood of mismatched or malformed objects is rejected on a cheap check without
  spending the expensive cryptographic operation. A Go behavioral test
  (`TestMismatchFloodRejectedBeforeSignature`) proves the ordering: mismatched objects are rejected
  while a counting verifier's call count stays at zero, with a positive control confirming the
  verifier is reached exactly once for a well-formed object.
- **Privacy Considerations (new draft section).** Normative options so personal data need not be
  correlatable or irreversibly retained on an immutable signed record: an optional body salt so
  that identical logical content does not yield a correlatable content id; personal data carried
  only as a salted one-way hash rather than in cleartext; and erasure resolved by destroying the
  off-chain preimage and its salt, which leaves the signed record intact but its personal content
  unrecoverable.
- **WebMCP signing outside the page context (normative).** The signing operation MUST be performed
  outside the page script context, so a compromised or malicious page can request but never forge a
  signature.
- **Requirements §26 (R-ABS-1..3)** records these three absolutes, and `scripts/doc_lint.py` gains
  seven mutation-surviving presence checks (cheapest-first, mismatch-flood, salted-body,
  hash-only-pii, erasure, sign-out-of-page, page-cannot-forge) so the normative text cannot be
  silently dropped from the draft.
- **Editorial status tiering in the Internet-Draft (normative spine vs experimental higher tiers).**
  The draft now states explicitly which surfaces a conforming implementation MUST provide and which
  are optional, so a first conforming implementation is not asked to build the whole surface at once.
  The normative surface required for conformance is the spine — object model, signing, identity,
  effects and authorization, approval and the single-use consume ledger, the baseline audit receipt
  chain, delivery, the per-stream commitment, the transport bindings, and the carriage-never-decodes
  rule — together with the frozen baseline (tier 0) surface of every channel. Every capability above
  tier 0 (the federated higher tier of ordering and any higher channel tier carried through the tier
  field and critical/non-critical extensions) is marked experimental: OPTIONAL, subject to change,
  and an implementation that omits it is still conforming; one that provides it MUST provide it
  exactly as specified and reject an unrecognized critical extension fail-closed. The tiering is
  editorial only — it bounds what conformance requires, not what the reference SDKs provide, which
  remains the full surface across all ten reference languages. Recorded as requirements §27
  (R-TIER-1..3) with five mutation-surviving `doc_lint.py` presence checks.
- **Cross-discipline hardening: ledger path, opaque carriage, effect-abuse note, continuation limit,
  key lifecycle.** Five normative additions to the Internet-Draft, each presence-checked and
  mutation-surviving in `doc_lint.py`, with executed Go tests where the item is a runtime behavior:
  - *Ledger on the spend path only.* The consume ledger is stated to be on the path for a single-use
    approval spend only, not for every object; non-approval and read-only objects verify from their
    own bytes with no ledger access and stay available under partition, while an unreachable ledger
    denies only the spend, fail-closed. Proven by
    `TestPartitionLedgerUnreachableDeniesSpendButNotVerify` (a spend succeeds against a reachable
    ledger and is denied with no state change when it is unreachable, while approval verification
    needs no ledger).
  - *Opaque carriage for every class.* Carriage never decodes or parses the foreign payload; it binds
    the opaque octets by hash under the object content id and signature, normative for every carriage
    class, so no binding adds a foreign-format parser to the verify path.
    `TestPerClassOctetExactRoundTrip` shows every class recovers its foreign octets byte-identically.
  - *Effect-inflation accepted risk.* The effect lattice's abuse direction (a wrapping signer
    inflating effects to force approvals) is stated plainly as an accepted risk, mitigated
    operationally by attribution plus per-signer rate limiting (a deployment control, not a wire
    field).
  - *Continuation-compromise limit.* The security considerations now state that a node compromised
    inside an open flow can keep emitting continuations up to the ceiling; the ceiling bounds the
    damage, it does not prevent it. The flow-ceiling behavior is covered by `TestAboveCeilingRejected`.
  - *Key lifecycle.* Rotation co-signed by old and new key, revocation by the revoked or a recovery
    key, and attribution surviving rotation are exercised by executed drills
    `TestRotationVsSubstitution`, `TestRevocation`, and `TestAttributionAcrossRotation`.
  Recorded as requirements §28 (R-LEDGER-PATH, R-CARRIAGE-OPAQUE, R-EFFECT-ABUSE, R-CONT-LIMIT,
  R-KEYLIFE) with eleven mutation-surviving `doc_lint.py` presence checks.

## [0.1.0] — 2026-07-27

Initial public release: Internet-Draft **draft-bubblefish-naalp-01** and the ten reference SDKs.
Object major version 1; domain-separation prefix `N-AALP/1`. Submission track: IETF Independent
Submission stream (ISE), Informational category, pre-adoption — no working-group consensus is
claimed at this revision.

### Added

- **Object model.** A single deterministic-CBOR object encoding (RFC 8949 §4.2.1) for every
  application-layer meaning, with a `content-id` = `multihash(0x20, SHA-384(body))` and a
  `signer-id` in multiformats `PeerHandle` form. One encoding, one canonical byte form; a
  transport-independent object guarantee.
- **Cryptographic profiles.** COSE_Sign1 (RFC 9052) over the deterministic body; ML-DSA-65 and
  ML-DSA-87 (FIPS 204, deterministic `rnd = 0`) as the post-quantum signature suites; Ed25519
  (RFC 8032) as the classical suite. No classical-only default; post-quantum first.
- **Identity.** The `signer-id` / `PeerHandle` construction, key binding, and the identity object
  that carries an agent's verifiable name.
- **Effect and authorization.** The effect object and the rule that effect *is* authorization — an
  object's declared effect is the unit an approver authorizes and an auditor verifies.
- **Approval.** The approval object: a single-use, independently-verifiable authorization bound to
  a specific effect and consumed exactly once.
- **Audit and federation.** The audit object, deterministic ordering, federated ordering across
  domains, and federation reconciliation.
- **Delivery.** The delivery surface and its receipts.
- **Streaming.** The streamed-object surface layered on N-PAMP's Stream channel.
- **Transport bindings.** Four bindings — N-PAMP, HTTP, WebSocket, and QUIC — each carrying the
  identical object bytes.
- **Carriage by class.** Foreign agent protocols (MCP, A2A, and more) are carried octet-exact by
  carriage **class** inside the governed signed envelope, with a carriage registry and an opaque
  class for unknown payloads.
- **Twenty channel surfaces** (`0x0000`–`0x0013`) and **65 kinds** — one application surface for
  each of N-PAMP's twenty channels, tiered from baseline to the higher tiers (including federated
  ordering and federation reconciliation).
- **Conformance.** The `naalp-conform` runner drives a 239-case op-replay corpus (assembled from
  independent, non-circular oracles anchored to RFC / FIPS / NIST vectors) through each SDK adapter;
  a cross-language deterministic-ML-DSA consensus gate; a machine-validated CDDL (RFC 8610); and a
  registry-drift gate.
- **Reference SDKs (ten languages).** Go and Rust are the primary references and produce
  byte-identical CBOR, signed input, signatures, and digests. Python, TypeScript, Java, Kotlin, and
  Ruby carry full post-quantum crypto and grade 239/239. PHP and Swift are pure-only (their
  ecosystems lack a deterministic ML-DSA seed-keygen path); they grade every non-crypto op plus
  Ed25519 and honestly skip-track the ML-DSA leg. C# is authored and graded in CI. Deterministic
  ML-DSA COSE_Sign1 is byte-identical across seven languages (Go, Rust, Python, TypeScript, Java,
  Kotlin, Ruby). Each SDK ships a package manifest, a high-level object-envelope API, a runnable
  example, tests, and a quickstart.
- **IANA Considerations.** Requests registration of the media type `application/vnd.bubblefish.naalp+cbor`
  (RFC 6838 vendor tree, Expert Review) and establishment of eight N-AALP registries under RFC Required
  (First Come First Served) / Experimental / Private Use policies. The CDDL in `spec/naalp-draft-01.cddl` is the
  byte-level wire authority.

[Unreleased]: https://github.com/bubblefish-tech/naalp_protocol/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bubblefish-tech/naalp_protocol/releases/tag/v0.1.0
