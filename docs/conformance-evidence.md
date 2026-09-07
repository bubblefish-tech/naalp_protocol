<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Conformance Evidence Matrix

This page is an implementation-status matrix in the spirit of [RFC 7942](https://www.rfc-editor.org/info/rfc7942):
per surface, what evidence exists that it works, and exactly what that evidence does and does not
show. As RFC 7942 itself puts it, listing an implementation here **does not imply endorsement**, and
none of this is validated by the IETF. It is the specification authors' own, tooling-derived account
of their reference implementations — not a survey of independent third-party implementations. See
[Limitations](#limitations) for what that distinction means in practice.

For the SDK-by-SDK signing/verification matrix and the clean-room (spec-only) grade, see
[Conformance → Overview](conformance.md); this page complements it with a capability-by-capability
breakdown.

## At a glance

- **33 capability groups** carry recorded mutation evidence — a mutation was applied to the
  implementation, a named test was confirmed to fail on that mutation, and the mutation was then
  reverted — across **322** capability × language pairs.
- **32 of those 33** are evidenced on **all ten reference SDKs** (Go, Rust, Python, TypeScript, Java,
  Kotlin, C#, Ruby, PHP, Swift).
- **1** (the core sign/verify facade shared by every other capability) is evidenced on **2 of 10**
  SDKs so far (Go, Rust); see [Emerging capabilities](#emerging-capabilities).
- **2 properties** additionally carry a machine-checked formal proof (Apalache/TLA+ inductive basis)
  beyond ordinary tests — see [Formal-proof-backed properties](#formal-proof-backed-properties).
- **3 further capabilities** are implemented and conformance-vector-graded on the two reference
  implementations but do not yet have recorded ten-SDK mutation evidence — an honest gap, not a
  silent one (see [Emerging capabilities](#emerging-capabilities)).

## Methodology

Four distinct claims appear in the tables below. They are graded differently and are not
interchangeable:

| Evidence type | What it shows | What it does not show |
|---|---|---|
| **Reference implementation, Go≡Rust≡oracle** | The Go and Rust implementations produce byte-identical output (or, for a state-machine surface, an identical transition/error decision) for the same input, and that output matches an independently constructed expected value — from the relevant RFC, FIPS/NIST known-answer vector, or a from-scratch constructor never derived from the code under test. | Agreement with a third implementation, or with an implementation authored by an unrelated party. |
| **Conformance-vector graded** | The construction is exercised by the shared, non-circular conformance corpus and its CDDL grammar, run by `bash harness/run.sh`. | That every non-Go/Rust SDK has been graded against every vector — see the per-SDK matrix in [Conformance → Overview](conformance.md). |
| **Mutation-tested across SDKs** | For each named language, a real mutation was applied to that language's implementation, a specific test was confirmed to fail because of the mutation (not a compile error or an unrelated failure), and the mutation was reverted. This is the strongest per-language signal on this page: it demonstrates the test can fail, not merely that it currently passes. | That the mutation set is exhaustive, or that every possible defect would be caught. |
| **Formal-proof-backed** | A machine-checked model additionally covers the property, beyond hand-written tests. See [Formal-proof-backed properties](#formal-proof-backed-properties) for the exact, bounded scope of each — these are deliberately not described as general or unbounded formal verification. | General or unbounded formal verification of the protocol. No such claim is made anywhere in this project. |

"✅" in the tables below means the claim in that column heading holds for that row, sourced from the
project's own conformance tooling as of this page's last revision. A dash (—) means the property does
not apply to that surface or has not been separately evidenced.

## Object model, cryptography, and identity

| Surface | Go≡Rust≡oracle | Conformance-vector graded | Mutation-tested across SDKs | Formal proof |
|---|:--:|:--:|:--:|:--:|
| Deterministic CBOR encoding and content identity ([Object Model](../ietf/draft-bubblefish-naalp-01.md#objmodel)) | ✅ | ✅ | 10 / 10 | — |
| Signed object envelope, versioning, and critical extensions ([Object Model](../ietf/draft-bubblefish-naalp-01.md#objmodel)) | ✅ | ✅ | 10 / 10 | — |
| COSE_Sign1 signing — ML-DSA / Ed25519 profiles, and the opt-in composite signature ([Cryptographic Constructions](../ietf/draft-bubblefish-naalp-01.md#crypto)) | ✅¹ | ✅ | 10 / 10 | — |
| Core sign/verify facade (the shared primitive underlying every signed object above) | ✅ | ✅ | 2 / 10 (Go, Rust) | — |
| Identity, self-certifying signer id, and key lifecycle ([Identity](../ietf/draft-bubblefish-naalp-01.md#identity)) | ✅ | ✅ | 10 / 10 | — |
| Rotation object co-signature (old-key + new-key) | ✅ | ✅ | 10 / 10 | — |
| Recheck procedure and per-signer forward-only counter (extension keys 13–14) | ✅ | ✅ | 10 / 10 | — |
| Producing-boundary extension (extension key 15) | ✅ | ✅ | 10 / 10 | — |

¹ The seven full-crypto SDKs are byte-identical on deterministic ML-DSA. PHP and Swift are
pure-language, ML-DSA-signing-optional ecosystems: they build byte-identical objects around an
externally produced signature and honestly skip-track the signing leg. Full detail:
[Conformance → Overview](conformance.md#cross-language-interoperability-matrix).

## Effects, approval, audit, and message lifecycle

| Surface | Go≡Rust≡oracle | Conformance-vector graded | Mutation-tested across SDKs | Formal proof |
|---|:--:|:--:|:--:|:--:|
| Effects, safety vocabulary, and authorization policy ([Effects and Authorization](../ietf/draft-bubblefish-naalp-01.md#effects)) | ✅ | ✅ | 10 / 10 | — |
| Approval and the single-use consume ledger ([Approval](../ietf/draft-bubblefish-naalp-01.md#approval)) | ✅ | ✅ | 10 / 10 | ✅ (bounded inductive basis) |
| Approval state machine ([Object State Machines](../ietf/draft-bubblefish-naalp-01.md#statemachines)) | ✅² | ✅ | 10 / 10 | — |
| Audit chain, causal graph, and ordering ([Audit, Causal Graph, and Ordering](../ietf/draft-bubblefish-naalp-01.md#audit)) | ✅ | ✅ | 10 / 10 | — |
| Typed error objects (N-AALP Error Code registry) | ✅ | ✅ | 10 / 10 | — |
| Audience-scoped approval and refusal ([Trust-decision closure sovereignty](../ietf/draft-bubblefish-naalp-01.md#closure)) | ✅ | ✅ | 10 / 10 | — |

² For a state-machine surface the compared artifact is the transition or error decision the vector
corpus specifies, not a signed object's bytes.

## Delivery, streaming, transport, and carriage

| Surface | Go≡Rust≡oracle | Conformance-vector graded | Mutation-tested across SDKs | Formal proof |
|---|:--:|:--:|:--:|:--:|
| Delivery stages and persist-before-ack ([Delivery](../ietf/draft-bubblefish-naalp-01.md#delivery)) | ✅ | ✅ | 10 / 10 | — |
| Native streaming and per-stream commitment ([Streaming](../ietf/draft-bubblefish-naalp-01.md#streaming)) | ✅ | ✅ | 10 / 10 | — |
| Stream state machine ([Object State Machines](../ietf/draft-bubblefish-naalp-01.md#statemachines)) | ✅² | ✅ | 10 / 10 | — |
| Transport bindings ([Transport Bindings](../ietf/draft-bubblefish-naalp-01.md#transport)) | ✅ | ✅ | 10 / 10 | — |
| Foreign carriage by class, including OPAQUE ([Foreign Carriage by Class](../ietf/draft-bubblefish-naalp-01.md#carriage)) | ✅ | ✅ | 10 / 10 | — |

## Channels and federation

| Surface | Go≡Rust≡oracle | Conformance-vector graded | Mutation-tested across SDKs | Formal proof |
|---|:--:|:--:|:--:|:--:|
| The twenty channel surfaces, 65 kinds ([Channel Surfaces](../ietf/draft-bubblefish-naalp-01.md#channels); per-channel detail: [Channel surfaces](../docs/spec/channels.md), [Registries](../docs/registries.md)) | ✅ | ✅ | 10 / 10 | — |
| Federated reconcile (Federation channel, higher tier) | ✅ | ✅ | 10 / 10 | — |
| Reconcile state machine ([Object State Machines](../ietf/draft-bubblefish-naalp-01.md#statemachines)) | ✅² | ✅ | 10 / 10 | — |
| Collaboration and rooms membership ([Collaboration and Rooms Membership](../ietf/draft-bubblefish-naalp-01.md#additive)) | ✅ | ✅ | 10 / 10 | — |

## Additive object families

| Surface | Go≡Rust≡oracle | Conformance-vector graded | Mutation-tested across SDKs | Formal proof |
|---|:--:|:--:|:--:|:--:|
| Multi-hop delegation grant ([Multi-Hop Delegation Grant](../ietf/draft-bubblefish-naalp-01.md#additive)) | ✅ | ✅ | 10 / 10 | ✅ (bounded inductive basis) |
| MCP tool-call binding ([MCP Tool-Call Binding](../ietf/draft-bubblefish-naalp-01.md#additive); protocol mapping: [MCP](mappings/mcp.md)) | ✅ | ✅ | 10 / 10 | — |
| Description and directory ([Description and Directory](../ietf/draft-bubblefish-naalp-01.md#additive)) | ✅ | ✅ | 10 / 10 | — |
| Name bindings and A2A task transitions ([Name Bindings and A2A Task Transitions](../ietf/draft-bubblefish-naalp-01.md#additive); protocol mapping: [A2A](mappings/a2a.md)) | ✅ | ✅ | 10 / 10 | — |
| Governed negotiation, advisory risk labels, and trust references ([Governed Negotiation](../ietf/draft-bubblefish-naalp-01.md#additive), [Advisory Risk Labels](../ietf/draft-bubblefish-naalp-01.md#additive)) | ✅ | ✅ | 10 / 10 | — |
| Flow continuations ([Flow Continuations](../ietf/draft-bubblefish-naalp-01.md#additive)) | ✅ | ✅ | 10 / 10 | — |
| Payment import, UI consent, and portable gateway evidence — payment leg (`naalp-payment-import` / `naalp-payment-charge-binding`) | ✅ | ✅ | 10 / 10 | — |
| Payment import, UI consent, and portable gateway evidence — UI consent events (`naalp-ui-event`) | ✅ | ✅ | 10 / 10 | — |
| Payment import, UI consent, and portable gateway evidence — gateway decision (`naalp-gateway-decision`) | ✅ | ✅ | 10 / 10 | — |
| Manufacturing physical-hazard claims and authorizations ([Manufacturing Physical-Hazard Claims and Authorizations](../ietf/draft-bubblefish-naalp-01.md#additive)) | ✅ | ✅ | 10 / 10 | — |

## Emerging capabilities

Three further object families are specified, implemented in the two reference implementations, and
covered by their own conformance-vector corpus, but do not yet have recorded ten-SDK mutation
evidence — the same bar every row above meets. Recorded here as an open, tracked gap rather than
folded silently into the tables above:

| Surface | Go/Rust implemented | Conformance vectors exist | Ten-SDK mutation evidence |
|---|:--:|:--:|:--:|
| Governed-decision records ([Governed-Decision Records and Transparency Log Primitives](../ietf/draft-bubblefish-naalp-01.md#additive)) | ✅ | ✅ | not yet recorded |
| Transparency-log checkpoints and inclusion proofs ([Governed-Decision Records and Transparency Log Primitives](../ietf/draft-bubblefish-naalp-01.md#additive)) | ✅ | ✅ | not yet recorded |
| Portable egress evidence ([Portable Egress Evidence](../ietf/draft-bubblefish-naalp-01.md#additive)) | ✅ | ✅ | not yet recorded |

## Formal-proof-backed properties

Two properties beyond the object model additionally carry a machine-checked proof, run with
[Apalache](https://apalache-mc.org/) against a TLA+ model. Both are deliberately scoped and described
as an **inductive basis over a bounded predecessor window with unbounded field values** — never as
general or unbounded formal verification, a phrase this project does not use for either property:

- **Delegation-chain monotone attenuation.** A descendant grant in a multi-hop delegation chain never
  holds more effect, scope, or realized-depth budget than any of its ancestors. Checked as an
  inductive basis (base case, inductive step, and a non-vacuity check that a genuine multi-hop
  predecessor exists) over predecessor chains of up to three grants, with every field left symbolic
  and unbounded. A companion bounded relational (Alloy) model separately checks the same invariant
  exhaustively over chains of up to three hops. The extension of the inductive basis to a chain of
  arbitrary length rests on a documented, pen-and-paper locality argument, not an additional
  machine-checked fact.
- **Consume-ledger exactly-once and fork-non-silence.** The first consumer to append for a given
  approval id wins a compare-and-set; a second append for the same id is rejected. Two
  ledger-signed consume receipts naming the same approval id that are not byte-identical surface as
  fork evidence and are never silently accepted, while two byte-identical receipts are recognized as
  a benign duplicate. Checked as an inductive basis over predecessor ledger histories of up to three
  records per side, with every field left symbolic and unbounded, additive to the existing
  race-condition tests. As with the attenuation property, extension to an arbitrarily long two-sided
  history rests on a documented, pen-and-paper locality argument, not an additional machine-checked
  fact.

## Limitations

- **This is a self-reported matrix, not third-party validation.** Per RFC 7942's own framing, listing
  a construction here does not imply endorsement by the IETF or by any party other than the
  specification's authors, and nothing here has been independently audited.
- **Independent interoperability is not yet demonstrated.** All ten reference SDKs come from one
  author, one reading of the specification, and one shared conformance corpus. That is strong
  evidence the specification is precise enough to implement consistently; it is not the same claim as
  interoperability between implementations built independently, by unrelated parties, from the
  specification text alone. That stronger claim is not made anywhere in this project and remains
  open.
- **PHP and Swift are pure-language, ML-DSA-signing-optional ecosystems.** They build byte-identical
  objects around an externally produced post-quantum signature rather than signing with a
  deterministic ML-DSA implementation of their own. See
  [Conformance → Overview](conformance.md#cross-language-interoperability-matrix) for the exact,
  per-SDK breakdown.
- **Ten-SDK coverage is a floor, not a ceiling, and it moves.** This page reflects the mutation
  evidence recorded as of its last revision; the [Emerging capabilities](#emerging-capabilities)
  section is the mechanism by which a newly specified capability is tracked honestly until it reaches
  the same ten-SDK bar as everything above it, rather than being asserted early.
- **Mutation testing demonstrates that named tests can fail, not that every defect would be caught.**
  A mutation set proves a test suite is not vacuous; it is not a claim of exhaustive fault coverage.
- **Formal proofs here are bounded.** Both proofs in this page use a small, explicitly bounded
  predecessor window with every field left symbolic; neither is a general or unbounded formal
  verification claim, and no such claim exists anywhere in this project for either property or for
  the specification as a whole.

## See also

- [Conformance → Overview](conformance.md) — the three grading gates, the non-circular oracle table,
  the SDK-by-SDK signing/verification matrix, and the clean-room (spec-only) grade.
- [The twenty channels](spec/channels.md) and [Channel surfaces](channels/control.md) — per-channel
  detail.
- [Registries](registries.md) and [Error codes](registries/error-codes.md) — the machine-readable
  registries the vector corpus and this matrix are checked against.
- [Internet-Draft](../ietf/draft-bubblefish-naalp-01.md) — the normative specification, including its
  own RFC 7942 Implementation Status section and Appendix A (Collected CDDL).
