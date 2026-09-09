<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Conformance Matrix

This matrix maps every normative requirement in `requirements.md` to the mechanism that
implements it, the gate that grades it, and its current status. Part A is the
requirement-by-requirement matrix; Part B is an honest implementation-status and roadmap
note in the spirit of RFC 7942.

Status is grounded in artifacts, never asserted by hand:

- `requirements.md` — the normative requirement ids (R-*), each with a Verify note.
- `scripts/run_gates.py` — the gate suite; self-testing (each gate proves it can fail
  before its check is trusted).
- `vectors/` + `tools/` — the non-circular conformance corpus and its independent oracles.
- `docs/conformance.md` — the cross-language grading narrative.
- `scripts/doc_lint.py`, `scripts/partition_case.py` — the Security-Considerations graders.

## Grading model

A requirement is **met** when its mechanism is wired in the two reference implementations
(Go, Rust), its bytes are graded byte-identical against a non-circular oracle, and its gate
is green. A requirement is **unmet** when its claim is not yet earned by a passing gate, or
when the mechanism is specified but work remains to complete it; that remaining work is
tracked in the implementation roadmap (Part B). "Graded on two references" is stated as
exactly that, never as ten-port or independent-party interoperability.

## Gate snapshot — `python scripts/run_gates.py`

| gate | self-test | check |
|---|---|---|
| claims_have_evidence | can fail | PASS |
| copyright_headers | can fail | PASS |
| identity_of_record | can fail | PASS |
| protocol_naming | can fail | PASS |
| no_unwatched_wire_constant | can fail | PASS |
| wire_constants | can fail | PASS |

Security-Considerations graders: `doc_lint.py` PASS (29/29 required phrases), `partition_case.py`
PASS (baseline partition-deny graded non-conforming for local spend, conforming for deny).

Wire truth: the protected-header `naalp-version` is `2` across all ten ports, and every
envelope wire constant is watched against `spec/wire-constants.csv` (the single
machine-readable authority, projected into all ten ports by `gen_wire_constants.py` and
compared per port by the wire-constant gate). Remaining coverage — full ten-port
capability/test parity and per-capability mutation evidence — is tracked in the
implementation roadmap (Part B).

---

## Part A — Requirement conformance by section

Status legend: **met** (graded on two references, gate green) · **met²** (graded on the two
references; ten-port capability coverage in progress — see Part B) · **partial** (met except
the sub-item named) · **unmet** (remaining work tracked in Part B).

### Goals

| id | mechanism / evidence | status |
|---|---|---|
| G-1..G-10, G-12, G-13 | traced by ≥1 requirement; forward/backward gap lists empty (`requirements.md` exit check) | met |
| G-11 two independent interoperable implementations | Go+Rust byte-identical on the corpus; an independent-party implementation trial is planned (Part B) | unmet |

### §0 Scope, naming, principles

| id | mechanism / evidence | status |
|---|---|---|
| R-0.1 transport-independent guarantees | C11 transport bindings (one object, four bindings) | met |
| R-0.2 no product name in normative text | `protocol_naming` gate PASS | met |
| R-0.3 no single-vendor dependency | corpus satisfiable from published standards + N-PAMP | met |
| R-0.4 verifiable by an independent party | independent build trial planned (Part B) | unmet |
| R-0.5 non-scope stated in one place | §17 present | met |

### §1 Substrate relationship (N-PAMP)

| id | mechanism / evidence | status |
|---|---|---|
| R-1.1..R-1.5 | substrate rules stated once; C11/C12 grade the bindings and carriage | met |

### §2 Signed object envelope (spine)

| id | mechanism / evidence | status |
|---|---|---|
| R-2.1 one envelope, one encoding | C3 envelope | met |
| R-2.2 byte-identical signed input across implementations | Go==Rust byte-identical; wire constants projected and watched across all ten ports (`spec/wire-constants.csv`) | met² |
| R-2.3 signature binds identity/kind/channel/signer/time/effect/causes/payload | C3 tamper vectors | met |
| R-2.4 offline verify | C2/C3 offline path | met |
| R-2.5 version + critical-extension mechanism | recheck T1.3 (version 2, cext reject) graded on Go/Rust; protected-header version 2 aligned across all ten ports | met² |
| R-2.6 no unsigned state-changing object | C5/C6 | met |

### §3 Encoding (deterministic CBOR + CDDL)

| id | mechanism / evidence | status |
|---|---|---|
| R-3.1 deterministic CBOR | C1 | met |
| R-3.2 CDDL is the byte-level authority | C14 (`cddl_check.sh` validates vectors); the authority is projected into all ten ports from `spec/wire-constants.csv` | met |
| R-3.3 encoding edge cases | C1/C3 edge vectors | met |
| R-3.4 reject malformed, no partial apply | fail-closed paths | met |

### §4 Cryptography and profiles

| id | mechanism / evidence | status |
|---|---|---|
| R-4.1..R-4.8 crypto-agility, PQ default, profiles, hashes, registries | C2 graded; deterministic ML-DSA byte-identical on the seven full-crypto ports | partial |
| — signing leg on PHP and Swift | pure-only ecosystems; object bytes byte-identical around an external signature, signing leg honestly skip-tracked (Part B) | unmet |

### §5 Identity and key lifecycle

| id | mechanism / evidence | status |
|---|---|---|
| R-5.1 self-certifying signer id | C4 | met |
| R-5.2 rotation continuity (signed link) | C4 mechanism graded; executed rotation drill outstanding (Part B) | partial |
| R-5.3 revocation distinct from rotation | C4 mechanism graded; executed revocation drill outstanding (Part B) | partial |
| R-5.4 foreign identity by cross-signature only | C4 | met |

### §6 Effects and safety

| id | mechanism / evidence | status |
|---|---|---|
| R-6.1..R-6.5 closed effect vocabulary, fail-closed unknown, effect-as-authorization, safety label, no metadata authority | C5 | met |

### §7 Approval and single-use consume ledger

| id | mechanism / evidence | status |
|---|---|---|
| R-7.1..R-7.4 argument-bound approval, single-use consume, no replay, held result | C6; T1.5 ledger-signed consume receipt | met |
| — ledger writes confined to approval paths + fuller partition test | baseline deny graded (R-SEC-3); confinement + network-partition test outstanding (Part B) | partial |

### §8 Audit, receipts, ordering, time

| id | mechanism / evidence | status |
|---|---|---|
| R-8.1..R-8.6 hash-chained receipts, ordering by receipt, fork proof, time anchor, causal order, tiered ordering | C7, C7.1 two-signature ForkProof, T13 federation | met |

### §9 Delivery and the live switchboard

| id | mechanism / evidence | status |
|---|---|---|
| R-9.1..R-9.4 delivery stages, persist-before-ack, switchboard, content-free relay | C8 | met |

### §10 Streaming (native full-duplex)

| id | mechanism / evidence | status |
|---|---|---|
| R-10.1..R-10.6 stream on 0x000C, one commitment, effect+approval, transport map, full-duplex, distinct from Bridge | C9 | met |
| — per-chunk streaming effect | ranked add-on, not yet specified (Part B) | unmet |

### §11 Channel surfaces (all twenty, tiered)

| id | mechanism / evidence | status |
|---|---|---|
| R-11.1..R-11.4 twenty channels, per-kind effect/state, one spine, baseline+higher tiers | C10 (20 channels, 65 kinds) | met |
| — normative vs experimental status labelling in the draft | editorial tiering outstanding (coverage stays ten) (Part B) | unmet |

### §12 Magnify and compound

| id | mechanism / evidence | status |
|---|---|---|
| R-12.1..R-12.3 three holes filled once, causal derivation graph, time-consistency | C5/C6/C7 | met |

### §13 Transport bindings and confidentiality delegation

| id | mechanism / evidence | status |
|---|---|---|
| R-13.1..R-13.4 four bindings, object security everywhere, confidentiality split, sensitive-payload refusal | C11 | met |
| — additional bindings (browser-context, editor-agent) | outstanding bindings (Part B) | unmet |

### §14 Foreign-protocol carriage (by class)

| id | mechanism / evidence | status |
|---|---|---|
| R-14.1..R-14.8 carriage by class, OPAQUE, N-AALP semantics, Bridge byte-exact, transparent, registry, no foreign authority, per-class vectors, typed mapping error | C12 | met |
| — carriage-never-decodes stated normatively across all eight bindings | editorial remediation outstanding (Part B) | unmet |
| — attestation carriage | ranked add-on (Part B) | unmet |

### §15 / §15A Profiles, editions, channel tiers

| id | mechanism / evidence | status |
|---|---|---|
| R-15.1..R-15.3, R-15.5 | one wire format, bound profile, no downgrade, aligned names | met |
| R-15.4 all editions pass the same corpus | protected-header version aligned (2) across all ten ports, wire-constant gate green; full ten-port corpus coverage tracked in Part B | met² |
| R-15A.1..R-15A.3 channel tiers, baseline frozen, federation as a tier | tier model graded | met |

### §16 Conformance and two-implementation parity

| id | mechanism / evidence | status |
|---|---|---|
| R-16.1 non-circular corpus | oracles cite RFC/FIPS/NIST/independent constructors | met |
| R-16.2 two implementations byte-identical | Go==Rust on the corpus; ten-port and independent-party coverage tracked in Part B | met² |
| R-16.3 honest implementation status | per-capability mutation-evidence recording in progress (Part B) | unmet |
| R-16.4 completion gate (negative + recovery + e2e) | pending full mutation-evidence coverage (Part B) | unmet |

### §17 Non-scope

| id | mechanism / evidence | status |
|---|---|---|
| §17 exclusions | stated; completeness review maps components to in-scope requirements | met |

### §18 Adoption and developer experience

| id | mechanism / evidence | status |
|---|---|---|
| R-18.1 reference implementations + copy-paste quickstarts | ten ports exist; the eight non-reference ports do not yet carry the full -01 capability set and quickstarts (Part B) | unmet |
| R-18.2 rendered docs site | `mkdocs.yml` + docs tree present; landing quickstart / page-per-primitive / verify-it-yourself outstanding (Part B) | partial |
| R-18.3 machine-readable registries, drift-checked | `registry_drift.py` green | met |
| R-18.4 runnable conformance harness | `harness/run.sh` | met |
| R-18.5 decision records | `docs/adr/` present; the six definition documents outstanding (Part B) | partial |
| R-18.6 OPAQUE + experimental/private ranges | C12 | met |
| R-18.7 permissive licence | `LICENSE.md` Apache-2.0 | met |

### §19 Multi-hop agent delegation (R-DEL-1..8)

| id | mechanism / evidence | status |
|---|---|---|
| R-DEL-1..8 grant object, actor-signs-action, separate signed grant, attenuation, chain-to-root, fail-closed, depth bound, delegation+approval composition | C15 graded on Go/Rust incl. the deny that rejects a hop raising its own effect ceiling (`CapExceedsParent`) | met² |

### §20 Offline-verification limits (R-SEC-1..10)

| id | mechanism / evidence | status |
|---|---|---|
| R-SEC-1..2, R-SEC-4..10 text | `doc_lint.py` PASS (29/29 phrases, mutation-surviving) | met |
| R-SEC-3 baseline partition-deny | `partition_case.py` PASS (local spend under unreachable ledger graded non-conforming) | met |

### §21–§25 Companion primitives (C17–C22)

| id | mechanism / evidence | status |
|---|---|---|
| R-CONT-1..7 (C17 flow continuation) | graded on Go/Rust; folded into the master corpus for the 8 ports via the content-id op | met² |
| R-DESC-1..8 (C18 signed description) | graded on Go/Rust | met² |
| R-NAME-1..6, R-A2A-1..7 (C19 name bindings + A2A task state) | graded on Go/Rust | met² |
| R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4 (C20 negotiation/risk/trust) | graded on Go/Rust; TRUST text doc-lint PASS | met² |
| R-PAY-1..6, R-AGUI-1..6, R-GW-1..6 (C21 payment/UI/gateway) | graded on Go/Rust | met² |
| R-TDCS-1..6 (C22 trust-decision closure sovereignty) | graded on Go/Rust: R-TDCS-2/4 behavioural graders (determinism, freshness-independence); R-TDCS-3/5 (refusal, audience) Go==Rust==oracle byte-parity + the CDDL grammar validates the audience approval and both refusals and rejects the malformed shapes; R-TDCS-1 property + 3-shape schema doc-lint (mutation-surviving) + the input-class registry drift-checked CSV==CDDL (`registry_drift.py`); R-TDCS-6 inherits the graded C15 delegation attenuation | met² |
| — intent echo (novelty + mechanism gated) | held behind its gates (Part B) | unmet |

---

## Part B — Implementation status and roadmap

In the spirit of RFC 7942, this section records what is graded today and what remains, so
that no status in Part A claims more than a gate has verified. Nothing listed here is a
conformance claim beyond what the named grader has actually graded.

### Graded today

- **Two reference implementations, byte-identical.** `impl/go` and `impl/rust` produce
  byte-identical CBOR, signed input, signatures, and digests across the full conformance
  corpus, graded against non-circular oracles (RFC / FIPS / NIST vectors and independent
  constructors in `tools/`).
- **One wire-constant authority across ten ports.** `spec/wire-constants.csv` is projected
  into all ten language ports (C#, Go, Java, Kotlin, PHP, Python, Ruby, Rust, Swift,
  TypeScript) by `gen_wire_constants.py` and compared per port by the wire-constant gate;
  the protected-header `naalp-version` is `2` everywhere.
- **Post-quantum signing.** Deterministic ML-DSA signing is byte-identical on the seven
  full-crypto ports. PHP and Swift are verify-oriented ecosystems: object bytes are
  byte-identical around an externally produced signature, and the signing leg is explicitly
  skip-tracked rather than silently claimed.
- **Security-Considerations text.** Graded by `doc_lint.py` (29/29 required phrases,
  mutation-surviving) and `partition_case.py` (baseline partition-deny).

### Remaining work (tracked in the implementation roadmap)

- **Ten-port capability parity.** Extending every companion capability, with exercised
  tests, from the two references to the eight remaining ports (the `met²` rows above).
- **Recorded mutation evidence.** Completing per-capability, per-language recorded-mutation
  coverage in CI, so every test is proven able to fail.
- **Independent-party interoperability.** A clean-room independent implementation trial;
  until it runs, conformance is stated as "graded on two references", never more.
- **Key-lifecycle drills.** Executing and recording the rotation and revocation drills
  (the mechanisms are already graded).
- **Approval-ledger hardening.** Confining ledger writes to approval paths and adding the
  fuller network-partition test beyond the graded baseline deny.
- **Editorial items.** Normative-vs-experimental labelling per surface,
  carriage-never-decodes stated normatively per binding, privacy considerations
  (salted-body option, hash-only personal data, erasure resolution), per-signer
  rate-limiting note, and the E-1 limit carried verbatim.
- **Adoption surface.** Quickstarts in all ten languages, an ergonomic sign/verify layer
  and CLI per language, the rendered docs-site quickstart / page-per-primitive /
  verify-it-yourself sections, MCP and A2A adapters (Python, TypeScript), typed verify
  results, an evidence explorer, and the six definition documents.
- **Ranked add-ons.** Per-chunk streaming effect, compact audit-signal profile,
  attestation carriage, intent echo (held behind its novelty and mechanism gates), the
  browser-context and editor-agent bindings, and a composed-stack security analysis.

---

## Exit condition

Every requirement id in `requirements.md` appears in Part A with an honest status. Every
requirement not yet fully met maps to a remaining-work item in Part B. No status claims
more than a passing gate has graded.
