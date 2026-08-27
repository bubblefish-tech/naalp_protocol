<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# NAEP-0000 — The N-AALP Enhancement Proposal Process

| | |
|---|---|
| **NAEP** | 0000 |
| **Title** | The N-AALP Enhancement Proposal Process |
| **Author** | Shawn Sammartano, BubbleFish Technologies, Inc. (`naalp-editor@bubblefish.sh`) |
| **Type** | Process |
| **Status** | Active |
| **Created** | 2026-07-29 |
| **Requires** | — |
| **Supersedes** | — |
| **Discussion** | GitHub issues/PRs on this repository, label `naep` |

> This is a **meta-NAEP**: it defines the NAEP process itself, and it is never
> "completed". Like it does for the meta-documents of the projects it draws on
> (Python's PEP 1, the Rust RFC `README`, the Kubernetes KEP `README`, and the
> substrate project's NEP-0000), the `Active` status marks a Process document
> that stays in force until a later NAEP supersedes it.

This process operates within the project's governance model:
[`GOVERNANCE.md`](../GOVERNANCE.md) defines who decides and by what rule — a NAEP is
the proposal-scale container for the normative-change process — and
[`MAINTAINERS.md`](../MAINTAINERS.md) lists the maintainers who review a NAEP and
help enforce its §6 Final gate. It extends, and does not replace, the three-layer
decision history that [`CONTRIBUTING.md`](../CONTRIBUTING.md) already defines
(ADRs in [`docs/adr/`](../docs/adr/), the in-draft change log, and issue/PR
labels).

N-AALP is the **Native Agentic Application Layer Protocol**
(`draft-bubblefish-naalp-00`), an application-layer **object** protocol offered
through the IETF **Independent Submission** stream (Informational category,
pre-adoption). It is carried by — and specified independently of — its substrate,
**N-PAMP** (`draft-bubblefish-npamp-01`); the two are separate documents with
separate concerns, and a NAEP governs changes to **N-AALP**, not to the substrate.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
and only when, they appear in all capitals.

---

## Abstract

A **NAEP** (N-AALP Enhancement Proposal) is the design document a contributor
writes to propose, justify, and specify a substantial change to N-AALP: a new
channel surface, a new object kind, a new carriage class, a change that alters
bytes on the wire (the CBOR object envelope, the deterministic canonicalization,
the signed input, the content-id/signer-id derivation, or the COSE_Sign1
profile), or a new code-point range or registration policy. The NAEP is where the
*why*, the *considered alternatives*, the normative *specification text*, and the
*evidence that the change is implementable and gradable* are gathered in one
reviewable place before the change lands in the draft, the registries, the CDDL,
or the reference implementations.

This document defines what a NAEP is, when one is REQUIRED versus when a smaller
change may proceed with only a pull request and an Architecture Decision Record
(ADR); the NAEP lifecycle (`Draft → Review → Accepted / Rejected → Final /
Withdrawn`); the sections every NAEP MUST contain; the numbering and directory
convention (`process/NAEP-NNNN-slug.md`); and — the load-bearing rule of this
process — that **a Standards-Track NAEP MUST NOT reach `Final` until it has at
least one working reference implementation AND machine-gradable, non-circular
conformance vectors.** A NAEP that specifies behavior but ships no implementation
and no vectors is at most `Accepted`; it is never `Final`. That rule is what keeps
N-AALP a protocol whose every normative claim is backed by executable evidence
rather than prose — two byte-identical reference implementations agreeing with an
independent oracle, the wire grammar machine-validated, and a cross-language SDK
set graded against a pinned corpus.

The NAEP process sits *above*, and feeds, the three-layer decision history that
`CONTRIBUTING.md` already defines. It does not replace any of them.

## Motivation

This repository already records decisions well. `CONTRIBUTING.md` defines a
three-layer history — a MADR-style ADR in [`docs/adr/`](../docs/adr/) for every
load-bearing decision, a per-revision change-log appendix in the draft, and
`design`/`editorial` issue labels per RFC 8874. That machinery is excellent for
capturing *what was decided and why after the fact*.

What it does not provide is a **container for a proposal that is too large for a
single ADR** — a change that touches the object wire format, introduces a whole
new channel surface or carriage class, or opens a new code-point range, and
therefore needs its own motivation, its own considered-options analysis,
backwards-compatibility reasoning, a reference implementation, and conformance
vectors, all reviewed as one unit before it lands. An ADR is a paragraph-scale
record of a decision; a NAEP is the document-scale proposal that *produces* one or
more ADRs when it is accepted.

Every comparable protocol/standards project reached the same conclusion and built
the same kind of instrument:

- The **IETF** distinguishes an editorial nit (fixed in the next revision) from a
  normative change that alters interoperability and must be argued on its merits
  (RFC 2026 process; RFC 7282 rough consensus; RFC 8126 for registry changes).
  N-AALP is offered through the IETF **Independent Submission** stream (RFC 4846),
  where the document author/editor — not a working-group vote — is responsible for
  each decision.
- **Python** created **PEP 1**: a numbered proposal with a fixed set of headers
  and sections, a `Draft → Accepted → Final` lifecycle, and the explicit rule that
  *"the reference implementation must be completed before any PEP is given status
  'Final'."*
- **Rust** created the **RFC process**: a Markdown proposal, a template
  (Summary/Motivation/Guide-level/Reference-level/Drawbacks/Alternatives/Prior
  art/Unresolved/Future), a Final Comment Period, and a hard separation between an
  *accepted* RFC and the *implementation* that a separate tracking issue chases —
  "being 'active' is not a rubber stamp".
- **Kubernetes** created the **KEP process**: a numbered directory per proposal,
  maturity stages, and graduation gates that *require tests* — for a feature to
  reach GA, "the graduation criteria must include conformance tests" and "all GA
  endpoints must be hit by conformance tests".
- The **substrate project** codified the same principle in **NEP-0000** for
  N-PAMP. NAEP is the N-AALP-layer sibling of that process, adapted to N-AALP's
  own conformance model (two byte-identical reference implementations, an
  independent oracle set, a machine-validated CDDL, and a ten-language SDK
  corpus) rather than N-PAMP's transport machinery.

The NAEP process adopts the parts of these that fit an Independent-Submission,
single-editor, evidence-first protocol repo, and rejects the parts that assume a
working group or a multi-maintainer vote. In particular, from PEP 1 and KEP it
takes the principle that **a proposal is not "done" until it is implemented and
independently graded**, and binds that principle to the assets this repository
already ships: two byte-identical reference implementations, ten-language SDK
adapters, an independent Python oracle set anchored to published standards, a
machine-validated wire grammar, and a pinned conformance corpus.

## Specification

### 1. What a NAEP is

A NAEP is a Markdown document in [`process/`](.), numbered `NAEP-NNNN`, that
proposes and specifies one coherent change to N-AALP and carries it from idea to
implemented, graded reality. A NAEP has one **Author** (who MAY be the document
editor) and a single **Status** at any time. Its normative specification text,
once the NAEP is `Accepted`, is merged into the governing document it targets (the
Internet-Draft, the CDDL wire authority
[`spec/naalp-draft-00.cddl`](../spec/naalp-draft-00.cddl), or a registry under
[`vectors/registry/`](../vectors/registry/)); the NAEP remains as the durable
record of the proposal and its rationale.

There are three **types** of NAEP (the PEP 1 taxonomy):

| Type | Purpose | Example |
|---|---|---|
| **Standards Track** | Adds or changes normative, on-the-wire or registry behavior. | A new channel surface; a new object kind; a new carriage class; an object-wire-format change; a new code-point range. |
| **Informational** | Describes a design issue, guideline, or convention without changing normative behavior. | A cross-implementation style guide; a worked-example convention. |
| **Process** | Changes how the project itself operates. | This document (NAEP-0000); a change to the review workflow. |

Only **Standards Track** NAEPs are subject to the reference-implementation and
conformance-vector gates for `Final` (§6). Informational and Process NAEPs use the
reduced lifecycle of §5.6.

### 2. When a NAEP is REQUIRED

A change **MUST** be proposed as a Standards Track NAEP if it does any of the
following:

1. **Adds, removes, or repurposes a channel surface or an object kind** — any
   change to [`vectors/registry/channels.csv`](../vectors/registry/channels.csv)
   that assigns a new channel code point (the twenty channels occupy
   `0x0000`–`0x0013`), adds or repurposes an object kind, changes a kind's
   **effect class** (`read_only`, `idempotent_write`, `non_idempotent_write`,
   `destructive`, or `variable`), or changes a channel's minimum profile. Because
   the effect class is the authorization primitive ([ADR-0004](../docs/adr/0004-effect-is-authorization.md)),
   any change to it is normative and wire-observable.
2. **Adds or changes a carriage class** — any change to the set of carriage
   classes (`JSONRPC`, `HTTP`, `MSG`, `STREAM`, `DOC`, `OPAQUE`) defined by the
   carriage-by-class design ([ADR-0005](../docs/adr/0005-carriage-by-class.md)). A
   **new** carriage class is a NAEP; a thin per-protocol mapping onto an
   **existing** carriage class is a §3 registration, not a NAEP.
3. **Is object-wire-affecting** — anything an interoperating implementation must
   change its byte-level behavior to accommodate: the CBOR object-envelope
   geometry, the protected-header map keys (including `naalp-version`, key 3), the
   deterministic CBOR canonicalization (RFC 8949 §4.2.1), the signed-input
   construction, the content-id or signer-id derivation, the COSE_Sign1 profile
   (RFC 9052), or the signature/multicodec suite sets. `CONTRIBUTING.md` already
   flags these as **major-version** changes (a new object version, and if
   warranted a new media type alongside `application/naalp+cbor`); such a change
   **MUST** be carried by a NAEP.
4. **Opens or re-policies a code-point range** — creating a new registry, adding a
   new range to an existing registry, or changing a range's **registration
   policy** (for example, converting a range from "Specification Required" to
   "Experimental", per RFC 8126). Registries in scope include
   [`channels.csv`](../vectors/registry/channels.csv),
   [`signatures.csv`](../vectors/registry/signatures.csv),
   [`multicodec.csv`](../vectors/registry/multicodec.csv), and
   [`protocols.csv`](../vectors/registry/protocols.csv), together with the
   effect-class and error-code registries defined in the draft, all collected in
   the Internet-Draft's IANA Considerations.

This mirrors the Rust "substantial change" trigger and the KEP "non-trivial
change" trigger: a NAEP is for changes that other implementers must reason about,
not for changes visible only to this repository's editors.

### 3. When a NAEP is NOT required

The following changes proceed through the existing pull-request + ADR path in
`CONTRIBUTING.md` and **MUST NOT** be inflated into a NAEP:

1. **Editorial fixes** — wording, formatting, examples, typo/`idnits` cleanup, or
   non-normative clarification (the `editorial` label of `CONTRIBUTING.md`).
2. **A single additive code-point registration within an existing range whose
   policy already permits it** — e.g. registering one new carriage `protocol_id`
   in the "standards" range `0x01`–`0x0F` of
   [`protocols.csv`](../vectors/registry/protocols.csv), or one new multicodec or
   signature code point in an additive registry. Per RFC 8126, a Specification
   Required registration needs a stable public specification reviewed by the
   designated expert, **not** a NAEP. A registration in the Experimental
   (`0x10`–`0x7F`) or Private (`0x80`–`0xFF`) carriage range needs no registration
   at all. Such an additive registration still gets an ADR and a change-log
   bullet.
3. **A thin per-protocol mapping onto an already-defined carriage class** — e.g. a
   new mapping that reuses `JSONRPC`/`HTTP`/`MSG`/`STREAM`/`DOC`/`OPAQUE`. It is a
   registration (item 2) plus a short document; it needs a NAEP only if it
   introduces a *new* carriage class (§2.2).
4. **Reference-implementation-only changes** — bug fixes, refactors, added
   language ports, or test additions that do not change any normative document,
   registry, CDDL rule, or vector.
5. **Non-normative repository mechanics** — CI, scripts, tooling, or pin/manifest
   maintenance that changes no normative artifact.

> Rule of thumb, taken from Rust: if the change "changes shape but not meaning"
> for an interoperating peer, it is not a NAEP. If a conforming implementation on
> the other end — the party that receives and verifies the object — would have to
> change to keep interoperating, it is. Because N-AALP is an **object** protocol
> ([ADR-0002](../docs/adr/0002-object-not-connection.md)), "the other end" is
> whoever verifies the object, over any transport, not a connection peer.

When in doubt, open an issue labelled `naep` and ask the editor; the editor
decides whether a NAEP is REQUIRED before any specification text is merged.

### 4. Numbering and directory convention

1. NAEPs live in [`process/`](.) and are named `NAEP-NNNN-slug.md`, where `NNNN`
   is a **4-digit, zero-padded** integer and `slug` is a short lowercase,
   dash-separated phrase (e.g. `process/NAEP-0007-spatial-frame-provenance.md`).
2. `NAEP-0000` (this document) is the meta-NAEP. Numbers are assigned **in
   ascending order** by the editor when a Draft is first accepted for the queue
   (the number is the proposal's identity for its whole life; it is **not** the
   GitHub PR number, to keep NAEP numbers stable and gap-free).
3. A NAEP's number **MUST NOT** be reused, even if the NAEP is `Rejected` or
   `Withdrawn`; a withdrawn number is retired with the NAEP.
4. Each NAEP begins with the metadata table shown at the top of this document
   (NAEP, Title, Author, Type, Status, Created, Requires, Supersedes, Discussion)
   and MAY add `Replaces`/`Superseded-By` when relevant.

### 5. The NAEP lifecycle

```
                 editor queues it
   (author writes)      │
        Draft ──────────┴────────► Review ──────► Accepted ──────► Final
          │                          │               │  \             ▲
          │ author abandons          │ editor        │   \  (2 ref    │
          ▼                          ▼ rejects       │    \  impls +   │
      Withdrawn                  Rejected             │     \  vectors  │
          ▲                          ▲                │      \  land)   │
          │                          │                │       └─────────┘
          └──────── author can withdraw at any pre-Final state ────────┘
```

The states, grounded in PEP 1 (`Draft → Accepted → Final`, plus
`Rejected`/`Withdrawn`) and the Rust RFC flow (draft → Final Comment Period →
accepted; postponed/closed):

#### 5.1 Draft
The author is actively writing. A NAEP enters `Draft` when it is opened as a pull
request adding `process/NAEP-NNNN-slug.md`. A Draft may change freely. It carries
no normative weight; nothing may cite a `Draft` NAEP as settled.

#### 5.2 Review
The author has declared the NAEP ready and the editor has opened the review
window. Discussion happens on the issue/PR under the `naep` label; the editor
seeks **rough consensus** in the RFC 7282 sense — objections are addressed on
their **technical merits**, not counted as votes ("consensus is when everyone is
sufficiently satisfied with the chosen solution, such that they no longer have
specific objections to it"). Analogous to the Rust **Final Comment Period**, the
review window is announced and stays open **at least ten calendar days** so that
reviewers in any time zone have a fair chance to object. The window is a floor,
not a ceiling; the editor extends it while substantive objections remain
unresolved.

#### 5.3 Accepted
The editor judges that rough consensus is reached and the **design** is sound, and
moves the NAEP to `Accepted`. Because N-AALP is an Independent Submission (RFC
4846), acceptance is the **editor's deliberate decision**, informed by consensus
but not bound to a tally — consistent with `CONTRIBUTING.md` ("acceptance of a
normative change is a deliberate editorial decision, not an automatic merge").

On acceptance, the NAEP's normative text is merged into its target document, and
the change is recorded in the existing three layers of `CONTRIBUTING.md`:
- **(1)** one or more MADR-style ADRs in [`docs/adr/`](../docs/adr/) (the NAEP
  cites the ADR number(s); the ADR cites the NAEP);
- **(2)** a change-log bullet in the draft's `## Changes Since …` appendix; and
- **(3)** the closing/consensus labels on the issue/PR.

`Accepted` means **the design is ratified**. It does **not** mean the change is
proven implementable. Per §6, a Standards Track NAEP **remains `Accepted`** —
never `Final` — until it ships reference implementations and conformance vectors.
This is the deliberate PEP 1 / KEP separation of *approved design* from *proven,
gradable feature*.

#### 5.4 Final
The terminal success state for a **Standards Track** NAEP. A NAEP is promoted from
`Accepted` to `Final` **only** when the §6 gates are all satisfied. `Final` is the
state a downstream consumer relies on: a `Final` NAEP is implemented in the
repository's reference implementations and is graded by machine-checkable vectors
pinned in this repository.

#### 5.5 Rejected and Withdrawn
- **Rejected** — the editor concludes the proposal should not proceed (unsound,
  out of scope, or superseded by a better proposal). A `Rejected` NAEP is kept in
  `process/` as a permanent record of the considered-and-declined option; its
  number is retired.
- **Withdrawn** — the **author** abandons the NAEP (or concedes a competing
  proposal is superior — the PEP 1 sense of `Withdrawn`). Allowed from any
  pre-`Final` state. Also retained; number retired.

An abandoned-but-not-formally-withdrawn NAEP MAY be marked `Withdrawn` by the
editor after a documented period of inactivity, the way Rust *postpones* a stale
RFC; the record notes it was withdrawn for inactivity and MAY be reopened under a
new number.

#### 5.6 Lifecycle for Informational and Process NAEPs
Informational and Process NAEPs use `Draft → Review → Accepted → Active` (or
`Rejected`/`Withdrawn`). They have **no `Final` state and are exempt from the §6
implementation/vector gates**, because they specify no on-the-wire behavior to
implement or grade. `Active` (as used by this NAEP) marks an in-force
Informational/Process NAEP; it is retired to `Superseded` when a later NAEP
replaces it.

### 6. The Final gate (normative — the core rule of this process)

> **A Standards Track NAEP MUST NOT be promoted to `Final` unless ALL of the
> following exist, are merged into this repository, and pass CI:**
>
> **(a)** **at least one working reference implementation** of the NAEP's
> normative behavior. For N-AALP the reference is deliberately **two**
> implementations: the behavior MUST be realized in both
> [`impl/go`](../impl/go) and [`impl/rust`](../impl/rust), which — per
> [ADR-0006](../docs/adr/0006-two-implementation-byte-parity.md) — MUST produce
> **byte-identical** CBOR, signed input, signatures, and digests for identical
> logical input. A behavior realized in only one of the two, or one whose two
> implementations disagree byte-for-byte, does not satisfy this gate; and
>
> **(b)** **machine-gradable, non-circular conformance vectors** that exercise the
> NAEP's normative behavior and can be **graded pass/fail by tooling**. For N-AALP
> that means all of:
> - an **independent Python oracle** in [`tools/`](../tools/) that constructs the
>   expected bytes from an underlying standard (RFC/FIPS/NIST) — **not** from
>   either implementation under test — and against which **both** Go and Rust are
>   cross-validated (`scripts/verify.sh`);
> - where the behavior has a wire production, the **CDDL** wire grammar
>   [`spec/naalp-draft-00.cddl`](../spec/naalp-draft-00.cddl) machine-validates the
>   vector bytes (`scripts/cddl_check.sh`), and the registries stay drift-free
>   against the graded vectors (`scripts/registry_drift.py`); and
> - the behavior is graded across the **ten-language SDK set**
>   (`go`, `rust`, `python`, `typescript`, `java`, `ruby`, `php`, `kotlin`,
>   `csharp`, `swift`) against the shared corpus by the **`naalp-conform`**
>   harness (`harness/run.sh` → `harness/cross_language.sh`),
>
> including the negative (MUST-reject) cases where the NAEP defines any.
>
> **A NAEP that specifies behavior but provides no reference implementation, or no
> machine-gradable vectors, is at most `Accepted`. It is never `Final`. A
> spec-only NAEP is not a Final NAEP.**

This rule is the direct application to N-AALP of PEP 1 ("the reference
implementation must be completed before any PEP is given status 'Final'") and of
the Kubernetes graduation gate ("the graduation criteria must include conformance
tests … all GA endpoints must be hit by conformance tests"). It exists so that
`Final` in N-AALP means the same thing it means in those projects: **the design
was not merely agreed, it was built twice, byte-for-byte, and independently
verified.**

Supporting requirements for the Final gate:

1. **Non-circularity (REQUIRED).** The conformance vectors MUST derive from an
   independent authority — the underlying standard (deterministic CBOR per RFC
   8949 §4.2.1, COSE_Sign1 per RFC 9052, ML-DSA-65/-87 per FIPS 204 with
   deterministic `rnd=0`, Ed25519 per RFC 8032, and NIST/FIPS known-answer
   vectors), a published third-party corpus, or an independent byte constructor —
   and **MUST NOT** be generated by either reference implementation they grade.
   Vectors that are the output of the implementation under test do not satisfy
   gate (b). Go and Rust are both cross-validated against the **same** oracle
   bytes, exactly as `CONTRIBUTING.md` requires.
2. **Wire-grammar and registry pinning (REQUIRED).** New vectors MUST pass the
   CDDL conformance check (`scripts/cddl_check.sh`: the grammar is well-formed in
   the Bormann `cddl` tool AND validates the committed vector bytes) and the
   registry-drift gate (`scripts/registry_drift.py`), and MUST be pinned by the
   repository's pin/verify tooling (`scripts/verify_pins.py`) so the bytes a
   consumer relies on are provably the bytes the NAEP shipped. The single command
   `harness/run.sh` runs the whole gate and exits non-zero if any construction is
   ungraded.
3. **Honest coverage (REQUIRED).** If a NAEP's behavior is only partially gradable
   today (for example, a behavior for which no independent oracle yet exists), the
   NAEP MUST state exactly which parts are machine-graded and which remain
   specification-audited or self-attested. A NAEP whose normative behavior is
   *entirely* un-gradable (no positive vector, no negative case, no oracle)
   **cannot** reach `Final`; it stops at `Accepted` with that limitation recorded,
   until an oracle is added.
4. **Object-major-version NAEPs.** A NAEP that changes the object wire in a
   backwards-incompatible way (§2.3) additionally requires bumping the
   `naalp-version` protected-header field (key 3; this draft = 1) and, if
   warranted, registering a new media type alongside `application/naalp+cbor`
   (RFC 6838) in the Internet-Draft's IANA Considerations, per `CONTRIBUTING.md`
   "Code-point stability". **N-AALP defines no ALPN identifier or other transport
   identifier of its own** — it carries the same meaning over any N-PAMP channel
   or any other transport ([ADR-0002](../docs/adr/0002-object-not-connection.md)),
   so a wire-breaking N-AALP change is a **new draft revision + a `naalp-version`
   bump + a media type**, never a transport-identifier digit. Transport concerns
   (handshake, AEAD, KEM, ALPN, RTT) belong to the N-PAMP substrate and its
   NEP-0000, not to a NAEP.

### 7. Firewall / controlled-material check (normative)

Every NAEP **MUST** pass a firewall check before it may enter `Review`, and again
before `Final`. A NAEP is a **public** document in the open reference repository;
it therefore **MUST NOT** contain any controlled or sealed material:

1. **No controlled or sealed material** — no controlled cryptographic extensions
   and no high-assurance implementation material. Publishing a **code point** (an
   identifier — e.g. a signature or multicodec suite value, a channel number, a
   carriage `protocol_id`) is permitted, because it discloses an identifier, not
   an implementation; publishing the high-assurance *implementation material*
   behind such a code point is **not**.
2. **No private product or vendor-internal names** — a NAEP names only the public
   protocol and its public author identity (Shawn Sammartano, BubbleFish
   Technologies, Inc.); it MUST NOT reference private downstream products or
   internal codenames.
3. **No absolute local filesystem paths** — all references are
   repository-relative.
4. **No non-public dependency** — a NAEP's normative text MUST be reproducible
   from public standards and this repository alone; it MUST NOT depend on a
   non-public specification, corpus, or artifact.

The firewall check is a REQUIRED, recorded step (a reviewer sign-off). A NAEP that
would require sealed material to be complete does not belong in this repository and
MUST be `Rejected`.

### 8. Backwards / wire compatibility

This is a Process NAEP; it changes no wire behavior and consumes no code points.
It is fully backwards compatible with the existing repository: it **adds** a
`process/` directory and a proposal instrument **on top of** the unchanged
three-layer decision history of `CONTRIBUTING.md`. Existing ADRs, the draft change
log, and the issue-label conventions continue exactly as they are; a NAEP, when
`Accepted`, **produces** entries in those layers rather than bypassing them. No
existing document, registry, CDDL rule, vector, or pin is altered by adopting this
NAEP.

### 9. Reference implementation

Per §5.6, a Process NAEP is exempt from the §6 reference-implementation gate — it
specifies process, not on-the-wire behavior, so there is nothing to implement in
`impl/`. Its "implementation" is the process artifacts themselves: this document,
the `process/` directory, and the `naep` issue label. This NAEP is `Active` on the
strength of those artifacts existing; it is not, and cannot be, `Final`.

### 10. Conformance vectors

Also per §5.6, a Process NAEP has no machine-gradable conformance vectors, because
it defines no gradable wire behavior. The analogous "conformance" check for this
document is structural and is satisfiable by inspection: (i) `process/` exists and
contains `NAEP-0000-naalp-enhancement-proposal-process.md`; (ii) the metadata
table and required sections of §11 are present; (iii) nothing in this document
contradicts `CONTRIBUTING.md`'s ADR/change-log/label process — it references and
extends it.

### 11. Required NAEP sections

Every NAEP **MUST** contain, in order, the metadata table (§4.4) followed by these
sections. Sections marked *(Standards Track)* are REQUIRED for Standards Track
NAEPs and MAY be marked "N/A" with a one-line reason for Informational/Process
NAEPs.

1. **Abstract** — one paragraph: what the NAEP changes and why, understandable on
   its own.
2. **Motivation** — the problem, the forces in tension, and why the existing
   design is insufficient. (Rust "Motivation"; PEP 1 "Motivation".)
3. **Specification** — the normative change in full, in the target document's
   style, precise enough that an independent implementer needs no further design
   decisions. Uses BCP 14 keywords where it states requirements. *(Standards
   Track: this is the text merged on `Accepted`.)*
4. **Backwards / Wire Compatibility** — the effect on interoperating peers;
   whether the change is additive or object-major; migration guidance; and the
   `naalp-version` bump plus any new media type if object-major. *(Standards
   Track)*
5. **Reference Implementation** — the plan for, and then the link to, the working
   reference implementation in **both** `impl/go` and `impl/rust`. **REQUIRED to
   exist, be byte-identical, and be merged before `Final`** (§6a). *(Standards
   Track)*
6. **Conformance Vectors** — the plan for, and then the link to, the
   machine-gradable, non-circular oracle in `tools/`, the vectors it produces, the
   CDDL rule(s) that validate them, and the `naalp-conform` cross-language grading.
   **REQUIRED to exist, be pinned, and pass CI before `Final`** (§6b). *(Standards
   Track)*
7. **Security Considerations** — the security effect of the change: new attack
   surface, downgrade/replay/nonce hazards, authentication bindings (signer-id,
   content-id, effect authorization), and how they are mitigated. (IETF
   requirement for every draft; RFC 8126 for registry changes; PEP 1 "Security
   Implications".)
8. **Firewall / Controlled-Material Check** — an explicit statement, per §7, that
   the NAEP contains no sealed identifiers, no high-assurance implementation
   internals, no private product names, and no non-public dependency, with the
   reviewer sign-off recorded.
9. **Considered Alternatives** — the options weighed and why they were not chosen
   (feeds the MADR ADR's "Considered Options"; Rust "Rationale and alternatives";
   PEP 1 "Rejected Ideas").
10. **Decision Record Links** — the ADR number(s) in `docs/adr/` this NAEP
    produced or updated, the change-log bullet, and the issue/PR (the three layers
    of `CONTRIBUTING.md`). Populated on `Accepted`.

### 12. Roles

- **Author** — writes and champions the NAEP, and is responsible for the two
  byte-identical reference implementations and the non-circular vectors reaching
  the repository before `Final` (the author MAY delegate the implementation, as
  Rust separates an accepted RFC from whoever implements it, but the NAEP does not
  reach `Final` until they land and grade green).
- **Editor** — the N-AALP document editor (the Independent Submission author of
  record, `naalp-editor@bubblefish.sh`). Assigns NAEP numbers, opens/extends the
  review window, judges rough consensus, and makes the `Accepted`/`Rejected` and
  `Final` determinations. On the IETF side, the Independent Submissions Editor and
  the RFC Editor process (RFC 4846) remain the ultimate authority over the
  published draft/RFC text; the NAEP process governs *this repository's* path up to
  that submission.
- **Reviewers** — anyone participating under the `naep` label, per
  [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md): critique text and design on the
  technical merits.

## Backwards / Wire Compatibility

Restated for the record: none. This Process NAEP is additive to the repository and
changes no wire behavior, no registry, no CDDL rule, no vector, and no pin. See §8.

## Reference Implementation

Not applicable to a Process NAEP; see §9. The process artifacts (this document,
`process/`, the `naep` label) are the deliverable, which is why this NAEP is
`Active` and not `Final`.

## Conformance Vectors

Not applicable to a Process NAEP; see §10. Conformance is structural and
inspectable, not machine-graded, because this document defines no wire behavior.

## Security Considerations

A change-management process has one real security property: it must not let a
security-relevant change slip in **without security review or without evidence**.
This NAEP addresses that in three ways. (1) Every Standards Track NAEP MUST carry a
Security Considerations section (§11.7) and MUST reach rough consensus in `Review`
before `Accepted`, so a security-affecting change — a new effect class, a change to
signer-id/content-id derivation, a new signature suite — is argued on its merits
(RFC 7282) rather than merged silently. (2) The §6 Final gate forbids a
security-relevant normative change from being presented as `Final` — i.e. as
something a deployer may rely on — until it is both implemented in two
byte-identical references and graded by non-circular vectors, closing the gap where
a "specified but unbuilt, untested" security mechanism is mistaken for a working
one. (3) The §7 firewall check keeps high-assurance implementation internals and
other controlled material out of the public record, so publishing a NAEP never
discloses sealed material — it discloses identifiers and public reference behavior
only.

The process does not itself defend the protocol; the protocol's security lives in
the draft, its CDDL, and its oracles. This NAEP defends the *integrity of how
changes to that security get made*.

## Firewall / Controlled-Material Check

This document contains: no controlled or sealed material (no controlled
cryptographic extensions, no high-assurance implementation material — it refers to
suites and profiles only as public identifiers/code points, which the repository
already publishes); no private downstream product or vendor-internal names; no
absolute local filesystem paths (all links are repository-relative); and no
dependency on any non-public specification or artifact. The only named identity is
the public IETF author of record, Shawn Sammartano, BubbleFish Technologies, Inc.
**Firewall check: clean.**

## Considered Alternatives

- **Do nothing; keep only ADRs + PRs.** Rejected: an ADR is decision-scale, not
  proposal-scale. Large, object-wire-affecting, or new-channel/new-carriage-class
  changes need one reviewable container with motivation, alternatives, an
  implementation, and vectors — and a status a consumer can trust. The ADR log
  remains, underneath.
- **Adopt the IETF working-group process wholesale.** Rejected: N-AALP is an
  **Independent Submission** (RFC 4846), a single-editor stream, not a
  working-group document. A WG-style vote/quorum would misrepresent how this repo
  actually decides; `CONTRIBUTING.md` already states acceptance is an editorial
  decision. NAEP keeps the editor final and uses rough consensus (RFC 7282) as
  input, not as a binding vote.
- **Reuse N-PAMP's NEP process unchanged.** Rejected: N-AALP is a separate
  document with a different conformance model. NEP-0000's Final gate is written
  around N-PAMP's transport machinery and ten-implementation corpus; N-AALP's gate
  is written around **two byte-identical reference implementations**, an
  **independent oracle set**, a **machine-validated CDDL**, and a **ten-language
  SDK** grading — and around the fact that N-AALP has **no ALPN of its own**. A
  shared process would blur those distinct conformance surfaces. NAEP is the
  sibling process, not a re-pointer to NEP.
- **Copy PEP/KEP verbatim.** Rejected in part: PEP's Steering Council and KEP's
  SIG/Production-Readiness-Review bodies assume multiple governing bodies this
  project does not have. NAEP keeps the parts that fit — the numbered lifecycle,
  the fixed sections, and above all the **implementation-and-tests-before-Final**
  gate — and drops the multi-body governance.
- **Let `Accepted` be the terminal state (no `Final`).** Rejected: that would
  erase the very distinction this repository is built on — agreed design versus
  built-twice-and-graded reality. The `Accepted → Final` step, gated on two
  byte-identical reference implementations and non-circular vectors, is the point
  of the whole process.

## Decision Record Links

On adoption, this NAEP is recorded in the three layers of `CONTRIBUTING.md`: an ADR
in [`docs/adr/`](../docs/adr/) recording the decision to adopt a NAEP process
(Considered Options: ADR-only / full IETF WG process / reuse-NEP / PEP-KEP-adapted
NAEP), a change-log bullet in the draft appendix noting the addition of the
`process/` directory, and the `naep`-labelled issue/PR in which it was adopted. The
NAEP process joins, and does not supersede, the existing ADRs 0001–0006 in
`docs/adr/`.

---

## NAEP template

Copy this into `process/NAEP-NNNN-slug.md` to start a new NAEP.

```markdown
<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# NAEP-NNNN — <Title>

| | |
|---|---|
| **NAEP** | NNNN |
| **Title** | <Title> |
| **Author** | <Name, affiliation, contact> |
| **Type** | Standards Track | Informational | Process |
| **Status** | Draft |
| **Created** | YYYY-MM-DD |
| **Requires** | <NAEP-NNNN, or —> |
| **Supersedes** | <NAEP-NNNN, or —> |
| **Discussion** | <issue/PR link>, label `naep` |

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174).

## Abstract
<One paragraph: what this NAEP changes and why.>

## Motivation
<The problem, the forces in tension, why the current design is insufficient.>

## Specification
<The full normative change, in the target document's style (the draft, the CDDL,
or a registry), precise enough that an independent implementer needs no further
design decisions. Use BCP 14 keywords for requirements. This text is what merges
into the target document on Accepted.>

## Backwards / Wire Compatibility
<Effect on interoperating peers; additive vs. object-major; migration; the
naalp-version bump and any new media type if object-major. N-AALP has no ALPN.>

## Reference Implementation
<Plan, then link, to the working reference implementation in BOTH impl/go and
impl/rust, byte-identical. REQUIRED to exist and be merged before Final.
(Standards Track)>

## Conformance Vectors
<Plan, then link, to the non-circular oracle in tools/, the vectors it produces,
the CDDL rule(s) that validate them, and the naalp-conform cross-language grading;
how they are pinned. REQUIRED to exist, be pinned, and pass CI before Final.
(Standards Track)>

## Security Considerations
<New attack surface; downgrade/replay/nonce effects; signer-id/content-id/effect
authentication effects; mitigations.>

## Firewall / Controlled-Material Check
<Explicit statement: no sealed identifiers, no high-assurance implementation
internals, no private product names, no absolute local paths, no non-public
dependency. Reviewer sign-off. State "clean" or "not clean — do not proceed".>

## Considered Alternatives
<Options weighed and why not chosen. Feeds the ADR's Considered Options.>

## Decision Record Links
<ADR number(s) in docs/adr/, the change-log bullet, and the issue/PR.
Populated on Accepted.>
```

---

## References (primary sources consulted)

- **RFC 2026** — *The Internet Standards Process — Revision 3.* BCP 9. The
  editorial-nit vs. normative-change distinction and the standards-track lifecycle
  N-AALP's change tiers echo.
- **RFC 4846** — *Independent Submissions to the RFC Editor.* Establishes the
  single-editor Independent Submission stream N-AALP is offered through; the basis
  for the NAEP process being editor-final rather than working-group-vote.
- **RFC 6838** — *Media Type Specifications and Registration Procedures.* BCP 13.
  The registration procedure for `application/naalp+cbor` and any successor media
  type an object-major NAEP introduces.
- **RFC 7282** — *On Consensus and Humming in the IETF.* "Consensus is when
  everyone is sufficiently satisfied with the chosen solution, such that they no
  longer have specific objections to it." The basis for §5.2 rough-consensus review
  (objections addressed on merits, not counted).
- **RFC 8126** — *Guidelines for Writing an IANA Considerations Section in RFCs.*
  BCP 26. The Specification-Required policy (Expert Review + a stable, clear,
  technically-sound public specification) that governs single additive
  registrations (§3.2) versus range/policy changes that need a NAEP (§2.4).
- **RFC 8174 / RFC 2119** — BCP 14 requirement keywords, used throughout.
- **RFC 8874** — *Working Group GitHub Usage Guidance.* The `design`/`editorial`
  issue-label convention `CONTRIBUTING.md` adopts and the NAEP `naep` label extends.
- **RFC 8949** — *Concise Binary Object Representation (CBOR).* §4.2.1 core
  deterministic encoding — the independent authority for the CBOR-canonicalization
  vectors a NAEP's oracle must match (§6.1).
- **RFC 9052** — *CBOR Object Signing and Encryption (COSE): Structures and
  Process.* The COSE_Sign1 profile the object signatures use; an independent
  authority for the signing vectors.
- **RFC 8032 / FIPS 204 / FIPS 205** — Ed25519, ML-DSA, and SLH-DSA signature
  standards; the independent known-answer authorities for the signature-suite
  vectors (FIPS 204 with deterministic `rnd=0`).
- **Python PEP 1** — *PEP Purpose and Guidelines.* The status set (Draft /
  Accepted / Final / Rejected / Withdrawn / Active), the type set (Standards Track
  / Informational / Process), and the load-bearing rule "the reference
  implementation must be completed before any PEP is given status 'Final'" (§6a).
- **Rust RFC process** (`rust-lang/rfcs` `README`) — the "substantial change"
  trigger (§2), the Final Comment Period (§5.2), the `NNNN-title.md` convention,
  the template sections, and the separation of an *accepted* RFC from its
  *implementation* tracking ("being 'active' is not a rubber stamp").
- **Kubernetes KEP process** (`kubernetes/enhancements` `keps/README`) — the
  numbered-directory convention, the "non-trivial change" trigger, and the
  graduation gate that "the graduation criteria must include conformance tests …
  all GA endpoints must be hit by conformance tests" — the direct precedent for
  §6b (machine-gradable vectors before `Final`).
- **N-PAMP NEP-0000** — *The N-PAMP Enhancement Proposal Process.* The substrate
  project's sibling process; NAEP adapts its lifecycle and Final-gate discipline to
  N-AALP's object-layer conformance model.

*N-AALP™ and BubbleFish™ are trademarks of BubbleFish Technologies, Inc.*
