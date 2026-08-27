<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP Project Governance

This document describes **how the N-AALP project is governed**: who holds which
role, how decisions are made and recorded, how a normative change to the protocol
differs from an editorial one, how the repository relates to the IETF submission
that is the protocol's source of truth, how code points are assigned, how
conformance gates the word "done," and how maintainership changes hands.

It is deliberately **lightweight and honest**. N-AALP is a small-team
specification effort, not a large standards body; this document describes the
governance that actually exists rather than a committee that does not. A small
project is best served by a governance model matched to its size — the pattern
recommended for early-stage open specifications — with the process written down
so a new contributor knows exactly how to engage.

This document does **not** replace [`CONTRIBUTING.md`](CONTRIBUTING.md), which
defines the day-to-day change mechanics (the ADR record process, the issue/PR
labels, the draft build-and-lint steps, and the licensing of contributions).
Governance references that process; it does not restate or override it. Where
this document and `CONTRIBUTING.md` appear to differ, `CONTRIBUTING.md` is
authoritative for mechanics and this document is authoritative for authority —
who decides, and on what basis.

Community conduct is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md); the
private reporting path for a design weakness is [`SECURITY.md`](SECURITY.md).

---

## 1. What is being governed

This repository is the **public reference home** of N-AALP — the Native Agentic
Application Layer Protocol: the Internet-Draft
(`draft-bubblefish-naalp-00`, offered through the IETF Independent Submission
stream), the spine design and per-channel interface references, the byte-level
CDDL wire authority, the machine-readable code-point registries, the conformance
corpus and standards-anchored oracles, the cross-implementation conformance
harness, and the ten reference implementations.

N-AALP is the **application layer** carried by **N-PAMP**
(`draft-bubblefish-npamp-01`), which is the transport substrate. N-AALP gives
every agentic application object a signed, deterministic, post-quantum,
offline-verifiable meaning — identity, effect, approval, and audit — over any
transport, and carries foreign agent protocols (MCP, A2A, and more) octet-exact
by carriage **class** inside a governed signed envelope. Transport-layer concerns
— the handshake, key agreement, AEAD, ALPN — belong to N-PAMP and are governed by
that project, not this one.

The governed artifacts fall into three tiers, and the governance weight scales
with the tier:

| Tier | Artifact | Governs what | Change weight |
|---|---|---|---|
| **Normative wire** | The Internet-Draft, the spine design, the channel interface references, `spec/naalp-draft-00.cddl`, the code-point registries | What an implementation MUST do on the wire | Heaviest — see [§4](#4-normative-vs-editorial-changes) and [§6](#6-code-point-governance) |
| **Conformance oracle** | The independent Python oracles in `tools/`, the pinned corpus in `vectors/`, the CDDL schema, the harness | What "conforms" means and how it is graded | Heavy — see [§7](#7-conformance-gates-done) |
| **Reference & tooling** | The ten implementations under `impl/`, quickstarts, scripts, CI, the docs site | How the protocol is demonstrated and tested | Ordinary open-source change |

The **draft is the source of truth**; everything else exists to conform to it or
to demonstrate it. Governance therefore concentrates its ceremony on the
normative-wire tier and stays out of the way of ordinary reference-implementation
work.

---

## 2. Roles

N-AALP uses a small, explicit set of roles. It does not claim a steering
committee, a working group, or an elected board — none exists, and inventing one
in a document would be dishonest.

### 2.1 Author / Editor

**Shawn Sammartano, BubbleFish Technologies, Inc.** is the document author and
editor. This is the same identity that appears on the Internet-Draft; it is the
single public identity of the project.

The Author/Editor holds final authority over normative content, consistent with
the Independent Submission stream, in which the document represents the author's
work and the author retains editorial control (RFC 4846). Concretely, the
Author/Editor:

- decides whether a proposed **normative** change is accepted, after the
  rough-consensus process of [§3](#3-how-decisions-are-made);
- owns the draft text and its submission to the Independent Submissions Editor;
- assigns code points within the registries' managed ranges ([§6](#6-code-point-governance));
- is the tie-breaker of last resort when discussion does not converge; and
- maintains the decision record so that every substantive choice is traceable.

This is a benevolent-single-editor model, which is the honest description of a
project this size. The tie-breaker authority is a backstop, not the normal path:
the normal path is that objections are addressed on their technical merits
([§3](#3-how-decisions-are-made)) and the outcome is obvious before anyone has to
invoke authority.

### 2.2 Maintainers

**Maintainers** hold commit access and keep the repository healthy: they review
and merge pull requests, triage and label issues, run and maintain the CI gates,
cut draft-revision tags, and shepherd reference-implementation and tooling
changes. A maintainer may accept any **editorial** or **reference/tooling** change
on their own judgment. A maintainer may **not** unilaterally land a **normative**
change; those follow [§3](#3-how-decisions-are-made) and
[§4](#4-normative-vs-editorial-changes) and require Author/Editor acceptance.

The current maintainer set is recorded in [`MAINTAINERS.md`](MAINTAINERS.md).
Adding and removing maintainers is [§8](#8-adding-and-removing-maintainers).

### 2.3 Contributors

**Contributors** are everyone who opens an issue or a pull request, reviews a
change, reports a security weakness, or proposes a code-point registration.
Contribution does not require any status; it requires following
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
By contributing you agree to the licensing terms in `CONTRIBUTING.md` (Apache-2.0
for repository code and original content; BCP 78 / `ipr: trust200902` for
Internet-Draft text).

Contributors have real influence: a technical objection from any contributor is
weighed on its merits, not on the contributor's status ([§3](#3-how-decisions-are-made)).

### 2.4 Designated experts

The IANA registrations tied to N-AALP fall into two groups, and one of them is
governed **outside** this project by IANA's own process:

- The **media type** `application/naalp+cbor` is registered under **Specification
  Required / Expert Review** (RFC 6838, RFC 8126 §4.6), reviewed by the
  media-types Designated Expert via `media-types@iana.org`. The project supplies
  the completed registration template (stated in the Internet-Draft's IANA Considerations); it does
  not appoint that expert and cannot register the value itself.
- N-AALP **reuses** the existing IANA **COSE Algorithms** registry for its
  signature identifiers (ML-DSA per RFC 9964, Ed25519 per RFC 9864) and requests
  **no new COSE code points**; those values are governed by the COSE registry's
  own experts, not by this project.

This is stated so no reader mistakes the project's internal registries
([§6](#6-code-point-governance)) for the IANA-managed identifiers, or assumes the
project can assign a media type or a COSE algorithm on its own authority.

---

## 3. How decisions are made

N-AALP decisions are made by **rough consensus**, in the IETF sense (RFC 7282),
scaled to a small project — **not** by majority vote. The distinction is load-
bearing:

- **Issues are addressed, not counted.** A decision is ready when the technical
  objections raised against it have been *addressed* — considered and answered —
  not when a headcount favors one side. An unaddressed, sound technical objection
  blocks consensus even if only one person raised it; conversely, an objection
  that has been genuinely answered does not block, even if its author remains
  unpersuaded (RFC 7282 §3, §6).
- **No voting, no vote-stuffing.** Because the question is "are there outstanding
  technical objections?" and not "how many people are on each side?", the process
  is immune to headcount manipulation (RFC 7282 §6). The project runs no polls
  and counts no votes.
- **Discussion happens in the open**, on the issue or pull request. The label
  taxonomy of `CONTRIBUTING.md` (`design` vs `editorial`, plus
  `needs-discussion` / `has-consensus` / `proposal-ready`, per RFC 8874 practice)
  is the discussion trail.
- **The Author/Editor is the backstop.** If a `design`-labeled discussion does not
  converge in a reasonable time, the Author/Editor makes the call and records the
  reasoning in an ADR. This mirrors the small-project pattern where a benevolent
  editor resolves a stalled discussion rather than leaving the protocol
  undecided, and it is consistent with the Independent Submission stream's single
  approving authority (RFC 4846).

Every `design`-labeled issue that reaches consensus produces **three artifacts**:
(1) a closing comment recording the resolution, (2) a numbered **Architecture
Decision Record** in [`docs/adr/`](docs/adr/), and (3) a change-log bullet in the
draft's change appendix and in [`CHANGELOG.md`](CHANGELOG.md). Governance adds no
fourth artifact and changes none of these three — it only states *who* has the
authority to declare that consensus was reached (the Author/Editor, for normative
content).

> **Why an ADR, not just a merge.** The project's stated value is that every spec
> decision is *traceable* — what was decided, why, which alternatives were weighed,
> and how the decision is verified
> ([ADR-0001](docs/adr/0001-record-architecture-decisions.md)). A merge without an
> ADR loses the "why." The ADR is the durable record; the merge is just the
> mechanics.

---

## 4. Normative vs. editorial changes

The single most important governance distinction in this project is **normative
vs. editorial**, because it determines both the process weight and the
compatibility contract. Every change is labeled one or the other; this section
defines the boundary and the consequence.

### 4.1 What makes a change normative

A change is **normative** if it affects what a conforming implementation does *on
the wire* or *at a security boundary*. This includes, at minimum:

- the object envelope geometry, its CBOR map keys, or the deterministic-encoding
  rules (RFC 8949 §4.2.1) that make two implementations produce identical bytes;
- the protected-header `naalp-version` octet or the critical-extension (`cext`)
  mechanism and its unknown-critical-extension rejection;
- the channel number space (`0x0000`–`0x0013`), the object-kind number space, or
  the closed effect set and its fail-closed lattice;
- the crypto **profile** parameter rows (Public, Enterprise, Sovereign: the COSE
  `alg` values, ML-DSA-65 / ML-DSA-87 per FIPS 204, the SHA-384 hash floor,
  [ADR-0003](docs/adr/0003-post-quantum-first.md));
- the `content-id` construction (multihash `0x20`, SHA-384 of the body) or the
  `signer-id` (multiformats PeerHandle) construction;
- the effect-is-authorization semantics
  ([ADR-0004](docs/adr/0004-effect-is-authorization.md)), the single-use approval
  consumption rule, or the audit ordering / causal-integrity rules;
- a carriage-class mapping's `MUST` / `MUST NOT` / `SHALL` behavior
  ([ADR-0005](docs/adr/0005-carriage-by-class.md)); and
- any code-point **assignment** or policy change in
  [`vectors/registry/`](vectors/registry/).

A change is **editorial** if it cannot change any of the above: wording,
formatting, examples, non-normative prose, typo fixes, added cross-references,
and improvements to informative worked examples. Reference-implementation and
tooling changes that do not alter the wire contract are **ordinary open-source
changes** and are neither of the two spec categories, though a change to an
implementation that reveals a *spec* ambiguity should open a `design` issue.

If a change is on the boundary, it is treated as **normative** until shown
otherwise. Misclassifying a normative change as editorial is the failure this
distinction exists to prevent.

### 4.2 Process by class

| Class | Who may accept | Process | Record produced |
|---|---|---|---|
| **Editorial** | Any maintainer | Ordinary PR review; label `editorial`; keep the draft at 0 errors / 0 flaws under `idnits` | Merge + `CHANGELOG.md` bullet |
| **Normative** | Author/Editor only, after rough consensus ([§3](#3-how-decisions-are-made)) | Label `design`; open the discussion; reach rough consensus; Author/Editor accepts | Closing comment **+ ADR + change-log bullet** (all three) |
| **Reference / tooling** | Any maintainer | Ordinary PR review; must keep CI green ([§7](#7-conformance-gates-done)) | Merge + `CHANGELOG.md` bullet where user-visible |

> **Proposal-scale changes carry the heaviest process.** A normative change that
> is large or structural — a new channel surface, a new object kind, a new
> carriage class, a new signature suite, or any wire-affecting change to the
> envelope geometry, the number spaces, the effect set, or the profile rows —
> runs the same rough-consensus process ([§3](#3-how-decisions-are-made)) and
> produces the same three-layer record (ADR + change-log + labels); it adds one
> gate this project treats as non-negotiable: such a change **MUST NOT** be
> declared *done* until it has a reference implementation in both primary
> languages and machine-gradable, non-circular conformance vectors that grade it
> ([§7](#7-conformance-gates-done)). A single additive registration in an existing
> *Specification Required* range does **not** need this ceremony — it follows the
> code-point procedure of [§6.2](#62-how-a-code-point-is-assigned).

### 4.3 Wire-compatibility consequence

A normative change carries a **compatibility class**:

- **Additive** — registering a new value in an existing number space (a new
  signature suite, a new carriage `protocol_id`, a new channel, or a new object
  kind) is a value addition. It does not change the object encoding and does not
  bump the wire major version.
- **Major** — any change to the object envelope geometry, the CBOR map-key
  layout, the deterministic-encoding rules, the `naalp-version` semantics, the
  closed effect set / lattice, or the `content-id` / `signer-id` construction is a
  wire-incompatible change. It requires a new object major version, expressed by
  incrementing the protected-header **`naalp-version`** field (currently `1`) and
  reflected in the media-type registration.

Note the honest boundary with the substrate: N-AALP carries **no transport
identifier of its own**. Transport identity — the ALPN token, the negotiated
suite — belongs to N-PAMP, and an N-AALP wire-major bump is expressed in the
`naalp-version` octet and the `application/naalp+cbor` media type, **not** in an
ALPN digit. The Author/Editor MUST state the compatibility class in the ADR for
any normative change, so a downstream implementer can tell an additive
registration from a breaking one at a glance.

---

## 5. Relationship to the IETF / ISE submission track

N-AALP is offered through the IETF **Independent Submission** stream
(Informational), draft-00, pre-adoption, with **no working-group consensus
claimed**. Two facts govern how this repository relates to that track, and they
are the reason the governance here is deliberately modest.

1. **The draft is the source of truth; the repository is the working area.** The
   normative specification is the Internet-Draft. The CDDL, channel references,
   registries, vectors, and implementations in this repository exist to *express*
   and *conform to* that draft — they are not an independent source of authority.
   When the repository and the published draft disagree, the draft wins, and the
   repository is corrected to match (or the draft is revised, deliberately, via
   [§3](#3-how-decisions-are-made)–[§4](#4-normative-vs-editorial-changes)).

2. **Final normative authority on the *track* is not the repository's to grant.**
   Under the Independent Submission stream (RFC 4846), an independent-stream
   document is *not* an IETF-consensus document; it represents the author's work,
   the author retains editorial control, and the decision to publish rests with
   the Independent Submissions Editor (ISE) after independent review, not with a
   working group. Opening an issue or pull request here is the right first step,
   and consensus here is real and recorded — but acceptance of a normative change
   into the *submitted draft* is a deliberate editorial act by the Author/Editor,
   and publication as an RFC is the ISE's decision. This repository governs the
   working area up to that boundary and makes no claim past it.

The practical upshot: this project can and does run a real, traceable decision
process for its own working area, without pretending to be a chartered IETF
working group. The three-layer record (ADR + in-draft change log + labeled
issue/PR trail) is exactly the "traceable rationale" practice IETF GitHub usage
recommends (RFC 8874), applied to an independent submission.

---

## 6. Code-point governance

The five N-AALP registries carry the protocol's public code points. Their
governance follows **RFC 8126** (the IANA-registration-policy vocabulary),
applied to the project's own managed number spaces. The registries are:

| Registry | Home | Number space | Policy shape |
|---|---|---|---|
| **N-AALP Channels** | [`vectors/registry/channels.csv`](vectors/registry/channels.csv) | `0x0000`–`0x0013` (20 channels) | Specification Required |
| **N-AALP Object Kinds** | [`vectors/registry/channels.csv`](vectors/registry/channels.csv) | per-channel kind codes (65 baseline kinds) | Specification Required |
| **N-AALP Effects** | the closed set in the draft | `0`–`3` (`read_only`, `idempotent_write`, `non_idempotent_write`, `destructive`) | Specification Required — **closed set** |
| **N-AALP Carriage Protocol Ids** | [`vectors/registry/protocols.csv`](vectors/registry/protocols.csv) | one octet, banded (below) | mixed, per band |
| **N-AALP Error Codes** | the named errors of the draft | 34 named codes | Specification Required |

The signature-suite mapping ([`vectors/registry/signatures.csv`](vectors/registry/signatures.csv))
and the multicodec table ([`vectors/registry/multicodec.csv`](vectors/registry/multicodec.csv))
record values N-AALP **reuses** from external authorities (the IANA COSE
Algorithms registry and the multiformats multicodec table) rather than assigning
itself; they are governed by their source registries, and this project only
records the values it depends on. The submission-form registration package for
all of the above is stated in the Internet-Draft's IANA Considerations.

Two things are true at once and must not be confused:

- The **project-internal** registries (channels, object kinds, effects, carriage
  protocol ids, error codes) are managed *here*, by the Author/Editor, under the
  policies each registry states.
- The **IANA-managed** identifiers tied to N-AALP (the `application/naalp+cbor`
  media type under Expert Review; the COSE algorithm identifiers N-AALP reuses)
  are managed by **IANA**, not by this project ([§2.4](#24-designated-experts)).

### 6.1 The three assignment bands

A registry with a managed number space partitions it into the standard RFC 8126
bands. The **Carriage Protocol Id** registry
([`vectors/registry/protocols.csv`](vectors/registry/protocols.csv)) is the
worked example:

| Band | Policy (RFC 8126) | Who assigns | What it means |
|---|---|---|---|
| **Standards / assigned** (`0x01`–`0x0F`) | **Specification Required** (RFC 8126 §4.6) | Author/Editor, via the code-point procedure | A permanent, readily available public specification with enough detail for interoperable independent implementations is required before a value is assigned; the assignment is recorded and MUST NOT be reassigned. |
| **Experimental** (`0x10`–`0x7F`) | **Experimental Use** (RFC 8126 §4.2) | No one — unregistered | Usable without registration for experiments; carries no guaranteed cross-domain meaning; MUST NOT be emitted toward a peer without out-of-band agreement. The project records nothing here. |
| **Private use** (`0x80`–`0xFF`) | **Private Use** (RFC 8126 §4.1) | No one — unregistered | Usable inside a single administrative domain without registration; never assigned by this registry; MUST NOT be emitted toward a peer outside that domain. |

The initial standards-range contents of that registry are `0x01` MCP (JSONRPC),
`0x02` A2A (JSONRPC), `0x03` HTTP (HTTP), `0x04` WebSocket (STREAM). The Channels,
Object Kinds, Effects, and Error Codes registries are wholly Specification
Required — their code points are fixed by the draft and requested as-is — with the
additional constraint that an Effects addition MUST preserve the fail-closed
lattice with `destructive` at the top. The exact numeric boundaries are
authoritative **in the registry CSV and the IANA package**, not here; this table
shows the *policy shape*.

### 6.2 How a code point is assigned

1. Open an issue proposing the registration, labeled `design` (a code-point
   assignment is normative, [§4.1](#41-what-makes-a-change-normative)).
2. Provide the **Specification Required** material: a stable, public description
   detailed enough for two independent implementations to interoperate — for a
   carriage mapping, this is the mapping written against the foreign protocol's
   own published specification; for a signature suite, the construction and its
   standards anchor.
3. Reach rough consensus ([§3](#3-how-decisions-are-made)); the Author/Editor
   assigns the next value in the managed band and records an ADR plus the CSV row.
4. If no specification is ready yet, the proposer uses the **experimental** band
   by out-of-band agreement, or the **private-use** band within one domain — no
   registration, and no standards meaning claimed. This is the honest path for
   work in progress.

### 6.3 Stability guarantee

An assigned value in a managed band is **stable within a wire major version** and
MUST NOT be reassigned. Changing the *layout* of a number space (as opposed to
adding a value to it) is a major-version change ([§4.3](#43-wire-compatibility-consequence)).

---

## 7. Conformance gates "done"

A change to the normative-wire or oracle tier is not "done" when it merges; it is
"done" when the **conformance gates** are green and, for a normative change, the
oracle has been updated to cover it. N-AALP's grading model is stricter than a
passing build: a construction is graded only when **two independent
implementations agree with an independent, non-circular oracle** and, where the
construction has a wire production, **the CDDL validates its bytes**. The
additional-language SDKs are graded against the same shared corpus. The
conformance model is defined in the [conformance docs](docs/conformance.md); governance only
states how it gates the project.

### 7.1 The grading surfaces

| Surface | Grades | Machine-gradable today | Oracle |
|---|---|---|---|
| **Spine** | Deterministic CBOR (RFC 8949 §4.2.1), COSE_Sign1 (RFC 9052), `content-id` / `signer-id`, the envelope, effect / approval / audit ordering, delivery, streaming digests | **Yes** | The independent Python oracles in [`tools/`](tools/), anchored to RFC / FIPS / NIST, cross-validated by **Go == Rust byte parity** and **CDDL** (RFC 8610) validation of the produced bytes |
| **Cross-language signing** | Deterministic ML-DSA COSE_Sign1 byte-identical across the seven crypto-complete SDKs | **Yes** | The cross-language consensus gate (`crypto_consensus`) over go / rust / python / typescript / java / kotlin / ruby |
| **Channel surfaces** | The twenty channel object surfaces and 65 kinds, driven as an op-replay | **Yes** for the wire-producing operations (CDDL-validated); specification-audited for behavior with no byte production | The 239-case op-replay corpus in [`vectors/`](vectors/) |
| **Registries** | Drift between the registry CSVs and the specification / IANA package | **Yes** | `scripts/registry_drift.py` |

These oracles are **non-circular by construction**: every expected value derives
from an external authority (NIST / FIPS 204, the RFC series, Project Wycheproof,
the multiformats and COSE tables, or a from-scratch Python constructor in
`tools/`) and never from an N-AALP implementation under test, so a bug shared
across implementations cannot silently pass.

The additional-language SDKs are honest about scope. Seven languages
(Go, Rust, Python, TypeScript, Java, Kotlin, Ruby) are graded **239 / 239**,
including the deterministic ML-DSA leg. **PHP** and **Swift** are pure-only —
their ecosystems lack a deterministic ML-DSA seed-keygen path, so they grade
every non-crypto operation plus Ed25519 and **honestly skip-track the ML-DSA
leg** rather than fake it. **C#** is authored and graded in CI. A skip-track is a
recorded gap, never a false green.

### 7.2 The gating rule

- **Every push and pull request** runs the CI workflow
  ([`.github/workflows/conformance.yml`](.github/workflows/conformance.yml)): the
  conformance harness (`harness/run.sh`), the Go == Rust byte-parity and
  vector-drift gate (`scripts/verify.sh`), the cross-language corpus and
  deterministic-ML-DSA parity gate (`harness/cross_language.sh`), CDDL validation
  of the schema and produced bytes, and the registry-drift gate. A red gate blocks
  merge.
- **A normative change that adds or alters wire behavior is not complete until its
  oracle exists.** If the change produces bytes, a corresponding vector MUST be
  added to the corpus and its expected values MUST come from an independent oracle
  in `tools/`, in the same or an immediately following change; a normative change
  that leaves its behavior ungraded is an open coverage gap that MUST be recorded,
  not silently shipped.
- **A conformance *claim* is honest about scope.** A claim names what it graded
  (which surface, which SDKs, which profile) and the corpus it was graded against,
  and MUST NOT overstate coverage — a spine-bytes pass is not a channel-behavior
  claim, a wire-producing pass is not a claim about a behavior that has no byte
  production, and a skip-tracked leg (PHP / Swift ML-DSA) is never reported as
  graded. Governance adopts this as the project's definition of "verified": a
  capability is verified when a pinned, non-circular oracle grades it green, and
  is otherwise recorded as self-attested or as a coverage gap.

The effect is that "done" for the protocol means **graded green by two
independent implementations against an independent oracle**, not "the author says
it works." That is the gate, and it is intentionally stricter than a passing
build.

---

## 8. Adding and removing maintainers

Maintainership is granted for **sustained, high-quality contribution and
demonstrated good judgment about the normative/editorial boundary**, not for a
single change. The process is deliberately simple because the team is small.

### 8.1 Adding a maintainer

1. An existing maintainer (or the Author/Editor) nominates the candidate in an
   issue labeled `governance`, citing the candidate's track record.
2. The existing maintainers and the Author/Editor discuss by rough consensus
   ([§3](#3-how-decisions-are-made)); an unaddressed, sound objection blocks the
   addition.
3. The **Author/Editor confirms** the addition (final authority, [§2.1](#21-author--editor)).
4. The change is recorded: the candidate is added to
   [`MAINTAINERS.md`](MAINTAINERS.md), granted commit access, and the decision is
   noted in the `governance` issue. A governance-role change of this weight also
   gets an ADR, so the roster's history is traceable like every other decision.

### 8.2 Stepping down or removal

- **Voluntary step-down.** A maintainer may step down at any time by opening a
  `governance` issue or a pull request removing themselves from `MAINTAINERS.md`.
  Commit access is revoked; the step-down is recorded. No justification is
  required and none is asked for.
- **Inactivity.** A maintainer who has been inactive for an extended period
  (default: **twelve months** with no reviews, merges, or triage) may be moved to
  *emeritus* in `MAINTAINERS.md` by the Author/Editor, after a good-faith attempt
  to reach them. Emeritus status is honorary; commit access lapses and is
  restored on request if the person returns to active contribution.
- **For cause.** A maintainer may be removed for a serious or sustained violation
  of [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), or for repeatedly landing
  normative changes without the process of [§4](#4-normative-vs-editorial-changes).
  Removal for cause is the Author/Editor's decision, recorded in a `governance`
  issue and an ADR.

### 8.3 Succession of the Author/Editor role

The Author/Editor role is tied to the public author identity of the Internet-
Draft and cannot be transferred by a repository action alone: transferring it
would require re-authorship of the submitted draft on the IETF Datatracker and
the Independent Submissions Editor's involvement, which is outside this
repository's control. Should the Author/Editor become unavailable, the maintainers
may keep the repository, the reference implementations, and the conformance oracle
running (editorial and tooling tiers) under this document; a change to the
*normative draft authorship* is an ISE-track action, not a repository merge. This
limit is stated so no reader assumes the repository can hand off the standards-
track identity by itself.

---

## 9. Changing this document

This GOVERNANCE.md is itself governed. A change to it is a `governance`-labeled
change: proposed in a pull request, discussed by rough consensus, confirmed by
the Author/Editor, and — because it is a substantive decision about how the
project runs — recorded with an ADR. Editorial fixes to this document (typos,
broken links, clarified wording that does not change who decides what) are
ordinary editorial changes ([§4](#4-normative-vs-editorial-changes)).

---

## Precedents

This governance model was written against, and is consistent with, the following
primary sources (consulted directly, not from memory):

- **RFC 7282 — "On Consensus and Humming in the IETF."** The rough-consensus
  model of [§3](#3-how-decisions-are-made): issues are *addressed, not counted*;
  an unaddressed sound objection blocks consensus regardless of headcount; no
  voting.
- **RFC 8126 — "Guidelines for Writing an IANA Considerations Section in RFCs."**
  The registration-policy vocabulary of [§6](#6-code-point-governance):
  Specification Required (§4.6), Experimental Use (§4.2), Private Use (§4.1), and
  the Expert Review policy of the IANA-managed media type.
- **RFC 6838 — "Media Type Specifications and Registration Procedures."** The
  registration path for `application/naalp+cbor` ([§2.4](#24-designated-experts),
  [§6](#6-code-point-governance)), reviewed by the media-types Designated Expert.
- **RFC 4846 — "Independent Submissions to the RFC Editor."** The
  repository-vs-submission relationship of [§5](#5-relationship-to-the-ietf--ise-submission-track):
  an independent-stream document is not an IETF-consensus document, the author
  retains editorial control, and the Independent Submissions Editor is the
  approving authority.
- **RFC 8874 — "Working Group GitHub Usage Guidance."** The traceable
  issue/PR-label discussion trail and rationale-capture practice this document
  references.
- **PEP 1 — "PEP Purpose and Guidelines."** The author-champion vs.
  editors-do-not-judge-merits vs. final-approving-authority separation of roles
  ([§2](#2-roles)), and the requirement that a decision be recorded with its
  rationale.
- **CNCF project-governance templates and the open-source "minimum viable
  governance" / benevolent-single-editor pattern.** The justification for a
  *lightweight, honest, size-matched* governance model with a written
  maintainer-add/step-down process ([§8](#8-adding-and-removing-maintainers)),
  rather than an invented steering committee.

---

*N-AALP is developed by Shawn Sammartano, BubbleFish Technologies, Inc. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how to contribute,
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) for community standards, and
[`SECURITY.md`](SECURITY.md) for reporting a design weakness.*
