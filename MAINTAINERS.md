<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Maintainers

This file lists the people responsible for **N-AALP** — the Native Agentic
Application Layer Protocol: the Internet-Draft `draft-bubblefish-naalp-00`
(Independent Submission stream), the spine design and per-channel interface
references, the `spec/naalp-draft-00.cddl` wire authority, the code-point
registries, and the ten reference implementations — and it states what
maintainership on this repository means: the review commitments, the merge and
release rights, how security reports are handled, and how a person becomes or
steps down as a maintainer.

It is a companion to two documents and does not restate them:

- **[GOVERNANCE.md](GOVERNANCE.md)** — the decision model for the project as a
  whole (who decides, by what rule, and how a normative change moves from
  proposal to accepted).
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — the mechanics a contributor follows:
  the `design`/`editorial` label split, the three-layer decision record (ADR +
  in-draft change log + issue/PR labels), the ADR format in
  [`docs/adr/`](docs/adr/), the idnits/`0 errors` bar for the draft, and the
  contribution licensing terms (Apache-2.0 for code, BCP 78 for the draft text).

Where this file and `GOVERNANCE.md` describe the same process, `GOVERNANCE.md`
is authoritative and this file summarizes it for the maintainer's-eye view.

---

## Current maintainers

N-AALP follows the common open-source `MAINTAINERS.md` shape — one row per
person, with their name, contact handle, and area of responsibility — as used in
the [CNCF project template][cncf-maintainers]. A maintainer here is a **merge
approver**: someone with write access who is trusted to review, approve, and
land changes and to keep the wire format and its conformance evidence honest.

| Name | GitHub handle | Affiliation | Area |
|---|---|---|---|
| Shawn Sammartano | `@<TODO-github-handle>` | BubbleFish Technologies, Inc. | **Lead maintainer / document editor.** Full scope: the Internet-Draft and all normative spec text, the spine and channel interface references, `spec/naalp-draft-00.cddl`, the code-point registries, the conformance corpus and independent oracles, the ten reference implementations, the conformance harness, and the integrity/CI gates. IETF author of record for `draft-bubblefish-naalp-00`. Contact: `naalp-editor@bubblefish.sh`. |

Shawn Sammartano is the **document editor** in the IETF sense (RFC 8874): the
person who holds write access to the draft source and who is responsible for the
normative text carried through the Independent Submission stream. This is the
one public identity of record for the specification.

> **Single-maintainer status is intentional and disclosed.** At draft-00 the
> project has one maintainer. This matches the reality of an Independent
> Submission authored by one editor, and it matches the CNCF guidance that a
> maintainer roster is the canonical, honest list — not an aspirational one. The
> **[Becoming a maintainer](#becoming-a-maintainer)** process below is the real,
> usable path for that to change; it is not decorative.

Reviewers and area experts who are not yet maintainers are welcome and are
credited in the draft's Acknowledgements and in the relevant ADRs; they do not
hold merge rights until they complete the process below.

### Contact

- **General maintainer contact and security reports:** `naalp-editor@bubblefish.sh`
  (the address used by [SECURITY.md](SECURITY.md) and
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- **Public technical discussion:** repository issues and pull requests, labeled
  per [CONTRIBUTING.md](CONTRIBUTING.md).

---

## What a maintainer is responsible for

A maintainer is not merely someone who *can* merge; they are accountable for the
health of the areas they own. The responsibilities below are the standing
commitments of the role.

### 1. Reviewing and merging changes

- **Review incoming issues and pull requests** in their area and route them to
  the right reviewer. Following RFC 8874, every issue is triaged as `design`
  (substantive — may affect implementations or interoperability) or `editorial`
  (no substantive effect); this is the same split CONTRIBUTING.md requires.
- **Hold the merge bar.** A change is merged only when CI is green — the gates in
  [`.github/workflows/conformance.yml`](.github/workflows/conformance.yml): the
  conformance harness (`harness/run.sh`), the Go == Rust byte-parity and
  vector-drift gate (`scripts/verify.sh`), the cross-language corpus and
  deterministic-ML-DSA parity gate (`harness/cross_language.sh`), CDDL
  validation, and the registry-drift gate — and the review requirements below are
  met. A red parity, CDDL, or drift gate is never merged past.
- **Prefer pull requests to direct commits.** Per RFC 8874, substantial changes
  go through a pull request so the artifact records *why* the change was made,
  even when the author is a maintainer.

### 2. Guarding the normative text (the higher bar)

A **normative** change is anything that alters what a conforming implementation
must do on the wire: the object envelope geometry, the CBOR map keys or
deterministic-encoding rules, the `naalp-version` octet or critical-extension
mechanism, the channel / object-kind number spaces, the closed effect set and its
fail-closed lattice, the crypto profiles (Public / Enterprise / Sovereign), the
`content-id` / `signer-id` construction, the effect-is-authorization or
single-use-approval or audit-ordering semantics, a carriage-class mapping's
`MUST`/`MUST NOT` behavior, or a code-point registry value. For any normative
change, a maintainer requires **all** of:

1. **A numbered ADR** in [`docs/adr/`](docs/adr/) (`NNNN-verb-phrase-title.md`),
   per CONTRIBUTING.md — the durable "why."
2. **At least one maintainer approval** on the pull request. When more than one
   maintainer exists, a normative change needs a second maintainer's approval
   (or, if only one maintainer is available, an explicit named external reviewer
   recorded in the ADR's confirmation step).
3. **An in-draft change-log bullet** and the appropriate issue/PR labels
   (`design`, and `has-consensus` once reached), so all three decision layers in
   CONTRIBUTING.md are satisfied.

A **proposal-scale** normative change — a new channel surface, a new object kind,
a new carriage class, a new signature suite, or any wire-affecting change to the
envelope, number spaces, effect set, or profile rows — carries the additional
non-negotiable gate from [GOVERNANCE.md §4.2](GOVERNANCE.md): it does not reach
*done* until a reference implementation exists in **both primary languages**
(Go and Rust, byte-identical) **and** machine-gradable, non-circular conformance
vectors grade it. The maintainer helps enforce that gate; see
[GOVERNANCE.md](GOVERNANCE.md) for the authority model.

Editorial changes (wording, formatting, examples that change no wire behavior)
may be resolved at an editor's discretion and merged without an ADR, consistent
with RFC 8874's treatment of `editorial` issues.

> The **final authority over the normative draft text is the IETF process**, not
> a repository vote: acceptance flows through the document editor and, for
> publication, the Independent Submissions Editor and independent review
> (GOVERNANCE.md §5). Maintainer approval gates what lands in this repository; it
> does not substitute for that stream.

### 3. Research and provenance discipline

Any claim about an external system (an RFC, a cipher, a library, a wire format)
that a maintainer accepts into the repository must be grounded in that system's
**current published specification**, cited in the ADR — never asserted from
memory. Conformance vectors are derived from the underlying standards (for
example RFC 8949, RFC 9052, FIPS 204, RFC 8032, RFC 8610, Project Wycheproof) or
a from-scratch independent constructor in [`tools/`](tools/), and are **never**
generated by the implementation they grade. Enforcing this on review is a
maintainer responsibility, not a nicety.

### 4. Releases and tags

- **Cut draft revisions.** Each Datatracker `-NN` revision is marked by one
  annotated git tag (`draft-bubblefish-naalp-00`, `-01`, …). The maintainer
  renders the draft to `0 errors / 0 flaws` under idnits, submits it to the
  Datatracker, tags the revision, and adds the change-log subsection.
- **Keep the conformance evidence current.** On any release, regenerate the
  independent-oracle vectors under [`vectors/`](vectors/) so the graded bytes
  match what ships, and confirm the parity, CDDL, and registry-drift gates exit
  zero.
- **Coordinate IANA state.** Keep the `application/naalp+cbor` media-type
  registration and the five N-AALP registry requests (in the Internet-Draft's
  IANA Considerations) accurate across revisions, and keep the reused
  COSE algorithm and multicodec references correct.

### 5. Handling security reports

Security reports arrive privately per [SECURITY.md](SECURITY.md) at
`naalp-editor@bubblefish.sh`. The receiving maintainer:

- **acknowledges** the report within a reasonable time;
- **assesses** it as a protocol-design weakness (a downgrade path, a missing
  authentication or effect-authorization binding, a replay/approval-reuse hazard,
  an audit-ordering or carriage-mapping flaw, or a specification ambiguity that
  would lead implementers to build something insecure);
- **coordinates disclosure**, honoring the target window of up to **90 days**
  before public discussion of an unmitigated design weakness; and
- where a specification change is warranted, drives it through the normative
  process above (ADR + revised draft) and credits the reporter in the draft's
  Acknowledgements if they wish.

A security report is never triaged in a public issue while it is unmitigated.

### 6. Conduct enforcement

Maintainers uphold [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and act on reports
sent to `naalp-editor@bubblefish.sh`, up to and including removing contributions
or banning a participant, handled as confidentially as practical.

---

## Review expectations at a glance

| Change class | Example | Requires ADR? | Maintainer approvals | Other gates |
|---|---|---|---|---|
| **Editorial** | wording, formatting, non-normative examples | No | 1 (may be self-merge by an editor) | CI green |
| **Normative — additive** | register a new signature suite / carriage `protocol_id` / channel / kind in the reserved *Specification-Required* range | Yes | 1 (2 when ≥2 maintainers exist) | CI green; change-log bullet; `design` label |
| **Normative — layout / major** | envelope geometry, CBOR map keys, deterministic-encoding rules, `naalp-version` semantics, effect set/lattice, `content-id`/`signer-id` construction | Yes | 2 (or 1 + named external reviewer in the ADR) | CI green; `naalp-version` bump if wire-incompatible; change-log bullet; `design`+`has-consensus` |
| **Implementation / harness** | fix in one of the ten reference impls or the conformance runner | No (unless it changes wire behavior) | 1 | CI green; corpus still passes byte-identically across languages |
| **Security fix** | mitigation for a reported design weakness | Yes if normative | per class above | private-first per SECURITY.md; coordinated disclosure |

The single-maintainer clause: while there is one maintainer, "2 approvals"
degrades to **1 maintainer approval plus one named external reviewer recorded in
the ADR's confirmation step** — the review is never silently dropped, only
sourced from outside the (empty) second-maintainer slot. This mirrors the
Node.js norm that a change may land on fewer approvals only under a stated,
recorded condition rather than by omission. ([Node.js governance][nodejs-gov].)

---

## Becoming a maintainer

The path is modeled on the CNCF maintainer-council process
([template][cncf-gov-maintainer]) and the Node.js collaborator nomination flow
([governance][nodejs-gov]), adapted to a specification project where the
strongest signal is *conformance-grade* contribution.

**Who is a candidate.** Someone who has, over a sustained period, done the work
a maintainer does: authored or reviewed non-trivial pull requests (spec text,
a reference implementation, or the conformance harness), grounded their claims
in primary sources per the research discipline, and collaborated constructively
under the Code of Conduct. Ideal evidence for a spec project includes landed
normative ADRs, an implementation brought to conformance against the shared
corpus, or vector/oracle work anchored to an external standard.

**The steps.**

1. **Nomination.** An existing maintainer proposes the candidate by email to
   `naalp-editor@bubblefish.sh`, and privately confirms the nominee is willing.
   A candidate may also self-nominate to the same address with a summary of
   their contributions.
2. **Public record.** The nomination is recorded in a repository issue that
   links the candidate's contributions, so the reasoning is durable and
   reviewable — the same "record the reasons" principle the project applies to
   every design decision.
3. **Decision.** Approval is by a **simple majority of the existing
   maintainers**, per the CNCF maintainer-council rule. While there is a single
   maintainer, that maintainer decides on the recorded evidence; the goal of
   this whole section is to make growing past one maintainer a real event with a
   written trail, not a private favor.
4. **Onboarding.** On acceptance, the new maintainer is added to this file (name,
   GitHub handle, affiliation, area), granted repository write access, added to
   the `naalp-editor@bubblefish.sh` security/CoC intake, and — where they will
   edit the draft — noted as a document editor with write access to the draft
   source per RFC 8874.

New maintainers normally start with a **scoped area** (for example one reference
implementation, or the conformance harness) rather than full document-editor
authority over the normative draft, which is expanded as trust is established.

---

## Stepping down and removal

**Voluntary step-down.** A maintainer may resign at any time — for example when
they can no longer meet the review commitments — by notifying
`naalp-editor@bubblefish.sh`. They are moved to
[Emeritus maintainers](#emeritus-maintainers) with thanks, and their write
access and security-intake membership are removed.

**Inactivity → emeritus.** Following the CNCF and Node.js conventions, a
maintainer with a period of very low or no activity in the project for roughly
**twelve months** (no authored or approved change that landed) may be moved to
emeritus. This is an administrative reflection of reality, not a judgment;
emeritus maintainers may request reinstatement to active status.

**Involuntary removal.** A maintainer may be removed for failure to fulfill the
responsibilities above, or for a Code-of-Conduct violation, by a **two-thirds
vote of the remaining maintainers** (the CNCF removal threshold). Depending on
the reason, the person may be moved to emeritus or removed outright. With a
single maintainer this clause is inert by construction and exists so the rule is
already in place before it is ever needed.

In all cases, removing a maintainer includes revoking write access and removing
them from the private security-report intake.

---

## Emeritus maintainers

Former maintainers who have stepped down or moved to emeritus are listed here
with thanks for their past stewardship. They hold no merge rights.

*(None yet.)*

---

## Precedents this file follows

This document is grounded in three real precedents, read (not merely cited) this
revision:

- **CNCF `project-template` — `MAINTAINERS.md` and `GOVERNANCE-maintainer.md`.**
  The one-row-per-maintainer shape (Name / affiliation / responsibilities), the
  rule that a maintainer *is* a merge approver, and the concrete
  add/step-down/remove thresholds (add by simple majority; remove by two-thirds;
  inactivity defined as ~a year; conversion to emeritus).
  ([template][cncf-maintainers], [governance][cncf-gov-maintainer])
- **RFC 8874 — Working Group GitHub Usage Guidance.** The document-editor
  write-access model ("chairs MUST give document editors write access … MAY also
  grant other individuals write access … for maintaining supporting code or
  build configurations"), the pull-request-over-direct-commit norm, and the
  `design`/`editorial` issue distinction this repo already uses.
  ([RFC 8874][rfc8874])
- **Node.js `GOVERNANCE.md`.** The collaborator responsibility set (help users,
  review, merge), the recorded-condition merge relaxation ("one approval is
  enough if the pull request has been open more than 7 days"), the
  nomination-with-public-record flow, and the ~12-month inactivity → emeritus
  rule. ([Node.js governance][nodejs-gov])

Where those precedents assume a multi-maintainer body, this file states the
honest single-maintainer adaptation explicitly rather than pretending a council
exists.

[cncf-maintainers]: https://github.com/cncf/project-template/blob/main/MAINTAINERS.md
[cncf-gov-maintainer]: https://github.com/cncf/project-template/blob/main/GOVERNANCE-maintainer.md
[rfc8874]: https://www.rfc-editor.org/rfc/rfc8874.html
[nodejs-gov]: https://github.com/nodejs/node/blob/main/GOVERNANCE.md
