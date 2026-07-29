<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — IETF Independent Submission + IANA: step-by-step instructions

This is the complete, ordered runbook for getting `draft-bubblefish-naalp-00` (a) posted as an
Internet-Draft, (b) published as an RFC via the **Independent Submission stream**, and (c) its
IANA registrations completed. Every process fact is tagged **[W]** (WITNESSED — a primary source
was read on 2026-07-27, URL given) or **[R]** (RELAYED — secondhand/inferred; verify before
relying on it). Re-verify the [R] items and the live dates/URLs before you submit, because IETF
process pages and blackout dates change.

**Two things to decide first (yours to make):**
- **Category:** `Informational` (current front matter, matches the N-PAMP sibling) or
  `Experimental`. Both are accepted by the ISE **[W]** (ISE checklist). Experimental better fits
  "a new protocol seeking implementation experience"; Informational fits "documenting a design."
  To switch, change `category: info` → `category: exp` in the draft front matter.
- **Monitored email:** `naalp-editor@bubblefish.sh` is a placeholder. The ISE, the IESG conflict
  review, and AUTH48 all use it — it MUST be an address you monitor. Confirm or replace it.

---

## Stage 0 — Build and self-check the draft

The source of truth is `ietf/draft-bubblefish-naalp-00.md` (kramdown-rfc). Toolchain:
kramdown-rfc, xml2rfc v3 (RFC 7991), and idnits.

```
# from ietf/
kramdown-rfc draft-bubblefish-naalp-00.md > draft-bubblefish-naalp-00.xml   # -> xml2rfc v3 XML
xml2rfc draft-bubblefish-naalp-00.xml --text --html                         # -> .txt + .html
# one-shot alternative: kdrfc draft-bubblefish-naalp-00.md
```

- kramdown-rfc: `https://github.com/cabo/kramdown-rfc` **[W]**; it defaults to v3 output **[W]**.
- xml2rfc current release **3.34.0**, requires Python ≥ 3.10, implements the RFC 7991 v3
  vocabulary **[W]** (`https://pypi.org/pypi/xml2rfc/json`, `https://www.rfc-editor.org/rfc/rfc7991`).
- **Run idnits in "Submission check" mode** at `https://author-tools.ietf.org/idnits` **[W]**
  (idnits v3 accepts XML). Fix every error and as many warnings as possible — the datatracker
  re-runs equivalent checks at upload and **can hard-block** on serious formatting errors **[W]**
  (`https://datatracker.ietf.org/submit/tool-instructions/`). `idnits` is not installed locally
  in this repo's toolchain; run it via author-tools.
- The local build is already clean: kramdown-rfc exit 0, xml2rfc exit 0, no unused references and
  no over-72-character lines.

**Filename / version rules [W]** (`https://ietf.github.io/id-guidelines/`): individual/independent
form `draft-<author-or-org>-<name>-NN`; characters lowercase `a-z`, digits `0-9`, hyphens only;
first version ends `-00`, each revision +1. `draft-bubblefish-naalp-00` conforms.

---

## Stage 1 — Post the Internet-Draft (datatracker)

An RFC can only be considered after the document is posted as an I-D **[W]** (ISE checklist:
"a document must first be posted online as an Internet-Draft").

1. **(Recommended) Create / sign in to a datatracker account** and list yourself as an author, so
   the email-confirmation step is bypassed. `https://datatracker.ietf.org/accounts/login/` **[W]**.
   An account is not strictly required for the web upload but simplifies it **[R]** (authors.ietf.org
   snippet).
2. **Check the live blackout banner** at `https://datatracker.ietf.org/submit/` **[W]**. The
   datatracker freezes *new* I-D submissions in a window before each IETF meeting until the meeting
   starts (the banner shows the exact UTC dates and is dynamic — do **not** hardcode). The freeze
   applies to individual/independent drafts too **[W]**; an Area Director can grant an exception in
   exceptional cases **[W]** (`https://www.ietf.org/blog/draft-deadlines-and-exceptions/`).
3. **Upload the `.xml`** at `https://datatracker.ietf.org/submit/` **[W]**. XML v3 source is
   preferred (v2 accepted; plain text accepted only if no XML) **[W]**
   (`.../submit/tool-instructions/`). The tool auto-generates txt/html from the XML and
   re-validates.
4. **Confirm authorship:** if you are not logged in as a listed author, an email goes to the
   authors listed in the `-00` document; open it and click the link to post the draft **[W]**. If
   logged in as an author, this step is skipped **[R]** (snippet).
5. **Posted:** the draft lands in the repository and an **I-D Action** announcement goes out within
   ~15 minutes **[W]**. No working-group-chair approval is needed for an individual
   `draft-bubblefish-naalp-*` **[W]**.

---

## Stage 2 — Request Independent-stream publication (the ISE)

The Independent Submission stream publishes RFCs "outside the official IETF, IAB, and IRTF
processes"; such documents "do not require community consensus and are not standards or best
practices." **[W]** (`https://www.rfc-editor.org/about/independent/`). The approver is the
**Independent Submissions Editor (ISE)**, currently **Eliot Lear**, at **`rfc-ise@rfc-editor.org`**
**[W]** (same page + ISE checklist).

**Email `rfc-ise@rfc-editor.org`** with all of the following (required by the ISE checklist **[W]**,
`https://www.rfc-editor.org/authors/ise/ise-checklist/`). There is **no web form** — the email is
the submission format **[W]**:

1. The **filename** of the posted I-D (`draft-bubblefish-naalp-00`).
2. The **desired category** — Informational or Experimental (see "decide first" above).
3. A **summary of any prior IETF WG / IESG discussion** — for N-AALP: *none; this is a
   privately-developed protocol with two independent reference implementations and no IETF
   working-group history.*
4. The **IANA assertion, verbatim** (from `IANA.md` Part E): *"No IANA allocation requested in
   draft-bubblefish-naalp-00 requires 'IETF Review' or 'Standards Action.'"* This is required
   **[W]** and is the reason `IANA.md` uses only Specification Required / Expert Review /
   Experimental / Private Use policies.
5. A **statement of purpose, intended audience, merits, and significance** (a paragraph; draw from
   the draft's Introduction).
6. An **acknowledgment that the IPR rules of RFC 4846 and RFC 5744 apply** **[W]**.
7. **Suggestions for one or more competent, independent reviewers** (people who understand
   agent protocols / CBOR / COSE / PQC and are not conflicted).

**What happens next [W]** (`https://www.rfc-editor.org/about/independent/`, RFC 4846): ISE initial
assessment → ISE-commissioned independent expert reviews (you may rebut) → **IESG conflict review
under RFC 5742 (BCP)** — non-technical, checks only for conflict with IETF work; it can request a
delay but cannot veto on technical grounds → ISE decision → RFC Production Center → **AUTH48**
final proofreading → RFC number assigned. Track state at `https://datatracker.ietf.org/stream/ise/`
**[W]**.

**Do NOT** anywhere imply IETF consensus, endorsement, or standards-track status; neither
Informational nor Experimental is on the standards track **[W]** (RFC 2026 §4.2; RFC 7841
boilerplate). The draft already states this in its Abstract and Status.

**Governing references to cite** (all **[W]** via rfc-editor.org `/info/` pages): RFC 8730 (ISE
model) as updated by RFC 9920 (Feb 2026, obsoletes RFC 9280); RFC 4846 (+ RFC 5744) decision/IPR
guidance; RFC 5742 (BCP) conflict review; RFC 2026 maturity levels; RFC 7841 streams/boilerplate;
RFC 8729 (RFC series, obsoletes RFC 4844); BCP 78 = RFC 5378 and BCP 79 = RFC 8179 (IPR).

---

## Stage 3 — IANA registrations

The full package is in `IANA.md`. Two paths, both requiring **no** IETF Review / Standards Action:

### 3a. Media type `application/naalp+cbor` (RFC 6838, BCP 13 — still current **[W]**,
`https://www.rfc-editor.org/info/rfc6838/`; updated by RFC 9694 which does not change the
`application`-tree process **[W]**).

- The `+cbor` structured syntax suffix is **already registered by RFC 8949** in the IANA
  "Structured Syntax Suffixes" registry **[W]**
  (`https://www.iana.org/assignments/media-type-structured-suffix/`). N-AALP references it; it does
  **not** register `+cbor`. (Note: RFC 9277 does NOT define `+cbor` — it is CBOR stable storage;
  do not cite it for the suffix **[W]**.)
- For an RFC-published registration, the completed template lives **inside the document's IANA
  Considerations** and IANA registers it on publication — no separate email needed **[W]** (RFC
  6838 §4.12). The template (all 17 fields) is in `IANA.md` Part A and in the draft's IANA
  Considerations.
- Notice of a standards-tree registration SHOULD be sent to **`media-types@iana.org`** for review
  **[W]** (RFC 6838 §5.1, §8 — this address replaced the old `ietf-types@iana.org`). For a non-RFC
  registration the web form is `http://www.iana.org/form/media-types` and general email is
  `iana@iana.org` **[W]** (RFC 6838 §5.2).

### 3b. The five new N-AALP registries (Channels, Object Kinds, Effects, Carriage Protocol Ids,
Error Codes).

- These are created by IANA from the draft's **IANA Considerations** on publication. Each uses
  **Specification Required** (or Experimental/Private Use ranges), naming a **Designated Expert**
  and giving **Expert guidance** (RFC 8126, BCP 26 — still current **[W]**,
  `https://www.rfc-editor.org/info/rfc8126/`). The policy names and their meanings are in `IANA.md`
  Part D and the draft.
- **Early allocation (RFC 7120, BCP 100 [W])** is a WG/IETF-stream mechanism (needs WG chairs +
  ADs) and is effectively unavailable to an Independent submission with no WG. N-AALP relies on
  Specification-Required registration at publication instead; N-AALP's own code points are already
  fixed by the specification (channels 0..19, effects 0..3, protocol-id ranges), so no pre-
  publication numeric assignment is needed.
- **Early IANA review is available and encouraged:** email `iana@iana.org` at any stage to have
  IANA review the IANA Considerations before publication **[W]**
  (`https://www.iana.org/help/protocol-registration`). IANA is not auto-notified of I-D updates —
  re-ping them if the section changes. Use `TBDn` placeholders for any value you want IANA (not
  the spec) to assign.

---

## Stage 4 — After publication

- The RFC Editor **removes the Implementation Status section and the RFC 7942 reference** before
  publication **[W]** (RFC 7942 §2.1) — the draft already carries the "please remove" note.
- Later draft revisions are `-01`, `-02`, … (each +1); update `docname` accordingly and re-run
  Stage 0.

---

## Could NOT verify this run (verify before submitting)

- The exact datatracker upload URL `https://datatracker.ietf.org/submit/` was WITNESSED as a page,
  but some behavior (no-container rule, the "not logged in" nuance, the API-requires-account rule)
  came from JavaScript-rendered pages returning only titles — marked **[R]**.
- RFC 7991 Appendix A exact `ipr`/`category`/`submissionType` enumerated values were not read
  verbatim (fetch truncated); the values used (`trust200902`, `info`/`exp`, `independent`) are
  from the official kramdown-rfc template and build cleanly, but confirm against RFC 7991 if a
  strict cite is needed.
- RFC 9920 (Feb 2026) is post-training; its detailed ISE-model changes vs RFC 8730 were not read
  in full. Treat 9920 as the operative top of the RFC-Editor-model chain but read it before citing
  specifics.
- Live blackout dates and the current ISE identity — re-check `datatracker.ietf.org/submit/` and
  `rfc-editor.org/about/independent/` at submission time.
