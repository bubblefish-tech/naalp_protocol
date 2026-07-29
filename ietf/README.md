<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# `ietf/` — the official N-AALP IETF submission folder

Everything needed to submit **N-AALP** to the IETF as an **Independent Submission**
(Informational) and to register its IANA code points. This folder is the single source of
truth for the Internet-Draft.

## Contents

| File | What it is |
|------|------------|
| `draft-bubblefish-naalp-00.md` | **The draft source** (kramdown-rfc / Markdown). Edit this; regenerate the rest. |
| `draft-bubblefish-naalp-00.xml` | **The submittable file** — RFCXML v3 (xml2rfc v3). This is what you upload to the datatracker. Generated. |
| `draft-bubblefish-naalp-00.txt` | The plain-text rendering (for review and the traditional record). Generated. |
| `draft-bubblefish-naalp-00.html` | The HTML rendering (for review). Generated. |
| `IANA.md` | The IANA registration package: the `application/naalp+cbor` media type (RFC 6838 / BCP 13) + five new N-AALP registries (all Specification Required / Expert Review / Experimental / Private Use), reused registries, Designated-Expert guidance, and the verbatim ISE assertion. |
| `ISE-cover-letter.md` | A ready-to-send cover letter to the Independent Submissions Editor (fill in two placeholders, then email). |
| `SUBMISSION.md` | The step-by-step runbook: build & self-check → post the I-D (datatracker) → request ISE publication → IANA → after publication. Every process fact tagged WITNESSED (with a source URL) or RELAYED. |

## Rebuild the draft

The `.xml`, `.txt`, and `.html` are generated from the `.md` source. Regenerate after any edit:

```sh
cd ietf
kramdown-rfc draft-bubblefish-naalp-00.md > draft-bubblefish-naalp-00.xml
xml2rfc --text --html draft-bubblefish-naalp-00.xml
# one-shot alternative:
#   kdrfc draft-bubblefish-naalp-00.md
```

Then run an idnits structural check. `idnits` is not installed here; run it online at
<https://author-tools.ietf.org/> (upload the `.xml` or `.txt`) and resolve any nits before
submitting. A local pass targets **0 errors, 0 flaws**.

## The submission, in four moves

1. **Post the Internet-Draft** at <https://datatracker.ietf.org/submit/> — upload
   `draft-bubblefish-naalp-00.xml`. (Details: `SUBMISSION.md` Stage 1.)
2. **Request Independent-stream publication** — email `ISE-cover-letter.md` to
   `rfc-ise@rfc-editor.org` once the draft is posted. (Stage 2.)
3. **IANA** — the registrations in `IANA.md` proceed at publication; no early allocation is
   requested. (Stage 3.)
4. **After publication** — see `SUBMISSION.md` Stage 4.

## Facts to confirm before submitting

- `naalp-editor@bubblefish.sh` is monitored (ISE, IESG conflict-review, and AUTH48 all use it).
- The current Independent Submissions Editor and contact at
  <https://www.rfc-editor.org/about/independent/> (the stable stream address is
  `rfc-ise@rfc-editor.org`).
- The draft's Implementation Status section (RFC 7942) is removed by the RFC Editor before
  publication — it is marked for removal in the source.

## Licensing

The draft text is under the **IETF Trust's Legal Provisions (BCP 78)** via the
`ipr: trust200902` attribute in the front matter — this is separate from and additional to the
repository's Apache-2.0 code license. See `../NOTICE` and `../LICENSE.md`.
