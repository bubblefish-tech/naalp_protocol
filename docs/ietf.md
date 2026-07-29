<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# IETF Internet-Draft

N-AALP is documented as an Internet-Draft for the **Independent Submission stream** (it does not
represent IETF consensus and is not a standards-track document).

| artifact | path |
|---|---|
| Internet-Draft source (kramdown-rfc) | `ietf/draft-bubblefish-naalp-00.md` |
| IANA registration package | `ietf/IANA.md` |
| Submission runbook (datatracker + ISE + IANA) | `ietf/SUBMISSION.md` |
| Normative CDDL wire authority | `spec/naalp-draft-00.cddl` |

## Building the draft

```console
$ cd ietf
$ kramdown-rfc draft-bubblefish-naalp-00.md > draft-bubblefish-naalp-00.xml
$ xml2rfc draft-bubblefish-naalp-00.xml --text --html
```

The draft builds clean (no unused references, no over-length lines). Run `idnits` in "Submission
check" mode online at `https://author-tools.ietf.org/idnits` before submitting.

## Submitting

The `SUBMISSION.md` runbook gives the exact, ordered steps — every process fact tagged WITNESSED
(with a primary-source URL) or RELAYED (verify before relying on it):

1. Build and self-check the draft (Stage 0).
2. Post the Internet-Draft via the datatracker (Stage 1).
3. Email the Independent Submissions Editor (`rfc-ise@rfc-editor.org`) with the checklist,
   including the assertion that **no IANA allocation requires IETF Review or Standards Action**
   (Stage 2).
4. IANA registrations — the media type `application/naalp+cbor` (RFC 6838) and the five N-AALP
   registries (Specification Required), all carried in the draft's IANA Considerations (Stage 3).

!!! warning "Before you submit"
    Confirm the monitored editor email, choose the category (`Informational` or `Experimental`),
    and re-check the live datatracker blackout dates and ISE identity — these change over time.
