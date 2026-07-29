<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Cover letter to the Independent Submissions Editor (ISE)

Ready-to-send request for Independent-stream publication of
`draft-bubblefish-naalp-00`. Fill in the two `<CONFIRM ...>` placeholders, post the
Internet-Draft first (see `SUBMISSION.md` Stage 1), then send this as the body of an
email. Independent-stream process authority: RFC 4846 (Independent Submissions to the
RFC Editor) and RFC 8730 (the ISE role and the Independent Submission stream).

---

**To:** rfc-ise@rfc-editor.org
**Subject:** Independent Submission request: draft-bubblefish-naalp-00 (N-AALP), Informational

Dear Independent Submissions Editor,

I request review and, if you find it suitable, publication of the following Internet-Draft
as an **Informational RFC** through the **Independent Submission stream** (RFC 4846,
RFC 8730):

- **Draft name:** draft-bubblefish-naalp-00
- **Title:** N-AALP: The Native Agentic Application Layer Protocol
- **Intended status:** Informational
- **Stream:** Independent Submission
- **Datatracker:** https://datatracker.ietf.org/doc/draft-bubblefish-naalp-00/
  (posted <CONFIRM POSTING DATE>)
- **Author / contact:** Shawn Sammartano, BubbleFish Technologies, Inc.,
  naalp-editor@bubblefish.sh <CONFIRM this address is monitored for ISE, IESG
  conflict-review, and AUTH48 correspondence>

## What the document specifies

N-AALP is an application-layer object protocol for autonomous software agents. Every N-AALP
object is a deterministically encoded CBOR structure (RFC 8949) signed with COSE (RFC 9052),
carrying under one signature its content identity, its originating signer, a closed effect
label that is an authorization input rather than an advisory hint, optional approval and
audit bindings, and its causal derivation. The identical signed object is carried, with
identical object-level guarantees, over several transports. The document defines a frozen
envelope, a post-quantum signature profile (ML-DSA per FIPS 204, with an optional Ed25519
hybrid), a self-certifying identity with key rotation, a single-use approval ledger, a
hash-chained audit and causal-ordering model, native streaming with a per-stream
commitment, foreign-protocol carriage by class, and twenty channel surfaces.

## Why the Independent Submission stream

This document is a stable, implemented specification produced outside any IETF Working
Group. It is not the product of IETF consensus, it does not claim to be, and its Abstract
and Introduction say so plainly. It does not modify or extend any IETF Standards-Track work;
it reuses existing IANA registries (the COSE algorithm registry, media types) rather than
forking them, and its new IANA registries use only Specification Required / Expert Review /
Experimental / Private Use policies (never IETF Review or Standards Action). It is offered
for the archival, citable, permanent record the RFC series provides, which is the purpose
the Independent stream serves.

To the best of my knowledge it does not conflict with, or compete with, the work of any
current IETF Working Group; I am content for the document to undergo the IESG conflict-review
that the Independent stream applies.

## IPR

The document carries the standard IETF Trust "trust200902" IPR boilerplate (`ipr:
trust200902` in the front matter). I am not aware of any IPR that applies to this document,
and no IPR disclosures relating to it have been filed. The reference code is licensed under
Apache-2.0; anyone may implement the protocol royalty-free.

## Implementation status (RFC 7942)

The document is not paper. It has an Implementation Status section (to be removed before
publication, per RFC 7942) describing multiple independent, interoperating reference
implementations. Deterministic post-quantum signatures are byte-identical across seven
independent implementations in seven languages, exercised by a machine-gradable conformance
corpus whose expected values derive from the underlying RFC/FIPS/NIST vectors (never from the
implementations under test). The CDDL data model is machine-validated. This gives a reviewer
running code and a non-circular conformance suite to check any claim in the text.

## IANA

The IANA Considerations register one media type (`application/naalp+cbor`, per RFC 6838 /
BCP 13) and create five new N-AALP registries, all under Specification Required or Expert
Review (RFC 8126 / BCP 26). No early allocation is requested; registration proceeds at
publication. A standalone `IANA.md` package accompanies this submission.

I am happy to answer questions and to make editorial changes you request. Thank you for
considering this submission.

Sincerely,
Shawn Sammartano
BubbleFish Technologies, Inc.
naalp-editor@bubblefish.sh

---

### Before you send

1. Post the I-D first (`SUBMISSION.md` Stage 1) so the datatracker URL resolves; fill in the
   posting date.
2. Confirm `naalp-editor@bubblefish.sh` is monitored — all ISE, IESG conflict-review, and
   AUTH48 correspondence goes there.
3. Confirm the current Independent Submissions Editor and the correct contact address at
   https://www.rfc-editor.org/about/independent/ (the ISE role and its holder change over
   time; `rfc-ise@rfc-editor.org` is the stable stream address).
4. Attach or link the rendered draft (`draft-bubblefish-naalp-00.txt`) and `IANA.md`.
