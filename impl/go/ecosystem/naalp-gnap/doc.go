// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package naalpgnap bridges N-AALP's native multi-hop agent-delegation chain
// (design.md §18, C15, the DelegationGrant object — R-DEL-1..8) to GNAP, the Grant
// Negotiation and Authorization Protocol (RFC 9635), per the grounded recommendation
// documented under design.md addendum E4.2 (requirements.md Requirement 6 item 2 / R6.2).
// It is purely additive: no wire format, CDDL, conformance
// vector, or corpus file is touched, and no N-AALP cryptographic primitive is
// reimplemented — key proofing reuses the agent's EXISTING signer-id keypair
// (impl/go/cose.Signer/Verifier), the DID-shaped JWK encoding reuses
// impl/go/ecosystem/naalp-did (E4.1), and the delegation-chain arithmetic this package
// depends on (policy.Effect.Authorizes, delegation.ScopeContained,
// delegation.Resolved/Grant) reuses impl/go/delegation (C15) unchanged — this package
// never re-verifies a chain, it only PROJECTS an already-verified chain's leaf into a
// GNAP-consumable assertion, fail-closed.
//
// # Grounding (primary sources fetched and read this session, 2026-09-01)
//
//   - GNAP core protocol: RFC 9635, "Grant Negotiation and Authorization Protocol",
//     https://www.rfc-editor.org/rfc/rfc9635.html (and the raw .txt rendering, fetched
//     separately to confirm exact section titles/field names) — IETF Standards Track,
//     Proposed Standard, published October 2024. Confirmed this session: the Grant
//     Request's top-level fields (access_token/client/subject/user/interact, §2), the
//     access_token.access array shape (§2.1.1: type/actions/locations/datatypes), the
//     client.key object (§2.3: proof + jwk), the Grant Response's top-level fields
//     (continue/access_token/interact/subject/instance_id/error, §3, with §3.1-§3.6 each
//     confirmed as a distinct subsection), the continuation POST body's "interact_ref"
//     field (§5.1), and the "GNAP Assertion Formats" IANA registry (§10.6, initial
//     values "id_token"/"saml2").
//   - Key proofing: RFC 9421, "HTTP Message Signatures",
//     https://www.rfc-editor.org/rfc/rfc9421.html — IETF Standards Track, published
//     February 2024. Confirmed this session: the signature-base line format (one
//     `"<sf-string component-id>": <value>` line per covered component, terminated by an
//     `"@signature-params": (<ordered component list>)<params>` line — §2.3/§2.5), the
//     component-identifier/parameter serialization as RFC 8941 Structured Field values
//     (an Inner List of sf-strings, with semicolon-prefixed parameters), and the
//     Signature-Input/Signature header shapes (a Dictionary keyed by a signature label,
//     §4.1/§4.2). RFC 9635 §7.3.1 names RFC 9421 ("httpsig") as its key-proofing
//     mechanism and requires covering at least "@method"/"@target-uri" unconditionally
//     plus "content-digest" (RFC 9530) when a body is present and "authorization" when
//     an Authorization header is present — gnapsig.go's RequiredComponents implements
//     exactly that split; see the Limitations section below for what was NOT
//     independently re-verified against the RFC's full normative text.
//   - design.md §18 (the DelegationGrant object this package bridges): the object being
//     bridged, its D2 fields (subject/effect_cap/max_depth/not_before/not_after/scope),
//     its D3 twelve-step chain verifier (impl/go/delegation.VerifyChain, unmodified by
//     this package), and its D4 export/attenuation posture.
//
// # A correction to the E4.2 grounding note's (c)2 mapping sketch (verify-relay)
//
// The grounding note's recommendation section (c)2 sketched carrying DelegationGrant
// evidence "as a subject.assertion_formats entry in the GNAP request". Reading RFC 9635's
// own text this session shows that sketch does not hold: §2.2 is titled "REQUESTING
// Subject Information" and its assertion_formats array is a list of formats the client
// asks the AS to RETURN about the resource owner (confirmed by the response-side
// counterpart, §3.4 "Returning Subject Information", whose "assertions" array — an
// array of {format, value} objects — is what the AS sends BACK). There is no field under
// "subject" for a client to PUSH an assertion it already holds. The field that does
// exactly that is §2.4, "Identifying the User": "user.assertions" is an array of
// {format, value} objects the client instance sends TO the AS, described normatively as
// data "the client instance knows" and "MAY send... to the AS" — the push direction E4.2
// needs. This package therefore carries the exported DelegationGrant evidence in
// GrantRequest.User.Assertions (gnapclient.go's BuildGrantRequest), not in
// GrantRequest.Subject. This is a grounding refinement recorded here per the
// verify-relay discipline (a grounding note's mapping sketch is a lead, not a witness;
// this package's own primary-source read is what the code implements), not a
// disagreement with the note's overall recommendation (GNAP as the bridge target)
// or its D15 export-only posture, both of which this package implements unchanged.
//
// # Decision surfaced, not frozen (per this repo's wire-freeze-completeness discipline)
//
// This package does NOT freeze, and this build item does not decide, the following —
// they are recorded here so the follow-on design/IANA pass inherits the reasoning
// instead of re-deriving it, exactly as the grounding note asked:
//
//  1. The concrete "GNAP Assertion Formats" registry value name — DECIDED 2026-09-02
//     (maintainer): the self-assigned value is "naalp-delegation-grant"
//     (AssertionFormatDelegationGrant, gnapclient.go), byte-identical to the frozen CDDL
//     union production `naalp-delegation-grant` (spec/naalp-draft-01.cddl) so one name
//     spans wire authority, code, and the GNAP assertion carrier. The lowercase-hyphenated
//     style matches the registry's initial entries. IANA registration under RFC 9635 §10.6
//     is DEFERRED to post-publish (the prerequisite is a frozen, published payload spec,
//     which is not yet ratified); register after publication under the BubbleFish
//     change-controller. The name is self-assigned now; only the external IANA submission
//     waits.
//  2. The JSON shape of DelegationAssertionPayload (gnapclient.go) — the bytes carried
//     in Assertion.Value for that format. RFC 9635 only requires "the JSON string
//     serialization of the assertion" (§2.4); the internal shape is exactly what a real
//     registry entry's own specification would define, and this package's shape
//     (subject/effect_cap/scope/root_issuer/content_id) is a first proposal, not a
//     ratified schema. It carries ONLY information already exposed by an already-verified
//     delegation.Resolved leaf (no new fields, no unverified claims).
//  3. Whether a full delegation CHAIN (multiple grants) or only the LEAF grant's
//     post-attenuation ceiling should be exported. This package exports the leaf's
//     effective ceiling only (ExportDelegationEvidence takes one delegation.Resolved);
//     carrying the full chain (so an external RS could re-verify it independently rather
//     than trust this bridge's projection) is a real alternative this package does not
//     rule out but does not implement — ContentID names only the leaf.
//
// # Honest, named gaps (B5 — what this session did NOT verify)
//
//   - RFC 9635 §7.3.1's exact, unconditional-vs-conditional covered-component
//     requirements for "httpsig" proofing were read via a summarizing fetch, not the
//     full raw normative paragraph text; RequiredComponents' split (content-digest iff a
//     body is present, authorization iff an Authorization header is present) is this
//     package's own reasonable default and should be re-verified against the RFC's full
//     §7.3.1 text before being treated as final.
//   - RFC 9635 §10.6's registration procedure/template fields (name/description/
//     change-controller/reference, per a summarizing fetch) were not read in full raw
//     text; the exact submission process for a new assertion-format value is not
//     verified here.
//   - The RFC 9421 "HTTP Signature Algorithms" IANA registry's exact registered-name
//     rules were not checked; the alg tags this package emits ("ml-dsa-65", "ml-dsa-87",
//     "ed25519" — gnapsig.go's AlgTag) are NOT confirmed as registered values and are
//     carried only for local self-description. Verify() never consults this string; it
//     is informational only.
//   - draft-ietf-gnap-resource-servers (the companion WG document governing how an RS
//     validates a GNAP-issued token) was not fetched this session — out of E4.2's
//     client-side scope per the grounding note, but adjacent to how an N-AALP-issued
//     grant would later be consumed.
//
// # Non-scope
//
// This package implements the CLIENT side of a GNAP exchange only (grant request,
// key-proofing, continuation polling) — it is not a GNAP authorization server, and it
// performs no HTTP transport itself (callers own the actual request/response I/O; this
// package produces and consumes the bytes/headers). It does not re-verify a
// DelegationGrant chain (impl/go/delegation.VerifyChain already does that, unmodified);
// it only exports an already-verified leaf's post-attenuation ceiling, fail-closed
// (ExportDelegationEvidence, gnapclient.go — the D15 "never lets an external GNAP AS
// mint new N-AALP authority" posture).
package naalpgnap
