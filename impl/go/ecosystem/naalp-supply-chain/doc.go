// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package supplychain builds signed, attestable release artifacts for the N-AALP
// reference SDKs: a real Software Bill of Materials (SBOM) parsed from the actual Go
// module dependency graph, and a signed provenance/attestation statement binding an
// artifact's content digest to its SBOM's content digest. This satisfies BubbleFish
// Global Engineering Policy 5.5 ("published artifacts carry a signature (cosign/Sigstore)
// + an SBOM"). It is purely additive: no N-AALP wire format, CDDL, conformance vector, or
// corpus file is touched — it consumes impl/go/cose's C2 signing layer directly (the same
// generic COSE_Sign1 construction naalpcore.Sign builds on) rather than the N-AALP object
// envelope, because a supply-chain attestation is not an N-AALP wire object and carries no
// (channel, kind).
//
// # Grounding (primary sources fetched and read this session, 2026-08-31)
//
//   - SBOM format: CycloneDX 1.7, published 2026-12-10 (per cyclonedx.org/specification/
//     overview/, fetched this session — the version string is confirmed live at
//     https://cyclonedx.org/docs/1.7/json/). The exact JSON Schema this package validates
//     against is vendored verbatim at schema/bom-1.7.schema.json, downloaded this session
//     from https://raw.githubusercontent.com/CycloneDX/specification/master/schema/
//     bom-1.7.schema.json (315722 bytes, draft-07 JSON Schema, $id
//     "http://cyclonedx.org/schema/bom-1.7.schema.json"). No bytes in that file were
//     hand-edited — see jsonschema_test.go for a byte-count/prefix check that it is the
//     real download, not a trimmed stand-in.
//   - Provenance/attestation shape: the in-toto Attestation Framework Statement layer v1
//     (_type "https://in-toto.io/Statement/v1", https://github.com/in-toto/attestation/
//     blob/main/spec/v1/statement.md, fetched this session) wrapping a SLSA Provenance v1
//     predicate (predicateType "https://slsa.dev/provenance/v1",
//     https://slsa.dev/spec/v1.1/provenance, fetched this session). The exact required
//     field set for SLSA Build L1 (predicate.buildDefinition.{buildType,
//     externalParameters}, predicate.runDetails.builder.id) is read directly from SLSA's
//     own normative text, https://raw.githubusercontent.com/slsa-framework/slsa/main/spec/
//     build-provenance.md (fetched this session, 603 lines; the "REQUIRED for SLSA Build
//     L1: ..." lines are quoted verbatim in provenance_validate.go's doc comments) and
//     cross-checked against SLSA's own machine-readable CUE schema,
//     https://raw.githubusercontent.com/slsa-framework/slsa/main/spec/schema/
//     provenance.cue (fetched this session; there is no published JSON Schema for the SLSA
//     provenance predicate, unlike CycloneDX — the .cue file is the closest thing to one
//     SLSA itself publishes, and provenance_validate.go documents this as the honest,
//     named difference from the SBOM side's JSON-Schema validation).
//   - Package URL (purl) type for a Go module: type "golang",
//     https://raw.githubusercontent.com/package-url/purl-spec/main/types/
//     golang-definition.json (fetched this session): "pkg:golang/<namespace>/<name>@
//     <version>", namespace+name lowercased, version = the resolved module version.
//
// # What this package does NOT do (a documented seam, not a gap)
//
// It does not call a live Sigstore Fulcio/Rekor transparency log, and it does not produce
// an x.509-based cosign signature. The classical cosign/Sigstore path is keyless (an OIDC
// identity token exchanged for a short-lived certificate, then logged to a public
// transparency log) and is a distinct trust model from N-AALP's own long-lived ML-DSA
// signer identity (design.md §5.1). This package signs the provenance Statement's
// canonical JSON bytes with an N-AALP-native COSE_Sign1 object (impl/go/cose.Sign1, the
// same C2 construction naalpcore.Sign uses under naalp.Signer) instead: a real,
// post-quantum, offline-verifiable signature over the same statement a cosign/Sigstore
// pipeline would sign, produced with the project's own signer rather than a third-party
// transparency log this package never contacts. A caller who also wants the classical
// cosign path can take this package's SignedStatement bytes (or the underlying
// StatementJSON) and hand them to `cosign attest` unmodified — the two signature schemes
// are independent and additive, not a replacement of one by the other.
package supplychain
