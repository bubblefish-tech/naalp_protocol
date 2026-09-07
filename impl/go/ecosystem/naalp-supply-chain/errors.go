// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import "github.com/bubblefish-tech/naalp_protocol/impl/go/cose"

// Named, fail-closed errors. Every rejection returns exactly one of these — no partial
// result, no silent fallback (this repo's CLAUDE.md FAIL-CLOSED discipline).
var (
	// ErrEmptyInput is returned by a digest function given a nil io.Reader argument where
	// bytes are required (DigestBytes accepts an empty []byte; DigestReader rejects a nil
	// Reader before any read is attempted).
	ErrEmptyInput = &cose.Error{Kind: "EmptyInput", Msg: "no reader supplied to digest"}

	// ErrMalformedModuleList is returned by DecodeGoListModules when the input is not a
	// well-formed stream of JSON objects in the shape `go list -m -json all` emits.
	ErrMalformedModuleList = &cose.Error{Kind: "MalformedModuleList", Msg: "go list -m -json stream is not well-formed JSON"}

	// ErrMalformedGoMod is returned by ParseGoModRequires when a `require` line or block
	// entry does not have exactly a module path and a version token.
	ErrMalformedGoMod = &cose.Error{Kind: "MalformedGoMod", Msg: "go.mod require entry is not (path, version)"}

	// ErrEmptyModulePath is returned by GoModulePURL when path is empty.
	ErrEmptyModulePath = &cose.Error{Kind: "EmptyModulePath", Msg: "module path must not be empty"}

	// ErrInvalidComponentType is returned by BuildSBOM when a component's Type is not one
	// of the fourteen CycloneDX 1.7 component-type enum values.
	ErrInvalidComponentType = &cose.Error{Kind: "InvalidComponentType", Msg: "component type is not a CycloneDX 1.7 enum value"}

	// ErrEmptyComponentName is returned by BuildSBOM when the root component's Name is
	// empty ("name" is REQUIRED on every CycloneDX component).
	ErrEmptyComponentName = &cose.Error{Kind: "EmptyComponentName", Msg: "component name must not be empty"}

	// ErrSchemaInvalid is returned by ValidateSBOM (wrapping SchemaValidationError) when a
	// generated BOM document fails the vendored CycloneDX 1.7 JSON Schema.
	ErrSchemaInvalid = &cose.Error{Kind: "SchemaInvalid", Msg: "document does not satisfy the CycloneDX 1.7 JSON Schema"}

	// ErrEmptyArtifactDigest / ErrEmptySBOMDigest / ErrEmptyBuilderID are returned by
	// BuildStatement when a required binding input is missing — a provenance statement
	// with no artifact digest, no SBOM digest, or no builder identity asserts nothing.
	ErrEmptyArtifactDigest = &cose.Error{Kind: "EmptyArtifactDigest", Msg: "artifact digest set must not be empty"}
	ErrEmptySBOMDigest     = &cose.Error{Kind: "EmptySBOMDigest", Msg: "sbom digest set must not be empty"}
	ErrEmptyBuilderID      = &cose.Error{Kind: "EmptyBuilderID", Msg: "runDetails.builder.id must not be empty"}

	// ErrStatementInvalid is returned by ValidateStatement when a Statement is missing a
	// field SLSA Build L1 requires (spec/build-provenance.md, "REQUIRED for SLSA Build
	// L1: ..." lines) or carries the wrong _type/predicateType URI.
	ErrStatementInvalid = &cose.Error{Kind: "StatementInvalid", Msg: "statement does not satisfy the SLSA Build L1 required-field set"}

	// ErrBindingMismatch is returned by VerifyBinding when a Statement's recorded artifact
	// digest or SBOM digest does not match the digest independently recomputed from the
	// artifact bytes / SBOM bytes actually supplied — the F3 non-circular binding check.
	ErrBindingMismatch = &cose.Error{Kind: "BindingMismatch", Msg: "statement digest does not match the independently recomputed digest"}

	// ErrSeedSize is returned by NewProvenanceSigner when seed is not exactly
	// mldsa65.SeedSize bytes.
	ErrSeedSize = &cose.Error{Kind: "SeedSize", Msg: "ML-DSA-65 seed must be 32 bytes"}

	// ErrPayloadMismatch is returned by VerifyStatementSignature when the COSE_Sign1
	// payload does not equal the expected canonical statement bytes — the signature may be
	// valid over SOME payload, but not the one the caller expects.
	ErrPayloadMismatch = &cose.Error{Kind: "PayloadMismatch", Msg: "COSE_Sign1 payload does not equal the expected statement bytes"}
)
