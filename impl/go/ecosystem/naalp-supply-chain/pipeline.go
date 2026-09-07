// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"encoding/json"
	"time"
)

// ReleaseArtifact is the artifact bytes a release is being produced for (e.g. a compiled
// SDK archive, a source tarball).
type ReleaseArtifact struct {
	Name string
	Data []byte
}

// BuildResult is everything BuildRelease produces: the real, schema-validated SBOM, the
// digest-bound and SLSA-L1-validated provenance Statement, and the N-AALP COSE_Sign1
// signature over that Statement's canonical JSON bytes.
type BuildResult struct {
	ArtifactDigest   DigestSet
	SBOM             *BOM
	SBOMJSON         []byte
	SBOMDigest       DigestSet
	Statement        *Statement
	StatementJSON    []byte
	SignedProvenance []byte // tagged COSE_Sign1 bytes over StatementJSON
}

// BuildRelease wires the full supply-chain pipeline: build artifact -> compute digest ->
// emit SBOM -> emit signed provenance statement over (artifact-digest, sbom-digest). Every
// stage is fail-closed — a schema-invalid SBOM or an SLSA-L1-invalid Statement aborts the
// whole call (no partial BuildResult is ever returned on error).
//
//  1. DigestBytes(artifact.Data) -> ArtifactDigest.
//  2. BuildSBOM(rootComponent, modules, finished) -> SBOM.
//  3. MarshalAndValidateSBOM(SBOM) -> SBOMJSON, schema-validated against the real
//     vendored CycloneDX 1.7 schema (ValidateSBOM) before proceeding.
//  4. DigestBytes(SBOMJSON) -> SBOMDigest.
//  5. BuildStatement(artifact.Name, ArtifactDigest, SBOMDigest, builderID, started,
//     finished) -> Statement, binding both digests into
//     predicate.buildDefinition.externalParameters / subject[0].digest.
//  6. ValidateStatement(Statement) — SLSA Build L1 required-field check.
//  7. json.Marshal(Statement) -> StatementJSON (canonical: encoding/json sorts map keys
//     and struct field order is fixed, so re-marshaling the same Statement always
//     produces byte-identical output — see pipeline_test.go's determinism test).
//  8. signer.SignStatement(StatementJSON) -> SignedProvenance.
func BuildRelease(artifact ReleaseArtifact, rootComponent Component, modules []Module, builderID string, signer *ProvenanceSigner, started, finished time.Time) (*BuildResult, error) {
	artifactDigest := DigestBytes(artifact.Data)

	sbom, err := BuildSBOM(rootComponent, modules, finished)
	if err != nil {
		return nil, err
	}
	sbomJSON, err := MarshalAndValidateSBOM(sbom)
	if err != nil {
		return nil, err
	}
	sbomDigest := DigestBytes(sbomJSON)

	statement, err := BuildStatement(artifact.Name, artifactDigest, sbomDigest, builderID, started, finished)
	if err != nil {
		return nil, err
	}
	if err := ValidateStatement(statement); err != nil {
		return nil, err
	}

	statementJSON, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}

	signed, err := signer.SignStatement(statementJSON)
	if err != nil {
		return nil, err
	}

	return &BuildResult{
		ArtifactDigest:   artifactDigest,
		SBOM:             sbom,
		SBOMJSON:         sbomJSON,
		SBOMDigest:       sbomDigest,
		Statement:        statement,
		StatementJSON:    statementJSON,
		SignedProvenance: signed,
	}, nil
}
