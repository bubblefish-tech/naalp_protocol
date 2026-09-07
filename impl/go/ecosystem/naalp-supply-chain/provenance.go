// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import "time"

// StatementType is the in-toto Statement layer v1 "_type" URI — always this exact string
// (spec/v1/statement.md, fetched this session: "Always `https://in-toto.io/Statement/v1`
// for this version of the spec").
const StatementType = "https://in-toto.io/Statement/v1"

// ProvenancePredicateType is the SLSA Provenance v1 predicateType URI (slsa.dev/spec/v1.1/
// provenance, fetched this session: "Always use the above string for `predicateType`
// rather than what is in the URL bar. The `predicateType` URI will always resolve to the
// latest minor version.").
const ProvenancePredicateType = "https://slsa.dev/provenance/v1"

// NAALPBuildType is the buildType URI this package asserts for every provenance statement
// it produces — a URI identifying N-AALP's own release build process (SLSA
// build-provenance.md, fetched this session: "REQUIRED for SLSA Build L1: `buildType`" —
// "a URI identifying the build template" whose documentation "SHOULD" describe the
// external parameters, dependency resolution, and environment). It is a first-party URI
// this package owns (no external registry assigns buildType URIs; each build platform
// defines and documents its own, per the spec's own guidance), not a placeholder.
const NAALPBuildType = "https://naalp.dev/supply-chain/buildtype/go-sdk@v1"

// ResourceDescriptor is the in-toto ResourceDescriptor field type
// (spec/v1/resource_descriptor.md, fetched this session): a size-efficient description of
// a software artifact or resource. Only Name/URI/Digest/MediaType are modeled — this
// package never emits `content` or `annotations`.
type ResourceDescriptor struct {
	Name      string            `json:"name,omitempty"`
	URI       string            `json:"uri,omitempty"`
	Digest    map[string]string `json:"digest,omitempty"`
	MediaType string            `json:"mediaType,omitempty"`
}

// Builder identifies the trusted build platform (SLSA runDetails.builder;
// "REQUIRED for SLSA Build L1: `id`").
type Builder struct {
	ID string `json:"id"`
}

// RunMetadata carries build execution timestamps (SLSA runDetails.metadata; all fields
// optional per SLSA build-provenance.md — "REQUIRED: (none)" for this sub-object).
type RunMetadata struct {
	InvocationID string `json:"invocationId,omitempty"`
	StartedOn    string `json:"startedOn,omitempty"`
	FinishedOn   string `json:"finishedOn,omitempty"`
}

// RunDetails captures how the build was run (SLSA predicate.runDetails).
type RunDetails struct {
	Builder  Builder      `json:"builder"`
	Metadata *RunMetadata `json:"metadata,omitempty"`
}

// BuildDefinition describes the build's inputs (SLSA predicate.buildDefinition).
// ExternalParameters carries the digest binding this package exists to produce: the SBOM
// digest that ties this provenance statement to a specific SBOM document.
type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   map[string]any       `json:"externalParameters"`
	InternalParameters   map[string]any       `json:"internalParameters,omitempty"`
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

// ProvenancePredicate is the SLSA Provenance v1 predicate object (slsa.dev/spec/v1.1/
// provenance and spec/schema/provenance.cue, both fetched this session).
type ProvenancePredicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// Statement is the in-toto Statement layer v1 wrapping a SLSA Provenance v1 predicate
// (spec/v1/statement.md, fetched this session).
type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     ProvenancePredicate  `json:"predicate"`
}

// BuildStatement builds a signed-ready in-toto Statement / SLSA Provenance v1 predicate
// binding artifactName+artifactDigest (the subject) to sbomDigest (recorded in
// buildDefinition.externalParameters["sbomDigest"] — the digest binding this package
// exists to produce; A4: this is a real field of the actual sbomDigest argument, not a
// constant, so BuildStatement's output changes whenever sbomDigest does — see
// provenance_test.go's mutation-surviving test). builderID identifies the build platform
// (SLSA runDetails.builder.id, REQUIRED). started/finished are the build's wall-clock
// bounds.
//
// All three inputs are validated before anything is built (fail-closed): an empty
// artifactDigest, empty sbomDigest, or empty builderID is rejected.
func BuildStatement(artifactName string, artifactDigest DigestSet, sbomDigest DigestSet, builderID string, started, finished time.Time) (*Statement, error) {
	if len(artifactDigest) == 0 {
		return nil, ErrEmptyArtifactDigest
	}
	if len(sbomDigest) == 0 {
		return nil, ErrEmptySBOMDigest
	}
	if builderID == "" {
		return nil, ErrEmptyBuilderID
	}

	externalParams := map[string]any{
		"sbomDigest": map[string]string(sbomDigest),
	}

	return &Statement{
		Type: StatementType,
		Subject: []ResourceDescriptor{
			{Name: artifactName, Digest: map[string]string(artifactDigest)},
		},
		PredicateType: ProvenancePredicateType,
		Predicate: ProvenancePredicate{
			BuildDefinition: BuildDefinition{
				BuildType:          NAALPBuildType,
				ExternalParameters: externalParams,
			},
			RunDetails: RunDetails{
				Builder: Builder{ID: builderID},
				Metadata: &RunMetadata{
					StartedOn:  started.UTC().Format(time.RFC3339),
					FinishedOn: finished.UTC().Format(time.RFC3339),
				},
			},
		},
	}, nil
}
