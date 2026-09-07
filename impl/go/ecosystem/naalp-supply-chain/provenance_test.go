// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBuildStatementShapeMatchesSpec(t *testing.T) {
	artifactDigest := DigestSet{"sha256": "aa"}
	sbomDigest := DigestSet{"sha256": "bb"}
	started := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	finished := time.Date(2026, 8, 31, 10, 5, 0, 0, time.UTC)

	s, err := BuildStatement("naalp-sdk.tar.gz", artifactDigest, sbomDigest, "https://naalp.dev/builders/gha@v1", started, finished)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	if s.Type != "https://in-toto.io/Statement/v1" {
		t.Fatalf("_type = %q", s.Type)
	}
	if s.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Fatalf("predicateType = %q", s.PredicateType)
	}
	if len(s.Subject) != 1 || s.Subject[0].Name != "naalp-sdk.tar.gz" || s.Subject[0].Digest["sha256"] != "aa" {
		t.Fatalf("subject = %+v", s.Subject)
	}
	if s.Predicate.BuildDefinition.BuildType == "" {
		t.Fatal("buildType must not be empty")
	}
	got, ok := s.Predicate.BuildDefinition.ExternalParameters["sbomDigest"].(map[string]string)
	if !ok || got["sha256"] != "bb" {
		t.Fatalf("externalParameters[sbomDigest] = %v", s.Predicate.BuildDefinition.ExternalParameters["sbomDigest"])
	}
	if s.Predicate.RunDetails.Builder.ID == "" {
		t.Fatal("runDetails.builder.id must not be empty")
	}
	if s.Predicate.RunDetails.Metadata.StartedOn != "2026-08-31T10:00:00Z" {
		t.Fatalf("startedOn = %q", s.Predicate.RunDetails.Metadata.StartedOn)
	}
}

func TestBuildStatementRejectsEmptyInputs(t *testing.T) {
	valid := DigestSet{"sha256": "aa"}
	now := time.Now()
	if _, err := BuildStatement("x", nil, valid, "b", now, now); err != ErrEmptyArtifactDigest {
		t.Fatalf("error = %v, want ErrEmptyArtifactDigest", err)
	}
	if _, err := BuildStatement("x", valid, nil, "b", now, now); err != ErrEmptySBOMDigest {
		t.Fatalf("error = %v, want ErrEmptySBOMDigest", err)
	}
	if _, err := BuildStatement("x", valid, valid, "", now, now); err != ErrEmptyBuilderID {
		t.Fatalf("error = %v, want ErrEmptyBuilderID", err)
	}
}

// TestBuildStatementChangesWithSBOMDigest is the A4 mutation-surviving test targeting the
// digest-BINDING property directly: two calls differing only in sbomDigest must produce
// statements whose externalParameters disagree.
func TestBuildStatementChangesWithSBOMDigest(t *testing.T) {
	artifactDigest := DigestSet{"sha256": "aa"}
	now := time.Now()
	a, err := BuildStatement("x", artifactDigest, DigestSet{"sha256": "111"}, "b", now, now)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := BuildStatement("x", artifactDigest, DigestSet{"sha256": "222"}, "b", now, now)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	aSBOM := a.Predicate.BuildDefinition.ExternalParameters["sbomDigest"].(map[string]string)
	bSBOM := b.Predicate.BuildDefinition.ExternalParameters["sbomDigest"].(map[string]string)
	if aSBOM["sha256"] == bSBOM["sha256"] {
		t.Fatal("two different sbomDigest inputs produced the same recorded externalParameters — the binding is not real")
	}
}

func TestValidateStatementAcceptsValid(t *testing.T) {
	s, err := BuildStatement("x", DigestSet{"sha256": "aa"}, DigestSet{"sha256": "bb"}, "builder", time.Now(), time.Now())
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	if err := ValidateStatement(s); err != nil {
		t.Fatalf("ValidateStatement rejected a well-formed statement: %v", err)
	}
}

func TestValidateStatementRejectsMissingFields(t *testing.T) {
	base := func() *Statement {
		s, err := BuildStatement("x", DigestSet{"sha256": "aa"}, DigestSet{"sha256": "bb"}, "builder", time.Now(), time.Now())
		if err != nil {
			t.Fatalf("BuildStatement: %v", err)
		}
		return s
	}

	if s := base(); true {
		s.Type = "wrong"
		if err := ValidateStatement(s); err != ErrStatementInvalid {
			t.Fatalf("wrong _type: error = %v", err)
		}
	}
	if s := base(); true {
		s.Subject = nil
		if err := ValidateStatement(s); err != ErrStatementInvalid {
			t.Fatalf("empty subject: error = %v", err)
		}
	}
	if s := base(); true {
		s.Subject[0].Digest = nil
		if err := ValidateStatement(s); err != ErrStatementInvalid {
			t.Fatalf("empty subject digest: error = %v", err)
		}
	}
	if s := base(); true {
		s.PredicateType = "wrong"
		if err := ValidateStatement(s); err != ErrStatementInvalid {
			t.Fatalf("wrong predicateType: error = %v", err)
		}
	}
	if s := base(); true {
		s.Predicate.BuildDefinition.BuildType = ""
		if err := ValidateStatement(s); err != ErrStatementInvalid {
			t.Fatalf("empty buildType: error = %v", err)
		}
	}
	if s := base(); true {
		s.Predicate.BuildDefinition.ExternalParameters = nil
		if err := ValidateStatement(s); err != ErrStatementInvalid {
			t.Fatalf("nil externalParameters: error = %v", err)
		}
	}
	if s := base(); true {
		s.Predicate.RunDetails.Builder.ID = ""
		if err := ValidateStatement(s); err != ErrStatementInvalid {
			t.Fatalf("empty builder.id: error = %v", err)
		}
	}
	if err := ValidateStatement(nil); err != ErrStatementInvalid {
		t.Fatalf("nil statement: error = %v", err)
	}
}

func TestVerifyBindingAcceptsMatchingDigests(t *testing.T) {
	artifact := []byte("release artifact bytes")
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)
	s, err := BuildStatement("x", DigestBytes(artifact), DigestBytes(sbomJSON), "builder", time.Now(), time.Now())
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	if err := VerifyBinding(s, artifact, sbomJSON); err != nil {
		t.Fatalf("VerifyBinding rejected a genuine match: %v", err)
	}
}

// TestVerifyBindingRejectsTamperedArtifact / SBOM is the load-bearing binding-mismatch
// mutation target (see sign.go/provenance_validate.go's doc comments and RED-EVIDENCE.md
// for the recorded WITNESS mutation on this exact check).
func TestVerifyBindingRejectsTamperedArtifact(t *testing.T) {
	artifact := []byte("release artifact bytes")
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)
	s, err := BuildStatement("x", DigestBytes(artifact), DigestBytes(sbomJSON), "builder", time.Now(), time.Now())
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	tampered := []byte("a DIFFERENT artifact")
	if err := VerifyBinding(s, tampered, sbomJSON); err != ErrBindingMismatch {
		t.Fatalf("VerifyBinding(tampered artifact) error = %v, want ErrBindingMismatch", err)
	}
}

func TestVerifyBindingRejectsTamperedSBOM(t *testing.T) {
	artifact := []byte("release artifact bytes")
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)
	s, err := BuildStatement("x", DigestBytes(artifact), DigestBytes(sbomJSON), "builder", time.Now(), time.Now())
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	tampered := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"type":"library","name":"injected"}]}`)
	if err := VerifyBinding(s, artifact, tampered); err != ErrBindingMismatch {
		t.Fatalf("VerifyBinding(tampered sbom) error = %v, want ErrBindingMismatch", err)
	}
}

// TestVerifyBindingSurvivesJSONRoundTrip proves VerifyBinding works on a Statement that
// actually WENT THROUGH json.Marshal/Unmarshal (where externalParameters["sbomDigest"]
// decodes as map[string]any, not map[string]string) — the realistic path a verifier on
// the OTHER side of a signature would take, not just the in-memory struct BuildStatement
// returned.
func TestVerifyBindingSurvivesJSONRoundTrip(t *testing.T) {
	artifact := []byte("release artifact bytes")
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)
	s, err := BuildStatement("x", DigestBytes(artifact), DigestBytes(sbomJSON), "builder", time.Now(), time.Now())
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var roundTripped Statement
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := VerifyBinding(&roundTripped, artifact, sbomJSON); err != nil {
		t.Fatalf("VerifyBinding on a JSON-round-tripped statement failed: %v", err)
	}
	tampered := []byte("different")
	if err := VerifyBinding(&roundTripped, tampered, sbomJSON); err != ErrBindingMismatch {
		t.Fatalf("VerifyBinding(round-tripped, tampered) error = %v, want ErrBindingMismatch", err)
	}
}
