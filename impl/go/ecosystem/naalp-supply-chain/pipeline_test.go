// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestBuildReleaseEndToEnd(t *testing.T) {
	f, err := os.Open("testdata/golist.jsonl")
	if err != nil {
		t.Fatalf("open testdata/golist.jsonl: %v", err)
	}
	mods, err := DecodeGoListModules(f)
	f.Close()
	if err != nil {
		t.Fatalf("DecodeGoListModules: %v", err)
	}

	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	artifact := ReleaseArtifact{Name: "naalp-impl-go.tar.gz", Data: []byte("a fake but non-empty release artifact")}
	root := Component{Type: ComponentTypeLibrary, Name: "naalp-impl-go", Version: "0.0.0-dev"}
	started := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
	finished := time.Date(2026, 8, 31, 9, 10, 0, 0, time.UTC)

	result, err := BuildRelease(artifact, root, mods, "https://naalp.dev/builders/gha@v1", signer, started, finished)
	if err != nil {
		t.Fatalf("BuildRelease: %v", err)
	}

	// 1. artifact digest is real (matches independent recomputation).
	if !result.ArtifactDigest.Equal(DigestBytes(artifact.Data)) {
		t.Fatal("ArtifactDigest does not match an independent DigestBytes(artifact.Data) recomputation")
	}

	// 2. SBOM is schema-valid (already checked inside BuildRelease via
	// MarshalAndValidateSBOM, but re-check here as an end-to-end assertion, not a
	// trust-the-pipeline assumption).
	if err := ValidateSBOM(result.SBOMJSON); err != nil {
		t.Fatalf("BuildRelease's SBOM output failed independent re-validation: %v", err)
	}
	if len(result.SBOM.Components) != 8 {
		t.Fatalf("got %d SBOM components, want 8", len(result.SBOM.Components))
	}

	// 3. Statement satisfies SLSA Build L1 and its digest binding independently verifies
	// against the artifact bytes and the SBOM bytes actually produced.
	if err := ValidateStatement(result.Statement); err != nil {
		t.Fatalf("BuildRelease's statement failed SLSA Build L1 validation: %v", err)
	}
	if err := VerifyBinding(result.Statement, artifact.Data, result.SBOMJSON); err != nil {
		t.Fatalf("VerifyBinding failed on BuildRelease's own output: %v", err)
	}

	// 4. The signature verifies under the signer's public key, over the exact statement
	// bytes BuildRelease reports.
	if err := VerifyStatementSignature(signer.PublicKey(), result.SignedProvenance, result.StatementJSON); err != nil {
		t.Fatalf("VerifyStatementSignature failed on BuildRelease's own output: %v", err)
	}

	// 5. StatementJSON round-trips to a Statement and passes VerifyBinding again after a
	// JSON round trip (the realistic verifier path).
	var roundTripped Statement
	if err := json.Unmarshal(result.StatementJSON, &roundTripped); err != nil {
		t.Fatalf("Unmarshal(StatementJSON): %v", err)
	}
	if err := VerifyBinding(&roundTripped, artifact.Data, result.SBOMJSON); err != nil {
		t.Fatalf("VerifyBinding on round-tripped StatementJSON: %v", err)
	}
}

func TestBuildReleaseRejectsInvalidRootComponent(t *testing.T) {
	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	_, err = BuildRelease(
		ReleaseArtifact{Name: "x", Data: []byte("y")},
		Component{Type: "not-real", Name: "x"},
		nil, "builder", signer, time.Now(), time.Now(),
	)
	if err != ErrInvalidComponentType {
		t.Fatalf("error = %v, want ErrInvalidComponentType", err)
	}
}

func TestBuildReleaseRejectsEmptyBuilderID(t *testing.T) {
	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	_, err = BuildRelease(
		ReleaseArtifact{Name: "x", Data: []byte("y")},
		Component{Type: ComponentTypeLibrary, Name: "x"},
		nil, "", signer, time.Now(), time.Now(),
	)
	if err != ErrEmptyBuilderID {
		t.Fatalf("error = %v, want ErrEmptyBuilderID", err)
	}
}

// TestBuildReleaseChangesWithArtifact is the A4 mutation-surviving test on the whole
// pipeline: two different artifacts must produce two different ArtifactDigest values and
// two different SignedProvenance byte strings.
func TestBuildReleaseChangesWithArtifact(t *testing.T) {
	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	root := Component{Type: ComponentTypeLibrary, Name: "x"}
	now := time.Now()

	a, err := BuildRelease(ReleaseArtifact{Name: "x", Data: []byte("artifact one")}, root, nil, "builder", signer, now, now)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := BuildRelease(ReleaseArtifact{Name: "x", Data: []byte("artifact two")}, root, nil, "builder", signer, now, now)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a.ArtifactDigest["sha256"] == b.ArtifactDigest["sha256"] {
		t.Fatal("two different artifacts produced the same digest")
	}
	if string(a.SignedProvenance) == string(b.SignedProvenance) {
		t.Fatal("two different artifacts produced the same signed provenance bytes")
	}
}
