// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// TestVendoredSchemaIsTheRealDownload asserts the embedded schema file matches, byte for
// byte, the file this package's doc.go says was downloaded this session — a guard against
// the schema file having been hand-trimmed or otherwise edited after the fact (F3: the
// authority must stay the real, unmodified document).
func TestVendoredSchemaIsTheRealDownload(t *testing.T) {
	data, err := os.ReadFile("schema/bom-1.7.schema.json")
	if err != nil {
		t.Fatalf("read schema/bom-1.7.schema.json: %v", err)
	}
	if len(data) != 315722 {
		t.Fatalf("schema file is %d bytes, want 315722 (the real download captured this session)", len(data))
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	const want = "73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce"
	if got != want {
		t.Fatalf("schema/bom-1.7.schema.json sha256 = %s, want %s (this session's download)", got, want)
	}
}

func TestValidateSBOMAcceptsRealBuiltDocument(t *testing.T) {
	f, err := os.Open("testdata/golist.jsonl")
	if err != nil {
		t.Fatalf("open testdata/golist.jsonl: %v", err)
	}
	defer f.Close()
	mods, err := DecodeGoListModules(f)
	if err != nil {
		t.Fatalf("DecodeGoListModules: %v", err)
	}
	root := Component{Type: ComponentTypeLibrary, Name: "naalp-impl-go", Version: "0.0.0-dev"}
	bom, err := BuildSBOM(root, mods, time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildSBOM: %v", err)
	}
	data, err := MarshalAndValidateSBOM(bom)
	if err != nil {
		t.Fatalf("a real BuildSBOM() output failed CycloneDX 1.7 schema validation: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("MarshalAndValidateSBOM returned no bytes")
	}
}

func TestValidateSBOMRejectsMissingBomFormat(t *testing.T) {
	err := ValidateSBOM([]byte(`{"specVersion":"1.7"}`))
	if err == nil {
		t.Fatal("a document missing bomFormat should fail CycloneDX schema validation")
	}
	sve, ok := err.(*SchemaValidationError)
	if !ok {
		t.Fatalf("error type = %T, want *SchemaValidationError", err)
	}
	if len(sve.Errors) == 0 {
		t.Fatal("SchemaValidationError.Errors is empty")
	}
}

func TestValidateSBOMRejectsWrongBomFormat(t *testing.T) {
	err := ValidateSBOM([]byte(`{"bomFormat":"NotCycloneDX","specVersion":"1.7"}`))
	if err == nil {
		t.Fatal("bomFormat must be exactly \"CycloneDX\" (enum) — a wrong value should fail")
	}
}

func TestValidateSBOMRejectsInvalidComponentType(t *testing.T) {
	doc := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.7",
		"components": [{"type": "not-a-real-type", "name": "x"}]
	}`)
	if err := ValidateSBOM(doc); err == nil {
		t.Fatal("an invalid component type should fail CycloneDX schema validation")
	}
}

func TestValidateSBOMAcceptsMinimalDocument(t *testing.T) {
	doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)
	if err := ValidateSBOM(doc); err != nil {
		t.Fatalf("the minimal valid CycloneDX document (only the two required fields) failed: %v", err)
	}
}

// TestValidateSBOMRejectsAdditionalPropertyAtRoot exercises the root schema's own
// "additionalProperties": false against an unlisted top-level key.
func TestValidateSBOMRejectsAdditionalPropertyAtRoot(t *testing.T) {
	doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","notARealField":true}`)
	if err := ValidateSBOM(doc); err == nil {
		t.Fatal("an unlisted root-level field should be rejected (root additionalProperties: false)")
	}
}
