// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"os"
	"testing"
	"time"
)

func realModules(t *testing.T) []Module {
	t.Helper()
	f, err := os.Open("testdata/golist.jsonl")
	if err != nil {
		t.Fatalf("open testdata/golist.jsonl: %v", err)
	}
	defer f.Close()
	mods, err := DecodeGoListModules(f)
	if err != nil {
		t.Fatalf("DecodeGoListModules: %v", err)
	}
	return mods
}

func TestBuildSBOMFromRealModuleGraph(t *testing.T) {
	root := Component{Type: ComponentTypeLibrary, Name: "naalp-impl-go", Version: "0.0.0-dev"}
	bom, err := BuildSBOM(root, realModules(t), time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildSBOM: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.7" {
		t.Fatalf("bomFormat/specVersion = %q/%q", bom.BOMFormat, bom.SpecVersion)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.Name != "naalp-impl-go" {
		t.Fatalf("metadata.component = %+v", bom.Metadata)
	}
	// 9 modules in the fixture, 1 is Main -> 8 dependency components.
	if len(bom.Components) != 8 {
		t.Fatalf("got %d components, want 8 (main module excluded)", len(bom.Components))
	}
	var circl *Component
	for i := range bom.Components {
		if bom.Components[i].Name == "github.com/cloudflare/circl" {
			circl = &bom.Components[i]
		}
	}
	if circl == nil {
		t.Fatal("circl component missing from BOM")
	}
	if circl.Version != "v1.6.4" {
		t.Fatalf("circl.Version = %q", circl.Version)
	}
	if circl.PURL != "pkg:golang/github.com/cloudflare/circl@v1.6.4" {
		t.Fatalf("circl.PURL = %q", circl.PURL)
	}
	if circl.Scope != ComponentScopeRequired {
		t.Fatalf("circl.Scope = %q, want required (direct dependency)", circl.Scope)
	}
	if len(circl.Hashes) != 1 || circl.Hashes[0].Alg != HashAlgSHA256 {
		t.Fatalf("circl.Hashes = %+v, want one SHA-256 hash decoded from its real go.sum Sum", circl.Hashes)
	}
	// Independent re-derivation: the h1 Sum for circl is "h1:pOXuDTCEYyzydgUpQ0CQz3LsinKjiSk6nNP5Lt5K64U=",
	// base64-decoded (32 bytes) and hex-encoded — recomputed here directly with stdlib,
	// not by calling decodeGoDirhashSHA256 itself, so this is not circular.
	wantHex := "a4e5ee0d3084632cf2760529434090cf72ec8a72a389293a9cd3f92ede4aeb85"
	if circl.Hashes[0].Content != wantHex {
		t.Fatalf("circl hash content = %s, want %s", circl.Hashes[0].Content, wantHex)
	}

	var sys *Component
	for i := range bom.Components {
		if bom.Components[i].Name == "golang.org/x/sys" {
			sys = &bom.Components[i]
		}
	}
	if sys == nil || sys.Scope != ComponentScopeOptional {
		t.Fatalf("golang.org/x/sys scope = %+v, want optional (indirect dependency)", sys)
	}
}

func TestBuildSBOMRejectsInvalidRootType(t *testing.T) {
	_, err := BuildSBOM(Component{Type: "not-a-real-type", Name: "x"}, nil, time.Now())
	if err != ErrInvalidComponentType {
		t.Fatalf("error = %v, want ErrInvalidComponentType", err)
	}
}

func TestBuildSBOMRejectsEmptyRootName(t *testing.T) {
	_, err := BuildSBOM(Component{Type: ComponentTypeLibrary, Name: ""}, nil, time.Now())
	if err != ErrEmptyComponentName {
		t.Fatalf("error = %v, want ErrEmptyComponentName", err)
	}
}

func TestBuildSBOMEmptyModuleGraphIsEmptyComponents(t *testing.T) {
	bom, err := BuildSBOM(Component{Type: ComponentTypeApplication, Name: "solo"}, nil, time.Now())
	if err != nil {
		t.Fatalf("BuildSBOM: %v", err)
	}
	if len(bom.Components) != 0 {
		t.Fatalf("got %d components from an empty module graph, want 0", len(bom.Components))
	}
}

// TestBuildSBOMChangesWithModuleGraph is the A4 mutation-surviving test: an SBOM builder
// that ignores its modules argument (always emitting the same fixed component list)
// fails this test, because two disjoint module graphs must produce disjoint component
// name sets.
func TestBuildSBOMChangesWithModuleGraph(t *testing.T) {
	root := Component{Type: ComponentTypeLibrary, Name: "root"}
	a, err := BuildSBOM(root, []Module{{Path: "example.com/foo", Version: "v1.0.0"}}, time.Now())
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := BuildSBOM(root, []Module{{Path: "example.com/bar", Version: "v2.0.0"}}, time.Now())
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if len(a.Components) != 1 || len(b.Components) != 1 {
		t.Fatalf("expected exactly one component each, got %d and %d", len(a.Components), len(b.Components))
	}
	if a.Components[0].Name == b.Components[0].Name {
		t.Fatal("two different module graphs produced the same single component name — modules argument is being ignored")
	}
}

func TestBuildSBOMSerialNumberIsUniquePerCall(t *testing.T) {
	root := Component{Type: ComponentTypeLibrary, Name: "root"}
	a, err := BuildSBOM(root, nil, time.Now())
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := BuildSBOM(root, nil, time.Now())
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a.SerialNumber == b.SerialNumber {
		t.Fatal("two independent BuildSBOM calls produced the same serialNumber")
	}
}

func TestDecodeGoDirhashSHA256(t *testing.T) {
	hexDigest, ok := decodeGoDirhashSHA256("h1:pOXuDTCEYyzydgUpQ0CQz3LsinKjiSk6nNP5Lt5K64U=")
	if !ok {
		t.Fatal("decodeGoDirhashSHA256 rejected a real h1 sum")
	}
	if len(hexDigest) != 64 {
		t.Fatalf("hex digest length = %d, want 64 (32-byte SHA-256)", len(hexDigest))
	}
	if _, ok := decodeGoDirhashSHA256(""); ok {
		t.Fatal("decodeGoDirhashSHA256(\"\") should be ok=false")
	}
	if _, ok := decodeGoDirhashSHA256("not-an-h1-sum"); ok {
		t.Fatal("decodeGoDirhashSHA256 accepted a non-h1-prefixed string")
	}
	if _, ok := decodeGoDirhashSHA256("h1:not-valid-base64!!!"); ok {
		t.Fatal("decodeGoDirhashSHA256 accepted invalid base64")
	}
}
