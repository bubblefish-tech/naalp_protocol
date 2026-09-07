// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"os"
	"strings"
	"testing"
)

// testdata/golist.jsonl is a real `go list -m -json all` capture (fields Dir/GoMod
// stripped only because they carried this machine's absolute build path — see
// impl/go/go.mod for the live equivalent; the module set, versions, and Sum hashes below
// are byte-identical to a real invocation run this session from impl/go). This is the
// non-circular F3 oracle for DecodeGoListModules: none of these bytes were produced by
// supplychain's own code.
func TestDecodeGoListModulesParsesRealCapture(t *testing.T) {
	f, err := os.Open("testdata/golist.jsonl")
	if err != nil {
		t.Fatalf("open testdata/golist.jsonl: %v", err)
	}
	defer f.Close()

	mods, err := DecodeGoListModules(f)
	if err != nil {
		t.Fatalf("DecodeGoListModules: %v", err)
	}
	if len(mods) != 9 {
		t.Fatalf("got %d modules, want 9 (1 main + 8 dependencies)", len(mods))
	}
	if !mods[0].Main || mods[0].Path != "github.com/bubblefish-tech/naalp_protocol/impl/go" {
		t.Fatalf("first module = %+v, want the main module", mods[0])
	}
	// circl is the only DIRECT, non-indirect dependency other than x/text in this real
	// capture; assert both its resolved version and its real captured Sum hash survive
	// parsing byte-for-byte.
	var circl *Module
	for i := range mods {
		if mods[i].Path == "github.com/cloudflare/circl" {
			circl = &mods[i]
		}
	}
	if circl == nil {
		t.Fatal("github.com/cloudflare/circl not found in parsed modules")
	}
	if circl.Version != "v1.6.4" {
		t.Fatalf("circl.Version = %q, want v1.6.4", circl.Version)
	}
	if circl.Indirect {
		t.Fatal("circl.Indirect = true, want false (it is a direct require in go.mod)")
	}
	if circl.Sum != "h1:pOXuDTCEYyzydgUpQ0CQz3LsinKjiSk6nNP5Lt5K64U=" {
		t.Fatalf("circl.Sum = %q, does not match the real captured go list output", circl.Sum)
	}

	var sys *Module
	for i := range mods {
		if mods[i].Path == "golang.org/x/sys" {
			sys = &mods[i]
		}
	}
	if sys == nil {
		t.Fatal("golang.org/x/sys not found in parsed modules")
	}
	if !sys.Indirect {
		t.Fatal("golang.org/x/sys.Indirect = false, want true")
	}
}

func TestDecodeGoListModulesRejectsMalformedJSON(t *testing.T) {
	_, err := DecodeGoListModules(strings.NewReader(`{"Path": "ok"} not-json-at-all`))
	if err != ErrMalformedModuleList {
		t.Fatalf("error = %v, want ErrMalformedModuleList", err)
	}
}

func TestDecodeGoListModulesRejectsEmptyPath(t *testing.T) {
	_, err := DecodeGoListModules(strings.NewReader(`{"Version":"v1.0.0"}`))
	if err != ErrMalformedModuleList {
		t.Fatalf("error = %v, want ErrMalformedModuleList", err)
	}
}

func TestDecodeGoListModulesEmptyStreamIsEmptyResult(t *testing.T) {
	mods, err := DecodeGoListModules(strings.NewReader(``))
	if err != nil {
		t.Fatalf("DecodeGoListModules(empty) error = %v", err)
	}
	if len(mods) != 0 {
		t.Fatalf("got %d modules from an empty stream, want 0", len(mods))
	}
}

func TestParseGoModRequiresRealFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/sample.go.mod")
	if err != nil {
		t.Fatalf("read testdata/sample.go.mod: %v", err)
	}
	mods, err := ParseGoModRequires(data)
	if err != nil {
		t.Fatalf("ParseGoModRequires: %v", err)
	}
	if len(mods) != 3 {
		t.Fatalf("got %d requires, want 3 (2 block + 1 single-line indirect)", len(mods))
	}
	byPath := map[string]Module{}
	for _, m := range mods {
		byPath[m.Path] = m
	}
	circl, ok := byPath["github.com/cloudflare/circl"]
	if !ok || circl.Version != "v1.6.4" || circl.Indirect {
		t.Fatalf("circl entry = %+v, ok=%v, want v1.6.4 direct", circl, ok)
	}
	text, ok := byPath["golang.org/x/text"]
	if !ok || text.Version != "v0.40.0" || text.Indirect {
		t.Fatalf("x/text entry = %+v, ok=%v, want v0.40.0 direct", text, ok)
	}
	sys, ok := byPath["golang.org/x/sys"]
	if !ok || sys.Version != "v0.38.0" || !sys.Indirect {
		t.Fatalf("x/sys entry = %+v, ok=%v, want v0.38.0 indirect", sys, ok)
	}
}

// TestParseGoModRequiresChangesWithInput is the A4 mutation-surviving test: a parser that
// ignores its input (returns a fixed module list regardless of the go.mod bytes given)
// fails this test, because two go.mod fixtures with disjoint require sets must produce
// disjoint parsed results.
func TestParseGoModRequiresChangesWithInput(t *testing.T) {
	a, err := ParseGoModRequires([]byte("module x\n\nrequire example.com/foo v1.0.0\n"))
	if err != nil {
		t.Fatalf("parse a: %v", err)
	}
	b, err := ParseGoModRequires([]byte("module x\n\nrequire example.com/bar v2.0.0\n"))
	if err != nil {
		t.Fatalf("parse b: %v", err)
	}
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected exactly one require each, got %d and %d", len(a), len(b))
	}
	if a[0].Path == b[0].Path {
		t.Fatal("two go.mod fixtures with different require paths produced the same parsed path — input is being ignored")
	}
}

func TestParseGoModRequiresRejectsMalformedEntry(t *testing.T) {
	_, err := ParseGoModRequires([]byte("module x\n\nrequire (\n\tonly-a-path-no-version\n)\n"))
	if err != ErrMalformedGoMod {
		t.Fatalf("error = %v, want ErrMalformedGoMod", err)
	}
}

func TestParseGoModRequiresIgnoresNonRequireLines(t *testing.T) {
	mods, err := ParseGoModRequires([]byte("module x\n\ngo 1.25.0\n\n// a comment\nrequire example.com/only v1.0.0\n"))
	if err != nil {
		t.Fatalf("ParseGoModRequires: %v", err)
	}
	if len(mods) != 1 || mods[0].Path != "example.com/only" {
		t.Fatalf("mods = %+v, want exactly [example.com/only]", mods)
	}
}
