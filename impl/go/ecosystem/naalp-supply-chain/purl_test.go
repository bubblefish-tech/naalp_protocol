// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import "testing"

// Independent oracle: the worked example verbatim from purl-spec's golang-definition.json
// (fetched this session): "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c".
func TestGoModulePURLMatchesSpecExample(t *testing.T) {
	got, err := GoModulePURL("github.com/gorilla/context", "234fd47e07d1004f0aed9c")
	if err != nil {
		t.Fatalf("GoModulePURL: %v", err)
	}
	want := "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c"
	if got != want {
		t.Fatalf("GoModulePURL = %q, want %q (purl-spec worked example)", got, want)
	}
}

func TestGoModulePURLNoVersion(t *testing.T) {
	got, err := GoModulePURL("google.golang.org/genproto", "")
	if err != nil {
		t.Fatalf("GoModulePURL: %v", err)
	}
	if got != "pkg:golang/google.golang.org/genproto" {
		t.Fatalf("GoModulePURL(no version) = %q", got)
	}
}

func TestGoModulePURLLowercases(t *testing.T) {
	got, err := GoModulePURL("GitHub.com/Cloudflare/CIRCL", "v1.6.4")
	if err != nil {
		t.Fatalf("GoModulePURL: %v", err)
	}
	want := "pkg:golang/github.com/cloudflare/circl@v1.6.4"
	if got != want {
		t.Fatalf("GoModulePURL did not lowercase: got %q, want %q", got, want)
	}
}

func TestGoModulePURLRejectsEmptyPath(t *testing.T) {
	_, err := GoModulePURL("", "v1.0.0")
	if err != ErrEmptyModulePath {
		t.Fatalf("error = %v, want ErrEmptyModulePath", err)
	}
}

// TestGoModulePURLChangesWithInput is the A4 mutation-surviving test.
func TestGoModulePURLChangesWithInput(t *testing.T) {
	a, err := GoModulePURL("example.com/foo", "v1.0.0")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := GoModulePURL("example.com/bar", "v2.0.0")
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a == b {
		t.Fatal("two different (path, version) inputs produced the same purl — input is being ignored")
	}
}

func TestPercentEncodePURLComponentEscapesUnsafeBytes(t *testing.T) {
	got := percentEncodePURLComponent("a b#c")
	want := "a%20b%23c"
	if got != want {
		t.Fatalf("percentEncodePURLComponent(%q) = %q, want %q", "a b#c", got, want)
	}
	// Round-trip sanity: a fully safe string is untouched (no wasted allocation/escaping).
	if percentEncodePURLComponent("github.com/foo-bar_baz.v2") != "github.com/foo-bar_baz.v2" {
		t.Fatal("percentEncodePURLComponent altered an already-safe string")
	}
}
