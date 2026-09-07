// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package naalperror

import (
	"encoding/hex"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// TestRegistrySize pins the registry to exactly 132 unique names with no gaps (the fields-of-record
// invariant: code == index+1, sequential 1..132). A mutation that drops or duplicates an entry flips
// this and the code/name relationship below.
func TestRegistrySize(t *testing.T) {
	if len(Names) != 132 {
		t.Fatalf("registry must have 132 names, got %d", len(Names))
	}
	seen := map[string]bool{}
	for i, n := range Names {
		if seen[n] {
			t.Fatalf("duplicate name %q at code %d", n, i+1)
		}
		seen[n] = true
		if c, ok := CodeForName(n); !ok || c != uint64(i+1) {
			t.Fatalf("CodeForName(%q)=%d,%v want %d", n, c, ok, i+1)
		}
	}
}

// TestEncodeKAT pins the deterministic naalp-error body bytes against hand-computed CBOR (independent
// of the oracle and of impl/rust): a2 (map-2) 01 <code> 02 <tstr name>. A mutation of Encode flips it.
func TestEncodeKAT(t *testing.T) {
	cases := []struct {
		code uint64
		name string
		want string // hand-computed canonical CBOR of {1:code, 2:name}
	}{
		// code 1 (single-byte uint), name "NonCanonical" (12 bytes -> tstr head 0x6c).
		{1, "NonCanonical", "a20101026c4e6f6e43616e6f6e6963616c"},
		// code 52 (>=24 -> two-byte uint 18 34), name "NotDelivered" (12 bytes).
		{52, "NotDelivered", "a2011834026c4e6f7444656c697665726564"},
	}
	for _, c := range cases {
		b, err := Encode(c.code, c.name, "", nil)
		if err != nil {
			t.Fatalf("Encode(%d,%q): %v", c.code, c.name, err)
		}
		if got := hex.EncodeToString(b); got != c.want {
			t.Fatalf("Encode(%d,%q) = %s, want %s", c.code, c.name, got, c.want)
		}
	}
}

// TestEncodeWithDetailSubject exercises the optional fields 3 and 4 (map grows to a3/a4, keys stay
// ascending). A mutation that drops a field or mis-orders keys flips the round-trip below.
func TestEncodeDecodeFull(t *testing.T) {
	subj := append([]byte{0x20, 0x30}, make([]byte, 48)...)
	b, err := Encode(CodeMust(t, "BadSignature"), "BadSignature", "reason", subj)
	if err != nil {
		t.Fatal(err)
	}
	o, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode round-trip: %v", err)
	}
	if o.Name != "BadSignature" || o.Detail != "reason" || len(o.Subject) != 50 {
		t.Fatalf("round-trip mismatch: %+v", o)
	}
}

// TestDualCarriageMismatch: a registered code carrying the wrong registered name is rejected
// Malformed (the strengthening direction). A mutation that skips the name check flips this.
func TestDualCarriageMismatch(t *testing.T) {
	b, err := Encode(CodeMust(t, "BadSignature"), "NotDelivered", "", nil) // code 22, name of code 52
	if err != nil {
		t.Fatal(err)
	}
	_, derr := Decode(b)
	ce, ok := derr.(*cose.Error)
	if !ok || ce.Kind != "Malformed" {
		t.Fatalf("registered code with wrong name must be Malformed, got %v", derr)
	}
}

// TestUnknownCodeOpaque: a code outside the registry is accepted opaque (open-registry contract). A
// mutation that rejects unknown codes flips this.
func TestUnknownCodeOpaque(t *testing.T) {
	b, err := Encode(60000, "SomeFutureError", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	o, derr := Decode(b)
	if derr != nil {
		t.Fatalf("unknown code must be opaque-accepted, got %v", derr)
	}
	if o.Code != 60000 || o.Name != "SomeFutureError" {
		t.Fatalf("unknown-code round-trip mismatch: %+v", o)
	}
}

// TestNameForCode pins a few known code->name entries + the unregistered boundary.
func TestNameForCode(t *testing.T) {
	for code, want := range map[uint64]string{1: "NonCanonical", 22: "BadSignature", 119: "RebindUnauthorized", 129: "ForeignProfileMalformed", 130: "HazardMalformed", 132: "HazardUnknown"} {
		if got, ok := NameForCode(code); !ok || got != want {
			t.Fatalf("NameForCode(%d)=%q,%v want %q", code, got, ok, want)
		}
	}
	for _, code := range []uint64{0, 133, 60000} {
		if _, ok := NameForCode(code); ok {
			t.Fatalf("NameForCode(%d) should be unregistered", code)
		}
	}
}

// --- small test helpers ---

func CodeMust(t *testing.T, name string) uint64 {
	t.Helper()
	c, ok := CodeForName(name)
	if !ok {
		t.Fatalf("name %q not registered", name)
	}
	return c
}
