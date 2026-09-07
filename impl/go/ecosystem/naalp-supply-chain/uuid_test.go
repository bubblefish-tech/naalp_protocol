// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"regexp"
	"testing"
)

// Independent oracle: RFC 4122's own version-4 canonical form is
// xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx where y is one of 8/9/a/b (variant bits 10) —
// this is the RFC's normative construction rule, not something newUUIDv4's own code
// asserts about itself.
var uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewUUIDv4MatchesRFC4122Shape(t *testing.T) {
	for i := 0; i < 20; i++ {
		id, err := newUUIDv4()
		if err != nil {
			t.Fatalf("newUUIDv4: %v", err)
		}
		if !uuidV4Pattern.MatchString(id) {
			t.Fatalf("newUUIDv4() = %q does not match the RFC 4122 v4 canonical shape", id)
		}
	}
}

// TestNewUUIDv4IsNotConstant is the A4/A3 mutation-surviving test: a stub that always
// returns the same fixed UUID string passes the shape check above but fails here.
func TestNewUUIDv4IsNotConstant(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		id, err := newUUIDv4()
		if err != nil {
			t.Fatalf("newUUIDv4: %v", err)
		}
		if seen[id] {
			t.Fatalf("newUUIDv4() produced a repeat after %d calls: %s", i, id)
		}
		seen[id] = true
	}
}
