// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package envelope

import (
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// TestAudienceRoundTrip: an object carrying a field-13 audience signs and verifies offline, and the
// decoded object preserves the audience byte-for-byte (design.md §2.5.3). Before the field-13 decode
// case exists this fails RED — objectFromMap's default rejects the unknown top-level field
// (Malformed) — the clean red this wire-field addition is proven against.
func TestAudienceRoundTrip(t *testing.T) {
	c := load(t)
	o := buildObject(t, c)
	o.Audience = "consuming-authority-xyz"
	s, v := testSigner(t)
	obj, err := Sign(o, s)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := Verify(ProfilePublicForTest(), v, acceptKind, nil, obj)
	if err != nil {
		t.Fatalf("verify audience-bearing object: %v", err)
	}
	if got.Audience != "consuming-authority-xyz" {
		t.Fatalf("audience not preserved: got %q want %q", got.Audience, "consuming-authority-xyz")
	}
}

// TestCheckAudience exercises the 3-branch point-of-use check (design.md §2.5.3). Mutation-surviving:
// replacing CheckAudience's body with `return nil` flips the three reject cases below to failures.
func TestCheckAudience(t *testing.T) {
	const self = "authority-A"
	cases := []struct {
		name        string
		audience    string
		consumeOnce bool
		wantReject  bool
	}{
		{"consume-once, correct audience", self, true, false},
		{"consume-once, wrong audience", "authority-B", true, true},
		{"consume-once, absent audience", "", true, true},
		{"unrestricted, absent audience", "", false, false},
		{"unrestricted, correct audience", self, false, false},
		{"named-but-not-consume-once, foreign audience", "authority-B", false, true},
	}
	for _, tc := range cases {
		o := &Object{Audience: tc.audience}
		err := CheckAudience(o, self, tc.consumeOnce)
		if tc.wantReject {
			ce, ok := err.(*cose.Error)
			if !ok || ce.Kind != "WrongAudience" {
				t.Errorf("%s: want WrongAudience, got %v", tc.name, err)
			}
		} else if err != nil {
			t.Errorf("%s: want nil, got %v", tc.name, err)
		}
	}
}
