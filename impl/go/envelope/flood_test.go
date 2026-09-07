// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package envelope

import (
	"fmt"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// countingVerifier wraps a real verifier and counts how many times the (expensive) ML-DSA
// signature verification is actually performed, so a test can prove the cheap checks reject a
// malformed object before the signature step is ever reached.
type countingVerifier struct {
	inner cose.Verifier
	n     int
}

func (c *countingVerifier) Alg() int                       { return c.inner.Alg() }
func (c *countingVerifier) PubKey() []byte                 { return c.inner.PubKey() }
func (c *countingVerifier) VerifyRaw(tbs, sig []byte) bool { c.n++; return c.inner.VerifyRaw(tbs, sig) }

// TestMismatchFloodRejectedBeforeSignature proves the normative cost-ordered (cheapest-first)
// verification of # Security Considerations: a flood of mismatched or malformed objects is rejected
// on a cheap check and never forces the ML-DSA signature verification. A positive control first
// shows a VALID object DOES reach signature verification exactly once, so the counter is not
// vacuously zero (the mutation-test discipline: this assertion would flip if Verify stopped
// reaching the signature step at all).
func TestMismatchFloodRejectedBeforeSignature(t *testing.T) {
	c := load(t)
	s, v := testSigner(t)
	cv := &countingVerifier{inner: v}

	// positive control — a valid object reaches signature verification exactly once.
	valid, err := Sign(buildObject(t, c), s)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Verify(cose.ProfilePublic, cv, acceptKind, nil, valid); err != nil {
		t.Fatalf("valid object should verify: %v", err)
	}
	if cv.n != 1 {
		t.Fatalf("positive control: signature verification should be reached once for a valid "+
			"object, got %d (otherwise the counter is vacuous)", cv.n)
	}

	before := cv.n

	// (b) a validly-SIGNED object carrying a wrong content id: its signature is real, but the
	// content-id check (a cheap step) rejects it before the signature verification is reached.
	bogus := make([]byte, 50)
	bogus[0], bogus[1] = 0x20, 0x30 // multihash prefix, then all-zero digest != the true id
	wrongID := signWithID(t, buildObject(t, c), s, bogus)
	if _, err := Verify(cose.ProfilePublic, cv, acceptKind, nil, wrongID); err == nil {
		t.Fatal("a wrong-content-id object must be rejected")
	}

	// (a) a flood of malformed byte strings: rejected at deterministic decode, the cheapest check.
	for i := 0; i < 1000; i++ {
		_, _ = Verify(cose.ProfilePublic, cv, acceptKind, nil, []byte(fmt.Sprintf("not-a-cose-object-%d", i)))
	}

	if cv.n != before {
		t.Fatalf("cheapest-first ordering broken: the signature verification was reached %d time(s) "+
			"during a 1001-object mismatch flood; malformed input must be rejected on a cheap check",
			cv.n-before)
	}
}
