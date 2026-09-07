// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/naalp"
)

// TestRunSucceeds confirms the full two-agent loop completes without an invariant violation and
// prints all five steps. Because run returns an error if the genuine object fails to verify, if
// the body does not round-trip, or if the tampered object is NOT rejected, a green run is
// evidence the whole loop held.
func TestRunSucceeds(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"[1] agent A generated an identity",
		"[2] agent A signed an object",
		"[3] over the wire to agent B",
		"[4] agent B VERIFIED the object offline",
		"[5] agent B REJECTED a tampered copy",
		"OK:",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q\n---\n%s", want, got)
		}
	}
}

// TestTamperedEnvelopeRejected is the standalone mutation guard for the loop's security claim: a
// one-bit change anywhere in a genuine object must be rejected by naalp.Verify. If verification
// were bypassed, this test fails.
func TestTamperedEnvelopeRejected(t *testing.T) {
	a, err := naalp.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	env, err := a.Sign(channelInteraction, kindElicit, 1785000000000, cbor.Tstr(message))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := naalp.Verify(a.PublicKey(), env); err != nil {
		t.Fatalf("genuine object must verify: %v", err)
	}
	for i := range env {
		tampered := append([]byte(nil), env...)
		tampered[i] ^= 0x01
		if _, err := naalp.Verify(a.PublicKey(), tampered); err == nil {
			t.Fatalf("tampered byte %d verified; must be rejected", i)
		}
	}
}
