// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpcore

import (
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// Channel/kind codes exercised here mirror impl/go/naalp/naalp_test.go: the Interaction
// surface (0x000F) and its baseline kinds Elicit (read_only) and Respond
// (idempotent_write).
const (
	chInteraction = 0x000F
	kindElicit    = 0
	kindRespond   = 1
	created       = 1785000000000
)

func newSigner(t *testing.T, seedByte byte) *Signer {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = seedByte
	}
	s, err := NewSigner(seed)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

// TestSignVerifyRoundTrip proves Sign/Verify are real delegations, not stubs: a signed
// object decodes back to its (channel, kind, body, effect) and reports the signer's own
// id. A constant-return Sign or Verify fails this immediately (no valid bytes to decode,
// or a decoded object that does not match what was signed).
func TestSignVerifyRoundTrip(t *testing.T) {
	s := newSigner(t, 0x11)
	obj, err := Sign(s, chInteraction, kindElicit, created, cbor.Tstr("facade round-trip"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	o, err := Verify(s.PublicKey(), obj)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if o.Channel != chInteraction || o.Kind != kindElicit {
		t.Fatalf("decoded (channel,kind)=(%d,%d), want (%d,%d)", o.Channel, o.Kind, chInteraction, kindElicit)
	}
	body, ok := o.Body.(cbor.Tstr)
	if !ok || string(body) != "facade round-trip" {
		t.Fatalf("decoded body=%v, want text %q", o.Body, "facade round-trip")
	}
	if o.Effect != uint64(policy.ReadOnly) {
		t.Fatalf("decoded effect=%d, want ReadOnly(%d) for Elicit", o.Effect, policy.ReadOnly)
	}
	if string(o.Signer) != s.SignerID() {
		t.Fatalf("decoded signer=%q, want %q", string(o.Signer), s.SignerID())
	}
}

// TestVerifyRejectsTamper is the mutation-surviving guard for Verify: flip one bit
// anywhere in the signed bytes and Verify must reject it. If Verify were replaced with a
// stub that always returns (obj, nil), every one of these flips would wrongly pass.
func TestVerifyRejectsTamper(t *testing.T) {
	s := newSigner(t, 0x22)
	obj, err := Sign(s, chInteraction, kindRespond, created, cbor.Tstr("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	for i := range obj {
		tampered := append([]byte(nil), obj...)
		tampered[i] ^= 0x01
		if _, err := Verify(s.PublicKey(), tampered); err == nil {
			t.Fatalf("tampered byte %d verified; a tamper must be rejected", i)
		}
	}
}

// TestSignRejectsUnknownKind is the mutation-surviving guard for Sign: it must refuse an
// unregistered (channel, kind) rather than silently signing it. A stub Sign that always
// returns (someBytes, nil) fails this.
func TestSignRejectsUnknownKind(t *testing.T) {
	s := newSigner(t, 0x33)
	if _, err := Sign(s, chInteraction, 99, created, cbor.Tstr("x")); err == nil {
		t.Fatalf("Sign accepted an unregistered kind; it must reject it")
	}
}

// TestContentIDDeterministic proves ContentID is a real digest over the body, not a
// stub: the same body produces the same id twice, and a changed body produces a
// different id. A constant-return ContentID fails the second half of this.
func TestContentIDDeterministic(t *testing.T) {
	bodyA := cbor.Map{{K: cbor.Uint(2), V: cbor.Tstr("hello")}}
	bodyB := cbor.Map{{K: cbor.Uint(2), V: cbor.Tstr("world")}}

	idA1, err := ContentID(bodyA)
	if err != nil {
		t.Fatalf("ContentID(bodyA) #1: %v", err)
	}
	idA2, err := ContentID(bodyA)
	if err != nil {
		t.Fatalf("ContentID(bodyA) #2: %v", err)
	}
	if string(idA1) != string(idA2) {
		t.Fatalf("ContentID not deterministic: %x != %x", idA1, idA2)
	}
	if len(idA1) != 50 {
		t.Fatalf("ContentID length=%d, want 50 (0x20 0x30 || 48-byte SHA-384)", len(idA1))
	}
	if idA1[0] != 0x20 || idA1[1] != 0x30 {
		t.Fatalf("ContentID multihash prefix=%x, want 2030", idA1[:2])
	}

	idB, err := ContentID(bodyB)
	if err != nil {
		t.Fatalf("ContentID(bodyB): %v", err)
	}
	if string(idA1) == string(idB) {
		t.Fatalf("two different bodies produced the same ContentID")
	}
}

// TestSignerIDExtraction proves SignerID is a real, pure function of (alg, pubkey): it
// agrees with the id a naalpcore.Signer was itself constructed with (the very same
// identity.SignerID call inside naalp.NewSigner), and two different keys under the same
// algorithm produce two different ids.
func TestSignerIDExtraction(t *testing.T) {
	a := newSigner(t, 0x44)
	b := newSigner(t, 0x55)

	gotA, err := SignerID(AlgMLDSA65, a.PublicKey())
	if err != nil {
		t.Fatalf("SignerID(a): %v", err)
	}
	if gotA != a.SignerID() {
		t.Fatalf("SignerID(a.PublicKey())=%q, want %q (the id a was constructed with)", gotA, a.SignerID())
	}

	gotB, err := SignerID(AlgMLDSA65, b.PublicKey())
	if err != nil {
		t.Fatalf("SignerID(b): %v", err)
	}
	if gotA == gotB {
		t.Fatalf("two different public keys produced the same signer id: %q", gotA)
	}

	// Cross-check against the underlying identity package directly, proving this is a
	// real delegation and not a locally recomputed value.
	want, err := identity.SignerID(AlgMLDSA65, a.PublicKey())
	if err != nil {
		t.Fatalf("identity.SignerID(a): %v", err)
	}
	if gotA != want {
		t.Fatalf("naalpcore.SignerID diverges from identity.SignerID: %q != %q", gotA, want)
	}
}

// TestSignerIDRejectsUnknownAlg proves SignerID fails closed on an algorithm the identity
// layer does not recognize, rather than silently hashing under an unregistered suite.
func TestSignerIDRejectsUnknownAlg(t *testing.T) {
	a := newSigner(t, 0x66)
	if _, err := SignerID(-1, a.PublicKey()); err == nil {
		t.Fatalf("SignerID accepted an unregistered algorithm id; it must reject it")
	}
}
