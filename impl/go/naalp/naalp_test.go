// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalp

import (
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// N-AALP channel / kind codes exercised here (design-channels.md): the Interaction surface
// (0x000F) and its baseline kinds Elicit (read_only), Respond (idempotent_write), and Confirm
// (non_idempotent_write).
const (
	chInteraction = 0x000F
	kindElicit    = 0
	kindRespond   = 1
	kindConfirm   = 2
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

// TestSignVerifyRoundTrip proves the genuine path: a signed Interaction message verifies under
// the signer's public key, decodes back to its (channel, kind) and body, and reports the same
// signer id the signer holds. If Verify were replaced with a constant (obj, nil) it would still
// pass here, so the tamper/wrong-key tests below are the mutation guards.
func TestSignVerifyRoundTrip(t *testing.T) {
	a := newSigner(t, 0x11)
	env, err := a.Sign(chInteraction, kindElicit, created, cbor.Tstr("hello from agent A"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	o, err := Verify(a.PublicKey(), env)
	if err != nil {
		t.Fatalf("Verify genuine object: %v", err)
	}
	if o.Channel != chInteraction || o.Kind != kindElicit {
		t.Fatalf("decoded (channel,kind)=(%d,%d), want (%d,%d)", o.Channel, o.Kind, chInteraction, kindElicit)
	}
	body, ok := o.Body.(cbor.Tstr)
	if !ok || string(body) != "hello from agent A" {
		t.Fatalf("decoded body=%v, want text %q", o.Body, "hello from agent A")
	}
	if string(o.Signer) != a.SignerID() {
		t.Fatalf("decoded signer=%q, want %q", string(o.Signer), a.SignerID())
	}
}

// TestVerifyRejectsTamper is the mutation-surviving guard: a one-bit change anywhere in the
// signed bytes must be rejected fail-closed. If Verify were bypassed (e.g. replaced by a stub
// that returns the object with a nil error), this test fails.
func TestVerifyRejectsTamper(t *testing.T) {
	a := newSigner(t, 0x22)
	env, err := a.Sign(chInteraction, kindRespond, created, cbor.Tstr("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	for i := range env {
		tampered := append([]byte(nil), env...)
		tampered[i] ^= 0x01
		if _, err := Verify(a.PublicKey(), tampered); err == nil {
			t.Fatalf("tampered byte %d verified; a tamper must be rejected", i)
		}
	}
}

// TestVerifyRejectsWrongKey proves the signature is bound to the signing key: a genuine object
// presented under a different public key is rejected (the id no longer binds to the presented
// key, or the signature does not verify).
func TestVerifyRejectsWrongKey(t *testing.T) {
	a := newSigner(t, 0x33)
	b := newSigner(t, 0x44)
	env, err := a.Sign(chInteraction, kindElicit, created, cbor.Tstr("hi"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(b.PublicKey(), env); err == nil {
		t.Fatalf("object verified under the wrong public key; it must be rejected")
	}
}

// TestSignRejectsUnknownKind proves Sign refuses to sign an object on a (channel, kind) the
// frozen registry does not admit — it delegates admission to channels.Lookup rather than
// signing arbitrary codes.
func TestSignRejectsUnknownKind(t *testing.T) {
	a := newSigner(t, 0x55)
	if _, err := a.Sign(chInteraction, 99, created, cbor.Tstr("x")); err == nil {
		t.Fatalf("Sign accepted an unregistered kind; it must reject it")
	}
}

// TestSignDerivesDeclaredEffect proves the effect field is taken from the kind's declared
// effect in the registry, not hardcoded. Elicit is read_only, Respond is idempotent_write,
// Confirm is non_idempotent_write; a constant-effect implementation fails at least two of these.
func TestSignDerivesDeclaredEffect(t *testing.T) {
	a := newSigner(t, 0x66)
	cases := []struct {
		kind uint64
		want policy.Effect
	}{
		{kindElicit, policy.ReadOnly},
		{kindRespond, policy.IdempotentWrite},
		{kindConfirm, policy.NonIdempotentWrite},
	}
	for _, c := range cases {
		env, err := a.Sign(chInteraction, c.kind, created, cbor.Tstr("m"))
		if err != nil {
			t.Fatalf("Sign kind %d: %v", c.kind, err)
		}
		o, err := Verify(a.PublicKey(), env)
		if err != nil {
			t.Fatalf("Verify kind %d: %v", c.kind, err)
		}
		if o.Effect != uint64(c.want) {
			t.Fatalf("kind %d effect=%d, want declared %d", c.kind, o.Effect, c.want)
		}
	}
}

// TestNewSignerRejectsBadSeed proves NewSigner is fail-closed on a wrong-length seed: no key
// is minted from 31 bytes.
func TestNewSignerRejectsBadSeed(t *testing.T) {
	if _, err := NewSigner(make([]byte, 31)); err != ErrSeedSize {
		t.Fatalf("NewSigner(31 bytes) err=%v, want ErrSeedSize", err)
	}
}

// TestVerifyRejectsMalformedKey proves Verify rejects a public key of the wrong length before
// any signature check, with the named ErrKeyMalformed.
func TestVerifyRejectsMalformedKey(t *testing.T) {
	a := newSigner(t, 0x77)
	env, err := a.Sign(chInteraction, kindElicit, created, cbor.Tstr("x"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify([]byte{1, 2, 3}, env); err != ErrKeyMalformed {
		t.Fatalf("Verify(short key) err=%v, want ErrKeyMalformed", err)
	}
}

// TestGenerateSignerDistinctIdentities proves GenerateSigner draws fresh random keys: two
// generated signers have different ids and public keys.
func TestGenerateSignerDistinctIdentities(t *testing.T) {
	a, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	b, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	if a.SignerID() == b.SignerID() {
		t.Fatalf("two generated signers share an id: %s", a.SignerID())
	}
	if string(a.PublicKey()) == string(b.PublicKey()) {
		t.Fatalf("two generated signers share a public key")
	}
	// A freshly generated identity still round-trips through sign/verify.
	env, err := a.Sign(chInteraction, kindElicit, created, cbor.Tstr("fresh"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(a.PublicKey(), env); err != nil {
		t.Fatalf("Verify generated-identity object: %v", err)
	}
	// Cross-verifying a's object under b's key must fail.
	if _, err := Verify(b.PublicKey(), env); err == nil {
		t.Fatalf("a's object verified under b's key; it must be rejected")
	}
}
