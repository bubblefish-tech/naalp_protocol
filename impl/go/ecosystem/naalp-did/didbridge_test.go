// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpdid

import (
	"crypto/ed25519"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Fixed test seeds — deterministic, reproducible, not secrets (this is a public,
// committed test file; these keys have no value outside this test binary).
var (
	seed65 = fixedSeed(0xA1, mldsa65.SeedSize)
	seed87 = fixedSeed(0xB2, mldsa87.SeedSize)
	seedEd = fixedSeed(0xC3, ed25519.SeedSize)
)

func fixedSeed(b byte, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b ^ byte(i)
	}
	return s
}

// testEd25519Signer implements cose.Signer for Ed25519 (the cose package exports only
// Ed25519Verifier, not a signer type — Ed25519 in this codebase is used only as a
// verify-side hybrid leg — so this test-only type fills that gap for exercising
// LinkSignerToDID's Ed25519 path, using the same stdlib crypto/ed25519.Sign the rest of
// the tree relies on).
type testEd25519Signer struct{ sk ed25519.PrivateKey }

func (testEd25519Signer) Alg() int { return cose.AlgEd25519 }
func (s testEd25519Signer) Sign(tbs []byte) ([]byte, error) {
	return ed25519.Sign(s.sk, tbs), nil
}

// TestToFromDIDJWK_RoundTripIdentity is acceptance criterion 2: for each algorithm
// N-AALP's identity package supports, identity.SignerID(alg, pub) computed directly must
// equal identity.SignerID applied to the pubkey recovered via
// FromDIDJWK(ToDIDJWK(alg, pub)) — the DID and the signer id must provably name the same
// key. This is the property that matters operationally.
func TestToFromDIDJWK_RoundTripIdentity(t *testing.T) {
	var s65 [mldsa65.SeedSize]byte
	copy(s65[:], seed65)
	pk65, _ := mldsa65.NewKeyFromSeed(&s65)

	var s87 [mldsa87.SeedSize]byte
	copy(s87[:], seed87)
	pk87, _ := mldsa87.NewKeyFromSeed(&s87)

	edPub := ed25519.NewKeyFromSeed(seedEd).Public().(ed25519.PublicKey)

	cases := []struct {
		name string
		alg  int
		pub  []byte
	}{
		{"ML-DSA-65", cose.AlgMLDSA65, pk65.Bytes()},
		{"ML-DSA-87", cose.AlgMLDSA87, pk87.Bytes()},
		{"Ed25519", cose.AlgEd25519, []byte(edPub)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantID, err := identity.SignerID(c.alg, c.pub)
			if err != nil {
				t.Fatalf("identity.SignerID: %v", err)
			}
			did, err := ToDIDJWK(c.alg, c.pub)
			if err != nil {
				t.Fatalf("ToDIDJWK: %v", err)
			}
			gotAlg, gotPub, err := FromDIDJWK(did)
			if err != nil {
				t.Fatalf("FromDIDJWK(%s): %v", did, err)
			}
			if gotAlg != c.alg {
				t.Errorf("alg round-trip: got %d want %d", gotAlg, c.alg)
			}
			gotID, err := identity.SignerID(gotAlg, gotPub)
			if err != nil {
				t.Fatalf("identity.SignerID on recovered key: %v", err)
			}
			if gotID != wantID {
				t.Errorf("signer id mismatch after did:jwk round trip: got %s want %s", gotID, wantID)
			}
			// NFC: ForeignID is base64url + ASCII structural characters only, so
			// identity.RequireNFC must trivially accept it — asserted explicitly
			// (acceptance criterion 4), not assumed.
			if err := identity.RequireNFC(did); err != nil {
				t.Errorf("did:jwk identifier failed RequireNFC: %v", err)
			}
		})
	}
}

func TestToDIDJWK_RejectsUnknownAlg(t *testing.T) {
	if _, err := ToDIDJWK(-9999, make([]byte, 32)); err != ErrUnknownAlg {
		t.Fatalf("got err=%v, want ErrUnknownAlg", err)
	}
}

func TestToDIDJWK_RejectsWrongKeySize(t *testing.T) {
	cases := []struct {
		alg int
		n   int
	}{
		{cose.AlgMLDSA65, mldsa65.PublicKeySize - 1},
		{cose.AlgMLDSA87, mldsa87.PublicKeySize + 1},
		{cose.AlgEd25519, ed25519.PublicKeySize - 1},
	}
	for _, c := range cases {
		if _, err := ToDIDJWK(c.alg, make([]byte, c.n)); err != ErrKeySize {
			t.Errorf("alg=%d len=%d: got err=%v, want ErrKeySize", c.alg, c.n, err)
		}
	}
}

func TestFromDIDJWK_RejectsUnsupportedAlgString(t *testing.T) {
	// A syntactically valid AKP JWK naming ML-DSA-44 (real per RFC 9964, but not an
	// N-AALP signer algorithm) must be rejected, not silently mapped to a nearby alg.
	did := wrapDIDJWK(buildAKPJWK("ML-DSA-44", bytesOfLen(1312, 0x01)))
	if _, _, err := FromDIDJWK(did); err != ErrUnsupportedAlgString {
		t.Fatalf("got err=%v, want ErrUnsupportedAlgString", err)
	}
}

func TestFromDIDJWK_RejectsPrivateKeyJWK(t *testing.T) {
	did := wrapDIDJWK([]byte(`{"kty":"AKP","alg":"ML-DSA-65","pub":"AAAA","priv":"AAAA"}`))
	if _, _, err := FromDIDJWK(did); err != ErrPrivateKeyJWK {
		t.Fatalf("got err=%v, want ErrPrivateKeyJWK", err)
	}
}

func TestFromDIDJWK_RejectsMalformedIdentifier(t *testing.T) {
	if _, _, err := FromDIDJWK("not-a-did-at-all"); err != ErrBadDIDPrefix {
		t.Fatalf("got err=%v, want ErrBadDIDPrefix", err)
	}
}

// TestLinkSignerToDID_VerifyForeignLink is acceptance criterion 3: LinkSignerToDID plus
// identity.VerifyForeignLink on the resulting record must confirm linkage (linked ==
// true) for a valid self-link, and must confirm NO linkage (linked == false) once the
// record is tampered with — not merely "no error". Two independent tamper paths are
// exercised: a byte flip in ForeignID (breaks the signature check) and NotAfter moved to
// the past (the expiry check, which short-circuits before the signature is even
// checked).
func TestLinkSignerToDID_VerifyForeignLink(t *testing.T) {
	var s65 [mldsa65.SeedSize]byte
	copy(s65[:], seed65)
	pk, sk := mldsa65.NewKeyFromSeed(&s65)
	pub := pk.Bytes()
	signer := cose.MLDSA65Signer{SK: sk}

	const notAfter = 2_000_000_000 // far future, unix seconds
	rec, sig, err := LinkSignerToDID(cose.AlgMLDSA65, pub, notAfter, signer)
	if err != nil {
		t.Fatalf("LinkSignerToDID: %v", err)
	}

	wantSignerID, err := identity.SignerID(cose.AlgMLDSA65, pub)
	if err != nil {
		t.Fatalf("identity.SignerID: %v", err)
	}
	if rec.Controls != wantSignerID {
		t.Fatalf("rec.Controls = %s, want %s", rec.Controls, wantSignerID)
	}
	wantDID, err := ToDIDJWK(cose.AlgMLDSA65, pub)
	if err != nil {
		t.Fatalf("ToDIDJWK: %v", err)
	}
	if rec.ForeignID != wantDID {
		t.Fatalf("rec.ForeignID = %s, want %s", rec.ForeignID, wantDID)
	}

	var vpk mldsa65.PublicKey
	if err := vpk.UnmarshalBinary(pub); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	verifier := cose.MLDSA65Verifier{PK: &vpk}

	linked, err := identity.VerifyForeignLink(rec, verifier, pub, sig, 1_000_000_000 /* now < notAfter */)
	if err != nil {
		t.Fatalf("VerifyForeignLink (valid record): %v", err)
	}
	if !linked {
		t.Fatal("VerifyForeignLink reported linked=false for a valid, freshly-signed record")
	}

	t.Run("tampered_ForeignID", func(t *testing.T) {
		tampered := rec
		tampered.ForeignID = rec.ForeignID[:len(rec.ForeignID)-1] + flipLastChar(rec.ForeignID)
		linked, err := identity.VerifyForeignLink(tampered, verifier, pub, sig, 1_000_000_000)
		if err != nil {
			t.Fatalf("VerifyForeignLink (tampered ForeignID): unexpected error %v", err)
		}
		if linked {
			t.Fatal("VerifyForeignLink reported linked=true for a ForeignID tampered after signing")
		}
	})

	t.Run("expired_NotAfter", func(t *testing.T) {
		linked, err := identity.VerifyForeignLink(rec, verifier, pub, sig, notAfter+1 /* now > NotAfter */)
		if err != nil {
			t.Fatalf("VerifyForeignLink (expired): unexpected error %v", err)
		}
		if linked {
			t.Fatal("VerifyForeignLink reported linked=true for a record evaluated after NotAfter")
		}
	})
}

// flipLastChar returns a single base64url character guaranteed to differ from the last
// character of s, so replacing s's last character with it is a genuine one-character
// mutation (never a no-op).
func flipLastChar(s string) string {
	if len(s) == 0 {
		return "A"
	}
	last := s[len(s)-1]
	if last == 'A' {
		return "B"
	}
	return "A"
}
