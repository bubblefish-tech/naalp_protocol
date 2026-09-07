// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpdid

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// TestBuildOKPJWK_ReproducesRFC8037Example is the non-circular KAT for the Ed25519 leg:
// RFC 8037 Appendix A.1's public-key-only example {"kty":"OKP","crv":"Ed25519","x":...}
// (fetched and read as raw text this session), decoded independently (stdlib
// base64.RawURLEncoding, not this package) to get the raw public key, then re-encoded by
// buildOKPJWK and confirmed to byte-match the RFC's own "x" field.
func TestBuildOKPJWK_ReproducesRFC8037Example(t *testing.T) {
	v := loadRFCVectors(t)
	rawPub, err := base64.RawURLEncoding.DecodeString(v.RFC8037Ed25519XB64URL)
	if err != nil {
		t.Fatalf("independent stdlib decode of RFC 8037's x field: %v", err)
	}
	if len(rawPub) != 32 {
		t.Fatalf("Ed25519 public keys are 32 bytes (RFC 8032); got %d", len(rawPub))
	}

	got := buildOKPJWK(rawPub)
	var parsed okpJWK
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("buildOKPJWK produced invalid JSON: %v", err)
	}
	if parsed.Kty != "OKP" {
		t.Errorf("kty = %q, want OKP (RFC 8037 §2)", parsed.Kty)
	}
	if parsed.Crv != "Ed25519" {
		t.Errorf("crv = %q, want Ed25519", parsed.Crv)
	}
	if parsed.X != v.RFC8037Ed25519XB64URL {
		t.Errorf("x field does not byte-match RFC 8037's own example\n got: %s\nwant: %s", parsed.X, v.RFC8037Ed25519XB64URL)
	}
}

func TestParseOKPJWK_RoundTrip(t *testing.T) {
	pub := bytesOfLen(32, 0x11)
	raw := buildOKPJWK(pub)
	got, err := parseOKPJWK(raw)
	if err != nil {
		t.Fatalf("parseOKPJWK: %v", err)
	}
	if string(got) != string(pub) {
		t.Fatalf("pub round-trip mismatch")
	}
}

func TestParseOKPJWK_RejectsPrivateKey(t *testing.T) {
	raw := []byte(`{"kty":"OKP","crv":"Ed25519","x":"AAAA","d":"BBBB"}`)
	if _, err := parseOKPJWK(raw); err != ErrPrivateKeyJWK {
		t.Fatalf("got err=%v, want ErrPrivateKeyJWK", err)
	}
}

func TestParseOKPJWK_RejectsWrongCurve(t *testing.T) {
	raw := []byte(`{"kty":"OKP","crv":"X25519","x":"AAAA"}`)
	if _, err := parseOKPJWK(raw); err != ErrUnsupportedCurve {
		t.Fatalf("got err=%v, want ErrUnsupportedCurve", err)
	}
}

func TestParseOKPJWK_RejectsWrongKty(t *testing.T) {
	raw := []byte(`{"kty":"AKP","crv":"Ed25519","x":"AAAA"}`)
	if _, err := parseOKPJWK(raw); err != ErrUnsupportedKty {
		t.Fatalf("got err=%v, want ErrUnsupportedKty", err)
	}
}
