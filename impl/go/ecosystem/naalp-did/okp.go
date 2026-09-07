// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpdid

import (
	"encoding/base64"
	"encoding/json"
)

// okpJWK is the RFC 8037 OKP JWK shape for a PUBLIC Ed25519 key only: "kty":"OKP",
// "crv":"Ed25519" (§2), "x":base64url(raw public key) (§2, "The 'x' ... member contains
// the public key"). Field order (kty, crv, x) matches RFC 8037 Appendix A.1's own
// public-key-only example. "d" (the private key, §2) is never a field of this type.
type okpJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// okpPrivateProbe decodes ONLY the "d" field, used to detect (and reject) a private-key
// OKP JWK before any public-key field is trusted (RFC 8037 §2: "d" is the private key).
type okpPrivateProbe struct {
	D *string `json:"d"`
}

// buildOKPJWK builds the compact JSON bytes of an RFC 8037 OKP public-key JWK for an
// Ed25519 public key — the only curve N-AALP's identity package signs with
// (identity.go's multicodecFor: ed25519-pub).
func buildOKPJWK(pub []byte) []byte {
	j := okpJWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
	b, _ := json.Marshal(j) // fixed string fields: cannot fail (see akp.go's buildAKPJWK).
	return b
}

// parseOKPJWK decodes an OKP JWK's JSON bytes, rejecting a private key (ErrPrivateKeyJWK),
// a non-"OKP" kty (ErrUnsupportedKty), or a non-Ed25519 curve (ErrUnsupportedCurve)
// before returning the raw public-key bytes it names.
func parseOKPJWK(raw []byte) (pub []byte, err error) {
	var probe okpPrivateProbe
	if e := json.Unmarshal(raw, &probe); e != nil {
		return nil, ErrMalformedJWK
	}
	if probe.D != nil {
		return nil, ErrPrivateKeyJWK
	}
	var j okpJWK
	if e := json.Unmarshal(raw, &j); e != nil {
		return nil, ErrMalformedJWK
	}
	if j.Kty != "OKP" {
		return nil, ErrUnsupportedKty
	}
	if j.Crv != "Ed25519" {
		return nil, ErrUnsupportedCurve
	}
	if j.X == "" {
		return nil, ErrMalformedJWK
	}
	pubBytes, e := base64.RawURLEncoding.DecodeString(j.X)
	if e != nil {
		return nil, ErrMalformedJWK
	}
	return pubBytes, nil
}
