// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpdid

import (
	"encoding/base64"
	"encoding/json"
)

// akpJWK is the RFC 9964 §3 AKP JWK shape for a PUBLIC key only: "kty":"AKP",
// "alg":"ML-DSA-65"|"ML-DSA-87" (§8.1.4), "pub":base64url(raw public key) (§8.1.6.1).
// Go's encoding/json marshals struct fields in declaration order, so this type's field
// order is what buildAKPJWK emits — deterministic, no separate canonicalization step
// (did-jwk spec.md: "Canonicalization such as JCS is not required"). "priv" (§8.1.6.2)
// is never a field of this type: RFC 9964 requires it MUST NOT be present in a public
// key, and did-jwk's own security rule requires a private-key JWK be rejected outright,
// so this package has no code path that could emit one.
type akpJWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Pub string `json:"pub"`
}

// akpPrivateProbe decodes ONLY the "priv" field, used to detect (and reject) a
// private-key AKP JWK before any public-key field is trusted (RFC 9964 §8.1.6.2: "priv"
// "MUST NOT be present in public keys").
type akpPrivateProbe struct {
	Priv *string `json:"priv"`
}

// buildAKPJWK builds the compact JSON bytes of an RFC 9964 AKP public-key JWK for the
// given JOSE algorithm name ("ML-DSA-44", "ML-DSA-65", or "ML-DSA-87" — RFC 9964
// §8.1.4.1-3) and raw ML-DSA public key. It performs no algorithm-name validation of its
// own (the KAT test below exercises it directly with "ML-DSA-44", which N-AALP's signer
// set does not use but RFC 9964 registers); ToDIDJWK is what restricts the algorithm set
// N-AALP identities may actually bridge.
func buildAKPJWK(algName string, pub []byte) []byte {
	j := akpJWK{Kty: "AKP", Alg: algName, Pub: base64.RawURLEncoding.EncodeToString(pub)}
	// akpJWK's three fields are all plain strings, so json.Marshal on this fixed,
	// struct-typed value cannot fail (matches the identity.go / cbor idiom already used
	// elsewhere in this tree for encoding a fixed-shape value).
	b, _ := json.Marshal(j)
	return b
}

// parseAKPJWK decodes an AKP JWK's JSON bytes, rejecting a private key (ErrPrivateKeyJWK)
// or a non-"AKP" kty (ErrUnsupportedKty) before returning the alg string and raw pubkey
// bytes it names. The private-key probe runs FIRST and independently of the public-field
// parse, so it cannot be bypassed by any parse-order shortcut in akpJWK's own fields.
func parseAKPJWK(raw []byte) (algName string, pub []byte, err error) {
	var probe akpPrivateProbe
	if e := json.Unmarshal(raw, &probe); e != nil {
		return "", nil, ErrMalformedJWK
	}
	if probe.Priv != nil {
		return "", nil, ErrPrivateKeyJWK
	}
	var j akpJWK
	if e := json.Unmarshal(raw, &j); e != nil {
		return "", nil, ErrMalformedJWK
	}
	if j.Kty != "AKP" {
		return "", nil, ErrUnsupportedKty
	}
	if j.Alg == "" || j.Pub == "" {
		return "", nil, ErrMalformedJWK
	}
	pubBytes, e := base64.RawURLEncoding.DecodeString(j.Pub)
	if e != nil {
		return "", nil, ErrMalformedJWK
	}
	return j.Alg, pubBytes, nil
}
