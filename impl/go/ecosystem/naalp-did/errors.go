// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpdid

import "github.com/bubblefish-tech/naalp_protocol/impl/go/cose"

// Named, fail-closed errors. Every rejection returns exactly one of these — no partial
// result, no silent fallback (this repo's CLAUDE.md FAIL-CLOSED discipline).
var (
	// ErrUnknownAlg is returned by ToDIDJWK when alg is not one N-AALP's identity
	// package recognizes (cose.AlgMLDSA65, cose.AlgMLDSA87, or cose.AlgEd25519).
	ErrUnknownAlg = &cose.Error{Kind: "UnknownAlg", Msg: "no did:jwk mapping for the algorithm"}

	// ErrKeySize is returned when a public key's length does not match the fixed size
	// FIPS 204 / RFC 8032 define for its algorithm.
	ErrKeySize = &cose.Error{Kind: "KeySize", Msg: "public key length does not match the algorithm"}

	// ErrBadDIDPrefix is returned when a string handed to FromDIDJWK does not start with
	// the did:jwk method prefix (did-jwk spec.md, "DID Format").
	ErrBadDIDPrefix = &cose.Error{Kind: "BadDIDPrefix", Msg: "identifier does not start with did:jwk:"}

	// ErrBadDIDEncoding is returned when the portion after "did:jwk:" is not valid
	// unpadded base64url.
	ErrBadDIDEncoding = &cose.Error{Kind: "BadDIDEncoding", Msg: "did:jwk value is not valid base64url"}

	// ErrMalformedJWK is returned when the decoded bytes are not a well-formed JSON
	// object, or a required field is missing or not the expected JSON type.
	ErrMalformedJWK = &cose.Error{Kind: "MalformedJWK", Msg: "decoded value is not a valid JWK object"}

	// ErrPrivateKeyJWK is returned when the decoded JWK carries private-key material
	// ("priv" for an AKP key, "d" for an OKP key). did-jwk spec.md, Security
	// Considerations: "a JWK for a private key must never be used and must be rejected
	// by all implementations when encountered." This is checked BEFORE any public-key
	// field is trusted.
	ErrPrivateKeyJWK = &cose.Error{Kind: "PrivateKeyJWK", Msg: "a private-key JWK MUST NOT be used as a did:jwk identifier"}

	// ErrUnsupportedKty is returned when the JWK's "kty" is neither "AKP" (RFC 9964,
	// ML-DSA) nor "OKP" (RFC 8037, Ed25519) — the only two key types N-AALP identities
	// can carry.
	ErrUnsupportedKty = &cose.Error{Kind: "UnsupportedKty", Msg: "kty is not AKP or OKP"}

	// ErrUnsupportedAlgString is returned when an AKP JWK's "alg" is not "ML-DSA-65" or
	// "ML-DSA-87" — the two ML-DSA parameter sets identity.go recognizes (ML-DSA-44 is a
	// real RFC 9964 registration but is not an N-AALP signer algorithm).
	ErrUnsupportedAlgString = &cose.Error{Kind: "UnsupportedAlgString", Msg: "AKP alg is not ML-DSA-65 or ML-DSA-87"}

	// ErrUnsupportedCurve is returned when an OKP JWK's "crv" is not "Ed25519" — the
	// only classical curve identity.go recognizes as a signing key.
	ErrUnsupportedCurve = &cose.Error{Kind: "UnsupportedCurve", Msg: "OKP crv is not Ed25519"}
)
