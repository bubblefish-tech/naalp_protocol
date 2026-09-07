// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpdid

import (
	"encoding/base64"
	"strings"
)

// didJWKPrefix is the did:jwk method prefix (did-jwk spec.md, "DID Format":
// `did-jwk-format := did:jwk:<base64url-value>`).
const didJWKPrefix = "did:jwk:"

// wrapDIDJWK implements the did:jwk method's "Create" operation, steps 2-4
// (did-jwk spec.md, github.com/quartzjer/did-jwk, fetched 2026-08-31): the caller has
// already produced the JWK as a UTF-8 JSON byte string (step 1); this function
// base64url-encodes it (unpadded, per every worked example in the spec — none of the
// P-256/X25519/X448 example DIDs carry a "=" padding character) and prepends the
// "did:jwk:" prefix. It performs no validation of jwkJSON's content — callers (akp.go,
// okp.go) are responsible for producing a public-key-only JWK before this is called.
func wrapDIDJWK(jwkJSON []byte) string {
	return didJWKPrefix + base64.RawURLEncoding.EncodeToString(jwkJSON)
}

// unwrapDIDJWK implements the did:jwk method's "Read" operation, steps 1-2: strip the
// "did:jwk:" prefix and base64url-decode the remainder back to the raw JWK JSON bytes.
// A string without the exact prefix, or whose remainder is not valid unpadded
// base64url, is rejected whole (fail-closed) before any JSON parsing is attempted.
func unwrapDIDJWK(did string) ([]byte, error) {
	rest, ok := strings.CutPrefix(did, didJWKPrefix)
	if !ok {
		return nil, ErrBadDIDPrefix
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return nil, ErrBadDIDEncoding
	}
	return b, nil
}
