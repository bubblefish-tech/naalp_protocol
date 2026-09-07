// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpdid

import (
	"encoding/json"
	"os"
	"testing"
)

// rfcVectors mirrors testdata/rfc_vectors.json: literal values extracted verbatim (by a
// script, never hand-retyped) from RFC 9964, RFC 8037, and the did:jwk spec — see that
// file's "_provenance" field for the exact source URLs and fetch date. These are the
// non-circular F3 oracle values: none of them was produced by any code in this package.
type rfcVectors struct {
	RFC9964MLDSA44RawPublicKeyHex string `json:"rfc9964_mldsa44_raw_public_key_hex"`
	RFC9964MLDSA44JWKPubB64URL    string `json:"rfc9964_mldsa44_jwk_pub_b64url"`
	RFC8037Ed25519XB64URL         string `json:"rfc8037_ed25519_x_b64url"`
	DIDJWKSpecP256DID             string `json:"didjwk_spec_p256_did"`
}

func loadRFCVectors(t *testing.T) rfcVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/rfc_vectors.json")
	if err != nil {
		t.Fatalf("read testdata/rfc_vectors.json: %v", err)
	}
	var v rfcVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse testdata/rfc_vectors.json: %v", err)
	}
	if v.RFC9964MLDSA44RawPublicKeyHex == "" || v.RFC9964MLDSA44JWKPubB64URL == "" ||
		v.RFC8037Ed25519XB64URL == "" || v.DIDJWKSpecP256DID == "" {
		t.Fatal("testdata/rfc_vectors.json is missing a required field")
	}
	return v
}
