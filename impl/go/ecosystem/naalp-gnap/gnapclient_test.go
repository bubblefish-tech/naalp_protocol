// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpgnap

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/delegation"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func clientTestKey(t *testing.T, seed byte) (cose.MLDSA65Signer, []byte) {
	t.Helper()
	var s [mldsa65.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	return cose.MLDSA65Signer{SK: sk}, pk.Bytes()
}

// leafFor builds a stand-in ALREADY-VERIFIED DelegationGrant leaf (design.md §18.1) — the
// shape impl/go/delegation.VerifyChain would have produced on success. This test package
// never calls VerifyChain itself (that machinery is graded in impl/go/delegation, out of
// this package's scope); it exercises ExportDelegationEvidence's OWN, independent
// fail-closed checks against a leaf it is simply handed.
func leafFor(subject string, cap policy.Effect, scope string) delegation.Resolved {
	return delegation.Resolved{
		ContentID: []byte{0x20, 0x30, 0xAA, 0xBB, 0xCC, 0xDD},
		Issuer:    "b" + "issueragent0000000000000000000000000000",
		Grant: delegation.Grant{
			Subject:   subject,
			EffectCap: cap,
			MaxDepth:  0,
			NotBefore: 0,
			NotAfter:  1 << 40,
			Scope:     scope,
		},
	}
}

// ---- Client.ClientField / keyJWK ------------------------------------------------------------

func TestClientField_ProducesValidAKPJWK(t *testing.T) {
	signer, pub := clientTestKey(t, 0x11)
	c := NewClientInstance(signer, cose.AlgMLDSA65, pub)

	cf, err := c.ClientField()
	if err != nil {
		t.Fatalf("ClientField: %v", err)
	}
	if cf.Key.Proof != "httpsig" {
		t.Fatalf("proof = %q, want httpsig", cf.Key.Proof)
	}
	var jwk struct {
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Pub string `json:"pub"`
	}
	if err := json.Unmarshal(cf.Key.JWK, &jwk); err != nil {
		t.Fatalf("decode jwk: %v", err)
	}
	if jwk.Kty != "AKP" {
		t.Errorf("kty = %q, want AKP (RFC 9964 §3)", jwk.Kty)
	}
	if jwk.Alg != "ML-DSA-65" {
		t.Errorf("alg = %q, want ML-DSA-65 (RFC 9964 §8.1.4.2)", jwk.Alg)
	}
	wantPub := base64.RawURLEncoding.EncodeToString(pub)
	if jwk.Pub != wantPub {
		t.Errorf("pub = %q, want %q (base64url of the SAME public key bytes)", jwk.Pub, wantPub)
	}
}

// ---- ExportDelegationEvidence: the D15 export-only, fail-closed enforcement ---------------

func TestExportDelegationEvidence_WithinCeilingSucceeds(t *testing.T) {
	leaf := leafFor("agentB", policy.NonIdempotentWrite, "/orders")
	a, err := ExportDelegationEvidence(leaf, "root-agent", "agentB", policy.IdempotentWrite, "/orders/123")
	if err != nil {
		t.Fatalf("ExportDelegationEvidence: %v", err)
	}
	if a.Format != AssertionFormatDelegationGrant {
		t.Errorf("format = %q, want %q", a.Format, AssertionFormatDelegationGrant)
	}
	var p DelegationAssertionPayload
	if err := json.Unmarshal([]byte(a.Value), &p); err != nil {
		t.Fatalf("decode assertion value: %v", err)
	}
	if p.Subject != "agentB" {
		t.Errorf("subject = %q, want agentB", p.Subject)
	}
	if p.EffectCap != "idempotent_write" {
		t.Errorf("effect_cap = %q, want idempotent_write", p.EffectCap)
	}
	if p.Scope != "/orders/123" {
		t.Errorf("scope = %q, want /orders/123", p.Scope)
	}
	if p.RootIssuer != "root-agent" {
		t.Errorf("root_issuer = %q, want root-agent", p.RootIssuer)
	}
	wantCID := base64.RawURLEncoding.EncodeToString(leaf.ContentID)
	if p.ContentID != wantCID {
		t.Errorf("content_id = %q, want %q", p.ContentID, wantCID)
	}
}

// TestExportDelegationEvidence_RejectsEffectExceedingCeiling is the primary mutation-
// witnessed test for the D15 export-only posture (RED-EVIDENCE.md M2): requesting a
// `destructive` export against a leaf whose own ceiling is `non_idempotent_write` MUST be
// refused. Mutating away the EffectCap.Authorizes check would let the bridge fabricate a
// GNAP assertion claiming authority the underlying DelegationGrant never actually granted
// — exactly the "external AS mints new N-AALP authority" failure D15 forbids.
func TestExportDelegationEvidence_RejectsEffectExceedingCeiling(t *testing.T) {
	leaf := leafFor("agentB", policy.NonIdempotentWrite, "")
	_, err := ExportDelegationEvidence(leaf, "root-agent", "agentB", policy.Destructive, "")
	if err != ErrAuthorityExport {
		t.Fatalf("err = %v, want ErrAuthorityExport", err)
	}
}

func TestExportDelegationEvidence_RejectsScopeNotContained(t *testing.T) {
	leaf := leafFor("agentB", policy.Destructive, "/orders")
	_, err := ExportDelegationEvidence(leaf, "root-agent", "agentB", policy.ReadOnly, "/other")
	if err != ErrAuthorityExport {
		t.Fatalf("err = %v, want ErrAuthorityExport", err)
	}
}

func TestExportDelegationEvidence_RejectsScopeWideningFromUnscopedChild(t *testing.T) {
	// A missing child scope under a scoped parent WIDENS authority (design.md §18.1 D2) —
	// requesting an unconstrained ("") export against a scoped leaf must be refused.
	leaf := leafFor("agentB", policy.Destructive, "/orders")
	_, err := ExportDelegationEvidence(leaf, "root-agent", "agentB", policy.ReadOnly, "")
	if err != ErrAuthorityExport {
		t.Fatalf("err = %v, want ErrAuthorityExport", err)
	}
}

func TestExportDelegationEvidence_RejectsWrongSubject(t *testing.T) {
	leaf := leafFor("agentB", policy.Destructive, "")
	_, err := ExportDelegationEvidence(leaf, "root-agent", "agentC", policy.ReadOnly, "")
	if err != ErrAuthorityExport {
		t.Fatalf("err = %v, want ErrAuthorityExport", err)
	}
}

// ---- Client.BuildGrantRequest ---------------------------------------------------------------

func TestBuildGrantRequest_CarriesAssertionInUserFieldNotSubject(t *testing.T) {
	signer, pub := clientTestKey(t, 0x22)
	c := NewClientInstance(signer, cose.AlgMLDSA65, pub)
	leaf := leafFor("agentB", policy.NonIdempotentWrite, "")
	a, err := ExportDelegationEvidence(leaf, "root-agent", "agentB", policy.NonIdempotentWrite, "")
	if err != nil {
		t.Fatalf("ExportDelegationEvidence: %v", err)
	}

	req, err := c.BuildGrantRequest([]AccessDescriptor{{Type: "naalp-effect"}}, a)
	if err != nil {
		t.Fatalf("BuildGrantRequest: %v", err)
	}
	if req.Subject != nil {
		t.Fatalf("assertion leaked into the request's Subject field: %+v", req.Subject)
	}
	if req.User == nil || len(req.User.Assertions) != 1 || req.User.Assertions[0].Format != AssertionFormatDelegationGrant {
		t.Fatalf("assertion not carried in User.Assertions: %+v", req.User)
	}
}

func TestBuildGrantRequest_OmitsUserWhenNoAssertion(t *testing.T) {
	signer, pub := clientTestKey(t, 0x33)
	c := NewClientInstance(signer, cose.AlgMLDSA65, pub)

	req, err := c.BuildGrantRequest([]AccessDescriptor{{Type: "x"}}, Assertion{})
	if err != nil {
		t.Fatalf("BuildGrantRequest: %v", err)
	}
	if req.User != nil {
		t.Fatalf("User = %+v, want nil when no assertion is presented", req.User)
	}
}
