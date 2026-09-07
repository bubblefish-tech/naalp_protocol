// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpgnap

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/delegation"
	naalpdid "github.com/bubblefish-tech/naalp_protocol/impl/go/ecosystem/naalp-did"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// AssertionFormatDelegationGrant is the CANDIDATE "GNAP Assertion Formats" (RFC 9635
// §10.6) registry value this bridge proposes for carrying N-AALP DelegationGrant evidence.
// It is DELIBERATELY NOT frozen/registered by this package — see doc.go's "Decision
// surfaced, not frozen" section. Changing it is a one-line, non-wire-breaking edit (it
// never appears in spec/naalp-draft-01.cddl or any conformance vector/corpus file).
const AssertionFormatDelegationGrant = "naalp-delegation-grant"

// DelegationAssertionPayload is the JSON shape this bridge serializes into an Assertion's
// Value field for AssertionFormatDelegationGrant (RFC 9635 §2.4: "value" is "the JSON
// string serialization of the assertion"). It is a NEW N-AALP-ecosystem JSON shape (not a
// CDDL/wire object) proposed by this package, not yet frozen — see doc.go. It carries ONLY
// information already exposed by an already-verified delegation.Resolved leaf; it asserts
// no new claim ExportDelegationEvidence has not itself checked against that leaf.
type DelegationAssertionPayload struct {
	// Subject is agent B's signer id (design.md §5.1) — the delegatee this evidence is
	// FOR. MUST equal the leaf grant's own Subject (ExportDelegationEvidence enforces
	// this).
	Subject string `json:"subject"`
	// EffectCap is the exported effect ceiling's name (policy.Effect.SafetyLabelName:
	// "read_only"/"idempotent_write"/"non_idempotent_write"/"destructive"). It is the
	// REQUESTED ceiling, never higher than the leaf grant's own EffectCap
	// (ExportDelegationEvidence enforces this via Grant.EffectCap.Authorizes).
	EffectCap string `json:"effect_cap"`
	// Scope is the exported resource scope, contained in the leaf grant's own Scope
	// under the design.md §18.1 D2 path-prefix rule (ExportDelegationEvidence enforces
	// this via delegation.ScopeContained). Omitted (absent) when unconstrained.
	Scope string `json:"scope,omitempty"`
	// RootIssuer is the trust-anchor signer id the caller's own delegation.VerifyChain
	// walk terminated at. This package does not re-derive or re-verify it — it is
	// carried exactly as the caller supplies it, so the external relying party is on
	// notice that trust-anchor validation is the CALLER's (not this bridge's)
	// responsibility if it chooses to trust this assertion without independently
	// re-verifying the chain.
	RootIssuer string `json:"root_issuer"`
	// ContentID is base64url(leaf.ContentID) — the leaf DelegationGrant's own envelope
	// content id (design.md §2.3), so a relying party holding the actual signed grant
	// object can independently confirm this assertion names the SAME grant.
	ContentID string `json:"content_id"`
}

// Client is an N-AALP agent presenting itself as a GNAP client instance (RFC 9635 §2.3):
// it proves possession of its EXISTING N-AALP signer-id keypair via RFC 9421 HTTP Message
// Signatures (gnapsig.go) — no new keypair, no new identity primitive is introduced.
type Client struct {
	Signer cose.Signer
	Alg    int
	PubKey []byte
}

// NewClientInstance builds a Client from an agent's existing cose.Signer/algorithm/public
// key — the SAME (signer, alg, pubkey) triple impl/go/envelope.Sign and
// impl/go/identity.SignerID already consume elsewhere in this tree, reused unchanged.
func NewClientInstance(signer cose.Signer, alg int, pubKey []byte) *Client {
	return &Client{Signer: signer, Alg: alg, PubKey: pubKey}
}

// keyJWK returns the client instance's public key as a JSON Web Key by reusing
// naalpdid.ToDIDJWK's did:jwk construction (E4.1, RFC 9964 for ML-DSA / RFC 8037 for
// Ed25519) and decoding the JWK JSON back out of the did:jwk string's base64url payload
// (the did:jwk method's own "Read" operation, unwrapped here) — the SAME JWK bytes the
// did:jwk bridge already produces, so this package reimplements no JWK-construction logic
// of its own (D5/A10: no parallel encoder for a thing that already exists and is graded).
func keyJWK(alg int, pubKey []byte) (json.RawMessage, error) {
	did, err := naalpdid.ToDIDJWK(alg, pubKey)
	if err != nil {
		return nil, err
	}
	rest, ok := strings.CutPrefix(did, "did:jwk:")
	if !ok {
		return nil, ErrMalformedRequest // unreachable in practice: ToDIDJWK always returns this prefix
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return nil, ErrMalformedRequest
	}
	return json.RawMessage(raw), nil
}

// ClientField builds the "client" object of a Grant Request (RFC 9635 §2.3): proof
// "httpsig" (RFC 9421, gnapsig.go — the only proofing method this package implements)
// over the instance's existing key.
func (c *Client) ClientField() (ClientField, error) {
	jwk, err := keyJWK(c.Alg, c.PubKey)
	if err != nil {
		return ClientField{}, err
	}
	return ClientField{Key: Key{Proof: "httpsig", JWK: jwk}}, nil
}

// ExportDelegationEvidence is the bridge's SOLE authority-carrying operation (design.md
// §18, the D15 fail-closed posture referenced in the E4.2 grounding note): given an
// ALREADY-VERIFIED DelegationGrant leaf (the caller's own successful
// impl/go/delegation.VerifyChain walk — this function re-verifies NOTHING about the
// chain, trust anchors, revocation, or validity window; it is not a chain verifier and
// does not import envelope/cose verification), it serializes EXACTLY the leaf's
// post-attenuation authority — never more. This is what makes the bridge EXPORT-ONLY:
// there is no code path in this package, or anywhere in Client/GrantRequest construction,
// that lets an external GNAP AS mint NEW N-AALP authority; this function only narrows or
// reproduces what the leaf already, verifiably, grants — and it checks that narrowing
// itself, independent of whatever the caller claims.
//
// The requested export is rejected ErrAuthorityExport, fail-closed, if ANY of:
//   - subject does not equal the leaf's own Grant.Subject (this leaf's evidence is not
//     valid FOR any other agent);
//   - requestedEffect exceeds the leaf's Grant.EffectCap on the §6.1 lattice
//     (Grant.EffectCap.Authorizes — the SAME check design.md §18.2 step 6 performs);
//   - requestedScope is not contained in the leaf's Grant.Scope
//     (delegation.ScopeContained — the SAME D2 containment rule step 6 performs).
func ExportDelegationEvidence(leaf delegation.Resolved, rootIssuer, subject string, requestedEffect policy.Effect, requestedScope string) (Assertion, error) {
	if subject != leaf.Grant.Subject {
		return Assertion{}, ErrAuthorityExport
	}
	if !leaf.Grant.EffectCap.Authorizes(requestedEffect) {
		return Assertion{}, ErrAuthorityExport
	}
	if !delegation.ScopeContained(requestedScope, leaf.Grant.Scope) {
		return Assertion{}, ErrAuthorityExport
	}
	payload := DelegationAssertionPayload{
		Subject:    subject,
		EffectCap:  requestedEffect.SafetyLabelName(),
		Scope:      requestedScope,
		RootIssuer: rootIssuer,
		ContentID:  base64.RawURLEncoding.EncodeToString(leaf.ContentID),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return Assertion{}, err
	}
	return Assertion{Format: AssertionFormatDelegationGrant, Value: string(b)}, nil
}

// BuildGrantRequest assembles a Grant Request (RFC 9635 §2) presenting this client
// instance's key and, when assertion.Format is non-empty, the DelegationGrant evidence
// ExportDelegationEvidence produced — carried in "user.assertions" (RFC 9635 §2.4), NOT
// "subject.assertion_formats": §2.2's assertion_formats field REQUESTS formats FROM the
// AS, it is not a channel for a client to PRESENT an assertion it already holds. See
// doc.go's "correction to the E4.2 grounding note" section for why this bridge departs
// from the earlier grounding note's (c)2 sketch on this specific point. A zero-value
// assertion (Format == "") omits the User field entirely.
func (c *Client) BuildGrantRequest(access []AccessDescriptor, assertion Assertion) (GrantRequest, error) {
	cf, err := c.ClientField()
	if err != nil {
		return GrantRequest{}, err
	}
	req := GrantRequest{
		AccessToken: AccessTokenRequest{Access: access},
		Client:      cf,
	}
	if assertion.Format != "" {
		req.User = &UserField{Assertions: []Assertion{assertion}}
	}
	return req, nil
}
