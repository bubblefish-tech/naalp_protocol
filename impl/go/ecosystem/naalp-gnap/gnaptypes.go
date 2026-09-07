// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpgnap

import "encoding/json"

// ---- RFC 9635 §2 — the Grant Request ----------------------------------------------------

// AccessDescriptor is one entry of an access_token's "access" array (RFC 9635 §2.1.1): a
// resource-API-specific description of the access being requested or granted. Type is the
// only field every resource API MUST define; Actions/Locations/Datatypes/Identifier are the
// RFC-named common optional dimensions a resource API may use to narrow it further.
type AccessDescriptor struct {
	Type       string   `json:"type"`
	Actions    []string `json:"actions,omitempty"`
	Locations  []string `json:"locations,omitempty"`
	Datatypes  []string `json:"datatypes,omitempty"`
	Identifier string   `json:"identifier,omitempty"`
}

// AccessTokenRequest is the "access_token" object of a Grant Request (RFC 9635 §2.1): the
// set of access being requested (§2.1.1), an optional client-chosen Label identifying this
// token among several in a multi-token request, and optional Flags (§2.1.2).
type AccessTokenRequest struct {
	Access []AccessDescriptor `json:"access"`
	Label  string             `json:"label,omitempty"`
	Flags  []string           `json:"flags,omitempty"`
}

// Key is the "key" object identifying a GNAP participant's key material and proofing
// method (RFC 9635 §7.1/§7.3): Proof names the key-proofing mechanism ("httpsig" for RFC
// 9421 HTTP Message Signatures — the ONLY proofing method this package implements,
// gnapsig.go); JWK carries the public key as a JSON Web Key (RFC 7517) — here always an
// N-AALP signer's existing key re-encoded as JSON, never a newly minted keypair.
type Key struct {
	Proof string          `json:"proof"`
	JWK   json.RawMessage `json:"jwk"`
}

// ClientField is the "client" field of a Grant Request (RFC 9635 §2.3): the minimal
// by-value form this bridge sends is a bare object naming the proofing Key. RFC 9635 also
// allows "client" to be a bare string (an already-registered client-instance handle) or to
// carry "class_id"/"display"; this bridge sends only the by-value Key form, since an
// N-AALP agent is not a pre-registered GNAP client instance.
type ClientField struct {
	Key Key `json:"key"`
}

// SubjectIdentifier is one RFC 9493 Subject Identifier: a JSON object whose only fixed key
// is "format" ("opaque", "iss_sub", "email", ...), the remaining keys being format-specific
// (e.g. "id" for "opaque"; "iss"+"sub" for "iss_sub"). Modeled as a generic string map so
// every registered format round-trips without this bridge hardcoding each shape.
type SubjectIdentifier map[string]string

// Assertion is one entry of a "user" (RFC 9635 §2.4) or subject-response (§3.4) assertions
// array: Format names a registered "GNAP Assertion Formats" value (§10.6 — "id_token",
// "saml2", or the candidate N-AALP value this package proposes, see doc.go); Value is "the
// JSON string serialization of the assertion" (§2.4) — for the N-AALP delegation format
// that is the JSON bytes of a DelegationAssertionPayload (gnapclient.go), never raw
// CBOR/COSE bytes.
type Assertion struct {
	Format string `json:"format"`
	Value  string `json:"value"`
}

// UserField is the "user" object of a Grant Request (RFC 9635 §2.4, "Identifying the
// User"): what the client instance already knows about the end user/principal it is acting
// for, PUSHED to the AS — as opposed to "subject" (§2.2), which REQUESTS information back
// FROM the AS (see doc.go's directionality correction). This is the field this bridge uses
// to carry a DelegationGrant's exported evidence: Assertions[i].Format is the candidate
// registry value, Assertions[i].Value is the DelegationAssertionPayload JSON.
type UserField struct {
	SubIDs     []SubjectIdentifier `json:"sub_ids,omitempty"`
	Assertions []Assertion         `json:"assertions,omitempty"`
}

// SubjectRequest is the "subject" object of a Grant Request (RFC 9635 §2.2, "Requesting
// Subject Information"): a REQUEST for information the AS should return about the resource
// owner — SubIDFormats/AssertionFormats name what is being asked FOR, not presented.
type SubjectRequest struct {
	SubIDFormats     []string            `json:"sub_id_formats,omitempty"`
	AssertionFormats []string            `json:"assertion_formats,omitempty"`
	SubIDs           []SubjectIdentifier `json:"sub_ids,omitempty"`
}

// InteractFinish is the "finish" object of an "interact" request (RFC 9635 §2.5): how the
// client instance wants to be notified that an interaction completed — a callback Method
// ("redirect" or "push"), the callback URI, and a client-generated Nonce the AS folds into
// its interaction-hash proof.
type InteractFinish struct {
	Method string `json:"method"`
	URI    string `json:"uri"`
	Nonce  string `json:"nonce"`
}

// InteractRequest is the "interact" object of a Grant Request (RFC 9635 §2.5): which
// interaction Start modes the client supports, and an optional Finish callback.
type InteractRequest struct {
	Start  []string        `json:"start"`
	Finish *InteractFinish `json:"finish,omitempty"`
}

// GrantRequest is the top-level Grant Request body (RFC 9635 §2): POSTed as
// application/json to the AS's grant endpoint. AccessToken is modeled as the common
// single-token object form (§2.1); a multi-token array request is out of this bridge's
// scope (an N-AALP agent requests one token per delegated action class).
type GrantRequest struct {
	AccessToken AccessTokenRequest `json:"access_token"`
	Client      ClientField        `json:"client"`
	User        *UserField         `json:"user,omitempty"`
	Subject     *SubjectRequest    `json:"subject,omitempty"`
	Interact    *InteractRequest   `json:"interact,omitempty"`
}

// EncodeGrantRequest validates and JSON-encodes a Grant Request, fail-closed: a request
// naming no access_token.access entries, or whose client.key.proof is not exactly
// "httpsig" (the only proofing method this package implements), is rejected before any
// bytes are produced — this bridge never emits a request claiming a proofing method it
// cannot itself back.
func EncodeGrantRequest(r GrantRequest) ([]byte, error) {
	if len(r.AccessToken.Access) == 0 {
		return nil, ErrMalformedRequest
	}
	if r.Client.Key.Proof != "httpsig" {
		return nil, ErrMalformedRequest
	}
	return json.Marshal(r)
}

// ---- RFC 9635 §3 — the Grant Response ---------------------------------------------------

// ContinueAccessToken is the "access_token" object inside a "continue" response field (RFC
// 9635 §3.1): the bearer value the client presents (as an Authorization header, per §5) on
// the continuation request.
type ContinueAccessToken struct {
	Value string `json:"value"`
}

// Continue is the "continue" field of a Grant Response (RFC 9635 §3.1): where and how the
// client instance may resume the grant request — a continuation access token, the URI to
// POST to, and an optional Wait (seconds) hint before the first poll.
type Continue struct {
	AccessToken ContinueAccessToken `json:"access_token"`
	URI         string              `json:"uri"`
	Wait        int                 `json:"wait,omitempty"`
}

// TokenManage is the "manage" object of an issued access token (RFC 9635 §3.2.1): the URI
// the client instance uses to rotate or revoke the token.
type TokenManage struct {
	URI string `json:"uri"`
}

// AccessTokenResponse is the "access_token" object of a Grant Response (RFC 9635 §3.2): the
// issued token Value, the granted Access (may be narrower than requested), and optional
// Manage/Label/ExpiresIn/Flags/Key (a bound-token proofing key, §3.2.1) fields.
type AccessTokenResponse struct {
	Value     string             `json:"value"`
	Access    []AccessDescriptor `json:"access,omitempty"`
	Manage    *TokenManage       `json:"manage,omitempty"`
	Label     string             `json:"label,omitempty"`
	ExpiresIn int                `json:"expires_in,omitempty"`
	Flags     []string           `json:"flags,omitempty"`
	Key       *Key               `json:"key,omitempty"`
}

// InteractResponse is the "interact" field of a Grant Response (RFC 9635 §3.3): how the AS
// wants the end user to interact — a redirect URI, an in-app reference, and/or a Finish
// hash method the AS will use to prove the interaction completed.
type InteractResponse struct {
	Redirect string `json:"redirect,omitempty"`
	App      string `json:"app,omitempty"`
	Finish   string `json:"finish,omitempty"`
}

// SubjectResponse is the "subject" field of a Grant Response (RFC 9635 §3.4, "Returning
// Subject Information"): the AS's answer to the request's SubjectRequest — SubIDs and
// Assertions carry the actual identifiers/assertions the AS chose to release, and
// UpdatedAt (RFC 3339) says when that information was last current.
type SubjectResponse struct {
	SubIDs     []SubjectIdentifier `json:"sub_ids,omitempty"`
	Assertions []Assertion         `json:"assertions,omitempty"`
	UpdatedAt  string              `json:"updated_at,omitempty"`
}

// GNAPError is the "error" field of a Grant Response (RFC 9635 §3.6).
type GNAPError struct {
	Code        string `json:"code"`
	Description string `json:"description,omitempty"`
}

// GrantResponse is the top-level Grant Response body (RFC 9635 §3).
type GrantResponse struct {
	Continue    *Continue            `json:"continue,omitempty"`
	AccessToken *AccessTokenResponse `json:"access_token,omitempty"`
	Interact    *InteractResponse    `json:"interact,omitempty"`
	Subject     *SubjectResponse     `json:"subject,omitempty"`
	InstanceID  string               `json:"instance_id,omitempty"`
	Error       *GNAPError           `json:"error,omitempty"`
}

// ---- RFC 9635 §5 — Continuing a Grant Request -------------------------------------------

// ContinuationRequest is the body POSTed to Continue.URI (RFC 9635 §5): InteractRef is
// present when resuming after a completed interaction (§5.1); an empty ContinuationRequest
// is a bare poll.
type ContinuationRequest struct {
	InteractRef string `json:"interact_ref,omitempty"`
}
