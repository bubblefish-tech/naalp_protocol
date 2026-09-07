// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpgnap

import (
	"encoding/json"
	"testing"
)

// TestEncodeGrantRequest_MatchesHandConstructedOracle: the expected JSON is typed by hand
// to match RFC 9635 §2.1.1's own access-descriptor example field names/shape
// (type/actions/locations/datatypes) and §2.3's client.key shape — an independent
// constructor, never derived by calling EncodeGrantRequest itself (F3/A7). Mutation: a
// field-dropping or constant-string encoder diverges from this exact byte string.
func TestEncodeGrantRequest_MatchesHandConstructedOracle(t *testing.T) {
	req := GrantRequest{
		AccessToken: AccessTokenRequest{
			Access: []AccessDescriptor{{
				Type:      "photo-api",
				Actions:   []string{"read", "write"},
				Locations: []string{"https://server.example.net/"},
				Datatypes: []string{"metadata", "images"},
			}},
		},
		Client: ClientField{
			Key: Key{Proof: "httpsig", JWK: json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"abc"}`)},
		},
	}
	want := `{"access_token":{"access":[{"type":"photo-api","actions":["read","write"],"locations":["https://server.example.net/"],"datatypes":["metadata","images"]}]},"client":{"key":{"proof":"httpsig","jwk":{"kty":"OKP","crv":"Ed25519","x":"abc"}}}}`

	got, err := EncodeGrantRequest(req)
	if err != nil {
		t.Fatalf("EncodeGrantRequest: %v", err)
	}
	if string(got) != want {
		t.Fatalf("EncodeGrantRequest =\n%s\nwant\n%s", got, want)
	}
}

func TestEncodeGrantRequest_RejectsEmptyAccess(t *testing.T) {
	req := GrantRequest{Client: ClientField{Key: Key{Proof: "httpsig"}}}
	if _, err := EncodeGrantRequest(req); err != ErrMalformedRequest {
		t.Fatalf("err = %v, want ErrMalformedRequest", err)
	}
}

func TestEncodeGrantRequest_RejectsNonHttpsigProof(t *testing.T) {
	req := GrantRequest{
		AccessToken: AccessTokenRequest{Access: []AccessDescriptor{{Type: "x"}}},
		Client:      ClientField{Key: Key{Proof: "mtls"}},
	}
	if _, err := EncodeGrantRequest(req); err != ErrMalformedRequest {
		t.Fatalf("err = %v, want ErrMalformedRequest", err)
	}
}

// TestUserField_CarriesAssertionsNotSubject_JSONShape locks in the directionality
// correction recorded in doc.go: a pushed assertion serializes under "user", never under
// "subject" — the RFC 9635 §2.2 field with the deceptively similar name is a REQUEST list
// of format strings, not a value-carrying push channel.
func TestUserField_CarriesAssertionsNotSubject_JSONShape(t *testing.T) {
	req := GrantRequest{
		AccessToken: AccessTokenRequest{Access: []AccessDescriptor{{Type: "naalp-effect"}}},
		Client:      ClientField{Key: Key{Proof: "httpsig", JWK: json.RawMessage(`{}`)}},
		User: &UserField{Assertions: []Assertion{
			{Format: AssertionFormatDelegationGrant, Value: `{"subject":"agentB"}`},
		}},
	}
	b, err := EncodeGrantRequest(req)
	if err != nil {
		t.Fatalf("EncodeGrantRequest: %v", err)
	}
	var round map[string]json.RawMessage
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if _, present := round["subject"]; present {
		t.Fatalf("assertion leaked into the top-level \"subject\" field: %s", b)
	}
	userRaw, present := round["user"]
	if !present {
		t.Fatalf("no top-level \"user\" field in %s", b)
	}
	var u UserField
	if err := json.Unmarshal(userRaw, &u); err != nil {
		t.Fatalf("decode user field: %v", err)
	}
	if len(u.Assertions) != 1 || u.Assertions[0].Format != AssertionFormatDelegationGrant {
		t.Fatalf("user.assertions = %+v, want one naalp-delegation-grant entry", u.Assertions)
	}
}

// ---- GrantResponse / ParseGrantResponse, against RFC 9635 §3-style example JSON -----------

func TestParseGrantResponse_ParsesIssuedToken(t *testing.T) {
	body := []byte(`{"access_token":{"value":"OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",` +
		`"manage":{"uri":"https://server.example.net/token/PRY5NM33O"},` +
		`"access":[{"type":"photo-api","actions":["read","write"]}],` +
		`"label":"token1","expires_in":3600,"flags":["bearer"]},` +
		`"instance_id":"7C7C4AZ9KHRS6X63AJAO"}`)

	r, err := ParseGrantResponse(body)
	if err != nil {
		t.Fatalf("ParseGrantResponse: %v", err)
	}
	if r.AccessToken == nil || r.AccessToken.Value != "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0" {
		t.Fatalf("access_token.value not parsed: %+v", r.AccessToken)
	}
	if r.AccessToken.Manage == nil || r.AccessToken.Manage.URI != "https://server.example.net/token/PRY5NM33O" {
		t.Fatalf("access_token.manage.uri not parsed: %+v", r.AccessToken.Manage)
	}
	if r.AccessToken.ExpiresIn != 3600 {
		t.Errorf("expires_in = %d, want 3600", r.AccessToken.ExpiresIn)
	}
	if r.InstanceID != "7C7C4AZ9KHRS6X63AJAO" {
		t.Errorf("instance_id = %q", r.InstanceID)
	}
}

func TestParseGrantResponse_ParsesContinue(t *testing.T) {
	body := []byte(`{"continue":{"access_token":{"value":"33OMUKMKSKU80UPRY5NM"},` +
		`"uri":"https://server.example.net/continue","wait":30}}`)
	r, err := ParseGrantResponse(body)
	if err != nil {
		t.Fatalf("ParseGrantResponse: %v", err)
	}
	if r.Continue == nil || r.Continue.URI != "https://server.example.net/continue" {
		t.Fatalf("continue.uri not parsed: %+v", r.Continue)
	}
	if r.Continue.AccessToken.Value != "33OMUKMKSKU80UPRY5NM" {
		t.Errorf("continue.access_token.value = %q", r.Continue.AccessToken.Value)
	}
	if r.Continue.Wait != 30 {
		t.Errorf("continue.wait = %d, want 30", r.Continue.Wait)
	}
}

func TestParseGrantResponse_RejectsErrorField(t *testing.T) {
	body := []byte(`{"error":{"code":"invalid_request","description":"missing client key"}}`)
	r, err := ParseGrantResponse(body)
	if err == nil {
		t.Fatal("ParseGrantResponse(error response) = nil error, want a GrantDenied error")
	}
	gErr, ok := err.(*Error)
	if !ok || gErr.Kind != "GrantDenied" {
		t.Fatalf("err = %v, want *Error{Kind:\"GrantDenied\"}", err)
	}
	if r == nil || r.Error == nil || r.Error.Code != "invalid_request" {
		t.Fatalf("parsed response's error.code not preserved: %+v", r)
	}
}

func TestParseGrantResponse_RejectsMalformedJSON(t *testing.T) {
	if _, err := ParseGrantResponse([]byte("{not json")); err != ErrMalformedResponse {
		t.Fatalf("err = %v, want ErrMalformedResponse", err)
	}
}

func TestParseGrantResponse_RejectsNeitherTokenNorContinue(t *testing.T) {
	if _, err := ParseGrantResponse([]byte(`{"instance_id":"x"}`)); err != ErrMalformedResponse {
		t.Fatalf("err = %v, want ErrMalformedResponse", err)
	}
}
