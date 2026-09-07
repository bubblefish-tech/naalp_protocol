// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpgnap

import (
	"encoding/json"
	"testing"
)

// ---- NewPoller / NextRequest -----------------------------------------------------------------

func TestNewPoller_AcceptsCompleteContinue(t *testing.T) {
	c := Continue{AccessToken: ContinueAccessToken{Value: "33OMUKMKSKU80UPRY5NM"}, URI: "https://server.example.net/continue"}
	p, err := NewPoller(c)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	if p.Continue.URI != c.URI {
		t.Errorf("Continue.URI = %q", p.Continue.URI)
	}
}

func TestNewPoller_RejectsMissingURI(t *testing.T) {
	c := Continue{AccessToken: ContinueAccessToken{Value: "tok"}}
	if _, err := NewPoller(c); err != ErrContinuationMissing {
		t.Fatalf("err = %v, want ErrContinuationMissing", err)
	}
}

func TestNewPoller_RejectsMissingAccessTokenValue(t *testing.T) {
	c := Continue{URI: "https://server.example.net/continue"}
	if _, err := NewPoller(c); err != ErrContinuationMissing {
		t.Fatalf("err = %v, want ErrContinuationMissing", err)
	}
}

func TestNextRequest_ProducesGNAPAuthorizationHeaderAndBody(t *testing.T) {
	p, err := NewPoller(Continue{
		AccessToken: ContinueAccessToken{Value: "33OMUKMKSKU80UPRY5NM"},
		URI:         "https://server.example.net/continue",
	})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	uri, auth, body, err := p.NextRequest("4IFWWIKYBC2PQ6U56NL1")
	if err != nil {
		t.Fatalf("NextRequest: %v", err)
	}
	if uri != "https://server.example.net/continue" {
		t.Errorf("uri = %q", uri)
	}
	wantAuth := "GNAP 33OMUKMKSKU80UPRY5NM"
	if auth != wantAuth {
		t.Errorf("authorization = %q, want %q", auth, wantAuth)
	}
	var req ContinuationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if req.InteractRef != "4IFWWIKYBC2PQ6U56NL1" {
		t.Errorf("interact_ref = %q", req.InteractRef)
	}
}

func TestNextRequest_EmptyInteractRefOmitsFieldFromBody(t *testing.T) {
	p, err := NewPoller(Continue{AccessToken: ContinueAccessToken{Value: "tok"}, URI: "https://server.example.net/continue"})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	_, _, body, err := p.NextRequest("")
	if err != nil {
		t.Fatalf("NextRequest: %v", err)
	}
	want := `{}`
	if string(body) != want {
		t.Fatalf("body = %s, want %s (interact_ref omitted on a bare poll)", body, want)
	}
}

// ---- Advance ------------------------------------------------------------------------------

func TestAdvance_TerminatesOnAccessToken(t *testing.T) {
	p, err := NewPoller(Continue{AccessToken: ContinueAccessToken{Value: "tok"}, URI: "https://server.example.net/continue"})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	resp := &GrantResponse{AccessToken: &AccessTokenResponse{Value: "final-token"}}
	if err := p.Advance(resp); err != nil {
		t.Fatalf("Advance(final token): %v", err)
	}
}

func TestAdvance_UpdatesContinueOnFreshOne(t *testing.T) {
	p, err := NewPoller(Continue{AccessToken: ContinueAccessToken{Value: "tok1"}, URI: "https://server.example.net/continue"})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	fresh := Continue{AccessToken: ContinueAccessToken{Value: "tok2"}, URI: "https://server.example.net/continue2", Wait: 5}
	resp := &GrantResponse{Continue: &fresh}
	if err := p.Advance(resp); err != nil {
		t.Fatalf("Advance(fresh continue): %v", err)
	}
	if p.Continue.AccessToken.Value != "tok2" || p.Continue.URI != "https://server.example.net/continue2" {
		t.Fatalf("Continue not updated: %+v", p.Continue)
	}
}

func TestAdvance_RejectsResponseWithNeitherTokenNorContinue(t *testing.T) {
	p, err := NewPoller(Continue{AccessToken: ContinueAccessToken{Value: "tok"}, URI: "https://server.example.net/continue"})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	resp := &GrantResponse{Interact: &InteractResponse{Redirect: "https://as.example.net/i"}}
	if err := p.Advance(resp); err != ErrContinuationMissing {
		t.Fatalf("err = %v, want ErrContinuationMissing", err)
	}
}

// ---- ParseGrantResponse -> Poller, end-to-end shape ----------------------------------------

func TestParseGrantResponse_ThenNewPoller_EndToEnd(t *testing.T) {
	body := []byte(`{"continue":{"access_token":{"value":"33OMUKMKSKU80UPRY5NM"},"uri":"https://server.example.net/continue","wait":30}}`)
	r, err := ParseGrantResponse(body)
	if err != nil {
		t.Fatalf("ParseGrantResponse: %v", err)
	}
	p, err := NewPoller(*r.Continue)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	if p.Continue.Wait != 30 {
		t.Errorf("Wait = %d, want 30", p.Continue.Wait)
	}
}
