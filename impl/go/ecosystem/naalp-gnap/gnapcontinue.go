// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpgnap

import "encoding/json"

// ParseGrantResponse decodes a Grant Response body (RFC 9635 §3), fail-closed: malformed
// JSON, or a response naming neither an issued access_token nor a way to continue, is
// ErrMalformedResponse (a response with neither is not actionable — the client has
// nothing to hold or poll). An AS-reported error object (§3.6) is surfaced as a distinct
// non-nil error (never silently dropped), alongside the parsed response so a caller can
// still inspect what the AS sent.
func ParseGrantResponse(body []byte) (*GrantResponse, error) {
	var r GrantResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, ErrMalformedResponse
	}
	if r.Error != nil {
		return &r, &Error{Kind: "GrantDenied", Msg: r.Error.Code + ": " + r.Error.Description}
	}
	if r.AccessToken == nil && r.Continue == nil {
		return nil, ErrMalformedResponse
	}
	return &r, nil
}

// Poller drives the RFC 9635 §5 continuation flow: repeated POSTs to Continue.URI, each
// authenticated with the continuation access token (as an Authorization header, per §5),
// until the AS issues the final access_token.
type Poller struct {
	Continue Continue
}

// NewPoller validates a Grant Response's `continue` object is complete enough to drive the
// flow (a non-empty URI and a non-empty continuation access token value), fail-closed.
func NewPoller(c Continue) (*Poller, error) {
	if c.URI == "" || c.AccessToken.Value == "" {
		return nil, ErrContinuationMissing
	}
	return &Poller{Continue: c}, nil
}

// NextRequest builds the next continuation POST (RFC 9635 §5): the target URI, the
// Authorization header value carrying the continuation bearer token ("GNAP <token>", the
// scheme §7.2 defines), and the JSON body — InteractRef non-empty when resuming after a
// completed interaction (§5.1), empty for a bare poll.
func (p *Poller) NextRequest(interactRef string) (uri, authorization string, body []byte, err error) {
	body, err = json.Marshal(ContinuationRequest{InteractRef: interactRef})
	if err != nil {
		return "", "", nil, err
	}
	return p.Continue.URI, "GNAP " + p.Continue.AccessToken.Value, body, nil
}

// Advance updates the poller's continuation state from a fresh Grant Response received
// during polling (RFC 9635 §5: each continuation response MAY carry a new `continue`
// object superseding the previous one). A response carrying neither a new continuation nor
// a final access_token is ErrContinuationMissing (the flow can neither proceed nor
// terminate, fail-closed).
func (p *Poller) Advance(resp *GrantResponse) error {
	if resp.AccessToken != nil {
		return nil // terminal: the AS issued the final token — nothing left to continue.
	}
	if resp.Continue == nil || resp.Continue.URI == "" || resp.Continue.AccessToken.Value == "" {
		return ErrContinuationMissing
	}
	p.Continue = *resp.Continue
	return nil
}
