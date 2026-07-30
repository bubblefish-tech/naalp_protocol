// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package transport implements C11 — the four transport bindings (design.md §12; requirements
// R-13.1..13.4).
//
// A binding carries exactly one signed object as one message unit, with identical object
// semantics across N-PAMP, QUIC, WebSocket, and HTTP (R-13.1). The object is self-secured by
// C2..C8; the binding adds only framing plus, from the transport, confidentiality and
// connection authentication (R-13.2, R-13.3). The media type is application/naalp+cbor. The
// confidentiality boundary is normative: an object marked sensitive MUST NOT be emitted in
// cleartext over a non-confidential transport — the binding refuses it
// (ConfidentialTransportRequired) and directs the deployment to a confidential transport
// (R-13.4). A transport lacking peer authentication where policy requires it is
// PeerUnauthenticated (§12.4).
package transport

import "github.com/bubblefish-tech/naalp_protocol/impl/go/cose"

// MediaType is the one-object-per-representation N-AALP media type (§12.1).
const MediaType = "application/naalp+cbor"

// Errors reuse the cose.Error type so every N-AALP error carries a stable Kind (§12.4).
var (
	ErrConfidentialTransportRequired = &cose.Error{Kind: "ConfidentialTransportRequired", Msg: "a sensitive object may not be emitted in cleartext over a non-confidential transport"}
	ErrPeerUnauthenticated           = &cose.Error{Kind: "PeerUnauthenticated", Msg: "transport peer is not authenticated where policy requires it"}
	ErrMalformed                     = &cose.Error{Kind: "Malformed", Msg: "message unit is not application/naalp+cbor"}
)

// Transport names one binding and the two conditional guarantees it provides: confidentiality
// (TLS / PQ AEAD) and connection-level peer authentication (§12.3). Object-level guarantees
// (integrity, identity, non-repudiation, effect, audit) are always present regardless.
type Transport struct {
	Name              string
	Confidential      bool
	PeerAuthenticated bool
}

// The four binding types (§12.2). WebSocket and HTTP have a confidential (wss/https) and a
// cleartext (ws/http) variant; confidentiality is what the §12.3 boundary turns on.
var (
	NPAMP        = Transport{"npamp", true, true}
	QUIC         = Transport{"quic", true, true}
	WebSocketWSS = Transport{"websocket+wss", true, false}
	WebSocketWS  = Transport{"websocket+ws", false, false}
	HTTPS        = Transport{"https", true, false}
	HTTP         = Transport{"http", false, false}
)

// All lists every transport variant (for tools/tests).
var All = []Transport{NPAMP, QUIC, WebSocketWSS, WebSocketWS, HTTPS, HTTP}

// ByName returns the transport variant with the given name.
func ByName(name string) (Transport, bool) {
	for _, t := range All {
		if t.Name == name {
			return t, true
		}
	}
	return Transport{}, false
}

// MessageUnit is one signed object framed for a transport: one object per unit (§12.1). The
// payload is the object bytes verbatim — the binding transforms nothing (R-13.2).
type MessageUnit struct {
	Transport string
	MediaType string
	Payload   []byte
}

// Frame carries one signed object as one message unit, adding only framing.
func Frame(t Transport, obj []byte) MessageUnit {
	return MessageUnit{Transport: t.Name, MediaType: MediaType, Payload: append([]byte(nil), obj...)}
}

// Object recovers the object bytes from a message unit, rejecting a wrong media type.
func (m MessageUnit) Object() ([]byte, error) {
	if m.MediaType != MediaType {
		return nil, ErrMalformed
	}
	return m.Payload, nil
}

// Emit applies the confidentiality boundary (§12.3) and the peer-auth rule (§12.4) before
// framing: a sensitive object over a non-confidential transport is refused
// (ConfidentialTransportRequired); a transport lacking peer authentication where policy requires
// it is refused (PeerUnauthenticated). Otherwise the object is framed unchanged. No partial
// state; refusals return a named error and emit nothing.
func Emit(t Transport, obj []byte, sensitive, requirePeerAuth bool) (MessageUnit, error) {
	if sensitive && !t.Confidential {
		return MessageUnit{}, ErrConfidentialTransportRequired
	}
	if requirePeerAuth && !t.PeerAuthenticated {
		return MessageUnit{}, ErrPeerUnauthenticated
	}
	return Frame(t, obj), nil
}
