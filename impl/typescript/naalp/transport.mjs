// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C11 transport bindings for the TypeScript SDK (design.md §12; R-13.1..13.4).
//
// A binding carries exactly one signed object as one message unit, with identical object semantics
// across N-PAMP, QUIC, WebSocket and HTTP (R-13.1). The object is self-secured by C2..C8; the
// binding adds only framing plus, from the transport, confidentiality and connection authentication
// (R-13.2, R-13.3). The media type is application/vnd.bubblefish.naalp+cbor. The confidentiality boundary is
// normative: a sensitive object MUST NOT be emitted in cleartext over a non-confidential transport
// -- the binding refuses it (ConfidentialTransportRequired, §12.3). A transport lacking peer
// authentication where policy requires it is PeerUnauthenticated (§12.4). Fail-closed: a refusal
// returns a named error and frames nothing. An independent transcription of the design, graded
// against the shared vectors/transport/cases.json.

// The one-object-per-representation N-AALP media type (§12.1).
export const MEDIA_TYPE = 'application/vnd.bubblefish.naalp+cbor';

// A named, fail-closed transport failure (§12.4); .kind is a stable string mirroring the
// Go/Rust/Python/Ruby error kinds.
export class TransportError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// One binding and its two conditional guarantees: confidentiality (TLS / PQ AEAD) and
// connection-level peer authentication (§12.3). Object-level guarantees are always present.
export class Transport {
  constructor(name, confidential, peerAuthenticated) {
    this.name = name;
    this.confidential = confidential;
    this.peerAuthenticated = peerAuthenticated;
    Object.freeze(this);
  }
}

// The four binding types (§12.2). WebSocket and HTTP have confidential (wss/https) and cleartext
// (ws/http) variants; confidentiality is what the §12.3 boundary turns on.
export const NPAMP = new Transport('npamp', true, true);
export const QUIC = new Transport('quic', true, true);
export const WEBSOCKET_WSS = new Transport('websocket+wss', true, false);
export const WEBSOCKET_WS = new Transport('websocket+ws', false, false);
export const HTTPS = new Transport('https', true, false);
export const HTTP = new Transport('http', false, false);

// Every transport variant (for tools/tests).
export const ALL = [NPAMP, QUIC, WEBSOCKET_WSS, WEBSOCKET_WS, HTTPS, HTTP];

// Return [transport, true] for the variant with this name, else [null, false].
export function byName(name) {
  for (const t of ALL) {
    if (t.name === name) return [t, true];
  }
  return [null, false];
}

// One signed object framed for a transport: one object per unit (§12.1). The payload is the object
// bytes verbatim -- the binding transforms nothing (R-13.2).
export class MessageUnit {
  constructor(transport, mediaType, payload) {
    this.transport = transport;
    this.mediaType = mediaType;
    this.payload = Uint8Array.from(payload);
  }

  // Recover the object bytes, rejecting a wrong media type (Malformed).
  object() {
    if (this.mediaType !== MEDIA_TYPE) {
      throw new TransportError('Malformed', 'message unit is not application/vnd.bubblefish.naalp+cbor');
    }
    return this.payload;
  }
}

// Carry one signed object as one message unit, adding only framing.
export function frame(t, obj) {
  return new MessageUnit(t.name, MEDIA_TYPE, obj);
}

// Apply the §12.3 confidentiality boundary and the §12.4 peer-auth rule before framing: a sensitive
// object over a non-confidential transport is refused first (ConfidentialTransportRequired); a
// transport lacking peer authentication where policy requires it is refused (PeerUnauthenticated).
// Otherwise the object is framed unchanged.
export function emit(t, obj, sensitive, requirePeerAuth) {
  if (sensitive && !t.confidential) {
    throw new TransportError(
      'ConfidentialTransportRequired',
      'a sensitive object may not be emitted in cleartext over a non-confidential transport',
    );
  }
  if (requirePeerAuth && !t.peerAuthenticated) {
    throw new TransportError(
      'PeerUnauthenticated', 'transport peer is not authenticated where policy requires it',
    );
  }
  return frame(t, obj);
}
