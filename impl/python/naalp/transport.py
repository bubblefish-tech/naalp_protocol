# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C11 transport bindings (design.md §12; R-13.1..13.4).

A binding carries exactly one signed object as one message unit, with identical object
semantics across N-PAMP, QUIC, WebSocket and HTTP (R-13.1). The object is self-secured by
C2..C8; the binding adds only framing plus, from the transport, confidentiality and
connection authentication (R-13.2, R-13.3). The media type is application/vnd.bubblefish.naalp+cbor. The
confidentiality boundary is normative: a sensitive object MUST NOT be emitted in cleartext
over a non-confidential transport -- the binding refuses it (ConfidentialTransportRequired,
§12.3). A transport lacking peer authentication where policy requires it is
PeerUnauthenticated (§12.4). Fail-closed: a refusal returns a named error and frames nothing.

Ported from impl/go/transport; graded against the shared vectors/transport/cases.json.
"""
from dataclasses import dataclass

# The one-object-per-representation N-AALP media type (§12.1).
MEDIA_TYPE = "application/vnd.bubblefish.naalp+cbor"


class TransportError(ValueError):
    """A named, fail-closed transport error (§12.4); .kind is the stable error kind."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


@dataclass(frozen=True)
class Transport:
    """One binding and its two conditional guarantees: confidentiality (TLS / PQ AEAD) and
    connection-level peer authentication (§12.3). Object-level guarantees are always present."""

    name: str
    confidential: bool
    peer_authenticated: bool


# The four binding types (§12.2). WebSocket and HTTP have confidential (wss/https) and
# cleartext (ws/http) variants; confidentiality is what the §12.3 boundary turns on.
NPAMP = Transport("npamp", True, True)
QUIC = Transport("quic", True, True)
WEBSOCKET_WSS = Transport("websocket+wss", True, False)
WEBSOCKET_WS = Transport("websocket+ws", False, False)
HTTPS = Transport("https", True, False)
HTTP = Transport("http", False, False)

# Every transport variant (for tools/tests).
ALL = [NPAMP, QUIC, WEBSOCKET_WSS, WEBSOCKET_WS, HTTPS, HTTP]


def by_name(name):
    """Return (transport, True) for the variant with this name, else (None, False)."""
    for t in ALL:
        if t.name == name:
            return t, True
    return None, False


@dataclass(frozen=True)
class MessageUnit:
    """One signed object framed for a transport: one object per unit (§12.1). The payload is
    the object bytes verbatim -- the binding transforms nothing (R-13.2)."""

    transport: str
    media_type: str
    payload: bytes

    def object(self):
        """Recover the object bytes, rejecting a wrong media type (Malformed)."""
        if self.media_type != MEDIA_TYPE:
            raise TransportError("Malformed", "message unit is not application/vnd.bubblefish.naalp+cbor")
        return self.payload


def frame(t, obj):
    """Carry one signed object as one message unit, adding only framing."""
    return MessageUnit(t.name, MEDIA_TYPE, bytes(obj))


def emit(t, obj, sensitive, require_peer_auth):
    """Apply the §12.3 confidentiality boundary and the §12.4 peer-auth rule before framing:
    a sensitive object over a non-confidential transport is refused first
    (ConfidentialTransportRequired); a transport lacking peer authentication where policy
    requires it is refused (PeerUnauthenticated). Otherwise the object is framed unchanged."""
    if sensitive and not t.confidential:
        raise TransportError(
            "ConfidentialTransportRequired",
            "a sensitive object may not be emitted in cleartext over a non-confidential transport")
    if require_peer_auth and not t.peer_authenticated:
        raise TransportError(
            "PeerUnauthenticated", "transport peer is not authenticated where policy requires it")
    return frame(t, obj)
