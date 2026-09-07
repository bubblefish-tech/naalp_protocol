// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C11 transport bindings for the Swift SDK (design.md §12; R-13.1..13.4).
//
// A binding carries exactly one signed object as one message unit, with identical object
// semantics across N-PAMP, QUIC, WebSocket and HTTP (R-13.1). The object is self-secured by
// C2..C8; the binding adds only framing plus, from the transport, confidentiality and connection
// authentication (R-13.2, R-13.3). The media type is application/vnd.bubblefish.naalp+cbor. The confidentiality
// boundary is normative: a sensitive object MUST NOT be emitted in cleartext over a
// non-confidential transport — the binding refuses it (ConfidentialTransportRequired, §12.3). A
// transport lacking peer authentication where policy requires it is PeerUnauthenticated (§12.4).
// Fail-closed: a refusal returns a named error and frames nothing.
//
// An independent transcription of impl/go/transport, graded against the shared
// vectors/transport/cases.json (== Go == Rust == Python == Ruby == PHP == oracle). Pure logic
// only, so the whole surface is corpus-graded on the pure Swift port. Failures use the module-wide
// NaalpError whose `kind` mirrors the Go/Rust error kinds (ConfidentialTransportRequired,
// PeerUnauthenticated, Malformed).

import Foundation

/// One binding and its two conditional guarantees: confidentiality (TLS / PQ AEAD) and
/// connection-level peer authentication (§12.3). Object-level guarantees (integrity, identity,
/// non-repudiation, effect, audit) are always present regardless. The type also carries the media
/// type constant and the static binding registry + framing/emit operations.
public struct Transport {

    /// The one-object-per-representation N-AALP media type (§12.1).
    public static let MEDIA_TYPE = "application/vnd.bubblefish.naalp+cbor"

    public let name: String
    public let confidential: Bool
    public let peerAuthenticated: Bool

    public init(name: String, confidential: Bool, peerAuthenticated: Bool) {
        self.name = name
        self.confidential = confidential
        self.peerAuthenticated = peerAuthenticated
    }

    /// Every transport variant (§12.2). WebSocket and HTTP have a confidential (wss/https) and a
    /// cleartext (ws/http) variant; confidentiality is what the §12.3 boundary turns on.
    public static let all: [Transport] = [
        Transport(name: "npamp", confidential: true, peerAuthenticated: true),
        Transport(name: "quic", confidential: true, peerAuthenticated: true),
        Transport(name: "websocket+wss", confidential: true, peerAuthenticated: false),
        Transport(name: "websocket+ws", confidential: false, peerAuthenticated: false),
        Transport(name: "https", confidential: true, peerAuthenticated: false),
        Transport(name: "http", confidential: false, peerAuthenticated: false),
    ]

    /// Return the transport variant with this name, or nil if there is no such binding.
    public static func byName(_ name: String) -> Transport? {
        return all.first { $0.name == name }
    }

    /// Carry one signed object as one message unit, adding only framing (R-13.2).
    public static func frame(_ t: Transport, _ obj: [UInt8]) -> MessageUnit {
        return MessageUnit(transport: t.name, mediaType: MEDIA_TYPE, payload: obj)
    }

    /// Apply the §12.3 confidentiality boundary and the §12.4 peer-auth rule before framing: a
    /// sensitive object over a non-confidential transport is refused first
    /// (ConfidentialTransportRequired); a transport lacking peer authentication where policy
    /// requires it is refused (PeerUnauthenticated). Otherwise the object is framed unchanged. No
    /// partial state: a refusal throws a named error and emits nothing.
    public static func emit(_ t: Transport, _ obj: [UInt8], _ sensitive: Bool,
                            _ requirePeerAuth: Bool) throws -> MessageUnit {
        if sensitive && !t.confidential {
            throw NaalpError("ConfidentialTransportRequired",
                             "a sensitive object may not be emitted in cleartext over a non-confidential transport")
        }
        if requirePeerAuth && !t.peerAuthenticated {
            throw NaalpError("PeerUnauthenticated",
                             "transport peer is not authenticated where policy requires it")
        }
        return frame(t, obj)
    }

    /// One signed object framed for a transport: one object per unit (§12.1). The payload is the
    /// object bytes verbatim — the binding transforms nothing (R-13.2).
    public struct MessageUnit {
        public let transport: String
        public let mediaType: String
        public let payload: [UInt8]

        public init(transport: String, mediaType: String, payload: [UInt8]) {
            self.transport = transport
            self.mediaType = mediaType
            self.payload = payload
        }

        /// Recover the object bytes, rejecting a wrong media type (Malformed).
        public func object() throws -> [UInt8] {
            if mediaType != Transport.MEDIA_TYPE {
                throw NaalpError("Malformed", "message unit is not \(Transport.MEDIA_TYPE)")
            }
            return payload
        }
    }
}
