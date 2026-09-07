// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * N-AALP C11 transport bindings for the Kotlin SDK (design.md §12; R-13.1..13.4).
 *
 * A binding carries exactly one signed object as one message unit, with identical object semantics
 * across N-PAMP, QUIC, WebSocket and HTTP (R-13.1). The object is self-secured by C2..C8; the binding
 * adds only framing plus, from the transport, confidentiality and connection authentication (R-13.2,
 * R-13.3). The media type is application/vnd.bubblefish.naalp+cbor. The confidentiality boundary is normative: a
 * sensitive object MUST NOT be emitted in cleartext over a non-confidential transport — the binding
 * refuses it (ConfidentialTransportRequired, §12.3). A transport lacking peer authentication where
 * policy requires it is PeerUnauthenticated (§12.4). Fail-closed: a refusal throws a named
 * [NaalpException] and frames nothing. An independent transcription of impl/go/transport, graded
 * against the shared vectors/transport/cases.json.
 */
class Transport(
    /** The binding name. */
    val name: String,
    /** Whether the transport provides confidentiality (TLS / PQ AEAD) — the §12.3 boundary. */
    val confidential: Boolean,
    /** Whether the transport provides connection-level peer authentication (§12.4). */
    val peerAuthenticated: Boolean,
) {

    /**
     * One signed object framed for a transport: one object per unit (§12.1). The payload is the object
     * bytes verbatim — the binding transforms nothing (R-13.2).
     */
    class MessageUnit(val transport: String, val mediaType: String, payload: ByteArray) {
        val payload: ByteArray = payload.copyOf()

        /** Recover the object bytes, rejecting a wrong media type (Malformed). */
        fun objectBytes(): ByteArray {
            if (mediaType != MEDIA_TYPE) {
                throw NaalpException("Malformed", "message unit is not $MEDIA_TYPE")
            }
            return payload
        }
    }

    companion object {
        /** The one-object-per-representation N-AALP media type (§12.1). */
        const val MEDIA_TYPE = "application/vnd.bubblefish.naalp+cbor"

        // The four binding types (§12.2). WebSocket and HTTP have confidential (wss/https) and cleartext
        // (ws/http) variants; confidentiality is what the §12.3 boundary turns on. Object-level
        // guarantees (integrity, identity, non-repudiation, effect, audit) are always present regardless.
        val NPAMP = Transport("npamp", true, true)
        val QUIC = Transport("quic", true, true)
        val WEBSOCKET_WSS = Transport("websocket+wss", true, false)
        val WEBSOCKET_WS = Transport("websocket+ws", false, false)
        val HTTPS = Transport("https", true, false)
        val HTTP = Transport("http", false, false)

        /** Every transport variant (for tools/tests). */
        val ALL: List<Transport> = listOf(NPAMP, QUIC, WEBSOCKET_WSS, WEBSOCKET_WS, HTTPS, HTTP)

        /** The transport variant with this name, or null if none. */
        fun byName(name: String): Transport? = ALL.firstOrNull { it.name == name }

        /** Carry one signed object as one message unit, adding only framing. */
        fun frame(t: Transport, obj: ByteArray): MessageUnit = MessageUnit(t.name, MEDIA_TYPE, obj)

        /**
         * Apply the §12.3 confidentiality boundary and the §12.4 peer-auth rule before framing: a
         * sensitive object over a non-confidential transport is refused first
         * (ConfidentialTransportRequired); a transport lacking peer authentication where policy requires
         * it is refused (PeerUnauthenticated). Otherwise the object is framed unchanged. No partial
         * state; a refusal throws a named error and emits nothing.
         */
        fun emit(t: Transport, obj: ByteArray, sensitive: Boolean, requirePeerAuth: Boolean): MessageUnit {
            if (sensitive && !t.confidential) {
                throw NaalpException(
                    "ConfidentialTransportRequired",
                    "a sensitive object may not be emitted in cleartext over a non-confidential transport"
                )
            }
            if (requirePeerAuth && !t.peerAuthenticated) {
                throw NaalpException(
                    "PeerUnauthenticated",
                    "transport peer is not authenticated where policy requires it"
                )
            }
            return frame(t, obj)
        }
    }
}
