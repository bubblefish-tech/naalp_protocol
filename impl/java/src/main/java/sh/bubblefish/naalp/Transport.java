// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.List;

/**
 * N-AALP C11 transport bindings for the Java SDK (design.md §12; R-13.1..13.4).
 *
 * <p>A binding carries exactly one signed object as one message unit, with identical object
 * semantics across N-PAMP, QUIC, WebSocket and HTTP (R-13.1). The object is self-secured by C2..C8;
 * the binding adds only framing plus, from the transport, confidentiality and connection
 * authentication (R-13.2, R-13.3). The media type is {@code application/vnd.bubblefish.naalp+cbor}. The
 * confidentiality boundary is normative: a sensitive object MUST NOT be emitted in cleartext over a
 * non-confidential transport — the binding refuses it ({@code ConfidentialTransportRequired}, §12.3).
 * A transport lacking peer authentication where policy requires it is {@code PeerUnauthenticated}
 * (§12.4). Fail-closed: a refusal throws a named {@link NaalpException} and frames nothing. An
 * independent transcription of impl/go/transport, graded against the shared vectors/transport/cases.json.
 */
public final class Transport {
    /** The one-object-per-representation N-AALP media type (§12.1). */
    public static final String MEDIA_TYPE = "application/vnd.bubblefish.naalp+cbor";

    /** The binding name. */
    public final String name;
    /** Whether the transport provides confidentiality (TLS / PQ AEAD) — the §12.3 boundary. */
    public final boolean confidential;
    /** Whether the transport provides connection-level peer authentication (§12.4). */
    public final boolean peerAuthenticated;

    public Transport(String name, boolean confidential, boolean peerAuthenticated) {
        this.name = name;
        this.confidential = confidential;
        this.peerAuthenticated = peerAuthenticated;
    }

    // The four binding types (§12.2). WebSocket and HTTP have confidential (wss/https) and cleartext
    // (ws/http) variants; confidentiality is what the §12.3 boundary turns on. Object-level guarantees
    // (integrity, identity, non-repudiation, effect, audit) are always present regardless.
    public static final Transport NPAMP = new Transport("npamp", true, true);
    public static final Transport QUIC = new Transport("quic", true, true);
    public static final Transport WEBSOCKET_WSS = new Transport("websocket+wss", true, false);
    public static final Transport WEBSOCKET_WS = new Transport("websocket+ws", false, false);
    public static final Transport HTTPS = new Transport("https", true, false);
    public static final Transport HTTP = new Transport("http", false, false);

    /** Every transport variant (for tools/tests). */
    public static final List<Transport> ALL =
            List.of(NPAMP, QUIC, WEBSOCKET_WSS, WEBSOCKET_WS, HTTPS, HTTP);

    /** The transport variant with this name, or {@code null} if none. */
    public static Transport byName(String name) {
        for (Transport t : ALL) {
            if (t.name.equals(name)) {
                return t;
            }
        }
        return null;
    }

    /**
     * One signed object framed for a transport: one object per unit (§12.1). The payload is the object
     * bytes verbatim — the binding transforms nothing (R-13.2).
     */
    public static final class MessageUnit {
        public final String transport;
        public final String mediaType;
        public final byte[] payload;

        public MessageUnit(String transport, String mediaType, byte[] payload) {
            this.transport = transport;
            this.mediaType = mediaType;
            this.payload = payload.clone();
        }

        /** Recover the object bytes, rejecting a wrong media type (Malformed). */
        public byte[] object() {
            if (!MEDIA_TYPE.equals(mediaType)) {
                throw new NaalpException("Malformed", "message unit is not " + MEDIA_TYPE);
            }
            return payload;
        }
    }

    /** Carry one signed object as one message unit, adding only framing. */
    public static MessageUnit frame(Transport t, byte[] obj) {
        return new MessageUnit(t.name, MEDIA_TYPE, obj);
    }

    /**
     * Apply the §12.3 confidentiality boundary and the §12.4 peer-auth rule before framing: a
     * sensitive object over a non-confidential transport is refused first
     * ({@code ConfidentialTransportRequired}); a transport lacking peer authentication where policy
     * requires it is refused ({@code PeerUnauthenticated}). Otherwise the object is framed unchanged.
     * No partial state; a refusal throws a named error and emits nothing.
     */
    public static MessageUnit emit(Transport t, byte[] obj, boolean sensitive, boolean requirePeerAuth) {
        if (sensitive && !t.confidential) {
            throw new NaalpException("ConfidentialTransportRequired",
                    "a sensitive object may not be emitted in cleartext over a non-confidential transport");
        }
        if (requirePeerAuth && !t.peerAuthenticated) {
            throw new NaalpException("PeerUnauthenticated",
                    "transport peer is not authenticated where policy requires it");
        }
        return frame(t, obj);
    }
}
