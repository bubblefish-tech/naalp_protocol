// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;

namespace Naalp
{
    /// <summary>
    /// C11 — the four transport bindings for the C# SDK (design.md §12; requirements
    /// R-13.1..13.4), ported from impl/go/transport.
    ///
    /// <para>A binding carries exactly one signed object as one message unit, with identical object
    /// semantics across N-PAMP, QUIC, WebSocket, and HTTP (R-13.1). The object is self-secured by
    /// C2..C8; the binding adds only framing plus, from the transport, confidentiality and connection
    /// authentication (R-13.2, R-13.3). The media type is <c>application/vnd.bubblefish.naalp+cbor</c>. The
    /// confidentiality boundary is normative: an object marked sensitive MUST NOT be emitted in
    /// cleartext over a non-confidential transport — the binding refuses it
    /// (ConfidentialTransportRequired) and directs the deployment to a confidential transport
    /// (R-13.4). A transport lacking peer authentication where policy requires it is
    /// PeerUnauthenticated (§12.4). Every refusal is fail-closed: it returns a named error and emits
    /// nothing partial.</para>
    /// </summary>
    public static class Transport
    {
        /// <summary>The one-object-per-representation N-AALP media type (§12.1).</summary>
        public const string MediaType = "application/vnd.bubblefish.naalp+cbor";

        /// <summary>
        /// One transport binding and the two conditional guarantees it provides: confidentiality
        /// (TLS / PQ AEAD) and connection-level peer authentication (§12.3). Object-level guarantees
        /// (integrity, identity, non-repudiation, effect, audit) are always present regardless.
        /// </summary>
        public sealed class Binding
        {
            public readonly string Name;
            public readonly bool Confidential;
            public readonly bool PeerAuthenticated;

            public Binding(string name, bool confidential, bool peerAuthenticated)
            {
                Name = name;
                Confidential = confidential;
                PeerAuthenticated = peerAuthenticated;
            }
        }

        // The four binding types (§12.2). WebSocket and HTTP have a confidential (wss/https) and a
        // cleartext (ws/http) variant; confidentiality is what the §12.3 boundary turns on.
        public static readonly Binding NPAMP = new Binding("npamp", true, true);
        public static readonly Binding QUIC = new Binding("quic", true, true);
        public static readonly Binding WebSocketWSS = new Binding("websocket+wss", true, false);
        public static readonly Binding WebSocketWS = new Binding("websocket+ws", false, false);
        public static readonly Binding HTTPS = new Binding("https", true, false);
        public static readonly Binding HTTP = new Binding("http", false, false);

        /// <summary>Every transport variant (for tools/tests).</summary>
        public static readonly Binding[] All = { NPAMP, QUIC, WebSocketWSS, WebSocketWS, HTTPS, HTTP };

        /// <summary>Returns the transport variant with the given name, or null if unknown.</summary>
        public static Binding? ByName(string name)
        {
            foreach (Binding b in All)
            {
                if (b.Name == name)
                {
                    return b;
                }
            }
            return null;
        }

        /// <summary>
        /// One signed object framed for a transport: one object per unit (§12.1). The payload is the
        /// object bytes verbatim — the binding transforms nothing (R-13.2).
        /// </summary>
        public sealed class MessageUnit
        {
            public readonly string TransportName;
            public readonly string MediaType;
            public readonly byte[] Payload;

            public MessageUnit(string transportName, string mediaType, byte[] payload)
            {
                TransportName = transportName;
                MediaType = mediaType;
                Payload = payload;
            }

            /// <summary>Recovers the object bytes from a message unit, rejecting a wrong media type.</summary>
            public byte[] Object()
            {
                if (MediaType != Transport.MediaType)
                {
                    throw new NaalpException("Malformed", "message unit is not application/vnd.bubblefish.naalp+cbor");
                }
                return Payload;
            }
        }

        /// <summary>Carries one signed object as one message unit, adding only framing.</summary>
        public static MessageUnit Frame(Binding t, byte[] obj)
        {
            byte[] copy = (byte[])obj.Clone();
            return new MessageUnit(t.Name, MediaType, copy);
        }

        /// <summary>
        /// Applies the confidentiality boundary (§12.3) and the peer-auth rule (§12.4) before framing:
        /// a sensitive object over a non-confidential transport is refused
        /// (ConfidentialTransportRequired); a transport lacking peer authentication where policy
        /// requires it is refused (PeerUnauthenticated). Otherwise the object is framed unchanged. No
        /// partial state; refusals throw a named error and emit nothing.
        /// </summary>
        public static MessageUnit Emit(Binding t, byte[] obj, bool sensitive, bool requirePeerAuth)
        {
            if (sensitive && !t.Confidential)
            {
                throw new NaalpException(
                    "ConfidentialTransportRequired",
                    "a sensitive object may not be emitted in cleartext over a non-confidential transport");
            }
            if (requirePeerAuth && !t.PeerAuthenticated)
            {
                throw new NaalpException(
                    "PeerUnauthenticated",
                    "transport peer is not authenticated where policy requires it");
            }
            return Frame(t, obj);
        }
    }
}
