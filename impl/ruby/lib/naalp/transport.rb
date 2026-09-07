# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C11 transport bindings for the Ruby SDK (design.md §12; R-13.1..13.4).
#
# A binding carries exactly one signed object as one message unit, with identical object
# semantics across N-PAMP, QUIC, WebSocket and HTTP (R-13.1). The object is self-secured by
# C2..C8; the binding adds only framing plus, from the transport, confidentiality and
# connection authentication (R-13.2, R-13.3). The media type is application/vnd.bubblefish.naalp+cbor. The
# confidentiality boundary is normative: a sensitive object MUST NOT be emitted in cleartext
# over a non-confidential transport -- the binding refuses it (ConfidentialTransportRequired,
# §12.3). A transport lacking peer authentication where policy requires it is PeerUnauthenticated
# (§12.4). Fail-closed: a refusal returns a named error and frames nothing. An independent
# transcription of the design, graded against the shared vectors/transport/cases.json.

module Naalp
  module Transport
    # The one-object-per-representation N-AALP media type (§12.1).
    MEDIA_TYPE = "application/vnd.bubblefish.naalp+cbor".freeze

    # A named, fail-closed transport failure (§12.4); #kind is a stable string mirroring the
    # Go/Rust/Python error kinds.
    class TransportError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        @kind = kind
        super(msg.empty? ? kind : "#{kind}: #{msg}")
      end
    end

    # One binding and its two conditional guarantees: confidentiality (TLS / PQ AEAD) and
    # connection-level peer authentication (§12.3). Object-level guarantees are always present.
    Transport = Struct.new(:name, :confidential, :peer_authenticated)

    # The four binding types (§12.2). WebSocket and HTTP have confidential (wss/https) and
    # cleartext (ws/http) variants; confidentiality is what the §12.3 boundary turns on.
    NPAMP         = Transport.new("npamp", true, true).freeze
    QUIC          = Transport.new("quic", true, true).freeze
    WEBSOCKET_WSS = Transport.new("websocket+wss", true, false).freeze
    WEBSOCKET_WS  = Transport.new("websocket+ws", false, false).freeze
    HTTPS         = Transport.new("https", true, false).freeze
    HTTP          = Transport.new("http", false, false).freeze

    # Every transport variant (for tools/tests).
    ALL = [NPAMP, QUIC, WEBSOCKET_WSS, WEBSOCKET_WS, HTTPS, HTTP].freeze

    # One signed object framed for a transport: one object per unit (§12.1). The payload is the
    # object bytes verbatim -- the binding transforms nothing (R-13.2).
    class MessageUnit
      attr_reader :transport, :media_type, :payload
      def initialize(transport, media_type, payload)
        @transport = transport
        @media_type = media_type
        @payload = payload.dup.force_encoding(Encoding::BINARY)
      end

      # Recover the object bytes, rejecting a wrong media type (Malformed).
      def object
        unless @media_type == MEDIA_TYPE
          raise TransportError.new("Malformed", "message unit is not #{MEDIA_TYPE}")
        end
        @payload
      end
    end

    module_function

    # Return [transport, true] for the variant with this name, else [nil, false].
    def by_name(name)
      t = ALL.find { |x| x.name == name }
      t.nil? ? [nil, false] : [t, true]
    end

    # Carry one signed object as one message unit, adding only framing.
    def frame(t, obj)
      MessageUnit.new(t.name, MEDIA_TYPE, obj)
    end

    # Apply the §12.3 confidentiality boundary and the §12.4 peer-auth rule before framing: a
    # sensitive object over a non-confidential transport is refused first
    # (ConfidentialTransportRequired); a transport lacking peer authentication where policy
    # requires it is refused (PeerUnauthenticated). Otherwise the object is framed unchanged.
    def emit(t, obj, sensitive, require_peer_auth)
      if sensitive && !t.confidential
        raise TransportError.new(
          "ConfidentialTransportRequired",
          "a sensitive object may not be emitted in cleartext over a non-confidential transport"
        )
      end
      if require_peer_auth && !t.peer_authenticated
        raise TransportError.new(
          "PeerUnauthenticated", "transport peer is not authenticated where policy requires it"
        )
      end
      frame(t, obj)
    end
  end
end
