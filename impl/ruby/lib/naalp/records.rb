# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP body builders for the Ruby SDK — the deterministic-CBOR bodies of the spine records:
# approval + consume ledger (C6, §7), audit receipt (C7, §8), delivery update (C8, §9), stream
# open/commit/checkpoint + rolling commitment (C9, §10), foreign carriage (C12, §13), and the
# transport confidentiality boundary (C11, §12). Each body is exactly what the Go, Rust and
# Python reference implementations encode, so the bytes are byte-identical.
require 'openssl'
require_relative 'cbor'

module Naalp
  module Records
    U = Naalp::CBOR::U
    B = Naalp::CBOR::B
    T = Naalp::CBOR::T
    M = Naalp::CBOR::M

    # --- C6 approval + consume ledger (§7) ---

    def self.approval_body(approves, approver, grant, nonce, not_after)
      Naalp::CBOR.encode(M.new([
        [U.new(1), B.new(approves)], [U.new(2), T.new(approver)], [U.new(3), U.new(grant)],
        [U.new(4), B.new(nonce)], [U.new(5), U.new(not_after)],
      ]))
    end

    def self.approval_id(approves, approver, grant, nonce, not_after)
      Naalp::CBOR.content_id(approval_body(approves, approver, grant, nonce, not_after))
    end

    def self.ledger_entry(seq, prev, approval_id_bytes, by)
      Naalp::CBOR.encode(M.new([
        [U.new(1), U.new(seq)], [U.new(2), B.new(prev)], [U.new(3), B.new(approval_id_bytes)], [U.new(4), T.new(by)],
      ]))
    end

    # --- C7 audit receipt (§8) ---

    def self.receipt_body(prev, obj, seq, at)
      Naalp::CBOR.encode(M.new([
        [U.new(1), B.new(prev)], [U.new(2), B.new(obj)], [U.new(3), U.new(seq)], [U.new(4), U.new(at)],
      ]))
    end

    def self.receipt_head(body)
      OpenSSL::Digest::SHA384.digest(body)
    end

    # --- C8 delivery (§9) ---

    def self.delivery_update(obj, stage, at)
      Naalp::CBOR.encode(M.new([[U.new(1), B.new(obj)], [U.new(2), U.new(stage)], [U.new(3), U.new(at)]]))
    end

    # --- C9 streaming (§10) ---

    # Rolling SHA-384 over the chunk data in absolute-offset order (R-10.2).
    def self.stream_digest(chunks)
      h = OpenSSL::Digest::SHA384.new
      chunks.sort_by { |offset, _data| offset }.each { |_offset, data| h.update(data) }
      h.digest
    end

    def self.stream_open_body(stream_id, effect, approval, substream)
      pairs = [[U.new(1), B.new(stream_id)], [U.new(2), U.new(effect)], [U.new(4), U.new(substream)]]
      pairs << [U.new(3), B.new(approval)] if approval && approval.bytesize > 0
      Naalp::CBOR.encode(M.new(pairs))
    end

    def self.stream_commit_body(stream_id, digest)
      Naalp::CBOR.encode(M.new([[U.new(1), B.new(stream_id)], [U.new(2), B.new(digest)]]))
    end

    def self.stream_checkpoint_body(stream_id, through_offset, digest_so_far)
      Naalp::CBOR.encode(M.new([
        [U.new(1), B.new(stream_id)], [U.new(2), U.new(through_offset)], [U.new(3), B.new(digest_so_far)],
      ]))
    end

    # --- C12 foreign carriage (§13) ---

    CLASS_JSONRPC = 0
    CLASS_HTTP = 1
    CLASS_MSG = 2
    CLASS_STREAM = 3
    CLASS_DOC = 4
    CLASS_OPAQUE = 5

    class MappingError < StandardError
      def kind; "MappingError"; end
    end

    def self.carriage_body(protocol_id, cls, content_type, correlation, method_name, foreign)
      raise MappingError, "carriage class #{cls} is not defined" if cls > CLASS_OPAQUE
      Naalp::CBOR.encode(M.new([
        [U.new(1), U.new(protocol_id)], [U.new(2), U.new(cls)], [U.new(3), U.new(content_type)],
        [U.new(4), B.new(correlation)], [U.new(5), T.new(method_name)], [U.new(6), B.new(foreign)],
      ]))
    end

    # --- C11 transport confidentiality boundary (§12) ---
    # value: [confidential, peer_authenticated]
    TRANSPORTS = {
      "npamp" => [true, true],
      "quic" => [true, true],
      "websocket+wss" => [true, false],
      "websocket+ws" => [false, false],
      "https" => [true, false],
      "http" => [false, false],
    }.freeze

    class UnknownTransport < StandardError
      def kind; "UnknownTransport"; end
    end

    # Apply the §12.3 confidentiality boundary + §12.4 peer-auth rule; returns the result label.
    def self.transport_emit(name, sensitive, require_peer_auth)
      t = TRANSPORTS[name]
      raise UnknownTransport, "unknown transport #{name.inspect}" if t.nil?
      confidential, peer_authenticated = t
      return "ConfidentialTransportRequired" if sensitive && !confidential
      return "PeerUnauthenticated" if require_peer_auth && !peer_authenticated
      "ok"
    end
  end
end
