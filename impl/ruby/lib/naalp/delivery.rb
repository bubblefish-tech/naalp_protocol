# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C8 delivery for the Ruby SDK -- delivery as four signed monotonic stages, the
# persist-before-acknowledge discipline, the live full-duplex switchboard, and the content-free relay
# (design.md §9; R-9.1..9.4).
#
# Delivery is four distinct, separately-observable stages, each a signed delivery.update naming the
# target object's content id and the stage reached -- there is no single "sent" boolean (§9.1):
# persisted_origin -> accepted_relay -> persisted_target -> presented. A stage is advanced only after
# the object is durably persisted (WAL fsync), so a crash right after an acknowledgment loses nothing
# (§9.2). Observing a stage earlier than the one already reached is StageOutOfOrder (§9.4). The
# switchboard holds two connections open and passes objects through both directions concurrently
# (§9.3); a relay that holds objects only in transit writes an audit trail over content ids while
# retaining no payload (§9.4, R-9.4).
#
# Ported from impl/go/delivery (cross-read against impl/python/naalp/delivery.py). The delivery.update
# SIGNATURE is a RAW deterministic ML-DSA signature over the update body (Naalp::COSE.mldsa_sign /
# mldsa_verify). The content-id framing and the relay's retained trail reuse the shared Naalp::CBOR
# and Naalp::Audit. Graded against the shared vectors/delivery/cases.json.
require 'thread'
require_relative 'cbor'
require_relative 'cose'
require_relative 'audit'

module Naalp
  module Delivery
    # Delivery stages (design §9.1), monotonic in this order.
    STAGE_PERSISTED_ORIGIN = 0
    STAGE_ACCEPTED_RELAY = 1
    STAGE_PERSISTED_TARGET = 2
    STAGE_PRESENTED = 3

    STAGE_NAMES = ["persisted_origin", "accepted_relay", "persisted_target", "presented"].freeze

    # A named, fail-closed delivery error; #kind is the stable error kind.
    class DeliveryError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # One signed delivery-stage notification (design §9.1): obj is the content id of the object whose
    # delivery this reports; stage is the stage reached (0..3); at is observer time, epoch ms.
    DeliveryUpdate = Struct.new(:obj, :stage, :at) do
      # Deterministic-CBOR encoding {1: obj, 2: stage, 3: at}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(obj)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(stage)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(at)],
        ]))
      end
    end

    # A durable, per-object delivery-stage tracker enforcing monotonic stages and
    # persist-before-acknowledge. Each advance persists to the write-ahead log and fsyncs before
    # returning the acknowledging update, so a crash after the ack loses nothing (§9.2). WAL records
    # are length-prefixed (4-byte big-endian) deterministic-CBOR update bodies.
    class Tracker
      def initialize(f)
        @lock = Mutex.new
        @f = f
        @current = {} # object-id (binary str) -> highest stage reached
        replay
      end

      def replay
        @f.seek(0)
        loop do
          len_buf = @f.read(4)
          break if len_buf.nil? || len_buf.empty?
          raise DeliveryError.new("Malformed", "truncated WAL length prefix") if len_buf.bytesize != 4
          n = len_buf.unpack1("N")
          rec = @f.read(n)
          raise DeliveryError.new("Malformed", "truncated WAL record") if rec.nil? || rec.bytesize != n
          u = Naalp::Delivery.parse_update(rec)
          @current[u.obj.dup.force_encoding(Encoding::BINARY)] = u.stage # last durable stage wins
        end
      end

      # Record that obj reached stage at time at, returning the acknowledging update. A stage earlier
      # than the one already reached is StageOutOfOrder (no state change); re-reporting the current
      # stage is an idempotent no-op; a later stage is persisted (WAL fsync) before the update is
      # returned. Skipping ahead is permitted; only regression is an error.
      def advance(obj, stage, at)
        key = obj.dup.force_encoding(Encoding::BINARY)
        @lock.synchronize do
          cur = @current[key]
          unless cur.nil?
            raise DeliveryError.new("StageOutOfOrder", "a delivery stage regressed to an earlier stage") if stage < cur
            return DeliveryUpdate.new(key, stage, at) if stage == cur
          end
          u = DeliveryUpdate.new(key, stage, at)
          rec = u.bytes
          @f.write([rec.bytesize].pack("N") + rec)
          @f.flush
          @f.fsync # persist-before-ack (R-9.2)
          @current[key] = stage
          u
        end
      end

      # The highest stage reached for obj and whether it has been seen.
      def stage(obj)
        @lock.synchronize do
          s = @current[obj.dup.force_encoding(Encoding::BINARY)]
          s.nil? ? [0, false] : [s, true]
        end
      end

      # Flush and close the WAL file.
      def close
        @lock.synchronize { @f.close }
      end
    end

    # One side of a switchboard connection: objects written to send are relayed to the peer's recv,
    # concurrently with the reverse direction.
    class Endpoint
      def initialize(send_q, recv_q)
        @send = send_q
        @recv = recv_q
      end

      # Submit an object into the switchboard toward the peer.
      def send(obj)
        @send.push(obj.dup.force_encoding(Encoding::BINARY))
      end

      # Receive the next object relayed from the peer (blocks until one arrives).
      def recv
        @recv.pop
      end
    end

    # Holds two connections open and relays objects through in both directions concurrently (design
    # §9.3) -- a live full-duplex relay, not a one-object mailbox. Two pump threads forward
    # left->right and right->left simultaneously; a pump retains nothing (content-free in transit).
    class Switchboard
      SENTINEL = Object.new

      def initialize(capacity)
        @l_send = SizedQueue.new(capacity)
        @l_recv = SizedQueue.new(capacity)
        @r_send = SizedQueue.new(capacity)
        @r_recv = SizedQueue.new(capacity)
        @left = Endpoint.new(@l_send, @l_recv)
        @right = Endpoint.new(@r_send, @r_recv)
        # left.send -> right.recv, and right.send -> left.recv, concurrently.
        @t1 = Thread.new { pump(@l_send, @r_recv) }
        @t2 = Thread.new { pump(@r_send, @l_recv) }
      end

      def pump(in_q, out_q)
        loop do
          obj = in_q.pop
          return if obj.equal?(SENTINEL)
          out_q.push(obj) # forwarded in transit; the pump retains nothing
        end
      end

      def left
        @left
      end

      def right
        @right
      end

      # Stop both pumps and wait for them to exit.
      def close
        @l_send.push(SENTINEL)
        @r_send.push(SENTINEL)
        @t1.join
        @t2.join
      end
    end

    # Routes objects while retaining no payload at rest: for each routed object it appends a C7 audit
    # receipt over the object's content id and returns the object for immediate forwarding, keeping
    # only the receipt chain (content ids), never the payload (§9.4, R-9.4). The retained audit trail
    # alone verifies as a valid chain.
    class ContentFreeRelay
      def initialize(alg, seed)
        @auth = Naalp::Audit::Authority.new(alg, seed)
        @receipts = []
        @sigs = []
      end

      # Record an audit receipt over obj's content id and return obj for forwarding. The relay keeps
      # the receipt only; it does not store obj.
      def route(obj, at)
        rec, sig = @auth.append(Naalp::Delivery.content_id(obj), at)
        @receipts << rec
        @sigs << sig
        obj.dup.force_encoding(Encoding::BINARY)
      end

      # The receipts and signatures the relay retained (its only persistent state), for offline chain
      # verification.
      def audit_trail
        [@receipts.dup, @sigs.dup]
      end
    end

    module_function

    # The name of a stage value (0..3), or 'unknown'.
    def stage_name(stage)
      (stage >= 0 && stage < STAGE_NAMES.length) ? STAGE_NAMES[stage] : "unknown"
    end

    # T1 content-id framing multihash(0x20, SHA-384(b)) = 0x20 0x30 || SHA-384(b) (50 octets),
    # identical to the spine framing (Naalp::CBOR.content_id over raw bytes).
    def content_id(b)
      Naalp::CBOR.content_id(b.dup.force_encoding(Encoding::BINARY))
    end

    # Sign a delivery.update with the observer's key: a RAW deterministic signature over the update body.
    def sign_update(update, alg, seed)
      Naalp::COSE.mldsa_sign(alg, seed, update.bytes)
    end

    # Verify a raw delivery.update signature under the observer's public key.
    def verify_update(update, alg, pubkey, sig)
      Naalp::COSE.mldsa_verify(alg, pubkey, update.bytes, sig)
    end

    # Reconstruct a DeliveryUpdate from a WAL record body; fail-closed on a malformed shape or a
    # non-canonical encoding.
    def parse_update(rec)
      begin
        v = Naalp::CBOR.decode(rec)
      rescue Naalp::CBOR::NonCanonical => e
        raise DeliveryError.new("Malformed", "delivery update is not canonical: #{e}")
      end
      raise DeliveryError.new("Malformed", "delivery update is not a map") unless v.is_a?(Naalp::CBOR::M)
      obj = nil
      stage = nil
      at = nil
      v.pairs.each do |k, val|
        raise DeliveryError.new("Malformed", "non-uint key") unless k.is_a?(Naalp::CBOR::U)
        if k.v == 1 && val.is_a?(Naalp::CBOR::B)
          obj = val.v
        elsif k.v == 2 && val.is_a?(Naalp::CBOR::U)
          stage = val.v
        elsif k.v == 3 && val.is_a?(Naalp::CBOR::U)
          at = val.v
        else
          raise DeliveryError.new("Malformed", "unknown or mistyped delivery-update field #{k.v}")
        end
      end
      raise DeliveryError.new("Malformed", "delivery update missing a mandatory field") if obj.nil? || stage.nil? || at.nil?
      DeliveryUpdate.new(obj, stage, at)
    end

    # Open (creating if needed) a WAL-backed tracker and replay it to recover the last durable stage
    # for every object.
    def open_tracker(path)
      f = File.exist?(path) ? File.open(path, "r+b") : File.open(path, "w+b")
      Tracker.new(f)
    end
  end
end
