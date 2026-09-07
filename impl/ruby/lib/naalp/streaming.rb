# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C9 native streaming with a single signed per-stream commitment for the Ruby SDK
# (design.md §10; R-10.1..10.6).
#
# A native stream is three signed objects plus unsigned chunks: StreamOpen establishes the stream's
# identity, effect, and (where it causes an effect) its approval binding, refusing a stream whose effect
# is not authorized before any chunk (§10.2, R-10.3); the chunks are raw data frames the transport AEAD
# already authenticates, so N-AALP does NOT sign them individually (R-10.2); StreamCommit carries a
# rolling SHA-384 over the chunks in absolute-offset order, making the whole stream non-repudiable with
# ONE signature, not N (§10.2). Optional signed StreamCheckpoints let a verifier confirm a prefix
# without the end. Altering any delivered byte invalidates the commitment (StreamDigestMismatch).
#
# Native streaming is channel 0x000C and is kept distinct from foreign streamed carriage (§13, 0x000D);
# this module never carries a foreign protocol (R-10.6). NOTE the name mismatch: this module is
# streaming.rb but its oracle directory is `stream` (vectors/stream/cases.json), matching the Go module
# streaming/ graded against vectors/stream/. Ported from impl/go/streaming (cross-read against
# impl/python/naalp/streaming.py). The StreamOpen/StreamCommit/StreamCheckpoint signatures are real
# deterministic ML-DSA-65 (a raw signature over the body), NOT corpus-graded.
require 'openssl'
require_relative 'cbor'
require_relative 'cose'
require_relative 'policy'
require_relative '_wire_constants_gen' # Naalp::Envelope::MAX_STREAM_CHUNKS (§3.4, R7)

module Naalp
  module Streaming
    # The N-PAMP Stream channel native streams run on; foreign streamed carriage uses the distinct
    # Bridge channel 0x000D (R-10.6).
    STREAM_CHANNEL = 0x000C

    # A named, fail-closed streaming error; #kind is the stable error kind (§15).
    class StreamError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # One absolute-offset-positioned data frame of a stream (unsigned; the transport authenticates it).
    Chunk = Struct.new(:offset, :data)

    # The rolling SHA-384 commitment accumulator (design.md §10.2). update feeds chunks in
    # absolute-offset order; digest_so_far returns the SHA-384 of everything fed so far WITHOUT ending
    # the stream, which is exactly a checkpoint's digest_so_far (the digest snapshot does not finalize
    # the accumulator, so streaming continues after a checkpoint).
    class StreamDigest
      def initialize
        @h = OpenSSL::Digest::SHA384.new
      end

      # Feed the next chunk's data into the rolling digest.
      def update(chunk)
        @h.update(chunk)
      end

      # The SHA-384 of all data fed so far; the underlying state is unchanged (a snapshot), so
      # streaming continues after a checkpoint.
      def digest_so_far
        @h.dup.digest
      end
    end

    # Establishes a stream's identity, effect, optional approval binding, and sub-stream id
    # (design.md §10.2). It is signed. approval is nil when the stream causes no effect.
    StreamOpen = Struct.new(:stream_id, :effect, :approval, :substream) do
      # Deterministic-CBOR encoding {1: stream_id, 2: effect, 3: approval?, 4: substream}; field 3 is
      # present only when an approval binding exists (encode emits canonical key order regardless of
      # insertion order).
      def bytes
        pairs = [
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(stream_id)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(effect)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::U.new(substream)],
        ]
        pairs << [Naalp::CBOR::U.new(3), Naalp::CBOR::B.new(approval)] unless approval.nil?
        Naalp::CBOR.encode(Naalp::CBOR::M.new(pairs))
      end
    end

    # Carries the completed stream's rolling-SHA-384 commitment (design.md §10.2).
    StreamCommit = Struct.new(:stream_id, :digest) do
      # Deterministic-CBOR encoding {1: stream_id, 2: digest}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(stream_id)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(digest)],
        ]))
      end
    end

    # Carries a mid-stream commitment over the prefix through through_offset (design.md §10.2).
    StreamCheckpoint = Struct.new(:stream_id, :through_offset, :digest_so_far) do
      # Deterministic-CBOR encoding {1: stream_id, 2: through_offset, 3: digest_so_far}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(stream_id)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(through_offset)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::B.new(digest_so_far)],
        ]))
      end
    end

    # A stream's lifecycle state (design.md §10, the stream state table): idle (no stream open for
    # this stream id), open, committed, or abandoned (the terminal state an open stream enters when
    # its idle/commit timer expires, § Timers -- like committed, it admits no further event and its
    # stream id is never re-admitted). Mirrors impl/go/streaming's State type.
    STATE_IDLE = 0
    STATE_OPEN = 1
    STATE_COMMITTED = 2
    STATE_ABANDONED = 3

    STATE_NAMES = ["idle", "open", "committed", "abandoned"].freeze

    # ErrStreamStateError's message: returned when a stream event arrives for a state the stream
    # state table does not admit: a second StreamOpen on an already-open stream, any chunk,
    # StreamCheckpoint, or StreamCommit after the stream has committed or been abandoned, or any of
    # those (including a StreamOpen reusing the id) on a stream that was never opened, committed, or
    # abandoned. Every (state, event) pair the table does not list is rejected under this name
    # (design.md §10; registered as naalp-error code 49).
    STREAM_STATE_ERROR_MSG = "stream event is illegal for the current stream state (§10 state table)"

    # Guard enforces the stream state machine across concurrently open streams, keyed by stream id.
    # It tracks only the current lifecycle state (idle/open/committed/abandoned), never chunk data,
    # and rejects an event the state table does not admit for the stream's current state before any
    # state change -- a rejected event leaves the state exactly as it was (fail-closed, no partial
    # transition). It holds no clock: the idle/commit timer (§ Timers) lives in the caller, which
    # calls #expire when a stream's interval elapses; the numeric interval is a deployment policy,
    # not a protocol constant.
    #
    # A Guard is per-connection: the caller discards it when the connection closes, so @states is
    # freed with the connection. There is no eviction of terminal (committed / abandoned) entries --
    # evicting one would re-admit a replayed signed StreamOpen reusing that id as a fresh idle -> open,
    # the exact replay the terminal states exist to refuse. Retained entries are therefore bounded by
    # the number of streams the connection actually opened, each of which cost the peer a full
    # StreamOpen signature to create.
    class Guard
      def initialize
        @mu = Mutex.new
        @states = {}
      end

      # state returns the current lifecycle state of stream_id (for callers and tests); an id never
      # seen is idle (design.md §10: "idle (no stream open for this stream id)").
      def state(stream_id)
        @mu.synchronize { state_locked(stream_id) }
      end

      # open validates a StreamOpen against the state table: only idle admits StreamOpen, and then
      # only when the effect is authorized (R-10.3) -- "idle | StreamOpen (effect authorized) ->
      # open" and "idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)". A
      # stream already open, committed, or abandoned rejects StreamStateError (committed+StreamOpen
      # and abandoned+StreamOpen fall under the table's unlisted-pair default -- an abandoned or
      # committed stream id is never re-admitted). On EffectNotAuthorized the stream stays idle,
      # since the open never took effect; on StreamStateError the existing state is untouched; only
      # a successful open advances to open.
      def open(o, granted_max)
        @mu.synchronize do
          unless state_locked(o.stream_id) == STATE_IDLE
            raise StreamError.new("StreamStateError", STREAM_STATE_ERROR_MSG)
          end
          Streaming.open_stream(o, granted_max) # raises EffectNotAuthorized; stream stays idle
          @states[o.stream_id] = STATE_OPEN
        end
        nil
      end

      # chunk validates a data chunk's arrival against the state table: only open admits a chunk
      # ("open | chunk -> open"); idle, committed, or abandoned reject it StreamStateError
      # (committed+chunk is listed explicitly; idle+chunk and abandoned+chunk fall under the
      # unlisted-pair default). A chunk never changes the stream's state -- it stays open.
      def chunk(stream_id)
        @mu.synchronize do
          unless state_locked(stream_id) == STATE_OPEN
            raise StreamError.new("StreamStateError", STREAM_STATE_ERROR_MSG)
          end
        end
        nil
      end

      # checkpoint validates a StreamCheckpoint's arrival against the state table: only open admits
      # it ("open | StreamCheckpoint -> open"); idle, committed, or abandoned reject it
      # StreamStateError (committed+StreamCheckpoint is listed explicitly; the others fall under the
      # unlisted-pair default). A checkpoint never changes the stream's state -- it stays open.
      def checkpoint(stream_id)
        @mu.synchronize do
          unless state_locked(stream_id) == STATE_OPEN
            raise StreamError.new("StreamStateError", STREAM_STATE_ERROR_MSG)
          end
        end
        nil
      end

      # commit validates a StreamCommit against the state table: only open admits it -- idle,
      # committed, or abandoned reject it StreamStateError before the digest is even inspected
      # (committed+StreamCommit is listed explicitly; the others fall under the unlisted-pair
      # default). When open, the commitment is verified against the delivered chunks (R-10.2): "open
      # | StreamCommit (digest mismatch) | reject (StreamDigestMismatch)" leaves the stream open
      # (this table row rejects without advancing, so a corrected commit may still follow), and
      # "open | StreamCommit (digest matches) -> committed" advances the stream to committed.
      def commit(c, chunks)
        @mu.synchronize do
          unless state_locked(c.stream_id) == STATE_OPEN
            raise StreamError.new("StreamStateError", STREAM_STATE_ERROR_MSG)
          end
          Streaming.verify_commit(c, chunks) # raises StreamDigestMismatch; stream stays open
          @states[c.stream_id] = STATE_COMMITTED
        end
        nil
      end

      # expire fires the idle/commit timer's expiry for stream_id (§ Timers): an open stream that
      # has not committed within its interval transitions "open -> abandoned", a terminal state
      # that rejects every subsequent event with StreamStateError -- including a StreamOpen reusing
      # the id, so an abandoned stream is never re-admitted and nothing it delivered without a
      # StreamCommit is non-repudiable. Only an open stream can be abandoned: the timer clears when
      # a StreamCommit transitions the stream to committed (§ Timers), so a correct caller fires
      # expire only while the stream is open; expire on an idle, committed, or already-abandoned
      # stream is rejected StreamStateError with no state change (fail-closed). The Guard holds no
      # clock -- the caller decides when the interval has elapsed; the interval itself is a
      # deployment policy.
      def expire(stream_id)
        @mu.synchronize do
          unless state_locked(stream_id) == STATE_OPEN
            raise StreamError.new("StreamStateError", STREAM_STATE_ERROR_MSG)
          end
          @states[stream_id] = STATE_ABANDONED
        end
        nil
      end

      private

      def state_locked(stream_id)
        @states.fetch(stream_id, STATE_IDLE)
      end
    end

    module_function

    # The name of a state value (0..3), or 'unknown' -- mirrors Go's State.String (Guard#state
    # returns the integer; this names it for callers/tests/adapters).
    def state_name(state)
      (state >= 0 && state < STATE_NAMES.length) ? STATE_NAMES[state] : "unknown"
    end

    # Compute the rolling SHA-384 over chunks in absolute-offset order. Input order is irrelevant --
    # the chunks are sorted by offset before folding -- so a delivered stream and a reordered delivery
    # of the same frames yield the same commitment, while swapping which bytes sit at which offset does
    # not.
    def commit_digest(chunks)
      sd = StreamDigest.new
      chunks.sort_by(&:offset).each { |c| sd.update(c.data) }
      sd.digest_so_far
    end

    # Authorize a StreamOpen against the granted effect ceiling, refusing a stream whose effect exceeds
    # it BEFORE any chunk (R-10.3). An unrecognized effect is treated as destructive (fail-closed, via
    # the C5 policy). Returns nil when the stream may proceed, else raises EffectNotAuthorized.
    def open_stream(open, granted_max)
      unless Naalp::Policy.authorizes(granted_max, Naalp::Policy.normalize_effect(open.effect))
        raise StreamError.new("EffectNotAuthorized", "stream effect exceeds the granted capability ceiling")
      end
      nil
    end

    # Recompute the rolling digest over the delivered chunks and compare it to the signed commitment;
    # any altered or reordered byte yields StreamDigestMismatch (R-10.2). Returns nil on a match.
    def verify_commit(commit, chunks)
      if chunks.length > Naalp::Envelope::MAX_STREAM_CHUNKS # stream chunk-count bound (§3.4, R7)
        raise StreamError.new("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)")
      end
      unless commit.digest == commit_digest(chunks)
        raise StreamError.new("StreamDigestMismatch", "stream commitment digest does not match the recomputed rolling digest")
      end
      nil
    end

    # Confirm a prefix without the end (design.md §10.2): the prefix chunks must be contiguous from
    # offset 0 and total exactly through_offset bytes, and their rolling digest must equal the
    # checkpoint's digest_so_far. Otherwise StreamDigestMismatch. Returns nil on a clean confirmation.
    def verify_checkpoint(cp, prefix)
      if prefix.length > Naalp::Envelope::MAX_STREAM_CHUNKS # stream chunk-count bound (§3.4, R7)
        raise StreamError.new("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)")
      end
      total = 0
      prefix.sort_by(&:offset).each do |c|
        raise StreamError.new("StreamDigestMismatch", "non-contiguous prefix") if c.offset != total
        total += c.data.bytesize
      end
      raise StreamError.new("StreamDigestMismatch", "prefix length does not match through_offset") if total != cp.through_offset
      unless cp.digest_so_far == commit_digest(prefix)
        raise StreamError.new("StreamDigestMismatch", "prefix digest does not match the checkpoint")
      end
      nil
    end

    # ---- signatures (real deterministic ML-DSA over the body, demonstrated in isolation) ----

    # A raw deterministic ML-DSA signature over the StreamOpen body (matches impl/go/streaming).
    def sign_open(open, alg, seed)
      Naalp::COSE.mldsa_sign(alg, seed, open.bytes)
    end

    # A raw deterministic ML-DSA signature over the StreamCommit body -- the ONE end-commitment
    # signature that covers the whole stream (R-10.2).
    def sign_commit(commit, alg, seed)
      Naalp::COSE.mldsa_sign(alg, seed, commit.bytes)
    end

    # A raw deterministic ML-DSA signature over the StreamCheckpoint body.
    def sign_checkpoint(cp, alg, seed)
      Naalp::COSE.mldsa_sign(alg, seed, cp.bytes)
    end

    # Verify a raw StreamOpen signature under the stream owner's public key.
    def verify_open_sig(open, alg, pubkey, sig)
      Naalp::COSE.mldsa_verify(alg, pubkey, open.bytes, sig)
    end

    # Verify a raw StreamCommit signature under the stream owner's public key.
    def verify_commit_sig(commit, alg, pubkey, sig)
      Naalp::COSE.mldsa_verify(alg, pubkey, commit.bytes, sig)
    end

    # Verify a raw StreamCheckpoint signature under the stream owner's public key.
    def verify_checkpoint_sig(cp, alg, pubkey, sig)
      Naalp::COSE.mldsa_verify(alg, pubkey, cp.bytes, sig)
    end
  end
end
