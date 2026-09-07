// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C9 — native streaming with a single signed per-stream commitment for the Swift SDK
// (design.md §10; R-10.1..10.6).
//
// A native stream is three signed objects plus unsigned chunks: StreamOpen establishes the stream's
// identity, effect, and (where it causes an effect) its approval binding, refusing a stream whose effect
// is not authorized BEFORE any chunk (§10.2, R-10.3); the chunks are raw data frames the transport AEAD
// already authenticates, so N-AALP does NOT sign them individually (R-10.2); StreamCommit carries a rolling
// SHA-384 over the chunks in absolute-offset order, making the whole stream non-repudiable with ONE
// signature, not N (§10.2). Optional signed StreamCheckpoints let a verifier confirm a prefix without the
// end. Altering any delivered byte invalidates the commitment (StreamDigestMismatch).
//
// Native streaming is channel 0x000C and is kept distinct from foreign streamed carriage (§13, 0x000D);
// this module never carries a foreign protocol (R-10.6). An independent transcription of impl/go/streaming
// (cross-read against impl/python/naalp/streaming.py), graded against the shared vectors/stream/cases.json
// (the oracle directory is `stream`, not `streaming`). Every check is fail-closed (§15).
//
// CRYPTO SCOPE (PURE-ONLY, honest F2/F4): the reference's StreamOpen/Commit/Checkpoint signatures are RAW
// deterministic ML-DSA (FIPS 204) over the body (matching impl/go/streaming's `s.Sign(bytes)` — no
// COSE_Sign1 assembly). Swift has no deterministic-from-seed ML-DSA signer (SwiftDilithium 3.6.0), so those
// signatures are NOT reproducible here and are NOT faked. Every surface this port grades against the corpus
// — the rolling commitment, the checkpoints, the bodies, the tamper digest, the order-independence, and the
// effect ceiling — is signature-independent. The ONE end-commitment signature is demonstrated in isolation
// with a real Ed25519 (RFC 8032) raw signature over the StreamCommit body via swift-crypto.

import Crypto
import Foundation

public enum Streaming {
    /// The N-PAMP Stream channel native streams run on; foreign streamed carriage uses the distinct Bridge
    /// channel 0x000D (R-10.6).
    public static let STREAM_CHANNEL: UInt64 = 0x000C

    /// One absolute-offset-positioned data frame of a stream (unsigned; the transport authenticates it).
    public struct Chunk {
        public let offset: UInt64
        public let data: [UInt8]
        public init(offset: UInt64, data: [UInt8]) {
            self.offset = offset
            self.data = data
        }
    }

    /// The rolling SHA-384 commitment accumulator (design.md §10.2). update() feeds chunks in absolute-offset
    /// order; digestSoFar() returns the SHA-384 of everything fed so far WITHOUT ending the stream — it
    /// copies the value-type hasher and finalizes the copy, so streaming continues after a checkpoint. This
    /// is exactly a checkpoint's digest_so_far.
    public struct StreamDigest {
        var hasher = SHA384()
        public init() {}

        /// Feed the next chunk's data into the rolling digest.
        public mutating func update(_ chunk: [UInt8]) { hasher.update(data: Data(chunk)) }

        /// The SHA-384 of all data fed so far; the underlying state is unchanged (a copy is finalized), so
        /// streaming continues after a checkpoint.
        public func digestSoFar() -> [UInt8] {
            var copy = hasher
            return Array(copy.finalize())
        }
    }

    /// Start an empty rolling commitment.
    public static func newStreamDigest() -> StreamDigest { return StreamDigest() }

    /// Compute the rolling SHA-384 over chunks in absolute-offset order. Input order is irrelevant — the
    /// chunks are sorted by offset before folding — so a delivered stream and a reordered delivery of the
    /// same frames yield the same commitment, while swapping which bytes sit at which offset does not.
    public static func commitDigest(_ chunks: [Chunk]) -> [UInt8] {
        var sd = StreamDigest()
        for c in chunks.sorted(by: { $0.offset < $1.offset }) { sd.update(c.data) }
        return sd.digestSoFar()
    }

    /// Establishes a stream's identity, effect, optional approval binding, and sub-stream id (design.md
    /// §10.2). It is signed.
    public struct StreamOpen {
        public let streamID: [UInt8]
        public let effect: UInt64
        public let approval: [UInt8]? // content id of the approval binding; nil when the stream causes no effect
        public let substream: UInt64
        public init(streamID: [UInt8], effect: UInt64, approval: [UInt8]?, substream: UInt64) {
            self.streamID = streamID
            self.effect = effect
            self.approval = approval
            self.substream = substream
        }

        func toMap() -> CborValue {
            var pairs: [(CborValue, CborValue)] = [
                (.u(1), .b(streamID)),
                (.u(2), .u(effect)),
                (.u(4), .u(substream)),
            ]
            if let a = approval { pairs.append((.u(3), .b(a))) }
            return .m(pairs)
        }

        /// Deterministic-CBOR encoding {1: stream_id, 2: effect, 3: approval?, 4: substream}; field 3 is
        /// present only when an approval binding exists (encode emits canonical key order regardless).
        public func bytes() throws -> [UInt8] { return try Cbor.encode(toMap()) }
    }

    /// Carries the completed stream's rolling-SHA-384 commitment (design.md §10.2).
    public struct StreamCommit {
        public let streamID: [UInt8]
        public let digest: [UInt8]
        public init(streamID: [UInt8], digest: [UInt8]) {
            self.streamID = streamID
            self.digest = digest
        }

        /// Deterministic-CBOR encoding {1: stream_id, 2: digest}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([(.u(1), .b(streamID)), (.u(2), .b(digest))]))
        }
    }

    /// Carries a mid-stream commitment over the prefix through throughOffset (design.md §10.2).
    public struct StreamCheckpoint {
        public let streamID: [UInt8]
        public let throughOffset: UInt64
        public let digestSoFar: [UInt8]
        public init(streamID: [UInt8], throughOffset: UInt64, digestSoFar: [UInt8]) {
            self.streamID = streamID
            self.throughOffset = throughOffset
            self.digestSoFar = digestSoFar
        }

        /// Deterministic-CBOR encoding {1: stream_id, 2: through_offset, 3: digest_so_far}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(streamID)),
                (.u(2), .u(throughOffset)),
                (.u(3), .b(digestSoFar)),
            ]))
        }
    }

    /// Authorize a StreamOpen against the granted effect ceiling, refusing a stream whose effect exceeds it
    /// BEFORE any chunk (R-10.3). An unrecognized effect is treated as destructive (fail-closed, via the C5
    /// policy) — a `UInt64 > 3` normalizes to destructive without a `UInt64 -> Int` conversion trap. Returns
    /// normally when the stream may proceed, else throws EffectNotAuthorized.
    public static func openStream(_ o: StreamOpen, _ grantedMax: Int) throws {
        let eff = o.effect <= 3 ? Policy.normalizeEffect(Int(o.effect)) : Policy.DESTRUCTIVE
        if !Policy.authorizes(grantedMax, eff) {
            throw NaalpError("EffectNotAuthorized", "stream effect exceeds the granted capability ceiling")
        }
    }

    /// Recompute the rolling digest over the delivered chunks and compare it to the signed commitment; any
    /// altered or reordered byte yields StreamDigestMismatch (R-10.2). Returns normally on a match.
    public static func verifyCommit(_ commit: StreamCommit, _ chunks: [Chunk]) throws {
        if UInt64(chunks.count) > MAX_STREAM_CHUNKS {  // stream chunk-count bound (§3.4, R7)
            throw NaalpError("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)")
        }
        if commit.digest != commitDigest(chunks) {
            throw NaalpError("StreamDigestMismatch", "stream commitment digest does not match the recomputed rolling digest")
        }
    }

    /// Confirm a prefix without the end (design.md §10.2): the prefix chunks must be contiguous from offset 0
    /// and total exactly throughOffset bytes, and their rolling digest must equal the checkpoint's
    /// digest_so_far. Otherwise StreamDigestMismatch. Returns normally on a clean confirmation.
    public static func verifyCheckpoint(_ cp: StreamCheckpoint, _ prefix: [Chunk]) throws {
        if UInt64(prefix.count) > MAX_STREAM_CHUNKS {  // stream chunk-count bound (§3.4, R7)
            throw NaalpError("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)")
        }
        var total: UInt64 = 0
        for c in prefix.sorted(by: { $0.offset < $1.offset }) {
            if c.offset != total {
                throw NaalpError("StreamDigestMismatch", "non-contiguous prefix")
            }
            total += UInt64(c.data.count)
        }
        if total != cp.throughOffset {
            throw NaalpError("StreamDigestMismatch", "prefix length does not match through_offset")
        }
        if cp.digestSoFar != commitDigest(prefix) {
            throw NaalpError("StreamDigestMismatch", "prefix digest does not match the checkpoint")
        }
    }

    // ---- stream state guard (design.md §10 state table + § Timers; naalp-error code 49) ------------------

    /// A stream's lifecycle state (design.md §10, the stream state table): idle (no stream open for this
    /// stream id), open, committed, or abandoned (the terminal state an open stream enters when its
    /// idle/commit timer expires, § Timers -- like committed, it admits no further event and its stream id
    /// is never re-admitted).
    public enum State: String {
        case idle
        case open
        case committed
        case abandoned

        /// The state's name ("idle", "open", "committed", "abandoned") -- mirrors Go's State.String().
        public var name: String { rawValue }
    }

    /// Enforces the stream state machine across concurrently open streams, keyed by stream id. It tracks
    /// only the current lifecycle state (idle/open/committed/abandoned), never chunk data, and rejects an
    /// event the state table does not admit for the stream's current state BEFORE any state change --
    /// fail-closed, no partial transition. It holds no clock: the idle/commit timer (§ Timers) lives in the
    /// caller, which calls expire() when a stream's interval elapses; the numeric interval is a deployment
    /// policy, not a protocol constant.
    ///
    /// A Guard is per-connection: the caller discards it when the connection closes, so the states map is
    /// freed with the connection. There is no eviction of terminal (committed/abandoned) entries --
    /// evicting one would re-admit a replayed signed StreamOpen reusing that id as a fresh idle -> open,
    /// the exact replay the terminal states exist to refuse. Retained entries are therefore bounded by the
    /// number of streams the connection actually opened, each of which cost the peer a full StreamOpen
    /// signature to create.
    public final class Guard {
        private let lock = NSLock()
        private var states: [[UInt8]: State] = [:]

        public init() {}

        /// The current lifecycle state of streamID (for callers and tests); an id never seen is idle
        /// (design.md §10: "idle (no stream open for this stream id)").
        public func state(_ streamID: [UInt8]) -> State {
            lock.lock()
            defer { lock.unlock() }
            return states[streamID] ?? .idle
        }

        /// Validates a StreamOpen against the state table: only idle admits StreamOpen, and then only
        /// when the effect is authorized (R-10.3) -- "idle | StreamOpen (effect authorized) -> open" and
        /// "idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)". A stream already
        /// open, committed, or abandoned rejects StreamStateError (an abandoned or committed stream id is
        /// never re-admitted). On EffectNotAuthorized the stream stays idle, since the open never took
        /// effect; on StreamStateError the existing state is untouched; only a successful open advances
        /// to open.
        public func open(_ o: StreamOpen, _ grantedMax: Int) throws {
            lock.lock()
            defer { lock.unlock() }
            if (states[o.streamID] ?? .idle) != .idle {
                throw NaalpError("StreamStateError", "stream event is illegal for the current stream state (§10 state table)")
            }
            try Streaming.openStream(o, grantedMax)
            states[o.streamID] = .open
        }

        /// Validates a data chunk's arrival against the state table: only open admits a chunk; idle,
        /// committed, or abandoned reject it StreamStateError. A chunk never changes the stream's state.
        public func chunk(_ streamID: [UInt8]) throws {
            lock.lock()
            defer { lock.unlock() }
            if (states[streamID] ?? .idle) != .open {
                throw NaalpError("StreamStateError", "stream event is illegal for the current stream state (§10 state table)")
            }
        }

        /// Validates a StreamCheckpoint's arrival against the state table: only open admits it; idle,
        /// committed, or abandoned reject it StreamStateError. A checkpoint never changes the stream's
        /// state.
        public func checkpoint(_ streamID: [UInt8]) throws {
            lock.lock()
            defer { lock.unlock() }
            if (states[streamID] ?? .idle) != .open {
                throw NaalpError("StreamStateError", "stream event is illegal for the current stream state (§10 state table)")
            }
        }

        /// Validates a StreamCommit against the state table: only open admits it -- idle, committed, or
        /// abandoned reject it StreamStateError BEFORE the digest is even inspected. When open, the
        /// commitment is verified against the delivered chunks (R-10.2): a digest mismatch rejects
        /// StreamDigestMismatch and leaves the stream open (this row rejects without advancing, so a
        /// corrected commit may still follow); a matching digest advances the stream to committed.
        public func commit(_ c: StreamCommit, _ chunks: [Chunk]) throws {
            lock.lock()
            defer { lock.unlock() }
            if (states[c.streamID] ?? .idle) != .open {
                throw NaalpError("StreamStateError", "stream event is illegal for the current stream state (§10 state table)")
            }
            try Streaming.verifyCommit(c, chunks)
            states[c.streamID] = .committed
        }

        /// Fires the idle/commit timer's expiry for streamID (§ Timers): an open stream that has not
        /// committed within its interval transitions open -> abandoned, a terminal state that rejects
        /// every subsequent event with StreamStateError -- including a StreamOpen reusing the id, so an
        /// abandoned stream is never re-admitted and nothing it delivered without a StreamCommit is
        /// non-repudiable. Only an open stream can be abandoned: the timer clears when a StreamCommit
        /// transitions the stream to committed, so a correct caller fires expire only while the stream is
        /// open; Expire on an idle, committed, or already-abandoned stream is rejected StreamStateError
        /// with no state change (fail-closed). The Guard holds no clock -- the caller decides when the
        /// interval has elapsed; the interval itself is a deployment policy.
        public func expire(_ streamID: [UInt8]) throws {
            lock.lock()
            defer { lock.unlock() }
            if (states[streamID] ?? .idle) != .open {
                throw NaalpError("StreamStateError", "stream event is illegal for the current stream state (§10 state table)")
            }
            states[streamID] = .abandoned
        }
    }

    /// A stream-state guard with no streams open yet -- mirrors Go's NewGuard().
    public static func newGuard() -> Guard { return Guard() }

    // ---- signatures (real Ed25519 raw signature over the body, demonstrated in isolation) --------------
    //
    // The reference (Go/Python) signs the body RAW (no COSE_Sign1 assembly) with deterministic ML-DSA; here
    // the pure-tier isolation demo produces a raw Ed25519 signature over the same body bytes. Verify with
    // `Cose.ed25519Verify(pk, <object>.bytes(), sig)`.

    /// A raw Ed25519 signature over the StreamOpen body.
    public static func signOpen(_ o: StreamOpen, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.ed25519Sign(seed, try o.bytes())
    }

    /// A raw Ed25519 signature over the StreamCommit body — the ONE end-commitment signature that covers
    /// the whole stream (R-10.2).
    public static func signCommit(_ c: StreamCommit, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.ed25519Sign(seed, try c.bytes())
    }

    /// A raw Ed25519 signature over the StreamCheckpoint body.
    public static func signCheckpoint(_ c: StreamCheckpoint, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.ed25519Sign(seed, try c.bytes())
    }
}
