// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

/**
 * N-AALP C9 native streaming with a single signed per-stream commitment for the Kotlin SDK
 * (design.md section 10; R-10.1..10.6).
 *
 * A native stream is three signed objects plus unsigned chunks: StreamOpen establishes the stream's
 * identity, effect, and (where it causes an effect) its approval binding, refusing a stream whose
 * effect is not authorized BEFORE any chunk (R-10.3); the chunks are raw data frames the transport
 * AEAD already authenticates, so N-AALP does NOT sign them individually (R-10.2); StreamCommit carries
 * a rolling SHA-384 over the chunks in absolute-offset order, making the whole stream non-repudiable
 * with ONE signature, not N. Optional signed StreamCheckpoints let a verifier confirm a prefix
 * without the end. Altering any delivered byte invalidates the commitment (StreamDigestMismatch).
 *
 * Native streaming is channel 0x000C and is kept distinct from foreign streamed carriage (channel
 * 0x000D); this module never carries a foreign protocol (R-10.6). An independent transcription of
 * impl/go/streaming (a second reference is impl/python/naalp/streaming.py), graded against the shared
 * vectors/stream/cases.json (the oracle directory is `stream`, not `streaming`).
 *
 * CRYPTO SCOPE: the StreamOpen/StreamCommit/StreamCheckpoint signatures are real deterministic
 * FIPS-204 ML-DSA-65 (BouncyCastle) raw signatures over the body (matching Go/Python), demonstrated
 * in isolation; the corpus carries no signed pin for streaming (correct -- the load-bearing bytes are
 * the commitment digests, which ARE pinned).
 */
object Streaming {
    /** The N-PAMP Stream channel native streams run on; foreign streamed carriage uses the distinct
     *  Bridge channel 0x000D (R-10.6). */
    const val STREAM_CHANNEL = 0x000CL

    /** A named, fail-closed streaming error kind (design.md section 15). */
    private fun mismatch(): NaalpException =
        NaalpException("StreamDigestMismatch", "stream commitment digest does not match the recomputed rolling digest")

    /** One absolute-offset-positioned data frame of a stream (unsigned; the transport authenticates
     *  it). */
    class Chunk(val offset: Long, data: ByteArray) {
        val data: ByteArray = data.copyOf()
    }

    /**
     * The rolling SHA-384 commitment accumulator (design.md section 10.2). [update] feeds chunks in
     * absolute-offset order; [digestSoFar] returns the SHA-384 of everything fed so far WITHOUT ending
     * the stream, which is exactly a checkpoint's digest_so_far. Java's MessageDigest.digest() resets
     * the digest, so [digestSoFar] clones the live digest and finalizes the clone -- the underlying
     * accumulator is unchanged, so streaming continues after a checkpoint (matching Go's Sum(nil) and
     * Python's .digest()).
     */
    class StreamDigest {
        private val h: MessageDigest = MessageDigest.getInstance("SHA-384")

        /** Feed the next chunk's data into the rolling digest. */
        fun update(chunk: ByteArray) = h.update(chunk)

        /** The SHA-384 of all data fed so far; the accumulator state is unchanged. */
        fun digestSoFar(): ByteArray = (h.clone() as MessageDigest).digest()
    }

    /**
     * Compute the rolling SHA-384 over chunks in absolute-offset order. Input order is irrelevant --
     * the chunks are sorted by offset before folding -- so a delivered stream and a reordered delivery
     * of the same frames yield the same commitment, while swapping which bytes sit at which offset
     * does not. This absolute-offset ordering is the load-bearing property (R-10.2).
     */
    fun commitDigest(chunks: List<Chunk>): ByteArray {
        val sorted = chunks.sortedBy { it.offset }
        val sd = StreamDigest()
        for (c in sorted) sd.update(c.data)
        return sd.digestSoFar()
    }

    /**
     * Establishes a stream's identity, effect, optional approval binding, and sub-stream id
     * (design.md section 10.2). It is signed. [approval] is the content id of the approval binding, or
     * null when the stream causes no effect.
     */
    class StreamOpen(streamId: ByteArray, val effect: Long, approval: ByteArray?, val substream: Long) {
        val streamId: ByteArray = streamId.copyOf()
        val approval: ByteArray? = approval?.copyOf()

        /** Deterministic-CBOR encoding {1: stream_id, 2: effect, 3: approval?, 4: substream}; field 3
         *  is present only when an approval binding exists (encode emits canonical key order). */
        fun bytes(): ByteArray {
            val pairs = ArrayList<Cbor.Pair>(4)
            pairs.add(Cbor.Pair(Cbor.U(1), Cbor.B(streamId)))
            pairs.add(Cbor.Pair(Cbor.U(2), Cbor.U(effect)))
            pairs.add(Cbor.Pair(Cbor.U(4), Cbor.U(substream)))
            approval?.let { pairs.add(Cbor.Pair(Cbor.U(3), Cbor.B(it))) }
            return Cbor.encode(Cbor.M(pairs))
        }
    }

    /** Carries the completed stream's rolling-SHA-384 commitment (design.md section 10.2). */
    class StreamCommit(streamId: ByteArray, digest: ByteArray) {
        val streamId: ByteArray = streamId.copyOf()
        val digest: ByteArray = digest.copyOf()

        /** Deterministic-CBOR encoding {1: stream_id, 2: digest}. */
        fun bytes(): ByteArray =
            Cbor.encode(Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.B(streamId)), Cbor.Pair(Cbor.U(2), Cbor.B(digest)))))
    }

    /** Carries a mid-stream commitment over the prefix through [throughOffset] (design.md section
     *  10.2). */
    class StreamCheckpoint(streamId: ByteArray, val throughOffset: Long, digestSoFar: ByteArray) {
        val streamId: ByteArray = streamId.copyOf()
        val digestSoFar: ByteArray = digestSoFar.copyOf()

        /** Deterministic-CBOR encoding {1: stream_id, 2: through_offset, 3: digest_so_far}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(streamId)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(throughOffset)),
                    Cbor.Pair(Cbor.U(3), Cbor.B(digestSoFar))
                )
            )
        )
    }

    /**
     * Authorize a StreamOpen against the granted effect ceiling, refusing a stream whose effect
     * exceeds it BEFORE any chunk (R-10.3). An unrecognized effect is treated as destructive
     * (fail-closed, via the C5 policy). Returns on authorization; throws EffectNotAuthorized otherwise.
     */
    fun openStream(o: StreamOpen, grantedMax: Long) {
        if (!Policy.authorizes(grantedMax, Policy.normalizeEffect(o.effect))) {
            throw NaalpException("EffectNotAuthorized", "stream effect exceeds the granted capability ceiling")
        }
    }

    /**
     * Recompute the rolling digest over the delivered chunks and compare it to the signed commitment;
     * any altered or reordered byte yields StreamDigestMismatch (R-10.2). Returns on a match.
     */
    fun verifyCommit(commit: StreamCommit, chunks: List<Chunk>) {
        if (chunks.size > MAX_STREAM_CHUNKS) { // stream chunk-count bound (§3.4, R7)
            throw NaalpException("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)")
        }
        if (!commit.digest.contentEquals(commitDigest(chunks))) throw mismatch()
    }

    /**
     * Confirm a prefix without the end (design.md section 10.2): the prefix chunks must be contiguous
     * from offset 0 and total exactly [StreamCheckpoint.throughOffset] bytes, and their rolling digest
     * must equal the checkpoint's digest_so_far. Otherwise StreamDigestMismatch.
     */
    fun verifyCheckpoint(cp: StreamCheckpoint, prefix: List<Chunk>) {
        if (prefix.size > MAX_STREAM_CHUNKS) { // stream chunk-count bound (§3.4, R7)
            throw NaalpException("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)")
        }
        val sorted = prefix.sortedBy { it.offset }
        var total = 0L
        for (c in sorted) {
            if (c.offset != total) throw mismatch() // non-contiguous prefix
            total += c.data.size.toLong()
        }
        if (total != cp.throughOffset) throw mismatch()
        if (!cp.digestSoFar.contentEquals(commitDigest(prefix))) throw mismatch()
    }

    // ---- signatures (real deterministic ML-DSA over the body, demonstrated in isolation) ----------

    /** A raw deterministic ML-DSA signature over the StreamOpen body (matches impl/go/streaming). */
    fun signOpen(o: StreamOpen, alg: Int, seed: ByteArray): ByteArray = Cose.mldsaSign(alg, seed, o.bytes())

    /** A raw deterministic ML-DSA signature over the StreamCommit body -- the ONE end-commitment
     *  signature that covers the whole stream (R-10.2). */
    fun signCommit(c: StreamCommit, alg: Int, seed: ByteArray): ByteArray = Cose.mldsaSign(alg, seed, c.bytes())

    /** A raw deterministic ML-DSA signature over the StreamCheckpoint body. */
    fun signCheckpoint(c: StreamCheckpoint, alg: Int, seed: ByteArray): ByteArray = Cose.mldsaSign(alg, seed, c.bytes())

    /** Verify a raw StreamOpen signature under the stream owner's public key. */
    fun verifyOpenSig(o: StreamOpen, alg: Int, pubkey: ByteArray, sig: ByteArray): Boolean =
        Cose.mldsaVerify(alg, pubkey, o.bytes(), sig)

    /** Verify a raw StreamCommit signature under the stream owner's public key. */
    fun verifyCommitSig(c: StreamCommit, alg: Int, pubkey: ByteArray, sig: ByteArray): Boolean =
        Cose.mldsaVerify(alg, pubkey, c.bytes(), sig)

    /** Verify a raw StreamCheckpoint signature under the stream owner's public key. */
    fun verifyCheckpointSig(c: StreamCheckpoint, alg: Int, pubkey: ByteArray, sig: ByteArray): Boolean =
        Cose.mldsaVerify(alg, pubkey, c.bytes(), sig)

    // ---- stream state guard (design.md section 10 state table + section Timers) ------------------

    /**
     * A stream's lifecycle state (design.md section 10, the stream state table): idle (no stream open
     * for this stream id), open, committed, or abandoned (the terminal state an open stream enters
     * when its idle/commit timer expires, section Timers -- like committed, it admits no further
     * event and its stream id is never re-admitted).
     */
    enum class State {
        IDLE, OPEN, COMMITTED, ABANDONED;

        /** The lowercase wire/log name ("idle", "open", "committed", "abandoned"), matching
         *  impl/go/streaming's State.String(). */
        override fun toString(): String = when (this) {
            IDLE -> "idle"
            OPEN -> "open"
            COMMITTED -> "committed"
            ABANDONED -> "abandoned"
        }
    }

    /** A named, fail-closed stream-state error (design.md section 10; registered as naalp-error code
     *  49): a stream event arrives for a state the stream state table does not admit -- a second
     *  StreamOpen on an already-open stream, any chunk/StreamCheckpoint/StreamCommit after the stream
     *  has committed or been abandoned, or any of those (including a StreamOpen reusing the id) on a
     *  stream that was never opened, committed, or abandoned. Every (state, event) pair the table
     *  does not list is rejected under this name. */
    private fun stateError(): NaalpException =
        NaalpException("StreamStateError", "stream event is illegal for the current stream state (§10 state table)")

    /**
     * Enforces the stream state machine across concurrently open streams, keyed by stream id. It
     * tracks only the current lifecycle state (idle/open/committed/abandoned), never chunk data, and
     * rejects an event the state table does not admit for the stream's current state BEFORE any state
     * change -- a rejected event leaves the state exactly as it was (fail-closed, no partial
     * transition). It holds no clock: the idle/commit timer (section Timers) lives in the caller,
     * which calls [expire] when a stream's interval elapses; the numeric interval is a deployment
     * policy, not a protocol constant.
     *
     * A Guard is per-connection: the caller discards it when the connection closes, so the states map
     * is freed with the connection. There is NO eviction of terminal (committed / abandoned) entries
     * -- evicting one would re-admit a replayed signed StreamOpen reusing that id as a fresh
     * idle -> open, the exact replay the terminal states exist to refuse. Retained entries are
     * therefore bounded by the number of streams the connection actually opened, each of which cost
     * the peer a full StreamOpen signature to create (a bound the underlying transport's concurrent
     * sub-stream limit further caps at any instant, section 10.1), so retention is bounded by work
     * the peer already performed rather than being an amplification surface.
     */
    class Guard {
        private val lock = Any()
        private val states = HashMap<String, State>() // stream-id hex -> current state

        /** Current state under [lock]; an id never seen is idle (design.md section 10: "idle (no
         *  stream open for this stream id)"). */
        private fun stateLocked(streamId: ByteArray): State = states[Hex.encode(streamId)] ?: State.IDLE

        /** The current lifecycle state of [streamId] (for callers and tests). */
        fun state(streamId: ByteArray): State = synchronized(lock) { stateLocked(streamId) }

        /**
         * Validate a StreamOpen against the state table: only idle admits StreamOpen, and then only
         * when the effect is authorized (R-10.3) -- "idle | StreamOpen (effect authorized) -> open"
         * and "idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)". A stream
         * already open, committed, or abandoned rejects StreamStateError ("open | StreamOpen | reject
         * (StreamStateError)"; committed+StreamOpen and abandoned+StreamOpen fall under the table's
         * unlisted-pair default -- an abandoned or committed stream id is never re-admitted). On
         * EffectNotAuthorized the stream stays idle, since the open never took effect; on
         * StreamStateError the existing state is untouched; only a successful open advances to open.
         */
        fun open(o: StreamOpen, grantedMax: Long) {
            synchronized(lock) {
                if (stateLocked(o.streamId) != State.IDLE) throw stateError()
                openStream(o, grantedMax) // throws EffectNotAuthorized; the stream stays idle
                states[Hex.encode(o.streamId)] = State.OPEN
            }
        }

        /** Validate a data chunk's arrival against the state table: only open admits a chunk ("open |
         *  chunk -> open"); idle, committed, or abandoned reject it StreamStateError (committed+chunk
         *  is listed explicitly; idle+chunk and abandoned+chunk fall under the unlisted-pair default).
         *  A chunk never changes the stream's state -- it stays open. */
        fun chunk(streamId: ByteArray) {
            synchronized(lock) {
                if (stateLocked(streamId) != State.OPEN) throw stateError()
            }
        }

        /** Validate a StreamCheckpoint's arrival against the state table: only open admits it ("open |
         *  StreamCheckpoint -> open"); idle, committed, or abandoned reject it StreamStateError
         *  (committed+StreamCheckpoint is listed explicitly; the others fall under the unlisted-pair
         *  default). A checkpoint never changes the stream's state -- it stays open. */
        fun checkpoint(streamId: ByteArray) {
            synchronized(lock) {
                if (stateLocked(streamId) != State.OPEN) throw stateError()
            }
        }

        /**
         * Validate a StreamCommit against the state table: only open admits it -- idle, committed, or
         * abandoned reject it StreamStateError BEFORE the digest is even inspected (committed+
         * StreamCommit is listed explicitly; the others fall under the unlisted-pair default). When
         * open, the commitment is verified against the delivered chunks (R-10.2): "open |
         * StreamCommit (digest mismatch) | reject (StreamDigestMismatch)" leaves the stream open
         * (this table row rejects without advancing, so a corrected commit may still follow), and
         * "open | StreamCommit (digest matches) -> committed" advances the stream to committed.
         */
        fun commit(c: StreamCommit, chunks: List<Chunk>) {
            synchronized(lock) {
                if (stateLocked(c.streamId) != State.OPEN) throw stateError()
                verifyCommit(c, chunks) // throws StreamDigestMismatch (or TooManyChunks); stream stays open
                states[Hex.encode(c.streamId)] = State.COMMITTED
            }
        }

        /**
         * Fire the idle/commit timer's expiry for [streamId] (section Timers): an open stream that
         * has not committed within its interval transitions "open -> abandoned", a terminal state
         * that rejects every subsequent event with StreamStateError -- including a StreamOpen reusing
         * the id, so an abandoned stream is never re-admitted and nothing it delivered without a
         * StreamCommit is non-repudiable. Only an open stream can be abandoned: the timer clears when
         * a StreamCommit transitions the stream to committed (section Timers), so a correct caller
         * fires [expire] only while the stream is open; Expire on an idle, committed, or already-
         * abandoned stream is rejected StreamStateError with no state change (fail-closed). The Guard
         * holds no clock -- the caller decides when the interval has elapsed; the interval itself is
         * a deployment policy.
         */
        fun expire(streamId: ByteArray) {
            synchronized(lock) {
                if (stateLocked(streamId) != State.OPEN) throw stateError()
                states[Hex.encode(streamId)] = State.ABANDONED
            }
        }
    }
}
