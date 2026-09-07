// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * C9 — native streaming with a single signed per-stream commitment for the Java SDK (design.md §10;
 * R-10.1..10.6).
 *
 * <p>A native stream is three signed objects plus unsigned chunks: {@link StreamOpen} establishes the
 * stream's identity, effect, and (where it causes an effect) its approval binding, refusing a stream
 * whose effect is not authorized before any chunk (§10.2, R-10.3); the chunks are raw data frames the
 * transport AEAD already authenticates, so N-AALP does NOT sign them individually (R-10.2);
 * {@link StreamCommit} carries a rolling SHA-384 over the chunks in absolute-offset order, making the
 * whole stream non-repudiable with one signature, not N (§10.2). Optional signed
 * {@link StreamCheckpoint}s let a verifier confirm a prefix without the end. Altering any delivered
 * byte invalidates the commitment (StreamDigestMismatch). Native streaming is channel 0x000C and is
 * kept distinct from foreign streamed carriage (§13, 0x000D); this class never carries a foreign
 * protocol (R-10.6).
 *
 * <p>An independent transcription of impl/go/streaming (cross-checked against
 * impl/python/naalp/streaming). The rolling commitment, the checkpoints, and the
 * StreamOpen/Commit/Checkpoint bodies are graded against the independent corpus
 * vectors/stream/cases.json; the one-signature-covers-the-stream commitment is demonstrated in
 * isolation with real deterministic ML-DSA-65 (via {@link Cose}). Every check is fail-closed (§15).
 *
 * <p>{@link Guard} enforces the stream state table (idle -&gt; open -&gt; committed, with abandoned as
 * the terminal state a StreamOpen leaves on the idle/commit timer's expiry) across concurrent
 * streams, rejecting an event the table does not admit for the stream's current state with
 * StreamStateError before any state change (§10 state table, § Timers; error code 49).
 */
public final class Streaming {
    /** The N-PAMP Stream channel native streams run on; foreign streamed carriage uses the distinct
     * Bridge channel 0x000D (R-10.6). */
    public static final long STREAM_CHANNEL = 0x000C;

    private Streaming() {}

    private static MessageDigest sha384() {
        try {
            return MessageDigest.getInstance("SHA-384");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    /** One absolute-offset-positioned data frame of a stream (unsigned; the transport authenticates it). */
    public static final class Chunk {
        public final long offset;
        public final byte[] data;

        public Chunk(long offset, byte[] data) {
            this.offset = offset;
            this.data = data.clone();
        }
    }

    /** The rolling SHA-384 commitment accumulator (design.md §10.2). {@link #update} feeds chunks in
     * absolute-offset order; {@link #digestSoFar} returns the SHA-384 of everything fed so far WITHOUT
     * ending the stream (it clones the digest, so streaming continues after a checkpoint) — exactly a
     * checkpoint's digest_so_far. */
    public static final class StreamDigest {
        private final MessageDigest h;

        StreamDigest(MessageDigest h) {
            this.h = h;
        }

        /** Feed the next chunk's data into the rolling digest. */
        public void update(byte[] chunk) {
            h.update(chunk);
        }

        /** The SHA-384 of all data fed so far, without disturbing the rolling state. */
        public byte[] digestSoFar() {
            try {
                return ((MessageDigest) h.clone()).digest();
            } catch (CloneNotSupportedException e) {
                throw new IllegalStateException("SHA-384 digest is not cloneable", e);
            }
        }
    }

    /** Start an empty rolling commitment. */
    public static StreamDigest newStreamDigest() {
        return new StreamDigest(sha384());
    }

    /** The rolling SHA-384 over chunks in absolute-offset order (input order is irrelevant). */
    public static byte[] commitDigest(List<Chunk> chunks) {
        List<Chunk> sorted = new ArrayList<>(chunks);
        sorted.sort((a, b) -> Long.compareUnsigned(a.offset, b.offset));
        StreamDigest sd = newStreamDigest();
        for (Chunk c : sorted) {
            sd.update(c.data);
        }
        return sd.digestSoFar();
    }

    /** Establishes a stream's identity, effect, optional approval binding, and sub-stream id
     * (design.md §10.2). It is signed. */
    public static final class StreamOpen {
        public final byte[] streamId;
        public final long effect;
        public final byte[] approval; // content id of the approval binding; null when the stream causes no effect
        public final long subStream;

        public StreamOpen(byte[] streamId, long effect, byte[] approval, long subStream) {
            this.streamId = streamId.clone();
            this.effect = effect;
            this.approval = approval == null ? null : approval.clone();
            this.subStream = subStream;
        }

        /** Deterministic-CBOR encoding {1:stream_id,2:effect,3:approval?,4:substream}; field 3 is
         * present only when an approval binding exists (the encoder emits canonical key order
         * regardless of construction order). */
        public byte[] bytes() {
            List<Cbor.Pair> pairs = new ArrayList<>(4);
            pairs.add(new Cbor.Pair(new Cbor.U(1), new Cbor.B(streamId)));
            pairs.add(new Cbor.Pair(new Cbor.U(2), new Cbor.U(effect)));
            if (approval != null) {
                pairs.add(new Cbor.Pair(new Cbor.U(3), new Cbor.B(approval)));
            }
            pairs.add(new Cbor.Pair(new Cbor.U(4), new Cbor.U(subStream)));
            return Cbor.encode(new Cbor.M(pairs));
        }
    }

    /** Carries the completed stream's rolling-SHA-384 commitment (design.md §10.2). */
    public static final class StreamCommit {
        public final byte[] streamId;
        public final byte[] digest;

        public StreamCommit(byte[] streamId, byte[] digest) {
            this.streamId = streamId.clone();
            this.digest = digest.clone();
        }

        /** Deterministic-CBOR encoding {1:stream_id,2:digest}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(streamId)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(digest)))));
        }
    }

    /** Carries a mid-stream commitment over the prefix through {@code throughOffset} (design.md §10.2). */
    public static final class StreamCheckpoint {
        public final byte[] streamId;
        public final long throughOffset;
        public final byte[] digestSoFar;

        public StreamCheckpoint(byte[] streamId, long throughOffset, byte[] digestSoFar) {
            this.streamId = streamId.clone();
            this.throughOffset = throughOffset;
            this.digestSoFar = digestSoFar.clone();
        }

        /** Deterministic-CBOR encoding {1:stream_id,2:through_offset,3:digest_so_far}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(streamId)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(throughOffset)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(digestSoFar)))));
        }
    }

    /** Sign a StreamOpen body with the stream owner's key (real deterministic ML-DSA); returns the raw
     * signature over the body bytes, one signature the whole stream is anchored to. */
    public static byte[] signOpen(StreamOpen o, int alg, byte[] seed) {
        return Cose.mldsaSign(alg, seed, o.bytes());
    }

    /** Sign a StreamCommit body — the single end-commitment signature covering the whole stream. */
    public static byte[] signCommit(StreamCommit c, int alg, byte[] seed) {
        return Cose.mldsaSign(alg, seed, c.bytes());
    }

    /** Sign a StreamCheckpoint body. */
    public static byte[] signCheckpoint(StreamCheckpoint c, int alg, byte[] seed) {
        return Cose.mldsaSign(alg, seed, c.bytes());
    }

    /** Verify a raw commitment signature over the StreamCommit body bytes. */
    public static boolean verifyCommitSig(StreamCommit c, int alg, byte[] pubkey, byte[] sig) {
        return Cose.coseVerify1Raw(alg, pubkey, c.bytes(), sig);
    }

    /** Verify a raw StreamOpen signature over its body bytes. */
    public static boolean verifyOpenSig(StreamOpen o, int alg, byte[] pubkey, byte[] sig) {
        return Cose.coseVerify1Raw(alg, pubkey, o.bytes(), sig);
    }

    /** Authorize a StreamOpen against the granted effect ceiling, refusing a stream whose effect
     * exceeds it BEFORE any chunk (R-10.3). An unrecognized effect is treated as destructive
     * (fail-closed, via the C5 policy). Returns normally when the stream may proceed. */
    public static void openStream(StreamOpen o, long grantedMax) {
        if (!Policy.authorizes(grantedMax, Policy.normalizeEffect(o.effect))) {
            throw new NaalpException("EffectNotAuthorized", "stream effect exceeds the granted capability ceiling");
        }
    }

    /** Recompute the rolling digest over the delivered chunks and compare it to the signed commitment;
     * any altered or reordered byte yields StreamDigestMismatch (R-10.2). Fail-closed. */
    public static void verifyCommit(StreamCommit commit, List<Chunk> chunks) {
        if (chunks.size() > WireConstants.MAX_STREAM_CHUNKS) { // stream chunk-count bound (§3.4, R7)
            throw new NaalpException("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)");
        }
        if (!Arrays.equals(commit.digest, commitDigest(chunks))) {
            throw new NaalpException("StreamDigestMismatch", "stream commitment digest does not match the recomputed rolling digest");
        }
    }

    /** Confirm a prefix without the end (design.md §10.2): the prefix chunks must be contiguous from
     * offset 0 and total exactly {@code throughOffset} bytes, and their rolling digest must equal the
     * checkpoint's digest_so_far. Otherwise StreamDigestMismatch. Fail-closed. */
    public static void verifyCheckpoint(StreamCheckpoint cp, List<Chunk> prefix) {
        if (prefix.size() > WireConstants.MAX_STREAM_CHUNKS) { // stream chunk-count bound (§3.4, R7)
            throw new NaalpException("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)");
        }
        List<Chunk> sorted = new ArrayList<>(prefix);
        sorted.sort((a, b) -> Long.compareUnsigned(a.offset, b.offset));
        long total = 0;
        for (Chunk c : sorted) {
            if (c.offset != total) {
                throw new NaalpException("StreamDigestMismatch", "non-contiguous prefix");
            }
            total += c.data.length;
        }
        if (total != cp.throughOffset) {
            throw new NaalpException("StreamDigestMismatch", "prefix length does not equal through_offset");
        }
        if (!Arrays.equals(cp.digestSoFar, commitDigest(prefix))) {
            throw new NaalpException("StreamDigestMismatch", "prefix digest does not match the checkpoint");
        }
    }

    /** A stream's lifecycle state (design.md §10, the stream state table): IDLE (no stream open for this
     * stream id), OPEN, COMMITTED, or ABANDONED (the terminal state an open stream enters when its
     * idle/commit timer expires, § Timers — like COMMITTED, it admits no further event and its stream id
     * is never re-admitted). */
    public enum State {
        IDLE, OPEN, COMMITTED, ABANDONED;

        /** The exact lowercase wire name: "idle", "open", "committed", or "abandoned". */
        @Override
        public String toString() {
            switch (this) {
                case IDLE:
                    return "idle";
                case OPEN:
                    return "open";
                case COMMITTED:
                    return "committed";
                case ABANDONED:
                    return "abandoned";
                default:
                    return "unknown";
            }
        }
    }

    /** Enforces the stream state machine across concurrently open streams, keyed by stream id
     * (design.md §10; reactions mirrored from impl/go/streaming.Guard). It tracks only the current
     * lifecycle state (idle/open/committed/abandoned), never chunk data, and rejects an event the state
     * table does not admit for the stream's current state before any state change — a rejected event
     * leaves the state exactly as it was (fail-closed, no partial transition). It holds no clock: the
     * idle/commit timer (§ Timers) lives in the caller, which calls {@link #expire} when a stream's
     * interval elapses; the numeric interval is a deployment policy, not a protocol constant.
     *
     * <p>A Guard is per-connection: the caller discards it when the connection closes, so the states map
     * is freed with the connection. There is no eviction of terminal (committed / abandoned) entries —
     * evicting one would re-admit a replayed signed StreamOpen reusing that id as a fresh idle -&gt; open,
     * the exact replay the terminal states exist to refuse. */
    public static final class Guard {
        private final ReentrantLock lock = new ReentrantLock();
        private final Map<String, State> states = new HashMap<>();

        private Guard() {}

        /** A stream-state guard with no streams open yet. */
        public static Guard newGuard() {
            return new Guard();
        }

        private static String key(byte[] streamId) {
            return Hex.encode(streamId);
        }

        // Caller MUST hold lock.
        private State stateLocked(byte[] streamId) {
            State s = states.get(key(streamId));
            return s == null ? State.IDLE : s;
        }

        /** The current lifecycle state of streamId (for callers and tests); an id never seen is idle
         * (design.md §10: "idle (no stream open for this stream id)"). */
        public State state(byte[] streamId) {
            lock.lock();
            try {
                return stateLocked(streamId);
            } finally {
                lock.unlock();
            }
        }

        /** Validate a StreamOpen against the state table: only idle admits StreamOpen, and then only when
         * the effect is authorized (R-10.3) — "idle | StreamOpen (effect authorized) -&gt; open" and
         * "idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)". A stream already
         * open, committed, or abandoned rejects StreamStateError (committed+StreamOpen and
         * abandoned+StreamOpen fall under the table's unlisted-pair default — an abandoned or committed
         * stream id is never re-admitted). On EffectNotAuthorized the stream stays idle, since the open
         * never took effect; on StreamStateError the existing state is untouched; only a successful open
         * advances to open. */
        public void open(StreamOpen o, long grantedMax) {
            lock.lock();
            try {
                if (stateLocked(o.streamId) != State.IDLE) {
                    throw new NaalpException("StreamStateError", "stream event is illegal for the current stream state (§10 state table)");
                }
                openStream(o, grantedMax); // throws EffectNotAuthorized; leaves the state untouched
                states.put(key(o.streamId), State.OPEN);
            } finally {
                lock.unlock();
            }
        }

        /** Validate a data chunk's arrival against the state table: only open admits a chunk ("open |
         * chunk -&gt; open"); idle, committed, or abandoned reject it StreamStateError (committed+chunk is
         * listed explicitly; idle+chunk and abandoned+chunk fall under the unlisted-pair default). A
         * chunk never changes the stream's state — it stays open. */
        public void chunk(byte[] streamId) {
            requireOpen(streamId);
        }

        /** Validate a StreamCheckpoint's arrival against the state table: only open admits it ("open |
         * StreamCheckpoint -&gt; open"); idle, committed, or abandoned reject it StreamStateError
         * (committed+StreamCheckpoint is listed explicitly; the others fall under the unlisted-pair
         * default). A checkpoint never changes the stream's state — it stays open. */
        public void checkpoint(byte[] streamId) {
            requireOpen(streamId);
        }

        private void requireOpen(byte[] streamId) {
            lock.lock();
            try {
                if (stateLocked(streamId) != State.OPEN) {
                    throw new NaalpException("StreamStateError", "stream event is illegal for the current stream state (§10 state table)");
                }
            } finally {
                lock.unlock();
            }
        }

        /** Validate a StreamCommit against the state table: only open admits it — idle, committed, or
         * abandoned reject it StreamStateError before the digest is even inspected (committed+
         * StreamCommit is listed explicitly; the others fall under the unlisted-pair default). When open,
         * the commitment is verified against the delivered chunks (R-10.2): "open | StreamCommit (digest
         * mismatch) | reject (StreamDigestMismatch)" leaves the stream open (this table row rejects
         * without advancing, so a corrected commit may still follow), and "open | StreamCommit (digest
         * matches) -&gt; committed" advances the stream to committed. */
        public void commit(StreamCommit c, List<Chunk> chunks) {
            lock.lock();
            try {
                if (stateLocked(c.streamId) != State.OPEN) {
                    throw new NaalpException("StreamStateError", "stream event is illegal for the current stream state (§10 state table)");
                }
                verifyCommit(c, chunks); // throws StreamDigestMismatch/TooManyChunks; leaves the state open
                states.put(key(c.streamId), State.COMMITTED);
            } finally {
                lock.unlock();
            }
        }

        /** Fire the idle/commit timer's expiry for streamId (§ Timers): an open stream that has not
         * committed within its interval transitions "open -&gt; abandoned", a terminal state that then
         * rejects every subsequent event with StreamStateError — including a StreamOpen reusing the id,
         * so an abandoned stream is never re-admitted and nothing it delivered without a StreamCommit is
         * non-repudiable. Only an open stream can be abandoned: the timer clears when a StreamCommit
         * transitions the stream to committed (§ Timers), so a correct caller fires expire only while the
         * stream is open; Expire on an idle, committed, or already-abandoned stream is rejected
         * StreamStateError with no state change (fail-closed). The Guard holds no clock — the caller
         * decides when the interval has elapsed; the interval itself is a deployment policy. */
        public void expire(byte[] streamId) {
            lock.lock();
            try {
                if (stateLocked(streamId) != State.OPEN) {
                    throw new NaalpException("StreamStateError", "stream event is illegal for the current stream state (§10 state table)");
                }
                states.put(key(streamId), State.ABANDONED);
            } finally {
                lock.unlock();
            }
        }
    }
}
