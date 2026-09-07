// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Naalp
{
    /// <summary>
    /// C9 — native streaming with a single signed per-stream commitment for the C# SDK (design.md §10;
    /// R-10.1..10.6), ported from impl/go/streaming and cross-checked against
    /// impl/python/naalp/streaming.py.
    ///
    /// <para>A native stream is three signed objects plus unsigned chunks: <see cref="StreamOpen"/>
    /// establishes the stream's identity, effect, and (where it causes an effect) its approval binding,
    /// refusing a stream whose effect is not authorized before any chunk (§10.2, R-10.3); the chunks are
    /// raw data frames the transport AEAD already authenticates, so N-AALP does NOT sign them
    /// individually (R-10.2); <see cref="StreamCommit"/> carries a rolling SHA-384 over the chunks in
    /// absolute-offset order, making the whole stream non-repudiable with one signature, not N (§10.2).
    /// Optional signed <see cref="StreamCheckpoint"/>s let a verifier confirm a prefix without the end.
    /// Altering any delivered byte invalidates the commitment (StreamDigestMismatch).</para>
    ///
    /// <para>Native streaming is channel 0x000C and is kept distinct from foreign streamed carriage
    /// (§13, 0x000D); this module never carries a foreign protocol (R-10.6). Graded against
    /// <c>vectors/stream/cases.json</c>. The StreamOpen/Commit/Checkpoint signatures are real
    /// deterministic ML-DSA-65 (a raw signature over the body, matching impl/go/streaming) but are not
    /// corpus-graded.</para>
    /// </summary>
    public static class Streaming
    {
        /// <summary>The N-PAMP Stream channel native streams run on; foreign streamed carriage uses the
        /// distinct Bridge channel 0x000D (R-10.6).</summary>
        public const long StreamChannel = 0x000C;

        /// <summary>One absolute-offset-positioned data frame of a stream (unsigned; the transport
        /// authenticates it).</summary>
        public sealed class Chunk
        {
            public readonly long Offset;
            public readonly byte[] Data;

            public Chunk(long offset, byte[] data)
            {
                Offset = offset;
                Data = data;
            }
        }

        /// <summary>
        /// The rolling SHA-384 commitment accumulator (design.md §10.2). <see cref="Update"/> feeds
        /// chunks in absolute-offset order; <see cref="DigestSoFar"/> returns the SHA-384 of everything
        /// fed so far WITHOUT ending the stream, which is exactly a checkpoint's digest_so_far — the
        /// underlying incremental-hash state is unchanged, so streaming continues after a checkpoint.
        /// </summary>
        public sealed class StreamDigest : IDisposable
        {
            private readonly IncrementalHash _h;

            public StreamDigest()
            {
                _h = IncrementalHash.CreateHash(HashAlgorithmName.SHA384);
            }

            /// <summary>Feed the next chunk's data into the rolling digest.</summary>
            public void Update(byte[] chunk) => _h.AppendData(chunk);

            /// <summary>The SHA-384 of all data fed so far; the underlying state is unchanged, so
            /// streaming continues after a checkpoint.</summary>
            public byte[] DigestSoFar() => _h.GetCurrentHash();

            public void Dispose() => _h.Dispose();
        }

        /// <summary>
        /// Computes the rolling SHA-384 over chunks in absolute-offset order. Input order is irrelevant —
        /// the chunks are sorted by offset before folding — so a delivered stream and a reordered
        /// delivery of the same frames yield the same commitment, while swapping which bytes sit at which
        /// offset does not.
        /// </summary>
        public static byte[] CommitDigest(IEnumerable<Chunk> chunks)
        {
            var sorted = new List<Chunk>(chunks);
            sorted.Sort((a, b) => a.Offset.CompareTo(b.Offset));
            using var sd = new StreamDigest();
            foreach (Chunk c in sorted) sd.Update(c.Data);
            return sd.DigestSoFar();
        }

        /// <summary>Establishes a stream's identity, effect, optional approval binding, and sub-stream id
        /// (design.md §10.2). It is signed.</summary>
        public sealed class StreamOpen
        {
            public readonly byte[] StreamID;
            public readonly long Effect;
            public readonly byte[]? Approval; // content id of the approval binding; null when no effect
            public readonly long SubStream;

            public StreamOpen(byte[] streamId, long effect, byte[]? approval, long subStream)
            {
                StreamID = streamId;
                Effect = effect;
                Approval = approval;
                SubStream = subStream;
            }

            /// <summary>Deterministic-CBOR encoding {1: stream_id, 2: effect, 3: approval?, 4: substream};
            /// field 3 is present only when an approval binding exists (Encode emits canonical key order
            /// regardless of insertion order).</summary>
            public byte[] Bytes()
            {
                var pairs = new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(StreamID)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(Effect)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.U(SubStream)),
                };
                if (Approval != null)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(3), new Cbor.B(Approval)));
                }
                return Cbor.Encode(new Cbor.M(pairs));
            }
        }

        /// <summary>Carries the completed stream's rolling-SHA-384 commitment (design.md §10.2).</summary>
        public sealed class StreamCommit
        {
            public readonly byte[] StreamID;
            public readonly byte[] Digest;

            public StreamCommit(byte[] streamId, byte[] digest)
            {
                StreamID = streamId;
                Digest = digest;
            }

            /// <summary>Deterministic-CBOR encoding {1: stream_id, 2: digest}.</summary>
            public byte[] Bytes() => Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(StreamID)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(Digest)),
            }));
        }

        /// <summary>Carries a mid-stream commitment over the prefix through ThroughOffset
        /// (design.md §10.2).</summary>
        public sealed class StreamCheckpoint
        {
            public readonly byte[] StreamID;
            public readonly long ThroughOffset;
            public readonly byte[] DigestSoFar;

            public StreamCheckpoint(byte[] streamId, long throughOffset, byte[] digestSoFar)
            {
                StreamID = streamId;
                ThroughOffset = throughOffset;
                DigestSoFar = digestSoFar;
            }

            /// <summary>Deterministic-CBOR encoding {1: stream_id, 2: through_offset, 3: digest_so_far}.</summary>
            public byte[] Bytes() => Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(StreamID)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(ThroughOffset)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.B(DigestSoFar)),
            }));
        }

        /// <summary>
        /// Authorizes a StreamOpen against the granted effect ceiling, refusing a stream whose effect
        /// exceeds it BEFORE any chunk (R-10.3). An unrecognized effect is treated as destructive
        /// (fail-closed, via the C5 policy). Returns when the stream may proceed, else throws
        /// EffectNotAuthorized.
        /// </summary>
        public static void OpenStream(StreamOpen o, long grantedMax)
        {
            if (!Policy.Authorizes(grantedMax, Policy.NormalizeEffect(o.Effect)))
            {
                throw new NaalpException("EffectNotAuthorized", "stream effect exceeds the granted capability ceiling");
            }
        }

        /// <summary>
        /// Recomputes the rolling digest over the delivered chunks and compares it to the signed
        /// commitment; any altered or reordered byte yields StreamDigestMismatch (R-10.2). Returns on a
        /// match.
        /// </summary>
        public static void VerifyCommit(StreamCommit commit, IEnumerable<Chunk> chunks)
        {
            List<Chunk> list = chunks as List<Chunk> ?? new List<Chunk>(chunks);
            if (list.Count > Envelope.MaxStreamChunks) // stream chunk-count bound (§3.4, R7)
            {
                throw new NaalpException("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)");
            }
            if (Cbor.CompareBytes(commit.Digest, CommitDigest(list)) != 0)
            {
                throw new NaalpException("StreamDigestMismatch", "stream commitment digest does not match the recomputed rolling digest");
            }
        }

        /// <summary>
        /// Confirms a prefix without the end (design.md §10.2): the prefix chunks must be contiguous from
        /// offset 0 and total exactly ThroughOffset bytes, and their rolling digest must equal the
        /// checkpoint's digest_so_far. Otherwise StreamDigestMismatch. Returns on a clean confirmation.
        /// </summary>
        public static void VerifyCheckpoint(StreamCheckpoint cp, IEnumerable<Chunk> prefix)
        {
            var sorted = new List<Chunk>(prefix);
            if (sorted.Count > Envelope.MaxStreamChunks) // stream chunk-count bound (§3.4, R7)
            {
                throw new NaalpException("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)");
            }
            sorted.Sort((a, b) => a.Offset.CompareTo(b.Offset));
            long total = 0;
            foreach (Chunk c in sorted)
            {
                if (c.Offset != total)
                {
                    throw new NaalpException("StreamDigestMismatch", "non-contiguous prefix");
                }
                total += c.Data.Length;
            }
            if (total != cp.ThroughOffset)
            {
                throw new NaalpException("StreamDigestMismatch", "prefix length does not match through_offset");
            }
            if (Cbor.CompareBytes(cp.DigestSoFar, CommitDigest(sorted)) != 0)
            {
                throw new NaalpException("StreamDigestMismatch", "prefix digest does not match the checkpoint");
            }
        }

        // ---- stream state machine guard (design.md §10 state table; § Timers) ----------------------

        /// <summary>A stream's lifecycle state (design.md §10, the stream state table): idle (no stream
        /// open for this stream id), open, committed, or abandoned (the terminal state an open stream
        /// enters when its idle/commit timer expires, § Timers — like committed, it admits no further
        /// event and its stream id is never re-admitted).</summary>
        public enum State
        {
            Idle,
            Open,
            Committed,
            Abandoned,
        }

        /// <summary>Names a State ("idle", "open", "committed", "abandoned", or "unknown").</summary>
        public static string StateName(State s)
        {
            switch (s)
            {
                case State.Idle: return "idle";
                case State.Open: return "open";
                case State.Committed: return "committed";
                case State.Abandoned: return "abandoned";
                default: return "unknown";
            }
        }

        /// <summary>
        /// Enforces the stream state machine across concurrently open streams, keyed by stream id (mirrors
        /// impl/go/streaming's Guard). It tracks only the current lifecycle state
        /// (idle/open/committed/abandoned), never chunk data, and rejects an event the state table does
        /// not admit for the stream's current state BEFORE any state change — a rejected event leaves the
        /// state exactly as it was (fail-closed, no partial transition). It holds no clock: the
        /// idle/commit timer (§ Timers) lives in the caller, which calls <see cref="Expire"/> when a
        /// stream's interval elapses; the numeric interval is a deployment policy, not a protocol
        /// constant.
        ///
        /// <para>A Guard is per-connection: the caller discards it when the connection closes, so the
        /// states map is freed with the connection. There is NO eviction of terminal (committed /
        /// abandoned) entries — evicting one would re-admit a replayed signed StreamOpen reusing that id
        /// as a fresh idle -&gt; open, the exact replay the terminal states exist to refuse.</para>
        /// </summary>
        public sealed class Guard
        {
            private readonly object _lock = new object();
            private readonly Dictionary<string, State> _states = new Dictionary<string, State>();

            private static string Key(byte[] streamId) => Hex.Encode(streamId);

            // Current state of streamId; an id never seen is idle (design.md §10: "idle (no stream open
            // for this stream id)"). Caller must hold _lock.
            private State StateLocked(byte[] streamId)
            {
                return _states.TryGetValue(Key(streamId), out State s) ? s : State.Idle;
            }

            /// <summary>Current lifecycle state of streamId (for callers and tests); an id never seen is
            /// idle.</summary>
            public State GetState(byte[] streamId)
            {
                lock (_lock)
                {
                    return StateLocked(streamId);
                }
            }

            /// <summary>
            /// Validates a StreamOpen against the state table: only idle admits StreamOpen, and then only
            /// when the effect is authorized (R-10.3) — "idle | StreamOpen (effect authorized) -&gt; open"
            /// and "idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)". A stream
            /// already open, committed, or abandoned rejects StreamStateError — an abandoned or committed
            /// stream id is never re-admitted. On EffectNotAuthorized the stream stays idle, since the
            /// open never took effect; on StreamStateError the existing state is untouched; only a
            /// successful open advances to open.
            /// </summary>
            public void Open(StreamOpen o, long grantedMax)
            {
                lock (_lock)
                {
                    if (StateLocked(o.StreamID) != State.Idle)
                    {
                        throw new NaalpException("StreamStateError", "stream event is illegal for the current stream state (§10 state table)");
                    }
                    OpenStream(o, grantedMax); // throws EffectNotAuthorized on failure; state stays idle
                    _states[Key(o.StreamID)] = State.Open;
                }
            }

            /// <summary>Validates a data chunk's arrival against the state table: only open admits a
            /// chunk; idle, committed, or abandoned reject it StreamStateError. A chunk never changes the
            /// stream's state — it stays open.</summary>
            public void Chunk(byte[] streamId)
            {
                lock (_lock)
                {
                    if (StateLocked(streamId) != State.Open)
                    {
                        throw new NaalpException("StreamStateError", "stream event is illegal for the current stream state (§10 state table)");
                    }
                }
            }

            /// <summary>Validates a StreamCheckpoint's arrival against the state table: only open admits
            /// it; idle, committed, or abandoned reject it StreamStateError. A checkpoint never changes
            /// the stream's state — it stays open.</summary>
            public void Checkpoint(byte[] streamId)
            {
                lock (_lock)
                {
                    if (StateLocked(streamId) != State.Open)
                    {
                        throw new NaalpException("StreamStateError", "stream event is illegal for the current stream state (§10 state table)");
                    }
                }
            }

            /// <summary>
            /// Validates a StreamCommit against the state table: only open admits it — idle, committed, or
            /// abandoned reject it StreamStateError BEFORE the digest is even inspected. When open, the
            /// commitment is verified against the delivered chunks (R-10.2): a digest mismatch rejects
            /// StreamDigestMismatch and leaves the stream open (this row rejects without advancing, so a
            /// corrected commit may still follow), and a matching digest advances the stream to committed.
            /// </summary>
            public void Commit(StreamCommit commit, IEnumerable<Chunk> chunks)
            {
                lock (_lock)
                {
                    if (StateLocked(commit.StreamID) != State.Open)
                    {
                        throw new NaalpException("StreamStateError", "stream event is illegal for the current stream state (§10 state table)");
                    }
                    VerifyCommit(commit, chunks); // throws StreamDigestMismatch/TooManyChunks; state stays open
                    _states[Key(commit.StreamID)] = State.Committed;
                }
            }

            /// <summary>
            /// Fires the idle/commit timer's expiry for streamId (§ Timers): an open stream that has not
            /// committed within its interval transitions open -&gt; abandoned, a terminal state that
            /// rejects every subsequent event with StreamStateError — including a StreamOpen reusing the
            /// id, so an abandoned stream is never re-admitted. Only an open stream can be abandoned: the
            /// timer clears when a StreamCommit transitions the stream to committed, so a correct caller
            /// fires Expire only while the stream is open; Expire on an idle, committed, or
            /// already-abandoned stream is rejected StreamStateError with no state change (fail-closed).
            /// The Guard holds no clock — the caller decides when the interval has elapsed.
            /// </summary>
            public void Expire(byte[] streamId)
            {
                lock (_lock)
                {
                    if (StateLocked(streamId) != State.Open)
                    {
                        throw new NaalpException("StreamStateError", "stream event is illegal for the current stream state (§10 state table)");
                    }
                    _states[Key(streamId)] = State.Abandoned;
                }
            }
        }

        // ---- signatures (real deterministic ML-DSA over the body, demonstrated in isolation) --------

        /// <summary>A raw deterministic ML-DSA signature over the StreamOpen body (matches
        /// impl/go/streaming).</summary>
        public static byte[] SignOpen(StreamOpen o, int alg, byte[] seed) => Cose.MldsaSign(alg, seed, o.Bytes());

        /// <summary>A raw deterministic ML-DSA signature over the StreamCommit body — the ONE
        /// end-commitment signature that covers the whole stream (R-10.2).</summary>
        public static byte[] SignCommit(StreamCommit c, int alg, byte[] seed) => Cose.MldsaSign(alg, seed, c.Bytes());

        /// <summary>A raw deterministic ML-DSA signature over the StreamCheckpoint body.</summary>
        public static byte[] SignCheckpoint(StreamCheckpoint c, int alg, byte[] seed) => Cose.MldsaSign(alg, seed, c.Bytes());

        /// <summary>Verify a raw StreamOpen signature under the stream owner's public key.</summary>
        public static bool VerifyOpenSig(StreamOpen o, int alg, byte[] pubkey, byte[] sig)
            => Cose.MldsaVerify(alg, pubkey, o.Bytes(), sig);

        /// <summary>Verify a raw StreamCommit signature under the stream owner's public key.</summary>
        public static bool VerifyCommitSig(StreamCommit c, int alg, byte[] pubkey, byte[] sig)
            => Cose.MldsaVerify(alg, pubkey, c.Bytes(), sig);

        /// <summary>Verify a raw StreamCheckpoint signature under the stream owner's public key.</summary>
        public static bool VerifyCheckpointSig(StreamCheckpoint c, int alg, byte[] pubkey, byte[] sig)
            => Cose.MldsaVerify(alg, pubkey, c.Bytes(), sig);
    }
}
