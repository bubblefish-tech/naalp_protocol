<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C9 native streaming with a single signed per-stream commitment for the PHP SDK (design.md §10;
 * R-10.1..10.6).
 *
 * A native stream is three signed objects plus unsigned chunks: StreamOpen establishes the stream's
 * identity, effect, and (where it causes an effect) its approval binding, refusing a stream whose effect
 * is not authorized BEFORE any chunk (§10.2, R-10.3); the chunks are raw data frames the transport AEAD
 * already authenticates, so N-AALP does NOT sign them individually (R-10.2); StreamCommit carries a
 * rolling SHA-384 over the chunks in absolute-offset order, making the whole stream non-repudiable with
 * ONE signature, not N (§10.2). Optional signed StreamCheckpoints let a verifier confirm a prefix
 * without the end. Altering any delivered byte invalidates the commitment (StreamDigestMismatch).
 *
 * Native streaming is channel 0x000C and is kept distinct from foreign streamed carriage (§13, 0x000D);
 * this module never carries a foreign protocol (R-10.6). An independent transcription of
 * impl/go/streaming (cross-read against impl/python/naalp/streaming.py), graded against the shared
 * vectors/stream/cases.json (the oracle directory is `stream`, not `streaming`).
 *
 * CRYPTO SCOPE (PURE-ONLY): the corpus-graded deliverable — the rolling commitment, the checkpoint
 * digests, and the StreamOpen/Commit/Checkpoint bodies — is pure and complete here. PHP cannot
 * deterministically sign or verify ML-DSA (FIPS 204); signCommit/signOpen/signCheckpoint therefore use a
 * real Ed25519 (RFC 8032) signature (ext-sodium) to demonstrate the ONE end-commitment signature in
 * isolation, and the matching verify*Sig verify it with real crypto.
 *
 * CONCURRENCY SCOPE: PHP CLI is single-threaded (no pthreads), so the reference's concurrent-stream
 * property (R-10.5) is not reproduced here; the offset-ordered commitment (which makes delivery order
 * irrelevant) is the property this port demonstrates.
 */

declare(strict_types=1);

namespace Naalp;

/**
 * A named, fail-closed streaming error; $kind mirrors the Go/Rust/Python/Ruby error kind
 * (StreamDigestMismatch). An over-ceiling effect at open reuses the shared Naalp\EffectNotAuthorized
 * (kind "EffectNotAuthorized").
 */
class StreamError extends \RuntimeException
{
    public string $kind;

    public function __construct(string $kind, string $msg = "")
    {
        $this->kind = $kind;
        parent::__construct($msg === "" ? $kind : "$kind: $msg");
    }
}

/** One absolute-offset-positioned data frame of a stream (unsigned; the transport authenticates it). */
final class Chunk
{
    public int $offset;
    public string $data;

    public function __construct(int $offset, string $data)
    {
        $this->offset = $offset;
        $this->data = $data;
    }
}

/**
 * The rolling SHA-384 commitment accumulator (design.md §10.2). update() feeds chunks in absolute-offset
 * order; digestSoFar() returns the SHA-384 of everything fed so far WITHOUT ending the stream — it copies
 * the running hash context and finalizes the copy, so the stream continues after a checkpoint, which is
 * exactly a checkpoint's digest_so_far.
 */
final class StreamDigest
{
    /** @var \HashContext */
    private $ctx;

    public function __construct()
    {
        $this->ctx = \hash_init('sha384');
    }

    /** Feed the next chunk's data into the rolling digest. */
    public function update(string $chunk): void
    {
        \hash_update($this->ctx, $chunk);
    }

    /** The SHA-384 of all data fed so far; the underlying state is unchanged (a copy is finalized). */
    public function digestSoFar(): string
    {
        return \hash_final(\hash_copy($this->ctx), true);
    }
}

/** Establishes a stream's identity, effect, optional approval binding, and sub-stream id (§10.2). Signed. */
final class StreamOpen
{
    public string $streamId;
    public int $effect;
    public ?string $approval; // content id of the approval binding; null when the stream causes no effect
    public int $substream;

    public function __construct(string $streamId, int $effect, ?string $approval, int $substream)
    {
        $this->streamId = $streamId;
        $this->effect = $effect;
        $this->approval = $approval;
        $this->substream = $substream;
    }

    /**
     * Deterministic-CBOR encoding {1: stream_id, 2: effect, 3: approval?, 4: substream}; field 3 is
     * present only when an approval binding exists (encode emits canonical key order regardless of
     * insertion order).
     */
    public function bytes(): string
    {
        $pairs = [
            [new U(1), new B($this->streamId)],
            [new U(2), new U($this->effect)],
            [new U(4), new U($this->substream)],
        ];
        if ($this->approval !== null) {
            $pairs[] = [new U(3), new B($this->approval)];
        }
        return Cbor::encode(new M($pairs));
    }
}

/** Carries the completed stream's rolling-SHA-384 commitment (design.md §10.2). */
final class StreamCommit
{
    public string $streamId;
    public string $digest;

    public function __construct(string $streamId, string $digest)
    {
        $this->streamId = $streamId;
        $this->digest = $digest;
    }

    /** Deterministic-CBOR encoding {1: stream_id, 2: digest}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->streamId)],
            [new U(2), new B($this->digest)],
        ]));
    }
}

/** Carries a mid-stream commitment over the prefix through $throughOffset (design.md §10.2). */
final class StreamCheckpoint
{
    public string $streamId;
    public int $throughOffset;
    public string $digestSoFar;

    public function __construct(string $streamId, int $throughOffset, string $digestSoFar)
    {
        $this->streamId = $streamId;
        $this->throughOffset = $throughOffset;
        $this->digestSoFar = $digestSoFar;
    }

    /** Deterministic-CBOR encoding {1: stream_id, 2: through_offset, 3: digest_so_far}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->streamId)],
            [new U(2), new U($this->throughOffset)],
            [new U(3), new B($this->digestSoFar)],
        ]));
    }
}

final class Streaming
{
    /**
     * The N-PAMP Stream channel native streams run on; foreign streamed carriage uses the distinct
     * Bridge channel 0x000D (R-10.6).
     */
    public const STREAM_CHANNEL = 0x000C;

    /** Start an empty rolling commitment. */
    public static function newStreamDigest(): StreamDigest
    {
        return new StreamDigest();
    }

    /**
     * Compute the rolling SHA-384 over chunks in absolute-offset order. Input order is irrelevant — the
     * chunks are sorted by offset before folding — so a delivered stream and a reordered delivery of the
     * same frames yield the same commitment, while swapping which bytes sit at which offset does not.
     *
     * @param array<int,Chunk> $chunks
     */
    public static function commitDigest(array $chunks): string
    {
        $sorted = $chunks;
        \usort($sorted, static fn(Chunk $a, Chunk $b): int => $a->offset <=> $b->offset);
        $sd = new StreamDigest();
        foreach ($sorted as $c) {
            $sd->update($c->data);
        }
        return $sd->digestSoFar();
    }

    /**
     * Authorize a StreamOpen against the granted effect ceiling, refusing a stream whose effect exceeds
     * it BEFORE any chunk (R-10.3). An unrecognized effect is treated as destructive (fail-closed, via
     * the C5 policy). Returns on success; throws EffectNotAuthorized otherwise.
     */
    public static function openStream(StreamOpen $o, int $grantedMax): void
    {
        if (!Policy::authorizes($grantedMax, Policy::normalizeEffect($o->effect))) {
            throw new EffectNotAuthorized("stream effect exceeds the granted capability ceiling");
        }
    }

    /**
     * Recompute the rolling digest over the delivered chunks and compare it to the signed commitment; any
     * altered or reordered byte yields StreamDigestMismatch (R-10.2). Returns on a match.
     *
     * @param array<int,Chunk> $chunks
     */
    public static function verifyCommit(StreamCommit $commit, array $chunks): void
    {
        if (\count($chunks) > WireConstants::MAX_STREAM_CHUNKS) { // stream chunk-count bound (§3.4, R7)
            throw new StreamError("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)");
        }
        if (!\hash_equals($commit->digest, self::commitDigest($chunks))) {
            throw new StreamError("StreamDigestMismatch", "stream commitment digest does not match the recomputed digest");
        }
    }

    /**
     * Confirm a prefix WITHOUT the end (design.md §10.2): the prefix chunks must be contiguous from
     * offset 0 and total exactly $throughOffset bytes, and their rolling digest must equal the
     * checkpoint's digest_so_far. Otherwise StreamDigestMismatch. Returns on a clean confirmation.
     *
     * @param array<int,Chunk> $prefix
     */
    public static function verifyCheckpoint(StreamCheckpoint $cp, array $prefix): void
    {
        if (\count($prefix) > WireConstants::MAX_STREAM_CHUNKS) { // stream chunk-count bound (§3.4, R7)
            throw new StreamError("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)");
        }
        $sorted = $prefix;
        \usort($sorted, static fn(Chunk $a, Chunk $b): int => $a->offset <=> $b->offset);
        $total = 0;
        foreach ($sorted as $c) {
            if ($c->offset !== $total) {
                throw new StreamError("StreamDigestMismatch", "non-contiguous prefix");
            }
            $total += \strlen($c->data);
        }
        if ($total !== $cp->throughOffset) {
            throw new StreamError("StreamDigestMismatch", "prefix length does not match through_offset");
        }
        if (!\hash_equals($cp->digestSoFar, self::commitDigest($prefix))) {
            throw new StreamError("StreamDigestMismatch", "prefix digest does not match the checkpoint");
        }
    }

    // ---- signatures (real Ed25519 over the body, demonstrated in isolation) ----------------------

    /** A raw Ed25519 signature over the StreamOpen body (the reference signs with ML-DSA). */
    public static function signOpen(StreamOpen $o, string $seed): string
    {
        return Cose::ed25519Sign($seed, $o->bytes());
    }

    /**
     * A raw Ed25519 signature over the StreamCommit body — the ONE end-commitment signature that covers
     * the whole stream (R-10.2).
     */
    public static function signCommit(StreamCommit $c, string $seed): string
    {
        return Cose::ed25519Sign($seed, $c->bytes());
    }

    /** A raw Ed25519 signature over the StreamCheckpoint body. */
    public static function signCheckpoint(StreamCheckpoint $c, string $seed): string
    {
        return Cose::ed25519Sign($seed, $c->bytes());
    }

    /** Verify a raw StreamOpen signature under the stream owner's public key. */
    public static function verifyOpenSig(StreamOpen $o, string $pubkey, string $sig): bool
    {
        return Cose::ed25519Verify($pubkey, $o->bytes(), $sig);
    }

    /** Verify a raw StreamCommit signature under the stream owner's public key. */
    public static function verifyCommitSig(StreamCommit $c, string $pubkey, string $sig): bool
    {
        return Cose::ed25519Verify($pubkey, $c->bytes(), $sig);
    }

    /** Verify a raw StreamCheckpoint signature under the stream owner's public key. */
    public static function verifyCheckpointSig(StreamCheckpoint $c, string $pubkey, string $sig): bool
    {
        return Cose::ed25519Verify($pubkey, $c->bytes(), $sig);
    }
}

/**
 * A stream's lifecycle state (design.md §10, the stream state table): idle (no stream open for
 * this stream id), open, committed, or abandoned (the terminal state an open stream enters when
 * its idle/commit timer expires, § Timers — like committed, it admits no further event and its
 * stream id is never re-admitted). An independent transcription of impl/go/streaming's State.
 */
final class State
{
    public const IDLE = 0;
    public const OPEN = 1;
    public const COMMITTED = 2;
    public const ABANDONED = 3;

    /** The lowercase name for a state value ("idle", "open", "committed", "abandoned", or "unknown"). */
    public static function name(int $s): string
    {
        switch ($s) {
            case self::IDLE:
                return "idle";
            case self::OPEN:
                return "open";
            case self::COMMITTED:
                return "committed";
            case self::ABANDONED:
                return "abandoned";
            default:
                return "unknown";
        }
    }
}

/**
 * Guard enforces the stream state machine across concurrently open streams, keyed by stream id
 * (design.md §10 state table; § Timers). It tracks ONLY the current lifecycle state
 * (idle/open/committed/abandoned), never chunk data, and rejects an event the state table does
 * not admit for the stream's current state BEFORE any state change — a rejected event leaves the
 * state exactly as it was (fail-closed, no partial transition). It holds no clock: the
 * idle/commit timer (§ Timers) lives in the caller, which calls expire() when a stream's interval
 * elapses; the numeric interval is a deployment policy, not a protocol constant.
 *
 * A Guard is per-connection: the caller discards it when the connection closes, so the states map
 * is freed with the connection. There is NO eviction of terminal (committed / abandoned)
 * entries — evicting one would re-admit a replayed signed StreamOpen reusing that id as a fresh
 * idle -> open, the exact replay the terminal states exist to refuse. Retained entries are
 * therefore bounded by the number of streams the connection actually opened, each of which cost
 * the peer a full StreamOpen signature to create.
 *
 * CONCURRENCY SCOPE: PHP CLI is single-threaded (no pthreads; see the module docblock above), so
 * this port carries no lock — the Go reference's mutex exists to guard concurrent goroutines, a
 * property this single-threaded runtime does not have.
 *
 * An independent transcription of impl/go/streaming's Guard.
 */
final class Guard
{
    /** @var array<string,int> 'x'+hex(stream id) -> State::* value (never a numeric-looking PHP array key). */
    private array $states = [];

    /** A key for $states that can never be mistaken for a numeric PHP array key (see Envelope.php). */
    private static function key(string $streamId): string
    {
        return 'x' . \bin2hex($streamId);
    }

    /** The current state of $streamId; an id never seen is idle (§10: "idle (no stream open for this stream id)"). */
    public function state(string $streamId): int
    {
        return $this->states[self::key($streamId)] ?? State::IDLE;
    }

    /**
     * Validate a StreamOpen against the state table: only idle admits StreamOpen, and then only
     * when the effect is authorized (R-10.3) — "idle | StreamOpen (effect authorized) -> open"
     * and "idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)". A stream
     * already open, committed, or abandoned is rejected StreamStateError (committed+StreamOpen and
     * abandoned+StreamOpen fall under the table's unlisted-pair default — an abandoned or
     * committed stream id is never re-admitted). On EffectNotAuthorized the stream stays idle,
     * since the open never took effect; on StreamStateError the existing state is untouched; only
     * a successful open advances to open.
     */
    public function open(StreamOpen $o, int $grantedMax): void
    {
        if ($this->state($o->streamId) !== State::IDLE) {
            throw new StreamError("StreamStateError", "a StreamOpen is only admitted while idle (§10 state table)");
        }
        Streaming::openStream($o, $grantedMax); // throws EffectNotAuthorized; the stream stays idle
        $this->states[self::key($o->streamId)] = State::OPEN;
    }

    /**
     * Validate a data chunk's arrival against the state table: only open admits a chunk ("open |
     * chunk -> open"); idle, committed, or abandoned reject it StreamStateError (committed+chunk
     * is listed explicitly; idle+chunk and abandoned+chunk fall under the unlisted-pair default).
     * A chunk never changes the stream's state — it stays open.
     */
    public function chunk(string $streamId): void
    {
        if ($this->state($streamId) !== State::OPEN) {
            throw new StreamError("StreamStateError", "a chunk is only admitted while open (§10 state table)");
        }
    }

    /**
     * Validate a StreamCheckpoint's arrival against the state table: only open admits it ("open |
     * StreamCheckpoint -> open"); idle, committed, or abandoned reject it StreamStateError
     * (committed+StreamCheckpoint is listed explicitly; the others fall under the unlisted-pair
     * default). A checkpoint never changes the stream's state — it stays open.
     */
    public function checkpoint(string $streamId): void
    {
        if ($this->state($streamId) !== State::OPEN) {
            throw new StreamError("StreamStateError", "a checkpoint is only admitted while open (§10 state table)");
        }
    }

    /**
     * Validate a StreamCommit against the state table: only open admits it — idle, committed, or
     * abandoned reject it StreamStateError BEFORE the digest is even inspected (committed+
     * StreamCommit is listed explicitly; the others fall under the unlisted-pair default). When
     * open, the commitment is verified against the delivered chunks (R-10.2): "open | StreamCommit
     * (digest mismatch) | reject (StreamDigestMismatch)" leaves the stream open (this table row
     * rejects without advancing, so a corrected commit may still follow), and "open | StreamCommit
     * (digest matches) -> committed" advances the stream to committed.
     *
     * @param array<int,Chunk> $chunks
     */
    public function commit(StreamCommit $commit, array $chunks): void
    {
        if ($this->state($commit->streamId) !== State::OPEN) {
            throw new StreamError("StreamStateError", "a commit is only admitted while open (§10 state table)");
        }
        Streaming::verifyCommit($commit, $chunks); // throws StreamDigestMismatch/TooManyChunks; stays open on failure
        $this->states[self::key($commit->streamId)] = State::COMMITTED;
    }

    /**
     * Fire the idle/commit timer's expiry for $streamId (§ Timers): an open stream that has not
     * committed within its interval transitions "open -> abandoned", a terminal state that then
     * rejects every subsequent event with StreamStateError — including a StreamOpen reusing the
     * id, so an abandoned stream is never re-admitted and nothing it delivered without a
     * StreamCommit is non-repudiable. Only an open stream can be abandoned: the timer clears when
     * a StreamCommit transitions the stream to committed (§ Timers), so a correct caller fires
     * expire() only while the stream is open; expire() on an idle, committed, or already-abandoned
     * stream is rejected StreamStateError with no state change (fail-closed). The Guard holds no
     * clock — the caller decides when the interval has elapsed; the interval itself is a
     * deployment policy.
     */
    public function expire(string $streamId): void
    {
        if ($this->state($streamId) !== State::OPEN) {
            throw new StreamError("StreamStateError", "expire is only admitted while open (§ Timers)");
        }
        $this->states[self::key($streamId)] = State::ABANDONED;
    }
}
