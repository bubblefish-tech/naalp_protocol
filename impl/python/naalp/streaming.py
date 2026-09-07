# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C9 native streaming with a single signed per-stream commitment for the Python SDK (design.md §10;
R-10.1..10.6).

A native stream is three signed objects plus unsigned chunks: StreamOpen establishes the stream's
identity, effect, and (where it causes an effect) its approval binding, refusing a stream whose effect
is not authorized before any chunk (§10.2, R-10.3); the chunks are raw data frames the transport AEAD
already authenticates, so N-AALP does NOT sign them individually (R-10.2); StreamCommit carries a
rolling SHA-384 over the chunks in absolute-offset order, making the whole stream non-repudiable with
one signature, not N (§10.2). Optional signed StreamCheckpoints let a verifier confirm a prefix
without the end. Altering any delivered byte invalidates the commitment (StreamDigestMismatch).

Native streaming is channel 0x000C and is kept distinct from foreign streamed carriage (§13, 0x000D);
this module never carries a foreign protocol (R-10.6). Ported from impl/go/streaming; graded against
vectors/stream/cases.json (the oracle directory is `stream`, not `streaming`). The StreamOpen /
StreamCommit / StreamCheckpoint signatures are real deterministic ML-DSA-65 (a raw signature over the
body) but not corpus-graded.
"""
import hashlib
import threading

from . import cbor, cose, policy
from .cbor import U, B, M
from ._wire_constants_gen import MAX_STREAM_CHUNKS

# StreamChannel is the N-PAMP Stream channel native streams run on; foreign streamed carriage uses the
# distinct Bridge channel 0x000D (R-10.6).
STREAM_CHANNEL = 0x000C


class StreamError(ValueError):
    """A named, fail-closed streaming error; .kind is the stable error kind (§15)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


class Chunk:
    """One absolute-offset-positioned data frame of a stream (unsigned; the transport authenticates
    it)."""

    __slots__ = ("offset", "data")

    def __init__(self, offset, data):
        self.offset = int(offset)
        self.data = bytes(data)


class StreamDigest:
    """The rolling SHA-384 commitment accumulator (design.md §10.2). update() feeds chunks in
    absolute-offset order; digest_so_far() returns the SHA-384 of everything fed so far WITHOUT ending
    the stream, which is exactly a checkpoint's digest_so_far (SHA-384 .digest() does not finalize, so
    streaming continues after a checkpoint)."""

    __slots__ = ("_h",)

    def __init__(self):
        self._h = hashlib.sha384()

    def update(self, chunk):
        """Feed the next chunk's data into the rolling digest."""
        self._h.update(bytes(chunk))

    def digest_so_far(self):
        """The SHA-384 of all data fed so far; the underlying state is unchanged, so streaming
        continues after a checkpoint."""
        return self._h.digest()


def commit_digest(chunks):
    """Compute the rolling SHA-384 over chunks in absolute-offset order. Input order is irrelevant --
    the chunks are sorted by offset before folding -- so a delivered stream and a reordered delivery of
    the same frames yield the same commitment, while swapping which bytes sit at which offset does
    not."""
    sd = StreamDigest()
    for c in sorted(chunks, key=lambda c: c.offset):
        sd.update(c.data)
    return sd.digest_so_far()


class StreamOpen:
    """Establishes a stream's identity, effect, optional approval binding, and sub-stream id
    (design.md §10.2). It is signed."""

    __slots__ = ("stream_id", "effect", "approval", "substream")

    def __init__(self, stream_id, effect, approval, substream):
        self.stream_id = bytes(stream_id)
        self.effect = int(effect)
        self.approval = None if approval is None else bytes(approval)
        self.substream = int(substream)

    def bytes(self):
        """Deterministic-CBOR encoding {1: stream_id, 2: effect, 3: approval?, 4: substream}; field 3
        is present only when an approval binding exists (encode emits canonical key order regardless of
        insertion order)."""
        pairs = [
            (U(1), B(self.stream_id)),
            (U(2), U(self.effect)),
            (U(4), U(self.substream)),
        ]
        if self.approval is not None:
            pairs.append((U(3), B(self.approval)))
        return cbor.encode(M(pairs))


class StreamCommit:
    """Carries the completed stream's rolling-SHA-384 commitment (design.md §10.2)."""

    __slots__ = ("stream_id", "digest")

    def __init__(self, stream_id, digest):
        self.stream_id = bytes(stream_id)
        self.digest = bytes(digest)

    def bytes(self):
        """Deterministic-CBOR encoding {1: stream_id, 2: digest}."""
        return cbor.encode(M([(U(1), B(self.stream_id)), (U(2), B(self.digest))]))


class StreamCheckpoint:
    """Carries a mid-stream commitment over the prefix through through_offset (design.md §10.2)."""

    __slots__ = ("stream_id", "through_offset", "digest_so_far")

    def __init__(self, stream_id, through_offset, digest_so_far):
        self.stream_id = bytes(stream_id)
        self.through_offset = int(through_offset)
        self.digest_so_far = bytes(digest_so_far)

    def bytes(self):
        """Deterministic-CBOR encoding {1: stream_id, 2: through_offset, 3: digest_so_far}."""
        return cbor.encode(M([
            (U(1), B(self.stream_id)),
            (U(2), U(self.through_offset)),
            (U(3), B(self.digest_so_far)),
        ]))


def open_stream(o, granted_max):
    """Authorize a StreamOpen against the granted effect ceiling, refusing a stream whose effect
    exceeds it BEFORE any chunk (R-10.3). An unrecognized effect is treated as destructive (fail-closed,
    via the C5 policy). Returns None when the stream may proceed, else raises EffectNotAuthorized."""
    if not policy.authorizes(granted_max, policy.normalize_effect(o.effect)):
        raise StreamError("EffectNotAuthorized", "stream effect exceeds the granted capability ceiling")
    return None


def verify_commit(commit, chunks):
    """Recompute the rolling digest over the delivered chunks and compare it to the signed commitment;
    any altered or reordered byte yields StreamDigestMismatch (R-10.2). Returns None on a match."""
    if len(chunks) > MAX_STREAM_CHUNKS:  # stream chunk-count bound (§3.4, R7)
        raise StreamError("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)")
    if commit.digest != commit_digest(chunks):
        raise StreamError("StreamDigestMismatch", "stream commitment digest does not match the recomputed digest")
    return None


def verify_checkpoint(cp, prefix):
    """Confirm a prefix without the end (design.md §10.2): the prefix chunks must be contiguous from
    offset 0 and total exactly through_offset bytes, and their rolling digest must equal the
    checkpoint's digest_so_far. Otherwise StreamDigestMismatch. Returns None on a clean confirmation."""
    if len(prefix) > MAX_STREAM_CHUNKS:  # stream chunk-count bound (§3.4, R7)
        raise StreamError("TooManyChunks", "stream chunk count exceeds the maximum (§3.4, R7)")
    total = 0
    for c in sorted(prefix, key=lambda c: c.offset):
        if c.offset != total:
            raise StreamError("StreamDigestMismatch", "non-contiguous prefix")
        total += len(c.data)
    if total != cp.through_offset:
        raise StreamError("StreamDigestMismatch", "prefix length does not match through_offset")
    if cp.digest_so_far != commit_digest(prefix):
        raise StreamError("StreamDigestMismatch", "prefix digest does not match the checkpoint")
    return None


# ---- signatures (real deterministic ML-DSA over the body, demonstrated in isolation) ----------

def sign_open(o, alg, seed):
    """A raw deterministic ML-DSA signature over the StreamOpen body (matches impl/go/streaming)."""
    return cose.mldsa_sign(alg, seed, o.bytes())


def sign_commit(c, alg, seed):
    """A raw deterministic ML-DSA signature over the StreamCommit body -- the ONE end-commitment
    signature that covers the whole stream (R-10.2)."""
    return cose.mldsa_sign(alg, seed, c.bytes())


def sign_checkpoint(c, alg, seed):
    """A raw deterministic ML-DSA signature over the StreamCheckpoint body."""
    return cose.mldsa_sign(alg, seed, c.bytes())


def verify_open_sig(o, alg, pubkey, sig):
    """Verify a raw StreamOpen signature under the stream owner's public key."""
    return cose.mldsa_verify(alg, pubkey, o.bytes(), sig)


def verify_commit_sig(c, alg, pubkey, sig):
    """Verify a raw StreamCommit signature under the stream owner's public key."""
    return cose.mldsa_verify(alg, pubkey, c.bytes(), sig)


def verify_checkpoint_sig(c, alg, pubkey, sig):
    """Verify a raw StreamCheckpoint signature under the stream owner's public key."""
    return cose.mldsa_verify(alg, pubkey, c.bytes(), sig)


# ---- stream state guard (design.md §10 state table + § Timers; naalp-error code 49) ------------

# STATE_*: a stream's lifecycle state (design.md §10, the stream state table): idle (no stream
# open for this stream id), open, committed, or abandoned (the terminal state an open stream
# enters when its idle/commit timer expires, § Timers -- like committed, it admits no further
# event and its stream id is never re-admitted). Mirrors impl/go/streaming's State enum, following
# the same closed-int-constant idiom this SDK already uses for policy.py's effect vocabulary.
STATE_IDLE = 0
STATE_OPEN = 1
STATE_COMMITTED = 2
STATE_ABANDONED = 3

_STATE_NAMES = ["idle", "open", "committed", "abandoned"]


def state_name(s):
    """Name a State (Go State.String): "idle", "open", "committed", "abandoned", or "unknown"."""
    return _STATE_NAMES[s] if 0 <= s <= 3 else "unknown"


class Guard:
    """Enforces the stream state machine across concurrently open streams, keyed by stream id
    (design.md §10, the stream state table; mirrors impl/go/streaming's Guard). It tracks only the
    current lifecycle state (idle/open/committed/abandoned), never chunk data, and rejects an event
    the state table does not admit for the stream's current state BEFORE any state change -- a
    rejected event leaves the state exactly as it was (fail-closed, no partial transition). It
    holds no clock: the idle/commit timer (§ Timers) lives in the caller, which calls expire() when
    a stream's interval elapses; the numeric interval is a deployment policy, not a protocol
    constant.

    A Guard is per-connection: the caller discards it when the connection closes, so the states
    dict is freed with the connection. There is NO eviction of terminal (committed/abandoned)
    entries -- evicting one would re-admit a replayed signed StreamOpen reusing that id as a fresh
    idle -> open, the exact replay the terminal states exist to refuse. Retained entries are
    therefore bounded by the number of streams the connection actually opened, each of which cost
    the peer a full StreamOpen signature to create."""

    __slots__ = ("_lock", "_states")

    def __init__(self):
        self._lock = threading.Lock()
        self._states = {}

    def state(self, stream_id):
        """The current lifecycle state of stream_id (for callers and tests); an id never seen is
        STATE_IDLE (design.md §10: "idle (no stream open for this stream id)")."""
        with self._lock:
            return self._states.get(bytes(stream_id), STATE_IDLE)

    def open(self, o, granted_max):
        """Validate a StreamOpen against the state table: only idle admits StreamOpen, and then
        only when the effect is authorized (R-10.3) -- "idle | StreamOpen (effect authorized) ->
        open" and "idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)". A
        stream already open, committed, or abandoned rejects StreamStateError (committed+StreamOpen
        and abandoned+StreamOpen fall under the table's unlisted-pair default -- an abandoned or
        committed stream id is never re-admitted). On EffectNotAuthorized the stream stays idle,
        since the open never took effect; on StreamStateError the existing state is untouched; only
        a successful open advances to open. Raises StreamError."""
        sid = bytes(o.stream_id)
        with self._lock:
            if self._states.get(sid, STATE_IDLE) != STATE_IDLE:
                raise StreamError("StreamStateError",
                                   "stream event is illegal for the current stream state (§10 state table)")
            open_stream(o, granted_max)  # raises EffectNotAuthorized; state stays idle on failure
            self._states[sid] = STATE_OPEN
        return None

    def chunk(self, stream_id):
        """Validate a data chunk's arrival against the state table: only open admits a chunk
        ("open | chunk -> open"); idle, committed, or abandoned reject it StreamStateError
        (committed+chunk is listed explicitly; idle+chunk and abandoned+chunk fall under the
        unlisted-pair default). A chunk never changes the stream's state -- it stays open."""
        sid = bytes(stream_id)
        with self._lock:
            if self._states.get(sid, STATE_IDLE) != STATE_OPEN:
                raise StreamError("StreamStateError",
                                   "stream event is illegal for the current stream state (§10 state table)")
        return None

    def checkpoint(self, stream_id):
        """Validate a StreamCheckpoint's arrival against the state table: only open admits it
        ("open | StreamCheckpoint -> open"); idle, committed, or abandoned reject it
        StreamStateError (committed+StreamCheckpoint is listed explicitly; the others fall under
        the unlisted-pair default). A checkpoint never changes the stream's state -- it stays
        open."""
        sid = bytes(stream_id)
        with self._lock:
            if self._states.get(sid, STATE_IDLE) != STATE_OPEN:
                raise StreamError("StreamStateError",
                                   "stream event is illegal for the current stream state (§10 state table)")
        return None

    def commit(self, commit_obj, chunks):
        """Validate a StreamCommit against the state table: only open admits it -- idle, committed,
        or abandoned reject it StreamStateError before the digest is even inspected (committed+
        StreamCommit is listed explicitly; the others fall under the unlisted-pair default). When
        open, the commitment is verified against the delivered chunks (R-10.2): a digest mismatch
        (StreamDigestMismatch) leaves the stream open (this table row rejects without advancing, so
        a corrected commit may still follow), and a digest match advances the stream to
        committed."""
        sid = bytes(commit_obj.stream_id)
        with self._lock:
            if self._states.get(sid, STATE_IDLE) != STATE_OPEN:
                raise StreamError("StreamStateError",
                                   "stream event is illegal for the current stream state (§10 state table)")
            verify_commit(commit_obj, chunks)  # raises StreamDigestMismatch/TooManyChunks; stays open on failure
            self._states[sid] = STATE_COMMITTED
        return None

    def expire(self, stream_id):
        """Fire the idle/commit timer's expiry for stream_id (§ Timers): an open stream that has
        not committed within its interval transitions "open -> abandoned", a terminal state that
        rejects every subsequent event with StreamStateError -- including a StreamOpen reusing the
        id, so an abandoned stream is never re-admitted and nothing it delivered without a
        StreamCommit is non-repudiable. Only an open stream can be abandoned: the timer clears when
        a StreamCommit transitions the stream to committed (§ Timers), so a correct caller fires
        expire() only while the stream is open; expire() on an idle, committed, or already-
        abandoned stream is rejected StreamStateError with no state change (fail-closed). The Guard
        holds no clock -- the caller decides when the interval has elapsed; the interval itself is
        a deployment policy."""
        sid = bytes(stream_id)
        with self._lock:
            if self._states.get(sid, STATE_IDLE) != STATE_OPEN:
                raise StreamError("StreamStateError",
                                   "stream event is illegal for the current stream state (§10 state table)")
            self._states[sid] = STATE_ABANDONED
        return None
