// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package streaming implements C9 — native streaming with a single signed per-stream
// commitment (design.md §10; requirements R-10.1..10.6).
//
// A native stream is three signed objects plus unsigned chunks: StreamOpen establishes the
// stream's identity, effect, and (where it causes an effect) its approval binding, refusing a
// stream whose effect is not authorized before any chunk (§10.2, R-10.3); the chunks are raw
// data frames the transport AEAD already authenticates, so N-AALP does NOT sign them
// individually (R-10.2); StreamCommit carries a rolling SHA-384 over the chunks in
// absolute-offset order, making the whole stream non-repudiable with one signature, not N
// (§10.2). Optional signed StreamCheckpoints let a verifier confirm a prefix without the end.
// Altering any delivered byte invalidates the commitment (StreamDigestMismatch). Native
// streaming is channel 0x000C and is kept distinct from foreign streamed carriage (§13,
// 0x000D); this package never carries a foreign protocol (R-10.6). Guard enforces the stream
// state table (idle -> open -> committed, with abandoned as the terminal state a StreamOpen
// leaves on the idle/commit timer's expiry) across concurrent streams, rejecting an event the
// table does not admit for the stream's current state with StreamStateError before any state
// change (§10 state table, § Timers; error code 49).
package streaming

import (
	"bytes"
	"crypto/sha512"
	"hash"
	"sort"
	"sync"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// StreamChannel is the N-PAMP Stream channel native streams run on; foreign streamed carriage
// uses the distinct Bridge channel 0x000D (R-10.6).
const StreamChannel uint64 = 0x000C

// ErrStreamDigestMismatch is returned when a commitment (or checkpoint) digest does not match
// the recomputed rolling digest.
var ErrStreamDigestMismatch = &cose.Error{Kind: "StreamDigestMismatch", Msg: "stream commitment digest does not match the recomputed rolling digest"}

// ErrTooManyChunks is returned when a stream presents more chunks than the maximum
// (design.md §3.4, R7): the stream chunk-count bound, a memory/verification-cost DoS guard.
var ErrTooManyChunks = &cose.Error{Kind: "TooManyChunks", Msg: "stream chunk count exceeds the maximum (§3.4, R7)"}

// Chunk is one absolute-offset-positioned data frame of a stream (unsigned; the transport
// authenticates it).
type Chunk struct {
	Offset uint64
	Data   []byte
}

// StreamDigest is the rolling SHA-384 commitment accumulator (design.md §10.2). Update feeds
// chunks in absolute-offset order; DigestSoFar returns the SHA-384 of everything fed so far
// without ending the stream, which is exactly a checkpoint's digest_so_far.
type StreamDigest struct {
	h hash.Hash
}

// NewStreamDigest starts an empty rolling commitment.
func NewStreamDigest() *StreamDigest { return &StreamDigest{h: sha512.New384()} }

// Update feeds the next chunk's data into the rolling digest.
func (s *StreamDigest) Update(chunk []byte) { s.h.Write(chunk) }

// DigestSoFar returns the SHA-384 of all data fed so far. Sum does not change the underlying
// state, so streaming continues after a checkpoint.
func (s *StreamDigest) DigestSoFar() []byte { return s.h.Sum(nil) }

// CommitDigest computes the rolling SHA-384 over chunks in absolute-offset order.
func CommitDigest(chunks []Chunk) []byte {
	sorted := append([]Chunk(nil), chunks...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Offset < sorted[j].Offset })
	sd := NewStreamDigest()
	for _, c := range sorted {
		sd.Update(c.Data)
	}
	return sd.DigestSoFar()
}

// StreamOpen establishes a stream's identity, effect, optional approval binding, and sub-stream
// id (design.md §10.2). It is signed.
type StreamOpen struct {
	StreamID  []byte
	Effect    uint64
	Approval  []byte // content id of the approval binding; nil when the stream causes no effect
	SubStream uint64
}

// Bytes is the deterministic-CBOR encoding {1: stream_id, 2: effect, 3: approval?, 4: substream};
// field 3 is present only when an approval binding exists.
func (o StreamOpen) Bytes() []byte {
	m := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(o.StreamID)},
		{K: cbor.Uint(2), V: cbor.Uint(o.Effect)},
		{K: cbor.Uint(4), V: cbor.Uint(o.SubStream)},
	}
	if o.Approval != nil {
		m = append(m, cbor.Pair{K: cbor.Uint(3), V: cbor.Bstr(o.Approval)})
	}
	b, _ := cbor.Encode(m) // Encode emits canonical key order regardless of append order
	return b
}

// StreamCommit carries the completed stream's rolling-SHA-384 commitment (design.md §10.2).
type StreamCommit struct {
	StreamID []byte
	Digest   []byte
}

// Bytes is the deterministic-CBOR encoding {1: stream_id, 2: digest}.
func (c StreamCommit) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(c.StreamID)},
		{K: cbor.Uint(2), V: cbor.Bstr(c.Digest)},
	})
	return b
}

// StreamCheckpoint carries a mid-stream commitment over the prefix through ThroughOffset
// (design.md §10.2).
type StreamCheckpoint struct {
	StreamID      []byte
	ThroughOffset uint64
	DigestSoFar   []byte
}

// Bytes is the deterministic-CBOR encoding {1: stream_id, 2: through_offset, 3: digest_so_far}.
func (c StreamCheckpoint) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(c.StreamID)},
		{K: cbor.Uint(2), V: cbor.Uint(c.ThroughOffset)},
		{K: cbor.Uint(3), V: cbor.Bstr(c.DigestSoFar)},
	})
	return b
}

// SignOpen, SignCommit, SignCheckpoint sign the respective bodies with the stream owner's key.
func SignOpen(o StreamOpen, s cose.Signer) ([]byte, error)     { return s.Sign(o.Bytes()) }
func SignCommit(c StreamCommit, s cose.Signer) ([]byte, error) { return s.Sign(c.Bytes()) }
func SignCheckpoint(c StreamCheckpoint, s cose.Signer) ([]byte, error) {
	return s.Sign(c.Bytes())
}

// OpenStream authorizes a StreamOpen against the granted effect ceiling, refusing a stream whose
// effect exceeds it BEFORE any chunk (R-10.3). An unrecognized effect is treated as destructive
// (fail-closed, via the C5 policy). Returns nil when the stream may proceed.
func OpenStream(o StreamOpen, grantedMax policy.Effect) error {
	if !grantedMax.Authorizes(policy.NormalizeEffect(o.Effect)) {
		return policy.ErrEffectNotAuthorized
	}
	return nil
}

// VerifyCommit recomputes the rolling digest over the delivered chunks and compares it to the
// signed commitment; any altered or reordered byte yields StreamDigestMismatch (R-10.2).
func VerifyCommit(commit StreamCommit, chunks []Chunk) error {
	if len(chunks) > envelope.MaxStreamChunks { // stream chunk-count bound (§3.4, R7)
		return ErrTooManyChunks
	}
	if !bytes.Equal(commit.Digest, CommitDigest(chunks)) {
		return ErrStreamDigestMismatch
	}
	return nil
}

// VerifyCheckpoint confirms a prefix without the end (design.md §10.2): the prefix chunks must be
// contiguous from offset 0 and total exactly ThroughOffset bytes, and their rolling digest must
// equal the checkpoint's digest_so_far. Otherwise StreamDigestMismatch.
func VerifyCheckpoint(cp StreamCheckpoint, prefix []Chunk) error {
	if len(prefix) > envelope.MaxStreamChunks { // stream chunk-count bound (§3.4, R7)
		return ErrTooManyChunks
	}
	sorted := append([]Chunk(nil), prefix...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Offset < sorted[j].Offset })
	var total uint64
	for _, c := range sorted {
		if c.Offset != total {
			return ErrStreamDigestMismatch // non-contiguous prefix
		}
		total += uint64(len(c.Data))
	}
	if total != cp.ThroughOffset {
		return ErrStreamDigestMismatch
	}
	if !bytes.Equal(cp.DigestSoFar, CommitDigest(prefix)) {
		return ErrStreamDigestMismatch
	}
	return nil
}

// State is a stream's lifecycle state (design.md §10, the stream state table): idle (no stream
// open for this stream id), open, committed, or abandoned (the terminal state an open stream
// enters when its idle/commit timer expires, § Timers — like committed, it admits no further
// event and its stream id is never re-admitted).
type State uint8

const (
	StateIdle State = iota
	StateOpen
	StateCommitted
	StateAbandoned
)

// String names a State ("idle", "open", "committed", "abandoned", or "unknown").
func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateOpen:
		return "open"
	case StateCommitted:
		return "committed"
	case StateAbandoned:
		return "abandoned"
	default:
		return "unknown"
	}
}

// ErrStreamStateError is returned when a stream event arrives for a state the stream state table
// does not admit: a second StreamOpen on an already-open stream, any chunk, StreamCheckpoint, or
// StreamCommit after the stream has committed or been abandoned, or any of those (including a
// StreamOpen reusing the id) on a stream that was never opened, committed, or abandoned. Every
// (state, event) pair the table does not list is rejected under this name (design.md §10;
// registered as naalp-error code 49).
var ErrStreamStateError = &cose.Error{Kind: "StreamStateError", Msg: "stream event is illegal for the current stream state (§10 state table)"}

// Guard enforces the stream state machine across concurrently open streams, keyed by stream id.
// It tracks only the current lifecycle state (idle/open/committed/abandoned), never chunk data,
// and rejects an event the state table does not admit for the stream's current state before any
// state change — a rejected event leaves the state exactly as it was (fail-closed, no partial
// transition). It holds no clock: the idle/commit timer (§ Timers) lives in the caller, which
// calls Expire when a stream's interval elapses; the numeric interval is a deployment policy,
// not a protocol constant.
//
// A Guard is per-connection: the caller discards it when the connection closes, so the states
// map is freed with the connection. There is no eviction of terminal (committed / abandoned)
// entries — evicting one would re-admit a replayed signed StreamOpen reusing that id as a fresh
// idle -> open, the exact replay the terminal states exist to refuse. Retained entries are
// therefore bounded by the number of streams the connection actually opened, each of which cost
// the peer a full StreamOpen signature to create (a bound the underlying transport's concurrent
// sub-stream limit further caps at any instant, §10.1), so retention is bounded by work the peer
// already performed rather than being an amplification surface.
type Guard struct {
	mu     sync.Mutex
	states map[string]State
}

// NewGuard returns a stream-state guard with no streams open yet.
func NewGuard() *Guard { return &Guard{states: make(map[string]State)} }

// state returns the current state of streamID under lock; an id never seen is idle (design.md
// §10: "idle (no stream open for this stream id)").
func (g *Guard) state(streamID []byte) State {
	if s, ok := g.states[string(streamID)]; ok {
		return s
	}
	return StateIdle
}

// State returns the current lifecycle state of streamID (for callers and tests).
func (g *Guard) State(streamID []byte) State {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state(streamID)
}

// Open validates a StreamOpen against the state table: only idle admits StreamOpen, and then
// only when the effect is authorized (R-10.3) — "idle | StreamOpen (effect authorized) -> open"
// and "idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)". A stream
// already open, committed, or abandoned rejects StreamStateError ("open | StreamOpen | reject
// (StreamStateError)"; committed+StreamOpen and abandoned+StreamOpen fall under the table's
// unlisted-pair default — an abandoned or committed stream id is never re-admitted). On
// EffectNotAuthorized the stream stays idle, since the open never took effect; on StreamStateError
// the existing state is untouched; only a successful open advances to open.
func (g *Guard) Open(o StreamOpen, grantedMax policy.Effect) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state(o.StreamID) != StateIdle {
		return ErrStreamStateError
	}
	if err := OpenStream(o, grantedMax); err != nil {
		return err
	}
	g.states[string(o.StreamID)] = StateOpen
	return nil
}

// Chunk validates a data chunk's arrival against the state table: only open admits a chunk
// ("open | chunk -> open"); idle, committed, or abandoned reject it StreamStateError (committed+
// chunk is listed explicitly; idle+chunk and abandoned+chunk fall under the unlisted-pair
// default). A chunk never changes the stream's state — it stays open.
func (g *Guard) Chunk(streamID []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state(streamID) != StateOpen {
		return ErrStreamStateError
	}
	return nil
}

// Checkpoint validates a StreamCheckpoint's arrival against the state table: only open admits
// it ("open | StreamCheckpoint -> open"); idle, committed, or abandoned reject it
// StreamStateError (committed+StreamCheckpoint is listed explicitly; the others fall under the
// unlisted-pair default). A checkpoint never changes the stream's state — it stays open.
func (g *Guard) Checkpoint(streamID []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state(streamID) != StateOpen {
		return ErrStreamStateError
	}
	return nil
}

// Commit validates a StreamCommit against the state table: only open admits it — idle, committed,
// or abandoned reject it StreamStateError before the digest is even inspected (committed+
// StreamCommit is listed explicitly; the others fall under the unlisted-pair default). When open,
// the commitment is verified against the delivered chunks (R-10.2): "open | StreamCommit (digest
// mismatch) | reject (StreamDigestMismatch)" leaves the stream open (this table row rejects
// without advancing, so a corrected commit may still follow), and "open | StreamCommit (digest
// matches) -> committed" advances the stream to committed.
func (g *Guard) Commit(commit StreamCommit, chunks []Chunk) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state(commit.StreamID) != StateOpen {
		return ErrStreamStateError
	}
	if err := VerifyCommit(commit, chunks); err != nil {
		return err
	}
	g.states[string(commit.StreamID)] = StateCommitted
	return nil
}

// Expire fires the idle/commit timer's expiry for streamID (§ Timers): an open stream that has
// not committed within its interval transitions "open -> abandoned", a terminal state that
// rejects every subsequent event with StreamStateError — including a StreamOpen reusing the id,
// so an abandoned stream is never re-admitted and nothing it delivered without a StreamCommit is
// non-repudiable. Only an open stream can be abandoned: the timer clears when a StreamCommit
// transitions the stream to committed (§ Timers), so a correct caller fires Expire only while
// the stream is open; Expire on an idle, committed, or already-abandoned stream is rejected
// StreamStateError with no state change (fail-closed). The Guard holds no clock — the caller
// decides when the interval has elapsed; the interval itself is a deployment policy.
func (g *Guard) Expire(streamID []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state(streamID) != StateOpen {
		return ErrStreamStateError
	}
	g.states[string(streamID)] = StateAbandoned
	return nil
}
