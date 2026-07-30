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
// 0x000D); this package never carries a foreign protocol (R-10.6).
package streaming

import (
	"bytes"
	"crypto/sha512"
	"hash"
	"sort"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// StreamChannel is the N-PAMP Stream channel native streams run on; foreign streamed carriage
// uses the distinct Bridge channel 0x000D (R-10.6).
const StreamChannel uint64 = 0x000C

// ErrStreamDigestMismatch is returned when a commitment (or checkpoint) digest does not match
// the recomputed rolling digest.
var ErrStreamDigestMismatch = &cose.Error{Kind: "StreamDigestMismatch", Msg: "stream commitment digest does not match the recomputed rolling digest"}

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
func SignOpen(o StreamOpen, s cose.Signer) ([]byte, error)       { return s.Sign(o.Bytes()) }
func SignCommit(c StreamCommit, s cose.Signer) ([]byte, error)   { return s.Sign(c.Bytes()) }
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
	if !bytes.Equal(commit.Digest, CommitDigest(chunks)) {
		return ErrStreamDigestMismatch
	}
	return nil
}

// VerifyCheckpoint confirms a prefix without the end (design.md §10.2): the prefix chunks must be
// contiguous from offset 0 and total exactly ThroughOffset bytes, and their rolling digest must
// equal the checkpoint's digest_so_far. Otherwise StreamDigestMismatch.
func VerifyCheckpoint(cp StreamCheckpoint, prefix []Chunk) error {
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
