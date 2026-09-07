// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package streaming_test

import (
	"encoding/binary"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/streaming"
)

// FuzzStreamChunkCount fuzzes the stream chunk-count bound (design.md §3.4, R7;
// envelope.MaxStreamChunks) via VerifyCommit/VerifyCheckpoint -- the two entry points that
// enforce it (bounds_test.go's TestBoundTooManyChunks pins the same property with two fixed
// cases; this fuzzes the count itself, and the mismatched-digest combination, rather than
// only the boundary pair).
//
// HONEST ADAPTATION FROM THE ORIGINAL GROUNDING PLAN (recorded, not silently narrowed): the
// #277 survey framed this target as fuzzing "arbitrary chunk-count ENCODINGS" -- i.e. raw
// wire bytes that decode into a chunk count. No such raw-byte decoder exists in this package:
// a Chunk arrives from the transport already as a Go []Chunk (design.md §10 -- chunks are
// unsigned data frames the transport AEAD authenticates, decoded/framed one layer below this
// package). There is therefore no CBOR/wire count field for this package's fuzz target to
// decode; grepped this session (`func Fuzz`, `TooManyChunks` across impl/go) confirmed no
// existing or planned wire-level chunk-count decoder to extend instead. What this target
// fuzzes instead is the actual attack surface this package DOES own: the derived chunk COUNT
// (from fuzzer bytes) driving VerifyCommit/VerifyCheckpoint directly, with a digest that is
// deliberately correct for the smaller (<=Max) cases and deliberately WRONG for others, so the
// fuzzer cannot merely find "any mismatch" -- it must find a count/digest combination where
// the TooManyChunks bound itself is not enforced BEFORE the (much more expensive, O(n log n)
// sort + SHA-384 over every chunk) digest computation.
//
// The derived count is bounded to [0, 2*MaxStreamChunks] (not left fully unbounded): the
// property being fuzzed only has two distinct regions (at-or-under the limit; over it), so a
// derived count is capped at twice the limit -- comfortably spanning both regions and the
// boundary itself -- to keep each fuzz iteration's O(n log n) CommitDigest cost bounded for a
// CI-viable campaign, rather than letting the byte-level mutator waste budget constructing
// enormous slices that exercise no new code path.
func FuzzStreamChunkCount(f *testing.F) {
	seeds := []uint32{
		0, 1,
		uint32(envelope.MaxStreamChunks - 1),
		uint32(envelope.MaxStreamChunks),     // AT the limit
		uint32(envelope.MaxStreamChunks + 1), // ONE past it
		uint32(envelope.MaxStreamChunks) * 2,
		0xFFFFFFFF,
	}
	for _, n := range seeds {
		b := make([]byte, 5)
		binary.LittleEndian.PutUint32(b, n)
		f.Add(b)
	}
	// A fifth "correct digest" flag byte lets the corpus explore both a matching and a
	// deliberately-wrong digest for the same derived count.
	for _, n := range seeds {
		b := make([]byte, 5)
		binary.LittleEndian.PutUint32(b, n)
		b[4] = 1
		f.Add(b)
	}

	const capN = uint64(envelope.MaxStreamChunks) * 2

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) < 5 {
			return
		}
		n := uint64(binary.LittleEndian.Uint32(raw)) % (capN + 1)
		correctDigest := raw[4]&1 == 1

		chunks := make([]streaming.Chunk, n)
		for i := range chunks {
			chunks[i] = streaming.Chunk{Offset: uint64(i)}
		}

		digest := streaming.CommitDigest(chunks)
		if !correctDigest {
			digest = append([]byte(nil), digest...)
			digest = append(digest, 0xFF) // guaranteed to differ from any real digest length/content
		}

		// VerifyCommit has no contiguity requirement (it only sorts by offset before hashing
		// Data), so its accept/reject outcome depends on exactly two things: the count bound
		// and the digest match -- both fully checkable here.
		commit := streaming.StreamCommit{Digest: digest}
		err := streaming.VerifyCommit(commit, chunks)
		if n > uint64(envelope.MaxStreamChunks) {
			ce, ok := err.(*cose.Error)
			if !ok || ce.Kind != "TooManyChunks" {
				t.Fatalf("VerifyCommit: count %d > MaxStreamChunks=%d must be TooManyChunks "+
					"regardless of digest correctness (correctDigest=%v), got %v",
					n, envelope.MaxStreamChunks, correctDigest, err)
			}
		} else if ce, ok := err.(*cose.Error); ok && ce.Kind == "TooManyChunks" {
			t.Fatalf("VerifyCommit: count %d <= MaxStreamChunks=%d must never be TooManyChunks",
				n, envelope.MaxStreamChunks)
		} else if correctDigest && err != nil {
			t.Fatalf("VerifyCommit: count %d <= MaxStreamChunks with a matching digest should verify, got %v", n, err)
		} else if !correctDigest && err == nil {
			t.Fatalf("VerifyCommit: count %d with a deliberately wrong digest should NOT verify", n)
		}

		// VerifyCheckpoint additionally requires prefix contiguity from offset 0 (these
		// synthetic all-empty-Data chunks are non-contiguous for n>=2, independent of digest
		// correctness), so only the count-bound-fires-first property is asserted here -- the
		// one this fuzz target exists to cover; VerifyCommit above already fully covers the
        // count+digest interaction.
		cp := streaming.StreamCheckpoint{ThroughOffset: 0, DigestSoFar: digest}
		cpErr := streaming.VerifyCheckpoint(cp, chunks)
		if n > uint64(envelope.MaxStreamChunks) {
			ce, ok := cpErr.(*cose.Error)
			if !ok || ce.Kind != "TooManyChunks" {
				t.Fatalf("VerifyCheckpoint: count %d > MaxStreamChunks=%d must be TooManyChunks "+
					"regardless of digest correctness (correctDigest=%v), got %v",
					n, envelope.MaxStreamChunks, correctDigest, cpErr)
			}
		} else if ce, ok := cpErr.(*cose.Error); ok && ce.Kind == "TooManyChunks" {
			t.Fatalf("VerifyCheckpoint: count %d <= MaxStreamChunks=%d must never be TooManyChunks",
				n, envelope.MaxStreamChunks)
		}
	})
}
