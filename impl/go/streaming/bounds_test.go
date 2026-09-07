// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package streaming_test

import (
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/streaming"
)

// TestBoundTooManyChunks pins the stream chunk-count bound (design.md §3.4, R7): a
// commit over exactly MaxStreamChunks chunks verifies, and one over MaxStreamChunks+1
// is rejected TooManyChunks. Both carry a MATCHING rolling digest, so the count is the
// only reason to reject — deleting the count check makes the +1 case verify (the
// mutation is caught). The chunks share one backing array to bound test memory.
func TestBoundTooManyChunks(t *testing.T) {
	over := make([]streaming.Chunk, envelope.MaxStreamChunks+1)
	atLimit := over[:envelope.MaxStreamChunks]

	okCommit := streaming.StreamCommit{Digest: streaming.CommitDigest(atLimit)}
	if err := streaming.VerifyCommit(okCommit, atLimit); err != nil {
		t.Fatalf("commit over %d chunks should verify, got %v", envelope.MaxStreamChunks, err)
	}

	overCommit := streaming.StreamCommit{Digest: streaming.CommitDigest(over)}
	err := streaming.VerifyCommit(overCommit, over)
	ce, ok := err.(*cose.Error)
	if !ok || ce.Kind != "TooManyChunks" {
		t.Fatalf("commit over %d chunks should be TooManyChunks, got %v", envelope.MaxStreamChunks+1, err)
	}

	// VerifyCheckpoint enforces the same bound, and the count check fires before the
	// contiguity/digest checks, so the diagnosis is TooManyChunks (not a digest error).
	cpErr := streaming.VerifyCheckpoint(streaming.StreamCheckpoint{}, over)
	cce, ok := cpErr.(*cose.Error)
	if !ok || cce.Kind != "TooManyChunks" {
		t.Fatalf("checkpoint over %d chunks should be TooManyChunks, got %v", envelope.MaxStreamChunks+1, cpErr)
	}
}
