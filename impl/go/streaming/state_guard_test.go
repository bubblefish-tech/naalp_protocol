// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package streaming_test

import (
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/streaming"
)

func wantKind(t *testing.T, err error, kind string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want %s, got nil", kind)
	}
	ce, ok := err.(*cose.Error)
	if !ok || ce.Kind != kind {
		t.Fatalf("want %s, got %v", kind, err)
	}
}

// TestGuardRejectsForbiddenTransitions drives forbidden (state, event) pairs from the stream
// state table (design.md §10) and asserts each is rejected StreamStateError. Every case is either
// a table row whose reaction is "reject (StreamStateError)" or falls under the table's "any
// (state, event) pair not listed above is rejected with StreamStateError" default.
func TestGuardRejectsForbiddenTransitions(t *testing.T) {
	sid := []byte("stream-forbidden")

	cases := []struct {
		name string
		run  func(g *streaming.Guard) error
	}{
		// idle + chunk -> unlisted pair, default StreamStateError.
		{"chunk_before_open", func(g *streaming.Guard) error { return g.Chunk(sid) }},
		// idle + StreamCheckpoint -> unlisted pair, default StreamStateError.
		{"checkpoint_before_open", func(g *streaming.Guard) error { return g.Checkpoint(sid) }},
		// idle + StreamCommit -> unlisted pair, default StreamStateError.
		{"commit_before_open", func(g *streaming.Guard) error {
			return g.Commit(streaming.StreamCommit{StreamID: sid}, nil)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := streaming.NewGuard()
			wantKind(t, c.run(g), "StreamStateError")
			if got := g.State(sid); got != streaming.StateIdle {
				t.Fatalf("a rejected event must not change state, got %s", got)
			}
		})
	}

	// open + StreamOpen -> reject (StreamStateError) — explicit table row.
	t.Run("double_open", func(t *testing.T) {
		id := []byte("stream-double-open")
		g := streaming.NewGuard()
		open := streaming.StreamOpen{StreamID: id, Effect: uint64(policy.IdempotentWrite)}
		if err := g.Open(open, policy.IdempotentWrite); err != nil {
			t.Fatalf("first open should succeed: %v", err)
		}
		wantKind(t, g.Open(open, policy.IdempotentWrite), "StreamStateError")
		if got := g.State(id); got != streaming.StateOpen {
			t.Fatalf("a rejected re-open must not change state, got %s", got)
		}
	})

	// committed + {chunk, StreamCheckpoint, StreamCommit, StreamOpen} — the first three are
	// explicit table rows ("reject (StreamStateError)"); StreamOpen-after-committed is the
	// unlisted-pair default.
	t.Run("events_after_commit", func(t *testing.T) {
		id := []byte("stream-after-commit")
		g := streaming.NewGuard()
		open := streaming.StreamOpen{StreamID: id, Effect: uint64(policy.IdempotentWrite)}
		if err := g.Open(open, policy.IdempotentWrite); err != nil {
			t.Fatalf("open: %v", err)
		}
		chunks := []streaming.Chunk{{Offset: 0, Data: []byte("payload")}}
		commit := streaming.StreamCommit{StreamID: id, Digest: streaming.CommitDigest(chunks)}
		if err := g.Commit(commit, chunks); err != nil {
			t.Fatalf("commit: %v", err)
		}
		if got := g.State(id); got != streaming.StateCommitted {
			t.Fatalf("stream should be committed, got %s", got)
		}

		wantKind(t, g.Chunk(id), "StreamStateError")
		wantKind(t, g.Checkpoint(id), "StreamStateError")
		wantKind(t, g.Commit(commit, chunks), "StreamStateError")
		wantKind(t, g.Open(open, policy.IdempotentWrite), "StreamStateError")

		if got := g.State(id); got != streaming.StateCommitted {
			t.Fatalf("rejected post-commit events must not change state, got %s", got)
		}
	})
}

// TestGuardValidSequenceSucceeds is the false-positive check: an ordered open -> chunk ->
// checkpoint -> commit sequence must succeed and drive the state idle -> open -> committed —
// the guard must not reject events the stream state table actually admits.
func TestGuardValidSequenceSucceeds(t *testing.T) {
	id := []byte("stream-valid")
	g := streaming.NewGuard()

	if got := g.State(id); got != streaming.StateIdle {
		t.Fatalf("an unopened stream should be idle, got %s", got)
	}

	open := streaming.StreamOpen{StreamID: id, Effect: uint64(policy.IdempotentWrite)}
	if err := g.Open(open, policy.IdempotentWrite); err != nil {
		t.Fatalf("open should succeed: %v", err)
	}
	if got := g.State(id); got != streaming.StateOpen {
		t.Fatalf("after open, state should be open, got %s", got)
	}

	chunks := []streaming.Chunk{
		{Offset: 0, Data: []byte("hello ")},
		{Offset: 6, Data: []byte("world")},
	}
	for i := range chunks {
		if err := g.Chunk(id); err != nil {
			t.Fatalf("chunk %d should succeed: %v", i, err)
		}
	}
	if err := g.Checkpoint(id); err != nil {
		t.Fatalf("checkpoint should succeed: %v", err)
	}
	if got := g.State(id); got != streaming.StateOpen {
		t.Fatalf("chunks/checkpoint must keep the stream open, got %s", got)
	}

	commit := streaming.StreamCommit{StreamID: id, Digest: streaming.CommitDigest(chunks)}
	if err := g.Commit(commit, chunks); err != nil {
		t.Fatalf("commit should succeed: %v", err)
	}
	if got := g.State(id); got != streaming.StateCommitted {
		t.Fatalf("after commit, state should be committed, got %s", got)
	}
}

// TestGuardDigestMismatchIsNotStateError distinguishes the guard's ordering check from the
// existing digest check: "open | StreamCommit (digest mismatch) | reject
// (StreamDigestMismatch)" must surface StreamDigestMismatch, not StreamStateError, and must
// leave the stream open (the row rejects without advancing) so a corrected commit still lands.
func TestGuardDigestMismatchIsNotStateError(t *testing.T) {
	id := []byte("stream-bad-digest")
	g := streaming.NewGuard()
	open := streaming.StreamOpen{StreamID: id, Effect: uint64(policy.IdempotentWrite)}
	if err := g.Open(open, policy.IdempotentWrite); err != nil {
		t.Fatalf("open: %v", err)
	}
	chunks := []streaming.Chunk{{Offset: 0, Data: []byte("payload")}}

	bad := streaming.StreamCommit{StreamID: id, Digest: []byte("not-the-real-digest-not-the-real-digest")}
	wantKind(t, g.Commit(bad, chunks), "StreamDigestMismatch")
	if got := g.State(id); got != streaming.StateOpen {
		t.Fatalf("a digest-mismatched commit must leave the stream open, got %s", got)
	}

	good := streaming.StreamCommit{StreamID: id, Digest: streaming.CommitDigest(chunks)}
	if err := g.Commit(good, chunks); err != nil {
		t.Fatalf("the corrected commit should still succeed: %v", err)
	}
	if got := g.State(id); got != streaming.StateCommitted {
		t.Fatalf("after the corrected commit, state should be committed, got %s", got)
	}
}

// TestGuardEffectNotAuthorizedLeavesIdle: "idle | StreamOpen (effect not authorized) | reject
// (EffectNotAuthorized)" must surface EffectNotAuthorized, not StreamStateError, and must leave
// the stream idle so a properly authorized open on the same stream id still succeeds (R-10.3).
func TestGuardEffectNotAuthorizedLeavesIdle(t *testing.T) {
	id := []byte("stream-unauthorized")
	g := streaming.NewGuard()

	destructive := streaming.StreamOpen{StreamID: id, Effect: uint64(policy.Destructive)}
	wantKind(t, g.Open(destructive, policy.ReadOnly), "EffectNotAuthorized")
	if got := g.State(id); got != streaming.StateIdle {
		t.Fatalf("an unauthorized open must leave the stream idle, got %s", got)
	}

	authorized := streaming.StreamOpen{StreamID: id, Effect: uint64(policy.IdempotentWrite)}
	if err := g.Open(authorized, policy.IdempotentWrite); err != nil {
		t.Fatalf("the authorized open should still succeed: %v", err)
	}
	if got := g.State(id); got != streaming.StateOpen {
		t.Fatalf("after the authorized open, state should be open, got %s", got)
	}
}

// TestGuardIndependentStreamsDoNotInterfere: the guard is keyed by stream id, so one stream's
// state never leaks into another's.
func TestGuardIndependentStreamsDoNotInterfere(t *testing.T) {
	g := streaming.NewGuard()
	a, b := []byte("stream-a"), []byte("stream-b")

	openA := streaming.StreamOpen{StreamID: a, Effect: uint64(policy.IdempotentWrite)}
	if err := g.Open(openA, policy.IdempotentWrite); err != nil {
		t.Fatalf("open a: %v", err)
	}
	// b was never opened; any event on b is still rejected StreamStateError even though a is open.
	wantKind(t, g.Chunk(b), "StreamStateError")
	if err := g.Chunk(a); err != nil {
		t.Fatalf("chunk on the open stream a should succeed: %v", err)
	}
}

// TestGuardExpireAbandonsOpenStream drives the idle/commit timer's expiry (§ Timers): Expire on
// an open stream transitions it "open -> abandoned", a terminal state that then rejects every
// event with StreamStateError — including a StreamOpen reusing the id, so an abandoned stream is
// never re-admitted. This is the fail-closed retention that stops a replayed signed StreamOpen
// from re-opening an abandoned id.
func TestGuardExpireAbandonsOpenStream(t *testing.T) {
	id := []byte("stream-abandoned")
	g := streaming.NewGuard()
	open := streaming.StreamOpen{StreamID: id, Effect: uint64(policy.IdempotentWrite)}
	if err := g.Open(open, policy.IdempotentWrite); err != nil {
		t.Fatalf("open: %v", err)
	}

	if err := g.Expire(id); err != nil {
		t.Fatalf("expiring an open stream should succeed: %v", err)
	}
	if got := g.State(id); got != streaming.StateAbandoned {
		t.Fatalf("after expiry, state should be abandoned, got %s", got)
	}

	// An abandoned stream admits nothing — chunk, checkpoint, commit, and a StreamOpen reusing
	// the id are all rejected StreamStateError (the id is never re-admitted).
	chunks := []streaming.Chunk{{Offset: 0, Data: []byte("payload")}}
	commit := streaming.StreamCommit{StreamID: id, Digest: streaming.CommitDigest(chunks)}
	wantKind(t, g.Chunk(id), "StreamStateError")
	wantKind(t, g.Checkpoint(id), "StreamStateError")
	wantKind(t, g.Commit(commit, chunks), "StreamStateError")
	wantKind(t, g.Open(open, policy.IdempotentWrite), "StreamStateError")

	if got := g.State(id); got != streaming.StateAbandoned {
		t.Fatalf("rejected post-abandon events must not change state, got %s", got)
	}
}

// TestGuardExpireOnNonOpenIsStateError: the idle/commit timer clears when a StreamCommit
// transitions the stream to committed (§ Timers), so a correct caller fires Expire only while
// the stream is open. Expire on an idle, committed, or already-abandoned stream is therefore
// rejected StreamStateError and leaves the state unchanged (fail-closed).
func TestGuardExpireOnNonOpenIsStateError(t *testing.T) {
	// idle: nothing has been opened.
	t.Run("idle", func(t *testing.T) {
		id := []byte("stream-expire-idle")
		g := streaming.NewGuard()
		wantKind(t, g.Expire(id), "StreamStateError")
		if got := g.State(id); got != streaming.StateIdle {
			t.Fatalf("expiring an idle stream must not change state, got %s", got)
		}
	})

	// committed: the timer should have cleared on commit; a spurious Expire is a state error and
	// must not turn a committed (non-repudiable) stream into an abandoned one.
	t.Run("committed", func(t *testing.T) {
		id := []byte("stream-expire-committed")
		g := streaming.NewGuard()
		open := streaming.StreamOpen{StreamID: id, Effect: uint64(policy.IdempotentWrite)}
		if err := g.Open(open, policy.IdempotentWrite); err != nil {
			t.Fatalf("open: %v", err)
		}
		chunks := []streaming.Chunk{{Offset: 0, Data: []byte("payload")}}
		commit := streaming.StreamCommit{StreamID: id, Digest: streaming.CommitDigest(chunks)}
		if err := g.Commit(commit, chunks); err != nil {
			t.Fatalf("commit: %v", err)
		}
		wantKind(t, g.Expire(id), "StreamStateError")
		if got := g.State(id); got != streaming.StateCommitted {
			t.Fatalf("expiring a committed stream must not change state, got %s", got)
		}
	})

	// already abandoned: a second Expire is a state error and a no-op.
	t.Run("already_abandoned", func(t *testing.T) {
		id := []byte("stream-expire-twice")
		g := streaming.NewGuard()
		open := streaming.StreamOpen{StreamID: id, Effect: uint64(policy.IdempotentWrite)}
		if err := g.Open(open, policy.IdempotentWrite); err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := g.Expire(id); err != nil {
			t.Fatalf("first expire: %v", err)
		}
		wantKind(t, g.Expire(id), "StreamStateError")
		if got := g.State(id); got != streaming.StateAbandoned {
			t.Fatalf("a second expire must not change state, got %s", got)
		}
	})
}
