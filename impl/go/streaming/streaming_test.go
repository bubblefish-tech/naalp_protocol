// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package streaming_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/streaming"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/stream/cases.json"

type streamCases struct {
	StreamIDHex string `json:"stream_id_hex"`
	SubStream   uint64 `json:"substream"`
	Effect      uint64 `json:"effect"`
	ApprovalHex string `json:"approval_hex"`
	Chunks      []struct {
		Offset  uint64 `json:"offset"`
		DataHex string `json:"data_hex"`
	} `json:"chunks"`
	FinalDigestHex string `json:"final_digest_hex"`
	Checkpoints    []struct {
		ThroughOffset  uint64 `json:"through_offset"`
		DigestSoFarHex string `json:"digest_so_far_hex"`
	} `json:"checkpoints"`
	OpenBodyHex       string `json:"open_body_hex"`
	CommitBodyHex     string `json:"commit_body_hex"`
	CheckpointBodyHex string `json:"checkpoint_body_hex"`
	Tamper            struct {
		ChunkIndex    int    `json:"chunk_index"`
		FlippedDataHex string `json:"flipped_data_hex"`
		DigestHex     string `json:"digest_hex"`
	} `json:"tamper"`
}

func load(t *testing.T) streamCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c streamCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func chunksOf(t *testing.T, c streamCases) []streaming.Chunk {
	out := make([]streaming.Chunk, 0, len(c.Chunks))
	for _, ch := range c.Chunks {
		out = append(out, streaming.Chunk{Offset: ch.Offset, Data: hx(t, ch.DataHex)})
	}
	return out
}

// TestDigestAndBodiesMatchOracle: the rolling commitment, the mid-stream checkpoints, and the
// StreamOpen/Commit/Checkpoint bodies all equal the independent oracle (⟹ Go == Rust).
func TestDigestAndBodiesMatchOracle(t *testing.T) {
	c := load(t)
	streamID := hx(t, c.StreamIDHex)
	chunks := chunksOf(t, c)

	if got := hex.EncodeToString(streaming.CommitDigest(chunks)); got != c.FinalDigestHex {
		t.Errorf("final digest\n got %s\nwant %s", got, c.FinalDigestHex)
	}
	// Rolling: DigestSoFar after each chunk equals the checkpoint, and the last equals final.
	sd := streaming.NewStreamDigest()
	for i, ch := range chunks {
		sd.Update(ch.Data)
		if i < len(c.Checkpoints) {
			if got := hex.EncodeToString(sd.DigestSoFar()); got != c.Checkpoints[i].DigestSoFarHex {
				t.Errorf("checkpoint %d\n got %s\nwant %s", i, got, c.Checkpoints[i].DigestSoFarHex)
			}
		}
	}
	if got := hex.EncodeToString(sd.DigestSoFar()); got != c.FinalDigestHex {
		t.Errorf("rolling final\n got %s\nwant %s", got, c.FinalDigestHex)
	}

	open := streaming.StreamOpen{StreamID: streamID, Effect: c.Effect, Approval: hx(t, c.ApprovalHex), SubStream: c.SubStream}
	if got := hex.EncodeToString(open.Bytes()); got != c.OpenBodyHex {
		t.Errorf("StreamOpen body\n got %s\nwant %s", got, c.OpenBodyHex)
	}
	commit := streaming.StreamCommit{StreamID: streamID, Digest: hx(t, c.FinalDigestHex)}
	if got := hex.EncodeToString(commit.Bytes()); got != c.CommitBodyHex {
		t.Errorf("StreamCommit body\n got %s\nwant %s", got, c.CommitBodyHex)
	}
	cp := streaming.StreamCheckpoint{StreamID: streamID, ThroughOffset: c.Checkpoints[0].ThroughOffset, DigestSoFar: hx(t, c.Checkpoints[0].DigestSoFarHex)}
	if got := hex.EncodeToString(cp.Bytes()); got != c.CheckpointBodyHex {
		t.Errorf("StreamCheckpoint body\n got %s\nwant %s", got, c.CheckpointBodyHex)
	}
}

// TestTamperInvalidatesCommit: R-10.2 — the correct stream verifies; altering one delivered
// byte invalidates the commitment (StreamDigestMismatch).
func TestTamperInvalidatesCommit(t *testing.T) {
	c := load(t)
	streamID := hx(t, c.StreamIDHex)
	chunks := chunksOf(t, c)
	commit := streaming.StreamCommit{StreamID: streamID, Digest: hx(t, c.FinalDigestHex)}

	if err := streaming.VerifyCommit(commit, chunks); err != nil {
		t.Fatalf("valid stream rejected: %v", err)
	}
	// Deliver a tampered chunk in place of chunk index 1.
	tampered := chunksOf(t, c)
	tampered[c.Tamper.ChunkIndex].Data = hx(t, c.Tamper.FlippedDataHex)
	if err := streaming.VerifyCommit(commit, tampered); err == nil {
		t.Fatal("tampered stream accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "StreamDigestMismatch" {
		t.Fatalf("want StreamDigestMismatch, got %v", err)
	}
}

// TestCheckpointVerifiesPrefix: a checkpoint confirms a prefix without the end; a prefix whose
// bytes do not match the checkpoint is rejected.
func TestCheckpointVerifiesPrefix(t *testing.T) {
	c := load(t)
	streamID := hx(t, c.StreamIDHex)
	all := chunksOf(t, c)
	for i, cpj := range c.Checkpoints {
		cp := streaming.StreamCheckpoint{StreamID: streamID, ThroughOffset: cpj.ThroughOffset, DigestSoFar: hx(t, cpj.DigestSoFarHex)}
		prefix := all[:i+1] // chunks through this checkpoint, WITHOUT the end
		if err := streaming.VerifyCheckpoint(cp, prefix); err != nil {
			t.Fatalf("checkpoint %d rejected a valid prefix: %v", i, err)
		}
	}
	// A checkpoint claiming the first prefix but given the full stream fails (wrong length).
	cp0 := streaming.StreamCheckpoint{StreamID: streamID, ThroughOffset: c.Checkpoints[0].ThroughOffset, DigestSoFar: hx(t, c.Checkpoints[0].DigestSoFarHex)}
	if err := streaming.VerifyCheckpoint(cp0, all); err == nil {
		t.Fatal("checkpoint accepted a prefix of the wrong length")
	}
}

// TestEffectRefusedBeforeChunk: R-10.3 — a stream whose effect exceeds the granted capability is
// refused at open, before any chunk is accepted.
func TestEffectRefusedBeforeChunk(t *testing.T) {
	c := load(t)
	streamID := hx(t, c.StreamIDHex)
	// A destructive stream under a read-only grant is refused.
	destructive := streaming.StreamOpen{StreamID: streamID, Effect: uint64(policy.Destructive), SubStream: 1}
	if err := streaming.OpenStream(destructive, policy.ReadOnly); err == nil {
		t.Fatal("destructive stream authorized under read-only grant")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "EffectNotAuthorized" {
		t.Fatalf("want EffectNotAuthorized, got %v", err)
	}
	// The corpus stream (idempotent_write) under an idempotent_write grant is authorized.
	ok := streaming.StreamOpen{StreamID: streamID, Effect: c.Effect, Approval: hx(t, c.ApprovalHex), SubStream: c.SubStream}
	if err := streaming.OpenStream(ok, policy.IdempotentWrite); err != nil {
		t.Fatalf("authorized stream refused: %v", err)
	}
	// An unrecognized effect fails closed to destructive and is refused below destructive.
	unknown := streaming.StreamOpen{StreamID: streamID, Effect: 99, SubStream: 1}
	if err := streaming.OpenStream(unknown, policy.NonIdempotentWrite); err == nil {
		t.Fatal("unknown effect authorized below destructive")
	}
}

func testSigner(t *testing.T, b byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier) {
	t.Helper()
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = b
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
}

// TestSignedCommitment: the StreamOpen and StreamCommit are signed objects (R-10.2/R-10.3) — one
// end-commitment signature covers the whole stream.
func TestSignedCommitment(t *testing.T) {
	c := load(t)
	signer, verifier := testSigner(t, 60)
	commit := streaming.StreamCommit{StreamID: hx(t, c.StreamIDHex), Digest: hx(t, c.FinalDigestHex)}
	sig, err := streaming.SignCommit(commit, signer)
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.VerifyRaw(commit.Bytes(), sig) {
		t.Fatal("commit signature does not verify")
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0x01
	if verifier.VerifyRaw(commit.Bytes(), bad) {
		t.Fatal("tampered commit signature verified")
	}
}

// TestFullDuplexConcurrent: R-10.5 — two streams driven concurrently on independent sub-streams
// both complete with valid commitments. Run under -race.
func TestFullDuplexConcurrent(t *testing.T) {
	mkStream := func(seed byte, n int) ([]streaming.Chunk, streaming.StreamCommit) {
		var chunks []streaming.Chunk
		var off uint64
		for i := 0; i < n; i++ {
			data := []byte{seed, byte(i), byte(i * 7)}
			chunks = append(chunks, streaming.Chunk{Offset: off, Data: data})
			off += uint64(len(data))
		}
		return chunks, streaming.StreamCommit{StreamID: []byte{seed}, Digest: streaming.CommitDigest(chunks)}
	}
	chunksA, commitA := mkStream(0xA1, 300)
	chunksB, commitB := mkStream(0xB2, 300)

	var wg sync.WaitGroup
	var errA, errB error
	wg.Add(2)
	go func() { defer wg.Done(); errA = streaming.VerifyCommit(commitA, chunksA) }()
	go func() { defer wg.Done(); errB = streaming.VerifyCommit(commitB, chunksB) }()
	wg.Wait()
	if errA != nil || errB != nil {
		t.Fatalf("concurrent streams: errA=%v errB=%v", errA, errB)
	}
	// The two streams have distinct commitments (content differs).
	if hex.EncodeToString(commitA.Digest) == hex.EncodeToString(commitB.Digest) {
		t.Fatal("distinct streams produced the same commitment")
	}
}

// TestOffsetOrderMatters: CommitDigest is over absolute-offset order — input order is irrelevant,
// but swapping which data sits at which offset changes the commitment.
func TestOffsetOrderMatters(t *testing.T) {
	c := load(t)
	chunks := chunksOf(t, c)
	reversed := make([]streaming.Chunk, len(chunks))
	for i := range chunks {
		reversed[len(chunks)-1-i] = chunks[i]
	}
	if hex.EncodeToString(streaming.CommitDigest(chunks)) != hex.EncodeToString(streaming.CommitDigest(reversed)) {
		t.Fatal("digest changed with input order (should sort by offset)")
	}
	// Swap the data at the first two offsets: same bytes, different positions -> different digest.
	swapped := chunksOf(t, c)
	swapped[0].Data, swapped[1].Data = swapped[1].Data, swapped[0].Data
	if hex.EncodeToString(streaming.CommitDigest(swapped)) == c.FinalDigestHex {
		t.Fatal("reordering content across offsets did not change the digest")
	}
}
