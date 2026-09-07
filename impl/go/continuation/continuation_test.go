// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package continuation_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/continuation"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/continuation/cases.json"

type vec struct {
	FlowOpen struct {
		FlowIDHex     string   `json:"flow_id_hex"`
		EffectCeiling uint64   `json:"effect_ceiling"`
		ApprovalsHex  []string `json:"approvals_hex"`
		BodyHex       string   `json:"body_hex"`
		HeadHex       string   `json:"head_hex"`
		IDHex         string   `json:"id_hex"`
	} `json:"flow_open"`
	Continuations []struct {
		Seq          uint64 `json:"seq"`
		Effect       uint64 `json:"effect"`
		PayloadIDHex string `json:"payload_id_hex"`
		PrevHex      string `json:"prev_hex"`
		BodyHex      string `json:"body_hex"`
		HeadHex      string `json:"head_hex"`
	} `json:"continuations"`
	FinalHeadHex string `json:"final_head_hex"`
	Checkpoint   struct {
		ThroughSeq uint64 `json:"through_seq"`
		HeadHex    string `json:"head_hex"`
		BodyHex    string `json:"body_hex"`
	} `json:"checkpoint"`
	FlowCommit struct {
		FinalHeadHex string `json:"final_head_hex"`
		BodyHex      string `json:"body_hex"`
	} `json:"flow_commit"`
	AboveCeiling struct {
		Seq          uint64 `json:"seq"`
		Effect       uint64 `json:"effect"`
		Ceiling      uint64 `json:"ceiling"`
		PayloadIDHex string `json:"payload_id_hex"`
		PrevHex      string `json:"prev_hex"`
		BodyHex      string `json:"body_hex"`
	} `json:"above_ceiling"`
	Gap struct {
		PresentSeqs []uint64 `json:"present_seqs"`
		MissingSeq  uint64   `json:"missing_seq"`
		ThroughSeq  uint64   `json:"through_seq"`
	} `json:"gap"`
	Replay struct {
		FlowOpenBBodyHex string `json:"flow_open_b_body_hex"`
		FlowOpenBHeadHex string `json:"flow_open_b_head_hex"`
		FlowOpenBIDHex   string `json:"flow_open_b_id_hex"`
	} `json:"replay"`
	RangeReject struct {
		OutOfLatticeValue         uint64 `json:"out_of_lattice_value"`
		FlowOpenCeilingBodyHex    string `json:"flow_open_ceiling_body_hex"`
		ContinuationEffectBodyHex string `json:"continuation_effect_body_hex"`
	} `json:"range_reject"`
	CheckpointOverflow struct {
		ThroughSeqStr string `json:"through_seq_str"`
		HeadHex       string `json:"head_hex"`
		BodyHex       string `json:"body_hex"`
	} `json:"checkpoint_overflow"`
	BigSeq struct {
		SeqStr       string `json:"seq_str"`
		Effect       uint64 `json:"effect"`
		PayloadIDHex string `json:"payload_id_hex"`
		PrevHex      string `json:"prev_hex"`
		BodyHex      string `json:"body_hex"`
		HeadHex      string `json:"head_hex"`
	} `json:"big_seq"`
	Minimal struct {
		FlowIDHex     string   `json:"flow_id_hex"`
		EffectCeiling uint64   `json:"effect_ceiling"`
		ApprovalsHex  []string `json:"approvals_hex"`
		BodyHex       string   `json:"body_hex"`
		HeadHex       string   `json:"head_hex"`
		IDHex         string   `json:"id_hex"`
	} `json:"minimal"`
	EmptyVsNonempty struct {
		EmptyApprovals struct {
			BodyHex string `json:"body_hex"`
			IDHex   string `json:"id_hex"`
		} `json:"empty_approvals"`
		OneApproval struct {
			BodyHex string `json:"body_hex"`
			IDHex   string `json:"id_hex"`
		} `json:"one_approval"`
	} `json:"empty_vs_nonempty"`
	KeysOutOfOrder struct {
		CanonicalCommitBodyHex    string `json:"canonical_commit_body_hex"`
		NoncanonicalCommitBodyHex string `json:"noncanonical_commit_body_hex"`
	} `json:"keys_out_of_order"`
	LookAlike struct {
		FlowCommitBodyHex string `json:"flow_commit_body_hex"`
	} `json:"look_alike"`
}

func hb(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func loadVec(t *testing.T) vec {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vec
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(v.Continuations) != 3 {
		t.Fatalf("expected 3 continuations in the corpus, got %d", len(v.Continuations))
	}
	return v
}

// openFrom rebuilds the FlowOpen struct from the oracle vector.
func openFrom(t *testing.T, v vec) continuation.FlowOpen {
	apps := make([][]byte, len(v.FlowOpen.ApprovalsHex))
	for i, a := range v.FlowOpen.ApprovalsHex {
		apps[i] = hb(t, a)
	}
	return continuation.FlowOpen{
		FlowID:        hb(t, v.FlowOpen.FlowIDHex),
		EffectCeiling: v.FlowOpen.EffectCeiling,
		Approvals:     apps,
	}
}

// contsFrom rebuilds the full continuation chain from the oracle vector.
func contsFrom(t *testing.T, v vec) []continuation.Continuation {
	out := make([]continuation.Continuation, len(v.Continuations))
	id := hb(t, v.FlowOpen.IDHex)
	for i, c := range v.Continuations {
		out[i] = continuation.Continuation{
			FlowOpenID: id,
			Seq:        c.Seq,
			Effect:     c.Effect,
			PayloadID:  hb(t, c.PayloadIDHex),
			Prev:       hb(t, c.PrevHex),
		}
	}
	return out
}

func key(seed byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier) {
	var s [mldsa65.SeedSize]byte
	s[0] = seed
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
}

// TestByteParityAgainstOracle: Go encoding == the non-circular Python oracle, byte-for-byte, for
// every object. Mutation: change any Bytes() field order/tag and a body_hex compare flips.
func TestByteParityAgainstOracle(t *testing.T) {
	v := loadVec(t)
	open := openFrom(t, v)

	if got := hex.EncodeToString(open.Bytes()); got != v.FlowOpen.BodyHex {
		t.Fatalf("FlowOpen.Bytes\n got %s\nwant %s", got, v.FlowOpen.BodyHex)
	}
	if got := hex.EncodeToString(open.Head()); got != v.FlowOpen.HeadHex {
		t.Fatalf("FlowOpen.Head got %s want %s", got, v.FlowOpen.HeadHex)
	}
	if got := hex.EncodeToString(open.ID()); got != v.FlowOpen.IDHex {
		t.Fatalf("FlowOpen.ID got %s want %s", got, v.FlowOpen.IDHex)
	}

	conts := contsFrom(t, v)
	for i, c := range conts {
		if got := hex.EncodeToString(c.Bytes()); got != v.Continuations[i].BodyHex {
			t.Fatalf("Continuation[%d].Bytes\n got %s\nwant %s", i, got, v.Continuations[i].BodyHex)
		}
		if got := hex.EncodeToString(c.Head()); got != v.Continuations[i].HeadHex {
			t.Fatalf("Continuation[%d].Head got %s want %s", i, got, v.Continuations[i].HeadHex)
		}
	}

	cp := continuation.Checkpoint{
		FlowOpenID: open.ID(),
		ThroughSeq: v.Checkpoint.ThroughSeq,
		Head:       hb(t, v.Checkpoint.HeadHex),
	}
	if got := hex.EncodeToString(cp.Bytes()); got != v.Checkpoint.BodyHex {
		t.Fatalf("Checkpoint.Bytes\n got %s\nwant %s", got, v.Checkpoint.BodyHex)
	}

	fc := continuation.FlowCommit{FlowOpenID: open.ID(), FinalHead: hb(t, v.FlowCommit.FinalHeadHex)}
	if got := hex.EncodeToString(fc.Bytes()); got != v.FlowCommit.BodyHex {
		t.Fatalf("FlowCommit.Bytes\n got %s\nwant %s", got, v.FlowCommit.BodyHex)
	}
}

// TestVerifyChainReachesFinalHead: the whole cheap chain verifies and lands on the oracle's final
// head. Mutation: drop the prev==prevHead check in VerifyContinuation and a tampered chain still
// "verifies" but the returned head diverges from the oracle.
func TestVerifyChainReachesFinalHead(t *testing.T) {
	v := loadVec(t)
	open := openFrom(t, v)
	conts := contsFrom(t, v)
	final, err := continuation.VerifyChain(open, conts)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if got := hex.EncodeToString(final); got != v.FinalHeadHex {
		t.Fatalf("final head got %s want %s", got, v.FinalHeadHex)
	}
}

// TestReconstructFromBytesAlone: the bearer-authority property — the ceiling and approvals are
// recovered from the FlowOpen bytes with no session state. Mutation: have ParseFlowOpen return a
// constant ceiling and this flips.
func TestReconstructFromBytesAlone(t *testing.T) {
	v := loadVec(t)
	open := openFrom(t, v)
	got, err := continuation.ParseFlowOpen(open.Bytes())
	if err != nil {
		t.Fatalf("ParseFlowOpen: %v", err)
	}
	if got.EffectCeiling != v.FlowOpen.EffectCeiling {
		t.Fatalf("reconstructed ceiling %d want %d", got.EffectCeiling, v.FlowOpen.EffectCeiling)
	}
	if !bytes.Equal(got.FlowID, hb(t, v.FlowOpen.FlowIDHex)) {
		t.Fatalf("reconstructed flow_id mismatch")
	}
	if len(got.Approvals) != len(v.FlowOpen.ApprovalsHex) {
		t.Fatalf("reconstructed approvals count %d want %d", len(got.Approvals), len(v.FlowOpen.ApprovalsHex))
	}
	for i, a := range got.Approvals {
		if !bytes.Equal(a, hb(t, v.FlowOpen.ApprovalsHex[i])) {
			t.Fatalf("reconstructed approval[%d] mismatch", i)
		}
	}
	// Reconstructed struct re-encodes to the same id (round-trip stability).
	if !bytes.Equal(got.ID(), open.ID()) {
		t.Fatalf("reconstructed FlowOpen re-encodes to a different id")
	}
}

// TestContinuationReplayUnderDifferentFlowFails: a continuation valid under FlowOpen A must not
// verify under FlowOpen B. Mutation: drop the flow_open_id check and (a) flips to allow.
func TestContinuationReplayUnderDifferentFlowFails(t *testing.T) {
	v := loadVec(t)
	openA := openFrom(t, v)
	conts := contsFrom(t, v)
	ceiling := policy.NormalizeEffect(openA.EffectCeiling)

	openBID := hb(t, v.Replay.FlowOpenBIDHex)
	openBHead := hb(t, v.Replay.FlowOpenBHeadHex)

	// (a) As delivered: the continuation still names flow A -> WrongFlow under B.
	if err := continuation.VerifyContinuation(conts[0], openBID, openBHead, 0, ceiling); err != continuation.ErrWrongFlow {
		t.Fatalf("replay (as-is) got %v, want WrongFlow", err)
	}
	// (b) Attacker rewrites the id to B's: now prev (head of A) no longer chains to B's head.
	forged := conts[0]
	forged.FlowOpenID = openBID
	if err := continuation.VerifyContinuation(forged, openBID, openBHead, 0, ceiling); err != continuation.ErrChainBroken {
		t.Fatalf("replay (forged id) got %v, want ChainBroken", err)
	}
	// Sanity: the same continuation DOES verify under its own FlowOpen A (positive control).
	if err := continuation.VerifyContinuation(conts[0], openA.ID(), openA.Head(), 0, ceiling); err != nil {
		t.Fatalf("positive control under FlowOpen A: %v", err)
	}
}

// TestAboveCeilingRejected: a continuation whose effect exceeds the ceiling is refused AboveCeiling.
// Mutation: remove the ceiling.Authorizes check and an above-ceiling link passes (the cheap path
// would then be able to escalate past the single full signature — the whole point of the ceiling).
func TestAboveCeilingRejected(t *testing.T) {
	v := loadVec(t)
	open := openFrom(t, v)
	ceiling := policy.NormalizeEffect(open.EffectCeiling)
	above := continuation.Continuation{
		FlowOpenID: open.ID(),
		Seq:        v.AboveCeiling.Seq,
		Effect:     v.AboveCeiling.Effect, // destructive (3) > ceiling non_idempotent_write (2)
		PayloadID:  hb(t, v.AboveCeiling.PayloadIDHex),
		Prev:       hb(t, v.AboveCeiling.PrevHex),
	}
	// byte-parity of the well-formed-but-forbidden body against the oracle
	if got := hex.EncodeToString(above.Bytes()); got != v.AboveCeiling.BodyHex {
		t.Fatalf("above-ceiling body\n got %s\nwant %s", got, v.AboveCeiling.BodyHex)
	}
	err := continuation.VerifyContinuation(above, open.ID(), hb(t, v.AboveCeiling.PrevHex), v.AboveCeiling.Seq, ceiling)
	if err != continuation.ErrAboveCeiling {
		t.Fatalf("above-ceiling got %v, want AboveCeiling", err)
	}
	// A within-ceiling effect at the same position is accepted (positive control).
	ok := above
	ok.Effect = uint64(policy.NonIdempotentWrite) // == ceiling
	if err := continuation.VerifyContinuation(ok, open.ID(), hb(t, v.AboveCeiling.PrevHex), v.AboveCeiling.Seq, ceiling); err != nil {
		t.Fatalf("within-ceiling positive control: %v", err)
	}
}

// TestCheckpointDetectsGap: a checkpoint over a prefix with a dropped/reordered link is GapDetected;
// an honest checkpoint verifies. Mutation: drop the contiguity/count/head checks in VerifyCheckpoint.
func TestCheckpointDetectsGap(t *testing.T) {
	v := loadVec(t)
	open := openFrom(t, v)
	conts := contsFrom(t, v)

	// Honest checkpoint over seq 0..1 verifies.
	cp := continuation.Checkpoint{FlowOpenID: open.ID(), ThroughSeq: v.Checkpoint.ThroughSeq, Head: hb(t, v.Checkpoint.HeadHex)}
	if err := continuation.VerifyCheckpoint(cp, open, conts[:v.Checkpoint.ThroughSeq+1]); err != nil {
		t.Fatalf("honest checkpoint: %v", err)
	}
	// Gap: claim through_seq 2 but deliver only [seq0, seq2] (seq1 dropped).
	gapPrefix := []continuation.Continuation{conts[0], conts[2]}
	gapCp := continuation.Checkpoint{FlowOpenID: open.ID(), ThroughSeq: v.Gap.ThroughSeq, Head: hb(t, v.FinalHeadHex)}
	if err := continuation.VerifyCheckpoint(gapCp, open, gapPrefix); err != continuation.ErrGapDetected {
		t.Fatalf("gap checkpoint got %v, want GapDetected", err)
	}
	// Reorder: [seq1, seq0] with the right count is still a gap (seq mismatch at index 0).
	reordered := []continuation.Continuation{conts[1], conts[0]}
	rcp := continuation.Checkpoint{FlowOpenID: open.ID(), ThroughSeq: 1, Head: hb(t, v.Checkpoint.HeadHex)}
	if err := continuation.VerifyCheckpoint(rcp, open, reordered); err != continuation.ErrGapDetected {
		t.Fatalf("reordered checkpoint got %v, want GapDetected", err)
	}
	// Tampered head with the right prefix is also GapDetected.
	bad := cp
	bad.Head = append([]byte(nil), bad.Head...)
	bad.Head[0] ^= 0x01
	if err := continuation.VerifyCheckpoint(bad, open, conts[:v.Checkpoint.ThroughSeq+1]); err != continuation.ErrGapDetected {
		t.Fatalf("tampered-head checkpoint got %v, want GapDetected", err)
	}
}

// TestFlowCommitFullSignature: the FlowCommit is a real ML-DSA signature binding the whole ordered
// sequence. It verifies under the owner key; a tampered final_head is CommitMismatch; a foreign key
// fails the signature; a missing continuation makes the recomputed chain diverge.
func TestFlowCommitFullSignature(t *testing.T) {
	v := loadVec(t)
	open := openFrom(t, v)
	conts := contsFrom(t, v)
	signer, verifier := key(0x11)
	_, foreign := key(0x22)

	fc := continuation.FlowCommit{FlowOpenID: open.ID(), FinalHead: hb(t, v.FinalHeadHex)}
	obj, err := continuation.SignFlowCommit(fc, signer)
	if err != nil {
		t.Fatalf("SignFlowCommit: %v", err)
	}
	if _, err := continuation.VerifyFlowCommit(obj, cose.ProfilePublic, verifier, open, conts); err != nil {
		t.Fatalf("VerifyFlowCommit (honest): %v", err)
	}
	// Foreign key -> bad signature.
	if _, err := continuation.VerifyFlowCommit(obj, cose.ProfilePublic, foreign, open, conts); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key commit got %v, want BadSignature", err)
	}
	// Missing the last continuation -> recomputed final head differs -> CommitMismatch.
	if _, err := continuation.VerifyFlowCommit(obj, cose.ProfilePublic, verifier, open, conts[:2]); err != continuation.ErrCommitMismatch {
		t.Fatalf("short-chain commit got %v, want CommitMismatch", err)
	}
	// Tampered final_head in the signed body -> the signature no longer matches the tampered bytes.
	badFC := continuation.FlowCommit{FlowOpenID: open.ID(), FinalHead: append([]byte(nil), fc.FinalHead...)}
	badFC.FinalHead[0] ^= 0x01
	badObj, err := continuation.SignFlowCommit(badFC, signer)
	if err != nil {
		t.Fatalf("sign tampered: %v", err)
	}
	if _, err := continuation.VerifyFlowCommit(badObj, cose.ProfilePublic, verifier, open, conts); err != continuation.ErrCommitMismatch {
		t.Fatalf("tampered-head commit got %v, want CommitMismatch", err)
	}
}

// TestFlowOpenFullSignatureAndDeterminism: the FlowOpen signature verifies + reconstructs the
// authority, a foreign key is rejected, and the deterministic ML-DSA path yields byte-identical
// signatures across repeated signings (the property the Rust byte-parity test relies on).
func TestFlowOpenFullSignatureAndDeterminism(t *testing.T) {
	v := loadVec(t)
	open := openFrom(t, v)
	signer, verifier := key(0x11)
	_, foreign := key(0x22)

	obj1, err := continuation.SignFlowOpen(open, signer)
	if err != nil {
		t.Fatalf("SignFlowOpen: %v", err)
	}
	obj2, _ := continuation.SignFlowOpen(open, signer)
	if !bytes.Equal(obj1, obj2) {
		t.Fatal("ML-DSA signing is not deterministic (repeated signings differ)")
	}
	got, err := continuation.VerifyFlowOpen(obj1, cose.ProfilePublic, verifier)
	if err != nil {
		t.Fatalf("VerifyFlowOpen: %v", err)
	}
	if got.EffectCeiling != open.EffectCeiling || !bytes.Equal(got.ID(), open.ID()) {
		t.Fatal("VerifyFlowOpen did not reconstruct the authority")
	}
	if _, err := continuation.VerifyFlowOpen(obj1, cose.ProfilePublic, foreign); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key open got %v, want BadSignature", err)
	}
}

// TestCheapPathIsCheaperThanFull measures the real per-op cost of the cheap continuation verify
// (hash-chain, no signature) against the full ML-DSA FlowOpen verify, and asserts the cheap path is
// actually cheaper — the whole economic premise of N-AALP-CONT. Numbers are logged (the tasks
// Phase-2 measurement point); no number is hard-coded. Mutation: make VerifyContinuation do an
// ML-DSA verify and this assertion flips.
func TestCheapPathIsCheaperThanFull(t *testing.T) {
	v := loadVec(t)
	open := openFrom(t, v)
	conts := contsFrom(t, v)
	signer, verifier := key(0x11)
	obj, err := continuation.SignFlowOpen(open, signer)
	if err != nil {
		t.Fatalf("SignFlowOpen: %v", err)
	}
	id, prev := open.ID(), open.Head()
	ceiling := policy.NormalizeEffect(open.EffectCeiling)
	c0 := conts[0]

	const nCheap = 50000
	const nFull = 500

	t0 := time.Now()
	for i := 0; i < nCheap; i++ {
		if continuation.VerifyContinuation(c0, id, prev, 0, ceiling) != nil {
			t.Fatal("cheap verify failed mid-benchmark")
		}
		_ = c0.Head() // advancing the chain is one SHA-384 — part of the real cheap-path cost
	}
	cheap := time.Since(t0) / nCheap

	t1 := time.Now()
	for i := 0; i < nFull; i++ {
		if _, err := continuation.VerifyFlowOpen(obj, cose.ProfilePublic, verifier); err != nil {
			t.Fatal("full verify failed mid-benchmark")
		}
	}
	full := time.Since(t1) / nFull

	ratio := float64(full) / float64(cheap)
	t.Logf("cheap-path Continuation verify+advance: %v/op; full-path ML-DSA-65 FlowOpen verify: %v/op; full is %.0fx the cheap path", cheap, full, ratio)
	if cheap >= full {
		t.Fatalf("cheap path (%v/op) is not cheaper than the full ML-DSA path (%v/op)", cheap, full)
	}
}

// TestCeilingOutOfLatticeRejected is the C17 audit-fix 0a regression: the effect_ceiling and a
// continuation effect are the CLOSED C5 lattice (0..3). An out-of-lattice value (4) is well-formed
// CBOR but not a legal effect and MUST be rejected RangeError — NOT NormalizeEffect'd to destructive
// (which would silently make an out-of-range CEILING the most-permissive one, a fail-open). Mutation:
// restore `policy.NormalizeEffect(open.EffectCeiling)` in VerifyChain and the ceiling=4 case wrongly
// verifies as destructive.
func TestCeilingOutOfLatticeRejected(t *testing.T) {
	v := loadVec(t)
	bad := v.RangeReject.OutOfLatticeValue // 4
	if bad <= uint64(policy.Destructive) {
		t.Fatalf("oracle out_of_lattice_value %d is inside the lattice; fixture is wrong", bad)
	}

	// (a) Byte parity: the well-formed-but-forbidden FlowOpen body (ceiling=4) matches the oracle.
	badOpen := continuation.FlowOpen{FlowID: hb(t, v.FlowOpen.FlowIDHex), EffectCeiling: bad, Approvals: openFrom(t, v).Approvals}
	if got := hex.EncodeToString(badOpen.Bytes()); got != v.RangeReject.FlowOpenCeilingBodyHex {
		t.Fatalf("ceiling=4 FlowOpen body\n got %s\nwant %s", got, v.RangeReject.FlowOpenCeilingBodyHex)
	}
	// ParseFlowOpen rejects an out-of-lattice ceiling on decode.
	if _, err := continuation.ParseFlowOpen(hb(t, v.RangeReject.FlowOpenCeilingBodyHex)); err != continuation.ErrRange {
		t.Fatalf("ParseFlowOpen(ceiling=4) got %v, want RangeError", err)
	}
	// VerifyChain rejects an out-of-lattice ceiling (never normalizes it to destructive).
	if _, err := continuation.VerifyChain(badOpen, nil); err != continuation.ErrRange {
		t.Fatalf("VerifyChain(ceiling=4) got %v, want RangeError", err)
	}

	// (b) A continuation carrying an out-of-lattice effect (4): byte parity + ParseContinuation +
	// VerifyContinuation all reject RangeError.
	open := openFrom(t, v)
	badCont := continuation.Continuation{FlowOpenID: open.ID(), Seq: 0, Effect: bad, PayloadID: contPayloadID(t), Prev: open.Head()}
	if got := hex.EncodeToString(badCont.Bytes()); got != v.RangeReject.ContinuationEffectBodyHex {
		t.Fatalf("effect=4 Continuation body\n got %s\nwant %s", got, v.RangeReject.ContinuationEffectBodyHex)
	}
	if _, err := continuation.ParseContinuation(hb(t, v.RangeReject.ContinuationEffectBodyHex)); err != continuation.ErrRange {
		t.Fatalf("ParseContinuation(effect=4) got %v, want RangeError", err)
	}
	if err := continuation.VerifyContinuation(badCont, open.ID(), open.Head(), 0, policy.Destructive); err != continuation.ErrRange {
		t.Fatalf("VerifyContinuation(effect=4) got %v, want RangeError", err)
	}
	// An out-of-lattice CEILING passed to VerifyContinuation is also RangeError (never treated as
	// the top of the lattice).
	okCont := continuation.Continuation{FlowOpenID: open.ID(), Seq: 0, Effect: 0, PayloadID: contPayloadID(t), Prev: open.Head()}
	if err := continuation.VerifyContinuation(okCont, open.ID(), open.Head(), 0, policy.Effect(bad)); err != continuation.ErrRange {
		t.Fatalf("VerifyContinuation(ceiling=4) got %v, want RangeError", err)
	}
}

// contPayloadID returns the content-id of "step-0" (the oracle's seq-0 payload) for building test
// continuations that byte-match the oracle's range-reject body.
func contPayloadID(t *testing.T) []byte {
	t.Helper()
	d := sha512.Sum384([]byte("step-0"))
	return append([]byte{0x20, 0x30}, d[:]...)
}

// TestCheckpointOverflowRejected is the C17 audit-fix 0c regression: through_seq is a 0-based index,
// so a prefix of length through_seq+1 is expected. At through_seq = u64::MAX that addition overflows
// (Go wraps to 0 and would false-accept an EMPTY prefix). VerifyCheckpoint MUST reject it
// GapDetected. Mutation: remove the math.MaxUint64 guard and an empty prefix false-verifies.
func TestCheckpointOverflowRejected(t *testing.T) {
	v := loadVec(t)
	open := openFrom(t, v)
	through, err := strconv.ParseUint(v.CheckpointOverflow.ThroughSeqStr, 10, 64)
	if err != nil {
		t.Fatalf("parse through_seq_str: %v", err)
	}
	if through != math.MaxUint64 {
		t.Fatalf("oracle through_seq %d is not u64::MAX; fixture is wrong", through)
	}
	// Byte parity of the overflow checkpoint body against the oracle.
	cp := continuation.Checkpoint{FlowOpenID: open.ID(), ThroughSeq: through, Head: hb(t, v.CheckpointOverflow.HeadHex)}
	if got := hex.EncodeToString(cp.Bytes()); got != v.CheckpointOverflow.BodyHex {
		t.Fatalf("overflow checkpoint body\n got %s\nwant %s", got, v.CheckpointOverflow.BodyHex)
	}
	// An empty prefix presented against the u64::MAX claim is rejected GapDetected (no MAX+1 links).
	if err := continuation.VerifyCheckpoint(cp, open, nil); err != continuation.ErrGapDetected {
		t.Fatalf("overflow checkpoint got %v, want GapDetected", err)
	}
	// ParseCheckpoint round-trips the overflow body byte-exact (the >2^64 counter is not corrupted).
	got, err := continuation.ParseCheckpoint(hb(t, v.CheckpointOverflow.BodyHex))
	if err != nil {
		t.Fatalf("ParseCheckpoint(overflow): %v", err)
	}
	if got.ThroughSeq != math.MaxUint64 {
		t.Fatalf("ParseCheckpoint through_seq %d, want u64::MAX (counter corrupted)", got.ThroughSeq)
	}
}

// TestParseContinuationAudited is the C17 audit-fix 0e regression: ParseContinuation is the single
// audited decode path for untrusted Continuation wire bytes. It round-trips a well-formed body and
// rejects an out-of-lattice effect (covered above). Mutation: drop the inLattice check in
// ParseContinuation and the effect=4 body wrongly decodes.
func TestParseContinuationAudited(t *testing.T) {
	v := loadVec(t)
	conts := contsFrom(t, v)
	for i, c := range conts {
		got, err := continuation.ParseContinuation(c.Bytes())
		if err != nil {
			t.Fatalf("ParseContinuation[%d]: %v", i, err)
		}
		if !bytes.Equal(got.Bytes(), c.Bytes()) {
			t.Fatalf("ParseContinuation[%d] did not round-trip byte-exact", i)
		}
	}
}

// TestOversizedSeqRoundTrip is Phase 6 edge case #3 (the >2^53 discipline): a continuation seq above
// 2^53 (0x0102030405060708 = 72623859790382856) MUST round-trip byte-exact through the impl (uint64
// all the way, no float64). The oracle carries the value as a JSON STRING; the test parses it with a
// 64-bit integer parser (never a float64), so the low octets are never rounded. Mutation: truncate
// seq to a float64 anywhere and the body_hex / recovered seq diverge.
func TestOversizedSeqRoundTrip(t *testing.T) {
	v := loadVec(t)
	seq, err := strconv.ParseUint(v.BigSeq.SeqStr, 10, 64)
	if err != nil {
		t.Fatalf("parse seq_str: %v", err)
	}
	if seq <= 1<<53 {
		t.Fatalf("oracle big seq %d is not > 2^53; fixture is wrong", seq)
	}
	open := openFrom(t, v)
	c := continuation.Continuation{
		FlowOpenID: open.ID(),
		Seq:        seq,
		Effect:     v.BigSeq.Effect,
		PayloadID:  hb(t, v.BigSeq.PayloadIDHex),
		Prev:       hb(t, v.BigSeq.PrevHex),
	}
	if got := hex.EncodeToString(c.Bytes()); got != v.BigSeq.BodyHex {
		t.Fatalf("big-seq body\n got %s\nwant %s", got, v.BigSeq.BodyHex)
	}
	if got := hex.EncodeToString(c.Head()); got != v.BigSeq.HeadHex {
		t.Fatalf("big-seq head got %s want %s", got, v.BigSeq.HeadHex)
	}
	// Decode the body back and confirm the seq survives byte-exact (no float rounding).
	got, err := continuation.ParseContinuation(c.Bytes())
	if err != nil {
		t.Fatalf("ParseContinuation(big seq): %v", err)
	}
	if got.Seq != seq {
		t.Fatalf("recovered seq %d != %d (>2^53 corrupted)", got.Seq, seq)
	}
}

// TestMinimalFlowOpen is Phase 6 edge case #4: the smallest valid FlowOpen (empty flow_id, ceiling
// read_only, no approvals) encodes, has a stable content-id, and reconstructs from its bytes alone.
func TestMinimalFlowOpen(t *testing.T) {
	v := loadVec(t)
	apps := make([][]byte, 0)
	for _, a := range v.Minimal.ApprovalsHex {
		apps = append(apps, hb(t, a))
	}
	m := continuation.FlowOpen{FlowID: hb(t, v.Minimal.FlowIDHex), EffectCeiling: v.Minimal.EffectCeiling, Approvals: apps}
	if got := hex.EncodeToString(m.Bytes()); got != v.Minimal.BodyHex {
		t.Fatalf("minimal FlowOpen body\n got %s\nwant %s", got, v.Minimal.BodyHex)
	}
	if got := hex.EncodeToString(m.Head()); got != v.Minimal.HeadHex {
		t.Fatalf("minimal FlowOpen head got %s want %s", got, v.Minimal.HeadHex)
	}
	if got := hex.EncodeToString(m.ID()); got != v.Minimal.IDHex {
		t.Fatalf("minimal FlowOpen id got %s want %s", got, v.Minimal.IDHex)
	}
	got, err := continuation.ParseFlowOpen(m.Bytes())
	if err != nil {
		t.Fatalf("ParseFlowOpen(minimal): %v", err)
	}
	if !bytes.Equal(got.ID(), m.ID()) {
		t.Fatal("minimal FlowOpen did not round-trip to the same id")
	}
}

// TestEmptyVsNonemptyApprovals is Phase 6 edge case #2: an empty approvals[] is DISTINCT on the wire
// and by content-id from a populated one — the empty list is never conflated with a non-empty one.
func TestEmptyVsNonemptyApprovals(t *testing.T) {
	v := loadVec(t)
	empty := continuation.FlowOpen{FlowID: hb(t, v.FlowOpen.FlowIDHex), EffectCeiling: v.FlowOpen.EffectCeiling, Approvals: [][]byte{}}
	one := continuation.FlowOpen{FlowID: hb(t, v.FlowOpen.FlowIDHex), EffectCeiling: v.FlowOpen.EffectCeiling, Approvals: [][]byte{hb(t, v.FlowOpen.ApprovalsHex[0])}}
	if got := hex.EncodeToString(empty.Bytes()); got != v.EmptyVsNonempty.EmptyApprovals.BodyHex {
		t.Fatalf("empty-approvals body\n got %s\nwant %s", got, v.EmptyVsNonempty.EmptyApprovals.BodyHex)
	}
	if got := hex.EncodeToString(one.Bytes()); got != v.EmptyVsNonempty.OneApproval.BodyHex {
		t.Fatalf("one-approval body\n got %s\nwant %s", got, v.EmptyVsNonempty.OneApproval.BodyHex)
	}
	if bytes.Equal(empty.ID(), one.ID()) {
		t.Fatal("empty and one-approval FlowOpens must have distinct content-ids")
	}
	if hex.EncodeToString(empty.ID()) != v.EmptyVsNonempty.EmptyApprovals.IDHex {
		t.Fatal("empty-approvals id diverges from the oracle")
	}
}

// TestKeysOutOfOrderRejected is Phase 6 edge case #1: the canonical encoder emits ascending map keys,
// and a hand-built body with keys in DESCENDING order (same content) is rejected NonCanonical by the
// strict shared decoder every family's Parse* consults (RFC 8949 §4.2.1). Mutation: relax the
// key-order check in the codec and the descending body wrongly decodes.
func TestKeysOutOfOrderRejected(t *testing.T) {
	v := loadVec(t)
	canon := hb(t, v.KeysOutOfOrder.CanonicalCommitBodyHex)
	noncanon := hb(t, v.KeysOutOfOrder.NoncanonicalCommitBodyHex)
	// The canonical encoder produces ascending keys (matches a FlowCommit's own Bytes()).
	open := openFrom(t, v)
	fc := continuation.FlowCommit{FlowOpenID: open.ID(), FinalHead: hb(t, v.FinalHeadHex)}
	if got := hex.EncodeToString(fc.Bytes()); got != v.KeysOutOfOrder.CanonicalCommitBodyHex {
		t.Fatalf("canonical FlowCommit body\n got %s\nwant %s", got, v.KeysOutOfOrder.CanonicalCommitBodyHex)
	}
	// The canonical body decodes; the descending-key body is rejected NonCanonical.
	if _, err := cbor.Decode(canon); err != nil {
		t.Fatalf("canonical commit body should decode: %v", err)
	}
	_, err := cbor.Decode(noncanon)
	ce, ok := err.(*cbor.Error)
	if !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("descending-key body got %v, want NonCanonical", err)
	}
}

// TestLookAlikeRejectedBySibling is Phase 6 edge case #5: a 2-field FlowCommit body closely resembles
// the family's other objects but is not a Checkpoint (3 fields) or a Continuation (5 fields); feeding
// it to a sibling parser is rejected. Mutation: make ParseCheckpoint tolerate a missing field 3 and
// the look-alike wrongly parses.
func TestLookAlikeRejectedBySibling(t *testing.T) {
	v := loadVec(t)
	commitBody := hb(t, v.LookAlike.FlowCommitBodyHex)
	if _, err := continuation.ParseCheckpoint(commitBody); err != continuation.ErrMalformed {
		t.Fatalf("FlowCommit body parsed as Checkpoint got %v, want ContMalformed", err)
	}
	if _, err := continuation.ParseContinuation(commitBody); err != continuation.ErrMalformed {
		t.Fatalf("FlowCommit body parsed as Continuation got %v, want ContMalformed", err)
	}
}

// crossLangSeed is the shared 32-byte ML-DSA seed both languages sign the FlowOpen with, so a Go
// verifier and a Rust verifier accept each other's FlowOpen objects. The pinned SHA-384 below is
// the digest of the deterministic COSE_Sign1 object; the Rust continuation test pins the same value.
const crossLangPinnedSignedOpenSHA384 = "13d7ab1f7d96ddb79df596eaff2ec423d9d2fbe5aab4a88d1052fb7ccf36cceb07b7706d8b231dab7efd695aa5892e6a"

// TestCrossLangSignedOpenPin proves Go and Rust produce a byte-identical signed FlowOpen for the
// same body + seed (deterministic ML-DSA-65 over identical canonical CBOR). Mutation: change the
// FlowOpen encoding or the signing input and the digest diverges from the pin.
func TestCrossLangSignedOpenPin(t *testing.T) {
	v := loadVec(t)
	open := openFrom(t, v)
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 0x11
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	obj, err := continuation.SignFlowOpen(open, cose.MLDSA65Signer{SK: sk})
	if err != nil {
		t.Fatalf("SignFlowOpen: %v", err)
	}
	d := sha512.Sum384(obj)
	got := hex.EncodeToString(d[:])
	t.Logf("CROSS-LANG signed FlowOpen SHA-384 (seed=0x11*32): %s", got)
	if crossLangPinnedSignedOpenSHA384 != "PIN_ME" && got != crossLangPinnedSignedOpenSHA384 {
		t.Fatalf("cross-lang signed-open digest %s != pinned %s", got, crossLangPinnedSignedOpenSHA384)
	}
}
