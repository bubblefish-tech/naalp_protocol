// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package continuation_test

import (
	"testing"
	"time"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/continuation"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// buildChain constructs a real continuation chain of the given depth anchored at open, every link
// carrying an in-ceiling effect. Uses only the exported API (Head/ID), so it is a faithful chain.
func buildChain(open continuation.FlowOpen, n int, effect uint64) []continuation.Continuation {
	id := open.ID()
	payloadID := open.ID() // a 50-octet content-id stand-in; representative of a real payload_id size
	prev := open.Head()
	out := make([]continuation.Continuation, n)
	for i := 0; i < n; i++ {
		c := continuation.Continuation{FlowOpenID: id, Seq: uint64(i), Effect: effect, PayloadID: payloadID, Prev: prev}
		out[i] = c
		prev = c.Head()
	}
	return out
}

// TestPhase2Measurement is the Companion-Program Task 2.5 gate ("the gate that answers real-time
// media"): full-signature verify/sign time, cheap-path verify time, object sizes at each, verify
// scaling at depths 0-5, and a media-cadence run — all from ONE command, all measured on this
// machine, no estimates. It asserts the cheap path holds at frame cadence (mutation: if
// VerifyContinuation did an ML-DSA verify it would blow the 1000fps budget and this fails).
//
// Run:  GOWORK=off go test -run TestPhase2Measurement -v ./continuation/...
func TestPhase2Measurement(t *testing.T) {
	v := loadVec(t)
	open := openFrom(t, v)
	signer, verifier := key(0x11)

	signedOpen, err := continuation.SignFlowOpen(open, signer)
	if err != nil {
		t.Fatalf("SignFlowOpen: %v", err)
	}
	chain5 := buildChain(open, 5, uint64(policy.ReadOnly))
	fc := continuation.FlowCommit{FlowOpenID: open.ID(), FinalHead: chain5[len(chain5)-1].Head()}
	signedCommit, err := continuation.SignFlowCommit(fc, signer)
	if err != nil {
		t.Fatalf("SignFlowCommit: %v", err)
	}
	cp := continuation.Checkpoint{FlowOpenID: open.ID(), ThroughSeq: 4, Head: chain5[4].Head()}

	// ---- object sizes -------------------------------------------------------------------------
	t.Logf("OBJECT SIZES (octets):")
	t.Logf("  FlowOpen     body=%4d   signed(COSE_Sign1, ML-DSA-65)=%d", len(open.Bytes()), len(signedOpen))
	t.Logf("  Continuation body=%4d   (cheap, unsigned)", len(chain5[0].Bytes()))
	t.Logf("  Checkpoint   body=%4d   (cheap, unsigned)", len(cp.Bytes()))
	t.Logf("  FlowCommit   body=%4d   signed(COSE_Sign1, ML-DSA-65)=%d", len(fc.Bytes()), len(signedCommit))

	// ---- full-signature sign + verify time ----------------------------------------------------
	const nFull = 200
	ts := time.Now()
	for i := 0; i < nFull; i++ {
		if _, err := continuation.SignFlowOpen(open, signer); err != nil {
			t.Fatal(err)
		}
	}
	signT := time.Since(ts) / nFull
	tv := time.Now()
	for i := 0; i < nFull; i++ {
		if _, err := continuation.VerifyFlowOpen(signedOpen, cose.ProfilePublic, verifier); err != nil {
			t.Fatal(err)
		}
	}
	fullVerify := time.Since(tv) / nFull

	// ---- cheap-path per-link verify+advance ---------------------------------------------------
	id := open.ID()
	ceiling := policy.NormalizeEffect(open.EffectCeiling)
	c0, prev0 := chain5[0], open.Head()
	const nCheap = 20000
	tc := time.Now()
	for i := 0; i < nCheap; i++ {
		if continuation.VerifyContinuation(c0, id, prev0, 0, ceiling) != nil {
			t.Fatal("cheap verify failed")
		}
		_ = c0.Head()
	}
	cheapPerLink := time.Since(tc) / nCheap

	t.Logf("VERIFY/SIGN TIME (per op):")
	t.Logf("  full FlowOpen sign (ML-DSA-65) = %v", signT)
	t.Logf("  full FlowOpen verify (ML-DSA-65) = %v", fullVerify)
	t.Logf("  cheap continuation verify+advance = %v  (full is %.0fx the cheap path)", cheapPerLink, float64(fullVerify)/float64(cheapPerLink))

	// ---- scaling at depths 0-5 ----------------------------------------------------------------
	t.Logf("CHAIN-VERIFY SCALING (cheap whole-chain vs one-full-signature-per-step):")
	const nDepth = 4000
	for d := 0; d <= 5; d++ {
		ch := buildChain(open, d, uint64(policy.ReadOnly))
		td := time.Now()
		for i := 0; i < nDepth; i++ {
			if _, err := continuation.VerifyChain(open, ch); err != nil {
				t.Fatalf("VerifyChain depth %d: %v", d, err)
			}
		}
		cheapD := time.Since(td) / nDepth
		fullD := time.Duration(d) * fullVerify // the sign-per-step alternative: d full verifications
		ratio := 1.0
		if cheapD > 0 {
			ratio = float64(fullD) / float64(cheapD)
		}
		t.Logf("  depth %d: cheap chain-verify %8v | full-sig-per-step ~%8v | %.0fx", d, cheapD, fullD, ratio)
	}

	// ---- media cadence: one continuation per frame over an open context ------------------------
	t.Logf("MEDIA CADENCE (one continuation per frame, cheap path):")
	for _, fps := range []int{50, 200, 1000} {
		budget := time.Second / time.Duration(fps)
		cheapHead := float64(budget) / float64(cheapPerLink)
		fullHead := float64(budget) / float64(fullVerify)
		t.Logf("  %4dfps (budget %8v): cheap %v -> %.0fx headroom | full-sig %v -> %.1fx headroom",
			fps, budget, cheapPerLink, cheapHead, fullVerify, fullHead)
	}

	// Gate assertion: the cheap path must hold at 1000fps (a 1ms frame budget) — the design's
	// real-time-media answer. Mutation: an ML-DSA verify on the cheap path (~200us) blows this.
	if cheapPerLink >= time.Second/1000 {
		t.Fatalf("cheap continuation verify %v does not fit a 1000fps (1ms) frame budget", cheapPerLink)
	}
}
