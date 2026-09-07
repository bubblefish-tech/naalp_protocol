// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package multiagent

import (
	"bytes"
	"sort"
	"sync"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/ecosystem/naalp-agent-go/react"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func sharedAction(sharedInputID []byte) (react.Action, error) {
	return react.Action{Name: "branch"}, nil
}

func TestNewParallelFanoutRejectsDuplicateAgentID(t *testing.T) {
	branches := []Branch{
		{AgentID: "x", Bridge: &recordingBridge{name: "x1"}, Executor: echoBranchExecutor, BuildAction: sharedAction},
		{AgentID: "x", Bridge: &recordingBridge{name: "x2"}, Executor: echoBranchExecutor, BuildAction: sharedAction},
	}
	_, err := NewParallelFanout(branches)
	me, ok := err.(*Error)
	if !ok || me.Kind != "DuplicateAgentId" {
		t.Fatalf("expected *Error{Kind: DuplicateAgentId}, got %#v", err)
	}
}

func echoBranchExecutor(branch Branch, request react.Request) ([]byte, error) {
	return []byte("resp-" + branch.AgentID), nil
}

func TestFanoutRunConcurrentBranchesReconcileDeterministically(t *testing.T) {
	sharedID := []byte{0xAA}
	makeBranches := func() []Branch {
		return []Branch{
			{AgentID: "agent-1", Bridge: &recordingBridge{name: "agent-1", respObs: react.Observation{OK: true, Name: "R"}}, Executor: echoBranchExecutor, BuildAction: sharedAction},
			{AgentID: "agent-2", Bridge: &recordingBridge{name: "agent-2", respObs: react.Observation{OK: true, Name: "R"}}, Executor: echoBranchExecutor, BuildAction: sharedAction},
			{AgentID: "agent-3", Bridge: &recordingBridge{name: "agent-3", respObs: react.Observation{OK: true, Name: "R"}}, Executor: echoBranchExecutor, BuildAction: sharedAction},
		}
	}

	var orders [][][]byte
	for i := 0; i < 20; i++ {
		f, err := NewParallelFanout(makeBranches())
		if err != nil {
			t.Fatalf("NewParallelFanout: %v", err)
		}
		run, err := f.Run(sharedID)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(run.Executed()) != 3 {
			t.Fatalf("expected 3 executed branches, got %v", run.Executed())
		}
		if string(run.ReconciledOrder[0]) != string(sharedID) {
			t.Fatalf("expected the shared input first in the reconciled order, got %x", run.ReconciledOrder[0])
		}
		orders = append(orders, run.ReconciledOrder)
	}

	for i := 1; i < len(orders); i++ {
		if len(orders[i]) != len(orders[0]) {
			t.Fatalf("run %d produced a different-length order", i)
		}
		for j := range orders[0] {
			if !bytes.Equal(orders[i][j], orders[0][j]) {
				t.Fatalf("run %d order diverged from run 0 at position %d: %x vs %x", i, j, orders[i][j], orders[0][j])
			}
		}
	}
}

func TestFanoutExcludesRefusedBranchesFromReconciledGraph(t *testing.T) {
	sharedID := []byte{0xBB}
	branches := []Branch{
		{AgentID: "good", Bridge: &recordingBridge{name: "good", respObs: react.Observation{OK: true, Name: "R"}}, Executor: echoBranchExecutor, BuildAction: sharedAction},
		{AgentID: "bad-verify", Bridge: &recordingBridge{name: "bad", respObs: react.Observation{OK: false, Error: "WrongAudience"}}, Executor: echoBranchExecutor, BuildAction: sharedAction},
		{AgentID: "bad-sign", Bridge: &recordingBridge{name: "badsign", refuseSign: true}, Executor: echoBranchExecutor, BuildAction: sharedAction},
	}
	f, err := NewParallelFanout(branches)
	if err != nil {
		t.Fatalf("NewParallelFanout: %v", err)
	}
	run, err := f.Run(sharedID)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if run.BranchResults["good"].Status != "executed" {
		t.Fatalf("expected good executed, got %s", run.BranchResults["good"].Status)
	}
	if run.BranchResults["bad-verify"].Status != "excluded" || run.BranchResults["bad-verify"].Error != "WrongAudience" {
		t.Fatalf("expected bad-verify excluded/WrongAudience, got %#v", run.BranchResults["bad-verify"])
	}
	if run.BranchResults["bad-sign"].Status != "excluded" || run.BranchResults["bad-sign"].Error != "SigningOrExecutionRefused" {
		t.Fatalf("expected bad-sign excluded/SigningOrExecutionRefused, got %#v", run.BranchResults["bad-sign"])
	}
	// reconciled order: shared input + exactly the ONE executed branch's request id.
	if len(run.ReconciledOrder) != 2 {
		t.Fatalf("expected 2 nodes in the reconciled order (shared + good), got %d: %x", len(run.ReconciledOrder), run.ReconciledOrder)
	}
}

func TestReconcileNodesRejectsCyclicGraph(t *testing.T) {
	a := []byte{1}
	b := []byte{2}
	_, err := ReconcileNodes([]CausalNode{
		{ID: a, Causes: [][]byte{b}},
		{ID: b, Causes: [][]byte{a}},
	})
	if err == nil {
		t.Fatal("expected a CausalViolation error for a cyclic graph")
	}
}

func TestReconcileNodesTieBreaksByContentID(t *testing.T) {
	// Three causally-concurrent nodes (no edges among them): the deterministic order
	// must be bytewise-ascending by content id, regardless of input order.
	n3 := CausalNode{ID: []byte{0x03}}
	n1 := CausalNode{ID: []byte{0x01}}
	n2 := CausalNode{ID: []byte{0x02}}
	order, err := ReconcileNodes([]CausalNode{n3, n1, n2})
	if err != nil {
		t.Fatalf("ReconcileNodes: %v", err)
	}
	want := [][]byte{{0x01}, {0x02}, {0x03}}
	for i := range want {
		if !bytes.Equal(order[i], want[i]) {
			t.Fatalf("expected bytewise-ascending tie-break, got %x", order)
		}
	}
}

// TestConcurrentSignVerifyNoCorruption empirically confirms (E8: assume nothing) that
// the Go Part-1 reference SDK's ML-DSA backend (github.com/cloudflare/circl) is safe
// under concurrent Sign/Verify calls from many goroutines, unlike the Python reference
// SDK's dilithium_py backend, which the sibling naalp_multiagent Python package's
// CRYPTO_LOCK exists specifically to work around (see this package's fanout.go module
// docstring). This test drives the SAME kind of concurrent load the Python package's own
// docstring reports finding corruption under (8 threads, sign+verify in a tight loop),
// run here with `go test -race` so both a logical-corruption assertion AND the Go race
// detector must agree nothing is shared unsafely.
func TestConcurrentSignVerifyNoCorruption(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = 0x77
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	signer := cose.MLDSA65Signer{SK: sk}
	verifier := cose.MLDSA65Verifier{PK: pk}

	const goroutines = 16
	const iterations = 20
	var wg sync.WaitGroup
	failures := make(chan string, goroutines*iterations)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				msg := []byte{byte(g), byte(i)}
				sig, err := signer.Sign(msg)
				if err != nil {
					failures <- "sign error"
					continue
				}
				if !verifier.VerifyRaw(msg, sig) {
					failures <- "verify failed on a signature this same call just produced"
				}
			}
		}(g)
	}
	wg.Wait()
	close(failures)

	var got []string
	for f := range failures {
		got = append(got, f)
	}
	if len(got) != 0 {
		sort.Strings(got)
		t.Fatalf("%d concurrent sign/verify failures (expected 0): %v", len(got), got[:min(5, len(got))])
	}
}
