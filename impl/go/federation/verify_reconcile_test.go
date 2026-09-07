// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package federation_test

import (
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/audit"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/federation"
)

// TestVerifyReconcileOrder exercises the verify-event choke point of the Reconcile state machine: an
// independent recomputation agrees with the record (verified), disagrees on a causally-valid but
// non-deterministic order (ReconcileMismatch), or rejects a node set that is not a valid partial
// order (CausalViolation). The mutation that neuters the order comparison flips the mismatch case.
func TestVerifyReconcileOrder(t *testing.T) {
	// Two causally-INDEPENDENT objects (no cause between them). Reconcile orders concurrent objects
	// by content id bytewise-ascending, so idA < idB => the one deterministic order is [idA, idB].
	idA := []byte{0x01}
	idB := []byte{0x02}
	concurrent := []audit.CausalNode{
		{ID: idA, Causes: nil, Position: 0},
		{ID: idB, Causes: nil, Position: 0},
	}

	wantKind := func(t *testing.T, err error, kind string) {
		t.Helper()
		ce, ok := err.(*cose.Error)
		if !ok || ce.Kind != kind {
			t.Fatalf("want error kind %q, got %v", kind, err)
		}
	}

	// verify agrees: the claimed order IS the deterministic order -> verified (nil).
	t.Run("agrees", func(t *testing.T) {
		rec := federation.ReconcileRecord{Authorities: []string{"auth-1"}, Order: [][]byte{idA, idB}}
		if err := federation.VerifyReconcileOrder(rec, concurrent); err != nil {
			t.Fatalf("agreeing record rejected: %v", err)
		}
	})

	// verify ReconcileMismatch: a causally-VALID-but-different order (the two objects are concurrent,
	// so [idB, idA] is causally valid) is not the deterministic order -> ReconcileMismatch.
	t.Run("mismatch", func(t *testing.T) {
		rec := federation.ReconcileRecord{Authorities: []string{"auth-1"}, Order: [][]byte{idB, idA}}
		err := federation.VerifyReconcileOrder(rec, concurrent)
		if err == nil {
			t.Fatal("a record claiming a non-deterministic order was accepted")
		}
		wantKind(t, err, "ReconcileMismatch")
	})

	// verify wrong-length claim -> ReconcileMismatch (a claim that drops or adds an element).
	t.Run("mismatch-length", func(t *testing.T) {
		rec := federation.ReconcileRecord{Authorities: []string{"auth-1"}, Order: [][]byte{idA}}
		wantKind(t, federation.VerifyReconcileOrder(rec, concurrent), "ReconcileMismatch")
	})

	// CausalViolation: a cyclic node set is not a valid partial order; the recomputation rejects it
	// before any order comparison, so the record is rejected under the graph fault, fail-closed.
	t.Run("causal-violation", func(t *testing.T) {
		idC := []byte{0x03}
		idD := []byte{0x04}
		cyclic := []audit.CausalNode{
			{ID: idC, Causes: [][]byte{idD}, Position: 1},
			{ID: idD, Causes: [][]byte{idC}, Position: 1},
		}
		rec := federation.ReconcileRecord{Authorities: []string{"auth-1"}, Order: [][]byte{idC, idD}}
		wantKind(t, federation.VerifyReconcileOrder(rec, cyclic), "CausalViolation")
	})
}
