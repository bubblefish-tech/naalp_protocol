// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package approval_test

// Behavioral graders for two trust-decision closure-sovereignty requirements (design.md §25, C22):
//   - R-TDCS-4 (freshness independence): a credential's present-moment validity is judged against an
//     ordering authority STRUCTURALLY DISTINCT from the party being authenticated; a party stamping
//     its own freshness is rejected FreshnessSelfAsserted.
//   - R-TDCS-2 (deterministic verification): verification is a pure function of (object, key,
//     posTime) — the same inputs yield the same verdict on every call, with no dependence on a
//     clock, RNG, map order, or call count.
//
// Each is mutation-surviving: removing the R-TDCS-4 distinctness check flips TestTDCS4..., and
// injecting nondeterminism into VerifyApproval flips TestTDCS2... (recorded in .shippable/red-evidence).

import (
	"bytes"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// freshScenario builds a valid signed approval and a ledger-signed consume receipt for it, with the
// approver, the ordering-authority ledger, and (returned separately) an authenticated-party id that
// the caller chooses distinct or self-referential. posTime is set at the approval's not_after (still
// valid). ledgerID is the ordering authority's id; approverID is the authenticated party's id.
func freshScenario(t *testing.T) (
	a approval.ApprovalRecord, approverV cose.Verifier, aSig, argsID []byte, posTime uint64,
	r approval.ConsumeReceipt, ledgerV cose.Verifier, rSig, ledgerID, approverID []byte,
) {
	t.Helper()
	approverS, aV := ledgerKey(t, 0x11) // the approver's key (the authenticated party)
	ledgerS, lV := ledgerKey(t, 0x22)   // the ordering authority (ledger) — a DISTINCT key
	argsID = []byte("the-exact-canonical-args-content-id")
	approverID = []byte("approver-authenticated-party-id")
	ledgerID = []byte("ordering-authority-ledger-id")
	a = approval.ApprovalRecord{
		Approves: argsID,
		Approver: "approver-authenticated-party-id",
		Grant:    1,
		Nonce:    []byte("anti-replay-nonce"),
		NotAfter: 1000,
	}
	sig, err := approval.SignApproval(a, approverS)
	if err != nil {
		t.Fatalf("SignApproval: %v", err)
	}
	r = approval.ConsumeReceipt{Ledger: ledgerID, ApprovalID: a.ID(), Position: 7}
	rs, err := approval.SignConsumeReceipt(r, ledgerS)
	if err != nil {
		t.Fatalf("SignConsumeReceipt: %v", err)
	}
	return a, aV, sig, argsID, 1000, r, lV, rs, ledgerID, approverID
}

// TestTDCS4FreshnessIndependence: R-TDCS-4. When the ordering authority is distinct from the
// authenticated party, an unexpired, correctly-signed approval with a valid ledger receipt verifies.
// When the ordering authority IS the authenticated party (the party stamping its own freshness), it
// is rejected FreshnessSelfAsserted — the load-bearing distinctness the closure property requires.
func TestTDCS4FreshnessIndependence(t *testing.T) {
	a, approverV, aSig, argsID, posTime, r, ledgerV, rSig, ledgerID, approverID := freshScenario(t)

	// Distinct ordering authority (party != ledger): verifies.
	if err := approval.VerifyFreshIndependent(a, approverV, aSig, argsID, posTime, r, ledgerV, rSig, approverID); err != nil {
		t.Fatalf("distinct ordering authority should verify, got %v", err)
	}

	// Self-asserted freshness (party == ledger): the party is the source of its own time — rejected.
	if err := approval.VerifyFreshIndependent(a, approverV, aSig, argsID, posTime, r, ledgerV, rSig, ledgerID); err == nil {
		t.Fatal("self-asserted freshness (party == ordering authority) must be rejected, got nil")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "FreshnessSelfAsserted" {
		t.Fatalf("want FreshnessSelfAsserted, got %v", err)
	}

	// The distinctness check does not weaken the underlying checks: an expired approval still fails
	// closed (posTime past not_after), and a distinct authority does not rescue it.
	if err := approval.VerifyFreshIndependent(a, approverV, aSig, argsID, a.NotAfter+1, r, ledgerV, rSig, approverID); err == nil {
		t.Fatal("expired approval must still be rejected under a distinct authority")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ApprovalExpired" {
		t.Fatalf("want ApprovalExpired, got %v", err)
	}

	// A receipt with no named ordering authority is not evidence (unnamed authority), even when the
	// party id supplied is distinct.
	empty := approval.ConsumeReceipt{Ledger: nil, ApprovalID: a.ID(), Position: 7}
	emptySig, _ := approval.SignConsumeReceipt(empty, mustLedgerSigner(t))
	if err := approval.VerifyFreshIndependent(a, approverV, aSig, argsID, posTime, empty, ledgerV, emptySig, approverID); err == nil {
		t.Fatal("unnamed ordering authority must not be accepted as freshness evidence")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ConsumeReceiptUnsigned" {
		t.Fatalf("want ConsumeReceiptUnsigned, got %v", err)
	}
}

// mustLedgerSigner returns a throwaway ledger signer for negative-path receipts.
func mustLedgerSigner(t *testing.T) cose.Signer {
	t.Helper()
	s, _ := ledgerKey(t, 0x33)
	return s
}

// TestTDCS2VerificationDeterminism: R-TDCS-2. VerifyApproval is a pure function of its inputs — the
// same (approval, key, args, posTime) yields the same verdict on every call. Calling it many times,
// interleaving accept and reject inputs, must return the identical verdict each time, proving the
// verify path depends on no clock, RNG, map iteration order, or call count. Injecting nondeterminism
// into the verify path flips this (recorded red-evidence).
func TestTDCS2VerificationDeterminism(t *testing.T) {
	approverS, approverV := ledgerKey(t, 0x11)
	argsID := []byte("the-exact-canonical-args-content-id")
	wrong := []byte("a-different-args-content-id-------")
	a := approval.ApprovalRecord{
		Approves: argsID,
		Approver: "approver",
		Grant:    1,
		Nonce:    []byte("nonce"),
		NotAfter: 1000,
	}
	sig, err := approval.SignApproval(a, approverS)
	if err != nil {
		t.Fatalf("SignApproval: %v", err)
	}

	const iters = 256
	// Accept path: identical nil verdict every time; and the signed body bytes are byte-stable.
	wantBody := a.Bytes()
	for i := 0; i < iters; i++ {
		if err := approval.VerifyApproval(a, approverV, sig, argsID, 500); err != nil {
			t.Fatalf("iter %d: valid approval verdict changed to %v (non-deterministic accept)", i, err)
		}
		if got := a.Bytes(); !bytes.Equal(got, wantBody) {
			t.Fatalf("iter %d: encoding is not byte-stable (non-deterministic serialization)", i)
		}
		// Interleave a reject input to prove no cross-call state leaks between verdicts.
		if err := approval.VerifyApproval(a, approverV, sig, wrong, 500); err == nil {
			t.Fatalf("iter %d: wrong-args approval accepted (non-deterministic reject)", i)
		} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ApprovalMismatch" {
			t.Fatalf("iter %d: reject verdict changed to %v (non-deterministic reject)", i, err)
		}
	}
}
