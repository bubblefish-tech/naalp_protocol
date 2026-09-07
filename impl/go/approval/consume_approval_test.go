// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package approval_test

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// TestConsumeApprovalPrecedence exercises the composed consume choke point (ConsumeApproval) against
// every reaction of the draft's "## Approval state machine" table and its two precedence rules
// (ApprovalMismatch over every cell; ApprovalExpired over AlreadyConsumed), plus the effect-ceiling
// and grant-range fail-closed refusals. It is written to survive mutation: swapping the expiry check
// after the ledger flips the expiry-over-consume case; dropping the mismatch check flips the mismatch
// cases; dropping the effect/grant guard flips the ApprovalRequired cases; and appending on a rejected
// request flips a Len() assertion. The expected reactions are the draft's, not read off the code.
func TestConsumeApprovalPrecedence(t *testing.T) {
	// A deterministic Ed25519 approver key (the signature is verified, not graded).
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	priv := ed25519.NewKeyFromSeed(seed)
	verifier := cose.Ed25519Verifier{PK: priv.Public().(ed25519.PublicKey)}

	argsCID := []byte("args-content-id-A") // the content id the approval binds (opaque to the machine)
	wrongCID := []byte("args-content-id-B") // a different presented args content id -> ApprovalMismatch

	// approvalOf builds a signed approval binding argsCID with the given grant + not_after.
	approvalOf := func(grant, notAfter uint64) (approval.ApprovalRecord, []byte) {
		a := approval.ApprovalRecord{
			Approves: argsCID, Approver: "approver-1",
			Grant: grant, Nonce: []byte{0x01, 0x02}, NotAfter: notAfter,
		}
		return a, ed25519.Sign(priv, a.Bytes())
	}
	freshLedger := func() *approval.Ledger {
		l, err := approval.OpenLedger(filepath.Join(t.TempDir(), "wal"))
		if err != nil {
			t.Fatalf("OpenLedger: %v", err)
		}
		t.Cleanup(func() { l.Close() })
		return l
	}
	wantKind := func(t *testing.T, err error, kind string) {
		t.Helper()
		ce, ok := err.(*cose.Error)
		if !ok || ce.Kind != kind {
			t.Fatalf("want error kind %q, got %v", kind, err)
		}
	}
	wantLen := func(t *testing.T, l *approval.Ledger, n int) {
		t.Helper()
		if got := l.Len(); got != n {
			t.Fatalf("ledger length: want %d, got %d", n, got)
		}
	}

	// approved + consume (match, grant covers required, unexpired, fresh) -> consumed; ledger appends 1.
	t.Run("consumed", func(t *testing.T) {
		a, sig := approvalOf(uint64(policy.Destructive), 1000)
		l := freshLedger()
		if _, err := approval.ConsumeApproval(a, verifier, sig, argsCID, 500, policy.ReadOnly, l, "by-1"); err != nil {
			t.Fatalf("valid consume rejected: %v", err)
		}
		wantLen(t, l, 1)
		// consumed + consume (same id) -> AlreadyConsumed; ledger unchanged at 1.
		if _, err := approval.ConsumeApproval(a, verifier, sig, argsCID, 500, policy.ReadOnly, l, "by-1"); err == nil {
			t.Fatal("second consume accepted")
		} else {
			wantKind(t, err, "AlreadyConsumed")
		}
		wantLen(t, l, 1)
	})

	// expired + consume -> ApprovalExpired; nothing appended.
	t.Run("expired", func(t *testing.T) {
		a, sig := approvalOf(uint64(policy.Destructive), 1000)
		l := freshLedger()
		if _, err := approval.ConsumeApproval(a, verifier, sig, argsCID, 2000, policy.ReadOnly, l, "by-1"); err == nil {
			t.Fatal("expired consume accepted")
		} else {
			wantKind(t, err, "ApprovalExpired")
		}
		wantLen(t, l, 0)
	})

	// expiry over consume: a first consume succeeds; a second, now past not_after, is ApprovalExpired
	// (NOT AlreadyConsumed) because expiry is checked before the ledger, and the ledger is untouched.
	t.Run("expiry-over-consume", func(t *testing.T) {
		a, sig := approvalOf(uint64(policy.Destructive), 1000)
		l := freshLedger()
		if _, err := approval.ConsumeApproval(a, verifier, sig, argsCID, 500, policy.ReadOnly, l, "by-1"); err != nil {
			t.Fatalf("first consume rejected: %v", err)
		}
		if _, err := approval.ConsumeApproval(a, verifier, sig, argsCID, 2000, policy.ReadOnly, l, "by-1"); err == nil {
			t.Fatal("expired-second consume accepted")
		} else {
			wantKind(t, err, "ApprovalExpired") // never AlreadyConsumed
		}
		wantLen(t, l, 1)
	})

	// mismatch over every cell: presented args content id != bound id -> ApprovalMismatch, no append,
	// even when the approval is also expired (mismatch is checked before expiry).
	t.Run("mismatch-fresh", func(t *testing.T) {
		a, sig := approvalOf(uint64(policy.Destructive), 1000)
		l := freshLedger()
		if _, err := approval.ConsumeApproval(a, verifier, sig, wrongCID, 500, policy.ReadOnly, l, "by-1"); err == nil {
			t.Fatal("mismatched consume accepted")
		} else {
			wantKind(t, err, "ApprovalMismatch")
		}
		wantLen(t, l, 0)
	})
	t.Run("mismatch-over-expired", func(t *testing.T) {
		a, sig := approvalOf(uint64(policy.Destructive), 1000)
		l := freshLedger()
		if _, err := approval.ConsumeApproval(a, verifier, sig, wrongCID, 2000, policy.ReadOnly, l, "by-1"); err == nil {
			t.Fatal("mismatched-and-expired consume accepted")
		} else {
			wantKind(t, err, "ApprovalMismatch") // mismatch precedence over expiry
		}
		wantLen(t, l, 0)
	})

	// a rejected mismatch leaves the ledger clean, so a subsequent valid consume still succeeds
	// (no-state-change-on-rejection): this is the observable form of "ledger left untouched".
	t.Run("reject-then-valid", func(t *testing.T) {
		a, sig := approvalOf(uint64(policy.Destructive), 1000)
		l := freshLedger()
		if _, err := approval.ConsumeApproval(a, verifier, sig, wrongCID, 500, policy.ReadOnly, l, "by-1"); err == nil {
			t.Fatal("mismatch accepted")
		}
		wantLen(t, l, 0)
		if _, err := approval.ConsumeApproval(a, verifier, sig, argsCID, 500, policy.ReadOnly, l, "by-1"); err != nil {
			t.Fatalf("valid consume after rejected mismatch: %v", err)
		}
		wantLen(t, l, 1)
	})

	// effect ceiling: the approval's granted effect does not cover the action -> ApprovalRequired,
	// no append. (The draft is silent on this cell's code; the impl and all four callers use
	// ApprovalRequired, which ConsumeApproval mirrors — this asserts the impl's behaviour, and the
	// F3 conformance oracle deliberately does NOT grade this cell; see the progress note.)
	t.Run("insufficient-grant", func(t *testing.T) {
		a, sig := approvalOf(uint64(policy.ReadOnly), 1000) // grants read_only
		l := freshLedger()
		if _, err := approval.ConsumeApproval(a, verifier, sig, argsCID, 500, policy.Destructive, l, "by-1"); err == nil {
			t.Fatal("under-granting consume accepted")
		} else {
			wantKind(t, err, "ApprovalRequired")
		}
		wantLen(t, l, 0)
	})

	// grant-range guard: a grant outside the closed 0..3 vocabulary authorizes nothing (fail-closed),
	// rather than truncating to a byte that over-authorizes.
	t.Run("malformed-grant", func(t *testing.T) {
		a, sig := approvalOf(7, 1000) // 7 is not a valid effect class
		l := freshLedger()
		if _, err := approval.ConsumeApproval(a, verifier, sig, argsCID, 500, policy.ReadOnly, l, "by-1"); err == nil {
			t.Fatal("malformed-grant consume accepted")
		} else {
			wantKind(t, err, "ApprovalRequired")
		}
		wantLen(t, l, 0)
	})

	// bad signature: an approval whose signature does not verify authorizes nothing (checked first).
	t.Run("bad-signature", func(t *testing.T) {
		a, sig := approvalOf(uint64(policy.Destructive), 1000)
		bad := append([]byte(nil), sig...)
		bad[len(bad)-1] ^= 0x01
		l := freshLedger()
		if _, err := approval.ConsumeApproval(a, verifier, bad, argsCID, 500, policy.ReadOnly, l, "by-1"); err == nil {
			t.Fatal("bad-signature consume accepted")
		} else {
			wantKind(t, err, "BadSignature")
		}
		wantLen(t, l, 0)
	})
}
