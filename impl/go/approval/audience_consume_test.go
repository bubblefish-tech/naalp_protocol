// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package approval

import (
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func audLedgerSigner(t *testing.T) cose.Signer {
	t.Helper()
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	return cose.MLDSA65Signer{SK: sk}
}

// TestConsumeObjectAudience: the audience-checked consume choke point (design.md §2.5.3). A
// consume-once object whose audience is wrong or absent is refused WrongAudience with NO ledger
// entry (fail-closed BEFORE the CAS); the correctly-addressed object consumes exactly once; and a
// ledger with no authority identity refuses fail-closed rather than consuming an unbound object.
// Mutation-surviving: replacing envelope.CheckAudience's body with `return nil` would let the wrong/
// absent cases append an entry and return nil, flipping this test red.
func TestConsumeObjectAudience(t *testing.T) {
	authority := []byte("authority-A")
	signer := audLedgerSigner(t)
	appID := []byte("approval-content-id-0001")
	obj := func(aud string) *envelope.Object { return &envelope.Object{Audience: aud} }

	l1, err := OpenLedgerSigned(filepath.Join(t.TempDir(), "l1.wal"), authority, signer)
	if err != nil {
		t.Fatalf("open signed ledger: %v", err)
	}
	defer l1.Close()

	// Wrong audience -> WrongAudience, no entry.
	if _, err := l1.ConsumeObject(obj("authority-B"), appID, "by-x"); !isKind(err, "WrongAudience") {
		t.Fatalf("wrong audience: want WrongAudience, got %v", err)
	}
	if l1.Len() != 0 || l1.IsConsumed(appID) {
		t.Fatalf("wrong audience must leave NO ledger entry (len=%d consumed=%v)", l1.Len(), l1.IsConsumed(appID))
	}

	// Absent audience on a consume-once path -> WrongAudience, no entry.
	if _, err := l1.ConsumeObject(obj(""), appID, "by-x"); !isKind(err, "WrongAudience") {
		t.Fatalf("absent audience: want WrongAudience, got %v", err)
	}
	if l1.Len() != 0 {
		t.Fatalf("absent audience must leave NO ledger entry (len=%d)", l1.Len())
	}

	// Correct audience -> consumes exactly once.
	if _, err := l1.ConsumeObject(obj("authority-A"), appID, "by-x"); err != nil {
		t.Fatalf("correct audience: want consume, got %v", err)
	}
	if l1.Len() != 1 || !l1.IsConsumed(appID) {
		t.Fatalf("correct audience must consume once (len=%d consumed=%v)", l1.Len(), l1.IsConsumed(appID))
	}

	// Unnamed ledger cannot enforce the binding -> fail-closed LedgerUnsigned.
	l2, err := OpenLedger(filepath.Join(t.TempDir(), "l2.wal"))
	if err != nil {
		t.Fatalf("open plain ledger: %v", err)
	}
	defer l2.Close()
	if _, err := l2.ConsumeObject(obj("authority-A"), appID, "by-x"); !isKind(err, "LedgerUnsigned") {
		t.Fatalf("unnamed ledger: want LedgerUnsigned, got %v", err)
	}
}

func isKind(err error, kind string) bool {
	ce, ok := err.(*cose.Error)
	return ok && ce.Kind == kind
}
