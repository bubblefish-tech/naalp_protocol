// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package approval_test

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bubblefish-tech/n-aalp/impl/go/approval"
	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/approval/cases.json"

type approvalCases struct {
	Args struct {
		ContentIDHex string `json:"content_id_hex"`
	} `json:"args"`
	Approvals []struct {
		Name         string `json:"name"`
		ApprovesHex  string `json:"approves_hex"`
		Approver     string `json:"approver"`
		Grant        uint64 `json:"grant"`
		NonceHex     string `json:"nonce_hex"`
		NotAfter     uint64 `json:"not_after"`
		RecordHex    string `json:"record_hex"`
		ApprovalIDHex string `json:"approval_id_hex"`
	} `json:"approvals"`
	Ledger struct {
		GenesisHeadHex string `json:"genesis_head_hex"`
		Consumes       []struct {
			ApprovalIDHex string `json:"approval_id_hex"`
			By            string `json:"by"`
			Expect        string `json:"expect"`
			Seq           uint64 `json:"seq"`
			EntryHex      string `json:"entry_hex"`
			HeadAfterHex  string `json:"head_after_hex"`
		} `json:"consumes"`
		FinalHeadHex string `json:"final_head_hex"`
	} `json:"ledger"`
	Expiry struct {
		NotAfter  uint64 `json:"not_after"`
		ValidAt   uint64 `json:"valid_at"`
		ExpiredAt uint64 `json:"expired_at"`
	} `json:"expiry"`
	Mismatch struct {
		WrongArgsIDHex string `json:"wrong_args_id_hex"`
	} `json:"mismatch"`
}

func load(t *testing.T) approvalCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c approvalCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func recOf(t *testing.T, c approvalCases, name string) approval.ApprovalRecord {
	t.Helper()
	for _, a := range c.Approvals {
		if a.Name == name {
			return approval.ApprovalRecord{
				Approves: mustHex(t, a.ApprovesHex), Approver: a.Approver,
				Grant: a.Grant, Nonce: mustHex(t, a.NonceHex), NotAfter: a.NotAfter,
			}
		}
	}
	t.Fatalf("no approval %q", name)
	return approval.ApprovalRecord{}
}

// TestApprovalBytesMatchOracle: the approval body bytes and the approval content id equal
// the independent oracle in this implementation (⟹ Go == Rust, which grades the same file).
func TestApprovalBytesMatchOracle(t *testing.T) {
	c := load(t)
	if len(c.Approvals) == 0 {
		t.Fatal("no approvals")
	}
	for _, a := range c.Approvals {
		rec := recOf(t, c, a.Name)
		if got := hex.EncodeToString(rec.Bytes()); got != a.RecordHex {
			t.Errorf("%s record bytes\n got %s\nwant %s", a.Name, got, a.RecordHex)
		}
		if got := hex.EncodeToString(rec.ID()); got != a.ApprovalIDHex {
			t.Errorf("%s approval id\n got %s\nwant %s", a.Name, got, a.ApprovalIDHex)
		}
	}
}

// TestLedgerScenarioMatchesOracle: running the oracle's consume scenario against the durable
// ledger produces byte-identical entries and chain heads, and the second consume of an
// already-consumed approval is rejected (AlreadyConsumed).
func TestLedgerScenarioMatchesOracle(t *testing.T) {
	c := load(t)
	l, err := approval.OpenLedger(filepath.Join(t.TempDir(), "wal"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer l.Close()
	if got := hex.EncodeToString(l.Head()); got != c.Ledger.GenesisHeadHex {
		t.Fatalf("genesis head got %s want %s", got, c.Ledger.GenesisHeadHex)
	}
	for i, cons := range c.Ledger.Consumes {
		id := mustHex(t, cons.ApprovalIDHex)
		e, err := l.Consume(id, cons.By)
		switch cons.Expect {
		case "ok":
			if err != nil {
				t.Fatalf("consume %d: %v", i, err)
			}
			if e.Seq != cons.Seq {
				t.Errorf("consume %d seq got %d want %d", i, e.Seq, cons.Seq)
			}
			if got := hex.EncodeToString(e.Bytes()); got != cons.EntryHex {
				t.Errorf("consume %d entry\n got %s\nwant %s", i, got, cons.EntryHex)
			}
			if got := hex.EncodeToString(l.Head()); got != cons.HeadAfterHex {
				t.Errorf("consume %d head\n got %s\nwant %s", i, got, cons.HeadAfterHex)
			}
		case "AlreadyConsumed":
			if ce, ok := err.(*cose.Error); !ok || ce.Kind != "AlreadyConsumed" {
				t.Errorf("consume %d: want AlreadyConsumed, got %v", i, err)
			}
		}
	}
	if got := hex.EncodeToString(l.Head()); got != c.Ledger.FinalHeadHex {
		t.Errorf("final head\n got %s\nwant %s", got, c.Ledger.FinalHeadHex)
	}
}

// TestDurabilityAcrossReopen: a consume that returned survives closing and reopening the WAL
// (persist-before-ack, R-7.2). The reopened ledger still rejects a re-consume.
func TestDurabilityAcrossReopen(t *testing.T) {
	c := load(t)
	path := filepath.Join(t.TempDir(), "wal")
	idA := mustHex(t, c.Approvals[0].ApprovalIDHex)

	l, err := approval.OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Consume(idA, "c1"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	headBefore := hex.EncodeToString(l.Head())
	if err := l.Close(); err != nil { // simulates process exit after the fsync'd consume
		t.Fatal(err)
	}

	l2, err := approval.OpenLedger(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	if !l2.IsConsumed(idA) {
		t.Fatal("consume did not survive reopen")
	}
	if got := hex.EncodeToString(l2.Head()); got != headBefore {
		t.Errorf("head after reopen %s, want %s", got, headBefore)
	}
	if _, err := l2.Consume(idA, "c2"); err == nil {
		t.Fatal("re-consume after reopen accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "AlreadyConsumed" {
		t.Fatalf("want AlreadyConsumed, got %v", err)
	}
}

// TestExactlyOnceUnderRace: N goroutines consume the same approval concurrently; exactly one
// succeeds and the rest get AlreadyConsumed (R-7.2). Run under -race in the recipe.
func TestExactlyOnceUnderRace(t *testing.T) {
	c := load(t)
	l, err := approval.OpenLedger(filepath.Join(t.TempDir(), "wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	idA := mustHex(t, c.Approvals[0].ApprovalIDHex)

	const N = 64
	var wg sync.WaitGroup
	var wins, alreadys int64
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start // release all goroutines together to maximise contention
			_, err := l.Consume(idA, "consumer")
			if err == nil {
				atomic.AddInt64(&wins, 1)
			} else if ce, ok := err.(*cose.Error); ok && ce.Kind == "AlreadyConsumed" {
				atomic.AddInt64(&alreadys, 1)
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly-once violated: %d winners (want 1)", wins)
	}
	if alreadys != N-1 {
		t.Fatalf("got %d AlreadyConsumed, want %d", alreadys, N-1)
	}
	if l.Len() != 1 {
		t.Fatalf("ledger has %d entries, want 1", l.Len())
	}
}

// TestApprovalVerify: R-7.1/R-7.3 — a correct approval verifies; a mutated-args content id is
// ApprovalMismatch; an expired approval is ApprovalExpired; a tampered signature is
// BadSignature. Uses real ML-DSA-65 signing (the approver's key).
func TestApprovalVerify(t *testing.T) {
	c := load(t)
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 11
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	signer, verifier := cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}

	rec := recOf(t, c, "A")
	argsID := mustHex(t, c.Args.ContentIDHex)
	sig, err := approval.SignApproval(rec, signer)
	if err != nil {
		t.Fatal(err)
	}

	if err := approval.VerifyApproval(rec, verifier, sig, argsID, c.Expiry.ValidAt); err != nil {
		t.Fatalf("valid approval rejected: %v", err)
	}
	// R-7.1: any mutation of the args changes their content id → no longer matches.
	wrong := mustHex(t, c.Mismatch.WrongArgsIDHex)
	if err := approval.VerifyApproval(rec, verifier, sig, wrong, c.Expiry.ValidAt); err == nil {
		t.Fatal("mismatched args accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ApprovalMismatch" {
		t.Fatalf("want ApprovalMismatch, got %v", err)
	}
	// R-7.3: valid at not_after, expired after it.
	if err := approval.VerifyApproval(rec, verifier, sig, argsID, c.Expiry.ExpiredAt); err == nil {
		t.Fatal("expired approval accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ApprovalExpired" {
		t.Fatalf("want ApprovalExpired, got %v", err)
	}
	// tampered signature → BadSignature
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0x01
	if err := approval.VerifyApproval(rec, verifier, bad, argsID, c.Expiry.ValidAt); err == nil {
		t.Fatal("tampered signature accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "BadSignature" {
		t.Fatalf("want BadSignature, got %v", err)
	}
}

// TestHeldResultSigned: R-7.4 — the held outcome is a distinct signed result, not a silent
// success/denial; its bytes are attributable via the signature.
func TestHeldResultSigned(t *testing.T) {
	c := load(t)
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 12
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	h := approval.HeldResult{Approves: mustHex(t, c.Args.ContentIDHex), Reason: "awaiting approver"}
	sig, err := approval.SignHeld(h, cose.MLDSA65Signer{SK: sk})
	if err != nil {
		t.Fatal(err)
	}
	if !(cose.MLDSA65Verifier{PK: pk}).VerifyRaw(h.Bytes(), sig) {
		t.Fatal("held result signature does not verify")
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0x01
	if (cose.MLDSA65Verifier{PK: pk}).VerifyRaw(h.Bytes(), bad) {
		t.Fatal("tampered held-result signature verified")
	}
}

// TestLedgerCorruptDetected: the mutation test for the chain — a WAL whose second entry does
// not link to the first (its prev ≠ SHA-384(entry0)) is rejected on open (LedgerCorrupt). A
// replay that ignored `prev` would accept it.
func TestLedgerCorruptDetected(t *testing.T) {
	c := load(t)
	path := filepath.Join(t.TempDir(), "wal")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writeRec := func(rec []byte) {
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(rec)))
		if _, err := f.Write(append(lb[:], rec...)); err != nil {
			t.Fatal(err)
		}
	}
	idA := mustHex(t, c.Approvals[0].ApprovalIDHex)
	idB := mustHex(t, c.Approvals[1].ApprovalIDHex)
	genesis := make([]byte, approval.HeadSize)
	e0 := approval.LedgerEntry{Seq: 0, Prev: genesis, ApprovalID: idA, By: "c1"}
	// e1's prev is left at genesis instead of SHA-384(e0) — a broken link.
	e1bad := approval.LedgerEntry{Seq: 1, Prev: genesis, ApprovalID: idB, By: "c1"}
	writeRec(e0.Bytes())
	writeRec(e1bad.Bytes())
	f.Close()

	if _, err := approval.OpenLedger(path); err == nil {
		t.Fatal("corrupt (broken-link) ledger opened without error")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "LedgerCorrupt" {
		t.Fatalf("want LedgerCorrupt, got %v", err)
	}
}
