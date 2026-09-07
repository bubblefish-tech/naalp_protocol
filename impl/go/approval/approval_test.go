// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package approval_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// flexU64 unmarshals a 64-bit position/counter carried as a JSON number OR, per R12
// (values above 2^53), as a decimal string -- so a float64 decoder cannot round it before
// this typed uint64 loader parses it exactly.
type flexU64 uint64

func (f *flexU64) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*f = flexU64(v)
	return nil
}

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

// ---- T1.5 (NAALP-REQ-121): ledger-signed consume receipt with forward-only position ------------

const crVectorPath = "../../../vectors/consume_receipt/cases.json"

type crReceiptJSON struct {
	Name          string `json:"name"`
	LedgerHex     string `json:"ledger_hex"`
	ApprovalIDHex string `json:"approval_id_hex"`
	Position      uint64 `json:"position"`
	BodyHex       string `json:"body_hex"`
}

type crForkJSON struct {
	Name   string        `json:"name"`
	A      crReceiptJSON `json:"a"`
	B      crReceiptJSON `json:"b"`
	Expect string        `json:"expect"`
}

type consumeReceiptCases struct {
	Ledgers struct {
		AHex string `json:"a_hex"`
		BHex string `json:"b_hex"`
	} `json:"ledgers"`
	Approvals struct {
		XHex string `json:"x_hex"`
		YHex string `json:"y_hex"`
	} `json:"approvals"`
	Base     crReceiptJSON   `json:"base"`
	Sequence []crReceiptJSON `json:"sequence"`
	Forks    []crForkJSON    `json:"forks"`
	Wire     struct {
		KeysOutOfOrder struct {
			PayloadHex          string `json:"payload_hex"`
			CanonicalPayloadHex string `json:"canonical_payload_hex"`
			Expect              string `json:"expect"`
		} `json:"keys_out_of_order"`
		PositionTooLarge []struct {
			Name     string  `json:"name"`
			Position flexU64 `json:"position"`
			BodyHex  string  `json:"body_hex"`
		} `json:"position_too_large"`
		EmptyLedger struct {
			LedgerHex     string `json:"ledger_hex"`
			ApprovalIDHex string `json:"approval_id_hex"`
			Position      uint64 `json:"position"`
			BodyHex       string `json:"body_hex"`
			ExpectVerify  string `json:"expect_verify"`
		} `json:"empty_ledger"`
		AbsentLedger struct {
			BodyHex string `json:"body_hex"`
			Expect  string `json:"expect"`
		} `json:"absent_ledger"`
	} `json:"wire"`
}

func loadCR(t *testing.T) consumeReceiptCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(crVectorPath))
	if err != nil {
		t.Fatalf("read consume-receipt corpus: %v", err)
	}
	var c consumeReceiptCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse consume-receipt corpus: %v", err)
	}
	return c
}

func ledgerKey(t *testing.T, seedByte byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier) {
	t.Helper()
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = seedByte
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
}

func recFromJSON(t *testing.T, rj crReceiptJSON) approval.ConsumeReceipt {
	t.Helper()
	return approval.ConsumeReceipt{
		Ledger:     mustHex(t, rj.LedgerHex),
		ApprovalID: mustHex(t, rj.ApprovalIDHex),
		Position:   rj.Position,
	}
}

// TestConsumeReceiptBytesMatchOracle: every consume-receipt body is byte-identical to the
// independent oracle in this implementation (⟹ Go == Rust, which grades the same file). A
// field-ignoring or mis-framing encoder diverges here.
func TestConsumeReceiptBytesMatchOracle(t *testing.T) {
	c := loadCR(t)
	all := append([]crReceiptJSON{c.Base}, c.Sequence...)
	for _, f := range c.Forks {
		all = append(all, f.A, f.B)
	}
	if len(all) == 0 {
		t.Fatal("no consume-receipt cases")
	}
	for _, rj := range all {
		got := hex.EncodeToString(recFromJSON(t, rj).Bytes())
		if got != rj.BodyHex {
			t.Errorf("receipt body\n got %s\nwant %s", got, rj.BodyHex)
		}
	}
}

// TestConsumeReceiptSignVerify: a ledger-signed receipt verifies under the ledger key (REQ-121);
// an unnamed ledger, a tampered signature, and the wrong ledger key are each rejected fail-closed.
func TestConsumeReceiptSignVerify(t *testing.T) {
	c := loadCR(t)
	signer, verifier := ledgerKey(t, 0x51)
	r := recFromJSON(t, c.Base)

	sig, err := approval.SignConsumeReceipt(r, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyConsumeReceipt(r, verifier, sig); err != nil {
		t.Fatalf("valid ledger-signed receipt rejected: %v", err)
	}
	// unnamed ordering authority (empty ledger id) is not evidence.
	unnamed := r
	unnamed.Ledger = nil
	if err := approval.VerifyConsumeReceipt(unnamed, verifier, sig); err == nil {
		t.Fatal("unnamed-ledger receipt accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ConsumeReceiptUnsigned" {
		t.Fatalf("want ConsumeReceiptUnsigned (unnamed), got %v", err)
	}
	// tampered signature.
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0x01
	if err := approval.VerifyConsumeReceipt(r, verifier, bad); err == nil {
		t.Fatal("tampered signature accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ConsumeReceiptUnsigned" {
		t.Fatalf("want ConsumeReceiptUnsigned (tamper), got %v", err)
	}
	// wrong ledger key.
	_, otherV := ledgerKey(t, 0x52)
	if err := approval.VerifyConsumeReceipt(r, otherV, sig); err == nil {
		t.Fatal("wrong ledger key accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ConsumeReceiptUnsigned" {
		t.Fatalf("want ConsumeReceiptUnsigned (wrong key), got %v", err)
	}
}

// resolverFor builds a ledger-id -> verifier resolver over the named (id, verifier) pairs.
func resolverFor(pairs map[string]cose.Verifier) func([]byte) (cose.Verifier, bool) {
	return func(id []byte) (cose.Verifier, bool) {
		v, ok := pairs[string(id)]
		return v, ok
	}
}

// TestConsumeForkDetected (case a): two ledger-signed receipts for the SAME approval id with
// DIFFERENT positions are detected as a fork, and the surfaced evidence carries BOTH positions and
// verifies as a non-repudiable double-spend proof.
func TestConsumeForkDetected(t *testing.T) {
	c := loadCR(t)
	var fk crForkJSON
	for _, f := range c.Forks {
		if f.Name == "same_ledger_diff_position" {
			fk = f
		}
	}
	if fk.Name == "" {
		t.Fatal("same_ledger_diff_position case missing from oracle")
	}
	if fk.Expect != "fork" {
		t.Fatalf("oracle marks %s as %q, want fork", fk.Name, fk.Expect)
	}
	signer, verifier := ledgerKey(t, 0x41) // one ledger signs both conflicting positions (a partition)
	rA := recFromJSON(t, fk.A)
	rB := recFromJSON(t, fk.B)
	sigA, _ := approval.SignConsumeReceipt(rA, signer)
	sigB, _ := approval.SignConsumeReceipt(rB, signer)

	resolve := resolverFor(map[string]cose.Verifier{string(rA.Ledger): verifier})
	rs := approval.NewReceiptSet(resolve)
	if fe, err := rs.Observe(rA, sigA); fe != nil || err != nil {
		t.Fatalf("first receipt flagged: fe=%v err=%v", fe, err)
	}
	fe, err := rs.Observe(rB, sigB)
	if fe == nil {
		t.Fatal("fork not detected on same approval id / different positions")
	}
	if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ConsumeFork" {
		t.Fatalf("want ConsumeFork, got %v", err)
	}
	// the two positions are surfaced (the contradiction is legible).
	if fe.A.Position == fe.B.Position {
		t.Fatalf("fork evidence hides the position conflict (%d == %d)", fe.A.Position, fe.B.Position)
	}
	t.Logf("fork detected on approval %x: position %d vs %d", fe.ApprovalID[:6], fe.A.Position, fe.B.Position)
	// the evidence is non-repudiable: both ledger signatures verify under the named key.
	if err := fe.Verify(resolve); err != nil {
		t.Fatalf("fork evidence failed to verify: %v", err)
	}
	// a byte-identical re-emission is a benign duplicate, never flagged.
	rs2 := approval.NewReceiptSet(resolve)
	rs2.Observe(rA, sigA)
	if fe, err := rs2.Observe(rA, sigA); fe != nil || err != nil {
		t.Fatalf("benign duplicate flagged: fe=%v err=%v", fe, err)
	}
}

// TestConsumeForkCrossLedger (case b): two DIFFERENT ledgers each sign a receipt for the SAME
// approval id (a single-use approval spent twice). Observing both yields a provable contradiction —
// concurrent execution of the two independent ledgers, then a comparison, surfaces the fork.
func TestConsumeForkCrossLedger(t *testing.T) {
	c := loadCR(t)
	ledgerAID := mustHex(t, c.Ledgers.AHex)
	ledgerBID := mustHex(t, c.Ledgers.BHex)
	approvalX := mustHex(t, c.Approvals.XHex)
	sA, vA := ledgerKey(t, 0x41)
	sB, vB := ledgerKey(t, 0x42)

	// Two independent ordering authorities, run concurrently, each consuming approval X on its own
	// signed ledger. Each SUCCEEDS locally (they cannot see each other) — the double spend is not
	// prevented, only made provable on comparison.
	openSigned := func(id []byte, s cose.MLDSA65Signer) *approval.Ledger {
		l, err := approval.OpenLedgerSigned(filepath.Join(t.TempDir(), "wal"), id, s)
		if err != nil {
			t.Fatalf("open signed ledger: %v", err)
		}
		return l
	}
	lA := openSigned(ledgerAID, sA)
	defer lA.Close()
	lB := openSigned(ledgerBID, sB)
	defer lB.Close()

	type signed struct {
		r   approval.ConsumeReceipt
		sig []byte
	}
	ch := make(chan signed, 2)
	var wg sync.WaitGroup
	for _, l := range []*approval.Ledger{lA, lB} {
		wg.Add(1)
		go func(l *approval.Ledger) {
			defer wg.Done()
			_, r, sig, err := l.ConsumeWithReceipt(approvalX, "requester")
			if err != nil {
				t.Errorf("independent ledger consume failed: %v", err)
				return
			}
			ch <- signed{r, sig}
		}(l)
	}
	wg.Wait()
	close(ch)

	resolve := resolverFor(map[string]cose.Verifier{string(ledgerAID): vA, string(ledgerBID): vB})
	rs := approval.NewReceiptSet(resolve)
	var forkEvidence *approval.ConsumeForkEvidence
	for s := range ch {
		fe, err := rs.Observe(s.r, s.sig)
		if fe != nil {
			forkEvidence = fe
			if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ConsumeFork" {
				t.Fatalf("want ConsumeFork, got %v", err)
			}
		}
	}
	if forkEvidence == nil {
		t.Fatal("cross-ledger double spend not detected")
	}
	if bytes.Equal(forkEvidence.A.Ledger, forkEvidence.B.Ledger) {
		t.Fatal("cross-ledger fork evidence names the same ledger twice")
	}
	if err := forkEvidence.Verify(resolve); err != nil {
		t.Fatalf("cross-ledger fork evidence failed to verify: %v", err)
	}
	t.Logf("cross-ledger fork: ledger %x @%d vs ledger %x @%d",
		forkEvidence.A.Ledger, forkEvidence.A.Position, forkEvidence.B.Ledger, forkEvidence.B.Position)
}

// TestConsumeFirstAppendWinsCAS (case c) is the compare-and-set MUTATION anchor. On ONE honest
// signed ledger, consuming the same approval id twice must yield exactly ONE ledger-signed receipt
// (first-append-wins): the first consume returns a receipt at position 0, the second returns
// AlreadyConsumed and signs nothing. Feeding the emitted receipts into a fork detector finds NO
// fork. If the CAS in ConsumeWithReceipt is mutated to always-succeed, the second consume mints a
// SECOND receipt at position 1 for the same approval id — so (1) the exactly-one-winner assertion
// flips pass->fail AND (2) the fork detector fires on a single honest ledger. Either flip catches
// the mutation.
func TestConsumeFirstAppendWinsCAS(t *testing.T) {
	c := loadCR(t)
	ledgerAID := mustHex(t, c.Ledgers.AHex)
	approvalX := mustHex(t, c.Approvals.XHex)
	signer, verifier := ledgerKey(t, 0x41)
	l, err := approval.OpenLedgerSigned(filepath.Join(t.TempDir(), "wal"), ledgerAID, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	resolve := resolverFor(map[string]cose.Verifier{string(ledgerAID): verifier})
	rs := approval.NewReceiptSet(resolve)

	// first consume wins with a receipt at the ledger's forward-only position 0.
	e, r1, sig1, err := l.ConsumeWithReceipt(approvalX, "requester")
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if e.Seq != 0 || r1.Position != 0 {
		t.Fatalf("first receipt position got seq=%d pos=%d want 0/0", e.Seq, r1.Position)
	}
	if fe, err := rs.Observe(r1, sig1); fe != nil || err != nil {
		t.Fatalf("first receipt flagged: fe=%v err=%v", fe, err)
	}

	// second consume of the same id: AlreadyConsumed, signs nothing (first-append-wins).
	_, _, sig2, err := l.ConsumeWithReceipt(approvalX, "requester")
	if err == nil {
		t.Fatal("second consume of the same approval id succeeded (CAS is not first-append-wins)")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "AlreadyConsumed" {
		t.Fatalf("want AlreadyConsumed, got %v", err)
	}
	if sig2 != nil {
		t.Fatal("second consume produced a receipt (CAS did not win-once)")
	}
	if l.Len() != 1 {
		t.Fatalf("ledger has %d entries, want exactly 1", l.Len())
	}
}

// TestConsumeReceiptExactlyOnceUnderRace: N goroutines call ConsumeWithReceipt for the same approval
// id concurrently on ONE signed ledger; exactly one wins and mints exactly one receipt, the rest get
// AlreadyConsumed, and the fork detector sees no fork from the single winner (run under -race).
func TestConsumeReceiptExactlyOnceUnderRace(t *testing.T) {
	c := loadCR(t)
	ledgerAID := mustHex(t, c.Ledgers.AHex)
	approvalX := mustHex(t, c.Approvals.XHex)
	signer, verifier := ledgerKey(t, 0x41)
	l, err := approval.OpenLedgerSigned(filepath.Join(t.TempDir(), "wal"), ledgerAID, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	const N = 64
	var wg sync.WaitGroup
	var wins, alreadys int64
	start := make(chan struct{})
	winner := make(chan approval.ConsumeReceipt, N)
	winnerSig := make(chan []byte, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, r, sig, err := l.ConsumeWithReceipt(approvalX, "requester")
			if err == nil {
				atomic.AddInt64(&wins, 1)
				winner <- r
				winnerSig <- sig
			} else if ce, ok := err.(*cose.Error); ok && ce.Kind == "AlreadyConsumed" {
				atomic.AddInt64(&alreadys, 1)
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(winner)
	close(winnerSig)
	if wins != 1 {
		t.Fatalf("exactly-once violated: %d winners (want 1)", wins)
	}
	if alreadys != N-1 {
		t.Fatalf("got %d AlreadyConsumed, want %d", alreadys, N-1)
	}
	// the single minted receipt is not a fork with itself.
	rs := approval.NewReceiptSet(resolverFor(map[string]cose.Verifier{string(ledgerAID): verifier}))
	r := <-winner
	if fe, err := rs.Observe(r, <-winnerSig); fe != nil || err != nil {
		t.Fatalf("sole winning receipt flagged: fe=%v err=%v", fe, err)
	}
}

// TestConsumeReceiptWireCases covers the section-4 wire cases: keys out of order (rejected
// NonCanonical at the CBOR layer, before any receipt rule), a position too large for a normal int
// (64-bit uint round-trip), and empty-value vs absent-value (empty != absent; empty ledger id is
// verify-rejected fail-closed).
func TestConsumeReceiptWireCases(t *testing.T) {
	c := loadCR(t)

	// keys out of order -> the strict decoder rejects NonCanonical.
	noncanon := mustHex(t, c.Wire.KeysOutOfOrder.PayloadHex)
	if _, err := cbor.Decode(noncanon); err == nil {
		t.Fatal("non-canonical (keys 3,2,1) receipt body accepted by decoder")
	} else if ce, ok := err.(*cbor.Error); !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("want NonCanonical, got %v", err)
	}
	// the canonical variant of the same logical receipt decodes cleanly.
	if _, err := cbor.Decode(mustHex(t, c.Wire.KeysOutOfOrder.CanonicalPayloadHex)); err != nil {
		t.Fatalf("canonical receipt body rejected: %v", err)
	}

	// position too large: a 64-bit uint position round-trips (encode == oracle, decode == value).
	ledgerX := mustHex(t, c.Base.LedgerHex)
	approvalX := mustHex(t, c.Base.ApprovalIDHex)
	for _, big := range c.Wire.PositionTooLarge {
		r := approval.ConsumeReceipt{Ledger: ledgerX, ApprovalID: approvalX, Position: uint64(big.Position)}
		if got := hex.EncodeToString(r.Bytes()); got != big.BodyHex {
			t.Errorf("%s encode\n got %s\nwant %s", big.Name, got, big.BodyHex)
		}
		v, err := cbor.Decode(mustHex(t, big.BodyHex))
		if err != nil {
			t.Fatalf("%s decode: %v", big.Name, err)
		}
		m, ok := v.(cbor.Map)
		if !ok {
			t.Fatalf("%s not a map", big.Name)
		}
		var pos uint64
		var found bool
		for _, p := range m {
			if p.K == cbor.Uint(3) {
				u, ok := p.V.(cbor.Uint)
				if !ok {
					t.Fatalf("%s position not a uint", big.Name)
				}
				pos, found = uint64(u), true
			}
		}
		if !found || pos != uint64(big.Position) {
			t.Errorf("%s position round-trip got %d want %d", big.Name, pos, uint64(big.Position))
		}
	}

	// empty-ledger receipt: well-formed bytes (match oracle) but verify-rejected fail-closed, and its
	// bytes differ from the absent-ledger variant (empty != absent).
	empty := approval.ConsumeReceipt{Ledger: []byte{}, ApprovalID: mustHex(t, c.Wire.EmptyLedger.ApprovalIDHex), Position: c.Wire.EmptyLedger.Position}
	if got := hex.EncodeToString(empty.Bytes()); got != c.Wire.EmptyLedger.BodyHex {
		t.Errorf("empty-ledger body\n got %s\nwant %s", got, c.Wire.EmptyLedger.BodyHex)
	}
	_, verifier := ledgerKey(t, 0x41)
	if err := approval.VerifyConsumeReceipt(empty, verifier, make([]byte, mldsa65.SignatureSize)); err == nil {
		t.Fatal("empty-ledger receipt verified")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ConsumeReceiptUnsigned" {
		t.Fatalf("want ConsumeReceiptUnsigned (empty ledger), got %v", err)
	}
	if c.Wire.EmptyLedger.BodyHex == c.Wire.AbsentLedger.BodyHex {
		t.Fatal("empty-ledger and absent-ledger receipts must encode to distinct bytes (empty != absent)")
	}
}
