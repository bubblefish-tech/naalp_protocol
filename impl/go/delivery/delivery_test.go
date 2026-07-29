// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package delivery_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bubblefish-tech/n-aalp/impl/go/audit"
	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
	"github.com/bubblefish-tech/n-aalp/impl/go/delivery"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/delivery/cases.json"

type deliveryCases struct {
	Stages []struct {
		Value uint64 `json:"value"`
		Name  string `json:"name"`
	} `json:"stages"`
	ObjContentIDHex string `json:"obj_content_id_hex"`
	Updates         []struct {
		Stage   uint64 `json:"stage"`
		At      uint64 `json:"at"`
		BodyHex string `json:"body_hex"`
	} `json:"updates"`
}

func load(t *testing.T) deliveryCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c deliveryCases
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

// TestUpdateBytesMatchOracle: the delivery.update bytes and stage names equal the independent
// oracle in this implementation (⟹ Go == Rust, which grades the same file).
func TestUpdateBytesMatchOracle(t *testing.T) {
	c := load(t)
	obj := hx(t, c.ObjContentIDHex)
	for _, s := range c.Stages {
		if got := delivery.StageName(s.Value); got != s.Name {
			t.Errorf("stage %d name got %q want %q", s.Value, got, s.Name)
		}
	}
	for _, u := range c.Updates {
		du := delivery.DeliveryUpdate{Obj: obj, Stage: u.Stage, At: u.At}
		if got := hex.EncodeToString(du.Bytes()); got != u.BodyHex {
			t.Errorf("stage %d update\n got %s\nwant %s", u.Stage, got, u.BodyHex)
		}
	}
}

// TestStageMonotonicAndRegression: stages advance monotonically; re-reporting the current stage
// is idempotent; regressing to an earlier stage is StageOutOfOrder.
func TestStageMonotonicAndRegression(t *testing.T) {
	c := load(t)
	obj := hx(t, c.ObjContentIDHex)
	tr, err := delivery.OpenTracker(filepath.Join(t.TempDir(), "wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	for _, s := range []uint64{delivery.StagePersistedOrigin, delivery.StageAcceptedRelay, delivery.StagePersistedTarget} {
		if _, err := tr.Advance(obj, s, 100+s); err != nil {
			t.Fatalf("advance to %d: %v", s, err)
		}
	}
	if _, err := tr.Advance(obj, delivery.StagePersistedTarget, 999); err != nil {
		t.Fatalf("idempotent re-report rejected: %v", err) // stage == current is a no-op
	}
	if _, err := tr.Advance(obj, delivery.StageAcceptedRelay, 999); err == nil {
		t.Fatal("stage regression accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "StageOutOfOrder" {
		t.Fatalf("want StageOutOfOrder, got %v", err)
	}
	if _, err := tr.Advance(obj, delivery.StagePresented, 104); err != nil {
		t.Fatalf("advance to presented: %v", err)
	}
	if s, _ := tr.Stage(obj); s != delivery.StagePresented {
		t.Fatalf("final stage %d, want %d", s, delivery.StagePresented)
	}
}

// TestPersistBeforeAckCrashRecovery: R-9.2 — the acknowledging update is returned only after the
// stage is durably persisted, so a crash (close) right after the ack loses nothing: the reopened
// tracker recovers the acked stage and refuses to regress below it.
func TestPersistBeforeAckCrashRecovery(t *testing.T) {
	c := load(t)
	obj := hx(t, c.ObjContentIDHex)
	path := filepath.Join(t.TempDir(), "wal")

	tr, err := delivery.OpenTracker(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Advance(obj, delivery.StagePersistedOrigin, 100); err != nil {
		t.Fatal(err)
	}
	ack, err := tr.Advance(obj, delivery.StagePersistedTarget, 102) // the ack we "received"
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil { // simulate a crash immediately after the ack
		t.Fatal(err)
	}

	tr2, err := delivery.OpenTracker(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer tr2.Close()
	s, seen := tr2.Stage(obj)
	if !seen || s != ack.Stage {
		t.Fatalf("acked stage did not survive crash: got (%d,%v) want %d", s, seen, ack.Stage)
	}
	if _, err := tr2.Advance(obj, delivery.StagePersistedOrigin, 200); err == nil {
		t.Fatal("regression accepted after recovery")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "StageOutOfOrder" {
		t.Fatalf("want StageOutOfOrder, got %v", err)
	}
	if _, err := tr2.Advance(obj, delivery.StagePresented, 203); err != nil {
		t.Fatalf("advance after recovery: %v", err)
	}
}

// TestSwitchboardFullDuplex: R-9.3 — the switchboard relays both directions concurrently. With
// per-direction capacity 1 and both directions saturated, a one-at-a-time mailbox would stall;
// full-duplex passthrough delivers every object each way, in order.
func TestSwitchboardFullDuplex(t *testing.T) {
	sb := delivery.NewSwitchboard(1)
	defer sb.Close()
	const N = 200

	var wg sync.WaitGroup
	wg.Add(4)
	// A -> B sender and B receiver.
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			sb.Left().Send([]byte{byte(i % 251), 0xAB})
		}
	}()
	gotAB := make([][]byte, 0, N)
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			gotAB = append(gotAB, sb.Right().Recv())
		}
	}()
	// B -> A sender and A receiver, at the same time.
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			sb.Right().Send([]byte{byte(i % 251), 0xBA})
		}
	}()
	gotBA := make([][]byte, 0, N)
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			gotBA = append(gotBA, sb.Left().Recv())
		}
	}()
	wg.Wait()

	if len(gotAB) != N || len(gotBA) != N {
		t.Fatalf("delivered A->B=%d B->A=%d, want %d each", len(gotAB), len(gotBA), N)
	}
	for i := 0; i < N; i++ {
		if !bytes.Equal(gotAB[i], []byte{byte(i % 251), 0xAB}) {
			t.Fatalf("A->B object %d out of order/content", i)
		}
		if !bytes.Equal(gotBA[i], []byte{byte(i % 251), 0xBA}) {
			t.Fatalf("B->A object %d out of order/content", i)
		}
	}
}

// TestContentFreeRelay: R-9.4 — a relay holding objects only in transit writes a valid audit
// trail (receipts over content ids) while retaining no payload at rest.
func TestContentFreeRelay(t *testing.T) {
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 50
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	relay := delivery.NewContentFreeRelay(cose.MLDSA65Signer{SK: sk})

	payloads := [][]byte{[]byte("object one"), []byte("object two"), []byte("object three")}
	for i, p := range payloads {
		out, err := relay.Route(p, uint64(100+i))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, p) {
			t.Fatal("relay altered the forwarded object")
		}
	}
	receipts, sigs := relay.AuditTrail()
	if len(receipts) != len(payloads) {
		t.Fatalf("audit trail has %d receipts, want %d", len(receipts), len(payloads))
	}
	// The retained audit trail is a valid signed chain.
	if err := audit.VerifyChain(receipts, sigs, cose.MLDSA65Verifier{PK: pk}); err != nil {
		t.Fatalf("relay audit trail does not verify: %v", err)
	}
	// Each receipt references the object's content id — not the payload (no payload at rest).
	for i, p := range payloads {
		if !bytes.Equal(receipts[i].Obj, delivery.ContentID(p)) {
			t.Fatalf("receipt %d does not reference the content id", i)
		}
		if bytes.Contains(receipts[i].Obj, p) {
			t.Fatalf("receipt %d retained payload bytes at rest", i)
		}
	}
}
