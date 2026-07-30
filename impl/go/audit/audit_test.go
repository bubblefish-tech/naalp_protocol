// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package audit_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/audit"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/audit/cases.json"

type receiptJSON struct {
	Seq          uint64 `json:"seq"`
	PrevHex      string `json:"prev_hex"`
	ObjHex       string `json:"obj_hex"`
	At           uint64 `json:"at"`
	BodyHex      string `json:"body_hex"`
	HeadAfterHex string `json:"head_after_hex"`
}

type nodeJSON struct {
	Name      string   `json:"name"`
	IDHex     string   `json:"id_hex"`
	CausesHex []string `json:"causes_hex"`
	Position  uint64   `json:"position"`
}

type auditCases struct {
	Chain struct {
		GenesisPrevHex string        `json:"genesis_prev_hex"`
		Receipts       []receiptJSON `json:"receipts"`
		FinalHeadHex   string        `json:"final_head_hex"`
	} `json:"chain"`
	ChainBroken struct {
		Receipts []receiptJSON `json:"receipts"`
		Expect   string        `json:"expect"`
	} `json:"chain_broken"`
	Equivocation struct {
		Seq      uint64      `json:"seq"`
		ReceiptA receiptJSON `json:"receipt_a"`
		ReceiptB receiptJSON `json:"receipt_b"`
		Expect   string      `json:"expect"`
	} `json:"equivocation"`
	CausalValid struct {
		Nodes        []nodeJSON `json:"nodes"`
		Valid        bool       `json:"valid"`
		TopoOrderHex []string   `json:"topo_order_hex"`
	} `json:"causal_valid"`
	CausalCycle  struct{ Nodes []nodeJSON `json:"nodes"` } `json:"causal_cycle"`
	CausalFuture struct{ Nodes []nodeJSON `json:"nodes"` } `json:"causal_future"`
}

func load(t *testing.T) auditCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c auditCases
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

func authKey(t *testing.T, seedByte byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier) {
	t.Helper()
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = seedByte
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
}

func nodes(t *testing.T, js []nodeJSON) []audit.CausalNode {
	t.Helper()
	out := make([]audit.CausalNode, 0, len(js))
	for _, n := range js {
		causes := make([][]byte, 0, len(n.CausesHex))
		for _, c := range n.CausesHex {
			causes = append(causes, hx(t, c))
		}
		out = append(out, audit.CausalNode{ID: hx(t, n.IDHex), Causes: causes, Position: n.Position})
	}
	return out
}

// TestReceiptChainMatchesOracle: the authority produces byte-identical receipt bodies and chain
// heads to the independent oracle (⟹ Go == Rust), and the signed chain verifies offline.
func TestReceiptChainMatchesOracle(t *testing.T) {
	c := load(t)
	signer, verifier := authKey(t, 20)
	auth := audit.NewAuthority(signer)
	if got := hex.EncodeToString(make([]byte, audit.HeadSize)); got != c.Chain.GenesisPrevHex {
		t.Fatalf("genesis prev %s want %s", got, c.Chain.GenesisPrevHex)
	}
	var receipts []audit.Receipt
	var sigs [][]byte
	for i, rj := range c.Chain.Receipts {
		r, sig, err := auth.Append(hx(t, rj.ObjHex), rj.At)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if r.Seq != rj.Seq {
			t.Errorf("receipt %d seq got %d want %d", i, r.Seq, rj.Seq)
		}
		if got := hex.EncodeToString(r.Bytes()); got != rj.BodyHex {
			t.Errorf("receipt %d body\n got %s\nwant %s", i, got, rj.BodyHex)
		}
		if got := hex.EncodeToString(r.Head()); got != rj.HeadAfterHex {
			t.Errorf("receipt %d head\n got %s\nwant %s", i, got, rj.HeadAfterHex)
		}
		receipts = append(receipts, r)
		sigs = append(sigs, sig)
	}
	if got := hex.EncodeToString(receipts[len(receipts)-1].Head()); got != c.Chain.FinalHeadHex {
		t.Errorf("final head %s want %s", got, c.Chain.FinalHeadHex)
	}
	if err := audit.VerifyChain(receipts, sigs, verifier); err != nil {
		t.Fatalf("valid signed chain rejected: %v", err)
	}
}

// TestChainBrokenAndReorder: a receipt whose prev does not link (ChainBroken), and a reordered
// chain (out-of-order seq), are both rejected — even with valid signatures.
func TestChainBrokenAndReorder(t *testing.T) {
	c := load(t)
	signer, verifier := authKey(t, 20)
	mk := func(rj receiptJSON) (audit.Receipt, []byte) {
		r := audit.Receipt{Prev: hx(t, rj.PrevHex), Obj: hx(t, rj.ObjHex), Seq: rj.Seq, At: rj.At}
		if got := hex.EncodeToString(r.Bytes()); got != rj.BodyHex {
			t.Fatalf("reconstructed body mismatch: %s vs %s", got, rj.BodyHex)
		}
		sig, err := signer.Sign(r.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return r, sig
	}
	r0, s0 := mk(c.ChainBroken.Receipts[0])
	r1, s1 := mk(c.ChainBroken.Receipts[1]) // prev = genesis, but head(r0) != genesis
	if err := audit.VerifyChain([]audit.Receipt{r0, r1}, [][]byte{s0, s1}, verifier); err == nil {
		t.Fatal("broken chain accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ChainBroken" {
		t.Fatalf("want ChainBroken, got %v", err)
	}
	// A valid chain reordered (seq out of order) is also ChainBroken.
	signer2, verifier2 := authKey(t, 21)
	auth := audit.NewAuthority(signer2)
	ra, sa, _ := auth.Append(hx(t, c.Chain.Receipts[0].ObjHex), 100)
	rb, sb, _ := auth.Append(hx(t, c.Chain.Receipts[1].ObjHex), 101)
	if err := audit.VerifyChain([]audit.Receipt{rb, ra}, [][]byte{sb, sa}, verifier2); err == nil {
		t.Fatal("reordered chain accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ChainBroken" {
		t.Fatalf("want ChainBroken on reorder, got %v", err)
	}
}

// TestReceiptUnsigned: a tampered receipt signature is rejected by both VerifyChain and the
// auditor.
func TestReceiptUnsigned(t *testing.T) {
	signer, verifier := authKey(t, 20)
	auth := audit.NewAuthority(signer)
	r, sig, _ := auth.Append([]byte{0x20, 0x30, 1, 2, 3}, 100)
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0x01
	if err := audit.VerifyChain([]audit.Receipt{r}, [][]byte{bad}, verifier); err == nil {
		t.Fatal("tampered receipt accepted by VerifyChain")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ReceiptUnsigned" {
		t.Fatalf("want ReceiptUnsigned, got %v", err)
	}
	if _, err := audit.NewAuditor(verifier).Observe(r, bad); err == nil {
		t.Fatal("tampered receipt accepted by auditor")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ReceiptUnsigned" {
		t.Fatalf("want ReceiptUnsigned from auditor, got %v", err)
	}
}

// TestEquivocationDetected: two validly-signed receipts by one authority at one seq naming
// different objects yield a ForkProof (Equivocation); an exact duplicate is benign.
func TestEquivocationDetected(t *testing.T) {
	c := load(t)
	signer, verifier := authKey(t, 20)
	// The two conflicting receipts share seq 1 and prev = head(receipt 0) but name different
	// objects; the oracle body encodes that prev, so reconstruct with it and byte-check.
	ra := audit.Receipt{Prev: hx(t, c.Chain.Receipts[0].HeadAfterHex), Obj: hx(t, c.Equivocation.ReceiptA.ObjHex), Seq: c.Equivocation.Seq, At: 101}
	rb := audit.Receipt{Prev: hx(t, c.Chain.Receipts[0].HeadAfterHex), Obj: hx(t, c.Equivocation.ReceiptB.ObjHex), Seq: c.Equivocation.Seq, At: 101}
	if got := hex.EncodeToString(ra.Bytes()); got != c.Equivocation.ReceiptA.BodyHex {
		t.Fatalf("receipt A body\n got %s\nwant %s", got, c.Equivocation.ReceiptA.BodyHex)
	}
	if got := hex.EncodeToString(rb.Bytes()); got != c.Equivocation.ReceiptB.BodyHex {
		t.Fatalf("receipt B body\n got %s\nwant %s", got, c.Equivocation.ReceiptB.BodyHex)
	}
	sa, _ := signer.Sign(ra.Bytes())
	sb, _ := signer.Sign(rb.Bytes())

	aud := audit.NewAuditor(verifier)
	if fp, err := aud.Observe(ra, sa); fp != nil || err != nil {
		t.Fatalf("first receipt flagged: fp=%v err=%v", fp, err)
	}
	if fp, err := aud.Observe(ra, sa); fp != nil || err != nil { // exact duplicate is benign
		t.Fatalf("duplicate flagged: fp=%v err=%v", fp, err)
	}
	fp, err := aud.Observe(rb, sb)
	if fp == nil {
		t.Fatal("equivocation not detected")
	}
	if ce, ok := err.(*cose.Error); !ok || ce.Kind != "Equivocation" {
		t.Fatalf("want Equivocation, got %v", err)
	}
	if !bytes.Equal(fp.A.Obj, ra.Obj) || !bytes.Equal(fp.B.Obj, rb.Obj) {
		t.Fatal("fork proof does not carry the two conflicting receipts")
	}
}

// TestCausalGraph: the valid DAG verifies with the oracle's topological order; a cycle and a
// future-cause each fire CausalViolation.
func TestCausalGraph(t *testing.T) {
	c := load(t)
	valid := nodes(t, c.CausalValid.Nodes)
	if err := audit.VerifyCausal(valid); err != nil {
		t.Fatalf("valid causal graph rejected: %v", err)
	}
	order, err := audit.TopoOrder(valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != len(c.CausalValid.TopoOrderHex) {
		t.Fatalf("topo len %d want %d", len(order), len(c.CausalValid.TopoOrderHex))
	}
	for i, id := range order {
		if hex.EncodeToString(id) != c.CausalValid.TopoOrderHex[i] {
			t.Errorf("topo[%d] = %s, want %s", i, hex.EncodeToString(id), c.CausalValid.TopoOrderHex[i])
		}
	}
	if err := audit.VerifyCausal(nodes(t, c.CausalCycle.Nodes)); err == nil {
		t.Fatal("cyclic graph accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "CausalViolation" {
		t.Fatalf("want CausalViolation (cycle), got %v", err)
	}
	if err := audit.VerifyCausal(nodes(t, c.CausalFuture.Nodes)); err == nil {
		t.Fatal("future-cause graph accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "CausalViolation" {
		t.Fatalf("want CausalViolation (future), got %v", err)
	}
}

// TestTimeAnchor: R-8.4 — an object's created time is consistent only if it does not exceed the
// authority's independent time anchor.
func TestTimeAnchor(t *testing.T) {
	if !audit.ConsistentWithAnchor(100, 102) {
		t.Error("created 100 <= anchor 102 should be consistent")
	}
	if audit.ConsistentWithAnchor(200, 102) {
		t.Error("created 200 > anchor 102 must be detectable")
	}
}

func mkObj(signer []byte, causes [][]byte) *envelope.Object {
	return &envelope.Object{
		Kind: 0, Channel: 0, Tier: 0, Signer: signer, Created: 100,
		Effect: 0, Causes: causes, Profile: uint64(cose.ProfilePublic), Body: cbor.Uint(0),
	}
}

// TestCausalEdgeProvenBySignature: R-8.2/R-8.5 — the edge "A causes B" is proven by B's
// signature over A's content id (envelope field 8), checkable offline with no authority.
func TestCausalEdgeProvenBySignature(t *testing.T) {
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 30
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	signer, verifier := cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
	kindOK := func(ch, k uint64) bool { return true }

	objA := mkObj(pk.Bytes(), nil)
	cidA, err := objA.ContentID()
	if err != nil {
		t.Fatal(err)
	}
	objB := mkObj(pk.Bytes(), [][]byte{cidA})
	signedB, err := envelope.Sign(objB, signer)
	if err != nil {
		t.Fatal(err)
	}
	oB, err := envelope.Verify(cose.ProfilePublic, verifier, kindOK, nil, signedB)
	if err != nil {
		t.Fatalf("verify B: %v", err)
	}
	if len(oB.Causes) != 1 || !bytes.Equal(oB.Causes[0], cidA) {
		t.Fatal("B's signed body does not carry the causal edge to A")
	}
	// The offline partial order over {A, B} with A before B verifies.
	cidB, _ := objB.ContentID()
	err = audit.VerifyCausal([]audit.CausalNode{
		{ID: cidA, Causes: nil, Position: 0},
		{ID: cidB, Causes: [][]byte{cidA}, Position: 1},
	})
	if err != nil {
		t.Fatalf("offline causal check rejected a valid edge: %v", err)
	}
}

// TestOrderingDoesNotMutateOrigin: R-8.2 — after the authority orders an object, the origin
// object's signature is still valid and its bytes are unchanged; the receipt references only
// the content id.
func TestOrderingDoesNotMutateOrigin(t *testing.T) {
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 31
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	signer, verifier := cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
	kindOK := func(ch, k uint64) bool { return true }

	obj := mkObj(pk.Bytes(), nil)
	signedO, err := envelope.Sign(obj, signer)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), signedO...)
	oO, err := envelope.Verify(cose.ProfilePublic, verifier, kindOK, nil, signedO)
	if err != nil {
		t.Fatal(err)
	}

	authSigner, _ := authKey(t, 40)
	auth := audit.NewAuthority(authSigner)
	r, _, err := auth.Append(oO.ID, 500)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signedO, before) {
		t.Fatal("ordering mutated the origin object bytes")
	}
	if _, err := envelope.Verify(cose.ProfilePublic, verifier, kindOK, nil, signedO); err != nil {
		t.Fatalf("origin object no longer verifies after ordering: %v", err)
	}
	if !bytes.Equal(r.Obj, oO.ID) {
		t.Fatal("receipt does not reference the object content id")
	}
}
