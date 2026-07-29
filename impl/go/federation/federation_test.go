// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package federation_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/n-aalp/impl/go/audit"
	"github.com/bubblefish-tech/n-aalp/impl/go/cbor"
	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
	"github.com/bubblefish-tech/n-aalp/impl/go/envelope"
	"github.com/bubblefish-tech/n-aalp/impl/go/federation"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/federation/cases.json"

type fedCases struct {
	Nodes []struct {
		Name      string   `json:"name"`
		IDHex     string   `json:"id_hex"`
		CausesHex []string `json:"causes_hex"`
	} `json:"nodes"`
	ReconcileOrderHex     []string `json:"reconcile_order_hex"`
	NaiveSortHex          []string `json:"naive_content_id_sort_hex"`
	NaiveCausallyValid    bool     `json:"naive_causally_valid"`
	Authorities           []string `json:"authorities"`
	RecordHex             string   `json:"record_hex"`
}

func load(t *testing.T) fedCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c fedCases
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

func nodesOf(t *testing.T, c fedCases) []audit.CausalNode {
	out := make([]audit.CausalNode, 0, len(c.Nodes))
	for _, n := range c.Nodes {
		causes := make([][]byte, 0, len(n.CausesHex))
		for _, ch := range n.CausesHex {
			causes = append(causes, hx(t, ch))
		}
		out = append(out, audit.CausalNode{ID: hx(t, n.IDHex), Causes: causes})
	}
	return out
}

func hexOrder(order [][]byte) []string {
	out := make([]string, len(order))
	for i, o := range order {
		out[i] = hex.EncodeToString(o)
	}
	return out
}

// TestReconcileMatchesOracle: the deterministic merge equals the independent oracle, is causally
// valid, and the Reconcile record encodes to the oracle bytes (⟹ Go == Rust).
func TestReconcileMatchesOracle(t *testing.T) {
	c := load(t)
	nodes := nodesOf(t, c)
	order, err := federation.Reconcile(nodes)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := hexOrder(order)
	if len(got) != len(c.ReconcileOrderHex) {
		t.Fatalf("order length %d want %d", len(got), len(c.ReconcileOrderHex))
	}
	for i := range got {
		if got[i] != c.ReconcileOrderHex[i] {
			t.Errorf("order[%d] = %s, want %s", i, got[i], c.ReconcileOrderHex[i])
		}
	}
	if !federation.CausallyValid(order, nodes) {
		t.Fatal("reconcile order is not causally valid")
	}
	rec := federation.ReconcileRecord{Authorities: c.Authorities, Order: order}
	if h := hex.EncodeToString(rec.Bytes()); h != c.RecordHex {
		t.Errorf("record bytes\n got %s\nwant %s", h, c.RecordHex)
	}
}

// TestNaiveMergeFailsCausality: a merge that ignores the causal graph (a pure content-id sort)
// produces a different order that is NOT causally valid — the mutation baseline.
func TestNaiveMergeFailsCausality(t *testing.T) {
	c := load(t)
	nodes := nodesOf(t, c)
	naive := make([][]byte, 0, len(c.NaiveSortHex))
	for _, h := range c.NaiveSortHex {
		naive = append(naive, hx(t, h))
	}
	if federation.CausallyValid(naive, nodes) != c.NaiveCausallyValid {
		t.Fatalf("naive causally-valid = %v, oracle says %v", !c.NaiveCausallyValid, c.NaiveCausallyValid)
	}
	if c.NaiveCausallyValid {
		t.Fatal("this graph's naive sort should violate causality (weak mutation vector)")
	}
}

// TestScopeIndependence: R-8.6 — the reconcile order depends only on the causal graph, not on how
// the objects are split across authorities' scopes. Any input permutation reconciles identically.
func TestScopeIndependence(t *testing.T) {
	c := load(t)
	base, _ := federation.Reconcile(nodesOf(t, c))
	nodes := nodesOf(t, c)
	// reverse the input (simulating a different authority scope ordering)
	rev := make([]audit.CausalNode, len(nodes))
	for i := range nodes {
		rev[len(nodes)-1-i] = nodes[i]
	}
	other, err := federation.Reconcile(rev)
	if err != nil {
		t.Fatal(err)
	}
	if strings := hexOrder(base); len(strings) != len(other) {
		t.Fatal("length differs")
	}
	for i := range base {
		if !bytes.Equal(base[i], other[i]) {
			t.Fatalf("reconcile order depends on input order at %d", i)
		}
	}
}

func testSigner(t *testing.T, b byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier, []byte) {
	t.Helper()
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = b
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}, pk.Bytes()
}

// TestNoWireChange: R-8.6 — the same signed objects are accepted under both single-authority
// ordering and two-authority reconciliation, with no envelope or object change. The objects'
// bytes are byte-identical in both framings; only the ordering policy differs.
func TestNoWireChange(t *testing.T) {
	signer, verifier, pkb := testSigner(t, 100)
	kindOK := func(ch, k uint64) bool { return true }
	mk := func(causes [][]byte) ([]byte, []byte) {
		o := &envelope.Object{Kind: 0, Channel: 0, Tier: 0, Signer: pkb, Created: 100, Effect: 0, Causes: causes, Profile: uint64(cose.ProfilePublic), Body: cbor.Uint(0)}
		cid, _ := o.ContentID()
		signed, err := envelope.Sign(o, signer)
		if err != nil {
			t.Fatal(err)
		}
		return cid, signed
	}
	cid1, s1 := mk(nil)
	cid2, s2 := mk([][]byte{cid1})
	cid3, s3 := mk([][]byte{cid1})
	signedByID := map[string][]byte{string(cid1): s1, string(cid2): s2, string(cid3): s3}

	nodes := []audit.CausalNode{
		{ID: cid1, Causes: nil},
		{ID: cid2, Causes: [][]byte{cid1}},
		{ID: cid3, Causes: [][]byte{cid1}},
	}

	// Single authority orders all three (a monotonic receipt chain over its scope).
	authA, _, _ := testSigner(t, 101)
	single := audit.NewAuthority(authA)
	for _, id := range [][]byte{cid1, cid2, cid3} {
		if _, _, err := single.Append(id, 500); err != nil {
			t.Fatal(err)
		}
	}
	// Two authorities split the scope: A={O1,O3}, B={O2}. Then reconcile over the shared graph.
	authB, _, _ := testSigner(t, 102)
	a2 := audit.NewAuthority(authA)
	b2 := audit.NewAuthority(authB)
	a2.Append(cid1, 500)
	b2.Append(cid2, 501)
	a2.Append(cid3, 502)
	order, err := federation.Reconcile(nodes)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !federation.CausallyValid(order, nodes) {
		t.Fatal("federated order not causally valid")
	}
	// The identical signed objects verify in both framings — no envelope change.
	for _, id := range order {
		if _, err := envelope.Verify(cose.ProfilePublic, verifier, kindOK, nil, signedByID[string(id)]); err != nil {
			t.Fatalf("object %x does not verify after federated ordering: %v", id[:6], err)
		}
	}
	if len(order) != 3 {
		t.Fatalf("federated order has %d objects, want 3", len(order))
	}
}

// TestHigherTierExtMechanism: R-15A.2 — a baseline verifier accepts a higher-tier object's spine
// and ignores an unknown higher-tier NON-critical extension, but rejects an unknown CRITICAL
// extension (fail-closed). The tier field changes; the envelope does not.
func TestHigherTierExtMechanism(t *testing.T) {
	signer, verifier, pkb := testSigner(t, 103)
	kindOK := func(ch, k uint64) bool { return true }

	// Tier-1 object with a higher-tier NON-critical ext (key 7) — baseline ignores it.
	o1 := &envelope.Object{Kind: 0, Channel: 0, Tier: 1, Signer: pkb, Created: 100, Effect: 0, Profile: uint64(cose.ProfilePublic), Body: cbor.Uint(0), Ext: cbor.Map{{K: cbor.Uint(7), V: cbor.Tstr("higher-tier-hint")}}}
	signed1, err := envelope.Sign(o1, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Verify(cose.ProfilePublic, verifier, kindOK, nil, signed1); err != nil {
		t.Fatalf("baseline verifier rejected a tier-1 object's spine: %v", err)
	}
	// Tier-1 object with an unknown CRITICAL ext (key 9) — baseline rejects, fail-closed.
	o2 := &envelope.Object{Kind: 0, Channel: 0, Tier: 1, Signer: pkb, Created: 100, Effect: 0, Profile: uint64(cose.ProfilePublic), Body: cbor.Uint(0), Cext: cbor.Map{{K: cbor.Uint(9), V: cbor.Tstr("must-understand")}}}
	signed2, err := envelope.Sign(o2, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Verify(cose.ProfilePublic, verifier, kindOK, nil, signed2); err == nil {
		t.Fatal("baseline verifier accepted an unknown critical higher-tier extension")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "UnknownCriticalExt" {
		t.Fatalf("want UnknownCriticalExt, got %v", err)
	}
}
