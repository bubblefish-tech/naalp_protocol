// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package audit implements C7 — the signed hash-chained receipt (the baseline single-authority
// ordering tier), the equivocation auditor, and the offline-checkable causal graph (design.md
// §8; requirements R-8.1..8.6, R-12.2, R-12.3).
//
// An ordering authority records each accepted object by appending a signed Receipt
// {prev, obj, seq, at}; the chain is tamper-evident because reordering, omission, or
// substitution breaks a `prev` link or a `seq` (§8.1). The authority never mutates the origin
// object to order it — ordering is an outer signed layer, and the object's own signature stays
// valid (§8.2). The causal graph is the authority-independent foundation: an edge "A causes B"
// is proven by B's signature over A's content id (envelope field 8) and is checkable offline;
// a total order is a policy layered over this partial order (§8.2). A cause an effect could not
// have seen (later position, or a cycle) is rejected (CausalViolation, §8.3). An auditor detects
// equivocation — two receipts by one authority at one seq naming different objects — from the
// signed receipts alone (§8.5). The federation (higher) tier reconciles multiple authorities'
// chains over this same causal graph with no wire change; it is built at T13.
package audit

import (
	"bytes"
	"crypto/sha512"

	"github.com/bubblefish-tech/n-aalp/impl/go/cbor"
	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
)

// HeadSize is the width of a chain head / prev link (SHA-384 = 48 bytes). Genesis is zero.
const HeadSize = 48

// Errors reuse the cose.Error type so every N-AALP error carries a stable Kind (design §8.6).
var (
	ErrChainBroken      = &cose.Error{Kind: "ChainBroken", Msg: "receipt prev/seq does not chain to the previous receipt"}
	ErrEquivocation     = &cose.Error{Kind: "Equivocation", Msg: "two receipts at one seq name different objects"}
	ErrCausalViolation  = &cose.Error{Kind: "CausalViolation", Msg: "causal graph has a cycle or a future cause"}
	ErrReceiptUnsigned  = &cose.Error{Kind: "ReceiptUnsigned", Msg: "receipt signature does not verify"}
)

// Receipt is one signed append to an ordering authority's chain (design.md §8.1).
type Receipt struct {
	Prev []byte // hash of the previous receipt body (HeadSize bytes; genesis is zero)
	Obj  []byte // content id of the accepted object (never the object itself — §8.2)
	Seq  uint64 // monotonic sequence position within this authority's chain
	At   uint64 // the authority's time anchor, epoch ms (independent of the signer's clock, R-8.4)
}

// Bytes is the deterministic-CBOR encoding of the receipt body {1: prev, 2: obj, 3: seq, 4: at}.
func (r Receipt) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(r.Prev)},
		{K: cbor.Uint(2), V: cbor.Bstr(r.Obj)},
		{K: cbor.Uint(3), V: cbor.Uint(r.Seq)},
		{K: cbor.Uint(4), V: cbor.Uint(r.At)},
	})
	return b
}

// Head is the chain head after this receipt: SHA-384 of the receipt body. Because the body
// carries Prev, editing any receipt breaks the next receipt's linkage.
func (r Receipt) Head() []byte {
	d := sha512.Sum384(r.Bytes())
	return d[:]
}

// Authority is a baseline single ordering authority (§8.4). It appends monotonic signed
// receipts over object content ids; it holds no object bodies and mutates none.
type Authority struct {
	signer cose.Signer
	head   []byte
	seq    uint64
}

// NewAuthority starts an authority with an empty (genesis) chain.
func NewAuthority(signer cose.Signer) *Authority {
	return &Authority{signer: signer, head: make([]byte, HeadSize)}
}

// Append records acceptance of the object named by content id obj at time at, returning the
// signed receipt and its signature. Seq increases by one per append (monotonic).
func (a *Authority) Append(obj []byte, at uint64) (Receipt, []byte, error) {
	r := Receipt{Prev: append([]byte(nil), a.head...), Obj: append([]byte(nil), obj...), Seq: a.seq, At: at}
	sig, err := a.signer.Sign(r.Bytes())
	if err != nil {
		return Receipt{}, nil, err
	}
	a.head = r.Head()
	a.seq++
	return r, sig, nil
}

// VerifyChain checks a receipt chain offline against the authority's key: each receipt's Seq is
// the next expected value, its Prev links to the previous receipt's Head (genesis is zero), and
// its signature verifies. A broken link or a seq gap is ChainBroken; a bad signature is
// ReceiptUnsigned. This detects any reorder, omission, or substitution (§8.1).
func VerifyChain(receipts []Receipt, sigs [][]byte, v cose.Verifier) error {
	if len(receipts) != len(sigs) {
		return ErrChainBroken
	}
	head := make([]byte, HeadSize)
	for i, r := range receipts {
		if r.Seq != uint64(i) || !bytes.Equal(r.Prev, head) {
			return ErrChainBroken
		}
		if !v.VerifyRaw(r.Bytes(), sigs[i]) {
			return ErrReceiptUnsigned
		}
		head = r.Head()
	}
	return nil
}

// ConsistentWithAnchor reports whether an object's advisory `created` time is consistent with
// the authority's independent time anchor `at` (R-8.4): an object cannot be created after the
// authority ordered it, so created MUST NOT exceed at. The receipt's `at` is signed and
// chained, so it is evidence a verifier checks independently of the signer's clock.
func ConsistentWithAnchor(created, at uint64) bool { return created <= at }

// ForkProof is the evidence of equivocation: two validly-signed receipts by one authority at
// the same seq naming different objects (§8.5). It is offline-verifiable by anyone.
type ForkProof struct {
	A, B Receipt
}

// Auditor observes an authority's receipts and detects equivocation from the signed receipts
// alone (§8.5). It does not and cannot force delivery of withheld events — that residual is a
// trust property of the authority, not something the wire removes.
type Auditor struct {
	v    cose.Verifier
	seen map[uint64]Receipt
}

// NewAuditor makes an auditor for one authority's key.
func NewAuditor(v cose.Verifier) *Auditor {
	return &Auditor{v: v, seen: make(map[uint64]Receipt)}
}

// Observe records a signed receipt. It returns ReceiptUnsigned if the signature is invalid; a
// non-nil ForkProof with Equivocation if a previously-seen receipt at the same seq named a
// different object; and (nil, nil) otherwise (including a benign exact duplicate).
func (a *Auditor) Observe(r Receipt, sig []byte) (*ForkProof, error) {
	if !a.v.VerifyRaw(r.Bytes(), sig) {
		return nil, ErrReceiptUnsigned
	}
	if prev, ok := a.seen[r.Seq]; ok {
		if !bytes.Equal(prev.Obj, r.Obj) {
			return &ForkProof{A: prev, B: r}, ErrEquivocation
		}
		return nil, nil
	}
	a.seen[r.Seq] = r
	return nil, nil
}

// CausalNode is an object's place in the causal graph: its content id, the content ids of its
// causes (envelope field 8), and its ordering position (authority seq, or `created` absent a
// receipt).
type CausalNode struct {
	ID       []byte
	Causes   [][]byte
	Position uint64
}

// VerifyCausal checks the signed partial order (§8.2, §8.3): no object names a cause whose
// position exceeds its own (a future cause it could not have seen), and the graph is acyclic.
// Either fault is CausalViolation. Edges to causes not present in the set are ignored (they are
// external references, offline-unresolvable here). This runs with no ordering authority present
// (R-8.5). It never authorizes; it only accepts or rejects.
func VerifyCausal(nodes []CausalNode) error {
	idx := make(map[string]int, len(nodes))
	for i, n := range nodes {
		idx[string(n.ID)] = i
	}
	// No future cause: a present cause must not sit at a later position than its effect.
	for _, n := range nodes {
		for _, c := range n.Causes {
			if j, ok := idx[string(c)]; ok && nodes[j].Position > n.Position {
				return ErrCausalViolation
			}
		}
	}
	// Acyclic: 3-colour DFS over depends-on edges (effect -> cause).
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make([]int, len(nodes))
	var hasCycle func(i int) bool
	hasCycle = func(i int) bool {
		color[i] = gray
		for _, c := range nodes[i].Causes {
			j, ok := idx[string(c)]
			if !ok {
				continue
			}
			if color[j] == gray {
				return true
			}
			if color[j] == white && hasCycle(j) {
				return true
			}
		}
		color[i] = black
		return false
	}
	for i := range nodes {
		if color[i] == white && hasCycle(i) {
			return ErrCausalViolation
		}
	}
	return nil
}

// TopoOrder returns the causal nodes' content ids in a deterministic topological order (a cause
// before its effects). Ties among ready nodes break by (position, input index), so the order is
// reproducible. It returns CausalViolation if the graph does not verify.
func TopoOrder(nodes []CausalNode) ([][]byte, error) {
	if err := VerifyCausal(nodes); err != nil {
		return nil, err
	}
	idx := make(map[string]int, len(nodes))
	for i, n := range nodes {
		idx[string(n.ID)] = i
	}
	indeg := make([]int, len(nodes))
	effects := make([][]int, len(nodes)) // cause index -> effect indices
	for i, n := range nodes {
		for _, c := range n.Causes {
			if j, ok := idx[string(c)]; ok {
				effects[j] = append(effects[j], i)
				indeg[i]++
			}
		}
	}
	done := make([]bool, len(nodes))
	order := make([][]byte, 0, len(nodes))
	for len(order) < len(nodes) {
		pick := -1
		for i := range nodes {
			if done[i] || indeg[i] != 0 {
				continue
			}
			if pick == -1 || nodes[i].Position < nodes[pick].Position {
				pick = i // lowest position wins; equal positions keep the lower index (first seen)
			}
		}
		if pick == -1 {
			return nil, ErrCausalViolation // unreachable after VerifyCausal, but fail-closed
		}
		done[pick] = true
		order = append(order, nodes[pick].ID)
		for _, e := range effects[pick] {
			indeg[e]--
		}
	}
	return order, nil
}
