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

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// HeadSize is the width of a chain head / prev link (SHA-384 = 48 bytes). Genesis is zero.
const HeadSize = 48

// Errors reuse the cose.Error type so every N-AALP error carries a stable Kind (design §8.6).
var (
	ErrChainBroken     = &cose.Error{Kind: "ChainBroken", Msg: "receipt prev/seq does not chain to the previous receipt"}
	ErrEquivocation    = &cose.Error{Kind: "Equivocation", Msg: "two receipts at one seq name different objects"}
	ErrCausalViolation = &cose.Error{Kind: "CausalViolation", Msg: "causal graph has a cycle or a future cause"}
	ErrReceiptUnsigned = &cose.Error{Kind: "ReceiptUnsigned", Msg: "receipt signature does not verify"}
	ErrForkProofInvalid = &cose.Error{Kind: "ForkProofInvalid", Msg: "fork proof does not prove equivocation"}
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

// ForkProof is the non-repudiable evidence of equivocation (design.md §8.5, R-8.3): two
// validly-signed receipts by ONE authority at the SAME seq naming DIFFERENT objects, together
// with the accused authority's OWN two signatures over those two receipt bodies. draft-01
// (finding #70) added SigA/SigB and the external counter: draft-00's proof named the two receipts
// but carried neither signature, so an accused signer could deny the fork; carrying both of the
// accused's signatures makes the proof self-contained — any third party verifies both signatures
// against the accused key with no further evidence and no repudiation.
type ForkProof struct {
	Signer     []byte  // accused authority signer id (envelope field-5 form); both sigs verify under its key
	ExtCounter uint64  // external monotonic counter bound into the proof (T2.1): fixes replay/reorder
	A          Receipt // first receipt (A.Bytes() is the signed input for SigA)
	SigA       []byte  // the accused authority's signature over A.Bytes()
	B          Receipt // second receipt at the same seq naming a different object
	SigB       []byte  // the accused authority's signature over B.Bytes()
}

// NewForkProof assembles a fork proof from two conflicting signed receipts, the accused signer id,
// and an external monotonic counter. It copies the byte slices so the proof owns its evidence.
// It performs no checks — Verify is the fail-closed gate; this is the pure constructor (A9).
func NewForkProof(signer []byte, a Receipt, sigA []byte, b Receipt, sigB []byte, extCounter uint64) ForkProof {
	return ForkProof{
		Signer:     append([]byte(nil), signer...),
		ExtCounter: extCounter,
		A:          a,
		SigA:       append([]byte(nil), sigA...),
		B:          b,
		SigB:       append([]byte(nil), sigB...),
	}
}

// Bytes is the deterministic-CBOR encoding of the fork-proof body (draft-01 naalp-fork-proof):
// {1: signer, 2: ext_counter, 3: body_a, 4: sig_a, 5: body_b, 6: sig_b}. The two receipt bodies
// are embedded as the exact bytes each signature covers.
func (fp ForkProof) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(fp.Signer)},
		{K: cbor.Uint(2), V: cbor.Uint(fp.ExtCounter)},
		{K: cbor.Uint(3), V: cbor.Bstr(fp.A.Bytes())},
		{K: cbor.Uint(4), V: cbor.Bstr(fp.SigA)},
		{K: cbor.Uint(5), V: cbor.Bstr(fp.B.Bytes())},
		{K: cbor.Uint(6), V: cbor.Bstr(fp.SigB)},
	})
	return b
}

// Preimage is the deterministic-CBOR framing witness: the fork-proof body with the two signature
// byte-strings elided to empty. It is the structural authority the independent oracle reproduces
// byte-for-byte; the two ML-DSA signatures are graded by cross-implementation deterministic
// byte-parity (the cose.sign1 consensus, anchored to the NIST keyGen KAT), as with every other
// signed object. This is not a wire object; it exists only to grade the framing.
func (fp ForkProof) Preimage() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(fp.Signer)},
		{K: cbor.Uint(2), V: cbor.Uint(fp.ExtCounter)},
		{K: cbor.Uint(3), V: cbor.Bstr(fp.A.Bytes())},
		{K: cbor.Uint(4), V: cbor.Bstr(nil)},
		{K: cbor.Uint(5), V: cbor.Bstr(fp.B.Bytes())},
		{K: cbor.Uint(6), V: cbor.Bstr(nil)},
	})
	return b
}

// Verify checks that fp is a non-repudiable proof of equivocation by the authority whose key is v
// (design.md §8.5, R-8.3). It accepts iff ALL hold: (1) the signer id is present; (2) the two
// receipts share one seq; (3) they name DIFFERENT objects (an authority contradicting itself); and
// (4) BOTH signatures verify under v — which, because a single verifier checks both, proves one
// signer. Any failure rejects the whole proof (fail-closed) with a named error and accepts nothing
// partial: a same-object / seq-mismatch / unnamed-signer proof is ForkProofInvalid, and a signature
// that does not verify is ReceiptUnsigned. v MUST be the verifier resolved for fp.Signer.
func (fp ForkProof) Verify(v cose.Verifier) error {
	if len(fp.Signer) == 0 {
		return ErrForkProofInvalid // an unnamed accused is not evidence
	}
	if fp.A.Seq != fp.B.Seq {
		return ErrForkProofInvalid // different sequence positions → not one-seq equivocation
	}
	if bytes.Equal(fp.A.Obj, fp.B.Obj) {
		return ErrForkProofInvalid // same object named twice → the authority did not equivocate
	}
	if !v.VerifyRaw(fp.A.Bytes(), fp.SigA) || !v.VerifyRaw(fp.B.Bytes(), fp.SigB) {
		return ErrReceiptUnsigned // a signature that does not verify under the accused key
	}
	return nil // a valid, non-repudiable proof of Equivocation
}

// seenReceipt is a receipt the auditor has accepted, kept with its signature so a later conflict
// can be minted into a ForkProof carrying BOTH of the accused's signatures (draft-01, §8.5).
type seenReceipt struct {
	r   Receipt
	sig []byte
}

// Auditor observes an authority's receipts and detects equivocation from the signed receipts
// alone (§8.5). On a conflict it mints a non-repudiable ForkProof carrying the accused signer id,
// both conflicting signatures, and an external monotonic counter (T2.1). It does not and cannot
// force delivery of withheld events — that residual is a trust property of the authority, not
// something the wire removes.
type Auditor struct {
	v          cose.Verifier
	signer     []byte // the accused authority's signer id, stamped into minted proofs
	extCounter uint64 // external monotonic counter; the current value is bound into each proof, then advanced
	seen       map[uint64]seenReceipt
}

// NewAuditor makes an auditor for one authority (its verifier v and signer id), its external
// counter starting at zero.
func NewAuditor(v cose.Verifier, signer []byte) *Auditor {
	return NewAuditorAt(v, signer, 0)
}

// NewAuditorAt makes an auditor whose external monotonic counter starts at extBase, so the counter
// bound into proofs can be seeded from an external source (T2.1).
func NewAuditorAt(v cose.Verifier, signer []byte, extBase uint64) *Auditor {
	return &Auditor{v: v, signer: append([]byte(nil), signer...), extCounter: extBase, seen: make(map[uint64]seenReceipt)}
}

// Observe records a signed receipt. It returns ReceiptUnsigned if the signature is invalid; a
// non-nil ForkProof with Equivocation if a previously-seen receipt at the same seq named a
// different object (the proof carries the accused signer id, both stored/observed signatures, and
// the auditor's current external counter, which then advances); and (nil, nil) otherwise (including
// a benign exact duplicate).
func (a *Auditor) Observe(r Receipt, sig []byte) (*ForkProof, error) {
	if !a.v.VerifyRaw(r.Bytes(), sig) {
		return nil, ErrReceiptUnsigned
	}
	if prev, ok := a.seen[r.Seq]; ok {
		if !bytes.Equal(prev.r.Obj, r.Obj) {
			fp := NewForkProof(a.signer, prev.r, prev.sig, r, sig, a.extCounter)
			a.extCounter++
			return &fp, ErrEquivocation
		}
		return nil, nil
	}
	a.seen[r.Seq] = seenReceipt{r: r, sig: append([]byte(nil), sig...)}
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
