// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package federation implements the Federation higher tier (tier 1) — federated ordering by a
// deterministic reconcile-merge over the shared causal graph (design.md §8.4;
// design-channels.md §7; requirements R-8.6, R-15A.2, R-15A.3).
//
// The baseline tier is a single ordering authority's monotonic receipt chain (C7, T7). The
// higher tier lets multiple independent authorities each order their own scope and reconcile
// over the shared causal graph — the partial order every authority already signs over (§8.2).
// Reconcile is a DETERMINISTIC linearization of the union causal DAG: a topological sort whose
// tie-break among causally-concurrent objects is the object content id (bytewise ascending).
// Because it depends only on the causal graph (not on how scopes are split), any split of the
// same objects reconciles to the same order — so moving from single-authority to federated
// ordering requires no envelope or object change (R-8.6). A higher tier adds capability without
// changing the baseline envelope/effect/identity/audit (R-15A.2).
package federation

import (
	"bytes"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/audit"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// ErrScopeOverlapConflict is Federation's named error: two authorities ordering the same scope.
// At the baseline tier an overlap is an operator error; at tier 1 the causal-graph reconcile
// resolves it (the object is ordered once by the shared causal constraints).
var ErrScopeOverlapConflict = &cose.Error{Kind: "ScopeOverlapConflict", Msg: "authorities' scopes overlap"}

// Reconcile deterministically merges the objects of a shared causal graph into one total order
// (design.md §8.4). It first verifies the graph is a valid partial order (acyclic, no
// future-cause; audit.VerifyCausal), then linearizes it with Kahn's algorithm, breaking ties
// among ready nodes by content id (bytewise ascending). The result is causally consistent and
// deterministic. A duplicate object id (scope overlap) is ordered once (resolved).
func Reconcile(nodes []audit.CausalNode) ([][]byte, error) {
	if err := audit.VerifyCausal(nodes); err != nil {
		return nil, err
	}
	present := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		present[string(n.ID)] = true
	}
	indeg := make([]int, len(nodes))
	for i, n := range nodes {
		for _, c := range n.Causes {
			if present[string(c)] {
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
			if pick == -1 || bytes.Compare(nodes[i].ID, nodes[pick].ID) < 0 {
				pick = i
			}
		}
		if pick == -1 {
			return nil, audit.ErrCausalViolation // unreachable after VerifyCausal; fail-closed
		}
		done[pick] = true
		order = append(order, nodes[pick].ID)
		for j := range nodes {
			if done[j] {
				continue
			}
			for _, c := range nodes[j].Causes {
				if bytes.Equal(c, nodes[pick].ID) {
					indeg[j]--
				}
			}
		}
	}
	return order, nil
}

// CausallyValid reports whether an order places every object's (present) causes before it.
func CausallyValid(order [][]byte, nodes []audit.CausalNode) bool {
	pos := make(map[string]int, len(order))
	for k, id := range order {
		pos[string(id)] = k
	}
	for _, n := range nodes {
		np, ok := pos[string(n.ID)]
		if !ok {
			continue
		}
		for _, c := range n.Causes {
			if cp, ok := pos[string(c)]; ok && cp > np {
				return false
			}
		}
	}
	return true
}

// ReconcileRecord is the tier-1 Federation Reconcile object body (design-channels.md §7): the
// authorities reconciled and the resulting deterministic total order (object content ids). It is
// signed with the C2 crypto over its deterministic-CBOR bytes; it orders the identical signed
// objects the baseline already produced (no envelope change).
type ReconcileRecord struct {
	Authorities []string
	Order       [][]byte
}

// Bytes is the deterministic-CBOR encoding {1: [authorities], 2: [order content-ids]}.
func (r ReconcileRecord) Bytes() []byte {
	auth := make(cbor.Arr, 0, len(r.Authorities))
	for _, a := range r.Authorities {
		auth = append(auth, cbor.Tstr(a))
	}
	order := make(cbor.Arr, 0, len(r.Order))
	for _, o := range r.Order {
		order = append(order, cbor.Bstr(o))
	}
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: auth},
		{K: cbor.Uint(2), V: order},
	})
	return b
}

// SignReconcile signs a Reconcile record with a tier-1 ordering authority's key.
func SignReconcile(r ReconcileRecord, s cose.Signer) ([]byte, error) { return s.Sign(r.Bytes()) }
