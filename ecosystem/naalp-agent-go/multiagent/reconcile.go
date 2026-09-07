// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package multiagent implements the N-AALP genuinely multi-agent patterns for Go agents
// (ecosystem task E1.4, requirement R2.4 -- mirroring the shipped Python ecosystem task
// E1.3/R2.3): SequentialPipeline ("agent A's signed output feeds agent B feeds C") and
// ParallelFanout (N agents converge via the real Part-1 federated-ordering reconcile
// primitive). See pipeline.go and fanout.go for the two shapes' full API and design
// rationale.
//
// This file, reconcile.go, is the reconcile step: converge a set of independently-signed,
// causally-linked N-AALP objects produced by MULTIPLE agents into one deterministic total
// order.
//
// This file performs NO topological sort, NO cycle detection, and NO tie-break logic of
// its own: ReconcileNodes is a direct, undecorated call to the real Part-1 tier-1
// federated-ordering primitive impl/go/federation.Reconcile (design.md Sec.8.4;
// design-channels.md Sec.7) -- the SAME deterministic linearization (Kahn's algorithm
// over the union causal DAG, ties broken by content id, bytewise ascending) every
// ordering authority in the protocol already uses to merge multiple scopes/authorities
// into one order (R-8.6: "any split of the same objects reconciles to the same order").
// This package's N parallel agents ARE exactly that primitive's "multiple independent
// authorities": this file supplies no second reconciliation algorithm, only a thin,
// directly-callable entry point plus a re-exported CausalNode type so callers building a
// graph never need to import impl/go/audit directly.
//
// A cyclic or otherwise inconsistent causal graph is rejected by impl/go/audit.VerifyCausal
// (invoked internally by federation.Reconcile) with the registered "CausalViolation" error
// (impl/go/naalperror.Names) -- propagated here UNCHANGED, never renamed or wrapped,
// because it is already the correct, registered semantic name for "this causal input is
// not a valid partial order" (the same reuse-not-reinvent convention the sibling react
// package follows for WrongAudience/CausalViolation: a Part-1 registered error is never
// given a second, competing name at the ecosystem layer).
package multiagent

import (
	"github.com/bubblefish-tech/naalp_protocol/impl/go/audit"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/federation"
)

// CausalNode is a node's place in the shared causal graph: its content id, the content
// ids it causally depends on, and its ordering position (0 for a plan-level/pre-position
// graph, matching the reference reconcile's own uniform-zero-position convention for
// causally-concurrent nodes -- see federation.Reconcile's own tie-break-by-content-id
// behaviour for nodes that all share position 0). A direct type alias for the real Part-1
// impl/go/audit.CausalNode, re-exported so callers never need to import impl/go/audit
// directly.
type CausalNode = audit.CausalNode

// ReconcileNodes deterministically linearizes the union causal DAG over nodes via the
// real Part-1 reconcile primitive. Returns the content ids (bytes) in the deterministic
// total order -- the shared root(s) before their dependents, ties among
// causally-concurrent objects broken bytewise-ascending by content id. Returns the
// registered CausalViolation error (propagated from impl/go/federation.Reconcile /
// impl/go/audit.VerifyCausal) if nodes is not a valid partial order -- a cycle, including
// a node that names itself (directly or transitively) among its own causes -- fail-closed,
// before any order is ever produced.
func ReconcileNodes(nodes []CausalNode) ([][]byte, error) {
	return federation.Reconcile(nodes)
}
