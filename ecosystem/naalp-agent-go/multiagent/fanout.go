// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// The N-AALP parallel multi-agent fan-out + reconcile (ecosystem task E1.4, requirement
// R2.4 -- mirroring the shipped Python ecosystem task E1.3/R2.3's parallel shape): N
// agents act CONCURRENTLY on a shared input -- each agent's own signed request causally
// links (Causes) to that ONE shared input's content id -- and their resulting signed,
// causally-linked branches then CONVERGE at a reconcile step that produces a
// deterministic linearization of the union causal graph (this package's own
// ReconcileNodes, a direct call to the real Part-1 impl/go/federation.Reconcile
// primitive), so two runs of the SAME parallel set reconcile to the SAME order regardless
// of which branch's goroutine happened to finish first. A branch whose response fails
// verification is EXCLUDED from the reconciled graph under its own named error (never
// silently dropped without a reason, never included with a fabricated causal edge); a
// caller-supplied causal graph that is not a valid partial order (a cycle) is rejected by
// the reconcile step with the registered "CausalViolation" error, propagated unchanged.
//
//	Branch, Branch, ..., sharedInputID -> Fanout.Run() -> a FanoutRun:
//	    per-agent BranchResult (agentID -> BranchResult) + the reconciled total order.
//
// Design choice -- calls react.Bridge's ActionToRequest/ResponseToObservation DIRECTLY
// for each branch's sign -> execute -> verify sequence, rather than routing through the
// sibling plan.Orchestrator: see pipeline.go's package docstring for the full reasoning
// -- Orchestrator.Run unconditionally recomputes a task's causal edges from ITS OWN
// task.Prereqs within that one run under one bridge, so it cannot accept an
// externally-supplied sharedInputID as a branch's cause (wrapping a branch in a
// single-task Orchestrator and pre-setting Causes does NOT survive: Orchestrator
// silently overwrites it with nil). This file therefore reuses the underlying primitive
// plan.Orchestrator itself reuses -- the react.Bridge -- directly; the per-branch
// build/sign/execute/verify/degrade control flow mirrors Orchestrator.Run's own
// per-node shape (this task's own scheduling glue, not a cryptographic primitive). The
// branches are then dispatched onto real goroutines so the fan-out is GENUINELY
// concurrent -- branch completion order is not fixed by dispatch order, which is
// precisely what makes "two runs reconcile to the same order" a real property of the
// reconcile step rather than an artifact of always processing branches in the same
// sequence.
//
// Design choice -- unlike the sibling Python ecosystem's naalp_multiagent.ParallelFanout,
// this Go package needs NO crypto-serialization lock around its concurrent signing calls:
// the Python package's CRYPTO_LOCK exists because the Python reference SDK's ML-DSA
// backend (the pure-Python dilithium_py library) is a process-wide, NOT thread-safe,
// mutable singleton. Go's Part-1 reference SDK signs through
// github.com/cloudflare/circl/sign/mldsa, whose ML-DSA-65/87 "scheme" type is a stateless
// EMPTY STRUCT (circl/sign/mldsa/mldsa65.scheme{}) dispatching to pure functions over
// caller-owned buffers -- there is no shared mutable singleton to corrupt. This was
// verified two ways: (1) reading the vendored circl source (no package-level mutable
// state in mldsa65/mldsa87 or their internal packages beyond one read-only
// init-computed bool), and (2) TestConcurrentSignVerifyNoCorruption in fanout_test.go,
// which drives many goroutines through concurrent cose.MLDSA65Signer.Sign +
// cose.MLDSA65Verifier.VerifyRaw calls under `go test -race` and asserts zero
// corruption -- the same empirical diligence the Python package's own docstring records
// for its (different, positive) finding.
//
// Design choice -- AgentID uniqueness is enforced BEFORE any branch runs
// (*Error{"DuplicateAgentId", ...}), never discovered after the fact: BranchResults is
// AgentID-keyed, so two branches sharing an id would silently discard one branch's real
// result -- the same class of structural pre-flight check plan.Orchestrator performs for
// "DuplicateTaskId" before any node is signed.
//
// Design choice -- the shared input is named by its content id (sharedInputID []byte)
// alone, never by a whole envelope.Object or a bridge of its own: R2.4 requires only that
// every branch's output causally link to "a shared input", and a caller who wants that
// input to be itself a REAL signed N-AALP object (e.g. a coordinator agent's own
// broadcast request) simply passes that object's own content id -- this file places no
// requirement on how the shared input was produced, or that it was produced by this
// package at all. The shared input's own id is included as a root CausalNode (with no
// causes) in every reconciled graph, so the reconciled order always places it before its
// dependent branches.
//
// Design choice -- a branch's Error name is the underlying registered N-AALP error
// (observation.Error, e.g. "WrongAudience"/"BadSignature"/"CausalViolation") whenever a
// response was actually verified and refused; only when no response was ever verified at
// all (the request itself could not be built/signed/validated, or the executor call
// failed) does this file fall back to its own glue-layer name
// "SigningOrExecutionRefused" -- never fabricating a Part-1 registered name for a
// failure Part-1 never actually classified.
package multiagent

import (
	"fmt"
	"sync"

	"github.com/bubblefish-tech/naalp_protocol/ecosystem/naalp-agent-go/react"
)

// Error is a named, fail-closed multiagent structural error. Kind is currently only
// "DuplicateAgentId" (two branches in the same Fanout share an AgentID -- checked before
// any branch is dispatched, so it never races the goroutine pool).
type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string { return e.Kind + ": " + e.Msg }

// BranchExecutor sends branch's signed request and returns the raw response bytes.
type BranchExecutor func(branch Branch, request react.Request) ([]byte, error)

// BranchBuildAction builds this branch's own Action from the shared input's content id.
// Its returned Action's own Causes field is IGNORED and overwritten with
// [sharedInputID], exactly as StageBuildAction's result is overwritten with the prior
// stage's content id. A non-nil error excludes this branch before any request is built.
type BranchBuildAction func(sharedInputID []byte) (react.Action, error)

// Branch is one branch in a parallel multi-agent fan-out. AgentID uniquely labels which
// agent runs this branch (the key into FanoutRun.BranchResults; MUST be unique across a
// single Fanout's branches -- checked by NewParallelFanout). Bridge is that agent's own
// injected react.Bridge-shaped object. Executor sends this branch's signed request and
// returns the raw response bytes. BuildAction builds this branch's own Action from the
// shared input's content id.
type Branch struct {
	AgentID     string
	Bridge      Bridge
	Executor    BranchExecutor
	BuildAction BranchBuildAction
}

// BranchResult is the outcome of one fan-out branch. Status is "executed" (this branch's
// request was signed, its executor ran, and the response verified OK -- its request
// content id IS included in the reconciled graph) or "excluded" (this branch's own
// request could not be built/signed/validated, its executor call failed, or its response
// failed verification -- its Error names the failure and its content id, if one was ever
// produced, is NEVER included in the reconciled graph).
type BranchResult struct {
	AgentID     string
	Status      string
	Request     *react.Request
	Observation *react.Observation
	Error       string
	Detail      string
}

// FanoutRun is the complete result of one Fanout.Run(): the shared input's content id,
// the per-agent BranchResult (keyed by AgentID), and the reconciled deterministic total
// order (the shared input's content id first, then every EXECUTED branch's signed
// request content id, in the Part-1 reconcile primitive's own tie-broken order).
type FanoutRun struct {
	SharedInputID   []byte
	BranchResults   map[string]BranchResult
	ReconciledOrder [][]byte
}

// Executed returns the agent ids whose branch reached Status == "executed".
func (r FanoutRun) Executed() []string {
	out := make([]string, 0, len(r.BranchResults))
	for aid, res := range r.BranchResults {
		if res.Status == "executed" {
			out = append(out, aid)
		}
	}
	return out
}

// branchAttempt is the internal outcome of running ONE branch's build -> sign -> execute
// -> verify sequence, before it is classified into a BranchResult and (if executed)
// folded into the reconciled graph. Never panics for a per-branch failure -- every
// failure point is checked at its own call site (mirrors Pipeline's runStage shape).
type branchAttempt struct {
	status      string
	request     *react.Request
	observation *react.Observation
	detail      string
}

// runBranch runs ONE branch's build -> sign -> execute -> verify sequence against
// branch's own bridge, with its Action causally linked to sharedInputID. This is the
// unit dispatched onto a goroutine, so it must not touch any state shared across
// branches -- it only closes over the one branch and the one shared sharedInputID value
// (immutable bytes).
func runBranch(branch Branch, sharedInputID []byte) branchAttempt {
	action, err := branch.BuildAction(sharedInputID)
	if err != nil {
		return branchAttempt{
			status: "refused",
			detail: fmt.Sprintf("action build or request signing/validation refused: %v", err),
		}
	}
	action.Causes = [][]byte{sharedInputID}

	request, err := branch.Bridge.ActionToRequest(action)
	if err != nil {
		// fail-closed: ANY build/sign/validate refusal excludes this branch only.
		return branchAttempt{
			status: "refused",
			detail: fmt.Sprintf("action build or request signing/validation refused: %v", err),
		}
	}

	responseBytes, err := branch.Executor(branch, request)
	if err != nil {
		// an executor failure excludes this branch; never a fabricated Observation.
		return branchAttempt{status: "refused", request: &request, detail: fmt.Sprintf("executor failed: %v", err)}
	}

	observation := branch.Bridge.ResponseToObservation(responseBytes, request)
	if !observation.OK {
		return branchAttempt{
			status: "refused", request: &request, observation: &observation,
			detail: "response verification refused: " + observation.Error,
		}
	}

	return branchAttempt{status: "executed", request: &request, observation: &observation}
}

// Fanout dispatches Branches CONCURRENTLY (real goroutines, never a sequential loop
// dressed up as "parallel") against a shared input, then converges every EXECUTED
// branch's signed request into one deterministic total order via the real Part-1
// reconcile primitive (ReconcileNodes). A branch that fails to build, sign, execute, or
// verify is EXCLUDED from the reconciled graph under its own named error -- never
// included, never silently dropped without a reason. Returns the registered
// CausalViolation error (propagated unchanged from the reconcile step) if the resulting
// causal graph is not a valid partial order -- which cannot happen from THIS type's own
// construction (every branch causes only the shared input, never another branch), but is
// exactly what the shared ReconcileNodes primitive itself guards against for an
// arbitrary caller-built graph.
type Fanout struct {
	Branches []Branch
}

// NewParallelFanout validates AgentID uniqueness across branches and returns a ready
// Fanout, or *Error{"DuplicateAgentId", ...} if two branches share an id.
func NewParallelFanout(branches []Branch) (*Fanout, error) {
	seen := make(map[string]bool, len(branches))
	for _, b := range branches {
		if seen[b.AgentID] {
			return nil, &Error{"DuplicateAgentId", fmt.Sprintf("agent id %q appears more than once in this fan-out", b.AgentID)}
		}
		seen[b.AgentID] = true
	}
	return &Fanout{Branches: branches}, nil
}

// Run dispatches every branch concurrently against sharedInputID, waits for all of them,
// then reconciles every EXECUTED branch's signed request content id (plus sharedInputID
// as the root) into one deterministic total order.
func (f *Fanout) Run(sharedInputID []byte) (FanoutRun, error) {
	type keyed struct {
		agentID string
		attempt branchAttempt
	}

	out := make(chan keyed, len(f.Branches))
	var wg sync.WaitGroup
	for _, b := range f.Branches {
		wg.Add(1)
		go func(branch Branch) {
			defer wg.Done()
			out <- keyed{agentID: branch.AgentID, attempt: runBranch(branch, sharedInputID)}
		}(b)
	}
	wg.Wait()
	close(out)

	attempts := make(map[string]branchAttempt, len(f.Branches))
	for k := range out {
		attempts[k.agentID] = k.attempt
	}

	branchResults := make(map[string]BranchResult, len(f.Branches))
	graphNodes := []CausalNode{{ID: sharedInputID, Causes: nil}}
	for _, b := range f.Branches {
		attempt := attempts[b.AgentID]
		if attempt.status == "executed" {
			branchResults[b.AgentID] = BranchResult{
				AgentID: b.AgentID, Status: "executed",
				Request: attempt.request, Observation: attempt.observation,
			}
			graphNodes = append(graphNodes, CausalNode{ID: attempt.request.ID, Causes: [][]byte{sharedInputID}})
		} else {
			errorName := "SigningOrExecutionRefused"
			if attempt.observation != nil {
				errorName = attempt.observation.Error
			}
			branchResults[b.AgentID] = BranchResult{
				AgentID: b.AgentID, Status: "excluded",
				Request: attempt.request, Observation: attempt.observation,
				Error: errorName, Detail: attempt.detail,
			}
		}
	}

	order, err := ReconcileNodes(graphNodes)
	if err != nil {
		return FanoutRun{}, err
	}
	return FanoutRun{SharedInputID: sharedInputID, BranchResults: branchResults, ReconciledOrder: order}, nil
}
