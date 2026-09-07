// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package plan is the N-AALP Plan-and-Execute orchestrator for Go agents (ecosystem task
// E1.4, requirement R2.4 -- mirroring the shipped Python ecosystem task E1.2/R2.2).
//
// Given a plan -- a DAG of tasks, each with an id, an Action, and a set of prerequisite
// task ids -- the orchestrator converts each node to a real signed N-AALP request object,
// sets its causal edges (Causes) to the content ids of its prerequisite nodes' request
// objects, executes nodes in a valid topological order, and is fail-closed: a node whose
// prerequisite refused/failed (or whose own request cannot be signed/validated) is NOT
// executed, and a cycle in the plan is rejected with a named error before any signing.
//
//	Plan (Task DAG) -> Orchestrator.Run() -> a Run: per-task NodeResult, in the
//	                                          topological order actually executed.
//
// This package performs NO cryptography, NO CBOR encoding, and NO second content-id
// computation of its own: every signed-object-level operation (canonical encoding,
// content-id binding, deterministic ML-DSA sign/verify, the audience point-of-use gate,
// the causal-linkage check on a response) is the real sibling react.Bridge's own
// ActionToRequest/ResponseToObservation, which in turn is the real Part-1
// impl/go/envelope primitive (design.md "Buy-before-make"; this package is
// DAG-scheduling and fail-closed-propagation glue, not a second copy of the ReAct bridge
// or the envelope/COSE primitive it wraps).
//
// Design choice -- the causal graph here is a PLAN-LEVEL, pre-signing DAG over
// caller-chosen task ids (plain strings), never impl/go/audit.VerifyCausal's SIGNED-object
// causal graph: VerifyCausal reconciles a set of ALREADY-SIGNED, ALREADY-POSITIONED nodes
// (it needs each node's final topological position up front, which does not exist yet for
// a plan that has not executed a single node), so it answers a different question than the
// one this orchestrator asks before any node is signed: "does this caller-declared task-id
// DAG contain a cycle, and in what order can its nodes be executed?" That question is
// answered here by a plain Kahn's-algorithm topological sort (ties broken lexicographically
// by task id, for a deterministic execution order) -- exactly mirroring the sibling
// react package's own documented choice not to reach for a graph-verification primitive
// when the narrower, pre-signing question is a better fit. Once a node IS signed, its
// causal edges are real N-AALP Causes entries -- the content ids of its prerequisites'
// real signed request objects -- so the resulting signed graph is exactly what
// audit.VerifyCausal would itself accept were it later run over the finished, positioned
// output (§8.2-§8.3): a plan-level topological sort here does not compete with that
// grading; it produces input that graph checks are already known to accept.
//
// Design choice -- an injected, interface-typed Bridge (never a hard construction of
// one): Bridge is any type exposing ActionToRequest(Action) (Request, error) and
// ResponseToObservation([]byte, Request) Observation -- exactly the sibling
// react.Bridge's own two public methods, so a real *react.Bridge (with its own
// clock/signing-key/audience/transport already set on IT) plugs in with zero adaptation,
// and a test can substitute a thin recording wrapper around a real bridge instead.
// Executor is any func(Task, Request) ([]byte, error): the synchronous "send this signed
// request, get the raw response bytes back" step -- the orchestrator's own analogue of a
// transport, injected exactly like react.Bridge's own Transport field, so no node's
// request/response cycle is ever driven by a hidden network call or a global. This keeps
// the whole orchestrator testable in isolation (this task's isolation-demo requirement)
// while still composing with a real bridge and a real transport exactly as the design
// intends.
//
// Design choice -- fail-closed by CATCHING, not by requiring callers to pre-filter: Run
// never lets a per-node signing/validation/execution/verification failure escape as a
// panic that aborts the whole plan (Go's analogue of Python's per-call try/except). Each
// of those three failure points is checked at its own call site and turned into a named
// NodeResult{Status: "refused", ...} for exactly that node, so one bad node degrades
// gracefully into "this node and everything that depends on it did not run" rather than
// crashing every other, unrelated branch of the plan. A cycle is the one failure that IS
// returned as an error from Run itself (*Error{"CyclicPlan", ...}) rather than recorded
// per-node, because a cyclic plan has no valid execution order at all -- there is no
// partial result to report, and it must be rejected before any node's request is ever
// signed.
package plan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bubblefish-tech/naalp_protocol/ecosystem/naalp-agent-go/react"
)

// Error is a named, fail-closed plan-structure error (E1.4/R2.4). Kind is one of:
// "CyclicPlan" (the task DAG contains a cycle -- returned before any node is signed),
// "DuplicateTaskId" (two tasks in the same plan share an id), or "UnknownPrerequisite"
// (a task names a prerequisite id that is not itself a task in the plan).
type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string { return e.Kind + ": " + e.Msg }

// Task is one node in a plan (R2.4's "a DAG of tasks, each with a name, an effect class,
// args, and a set of prerequisite task-ids"). ID is the caller-chosen, plan-local
// identifier used only to express the DAG (Prereqs) -- it never reaches the wire. Action
// is the N-AALP react.Action this node will request (name/channel/kind/effect/args); its
// own Causes field is IGNORED and overwritten by the orchestrator with the real content
// ids of Prereqs' signed request objects -- the caller declares causal STRUCTURE via
// Prereqs, never authors Causes bytes directly, because those bytes do not exist until a
// prerequisite is actually signed. Prereqs is nil/empty for a first-turn (root) task.
type Task struct {
	ID      string
	Action  react.Action
	Prereqs []string
}

// NodeResult is the outcome of one task after Orchestrator.Run(). Status is exactly one
// of: "executed" (the request was signed, the executor ran, and the response verified
// OK), "refused" (this task's OWN request could not be signed/validated, its executor
// call failed, or its response failed verification), or "blocked" (a prerequisite was
// not "executed", so this task's request was never even built or signed). Request is set
// whenever a signed request was actually produced (including a later-refused response);
// Observation is set only when a response was actually verified (never fabricated on a
// "blocked" or pre-verification "refused" outcome).
type NodeResult struct {
	TaskID      string
	Status      string
	Request     *react.Request
	Observation *react.Observation
	Detail      string
}

// Run is the complete result of executing a plan: the topological order actually used,
// and the per-task NodeResults (one entry per task in the plan, always present regardless
// of outcome).
type Run struct {
	Order      []string
	Results    map[string]NodeResult
	StartedAt  uint64
	FinishedAt uint64
}

// ObservationFor returns the Observation for taskID (nil if none was ever verified).
func (r Run) ObservationFor(taskID string) *react.Observation {
	return r.Results[taskID].Observation
}

// RequestIDFor returns the content id of taskID's signed request (nil if none was ever
// produced).
func (r Run) RequestIDFor(taskID string) []byte {
	if req := r.Results[taskID].Request; req != nil {
		return req.ID
	}
	return nil
}

// Executed returns the task ids that reached Status == "executed", in Run.Order.
func (r Run) Executed() []string {
	out := make([]string, 0, len(r.Order))
	for _, tid := range r.Order {
		if r.Results[tid].Status == "executed" {
			out = append(out, tid)
		}
	}
	return out
}

// Bridge is the interface Orchestrator depends on -- exactly react.Bridge's own two
// public methods, so a real *react.Bridge plugs in with zero adaptation.
type Bridge interface {
	ActionToRequest(action react.Action) (react.Request, error)
	ResponseToObservation(responseBytes []byte, request react.Request) react.Observation
}

// Executor sends task's signed request and returns the raw response bytes.
type Executor func(task Task, request react.Request) ([]byte, error)

// Orchestrator schedules a Task DAG into a valid topological order, converting each task
// into a real signed N-AALP request (via the injected Bridge) whose Causes names exactly
// its prerequisites' signed request content ids, running the injected Executor to get
// each request's response, and verifying that response back into an Observation (via the
// same injected Bridge) before letting any dependent task proceed. The Bridge, the
// Executor, and the Clock are all struct fields the caller sets directly (never a hidden
// global, never a network call this type makes itself, never a bridge this type
// constructs on its own) so the whole orchestrator is testable in isolation.
type Orchestrator struct {
	Bridge   Bridge
	Executor Executor
	// Clock returns the wall clock in epoch milliseconds; react.DefaultClockMS if nil.
	Clock func() uint64
}

// New returns a ready Orchestrator wrapping bridge and executor.
func New(bridge Bridge, executor Executor) *Orchestrator {
	return &Orchestrator{Bridge: bridge, Executor: executor}
}

func (o *Orchestrator) clock() uint64 {
	if o.Clock != nil {
		return o.Clock()
	}
	return react.DefaultClockMS()
}

// Run executes tasks to completion. Returns a non-nil *Error (before any signing) if the
// plan itself is malformed (a cycle, a duplicate id, or an unknown prerequisite);
// otherwise NEVER returns an error -- every per-node failure is recorded as that node's
// own NodeResult{Status: "refused"/"blocked", ...} and execution continues over the rest
// of the plan (package docstring, "fail-closed by catching").
func (o *Orchestrator) Run(tasks []Task) (Run, error) {
	byID, order, err := validateAndOrder(tasks)
	if err != nil {
		return Run{}, err
	}

	startedAt := o.clock()
	results := make(map[string]NodeResult, len(byID))
	requestIDs := make(map[string][]byte, len(byID))

	for _, tid := range order {
		task := byID[tid]

		var unresolved []string
		for _, p := range task.Prereqs {
			if results[p].Status != "executed" {
				unresolved = append(unresolved, p)
			}
		}
		if len(unresolved) > 0 {
			// (task bar c/e): a node whose prerequisite refused, was itself blocked, or
			// never executed is NOT executed -- no request is ever built or signed for
			// it, and no Observation is ever fabricated.
			sort.Strings(unresolved)
			results[tid] = NodeResult{
				TaskID: tid, Status: "blocked",
				Detail: "blocked on unresolved prerequisite(s): " + strings.Join(unresolved, ", "),
			}
			continue
		}

		causes := make([][]byte, 0, len(task.Prereqs))
		for _, p := range task.Prereqs {
			causes = append(causes, requestIDs[p])
		}
		linkedAction := task.Action
		linkedAction.Causes = causes

		request, err := o.Bridge.ActionToRequest(linkedAction)
		if err != nil {
			// fail-closed: ANY sign/validate refusal degrades this node only.
			results[tid] = NodeResult{
				TaskID: tid, Status: "refused",
				Detail: fmt.Sprintf("request signing/validation refused: %v", err),
			}
			continue
		}
		requestIDs[tid] = request.ID

		responseBytes, err := o.Executor(task, request)
		if err != nil {
			// an executor failure refuses this node; it is never an Observation.
			results[tid] = NodeResult{
				TaskID: tid, Status: "refused", Request: &request,
				Detail: fmt.Sprintf("executor failed: %v", err),
			}
			continue
		}

		observation := o.Bridge.ResponseToObservation(responseBytes, request)
		if !observation.OK {
			results[tid] = NodeResult{
				TaskID: tid, Status: "refused", Request: &request, Observation: &observation,
				Detail: "response verification refused: " + observation.Error,
			}
			continue
		}

		results[tid] = NodeResult{TaskID: tid, Status: "executed", Request: &request, Observation: &observation}
	}

	finishedAt := o.clock()
	return Run{Order: order, Results: results, StartedAt: startedAt, FinishedAt: finishedAt}, nil
}

// validateAndOrder builds the id->Task map and computes a deterministic topological
// order, or returns a named *Error -- BEFORE any node is signed. This is the structural
// gate Run depends on: Run calls this before its execution loop ever touches
// Bridge.ActionToRequest, so a cyclic (or otherwise malformed) plan produces zero signed
// bytes.
func validateAndOrder(tasks []Task) (map[string]Task, []string, error) {
	byID := make(map[string]Task, len(tasks))
	for _, t := range tasks {
		if _, exists := byID[t.ID]; exists {
			return nil, nil, &Error{"DuplicateTaskId", fmt.Sprintf("task id %q appears more than once in the plan", t.ID)}
		}
		byID[t.ID] = t
	}

	for _, t := range byID {
		for _, p := range t.Prereqs {
			if _, ok := byID[p]; !ok {
				return nil, nil, &Error{"UnknownPrerequisite", fmt.Sprintf("task %q names unknown prerequisite %q", t.ID, p)}
			}
		}
	}

	order, err := topologicalOrder(byID)
	if err != nil {
		return nil, nil, err
	}
	return byID, order, nil
}

// topologicalOrder runs Kahn's algorithm over the Prereqs DAG, ties broken
// lexicographically by task id for a deterministic execution order. Returns
// *Error{"CyclicPlan", ...} naming every task id that could never be scheduled -- the
// definitive sign of a cycle (a self-loop included: a task naming itself as its own
// prerequisite can never reach indegree 0).
func topologicalOrder(byID map[string]Task) ([]string, error) {
	indegree := make(map[string]int, len(byID))
	dependents := make(map[string][]string, len(byID))
	for tid := range byID {
		indegree[tid] = 0
	}
	for tid, task := range byID {
		for _, p := range task.Prereqs {
			dependents[p] = append(dependents[p], tid)
			indegree[tid]++
		}
	}

	var ready []string
	for tid, deg := range indegree {
		if deg == 0 {
			ready = append(ready, tid)
		}
	}
	sort.Strings(ready)

	order := make([]string, 0, len(byID))
	for len(ready) > 0 {
		sort.Strings(ready)
		current := ready[0]
		ready = ready[1:]
		order = append(order, current)
		for _, dep := range dependents[current] {
			indegree[dep]--
			if indegree[dep] == 0 {
				ready = append(ready, dep)
			}
		}
	}

	if len(order) != len(byID) {
		seen := make(map[string]bool, len(order))
		for _, tid := range order {
			seen[tid] = true
		}
		var unresolved []string
		for tid := range byID {
			if !seen[tid] {
				unresolved = append(unresolved, tid)
			}
		}
		sort.Strings(unresolved)
		return nil, &Error{"CyclicPlan", "the plan's task DAG contains a cycle reachable from: " + strings.Join(unresolved, ", ")}
	}
	return order, nil
}
