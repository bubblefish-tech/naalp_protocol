// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// The N-AALP sequential multi-agent pipeline (ecosystem task E1.4, requirement R2.4 --
// mirroring the shipped Python ecosystem task E1.3/R2.3's sequential shape): "agent A's
// signed output feeds agent B feeds C" -- a chain of DISTINCT agents (each with its own
// signing identity), where each stage's signed request causally links (Causes) to the
// PRIOR stage's signed request content id, and a stage refusal fails the pipeline closed:
// no downstream stage is ever built, signed, or run.
//
//	[Stage(agent A), Stage(agent B), Stage(agent C)] -> Pipeline.Run() -> a PipelineRun:
//	    one StageResult per stage, in pipeline order.
//
// This is the genuinely MULTI-agent counterpart to the sibling plan.Orchestrator (E1.4's
// own DAG shape): Orchestrator schedules a DAG of tasks under ONE bridge (one signing
// identity orchestrating several tool/sub-agent calls); a Pipeline composes SEVERAL
// independent bridges (several signing identities -- "agent A", "agent B", "agent C")
// into a straight hand-off chain.
//
// Design choice -- calls react.Bridge's ActionToRequest/ResponseToObservation DIRECTLY,
// rather than routing through the sibling plan.Orchestrator: Orchestrator.Run
// UNCONDITIONALLY recomputes each task's causal edges from that same run's own
// task.Prereqs -- it has no way to accept an EXTERNALLY-supplied predecessor content id
// from a prior, independently-run stage under a DIFFERENT bridge, because its
// requestIDs map is private state scoped to a single Run call under a single bridge. A
// cross-agent chain's whole point is that stage B's predecessor content id comes from a
// PRIOR react.Bridge instance's own signed output, not from a prerequisite task inside
// THIS stage's own (single-task) DAG -- so wrapping each stage in its own single-task
// Orchestrator and pre-setting Causes on the task's Action does NOT work: Orchestrator
// silently overwrites it with nil (no prereqs in a lone task) before ever calling the
// bridge. This file therefore reuses the underlying primitive plan.Orchestrator itself
// reuses -- the react.Bridge -- directly, at the SAME layer as the plan package, not on
// top of it; the per-stage build/sign/execute/verify/degrade control flow below
// intentionally mirrors plan.Orchestrator.Run's own per-node shape (same three failure
// points, same fail-closed-by-catching discipline), because that shape is this task's
// own scheduling glue, not a cryptographic primitive that would be wrong to write twice.
//
// Design choice -- BuildAction is a caller func(*react.Observation) (react.Action,
// error), never a value this file inspects/transforms itself: the prior stage's verified
// Observation body is caller-defined data (an impl/go/cbor value), and turning it into
// the NEXT agent's own Action (its kind/channel/effect/args) is a domain decision this
// file does not make (package docstring's "buy-before-make": no second
// body-parsing/transform layer here, exactly the sibling react package's "this package
// defines no value-coercion rules of its own"). BuildAction(nil) is called for the
// pipeline's first stage (no prior Observation exists). Its returned error is treated
// exactly like a failed ActionToRequest call -- one more fail-closed pre-sign refusal
// point, since Go has no exception to catch around an inline value-build the way the
// Python reference's single try/except does.
//
// Design choice -- injected Bridge/Executor per stage (never a hard construction of
// either): each Stage.Bridge is anything shaped like react.Bridge (its own
// clock/signing-key/audience/transport already set on IT), and each Stage.Executor is
// any func(Stage, react.Request) ([]byte, error) -- the same "send this signed request,
// get the raw response bytes back" shape plan.Executor and react.Bridge's own Transport
// use, so the whole pipeline is testable in isolation (this task's isolation-demo
// requirement) with recording spies wrapping real bridges.
package multiagent

import (
	"fmt"

	"github.com/bubblefish-tech/naalp_protocol/ecosystem/naalp-agent-go/react"
)

// Bridge is the interface Pipeline (and ParallelFanout) depend on -- exactly
// react.Bridge's own two public methods, so a real *react.Bridge plugs in with zero
// adaptation.
type Bridge interface {
	ActionToRequest(action react.Action) (react.Request, error)
	ResponseToObservation(responseBytes []byte, request react.Request) react.Observation
}

// StageExecutor sends stage's signed request and returns the raw response bytes.
type StageExecutor func(stage Stage, request react.Request) ([]byte, error)

// StageBuildAction builds THIS stage's own Action from the prior stage's Observation
// (nil for the pipeline's first stage). Its returned Action's own Causes field is
// IGNORED and overwritten by the pipeline with the prior stage's real signed request
// content id, exactly as plan.Task.Action.Causes is documented to be ignored and
// overwritten by prerequisite wiring. A non-nil error refuses this stage before any
// request is built.
type StageBuildAction func(prevObservation *react.Observation) (react.Action, error)

// Stage is one stage in a sequential multi-agent pipeline. AgentID is a caller-chosen
// label for which agent runs this stage (used only for reporting; it never reaches the
// wire). Bridge is THAT agent's own injected react.Bridge-shaped object (its own signing
// identity/keys/audience); a different stage normally injects a DIFFERENT bridge, which
// is what makes this a multi-agent chain rather than a single orchestrated plan.
// Executor sends this stage's signed request and returns the raw response bytes.
// BuildAction builds this stage's own Action from the prior stage's Observation.
type Stage struct {
	AgentID     string
	Bridge      Bridge
	Executor    StageExecutor
	BuildAction StageBuildAction
}

// StageResult is the outcome of one pipeline stage after Pipeline.Run(). Status is
// exactly one of: "executed" (this stage's request was signed, its executor ran, and the
// response verified OK), "refused" (this stage's OWN action could not be built, its
// request could not be signed/validated, its executor call failed, or its response
// failed verification), or "blocked" (an earlier stage in the pipeline did not reach
// "executed", so this stage's Action was never even built and its bridge/executor were
// never touched).
type StageResult struct {
	AgentID     string
	Status      string
	Request     *react.Request
	Observation *react.Observation
	Detail      string
}

// PipelineRun is the complete result of running a Pipeline: one StageResult per stage,
// in pipeline (chain) order, always present regardless of outcome.
type PipelineRun struct {
	Results []StageResult
}

// Executed returns the agent ids whose stage reached Status == "executed", in pipeline
// order.
func (r PipelineRun) Executed() []string {
	out := make([]string, 0, len(r.Results))
	for _, res := range r.Results {
		if res.Status == "executed" {
			out = append(out, res.AgentID)
		}
	}
	return out
}

// ResultFor returns the StageResult for agentID (ok=false if no such stage ran).
func (r PipelineRun) ResultFor(agentID string) (StageResult, bool) {
	for _, res := range r.Results {
		if res.AgentID == agentID {
			return res, true
		}
	}
	return StageResult{}, false
}

// Pipeline runs Stages in chain order, each stage's signed request causally linked to
// the PRIOR stage's signed request content id (nil Causes for the first stage).
// Fail-closed by PROPAGATING the chain, not by requiring callers to pre-filter: the
// moment a stage does not reach "executed", every remaining stage is recorded "blocked"
// and NONE of them ever reaches its own bridge or executor (verified by red-evidence
// against a spy on the downstream stage's bridge/executor).
type Pipeline struct {
	Stages []Stage
}

// NewSequentialPipeline returns a ready Pipeline over stages, run in the given order.
func NewSequentialPipeline(stages []Stage) *Pipeline {
	return &Pipeline{Stages: stages}
}

// Run executes the pipeline to completion. NEVER returns an error: every failure is
// recorded per-stage in the returned PipelineRun.
func (p *Pipeline) Run() PipelineRun {
	results := make([]StageResult, 0, len(p.Stages))
	var prevObservation *react.Observation
	var prevRequestID []byte
	chainBroken := false

	for _, stage := range p.Stages {
		if chainBroken {
			results = append(results, StageResult{
				AgentID: stage.AgentID, Status: "blocked",
				Detail: "an earlier stage in the pipeline did not execute",
			})
			continue
		}

		result := runStage(stage, prevObservation, prevRequestID)
		results = append(results, result)
		if result.Status != "executed" {
			chainBroken = true
			continue
		}
		prevObservation = result.Observation
		prevRequestID = result.Request.ID
	}

	return PipelineRun{Results: results}
}

// runStage runs ONE stage's build -> sign -> execute -> verify sequence. Never panics for
// a per-stage failure -- every failure point is checked at its own call site (mirrors
// plan.Orchestrator.Run's per-node shape).
func runStage(stage Stage, prevObservation *react.Observation, prevRequestID []byte) StageResult {
	action, err := stage.BuildAction(prevObservation)
	if err != nil {
		return StageResult{
			AgentID: stage.AgentID, Status: "refused",
			Detail: fmt.Sprintf("action build or request signing/validation refused: %v", err),
		}
	}
	if prevRequestID != nil {
		action.Causes = [][]byte{prevRequestID}
	} else {
		action.Causes = nil
	}

	request, err := stage.Bridge.ActionToRequest(action)
	if err != nil {
		// fail-closed: ANY build/sign/validate refusal degrades this stage only.
		return StageResult{
			AgentID: stage.AgentID, Status: "refused",
			Detail: fmt.Sprintf("action build or request signing/validation refused: %v", err),
		}
	}

	responseBytes, err := stage.Executor(stage, request)
	if err != nil {
		// an executor failure refuses this stage; never an Observation.
		return StageResult{
			AgentID: stage.AgentID, Status: "refused", Request: &request,
			Detail: fmt.Sprintf("executor failed: %v", err),
		}
	}

	observation := stage.Bridge.ResponseToObservation(responseBytes, request)
	if !observation.OK {
		return StageResult{
			AgentID: stage.AgentID, Status: "refused", Request: &request, Observation: &observation,
			Detail: "response verification refused: " + observation.Error,
		}
	}

	return StageResult{AgentID: stage.AgentID, Status: "executed", Request: &request, Observation: &observation}
}
