// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package multiagent

import (
	"errors"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/ecosystem/naalp-agent-go/react"
)

// recordingBridge is an in-process stand-in satisfying the Bridge interface, so
// Pipeline/Fanout's own scheduling/fail-closed logic is exercised in isolation from any
// real crypto (the package's own isolation-demo requirement). touched proves (or
// disproves) that a downstream stage's bridge was ever invoked -- the property
// "blocked" stages must never satisfy.
type recordingBridge struct {
	name       string
	touched    *bool
	refuseSign bool
	respObs    react.Observation // canned ResponseToObservation outcome
	nextID     byte
}

func (b *recordingBridge) ActionToRequest(action react.Action) (react.Request, error) {
	if b.touched != nil {
		*b.touched = true
	}
	if b.refuseSign {
		return react.Request{}, errors.New("signing refused")
	}
	b.nextID++
	return react.Request{Payload: []byte("payload-" + b.name), ID: []byte{b.nextID}}, nil
}

func (b *recordingBridge) ResponseToObservation(responseBytes []byte, request react.Request) react.Observation {
	if b.touched != nil {
		*b.touched = true
	}
	return b.respObs
}

func okAction(name string) StageBuildAction {
	return func(prev *react.Observation) (react.Action, error) {
		return react.Action{Name: name}, nil
	}
}

func echoExecutor(stage Stage, request react.Request) ([]byte, error) {
	return []byte("resp-" + stage.AgentID), nil
}

func TestPipelineHappyPathCausallyLinksEachStage(t *testing.T) {
	var touchedB, touchedC bool
	bridgeA := &recordingBridge{name: "A", respObs: react.Observation{OK: true, Name: "Result"}}
	bridgeB := &recordingBridge{name: "B", touched: &touchedB, respObs: react.Observation{OK: true, Name: "Result"}}
	bridgeC := &recordingBridge{name: "C", touched: &touchedC, respObs: react.Observation{OK: true, Name: "Result"}}

	var capturedCausesB, capturedCausesC [][]byte
	stages := []Stage{
		{AgentID: "A", Bridge: bridgeA, Executor: echoExecutor, BuildAction: okAction("a")},
		{AgentID: "B", Bridge: bridgeB, Executor: echoExecutor, BuildAction: func(prev *react.Observation) (react.Action, error) {
			return react.Action{Name: "b"}, nil
		}},
		{AgentID: "C", Bridge: bridgeC, Executor: echoExecutor, BuildAction: func(prev *react.Observation) (react.Action, error) {
			return react.Action{Name: "c"}, nil
		}},
	}
	// wrap bridges to capture the causally-linked action they actually received
	stages[1].Bridge = captureCausesBridge{recordingBridge: bridgeB, out: &capturedCausesB}
	stages[2].Bridge = captureCausesBridge{recordingBridge: bridgeC, out: &capturedCausesC}

	p := NewSequentialPipeline(stages)
	run := p.Run()

	if got := run.Executed(); len(got) != 3 {
		t.Fatalf("expected 3 executed stages, got %v", got)
	}
	resA, _ := run.ResultFor("A")
	resB, _ := run.ResultFor("B")
	if len(capturedCausesB) != 1 || string(capturedCausesB[0]) != string(resA.Request.ID) {
		t.Fatalf("stage B must causally link to stage A's request id, got %v want %v", capturedCausesB, resA.Request.ID)
	}
	if len(capturedCausesC) != 1 || string(capturedCausesC[0]) != string(resB.Request.ID) {
		t.Fatalf("stage C must causally link to stage B's request id, got %v want %v", capturedCausesC, resB.Request.ID)
	}
}

type captureCausesBridge struct {
	*recordingBridge
	out *[][]byte
}

func (b captureCausesBridge) ActionToRequest(action react.Action) (react.Request, error) {
	*b.out = action.Causes
	return b.recordingBridge.ActionToRequest(action)
}

func TestPipelineRefusalBlocksDownstreamStagesWithoutTouchingThem(t *testing.T) {
	var touchedB bool
	bridgeA := &recordingBridge{name: "A", refuseSign: true}
	bridgeB := &recordingBridge{name: "B", touched: &touchedB}

	stages := []Stage{
		{AgentID: "A", Bridge: bridgeA, Executor: echoExecutor, BuildAction: okAction("a")},
		{AgentID: "B", Bridge: bridgeB, Executor: echoExecutor, BuildAction: okAction("b")},
	}
	p := NewSequentialPipeline(stages)
	run := p.Run()

	resA, _ := run.ResultFor("A")
	resB, _ := run.ResultFor("B")
	if resA.Status != "refused" {
		t.Fatalf("expected stage A refused, got %s", resA.Status)
	}
	if resB.Status != "blocked" {
		t.Fatalf("expected stage B blocked, got %s", resB.Status)
	}
	if touchedB {
		t.Fatal("a blocked stage must NEVER reach its own bridge (fail-closed-by-propagating)")
	}
}

func TestPipelineBuildActionErrorRefusesStage(t *testing.T) {
	bridgeA := &recordingBridge{name: "A"}
	stages := []Stage{
		{AgentID: "A", Bridge: bridgeA, Executor: echoExecutor, BuildAction: func(prev *react.Observation) (react.Action, error) {
			return react.Action{}, errors.New("cannot build action from nil observation")
		}},
	}
	run := NewSequentialPipeline(stages).Run()
	res, _ := run.ResultFor("A")
	if res.Status != "refused" {
		t.Fatalf("expected refused, got %s", res.Status)
	}
	if res.Request != nil {
		t.Fatal("a BuildAction refusal must occur before any request is signed")
	}
	_ = bridgeA
}

func TestPipelineExecutorFailureRefusesStage(t *testing.T) {
	bridgeA := &recordingBridge{name: "A", respObs: react.Observation{OK: true}}
	failingExecutor := func(stage Stage, request react.Request) ([]byte, error) {
		return nil, errors.New("transport unreachable")
	}
	stages := []Stage{
		{AgentID: "A", Bridge: bridgeA, Executor: failingExecutor, BuildAction: okAction("a")},
	}
	run := NewSequentialPipeline(stages).Run()
	res, _ := run.ResultFor("A")
	if res.Status != "refused" || res.Request == nil {
		t.Fatalf("expected refused with a signed request recorded, got %#v", res)
	}
}
