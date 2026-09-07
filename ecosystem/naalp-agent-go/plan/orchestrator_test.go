// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package plan

import (
	"errors"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/ecosystem/naalp-agent-go/react"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	workflowChannel = 0x0011
	taskCreate      = 0
	taskResult      = 3
)

// fakeBridge is a recording, in-process stand-in for react.Bridge that satisfies the
// plan.Bridge interface without touching any real crypto: it signs nothing and simply
// records what it was asked to do, so PlanOrchestrator's own scheduling/fail-closed
// logic can be exercised in total isolation from the react package (per the task's
// "testable in isolation" design goal). A response is "verified" by table lookup: the
// test controls exactly which request ids succeed/fail/return which error.
type fakeBridge struct {
	nextID     int
	byResponse map[string]react.Observation // responseBytes (as string) -> canned Observation
	refuseSign map[string]error             // action.Name -> forced ActionToRequest error
	requests   []react.Action               // every action actually passed to ActionToRequest
}

func newFakeBridge() *fakeBridge {
	return &fakeBridge{byResponse: map[string]react.Observation{}, refuseSign: map[string]error{}}
}

func (f *fakeBridge) ActionToRequest(action react.Action) (react.Request, error) {
	f.requests = append(f.requests, action)
	if err, ok := f.refuseSign[action.Name]; ok {
		return react.Request{}, err
	}
	f.nextID++
	id := []byte{byte(f.nextID)}
	return react.Request{Payload: []byte("payload-" + action.Name), ID: id}, nil
}

func (f *fakeBridge) ResponseToObservation(responseBytes []byte, request react.Request) react.Observation {
	if obs, ok := f.byResponse[string(responseBytes)]; ok {
		return obs
	}
	return react.Observation{OK: true, Name: "TaskResult"}
}

func executorEcho(task Task, request react.Request) ([]byte, error) {
	return []byte("resp-" + task.ID), nil
}

func TestRunHappyPathDAG(t *testing.T) {
	bridge := newFakeBridge()
	o := New(bridge, executorEcho)

	tasks := []Task{
		{ID: "root", Action: react.Action{Name: "root"}},
		{ID: "leaf-a", Action: react.Action{Name: "leaf-a"}, Prereqs: []string{"root"}},
		{ID: "leaf-b", Action: react.Action{Name: "leaf-b"}, Prereqs: []string{"root"}},
	}
	run, err := o.Run(tasks)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(run.Executed()) != 3 {
		t.Fatalf("expected 3 executed tasks, got %v", run.Executed())
	}
	if run.Order[0] != "root" {
		t.Fatalf("root must execute before its dependents, order=%v", run.Order)
	}
	// leaf-a and leaf-b must both causally link to root's real request id.
	rootID := run.RequestIDFor("root")
	for _, leaf := range []string{"leaf-a", "leaf-b"} {
		var found bool
		for _, a := range bridge.requests {
			if a.Name == leaf {
				found = true
				if len(a.Causes) != 1 || string(a.Causes[0]) != string(rootID) {
					t.Fatalf("%s: expected Causes=[root id], got %v", leaf, a.Causes)
				}
			}
		}
		if !found {
			t.Fatalf("%s never reached ActionToRequest", leaf)
		}
	}
}

func TestRunRefusedPrerequisiteBlocksDependent(t *testing.T) {
	bridge := newFakeBridge()
	bridge.refuseSign["root"] = errors.New("signing refused")
	o := New(bridge, executorEcho)

	tasks := []Task{
		{ID: "root", Action: react.Action{Name: "root"}},
		{ID: "child", Action: react.Action{Name: "child"}, Prereqs: []string{"root"}},
	}
	run, err := o.Run(tasks)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Results["root"].Status != "refused" {
		t.Fatalf("expected root refused, got %s", run.Results["root"].Status)
	}
	if run.Results["child"].Status != "blocked" {
		t.Fatalf("expected child blocked, got %s", run.Results["child"].Status)
	}
	if run.Results["child"].Request != nil {
		t.Fatal("a blocked task must never have a Request (D3: never fabricate progress)")
	}
	for _, a := range bridge.requests {
		if a.Name == "child" {
			t.Fatal("child's Action must never reach ActionToRequest once its prerequisite refused")
		}
	}
}

func TestRunCyclicPlanRejectedBeforeAnySigning(t *testing.T) {
	bridge := newFakeBridge()
	o := New(bridge, executorEcho)

	tasks := []Task{
		{ID: "a", Action: react.Action{Name: "a"}, Prereqs: []string{"b"}},
		{ID: "b", Action: react.Action{Name: "b"}, Prereqs: []string{"a"}},
	}
	_, err := o.Run(tasks)
	if err == nil {
		t.Fatal("expected a CyclicPlan error")
	}
	pe, ok := err.(*Error)
	if !ok || pe.Kind != "CyclicPlan" {
		t.Fatalf("expected *Error{Kind: CyclicPlan}, got %#v", err)
	}
	if len(bridge.requests) != 0 {
		t.Fatalf("a cyclic plan must produce ZERO signed bytes: %d actions reached ActionToRequest", len(bridge.requests))
	}
}

func TestRunDuplicateTaskIDRejected(t *testing.T) {
	bridge := newFakeBridge()
	o := New(bridge, executorEcho)
	tasks := []Task{
		{ID: "x", Action: react.Action{Name: "x1"}},
		{ID: "x", Action: react.Action{Name: "x2"}},
	}
	_, err := o.Run(tasks)
	pe, ok := err.(*Error)
	if !ok || pe.Kind != "DuplicateTaskId" {
		t.Fatalf("expected *Error{Kind: DuplicateTaskId}, got %#v", err)
	}
}

func TestRunUnknownPrerequisiteRejected(t *testing.T) {
	bridge := newFakeBridge()
	o := New(bridge, executorEcho)
	tasks := []Task{
		{ID: "a", Action: react.Action{Name: "a"}, Prereqs: []string{"ghost"}},
	}
	_, err := o.Run(tasks)
	pe, ok := err.(*Error)
	if !ok || pe.Kind != "UnknownPrerequisite" {
		t.Fatalf("expected *Error{Kind: UnknownPrerequisite}, got %#v", err)
	}
}

func TestRunResponseVerificationRefusalDoesNotFabricateObservation(t *testing.T) {
	bridge := newFakeBridge()
	bridge.byResponse["resp-root"] = react.Observation{OK: false, Error: "WrongAudience"}
	o := New(bridge, executorEcho)

	tasks := []Task{{ID: "root", Action: react.Action{Name: "root"}}}
	run, err := o.Run(tasks)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	res := run.Results["root"]
	if res.Status != "refused" {
		t.Fatalf("expected refused, got %s", res.Status)
	}
	if res.Observation == nil || res.Observation.OK {
		t.Fatal("expected a recorded, non-OK Observation on a refused response")
	}
}

// --- integration test: a real react.Bridge end to end through PlanOrchestrator ------------

func TestRunEndToEndWithRealBridge(t *testing.T) {
	var agentSeed, respSeed [32]byte
	for i := range agentSeed {
		agentSeed[i] = 0x61
		respSeed[i] = 0x62
	}
	agentPK, agentSK := mldsa65.NewKeyFromSeed(&agentSeed)
	respPK, respSK := mldsa65.NewKeyFromSeed(&respSeed)
	agentID, err := identity.SignerID(cose.AlgMLDSA65, agentPK.Bytes())
	if err != nil {
		t.Fatalf("SignerID: %v", err)
	}
	respID, err := identity.SignerID(cose.AlgMLDSA65, respPK.Bytes())
	if err != nil {
		t.Fatalf("SignerID: %v", err)
	}

	bridge, err := react.New(react.Bridge{
		Signer: cose.MLDSA65Signer{SK: agentSK}, SignerID: agentID,
		Profile: cose.ProfilePublic, Audience: "svc:tool", SelfIdentity: agentID,
		ResponderVerifier: cose.MLDSA65Verifier{PK: respPK},
	})
	if err != nil {
		t.Fatalf("react.New: %v", err)
	}

	executor := func(task Task, request react.Request) ([]byte, error) {
		obj := &envelope.Object{
			Kind: taskResult, Channel: workflowChannel, Signer: []byte(respID),
			Created: 1785000000000, Effect: uint64(policy.NonIdempotentWrite),
			Body:   cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("ok:" + task.ID)}},
			Causes: [][]byte{request.ID}, Profile: cose.ProfilePublic, Audience: agentID,
		}
		return envelope.Sign(obj, cose.MLDSA65Signer{SK: respSK})
	}

	o := New(bridge, executor)
	tasks := []Task{
		{ID: "one", Action: react.Action{
			Name: "one", Channel: workflowChannel, Kind: taskCreate,
			Effect: policy.NonIdempotentWrite, Args: cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("go")}},
		}},
	}
	run, err := o.Run(tasks)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Results["one"].Status != "executed" {
		t.Fatalf("expected executed, got %s (%s)", run.Results["one"].Status, run.Results["one"].Detail)
	}
	if run.StartedAt == 0 || run.FinishedAt == 0 {
		t.Fatal("expected non-zero StartedAt/FinishedAt from the real clock")
	}
}
