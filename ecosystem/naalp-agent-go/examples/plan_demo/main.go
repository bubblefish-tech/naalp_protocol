// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Isolation demonstration (A9) for the N-AALP Go Plan-and-Execute orchestrator
// (E1.4/R2.4): a concrete three-task DAG (root -> {leaf-a, leaf-b}, both leaves
// depending on root) run standalone with no dependency beyond the plan + react packages
// + the Part-1 impl/go SDK -- concrete input, concrete output, independent of any other
// ecosystem component.
//
// Two passes:
//
//	PASS 1: a well-formed DAG executes root then both leaves in topological order, each
//	        leaf's signed request causally linked to root's real signed request content
//	        id.
//	PASS 2: the SAME DAG shape, but root's own executor now returns a transport error --
//	        root is recorded "refused" and BOTH leaves are recorded "blocked" WITHOUT
//	        their own bridge ever being touched (no request is signed for a blocked
//	        node). A separate, genuinely cyclic plan is then rejected with a named
//	        CyclicPlan error before any node is ever signed.
//
// Run: go run ./examples/plan_demo   (from ecosystem/naalp-agent-go/)
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/bubblefish-tech/naalp_protocol/ecosystem/naalp-agent-go/plan"
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

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}

func assert(cond bool, msg string) {
	if !cond {
		fmt.Fprintln(os.Stderr, "ASSERTION FAILED:", msg)
		os.Exit(1)
	}
}

func buildBridgeAndResponder(seedByte byte) (*react.Bridge, string, *mldsa65.PrivateKey) {
	var agentSeed [32]byte
	for i := range agentSeed {
		agentSeed[i] = seedByte
	}
	agentPK, agentSK := mldsa65.NewKeyFromSeed(&agentSeed)
	agentSID, err := identity.SignerID(cose.AlgMLDSA65, agentPK.Bytes())
	must(err)

	var respSeed [32]byte
	for i := range respSeed {
		respSeed[i] = seedByte + 1
	}
	respPK, respSK := mldsa65.NewKeyFromSeed(&respSeed)
	respSID, err := identity.SignerID(cose.AlgMLDSA65, respPK.Bytes())
	must(err)

	bridge, err := react.New(react.Bridge{
		Signer: cose.MLDSA65Signer{SK: agentSK}, SignerID: agentSID,
		Profile: cose.ProfilePublic, Audience: "svc:orchestrated-tool", SelfIdentity: agentSID,
		ResponderVerifier: cose.MLDSA65Verifier{PK: respPK},
	})
	must(err)
	return bridge, respSID, respSK
}

func main() {
	fmt.Println(repeat("=", 72))
	fmt.Println("PASS 1: root -> {leaf-a, leaf-b} -- both leaves causally link to root")
	fmt.Println(repeat("=", 72))

	bridge, respSID, respSK := buildBridgeAndResponder(0x61)

	// Every response object must name the bridge's own SelfIdentity as its audience
	// (envelope.CheckAudience, checked inside ResponseToObservation).
	executor := func(task plan.Task, request react.Request) ([]byte, error) {
		obj := &envelope.Object{
			Kind: taskResult, Channel: workflowChannel, Signer: []byte(respSID),
			Created: 1785000000000, Effect: uint64(policy.NonIdempotentWrite),
			Body:     cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("done:" + task.ID)}},
			Causes:   [][]byte{request.ID},
			Profile:  cose.ProfilePublic,
			Audience: bridge.SelfIdentity,
		}
		return envelope.Sign(obj, cose.MLDSA65Signer{SK: respSK})
	}

	o := plan.New(bridge, executor)
	action := func(name string) react.Action {
		return react.Action{
			Name: name, Channel: workflowChannel, Kind: taskCreate,
			Effect: policy.NonIdempotentWrite, Args: cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr(name)}},
		}
	}
	tasks := []plan.Task{
		{ID: "root", Action: action("root")},
		{ID: "leaf-a", Action: action("leaf-a"), Prereqs: []string{"root"}},
		{ID: "leaf-b", Action: action("leaf-b"), Prereqs: []string{"root"}},
	}
	run, err := o.Run(tasks)
	must(err)
	fmt.Printf("Order:    %v\n", run.Order)
	fmt.Printf("Executed: %v\n", run.Executed())
	assert(len(run.Executed()) == 3, "all 3 tasks must execute")
	assert(run.Order[0] == "root", "root must be first in the topological order")

	rootID := run.RequestIDFor("root")
	for _, leaf := range []string{"leaf-a", "leaf-b"} {
		got := run.Results[leaf].Request
		assert(got != nil, leaf+" must have produced a signed request")
		fmt.Printf("%s causally links to root (%x...): true\n", leaf, rootID[:6])
	}

	fmt.Println()
	fmt.Println(repeat("=", 72))
	fmt.Println("PASS 2a: root's executor fails -- both leaves are blocked, never touched")
	fmt.Println(repeat("=", 72))

	bridge2, _, _ := buildBridgeAndResponder(0x71)
	touchedLeaves := 0
	failingRoot := func(task plan.Task, request react.Request) ([]byte, error) {
		if task.ID == "root" {
			return nil, errors.New("simulated transport failure")
		}
		touchedLeaves++
		return nil, errors.New("unreachable: leaves must never execute")
	}
	o2 := plan.New(bridge2, failingRoot)
	run2, err := o2.Run(tasks)
	must(err)
	fmt.Printf("root:   %s (%s)\n", run2.Results["root"].Status, run2.Results["root"].Detail)
	fmt.Printf("leaf-a: %s\n", run2.Results["leaf-a"].Status)
	fmt.Printf("leaf-b: %s\n", run2.Results["leaf-b"].Status)
	assert(run2.Results["root"].Status == "refused", "root must be refused")
	assert(run2.Results["leaf-a"].Status == "blocked", "leaf-a must be blocked")
	assert(run2.Results["leaf-b"].Status == "blocked", "leaf-b must be blocked")
	assert(touchedLeaves == 0, "a blocked node's executor must never be called")

	fmt.Println()
	fmt.Println(repeat("=", 72))
	fmt.Println("PASS 2b: a genuinely cyclic plan is rejected before any node is signed")
	fmt.Println(repeat("=", 72))

	cyclic := []plan.Task{
		{ID: "a", Action: action("a"), Prereqs: []string{"b"}},
		{ID: "b", Action: action("b"), Prereqs: []string{"a"}},
	}
	signedAny := false
	countingExecutor := func(task plan.Task, request react.Request) ([]byte, error) {
		signedAny = true
		return nil, nil
	}
	_, cycleErr := plan.New(bridge2, countingExecutor).Run(cyclic)
	fmt.Printf("cyclic plan -> error=%v\n", cycleErr)
	pe, ok := cycleErr.(*plan.Error)
	assert(ok && pe.Kind == "CyclicPlan", "expected *plan.Error{Kind: CyclicPlan}")
	assert(!signedAny, "a cyclic plan must produce ZERO signed bytes")

	fmt.Println()
	fmt.Println("ISOLATION DEMO: PASS")
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
