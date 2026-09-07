// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Isolation demonstration (A9) for the N-AALP Go multiagent package (E1.4/R2.4): a
// concrete SequentialPipeline (agent A -> agent B, two DISTINCT signing identities) and
// a concrete ParallelFanout (3 agents converging on one shared input via the real Part-1
// federated-ordering reconcile primitive), run standalone with no dependency beyond the
// multiagent + react packages + the Part-1 impl/go SDK.
//
// Three passes:
//
//	PASS 1 (sequential): agent A's signed output causally links agent B's request; B's
//	        response verifies as a real Observation.
//	PASS 2 (sequential, fail-closed): agent A's response fails verification (wrong
//	        audience) -- agent B is recorded "blocked" and its own bridge is NEVER
//	        touched.
//	PASS 3 (parallel): 3 agents fan out CONCURRENTLY on a shared input; one agent's
//	        response is deliberately malformed (tampered signature) and is EXCLUDED
//	        under its own named error, while the other two reconcile into one
//	        deterministic total order alongside the shared input.
//
// Run: go run ./examples/multiagent_demo   (from ecosystem/naalp-agent-go/)
package main

import (
	"fmt"
	"os"

	"github.com/bubblefish-tech/naalp_protocol/ecosystem/naalp-agent-go/multiagent"
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

type agentIdentity struct {
	bridge *react.Bridge
	sk     *mldsa65.PrivateKey
	sid    string
}

func newAgent(seedByte byte, audience string) agentIdentity {
	var seed [32]byte
	for i := range seed {
		seed[i] = seedByte
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	sid, err := identity.SignerID(cose.AlgMLDSA65, pk.Bytes())
	must(err)
	// Each agent verifies incoming responses against ITS OWN key here (a real deployment
	// would use the actual counterparty's key; this demo has each agent counter-sign its
	// own "responses" to keep the isolation demo self-contained, matching the react
	// package's own isolation_demo pattern of a fixed agent+responder pair per bridge).
	b, err := react.New(react.Bridge{
		Signer: cose.MLDSA65Signer{SK: sk}, SignerID: sid,
		Profile: cose.ProfilePublic, Audience: audience, SelfIdentity: sid,
		ResponderVerifier: cose.MLDSA65Verifier{PK: pk},
	})
	must(err)
	return agentIdentity{bridge: b, sk: sk, sid: sid}
}

func signResultFor(a agentIdentity, taskLabel string, causes [][]byte) []byte {
	obj := &envelope.Object{
		Kind: taskResult, Channel: workflowChannel, Signer: []byte(a.sid),
		Created: 1785000000000, Effect: uint64(policy.NonIdempotentWrite),
		Body:   cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr(taskLabel)}},
		Causes: causes, Profile: cose.ProfilePublic, Audience: a.sid,
	}
	signed, err := envelope.Sign(obj, cose.MLDSA65Signer{SK: a.sk})
	must(err)
	return signed
}

func main() {
	fmt.Println(repeat("=", 72))
	fmt.Println("PASS 1 (sequential): agent A -> agent B, causally linked, both execute")
	fmt.Println(repeat("=", 72))

	agentA := newAgent(0x11, "svc:pipeline")
	agentB := newAgent(0x12, "svc:pipeline")

	stages := []multiagent.Stage{
		{
			AgentID: "agent-A", Bridge: agentA.bridge,
			BuildAction: func(prev *react.Observation) (react.Action, error) {
				return react.Action{
					Name: "a", Channel: workflowChannel, Kind: taskCreate,
					Effect: policy.NonIdempotentWrite, Args: cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("start")}},
				}, nil
			},
			Executor: func(stage multiagent.Stage, request react.Request) ([]byte, error) {
				return signResultFor(agentA, "A-done", [][]byte{request.ID}), nil
			},
		},
		{
			AgentID: "agent-B", Bridge: agentB.bridge,
			BuildAction: func(prev *react.Observation) (react.Action, error) {
				return react.Action{
					Name: "b", Channel: workflowChannel, Kind: taskCreate,
					Effect: policy.NonIdempotentWrite, Args: cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("continue")}},
				}, nil
			},
			Executor: func(stage multiagent.Stage, request react.Request) ([]byte, error) {
				return signResultFor(agentB, "B-done", [][]byte{request.ID}), nil
			},
		},
	}
	run1 := multiagent.NewSequentialPipeline(stages).Run()
	fmt.Printf("executed: %v\n", run1.Executed())
	assert(len(run1.Executed()) == 2, "both stages must execute")

	fmt.Println()
	fmt.Println(repeat("=", 72))
	fmt.Println("PASS 2 (sequential, fail-closed): agent A's response fails -- B never runs")
	fmt.Println(repeat("=", 72))

	touchedB := false
	badStages := []multiagent.Stage{
		{
			AgentID: "agent-A", Bridge: agentA.bridge,
			BuildAction: stages[0].BuildAction,
			Executor: func(stage multiagent.Stage, request react.Request) ([]byte, error) {
				// Sign under a DIFFERENT audience so A's own response verification fails.
				obj := &envelope.Object{
					Kind: taskResult, Channel: workflowChannel, Signer: []byte(agentA.sid),
					Created: 1785000000000, Effect: uint64(policy.NonIdempotentWrite),
					Body:   cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("A-done")}},
					Causes: [][]byte{request.ID}, Profile: cose.ProfilePublic, Audience: "svc:someone-else",
				}
				return envelope.Sign(obj, cose.MLDSA65Signer{SK: agentA.sk})
			},
		},
		{
			AgentID: "agent-B", Bridge: agentB.bridge,
			BuildAction: stages[1].BuildAction,
			Executor: func(stage multiagent.Stage, request react.Request) ([]byte, error) {
				touchedB = true
				return signResultFor(agentB, "B-done", [][]byte{request.ID}), nil
			},
		},
	}
	run2 := multiagent.NewSequentialPipeline(badStages).Run()
	resA, _ := run2.ResultFor("agent-A")
	resB, _ := run2.ResultFor("agent-B")
	fmt.Printf("agent-A: %s (%s)\n", resA.Status, resA.Detail)
	fmt.Printf("agent-B: %s\n", resB.Status)
	assert(resA.Status == "refused", "agent-A must be refused (WrongAudience)")
	assert(resB.Status == "blocked", "agent-B must be blocked")
	assert(!touchedB, "a blocked stage must never reach its own bridge/executor")

	fmt.Println()
	fmt.Println(repeat("=", 72))
	fmt.Println("PASS 3 (parallel): 3 agents fan out concurrently; one is excluded, malformed")
	fmt.Println(repeat("=", 72))

	sharedInputID := []byte{0xC0, 0xFF, 0xEE}
	fanAgents := []agentIdentity{newAgent(0x21, "svc:fanout"), newAgent(0x22, "svc:fanout"), newAgent(0x23, "svc:fanout")}
	branchBuild := func(sharedInputID []byte) (react.Action, error) {
		return react.Action{
			Name: "branch", Channel: workflowChannel, Kind: taskCreate,
			Effect: policy.NonIdempotentWrite, Args: cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("go")}},
		}, nil
	}
	branches := make([]multiagent.Branch, 0, 3)
	for i, a := range fanAgents {
		agent := a
		idx := i
		branches = append(branches, multiagent.Branch{
			AgentID:     fmt.Sprintf("agent-%d", idx),
			Bridge:      agent.bridge,
			BuildAction: branchBuild,
			Executor: func(branch multiagent.Branch, request react.Request) ([]byte, error) {
				signed := signResultFor(agent, fmt.Sprintf("branch-%d-done", idx), [][]byte{request.ID})
				if idx == 2 {
					// deliberately corrupt agent-2's response signature
					signed[len(signed)-1] ^= 0xFF
				}
				return signed, nil
			},
		})
	}
	fanout, err := multiagent.NewParallelFanout(branches)
	must(err)
	run3, err := fanout.Run(sharedInputID)
	must(err)
	for _, id := range []string{"agent-0", "agent-1", "agent-2"} {
		res := run3.BranchResults[id]
		fmt.Printf("%s: %s error=%q\n", id, res.Status, res.Error)
	}
	assert(run3.BranchResults["agent-0"].Status == "executed", "agent-0 must execute")
	assert(run3.BranchResults["agent-1"].Status == "executed", "agent-1 must execute")
	assert(run3.BranchResults["agent-2"].Status == "excluded", "agent-2 must be excluded (tampered signature)")
	assert(run3.BranchResults["agent-2"].Error == "BadSignature", "agent-2's exclusion reason must be BadSignature")
	assert(len(run3.ReconciledOrder) == 3, "reconciled order = shared input + 2 executed branches")
	fmt.Printf("reconciled order length: %d (shared input + 2 executed branches)\n", len(run3.ReconciledOrder))

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
