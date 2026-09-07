// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Isolation demonstration (A9) for the N-AALP Go ReAct bridge (E1.4/R2.4): a concrete
// Thought -> Action -> [sign+encode] -> (in-memory transport) -> [verify+causal-link] ->
// Observation round trip, run standalone with no dependency beyond the react package +
// the Part-1 impl/go SDK (no HITL hook, no validator, no N-PAMP transport) -- concrete
// input, concrete output, independent of any other ecosystem component.
//
// Two passes:
//
//	PASS 1: a well-formed Action becomes a signed request; a correctly-linked response
//	        becomes a real, typed Observation.
//	PASS 2: the same request, but three DISTINCT malformed responses -- a tampered
//	        signature, a wrong audience, and a missing causal link -- each verified and
//	        shown failing closed with the exact named error, never a crash and never a
//	        silently-accepted body.
//
// Run: go run ./examples/react_demo   (from ecosystem/naalp-agent-go/)
package main

import (
	"fmt"
	"os"

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

type memTransport struct{ sent [][]byte }

func (t *memTransport) Send(payload []byte) error {
	t.sent = append(t.sent, payload)
	return nil
}

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

func main() {
	// --- fixed identities (a real agent and a real tool-executor responder) ---
	var agentSeed, responderSeed [32]byte
	for i := range agentSeed {
		agentSeed[i] = 0x51
		responderSeed[i] = 0x52
	}
	agentPK, agentSK := mldsa65.NewKeyFromSeed(&agentSeed)
	agentSID, err := identity.SignerID(cose.AlgMLDSA65, agentPK.Bytes())
	must(err)

	responderPK, responderSK := mldsa65.NewKeyFromSeed(&responderSeed)
	responderSID, err := identity.SignerID(cose.AlgMLDSA65, responderPK.Bytes())
	must(err)

	transport := &memTransport{}
	bridge, err := react.New(react.Bridge{
		Signer:            cose.MLDSA65Signer{SK: agentSK},
		SignerID:          agentSID,
		Profile:           cose.ProfilePublic,
		Audience:          "svc:weather-tool",
		SelfIdentity:      agentSID,
		ResponderVerifier: cose.MLDSA65Verifier{PK: responderPK},
		Transport:         transport,
	})
	must(err)

	fmt.Println(repeat("=", 72))
	fmt.Println("PASS 1: Thought -> Action -> signed request -> Observation (the happy path)")
	fmt.Println(repeat("=", 72))

	action := react.Action{
		Name: "get_weather", Channel: workflowChannel, Kind: taskCreate,
		Effect:      policy.NonIdempotentWrite,
		Args:        cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("Tokyo")}},
		ArgsSummary: "get_weather(city='Tokyo')",
	}
	request, err := bridge.ActionToRequest(action)
	must(err)
	fmt.Printf("Action:  %s\n", action.ArgsSummary)
	fmt.Printf("Request: %d signed bytes, content id %x...\n", len(request.Payload), request.ID[:8])
	assert(len(transport.sent) == 1 && string(transport.sent[0]) == string(request.Payload), "transport must receive exactly the request payload")
	fmt.Println("Transport received exactly this request: true")

	// The (fake) tool-executor responds asynchronously: a REAL signed N-AALP object,
	// addressed back to the agent, citing the request's content id in Causes.
	responseObj := &envelope.Object{
		Kind: taskResult, Channel: workflowChannel, Signer: []byte(responderSID),
		Created: 1785000000000, Effect: uint64(policy.NonIdempotentWrite),
		Body:     cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("72F and sunny")}},
		Causes:   [][]byte{request.ID},
		Profile:  cose.ProfilePublic,
		Audience: agentSID,
	}
	responseBytes, err := envelope.Sign(responseObj, cose.MLDSA65Signer{SK: responderSK})
	must(err)

	observation := bridge.ResponseToObservation(responseBytes, request)
	fmt.Printf("Observation: ok=%v name=%q\n", observation.OK, observation.Name)
	assert(observation.OK, "observation must verify OK")
	assert(observation.Name == "TaskResult", "observation kind name must be TaskResult")
	assert(observation.Error == "", "an OK observation must carry no error")
	body, ok := observation.Body.(cbor.Map)
	assert(ok && len(body) == 1, "observation body must decode to the signed map")

	fmt.Println()
	fmt.Println(repeat("=", 72))
	fmt.Println("PASS 2: three distinct malformed responses to the SAME request, each refused")
	fmt.Println(repeat("=", 72))

	// 2a. Tampered signature.
	tampered := append([]byte(nil), responseBytes...)
	tampered[len(tampered)-1] ^= 0xFF
	obsBadSig := bridge.ResponseToObservation(tampered, request)
	fmt.Printf("2a. tampered signature -> ok=%v error=%s\n", obsBadSig.OK, obsBadSig.Error)
	assert(!obsBadSig.OK && obsBadSig.Error == "BadSignature" && obsBadSig.Body == nil, "tampered signature must fail closed as BadSignature with no body")

	// 2b. Wrong audience (addressed to a different agent).
	wrongAudienceObj := &envelope.Object{
		Kind: taskResult, Channel: workflowChannel, Signer: []byte(responderSID),
		Created: 1785000000000, Effect: uint64(policy.NonIdempotentWrite),
		Body:     cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("72F and sunny")}},
		Causes:   [][]byte{request.ID},
		Profile:  cose.ProfilePublic,
		Audience: "svc:a-different-agent",
	}
	wrongAudienceBytes, err := envelope.Sign(wrongAudienceObj, cose.MLDSA65Signer{SK: responderSK})
	must(err)
	obsWrongAud := bridge.ResponseToObservation(wrongAudienceBytes, request)
	fmt.Printf("2b. wrong audience     -> ok=%v error=%s\n", obsWrongAud.OK, obsWrongAud.Error)
	assert(!obsWrongAud.OK && obsWrongAud.Error == "WrongAudience" && obsWrongAud.Body == nil, "wrong audience must fail closed as WrongAudience with no body")

	// 2c. Missing causal linkage (a real, correctly-addressed, correctly-signed response
	// -- but it never cites THIS request's content id).
	unlinkedObj := &envelope.Object{
		Kind: taskResult, Channel: workflowChannel, Signer: []byte(responderSID),
		Created: 1785000000000, Effect: uint64(policy.NonIdempotentWrite),
		Body:     cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("72F and sunny")}},
		Causes:   nil,
		Profile:  cose.ProfilePublic,
		Audience: agentSID,
	}
	unlinkedBytes, err := envelope.Sign(unlinkedObj, cose.MLDSA65Signer{SK: responderSK})
	must(err)
	obsUnlinked := bridge.ResponseToObservation(unlinkedBytes, request)
	fmt.Printf("2c. missing causal link -> ok=%v error=%s\n", obsUnlinked.OK, obsUnlinked.Error)
	assert(!obsUnlinked.OK && obsUnlinked.Error == "CausalViolation" && obsUnlinked.Body == nil, "missing causal link must fail closed as CausalViolation with no body")

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
