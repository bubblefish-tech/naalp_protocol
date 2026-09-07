// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package react

import (
	"errors"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	testWorkflowChannel = 0x0011
	testTaskCreate      = 0
	testTaskResult      = 3
)

type party struct {
	sk *mldsa65.PrivateKey
	pk *mldsa65.PublicKey
	id string
}

func newParty(t *testing.T, seedByte byte) party {
	t.Helper()
	var seed [32]byte
	for i := range seed {
		seed[i] = seedByte
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	sid, err := identity.SignerID(cose.AlgMLDSA65, pk.Bytes())
	if err != nil {
		t.Fatalf("SignerID: %v", err)
	}
	return party{sk: sk, pk: pk, id: sid}
}

func newTestBridge(t *testing.T, agent, responder party) *Bridge {
	t.Helper()
	b, err := New(Bridge{
		Signer:            cose.MLDSA65Signer{SK: agent.sk},
		SignerID:          agent.id,
		Profile:           cose.ProfilePublic,
		Audience:          "svc:weather-tool",
		SelfIdentity:      agent.id,
		ResponderVerifier: cose.MLDSA65Verifier{PK: responder.pk},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func testAction() Action {
	return Action{
		Name:    "get_weather",
		Channel: testWorkflowChannel,
		Kind:    testTaskCreate,
		Effect:  policy.NonIdempotentWrite,
		Args:    cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("Tokyo")}},
	}
}

// signResponse builds and signs a real N-AALP TaskResult response object addressed back
// to selfIdentity, causally linked to requestID.
func signResponse(t *testing.T, responder party, selfIdentity string, requestID []byte) []byte {
	t.Helper()
	obj := &envelope.Object{
		Kind: testTaskResult, Channel: testWorkflowChannel, Signer: []byte(responder.id),
		Created: 1785000000000, Effect: uint64(policy.NonIdempotentWrite),
		Body:     cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("72F and sunny")}},
		Causes:   [][]byte{requestID},
		Profile:  cose.ProfilePublic,
		Audience: selfIdentity,
	}
	signed, err := envelope.Sign(obj, cose.MLDSA65Signer{SK: responder.sk})
	if err != nil {
		t.Fatalf("sign response: %v", err)
	}
	return signed
}

func TestActionToRequestThenResponseVerifies(t *testing.T) {
	agent := newParty(t, 0x51)
	responder := newParty(t, 0x52)
	b := newTestBridge(t, agent, responder)

	var sent [][]byte
	b.Transport = transportFunc(func(payload []byte) error {
		sent = append(sent, payload)
		return nil
	})

	request, err := b.ActionToRequest(testAction())
	if err != nil {
		t.Fatalf("ActionToRequest: %v", err)
	}
	if len(sent) != 1 || string(sent[0]) != string(request.Payload) {
		t.Fatalf("transport did not receive exactly the request payload")
	}

	responseBytes := signResponse(t, responder, agent.id, request.ID)
	obs := b.ResponseToObservation(responseBytes, request)
	if !obs.OK {
		t.Fatalf("expected OK observation, got error=%s detail=%s", obs.Error, obs.Detail)
	}
	if obs.Name != "TaskResult" {
		t.Fatalf("expected kind name TaskResult, got %q", obs.Name)
	}
	if obs.Error != "" {
		t.Fatalf("OK observation must carry no error, got %q", obs.Error)
	}
}

type transportFunc func(payload []byte) error

func (f transportFunc) Send(payload []byte) error { return f(payload) }

func TestValidatorRejectsCandidatePreSend(t *testing.T) {
	agent := newParty(t, 0x51)
	responder := newParty(t, 0x52)
	b := newTestBridge(t, agent, responder)

	rejectErr := errors.New("EffectDeclarationMismatch(effect)")
	b.Validator = func(candidate *envelope.Object) error { return rejectErr }

	_, err := b.ActionToRequest(testAction())
	if err == nil {
		t.Fatal("expected ActionToRequest to fail closed on validator refusal")
	}
	ve, ok := err.(*Error)
	if !ok || ve.Kind != "ValidationRefused" {
		t.Fatalf("expected *Error{Kind: ValidationRefused}, got %#v", err)
	}
}

func TestHITLRefusalNeverEmits(t *testing.T) {
	agent := newParty(t, 0x51)
	responder := newParty(t, 0x52)
	b := newTestBridge(t, agent, responder)

	executeCalled := false
	b.HITL = func(pending PendingAction) error {
		return errors.New("HITLError: operator declined")
	}
	// Wrap Execute to detect an accidental call (it must never be invoked on refusal).
	origHITL := b.HITL
	b.HITL = func(pending PendingAction) error {
		wrapped := pending
		wrapped.Execute = func() ([]byte, error) {
			executeCalled = true
			return pending.Execute()
		}
		return origHITL(wrapped)
	}

	_, err := b.ActionToRequest(testAction())
	if err == nil {
		t.Fatal("expected ActionToRequest to fail closed on HITL refusal")
	}
	if executeCalled {
		t.Fatal("HITL refusal must never call PendingAction.Execute (the effecting action must not be signed/emitted)")
	}
}

func TestHITLApprovalSignsAndEmits(t *testing.T) {
	agent := newParty(t, 0x51)
	responder := newParty(t, 0x52)
	b := newTestBridge(t, agent, responder)

	b.HITL = func(pending PendingAction) error {
		_, err := pending.Execute()
		return err
	}

	request, err := b.ActionToRequest(testAction())
	if err != nil {
		t.Fatalf("ActionToRequest: %v", err)
	}
	if len(request.Payload) == 0 || len(request.ID) == 0 {
		t.Fatal("expected a real signed request")
	}
}

func TestNotEmittedWhenHITLSwallowsWithoutExecuting(t *testing.T) {
	agent := newParty(t, 0x51)
	responder := newParty(t, 0x52)
	b := newTestBridge(t, agent, responder)

	// A non-conformant HITL hook: returns nil without ever calling Execute.
	b.HITL = func(pending PendingAction) error { return nil }

	_, err := b.ActionToRequest(testAction())
	if err == nil {
		t.Fatal("expected ActionToRequest to fail closed when HITL never emits")
	}
	ve, ok := err.(*Error)
	if !ok || ve.Kind != "NotEmitted" {
		t.Fatalf("expected *Error{Kind: NotEmitted}, got %#v", err)
	}
}

func TestResponseToObservationBadSignatureFailsClosed(t *testing.T) {
	agent := newParty(t, 0x51)
	responder := newParty(t, 0x52)
	b := newTestBridge(t, agent, responder)

	request, err := b.ActionToRequest(testAction())
	if err != nil {
		t.Fatalf("ActionToRequest: %v", err)
	}
	responseBytes := signResponse(t, responder, agent.id, request.ID)
	tampered := append([]byte(nil), responseBytes...)
	tampered[len(tampered)-1] ^= 0xFF

	obs := b.ResponseToObservation(tampered, request)
	if obs.OK || obs.Error != "BadSignature" || obs.Body != nil {
		t.Fatalf("expected fail-closed BadSignature with no body, got %#v", obs)
	}
}

func TestResponseToObservationWrongAudienceFailsClosed(t *testing.T) {
	agent := newParty(t, 0x51)
	responder := newParty(t, 0x52)
	b := newTestBridge(t, agent, responder)

	request, err := b.ActionToRequest(testAction())
	if err != nil {
		t.Fatalf("ActionToRequest: %v", err)
	}
	responseBytes := signResponse(t, responder, "svc:a-different-agent", request.ID)

	obs := b.ResponseToObservation(responseBytes, request)
	if obs.OK || obs.Error != "WrongAudience" || obs.Body != nil {
		t.Fatalf("expected fail-closed WrongAudience with no body, got %#v", obs)
	}
}

func TestResponseToObservationAbsentAudienceFailsClosed(t *testing.T) {
	agent := newParty(t, 0x51)
	responder := newParty(t, 0x52)
	b := newTestBridge(t, agent, responder)

	request, err := b.ActionToRequest(testAction())
	if err != nil {
		t.Fatalf("ActionToRequest: %v", err)
	}
	obj := &envelope.Object{
		Kind: testTaskResult, Channel: testWorkflowChannel, Signer: []byte(responder.id),
		Created: 1785000000000, Effect: uint64(policy.NonIdempotentWrite),
		Body:    cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("72F and sunny")}},
		Causes:  [][]byte{request.ID},
		Profile: cose.ProfilePublic, // Audience left absent
	}
	signed, err := envelope.Sign(obj, cose.MLDSA65Signer{SK: responder.sk})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	obs := b.ResponseToObservation(signed, request)
	if obs.OK || obs.Error != "WrongAudience" || obs.Body != nil {
		t.Fatalf("expected fail-closed WrongAudience (absent) with no body, got %#v", obs)
	}
}

func TestResponseToObservationMissingCausalLinkFailsClosed(t *testing.T) {
	agent := newParty(t, 0x51)
	responder := newParty(t, 0x52)
	b := newTestBridge(t, agent, responder)

	request, err := b.ActionToRequest(testAction())
	if err != nil {
		t.Fatalf("ActionToRequest: %v", err)
	}
	obj := &envelope.Object{
		Kind: testTaskResult, Channel: testWorkflowChannel, Signer: []byte(responder.id),
		Created: 1785000000000, Effect: uint64(policy.NonIdempotentWrite),
		Body:     cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("72F and sunny")}},
		Causes:   nil, // no causal edge at all
		Profile:  cose.ProfilePublic,
		Audience: agent.id,
	}
	signed, err := envelope.Sign(obj, cose.MLDSA65Signer{SK: responder.sk})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	obs := b.ResponseToObservation(signed, request)
	if obs.OK || obs.Error != "CausalViolation" || obs.Body != nil {
		t.Fatalf("expected fail-closed CausalViolation (missing) with no body, got %#v", obs)
	}
}

func TestResponseToObservationWrongCausalLinkFailsClosed(t *testing.T) {
	agent := newParty(t, 0x51)
	responder := newParty(t, 0x52)
	b := newTestBridge(t, agent, responder)

	request, err := b.ActionToRequest(testAction())
	if err != nil {
		t.Fatalf("ActionToRequest: %v", err)
	}
	unrelated := append([]byte(nil), request.ID...)
	unrelated[0] ^= 0xFF

	obj := &envelope.Object{
		Kind: testTaskResult, Channel: testWorkflowChannel, Signer: []byte(responder.id),
		Created: 1785000000000, Effect: uint64(policy.NonIdempotentWrite),
		Body:     cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("72F and sunny")}},
		Causes:   [][]byte{unrelated},
		Profile:  cose.ProfilePublic,
		Audience: agent.id,
	}
	signed, err := envelope.Sign(obj, cose.MLDSA65Signer{SK: responder.sk})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	obs := b.ResponseToObservation(signed, request)
	if obs.OK || obs.Error != "CausalViolation" || obs.Body != nil {
		t.Fatalf("expected fail-closed CausalViolation (wrong) with no body, got %#v", obs)
	}
}

func TestNewRejectsEmptyIdentityFields(t *testing.T) {
	agent := newParty(t, 0x51)
	if _, err := New(Bridge{
		Signer: cose.MLDSA65Signer{SK: agent.sk}, SignerID: agent.id,
		Profile: cose.ProfilePublic, Audience: "", SelfIdentity: agent.id,
	}); err == nil {
		t.Fatal("expected New to reject an empty Audience")
	}
	if _, err := New(Bridge{
		Signer: cose.MLDSA65Signer{SK: agent.sk}, SignerID: agent.id,
		Profile: cose.ProfilePublic, Audience: "svc:x", SelfIdentity: "",
	}); err == nil {
		t.Fatal("expected New to reject an empty SelfIdentity")
	}
}
