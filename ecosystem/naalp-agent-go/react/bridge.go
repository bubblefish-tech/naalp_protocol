// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package react is the N-AALP ReAct bridge for Go agents (ecosystem task E1.4,
// requirement R2.4 -- the Go-half offering mirroring the shipped Python ecosystem task
// E1.1/R2.1). It maps an agent's Thought->Action->Observation loop into signed N-AALP
// objects:
//
//	Action  -> Bridge.ActionToRequest()      -> a real signed, encoded N-AALP request
//	response -> Bridge.ResponseToObservation() -> a verified, causally-linked Observation
//
// This package performs NO cryptography, NO CBOR encoding, and NO second content-id
// computation of its own: every byte-level and signature-level operation (canonical
// encoding, content-id binding, deterministic ML-DSA sign/verify, the audience
// point-of-use gate) is the real Part-1 reference implementation's own
// impl/go/envelope and impl/go/channels code, imported and called directly
// (design.md "Buy-before-make"; the ReAct bridge is N-AALP-specific glue -- the
// Thought/Action/Observation <-> signed-object translation -- not a second copy of the
// envelope/COSE primitive). Any raw CBOR value construction a caller performs for an
// Action's Args goes through the sibling impl/go/cbor value types directly -- Go, unlike
// the Python ecosystem, needs no separate codec-binding package: impl/go/cbor already IS
// the one blessed encoder, so there is nothing else to import.
//
// Design choice -- injected, composable hooks, never a hard import of a sibling
// ecosystem package: Validator and HITL are plain function values whose signature
// matches what a real pre-send validator or a real human-in-the-loop interceptor would
// supply, but this package never imports one. A caller wires a real validator (any
// func(*envelope.Object) error) as Validator, and a real HITL interceptor (any
// func(PendingAction) error that calls pending.Execute() on approval and returns a
// non-nil error on refusal, never calling Execute) as HITL -- exactly the shape a Go
// port of naalp_hitl's HITLInterceptor.intercept() would expose. This keeps the react
// package buildable and testable in total isolation (this task's isolation-demo
// requirement) while still composing with a real hook exactly as the design intends.
//
// Design choice -- audience reuse, not reinvention: verifying that a response is
// addressed to THIS bridge reuses the real Part-1 point-of-use gate
// envelope.CheckAudience (the same function every consuming authority in the protocol
// uses, design.md Sec.2.5.3) with consumeOnce=true, so an ABSENT audience and a WRONG
// audience are both rejected WrongAudience -- the identical fail-closed behaviour Part-1
// already defines and grades, never a bridge-local reimplementation of that rule.
//
// Design choice -- causal linkage is a plain membership check, not audit.VerifyCausal:
// audit.VerifyCausal reconciles a whole SET of causally-ordered nodes (positions,
// cycles) and is the right tool for a multi-agent causal graph (design.md "multi-agent:
// causes[] graph", see the sibling multiagent package), but this bridge asks a much
// narrower question -- does THIS ONE response object name THIS ONE request's content id
// among its Causes? That is a direct membership test against the response's own
// (already content-id-verified, already signature-verified) Causes slice, reported
// under the registered "CausalViolation" name (naalperror.Names), the correct semantic
// category for "the expected causal edge is absent" even though the check does not run
// audit.VerifyCausal's specific position/cycle algorithm.
package react

import (
	"bytes"
	"fmt"
	"time"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// DefaultClockMS is the wall clock in epoch milliseconds -- the unit envelope.Object.Created
// uses.
func DefaultClockMS() uint64 { return uint64(time.Now().UnixMilli()) }

// Error is a named, fail-closed react-bridge error (E1.4/R2.4). Kind is one of this
// bridge's own two glue-layer outcomes: "ValidationRefused" (the injected pre-send
// Validator rejected the candidate) and "NotEmitted" (an injected HITL hook returned nil
// without ever calling PendingAction.Execute, so no request was produced -- a defensive
// guard against a non-conformant HITL implementation silently reporting success on an
// unsent request). A signing/verification failure from the underlying Part-1 primitives
// propagates as ITS OWN error type (typically *cose.Error), never wrapped into this type.
type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string { return e.Kind + ": " + e.Msg }

// Action is R2.4's "Thought -> Action": an agent's intended tool/effect invocation, not
// yet an N-AALP object. Name is a human-readable action/tool name (never placed on the
// wire directly; it is what a HITL front end shows a human). Channel/Kind select the
// registered N-AALP surface this Action maps onto (impl/go/channels.Table); Effect is
// the C5 effect class the object will carry; Args is the request body -- an
// impl/go/cbor.Value (e.g. cbor.Map{...}), never a raw unwrapped Go value (this package
// defines no value-coercion rules of its own, per the package docstring). Causes names
// any prior N-AALP object content ids this Action causally derives from (design.md
// "multi-agent: causes[] graph"); nil/empty for a first-turn Action -- and is IGNORED and
// overwritten by the sibling plan/multiagent orchestrators, which own causal wiring.
type Action struct {
	Name        string
	Channel     uint64
	Kind        uint64
	Effect      policy.Effect
	Args        cbor.Value
	ArgsSummary string
	Causes      [][]byte
}

// Request is the output of ActionToRequest: a real signed, encoded N-AALP request object
// (Payload, the exact bytes to hand to a transport) plus its content id (ID) -- the value
// an eventual response is expected to cite in its own Causes for ResponseToObservation to
// accept it as causally linked to THIS request.
type Request struct {
	Payload []byte
	ID      []byte
}

// Observation is R2.4's "Observation": the typed outcome of verifying an async N-AALP
// response. OK=true carries the verified response's registered kind Name
// (impl/go/channels) and its decoded Body value. OK=false NEVER carries a Body -- only
// the registered error Name (impl/go/naalperror, e.g. "BadSignature"/"WrongAudience"/
// "CausalViolation") and a human-readable Detail -- a verification failure is a refusal,
// never a partially-trusted result.
type Observation struct {
	OK     bool
	Name   string
	Body   cbor.Value
	Error  string
	Detail string
}

// PendingAction is the exact shape a Go port of naalp_hitl's HITLInterceptor.Intercept
// would read off its argument (Kind/Effect/Args/Execute/ArgsSummary) -- defined here,
// duck-typed via a plain struct, rather than imported from a sibling naalp-hitl-go
// package, so this package has NO hard dependency on one (package docstring, "injected,
// composable hooks"). Execute performs the real sign+encode(+transport-send) and MUST be
// called by the HITL hook on approval; it returns the signed bytes it produced.
type PendingAction struct {
	Kind        string
	Effect      policy.Effect
	Args        cbor.Value
	ArgsSummary string
	Execute     func() ([]byte, error)
}

// Validator is an injected pre-send hook: it receives the fully-built (not yet signed)
// candidate object and returns a non-nil error to refuse it -- P-PRESIGN, nothing
// invalid reaches the wire. A nil Validator performs no pre-send check.
type Validator func(candidate *envelope.Object) error

// HITL is an injected human-in-the-loop hook: it receives a PendingAction and MUST
// either call pending.Execute() (approval) or return a non-nil error WITHOUT calling
// Execute (refusal) -- exactly the fail-closed contract naalp_hitl.HITLInterceptor.intercept
// already implements in the Python ecosystem. A nil HITL performs no gating; the action
// is signed and emitted immediately.
type HITL func(pending PendingAction) error

// Transport sends a signed request's raw bytes onward. A nil Transport performs no send
// (ActionToRequest still signs and returns the bytes; a caller who wants no side effect
// beyond building the request simply omits a Transport).
type Transport interface {
	Send(payload []byte) error
}

// Bridge translates an agent's Action into a real signed N-AALP request object, and an
// async N-AALP response back into a typed, verified Observation. The signing key, the
// responder's verifying key, the audience/use-context, the transport, and the optional
// Validator/HITL hooks are all struct fields the caller sets directly (never a wall
// clock read inline unless Clock is left nil, never a hidden global, never a network
// call this type makes itself beyond the injected Transport) so the whole bridge is
// testable in isolation.
type Bridge struct {
	// Signer is this agent's own signing key (also carries its algorithm, cose.Signer.Alg()).
	Signer cose.Signer
	// SignerID is this agent's own signer id (impl/go/identity.SignerID(...)), placed in
	// every outgoing request's Signer field.
	SignerID string
	// Profile is the crypto profile floor a produced/verified object must meet
	// (cose.ProfilePublic / cose.ProfileEnterprise / cose.ProfileSovereign).
	Profile int
	// Audience is the intended consuming authority for every outgoing request (§2.5.3).
	Audience string
	// SelfIdentity is this bridge's own identity: the audience a verified response MUST
	// name (envelope.CheckAudience, consumeOnce=true).
	SelfIdentity string
	// ResponderVerifier verifies an incoming response's signature.
	ResponderVerifier cose.Verifier

	// Clock returns the wall clock in epoch milliseconds; DefaultClockMS if nil.
	Clock func() uint64
	// Validator, if non-nil, is called against every candidate before it is signed.
	Validator Validator
	// HITL, if non-nil, gates every emit through a human-in-the-loop hook.
	HITL HITL
	// Transport, if non-nil, receives every signed request's raw bytes.
	Transport Transport
}

// New validates the required identity fields and returns a ready Bridge. Audience (the
// request's intended consuming authority) and SelfIdentity (the required response
// audience) must both be non-empty -- the same two constructor checks
// naalp_react.ReActBridge.__init__ performs.
func New(cfg Bridge) (*Bridge, error) {
	if cfg.Audience == "" {
		return nil, &Error{"InvalidConfig", "Audience (the request's intended consuming authority) must be non-empty"}
	}
	if cfg.SelfIdentity == "" {
		return nil, &Error{"InvalidConfig", "SelfIdentity (the required response audience) must be non-empty"}
	}
	b := cfg
	if b.Clock == nil {
		b.Clock = DefaultClockMS
	}
	return &b, nil
}

// ActionToRequest builds the N-AALP request object for action (kind/channel/effect/body/
// audience/causes), OPTIONALLY rejects it pre-sign via the injected Validator
// (P-PRESIGN: nothing invalid reaches the wire), OPTIONALLY pauses it for human approval
// via the injected HITL (an effecting Action is gated exactly as a real
// naalp_hitl.HITLInterceptor already gates one), then signs+encodes it with the real
// Part-1 primitive and returns the resulting bytes plus the request's content id.
//
// Returns a non-nil error on ANY pre-send refusal (*Error{"ValidationRefused",...},
// *Error{"NotEmitted",...}, the injected Validator's own error, the injected HITL's own
// error, or a Part-1 signing error); on every refusal path envelope.Sign is NEVER called
// unless the HITL hook itself calls PendingAction.Execute (no signature is produced, so
// no bytes can leak to a transport) -- verified by red-evidence against a swallowed HITL
// denial and the pre-send validator test.
func (b *Bridge) ActionToRequest(action Action) (Request, error) {
	candidate := &envelope.Object{
		Kind:     action.Kind,
		Channel:  action.Channel,
		Signer:   []byte(b.SignerID),
		Created:  b.Clock(),
		Effect:   uint64(action.Effect),
		Body:     action.Args,
		Causes:   action.Causes,
		Profile:  uint64(b.Profile),
		Audience: b.Audience,
	}

	if b.Validator != nil {
		if err := b.Validator(candidate); err != nil {
			return Request{}, &Error{"ValidationRefused", fmt.Sprintf("pre-send validation rejected the candidate: %v", err)}
		}
	}

	var emitted []byte
	signAndEmit := func() ([]byte, error) {
		signedBytes, err := envelope.Sign(candidate, b.Signer)
		if err != nil {
			return nil, err
		}
		emitted = signedBytes
		if b.Transport != nil {
			if err := b.Transport.Send(signedBytes); err != nil {
				return nil, err
			}
		}
		return signedBytes, nil
	}

	if b.HITL != nil {
		pending := PendingAction{
			Kind:        action.Name,
			Effect:      action.Effect,
			Args:        candidate.Body,
			ArgsSummary: argsSummaryOrName(action),
			Execute:     signAndEmit,
		}
		// raises fail-closed on any refusal; never calls signAndEmit then
		if err := b.HITL(pending); err != nil {
			return Request{}, err
		}
	} else {
		if _, err := signAndEmit(); err != nil {
			return Request{}, err
		}
	}

	if emitted == nil {
		// Defensive (D3): an injected HITL that returns nil WITHOUT ever calling Execute
		// must not be mistaken for a successfully emitted request.
		return Request{}, &Error{"NotEmitted", "the injected HITL hook returned without emitting the request"}
	}

	return Request{Payload: emitted, ID: candidate.ID}, nil
}

func argsSummaryOrName(action Action) string {
	if action.ArgsSummary != "" {
		return action.ArgsSummary
	}
	return action.Name
}

// ResponseToObservation verifies responseBytes end-to-end (signature + audience + the
// expected causal linkage back to request), then converts it into a typed Observation. A
// verification failure at ANY step returns a fail-closed Observation{OK: false, ...}
// carrying the named error -- it NEVER returns a Body alongside OK=false (no
// silently-accepted partial result).
func (b *Bridge) ResponseToObservation(responseBytes []byte, request Request) Observation {
	obj, err := envelope.Verify(b.Profile, b.ResponderVerifier, channels.KindValidator, nil, responseBytes)
	if err != nil {
		return Observation{OK: false, Error: errKind(err), Detail: err.Error()}
	}

	// Reuse (never reinvent) the real Part-1 point-of-use audience gate: absent OR wrong
	// audience both reject WrongAudience (design.md Sec.2.5.3).
	if err := envelope.CheckAudience(obj, b.SelfIdentity, true); err != nil {
		return Observation{OK: false, Error: errKind(err), Detail: err.Error()}
	}

	linked := false
	for _, c := range obj.Causes {
		if bytes.Equal(c, request.ID) {
			linked = true
			break
		}
	}
	if !linked {
		return Observation{
			OK:     false,
			Error:  "CausalViolation",
			Detail: fmt.Sprintf("response causes[] does not name this request's content id (%x)", request.ID),
		}
	}

	spec, _ := channels.Lookup(obj.Channel, obj.Kind) // already accepted by kindOK inside Verify
	return Observation{OK: true, Name: spec.Name, Body: obj.Body}
}

// errKind extracts the registered Kind from a Part-1 error (typically *cose.Error), or
// falls back to "Malformed" for anything else (e.g. a malformed-COSE structural error
// that surfaces as a plain error).
func errKind(err error) string {
	if ce, ok := err.(*cose.Error); ok {
		return ce.Kind
	}
	return "Malformed"
}
