// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package naalperror implements the N-AALP error object and the numeric error-code registry
// (design.md §3.5, R3.3/R3.4, T3.3). The naalp-error object is the Control/Error body (channel
// 0x0000, kind 3, effect read_only) that carries one fail-closed rejection reason as
// {1:code, 2:name, ?3:detail, ?4:subject}. The registry is the ordered 119-entry name<->code table
// below (the code for Names[i] is i+1; 0 is reserved). Names is the single source the machine-
// readable registry (vectors/registry/error-codes.csv) and the CDDL naalp-error-code enum are
// generated to match, and scripts/registry_drift.py asserts the three agree; the table itself is
// graded against the non-circular oracle by the error.name_for_code conformance op.
//
// Two dual-carriage rules keep the code/name pair unambiguous and forward-compatible: a registered
// code whose name disagrees with the registry is rejected Malformed (the code is authoritative — the
// strengthening direction); a code outside the registry is opaque and non-fatal (the name is
// diagnostic only), so a receiver interoperates with a peer emitting a later-registered code.
package naalperror

import (
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// StandardsMax is the top of the RFC-Required standards range; codes >= 0x8000 are private-use.
const StandardsMax = 0x7FFF

// Names is the ordered error-code registry: the code for Names[i] is i+1 (0 is reserved and MUST
// NOT appear on the wire). Order is the fields-of-record authority for every code (§3.5).
var Names = []string{
	"NonCanonical", "DepthExceeded", "Malformed", "ContentIdMismatch", "HeaderBodyMismatch",
	"UnsupportedVersion", "UnknownCriticalExt", "UnknownKind", "RangeError", "NonNFC",
	"WrongAudience", "TooLarge", "TooManyCauses", "TooManyExtensions", "TooManyChunks",
	"UnknownAlg", "KeyAlgMismatch", "ProfileDowngrade", "HybridIncomplete", "SuiteMismatch",
	"CompositeRefused", "BadSignature", "SignerMismatch", "RotationUnauthorized", "KeyRevoked",
	"EffectNotAuthorized", "UnauthenticatedPrincipal", "MalformedSafetyLabel", "ApprovalRequired",
	"ApprovalMismatch", "ApprovalExpired", "AlreadyConsumed", "ConsumeFork", "ConsumeForkInvalid",
	"ConsumeReceiptUnsigned", "LedgerCorrupt", "LedgerUnsigned", "AudienceMismatch",
	"FreshnessSelfAsserted", "UnknownRefusalOutcome", "RefusalDetailLeak", "ChainBroken",
	"Equivocation", "CausalViolation", "ReceiptUnsigned", "ForkProofInvalid", "StageOutOfOrder",
	"StreamDigestMismatch", "StreamStateError", "ConfidentialTransportRequired", "PeerUnauthenticated",
	"NotDelivered", "MappingError", "EffectDeclarationMismatch", "StateTransitionError",
	"CapExceedsParent", "TransformCycle", "InputGateBypass", "TaskStateError", "ScopeOverlapConflict",
	"ReconcileMismatch", "WrongFlow", "SeqGap", "AboveCeiling", "GapDetected", "CommitMismatch",
	"ContMalformed", "GrantExpired", "GrantNotYetValid", "GrantRevoked", "UntrustedChainRoot",
	"DelegationDepthExceeded", "GrantMalformed", "NameMalformed", "NameChainBroken",
	"NameForkProofInvalid", "IllegalTransition", "TaskChainBroken", "ForeignCard", "DescMalformed",
	"MalformedApprovalFlag", "DirForkProofInvalid", "ImporterMismatch", "UnknownDescriptionFormat",
	"VerifierKeyMismatch", "NegMalformed", "UnknownRole", "UnknownProfile", "NotDescended",
	"NotOffer", "NotAccept", "MalformedCriticalFlag", "UnknownCriticalRisk", "ReferenceMismatch",
	"MalformedAnnotation", "EffectUnderDeclared", "EffectOutsideLattice", "ToolCallMalformed",
	"PayMalformed", "UnknownPaymentFormat", "GwMalformed", "UnknownGatewayDecision", "UIMalformed",
	"UIChainBroken", "UnknownUIEventKind", "ActionSubstituted", "UINoConsent", "StaleEpoch",
	"Unauthorized", "OwnerImmutable", "MemberExists", "MemberUnknown", "OwnerExists", "RoleInvalid",
	"RoomOpMismatch", "OpUnknown", "PrincipalUnknown", "PrincipalExists", "RebindUnauthorized",
	// Evidence-record family (E6.3 egress + S1 decision-record + S3 checkpoint + R1/R8), codes 120-129.
	"EgMalformed", "UnknownEgressBinding", "DecisionMalformed", "UnknownOrderingBasis", "OrderingDisclosureMalformed",
	"TermDispositionMalformed", "CheckpointMalformed", "WitnessRootMismatch", "InclusionProofInvalid", "ForeignProfileMalformed",
	// Manufacturing physical-hazard (Mfg-F), codes 130-132.
	"HazardMalformed", "HazardNotCovered", "HazardUnknown",
}

var codeByName = func() map[string]uint64 {
	m := make(map[string]uint64, len(Names))
	for i, n := range Names {
		m[n] = uint64(i + 1)
	}
	return m
}()

// NameForCode returns the registered name for a code and whether the code is registered. A code of
// 0, or any value past the registered range, is unregistered (opaque per the open-registry rule).
func NameForCode(code uint64) (string, bool) {
	if code >= 1 && int(code) <= len(Names) {
		return Names[code-1], true
	}
	return "", false
}

// CodeForName returns the registered code for a name and whether the name is registered.
func CodeForName(name string) (uint64, bool) {
	c, ok := codeByName[name]
	return c, ok
}

// Object is a decoded naalp-error body.
type Object struct {
	Code    uint64
	Name    string
	Detail  string // "" if field 3 absent
	Subject []byte // nil if field 4 absent
}

// Encode returns the deterministic CBOR (RFC 8949 §4.2.1) of a naalp-error body
// {1:code, 2:name, ?3:detail, ?4:subject}. detail=="" omits field 3; subject==nil omits field 4.
// The integer keys 1..4 are already in canonical ascending order.
func Encode(code uint64, name, detail string, subject []byte) ([]byte, error) {
	m := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(code)},
		{K: cbor.Uint(2), V: cbor.Tstr(name)},
	}
	if detail != "" {
		m = append(m, cbor.Pair{K: cbor.Uint(3), V: cbor.Tstr(detail)})
	}
	if subject != nil {
		m = append(m, cbor.Pair{K: cbor.Uint(4), V: cbor.Bstr(subject)})
	}
	return cbor.Encode(m)
}

// Decode parses a naalp-error body and enforces the dual-carriage rules. A structurally malformed
// body (not a map, a non-integer key, a wrong-typed or unknown field, or a missing code/name) is
// rejected Malformed. A registered code whose name disagrees with the registry is rejected Malformed
// (the code is authoritative). An unregistered code is accepted opaque (name diagnostic only).
func Decode(data []byte) (*Object, error) {
	v, err := cbor.Decode(data)
	if err != nil {
		return nil, cose.ErrMalformed
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, cose.ErrMalformed
	}
	var o Object
	var haveCode, haveName bool
	for _, p := range m {
		k, ok := p.K.(cbor.Uint)
		if !ok {
			return nil, cose.ErrMalformed
		}
		switch uint64(k) {
		case 1:
			c, ok := p.V.(cbor.Uint)
			if !ok {
				return nil, cose.ErrMalformed
			}
			o.Code = uint64(c)
			haveCode = true
		case 2:
			n, ok := p.V.(cbor.Tstr)
			if !ok {
				return nil, cose.ErrMalformed
			}
			o.Name = string(n)
			haveName = true
		case 3:
			d, ok := p.V.(cbor.Tstr)
			if !ok {
				return nil, cose.ErrMalformed
			}
			o.Detail = string(d)
		case 4:
			s, ok := p.V.(cbor.Bstr)
			if !ok {
				return nil, cose.ErrMalformed
			}
			o.Subject = []byte(s)
		default:
			return nil, cose.ErrMalformed // closed grammar: an unknown field key is malformed
		}
	}
	if !haveCode || !haveName {
		return nil, cose.ErrMalformed
	}
	if regName, registered := NameForCode(o.Code); registered && regName != o.Name {
		return nil, cose.ErrMalformed // registered code + disagreeing name
	}
	return &o, nil
}
