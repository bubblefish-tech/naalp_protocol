// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package policy implements C5 — the closed effect vocabulary, the fail-closed
// unknown->destructive rule, effect-as-authorization-input, and the optional signed
// safety label (design.md §6; requirements R-6.1..6.5).
//
// The effect (envelope field 7) is a closed four-value set aligned 1:1 with the N-PAMP
// Bridge SafetyLabel u8 (N-PAMP draft-01 spec/companion/10_bridge_framework.md §7):
// read_only=0, idempotent_write=1, non_idempotent_write=2, destructive=3. The values form
// a lattice with destructive at the top. N-PAMP states the label "describes intent and
// does not replace authorization"; N-AALP closes that hole here (§6.3): an endpoint grants
// a maximum effect (a capability) to an AUTHENTICATED signer id, and an object is
// authorized iff its effect does not exceed the grant. Every rejection is fail-closed.
package policy

import (
	"github.com/bubblefish-tech/n-aalp/impl/go/cbor"
	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
)

// Effect is one of the closed four-value N-AALP effect set (design.md §6.1).
type Effect uint8

const (
	ReadOnly           Effect = 0
	IdempotentWrite    Effect = 1
	NonIdempotentWrite Effect = 2
	Destructive        Effect = 3
)

var safetyLabelNames = [...]string{"read_only", "idempotent_write", "non_idempotent_write", "destructive"}

// SafetyLabelName returns the N-PAMP SafetyLabel name for a normalized effect (0..3).
func (e Effect) SafetyLabelName() string { return safetyLabelNames[e] }

// SafetyLabelByte is the N-PAMP Bridge SafetyLabel u8 (design.md §6.1: identity map, so
// carriage over the Bridge is loss-free).
func (e Effect) SafetyLabelByte() uint8 { return uint8(e) }

// EffectFromSafetyLabelByte maps an N-PAMP SafetyLabel u8 back to an N-AALP effect. An
// unrecognized byte is treated as destructive (R-6.2 / N-PAMP §7 fail-safe), never as a
// weaker class.
func EffectFromSafetyLabelByte(b uint8) Effect { return NormalizeEffect(uint64(b)) }

// NormalizeEffect maps a raw effect value to the closed set. Any value outside 0..3 is an
// effect the evaluator does not recognize and is treated as the most dangerous class,
// destructive, so the evaluator never fails open (R-6.2). Reusable by carriage (T11),
// where a foreign Bridge SafetyLabel byte may carry a value this draft does not define.
func NormalizeEffect(v uint64) Effect {
	if v <= 3 {
		return Effect(v)
	}
	return Destructive
}

// Authorizes reports whether an action of class `action` is permitted under a capability
// (or object) whose effect ceiling is e — the design §6.1 lattice: action <= e. read_only
// authorizes only observation; destructive (top) authorizes everything.
func (e Effect) Authorizes(action Effect) bool { return action <= e }

// Errors reuse the cose.Error type so every N-AALP error carries a stable Kind.
var (
	ErrEffectNotAuthorized      = &cose.Error{Kind: "EffectNotAuthorized", Msg: "object effect exceeds the granted capability"}
	ErrUnauthenticatedPrincipal = &cose.Error{Kind: "UnauthenticatedPrincipal", Msg: "an authorization identity must be signature-derived, not transport/foreign/client-asserted"}
	ErrMalformedSafetyLabel     = &cose.Error{Kind: "MalformedSafetyLabel", Msg: "safety label is not {1:tstr risk, 2:tstr scope}"}
)

// PrincipalSource is where a claimed identity came from. Only a signature-derived identity
// is an authorization principal (R-6.5).
type PrincipalSource int

const (
	SourceSignature         PrincipalSource = iota // the verified COSE signature's signer id
	SourceTransportMetadata                        // e.g. a TLS peer name / connection tag
	SourceForeignHeader                            // e.g. an X-Agent-ID or a carried foreign header
	SourceClientName                               // e.g. a self-asserted clientInfo.name
)

// ResolveAuthPrincipal returns the authorization principal id iff it is signature-derived
// and non-empty (R-6.5). A transport-metadata, foreign-header, or client-supplied name is
// refused with UnauthenticatedPrincipal — it is never treated as an authorization identity.
func ResolveAuthPrincipal(src PrincipalSource, id string) (string, error) {
	if src != SourceSignature || id == "" {
		return "", ErrUnauthenticatedPrincipal
	}
	return id, nil
}

// Grant is a capability an endpoint issues to an authenticated signer id: the most
// dangerous effect that principal is permitted to carry. The zero MaxEffect (ReadOnly) is
// the least-privilege default, so a zero-value Grant authorizes only read_only.
type Grant struct {
	Principal string // the signature-derived signer id this grant is issued to
	MaxEffect Effect // the effect ceiling this grant authorizes
}

// AuthorizeObject is the endpoint policy check that makes the effect an authorization
// input, not a hint (R-6.3). It (1) resolves the presenter's identity, refusing any
// non-signature source (R-6.5); (2) requires that identity to match the grant's principal
// — no matching grant means no authority; (3) normalizes the object's effect fail-closed
// (R-6.2) and denies it if it exceeds the grant's ceiling. It performs no side effect and
// returns a named error on any failure (fail-closed).
func (g Grant) AuthorizeObject(src PrincipalSource, presented string, objectEffect uint64) error {
	who, err := ResolveAuthPrincipal(src, presented)
	if err != nil {
		return err
	}
	if who != g.Principal {
		return ErrEffectNotAuthorized
	}
	if !g.MaxEffect.Authorizes(NormalizeEffect(objectEffect)) {
		return ErrEffectNotAuthorized
	}
	return nil
}

// SafetyLabelExtKey is the non-critical ext key under which the optional safety label is
// carried (ext[1], design.md §6.4). Recorded in vectors/registry (T14).
const SafetyLabelExtKey uint64 = 1

// SafetyLabel is the OPTIONAL signed safety annotation (R-6.4). It is attributable to the
// object's signer and auditable. It is an ACCOUNTABLE CLAIM, not a guarantee the content
// is safe (design.md §6.4; stated in the security considerations, T15).
type SafetyLabel struct {
	Risk  string // an accountable risk claim, e.g. "elevated"
	Scope string // what the object affects, e.g. "billing-records"
}

// ToValue encodes the safety label as its CBOR map {1: risk, 2: scope}.
func (s SafetyLabel) ToValue() cbor.Value {
	return cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr(s.Risk)},
		{K: cbor.Uint(2), V: cbor.Tstr(s.Scope)},
	}
}

// Encode returns the deterministic-CBOR bytes of the safety-label map.
func (s SafetyLabel) Encode() ([]byte, error) { return cbor.Encode(s.ToValue()) }

// Ext returns an ext map carrying only this safety label, ready to place in an object's
// field 11 (or merge into an existing ext map).
func (s SafetyLabel) Ext() cbor.Map {
	return cbor.Map{{K: cbor.Uint(SafetyLabelExtKey), V: s.ToValue()}}
}

// SafetyLabelFromExt extracts the optional safety label from an object's ext map. It
// returns (label, true, nil) when a well-formed label is present, (nil, false, nil) when
// absent, and (nil, false, MalformedSafetyLabel) when the ext[1] entry is present but not
// exactly {1:tstr, 2:tstr} — a malformed label is rejected, never silently accepted.
func SafetyLabelFromExt(ext cbor.Map) (*SafetyLabel, bool, error) {
	for _, p := range ext {
		k, ok := p.K.(cbor.Uint)
		if !ok || uint64(k) != SafetyLabelExtKey {
			continue
		}
		m, ok := p.V.(cbor.Map)
		if !ok {
			return nil, false, ErrMalformedSafetyLabel
		}
		var risk, scope string
		var haveRisk, haveScope bool
		for _, q := range m {
			kk, ok := q.K.(cbor.Uint)
			if !ok {
				return nil, false, ErrMalformedSafetyLabel
			}
			vv, ok := q.V.(cbor.Tstr)
			if !ok {
				return nil, false, ErrMalformedSafetyLabel
			}
			switch uint64(kk) {
			case 1:
				risk, haveRisk = string(vv), true
			case 2:
				scope, haveScope = string(vv), true
			default:
				return nil, false, ErrMalformedSafetyLabel
			}
		}
		if !haveRisk || !haveScope {
			return nil, false, ErrMalformedSafetyLabel
		}
		return &SafetyLabel{Risk: risk, Scope: scope}, true, nil
	}
	return nil, false, nil
}
