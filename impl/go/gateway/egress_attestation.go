// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// egress_attestation.go implements E6.3 — the egress-attestation object. HELD AT THE WIRE-FREEZE
// GATE: this file is impl-behind-the-approval-gate, built ahead of the CDDL production, the
// top-level object-choice registration, the parity-baseline entry, and the conformance-corpus op,
// which all land in a separate maintainer-approved freeze commit.
//
// A naalp-egress-attestation is a SIGNED attestation a GATEWAY/SIDECAR emits that an object of a
// given effect class, bound to a given audience, crossed an egress boundary at a given time —
// third-party verifiable WITHOUT the payload. It is a new standalone signed record, a near-clone
// of GatewayDecision (design §24, this package's sibling): the gateway is the SIGNER (envelope
// field-5 self-certifying signer id), and VerifyEgressAttestation takes NO serving-party or
// connection identity — the authority is the signature over the bytes, so the identical attested
// evidence re-verifies whether the gateway or an unrelated third party serves it. It introduces
// NO new envelope, encoding, signature, or identity mechanism: an ordinary N-AALP signed body
// (COSE_Sign1, §4), reusing the closed C5 effect lattice (policy) and the T1 content-id framing
// (§2.3) unchanged.
//
//   - naalp-egress-attestation {1: binding, 2: digest, 3: effect, 4: audience, 5: at,
//     ?6: ordering-disclosure}. `binding` is a closed set (content_bound / content_free); `digest`
//     is either the T1 content-id of the crossed object (content_bound) or a hiding commitment
//     SHA-384(content_id||salt) (content_free) — never both, and a content_free digest never
//     discloses the content-id it commits to; `effect` is the C5 effect class of the crossed
//     object; `audience` is the bound destination (empty-permitted); `at` is the crossing time in
//     epoch milliseconds. Field 6 (`ordering`, design.md §26.3/§26.6) is OPTIONAL: an egress
//     attestation is precisely an effect-side evidence record the ordering claim applies to;
//     ABSENT reads correspondence-only, never a stronger claim inferred from silence.
//
// The content_free binding lets a gateway attest an egress crossing WITHOUT disclosing which
// object crossed. EgressCommit/OpenEgressCommitment is the open/verify pair: the gateway (or
// anyone it later discloses content-id+salt to) can PROVE which object a content_free attestation
// names, without the attestation bytes themselves ever carrying the content-id.
//
// Every check is fail-closed (§15): a failing object is rejected whole, returns its named error,
// and causes no state change.
package gateway

import (
	"crypto/subtle"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// Binding codes — the closed set an egress attestation may declare. A code outside the set is
// rejected (UnknownEgressBinding).
const (
	BindingContentBound uint64 = 0 // digest is the crossed object's T1 content-id
	BindingContentFree  uint64 = 1 // digest is a hiding commitment SHA-384(content_id||salt)
)

// bindingName maps a binding code to its name (diagnostics); an unknown code returns "".
var bindingName = map[uint64]string{BindingContentBound: "content_bound", BindingContentFree: "content_free"}

// IsKnownBinding reports whether code is one of the closed binding codes.
func IsKnownBinding(code uint64) bool { _, ok := bindingName[code]; return ok }

// BindingName returns the binding name, or "unknown".
func BindingName(code uint64) string {
	if n, ok := bindingName[code]; ok {
		return n
	}
	return "unknown"
}

// Named, fail-closed errors (§15). A bad signature is the existing cose.ErrBadSignature reused
// unchanged, exactly as GatewayDecision.
var (
	ErrEgressMalformed      = &cose.Error{Kind: "EgMalformed", Msg: "object is not a well-formed N-AALP egress-attestation body"}
	ErrUnknownEgressBinding = &cose.Error{Kind: "UnknownEgressBinding", Msg: "egress attestation binding code is outside the closed set content_bound/content_free"}
)

// ---- EgressAttestation: the portable egress-crossing evidence object -------------------------

// EgressAttestation is a signed attestation a gateway/sidecar emits that an object crossed an
// egress boundary. Binding selects how Digest is interpreted (content_bound: the crossed object's
// T1 content-id; content_free: a hiding commitment). Effect is the crossed object's C5 effect
// class. Audience is the bound destination (empty-permitted). At is the crossing time, epoch ms.
type EgressAttestation struct {
	Binding  uint64
	Digest   []byte
	Effect   uint64
	Audience []byte
	At       uint64
	// Ordering is the OPTIONAL field 6 (design.md §26.3/§26.6). nil == ABSENT (reads
	// correspondence-only); a non-nil pointer to the zero value is a DISTINCT wire encoding
	// (field 6 present, {1:0}) from the field being omitted entirely — the same distinction
	// TestEgEmptyVsAbsentAudience already draws for field 4.
	Ordering *OrderingDisclosure
}

// Bytes is the deterministic-CBOR encoding {1: binding, 2: digest, 3: effect, 4: audience, 5: at,
// ?6: ordering}. Field 6 is OMITTED when Ordering is nil.
func (a EgressAttestation) Bytes() []byte {
	m := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(a.Binding)},
		{K: cbor.Uint(2), V: cbor.Bstr(a.Digest)},
		{K: cbor.Uint(3), V: cbor.Uint(a.Effect)},
		{K: cbor.Uint(4), V: cbor.Bstr(a.Audience)},
		{K: cbor.Uint(5), V: cbor.Uint(a.At)},
	}
	if a.Ordering != nil {
		m = append(m, cbor.Pair{K: cbor.Uint(6), V: a.Ordering.toCBOR()})
	}
	b, _ := cbor.Encode(m)
	return b
}

// Head is the attestation's SHA-384 head (48 octets).
func (a EgressAttestation) Head() []byte { return head(a.Bytes()) }

// ID is the attestation's T1 content-id (50 octets).
func (a EgressAttestation) ID() []byte { return contentID(a.Bytes()) }

// EffectClass is the attestation's C5 effect class, normalized fail-closed: a value the evaluator
// does not recognize is treated as destructive (R-6.2), never as a weaker class.
func (a EgressAttestation) EffectClass() policy.Effect { return policy.NormalizeEffect(a.Effect) }

// ParseEgressAttestation reconstructs an EgressAttestation from its body bytes alone. It does NOT
// validate the binding code against the closed set — that is VerifyEgressAttestation's job — so an
// attestation carrying an unknown binding can be represented (and then rejected). Fail-closed on a
// malformed shape: every one of the five fields is mandatory.
func ParseEgressAttestation(b []byte) (EgressAttestation, error) {
	m, ok := decodeMap(b)
	if !ok {
		return EgressAttestation{}, ErrEgressMalformed
	}
	binding, ok1 := uintField(m, 1)
	digest, ok2 := bstrField(m, 2)
	effect, ok3 := uintField(m, 3)
	audience, ok4 := bstrField(m, 4)
	at, ok5 := uintField(m, 5)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return EgressAttestation{}, ErrEgressMalformed
	}
	var ordering *OrderingDisclosure
	if ov, present := field(m, 6); present {
		od, ok := orderingFromCBOR(ov)
		if !ok {
			return EgressAttestation{}, ErrEgressMalformed
		}
		ordering = &od
	}
	return EgressAttestation{Binding: binding, Digest: digest, Effect: effect, Audience: audience, At: at, Ordering: ordering}, nil
}

// SignEgressAttestation produces the tagged COSE_Sign1 object over the attestation body, signed by
// the gateway.
func SignEgressAttestation(a EgressAttestation, s cose.Signer) ([]byte, error) {
	return cose.Sign1(s, a.Bytes())
}

// ResolvedEgressAttestation is an EgressAttestation that has passed signature verification. It
// carries NOTHING about WHO served the bytes — the authority is the signature, so the resolved
// evidence is identical regardless of the serving party (the third-party re-serve property).
type ResolvedEgressAttestation struct {
	Binding  uint64
	Digest   []byte
	Effect   policy.Effect
	Audience []byte
	At       uint64
	Ordering *OrderingDisclosure
}

// ValidateEgressAttestation performs the semantic, closed-set checks ParseEgressAttestation
// deliberately does not (mirroring gateway.go's Parse/Verify split): the binding must be in the
// closed set (UnknownEgressBinding), and — if present — the field-6 ordering disclosure must
// satisfy its basis-conditioned well-formedness rule (UnknownOrderingBasis /
// OrderingDisclosureMalformed, §26.3).
func ValidateEgressAttestation(a EgressAttestation) error {
	if !IsKnownBinding(a.Binding) {
		return ErrUnknownEgressBinding
	}
	if a.Ordering != nil {
		if err := a.Ordering.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// VerifyEgressAttestation verifies an egress attestation end-to-end and returns the resolved
// evidence. It (1) verifies the signed object under the profile with real crypto (cose.Verify1 —
// signature, alg registry, profile floor) against the GATEWAY's verifier `gatewayV`; (2)
// reconstructs it from the signed bytes; and (3) validates the binding code against the closed
// set (UnknownEgressBinding). It takes NO serving-party or connection identity: the authority is
// the signature over the bytes, so the same `obj` yields an identical ResolvedEgressAttestation
// whether the gateway or an unrelated third party served it (the third-party re-serve property,
// mirroring VerifyDecision/R-GW-3). Any failure returns its named error and resolves nothing
// (fail-closed).
func VerifyEgressAttestation(obj []byte, profile int, gatewayV cose.Verifier) (ResolvedEgressAttestation, error) {
	if err := cose.Verify1(profile, gatewayV, obj); err != nil {
		return ResolvedEgressAttestation{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return ResolvedEgressAttestation{}, err
	}
	a, err := ParseEgressAttestation(payload)
	if err != nil {
		return ResolvedEgressAttestation{}, err
	}
	if err := ValidateEgressAttestation(a); err != nil {
		return ResolvedEgressAttestation{}, err
	}
	return ResolvedEgressAttestation{
		Binding:  a.Binding,
		Digest:   append([]byte(nil), a.Digest...),
		Effect:   policy.NormalizeEffect(a.Effect),
		Audience: append([]byte(nil), a.Audience...),
		At:       a.At,
		Ordering: a.Ordering,
	}, nil
}

// ---- content_free commitment open/verify pair ---------------------------------------------

// EgressCommit is the content_free hiding commitment over an object's T1 content-id and a salt:
// SHA-384(objectCID || salt) (48 octets). The commitment reveals nothing about objectCID without
// the salt; a gateway builds it once to populate a content_free attestation's Digest field, and
// retains objectCID+salt to later prove which object crossed via OpenEgressCommitment.
func EgressCommit(objectCID, salt []byte) []byte {
	b := make([]byte, 0, len(objectCID)+len(salt))
	b = append(b, objectCID...)
	b = append(b, salt...)
	return head(b)
}

// OpenEgressCommitment proves which object crossed under a content_free attestation. It recomputes
// EgressCommit(objectCID, salt) and compares it, in constant time, against `a.Digest`. It returns
// true iff `a` is a content_free attestation AND the recomputed commitment matches: a wrong salt
// or a wrong objectCID both fail to open (return false), and a content_bound attestation never
// opens (its Digest is not a commitment).
func OpenEgressCommitment(a EgressAttestation, objectCID, salt []byte) bool {
	if a.Binding != BindingContentFree {
		return false
	}
	want := EgressCommit(objectCID, salt)
	if len(want) != len(a.Digest) {
		return false
	}
	return subtle.ConstantTimeCompare(want, a.Digest) == 1
}
