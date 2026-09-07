// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// ordering.go implements the ordering-disclosure embeddable group and the term-disposition /
// enforcement-disposition vocabularies shared by the evidence-record family (design.md §26.3,
// §26.4; spec/naalp-draft-01.cddl `ordering-disclosure` / `term-disposition` /
// `enforcement-disposition`).
//
// `ordering-disclosure` states what, if anything, establishes decision->effect / record->event
// ORDER, and from which observational domain, rather than leaving the reader to assume more than
// the bytes support. It is carried as a field inside naalp-decision-record (mandatory, field 5),
// naalp-egress-attestation (optional, field 6), and naalp-gateway-decision (optional, field 5) —
// never as a top-level object of its own, so it has no Head/ID of its own; it is embedded directly
// as a nested CBOR map value inside its carrying record.
//
// `correspondence-only` (0) is the weakest claim and the value a verifier MUST read when the field
// is ABSENT on an optional carrier — never a stronger claim inferred from silence.
// `single-boundary` (1) names one covering boundary. `external-mechanism` (2) names an external
// sequencing mechanism and, optionally, the log relation binding the record under it.
//
// Well-formedness is fail-closed and NATIVE (unlike the may-ignore `ext`-carried
// producing-boundary): correspondence-only requires keys 2/3/4 absent; single-boundary requires
// key 2 present and 3/4 absent; external-mechanism requires key 3 present (4 optional) and key 2
// absent. Any violation rejects the WHOLE carrying record (OrderingDisclosureMalformed).
package gateway

import (
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// Ordering-basis codes — the closed set (design.md §26.3).
const (
	OrderingCorrespondenceOnly uint64 = 0 // the record orders only its own two-party construction (the weakest claim)
	OrderingSingleBoundary     uint64 = 1 // one boundary observed both terms and is named
	OrderingExternalMechanism  uint64 = 2 // an external sequencing mechanism is named
)

// orderingBasisName maps an ordering-basis code to its name (diagnostics); an unknown code returns "".
var orderingBasisName = map[uint64]string{
	OrderingCorrespondenceOnly: "correspondence-only",
	OrderingSingleBoundary:     "single-boundary",
	OrderingExternalMechanism:  "external-mechanism",
}

// IsKnownOrderingBasis reports whether code is one of the closed ordering-basis codes.
func IsKnownOrderingBasis(code uint64) bool { _, ok := orderingBasisName[code]; return ok }

// OrderingBasisName returns the ordering-basis name, or "unknown".
func OrderingBasisName(code uint64) string {
	if n, ok := orderingBasisName[code]; ok {
		return n
	}
	return "unknown"
}

// Enforcement-disposition codes — the closed set (design.md §26.4).
const (
	EnforcementEnforced uint64 = 1 // the producer states it actually enforces this outcome
	EnforcementAdvised  uint64 = 2 // the producer's own unverifiable self-account that it only advises
)

// Term-disposition kind codes — reused unchanged from the §2.5.4 producing-boundary kind vocabulary.
const (
	TermObserved uint64 = 1 // the term was observed first-hand
	TermReported uint64 = 2 // the term was reported, relayed from a named source
)

// Named, fail-closed errors for the ordering-disclosure group (§26.8). A bad signature is the
// existing cose.ErrBadSignature reused unchanged, exactly as the rest of this package.
var (
	ErrUnknownOrderingBasis        = &cose.Error{Kind: "UnknownOrderingBasis", Msg: "ordering-disclosure basis is outside the closed set correspondence-only/single-boundary/external-mechanism"}
	ErrOrderingDisclosureMalformed = &cose.Error{Kind: "OrderingDisclosureMalformed", Msg: "ordering-disclosure does not satisfy its basis-conditioned field rule"}
)

// OrderingDisclosure is the embeddable group {1: basis, ?2: boundary, ?3: mechanism, ?4: relation}
// (design.md §26.3). It is never a top-level signed object; it is always a field inside another
// record. The zero value (Basis: OrderingCorrespondenceOnly, no boundary/mechanism/relation) is the
// weakest claim and is exactly what an ABSENT optional ordering-disclosure field reads as.
type OrderingDisclosure struct {
	Basis     uint64
	Boundary  []byte // present iff Basis == OrderingSingleBoundary
	Mechanism []byte // present iff Basis == OrderingExternalMechanism
	Relation  []byte // present ONLY when Basis == OrderingExternalMechanism (optional even then)
}

// CorrespondenceOnly returns the weakest ordering-disclosure claim, exactly what a verifier reads
// for an absent optional ordering-disclosure field.
func CorrespondenceOnly() OrderingDisclosure { return OrderingDisclosure{Basis: OrderingCorrespondenceOnly} }

// toCBOR returns o as a nested CBOR map VALUE (never top-level bytes — o is always embedded as a
// field inside its carrying record, so it has no Bytes()/Head()/ID() of its own).
func (o OrderingDisclosure) toCBOR() cbor.Map {
	m := cbor.Map{{K: cbor.Uint(1), V: cbor.Uint(o.Basis)}}
	if len(o.Boundary) > 0 {
		m = append(m, cbor.Pair{K: cbor.Uint(2), V: cbor.Bstr(o.Boundary)})
	}
	if len(o.Mechanism) > 0 {
		m = append(m, cbor.Pair{K: cbor.Uint(3), V: cbor.Bstr(o.Mechanism)})
	}
	if len(o.Relation) > 0 {
		m = append(m, cbor.Pair{K: cbor.Uint(4), V: cbor.Bstr(o.Relation)})
	}
	return m
}

// orderingFromCBOR decodes a nested ordering-disclosure map value. ok=false on any wrong shape,
// including an optional key present with the wrong CBOR type (never silently treated as absent).
func orderingFromCBOR(v cbor.Value) (OrderingDisclosure, bool) {
	m, ok := v.(cbor.Map)
	if !ok {
		return OrderingDisclosure{}, false
	}
	basisV, ok1 := field(m, 1)
	if !ok1 {
		return OrderingDisclosure{}, false
	}
	basis, ok1t := basisV.(cbor.Uint)
	if !ok1t {
		return OrderingDisclosure{}, false
	}
	var boundary, mechanism, relation []byte
	if v2, present := field(m, 2); present {
		bs, ok := v2.(cbor.Bstr)
		if !ok {
			return OrderingDisclosure{}, false
		}
		boundary = []byte(bs)
	}
	if v3, present := field(m, 3); present {
		bs, ok := v3.(cbor.Bstr)
		if !ok {
			return OrderingDisclosure{}, false
		}
		mechanism = []byte(bs)
	}
	if v4, present := field(m, 4); present {
		bs, ok := v4.(cbor.Bstr)
		if !ok {
			return OrderingDisclosure{}, false
		}
		relation = []byte(bs)
	}
	return OrderingDisclosure{Basis: uint64(basis), Boundary: boundary, Mechanism: mechanism, Relation: relation}, true
}

// Validate checks (a) Basis is in the closed set (UnknownOrderingBasis) and (b) the
// basis-conditioned field well-formedness rule (design.md §26.3, native and fail-closed — any
// violation rejects the whole carrying record, OrderingDisclosureMalformed). UnknownOrderingBasis
// is checked and returned FIRST: an out-of-set basis is never additionally reported as malformed.
func (o OrderingDisclosure) Validate() error {
	if !IsKnownOrderingBasis(o.Basis) {
		return ErrUnknownOrderingBasis
	}
	switch o.Basis {
	case OrderingCorrespondenceOnly:
		if len(o.Boundary) > 0 || len(o.Mechanism) > 0 || len(o.Relation) > 0 {
			return ErrOrderingDisclosureMalformed
		}
	case OrderingSingleBoundary:
		if len(o.Boundary) == 0 || len(o.Mechanism) > 0 || len(o.Relation) > 0 {
			return ErrOrderingDisclosureMalformed
		}
	case OrderingExternalMechanism:
		if len(o.Boundary) > 0 || len(o.Mechanism) == 0 {
			return ErrOrderingDisclosureMalformed
		}
	}
	return nil
}

// TermDisposition is the embeddable group {1: kind, ?2: source} (design.md §26.4). kind is carried
// as a plain uint on the wire (the CDDL does not close its value set the way ordering-basis does),
// so TermDisposition itself validates no closed set — only naalp-decision-record's own field-6 key
// set (the record's own field numbers) is fail-closed (TermDispositionMalformed).
type TermDisposition struct {
	Kind   uint64
	Source []byte // present iff Kind == TermReported
}

func (t TermDisposition) toCBOR() cbor.Map {
	m := cbor.Map{{K: cbor.Uint(1), V: cbor.Uint(t.Kind)}}
	if len(t.Source) > 0 {
		m = append(m, cbor.Pair{K: cbor.Uint(2), V: cbor.Bstr(t.Source)})
	}
	return m
}

func termDispositionFromCBOR(v cbor.Value) (TermDisposition, bool) {
	m, ok := v.(cbor.Map)
	if !ok {
		return TermDisposition{}, false
	}
	kindV, ok1 := field(m, 1)
	if !ok1 {
		return TermDisposition{}, false
	}
	kind, ok1t := kindV.(cbor.Uint)
	if !ok1t {
		return TermDisposition{}, false
	}
	var source []byte
	if v2, present := field(m, 2); present {
		bs, ok := v2.(cbor.Bstr)
		if !ok {
			return TermDisposition{}, false
		}
		source = []byte(bs)
	}
	return TermDisposition{Kind: uint64(kind), Source: source}, true
}
