// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package envelope

import (
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
)

// ProducingBoundaryKey is the ext extension key under which an object OPTIONALLY carries a per-object
// producing-boundary disclosure (design.md §2.5.4, NA-IETF-1): the trust boundary that emitted the
// object and whether that boundary OBSERVED the event it describes first-hand or is RELAYING a report
// of it. It lives in the NON-CRITICAL ext map (field 11): a verifier that does not understand it, or
// that reads a malformed value, ignores the entry and the object still verifies (may-ignore). Because
// ext (field 11) is part of the signed body/payload, the disclosure is covered by the SIGNER's own
// COSE_Sign1 signature — it is a SELF-ASSERTED claim. 15 is the next free ext/cext key: it collides
// with neither the safety-label ext key 1 (§6.4), the recheck ext/cext key 13 (§2.5.1), nor the
// signer-counter ext key 14 (§2.5.2). Byte-identical to impl/rust.
//
// The disclosure establishes record-order / observational domain, NOT cross-boundary event
// precedence (# Security Considerations): each boundary's observational domain is authoritative only
// within itself. It is a NON-CRITICAL field only — placing it in the critical cext map (field 12) is
// an unrecognized critical extension and is rejected fail-closed (UnknownCriticalExt), because a
// disclosure is never a must-understand verification gate.
const ProducingBoundaryKey = 15

// The producing-boundary kind (design.md §2.5.4): a closed enum naming whether the emitting boundary
// witnessed the event directly or is relaying a report of it.
const (
	ProducingBoundaryObserved = 1 // this boundary witnessed the event directly (first-hand)
	ProducingBoundaryReported = 2 // this boundary is relaying a report it did not witness
)

// The producing-boundary value sub-map keys (design.md §2.5.4).
const (
	pbFieldBoundary  = 1 // bstr — the emitting trust boundary (party id)
	pbFieldKind      = 2 // 1 observed / 2 reported
	pbFieldReporting = 3 // bstr — report origin; present iff kind = reported
)

// ProducingBoundary is a decoded producing-boundary disclosure (ProducingBoundaryKey, §2.5.4).
// Boundary is the emitting trust boundary (the same bstr party-id form as Object.Signer). Kind is
// ProducingBoundaryObserved or ProducingBoundaryReported. Reporting names the report origin and is
// non-nil ONLY when Kind is ProducingBoundaryReported (an observer relays from no one).
type ProducingBoundary struct {
	Boundary  []byte
	Kind      uint64
	Reporting []byte
}

// extGetValue returns the raw value under key in a CBOR map (ext or cext), reporting present when the
// key exists regardless of the value's type; the caller checks the type.
func extGetValue(m cbor.Map, key uint64) (cbor.Value, bool) {
	for _, p := range m {
		if k, ok := p.K.(cbor.Uint); ok && uint64(k) == key {
			return p.V, true
		}
	}
	return nil, false
}

// ProducingBoundary returns the producing-boundary disclosure the object names (ProducingBoundaryKey,
// §2.5.4): present is true iff a WELL-FORMED disclosure is carried in the non-critical ext map
// (field 11) — a non-empty boundary (key 1), a kind (key 2) in {observed, reported}, and a
// reporting-boundary (key 3) absent unless the kind is reported. A malformed value is IGNORED
// (present == false) and the object still verifies (may-ignore). The field is OPTIONAL: an absent
// disclosure (present == false) is valid. An unrecognized sub-key is ignored (may-ignore) and does
// not by itself make an otherwise well-formed value malformed.
func (o *Object) ProducingBoundary() (pb ProducingBoundary, present bool) {
	v, ok := extGetValue(o.Ext, ProducingBoundaryKey)
	if !ok {
		return ProducingBoundary{}, false
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return ProducingBoundary{}, false
	}
	var boundary, reporting []byte
	var kind uint64
	var haveBoundary, haveKind, haveReporting bool
	for _, p := range m {
		k, ok := p.K.(cbor.Uint)
		if !ok {
			return ProducingBoundary{}, false
		}
		switch uint64(k) {
		case pbFieldBoundary:
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return ProducingBoundary{}, false
			}
			boundary = []byte(b)
			haveBoundary = true
		case pbFieldKind:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return ProducingBoundary{}, false
			}
			kind = uint64(u)
			haveKind = true
		case pbFieldReporting:
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return ProducingBoundary{}, false
			}
			reporting = []byte(b)
			haveReporting = true
		default:
			// an unrecognized sub-key: may-ignore. It does not surface a disclosure of its own and
			// does not invalidate a well-formed {boundary, kind, reporting?} core.
		}
	}
	// well-formedness (§2.5.4). Any failure returns present == false (may-ignore), never an error.
	if !haveBoundary || len(boundary) == 0 {
		return ProducingBoundary{}, false // no boundary named
	}
	if !haveKind || (kind != ProducingBoundaryObserved && kind != ProducingBoundaryReported) {
		return ProducingBoundary{}, false // absent or out-of-enum kind
	}
	if haveReporting && kind != ProducingBoundaryReported {
		return ProducingBoundary{}, false // a reporting-boundary under observed: an observer relays from no one
	}
	pb = ProducingBoundary{Boundary: boundary, Kind: kind}
	if haveReporting {
		pb.Reporting = reporting
	}
	return pb, true
}

// SetProducingBoundary names pb as this object's producing-boundary disclosure in the NON-CRITICAL
// ext map (field 11), covered by the signer's COSE_Sign1 signature. It creates the ext carrier if
// absent and leaves any other extension entries intact. The reporting-boundary is emitted ONLY when
// non-nil AND the kind is reported, so a caller cannot accidentally emit a malformed
// observed-with-reporting disclosure (an observer relays from no one). Sub-map keys are appended in
// ascending order; Encode emits canonical CBOR regardless, so the object stays deterministic.
func (o *Object) SetProducingBoundary(pb ProducingBoundary) {
	sub := cbor.Map{
		{K: cbor.Uint(pbFieldBoundary), V: cbor.Bstr(pb.Boundary)},
		{K: cbor.Uint(pbFieldKind), V: cbor.Uint(pb.Kind)},
	}
	if pb.Reporting != nil && pb.Kind == ProducingBoundaryReported {
		sub = append(sub, cbor.Pair{K: cbor.Uint(pbFieldReporting), V: cbor.Bstr(pb.Reporting)})
	}
	entry := cbor.Pair{K: cbor.Uint(ProducingBoundaryKey), V: sub}
	for i := range o.Ext {
		if k, ok := o.Ext[i].K.(cbor.Uint); ok && uint64(k) == ProducingBoundaryKey {
			o.Ext[i] = entry
			return
		}
	}
	o.Ext = append(o.Ext, entry)
}
