// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// decision_record.go implements S1 — naalp-decision-record, the full governed-decision
// accountability record (design.md §26.4; spec/naalp-draft-01.cddl `naalp-decision-record`).
//
// A DecisionRecord is the SIGNED record a governed decision point emits that it decided about an
// action under a CLOSED, uniquely-selected condition set. It carries the T/T+n accountability
// triple (§26.1): UNIQUE SELECTION (field 2, the governing set in the clear as content ids);
// GOVERNED-AT-T (field 3, the naalp-consume-receipt spent at decision time); BINDING-FIXED-BY-T
// (established off-record by inclusion under a witnessed naalp-checkpoint-root, checkpoint.go).
// The record is deliberately CLOCK-FREE: it carries no claimed timestamp anywhere in its own body;
// both time properties are POSITIONAL, never a self-asserted timestamp. It introduces no new
// envelope, encoding, signature, or identity mechanism: an ordinary N-AALP signed body
// (COSE_Sign1, §4), reusing the closed gw-decision outcome vocabulary (gateway.go) unchanged.
//
// Following gateway.go's ParseDecision/VerifyDecision split: ParseDecisionRecord reconstructs the
// record from its body bytes ALONE and performs only STRUCTURAL checks (field presence and CBOR
// type); it does NOT validate the outcome against the closed gw-decision set, the ordering
// disclosure's well-formedness, the deny/hold-with-consume rule, or the terms key set — those are
// ValidateDecisionRecord's job, exactly as gateway.go's own outcome-closed-set check is
// VerifyDecision's job, not ParseDecision's.
//
// Every check is fail-closed (§15): a failing object is rejected whole, returns its named error,
// and causes no state change.
package gateway

import (
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// Named, fail-closed errors (§26.8). A bad signature is the existing cose.ErrBadSignature reused
// unchanged; an unknown outcome code reuses gateway.go's existing ErrUnknownDecision
// (UnknownGatewayDecision) since naalp-decision-record's field 4 reuses the gw-decision set
// unchanged (design.md §26.4).
var (
	ErrDecisionRecordMalformed  = &cose.Error{Kind: "DecisionMalformed", Msg: "object is not a well-formed N-AALP decision-record body, or a deny/hold outcome carries a consume reference"}
	ErrTermDispositionMalformed = &cose.Error{Kind: "TermDispositionMalformed", Msg: "a terms map key is outside the record's own field set 1..5"}
)

// DecisionRecord is the governed-decision accountability record (design.md §26.4).
type DecisionRecord struct {
	Action      []byte              // content id of the action decided about
	Governing   [][]byte            // the closed governing condition set, content ids, in the clear; may be empty
	Consume     []byte              // OPTIONAL field 3: content id of the consume-receipt spent at decision time; len==0 == absent
	Outcome     uint64              // field 4: allow/deny/hold (reuses the closed gw-decision set)
	Ordering    OrderingDisclosure  // field 5, MANDATORY: no silent default — every record states its ordering basis
	Terms       map[uint64]TermDisposition // OPTIONAL field 6: per-term observed/reported, keyed by this record's OWN field numbers 1..5; nil/empty == absent
	Enforcement uint64              // OPTIONAL field 7: enforced(1)/advised(2); 0 == absent (0 is not a member of the closed set)
}

// governingArr converts a governing-set slice to a CBOR array of byte strings ([* bstr]).
func governingArr(gs [][]byte) cbor.Arr {
	arr := make(cbor.Arr, len(gs))
	for i, g := range gs {
		arr[i] = cbor.Bstr(g)
	}
	return arr
}

// Bytes is the deterministic-CBOR encoding {1:action, 2:governing[], ?3:consume, 4:outcome,
// 5:ordering, ?6:terms, ?7:enforcement}. Fields 3/6/7 are OMITTED when absent (Consume empty,
// Terms empty, Enforcement zero) — the omit-when-absent precedent (naalp-approval ?6:audience).
func (d DecisionRecord) Bytes() []byte {
	m := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(d.Action)},
		{K: cbor.Uint(2), V: governingArr(d.Governing)},
	}
	if len(d.Consume) > 0 {
		m = append(m, cbor.Pair{K: cbor.Uint(3), V: cbor.Bstr(d.Consume)})
	}
	m = append(m,
		cbor.Pair{K: cbor.Uint(4), V: cbor.Uint(d.Outcome)},
		cbor.Pair{K: cbor.Uint(5), V: d.Ordering.toCBOR()},
	)
	if len(d.Terms) > 0 {
		tm := make(cbor.Map, 0, len(d.Terms))
		for k, td := range d.Terms {
			tm = append(tm, cbor.Pair{K: cbor.Uint(k), V: td.toCBOR()})
		}
		m = append(m, cbor.Pair{K: cbor.Uint(6), V: tm})
	}
	if d.Enforcement != 0 {
		m = append(m, cbor.Pair{K: cbor.Uint(7), V: cbor.Uint(d.Enforcement)})
	}
	b, _ := cbor.Encode(m)
	return b
}

// Head is the record's SHA-384 head (48 octets).
func (d DecisionRecord) Head() []byte { return head(d.Bytes()) }

// ID is the record's T1 content-id (50 octets).
func (d DecisionRecord) ID() []byte { return contentID(d.Bytes()) }

// ParseDecisionRecord reconstructs a DecisionRecord from its body bytes alone. It performs ONLY
// structural checks (mandatory-field presence and CBOR type); it does NOT validate the outcome
// against the closed gw-decision set, the ordering disclosure's basis-conditioned well-formedness,
// the deny/hold-with-consume rule, or the terms key set — see ValidateDecisionRecord. Fail-closed
// on any malformed shape (DecisionMalformed).
func ParseDecisionRecord(b []byte) (DecisionRecord, error) {
	m, ok := decodeMap(b)
	if !ok {
		return DecisionRecord{}, ErrDecisionRecordMalformed
	}
	action, ok1 := bstrField(m, 1)
	govV, ok2 := field(m, 2)
	if !ok1 || !ok2 {
		return DecisionRecord{}, ErrDecisionRecordMalformed
	}
	govArr, ok := govV.(cbor.Arr)
	if !ok {
		return DecisionRecord{}, ErrDecisionRecordMalformed
	}
	governing := make([][]byte, len(govArr))
	for i, e := range govArr {
		bs, ok := e.(cbor.Bstr)
		if !ok {
			return DecisionRecord{}, ErrDecisionRecordMalformed
		}
		governing[i] = []byte(bs)
	}
	var consume []byte
	if cv, present := field(m, 3); present {
		bs, ok := cv.(cbor.Bstr)
		if !ok {
			return DecisionRecord{}, ErrDecisionRecordMalformed
		}
		consume = []byte(bs)
	}
	outcome, ok4 := uintField(m, 4)
	if !ok4 {
		return DecisionRecord{}, ErrDecisionRecordMalformed
	}
	ordV, ok5 := field(m, 5)
	if !ok5 {
		return DecisionRecord{}, ErrDecisionRecordMalformed
	}
	ordering, ok := orderingFromCBOR(ordV)
	if !ok {
		return DecisionRecord{}, ErrDecisionRecordMalformed
	}
	var terms map[uint64]TermDisposition
	if tv, present := field(m, 6); present {
		tm, ok := tv.(cbor.Map)
		if !ok {
			return DecisionRecord{}, ErrDecisionRecordMalformed
		}
		terms = make(map[uint64]TermDisposition, len(tm))
		for _, p := range tm {
			ku, ok := p.K.(cbor.Uint)
			if !ok {
				return DecisionRecord{}, ErrDecisionRecordMalformed
			}
			td, ok := termDispositionFromCBOR(p.V)
			if !ok {
				return DecisionRecord{}, ErrDecisionRecordMalformed
			}
			terms[uint64(ku)] = td
		}
	}
	var enforcement uint64
	if ev, present := field(m, 7); present {
		eu, ok := ev.(cbor.Uint)
		if !ok {
			return DecisionRecord{}, ErrDecisionRecordMalformed
		}
		enforcement = uint64(eu)
	}
	return DecisionRecord{
		Action: action, Governing: governing, Consume: consume, Outcome: outcome,
		Ordering: ordering, Terms: terms, Enforcement: enforcement,
	}, nil
}

// validDecisionRecordTermKey reports whether k is one of the record's own field numbers 1..5 — the
// only valid keys for the field-6 terms map (design.md §26.4; TermDispositionMalformed otherwise).
func validDecisionRecordTermKey(k uint64) bool { return k >= 1 && k <= 5 }

// ValidateDecisionRecord performs the semantic, closed-set, and native well-formedness checks
// ParseDecisionRecord deliberately does not (mirroring gateway.go's Parse/Verify split):
//
//  1. Outcome must be in the closed gw-decision set (UnknownGatewayDecision).
//  2. Ordering must satisfy its basis-conditioned well-formedness rule (UnknownOrderingBasis /
//     OrderingDisclosureMalformed, §26.3) — checked BEFORE the deny/hold-consume rule so a record
//     whose ordering is itself malformed is never additionally reported as a consume violation.
//  3. A deny/hold outcome carrying a field-3 consume reference is rejected in full
//     (DecisionMalformed) — nothing was consumed, so a value here would assert authority spent for
//     an action the record's own outcome says was not taken.
//  4. Every terms map key must be one of the record's own field numbers 1..5
//     (TermDispositionMalformed) — the map discloses provenance of the record's OWN terms, not an
//     arbitrary side channel.
func ValidateDecisionRecord(d DecisionRecord) error {
	if !IsKnownDecision(d.Outcome) {
		return ErrUnknownDecision
	}
	if err := d.Ordering.Validate(); err != nil {
		return err
	}
	if d.Outcome != DecisionAllow && len(d.Consume) > 0 {
		return ErrDecisionRecordMalformed
	}
	for k := range d.Terms {
		if !validDecisionRecordTermKey(k) {
			return ErrTermDispositionMalformed
		}
	}
	return nil
}

// SignDecisionRecord produces the tagged COSE_Sign1 object over the record body, signed by the
// governed decision point.
func SignDecisionRecord(d DecisionRecord, s cose.Signer) ([]byte, error) { return cose.Sign1(s, d.Bytes()) }

// ResolvedDecisionRecord is a DecisionRecord that has passed signature verification and full
// semantic validation.
type ResolvedDecisionRecord struct {
	Action      []byte
	Governing   [][]byte
	Consume     []byte
	Outcome     uint64
	Ordering    OrderingDisclosure
	Terms       map[uint64]TermDisposition
	Enforcement uint64
}

// VerifyDecisionRecord verifies a decision record end-to-end: (1) the signed object under the
// profile with real crypto (cose.Verify1); (2) structural reconstruction (ParseDecisionRecord); and
// (3) full semantic validation (ValidateDecisionRecord). It takes no serving-party or connection
// identity — the authority is the signature over the bytes, mirroring VerifyDecision/R-GW-3. Any
// failure returns its named error and resolves nothing (fail-closed).
func VerifyDecisionRecord(obj []byte, profile int, producerV cose.Verifier) (ResolvedDecisionRecord, error) {
	if err := cose.Verify1(profile, producerV, obj); err != nil {
		return ResolvedDecisionRecord{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return ResolvedDecisionRecord{}, err
	}
	d, err := ParseDecisionRecord(payload)
	if err != nil {
		return ResolvedDecisionRecord{}, err
	}
	if err := ValidateDecisionRecord(d); err != nil {
		return ResolvedDecisionRecord{}, err
	}
	return ResolvedDecisionRecord{
		Action:      append([]byte(nil), d.Action...),
		Governing:   append([][]byte(nil), d.Governing...),
		Consume:     append([]byte(nil), d.Consume...),
		Outcome:     d.Outcome,
		Ordering:    d.Ordering,
		Terms:       d.Terms,
		Enforcement: d.Enforcement,
	}, nil
}
