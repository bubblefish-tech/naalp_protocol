// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package approval

// R-TDCS-3 (design.md §25, C22) — the party-visible coarse refusal object. A refusal returned to the
// authenticated party carries ONLY a single value from a closed vocabulary and the content id of the
// full signed record that carries the discriminating detail — a reference, not the reason. The detail
// exists, is signed, and is auditor-resolvable through the record channel, but never reaches the
// adversary-facing surface, so repeated refusals cannot serve an adaptive party as an oracle. A
// party-visible refusal that carries discriminating detail, or omits the record content id, is a
// RefusalDetailLeak; an outcome outside the closed set is UnknownRefusalOutcome.

import (
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// The closed refusal-outcome set (CDDL refusal-outcome).
const (
	RefusalDenied       uint64 = 0 // the action is refused
	RefusalHeld         uint64 = 1 // the action requires a further step not yet taken
	RefusalUnverifiable uint64 = 2 // required evidence did not verify
)

var refusalOutcomeName = map[uint64]string{
	RefusalDenied: "denied", RefusalHeld: "held", RefusalUnverifiable: "unverifiable",
}

// IsKnownRefusalOutcome reports whether code is in the closed refusal-outcome set.
func IsKnownRefusalOutcome(code uint64) bool { _, ok := refusalOutcomeName[code]; return ok }

var (
	ErrUnknownRefusalOutcome = &cose.Error{Kind: "UnknownRefusalOutcome", Msg: "refusal outcome is outside the closed set denied/held/unverifiable"}
	ErrRefusalDetailLeak     = &cose.Error{Kind: "RefusalDetailLeak", Msg: "party-visible refusal carries discriminating detail or omits the record content id"}
)

// Refusal is the party-visible coarse refusal body {1: outcome, 2: record}. Outcome is the closed-set
// coarse outcome; Record is the T1 content id of the full signed record carrying the detail.
type Refusal struct {
	Outcome uint64 // denied / held / unverifiable (closed set)
	Record  []byte // content id of the full signed record carrying the discriminating detail
}

// Bytes is the deterministic-CBOR encoding {1: outcome, 2: record}.
func (r Refusal) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(r.Outcome)},
		{K: cbor.Uint(2), V: cbor.Bstr(r.Record)},
	})
	return b
}

// RefusalFromRecord builds the party-visible refusal for a full signed record: it carries the coarse
// outcome and the content id of fullRecord, and NOTHING drawn from inside fullRecord — the
// discriminating detail stays in the record, referenced only by its id. This is the coarse-to-party
// split the closure property requires (R-TDCS-3).
func RefusalFromRecord(outcome uint64, fullRecord []byte) Refusal {
	return Refusal{Outcome: outcome, Record: contentID(fullRecord)}
}

// ParseRefusal reconstructs a Refusal from its body bytes, enforcing that a party-visible refusal
// carries ONLY {outcome, record} and nothing more (R-TDCS-3). It rejects, fail-closed: a malformed
// body, any key other than 1 and 2, a missing or empty record id (RefusalDetailLeak — discriminating
// detail leaked, or the auditor reference dropped), and an outcome outside the closed set
// (UnknownRefusalOutcome). It authorizes nothing.
func ParseRefusal(b []byte) (Refusal, error) {
	v, err := cbor.Decode(b)
	if err != nil {
		return Refusal{}, ErrRefusalDetailLeak
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return Refusal{}, ErrRefusalDetailLeak
	}
	var outcome uint64
	var record []byte
	haveOutcome, haveRecord := false, false
	for _, p := range m {
		k, ok := p.K.(cbor.Uint)
		if !ok {
			return Refusal{}, ErrRefusalDetailLeak
		}
		switch uint64(k) {
		case 1:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return Refusal{}, ErrRefusalDetailLeak
			}
			outcome, haveOutcome = uint64(u), true
		case 2:
			bs, ok := p.V.(cbor.Bstr)
			if !ok {
				return Refusal{}, ErrRefusalDetailLeak
			}
			record, haveRecord = []byte(bs), true
		default:
			return Refusal{}, ErrRefusalDetailLeak // any field beyond {1,2} is leaked detail
		}
	}
	if !haveOutcome || !haveRecord || len(record) == 0 {
		return Refusal{}, ErrRefusalDetailLeak // a refusal must carry the full-record content id
	}
	if !IsKnownRefusalOutcome(outcome) {
		return Refusal{}, ErrUnknownRefusalOutcome
	}
	return Refusal{Outcome: outcome, Record: record}, nil
}
