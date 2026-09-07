// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package envelope

import (
	"bytes"
	"sort"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
)

// SignerCounterKey is the ext extension key under which an object OPTIONALLY carries a forward-only
// per-signer counter (design.md §2.5.2, NAALP-REQ-120 — the per-signer counter). The value is a
// forward-only position (a uint) the signer increments on each object. It lives in the NON-CRITICAL
// ext map (field 11): a verifier that does not perform duplication-detection ignores it and the
// object still verifies (may-ignore). Because ext (field 11) is part of the signed body/payload, the
// counter is covered by the SIGNER's own COSE_Sign1 signature — the deliberate contrast with the T1.5
// consume-receipt position, which is signed by the LEDGER key. 14 is the next free ext/cext key: it
// does not collide with the safety-label ext key 1 (§6.4) or the recheck ext/cext key 13 (T1.3).
// Byte-identical to impl/rust.
//
// The counter is DETECTION, not prevention (NAALP-REQ-120; # Security Considerations): a single
// self-authored sequence proves nothing. It is a NON-CRITICAL field only — placing it in the critical
// cext map (field 12) is an unrecognized critical extension and is rejected fail-closed
// (UnknownCriticalExt, the existing §2.5 rule), because a detection aid is never a must-understand
// verification gate.
const SignerCounterKey = 14

// SignerCounter returns the forward-only per-signer position the object names (SignerCounterKey,
// §2.5.2): present is true iff a counter is named in the non-critical ext map (field 11) as a uint.
// The field is OPTIONAL — absent (present == false) is valid. present is keyed on the KEY being
// present, not on the value: a present counter of value 0 returns (0, true).
func (o *Object) SignerCounter() (seq uint64, present bool) {
	return cextGetUint(o.Ext, SignerCounterKey)
}

// SetSignerCounter names seq as this object's forward-only per-signer position in the NON-CRITICAL
// ext map (field 11), covered by the signer's COSE_Sign1 signature. It creates the ext carrier if
// absent and leaves any other extension entries intact. The counter is deliberately never placed in
// the critical cext map (it is detection, not a verification gate).
func (o *Object) SetSignerCounter(seq uint64) {
	entry := cbor.Pair{K: cbor.Uint(SignerCounterKey), V: cbor.Uint(seq)}
	for i := range o.Ext {
		if k, ok := o.Ext[i].K.(cbor.Uint); ok && uint64(k) == SignerCounterKey {
			o.Ext[i] = entry
			return
		}
	}
	o.Ext = append(o.Ext, entry)
}

// DuplicationFinding surfaces one detected per-signer counter conflict: two or more DISTINCT objects
// (distinct content ids) from the SAME signer id that carry the SAME forward-only counter value.
// A forward-only counter binds each value to at most one object, so a value bound to >= 2 distinct
// objects is the observable fingerprint of the key incrementing in two places (key duplication).
// The finding surfaces BOTH sides of the contradiction: the reused Counter value and every
// conflicting content id (IDs, ascending by bytes) — never a single flag with the evidence hidden.
type DuplicationFinding struct {
	Signer  []byte   // the signer id whose forward-only counter was reused
	Counter uint64   // the reused forward-only counter value
	IDs     [][]byte // the content ids of the >= 2 conflicting objects, ascending by bytes
}

// DetectSignerDuplication scans a SET of PRESENTED objects for per-signer counter reuse. This is the
// whole point of the field, and it is DETECTION, not prevention (NAALP-REQ-120): it flags a signer
// id ONLY when two conflicting sequences from that signer physically MEET in the presented set — a
// counter value bound to >= 2 distinct content ids by one signer. Given only ONE object per value
// (one sequence) it returns no findings; the second conflicting object must be present, unsuppressed,
// for the duplication to become provable. Objects with no counter do not participate. Output is
// deterministic (findings ordered by signer id then counter; ids within a finding ascending).
//
// It operates over the SET, never per object: a per-object boolean could never express "these two
// distinct objects reuse one position," and a single self-authored counter proves nothing on its own.
func DetectSignerDuplication(objs []*Object) []DuplicationFinding {
	// signerKey -> counter -> (content-id-string -> content-id-bytes), a set that de-dups a
	// byte-identical re-presentation (one content id twice) so it is NOT a conflict.
	groups := make(map[string]map[uint64]map[string][]byte)
	signerBytes := make(map[string][]byte)
	for _, o := range objs {
		seq, present := o.SignerCounter()
		if !present {
			continue // a counter-less object does not participate in detection
		}
		id, err := o.ContentID()
		if err != nil {
			continue // a body that cannot be canonically encoded cannot be a presented object
		}
		sk := string(o.Signer)
		signerBytes[sk] = o.Signer
		if groups[sk] == nil {
			groups[sk] = make(map[uint64]map[string][]byte)
		}
		if groups[sk][seq] == nil {
			groups[sk][seq] = make(map[string][]byte)
		}
		groups[sk][seq][string(id)] = id
	}

	signers := make([]string, 0, len(groups))
	for sk := range groups {
		signers = append(signers, sk)
	}
	sort.Strings(signers)

	var findings []DuplicationFinding
	for _, sk := range signers {
		byCounter := groups[sk]
		counters := make([]uint64, 0, len(byCounter))
		for c := range byCounter {
			counters = append(counters, c)
		}
		sort.Slice(counters, func(i, j int) bool { return counters[i] < counters[j] })
		for _, c := range counters {
			idset := byCounter[c]
			// A (signer, counter) that binds two-or-more DISTINCT content ids is a detected
			// duplication. The >= 2 requirement is the detection-requires-both invariant: relax it
			// to >= 1 and a single sequence would flag (prevention theatre) — the mutation the
			// "one sequence alone -> not flagged" test is built to catch.
			if len(idset) < 2 {
				continue
			}
			ids := make([][]byte, 0, len(idset))
			for _, id := range idset {
				ids = append(ids, id)
			}
			sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i], ids[j]) < 0 })
			findings = append(findings, DuplicationFinding{Signer: signerBytes[sk], Counter: c, IDs: ids})
		}
	}
	return findings
}
