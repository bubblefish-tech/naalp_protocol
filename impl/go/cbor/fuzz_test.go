// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package cbor

import "testing"

// FuzzDecodeBounded fuzzes arbitrary bytes into the untrusted-object decode path
// (design.md §3.4 (R7)). The property checked is NOT "matches an independent decoder" --
// this is the only implementation of this exact deterministic-CBOR subset, so there is no
// second decoder to differ against -- it is the resource-bound / crash-safety property RFC
// 8949 §10 exists to name: decoding arbitrary untrusted bytes must NEVER panic, and any value
// DecodeBounded does accept must actually respect the caller's maxDepth bound (walked
// post-decode, independent of whatever internal counting decode() itself did). A decoder that
// accepted an over-depth structure while claiming to have bounded it would be exactly as
// dangerous as one that panics -- it would silently defeat the caller's own defense.
//
// Seeded from impl/go/cbor/bounds_test.go's existing boundary-pair fixtures (the depth
// boundary pair, and the array/map resource-bound boundary pairs this session added) plus the
// literal pathological inputs that motivated the array/map pre-allocation bound fix.
func FuzzDecodeBounded(f *testing.F) {
	const maxDepth = 16

	seeds := [][]byte{
		{},                                           // empty input
		{0x00},                                       // a bare zero uint
		nestedArraysCBOR(maxDepth - 1),                // deepest scalar at depth==maxDepth: accepted
		nestedArraysCBOR(maxDepth),                    // deepest scalar at depth==maxDepth+1: rejected
		{0x84, 0x00, 0x00, 0x00, 0x00},                // array count AT the remaining-input limit
		{0x85, 0x00, 0x00, 0x00, 0x00},                // array count ONE past it
		{0xa2, 0x00, 0x00, 0x01, 0x00},                // map count AT the remaining-input limit
		{0xa3, 0x00, 0x00, 0x00, 0x00},                // map count ONE past it
		{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // maximal array count, tiny message
		{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // maximal map count, tiny message
		{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // maximal uint argument (8-byte form)
		{0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // maximal negative-int argument
		{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // maximal byte-string length, no data
		{0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // maximal text-string length, no data
		{0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // maximal tag number, no content
		{0xff}, // reserved/indefinite additional information (ai=31)
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := DecodeBounded(data, maxDepth)
		if err != nil {
			return // rejection is always an acceptable outcome for untrusted input
		}
		// Accepted: the decoded value's ACTUAL maximum nesting depth, walked independently
		// of decode()'s own bookkeeping, must never exceed the bound the caller asked for.
		if d := actualDepth(v); d > maxDepth {
			t.Fatalf("DecodeBounded(data, %d) accepted a value with actual depth %d: %x", maxDepth, d, data)
		}
	})
}

// actualDepth independently re-measures the maximum nesting depth of a decoded Value, by
// direct structural recursion over the returned tree -- NOT by reading any counter decode()
// itself maintained. This is the independent side of the property: DecodeBounded's OWN
// internal depth tracking is exactly the thing under test, so the oracle must not reuse it.
func actualDepth(v Value) int {
	switch t := v.(type) {
	case Arr:
		max := 0
		for _, e := range t {
			if d := actualDepth(e); d > max {
				max = d
			}
		}
		return 1 + max
	case Map:
		max := 0
		for _, p := range t {
			if d := actualDepth(p.K); d > max {
				max = d
			}
			if d := actualDepth(p.V); d > max {
				max = d
			}
		}
		return 1 + max
	case Tag:
		return 1 + actualDepth(t.Content)
	default:
		return 1
	}
}
