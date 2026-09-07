// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package cbor

import (
	"bytes"
	"testing"
)

// nestedArraysCBOR returns canonical CBOR for k single-element arrays wrapping a zero
// scalar: 0x81 (array of one) repeated k times, then 0x00. Decoding it, the outermost
// array is at depth 1 and the innermost scalar is at depth k+1.
func nestedArraysCBOR(k int) []byte {
	b := bytes.Repeat([]byte{0x81}, k)
	return append(b, 0x00)
}

// TestDecodeBoundedDepth pins the nesting-depth counter (design.md §3.4, R7): the
// outermost item is depth 1, and DecodeBounded rejects the first item at depth
// maxDepth+1 with a DepthExceeded error, before it is materialized. The unbounded
// Decode path still accepts the same structure, so the bound is what does the work.
func TestDecodeBoundedDepth(t *testing.T) {
	const d = 3

	// deepest scalar at depth d (k = d-1): accepted at maxDepth=d.
	atLimit := nestedArraysCBOR(d - 1)
	if _, err := DecodeBounded(atLimit, d); err != nil {
		t.Fatalf("deepest item at depth %d should decode at maxDepth=%d, got %v", d, d, err)
	}

	// deepest scalar at depth d+1 (k = d): rejected DepthExceeded at maxDepth=d.
	over := nestedArraysCBOR(d)
	_, err := DecodeBounded(over, d)
	ce, ok := err.(*Error)
	if !ok || ce.Kind != "DepthExceeded" {
		t.Fatalf("deepest item at depth %d should be DepthExceeded at maxDepth=%d, got %v", d+1, d, err)
	}

	// The unbounded path accepts the same over-depth structure: the bound, not another
	// check, is what rejected it above.
	if _, err := Decode(over); err != nil {
		t.Fatalf("unbounded Decode should accept the depth-%d structure, got %v", d+1, err)
	}
}

// TestDecodeBoundsArrayMapCountByRemainingInput pins the array/map resource-bound decoder
// hardening (design.md §3.4 (R7); RFC 8949 §10 decoder-memory guard): an array/map header's
// declared element/pair count is rejected -- BEFORE any pre-allocation -- whenever it exceeds
// what the remaining input can possibly satisfy (an item needs >=1 byte; a map pair needs >=2,
// one each for its key and its value head). This is the array/map counterpart of the pre-existing
// byte/text-string length check a few lines above in decode(); its absence let a single ~9-byte
// message declare an arbitrarily large element count and either crash the runtime's own overflow
// guard (recoverable panic: "makeslice: cap out of range") or, for a count below that guard but
// still far larger than the input, drive a real multi-gigabyte allocation attempt -- the
// decoder-memory-exhaustion class RFC 8949 §10 names and design.md §3.4 (R7) exists to guard
// against. Boundary pairs throughout: AT the limit decodes; ONE past it is rejected -- so the
// check itself, not something else, is what does the rejecting (mutation survival).
func TestDecodeBoundsArrayMapCountByRemainingInput(t *testing.T) {
	// Array AT the boundary: a header declaring exactly as many items as fit (1 byte/item,
	// four single-byte uints) decodes cleanly.
	atLimit := []byte{0x84, 0x00, 0x00, 0x00, 0x00}
	if _, err := Decode(atLimit); err != nil {
		t.Fatalf("array count == remaining bytes should decode, got %v", err)
	}

	// Array ONE past the boundary: declaring one more item than the input can hold is
	// rejected outright, not merely truncated mid-decode.
	over := []byte{0x85, 0x00, 0x00, 0x00, 0x00} // count=5, only four bytes follow
	_, err := Decode(over)
	if ce, ok := err.(*Error); !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("array count > remaining bytes should be NonCanonical, got %v", err)
	}

	// Map AT the boundary: two pairs (distinct ascending keys 0x00 < 0x01, so the canonical-
	// order/duplicate check does not itself reject this) need exactly 4 bytes (>=2 each).
	mapAtLimit := []byte{0xa2, 0x00, 0x00, 0x01, 0x00}
	if _, err := Decode(mapAtLimit); err != nil {
		t.Fatalf("map count == remaining bytes/2 should decode, got %v", err)
	}

	// Map ONE past the boundary: 3 pairs need >=6 bytes; only 4 remain.
	overMap := []byte{0xa3, 0x00, 0x00, 0x00, 0x00}
	_, err = Decode(overMap)
	if ce, ok := err.(*Error); !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("map count > remaining bytes/2 should be NonCanonical, got %v", err)
	}

	// The pathological inputs that motivated this test: a maximal 8-byte count field
	// (0xFFFFFFFFFFFFFFFF elements/pairs) over a 9-byte message must be rejected -- never
	// panic, never attempt to pre-allocate anything close to that count. These two cases are
	// the ones actually SENSITIVE to the bound check's removal: for the small boundary cases
	// above, decode()'s own recursive end-of-input check happens to also reject a truncated
	// structure once the loop runs out of bytes, so those alone would not catch the bound
	// check going missing. Only a count large enough to overflow the runtime's own makeslice
	// size computation (or, below that, drive a real multi-gigabyte allocation attempt) is
	// where a missing front-loaded bound actually differs in observable behaviour -- which is
	// exactly the amplification vulnerability this bound exists to close.
	hugeArr := []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	_, err = DecodeBounded(hugeArr, 16)
	if ce, ok := err.(*Error); !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("maximal array count over a 9-byte message should be NonCanonical (never panic), got %v", err)
	}

	hugeMap := []byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	_, err = DecodeBounded(hugeMap, 16)
	if ce, ok := err.(*Error); !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("maximal map count over a 9-byte message should be NonCanonical (never panic), got %v", err)
	}
}
