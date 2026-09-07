// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package brokenbounds is a DELIBERATELY VULNERABLE fixture. It exists solely so
// scripts/gates/gate_fuzz_decoder_bounds.py can prove its own crash-detection machinery
// actually distinguishes "the fuzzer found a crash" from "the fuzzer found nothing" (this
// repo's _gate.py self-test contract: a gate that cannot fail is asserting nothing). It is
// NOT a copy of impl/go/cbor and is intentionally isolated from it, matching this session's
// gate_formal_attenuation_unbounded.py precedent of a small, standalone fixture rather than a
// full duplicate of the real model.
//
// It reproduces, in miniature, the exact defect CLASS impl/go/cbor.decode's array/map cases
// were fixed against this session (2026-09-04): an attacker-controlled count read straight
// from untrusted bytes, used to pre-allocate a slice with NO check against how much input
// remains. A count near the top of uint64's range panics the Go runtime's own overflow guard
// ("makeslice: cap out of range"); a count below that guard but still far larger than the
// input drives a real, disproportionate allocation attempt -- the RFC 8949 §10
// decoder-memory-exhaustion class design.md §3.4 (R7) exists to guard against.
//
// THIS FUNCTION MUST NEVER BE FIXED. Fixing it would make the gate's self-test vacuous: its
// whole job is to stay exploitable so the fuzzer (or, for a maximal-count input, even a plain
// `go test -run`) reliably finds the crash within a short, bounded, deterministic budget.
package brokenbounds

import "encoding/binary"

// DecodeCountPrefixed reads an 8-byte big-endian count, then a slice of that many bytes,
// WITHOUT checking the count against len(data) -- deliberately, see the package doc above.
func DecodeCountPrefixed(data []byte) ([]byte, bool) {
	if len(data) < 8 {
		return nil, false
	}
	n := binary.BigEndian.Uint64(data[:8])
	out := make([]byte, n) // NO bound check against len(data) -- deliberate, never fix
	copy(out, data[8:])
	return out, true
}
