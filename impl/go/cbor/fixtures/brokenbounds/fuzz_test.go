// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package brokenbounds

import "testing"

// FuzzDecodeCountPrefixed is the sensitivity fixture scripts/gates/gate_fuzz_decoder_bounds.py
// runs (with a short, bounded -fuzztime) as its self-test. Its seed is DELIBERATELY benign (a
// zero count, which decodes cleanly) rather than the crash-triggering input itself: a fuzz
// target's `f.Add` seeds are replayed as ordinary subtests by a bare `go test ./...` with no
// -fuzz flag, and this package must never fail the repository's normal, unfiltered test run
// (CLAUDE.md's verification recipe) merely because it exists -- fixing that would leave the
// crash-finding job to committed testdata/fuzz corpus entries, which the same bare `go test
// ./...` would ALSO replay, reintroducing the identical problem. So this fixture stays
// deterministically SAFE under any invocation that does not pass -fuzz, and the crash is only
// ever found by the gate's own short, genuinely-random -fuzztime run -- exercising the exact
// same "go test -fuzz" invocation + exit-code + panic-output classification the gate applies
// to the three real targets, just against a target that is trivially, deliberately
// exploitable (any 8+-byte input with a non-trivial high byte overflows) so the crash is found
// in well under a second of real fuzzing, not merely by seed replay.
func FuzzDecodeCountPrefixed(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // count=0, decodes cleanly
	f.Fuzz(func(t *testing.T, data []byte) {
		DecodeCountPrefixed(data)
	})
}
