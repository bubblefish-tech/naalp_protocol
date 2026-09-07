// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package main

import "testing"

// TestNumEqualExact64Bit pins R12 (NAALP-01-03): a 64-bit counter carried as a decimal string
// compares to an integer-valued expectation EXACTLY, never through float64.
//
// The load-bearing, mutation-surviving case is exactStringDiffersByOneAbove2p53: the expected
// value 2^53 and the actual string "9007199254740993" (2^53+1) are DIFFERENT integers, but
// strconv.ParseFloat("9007199254740993") rounds to 9007199254740992.0, so the earlier float-only
// string branch returned true for two different counters. This test fails against that prior
// implementation and passes only against the exact-integer branch.
func TestNumEqualExact64Bit(t *testing.T) {
	const twoTo53 = float64(1 << 53) // 9007199254740992, exactly representable in float64
	cases := []struct {
		name string
		a    float64
		b    interface{}
		want bool
	}{
		{"exactStringDiffersByOneAbove2p53", twoTo53, "9007199254740993", false}, // the mutation witness
		{"exactStringEqualAt2p53", twoTo53, "9007199254740992", true},
		{"smallStringEqual", 5, "5", true},
		{"smallStringUnequal", 5, "6", false},
		{"smallFloatEqual", 5, float64(5), true},
		{"fractionalStringFallbackEqual", 1.5, "1.5", true},
		{"fractionalStringFallbackUnequal", 1.5, "1.6", false},
		{"uint64MaxStringCannotMatchSmall", 5, "18446744073709551615", false},
		{"nonNumericStringUnequal", 5, "abc", false},
		{"unsupportedTypeUnequal", 5, []interface{}{1.0}, false},
	}
	for _, c := range cases {
		if got := numEqual(c.a, c.b); got != c.want {
			t.Errorf("%s: numEqual(%v, %v) = %v, want %v", c.name, c.a, c.b, got, c.want)
		}
	}
}
