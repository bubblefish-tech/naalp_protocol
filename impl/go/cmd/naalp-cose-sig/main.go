// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command naalp-cose-sig prints the hex of a deterministic COSE_Sign1 object over a fixed
// payload ({7:0}), using an ML-DSA-65 key derived from the 32-byte seed passed as the
// first argument. It is the Go half of the cross-language byte-parity demonstration
// (R-16.2): scripts/verify.sh runs this and the Rust `naalp_cose_sig` example with the
// same NIST keyGen seed and asserts they print identical bytes.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: naalp-cose-sig <seed-hex-32-bytes>")
		os.Exit(2)
	}
	seed, err := hex.DecodeString(os.Args[1])
	if err != nil || len(seed) != 32 {
		fmt.Fprintln(os.Stderr, "seed must be 32 bytes of hex")
		os.Exit(2)
	}
	var s [32]byte
	copy(s[:], seed)
	_, sk := mldsa65.NewKeyFromSeed(&s)
	obj, err := cose.Sign1(cose.MLDSA65Signer{SK: sk}, []byte{0xa1, 0x07, 0x00})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(obj))
}
