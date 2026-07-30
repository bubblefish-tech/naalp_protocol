// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command naalp-envelope prints the hex of a deterministic, signed N-AALP object envelope
// for a fixed worked object, using an ML-DSA-65 key derived from the 32-byte seed given as
// the first argument. It is the Go half of the C3 cross-language byte-parity check
// (R-16.2): scripts/verify.sh runs this and the Rust `naalp_envelope` example with the
// same seed and asserts identical bytes. The worked object matches tools/envelope_oracle.py.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: naalp-envelope <seed-hex-32-bytes>")
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

	o := &envelope.Object{
		Kind:    2,
		Channel: 4,
		Tier:    0,
		Signer:  []byte("SIGNER_A"),
		Created: 1785000000000,
		Effect:  2,
		Causes:  nil,
		Profile: 1,
		Body:    cbor.Tstr("hello"),
	}
	obj, err := envelope.Sign(o, cose.MLDSA65Signer{SK: sk})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(obj))
}
