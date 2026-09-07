// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command naalp-composite prints the hex of a deterministic, signed N-AALP object envelope
// carrying the opt-in LAMPS composite signature (§4.2), for a fixed worked object. The
// ML-DSA-65 key is derived from the 32-byte seed given as the first argument; the Ed25519
// key from a fixed seed. It is the Go half of the composite cross-language byte-parity check
// (R-16.2): scripts/verify.sh runs this and the Rust `naalp_composite` example with the same
// seed and asserts identical bytes (the composite signature is deterministic in both legs).
package main

import (
	"crypto/ed25519"
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
		fmt.Fprintln(os.Stderr, "usage: naalp-composite <seed-hex-32-bytes>")
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
	edSk := ed25519.NewKeyFromSeed([]byte("naalp-composite-ed25519-seed-32b"))

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
	obj, err := envelope.Sign(o, cose.CompositeSigner{ML65: sk, Ed: edSk})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(obj))
}
