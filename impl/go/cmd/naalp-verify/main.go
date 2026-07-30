// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command naalp-verify demonstrates the N-AALP headline capability: verifying a signed object
// OFFLINE — from the object bytes, the signer's public key, and the spec alone, with no network
// call and no issuer callback (R-2.4) — and rejecting, fail-closed, anything that fails a check.
//
// It builds and signs a Governance Approval object (channel 0x0004, kind 1), then exercises four
// outcomes: (1) the untouched object verifies and decodes back to its fields; (2) a one-bit tamper
// is rejected; (3) verification under the wrong public key is rejected; (4) a kind the channel
// validator does not admit is rejected (kind dispatch runs before the signature check). The
// program exits non-zero if any outcome differs from the expected one, so it doubles as a
// self-checking smoke test:
//
//	go run ./cmd/naalp-verify
package main

import (
	"fmt"
	"os"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	// A deterministic ML-DSA-65 signer, plus a DIFFERENT key standing in for an impostor.
	var seed, wrongSeed [32]byte
	for i := range seed {
		seed[i] = 0x2a
		wrongSeed[i] = 0x99
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	wrongPK, _ := mldsa65.NewKeyFromSeed(&wrongSeed)
	signerID, err := identity.SignerID(cose.AlgMLDSA65, pk.Bytes())
	if err != nil {
		fail(err)
	}

	// A Governance Approval object (channel 0x0004, kind 1), effect non_idempotent_write, Public.
	obj := &envelope.Object{
		Kind:    1,
		Channel: 4,
		Tier:    0,
		Signer:  []byte(signerID),
		Created: 1785000000000,
		Effect:  2,
		Profile: uint64(cose.ProfilePublic),
		Body:    cbor.Tstr("approve: deploy build 4"),
	}
	signed, err := envelope.Sign(obj, cose.MLDSA65Signer{SK: sk})
	if err != nil {
		fail(err)
	}
	fmt.Printf("signed object: %d bytes, signer %s...\n", len(signed), signerID[:12])

	verifier := cose.MLDSA65Verifier{PK: pk}
	// The channel validator admits kind 1 on the Governance channel (0x0004) and nothing else.
	kindOK := func(ch, k uint64) bool { return ch == 4 && k == 1 }

	// (1) The untouched object verifies offline and decodes back to its fields.
	got, err := envelope.Verify(cose.ProfilePublic, verifier, kindOK, nil, signed)
	if err != nil {
		fail(fmt.Errorf("a valid object failed to verify: %w", err))
	}
	fmt.Printf("(1) VERIFIED offline: channel=%d kind=%d effect=%d\n", got.Channel, got.Kind, got.Effect)

	// (2) A one-bit tamper anywhere in the bytes is rejected, fail-closed.
	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := envelope.Verify(cose.ProfilePublic, verifier, kindOK, nil, tampered); err == nil {
		fail(fmt.Errorf("a tampered object verified (it should have been rejected)"))
	} else {
		fmt.Printf("(2) REJECTED tampered object: %v\n", err)
	}

	// (3) The genuine object under the WRONG public key is rejected at the signature check.
	if _, err := envelope.Verify(cose.ProfilePublic, cose.MLDSA65Verifier{PK: wrongPK}, kindOK, nil, signed); err == nil {
		fail(fmt.Errorf("an object verified under the wrong key (it should have been rejected)"))
	} else {
		fmt.Printf("(3) REJECTED wrong-key verification: %v\n", err)
	}

	// (4) A kind the channel validator does not admit is rejected before the signature is checked.
	denyKind := func(ch, k uint64) bool { return false }
	if _, err := envelope.Verify(cose.ProfilePublic, verifier, denyKind, nil, signed); err == nil {
		fail(fmt.Errorf("an unadmitted kind verified (it should have been rejected)"))
	} else {
		fmt.Printf("(4) REJECTED unadmitted kind: %v\n", err)
	}

	fmt.Println("OK: every offline-verification outcome was as expected")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "naalp-verify:", err)
	os.Exit(1)
}
