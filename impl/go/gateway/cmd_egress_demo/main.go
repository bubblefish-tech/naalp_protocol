// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command naalp-egress-demo is the A9 isolation demonstration for E6.3 (held at the wire-freeze
// gate): a concrete sign -> verify of a real signed EgressAttestation using real ML-DSA-65
// crypto, plus the content_free commitment open/verify pair — open(success) then open(wrong
// salt = fail) — run entirely inside this process, independent of the rest of the system. It
// prints each step's concrete input/output and exits 0 iff every assertion holds; any failure
// prints the mismatch and exits 1.
package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/gateway"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", a...)
	os.Exit(1)
}

// contentID mirrors gateway's unexported T1 framing (this is a separate `main` package, so it is
// reconstructed by hand from the same design.md §2.3 rule the gateway package itself implements —
// this demo's own input construction, not a shortcut into the package under test).
func contentID(b []byte) []byte {
	d := sha512.Sum384(b)
	out := make([]byte, 0, 2+len(d))
	out = append(out, 0x20, 0x30)
	return append(out, d[:]...)
}

func gatewayKey(seed byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier, []byte) {
	var s [mldsa65.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	pub, err := pk.MarshalBinary()
	if err != nil {
		fail("MarshalBinary: %v", err)
	}
	id, err := identity.SignerID(cose.AlgMLDSA65, pub)
	if err != nil {
		fail("SignerID: %v", err)
	}
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}, []byte(id)
}

func main() {
	// ---- Step 1: a gateway signs a content_bound egress attestation, and a THIRD PARTY (an
	// unrelated verifier holding only the gateway's public key) verifies it, with no serving-
	// party/connection identity involved anywhere in the call. ----
	gwSigner, gwVerifier, gwID := gatewayKey(0xE6)
	object := []byte(`{"tool":"export_customer_data","args":{"table":"users","rows":4821}}`)
	objectCID := contentID(object)

	att := gateway.EgressAttestation{
		Binding:  gateway.BindingContentBound,
		Digest:   objectCID,
		Effect:   1, // idempotent_write
		Audience: []byte("acme-partner-endpoint"),
		At:       1735689600000, // 2025-01-01T00:00:00Z epoch ms
	}
	obj, err := gateway.SignEgressAttestation(att, gwSigner)
	if err != nil {
		fail("SignEgressAttestation: %v", err)
	}
	fmt.Printf("gateway id:        %s...\n", hex.EncodeToString(gwID)[:16])
	fmt.Printf("object crossed:    %s\n", object)
	fmt.Printf("object content-id: %s\n", hex.EncodeToString(objectCID))
	fmt.Printf("signed attestation: %d bytes, sha384=%x\n", len(obj), sha512.Sum384(obj))

	resolved, err := gateway.VerifyEgressAttestation(obj, cose.ProfilePublic, gwVerifier)
	if err != nil {
		fail("VerifyEgressAttestation (third-party re-serve): %v", err)
	}
	if resolved.Binding != gateway.BindingContentBound {
		fail("resolved binding = %d, want content_bound", resolved.Binding)
	}
	if hex.EncodeToString(resolved.Digest) != hex.EncodeToString(objectCID) {
		fail("resolved digest %s != object content-id %s", hex.EncodeToString(resolved.Digest), hex.EncodeToString(objectCID))
	}
	fmt.Printf("VERIFIED (content_bound): binding=%s effect=%d audience=%q at=%d\n",
		gateway.BindingName(resolved.Binding), resolved.Effect, resolved.Audience, resolved.At)

	// A foreign key must NOT verify the gateway's attestation.
	_, foreignVerifier, _ := gatewayKey(0xE7)
	if _, err := gateway.VerifyEgressAttestation(obj, cose.ProfilePublic, foreignVerifier); err != cose.ErrBadSignature {
		fail("foreign-key verify got %v, want BadSignature", err)
	}
	fmt.Println("foreign key correctly rejected: BadSignature")

	// ---- Step 2: a content_free attestation — the gateway attests an egress crossing WITHOUT
	// disclosing which object crossed; the digest is a hiding commitment. ----
	salt := []byte("0123456789abcdef0123456789abcdef")[:32]
	commitment := gateway.EgressCommit(objectCID, salt)
	cfAtt := gateway.EgressAttestation{
		Binding:  gateway.BindingContentFree,
		Digest:   commitment,
		Effect:   3, // destructive
		Audience: []byte("acme-partner-endpoint"),
		At:       1738368000000,
	}
	cfObj, err := gateway.SignEgressAttestation(cfAtt, gwSigner)
	if err != nil {
		fail("SignEgressAttestation (content_free): %v", err)
	}
	cfResolved, err := gateway.VerifyEgressAttestation(cfObj, cose.ProfilePublic, gwVerifier)
	if err != nil {
		fail("VerifyEgressAttestation (content_free): %v", err)
	}
	fmt.Printf("VERIFIED (content_free):  binding=%s commitment=%s...\n",
		gateway.BindingName(cfResolved.Binding), hex.EncodeToString(cfResolved.Digest)[:16])

	// commit -> open(success): the correct (objectCID, salt) pair opens the commitment.
	if !gateway.OpenEgressCommitment(cfAtt, objectCID, salt) {
		fail("OpenEgressCommitment(correct object_cid, correct salt) = false, want true")
	}
	fmt.Println("open(correct object_cid, correct salt) = true  (commitment PROVEN)")

	// open(wrong salt) must fail.
	wrongSalt := []byte("fedcba9876543210fedcba9876543210")[:32]
	if gateway.OpenEgressCommitment(cfAtt, objectCID, wrongSalt) {
		fail("OpenEgressCommitment(correct object_cid, WRONG salt) = true, want false")
	}
	fmt.Println("open(correct object_cid, WRONG salt)   = false (correctly refused)")

	// open with a wrong object entirely must also fail.
	wrongObject := []byte(`{"tool":"export_customer_data","args":{"table":"invoices","rows":90}}`)
	wrongObjectCID := contentID(wrongObject)
	if gateway.OpenEgressCommitment(cfAtt, wrongObjectCID, salt) {
		fail("OpenEgressCommitment(WRONG object_cid, correct salt) = true, want false")
	}
	fmt.Println("open(WRONG object_cid, correct salt)   = false (correctly refused)")

	fmt.Println("OK: all egress-attestation isolation checks passed")
}
