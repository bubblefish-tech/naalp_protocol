// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command naalp-worked-example emits a complete, every-byte-grounded worked N-AALP object as
// JSON: the object body fields, the recomputed content id, the COSE protected header, the COSE
// Sig_structure that is signed, the ML-DSA-65 signature length, and the final tagged COSE_Sign1
// bytes. All bytes are produced by the reference implementation (never hand-typed) from a fixed
// 32-byte seed, so the example is deterministic and reproducible, and it verifies end-to-end
// (docs/examples/worked-object.md presents it). It is a Governance Approval object (channel
// 0x0004, kind 1), effect non_idempotent_write, on the Public profile.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	var seed [32]byte
	for i := range seed {
		seed[i] = 0x2a
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	signerID, err := identity.SignerID(cose.AlgMLDSA65, pk.Bytes())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// The approval body: approves the args with content id A, granted effect 2, a nonce, expiry.
	argsID, _ := hex.DecodeString("20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff")
	approvalBody := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(argsID)},
		{K: cbor.Uint(2), V: cbor.Tstr(signerID)},
		{K: cbor.Uint(3), V: cbor.Uint(2)},
		{K: cbor.Uint(4), V: cbor.Bstr([]byte{1, 2, 3, 4, 5, 6, 7, 8})},
		{K: cbor.Uint(5), V: cbor.Uint(1785000000000)},
	}

	o := &envelope.Object{
		Kind:    1, // Governance Approval
		Channel: 4, // Governance (0x0004)
		Tier:    0,
		Signer:  []byte(signerID),
		Created: 1785000000000,
		Effect:  2, // non_idempotent_write
		Causes:  nil,
		Profile: uint64(cose.ProfilePublic),
		Body:    approvalBody,
	}
	cid, _ := o.ContentID()
	signed, err := envelope.Sign(o, cose.MLDSA65Signer{SK: sk})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	protected, payload, sig, err := cose.ParseSign1Raw(signed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	tbs, _ := cose.ToBeSignedRaw(protected, payload)

	out := map[string]any{
		"note":              "Every byte here is produced by the reference implementation from the fixed seed; both Go and Rust produce it identically. Governance Approval object (channel 0x0004, kind 1).",
		"seed_hex":          hex.EncodeToString(seed[:]),
		"signer_id":         signerID,
		"object_fields": map[string]any{
			"kind": 1, "channel": 4, "tier": 0, "created": 1785000000000,
			"effect": 2, "profile": 1,
		},
		"content_id_hex":    hex.EncodeToString(cid),
		"protected_hdr_hex": hex.EncodeToString(protected),
		"payload_body_hex":  hex.EncodeToString(payload),
		"to_be_signed_hex":  hex.EncodeToString(tbs),
		"signature_len":     len(sig),
		"signed_object_hex": hex.EncodeToString(signed),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
