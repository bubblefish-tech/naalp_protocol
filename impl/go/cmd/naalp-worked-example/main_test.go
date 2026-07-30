// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TestWorkedExampleVerifies grades the committed worked example (docs/examples/worked-object.md):
// its bytes are real (produced by the implementation) and the signed object verifies end-to-end
// against the channel surface validator, with the recomputed content id and signer matching.
func TestWorkedExampleVerifies(t *testing.T) {
	b, err := os.ReadFile(filepath.Clean("../../../../vectors/worked/example.json"))
	if err != nil {
		t.Fatalf("read worked example: %v", err)
	}
	var c struct {
		SeedHex         string `json:"seed_hex"`
		SignerID        string `json:"signer_id"`
		ContentIDHex    string `json:"content_id_hex"`
		SignedObjectHex string `json:"signed_object_hex"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse: %v", err)
	}
	seed, _ := hex.DecodeString(c.SeedHex)
	var s [32]byte
	copy(s[:], seed)
	pk, _ := mldsa65.NewKeyFromSeed(&s)

	signed, _ := hex.DecodeString(c.SignedObjectHex)
	o, err := envelope.Verify(cose.ProfilePublic, cose.MLDSA65Verifier{PK: pk}, channels.KindValidator, nil, signed)
	if err != nil {
		t.Fatalf("worked example does not verify: %v", err)
	}
	if hex.EncodeToString(o.ID) != c.ContentIDHex {
		t.Errorf("content id: got %s want %s", hex.EncodeToString(o.ID), c.ContentIDHex)
	}
	if string(o.Signer) != c.SignerID {
		t.Errorf("signer: got %s want %s", string(o.Signer), c.SignerID)
	}
	if o.Channel != 4 || o.Kind != 1 {
		t.Errorf("expected Governance Approval (channel 4, kind 1), got channel %d kind %d", o.Channel, o.Kind)
	}
}
