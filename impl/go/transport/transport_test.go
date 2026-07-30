// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package transport_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/transport"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/transport/cases.json"

type transportCases struct {
	MediaType  string `json:"media_type"`
	Transports []struct {
		Name              string `json:"name"`
		Confidential      bool   `json:"confidential"`
		PeerAuthenticated bool   `json:"peer_authenticated"`
	} `json:"transports"`
	EmitMatrix []struct {
		Transport      string `json:"transport"`
		Sensitive      bool   `json:"sensitive"`
		RequirePeerAuth bool  `json:"require_peer_auth"`
		Result         string `json:"result"`
	} `json:"emit_matrix"`
}

func load(t *testing.T) transportCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c transportCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

// TestTransportTableMatchesOracle: the media type and each transport's conditional guarantees
// equal the independent oracle (⟹ Go == Rust).
func TestTransportTableMatchesOracle(t *testing.T) {
	c := load(t)
	if transport.MediaType != c.MediaType {
		t.Errorf("media type %q want %q", transport.MediaType, c.MediaType)
	}
	for _, tr := range c.Transports {
		got, ok := transport.ByName(tr.Name)
		if !ok {
			t.Fatalf("unknown transport %q", tr.Name)
		}
		if got.Confidential != tr.Confidential || got.PeerAuthenticated != tr.PeerAuthenticated {
			t.Errorf("%s: confidential=%v peerAuth=%v, want %v/%v", tr.Name, got.Confidential, got.PeerAuthenticated, tr.Confidential, tr.PeerAuthenticated)
		}
	}
}

// TestEmitMatrix: R-13.4/§12.4 — the confidentiality boundary + peer-auth decisions match the
// oracle for every (transport, sensitive, require_peer_auth) combination.
func TestEmitMatrix(t *testing.T) {
	c := load(t)
	obj := []byte{0xDE, 0xAD, 0xBE, 0xEF} // stand-in object bytes
	confidentialRefusals, authRefusals := 0, 0
	for _, r := range c.EmitMatrix {
		tr, ok := transport.ByName(r.Transport)
		if !ok {
			t.Fatalf("unknown transport %q", r.Transport)
		}
		mu, err := transport.Emit(tr, obj, r.Sensitive, r.RequirePeerAuth)
		switch r.Result {
		case "ok":
			if err != nil {
				t.Errorf("%s sens=%v auth=%v: want ok, got %v", r.Transport, r.Sensitive, r.RequirePeerAuth, err)
			}
			if !bytes.Equal(mu.Payload, obj) {
				t.Errorf("%s: framed payload differs from the object", r.Transport)
			}
		case "ConfidentialTransportRequired":
			confidentialRefusals++
			if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ConfidentialTransportRequired" {
				t.Errorf("%s: want ConfidentialTransportRequired, got %v", r.Transport, err)
			}
		case "PeerUnauthenticated":
			authRefusals++
			if ce, ok := err.(*cose.Error); !ok || ce.Kind != "PeerUnauthenticated" {
				t.Errorf("%s: want PeerUnauthenticated, got %v", r.Transport, err)
			}
		default:
			t.Fatalf("unknown expected result %q", r.Result)
		}
	}
	if confidentialRefusals == 0 || authRefusals == 0 {
		t.Fatalf("matrix must exercise both refusals (confidential=%d auth=%d)", confidentialRefusals, authRefusals)
	}
}

func testSigner(t *testing.T) (cose.MLDSA65Signer, cose.MLDSA65Verifier, []byte) {
	t.Helper()
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 70
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}, pk.Bytes()
}

// TestCrossBindingIdentity: R-13.1 — the SAME signed object, framed for each of the four
// bindings and recovered, is byte-identical and verifies identically. An object over plain HTTPS
// has the same object-level guarantees as over N-PAMP.
func TestCrossBindingIdentity(t *testing.T) {
	signer, verifier, pkb := testSigner(t)
	kindOK := func(ch, k uint64) bool { return true }
	obj := &envelope.Object{Kind: 0, Channel: 0, Tier: 0, Signer: pkb, Created: 100, Effect: 0, Profile: uint64(cose.ProfilePublic), Body: cbor.Uint(0)}
	signed, err := envelope.Sign(obj, signer)
	if err != nil {
		t.Fatal(err)
	}
	// The four binding types (using the confidential variants for WS/HTTP).
	for _, tr := range []transport.Transport{transport.NPAMP, transport.QUIC, transport.WebSocketWSS, transport.HTTPS} {
		mu, err := transport.Emit(tr, signed, false, false)
		if err != nil {
			t.Fatalf("%s emit: %v", tr.Name, err)
		}
		payload, err := mu.Object()
		if err != nil {
			t.Fatalf("%s object: %v", tr.Name, err)
		}
		if !bytes.Equal(payload, signed) {
			t.Fatalf("%s: framing changed the object bytes", tr.Name)
		}
		if _, err := envelope.Verify(cose.ProfilePublic, verifier, kindOK, nil, payload); err != nil {
			t.Fatalf("%s: object does not verify after binding: %v", tr.Name, err)
		}
	}
}

// TestMutationBreaksVerification: a binding that mutates the object body breaks verification.
func TestMutationBreaksVerification(t *testing.T) {
	signer, verifier, pkb := testSigner(t)
	kindOK := func(ch, k uint64) bool { return true }
	obj := &envelope.Object{Kind: 0, Channel: 0, Tier: 0, Signer: pkb, Created: 100, Effect: 0, Profile: uint64(cose.ProfilePublic), Body: cbor.Uint(0)}
	signed, err := envelope.Sign(obj, signer)
	if err != nil {
		t.Fatal(err)
	}
	mu := transport.Frame(transport.QUIC, signed)
	mu.Payload[len(mu.Payload)/2] ^= 0x01 // a byte mutated in transit
	payload, err := mu.Object()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Verify(cose.ProfilePublic, verifier, kindOK, nil, payload); err == nil {
		t.Fatal("a mutated object body still verified")
	}
}

// TestMediaTypeRejected: a message unit with the wrong media type is rejected.
func TestMediaTypeRejected(t *testing.T) {
	mu := transport.MessageUnit{Transport: "http", MediaType: "application/json", Payload: []byte{1, 2, 3}}
	if _, err := mu.Object(); err == nil {
		t.Fatal("wrong media type accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "Malformed" {
		t.Fatalf("want Malformed, got %v", err)
	}
}
