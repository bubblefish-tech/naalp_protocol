// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package envelope

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// §3.1.1 determinism dispositions (R5): a CBOR float in the body/ext/cext, a duplicate map key,
// and the 0x41A0 (bstr-wrapped-empty-map) encoding of an empty protected header are each rejected
// NonCanonical at the parse/decode stage, before the object is authenticated. The reject vectors
// are the independent oracle's output (tools/determinism_oracle.py); every one is an
// otherwise-valid tag-18 object carrying exactly one violation, so the reject is the disposition.
//
// MUTATION (0x41A0 pin — the new §3.1.1 logic): deleting the `len(prot)==1 && prot[0]==0xA0`
// guard at the top of parseProtected (and cose.algFromProtected) makes the protected_0x41a0
// object decode its 0xA0 protected header as an empty map, find no alg, and return Malformed
// instead of NonCanonical — flipping this test. The float/dup-key vectors are rejected by the
// strict CBOR decoder itself; they are graded here so the rule is exercised, not only asserted.

type detReject struct {
	Name   string `json:"name"`
	ObjHex string `json:"obj_hex"`
	Error  string `json:"error"`
	Note   string `json:"note"`
}

type detCases struct {
	ObjectDecodeReject []detReject `json:"object_decode_reject"`
}

func loadDeterminism(t *testing.T) detCases {
	t.Helper()
	path := filepath.Join("..", "..", "..", "vectors", "determinism", "cases.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read determinism cases: %v", err)
	}
	var c detCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse determinism cases: %v", err)
	}
	if len(c.ObjectDecodeReject) != 5 {
		t.Fatalf("want 5 determinism reject vectors, got %d", len(c.ObjectDecodeReject))
	}
	return c
}

// TestDeterminismRejects grades each §3.1.1 must-reject vector: an otherwise-valid object with one
// determinism violation is rejected with the named error (NonCanonical), before crypto.
func TestDeterminismRejects(t *testing.T) {
	c := loadDeterminism(t)
	s, v := testSigner(t)
	_ = s
	for _, r := range c.ObjectDecodeReject {
		obj, err := hex.DecodeString(r.ObjHex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", r.Name, err)
		}
		_, verr := Verify(cose.ProfilePublic, v, acceptKind, nil, obj)
		ce, ok := verr.(*cose.Error)
		if !ok || ce.Kind != r.Error {
			t.Errorf("%s: want %s, got %v", r.Name, r.Error, verr)
		}
	}
}

// TestProtectedHeaderPin isolates the new §3.1.1 logic: the 0x41A0 empty-protected-header form is
// NonCanonical, while a normal (non-empty) object header is not tripped by the pin. This is the
// direct mutation witness for the parseProtected guard.
func TestProtectedHeaderPin(t *testing.T) {
	c := loadDeterminism(t)
	_, v := testSigner(t)
	var found bool
	for _, r := range c.ObjectDecodeReject {
		if r.Name != "protected_0x41a0" {
			continue
		}
		found = true
		obj, _ := hex.DecodeString(r.ObjHex)
		_, verr := Verify(cose.ProfilePublic, v, acceptKind, nil, obj)
		ce, ok := verr.(*cose.Error)
		if !ok || ce.Kind != "NonCanonical" {
			t.Fatalf("0x41A0 header: want NonCanonical, got %v", verr)
		}
	}
	if !found {
		t.Fatal("protected_0x41a0 vector missing")
	}
	// A properly-signed object with a real (non-empty) protected header must NOT be caught by the
	// pin — proving the guard is scoped to the 0x41A0 form, not to protected headers generally.
	s, _ := testSigner(t)
	o := buildObject(t, load(t))
	obj, err := Sign(o, s)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Verify(cose.ProfilePublic, v, acceptKind, nil, obj); err != nil {
		t.Fatalf("valid object rejected by the 0x41A0 pin: %v", err)
	}
}
