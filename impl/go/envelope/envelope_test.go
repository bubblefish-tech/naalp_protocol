// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package envelope

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/n-aalp/impl/go/cbor"
	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/envelope/cases.json"

type envCase struct {
	Object struct {
		Kind         uint64   `json:"kind"`
		Channel      uint64   `json:"channel"`
		Tier         uint64   `json:"tier"`
		SignerHex    string   `json:"signer_hex"`
		Created      uint64   `json:"created"`
		Effect       uint64   `json:"effect"`
		CausesHex    []string `json:"causes_hex"`
		Profile      uint64   `json:"profile"`
		BodyStr      string   `json:"body_str"`
		Alg          int      `json:"alg"`
		Version      uint64   `json:"version"`
		BodyNoIDHex  string   `json:"body_no_id_hex"`
		ContentIDHex string   `json:"content_id_hex"`
		PayloadHex   string   `json:"payload_hex"`
		ProtectedHex string   `json:"protected_hex"`
		TBSHex       string   `json:"tobesigned_hex"`
	} `json:"object"`
}

func load(t *testing.T) envCase {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c envCase
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

func mh(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func buildObject(t *testing.T, c envCase) *Object {
	o := c.Object
	var causes [][]byte
	for _, h := range o.CausesHex {
		causes = append(causes, mh(t, h))
	}
	return &Object{
		Kind: o.Kind, Channel: o.Channel, Tier: o.Tier, Signer: mh(t, o.SignerHex),
		Created: o.Created, Effect: o.Effect, Causes: causes, Profile: o.Profile,
		Body: cbor.Tstr(o.BodyStr),
	}
}

// testSigner derives a fixed ML-DSA-65 keypair for the envelope round-trip tests (the
// crypto key is independent of the opaque body `signer` field, which is C4/T4 territory).
func testSigner(t *testing.T) (cose.MLDSA65Signer, cose.MLDSA65Verifier) {
	t.Helper()
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
}

func acceptKind(channel, kind uint64) bool { return channel == 4 && kind == 2 }

// TestEnvelopeBytesMatchOracle grades the envelope byte construction against the
// independent oracle (content id, body, payload, protected header, ToBeSigned).
func TestEnvelopeBytesMatchOracle(t *testing.T) {
	c := load(t)
	o := buildObject(t, c)

	id, err := o.ContentID()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(id); got != c.Object.ContentIDHex {
		t.Errorf("content-id\n got %s\nwant %s", got, c.Object.ContentIDHex)
	}
	bn, _ := cbor.Encode(o.bodyMap(false))
	if got := hex.EncodeToString(bn); got != c.Object.BodyNoIDHex {
		t.Errorf("body-no-id\n got %s\nwant %s", got, c.Object.BodyNoIDHex)
	}
	o.ID = id
	payload, _ := cbor.Encode(o.bodyMap(true))
	if got := hex.EncodeToString(payload); got != c.Object.PayloadHex {
		t.Errorf("payload\n got %s\nwant %s", got, c.Object.PayloadHex)
	}
	prot, _ := protectedHeader(c.Object.Alg, o.Signer, o.Profile)
	if got := hex.EncodeToString(prot); got != c.Object.ProtectedHex {
		t.Errorf("protected\n got %s\nwant %s", got, c.Object.ProtectedHex)
	}
	tbs, _ := cose.ToBeSignedRaw(prot, payload)
	if got := hex.EncodeToString(tbs); got != c.Object.TBSHex {
		t.Errorf("tobesigned\n got %s\nwant %s", got, c.Object.TBSHex)
	}
}

// TestSignVerifyOffline: a valid object verifies offline from object+key+spec alone.
func TestSignVerifyOffline(t *testing.T) {
	c := load(t)
	o := buildObject(t, c)
	s, v := testSigner(t)
	obj, err := Sign(o, s)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := Verify(ProfilePublicForTest(), v, acceptKind, nil, obj)
	if err != nil {
		t.Fatalf("verify valid: %v", err)
	}
	if got.Channel != 4 || got.Kind != 2 || got.Effect != 2 {
		t.Fatalf("decoded object fields wrong: %+v", got)
	}
}

// ProfilePublicForTest exposes the cose profile constant to keep the test readable.
func ProfilePublicForTest() int { return cose.ProfilePublic }

// TestFailureModes drives every §2.6 failure mode plus RangeError and UnsupportedVersion,
// each expecting its named error (fail-closed).
func TestFailureModes(t *testing.T) {
	c := load(t)
	s, v := testSigner(t)

	expect := func(name string, obj []byte, kind string, kindOK KindValidator, knownCext map[uint64]bool) {
		_, err := Verify(cose.ProfilePublic, v, kindOK, knownCext, obj)
		ce, ok := err.(*cose.Error)
		if !ok || ce.Kind != kind {
			t.Errorf("%s: want %s, got %v", name, kind, err)
		}
	}

	// BadSignature: flip the trailing signature byte of a valid object.
	valid, _ := Sign(buildObject(t, c), s)
	bad := append([]byte(nil), valid...)
	bad[len(bad)-1] ^= 0x01
	expect("BadSignature", bad, "BadSignature", acceptKind, nil)

	// ContentIdMismatch: sign with a bogus content id (valid signature, wrong id field).
	bogus := make([]byte, 50)
	bogus[0], bogus[1] = 0x20, 0x30
	expect("ContentIdMismatch", signWithID(t, buildObject(t, c), s, bogus), "ContentIdMismatch", acceptKind, nil)

	// HeaderBodyMismatch: protected-header profile copy (2) disagrees with body profile (1).
	expect("HeaderBodyMismatch", signWithHeaderProfile(t, buildObject(t, c), s, 2), "HeaderBodyMismatch", acceptKind, nil)

	// UnknownCriticalExt: an object carrying a critical extension key with none known.
	oc := buildObject(t, c)
	oc.Cext = cbor.Map{{K: cbor.Uint(100), V: cbor.Uint(7)}}
	oce, _ := Sign(oc, s)
	expect("UnknownCriticalExt", oce, "UnknownCriticalExt", acceptKind, nil)

	// NonCanonical: a COSE object whose payload is non-canonical CBOR (out-of-order keys).
	nc := signRawPayload(t, s, mh(t, "a203000200")) // map{3:0,2:0} keys out of order
	expect("NonCanonical", nc, "NonCanonical", acceptKind, nil)

	// UnknownKind: a validator that recognizes nothing.
	expect("UnknownKind", valid, "UnknownKind", func(uint64, uint64) bool { return false }, nil)

	// RangeError: channel out of the 0..19 range.
	orange := buildObject(t, c)
	orange.Channel = 99
	or, _ := Sign(orange, s)
	expect("RangeError", or, "RangeError", func(ch, k uint64) bool { return true }, nil)

	// UnsupportedVersion: protected header carries a version != 1.
	expect("UnsupportedVersion", signWithVersion(t, buildObject(t, c), s, 2), "UnsupportedVersion", acceptKind, nil)
}

// TestNonCriticalExtIgnored: an unknown non-critical extension (field 11) is accepted.
func TestNonCriticalExtIgnored(t *testing.T) {
	c := load(t)
	s, v := testSigner(t)
	o := buildObject(t, c)
	o.Ext = cbor.Map{{K: cbor.Uint(100), V: cbor.Uint(7)}}
	obj, _ := Sign(o, s)
	if _, err := Verify(cose.ProfilePublic, v, acceptKind, nil, obj); err != nil {
		t.Fatalf("unknown non-critical ext must be ignored, got %v", err)
	}
}

// TestKnownCriticalExtAccepted: a critical extension whose key the verifier knows is OK.
func TestKnownCriticalExtAccepted(t *testing.T) {
	c := load(t)
	s, v := testSigner(t)
	o := buildObject(t, c)
	o.Cext = cbor.Map{{K: cbor.Uint(100), V: cbor.Uint(7)}}
	obj, _ := Sign(o, s)
	if _, err := Verify(cose.ProfilePublic, v, acceptKind, map[uint64]bool{100: true}, obj); err != nil {
		t.Fatalf("known critical ext must be accepted, got %v", err)
	}
}

// --- white-box test helpers that assemble objects with deliberately-off components ---

func signWithID(t *testing.T, o *Object, s cose.Signer, id []byte) []byte {
	t.Helper()
	o.ID = id
	payload, _ := cbor.Encode(o.bodyMap(true))
	prot, _ := protectedHeader(s.Alg(), o.Signer, o.Profile)
	tbs, _ := cose.ToBeSignedRaw(prot, payload)
	sig, _ := s.Sign(tbs)
	obj, _ := cose.AssembleSign1Raw(prot, payload, sig)
	return obj
}

func signWithHeaderProfile(t *testing.T, o *Object, s cose.Signer, hdrProfile uint64) []byte {
	t.Helper()
	id, _ := o.ContentID()
	o.ID = id
	payload, _ := cbor.Encode(o.bodyMap(true))
	prot, _ := protectedHeader(s.Alg(), o.Signer, hdrProfile) // mismatched profile copy
	tbs, _ := cose.ToBeSignedRaw(prot, payload)
	sig, _ := s.Sign(tbs)
	obj, _ := cose.AssembleSign1Raw(prot, payload, sig)
	return obj
}

func signWithVersion(t *testing.T, o *Object, s cose.Signer, version uint64) []byte {
	t.Helper()
	id, _ := o.ContentID()
	o.ID = id
	payload, _ := cbor.Encode(o.bodyMap(true))
	naalp := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(o.Signer)},
		{K: cbor.Uint(2), V: cbor.Uint(o.Profile)},
		{K: cbor.Uint(3), V: cbor.Uint(version)},
	}
	hdr := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Nint(int64(s.Alg()))},
		{K: cbor.Tstr(naalpHeaderLabel), V: naalp},
	}
	prot, _ := cbor.Encode(hdr)
	tbs, _ := cose.ToBeSignedRaw(prot, payload)
	sig, _ := s.Sign(tbs)
	obj, _ := cose.AssembleSign1Raw(prot, payload, sig)
	return obj
}

func signRawPayload(t *testing.T, s cose.Signer, payload []byte) []byte {
	t.Helper()
	prot, _ := protectedHeader(s.Alg(), []byte("SIGNER_A"), 1)
	tbs, _ := cose.ToBeSignedRaw(prot, payload)
	sig, _ := s.Sign(tbs)
	obj, _ := cose.AssembleSign1Raw(prot, payload, sig)
	return obj
}
