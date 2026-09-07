// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package envelope

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
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
	ObjectWithAudience struct {
		Audience     string `json:"audience"`
		BodyNoIDHex  string `json:"body_no_id_hex"`
		ContentIDHex string `json:"content_id_hex"`
		PayloadHex   string `json:"payload_hex"`
		ProtectedHex string `json:"protected_hex"`
		TBSHex       string `json:"tobesigned_hex"`
	} `json:"object_with_audience"`
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

// TestAudienceBytesMatchOracle grades the field-13 audience object byte-construction against the
// independent oracle (F3 non-circular): the SAME worked object plus the audience reproduces the
// oracle's body-no-id, content-id, payload, and to-be-signed. The protected header is unchanged
// (audience does not touch alg/signer/profile/version). Mutation-surviving: a constant or
// field-dropping encoder fails the fixed hex expectations.
func TestAudienceBytesMatchOracle(t *testing.T) {
	c := load(t)
	a := c.ObjectWithAudience
	o := buildObject(t, c) // the base worked object (kind 2, channel 4, ..., body "hello")
	o.Audience = a.Audience

	bn, _ := cbor.Encode(o.bodyMap(false))
	if got := hex.EncodeToString(bn); got != a.BodyNoIDHex {
		t.Errorf("audience body-no-id\n got %s\nwant %s", got, a.BodyNoIDHex)
	}
	id, err := o.ContentID()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(id); got != a.ContentIDHex {
		t.Errorf("audience content-id\n got %s\nwant %s", got, a.ContentIDHex)
	}
	o.ID = id
	payload, _ := cbor.Encode(o.bodyMap(true))
	if got := hex.EncodeToString(payload); got != a.PayloadHex {
		t.Errorf("audience payload\n got %s\nwant %s", got, a.PayloadHex)
	}
	prot, _ := protectedHeader(c.Object.Alg, o.Signer, o.Profile)
	if got := hex.EncodeToString(prot); got != a.ProtectedHex {
		t.Errorf("audience protected\n got %s\nwant %s", got, a.ProtectedHex)
	}
	tbs, _ := cose.ToBeSignedRaw(prot, payload)
	if got := hex.EncodeToString(tbs); got != a.TBSHex {
		t.Errorf("audience tobesigned\n got %s\nwant %s", got, a.TBSHex)
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

	// UnsupportedVersion: protected header carries a version != 2 (draft-01 wire is version 2).
	// Version 1 is the superseded pre-recheck wire; a version-1 object is now rejected.
	expect("UnsupportedVersion", signWithVersion(t, buildObject(t, c), s, 1), "UnsupportedVersion", acceptKind, nil)
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

// --- T1.3 recheck (the checkable-minimum field, NAALP-REQ-110/111) --------------------

const recheckVectorPath = "../../../vectors/recheck/cases.json"

type recheckCorpus struct {
	RecheckKey uint64 `json:"recheck_key"`
	Base       struct {
		Kind      uint64   `json:"kind"`
		Channel   uint64   `json:"channel"`
		Tier      uint64   `json:"tier"`
		SignerHex string   `json:"signer_hex"`
		Created   uint64   `json:"created"`
		Effect    uint64   `json:"effect"`
		CausesHex []string `json:"causes_hex"`
		Profile   uint64   `json:"profile"`
		BodyStr   string   `json:"body_str"`
	} `json:"base_object"`
	Cases []struct {
		Name         string  `json:"name"`
		Placement    string  `json:"placement"`
		Critical     bool    `json:"critical"`
		Present      bool    `json:"present"`
		ProcedureID  *uint64 `json:"procedure_id"`
		BodyNoIDHex  string  `json:"body_no_id_hex"`
		ContentIDHex string  `json:"content_id_hex"`
		FullHex      string  `json:"full_hex"`
		Expect       string  `json:"expect"`
	} `json:"cases"`
	Negatives []struct {
		Name       string `json:"name"`
		PayloadHex string `json:"payload_hex"`
		Expect     string `json:"expect"`
	} `json:"negatives"`
}

func loadRecheck(t *testing.T) recheckCorpus {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(recheckVectorPath))
	if err != nil {
		t.Fatalf("read recheck corpus: %v", err)
	}
	var c recheckCorpus
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse recheck corpus: %v", err)
	}
	return c
}

// buildRecheckObject builds the base object and applies the case's recheck placement — the ONLY
// variable across cases. The impl builds it from logical fields (never from the oracle's hex), so
// a constant/field-ignoring encoder diverges from the pinned body bytes.
func buildRecheckObject(t *testing.T, corpus recheckCorpus, placement string, procID *uint64) *Object {
	t.Helper()
	var causes [][]byte
	for _, h := range corpus.Base.CausesHex {
		causes = append(causes, mh(t, h))
	}
	o := &Object{
		Kind: corpus.Base.Kind, Channel: corpus.Base.Channel, Tier: corpus.Base.Tier,
		Signer: mh(t, corpus.Base.SignerHex), Created: corpus.Base.Created, Effect: corpus.Base.Effect,
		Causes: causes, Profile: corpus.Base.Profile, Body: cbor.Tstr(corpus.Base.BodyStr),
	}
	switch placement {
	case "cext":
		o.SetRecheck(*procID, true)
	case "ext":
		o.SetRecheck(*procID, false)
	case "ext_empty":
		o.Ext = cbor.Map{} // present but empty (no recheck) — distinct bytes from absent
	case "absent":
		// no ext, no cext
	default:
		t.Fatalf("unknown placement %q", placement)
	}
	return o
}

// TestRecheckMatchesOracle grades recheck body bytes AND accept/reject verdicts against the
// independent oracle (tools/recheck_oracle.py): every body_no_id_hex/content_id_hex/full_hex is
// byte-identical, and every case verifies or fails with exactly the oracle's verdict over a REAL
// ML-DSA-65 signed object. knownCext is nil throughout — recheck is enforced by the envelope, not
// by the caller's critical-extension set.
func TestRecheckMatchesOracle(t *testing.T) {
	corpus := loadRecheck(t)
	if corpus.RecheckKey != RecheckKey {
		t.Fatalf("recheck_key: corpus %d != impl %d", corpus.RecheckKey, RecheckKey)
	}
	s, v := testSigner(t)
	for _, tc := range corpus.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			o := buildRecheckObject(t, corpus, tc.Placement, tc.ProcedureID)

			// byte parity: body-without-id, content id, full body.
			bn, _ := cbor.Encode(o.bodyMap(false))
			if got := hex.EncodeToString(bn); got != tc.BodyNoIDHex {
				t.Fatalf("body-no-id\n got %s\nwant %s", got, tc.BodyNoIDHex)
			}
			id, err := o.ContentID()
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(id); got != tc.ContentIDHex {
				t.Fatalf("content-id\n got %s\nwant %s", got, tc.ContentIDHex)
			}
			o.ID = id
			full, _ := cbor.Encode(o.bodyMap(true))
			if got := hex.EncodeToString(full); got != tc.FullHex {
				t.Fatalf("full-body\n got %s\nwant %s", got, tc.FullHex)
			}

			// verdict: sign for real and verify offline; assert accept vs the named error.
			o2 := buildRecheckObject(t, corpus, tc.Placement, tc.ProcedureID)
			signed, err := Sign(o2, s)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			got, verr := Verify(cose.ProfilePublic, v, acceptKind, nil, signed)
			if tc.Expect == "accept" {
				if verr != nil {
					t.Fatalf("expected accept, got %v", verr)
				}
				// the named procedure is readable back from the verified object.
				rid, present, critical := got.Recheck()
				if present != tc.Present {
					t.Fatalf("Recheck present: got %v want %v", present, tc.Present)
				}
				if present {
					if tc.ProcedureID == nil || rid != *tc.ProcedureID {
						t.Fatalf("Recheck id: got %d want %v", rid, tc.ProcedureID)
					}
					if critical != tc.Critical {
						t.Fatalf("Recheck critical: got %v want %v", critical, tc.Critical)
					}
				}
			} else {
				ce, ok := verr.(*cose.Error)
				if !ok || ce.Kind != tc.Expect {
					t.Fatalf("expected %s, got %v", tc.Expect, verr)
				}
			}
		})
	}

	// non-canonical recheck bodies (keys out of order) are rejected at the CBOR layer.
	for _, neg := range corpus.Negatives {
		neg := neg
		t.Run("negative_"+neg.Name, func(t *testing.T) {
			obj := signRawPayload(t, s, mh(t, neg.PayloadHex))
			_, verr := Verify(cose.ProfilePublic, v, acceptKind, nil, obj)
			ce, ok := verr.(*cose.Error)
			if !ok || ce.Kind != neg.Expect {
				t.Fatalf("expected %s, got %v", neg.Expect, verr)
			}
		})
	}
}

// TestRecheckRejectPathIsReal is the mutation anchor for the reject path: a CRITICAL recheck
// naming an UNKNOWN procedure id MUST be rejected with UnknownCriticalExt. If the Verify recheck
// branch is mutated to accept (drop the `return nil, ErrUnknownCriticalExt`), this test flips
// pass->fail. A known critical procedure and a non-critical unknown procedure both verify,
// proving the reject is specific to unknown-under-critical and not a blanket denial.
func TestRecheckRejectPathIsReal(t *testing.T) {
	c := load(t)
	s, v := testSigner(t)

	criticalUnknown := buildObject(t, c)
	criticalUnknown.SetRecheck(99, true) // unknown id, critical
	su, _ := Sign(criticalUnknown, s)
	if _, err := Verify(cose.ProfilePublic, v, acceptKind, nil, su); err == nil {
		t.Fatal("critical unknown recheck must be rejected, got accept")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "UnknownCriticalExt" {
		t.Fatalf("want UnknownCriticalExt, got %v", err)
	}

	criticalKnown := buildObject(t, c)
	criticalKnown.SetRecheck(RecheckWalkCauses, true) // known id, critical
	sk, _ := Sign(criticalKnown, s)
	if _, err := Verify(cose.ProfilePublic, v, acceptKind, nil, sk); err != nil {
		t.Fatalf("known critical recheck must verify, got %v", err)
	}

	nonCritUnknown := buildObject(t, c)
	nonCritUnknown.SetRecheck(99, false) // unknown id, non-critical -> ignored
	sn, _ := Sign(nonCritUnknown, s)
	if _, err := Verify(cose.ProfilePublic, v, acceptKind, nil, sn); err != nil {
		t.Fatalf("unknown non-critical recheck must be ignored, got %v", err)
	}
}

// TestRecheckReaderRoundTrip proves Recheck()/SetRecheck() carry the id and criticality, and that
// cext (critical) takes precedence over ext (non-critical) when both name the key.
func TestRecheckReaderRoundTrip(t *testing.T) {
	c := load(t)
	o := buildObject(t, c)
	if _, present, _ := o.Recheck(); present {
		t.Fatal("fresh object must have no recheck")
	}
	o.SetRecheck(RecheckVerifyCoseSign1, false)
	if id, present, critical := o.Recheck(); !present || id != RecheckVerifyCoseSign1 || critical {
		t.Fatalf("non-critical recheck read back wrong: id=%d present=%v critical=%v", id, present, critical)
	}
	o.SetRecheck(RecheckReplayConsumeCheck, true) // critical wins over the ext entry
	if id, present, critical := o.Recheck(); !present || id != RecheckReplayConsumeCheck || !critical {
		t.Fatalf("critical recheck must take precedence: id=%d present=%v critical=%v", id, present, critical)
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

// --- opt-in composite signature integration (design.md §4.2) --------------------------

// compositeTestKeys derives a fixed composite keypair: ML-DSA-65 (seed i+1) and Ed25519.
func compositeTestKeys(t *testing.T) (cose.CompositeSigner, cose.CompositeVerifier) {
	t.Helper()
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	edPriv := ed25519.NewKeyFromSeed([]byte("naalp-composite-ed25519-seed-32b"))
	edPub := edPriv.Public().(ed25519.PublicKey)
	return cose.CompositeSigner{ML65: sk, Ed: edPriv}, cose.CompositeVerifier{ML65: pk, Ed: edPub}
}

// signWhitebox assembles a signed object using the object's CALLER-SET Suite field, bypassing
// Sign's present-iff-composite auto-derive, so a test can build SuiteMismatch cases.
func signWhitebox(t *testing.T, o *Object, signer cose.Signer) []byte {
	t.Helper()
	id, err := o.ContentID()
	if err != nil {
		t.Fatal(err)
	}
	o.ID = id
	payload, err := cbor.Encode(o.bodyMap(true))
	if err != nil {
		t.Fatal(err)
	}
	prot, err := protectedHeader(signer.Alg(), o.Signer, o.Profile)
	if err != nil {
		t.Fatal(err)
	}
	tbs, _ := cose.ToBeSignedRaw(prot, payload)
	sig, err := signer.Sign(tbs)
	if err != nil {
		t.Fatal(err)
	}
	obj, _ := cose.AssembleSign1Raw(prot, payload, sig)
	return obj
}

// TestCompositeObjectRoundTrip: a composite object signs with field 14 present, verifies under
// a composite verifier at Public, and a PURE verifier is rejected (KeyAlgMismatch).
func TestCompositeObjectRoundTrip(t *testing.T) {
	c := load(t)
	o := buildObject(t, c)
	cs, cv := compositeTestKeys(t)
	obj, err := Sign(o, cs)
	if err != nil {
		t.Fatalf("sign composite object: %v", err)
	}
	if o.Suite != SuiteMLDSA65Ed25519 {
		t.Fatalf("composite Sign must set field 14 = %d, got %d", SuiteMLDSA65Ed25519, o.Suite)
	}
	got, err := Verify(cose.ProfilePublic, cv, acceptKind, nil, obj)
	if err != nil {
		t.Fatalf("verify composite object: %v", err)
	}
	if got.Suite != SuiteMLDSA65Ed25519 {
		t.Fatalf("verified object suite %d, want %d", got.Suite, SuiteMLDSA65Ed25519)
	}
	_, pv := testSigner(t)
	if _, err := Verify(cose.ProfilePublic, pv, acceptKind, nil, obj); err == nil || err.(*cose.Error).Kind != "KeyAlgMismatch" {
		t.Fatalf("pure verifier on composite object: want KeyAlgMismatch, got %v", err)
	}
}

// TestCompositeObjectHybridIncomplete: tampering the composite signature (ed leg) yields
// HybridIncomplete through the envelope Verify path.
func TestCompositeObjectHybridIncomplete(t *testing.T) {
	c := load(t)
	cs, cv := compositeTestKeys(t)
	obj, err := Sign(buildObject(t, c), cs)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), obj...)
	tampered[len(tampered)-1] ^= 0x01 // corrupt the trailing Ed25519 leg byte
	if _, err := Verify(cose.ProfilePublic, cv, acceptKind, nil, tampered); err == nil || err.(*cose.Error).Kind != "HybridIncomplete" {
		t.Fatalf("tampered composite: want HybridIncomplete, got %v", err)
	}
}

// TestCompositeSuiteMismatch (bar 4): field 14 must be present iff the alg is composite.
func TestCompositeSuiteMismatch(t *testing.T) {
	c := load(t)
	ps, pv := testSigner(t)
	cs, cv := compositeTestKeys(t)

	// (a) pure alg (-49) but the body carries field 14 -> SuiteMismatch.
	oa := buildObject(t, c)
	oa.Suite = SuiteMLDSA65Ed25519
	if _, err := Verify(cose.ProfilePublic, pv, acceptKind, nil, signWhitebox(t, oa, ps)); err == nil || err.(*cose.Error).Kind != "SuiteMismatch" {
		t.Fatalf("pure alg + field 14: want SuiteMismatch, got %v", err)
	}
	// (b) composite alg but field 14 absent -> SuiteMismatch.
	ob := buildObject(t, c)
	ob.Suite = 0
	if _, err := Verify(cose.ProfilePublic, cv, acceptKind, nil, signWhitebox(t, ob, cs)); err == nil || err.(*cose.Error).Kind != "SuiteMismatch" {
		t.Fatalf("composite alg + no field 14: want SuiteMismatch, got %v", err)
	}
	// (c) composite alg but WRONG suite id -> SuiteMismatch.
	oc := buildObject(t, c)
	oc.Suite = SuiteMLDSA65Ed25519 + 1
	if _, err := Verify(cose.ProfilePublic, cv, acceptKind, nil, signWhitebox(t, oc, cs)); err == nil || err.(*cose.Error).Kind != "SuiteMismatch" {
		t.Fatalf("composite alg + wrong suite: want SuiteMismatch, got %v", err)
	}
}

// TestCompositeRefusedBySovereign (bar 4): a Sovereign verifier refuses a composite object
// with CompositeRefused — distinct from the generic ProfileDowngrade it would otherwise give.
func TestCompositeRefusedBySovereign(t *testing.T) {
	c := load(t)
	cs, cv := compositeTestKeys(t)
	obj, err := Sign(buildObject(t, c), cs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(cose.ProfileSovereign, cv, acceptKind, nil, obj); err == nil || err.(*cose.Error).Kind != "CompositeRefused" {
		t.Fatalf("sovereign on composite: want CompositeRefused, got %v", err)
	}
}

// --- #143 Rotation object (tag-98 COSE_Sign, old+new co-signature; design.md §5.2) ----

func rotationKindOK(channel, kind uint64) bool { return channel == 3 && kind == 0 }

func mldsa65Pair(t *testing.T, seed byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier) {
	t.Helper()
	var s [mldsa65.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
}

// rotationObject is the worked object relabeled to the Identity Rotation kind (channel 3, kind 0,
// effect non_idempotent_write per channels.csv).
func rotationObject(t *testing.T, c envCase) *Object {
	o := buildObject(t, c)
	o.Channel, o.Kind, o.Effect = 3, 0, 2
	return o
}

// TestRotationRoundTrip: a co-signed rotation object signs and verifies (happy path).
func TestRotationRoundTrip(t *testing.T) {
	c := load(t)
	oldS, oldV := mldsa65Pair(t, 11)
	newS, newV := mldsa65Pair(t, 22)
	obj, err := SignRotation(rotationObject(t, c), oldS, newS)
	if err != nil {
		t.Fatalf("SignRotation: %v", err)
	}
	got, err := VerifyRotationObject(cose.ProfilePublic, oldV, newV, rotationKindOK, nil, obj)
	if err != nil {
		t.Fatalf("VerifyRotationObject: %v", err)
	}
	if got.Channel != 3 || got.Kind != 0 {
		t.Fatalf("decoded rotation fields wrong: %+v", got)
	}
}

// TestRotationTag18SingleSigRejected (gap-fix mutation anchor): a single-Sign1 (tag-18) Rotation
// object with a VALID new-key signature is rejected RotationUnauthorized — removing the
// isRotationObject reject in Verify flips this pass->fail.
func TestRotationTag18SingleSigRejected(t *testing.T) {
	c := load(t)
	newS, newV := mldsa65Pair(t, 22)
	obj, err := Sign(rotationObject(t, c), newS) // tag-18 single-signature rotation
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(cose.ProfilePublic, newV, rotationKindOK, nil, obj); err == nil || err.(*cose.Error).Kind != "RotationUnauthorized" {
		t.Fatalf("tag-18 single-sig rotation: want RotationUnauthorized, got %v", err)
	}
}

// TestRotationOldLegDropped: a tag-98 rotation with the OLD leg dropped (one leg) is
// RotationUnauthorized.
func TestRotationOldLegDropped(t *testing.T) {
	c := load(t)
	oldS, oldV := mldsa65Pair(t, 11)
	newS, newV := mldsa65Pair(t, 22)
	obj, _ := SignRotation(rotationObject(t, c), oldS, newS)
	bodyProt, payload, legs, err := cose.ParseSignRaw(obj)
	if err != nil {
		t.Fatal(err)
	}
	oneLeg, _ := cose.AssembleSignRaw(bodyProt, payload, []cose.CoseSignLeg{legs[1]}) // drop old leg
	if _, err := VerifyRotationObject(cose.ProfilePublic, oldV, newV, rotationKindOK, nil, oneLeg); err == nil || err.(*cose.Error).Kind != "RotationUnauthorized" {
		t.Fatalf("dropped old leg: want RotationUnauthorized, got %v", err)
	}
}

// TestRotationOldLegWrongKey: the old leg replaced by a SECOND new-key leg does not verify under
// the trusted old key -> RotationUnauthorized (bar 4 wrong-key case; the caller-supplied-oldV
// design defeats the duplicated-new-key-leg forgery).
func TestRotationOldLegWrongKey(t *testing.T) {
	c := load(t)
	_, oldV := mldsa65Pair(t, 11)
	newS, newV := mldsa65Pair(t, 22)
	obj, _ := SignRotation(rotationObject(t, c), newS, newS) // both legs the NEW key
	if _, err := VerifyRotationObject(cose.ProfilePublic, oldV, newV, rotationKindOK, nil, obj); err == nil || err.(*cose.Error).Kind != "RotationUnauthorized" {
		t.Fatalf("wrong old-key leg: want RotationUnauthorized, got %v", err)
	}
}

// TestRotationTag98NonRotationKind: a tag-98 object on a non-rotation (channel,kind) is
// UnknownKind (tag-98 is permitted ONLY for the Identity Rotation kind).
func TestRotationTag98NonRotationKind(t *testing.T) {
	c := load(t)
	oldS, oldV := mldsa65Pair(t, 11)
	newS, newV := mldsa65Pair(t, 22)
	o := buildObject(t, c) // channel 4, kind 2 (NOT rotation)
	o.Suite = 0
	o.ID, _ = o.ContentID()
	payload, _ := cbor.Encode(o.bodyMap(true))
	bodyProt, _ := protectedHeader(newS.Alg(), o.Signer, o.Profile)
	oldLeg, _ := cose.SignatureLeg(bodyProt, oldS, payload)
	newLeg, _ := cose.SignatureLeg(bodyProt, newS, payload)
	obj, _ := cose.AssembleSignRaw(bodyProt, payload, []cose.CoseSignLeg{oldLeg, newLeg})
	if _, err := VerifyRotationObject(cose.ProfilePublic, oldV, newV, acceptKind, nil, obj); err == nil || err.(*cose.Error).Kind != "UnknownKind" {
		t.Fatalf("tag-98 non-rotation kind: want UnknownKind, got %v", err)
	}
}

// TestRotationSovereignOldLegFloor (OPEN-DECISION evidence): old=ML-DSA-65 (level 3), new=ML-DSA-87
// (level 5), profile=Sovereign (floor 5). With the DEFAULT toggle (floor applies to BOTH legs) the
// sub-floor OLD leg yields ProfileDowngrade. This is the exact open-decision scenario
// (rotationOldLegFloorApplies in rotation.go); set the toggle false to floor only the new leg.
func TestRotationSovereignOldLegFloor(t *testing.T) {
	c := load(t)
	var os1, ns1 [mldsa65.SeedSize]byte
	for i := range os1 {
		os1[i], ns1[i] = 33, 44
	}
	oldPk, oldSk := mldsa65.NewKeyFromSeed(&os1)
	newPk, newSk := mldsa87.NewKeyFromSeed(&ns1)
	oldS := cose.MLDSA65Signer{SK: oldSk}
	oldV := cose.MLDSA65Verifier{PK: oldPk}
	newS := cose.MLDSA87Signer{SK: newSk}
	newV := cose.MLDSA87Verifier{PK: newPk}

	o := rotationObject(t, c)
	o.Profile = 3 // Sovereign object
	obj, err := SignRotation(o, oldS, newS)
	if err != nil {
		t.Fatalf("SignRotation: %v", err)
	}
	if _, err := VerifyRotationObject(cose.ProfileSovereign, oldV, newV, rotationKindOK, nil, obj); err == nil || err.(*cose.Error).Kind != "ProfileDowngrade" {
		t.Fatalf("sovereign old-leg floor: want ProfileDowngrade, got %v", err)
	}
}
