// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package envelope

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// --- T1.6 per-signer forward-only counter (the OPTIONAL detection field, NAALP-REQ-120) --------

const signerCounterVectorPath = "../../../vectors/signer_counter/cases.json"

// flexU64 unmarshals a 64-bit counter carried as a JSON number OR, per R12 (values above 2^53),
// as a decimal string -- so a float64 decoder cannot round it before this loader parses it exactly.
// A JSON null leaves a *flexU64 field nil (encoding/json never calls UnmarshalJSON for null).
type flexU64 uint64

func (f *flexU64) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*f = flexU64(v)
	return nil
}

type counterCorpus struct {
	CounterKey uint64 `json:"counter_key"`
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
		Present      bool     `json:"present"`
		Counter      *flexU64 `json:"counter"`
		SignerHex    string   `json:"signer_hex"`
		BodyStr      string  `json:"body_str"`
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
	Detection struct {
		Scenarios []struct {
			Name    string `json:"name"`
			Objects []struct {
				SignerHex    string  `json:"signer_hex"`
				Counter      *uint64 `json:"counter"`
				BodyStr      string  `json:"body_str"`
				ContentIDHex string  `json:"content_id_hex"`
			} `json:"objects"`
			Expect []struct {
				SignerHex string   `json:"signer_hex"`
				Counter   uint64   `json:"counter"`
				IDsHex    []string `json:"ids_hex"`
			} `json:"expect"`
		} `json:"scenarios"`
	} `json:"detection"`
}

func loadCounter(t *testing.T) counterCorpus {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(signerCounterVectorPath))
	if err != nil {
		t.Fatalf("read signer_counter corpus: %v", err)
	}
	var c counterCorpus
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse signer_counter corpus: %v", err)
	}
	return c
}

// baseCounterObject builds the shared base object (fields 2..10) from logical fields, with an
// optional signer/body override — never from the oracle hex, so a constant encoder diverges.
func baseCounterObject(t *testing.T, corpus counterCorpus, signerHex, bodyStr string) *Object {
	t.Helper()
	var causes [][]byte
	for _, h := range corpus.Base.CausesHex {
		causes = append(causes, mh(t, h))
	}
	sh := corpus.Base.SignerHex
	if signerHex != "" {
		sh = signerHex
	}
	bs := corpus.Base.BodyStr
	if bodyStr != "" {
		bs = bodyStr
	}
	return &Object{
		Kind: corpus.Base.Kind, Channel: corpus.Base.Channel, Tier: corpus.Base.Tier,
		Signer: mh(t, sh), Created: corpus.Base.Created, Effect: corpus.Base.Effect,
		Causes: causes, Profile: corpus.Base.Profile, Body: cbor.Tstr(bs),
	}
}

// applyPlacement applies the case's counter placement — the ONLY variable per case.
func applyPlacement(t *testing.T, o *Object, placement string, counter *flexU64) {
	t.Helper()
	switch placement {
	case "ext":
		o.SetSignerCounter(uint64(*counter))
	case "cext":
		// the counter placed in the CRITICAL map is an unrecognized critical extension.
		o.Cext = cbor.Map{{K: cbor.Uint(SignerCounterKey), V: cbor.Uint(uint64(*counter))}}
	case "ext_empty":
		o.Ext = cbor.Map{} // present but empty (no counter) — distinct bytes from absent
	case "absent":
		// no ext, no cext
	default:
		t.Fatalf("unknown placement %q", placement)
	}
}

// TestSignerCounterMatchesOracle grades counter body bytes AND accept/reject verdicts against the
// independent oracle (tools/signer_counter_oracle.py): every body_no_id_hex/content_id_hex/full_hex
// is byte-identical, and every case verifies or fails with exactly the oracle's verdict over a REAL
// ML-DSA-65 signed object. knownCext is nil throughout — the counter is enforced by the envelope's
// existing rules, not the caller's critical-extension set.
func TestSignerCounterMatchesOracle(t *testing.T) {
	corpus := loadCounter(t)
	if corpus.CounterKey != SignerCounterKey {
		t.Fatalf("counter_key: corpus %d != impl %d", corpus.CounterKey, SignerCounterKey)
	}
	s, v := testSigner(t)
	for _, tc := range corpus.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			o := baseCounterObject(t, corpus, tc.SignerHex, tc.BodyStr)
			applyPlacement(t, o, tc.Placement, tc.Counter)

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
			o2 := baseCounterObject(t, corpus, tc.SignerHex, tc.BodyStr)
			applyPlacement(t, o2, tc.Placement, tc.Counter)
			signed, err := Sign(o2, s)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			got, verr := Verify(cose.ProfilePublic, v, acceptKind, nil, signed)
			if tc.Expect == "accept" {
				if verr != nil {
					t.Fatalf("expected accept, got %v", verr)
				}
				seq, present := got.SignerCounter()
				if present != tc.Present {
					t.Fatalf("SignerCounter present: got %v want %v", present, tc.Present)
				}
				if present {
					if tc.Counter == nil || seq != uint64(*tc.Counter) {
						t.Fatalf("SignerCounter value: got %d want %v", seq, tc.Counter)
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

	// non-canonical counter bodies (ext keys out of order) are rejected at the CBOR layer.
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

// TestSignerCounterUnderSignature proves the counter is folded into the SIGNER's COSE_Sign1 signed
// input (ext, field 11, is part of the signed body): flipping the counter value in a signed object's
// payload breaks verification. A signer-signed (not ledger-signed) counter is the whole point.
func TestSignerCounterUnderSignature(t *testing.T) {
	corpus := loadCounter(t)
	s, v := testSigner(t)
	o := baseCounterObject(t, corpus, "", "")
	o.SetSignerCounter(5)
	signed, err := Sign(o, s)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// baseline: the signed object verifies and reads back counter 5.
	got, err := Verify(cose.ProfilePublic, v, acceptKind, nil, signed)
	if err != nil {
		t.Fatalf("verify valid: %v", err)
	}
	if seq, present := got.SignerCounter(); !present || seq != 5 {
		t.Fatalf("counter read-back: got (%d,%v) want (5,true)", seq, present)
	}
	// tamper: change the counter to 6 and re-encode the body WITHOUT re-signing; the object must be
	// rejected (the content id no longer matches the signed body / the signature no longer covers it).
	tampered := baseCounterObject(t, corpus, "", "")
	tampered.SetSignerCounter(6)
	tampered.ID = o.ID // keep the original (counter=5) content id — a splice, not a re-sign
	payload, _ := cbor.Encode(tampered.bodyMap(true))
	prot, _ := protectedHeader(s.Alg(), tampered.Signer, tampered.Profile)
	// reuse the ORIGINAL signature bytes from the counter=5 object (a real forgery attempt).
	_, _, origSig, _ := cose.ParseSign1Raw(signed)
	forged, _ := cose.AssembleSign1Raw(prot, payload, origSig)
	if _, verr := Verify(cose.ProfilePublic, v, acceptKind, nil, forged); verr == nil {
		t.Fatal("tampered counter must be rejected (the counter is under signature), got accept")
	}
}

// TestSignerCounterReaderRoundTrip proves SetSignerCounter/SignerCounter carry the value, that the
// field is OPTIONAL (a fresh object has none), and that a present counter of value 0 reads back
// present (present is keyed on the key, not the value).
func TestSignerCounterReaderRoundTrip(t *testing.T) {
	corpus := loadCounter(t)
	o := baseCounterObject(t, corpus, "", "")
	if _, present := o.SignerCounter(); present {
		t.Fatal("fresh object must have no counter")
	}
	o.SetSignerCounter(42)
	if seq, present := o.SignerCounter(); !present || seq != 42 {
		t.Fatalf("counter read back wrong: seq=%d present=%v", seq, present)
	}
	o.SetSignerCounter(0) // present with value zero
	if seq, present := o.SignerCounter(); !present || seq != 0 {
		t.Fatalf("present-zero counter must read back present: seq=%d present=%v", seq, present)
	}
}

// buildScenarioObjects reconstructs a detection scenario's presented objects from their logical
// fields and cross-checks each recomputed content id against the oracle's.
func buildScenarioObjects(t *testing.T, corpus counterCorpus, objs []struct {
	SignerHex    string  `json:"signer_hex"`
	Counter      *uint64 `json:"counter"`
	BodyStr      string  `json:"body_str"`
	ContentIDHex string  `json:"content_id_hex"`
}) []*Object {
	t.Helper()
	out := make([]*Object, 0, len(objs))
	for _, ro := range objs {
		o := baseCounterObject(t, corpus, ro.SignerHex, ro.BodyStr)
		if ro.Counter != nil {
			o.SetSignerCounter(*ro.Counter)
		}
		id, err := o.ContentID()
		if err != nil {
			t.Fatalf("content id: %v", err)
		}
		if got := hex.EncodeToString(id); got != ro.ContentIDHex {
			t.Fatalf("scenario object content-id\n got %s\nwant %s", got, ro.ContentIDHex)
		}
		out = append(out, o)
	}
	return out
}

// TestDetectSignerDuplicationMatchesOracle grades DetectSignerDuplication over every scenario in the
// independent oracle: the impl reconstructs the presented set and MUST reproduce the oracle's exact
// findings (signer, counter, and the SET of surfaced content ids).
func TestDetectSignerDuplicationMatchesOracle(t *testing.T) {
	corpus := loadCounter(t)
	for _, sc := range corpus.Detection.Scenarios {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			objs := buildScenarioObjects(t, corpus, sc.Objects)
			findings := DetectSignerDuplication(objs)
			if len(findings) != len(sc.Expect) {
				t.Fatalf("findings count: got %d want %d", len(findings), len(sc.Expect))
			}
			for i, want := range sc.Expect {
				got := findings[i]
				if hex.EncodeToString(got.Signer) != want.SignerHex {
					t.Fatalf("finding %d signer: got %s want %s", i, hex.EncodeToString(got.Signer), want.SignerHex)
				}
				if got.Counter != want.Counter {
					t.Fatalf("finding %d counter: got %d want %d", i, got.Counter, want.Counter)
				}
				if len(got.IDs) != len(want.IDsHex) {
					t.Fatalf("finding %d ids count: got %d want %d", i, len(got.IDs), len(want.IDsHex))
				}
				for j, idHex := range want.IDsHex {
					if hex.EncodeToString(got.IDs[j]) != idHex {
						t.Fatalf("finding %d id %d: got %s want %s", i, j, hex.EncodeToString(got.IDs[j]), idHex)
					}
				}
			}
		})
	}
}

// TestDetectOneSequenceNotFlagged is case (a) and the MUTATION ANCHOR for the detection function:
// a single sequence (one object per value) MUST NOT be flagged — detection requires two conflicting
// sequences to physically meet. Relaxing the `len(idset) < 2` guard in DetectSignerDuplication to
// `< 1` (flag from one) flips this test pass->fail; that is the whole detection-not-prevention line.
func TestDetectOneSequenceNotFlagged(t *testing.T) {
	corpus := loadCounter(t)
	// one object alone at position 5.
	one := baseCounterObject(t, corpus, "", "holder")
	one.SetSignerCounter(5)
	if f := DetectSignerDuplication([]*Object{one}); len(f) != 0 {
		t.Fatalf("one sequence alone must not be flagged, got %d finding(s)", len(f))
	}
	// a full honest forward-only sequence from one signer (1,2,3) is also one sequence -> not flagged.
	var seqObjs []*Object
	for i, body := range []string{"s1", "s2", "s3"} {
		o := baseCounterObject(t, corpus, "", body)
		o.SetSignerCounter(uint64(i + 1))
		seqObjs = append(seqObjs, o)
	}
	if f := DetectSignerDuplication(seqObjs); len(f) != 0 {
		t.Fatalf("an honest forward-only sequence must not be flagged, got %d finding(s)", len(f))
	}
}

// TestDetectTwoConflictingFlagged is case (b): two DISTINCT objects, SAME signer id, SAME counter
// value, presented TOGETHER -> flagged once, surfacing BOTH content ids. This is the duplication
// fingerprint and it is only observable because both objects are present.
func TestDetectTwoConflictingFlagged(t *testing.T) {
	corpus := loadCounter(t)
	holder := baseCounterObject(t, corpus, "", "holder")
	holder.SetSignerCounter(5)
	thief := baseCounterObject(t, corpus, "", "thief")
	thief.SetSignerCounter(5)

	f := DetectSignerDuplication([]*Object{holder, thief})
	if len(f) != 1 {
		t.Fatalf("two conflicting sequences must be flagged once, got %d", len(f))
	}
	if f[0].Counter != 5 {
		t.Fatalf("finding counter: got %d want 5", f[0].Counter)
	}
	if len(f[0].IDs) != 2 {
		t.Fatalf("both conflicting content ids must be surfaced, got %d", len(f[0].IDs))
	}
	hid, _ := holder.ContentID()
	tid, _ := thief.ContentID()
	surfaced := map[string]bool{}
	for _, id := range f[0].IDs {
		surfaced[string(id)] = true
	}
	if !surfaced[string(hid)] || !surfaced[string(tid)] {
		t.Fatal("the finding must surface both the holder's and the thief's content ids")
	}
}

// TestDetectForwardOnlyConsistentNotFlagged is case (c): two objects from one signer at DIFFERENT
// (forward-only consistent) positions are not flagged; nor are two different signers at one position.
func TestDetectForwardOnlyConsistentNotFlagged(t *testing.T) {
	corpus := loadCounter(t)
	a5 := baseCounterObject(t, corpus, "", "holder")
	a5.SetSignerCounter(5)
	a6 := baseCounterObject(t, corpus, "", "next")
	a6.SetSignerCounter(6)
	if f := DetectSignerDuplication([]*Object{a5, a6}); len(f) != 0 {
		t.Fatalf("forward-only-consistent sequence must not be flagged, got %d", len(f))
	}

	// per-signer: SIGNER_B at position 5 does not conflict with SIGNER_A at position 5.
	b5 := baseCounterObject(t, corpus, "5349474e45525f42", "other")
	b5.SetSignerCounter(5)
	if f := DetectSignerDuplication([]*Object{a5, b5}); len(f) != 0 {
		t.Fatalf("different signers at one value must not be flagged, got %d", len(f))
	}
}

// TestSignerCounterAbsentValidates is case (d) and the MUTATION ANCHOR for optionality: an object
// carrying NO counter Signs and Verifies. Making the field mandatory (e.g. adding a
// reject-if-absent check to Verify) flips this test pass->fail.
func TestSignerCounterAbsentValidates(t *testing.T) {
	corpus := loadCounter(t)
	s, v := testSigner(t)
	o := baseCounterObject(t, corpus, "", "")
	if _, present := o.SignerCounter(); present {
		t.Fatal("object built without a counter must have none")
	}
	signed, err := Sign(o, s)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := Verify(cose.ProfilePublic, v, acceptKind, nil, signed)
	if err != nil {
		t.Fatalf("an object with an absent counter must verify (the field is OPTIONAL), got %v", err)
	}
	if _, present := got.SignerCounter(); present {
		t.Fatal("verified object must report no counter")
	}
}
