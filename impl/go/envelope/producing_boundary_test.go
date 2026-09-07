// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package envelope

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// --- NA-IETF-1 producing-boundary disclosure (the OPTIONAL, self-asserted ext key 15, §2.5.4) ----

const producingBoundaryVectorPath = "../../../vectors/producing_boundary/cases.json"

type pbSurfaced struct {
	Kind         uint64  `json:"kind"`
	BoundaryHex  string  `json:"boundary_hex"`
	ReportingHex *string `json:"reporting_hex"`
}

type pbCase struct {
	Name         string      `json:"name"`
	Placement    string      `json:"placement"`
	BoundaryHex  *string     `json:"boundary_hex"`
	Kind         *uint64     `json:"kind"`
	ReportingHex *string     `json:"reporting_hex"`
	Present      bool        `json:"present"`
	Surfaced     *pbSurfaced `json:"surfaced"`
	BodyNoIDHex  string      `json:"body_no_id_hex"`
	ContentIDHex string      `json:"content_id_hex"`
	FullHex      string      `json:"full_hex"`
	Expect       string      `json:"expect"`
}

type pbCorpus struct {
	Key  uint64 `json:"producing_boundary_key"`
	Base struct {
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
	Cases     []pbCase `json:"cases"`
	Negatives []struct {
		Name       string `json:"name"`
		PayloadHex string `json:"payload_hex"`
		Expect     string `json:"expect"`
	} `json:"negatives"`
}

func loadPB(t *testing.T) pbCorpus {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(producingBoundaryVectorPath))
	if err != nil {
		t.Fatalf("read producing_boundary corpus: %v", err)
	}
	var c pbCorpus
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse producing_boundary corpus: %v", err)
	}
	return c
}

// basePBObject builds the shared base object (fields 2..10) from logical fields — never from the
// oracle hex, so a constant encoder diverges from the pinned bytes.
func basePBObject(t *testing.T, corpus pbCorpus) *Object {
	t.Helper()
	var causes [][]byte
	for _, h := range corpus.Base.CausesHex {
		causes = append(causes, mh(t, h))
	}
	return &Object{
		Kind: corpus.Base.Kind, Channel: corpus.Base.Channel, Tier: corpus.Base.Tier,
		Signer: mh(t, corpus.Base.SignerHex), Created: corpus.Base.Created, Effect: corpus.Base.Effect,
		Causes: causes, Profile: corpus.Base.Profile, Body: cbor.Tstr(corpus.Base.BodyStr),
	}
}

// applyPBPlacement builds the ext[15]/cext[15] sub-map DIRECTLY from the case's logical fields — the
// ONLY variable per case — reproducing the oracle bytes for well-formed AND malformed values (the
// malformed cases cannot be built via SetProducingBoundary by design, so they are constructed here).
func applyPBPlacement(t *testing.T, o *Object, tc pbCase) {
	t.Helper()
	if tc.Placement == "absent" {
		return
	}
	var sub cbor.Map
	if tc.BoundaryHex != nil {
		sub = append(sub, cbor.Pair{K: cbor.Uint(pbFieldBoundary), V: cbor.Bstr(mh(t, *tc.BoundaryHex))})
	}
	if tc.Kind != nil {
		sub = append(sub, cbor.Pair{K: cbor.Uint(pbFieldKind), V: cbor.Uint(*tc.Kind)})
	}
	if tc.ReportingHex != nil {
		sub = append(sub, cbor.Pair{K: cbor.Uint(pbFieldReporting), V: cbor.Bstr(mh(t, *tc.ReportingHex))})
	}
	ext := cbor.Map{{K: cbor.Uint(ProducingBoundaryKey), V: sub}}
	switch tc.Placement {
	case "ext":
		o.Ext = ext
	case "cext":
		o.Cext = ext
	default:
		t.Fatalf("unknown placement %q", tc.Placement)
	}
}

// TestProducingBoundaryMatchesOracle grades disclosure body bytes, accept/reject verdicts, AND the
// parsed disclosure (present/kind/boundary/reporting) against the independent oracle
// (tools/producing_boundary_oracle.py): every body_no_id_hex/content_id_hex/full_hex is
// byte-identical, and every case verifies or fails with exactly the oracle's verdict over a REAL
// ML-DSA-65 signed object. knownCext is nil throughout — the disclosure is enforced by the
// envelope's existing rules, not the caller's critical-extension set.
func TestProducingBoundaryMatchesOracle(t *testing.T) {
	corpus := loadPB(t)
	if corpus.Key != ProducingBoundaryKey {
		t.Fatalf("producing_boundary_key: corpus %d != impl %d", corpus.Key, ProducingBoundaryKey)
	}
	s, v := testSigner(t)
	for _, tc := range corpus.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			o := basePBObject(t, corpus)
			applyPBPlacement(t, o, tc)

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
			o2 := basePBObject(t, corpus)
			applyPBPlacement(t, o2, tc)
			signed, err := Sign(o2, s)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			got, verr := Verify(cose.ProfilePublic, v, acceptKind, nil, signed)
			if tc.Expect == "accept" {
				if verr != nil {
					t.Fatalf("expected accept, got %v", verr)
				}
				pb, present := got.ProducingBoundary()
				if present != tc.Present {
					t.Fatalf("ProducingBoundary present: got %v want %v", present, tc.Present)
				}
				if present {
					if tc.Surfaced == nil {
						t.Fatal("corpus marks present but carries no surfaced disclosure")
					}
					if pb.Kind != tc.Surfaced.Kind {
						t.Fatalf("kind: got %d want %d", pb.Kind, tc.Surfaced.Kind)
					}
					if got := hex.EncodeToString(pb.Boundary); got != tc.Surfaced.BoundaryHex {
						t.Fatalf("boundary: got %s want %s", got, tc.Surfaced.BoundaryHex)
					}
					wantReporting := ""
					if tc.Surfaced.ReportingHex != nil {
						wantReporting = *tc.Surfaced.ReportingHex
					}
					if got := hex.EncodeToString(pb.Reporting); got != wantReporting {
						t.Fatalf("reporting: got %s want %s", got, wantReporting)
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

	// non-canonical disclosure bodies (sub-map keys out of order) are rejected at the CBOR layer.
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

// TestProducingBoundaryUnderSignature proves the disclosure is folded into the SIGNER's COSE_Sign1
// signed input (ext, field 11, is part of the signed body): changing the boundary in a signed
// object's payload without re-signing breaks verification. A self-asserted disclosure that is NOT
// under the signer's signature would be forgeable, defeating attributability.
func TestProducingBoundaryUnderSignature(t *testing.T) {
	corpus := loadPB(t)
	s, v := testSigner(t)
	o := basePBObject(t, corpus)
	o.SetProducingBoundary(ProducingBoundary{Boundary: mh(t, "424f554e444152595f58"), Kind: ProducingBoundaryObserved})
	signed, err := Sign(o, s)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// baseline: the signed object verifies and reads back the disclosure.
	got, err := Verify(cose.ProfilePublic, v, acceptKind, nil, signed)
	if err != nil {
		t.Fatalf("verify valid: %v", err)
	}
	if pb, present := got.ProducingBoundary(); !present || pb.Kind != ProducingBoundaryObserved {
		t.Fatalf("disclosure read-back: got (%+v,%v)", pb, present)
	}
	// tamper: change the boundary and re-encode the body WITHOUT re-signing; keep the original id
	// and reuse the original signature bytes — a real forgery attempt that MUST be rejected.
	tampered := basePBObject(t, corpus)
	tampered.SetProducingBoundary(ProducingBoundary{Boundary: mh(t, "4f524947494e5f59"), Kind: ProducingBoundaryObserved})
	tampered.ID = o.ID // keep the original content id — a splice, not a re-sign
	payload, _ := cbor.Encode(tampered.bodyMap(true))
	prot, _ := protectedHeader(s.Alg(), tampered.Signer, tampered.Profile)
	_, _, origSig, _ := cose.ParseSign1Raw(signed)
	forged, _ := cose.AssembleSign1Raw(prot, payload, origSig)
	if _, verr := Verify(cose.ProfilePublic, v, acceptKind, nil, forged); verr == nil {
		t.Fatal("tampered producing-boundary must be rejected (it is under signature), got accept")
	}
}

// TestProducingBoundaryReaderRoundTrip proves SetProducingBoundary/ProducingBoundary carry the value,
// that the field is OPTIONAL (a fresh object has none), that a reported disclosure carries its
// reporting-boundary, and that the setter DROPS a reporting-boundary under observed (an observer
// relays from no one) so a caller cannot accidentally build a malformed disclosure.
func TestProducingBoundaryReaderRoundTrip(t *testing.T) {
	corpus := loadPB(t)
	o := basePBObject(t, corpus)
	if _, present := o.ProducingBoundary(); present {
		t.Fatal("fresh object must have no producing-boundary disclosure")
	}
	x := mh(t, "424f554e444152595f58")
	y := mh(t, "4f524947494e5f59")

	o.SetProducingBoundary(ProducingBoundary{Boundary: x, Kind: ProducingBoundaryReported, Reporting: y})
	pb, present := o.ProducingBoundary()
	if !present || pb.Kind != ProducingBoundaryReported ||
		hex.EncodeToString(pb.Boundary) != "424f554e444152595f58" ||
		hex.EncodeToString(pb.Reporting) != "4f524947494e5f59" {
		t.Fatalf("reported disclosure round-trip wrong: %+v present=%v", pb, present)
	}

	// the setter drops a reporting-boundary under observed: the read-back must have no reporting.
	o.SetProducingBoundary(ProducingBoundary{Boundary: x, Kind: ProducingBoundaryObserved, Reporting: y})
	pb, present = o.ProducingBoundary()
	if !present || pb.Kind != ProducingBoundaryObserved || pb.Reporting != nil {
		t.Fatalf("observed disclosure must drop reporting: %+v present=%v", pb, present)
	}
}

// TestProducingBoundaryMalformedIgnored is the MUTATION ANCHOR for the may-ignore rule: a well-formed
// object carrying a MALFORMED producing-boundary in the non-critical ext map (a reporting-boundary
// under observed) still Signs and Verifies, and the disclosure is NOT surfaced. Removing the
// "reporting under observed -> malformed" check in ProducingBoundary flips present false->true and
// this test pass->fail; that check is the observer-relays-from-no-one invariant.
func TestProducingBoundaryMalformedIgnored(t *testing.T) {
	corpus := loadPB(t)
	s, v := testSigner(t)
	o := basePBObject(t, corpus)
	// build the malformed ext[15] = {1:X, 2:observed, 3:Y} directly (the setter refuses to build it).
	o.Ext = cbor.Map{{K: cbor.Uint(ProducingBoundaryKey), V: cbor.Map{
		{K: cbor.Uint(pbFieldBoundary), V: cbor.Bstr(mh(t, "424f554e444152595f58"))},
		{K: cbor.Uint(pbFieldKind), V: cbor.Uint(ProducingBoundaryObserved)},
		{K: cbor.Uint(pbFieldReporting), V: cbor.Bstr(mh(t, "4f524947494e5f59"))},
	}}}
	signed, err := Sign(o, s)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := Verify(cose.ProfilePublic, v, acceptKind, nil, signed)
	if err != nil {
		t.Fatalf("a malformed non-critical disclosure must be ignored, not rejected (may-ignore), got %v", err)
	}
	if _, present := got.ProducingBoundary(); present {
		t.Fatal("a malformed disclosure (reporting under observed) must NOT be surfaced")
	}
}

// TestProducingBoundaryCextRejected is the MUTATION ANCHOR for the fail-closed rule: the disclosure
// placed in the CRITICAL cext map (field 12) is an unrecognized critical extension and the object is
// rejected UnknownCriticalExt. A disclosure must never masquerade as a must-understand gate.
func TestProducingBoundaryCextRejected(t *testing.T) {
	corpus := loadPB(t)
	s, v := testSigner(t)
	o := basePBObject(t, corpus)
	o.Cext = cbor.Map{{K: cbor.Uint(ProducingBoundaryKey), V: cbor.Map{
		{K: cbor.Uint(pbFieldBoundary), V: cbor.Bstr(mh(t, "424f554e444152595f58"))},
		{K: cbor.Uint(pbFieldKind), V: cbor.Uint(ProducingBoundaryObserved)},
	}}}
	signed, err := Sign(o, s)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, verr := Verify(cose.ProfilePublic, v, acceptKind, nil, signed)
	ce, ok := verr.(*cose.Error)
	if !ok || ce.Kind != "UnknownCriticalExt" {
		t.Fatalf("cext producing-boundary must be rejected UnknownCriticalExt, got %v", verr)
	}
}
