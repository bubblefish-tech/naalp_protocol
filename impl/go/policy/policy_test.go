// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package policy_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/n-aalp/impl/go/cbor"
	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
	"github.com/bubblefish-tech/n-aalp/impl/go/envelope"
	"github.com/bubblefish-tech/n-aalp/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/effect/cases.json"

type effCases struct {
	Effects []struct {
		Value       uint64 `json:"value"`
		SafetyLabel string `json:"safety_label"`
	} `json:"effects"`
	BridgeMapping []struct {
		Effect      uint64 `json:"effect"`
		NpampU8     uint8  `json:"npamp_u8"`
		SafetyLabel string `json:"safety_label"`
	} `json:"bridge_mapping"`
	AuthorizationMatrix []struct {
		Granted uint8  `json:"granted"`
		Effect  uint64 `json:"effect"`
		Allow   bool   `json:"allow"`
	} `json:"authorization_matrix"`
	UnknownNormalization []struct {
		Input  uint64 `json:"input"`
		Effect uint64 `json:"effect"`
	} `json:"unknown_normalization"`
	PrincipalSources []struct {
		Source   string `json:"source"`
		Accepted bool   `json:"accepted"`
	} `json:"principal_sources"`
	SafetyLabel struct {
		Risk    string `json:"risk"`
		Scope   string `json:"scope"`
		ExtKey  uint64 `json:"ext_key"`
		CborHex string `json:"cbor_hex"`
	} `json:"safety_label"`
}

func load(t *testing.T) effCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c effCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

// TestEffectNamesAndBridgeMatchOracle: the four names and the identity Bridge SafetyLabel
// mapping equal the independent oracle (⟹ Go == Rust, which grades the same file).
func TestEffectNamesAndBridgeMatchOracle(t *testing.T) {
	c := load(t)
	if len(c.Effects) != 4 {
		t.Fatalf("want 4 effects, got %d", len(c.Effects))
	}
	for _, e := range c.Effects {
		if got := policy.Effect(e.Value).SafetyLabelName(); got != e.SafetyLabel {
			t.Errorf("effect %d name: got %q want %q", e.Value, got, e.SafetyLabel)
		}
		if got := policy.Effect(e.Value).SafetyLabelByte(); got != uint8(e.Value) {
			t.Errorf("effect %d byte: got %d want %d", e.Value, got, e.Value)
		}
	}
	for _, m := range c.BridgeMapping {
		if got := policy.EffectFromSafetyLabelByte(m.NpampU8); got != policy.Effect(m.Effect) {
			t.Errorf("bridge u8 %d -> effect %d, want %d", m.NpampU8, got, m.Effect)
		}
	}
}

// TestNormalizeUnknownIsDestructive: R-6.2 — any unrecognized effect value normalizes to
// destructive and never fails open.
func TestNormalizeUnknownIsDestructive(t *testing.T) {
	c := load(t)
	// closed set is identity
	for v := uint64(0); v <= 3; v++ {
		if got := policy.NormalizeEffect(v); got != policy.Effect(v) {
			t.Errorf("normalize(%d) = %d, want %d", v, got, v)
		}
	}
	if len(c.UnknownNormalization) == 0 {
		t.Fatal("no unknown-normalization cases")
	}
	for _, u := range c.UnknownNormalization {
		got := policy.NormalizeEffect(u.Input)
		if got != policy.Effect(u.Effect) {
			t.Errorf("normalize(%d) = %d, want %d", u.Input, got, u.Effect)
		}
		if got != policy.Destructive {
			t.Errorf("unknown %d must be destructive, got %d", u.Input, got)
		}
	}
	// Bridge carriage is fail-closed too (R-6.2 / N-PAMP §7): an unknown SafetyLabel byte.
	if policy.EffectFromSafetyLabelByte(200) != policy.Destructive {
		t.Error("unknown SafetyLabel byte must map to destructive")
	}
}

// TestAuthorizationMatrix: R-6.3 — the full granted×effect authorize/deny table holds, and
// a grant authorizes exactly the effects at or below its ceiling. A policy that ignored the
// effect (constant allow/deny) would fail: the matrix contains both allows and denies.
func TestAuthorizationMatrix(t *testing.T) {
	c := load(t)
	if len(c.AuthorizationMatrix) != 16 {
		t.Fatalf("want 16 matrix cells, got %d", len(c.AuthorizationMatrix))
	}
	allows, denies := 0, 0
	for _, r := range c.AuthorizationMatrix {
		g := policy.Grant{Principal: "pA", MaxEffect: policy.Effect(r.Granted)}
		err := g.AuthorizeObject(policy.SourceSignature, "pA", r.Effect)
		if r.Allow {
			allows++
			if err != nil {
				t.Errorf("granted=%d effect=%d: want allow, got %v", r.Granted, r.Effect, err)
			}
		} else {
			denies++
			if ce, ok := err.(*cose.Error); !ok || ce.Kind != "EffectNotAuthorized" {
				t.Errorf("granted=%d effect=%d: want EffectNotAuthorized, got %v", r.Granted, r.Effect, err)
			}
		}
		// the raw lattice must agree with the matrix
		if got := policy.Effect(r.Granted).Authorizes(policy.NormalizeEffect(r.Effect)); got != r.Allow {
			t.Errorf("Authorizes(%d,%d)=%v, want %v", r.Granted, r.Effect, got, r.Allow)
		}
	}
	if allows == 0 || denies == 0 {
		t.Fatalf("matrix must contain both allows and denies (allows=%d denies=%d)", allows, denies)
	}
}

// TestPrincipalSourceGate: R-6.5 — only a signature-derived identity is an authorization
// principal. A grant that would authorize the effect is still denied when the presenter's
// identity is transport metadata, a foreign header, or a client-supplied name.
func TestPrincipalSourceGate(t *testing.T) {
	c := load(t)
	srcMap := map[string]policy.PrincipalSource{
		"signature":          policy.SourceSignature,
		"transport_metadata": policy.SourceTransportMetadata,
		"foreign_header":     policy.SourceForeignHeader,
		"client_name":        policy.SourceClientName,
	}
	g := policy.Grant{Principal: "pA", MaxEffect: policy.Destructive} // maximally permissive ceiling
	for _, ps := range c.PrincipalSources {
		src, ok := srcMap[ps.Source]
		if !ok {
			t.Fatalf("unknown principal source %q in corpus", ps.Source)
		}
		_, err := policy.ResolveAuthPrincipal(src, "pA")
		if (err == nil) != ps.Accepted {
			t.Errorf("ResolveAuthPrincipal(%s): accepted=%v, want %v (err=%v)", ps.Source, err == nil, ps.Accepted, err)
		}
		// even a read_only object (within the ceiling) is denied from a non-signature source.
		err = g.AuthorizeObject(src, "pA", uint64(policy.ReadOnly))
		if ps.Accepted {
			if err != nil {
				t.Errorf("%s: signature-derived read_only should authorize, got %v", ps.Source, err)
			}
		} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "UnauthenticatedPrincipal" {
			t.Errorf("%s: want UnauthenticatedPrincipal, got %v", ps.Source, err)
		}
	}
}

// TestSafetyLabelBytesMatchOracle: the safety-label CBOR equals the independently
// constructed bytes (⟹ Go == Rust).
func TestSafetyLabelBytesMatchOracle(t *testing.T) {
	c := load(t)
	got, err := policy.SafetyLabel{Risk: c.SafetyLabel.Risk, Scope: c.SafetyLabel.Scope}.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if hex.EncodeToString(got) != c.SafetyLabel.CborHex {
		t.Errorf("safety-label bytes\n got %s\nwant %s", hex.EncodeToString(got), c.SafetyLabel.CborHex)
	}
}

func testSigner(t *testing.T) (cose.MLDSA65Signer, cose.MLDSA65Verifier, []byte) {
	t.Helper()
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 5
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}, pk.Bytes()
}

func mkObj(signer []byte, label policy.SafetyLabel) *envelope.Object {
	return &envelope.Object{
		Kind: 0, Channel: 0, Tier: 0, Signer: signer, Created: 1000,
		Effect: uint64(policy.IdempotentWrite), Causes: nil,
		Profile: uint64(cose.ProfilePublic), Body: cbor.Uint(0), Ext: label.Ext(),
	}
}

// TestSafetyLabelBoundUnderSignature: R-6.4 — the optional safety label is carried in the
// signed body, so it is attributable to the signer and cannot be swapped without breaking
// the signature. Two objects differing only in the label sign to different bytes, each
// recovers its own label (a constant extractor fails this), and splicing one object's body
// under the other's signature is rejected as BadSignature.
func TestSafetyLabelBoundUnderSignature(t *testing.T) {
	s, v, signer := testSigner(t)
	kindOK := func(ch, k uint64) bool { return true }

	low := policy.SafetyLabel{Risk: "low", Scope: "cache"}
	high := policy.SafetyLabel{Risk: "elevated", Scope: "billing-records"}

	signedA, err := envelope.Sign(mkObj(signer, low), s)
	if err != nil {
		t.Fatalf("sign A: %v", err)
	}
	signedB, err := envelope.Sign(mkObj(signer, high), s)
	if err != nil {
		t.Fatalf("sign B: %v", err)
	}
	if hex.EncodeToString(signedA) == hex.EncodeToString(signedB) {
		t.Fatal("differing safety labels produced identical signed bytes (label is not under signature)")
	}

	oa, err := envelope.Verify(cose.ProfilePublic, v, kindOK, nil, signedA)
	if err != nil {
		t.Fatalf("verify A: %v", err)
	}
	gotA, present, err := policy.SafetyLabelFromExt(oa.Ext)
	if err != nil || !present || *gotA != low {
		t.Fatalf("recover A: label=%v present=%v err=%v", gotA, present, err)
	}
	ob, err := envelope.Verify(cose.ProfilePublic, v, kindOK, nil, signedB)
	if err != nil {
		t.Fatalf("verify B: %v", err)
	}
	gotB, _, _ := policy.SafetyLabelFromExt(ob.Ext)
	if gotB == nil || *gotB != high {
		t.Fatalf("recover B: got %v want %v", gotB, high)
	}

	// Splice objB's body under objA's signature (headers are identical). Rejected as
	// BadSignature — the label is inside the signed content.
	protA, _, sigA, err := cose.ParseSign1Raw(signedA)
	if err != nil {
		t.Fatalf("parse A: %v", err)
	}
	_, payloadB, _, err := cose.ParseSign1Raw(signedB)
	if err != nil {
		t.Fatalf("parse B: %v", err)
	}
	forge, err := cose.AssembleSign1Raw(protA, payloadB, sigA)
	if err != nil {
		t.Fatalf("assemble forge: %v", err)
	}
	if _, err := envelope.Verify(cose.ProfilePublic, v, kindOK, nil, forge); err == nil {
		t.Fatal("spliced label accepted (safety label not bound under signature)")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "BadSignature" {
		t.Fatalf("want BadSignature on forge, got %v", err)
	}
}

// TestSafetyLabelExtErrors: absent label is (nil,false,nil); a malformed ext[1] is rejected.
func TestSafetyLabelExtErrors(t *testing.T) {
	if l, present, err := policy.SafetyLabelFromExt(nil); l != nil || present || err != nil {
		t.Errorf("absent ext: got (%v,%v,%v)", l, present, err)
	}
	// ext[1] present but not a map
	bad := cbor.Map{{K: cbor.Uint(policy.SafetyLabelExtKey), V: cbor.Uint(9)}}
	if _, _, err := policy.SafetyLabelFromExt(bad); err == nil {
		t.Error("malformed safety label (non-map) accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "MalformedSafetyLabel" {
		t.Errorf("want MalformedSafetyLabel, got %v", err)
	}
	// ext[1] a map missing the scope field
	bad2 := cbor.Map{{K: cbor.Uint(policy.SafetyLabelExtKey), V: cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("x")}}}}
	if _, _, err := policy.SafetyLabelFromExt(bad2); err == nil {
		t.Error("incomplete safety label accepted")
	}
}
