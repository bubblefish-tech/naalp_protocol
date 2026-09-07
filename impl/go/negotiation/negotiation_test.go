// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package negotiation_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/negotiation"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/negotiation/cases.json"

type msgVec struct {
	Role      uint64   `json:"role"`
	Profile   uint64   `json:"profile"`
	CausesHex []string `json:"causes_hex"`
	BodyHex   string   `json:"body_hex"`
	HeadHex   string   `json:"head_hex"`
	IDHex     string   `json:"id_hex"`
}

type objVec struct {
	BodyHex string `json:"body_hex"`
	HeadHex string `json:"head_hex"`
	IDHex   string `json:"id_hex"`
}

type carriedVec struct {
	Code     uint64 `json:"code"`
	Critical uint64 `json:"critical"`
}

type vec struct {
	Negotiation struct {
		NegotiationHex     string            `json:"negotiation_hex"`
		UnknownProfile     uint64            `json:"unknown_profile"`
		Roles              map[string]uint64 `json:"roles"`
		Profiles           map[string]uint64 `json:"profiles"`
		Offer              msgVec `json:"offer"`
		Counter            msgVec `json:"counter"`
		Accept             msgVec `json:"accept"`
		Offer2             msgVec `json:"offer2"`
		AcceptNotDescended msgVec `json:"accept_not_descended"`
		UnknownProfileOff  msgVec `json:"unknown_profile_offer"`
		UnknownRoleMessage msgVec `json:"unknown_role_message"`
		Descends           struct {
			AcceptFromOffer   bool `json:"accept_from_offer"`
			AcceptBadFromOffer bool `json:"accept_bad_from_offer"`
		} `json:"descends"`
		AgreedProfile uint64 `json:"agreed_profile"`
	} `json:"negotiation"`
	Risk struct {
		Vocabulary []struct {
			Name  string `json:"name"`
			Code  uint64 `json:"code"`
			Class string `json:"class"`
		} `json:"vocabulary"`
		ExtensibleRangeStart uint64       `json:"extensible_range_start"`
		CarriedOnLabeled     []carriedVec `json:"carried_on_labeled_objects"`
		LabeledObjects       []struct {
			Effect        uint64 `json:"effect"`
			EffectName    string `json:"effect_name"`
			EffectClass   uint64 `json:"effect_class"`
			WithLabels    objVec `json:"with_labels"`
			WithoutLabels objVec `json:"without_labels"`
		} `json:"labeled_objects"`
		Validate struct {
			RecognizedSet struct {
				Carried         []carriedVec `json:"carried"`
				RecognizedCodes []uint64     `json:"recognized_codes"`
			} `json:"recognized_set"`
			UnknownCriticalRejected struct {
				Carried []carriedVec `json:"carried"`
				Error   string       `json:"error"`
			} `json:"unknown_critical_rejected"`
		} `json:"validate"`
	} `json:"risk"`
	Trust struct {
		RegistryAHex        string `json:"registry_a_hex"`
		RegistryBHex        string `json:"registry_b_hex"`
		SubjectHex          string `json:"subject_hex"`
		ExternalRecordHex   string `json:"external_record_hex"`
		ReferenceHex        string `json:"reference_hex"`
		TamperedRecordHex   string `json:"tampered_record_hex"`
		TamperedReferenceHex string `json:"tampered_reference_hex"`
		RefA                objVec `json:"ref_a"`
		RefB                objVec `json:"ref_b"`
	} `json:"trust"`
	EdgeCases struct {
		KeysOutOfOrder struct {
			CanonicalOfferBodyHex    string `json:"canonical_offer_body_hex"`
			NoncanonicalOfferBodyHex string `json:"noncanonical_offer_body_hex"`
		} `json:"keys_out_of_order"`
		EmptyVsAbsent struct {
			Causes struct {
				EmptyPresent objVec `json:"empty_present"`
				OneCause     struct {
					CauseHex string `json:"cause_hex"`
					BodyHex  string `json:"body_hex"`
					IDHex    string `json:"id_hex"`
				} `json:"one_cause"`
				AbsentField struct {
					BodyHex string `json:"body_hex"`
				} `json:"absent_field"`
			} `json:"causes"`
			Labels struct {
				EmptyPresent objVec `json:"empty_present"`
				OneLabel     struct {
					Code     uint64 `json:"code"`
					Critical uint64 `json:"critical"`
					BodyHex  string `json:"body_hex"`
					IDHex    string `json:"id_hex"`
				} `json:"one_label"`
				AbsentField struct {
					BodyHex string `json:"body_hex"`
				} `json:"absent_field"`
			} `json:"labels"`
		} `json:"empty_vs_absent"`
		Minimal struct {
			Offer struct {
				NegotiationHex string `json:"negotiation_hex"`
				Role           uint64 `json:"role"`
				Profile        uint64 `json:"profile"`
				BodyHex        string `json:"body_hex"`
				IDHex          string `json:"id_hex"`
			} `json:"offer"`
			LabeledObject struct {
				Effect  uint64 `json:"effect"`
				BodyHex string `json:"body_hex"`
				IDHex   string `json:"id_hex"`
			} `json:"labeled_object"`
			TrustRef struct {
				BodyHex string `json:"body_hex"`
				IDHex   string `json:"id_hex"`
			} `json:"trust_ref"`
		} `json:"minimal"`
		LookAlike struct {
			TrustRefAsMessage struct {
				BodyHex string `json:"body_hex"`
			} `json:"trust_ref_as_message"`
			MessageAsTrustRef struct {
				BodyHex string `json:"body_hex"`
			} `json:"message_as_trust_ref"`
		} `json:"look_alike"`
	} `json:"edge_cases"`
}

func hb(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func loadVec(t *testing.T) vec {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vec
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(v.Risk.LabeledObjects) != 4 {
		t.Fatalf("expected 4 labeled objects in the corpus, got %d", len(v.Risk.LabeledObjects))
	}
	return v
}

func causesFrom(t *testing.T, hexes []string) [][]byte {
	out := make([][]byte, len(hexes))
	for i, h := range hexes {
		out[i] = hb(t, h)
	}
	return out
}

func msgFrom(t *testing.T, neg []byte, mv msgVec) negotiation.Message {
	return negotiation.Message{
		Negotiation: neg,
		Role:        negotiation.Role(mv.Role),
		Profile:     negotiation.Profile(mv.Profile),
		Causes:      causesFrom(t, mv.CausesHex),
	}
}

// key derives a real ML-DSA-65 keypair from a seed.
func key(t *testing.T, seed byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier) {
	t.Helper()
	var s [mldsa65.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
}

// TestByteParityAgainstOracle: Go encoding == the non-circular Python oracle, byte-for-byte, for
// every negotiation message, risk label, labeled object, and trust ref body/head/id. Mutation:
// change any Bytes() field order/tag/key and a *_hex compare flips.
func TestByteParityAgainstOracle(t *testing.T) {
	v := loadVec(t)
	neg := hb(t, v.Negotiation.NegotiationHex)

	// Negotiation messages.
	for name, mv := range map[string]msgVec{
		"offer": v.Negotiation.Offer, "counter": v.Negotiation.Counter, "accept": v.Negotiation.Accept,
		"offer2": v.Negotiation.Offer2, "accept_not_descended": v.Negotiation.AcceptNotDescended,
		"unknown_profile_offer": v.Negotiation.UnknownProfileOff, "unknown_role_message": v.Negotiation.UnknownRoleMessage,
	} {
		m := msgFrom(t, neg, mv)
		if got := hex.EncodeToString(m.Bytes()); got != mv.BodyHex {
			t.Fatalf("%s Message.Bytes\n got %s\nwant %s", name, got, mv.BodyHex)
		}
		if got := hex.EncodeToString(m.Head()); got != mv.HeadHex {
			t.Fatalf("%s Message.Head got %s want %s", name, got, mv.HeadHex)
		}
		if got := hex.EncodeToString(m.ID()); got != mv.IDHex {
			t.Fatalf("%s Message.ID got %s want %s", name, got, mv.IDHex)
		}
	}

	// Labeled objects (with and without labels).
	for i, lo := range v.Risk.LabeledObjects {
		with := negotiation.LabeledObject{Effect: lo.Effect, Labels: carriedLabels(v)}
		if got := hex.EncodeToString(with.Bytes()); got != lo.WithLabels.BodyHex {
			t.Fatalf("labeled[%d] with-labels Bytes\n got %s\nwant %s", i, got, lo.WithLabels.BodyHex)
		}
		if got := hex.EncodeToString(with.Head()); got != lo.WithLabels.HeadHex {
			t.Fatalf("labeled[%d] with-labels Head got %s want %s", i, got, lo.WithLabels.HeadHex)
		}
		if got := hex.EncodeToString(with.ID()); got != lo.WithLabels.IDHex {
			t.Fatalf("labeled[%d] with-labels ID got %s want %s", i, got, lo.WithLabels.IDHex)
		}
		without := negotiation.LabeledObject{Effect: lo.Effect}
		if got := hex.EncodeToString(without.Bytes()); got != lo.WithoutLabels.BodyHex {
			t.Fatalf("labeled[%d] without-labels Bytes\n got %s\nwant %s", i, got, lo.WithoutLabels.BodyHex)
		}
	}

	// Trust refs.
	refA := negotiation.TrustRef{Registry: hb(t, v.Trust.RegistryAHex), Reference: hb(t, v.Trust.ReferenceHex), Subject: hb(t, v.Trust.SubjectHex)}
	if got := hex.EncodeToString(refA.Bytes()); got != v.Trust.RefA.BodyHex {
		t.Fatalf("TrustRef A Bytes\n got %s\nwant %s", got, v.Trust.RefA.BodyHex)
	}
	if got := hex.EncodeToString(refA.Head()); got != v.Trust.RefA.HeadHex {
		t.Fatalf("TrustRef A Head got %s want %s", got, v.Trust.RefA.HeadHex)
	}
	if got := hex.EncodeToString(refA.ID()); got != v.Trust.RefA.IDHex {
		t.Fatalf("TrustRef A ID got %s want %s", got, v.Trust.RefA.IDHex)
	}
	refB := negotiation.TrustRef{Registry: hb(t, v.Trust.RegistryBHex), Reference: hb(t, v.Trust.ReferenceHex), Subject: hb(t, v.Trust.SubjectHex)}
	if got := hex.EncodeToString(refB.Bytes()); got != v.Trust.RefB.BodyHex {
		t.Fatalf("TrustRef B Bytes\n got %s\nwant %s", got, v.Trust.RefB.BodyHex)
	}
}

func carriedLabels(v vec) []negotiation.RiskLabel {
	out := make([]negotiation.RiskLabel, len(v.Risk.CarriedOnLabeled))
	for i, c := range v.Risk.CarriedOnLabeled {
		out[i] = negotiation.RiskLabel{Code: negotiation.RiskCode(c.Code), Critical: c.Critical}
	}
	return out
}

// TestNegotiationDescendFromOffer is the governed-negotiation checkpoint: an accept descends from
// its offer along the causes chain (via a counter) and is accepted, returning the agreed
// pre-registered profile; an accept that does NOT descend from the offer is rejected NotDescended;
// an unknown profile and an unknown role are rejected. Mutation: have Descends return a constant and
// the honest/bad cases diverge; drop the profile/role guard and the unknown cases wrongly pass.
func TestNegotiationDescendFromOffer(t *testing.T) {
	v := loadVec(t)
	neg := hb(t, v.Negotiation.NegotiationHex)
	signer, verifier := key(t, 0x11)
	_, foreign := key(t, 0x22)

	offer := msgFrom(t, neg, v.Negotiation.Offer)
	counter := msgFrom(t, neg, v.Negotiation.Counter)
	accept := msgFrom(t, neg, v.Negotiation.Accept)
	offer2 := msgFrom(t, neg, v.Negotiation.Offer2)
	acceptBad := msgFrom(t, neg, v.Negotiation.AcceptNotDescended)

	// The causes wiring reproduces the oracle: counter -> offer, accept -> counter (descends), and
	// acceptBad -> offer2 (does not descend from offer).
	if !bytes.Equal(counter.Causes[0], offer.ID()) {
		t.Fatal("counter does not chain onto the offer")
	}
	if !bytes.Equal(accept.Causes[0], counter.ID()) {
		t.Fatal("accept does not chain onto the counter")
	}
	if !bytes.Equal(acceptBad.Causes[0], offer2.ID()) {
		t.Fatal("acceptBad does not chain onto offer2")
	}

	// Sign and verify every message under the real key; foreign key is rejected.
	all := []negotiation.Message{offer, counter, accept, offer2, acceptBad}
	verified := make([]negotiation.Message, 0, len(all))
	for _, m := range all {
		obj, err := negotiation.SignMessage(m, signer)
		if err != nil {
			t.Fatalf("SignMessage(%s): %v", m.Role.Name(), err)
		}
		vm, err := negotiation.VerifyMessage(obj, cose.ProfilePublic, verifier)
		if err != nil {
			t.Fatalf("VerifyMessage(%s): %v", m.Role.Name(), err)
		}
		if !bytes.Equal(vm.ID(), m.ID()) {
			t.Fatalf("verified message id mismatch for %s", m.Role.Name())
		}
		if _, err := negotiation.VerifyMessage(obj, cose.ProfilePublic, foreign); err != cose.ErrBadSignature {
			t.Fatalf("foreign-key verify got %v, want BadSignature", err)
		}
		verified = append(verified, vm)
	}
	byID := negotiation.IndexByID(verified)

	// The honest accept descends from the offer and yields the agreed pre-registered profile.
	if got := negotiation.Descends(accept, offer, byID); got != v.Negotiation.Descends.AcceptFromOffer {
		t.Fatalf("Descends(accept, offer)=%v want %v", got, v.Negotiation.Descends.AcceptFromOffer)
	}
	agreed, err := negotiation.VerifyAccept(accept, offer, byID)
	if err != nil {
		t.Fatalf("VerifyAccept (honest): %v", err)
	}
	if uint64(agreed) != v.Negotiation.AgreedProfile {
		t.Fatalf("agreed profile %d want %d", agreed, v.Negotiation.AgreedProfile)
	}

	// The bad accept does NOT descend from the offer and is rejected NotDescended.
	if got := negotiation.Descends(acceptBad, offer, byID); got != v.Negotiation.Descends.AcceptBadFromOffer {
		t.Fatalf("Descends(acceptBad, offer)=%v want %v", got, v.Negotiation.Descends.AcceptBadFromOffer)
	}
	if _, err := negotiation.VerifyAccept(acceptBad, offer, byID); err != negotiation.ErrNotDescended {
		t.Fatalf("VerifyAccept (not descended) got %v, want NotDescended", err)
	}

	// An unknown profile and an unknown role are rejected at verify time.
	unkProfObj, _ := negotiation.SignMessage(msgFrom(t, neg, v.Negotiation.UnknownProfileOff), signer)
	if _, err := negotiation.VerifyMessage(unkProfObj, cose.ProfilePublic, verifier); err != negotiation.ErrUnknownProfile {
		t.Fatalf("unknown-profile verify got %v, want UnknownProfile", err)
	}
	unkRoleObj, _ := negotiation.SignMessage(msgFrom(t, neg, v.Negotiation.UnknownRoleMessage), signer)
	if _, err := negotiation.VerifyMessage(unkRoleObj, cose.ProfilePublic, verifier); err != negotiation.ErrUnknownRole {
		t.Fatalf("unknown-role verify got %v, want UnknownRole", err)
	}

	// Presenting a non-offer as the offer, or a non-accept as the accept, is rejected fail-closed.
	if _, err := negotiation.VerifyAccept(accept, counter, byID); err != negotiation.ErrNotOffer {
		t.Fatalf("non-offer-as-offer got %v, want NotOffer", err)
	}
	if _, err := negotiation.VerifyAccept(counter, offer, byID); err != negotiation.ErrNotAccept {
		t.Fatalf("non-accept-as-accept got %v, want NotAccept", err)
	}

	// No free-form/runtime capability is negotiable: the only accepted profiles are the closed set.
	if negotiation.IsRegisteredProfile(negotiation.Profile(v.Negotiation.UnknownProfile)) {
		t.Fatal("an unregistered profile code must not be accepted")
	}
	for _, p := range []negotiation.Profile{negotiation.ProfileBaseline, negotiation.ProfileStreaming, negotiation.ProfileBatch} {
		if !negotiation.IsRegisteredProfile(p) {
			t.Fatalf("pre-registered profile %s not recognized", p.Name())
		}
	}
}

// TestRoleProfileNamesAndReferenceIDMatchOracle grades three surfaces that were previously carried
// only in diagnostic strings and never asserted: Role.Name()/Profile.Name() must equal the exact
// name string the independent oracle assigns to each closed-set code (vectors/negotiation/cases.json
// negotiation.roles / negotiation.profiles — the oracle's own name->code assignment, cross-checked
// against the Role/Profile constants used to build the corpus), and TrustRef.ReferenceID() must
// return exactly the carried reference bytes (trust.reference_hex). Mutation: swap any two entries
// in roleName/profileName, or have ReferenceID return Subject instead of Reference, and this fails.
func TestRoleProfileNamesAndReferenceIDMatchOracle(t *testing.T) {
	v := loadVec(t)
	if len(v.Negotiation.Roles) != 3 {
		t.Fatalf("expected 3 roles in the corpus, got %d", len(v.Negotiation.Roles))
	}
	for name, code := range v.Negotiation.Roles {
		if got := negotiation.Role(code).Name(); got != name {
			t.Errorf("Role(%d).Name() = %q, want %q", code, got, name)
		}
	}
	if len(v.Negotiation.Profiles) != 3 {
		t.Fatalf("expected 3 profiles in the corpus, got %d", len(v.Negotiation.Profiles))
	}
	for name, code := range v.Negotiation.Profiles {
		if got := negotiation.Profile(code).Name(); got != name {
			t.Errorf("Profile(%d).Name() = %q, want %q", code, got, name)
		}
	}
	// An out-of-range code names neither: Name() falls back to "unknown".
	if got := negotiation.Role(99).Name(); got != "unknown" {
		t.Errorf("Role(99).Name() = %q, want \"unknown\"", got)
	}
	if got := negotiation.Profile(99).Name(); got != "unknown" {
		t.Errorf("Profile(99).Name() = %q, want \"unknown\"", got)
	}

	ref := negotiation.TrustRef{Registry: hb(t, v.Trust.RegistryAHex), Reference: hb(t, v.Trust.ReferenceHex), Subject: hb(t, v.Trust.SubjectHex)}
	if got := hex.EncodeToString(ref.ReferenceID()); got != v.Trust.ReferenceHex {
		t.Errorf("ReferenceID() = %s, want %s", got, v.Trust.ReferenceHex)
	}
	if !bytes.Equal(ref.ReferenceID(), ref.Reference) {
		t.Error("ReferenceID() must equal the carried Reference field")
	}
}

// TestRiskLabelEffectClassUnchanged is the load-bearing C20 invariant: adding or carrying a risk
// label NEVER changes an object's effect class (the closed C5 lattice is untouched — risk labels are
// an advisory dimension, not a fifth effect). For every effect class, an object carrying the gating
// "sensitive"/"egress" labels resolves to the SAME effect class as the identical object with no
// labels, and to the oracle's normalized effect. Mutation: if EffectClass consulted a gating label to
// escalate the effect, the read_only+sensitive object would resolve to destructive and this FAILS.
func TestRiskLabelEffectClassUnchanged(t *testing.T) {
	v := loadVec(t)
	labels := carriedLabels(v)
	// The carried set must include a GATING label so the mutation seam is real.
	sawGating := false
	for _, l := range labels {
		if c, ok := negotiation.RiskClassOf(l.Code); ok && c == negotiation.ClassGating {
			sawGating = true
		}
	}
	if !sawGating {
		t.Fatal("corpus must carry at least one gating label so the effect-unchanged mutation is exercised")
	}

	for _, lo := range v.Risk.LabeledObjects {
		with := negotiation.LabeledObject{Effect: lo.Effect, Labels: labels}
		without := negotiation.LabeledObject{Effect: lo.Effect}
		wantClass := policy.NormalizeEffect(lo.Effect)
		if with.EffectClass() != wantClass {
			t.Fatalf("effect %s: with-labels EffectClass=%d, want %d (a label changed the effect!)",
				lo.EffectName, with.EffectClass(), wantClass)
		}
		if without.EffectClass() != wantClass {
			t.Fatalf("effect %s: without-labels EffectClass=%d, want %d", lo.EffectName, without.EffectClass(), wantClass)
		}
		// The invariant, stated directly: labels do not change the class.
		if with.EffectClass() != without.EffectClass() {
			t.Fatalf("effect %s: carrying labels changed the effect class (%d != %d)",
				lo.EffectName, with.EffectClass(), without.EffectClass())
		}
		if uint64(with.EffectClass()) != lo.EffectClass {
			t.Fatalf("effect %s: EffectClass %d != oracle effect_class %d", lo.EffectName, with.EffectClass(), lo.EffectClass)
		}
	}

	// Concretely: a read_only object carrying the gating "sensitive" label is still read_only.
	sensitive := negotiation.LabeledObject{
		Effect: uint64(policy.ReadOnly),
		Labels: []negotiation.RiskLabel{{Code: negotiation.RiskSensitive, Critical: 1}},
	}
	if sensitive.EffectClass() != policy.ReadOnly {
		t.Fatalf("read_only + sensitive resolved to %d; a risk label must NOT escalate the effect", sensitive.EffectClass())
	}
}

// TestRiskLabelCriticalExtensionRule is the R-2.5 checkpoint over risk labels: an unknown CRITICAL
// label is rejected; an unknown NON-critical label is ignored (dropped from the recognized set); a
// recognized label is kept; and the vocabulary/class matches the oracle. Mutation: drop the
// unknown-critical guard and the reject case flips; keep unknowns and the recognized set diverges.
func TestRiskLabelCriticalExtensionRule(t *testing.T) {
	v := loadVec(t)

	// The vocabulary and its gating/informing classes match the oracle.
	for _, e := range v.Risk.Vocabulary {
		class, ok := negotiation.RiskClassOf(negotiation.RiskCode(e.Code))
		if !ok {
			t.Fatalf("vocab label %q (code %d) not registered", e.Name, e.Code)
		}
		if class.Name() != e.Class {
			t.Fatalf("vocab label %q class %q != oracle %q", e.Name, class.Name(), e.Class)
		}
	}
	if uint64(negotiation.ExtensibleRangeStart) != v.Risk.ExtensibleRangeStart {
		t.Fatalf("extensible range start %d != oracle %d", negotiation.ExtensibleRangeStart, v.Risk.ExtensibleRangeStart)
	}

	// A recognized-plus-unknown-noncritical set validates; the unknown non-critical label is dropped.
	recSet := labelsFrom(v.Risk.Validate.RecognizedSet.Carried)
	got, err := negotiation.ValidateLabels(recSet)
	if err != nil {
		t.Fatalf("ValidateLabels (recognized set): %v", err)
	}
	wantCodes := v.Risk.Validate.RecognizedSet.RecognizedCodes
	if len(got) != len(wantCodes) {
		t.Fatalf("recognized labels %d, want %d", len(got), len(wantCodes))
	}
	for i, l := range got {
		if uint64(l.Code) != wantCodes[i] {
			t.Fatalf("recognized[%d] code %d, want %d", i, l.Code, wantCodes[i])
		}
		if !negotiation.IsRegisteredRisk(l.Code) {
			t.Fatalf("recognized[%d] code %d is not a standard label", i, l.Code)
		}
	}

	// An unknown CRITICAL label is rejected (R-2.5).
	critSet := labelsFrom(v.Risk.Validate.UnknownCriticalRejected.Carried)
	if _, err := negotiation.ValidateLabels(critSet); err != negotiation.ErrUnknownCriticalRisk {
		t.Fatalf("unknown-critical got %v, want UnknownCriticalRisk", err)
	}

	// A malformed critical flag (outside {0,1}) is rejected at parse time (no CBOR boolean).
	badFlag := negotiation.LabeledObject{Effect: 0, Labels: []negotiation.RiskLabel{{Code: negotiation.RiskSensitive, Critical: 2}}}
	if _, err := negotiation.ParseLabeledObject(badFlag.Bytes()); err != negotiation.ErrCriticalFlag {
		t.Fatalf("malformed critical flag got %v, want MalformedCriticalFlag", err)
	}
}

func labelsFrom(cs []carriedVec) []negotiation.RiskLabel {
	out := make([]negotiation.RiskLabel, len(cs))
	for i, c := range cs {
		out[i] = negotiation.RiskLabel{Code: negotiation.RiskCode(c.Code), Critical: c.Critical}
	}
	return out
}

// TestTrustRefCheckableNeverWeighed is the C20 trust checkpoint: a carried reputation/registry
// reference VERIFIES — its content-id recomputes over the external record and its signature checks —
// but NOTHING on the wire scores it. A tampered external record no longer recomputes (rejected). Two
// different registries referencing the SAME record verify symmetrically (the wire weighs neither).
// Mutation: have BindsRecord ignore the record and the tampered case wrongly verifies.
func TestTrustRefCheckableNeverWeighed(t *testing.T) {
	v := loadVec(t)
	signer, verifier := key(t, 0x11)
	_, foreign := key(t, 0x22)

	record := hb(t, v.Trust.ExternalRecordHex)
	reference := hb(t, v.Trust.ReferenceHex)
	tampered := hb(t, v.Trust.TamperedRecordHex)

	refA := negotiation.TrustRef{Registry: hb(t, v.Trust.RegistryAHex), Reference: reference, Subject: hb(t, v.Trust.SubjectHex)}
	// The carried reference is the content-id of the external record (checkable by recompute).
	if !refA.BindsRecord(record) {
		t.Fatal("trust ref does not bind the external record it references")
	}
	if refA.BindsRecord(tampered) {
		t.Fatal("trust ref wrongly binds a tampered record (content-id must recompute)")
	}

	obj, err := negotiation.SignTrustRef(refA, signer)
	if err != nil {
		t.Fatalf("SignTrustRef: %v", err)
	}
	// It verifies (signature + content-id recompute).
	r, err := negotiation.VerifyTrustRef(obj, cose.ProfilePublic, verifier, record)
	if err != nil {
		t.Fatalf("VerifyTrustRef (honest): %v", err)
	}
	if !bytes.Equal(r.Reference, reference) {
		t.Fatal("resolved reference does not equal the carried content-id")
	}
	// A tampered record does not recompute to the carried reference: rejected.
	if _, err := negotiation.VerifyTrustRef(obj, cose.ProfilePublic, verifier, tampered); err != negotiation.ErrReferenceMismatch {
		t.Fatalf("tampered-record verify got %v, want ReferenceMismatch", err)
	}
	// A foreign key never authenticates the object.
	if _, err := negotiation.VerifyTrustRef(obj, cose.ProfilePublic, foreign, record); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key verify got %v, want BadSignature", err)
	}

	// Two DIFFERENT registries referencing the SAME record both verify — the wire carries both and
	// weighs neither (no score, no ordering). Resolution is left to the relying party.
	refB := negotiation.TrustRef{Registry: hb(t, v.Trust.RegistryBHex), Reference: reference, Subject: hb(t, v.Trust.SubjectHex)}
	objB, _ := negotiation.SignTrustRef(refB, signer)
	rB, err := negotiation.VerifyTrustRef(objB, cose.ProfilePublic, verifier, record)
	if err != nil {
		t.Fatalf("VerifyTrustRef (registry B): %v", err)
	}
	// Both resolve to the same referenced record with no relative weight between them.
	if !bytes.Equal(r.Reference, rB.Reference) {
		t.Fatal("two registries referencing the same record resolved to different references")
	}
	if bytes.Equal(r.Registry, rB.Registry) {
		t.Fatal("test fixture: the two registries must differ to prove symmetry")
	}
}

// crossLangPinnedSignedOfferSHA384 / LabeledObject / TrustRef are the pinned SHA-384 of the
// deterministic COSE_Sign1 objects obtained by signing the offer body, the read_only-with-labels
// labeled-object body, and the trust-ref A body with the shared all-0x11 32-byte ML-DSA-65 seed. Go
// and Rust both pin these, proving the two independent ML-DSA stacks emit byte-identical signed C20
// objects for identical canonical CBOR + seed. Mutation: change any encoding/signing input and a
// digest diverges from its pin.
const (
	crossLangPinnedSignedOfferSHA384    = "28b5c4e082cfae270bcc0317ef95c88c451f5af7c0d984b2120496afad4870964845b699fe501bb8cd6fab99298729fd"
	crossLangPinnedSignedLabeledSHA384  = "c6f4ba4c897f2f34f075ec504cd8329da7b138764cac5f4b7dcd120348b15d36fab9bf55bb5302dd024f1b077ecc1a0c"
	crossLangPinnedSignedTrustRefSHA384 = "80a7d8302bdb01d0fec577a28a4cb0e37c540f80c4d588a8be8324d9e80229fbf3f6a850c6c50d24ca1991e03b84699f"
)

// TestCrossLangSignedNegotiationPin proves Go and Rust produce byte-identical signed C20 objects for
// the same bodies + seed (deterministic ML-DSA-65 over identical canonical CBOR).
func TestCrossLangSignedNegotiationPin(t *testing.T) {
	v := loadVec(t)
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 0x11
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	s := cose.MLDSA65Signer{SK: sk}

	offer := msgFrom(t, hb(t, v.Negotiation.NegotiationHex), v.Negotiation.Offer)
	offerObj, err := negotiation.SignMessage(offer, s)
	if err != nil {
		t.Fatalf("SignMessage(offer): %v", err)
	}
	offerDG := sha512.Sum384(offerObj)
	offerHex := hex.EncodeToString(offerDG[:])

	labeled := negotiation.LabeledObject{Effect: v.Risk.LabeledObjects[0].Effect, Labels: carriedLabels(v)}
	labeledObj, err := negotiation.SignLabeledObject(labeled, s)
	if err != nil {
		t.Fatalf("SignLabeledObject: %v", err)
	}
	labeledDG := sha512.Sum384(labeledObj)
	labeledHex := hex.EncodeToString(labeledDG[:])

	tref := negotiation.TrustRef{Registry: hb(t, v.Trust.RegistryAHex), Reference: hb(t, v.Trust.ReferenceHex), Subject: hb(t, v.Trust.SubjectHex)}
	trefObj, err := negotiation.SignTrustRef(tref, s)
	if err != nil {
		t.Fatalf("SignTrustRef: %v", err)
	}
	trefDG := sha512.Sum384(trefObj)
	trefHex := hex.EncodeToString(trefDG[:])

	t.Logf("CROSS-LANG signed offer      SHA-384 (seed=0x11*32): %s", offerHex)
	t.Logf("CROSS-LANG signed labeled    SHA-384 (seed=0x11*32): %s", labeledHex)
	t.Logf("CROSS-LANG signed trust-ref  SHA-384 (seed=0x11*32): %s", trefHex)

	if crossLangPinnedSignedOfferSHA384 != "PIN_ME" && offerHex != crossLangPinnedSignedOfferSHA384 {
		t.Fatalf("cross-lang signed-offer digest %s != pinned %s", offerHex, crossLangPinnedSignedOfferSHA384)
	}
	if crossLangPinnedSignedLabeledSHA384 != "PIN_ME" && labeledHex != crossLangPinnedSignedLabeledSHA384 {
		t.Fatalf("cross-lang signed-labeled digest %s != pinned %s", labeledHex, crossLangPinnedSignedLabeledSHA384)
	}
	if crossLangPinnedSignedTrustRefSHA384 != "PIN_ME" && trefHex != crossLangPinnedSignedTrustRefSHA384 {
		t.Fatalf("cross-lang signed-trust-ref digest %s != pinned %s", trefHex, crossLangPinnedSignedTrustRefSHA384)
	}
}

// ---- standard wire-format edge cases (Part 1) --------------------------------------------

// TestNegKeysOutOfOrderRejected is edge case #1: the canonical encoder emits ascending top-level map
// keys; a hand-built offer body with keys in DESCENDING order (4,3,2,1) is rejected NonCanonical by
// the strict shared decoder ParseMessage routes through (RFC 8949 §4.2.1). Mutation: relax the
// key-order check in the C1 codec and the descending body wrongly decodes.
func TestNegKeysOutOfOrderRejected(t *testing.T) {
	v := loadVec(t)
	e := v.EdgeCases.KeysOutOfOrder
	offer := negotiation.Message{Negotiation: []byte("neg-0001"), Role: negotiation.RoleOffer, Profile: negotiation.ProfileBaseline}
	if got := hex.EncodeToString(offer.Bytes()); got != e.CanonicalOfferBodyHex {
		t.Fatalf("canonical offer body\n got %s\nwant %s", got, e.CanonicalOfferBodyHex)
	}
	canon := hb(t, e.CanonicalOfferBodyHex)
	noncanon := hb(t, e.NoncanonicalOfferBodyHex)
	// The canonical body decodes and parses; the descending-key body is rejected NonCanonical, and
	// ParseMessage (which routes through the strict decoder) rejects it NegMalformed.
	if _, err := cbor.Decode(canon); err != nil {
		t.Fatalf("canonical offer body should decode: %v", err)
	}
	if _, err := negotiation.ParseMessage(canon); err != nil {
		t.Fatalf("canonical offer body should parse: %v", err)
	}
	if _, err := cbor.Decode(noncanon); err == nil {
		t.Fatal("descending-key offer body decoded (want NonCanonical)")
	} else if ce, ok := err.(*cbor.Error); !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("descending-key body got %v, want NonCanonical", err)
	}
	if _, err := negotiation.ParseMessage(noncanon); err != negotiation.ErrMalformed {
		t.Fatalf("ParseMessage(noncanon) got %v, want NegMalformed", err)
	}
}

// TestNegEmptyVsAbsentCauses is edge case #2 for the message causes[] (field 4): an empty causes[] is
// DISTINCT on the wire and by content-id from a populated one, and BOTH differ from a body whose
// causes field is ABSENT — which is rejected NegMalformed (field 4 is mandatory). Mutation: drop the
// causes-field presence requirement in ParseMessage and the absent body wrongly parses.
func TestNegEmptyVsAbsentCauses(t *testing.T) {
	v := loadVec(t)
	ec := v.EdgeCases.EmptyVsAbsent.Causes
	neg := []byte("neg-0001")
	empty := negotiation.Message{Negotiation: neg, Role: negotiation.RoleOffer, Profile: negotiation.ProfileBaseline, Causes: [][]byte{}}
	one := negotiation.Message{Negotiation: neg, Role: negotiation.RoleOffer, Profile: negotiation.ProfileBaseline, Causes: [][]byte{hb(t, ec.OneCause.CauseHex)}}
	if got := hex.EncodeToString(empty.Bytes()); got != ec.EmptyPresent.BodyHex {
		t.Fatalf("empty-causes body\n got %s\nwant %s", got, ec.EmptyPresent.BodyHex)
	}
	if got := hex.EncodeToString(one.Bytes()); got != ec.OneCause.BodyHex {
		t.Fatalf("one-cause body\n got %s\nwant %s", got, ec.OneCause.BodyHex)
	}
	if bytes.Equal(empty.ID(), one.ID()) {
		t.Fatal("empty and one-cause messages must have distinct content-ids")
	}
	if hex.EncodeToString(empty.ID()) != ec.EmptyPresent.IDHex {
		t.Fatalf("empty-causes id diverges from the oracle")
	}
	// Both present forms parse; the absent-field body is rejected NegMalformed.
	if _, err := negotiation.ParseMessage(empty.Bytes()); err != nil {
		t.Fatalf("ParseMessage(empty causes): %v", err)
	}
	if _, err := negotiation.ParseMessage(one.Bytes()); err != nil {
		t.Fatalf("ParseMessage(one cause): %v", err)
	}
	if _, err := negotiation.ParseMessage(hb(t, ec.AbsentField.BodyHex)); err != negotiation.ErrMalformed {
		t.Fatalf("absent causes field got %v, want NegMalformed", err)
	}
}

// TestNegEmptyVsAbsentLabels is edge case #2 for the labeled-object labels[] (field 2): an empty
// labels[] is DISTINCT on the wire and by content-id from a populated one, and BOTH differ from a body
// whose labels field is ABSENT — rejected NegMalformed (field 2 is mandatory). Mutation: drop the
// labels-field presence requirement in ParseLabeledObject and the absent body wrongly parses.
func TestNegEmptyVsAbsentLabels(t *testing.T) {
	v := loadVec(t)
	el := v.EdgeCases.EmptyVsAbsent.Labels
	empty := negotiation.LabeledObject{Effect: 0, Labels: []negotiation.RiskLabel{}}
	one := negotiation.LabeledObject{Effect: 0, Labels: []negotiation.RiskLabel{{Code: negotiation.RiskCode(el.OneLabel.Code), Critical: el.OneLabel.Critical}}}
	if got := hex.EncodeToString(empty.Bytes()); got != el.EmptyPresent.BodyHex {
		t.Fatalf("empty-labels body\n got %s\nwant %s", got, el.EmptyPresent.BodyHex)
	}
	if got := hex.EncodeToString(one.Bytes()); got != el.OneLabel.BodyHex {
		t.Fatalf("one-label body\n got %s\nwant %s", got, el.OneLabel.BodyHex)
	}
	if bytes.Equal(empty.ID(), one.ID()) {
		t.Fatal("empty and one-label objects must have distinct content-ids")
	}
	if hex.EncodeToString(empty.ID()) != el.EmptyPresent.IDHex {
		t.Fatalf("empty-labels id diverges from the oracle")
	}
	if _, err := negotiation.ParseLabeledObject(empty.Bytes()); err != nil {
		t.Fatalf("ParseLabeledObject(empty labels): %v", err)
	}
	if _, err := negotiation.ParseLabeledObject(one.Bytes()); err != nil {
		t.Fatalf("ParseLabeledObject(one label): %v", err)
	}
	if _, err := negotiation.ParseLabeledObject(hb(t, el.AbsentField.BodyHex)); err != negotiation.ErrMalformed {
		t.Fatalf("absent labels field got %v, want NegMalformed", err)
	}
}

// TestNegMinimal is edge case #4: the smallest legal offer, labeled-object, and trust-ref each encode
// to the oracle bytes, have a stable content-id, and round-trip through their Parse*.
func TestNegMinimal(t *testing.T) {
	v := loadVec(t)
	m := v.EdgeCases.Minimal
	offer := negotiation.Message{Negotiation: []byte{}, Role: negotiation.RoleOffer, Profile: negotiation.ProfileBaseline}
	if got := hex.EncodeToString(offer.Bytes()); got != m.Offer.BodyHex {
		t.Fatalf("minimal offer body\n got %s\nwant %s", got, m.Offer.BodyHex)
	}
	if got := hex.EncodeToString(offer.ID()); got != m.Offer.IDHex {
		t.Fatalf("minimal offer id got %s want %s", got, m.Offer.IDHex)
	}
	if _, err := negotiation.ParseMessage(offer.Bytes()); err != nil {
		t.Fatalf("ParseMessage(minimal offer): %v", err)
	}
	lo := negotiation.LabeledObject{Effect: m.LabeledObject.Effect}
	if got := hex.EncodeToString(lo.Bytes()); got != m.LabeledObject.BodyHex {
		t.Fatalf("minimal labeled-object body\n got %s\nwant %s", got, m.LabeledObject.BodyHex)
	}
	if got := hex.EncodeToString(lo.ID()); got != m.LabeledObject.IDHex {
		t.Fatalf("minimal labeled-object id got %s want %s", got, m.LabeledObject.IDHex)
	}
	if _, err := negotiation.ParseLabeledObject(lo.Bytes()); err != nil {
		t.Fatalf("ParseLabeledObject(minimal): %v", err)
	}
	tr := negotiation.TrustRef{Registry: []byte{}, Reference: []byte{}, Subject: []byte{}}
	if got := hex.EncodeToString(tr.Bytes()); got != m.TrustRef.BodyHex {
		t.Fatalf("minimal trust-ref body\n got %s\nwant %s", got, m.TrustRef.BodyHex)
	}
	if got := hex.EncodeToString(tr.ID()); got != m.TrustRef.IDHex {
		t.Fatalf("minimal trust-ref id got %s want %s", got, m.TrustRef.IDHex)
	}
	if _, err := negotiation.ParseTrustRef(tr.Bytes()); err != nil {
		t.Fatalf("ParseTrustRef(minimal): %v", err)
	}
}

// TestNegLookAlikeRejected is edge case #5, a CROSS-KIND rejection beyond the offer/accept role-literal
// already graded by VerifyAccept/CDDL: a trust-ref body {1:bstr,2:bstr,3:bstr} fed to ParseMessage is
// rejected NegMalformed (field 2 is not the uint role), and a message body {1:bstr,2:uint,3:uint,4:arr}
// fed to ParseTrustRef is rejected NegMalformed (field 2 is not a bstr reference). Mutation: relax the
// field-type/presence checks in Parse* and a sibling kind wrongly parses.
func TestNegLookAlikeRejected(t *testing.T) {
	v := loadVec(t)
	la := v.EdgeCases.LookAlike
	if _, err := negotiation.ParseMessage(hb(t, la.TrustRefAsMessage.BodyHex)); err != negotiation.ErrMalformed {
		t.Fatalf("trust-ref body parsed as a message got %v, want NegMalformed", err)
	}
	if _, err := negotiation.ParseTrustRef(hb(t, la.MessageAsTrustRef.BodyHex)); err != negotiation.ErrMalformed {
		t.Fatalf("message body parsed as a trust-ref got %v, want NegMalformed", err)
	}
}
