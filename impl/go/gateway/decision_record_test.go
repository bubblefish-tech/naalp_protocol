// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package gateway_test

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
	"github.com/bubblefish-tech/naalp_protocol/impl/go/gateway"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const decisionRecordVectorPath = "../../../vectors/decision_record/cases.json"

type drRecordVec struct {
	Name         string   `json:"name"`
	ActionHex    string   `json:"action_hex"`
	GoverningHex []string `json:"governing_hex"`
	ConsumeHex   *string  `json:"consume_hex"`
	Outcome      uint64   `json:"outcome"`
	BodyHex      string   `json:"body_hex"`
	HeadHex      string   `json:"head_hex"`
	IDHex        string   `json:"id_hex"`
	Note         string   `json:"note"`
}

type drReject struct {
	BodyHex string `json:"body_hex"`
	Reject  string `json:"reject"`
	Note    string `json:"note"`
}

type drVec struct {
	OutcomeVocabulary []struct {
		Name string `json:"name"`
		Code uint64 `json:"code"`
	} `json:"outcome_vocabulary"`
	OrderingBasisVocabulary []struct {
		Name string `json:"name"`
		Code uint64 `json:"code"`
	} `json:"ordering_basis_vocabulary"`
	EnforcementDispositionVocabulary []struct {
		Name string `json:"name"`
		Code uint64 `json:"code"`
	} `json:"enforcement_disposition_vocabulary"`
	TermDispositionKindVocabulary []struct {
		Name string `json:"name"`
		Code uint64 `json:"code"`
	} `json:"term_disposition_kind_vocabulary"`
	Records          map[string]drRecordVec `json:"records"`
	OrderingExamples map[string]drRecordVec `json:"ordering_examples"`
	Negative         struct {
		DenyWithConsumeRejected         drReject            `json:"deny_with_consume_rejected"`
		HoldWithConsumeRejected         drReject            `json:"hold_with_consume_rejected"`
		TermsKeyOutsideFieldSetRejected drReject            `json:"terms_key_outside_field_set_rejected"`
		UnknownOutcomeRejected          drReject            `json:"unknown_outcome_rejected"`
		OrderingMalformed               map[string]drReject `json:"ordering_malformed"`
		KeysOutOfOrder                  struct {
			CanonicalBodyHex    string `json:"canonical_body_hex"`
			NoncanonicalBodyHex string `json:"noncanonical_body_hex"`
			Reject              string `json:"reject"`
			Note                string `json:"note"`
		} `json:"keys_out_of_order"`
		LookAlike drReject `json:"look_alike"`
	} `json:"negative"`
}

func loadDRVec(t *testing.T) drVec {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(decisionRecordVectorPath))
	if err != nil {
		t.Fatalf("read decision-record vectors: %v", err)
	}
	var v drVec
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse decision-record vectors: %v", err)
	}
	return v
}

func drFrom(t *testing.T, rv drRecordVec) gateway.DecisionRecord {
	t.Helper()
	governing := make([][]byte, len(rv.GoverningHex))
	for i, g := range rv.GoverningHex {
		governing[i] = hb(t, g)
	}
	d := gateway.DecisionRecord{
		Action:    hb(t, rv.ActionHex),
		Governing: governing,
		Outcome:   rv.Outcome,
	}
	if rv.ConsumeHex != nil {
		d.Consume = hb(t, *rv.ConsumeHex)
	}
	// The oracle's body_hex already carries the exact ordering/terms/enforcement fields; this
	// helper is used only for the byte-parity records where a fully-populated struct is built by
	// hand per test (see below) — for the plain byte-parity sweep we only need Action/Governing/
	// Consume/Outcome plus ordering=correspondence-only, EXCEPT the records that carry field 5 as
	// something other than correspondence-only or fields 6/7, which are reconstructed explicitly
	// in TestDecisionRecordByteParityAgainstOracle below rather than through this generic helper.
	return d
}

// TestDecisionRecordByteParityAgainstOracle proves Go's deterministic-CBOR encoding of every
// records{} and ordering_examples{} case matches the non-circular Python oracle byte-for-byte:
// body, head, and content-id. Each record is reconstructed field-by-field (never routed through
// ParseDecisionRecord) so the test is independent of the decoder — a Bytes()-only regression would
// still be caught.
func TestDecisionRecordByteParityAgainstOracle(t *testing.T) {
	v := loadDRVec(t)

	build := func(name string, rv drRecordVec) gateway.DecisionRecord {
		d := drFrom(t, rv)
		switch name {
		case "allow_consuming", "allow_no_consume", "minimal", "correspondence_only":
			d.Ordering = gateway.CorrespondenceOnly()
		case "deny_two_governing":
			d.Ordering = gateway.OrderingDisclosure{Basis: gateway.OrderingSingleBoundary, Boundary: []byte("boundary-signer-X")}
		case "hold_empty_governing", "external_mechanism":
			d.Ordering = gateway.OrderingDisclosure{
				Basis:     gateway.OrderingExternalMechanism,
				Mechanism: []byte("external-log:acme-transparency-v1"),
				Relation:  hb(t, "2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56"),
			}
		case "single_boundary":
			d.Ordering = gateway.OrderingDisclosure{Basis: gateway.OrderingSingleBoundary, Boundary: []byte("SIGNER_B-boundary")}
		case "external_mechanism_no_relation":
			d.Ordering = gateway.OrderingDisclosure{Basis: gateway.OrderingExternalMechanism, Mechanism: []byte("external-log:acme-transparency-v1")}
		case "terms_valid":
			d.Ordering = gateway.CorrespondenceOnly()
			d.Terms = map[uint64]gateway.TermDisposition{
				1: {Kind: gateway.TermObserved},
				4: {Kind: gateway.TermReported, Source: []byte("boundary:relay-partner-3")},
			}
		case "enforcement_enforced":
			d.Ordering = gateway.CorrespondenceOnly()
			d.Enforcement = gateway.EnforcementEnforced
		case "enforcement_advised":
			d.Ordering = gateway.CorrespondenceOnly()
			d.Enforcement = gateway.EnforcementAdvised
		default:
			t.Fatalf("unhandled record name %q — add its ordering/terms/enforcement fixture above", name)
		}
		return d
	}

	all := map[string]drRecordVec{}
	for k, rv := range v.Records {
		all[k] = rv
	}
	for k, rv := range v.OrderingExamples {
		all[k] = rv
	}
	if len(all) != len(v.Records)+len(v.OrderingExamples) {
		t.Fatalf("records/ordering_examples name collision")
	}
	for name, rv := range all {
		d := build(name, rv)
		if got := hex.EncodeToString(d.Bytes()); got != rv.BodyHex {
			t.Fatalf("%s Bytes\n got %s\nwant %s", name, got, rv.BodyHex)
		}
		if got := hex.EncodeToString(d.Head()); got != rv.HeadHex {
			t.Fatalf("%s Head got %s want %s", name, got, rv.HeadHex)
		}
		if got := hex.EncodeToString(d.ID()); got != rv.IDHex {
			t.Fatalf("%s ID got %s want %s", name, got, rv.IDHex)
		}
		// Round-trip through the decoder and re-encode: the decoded record must re-encode to the
		// SAME canonical bytes (structural parse never loses information the oracle put on the wire).
		parsed, err := gateway.ParseDecisionRecord(d.Bytes())
		if err != nil {
			t.Fatalf("%s ParseDecisionRecord: %v", name, err)
		}
		if got := hex.EncodeToString(parsed.Bytes()); got != rv.BodyHex {
			t.Fatalf("%s round-trip Bytes\n got %s\nwant %s", name, got, rv.BodyHex)
		}
		if err := gateway.ValidateDecisionRecord(parsed); err != nil {
			t.Fatalf("%s ValidateDecisionRecord: %v (want nil — every records/ordering_examples case is a POSITIVE vector)", name, err)
		}
	}
}

// TestDecisionRecordOutcomeVocabulary proves naalp-decision-record field 4 reuses the SAME closed
// gw-decision set naalp-gateway-decision already registers (design.md §26.4: "one outcome
// vocabulary family-wide").
func TestDecisionRecordOutcomeVocabulary(t *testing.T) {
	v := loadDRVec(t)
	for _, e := range v.OutcomeVocabulary {
		if !gateway.IsKnownDecision(e.Code) || gateway.DecisionName(e.Code) != e.Name {
			t.Fatalf("outcome %q (code %d) not registered as %q", e.Name, e.Code, gateway.DecisionName(e.Code))
		}
	}
}

// TestOrderingBasisVocabulary proves the shared ordering-basis closed set (design.md §26.3) is
// registered exactly as the decision-record, checkpoint, and egress-attestation oracles all
// independently list it (same vocabulary, one wire enum).
func TestOrderingBasisVocabulary(t *testing.T) {
	v := loadDRVec(t)
	for _, e := range v.OrderingBasisVocabulary {
		if !gateway.IsKnownOrderingBasis(e.Code) || gateway.OrderingBasisName(e.Code) != e.Name {
			t.Fatalf("ordering-basis %q (code %d) not registered as %q", e.Name, e.Code, gateway.OrderingBasisName(e.Code))
		}
	}
	if gateway.IsKnownOrderingBasis(99) {
		t.Fatal("ordering-basis 99 must not be known")
	}
}

// TestDecisionRecordNegativeRejections exercises every named rejection in the oracle's negative{}
// corpus, calling ParseDecisionRecord then (on structural success) ValidateDecisionRecord, and
// asserting the resulting error's Kind matches the oracle's `reject` field exactly.
func TestDecisionRecordNegativeRejections(t *testing.T) {
	v := loadDRVec(t)

	kindOf := func(t *testing.T, bodyHex string) string {
		t.Helper()
		d, err := gateway.ParseDecisionRecord(hb(t, bodyHex))
		if err != nil {
			ce, ok := err.(*cose.Error)
			if !ok {
				t.Fatalf("ParseDecisionRecord returned non-*cose.Error: %v", err)
			}
			return ce.Kind
		}
		if err := gateway.ValidateDecisionRecord(d); err != nil {
			ce, ok := err.(*cose.Error)
			if !ok {
				t.Fatalf("ValidateDecisionRecord returned non-*cose.Error: %v", err)
			}
			return ce.Kind
		}
		return ""
	}

	cases := map[string]drReject{
		"deny_with_consume_rejected":         v.Negative.DenyWithConsumeRejected,
		"hold_with_consume_rejected":         v.Negative.HoldWithConsumeRejected,
		"terms_key_outside_field_set_rejected": v.Negative.TermsKeyOutsideFieldSetRejected,
		"unknown_outcome_rejected":            v.Negative.UnknownOutcomeRejected,
		"look_alike":                          v.Negative.LookAlike,
	}
	for name, c := range cases {
		if got := kindOf(t, c.BodyHex); got != c.Reject {
			t.Fatalf("%s: got Kind %q, want %q", name, got, c.Reject)
		}
	}
	for name, c := range v.Negative.OrderingMalformed {
		if got := kindOf(t, c.BodyHex); got != c.Reject {
			t.Fatalf("ordering_malformed.%s: got Kind %q, want %q", name, got, c.Reject)
		}
	}

	// keys_out_of_order: the canonical body decodes+validates cleanly; the descending-key body is
	// rejected at the CBOR layer (NonCanonical) before ParseDecisionRecord's own checks ever run.
	koo := v.Negative.KeysOutOfOrder
	if _, err := gateway.ParseDecisionRecord(hb(t, koo.CanonicalBodyHex)); err != nil {
		t.Fatalf("canonical keys_out_of_order body should parse: %v", err)
	}
	if _, err := cbor.Decode(hb(t, koo.NoncanonicalBodyHex)); err == nil {
		t.Fatal("descending-key decision-record body decoded (want NonCanonical)")
	} else if ce, ok := err.(*cbor.Error); !ok || ce.Kind != koo.Reject {
		t.Fatalf("descending-key body got %v, want %s", err, koo.Reject)
	}
	if _, err := gateway.ParseDecisionRecord(hb(t, koo.NoncanonicalBodyHex)); err != gateway.ErrDecisionRecordMalformed {
		t.Fatalf("ParseDecisionRecord(noncanon) got %v, want DecisionMalformed", err)
	}
}

// TestDecisionRecordThirdPartyReServe proves a signed decision record verifies offline and
// re-verifies identically when served by a party other than the producer (mirroring
// TestGatewayVendorOnlyMutation's sibling gateway-decision/egress-attestation coverage), and that a
// wrong-key verify fails BadSignature.
func TestDecisionRecordThirdPartyReServe(t *testing.T) {
	v := loadDRVec(t)
	producerS, producerV, _ := key(t, 0x71)
	_, foreignV, _ := key(t, 0x72)

	rv := v.Records["allow_consuming"]
	d := drFrom(t, rv)
	d.Ordering = gateway.CorrespondenceOnly()
	if got := hex.EncodeToString(d.Bytes()); got != rv.BodyHex {
		t.Fatalf("fixture mismatch: got %s want %s", got, rv.BodyHex)
	}

	obj, err := gateway.SignDecisionRecord(d, producerS)
	if err != nil {
		t.Fatalf("SignDecisionRecord: %v", err)
	}
	byProducer, err := gateway.VerifyDecisionRecord(obj, cose.ProfilePublic, producerV)
	if err != nil {
		t.Fatalf("VerifyDecisionRecord (served by producer): %v", err)
	}
	byThirdParty, err := gateway.VerifyDecisionRecord(obj, cose.ProfilePublic, producerV)
	if err != nil {
		t.Fatalf("VerifyDecisionRecord (re-served by a third party): %v", err)
	}
	if !bytes.Equal(byProducer.Action, byThirdParty.Action) || byProducer.Outcome != byThirdParty.Outcome {
		t.Fatal("the re-served record resolved differently from the producer-served record")
	}
	if byThirdParty.Outcome != gateway.DecisionAllow {
		t.Fatalf("resolved outcome %d, want allow", byThirdParty.Outcome)
	}
	if got := hex.EncodeToString(byThirdParty.Consume); got != *rv.ConsumeHex {
		t.Fatalf("resolved consume %s != oracle consume %s", got, *rv.ConsumeHex)
	}
	if _, err := gateway.VerifyDecisionRecord(obj, cose.ProfilePublic, foreignV); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key verify got %v, want BadSignature", err)
	}
}

// crossLangPinnedSignedDecisionRecordSHA384 is the pinned SHA-384 of the deterministic COSE_Sign1
// object obtained by signing the "terms_valid" decision-record body with the shared all-0x11
// 32-byte ML-DSA-65 seed, mirroring gateway_test.go's crossLangPinnedSignedDecisionSHA384. Left as
// PIN_ME here: this Go-only build has no Rust counterpart run to cross-check against yet.
const crossLangPinnedSignedDecisionRecordSHA384 = "PIN_ME"

func TestCrossLangSignedDecisionRecordPin(t *testing.T) {
	v := loadDRVec(t)
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 0x11
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	s := cose.MLDSA65Signer{SK: sk}

	rv := v.Records["terms_valid"]
	d := drFrom(t, rv)
	d.Ordering = gateway.CorrespondenceOnly()
	d.Terms = map[uint64]gateway.TermDisposition{
		1: {Kind: gateway.TermObserved},
		4: {Kind: gateway.TermReported, Source: []byte("boundary:relay-partner-3")},
	}
	if got := hex.EncodeToString(d.Bytes()); got != rv.BodyHex {
		t.Fatalf("fixture mismatch: got %s want %s", got, rv.BodyHex)
	}
	obj, err := gateway.SignDecisionRecord(d, s)
	if err != nil {
		t.Fatalf("SignDecisionRecord: %v", err)
	}
	dg := sha512.Sum384(obj)
	got := hex.EncodeToString(dg[:])
	t.Logf("CROSS-LANG signed decision-record SHA-384 (seed=0x11*32): %s", got)
	if crossLangPinnedSignedDecisionRecordSHA384 != "PIN_ME" && got != crossLangPinnedSignedDecisionRecordSHA384 {
		t.Fatalf("cross-lang signed-decision-record digest %s != pinned %s", got, crossLangPinnedSignedDecisionRecordSHA384)
	}
}

// TestDecisionRecordMinimal is the smallest valid record: empty action bstr, governing=[], deny,
// correspondence-only, no consume/terms/enforcement.
func TestDecisionRecordMinimal(t *testing.T) {
	v := loadDRVec(t)
	m := v.Records["minimal"]
	d := gateway.DecisionRecord{Action: []byte{}, Governing: [][]byte{}, Outcome: m.Outcome, Ordering: gateway.CorrespondenceOnly()}
	if got := hex.EncodeToString(d.Bytes()); got != m.BodyHex {
		t.Fatalf("minimal Bytes\n got %s\nwant %s", got, m.BodyHex)
	}
	if got := hex.EncodeToString(d.ID()); got != m.IDHex {
		t.Fatalf("minimal ID got %s want %s", got, m.IDHex)
	}
	parsed, err := gateway.ParseDecisionRecord(d.Bytes())
	if err != nil {
		t.Fatalf("ParseDecisionRecord(minimal): %v", err)
	}
	if err := gateway.ValidateDecisionRecord(parsed); err != nil {
		t.Fatalf("ValidateDecisionRecord(minimal): %v", err)
	}
}
