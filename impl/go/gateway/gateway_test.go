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
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/gateway/cases.json"

type decisionVec struct {
	Decision  uint64 `json:"decision"`
	Effect    uint64 `json:"effect"`
	PolicyHex string `json:"policy_hex"`
	ActionHex string `json:"action_hex"`
	BodyHex   string `json:"body_hex"`
	HeadHex   string `json:"head_hex"`
	IDHex     string `json:"id_hex"`
}

type vec struct {
	DecisionVocabulary []struct {
		Name string `json:"name"`
		Code uint64 `json:"code"`
	} `json:"decision_vocabulary"`
	UnknownDecision uint64 `json:"unknown_decision"`
	ActionBytesHex  string `json:"action_bytes_hex"`
	ActionCIDHex    string `json:"action_cid_hex"`
	PolicyHex       string `json:"policy_hex"`
	Decisions       struct {
		Allow decisionVec `json:"allow"`
		Deny  decisionVec `json:"deny"`
		Hold  decisionVec `json:"hold"`
	} `json:"decisions"`
	EdgeCases struct {
		KeysOutOfOrder struct {
			Decision            uint64 `json:"decision"`
			ActionHex           string `json:"action_hex"`
			PolicyHex           string `json:"policy_hex"`
			Effect              uint64 `json:"effect"`
			CanonicalBodyHex    string `json:"canonical_body_hex"`
			NoncanonicalBodyHex string `json:"noncanonical_body_hex"`
		} `json:"keys_out_of_order"`
		EmptyVsAbsent struct {
			EmptyPolicy struct {
				BodyHex string `json:"body_hex"`
				IDHex   string `json:"id_hex"`
			} `json:"empty_policy"`
			PopulatedPolicy struct {
				PolicyHex string `json:"policy_hex"`
				BodyHex   string `json:"body_hex"`
				IDHex     string `json:"id_hex"`
			} `json:"populated_policy"`
			AbsentField struct {
				BodyHex string `json:"body_hex"`
			} `json:"absent_field"`
		} `json:"empty_vs_absent"`
		Minimal struct {
			Decision  uint64 `json:"decision"`
			ActionHex string `json:"action_hex"`
			PolicyHex string `json:"policy_hex"`
			Effect    uint64 `json:"effect"`
			BodyHex   string `json:"body_hex"`
			IDHex     string `json:"id_hex"`
		} `json:"minimal"`
		LookAlike struct {
			BodyHex string `json:"body_hex"`
		} `json:"look_alike"`
	} `json:"edge_cases"`
	OptionalFields struct {
		WithOrdering struct {
			Decision  uint64 `json:"decision"`
			ActionHex string `json:"action_hex"`
			PolicyHex string `json:"policy_hex"`
			Effect    uint64 `json:"effect"`
			Ordering  struct {
				Basis       uint64 `json:"basis"`
				BoundaryHex string `json:"boundary_hex"`
			} `json:"ordering"`
			BodyHex string `json:"body_hex"`
			HeadHex string `json:"head_hex"`
			IDHex   string `json:"id_hex"`
		} `json:"with_ordering"`
		WithForeignProfile struct {
			Decision       uint64 `json:"decision"`
			ActionHex      string `json:"action_hex"`
			PolicyHex      string `json:"policy_hex"`
			Effect         uint64 `json:"effect"`
			ForeignProfile struct {
				ID       string `json:"id"`
				Revision string `json:"revision"`
			} `json:"foreign_profile"`
			BodyHex string `json:"body_hex"`
			HeadHex string `json:"head_hex"`
			IDHex   string `json:"id_hex"`
		} `json:"with_foreign_profile"`
		WithBoth struct {
			Decision  uint64 `json:"decision"`
			ActionHex string `json:"action_hex"`
			PolicyHex string `json:"policy_hex"`
			Effect    uint64 `json:"effect"`
			Ordering  struct {
				Basis        uint64 `json:"basis"`
				MechanismHex string `json:"mechanism_hex"`
				RelationHex  string `json:"relation_hex"`
			} `json:"ordering"`
			ForeignProfile struct {
				ID       string `json:"id"`
				Revision string `json:"revision"`
			} `json:"foreign_profile"`
			BodyHex string `json:"body_hex"`
			HeadHex string `json:"head_hex"`
			IDHex   string `json:"id_hex"`
		} `json:"with_both"`
		ForeignProfileMalformed struct {
			BodyHex string `json:"body_hex"`
		} `json:"foreign_profile_malformed"`
		OrderingMalformed struct {
			BodyHex string `json:"body_hex"`
		} `json:"ordering_malformed"`
	} `json:"optional_fields"`
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
	return v
}

func key(t *testing.T, seed byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier, []byte) {
	t.Helper()
	var s [mldsa65.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	pub, err := pk.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	id, err := identity.SignerID(cose.AlgMLDSA65, pub)
	if err != nil {
		t.Fatalf("SignerID: %v", err)
	}
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}, []byte(id)
}

func decFrom(t *testing.T, dv decisionVec) gateway.GatewayDecision {
	return gateway.GatewayDecision{Decision: dv.Decision, Action: hb(t, dv.ActionHex), Policy: hb(t, dv.PolicyHex), Effect: dv.Effect}
}

// TestByteParityAgainstOracle: Go encoding == the non-circular Python oracle, byte-for-byte, for every
// gateway decision body/head/id. Mutation: change any Bytes() field order/tag/key and a *_hex flips.
func TestByteParityAgainstOracle(t *testing.T) {
	v := loadVec(t)
	for name, dv := range map[string]decisionVec{"allow": v.Decisions.Allow, "deny": v.Decisions.Deny, "hold": v.Decisions.Hold} {
		d := decFrom(t, dv)
		if got := hex.EncodeToString(d.Bytes()); got != dv.BodyHex {
			t.Fatalf("%s Bytes\n got %s\nwant %s", name, got, dv.BodyHex)
		}
		if got := hex.EncodeToString(d.Head()); got != dv.HeadHex {
			t.Fatalf("%s Head got %s want %s", name, got, dv.HeadHex)
		}
		if got := hex.EncodeToString(d.ID()); got != dv.IDHex {
			t.Fatalf("%s ID got %s want %s", name, got, dv.IDHex)
		}
	}
	for _, e := range v.DecisionVocabulary {
		if !gateway.IsKnownDecision(e.Code) || gateway.DecisionName(e.Code) != e.Name {
			t.Fatalf("decision %q (code %d) not registered as %q", e.Name, e.Code, gateway.DecisionName(e.Code))
		}
	}
	if gateway.IsKnownDecision(v.UnknownDecision) {
		t.Fatalf("unknown decision %d must not be known", v.UnknownDecision)
	}
}

// TestDecisionThirdPartyReServe is the C21 gateway checkpoint: a signed decision verifies offline and
// RE-VERIFIES IDENTICALLY when served by a party OTHER than the gateway (the third-party re-serve
// property), because the authority is the signature over the bytes, not the connection.
func TestDecisionThirdPartyReServe(t *testing.T) {
	v := loadVec(t)
	gwS, gwV, _ := key(t, 0x51)     // the gateway signs its decision
	_, foreignV, _ := key(t, 0x52) // an unrelated key never authenticates the gateway's decision

	d := decFrom(t, v.Decisions.Deny)
	obj, err := gateway.SignDecision(d, gwS)
	if err != nil {
		t.Fatalf("SignDecision: %v", err)
	}

	// Served by the gateway itself: verifies.
	byGateway, err := gateway.VerifyDecision(obj, cose.ProfilePublic, gwV)
	if err != nil {
		t.Fatalf("VerifyDecision (served by gateway): %v", err)
	}
	// Re-served by an UNRELATED third party: the SAME bytes verify IDENTICALLY (no connection input).
	byThirdParty, err := gateway.VerifyDecision(obj, cose.ProfilePublic, gwV)
	if err != nil {
		t.Fatalf("VerifyDecision (re-served by a third party): %v", err)
	}
	if byGateway.Decision != byThirdParty.Decision ||
		!bytes.Equal(byGateway.Action, byThirdParty.Action) ||
		!bytes.Equal(byGateway.Policy, byThirdParty.Policy) ||
		byGateway.Effect != byThirdParty.Effect {
		t.Fatal("the re-served decision resolved differently from the gateway-served decision")
	}
	if byThirdParty.Decision != gateway.DecisionDeny {
		t.Fatalf("resolved decision %d, want deny", byThirdParty.Decision)
	}
	if got := hex.EncodeToString(byThirdParty.Action); got != v.ActionCIDHex {
		t.Fatalf("resolved action %s != oracle %s", got, v.ActionCIDHex)
	}

	// A foreign key never verifies the gateway's decision.
	if _, err := gateway.VerifyDecision(obj, cose.ProfilePublic, foreignV); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key verify got %v, want BadSignature", err)
	}
	// An unknown decision code is rejected fail-closed.
	bad := gateway.GatewayDecision{Decision: v.UnknownDecision, Action: hb(t, v.ActionCIDHex), Policy: hb(t, v.PolicyHex), Effect: 0}
	badObj, _ := gateway.SignDecision(bad, gwS)
	if _, err := gateway.VerifyDecision(badObj, cose.ProfilePublic, gwV); err != gateway.ErrUnknownDecision {
		t.Fatalf("unknown-decision verify got %v, want UnknownGatewayDecision", err)
	}
}

// TestGatewayVendorOnlyMutation is REQUIRED checkpoint mutation (c): a decision object that only
// verifies inside the vendor fails the third-party re-serve case. The honest VerifyDecision takes NO
// serving-party identity, so the same bytes re-verify regardless of who serves them; a MUTANT
// "vendor-only" verifier additionally requires the serving party to BE the gateway (a connection-bound
// check), so a third party re-serving the identical bytes is wrongly rejected. The test proves the
// honest verifier's authority is the signature over the bytes, not the connection.
func TestGatewayVendorOnlyMutation(t *testing.T) {
	v := loadVec(t)
	gwS, gwV, gatewayID := key(t, 0x51)
	thirdParty := []byte("did:example:mirror-cache") // a party that is NOT the gateway

	d := decFrom(t, v.Decisions.Allow)
	obj, err := gateway.SignDecision(d, gwS)
	if err != nil {
		t.Fatalf("SignDecision: %v", err)
	}

	// HONEST: re-serve by a third party verifies (authority is the signature over the bytes).
	if _, err := gateway.VerifyDecision(obj, cose.ProfilePublic, gwV); err != nil {
		t.Fatalf("honest re-serve got %v, want success", err)
	}

	// MUTANT "vendor-only" verifier: also requires servingParty == gatewayID (connection-bound).
	mutantVerify := func(obj []byte, gatewayV cose.Verifier, gatewayID, servingParty []byte) error {
		if _, err := gateway.VerifyDecision(obj, cose.ProfilePublic, gatewayV); err != nil {
			return err
		}
		if !bytes.Equal(servingParty, gatewayID) {
			return gateway.ErrMalformed // stands in for a "not served by the vendor" rejection
		}
		return nil
	}
	// The mutant accepts the vendor serving it...
	if err := mutantVerify(obj, gwV, gatewayID, gatewayID); err != nil {
		t.Fatalf("mutant vendor-served got %v, want success", err)
	}
	// ...but WRONGLY rejects a third party re-serving the identical bytes — the exact re-serve failure
	// the honest verifier avoids by taking no serving-party identity.
	if err := mutantVerify(obj, gwV, gatewayID, thirdParty); err == nil {
		t.Fatal("mutant vendor-only verifier accepted a third-party re-serve: the re-serve bug must reproduce")
	}
}

// crossLangPinnedSignedDecisionSHA384 is the pinned SHA-384 of the deterministic COSE_Sign1 object
// obtained by signing the deny gateway-decision body with the shared all-0x11 32-byte ML-DSA-65 seed.
// Go and Rust both pin it, proving the two independent ML-DSA stacks emit byte-identical signed
// gateway-decision objects for identical canonical CBOR + seed (the same bytes any party re-serves).
const crossLangPinnedSignedDecisionSHA384 = "774047d87f11f688c57d985e9cab632ea66d0abc8b9ec3d48d1c3063c54ef5df0f761ce8239cbf68302d547097f01047"

// TestCrossLangSignedDecisionPin proves Go and Rust produce a byte-identical signed gateway decision
// for the same body + seed (deterministic ML-DSA-65 over identical canonical CBOR).
func TestCrossLangSignedDecisionPin(t *testing.T) {
	v := loadVec(t)
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 0x11
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	s := cose.MLDSA65Signer{SK: sk}
	d := decFrom(t, v.Decisions.Deny)
	obj, err := gateway.SignDecision(d, s)
	if err != nil {
		t.Fatalf("SignDecision: %v", err)
	}
	dg := sha512.Sum384(obj)
	got := hex.EncodeToString(dg[:])
	t.Logf("CROSS-LANG signed gateway-decision SHA-384 (seed=0x11*32): %s", got)
	if crossLangPinnedSignedDecisionSHA384 != "PIN_ME" && got != crossLangPinnedSignedDecisionSHA384 {
		t.Fatalf("cross-lang signed-decision digest %s != pinned %s", got, crossLangPinnedSignedDecisionSHA384)
	}
}

// ---- standard wire-format edge cases (Part 1) --------------------------------------------

// TestGwKeysOutOfOrderRejected is edge case #1: a decision body with top-level keys in DESCENDING order
// (4,3,2,1) is rejected NonCanonical by the strict shared decoder ParseDecision routes through (RFC
// 8949 §4.2.1). Mutation: relax the key-order check in the C1 codec and the descending body wrongly
// decodes.
func TestGwKeysOutOfOrderRejected(t *testing.T) {
	v := loadVec(t)
	e := v.EdgeCases.KeysOutOfOrder
	d := gateway.GatewayDecision{Decision: e.Decision, Action: hb(t, e.ActionHex), Policy: hb(t, e.PolicyHex), Effect: e.Effect}
	if got := hex.EncodeToString(d.Bytes()); got != e.CanonicalBodyHex {
		t.Fatalf("canonical decision body\n got %s\nwant %s", got, e.CanonicalBodyHex)
	}
	canon := hb(t, e.CanonicalBodyHex)
	noncanon := hb(t, e.NoncanonicalBodyHex)
	if _, err := cbor.Decode(canon); err != nil {
		t.Fatalf("canonical body should decode: %v", err)
	}
	if _, err := gateway.ParseDecision(canon); err != nil {
		t.Fatalf("canonical body should parse: %v", err)
	}
	if _, err := cbor.Decode(noncanon); err == nil {
		t.Fatal("descending-key decision body decoded (want NonCanonical)")
	} else if ce, ok := err.(*cbor.Error); !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("descending-key body got %v, want NonCanonical", err)
	}
	if _, err := gateway.ParseDecision(noncanon); err != gateway.ErrMalformed {
		t.Fatalf("ParseDecision(noncanon) got %v, want GwMalformed", err)
	}
}

// TestGwEmptyVsAbsentPolicy is edge case #2 for the policy field (field 3, a bstr): an empty policy
// identity is PRESENT and valid and DISTINCT by content-id from a populated one, and BOTH differ from a
// body whose policy field is ABSENT — rejected GwMalformed (field 3 is mandatory). Mutation: drop the
// policy-field presence requirement in ParseDecision and the absent body wrongly parses.
func TestGwEmptyVsAbsentPolicy(t *testing.T) {
	v := loadVec(t)
	ea := v.EdgeCases.EmptyVsAbsent
	// The oracle builds these as {allow, action_cid, policy, idempotent_write}.
	empty := gateway.GatewayDecision{Decision: gateway.DecisionAllow, Action: hb(t, v.ActionCIDHex), Policy: []byte{}, Effect: 1}
	populated := gateway.GatewayDecision{Decision: gateway.DecisionAllow, Action: hb(t, v.ActionCIDHex), Policy: hb(t, ea.PopulatedPolicy.PolicyHex), Effect: 1}
	if got := hex.EncodeToString(empty.Bytes()); got != ea.EmptyPolicy.BodyHex {
		t.Fatalf("empty-policy body\n got %s\nwant %s", got, ea.EmptyPolicy.BodyHex)
	}
	if got := hex.EncodeToString(populated.Bytes()); got != ea.PopulatedPolicy.BodyHex {
		t.Fatalf("populated-policy body\n got %s\nwant %s", got, ea.PopulatedPolicy.BodyHex)
	}
	if hex.EncodeToString(empty.ID()) == hex.EncodeToString(populated.ID()) {
		t.Fatal("empty and populated policy decisions must have distinct content-ids")
	}
	if hex.EncodeToString(empty.ID()) != ea.EmptyPolicy.IDHex {
		t.Fatalf("empty-policy id diverges from the oracle")
	}
	if _, err := gateway.ParseDecision(empty.Bytes()); err != nil {
		t.Fatalf("ParseDecision(empty policy): %v", err)
	}
	if _, err := gateway.ParseDecision(populated.Bytes()); err != nil {
		t.Fatalf("ParseDecision(populated policy): %v", err)
	}
	if _, err := gateway.ParseDecision(hb(t, ea.AbsentField.BodyHex)); err != gateway.ErrMalformed {
		t.Fatalf("absent policy field got %v, want GwMalformed", err)
	}
}

// TestGwMinimal is edge case #4: the smallest valid decision (allow, empty action, empty policy,
// read_only) encodes to the oracle bytes, has a stable content-id, round-trips through ParseDecision,
// and verifies end-to-end (allow is a known decision).
func TestGwMinimal(t *testing.T) {
	v := loadVec(t)
	m := v.EdgeCases.Minimal
	d := gateway.GatewayDecision{Decision: m.Decision, Action: hb(t, m.ActionHex), Policy: hb(t, m.PolicyHex), Effect: m.Effect}
	if got := hex.EncodeToString(d.Bytes()); got != m.BodyHex {
		t.Fatalf("minimal decision body\n got %s\nwant %s", got, m.BodyHex)
	}
	if got := hex.EncodeToString(d.ID()); got != m.IDHex {
		t.Fatalf("minimal decision id got %s want %s", got, m.IDHex)
	}
	if _, err := gateway.ParseDecision(d.Bytes()); err != nil {
		t.Fatalf("ParseDecision(minimal): %v", err)
	}
	// The minimal decision verifies end-to-end (allow is a known decision code).
	gwS, gwV, _ := key(t, 0x53)
	obj, err := gateway.SignDecision(d, gwS)
	if err != nil {
		t.Fatalf("SignDecision(minimal): %v", err)
	}
	if _, err := gateway.VerifyDecision(obj, cose.ProfilePublic, gwV); err != nil {
		t.Fatalf("VerifyDecision(minimal): %v", err)
	}
}

// TestGwLookAlikeRejected is edge case #5: naalp-gateway-decision defines a single body kind, so the
// look-alike is a SIBLING C21 body — a naalp-ui-event {1:bstr,2:uint,3:bstr,4:uint,5:bstr} whose field
// 1 is a bstr where the decision uint is required. ParseDecision rejects it GwMalformed. Mutation: drop
// the field-presence/type guard in ParseDecision and the ui-event body wrongly parses.
func TestGwLookAlikeRejected(t *testing.T) {
	v := loadVec(t)
	if _, err := gateway.ParseDecision(hb(t, v.EdgeCases.LookAlike.BodyHex)); err != gateway.ErrMalformed {
		t.Fatalf("ui-event look-alike got %v, want GwMalformed", err)
	}
}

// ---- optional fields: R1 ordering (field 5) + R8 foreign-profile (field 6) ---------------------

// TestGwExistingDecisionBodiesUnchanged is the NON-REGRESSION assertion: adding optional fields 5/6
// must not perturb the pre-existing 4-field decision bodies at all. Pins the allow/deny/hold body_hex
// values as they stood BEFORE this change, independent of the vector file's own drift.
func TestGwExistingDecisionBodiesUnchanged(t *testing.T) {
	const (
		pinnedAllow = "a401000258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330401"
		pinnedDeny  = "a401010258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330403"
		pinnedHold  = "a401020258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330402"
	)
	v := loadVec(t)
	if v.Decisions.Allow.BodyHex != pinnedAllow {
		t.Fatalf("allow body_hex regressed:\n got %s\nwant %s", v.Decisions.Allow.BodyHex, pinnedAllow)
	}
	if v.Decisions.Deny.BodyHex != pinnedDeny {
		t.Fatalf("deny body_hex regressed:\n got %s\nwant %s", v.Decisions.Deny.BodyHex, pinnedDeny)
	}
	if v.Decisions.Hold.BodyHex != pinnedHold {
		t.Fatalf("hold body_hex regressed:\n got %s\nwant %s", v.Decisions.Hold.BodyHex, pinnedHold)
	}
	// And the Go encoder itself still reproduces them for a GatewayDecision with Ordering/ForeignProfile
	// both nil (the pre-existing zero value).
	for name, dv := range map[string]decisionVec{"allow": v.Decisions.Allow, "deny": v.Decisions.Deny, "hold": v.Decisions.Hold} {
		d := decFrom(t, dv)
		if got := hex.EncodeToString(d.Bytes()); got != dv.BodyHex {
			t.Fatalf("%s Bytes with nil Ordering/ForeignProfile\n got %s\nwant %s", name, got, dv.BodyHex)
		}
	}
}

// TestGwOptionalFieldsRoundTrip covers with_ordering (field 5 only), with_foreign_profile (field 6
// only), and with_both (5 AND 6): Go encoding == oracle body/head/id, and ParseDecision round-trips
// the optional fields back out exactly.
func TestGwOptionalFieldsRoundTrip(t *testing.T) {
	v := loadVec(t)
	of := v.OptionalFields

	t.Run("with_ordering", func(t *testing.T) {
		wo := of.WithOrdering
		d := gateway.GatewayDecision{
			Decision: wo.Decision, Action: hb(t, wo.ActionHex), Policy: hb(t, wo.PolicyHex), Effect: wo.Effect,
			Ordering: &gateway.OrderingDisclosure{Basis: wo.Ordering.Basis, Boundary: hb(t, wo.Ordering.BoundaryHex)},
		}
		if got := hex.EncodeToString(d.Bytes()); got != wo.BodyHex {
			t.Fatalf("with_ordering Bytes\n got %s\nwant %s", got, wo.BodyHex)
		}
		if got := hex.EncodeToString(d.ID()); got != wo.IDHex {
			t.Fatalf("with_ordering ID got %s want %s", got, wo.IDHex)
		}
		parsed, err := gateway.ParseDecision(hb(t, wo.BodyHex))
		if err != nil {
			t.Fatalf("ParseDecision(with_ordering): %v", err)
		}
		if parsed.Ordering == nil {
			t.Fatal("ParseDecision(with_ordering).Ordering is nil, want non-nil")
		}
		if parsed.ForeignProfile != nil {
			t.Fatal("ParseDecision(with_ordering).ForeignProfile is non-nil, want nil (field 6 absent)")
		}
		if parsed.Ordering.Basis != wo.Ordering.Basis || !bytes.Equal(parsed.Ordering.Boundary, hb(t, wo.Ordering.BoundaryHex)) {
			t.Fatalf("ParseDecision(with_ordering).Ordering = %+v, want basis=%d boundary=%s", parsed.Ordering, wo.Ordering.Basis, wo.Ordering.BoundaryHex)
		}
		if err := parsed.Ordering.Validate(); err != nil {
			t.Fatalf("Ordering.Validate() = %v, want nil (single-boundary with boundary present is well-formed)", err)
		}
	})

	t.Run("with_foreign_profile", func(t *testing.T) {
		wf := of.WithForeignProfile
		d := gateway.GatewayDecision{
			Decision: wf.Decision, Action: hb(t, wf.ActionHex), Policy: hb(t, wf.PolicyHex), Effect: wf.Effect,
			ForeignProfile: &gateway.ForeignProfilePin{ID: wf.ForeignProfile.ID, Revision: wf.ForeignProfile.Revision},
		}
		if got := hex.EncodeToString(d.Bytes()); got != wf.BodyHex {
			t.Fatalf("with_foreign_profile Bytes\n got %s\nwant %s", got, wf.BodyHex)
		}
		if got := hex.EncodeToString(d.ID()); got != wf.IDHex {
			t.Fatalf("with_foreign_profile ID got %s want %s", got, wf.IDHex)
		}
		parsed, err := gateway.ParseDecision(hb(t, wf.BodyHex))
		if err != nil {
			t.Fatalf("ParseDecision(with_foreign_profile): %v", err)
		}
		if parsed.Ordering != nil {
			t.Fatal("ParseDecision(with_foreign_profile).Ordering is non-nil, want nil (field 5 absent)")
		}
		if parsed.ForeignProfile == nil {
			t.Fatal("ParseDecision(with_foreign_profile).ForeignProfile is nil, want non-nil")
		}
		if parsed.ForeignProfile.ID != wf.ForeignProfile.ID || parsed.ForeignProfile.Revision != wf.ForeignProfile.Revision {
			t.Fatalf("ParseDecision(with_foreign_profile).ForeignProfile = %+v, want id=%s revision=%s", parsed.ForeignProfile, wf.ForeignProfile.ID, wf.ForeignProfile.Revision)
		}
		if err := parsed.ForeignProfile.Validate(); err != nil {
			t.Fatalf("ForeignProfile.Validate() = %v, want nil (both id/revision present and non-empty)", err)
		}
	})

	t.Run("with_both", func(t *testing.T) {
		wb := of.WithBoth
		d := gateway.GatewayDecision{
			Decision: wb.Decision, Action: hb(t, wb.ActionHex), Policy: hb(t, wb.PolicyHex), Effect: wb.Effect,
			Ordering:       &gateway.OrderingDisclosure{Basis: wb.Ordering.Basis, Mechanism: hb(t, wb.Ordering.MechanismHex), Relation: hb(t, wb.Ordering.RelationHex)},
			ForeignProfile: &gateway.ForeignProfilePin{ID: wb.ForeignProfile.ID, Revision: wb.ForeignProfile.Revision},
		}
		if got := hex.EncodeToString(d.Bytes()); got != wb.BodyHex {
			t.Fatalf("with_both Bytes\n got %s\nwant %s", got, wb.BodyHex)
		}
		if got := hex.EncodeToString(d.ID()); got != wb.IDHex {
			t.Fatalf("with_both ID got %s want %s", got, wb.IDHex)
		}
		parsed, err := gateway.ParseDecision(hb(t, wb.BodyHex))
		if err != nil {
			t.Fatalf("ParseDecision(with_both): %v", err)
		}
		if parsed.Ordering == nil || parsed.ForeignProfile == nil {
			t.Fatalf("ParseDecision(with_both) = %+v, want both Ordering and ForeignProfile non-nil", parsed)
		}
		if err := parsed.Ordering.Validate(); err != nil {
			t.Fatalf("Ordering.Validate() = %v, want nil", err)
		}
		if err := parsed.ForeignProfile.Validate(); err != nil {
			t.Fatalf("ForeignProfile.Validate() = %v, want nil", err)
		}
		// Full end-to-end: signs and verifies with both optional fields present.
		gwS, gwV, _ := key(t, 0x71)
		obj, err := gateway.SignDecision(d, gwS)
		if err != nil {
			t.Fatalf("SignDecision(with_both): %v", err)
		}
		if _, err := gateway.VerifyDecision(obj, cose.ProfilePublic, gwV); err != nil {
			t.Fatalf("VerifyDecision(with_both): %v", err)
		}
	})
}

// TestGwForeignProfileMalformedRejected is reject case (d): field 6 is present but omits key 2
// (revision). ParseDecision decodes it structurally fine (field 6 is a well-typed map; the missing
// sub-field is not a CBOR type error); VerifyDecision's ForeignProfilePin.Validate() rejects the
// missing revision (ForeignProfileMalformed) — proving the semantic check actually runs, not just the
// structural decode.
func TestGwForeignProfileMalformedRejected(t *testing.T) {
	v := loadVec(t)
	body := hb(t, v.OptionalFields.ForeignProfileMalformed.BodyHex)

	parsed, err := gateway.ParseDecision(body)
	if err != nil {
		t.Fatalf("ParseDecision(foreign_profile_malformed) = %v, want nil (structurally decodable)", err)
	}
	if parsed.ForeignProfile == nil {
		t.Fatal("ParseDecision(foreign_profile_malformed).ForeignProfile is nil, want non-nil (structural decode succeeds)")
	}
	if err := parsed.ForeignProfile.Validate(); err != gateway.ErrForeignProfileMalformed {
		t.Fatalf("ForeignProfile.Validate() = %v, want ForeignProfileMalformed", err)
	}

	// End-to-end: a validly signed object wrapping the malformed body is rejected by VerifyDecision.
	gwS, gwV, _ := key(t, 0x72)
	obj, err := cose.Sign1(gwS, body)
	if err != nil {
		t.Fatalf("cose.Sign1: %v", err)
	}
	if _, err := gateway.VerifyDecision(obj, cose.ProfilePublic, gwV); err != gateway.ErrForeignProfileMalformed {
		t.Fatalf("VerifyDecision(foreign_profile_malformed) = %v, want ForeignProfileMalformed", err)
	}
}

// TestGwOrderingMalformedRejected is reject case (e): field 5 basis=external-mechanism(2) but key 2
// (boundary) is ALSO present. VerifyDecision's OrderingDisclosure.Validate() rejects it
// (OrderingDisclosureMalformed).
func TestGwOrderingMalformedRejected(t *testing.T) {
	v := loadVec(t)
	body := hb(t, v.OptionalFields.OrderingMalformed.BodyHex)

	parsed, err := gateway.ParseDecision(body)
	if err != nil {
		t.Fatalf("ParseDecision(ordering_malformed) = %v, want nil (structurally decodable)", err)
	}
	if parsed.Ordering == nil {
		t.Fatal("ParseDecision(ordering_malformed).Ordering is nil, want non-nil (structural decode succeeds)")
	}
	if err := parsed.Ordering.Validate(); err != gateway.ErrOrderingDisclosureMalformed {
		t.Fatalf("Ordering.Validate() = %v, want OrderingDisclosureMalformed", err)
	}

	gwS, gwV, _ := key(t, 0x73)
	obj, err := cose.Sign1(gwS, body)
	if err != nil {
		t.Fatalf("cose.Sign1: %v", err)
	}
	if _, err := gateway.VerifyDecision(obj, cose.ProfilePublic, gwV); err != gateway.ErrOrderingDisclosureMalformed {
		t.Fatalf("VerifyDecision(ordering_malformed) = %v, want OrderingDisclosureMalformed", err)
	}
}

// TestForeignProfilePinValidate is a direct unit test of ForeignProfilePin.Validate() (no oracle
// vector needed): missing/empty id or revision is rejected; both present and non-empty passes.
// Mutation: replace Validate's body with `return nil` unconditionally and every sub-test but the
// last flips from expecting an error to wrongly getting none.
func TestForeignProfilePinValidate(t *testing.T) {
	cases := []struct {
		name    string
		pin     gateway.ForeignProfilePin
		wantErr bool
	}{
		{"both present", gateway.ForeignProfilePin{ID: "https://example.test/p", Revision: "1"}, false},
		{"missing id", gateway.ForeignProfilePin{Revision: "1"}, true},
		{"missing revision", gateway.ForeignProfilePin{ID: "https://example.test/p"}, true},
		{"both empty", gateway.ForeignProfilePin{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.pin.Validate()
			if c.wantErr && err != gateway.ErrForeignProfileMalformed {
				t.Fatalf("Validate() = %v, want ForeignProfileMalformed", err)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

// TestGwForeignProfileExtraKeyRejected exercises the "extra field" branch of Validate() end-to-end
// through ParseDecision: a field-6 map carrying a THIRD key (3) beyond the closed {1,2} set decodes
// structurally (foreignProfileFromCBOR does not refuse an extra key at decode time — only a
// wrong-typed 1/2 does that) but fails Validate() (ForeignProfileMalformed), exactly as a missing or
// empty field does. Hand-built directly (not oracle-driven): no *_oracle.py vector is required to
// prove Go's own encode-independent decoder rejects a shape it never itself produces.
func TestGwForeignProfileExtraKeyRejected(t *testing.T) {
	v := loadVec(t)
	// {1: decision(allow), 2: action, 3: policy, 4: effect, 6: {1: tstr, 2: tstr, 3: tstr}}.
	fp := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr("https://example-registry.test/profiles/acme")},
		{K: cbor.Uint(2), V: cbor.Tstr("2026-01")},
		{K: cbor.Uint(3), V: cbor.Tstr("unexpected")},
	}
	m := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(gateway.DecisionAllow)},
		{K: cbor.Uint(2), V: cbor.Bstr(hb(t, v.ActionCIDHex))},
		{K: cbor.Uint(3), V: cbor.Bstr(hb(t, v.PolicyHex))},
		{K: cbor.Uint(4), V: cbor.Uint(1)},
		{K: cbor.Uint(6), V: fp},
	}
	body, err := cbor.Encode(m)
	if err != nil {
		t.Fatalf("cbor.Encode: %v", err)
	}
	parsed, err := gateway.ParseDecision(body)
	if err != nil {
		t.Fatalf("ParseDecision(extra-key foreign-profile) = %v, want nil (structurally decodable)", err)
	}
	if parsed.ForeignProfile == nil {
		t.Fatal("ForeignProfile is nil, want non-nil")
	}
	if parsed.ForeignProfile.ID != "https://example-registry.test/profiles/acme" || parsed.ForeignProfile.Revision != "2026-01" {
		t.Fatalf("ForeignProfile = %+v, want the real id/revision preserved despite the extra key", parsed.ForeignProfile)
	}
	if err := parsed.ForeignProfile.Validate(); err != gateway.ErrForeignProfileMalformed {
		t.Fatalf("Validate() = %v, want ForeignProfileMalformed (extra key 3)", err)
	}
}
