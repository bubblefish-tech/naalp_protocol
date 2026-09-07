// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package gateway_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/gateway"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const egressVectorPath = "../../../vectors/egress_attestation/cases.json"

type egressAttVec struct {
	Binding     uint64 `json:"binding"`
	DigestHex   string `json:"digest_hex"`
	Effect      uint64 `json:"effect"`
	AudienceHex string `json:"audience_hex"`
	AtStr       string `json:"at_str"`
	BodyHex     string `json:"body_hex"`
	HeadHex     string `json:"head_hex"`
	IDHex       string `json:"id_hex"`
}

type egressVec struct {
	BindingVocabulary []struct {
		Name string `json:"name"`
		Code uint64 `json:"code"`
	} `json:"binding_vocabulary"`
	UnknownBinding    uint64 `json:"unknown_binding"`
	ObjectCIDHex      string `json:"object_cid_hex"`
	WrongObjectCIDHex string `json:"wrong_object_cid_hex"`
	AudienceHex       string `json:"audience_hex"`
	Attestations      struct {
		ContentBound egressAttVec `json:"content_bound"`
		ContentFree  egressAttVec `json:"content_free"`
	} `json:"attestations"`
	CommitmentOpen struct {
		ObjectCIDHex      string `json:"object_cid_hex"`
		WrongObjectCIDHex string `json:"wrong_object_cid_hex"`
		SaltHex           string `json:"salt_hex"`
		WrongSaltHex      string `json:"wrong_salt_hex"`
		CommitmentHex     string `json:"commitment_hex"`
	} `json:"commitment_open"`
	EdgeCases struct {
		KeysOutOfOrder struct {
			Binding             uint64 `json:"binding"`
			DigestHex           string `json:"digest_hex"`
			Effect              uint64 `json:"effect"`
			AudienceHex         string `json:"audience_hex"`
			AtStr               string `json:"at_str"`
			CanonicalBodyHex    string `json:"canonical_body_hex"`
			NoncanonicalBodyHex string `json:"noncanonical_body_hex"`
		} `json:"keys_out_of_order"`
		EmptyVsAbsent struct {
			EmptyAudience struct {
				BodyHex string `json:"body_hex"`
				IDHex   string `json:"id_hex"`
			} `json:"empty_audience"`
			PopulatedAudience struct {
				AudienceHex string `json:"audience_hex"`
				BodyHex     string `json:"body_hex"`
				IDHex       string `json:"id_hex"`
			} `json:"populated_audience"`
			AbsentField struct {
				BodyHex string `json:"body_hex"`
			} `json:"absent_field"`
		} `json:"empty_vs_absent"`
		OversizedCounter egressAttVec `json:"oversized_counter"`
		Minimal          egressAttVec `json:"minimal"`
		LookAlike        struct {
			BodyHex string `json:"body_hex"`
		} `json:"look_alike"`
	} `json:"edge_cases"`
	AttestationsWithOrdering map[string]egressAttVec `json:"attestations_with_ordering"`
	OrderingBasisVocabulary  []struct {
		Name string `json:"name"`
		Code uint64 `json:"code"`
	} `json:"ordering_basis_vocabulary"`
	NegativeOrdering struct {
		OrderingMalformedSingleBoundaryWithMechanism struct {
			BodyHex string `json:"body_hex"`
			Reject  string `json:"reject"`
		} `json:"ordering_malformed_single_boundary_with_mechanism"`
		UnknownOrderingBasis struct {
			BodyHex string `json:"body_hex"`
			Reject  string `json:"reject"`
		} `json:"unknown_ordering_basis"`
	} `json:"negative_ordering"`
}

func loadEgressVec(t *testing.T) egressVec {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(egressVectorPath))
	if err != nil {
		t.Fatalf("read egress vectors: %v", err)
	}
	var v egressVec
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse egress vectors: %v", err)
	}
	return v
}

// atU64 parses an epoch-ms field from its decimal-string corpus representation (never a bare JSON
// number — the nonce.derive seq lesson: a float64 JSON decoder anywhere in the toolchain would
// silently round a value above 2^53; strconv.ParseUint is lossless across the full uint64 range).
func atU64(t *testing.T, s string) uint64 {
	t.Helper()
	u, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("bad at_str %q: %v", s, err)
	}
	return u
}

func attFrom(t *testing.T, av egressAttVec) gateway.EgressAttestation {
	return gateway.EgressAttestation{
		Binding:  av.Binding,
		Digest:   hb(t, av.DigestHex),
		Effect:   av.Effect,
		Audience: hb(t, av.AudienceHex),
		At:       atU64(t, av.AtStr),
	}
}

// TestEgressByteParityAgainstOracle: Go encoding == the non-circular Python oracle, byte-for-byte,
// for every egress attestation body/head/id, including the full-width oversized-counter edge case.
// Mutation: change any Bytes() field order/tag/key and a *_hex flips.
func TestEgressByteParityAgainstOracle(t *testing.T) {
	v := loadEgressVec(t)
	for name, av := range map[string]egressAttVec{"content_bound": v.Attestations.ContentBound, "content_free": v.Attestations.ContentFree} {
		a := attFrom(t, av)
		if got := hex.EncodeToString(a.Bytes()); got != av.BodyHex {
			t.Fatalf("%s Bytes\n got %s\nwant %s", name, got, av.BodyHex)
		}
		if got := hex.EncodeToString(a.Head()); got != av.HeadHex {
			t.Fatalf("%s Head got %s want %s", name, got, av.HeadHex)
		}
		if got := hex.EncodeToString(a.ID()); got != av.IDHex {
			t.Fatalf("%s ID got %s want %s", name, got, av.IDHex)
		}
	}
	for _, e := range v.BindingVocabulary {
		if !gateway.IsKnownBinding(e.Code) || gateway.BindingName(e.Code) != e.Name {
			t.Fatalf("binding %q (code %d) not registered as %q", e.Name, e.Code, gateway.BindingName(e.Code))
		}
	}
	if gateway.IsKnownBinding(v.UnknownBinding) {
		t.Fatalf("unknown binding %d must not be known", v.UnknownBinding)
	}
}

// TestEgressOversizedCounter proves field 5 (`at`) round-trips losslessly at the top of the uint64
// range (2^64-1), carried through the corpus as a decimal string, never a bare JSON number.
func TestEgressOversizedCounter(t *testing.T) {
	v := loadEgressVec(t)
	e := v.EdgeCases.OversizedCounter
	if e.AtStr != "18446744073709551615" {
		t.Fatalf("oracle at_str got %s, want 2^64-1", e.AtStr)
	}
	a := attFrom(t, e)
	if a.At != ^uint64(0) {
		t.Fatalf("parsed At = %d, want 2^64-1", a.At)
	}
	if got := hex.EncodeToString(a.Bytes()); got != e.BodyHex {
		t.Fatalf("oversized-counter Bytes\n got %s\nwant %s", got, e.BodyHex)
	}
	parsed, err := gateway.ParseEgressAttestation(a.Bytes())
	if err != nil {
		t.Fatalf("ParseEgressAttestation(oversized): %v", err)
	}
	if parsed.At != a.At {
		t.Fatalf("round-tripped At = %d, want %d (precision lost)", parsed.At, a.At)
	}
}

// TestEgressAttestationThirdPartyReServe is the checkpoint mirroring TestDecisionThirdPartyReServe: a
// signed egress attestation verifies offline and RE-VERIFIES IDENTICALLY when served by a party
// OTHER than the gateway, because the authority is the signature over the bytes, not the connection.
func TestEgressAttestationThirdPartyReServe(t *testing.T) {
	v := loadEgressVec(t)
	gwS, gwV, _ := key(t, 0x61)
	_, foreignV, _ := key(t, 0x62)

	a := attFrom(t, v.Attestations.ContentBound)
	obj, err := gateway.SignEgressAttestation(a, gwS)
	if err != nil {
		t.Fatalf("SignEgressAttestation: %v", err)
	}

	byGateway, err := gateway.VerifyEgressAttestation(obj, cose.ProfilePublic, gwV)
	if err != nil {
		t.Fatalf("VerifyEgressAttestation (served by gateway): %v", err)
	}
	byThirdParty, err := gateway.VerifyEgressAttestation(obj, cose.ProfilePublic, gwV)
	if err != nil {
		t.Fatalf("VerifyEgressAttestation (re-served by a third party): %v", err)
	}
	if byGateway.Binding != byThirdParty.Binding ||
		!bytes.Equal(byGateway.Digest, byThirdParty.Digest) ||
		byGateway.Effect != byThirdParty.Effect ||
		!bytes.Equal(byGateway.Audience, byThirdParty.Audience) ||
		byGateway.At != byThirdParty.At {
		t.Fatal("the re-served attestation resolved differently from the gateway-served attestation")
	}
	if byThirdParty.Binding != gateway.BindingContentBound {
		t.Fatalf("resolved binding %d, want content_bound", byThirdParty.Binding)
	}
	if got := hex.EncodeToString(byThirdParty.Digest); got != v.ObjectCIDHex {
		t.Fatalf("resolved digest %s != oracle object cid %s", got, v.ObjectCIDHex)
	}

	if _, err := gateway.VerifyEgressAttestation(obj, cose.ProfilePublic, foreignV); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key verify got %v, want BadSignature", err)
	}
	bad := gateway.EgressAttestation{Binding: v.UnknownBinding, Digest: hb(t, v.ObjectCIDHex), Effect: 0, Audience: hb(t, v.AudienceHex), At: 0}
	badObj, _ := gateway.SignEgressAttestation(bad, gwS)
	if _, err := gateway.VerifyEgressAttestation(badObj, cose.ProfilePublic, gwV); err != gateway.ErrUnknownEgressBinding {
		t.Fatalf("unknown-binding verify got %v, want UnknownEgressBinding", err)
	}
}

// TestEgressVendorOnlyMutation mirrors TestGatewayVendorOnlyMutation: the honest VerifyEgressAttestation
// takes NO serving-party identity, so a mutant "vendor-only" verifier that additionally requires
// servingParty == gatewayID wrongly rejects a third party re-serving the identical bytes.
func TestEgressVendorOnlyMutation(t *testing.T) {
	v := loadEgressVec(t)
	gwS, gwV, gatewayID := key(t, 0x61)
	thirdParty := []byte("did:example:mirror-cache")

	a := attFrom(t, v.Attestations.ContentFree)
	obj, err := gateway.SignEgressAttestation(a, gwS)
	if err != nil {
		t.Fatalf("SignEgressAttestation: %v", err)
	}

	if _, err := gateway.VerifyEgressAttestation(obj, cose.ProfilePublic, gwV); err != nil {
		t.Fatalf("honest re-serve got %v, want success", err)
	}

	mutantVerify := func(obj []byte, gatewayV cose.Verifier, gatewayID, servingParty []byte) error {
		if _, err := gateway.VerifyEgressAttestation(obj, cose.ProfilePublic, gatewayV); err != nil {
			return err
		}
		if !bytes.Equal(servingParty, gatewayID) {
			return gateway.ErrEgressMalformed // stands in for a "not served by the vendor" rejection
		}
		return nil
	}
	if err := mutantVerify(obj, gwV, gatewayID, gatewayID); err != nil {
		t.Fatalf("mutant vendor-served got %v, want success", err)
	}
	if err := mutantVerify(obj, gwV, gatewayID, thirdParty); err == nil {
		t.Fatal("mutant vendor-only verifier accepted a third-party re-serve: the re-serve bug must reproduce")
	}
}

// TestOpenEgressCommitment is the A7 opening-side checkpoint this brief specifically calls out: a
// content_free attestation's digest is a hiding commitment SHA-384(object_cid||salt); the CORRECT
// (object_cid, salt) pair opens it, and a WRONG salt or a WRONG object_cid must both fail to open.
// Mutation: make OpenEgressCommitment ignore salt/objectCID (or always return true) and this flips.
func TestOpenEgressCommitment(t *testing.T) {
	v := loadEgressVec(t)
	co := v.CommitmentOpen
	a := attFrom(t, v.Attestations.ContentFree)
	if hex.EncodeToString(a.Digest) != co.CommitmentHex {
		t.Fatalf("content_free digest %s != oracle commitment %s", hex.EncodeToString(a.Digest), co.CommitmentHex)
	}

	objectCID := hb(t, co.ObjectCIDHex)
	wrongObjectCID := hb(t, co.WrongObjectCIDHex)
	salt := hb(t, co.SaltHex)
	wrongSalt := hb(t, co.WrongSaltHex)

	if got := hex.EncodeToString(gateway.EgressCommit(objectCID, salt)); got != co.CommitmentHex {
		t.Fatalf("EgressCommit(object_cid, salt) = %s, want oracle commitment %s", got, co.CommitmentHex)
	}
	if !gateway.OpenEgressCommitment(a, objectCID, salt) {
		t.Fatal("OpenEgressCommitment(correct object_cid, correct salt) = false, want true")
	}
	if gateway.OpenEgressCommitment(a, objectCID, wrongSalt) {
		t.Fatal("OpenEgressCommitment(correct object_cid, WRONG salt) = true, want false")
	}
	if gateway.OpenEgressCommitment(a, wrongObjectCID, salt) {
		t.Fatal("OpenEgressCommitment(WRONG object_cid, correct salt) = true, want false")
	}
	if gateway.OpenEgressCommitment(a, wrongObjectCID, wrongSalt) {
		t.Fatal("OpenEgressCommitment(WRONG object_cid, WRONG salt) = true, want false")
	}
	// A content_bound attestation never opens (its Digest is not a commitment).
	bound := attFrom(t, v.Attestations.ContentBound)
	if gateway.OpenEgressCommitment(bound, objectCID, salt) {
		t.Fatal("OpenEgressCommitment on a content_bound attestation = true, want false (not a commitment)")
	}
}

// crossLangPinnedSignedEgressAttestationSHA384 is the pinned SHA-384 of the deterministic
// COSE_Sign1 object obtained by signing the content_free egress-attestation body with the shared
// all-0x11 32-byte ML-DSA-65 seed, mirroring gateway_test.go's crossLangPinnedSignedDecisionSHA384.
// Go and Rust both pin it, proving the two independent ML-DSA stacks emit byte-identical signed
// egress-attestation objects for identical canonical CBOR + seed.
const crossLangPinnedSignedEgressAttestationSHA384 = "d811b056d7a9710ab7049ff34b43628d5b6c9abb2e31bb24b486e9cb42ad853d4b78dc4f359e9b724efdad3eb6fe625a"

func TestCrossLangSignedEgressAttestationPin(t *testing.T) {
	v := loadEgressVec(t)
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 0x11
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	s := cose.MLDSA65Signer{SK: sk}
	a := attFrom(t, v.Attestations.ContentFree)
	obj, err := gateway.SignEgressAttestation(a, s)
	if err != nil {
		t.Fatalf("SignEgressAttestation: %v", err)
	}
	dg := sha512.Sum384(obj)
	got := hex.EncodeToString(dg[:])
	t.Logf("CROSS-LANG signed egress-attestation SHA-384 (seed=0x11*32): %s", got)
	if crossLangPinnedSignedEgressAttestationSHA384 != "PIN_ME" && got != crossLangPinnedSignedEgressAttestationSHA384 {
		t.Fatalf("cross-lang signed-attestation digest %s != pinned %s", got, crossLangPinnedSignedEgressAttestationSHA384)
	}
}

// ---- standard wire-format edge cases (Part 1) --------------------------------------------

// TestEgKeysOutOfOrderRejected is edge case #1: an attestation body with top-level keys in
// DESCENDING order (5,4,3,2,1) is rejected NonCanonical by the strict shared decoder
// ParseEgressAttestation routes through (RFC 8949 §4.2.1).
func TestEgKeysOutOfOrderRejected(t *testing.T) {
	v := loadEgressVec(t)
	e := v.EdgeCases.KeysOutOfOrder
	a := gateway.EgressAttestation{Binding: e.Binding, Digest: hb(t, e.DigestHex), Effect: e.Effect, Audience: hb(t, e.AudienceHex), At: atU64(t, e.AtStr)}
	if got := hex.EncodeToString(a.Bytes()); got != e.CanonicalBodyHex {
		t.Fatalf("canonical attestation body\n got %s\nwant %s", got, e.CanonicalBodyHex)
	}
	canon := hb(t, e.CanonicalBodyHex)
	noncanon := hb(t, e.NoncanonicalBodyHex)
	if _, err := cbor.Decode(canon); err != nil {
		t.Fatalf("canonical body should decode: %v", err)
	}
	if _, err := gateway.ParseEgressAttestation(canon); err != nil {
		t.Fatalf("canonical body should parse: %v", err)
	}
	if _, err := cbor.Decode(noncanon); err == nil {
		t.Fatal("descending-key attestation body decoded (want NonCanonical)")
	} else if ce, ok := err.(*cbor.Error); !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("descending-key body got %v, want NonCanonical", err)
	}
	if _, err := gateway.ParseEgressAttestation(noncanon); err != gateway.ErrEgressMalformed {
		t.Fatalf("ParseEgressAttestation(noncanon) got %v, want EgMalformed", err)
	}
}

// TestEgEmptyVsAbsentAudience is edge case #2 for the audience field (field 4, empty-permitted): an
// empty audience is PRESENT and valid and DISTINCT by content-id from a populated one, and BOTH
// differ from a body whose audience field is ABSENT — rejected EgMalformed (field 4 is mandatory).
func TestEgEmptyVsAbsentAudience(t *testing.T) {
	v := loadEgressVec(t)
	ea := v.EdgeCases.EmptyVsAbsent
	empty := gateway.EgressAttestation{Binding: gateway.BindingContentBound, Digest: hb(t, v.ObjectCIDHex), Effect: 1, Audience: []byte{}, At: 1735689600000}
	populated := gateway.EgressAttestation{Binding: gateway.BindingContentBound, Digest: hb(t, v.ObjectCIDHex), Effect: 1, Audience: hb(t, ea.PopulatedAudience.AudienceHex), At: 1735689600000}
	if got := hex.EncodeToString(empty.Bytes()); got != ea.EmptyAudience.BodyHex {
		t.Fatalf("empty-audience body\n got %s\nwant %s", got, ea.EmptyAudience.BodyHex)
	}
	if got := hex.EncodeToString(populated.Bytes()); got != ea.PopulatedAudience.BodyHex {
		t.Fatalf("populated-audience body\n got %s\nwant %s", got, ea.PopulatedAudience.BodyHex)
	}
	if hex.EncodeToString(empty.ID()) == hex.EncodeToString(populated.ID()) {
		t.Fatal("empty and populated audience attestations must have distinct content-ids")
	}
	if hex.EncodeToString(empty.ID()) != ea.EmptyAudience.IDHex {
		t.Fatalf("empty-audience id diverges from the oracle")
	}
	if _, err := gateway.ParseEgressAttestation(empty.Bytes()); err != nil {
		t.Fatalf("ParseEgressAttestation(empty audience): %v", err)
	}
	if _, err := gateway.ParseEgressAttestation(populated.Bytes()); err != nil {
		t.Fatalf("ParseEgressAttestation(populated audience): %v", err)
	}
	if _, err := gateway.ParseEgressAttestation(hb(t, ea.AbsentField.BodyHex)); err != gateway.ErrEgressMalformed {
		t.Fatalf("absent audience field got %v, want EgMalformed", err)
	}
}

// TestEgMinimal is edge case #4: the smallest valid attestation (content_bound, empty digest, empty
// audience, read_only, at=0) encodes to the oracle bytes, has a stable content-id, round-trips
// through ParseEgressAttestation, and verifies end-to-end.
func TestEgMinimal(t *testing.T) {
	v := loadEgressVec(t)
	m := v.EdgeCases.Minimal
	a := gateway.EgressAttestation{Binding: m.Binding, Digest: hb(t, m.DigestHex), Effect: m.Effect, Audience: hb(t, m.AudienceHex), At: atU64(t, m.AtStr)}
	if got := hex.EncodeToString(a.Bytes()); got != m.BodyHex {
		t.Fatalf("minimal attestation body\n got %s\nwant %s", got, m.BodyHex)
	}
	if got := hex.EncodeToString(a.ID()); got != m.IDHex {
		t.Fatalf("minimal attestation id got %s want %s", got, m.IDHex)
	}
	if _, err := gateway.ParseEgressAttestation(a.Bytes()); err != nil {
		t.Fatalf("ParseEgressAttestation(minimal): %v", err)
	}
	gwS, gwV, _ := key(t, 0x63)
	obj, err := gateway.SignEgressAttestation(a, gwS)
	if err != nil {
		t.Fatalf("SignEgressAttestation(minimal): %v", err)
	}
	if _, err := gateway.VerifyEgressAttestation(obj, cose.ProfilePublic, gwV); err != nil {
		t.Fatalf("VerifyEgressAttestation(minimal): %v", err)
	}
}

// TestEgLookAlikeRejected is edge case #5: naalp-egress-attestation is a near-clone of the SIBLING
// C21 body naalp-gateway-decision {1:uint,2:bstr,3:bstr,4:uint} — four fields, no field 5 — fed to
// ParseEgressAttestation, which requires five mandatory fields. Rejected EgMalformed.
func TestEgLookAlikeRejected(t *testing.T) {
	v := loadEgressVec(t)
	if _, err := gateway.ParseEgressAttestation(hb(t, v.EdgeCases.LookAlike.BodyHex)); err != gateway.ErrEgressMalformed {
		t.Fatalf("gateway-decision look-alike got %v, want EgMalformed", err)
	}
}

// TestEgressOrderingByteParity proves Go's field-6 (ordering) encoding matches the oracle's
// attestations_with_ordering{} corpus byte-for-byte, that the shared ordering-basis vocabulary is
// registered, and that an ABSENT field 6 (the plain attestations{} cases) round-trips with
// Ordering == nil (never a synthesized correspondence-only value at the Go struct level, though
// both read identically once decoded).
func TestEgressOrderingByteParity(t *testing.T) {
	v := loadEgressVec(t)
	for _, e := range v.OrderingBasisVocabulary {
		if !gateway.IsKnownOrderingBasis(e.Code) || gateway.OrderingBasisName(e.Code) != e.Name {
			t.Fatalf("ordering-basis %q (code %d) not registered as %q", e.Name, e.Code, gateway.OrderingBasisName(e.Code))
		}
	}

	build := func(name string, av egressAttVec) gateway.EgressAttestation {
		a := attFrom(t, av)
		switch name {
		case "correspondence_only":
			o := gateway.CorrespondenceOnly()
			a.Ordering = &o
		case "single_boundary":
			o := gateway.OrderingDisclosure{Basis: gateway.OrderingSingleBoundary, Boundary: []byte("boundary-signer-X")}
			a.Ordering = &o
		case "external_mechanism":
			o := gateway.OrderingDisclosure{
				Basis:     gateway.OrderingExternalMechanism,
				Mechanism: []byte("external-log:acme-transparency-v1"),
				Relation:  hb(t, "2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56"),
			}
			a.Ordering = &o
		default:
			t.Fatalf("unhandled attestations_with_ordering name %q — add its ordering fixture above", name)
		}
		return a
	}

	for name, av := range v.AttestationsWithOrdering {
		a := build(name, av)
		if got := hex.EncodeToString(a.Bytes()); got != av.BodyHex {
			t.Fatalf("%s Bytes\n got %s\nwant %s", name, got, av.BodyHex)
		}
		if got := hex.EncodeToString(a.Head()); got != av.HeadHex {
			t.Fatalf("%s Head got %s want %s", name, got, av.HeadHex)
		}
		if got := hex.EncodeToString(a.ID()); got != av.IDHex {
			t.Fatalf("%s ID got %s want %s", name, got, av.IDHex)
		}
		parsed, err := gateway.ParseEgressAttestation(a.Bytes())
		if err != nil {
			t.Fatalf("%s ParseEgressAttestation: %v", name, err)
		}
		if parsed.Ordering == nil {
			t.Fatalf("%s: parsed Ordering is nil, want present", name)
		}
		if got := hex.EncodeToString(parsed.Bytes()); got != av.BodyHex {
			t.Fatalf("%s round-trip Bytes\n got %s\nwant %s", name, got, av.BodyHex)
		}
		if err := gateway.ValidateEgressAttestation(parsed); err != nil {
			t.Fatalf("%s ValidateEgressAttestation: %v, want nil", name, err)
		}
	}

	// An attestation with NO field 6 parses to Ordering == nil (absent, not a synthesized value).
	plain, err := gateway.ParseEgressAttestation(attFrom(t, v.Attestations.ContentBound).Bytes())
	if err != nil {
		t.Fatalf("ParseEgressAttestation(no ordering): %v", err)
	}
	if plain.Ordering != nil {
		t.Fatal("attestation with no field 6 parsed with a non-nil Ordering (should be absent, nil)")
	}
}

// TestEgressOrderingNegative exercises the two named field-6 rejections: single-boundary carrying a
// mechanism (OrderingDisclosureMalformed) and an out-of-set basis value (UnknownOrderingBasis).
func TestEgressOrderingNegative(t *testing.T) {
	v := loadEgressVec(t)

	kindOf := func(t *testing.T, bodyHex string) string {
		t.Helper()
		a, err := gateway.ParseEgressAttestation(hb(t, bodyHex))
		if err != nil {
			ce, ok := err.(*cose.Error)
			if !ok {
				t.Fatalf("ParseEgressAttestation returned non-*cose.Error: %v", err)
			}
			return ce.Kind
		}
		if err := gateway.ValidateEgressAttestation(a); err != nil {
			ce, ok := err.(*cose.Error)
			if !ok {
				t.Fatalf("ValidateEgressAttestation returned non-*cose.Error: %v", err)
			}
			return ce.Kind
		}
		return ""
	}

	sbwm := v.NegativeOrdering.OrderingMalformedSingleBoundaryWithMechanism
	if got := kindOf(t, sbwm.BodyHex); got != sbwm.Reject {
		t.Fatalf("single_boundary_with_mechanism: got %q, want %q", got, sbwm.Reject)
	}
	uob := v.NegativeOrdering.UnknownOrderingBasis
	if got := kindOf(t, uob.BodyHex); got != uob.Reject {
		t.Fatalf("unknown_ordering_basis: got %q, want %q", got, uob.Reject)
	}
}

// TestEgMissingAtFieldRejected exercises the field-5 (`at`) mandatory check IN ISOLATION: a body
// whose fields 1-4 all carry the CORRECT types but which omits field 5 must be rejected
// EgMalformed. The C21 gateway-decision look-alike (TestEgLookAlikeRejected) is caught earlier by
// its field-3 type mismatch (bstr vs the uint effect), so only this case isolates the at-mandatory
// rule: dropping the `!ok5` guard in ParseEgressAttestation flips exactly this test and no other.
func TestEgMissingAtFieldRejected(t *testing.T) {
	body, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(gateway.BindingContentBound)},
		{K: cbor.Uint(2), V: cbor.Bstr([]byte{0x20, 0x30})},
		{K: cbor.Uint(3), V: cbor.Uint(1)},
		{K: cbor.Uint(4), V: cbor.Bstr(nil)},
	})
	if _, err := gateway.ParseEgressAttestation(body); err != gateway.ErrEgressMalformed {
		t.Fatalf("body missing field 5 (at) got %v, want EgMalformed", err)
	}
}
