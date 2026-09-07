// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package mixedmode

import (
	"strings"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Workflow/TaskCreate (channels.Table, channel 0x0011 kind 0) -- a real registered
// baseline surface, reused exactly as the sibling react package's tests do.
const (
	testChannel = 0x0011
	testKind    = 0
)

type party struct {
	sk *mldsa65.PrivateKey
	pk *mldsa65.PublicKey
	id string
}

func newParty(t *testing.T, seedByte byte) party {
	t.Helper()
	var seed [32]byte
	for i := range seed {
		seed[i] = seedByte
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	sid, err := identity.SignerID(cose.AlgMLDSA65, pk.Bytes())
	if err != nil {
		t.Fatalf("SignerID: %v", err)
	}
	return party{sk: sk, pk: pk, id: sid}
}

// signStrictObject builds and signs a real N-AALP object, the exact bytes a strict
// caller would POST to a mixed-mode endpoint.
func signStrictObject(t *testing.T, signer party, effect policy.Effect) []byte {
	t.Helper()
	obj := &envelope.Object{
		Kind: testKind, Channel: testChannel, Signer: []byte(signer.id),
		Created: 1785000000000, Effect: uint64(effect),
		Body:    cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("hello")}},
		Profile: cose.ProfilePublic,
	}
	signed, err := envelope.Sign(obj, cose.MLDSA65Signer{SK: signer.sk})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func newTestEndpoint(responder party, allowLegacy bool) *Endpoint {
	return &Endpoint{
		Profile:       cose.ProfilePublic,
		Verifier:      cose.MLDSA65Verifier{PK: responder.pk},
		KindValidator: channels.KindValidator,
		AllowLegacy:   allowLegacy,
	}
}

// legacyJSONBody is a plausible NPAMP-CC-HTTP legacy body -- crucially it CLAIMS a
// destructive effect and an admin audience inside its own (unsigned) JSON. Every
// legacy-path test below proves this claim is never consulted.
var legacyJSONBody = []byte(`{"jsonrpc":"1.0","method":"do_thing","params":{"effect":3,"audience":"admin"}}`)

func TestHandle_StrictObjectVerifies_TaggedStrictOrigin(t *testing.T) {
	signer := newParty(t, 0x11)
	e := newTestEndpoint(signer, false)
	signed := signStrictObject(t, signer, policy.NonIdempotentWrite)

	rec, err := e.Handle(signed)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if rec.Origin != OriginStrict {
		t.Fatalf("expected OriginStrict, got %s", rec.Origin)
	}
	if rec.Object == nil {
		t.Fatal("expected a non-nil verified Object for a strict record")
	}
	if string(rec.Object.Signer) != signer.id {
		t.Fatalf("verified object signer = %q, want %q", rec.Object.Signer, signer.id)
	}
}

func TestHandle_LegacyJSON_AllowLegacyTrue_TaggedLegacyOrigin_WrapsForeignVerbatim(t *testing.T) {
	signer := newParty(t, 0x12)
	e := newTestEndpoint(signer, true)

	rec, err := e.Handle(legacyJSONBody)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if rec.Origin != OriginLegacy {
		t.Fatalf("expected OriginLegacy, got %s", rec.Origin)
	}
	if rec.Object != nil {
		t.Fatal("expected a nil Object for a legacy record")
	}
	if rec.Carriage.Class != 1 { // carriage.ClassHTTP
		t.Fatalf("expected carriage class HTTP(1), got %d", rec.Carriage.Class)
	}
	if rec.Carriage.ContentType != ContentTypeJSON {
		t.Fatalf("expected content_type json(0), got %d", rec.Carriage.ContentType)
	}
	if string(rec.Carriage.Foreign) != string(legacyJSONBody) {
		t.Fatalf("legacy body was not carried verbatim: got %q", rec.Carriage.Foreign)
	}
}

// TestHandle_LegacyJSON_AllowLegacyFalse_RefusedLegacyDisabled proves AC4: strict is
// the default, and a strict-parse failure is refused outright -- never silently
// retried as legacy -- unless a caller explicitly opts in.
func TestHandle_LegacyJSON_AllowLegacyFalse_RefusedLegacyDisabled(t *testing.T) {
	signer := newParty(t, 0x13)
	e := newTestEndpoint(signer, false) // zero-value default: AllowLegacy=false

	_, err := e.Handle(legacyJSONBody)
	if err == nil {
		t.Fatal("expected ErrLegacyDisabled, got nil")
	}
	me, ok := err.(*Error)
	if !ok || me.Kind != "LegacyDisabled" {
		t.Fatalf("expected *Error{Kind: LegacyDisabled}, got %#v", err)
	}
}

func TestAuthorize_StrictRecord_DelegatesToRealGrant(t *testing.T) {
	signer := newParty(t, 0x14)
	e := newTestEndpoint(signer, false)
	signed := signStrictObject(t, signer, policy.NonIdempotentWrite)
	rec, err := e.Handle(signed)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	// A grant for a DIFFERENT principal must deny, even though the effect requested
	// is within that (irrelevant) grant's ceiling -- proves Authorize really calls
	// the real Part-1 Grant.AuthorizeObject (principal binding included), not a
	// bespoke check of its own.
	wrongGrant := policy.Grant{Principal: "someone-else", MaxEffect: policy.Destructive}
	if err := e.Authorize(rec, wrongGrant, policy.NonIdempotentWrite); err == nil {
		t.Fatal("expected denial: grant belongs to a different principal")
	}

	// The real, matching grant, ceiling high enough: authorized.
	rightGrant := policy.Grant{Principal: signer.id, MaxEffect: policy.NonIdempotentWrite}
	if err := e.Authorize(rec, rightGrant, policy.NonIdempotentWrite); err != nil {
		t.Fatalf("expected authorization to succeed, got %v", err)
	}

	// The matching grant but too low a ceiling for the requested effect: denied.
	lowGrant := policy.Grant{Principal: signer.id, MaxEffect: policy.ReadOnly}
	if err := e.Authorize(rec, lowGrant, policy.NonIdempotentWrite); err == nil {
		t.Fatal("expected denial: requested effect exceeds the grant's ceiling")
	}
}

// TestAuthorize_LegacyRecord_CappedAtReadOnly_RegardlessOfGrantOrForeignClaim is this
// package's CRITICAL AUTHZ test (design.md Sec.13.8(b), D15). It hands Authorize the
// most permissive Grant representable (Destructive ceiling, and a Principal chosen to
// equal what an attacker might hope a naive implementation derives from the legacy
// JSON's own claims) and a legacy record whose foreign JSON body explicitly claims
// effect=3 (destructive) and audience="admin". Every requested effect above read_only
// MUST still be refused -- proving the legacy path gains no authority no matter what
// the (unsigned, unverified) legacy body claims and no matter how permissive the
// caller-supplied Grant is.
func TestAuthorize_LegacyRecord_CappedAtReadOnly_RegardlessOfGrantOrForeignClaim(t *testing.T) {
	signer := newParty(t, 0x15)
	e := newTestEndpoint(signer, true)
	rec, err := e.Handle(legacyJSONBody) // claims effect=3, audience=admin, internally
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if rec.Origin != OriginLegacy {
		t.Fatalf("expected OriginLegacy, got %s", rec.Origin)
	}
	if !strings.Contains(string(rec.Carriage.Foreign), `"effect":3`) {
		t.Fatal("test fixture sanity: legacy body must claim a destructive effect")
	}

	mostPermissiveGrant := policy.Grant{Principal: "admin", MaxEffect: policy.Destructive}

	for _, eff := range []policy.Effect{policy.IdempotentWrite, policy.NonIdempotentWrite, policy.Destructive} {
		if err := e.Authorize(rec, mostPermissiveGrant, eff); err == nil {
			t.Fatalf("effect %d: expected ErrLegacyEffectNotAuthorized, got nil authorization", eff)
		} else if me, ok := err.(*Error); !ok || me.Kind != "LegacyEffectNotAuthorized" {
			t.Fatalf("effect %d: expected *Error{Kind: LegacyEffectNotAuthorized}, got %#v", eff, err)
		}
	}

	// read_only-equivalent IS still allowed for a legacy record (AC1: "read-only-
	// equivalent unless upgraded"), and this allow path also never consults the Grant
	// or the foreign body -- it succeeds even under a Grant naming a principal that
	// does not exist anywhere in this test ("nobody").
	nobodyGrant := policy.Grant{Principal: "nobody", MaxEffect: policy.ReadOnly}
	if err := e.Authorize(rec, nobodyGrant, policy.ReadOnly); err != nil {
		t.Fatalf("expected read_only to be authorized for a legacy record, got %v", err)
	}
}

// consumeOnceChannel/consumeOnceKind is a second registered baseline surface, distinct
// from testChannel/testKind, dedicated to the Sec.2.5.3 consume-once tests below so
// they cannot be satisfied by accident by the non-consume-once fixtures above.
const (
	consumeOnceChannel = 0x0011
	consumeOnceKind    = 1 // Workflow/TaskInput (channels.Table) -- a distinct registered kind
)

// signStrictObjectWithAudience is signStrictObject plus an explicit Audience (field 13,
// Sec.2.5.3), targeting the dedicated consume-once (channel,kind) above.
func signStrictObjectWithAudience(t *testing.T, signer party, effect policy.Effect, audience string) []byte {
	t.Helper()
	obj := &envelope.Object{
		Kind: consumeOnceKind, Channel: consumeOnceChannel, Signer: []byte(signer.id),
		Created: 1785000000000, Effect: uint64(effect),
		Body:     cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("hello")}},
		Profile:  cose.ProfilePublic,
		Audience: audience,
	}
	signed, err := envelope.Sign(obj, cose.MLDSA65Signer{SK: signer.sk})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func newConsumeOnceEndpoint(responder party, allowLegacy bool, selfAuthority string) *Endpoint {
	e := newTestEndpoint(responder, allowLegacy)
	e.SelfAuthority = selfAuthority
	e.ConsumeOnceKinds = map[ConsumeOnceKey]bool{
		{Channel: consumeOnceChannel, Kind: consumeOnceKind}: true,
	}
	return e
}

// TestAuthorize_StrictRecord_ConsumeOnceKind_WrongOrAbsentAudienceRefused is this
// package's Fable-parity-closing test: a strict-origin record targeting a registered
// ConsumeOnceKinds pair MUST additionally pass envelope.CheckAudience (design.md
// Sec.2.5.3) -- both an absent audience and one naming a DIFFERENT authority than
// e.SelfAuthority MUST be refused, even though the object's signature verifies and its
// effect is fully within the grant's ceiling (proving the new check is a genuinely
// ADDITIONAL gate, not a substitute for the existing two).
func TestAuthorize_StrictRecord_ConsumeOnceKind_WrongOrAbsentAudienceRefused(t *testing.T) {
	signer := newParty(t, 0x16)
	e := newConsumeOnceEndpoint(signer, false, "consuming-authority-X")
	grant := policy.Grant{Principal: signer.id, MaxEffect: policy.Destructive}

	cases := []struct {
		name     string
		audience string
	}{
		{"absent", ""},
		{"wrong-authority", "consuming-authority-Y"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signed := signStrictObjectWithAudience(t, signer, policy.NonIdempotentWrite, tc.audience)
			rec, err := e.Handle(signed)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			err = e.Authorize(rec, grant, policy.NonIdempotentWrite)
			if err == nil {
				t.Fatal("expected the consume-once audience gate to refuse, got nil authorization")
			}
			ce, ok := err.(*cose.Error)
			if !ok || ce.Kind != "WrongAudience" {
				t.Fatalf("expected *cose.Error{Kind: WrongAudience}, got %#v", err)
			}
		})
	}
}

// TestAuthorize_StrictRecord_ConsumeOnceKind_MatchingAudienceAuthorized proves the new
// gate is not a blanket refusal: a strict-origin record naming e.SelfAuthority as its
// audience, on a registered consume-once (channel,kind), is authorized exactly like any
// other properly-authorized strict record.
func TestAuthorize_StrictRecord_ConsumeOnceKind_MatchingAudienceAuthorized(t *testing.T) {
	signer := newParty(t, 0x17)
	e := newConsumeOnceEndpoint(signer, false, "consuming-authority-X")
	grant := policy.Grant{Principal: signer.id, MaxEffect: policy.Destructive}

	signed := signStrictObjectWithAudience(t, signer, policy.NonIdempotentWrite, "consuming-authority-X")
	rec, err := e.Handle(signed)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if err := e.Authorize(rec, grant, policy.NonIdempotentWrite); err != nil {
		t.Fatalf("expected a matching-audience consume-once record to be authorized, got %v", err)
	}
}

// TestAuthorize_StrictRecord_NonConsumeOnceKind_AudienceNeverChecked proves the new
// gate is scoped to ConsumeOnceKinds ONLY: a strict record on the ordinary testChannel/
// testKind pair (never registered as consume-once) is authorized regardless of its
// (absent) audience -- the pre-existing non-consume-once behavior is unchanged.
func TestAuthorize_StrictRecord_NonConsumeOnceKind_AudienceNeverChecked(t *testing.T) {
	signer := newParty(t, 0x18)
	e := newConsumeOnceEndpoint(signer, false, "consuming-authority-X")
	grant := policy.Grant{Principal: signer.id, MaxEffect: policy.NonIdempotentWrite}

	signed := signStrictObject(t, signer, policy.NonIdempotentWrite) // testChannel/testKind, no Audience
	rec, err := e.Handle(signed)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if err := e.Authorize(rec, grant, policy.NonIdempotentWrite); err != nil {
		t.Fatalf("expected a non-consume-once record to be authorized regardless of audience, got %v", err)
	}
}

// TestAuthorize_LegacyRecord_ConsumeOnceKind_AlwaysRefused_RegardlessOfClaimedAudience
// is the legacy-leg half of the Fable-parity fix (mirrors the Python
// _handle_legacy surrogate): a legacy record whose (unsigned) foreign JSON body
// explicitly claims an audience equal to e.SelfAuthority MUST STILL be refused when
// the caller names a registered ConsumeOnceKinds target via Authorize's legacyTarget
// argument -- an unsigned legacy record can never present a real audience, so the
// claim inside its own body is never consulted (D15's anti-bypass rule, extended).
func TestAuthorize_LegacyRecord_ConsumeOnceKind_AlwaysRefused_RegardlessOfClaimedAudience(t *testing.T) {
	signer := newParty(t, 0x19)
	e := newConsumeOnceEndpoint(signer, true, "consuming-authority-X")

	legacyBodyClaimingOurAudience := []byte(
		`{"jsonrpc":"1.0","method":"do_thing","params":{"effect":0,"audience":"consuming-authority-X"}}`,
	)
	rec, err := e.Handle(legacyBodyClaimingOurAudience)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if rec.Origin != OriginLegacy {
		t.Fatalf("expected OriginLegacy, got %s", rec.Origin)
	}

	target := ConsumeOnceKey{Channel: consumeOnceChannel, Kind: consumeOnceKind}
	nobodyGrant := policy.Grant{Principal: "nobody", MaxEffect: policy.ReadOnly}
	err = e.Authorize(rec, nobodyGrant, policy.ReadOnly, target)
	if err == nil {
		t.Fatal("expected the legacy consume-once refusal, got nil authorization")
	}
	ce, ok := err.(*cose.Error)
	if !ok || ce.Kind != "WrongAudience" {
		t.Fatalf("expected *cose.Error{Kind: WrongAudience}, got %#v", err)
	}
}

// TestAuthorize_LegacyRecord_NoLegacyTargetNamed_PreExistingBehaviorUnchanged proves
// backward compatibility: a caller that omits the new legacyTarget argument entirely
// (every pre-existing call site in this file) gets EXACTLY the pre-parity-fix D15
// behavior -- read_only is authorized, nothing about the new consume-once gate fires.
func TestAuthorize_LegacyRecord_NoLegacyTargetNamed_PreExistingBehaviorUnchanged(t *testing.T) {
	signer := newParty(t, 0x1a)
	e := newConsumeOnceEndpoint(signer, true, "consuming-authority-X")

	rec, err := e.Handle(legacyJSONBody)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	nobodyGrant := policy.Grant{Principal: "nobody", MaxEffect: policy.ReadOnly}
	if err := e.Authorize(rec, nobodyGrant, policy.ReadOnly); err != nil {
		t.Fatalf("expected read_only to be authorized with no legacyTarget named, got %v", err)
	}
}
