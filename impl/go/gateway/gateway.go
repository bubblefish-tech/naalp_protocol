// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package gateway implements C21 task 5B.3 — the portable gateway decision object (design.md §24;
// requirements R-GW-1..6).
//
// A GatewayDecision is a SIGNED decision object an enforcement gateway of ANY vendor emits as PORTABLE
// EVIDENCE that it decided about an action. Its load-bearing property, exactly as the C18 signed
// description (§21), is that authority lives in the SIGNED BYTES, never in the connection or the host
// that served them: VerifyDecision takes NO serving-party/connection identity, so the same signed
// decision RE-VERIFIES IDENTICALLY when a party OTHER than the gateway serves it (the third-party
// re-serve property). It introduces NO new envelope, encoding, signature, identity, or audit mechanism
// (R-11.3): the object is an ordinary signed N-AALP body (COSE_Sign1, §4), reusing the closed C5
// effect lattice (policy) and the T1 content-id framing (§2.3) unchanged.
//
// This defines the EVIDENCE FORMAT ONLY — never a policy language:
//
//   - GatewayDecision {1: decision, 2: action, 3: policy, 4: effect}. `decision` is a closed set
//     (allow / deny / hold); `action` is the T1 content id of the action decided about; `policy` is
//     the opaque identity of the deciding policy (a name, NOT a policy program); `effect` is the C5
//     effect class of the action. The gateway is the SIGNER; a verifier resolves its key offline from
//     the self-certifying signer id and checks the signature over the bytes.
//
// Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
// causes no state change.
package gateway

import (
	"crypto/sha512"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// HeadSize is the width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit
// chain (audit.HeadSize).
const HeadSize = 48

// Decision codes — the closed set a gateway may emit. A code outside the set is rejected
// (UnknownGatewayDecision).
const (
	DecisionAllow uint64 = 0 // the gateway allows the action
	DecisionDeny  uint64 = 1 // the gateway denies the action
	DecisionHold  uint64 = 2 // the gateway holds the action pending a further step
)

// decisionName maps a decision code to its name (diagnostics); an unknown code returns "".
var decisionName = map[uint64]string{DecisionAllow: "allow", DecisionDeny: "deny", DecisionHold: "hold"}

// IsKnownDecision reports whether code is one of the closed decision codes.
func IsKnownDecision(code uint64) bool { _, ok := decisionName[code]; return ok }

// DecisionName returns the decision name, or "unknown".
func DecisionName(code uint64) string {
	if n, ok := decisionName[code]; ok {
		return n
	}
	return "unknown"
}

// Named, fail-closed errors. A failing object is rejected whole and causes no state change (§15).
// A bad signature is the EXISTING cose.ErrBadSignature reused unchanged.
var (
	ErrMalformed       = &cose.Error{Kind: "GwMalformed", Msg: "object is not a well-formed N-AALP gateway-decision body"}
	ErrUnknownDecision = &cose.Error{Kind: "UnknownGatewayDecision", Msg: "gateway decision code is outside the closed set allow/deny/hold"}

	// ErrForeignProfileMalformed is the named error for field 6 (naalp-foreign-profile-pin, R8):
	// registered as code 129 in the FROZEN CDDL naalp-error-code enum.
	ErrForeignProfileMalformed = &cose.Error{Kind: "ForeignProfileMalformed", Msg: "foreign-profile-pin is not well-formed (id and revision are mandatory tstr, no other keys)"}
)

// contentID is the T1 framing multihash(0x20, SHA-384(b)) = 0x20 0x30 || SHA-384(b) (50 octets).
func contentID(b []byte) []byte {
	d := sha512.Sum384(b)
	out := make([]byte, 0, 2+len(d))
	out = append(out, 0x20, 0x30)
	return append(out, d[:]...)
}

// head is SHA-384 over a body — a 48-octet digest.
func head(b []byte) []byte {
	d := sha512.Sum384(b)
	return d[:]
}

// ---- GatewayDecision: the portable evidence object (design.md §24) ----------------------------

// GatewayDecision is a signed decision an enforcement gateway emits as portable evidence. Decision is
// the closed-set outcome; Action is the content id of the action decided about; Policy is the opaque
// deciding-policy identity (a name, not a program); Effect is the action's C5 effect class. Ordering
// (field 5, R1) and ForeignProfile (field 6, R8) are OPTIONAL: nil reads exactly as an absent field
// (correspondence-only ordering / no foreign-profile pin) — never a stronger claim inferred from
// silence.
type GatewayDecision struct {
	Decision uint64 // allow / deny / hold (closed set)
	Action   []byte // content id of the action decided about
	Policy   []byte // the deciding policy's opaque identity (NOT a policy language)
	Effect   uint64 // the C5 effect class of the action

	Ordering       *OrderingDisclosure // OPTIONAL field 5 (R1); nil == absent (reads correspondence-only)
	ForeignProfile *ForeignProfilePin  // OPTIONAL field 6 (R8); non-nil iff decided over foreign-protocol evidence
}

// Bytes is the deterministic-CBOR encoding {1: decision, 2: action, 3: policy, 4: effect,
// ?5: ordering, ?6: foreign-profile}. Fields 5/6 are OMITTED entirely when nil (the same
// omit-when-absent precedent as naalp-decision-record's optional fields 3/6/7).
func (d GatewayDecision) Bytes() []byte {
	m := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(d.Decision)},
		{K: cbor.Uint(2), V: cbor.Bstr(d.Action)},
		{K: cbor.Uint(3), V: cbor.Bstr(d.Policy)},
		{K: cbor.Uint(4), V: cbor.Uint(d.Effect)},
	}
	if d.Ordering != nil {
		m = append(m, cbor.Pair{K: cbor.Uint(5), V: d.Ordering.toCBOR()})
	}
	if d.ForeignProfile != nil {
		m = append(m, cbor.Pair{K: cbor.Uint(6), V: d.ForeignProfile.toCBOR()})
	}
	b, _ := cbor.Encode(m)
	return b
}

// Head is the decision's SHA-384 head (48 octets).
func (d GatewayDecision) Head() []byte { return head(d.Bytes()) }

// ID is the decision's T1 content-id (50 octets).
func (d GatewayDecision) ID() []byte { return contentID(d.Bytes()) }

// EffectClass is the decision's C5 effect class, normalized fail-closed: a value the evaluator does
// not recognize is treated as destructive (R-6.2), never as a weaker class.
func (d GatewayDecision) EffectClass() policy.Effect { return policy.NormalizeEffect(d.Effect) }

// ParseDecision reconstructs a GatewayDecision from its body bytes alone. It does NOT validate the
// decision code against the closed set, the ordering-disclosure's basis-conditioned well-formedness,
// or the foreign-profile-pin's field well-formedness — those are VerifyDecision's job (mirroring the
// decision-record Parse/Validate split), so a decision carrying an unknown code, or an ordering/
// foreign-profile that is structurally decodable but semantically malformed, can be represented (and
// then rejected). It DOES enforce field-1-4 presence/type and, when field 5/6 is PRESENT, that it
// decodes to the expected CBOR shape: present-with-wrong-type fails here (ErrMalformed), never
// silently treated as absent. Fail-closed on any malformed shape.
func ParseDecision(b []byte) (GatewayDecision, error) {
	m, ok := decodeMap(b)
	if !ok {
		return GatewayDecision{}, ErrMalformed
	}
	dec, ok1 := uintField(m, 1)
	action, ok2 := bstrField(m, 2)
	pol, ok3 := bstrField(m, 3)
	eff, ok4 := uintField(m, 4)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return GatewayDecision{}, ErrMalformed
	}
	gd := GatewayDecision{Decision: dec, Action: action, Policy: pol, Effect: eff}
	if ordV, present := field(m, 5); present {
		ordering, ok := orderingFromCBOR(ordV)
		if !ok {
			return GatewayDecision{}, ErrMalformed
		}
		gd.Ordering = &ordering
	}
	if fpV, present := field(m, 6); present {
		fp, ok := foreignProfileFromCBOR(fpV)
		if !ok {
			return GatewayDecision{}, ErrMalformed
		}
		gd.ForeignProfile = &fp
	}
	return gd, nil
}

// SignDecision produces the tagged COSE_Sign1 object over the decision body, signed by the gateway.
func SignDecision(d GatewayDecision, s cose.Signer) ([]byte, error) { return cose.Sign1(s, d.Bytes()) }

// ResolvedDecision is a GatewayDecision that has passed signature verification. It carries the
// verified decision, action content id, policy identity, and effect class. It carries NOTHING about
// WHO served the bytes — the authority is the signature, so the resolved evidence is identical
// regardless of the serving party (the third-party re-serve property).
type ResolvedDecision struct {
	Decision uint64
	Action   []byte
	Policy   []byte
	Effect   policy.Effect
}

// VerifyDecision verifies a gateway decision end-to-end and returns the resolved evidence. It (1)
// verifies the signed object under the profile with real crypto (cose.Verify1 — signature, alg
// registry, profile floor) against the GATEWAY's verifier `gatewayV`; (2) reconstructs it from the
// signed bytes (ParseDecision — structural only); (3) validates the decision code against the closed
// set (UnknownGatewayDecision); (4) if field 5 (ordering) is present, its basis-conditioned
// well-formedness (UnknownOrderingBasis / OrderingDisclosureMalformed); and (5) if field 6
// (foreign-profile) is present, its own well-formedness (ForeignProfileMalformed). Mandatory fields
// 1-4 are validated FIRST via ParseDecision: a body failing a mandatory-field check is GwMalformed
// regardless of any optional 5/6. It takes NO serving-party or connection identity: the authority is
// the signature over the bytes, so the same `obj` yields an identical ResolvedDecision whether the
// gateway or an unrelated third party served it (the third-party re-serve property, R-GW-3). Any
// failure returns its named error and resolves nothing (fail-closed).
func VerifyDecision(obj []byte, profile int, gatewayV cose.Verifier) (ResolvedDecision, error) {
	if err := cose.Verify1(profile, gatewayV, obj); err != nil {
		return ResolvedDecision{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return ResolvedDecision{}, err
	}
	d, err := ParseDecision(payload)
	if err != nil {
		return ResolvedDecision{}, err
	}
	if !IsKnownDecision(d.Decision) {
		return ResolvedDecision{}, ErrUnknownDecision
	}
	if d.Ordering != nil {
		if err := d.Ordering.Validate(); err != nil {
			return ResolvedDecision{}, err
		}
	}
	if d.ForeignProfile != nil {
		if err := d.ForeignProfile.Validate(); err != nil {
			return ResolvedDecision{}, err
		}
	}
	return ResolvedDecision{
		Decision: d.Decision,
		Action:   append([]byte(nil), d.Action...),
		Policy:   append([]byte(nil), d.Policy...),
		Effect:   policy.NormalizeEffect(d.Effect),
	}, nil
}

// ---- ForeignProfilePin: field 6, R8 -----------------------------------------------------------

// ForeignProfilePin is the embeddable group {1: id, 2: revision} (naalp-foreign-profile-pin, R8).
// Present on GatewayDecision field 6 iff the decision was over foreign-protocol evidence: it pins
// the foreign evidence profile's identifier (an absolute URI) AND the revision pinned at decision
// time — binding the reference, not just the class. Both fields are mandatory tstr; the group
// carries no other keys. It is never a top-level signed object — always embedded as field 6 of its
// carrying naalp-gateway-decision, so it has no Head/ID of its own (mirroring OrderingDisclosure).
type ForeignProfilePin struct {
	ID       string
	Revision string

	unknownField bool // an unrecognized key besides 1/2 was present in the decoded CBOR map
}

// toCBOR returns f as a nested CBOR map VALUE {1: tstr(id), 2: tstr(revision)}.
func (f ForeignProfilePin) toCBOR() cbor.Map {
	return cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr(f.ID)},
		{K: cbor.Uint(2), V: cbor.Tstr(f.Revision)},
	}
}

// foreignProfileFromCBOR decodes a nested foreign-profile-pin map value. Decode is STRUCTURAL only,
// mirroring orderingFromCBOR: a key present under the WRONG CBOR type fails decode (ok=false, never
// silently treated as absent); a key that is simply ABSENT decodes to the empty string, leaving the
// mandatory-presence check to Validate (mirroring OrderingDisclosure's own decode/Validate split — a
// structurally-decodable-but-semantically-incomplete group is a distinct case from a body that does
// not even decode). A key besides 1/2 marks the group unknownField, also caught by Validate — the
// closed 2-key set is enforced semantically, not by refusing to decode a map that merely carries an
// extra key.
func foreignProfileFromCBOR(v cbor.Value) (ForeignProfilePin, bool) {
	m, ok := v.(cbor.Map)
	if !ok {
		return ForeignProfilePin{}, false
	}
	var f ForeignProfilePin
	if v1, present := field(m, 1); present {
		s, ok := v1.(cbor.Tstr)
		if !ok {
			return ForeignProfilePin{}, false
		}
		f.ID = string(s)
	}
	if v2, present := field(m, 2); present {
		s, ok := v2.(cbor.Tstr)
		if !ok {
			return ForeignProfilePin{}, false
		}
		f.Revision = string(s)
	}
	for _, p := range m {
		if p.K != cbor.Uint(1) && p.K != cbor.Uint(2) {
			f.unknownField = true
			break
		}
	}
	return f, true
}

// Validate checks the foreign-profile-pin's own well-formedness (R8): both id and revision are
// mandatory non-empty tstr, and no key besides 1/2 may be present. A missing, empty, or extra field
// rejects the WHOLE carrying naalp-gateway-decision (ForeignProfileMalformed).
func (f ForeignProfilePin) Validate() error {
	if f.ID == "" || f.Revision == "" || f.unknownField {
		return ErrForeignProfileMalformed
	}
	return nil
}

// ---- small deterministic-CBOR field accessors ------------------------------------------------

func decodeMap(b []byte) (cbor.Map, bool) {
	v, err := cbor.Decode(b)
	if err != nil {
		return nil, false
	}
	m, ok := v.(cbor.Map)
	return m, ok
}

func field(m cbor.Map, k uint64) (cbor.Value, bool) {
	for _, p := range m {
		if p.K == cbor.Uint(k) {
			return p.V, true
		}
	}
	return nil, false
}

func bstrField(m cbor.Map, k uint64) ([]byte, bool) {
	v, ok := field(m, k)
	if !ok {
		return nil, false
	}
	bs, ok := v.(cbor.Bstr)
	return []byte(bs), ok
}

func uintField(m cbor.Map, k uint64) (uint64, bool) {
	v, ok := field(m, k)
	if !ok {
		return 0, false
	}
	u, ok := v.(cbor.Uint)
	return uint64(u), ok
}
