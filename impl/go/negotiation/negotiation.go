// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package negotiation implements C20 — governed negotiation, advisory risk labels, and trust
// (design.md §23; requirements R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4).
//
// C20 adds three signed surfaces carried on N-AALP's own signed object. It introduces NO new
// envelope, encoding, signature, identity, or audit mechanism (R-11.3): each object is an ordinary
// signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice (policy), the T1
// content-id framing (§2.3), and the §8.2 causal partial order (the `causes` field) UNCHANGED.
//
// Task 5.1 — governed negotiation:
//
//   - Message {1: negotiation, 2: role, 3: profile, 4: causes[]} is one signed step of a negotiation:
//     an OFFER, a COUNTER, or an ACCEPT. The steps are CAUSALLY LINKED — each references its
//     predecessor by content-id in `causes` (the same list-of-content-ids shape §8.2 uses). Each step
//     SELECTS a profile from a CLOSED, PRE-REGISTERED set (Profile) — the negotiation selects a
//     pre-registered profile, it never negotiates free-form runtime behavior: there are no
//     runtime-generated handlers and no free-form capability strings on the wire, by design (§23.9).
//     An ACCEPT MUST DESCEND from its offer: walking the `causes` DAG from the accept must reach the
//     offer's content-id (VerifyAccept), or the accept is rejected (ErrNotDescended). An unknown
//     profile is rejected (ErrUnknownProfile); an unknown role is rejected (ErrUnknownRole).
//
// Task 5.2 — advisory risk labels:
//
//   - RiskLabel {1: code, 2: critical} is one carried advisory risk label; LabeledObject
//     {1: effect, 2: labels[]} carries an effect together with a set of risk labels. The vocabulary
//     (vectors/registry/risk-labels.csv) is a closed standard set — sensitive (gating), egress
//     (gating), reversible (informing) — plus a private/experimental extensible range. `critical` is
//     the per-carriage must-understand flag (uint 1/0; the spine carries no CBOR boolean, §3.1). The
//     critical-extension rule (R-2.5) applies: an unknown CRITICAL label is rejected
//     (ErrUnknownCriticalRisk); an unknown NON-critical label is ignored. The LOAD-BEARING invariant:
//     adding or carrying a risk label NEVER changes an object's effect class — LabeledObject.EffectClass
//     derives from field 7 ALONE (policy.NormalizeEffect), so the closed C5 lattice is untouched. Risk
//     labels are an advisory dimension, not a fifth effect.
//
// Task 5.3 — trust references:
//
//   - TrustRef {1: registry, 2: reference, 3: subject} carries a third-party trust statement as a
//     CHECKABLE signed object: `reference` is the T1 content-id of an EXTERNAL registry record (an
//     ERC-8004-style reputation/identity registry record). VerifyTrustRef checks the signature and,
//     given the external bytes, confirms the reference by RECOMPUTING that content-id (BindsRecord).
//     But NO wire field WEIGHS the statement: there is no score, rank, or ordering on the wire, and
//     this package provides NO scoring function — the protocol carries trust statements, it does not
//     weigh them (§23.7). Which statement to believe is left to the relying party.
//
// Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
// causes no state change.
package negotiation

import (
	"bytes"
	"crypto/sha512"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// HeadSize is the width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit
// chain (audit.HeadSize).
const HeadSize = 48

// Named, fail-closed errors. A failing object is rejected whole and causes no state change (§15).
// They reuse the cose.Error type so every N-AALP error carries a stable Kind.
var (
	ErrMalformed           = &cose.Error{Kind: "NegMalformed", Msg: "object is not a well-formed N-AALP negotiation/risk-label/labeled-object/trust-ref body"}
	ErrUnknownRole         = &cose.Error{Kind: "UnknownRole", Msg: "negotiation message role is not offer/counter/accept"}
	ErrUnknownProfile      = &cose.Error{Kind: "UnknownProfile", Msg: "negotiation selects a profile outside the closed pre-registered set — no free-form or runtime capability is negotiable"}
	ErrNotDescended        = &cose.Error{Kind: "NotDescended", Msg: "accept does not descend from its offer along the causes chain"}
	ErrNotOffer            = &cose.Error{Kind: "NotOffer", Msg: "the object presented as the offer is not an offer role"}
	ErrNotAccept           = &cose.Error{Kind: "NotAccept", Msg: "the object presented as the accept is not an accept role"}
	ErrCriticalFlag        = &cose.Error{Kind: "MalformedCriticalFlag", Msg: "risk-label critical flag is outside {0,1}: the spine carries no CBOR boolean, so it is rejected, never defaulted"}
	ErrUnknownCriticalRisk = &cose.Error{Kind: "UnknownCriticalRisk", Msg: "an unknown risk label carried critical is rejected (R-2.5 critical-extension rule)"}
	ErrReferenceMismatch   = &cose.Error{Kind: "ReferenceMismatch", Msg: "trust-ref reference content-id does not recompute over the presented external record"}
)

// head is SHA-384 over a body — a 48-octet digest (the same construction as audit.Receipt.Head).
func head(b []byte) []byte {
	d := sha512.Sum384(b)
	return d[:]
}

// contentID is the T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
func contentID(b []byte) []byte {
	h := head(b)
	return append([]byte{0x20, 0x30}, h...)
}

// ==== Task 5.1 — governed negotiation =========================================================

// Role is a negotiation message's role: the closed set offer / counter / accept. A role outside the
// set is rejected (ErrUnknownRole) — there is no open-ended message type.
type Role uint64

const (
	RoleOffer   Role = 0 // the initiating offer (the root of a negotiation; no causes)
	RoleCounter Role = 1 // a counter-offer chaining onto the offer or a prior counter
	RoleAccept  Role = 2 // the accept; it MUST descend from its offer
)

// roleName maps a role code to its name (diagnostics); an unknown code returns "".
var roleName = map[Role]string{RoleOffer: "offer", RoleCounter: "counter", RoleAccept: "accept"}

// KnownRole reports whether r is one of the three defined negotiation roles.
func KnownRole(r Role) bool { _, ok := roleName[r]; return ok }

// Name returns the role name, or "unknown" for an out-of-range code.
func (r Role) Name() string {
	if n, ok := roleName[r]; ok {
		return n
	}
	return "unknown"
}

// Profile is a PRE-REGISTERED negotiation profile code (the closed set). A negotiation SELECTS a
// pre-registered profile; it never carries a free-form capability string or a runtime-generated
// handler. A profile outside the set is rejected (ErrUnknownProfile).
type Profile uint64

const (
	ProfileBaseline  Profile = 0 // the baseline capability profile
	ProfileStreaming Profile = 1 // the native-streaming capability profile (C9)
	ProfileBatch     Profile = 2 // the batched-delivery capability profile
)

// profileName maps a profile code to its name (diagnostics); an unknown code returns "".
var profileName = map[Profile]string{ProfileBaseline: "baseline", ProfileStreaming: "streaming", ProfileBatch: "batch"}

// IsRegisteredProfile reports whether p is one of the pre-registered profiles.
func IsRegisteredProfile(p Profile) bool { _, ok := profileName[p]; return ok }

// Name returns the profile name, or "unknown" for an unregistered code.
func (p Profile) Name() string {
	if n, ok := profileName[p]; ok {
		return n
	}
	return "unknown"
}

// Message is one signed step of a governed negotiation: an offer, a counter, or an accept. It is
// CAUSALLY LINKED to its predecessor(s) by content-id in Causes (empty for an offer). It SELECTS a
// pre-registered Profile.
type Message struct {
	Negotiation []byte   // opaque negotiation id (ties the exchange together)
	Role        Role     // offer / counter / accept (closed set)
	Profile     Profile  // the selected pre-registered profile (closed set; unknown rejected)
	Causes      [][]byte // content-ids of predecessor messages (the causal links; empty for an offer)
}

// NewOffer builds an offer (the root of a negotiation): role offer, no causes.
func NewOffer(negotiation []byte, profile Profile) Message {
	return Message{Negotiation: negotiation, Role: RoleOffer, Profile: profile}
}

// NewCounter builds a counter chaining onto the predecessor named by predecessorID.
func NewCounter(negotiation []byte, profile Profile, predecessorID []byte) Message {
	return Message{Negotiation: negotiation, Role: RoleCounter, Profile: profile, Causes: [][]byte{predecessorID}}
}

// NewAccept builds an accept chaining onto the predecessor named by predecessorID. It must descend
// from its offer (checked by VerifyAccept).
func NewAccept(negotiation []byte, profile Profile, predecessorID []byte) Message {
	return Message{Negotiation: negotiation, Role: RoleAccept, Profile: profile, Causes: [][]byte{predecessorID}}
}

// Bytes is the deterministic-CBOR encoding {1: negotiation, 2: role, 3: profile, 4: causes[]}.
func (m Message) Bytes() []byte {
	arr := make(cbor.Arr, len(m.Causes))
	for i, c := range m.Causes {
		arr[i] = cbor.Bstr(c)
	}
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(m.Negotiation)},
		{K: cbor.Uint(2), V: cbor.Uint(uint64(m.Role))},
		{K: cbor.Uint(3), V: cbor.Uint(uint64(m.Profile))},
		{K: cbor.Uint(4), V: arr},
	})
	return b
}

// Head is the Message's SHA-384 head (48 octets).
func (m Message) Head() []byte { return head(m.Bytes()) }

// ID is the Message's T1 content-id (50 octets) — the id a successor names in its Causes.
func (m Message) ID() []byte { return contentID(m.Bytes()) }

// ParseMessage reconstructs a Message from its body bytes alone. It does NOT validate the role or
// profile against the closed sets — that is VerifyMessage's job — so a message carrying an unknown
// role or profile can be represented (and then rejected).
func ParseMessage(b []byte) (Message, error) {
	m, ok := decodeMap(b)
	if !ok {
		return Message{}, ErrMalformed
	}
	neg, ok1 := bstrField(m, 1)
	role, ok2 := uintField(m, 2)
	prof, ok3 := uintField(m, 3)
	causesV, ok4 := field(m, 4)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return Message{}, ErrMalformed
	}
	arr, ok := causesV.(cbor.Arr)
	if !ok {
		return Message{}, ErrMalformed
	}
	causes := make([][]byte, len(arr))
	for i, e := range arr {
		bs, ok := e.(cbor.Bstr)
		if !ok {
			return Message{}, ErrMalformed
		}
		causes[i] = []byte(bs)
	}
	return Message{Negotiation: neg, Role: Role(role), Profile: Profile(prof), Causes: causes}, nil
}

// SignMessage produces the tagged COSE_Sign1 object over the Message body.
func SignMessage(m Message, s cose.Signer) ([]byte, error) { return cose.Sign1(s, m.Bytes()) }

// VerifyMessage verifies the Message's full signature under the profile, reconstructs it from the
// signed body bytes, and validates it against the closed sets: the role MUST be one of
// offer/counter/accept (ErrUnknownRole) and the selected profile MUST be pre-registered
// (ErrUnknownProfile). A bad signature propagates from cose.Verify1 (BadSignature). Fail-closed.
func VerifyMessage(obj []byte, profile int, v cose.Verifier) (Message, error) {
	if err := cose.Verify1(profile, v, obj); err != nil {
		return Message{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return Message{}, err
	}
	m, err := ParseMessage(payload)
	if err != nil {
		return Message{}, err
	}
	if !KnownRole(m.Role) {
		return Message{}, ErrUnknownRole
	}
	if !IsRegisteredProfile(m.Profile) {
		return Message{}, ErrUnknownProfile
	}
	return m, nil
}

// IndexByID builds the content-id -> Message index the descent walk resolves predecessors through.
// The key is the string form of the T1 content-id (Message.ID()).
func IndexByID(msgs []Message) map[string]Message {
	byID := make(map[string]Message, len(msgs))
	for _, m := range msgs {
		byID[string(m.ID())] = m
	}
	return byID
}

// descends reports whether `from` reaches `targetID` by following causes edges resolved through
// byID: a real reachability walk over the causal DAG. A cause that cannot be resolved through byID
// cannot extend the chain through it (the walk simply does not traverse past it), so a forged
// causes pointer to an id the verifier never saw does not manufacture descent. Fail-closed.
func descends(from Message, targetID []byte, byID map[string]Message) bool {
	target := string(targetID)
	seen := map[string]bool{}
	stack := make([][]byte, 0, len(from.Causes))
	stack = append(stack, from.Causes...)
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		k := string(id)
		if k == target {
			return true
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		pred, ok := byID[k]
		if !ok {
			continue // an unresolved cause: the chain cannot be walked through it
		}
		stack = append(stack, pred.Causes...)
	}
	return false
}

// Descends reports whether `accept` descends from `offer` by walking the causes DAG through byID
// (a counter or a chain of counters between them is traversed). It is the graph predicate underlying
// VerifyAccept; it performs no signature check.
func Descends(accept, offer Message, byID map[string]Message) bool {
	return descends(accept, offer.ID(), byID)
}

// VerifyAccept checks an accept against its offer over a set of verified messages, fail-closed. It
// (1) requires `offer` to be a genuine offer selecting a pre-registered profile (ErrNotOffer /
// ErrUnknownProfile); (2) requires `accept` to be an accept selecting a pre-registered profile
// (ErrNotAccept / ErrUnknownProfile); (3) requires the accept to DESCEND from the offer by walking
// the causes DAG through byID (ErrNotDescended otherwise). It returns the AGREED profile (the
// accept's selected pre-registered profile). It authorizes nothing; it accepts or rejects. byID MUST
// index the negotiation's verified messages (build it with IndexByID over VerifyMessage results).
func VerifyAccept(accept, offer Message, byID map[string]Message) (Profile, error) {
	if offer.Role != RoleOffer {
		return 0, ErrNotOffer
	}
	if !IsRegisteredProfile(offer.Profile) {
		return 0, ErrUnknownProfile
	}
	if accept.Role != RoleAccept {
		return 0, ErrNotAccept
	}
	if !IsRegisteredProfile(accept.Profile) {
		return 0, ErrUnknownProfile
	}
	if !Descends(accept, offer, byID) {
		return 0, ErrNotDescended
	}
	return accept.Profile, nil
}

// ==== Task 5.2 — advisory risk labels =========================================================

// RiskClass is a risk label's advisory class in the vocabulary: informing (purely informational) or
// gating (a policy MAY gate on it). This is a REGISTRY attribute of the label code, distinct from the
// per-carriage critical flag.
type RiskClass uint64

const (
	ClassInforming RiskClass = 0 // purely informational
	ClassGating    RiskClass = 1 // a policy MAY require an additional gate when this label is present
)

// riskClassName maps a class to its registry name (matches risk-labels.csv `class`).
var riskClassName = map[RiskClass]string{ClassInforming: "informing", ClassGating: "gating"}

// Name returns the class name ("gating"/"informing"), or "" for an out-of-range value.
func (c RiskClass) Name() string { return riskClassName[c] }

// RiskCode is a risk-label code. The closed standard vocabulary is defined below; codes at or above
// ExtensibleRangeStart are the private/experimental extensible range (unknown to a verifier lacking
// them).
type RiskCode uint64

const (
	RiskSensitive  RiskCode = 1 // gating: the object touches sensitive material
	RiskEgress     RiskCode = 2 // gating: the object causes data egress
	RiskReversible RiskCode = 3 // informing: the object's effect is reversible
)

// ExtensibleRangeStart is the first code of the private/experimental extensible range. A code at or
// above it is not in the standard vocabulary and is unknown to a verifier that lacks it — carried
// critical it is rejected (R-2.5), carried non-critical it is ignored.
const ExtensibleRangeStart RiskCode = 0x1000

// riskVocab is the closed standard risk-label vocabulary: code -> class. It is the authority the
// registry (vectors/registry/risk-labels.csv) is cross-checked against and the two implementations
// grade Go == Rust == oracle.
var riskVocab = map[RiskCode]RiskClass{
	RiskSensitive:  ClassGating,
	RiskEgress:     ClassGating,
	RiskReversible: ClassInforming,
}

// RiskClassOf returns a code's vocabulary class and whether the code is a registered standard label.
func RiskClassOf(code RiskCode) (RiskClass, bool) { c, ok := riskVocab[code]; return c, ok }

// IsRegisteredRisk reports whether code is in the closed standard vocabulary.
func IsRegisteredRisk(code RiskCode) bool { _, ok := riskVocab[code]; return ok }

// InExtensibleRange reports whether code lies in the private/experimental extensible range.
func InExtensibleRange(code RiskCode) bool { return code >= ExtensibleRangeStart }

// RiskLabel is one advisory risk label carried on an object. Code is the label code; Critical is the
// per-carriage must-understand flag (1 = critical, 0 = advisory) — the uint 1/0, no CBOR boolean.
type RiskLabel struct {
	Code     RiskCode
	Critical uint64
}

// IsCritical reports whether the label is carried critical (must-understand).
func (l RiskLabel) IsCritical() bool { return l.Critical == 1 }

// toMap encodes the risk label as its CBOR map {1: code, 2: critical}.
func (l RiskLabel) toMap() cbor.Map {
	return cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(uint64(l.Code))},
		{K: cbor.Uint(2), V: cbor.Uint(l.Critical)},
	}
}

// Bytes is the deterministic-CBOR encoding of the risk-label body.
func (l RiskLabel) Bytes() []byte {
	b, _ := cbor.Encode(l.toMap())
	return b
}

// riskLabelFromValue parses one risk-label map, rejecting a malformed shape (ErrMalformed) or a
// critical flag outside {0,1} (ErrCriticalFlag). Fail-closed.
func riskLabelFromValue(v cbor.Value) (RiskLabel, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return RiskLabel{}, ErrMalformed
	}
	code, ok1 := uintField(m, 1)
	crit, ok2 := uintField(m, 2)
	if !ok1 || !ok2 {
		return RiskLabel{}, ErrMalformed
	}
	if crit > 1 {
		return RiskLabel{}, ErrCriticalFlag
	}
	return RiskLabel{Code: RiskCode(code), Critical: crit}, nil
}

// ValidateLabels applies the critical-extension rule (R-2.5) to a set of carried risk labels: it
// returns the RECOGNIZED (standard-vocabulary) labels, DROPS unknown non-critical labels, and
// REJECTS an unknown CRITICAL label (ErrUnknownCriticalRisk). A critical flag outside {0,1} is
// ErrCriticalFlag. It NEVER inspects or returns an effect — risk labels are an advisory dimension,
// never a fifth effect (the closed C5 lattice is untouched). Fail-closed.
func ValidateLabels(labels []RiskLabel) ([]RiskLabel, error) {
	recognized := make([]RiskLabel, 0, len(labels))
	for _, l := range labels {
		if l.Critical > 1 {
			return nil, ErrCriticalFlag
		}
		if IsRegisteredRisk(l.Code) {
			recognized = append(recognized, l)
			continue
		}
		if l.IsCritical() {
			return nil, ErrUnknownCriticalRisk // R-2.5: an unknown must-understand label is rejected
		}
		// unknown non-critical: ignored (dropped from the recognized set)
	}
	return recognized, nil
}

// LabeledObject is a minimal N-AALP object carrying an effect (field 7, C5) and a set of advisory
// risk labels. It exists to demonstrate — provably, in isolation — the load-bearing invariant that
// carrying a risk label NEVER changes the object's effect class.
type LabeledObject struct {
	Effect uint64      // the C5 effect field (field 7)
	Labels []RiskLabel // the advisory risk labels carried on the object
}

// Bytes is the deterministic-CBOR encoding {1: effect, 2: labels[]}.
func (o LabeledObject) Bytes() []byte {
	arr := make(cbor.Arr, len(o.Labels))
	for i, l := range o.Labels {
		arr[i] = l.toMap()
	}
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(o.Effect)},
		{K: cbor.Uint(2), V: arr},
	})
	return b
}

// Head is the LabeledObject's SHA-384 head (48 octets).
func (o LabeledObject) Head() []byte { return head(o.Bytes()) }

// ID is the LabeledObject's T1 content-id (50 octets).
func (o LabeledObject) ID() []byte { return contentID(o.Bytes()) }

// EffectClass is the object's C5 effect class, derived from the effect field (field 7) ALONE and
// normalized fail-closed (unknown -> destructive, R-6.2). It DELIBERATELY does not consult the risk
// labels: a risk label is an advisory dimension, never a fifth effect, so the closed lattice is
// untouched by any label the object carries. This is the load-bearing C20 invariant; the mutation
// test proves a read_only object carrying a gating "sensitive" label still resolves to read_only.
func (o LabeledObject) EffectClass() policy.Effect { return policy.NormalizeEffect(o.Effect) }

// ValidateLabels applies the critical-extension rule to the object's carried labels (ValidateLabels).
func (o LabeledObject) ValidateLabels() ([]RiskLabel, error) { return ValidateLabels(o.Labels) }

// ParseLabeledObject reconstructs a LabeledObject from its body bytes alone.
func ParseLabeledObject(b []byte) (LabeledObject, error) {
	m, ok := decodeMap(b)
	if !ok {
		return LabeledObject{}, ErrMalformed
	}
	eff, ok1 := uintField(m, 1)
	labelsV, ok2 := field(m, 2)
	if !ok1 || !ok2 {
		return LabeledObject{}, ErrMalformed
	}
	arr, ok := labelsV.(cbor.Arr)
	if !ok {
		return LabeledObject{}, ErrMalformed
	}
	labels := make([]RiskLabel, len(arr))
	for i, e := range arr {
		l, err := riskLabelFromValue(e)
		if err != nil {
			return LabeledObject{}, err
		}
		labels[i] = l
	}
	return LabeledObject{Effect: eff, Labels: labels}, nil
}

// SignLabeledObject produces the tagged COSE_Sign1 object over the LabeledObject body.
func SignLabeledObject(o LabeledObject, s cose.Signer) ([]byte, error) { return cose.Sign1(s, o.Bytes()) }

// VerifyLabeledObject verifies the signature under the profile, reconstructs the object, and applies
// the critical-extension rule to its labels (an unknown critical label is rejected). It returns the
// verified object and its recognized labels. The returned object's EffectClass is unchanged by any
// label — labels never participate in the effect. Fail-closed.
func VerifyLabeledObject(obj []byte, profile int, v cose.Verifier) (LabeledObject, []RiskLabel, error) {
	if err := cose.Verify1(profile, v, obj); err != nil {
		return LabeledObject{}, nil, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return LabeledObject{}, nil, err
	}
	o, err := ParseLabeledObject(payload)
	if err != nil {
		return LabeledObject{}, nil, err
	}
	recognized, err := ValidateLabels(o.Labels)
	if err != nil {
		return LabeledObject{}, nil, err
	}
	return o, recognized, nil
}

// ==== Task 5.3 — trust references (checkable, never weighed) ==================================

// TrustRef carries a third-party trust statement as a CHECKABLE signed object. Registry is an opaque
// external-registry identifier (an ERC-8004-style reputation/identity registry — a name, not a URL
// the wire resolves); Reference is the T1 content-id of the referenced external record; Subject is
// the opaque id the statement is about. The wire CARRIES the reference; NO field here weighs it —
// there is no score, rank, or ordering. The relying party resolves what to believe.
type TrustRef struct {
	Registry  []byte // opaque external-registry identifier (e.g. "erc-8004:reputation")
	Reference []byte // content-id of the referenced external record (multihash(0x20, SHA-384(record)))
	Subject   []byte // the subject the statement is about (opaque id)
}

// Bytes is the deterministic-CBOR encoding {1: registry, 2: reference, 3: subject}.
func (r TrustRef) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(r.Registry)},
		{K: cbor.Uint(2), V: cbor.Bstr(r.Reference)},
		{K: cbor.Uint(3), V: cbor.Bstr(r.Subject)},
	})
	return b
}

// Head is the TrustRef's SHA-384 head (48 octets).
func (r TrustRef) Head() []byte { return head(r.Bytes()) }

// ID is the TrustRef's own T1 content-id (50 octets).
func (r TrustRef) ID() []byte { return contentID(r.Bytes()) }

// ReferenceID returns the content-id the trust ref binds (the carried external-record reference).
func (r TrustRef) ReferenceID() []byte { return append([]byte(nil), r.Reference...) }

// BindsRecord reports whether the carried Reference is the T1 content-id of `record` — i.e. the
// reference recomputes over the presented external bytes. This is the CHECK a relying party runs to
// confirm the reference names those exact external bytes; it computes NO score. A changed record
// yields a different content-id, so BindsRecord returns false.
func (r TrustRef) BindsRecord(record []byte) bool {
	return bytes.Equal(r.Reference, contentID(record))
}

// ParseTrustRef reconstructs a TrustRef from its body bytes alone.
func ParseTrustRef(b []byte) (TrustRef, error) {
	m, ok := decodeMap(b)
	if !ok {
		return TrustRef{}, ErrMalformed
	}
	reg, ok1 := bstrField(m, 1)
	ref, ok2 := bstrField(m, 2)
	subj, ok3 := bstrField(m, 3)
	if !ok1 || !ok2 || !ok3 {
		return TrustRef{}, ErrMalformed
	}
	return TrustRef{Registry: reg, Reference: ref, Subject: subj}, nil
}

// SignTrustRef produces the tagged COSE_Sign1 object over the TrustRef body.
func SignTrustRef(r TrustRef, s cose.Signer) ([]byte, error) { return cose.Sign1(s, r.Bytes()) }

// ResolvedTrustRef is a TrustRef that has passed signature verification and (given the external
// record) the content-id recompute. It carries NO score, rank, or trust weight — the protocol does
// not weigh trust; which statement to believe is left to the relying party.
type ResolvedTrustRef struct {
	Registry  []byte // the external-registry identifier, verbatim
	Reference []byte // the confirmed external-record content-id
	Subject   []byte // the subject the statement is about
}

// VerifyTrustRef verifies a trust reference end-to-end: it (1) verifies the signed object under the
// profile with real crypto (cose.Verify1); (2) reconstructs it from the signed bytes; and (3)
// confirms the reference by RECOMPUTING the external record's content-id and requiring it to equal
// the carried Reference (ErrReferenceMismatch otherwise). It returns the resolved reference — and
// NOTHING that scores it: this package has no trust-weighting function, by design. Any failure
// returns its named error and resolves nothing (fail-closed).
func VerifyTrustRef(obj []byte, profile int, v cose.Verifier, externalRecord []byte) (ResolvedTrustRef, error) {
	if err := cose.Verify1(profile, v, obj); err != nil {
		return ResolvedTrustRef{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return ResolvedTrustRef{}, err
	}
	r, err := ParseTrustRef(payload)
	if err != nil {
		return ResolvedTrustRef{}, err
	}
	if !r.BindsRecord(externalRecord) {
		return ResolvedTrustRef{}, ErrReferenceMismatch
	}
	return ResolvedTrustRef{Registry: r.Registry, Reference: r.Reference, Subject: r.Subject}, nil
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
