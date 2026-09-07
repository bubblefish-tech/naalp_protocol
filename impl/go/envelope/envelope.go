// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package envelope implements N-AALP's C3 object envelope (design.md §2): the single
// signed object every kind, channel, and transport reuses. The object body is a
// deterministic-CBOR map (fields 1..12) carried as the COSE_Sign1 payload; field 1 is the
// content id, multihash(0x20, SHA-384(canonical-body-without-field-1)) (§2.3). The COSE
// protected header carries the signature algorithm plus a routing copy of the signer,
// profile, and naalp-version (§2.1, §2.5); a verifier that finds the header copies
// disagreeing with the body rejects the object (HeaderBodyMismatch), and every failure is
// fail-closed with a named error and no partial application (§2.6).
package envelope

import (
	"bytes"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// The object body field numbers (FieldID..FieldCext), the protected-header
// NaalpVersion, and naalpHeaderLabel are GENERATED from spec/wire-constants.csv into
// wire_constants_gen.go (same package) so the ten ports cannot drift on the wire.
// Change the CSV and run scripts/gen_wire_constants.py; never edit the values here.

// RecheckKey is the ext/cext extension key under which an object NAMES the re-check procedure
// for the claim in its body (§2.5, NAALP-REQ-111(c) — the "checkable minimum"). The value is a
// procedure id into the closed registry below. In the non-critical ext map (field 11) it is
// may-ignore; in the critical cext map (field 12) it is must-understand and an unknown
// procedure id is rejected fail-closed (UnknownCriticalExt), the same C3 critical-extension
// rule reaching the procedure it names. 13 does not collide with the safety-label ext key 1
// (§6.4). Byte-identical to impl/rust.
const RecheckKey = 13

// The closed re-check procedure registry (design.md §2.5; T1.3); mirrors the spec
// recheck-procedure production and vectors/registry/recheck.csv.
const (
	RecheckRecomputeContentID = 1 // recompute the content id from the body and compare (§2.3)
	RecheckVerifyCoseSign1    = 2 // verify the COSE_Sign1 signature under the signer key (§4)
	RecheckWalkCauses         = 3 // walk the signed causal partial order offline (§8.2)
	RecheckReplayConsumeCheck = 4 // replay the single-use consume ledger for the approval (§7.2)
)

// IsKnownRecheckProcedure reports whether id is a recognized re-check procedure. The registry
// is CLOSED: an id outside it is unknown, and an unknown id under the critical map is rejected
// (§2.5).
func IsKnownRecheckProcedure(id uint64) bool {
	return id >= RecheckRecomputeContentID && id <= RecheckReplayConsumeCheck
}

// Errors (design.md §2.6). Reuse the cose.Error type so every N-AALP error carries a
// stable Kind; the COSE-layer errors (UnknownAlg, ProfileDowngrade, BadSignature,
// KeyAlgMismatch) are reused directly from package cose.
var (
	ErrContentIDMismatch  = &cose.Error{Kind: "ContentIdMismatch", Msg: "id does not equal the recomputed content id"}
	ErrHeaderBodyMismatch = &cose.Error{Kind: "HeaderBodyMismatch", Msg: "protected-header signer/profile disagree with the body"}
	ErrUnknownCriticalExt = &cose.Error{Kind: "UnknownCriticalExt", Msg: "unrecognized critical extension key"}
	ErrUnknownKind        = &cose.Error{Kind: "UnknownKind", Msg: "kind/channel not recognized by any surface"}
	ErrRangeError         = &cose.Error{Kind: "RangeError", Msg: "field value outside its permitted range"}
	ErrUnsupportedVersion = &cose.Error{Kind: "UnsupportedVersion", Msg: "unsupported naalp-version"}
	ErrMalformed          = &cose.Error{Kind: "Malformed", Msg: "malformed object"}
	ErrNonCanonical       = &cose.Error{Kind: "NonCanonical", Msg: "non-canonical encoding: empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)"}
	ErrWrongAudience      = &cose.Error{Kind: "WrongAudience", Msg: "consume-once object audience is not this consuming authority (or absent)"}
	// Decoder bounds (design.md §3.4, R7). DepthExceeded is raised in package cbor
	// (DecodeBounded) and surfaced here as a cose.Error via decodeAndCheck.
	ErrTooLarge          = &cose.Error{Kind: "TooLarge", Msg: "object exceeds the maximum octet size (§3.4, R7)"}
	ErrTooManyCauses     = &cose.Error{Kind: "TooManyCauses", Msg: "causes[] exceeds the maximum count (§3.4, R7)"}
	ErrTooManyExtensions = &cose.Error{Kind: "TooManyExtensions", Msg: "ext/cext exceeds the maximum cardinality (§3.4, R7)"}
)

// Object is a decoded N-AALP object body. ID is set by Sign (content id §2.3).
type Object struct {
	ID       []byte
	Kind     uint64
	Channel  uint64
	Tier     uint64
	Signer   []byte
	Created  uint64
	Effect   uint64
	Causes   [][]byte
	Profile  uint64
	Body     cbor.Value
	Ext      cbor.Map // optional non-critical extensions (field 11); nil = absent
	Cext     cbor.Map // optional critical extensions (field 12); nil = absent
	Audience string   // optional single-use consume binding (field 13, §2.5.3); "" = absent (omitted)
	Suite    uint64   // optional signed suite declaration (field 14, §4.2); 0 = absent (pure object)
}

// SuiteMLDSA65Ed25519 is the signed suite id carried in field 14 for the opt-in
// Public/Enterprise composite (design.md §4.2). Field 14 is present iff the object's alg is
// the composite id; a pure-ML-DSA object omits it and stays byte-identical to a pre-composite
// object. This small-uint suite id is an N-AALP-provisional assignment.
const SuiteMLDSA65Ed25519 = 1

// compositeSuiteForAlg maps a composite signature alg id to its signed suite id (field 14).
// A non-composite alg returns ok=false, so field 14 is absent for a pure object.
func compositeSuiteForAlg(alg int) (uint64, bool) {
	switch alg {
	case cose.AlgComposite65Ed25519:
		return SuiteMLDSA65Ed25519, true
	default:
		return 0, false
	}
}

// KindValidator reports whether (channel, kind) is a recognized surface kind. The
// envelope owns the fail-closed dispatch (UnknownKind); the per-channel kind tables are
// the surface layer's content (C10 / T12). A nil validator rejects every kind.
type KindValidator func(channel, kind uint64) bool

func causesArr(causes [][]byte) cbor.Arr {
	a := make(cbor.Arr, 0, len(causes))
	for _, c := range causes {
		a = append(a, cbor.Bstr(c))
	}
	return a
}

// bodyMap builds the object body as a CBOR map. Encode emits canonical key order, so the
// append order here is irrelevant to the bytes.
func (o *Object) bodyMap(includeID bool) cbor.Map {
	m := make(cbor.Map, 0, 12)
	if includeID {
		m = append(m, cbor.Pair{K: cbor.Uint(FieldID), V: cbor.Bstr(o.ID)})
	}
	m = append(m,
		cbor.Pair{K: cbor.Uint(FieldKind), V: cbor.Uint(o.Kind)},
		cbor.Pair{K: cbor.Uint(FieldChannel), V: cbor.Uint(o.Channel)},
		cbor.Pair{K: cbor.Uint(FieldTier), V: cbor.Uint(o.Tier)},
		cbor.Pair{K: cbor.Uint(FieldSigner), V: cbor.Bstr(o.Signer)},
		cbor.Pair{K: cbor.Uint(FieldCreated), V: cbor.Uint(o.Created)},
		cbor.Pair{K: cbor.Uint(FieldEffect), V: cbor.Uint(o.Effect)},
		cbor.Pair{K: cbor.Uint(FieldCauses), V: causesArr(o.Causes)},
		cbor.Pair{K: cbor.Uint(FieldProfile), V: cbor.Uint(o.Profile)},
		cbor.Pair{K: cbor.Uint(FieldBody), V: o.Body},
	)
	if o.Ext != nil {
		m = append(m, cbor.Pair{K: cbor.Uint(FieldExt), V: o.Ext})
	}
	if o.Cext != nil {
		m = append(m, cbor.Pair{K: cbor.Uint(FieldCext), V: o.Cext})
	}
	if o.Audience != "" {
		m = append(m, cbor.Pair{K: cbor.Uint(FieldAudience), V: cbor.Tstr(o.Audience)})
	}
	if o.Suite != 0 {
		m = append(m, cbor.Pair{K: cbor.Uint(FieldSuite), V: cbor.Uint(o.Suite)})
	}
	return m
}

// ContentID computes the object content id over the body without field 1 (design.md §2.3).
func (o *Object) ContentID() ([]byte, error) {
	return cbor.ContentID(o.bodyMap(false))
}

// Recheck returns the re-check procedure the object names (RecheckKey, §2.5): present is true
// when a procedure is named, and critical is true iff it is named in the cext map (field 12,
// must-understand) rather than the ext map (field 11, may-ignore). cext takes precedence when
// both carry the key. When no procedure is named the claim is attributable-only (NAALP-REQ-111).
func (o *Object) Recheck() (id uint64, present, critical bool) {
	if v, ok := cextGetUint(o.Cext, RecheckKey); ok {
		return v, true, true
	}
	if v, ok := cextGetUint(o.Ext, RecheckKey); ok {
		return v, true, false
	}
	return 0, false, false
}

// SetRecheck names procID as the body claim's re-check procedure. critical places it in the
// cext map (field 12, must-understand); otherwise the ext map (field 11, may-ignore). It
// creates the carrier if absent and leaves any other extension entries intact.
func (o *Object) SetRecheck(procID uint64, critical bool) {
	entry := cbor.Pair{K: cbor.Uint(RecheckKey), V: cbor.Uint(procID)}
	target := &o.Ext
	if critical {
		target = &o.Cext
	}
	for i := range *target {
		if k, ok := (*target)[i].K.(cbor.Uint); ok && uint64(k) == RecheckKey {
			(*target)[i] = entry
			return
		}
	}
	*target = append(*target, entry)
}

// cextGetUint returns the uint value under key in a CBOR map (ext or cext), reporting present
// only when the key exists AND its value is a uint.
func cextGetUint(m cbor.Map, key uint64) (uint64, bool) {
	for _, p := range m {
		if k, ok := p.K.(cbor.Uint); ok && uint64(k) == key {
			if v, ok := p.V.(cbor.Uint); ok {
				return uint64(v), true
			}
			return 0, false
		}
	}
	return 0, false
}

// CheckAudience enforces the single-use consume binding (design.md §2.5.3). The CONSUMING AUTHORITY
// calls it at the point of use — before the consume CAS — never inside the core object Verify: an
// in-transit relay, ordering authority, or auditor verifies objects addressed to OTHERS, so binding
// this into signature verification would break relaying and receipt issuance. selfAuthority is the
// checking authority's own identity; consumeOnce is true when the object's acceptance spends a
// single-use ledger resource (the consume_once kinds in vectors/registry/channels.csv). Fail-closed:
//   - a consume-once object naming no audience is bound to no authority -> WrongAudience;
//   - an audience naming some X != selfAuthority                        -> WrongAudience;
//   - a non-consume-once object naming no audience is unrestricted      -> nil (a deployment MAY tighten);
//   - an audience equal to selfAuthority                                -> nil.
func CheckAudience(o *Object, selfAuthority string, consumeOnce bool) error {
	if o.Audience == "" {
		if consumeOnce {
			return ErrWrongAudience // required-but-absent: names no consuming authority
		}
		return nil // unrestricted
	}
	if o.Audience != selfAuthority {
		return ErrWrongAudience // names an authority other than this one
	}
	return nil
}

// protectedHeader builds the COSE protected header {1: alg, "naalp": {1:signer, 2:profile,
// 3:version}} as deterministic CBOR.
func protectedHeader(alg int, signer []byte, profile uint64) ([]byte, error) {
	naalp := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(signer)},
		{K: cbor.Uint(2), V: cbor.Uint(profile)},
		{K: cbor.Uint(3), V: cbor.Uint(NaalpVersion)},
	}
	hdr := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Nint(int64(alg))},
		{K: cbor.Tstr(naalpHeaderLabel), V: naalp},
	}
	return cbor.Encode(hdr)
}

// Sign assembles, content-id-binds, and signs a full N-AALP object. The signer's
// algorithm and the object's Signer/Profile fields populate the protected-header copies.
// The signed suite field (14) is set present iff the signer is a composite (§4.2), so a pure
// object omits it and stays byte-identical to a pre-composite object.
func Sign(o *Object, signer cose.Signer) ([]byte, error) {
	if suiteID, ok := compositeSuiteForAlg(signer.Alg()); ok {
		o.Suite = suiteID
	} else {
		o.Suite = 0
	}
	id, err := o.ContentID()
	if err != nil {
		return nil, err
	}
	o.ID = id
	payload, err := cbor.Encode(o.bodyMap(true))
	if err != nil {
		return nil, err
	}
	prot, err := protectedHeader(signer.Alg(), o.Signer, o.Profile)
	if err != nil {
		return nil, err
	}
	tbs, err := cose.ToBeSignedRaw(prot, payload)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(tbs)
	if err != nil {
		return nil, err
	}
	return cose.AssembleSign1Raw(prot, payload, sig)
}

// Verify checks a signed N-AALP object end-to-end, offline, from the object + key + spec
// alone (R-2.4). It returns the decoded Object on success, or the first named failure.
// Check order (fail-closed throughout): decode -> content-id -> field ranges ->
// header/body copies + version -> critical extensions -> kind/channel dispatch ->
// profile floor -> signature.
func Verify(profile int, v cose.Verifier, kindOK KindValidator, knownCext map[uint64]bool, obj []byte) (*Object, error) {
	// Object octet-size bound (§3.4, R7): reject an oversized signed object on the raw
	// bytes, before any parse (RFC 8949 §10 decoder-memory guard).
	if len(obj) > MaxObjectSize {
		return nil, ErrTooLarge
	}
	prot, payload, sig, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return nil, ErrMalformed
	}
	o, alg, err := decodeAndCheck(prot, payload, knownCext)
	if err != nil {
		return nil, err
	}

	// A Rotation object (Identity channel, kind 0) MUST be a tag-98 COSE_Sign co-signed by the
	// old AND new key (§5.2); a single-Sign1 rotation is missing the old-key co-signature, so it
	// is rejected here (RotationUnauthorized) rather than accepted on the new key alone. This is
	// the #143 STRENGTHENING; the co-signed path is VerifyRotationObject (rotation.go).
	if isRotationObject(o.Channel, o.Kind) {
		return nil, ErrRotationUnauthorized
	}

	// kind/channel surface dispatch (UnknownKind, §2.6).
	if kindOK == nil || !kindOK(o.Channel, o.Kind) {
		return nil, ErrUnknownKind
	}

	// profile floor + signed suite declaration + COSE signature (reuse the C2 registry).
	level, known := cose.AlgLevel(alg)
	if !known {
		return nil, cose.ErrUnknownAlg
	}
	tbs, err := cose.ToBeSignedRaw(prot, payload)
	if err != nil {
		return nil, err
	}

	if alg == cose.AlgComposite65Ed25519 {
		// Opt-in composite path (§4.2/§4.4/§4.5). Check order: CompositeRefused (Sovereign) ->
		// SuiteMismatch (field 14 must declare the matching suite) -> ProfileDowngrade ->
		// KeyAlgMismatch (a composite verifier is required) -> both-leg signature.
		if profile == cose.ProfileSovereign {
			return nil, cose.ErrCompositeRefused
		}
		if o.Suite != SuiteMLDSA65Ed25519 {
			return nil, cose.ErrSuiteMismatch
		}
		if level < cose.ProfileMinLevel(profile) {
			return nil, cose.ErrProfileDowngrade
		}
		if alg != v.Alg() {
			return nil, cose.ErrKeyAlgMismatch
		}
		cv, ok := v.(cose.CompositeVerifier)
		if !ok {
			return nil, cose.ErrKeyAlgMismatch // composite alg requires a composite verifier
		}
		if err := cose.VerifyComposite(cv, tbs, sig); err != nil {
			return nil, err // HybridIncomplete (single-leg failure) or Malformed (structural)
		}
		return o, nil
	}

	// pure path: a non-composite alg MUST NOT carry the signed suite field (§4.2).
	if o.Suite != 0 {
		return nil, cose.ErrSuiteMismatch
	}
	if level < cose.ProfileMinLevel(profile) {
		return nil, cose.ErrProfileDowngrade
	}
	if alg != v.Alg() {
		return nil, cose.ErrKeyAlgMismatch
	}
	if !v.VerifyRaw(tbs, sig) {
		return nil, cose.ErrBadSignature
	}
	return o, nil
}

// decodeAndCheck runs the tag-agnostic object checks over a (protected, payload) pair and
// returns the decoded Object and its header alg: decode (NonCanonical surfaced) -> content-id ->
// field ranges -> header/body copies + version -> critical extensions. It does NOT do the
// kind/channel dispatch or the signature (those are tag-specific). The tag-18 Verify and the
// tag-98 rotation path (rotation.go) both call it, so the two never drift on these checks.
func decodeAndCheck(prot, payload []byte, knownCext map[uint64]bool) (*Object, int, error) {
	bv, err := cbor.DecodeBounded(payload, MaxNestingDepth) // non-canonical -> NonCanonical (§2.6); over-nested -> DepthExceeded (§3.4, R7)
	if err != nil {
		if ce, ok := err.(*cbor.Error); ok { // surface the codec's Kind as a cose.Error
			return nil, 0, &cose.Error{Kind: ce.Kind, Msg: ce.Msg}
		}
		return nil, 0, ErrMalformed
	}
	bodyMap, ok := bv.(cbor.Map)
	if !ok {
		return nil, 0, ErrMalformed
	}

	// content-id: recompute over the body without field 1 and compare to the claimed id.
	var claimedID []byte
	withoutID := make(cbor.Map, 0, len(bodyMap))
	for _, p := range bodyMap {
		if k, ok := p.K.(cbor.Uint); ok && k == FieldID {
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return nil, 0, ErrMalformed
			}
			claimedID = []byte(b)
			continue
		}
		withoutID = append(withoutID, p)
	}
	if claimedID == nil {
		return nil, 0, ErrMalformed
	}
	recomputed, err := cbor.ContentID(withoutID)
	if err != nil {
		return nil, 0, err
	}
	if !bytes.Equal(recomputed, claimedID) {
		return nil, 0, ErrContentIDMismatch
	}

	o, err := objectFromMap(bodyMap)
	if err != nil {
		return nil, 0, err
	}

	// field ranges (RangeError, §3.3 / R-3.3): channel 0..19, effect 0..3, profile 1..3.
	if o.Channel > 19 || o.Effect > 3 || o.Profile < 1 || o.Profile > 3 {
		return nil, 0, ErrRangeError
	}

	// protected-header copies vs body (HeaderBodyMismatch, §2.1) + version.
	alg, hSigner, hProfile, hVersion, err := parseProtected(prot)
	if err != nil {
		return nil, 0, err
	}
	if hVersion != NaalpVersion {
		return nil, 0, ErrUnsupportedVersion
	}
	if !bytes.Equal(hSigner, o.Signer) || hProfile != o.Profile {
		return nil, 0, ErrHeaderBodyMismatch
	}

	// critical extensions: any unrecognized key rejects (§2.5, R-2.5). RecheckKey (13) is an
	// envelope-recognized critical key: a critical recheck naming an UNKNOWN procedure id is
	// rejected fail-closed (the critical-extension rule reaching the procedure it names, T1.3);
	// a known procedure id is recognized. A NON-critical recheck (ext, field 11) is never
	// rejected here — an unknown non-critical procedure is ignored per the may-ignore rule.
	if o.Cext != nil {
		for _, p := range o.Cext {
			k, ok := p.K.(cbor.Uint)
			if !ok {
				return nil, 0, ErrUnknownCriticalExt
			}
			if uint64(k) == RecheckKey {
				id, ok := p.V.(cbor.Uint)
				if !ok {
					return nil, 0, ErrMalformed
				}
				if !IsKnownRecheckProcedure(uint64(id)) {
					return nil, 0, ErrUnknownCriticalExt
				}
				continue
			}
			if !knownCext[uint64(k)] {
				return nil, 0, ErrUnknownCriticalExt
			}
		}
	}
	return o, alg, nil
}

// objectFromMap reads the fixed body fields (1..12) into an Object. Unknown top-level
// field numbers or wrong field types are Malformed; extension carriers are fields 11/12.
func objectFromMap(m cbor.Map) (*Object, error) {
	o := &Object{}
	var haveKind, haveChan, haveTier, haveSigner, haveCreated, haveEffect, haveCauses, haveProfile, haveBody bool
	for _, p := range m {
		k, ok := p.K.(cbor.Uint)
		if !ok {
			return nil, ErrMalformed
		}
		switch k {
		case FieldID:
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return nil, ErrMalformed
			}
			o.ID = []byte(b)
		case FieldKind:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return nil, ErrMalformed
			}
			o.Kind = uint64(u)
			haveKind = true
		case FieldChannel:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return nil, ErrMalformed
			}
			o.Channel = uint64(u)
			haveChan = true
		case FieldTier:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return nil, ErrMalformed
			}
			o.Tier = uint64(u)
			haveTier = true
		case FieldSigner:
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return nil, ErrMalformed
			}
			o.Signer = []byte(b)
			haveSigner = true
		case FieldCreated:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return nil, ErrMalformed
			}
			o.Created = uint64(u)
			haveCreated = true
		case FieldEffect:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return nil, ErrMalformed
			}
			o.Effect = uint64(u)
			haveEffect = true
		case FieldCauses:
			a, ok := p.V.(cbor.Arr)
			if !ok {
				return nil, ErrMalformed
			}
			if len(a) > MaxCauses { // causal fan-in bound (§3.4, R7)
				return nil, ErrTooManyCauses
			}
			for _, it := range a {
				b, ok := it.(cbor.Bstr)
				if !ok {
					return nil, ErrMalformed
				}
				o.Causes = append(o.Causes, []byte(b))
			}
			haveCauses = true
		case FieldProfile:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return nil, ErrMalformed
			}
			o.Profile = uint64(u)
			haveProfile = true
		case FieldBody:
			o.Body = p.V
			haveBody = true
		case FieldExt:
			mm, ok := p.V.(cbor.Map)
			if !ok {
				return nil, ErrMalformed
			}
			if len(mm) > MaxExt { // ext cardinality bound (§3.4, R7)
				return nil, ErrTooManyExtensions
			}
			o.Ext = mm
		case FieldCext:
			mm, ok := p.V.(cbor.Map)
			if !ok {
				return nil, ErrMalformed
			}
			if len(mm) > MaxCext { // cext cardinality bound (§3.4, R7)
				return nil, ErrTooManyExtensions
			}
			o.Cext = mm
		case FieldAudience:
			s, ok := p.V.(cbor.Tstr)
			if !ok {
				return nil, ErrMalformed
			}
			o.Audience = string(s)
		case FieldSuite:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return nil, ErrMalformed
			}
			o.Suite = uint64(u)
		default:
			return nil, ErrMalformed // unknown top-level field
		}
	}
	if !(haveKind && haveChan && haveTier && haveSigner && haveCreated && haveEffect && haveCauses && haveProfile && haveBody) {
		return nil, ErrMalformed
	}
	return o, nil
}

// parseProtected reads {1: alg, "naalp": {1:signer, 2:profile, 3:version}} from a
// serialized protected header.
func parseProtected(prot []byte) (alg int, signer []byte, profile, version uint64, err error) {
	// §3.1.1 (R5): the empty protected header is pinned to 0x40; a byte string wrapping an
	// empty CBOR map (the 0x41A0 form — its unwrapped content is the single byte 0xA0) is the
	// one redundant encoding RFC 9052 §3 otherwise permits, and MUST be rejected as
	// NonCanonical before the header is interpreted (otherwise it dies downstream as a generic
	// Malformed / no-alg, losing the determinism verdict).
	if len(prot) == 1 && prot[0] == 0xA0 {
		return 0, nil, 0, 0, ErrNonCanonical
	}
	pv, e := cbor.Decode(prot)
	if e != nil {
		return 0, nil, 0, 0, ErrMalformed
	}
	m, ok := pv.(cbor.Map)
	if !ok {
		return 0, nil, 0, 0, ErrMalformed
	}
	var haveAlg, haveNaalp bool
	for _, p := range m {
		switch k := p.K.(type) {
		case cbor.Uint:
			if k == 1 {
				a, ok := p.V.(cbor.Nint)
				if !ok {
					return 0, nil, 0, 0, ErrMalformed
				}
				alg = int(a)
				haveAlg = true
			}
		case cbor.Tstr:
			if string(k) == naalpHeaderLabel {
				nm, ok := p.V.(cbor.Map)
				if !ok {
					return 0, nil, 0, 0, ErrMalformed
				}
				for _, np := range nm {
					nk, ok := np.K.(cbor.Uint)
					if !ok {
						continue
					}
					switch nk {
					case 1:
						if s, ok := np.V.(cbor.Bstr); ok {
							signer = []byte(s)
						}
					case 2:
						if pr, ok := np.V.(cbor.Uint); ok {
							profile = uint64(pr)
						}
					case 3:
						if vv, ok := np.V.(cbor.Uint); ok {
							version = uint64(vv)
						}
					}
				}
				haveNaalp = true
			}
		}
	}
	if !haveAlg || !haveNaalp {
		return 0, nil, 0, 0, ErrMalformed
	}
	return alg, signer, profile, version, nil
}
