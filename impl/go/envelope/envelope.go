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

// Object body field numbers (design.md §2.1).
const (
	FieldID      = 1
	FieldKind    = 2
	FieldChannel = 3
	FieldTier    = 4
	FieldSigner  = 5
	FieldCreated = 6
	FieldEffect  = 7
	FieldCauses  = 8
	FieldProfile = 9
	FieldBody    = 10
	FieldExt     = 11
	FieldCext    = 12
)

// NaalpVersion is the protected-header naalp-version (design.md §2.5).
const NaalpVersion = 1

// naalpHeaderLabel is the COSE protected-header parameter (a text-string label, which
// cannot collide with any integer-labeled standard COSE parameter, RFC 9052 §3.1) under
// which N-AALP carries its routing copies {1:signer, 2:profile, 3:version}.
const naalpHeaderLabel = "naalp"

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
)

// Object is a decoded N-AALP object body. ID is set by Sign (content id §2.3).
type Object struct {
	ID      []byte
	Kind    uint64
	Channel uint64
	Tier    uint64
	Signer  []byte
	Created uint64
	Effect  uint64
	Causes  [][]byte
	Profile uint64
	Body    cbor.Value
	Ext     cbor.Map // optional non-critical extensions (field 11); nil = absent
	Cext    cbor.Map // optional critical extensions (field 12); nil = absent
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
	return m
}

// ContentID computes the object content id over the body without field 1 (design.md §2.3).
func (o *Object) ContentID() ([]byte, error) {
	return cbor.ContentID(o.bodyMap(false))
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
func Sign(o *Object, signer cose.Signer) ([]byte, error) {
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
	prot, payload, sig, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return nil, ErrMalformed
	}
	bv, err := cbor.Decode(payload) // rejects non-canonical CBOR (NonCanonical, §2.6)
	if err != nil {
		if ce, ok := err.(*cbor.Error); ok { // surface the codec's Kind as a cose.Error
			return nil, &cose.Error{Kind: ce.Kind, Msg: ce.Msg}
		}
		return nil, ErrMalformed
	}
	bodyMap, ok := bv.(cbor.Map)
	if !ok {
		return nil, ErrMalformed
	}

	// content-id: recompute over the body without field 1 and compare to the claimed id.
	var claimedID []byte
	withoutID := make(cbor.Map, 0, len(bodyMap))
	for _, p := range bodyMap {
		if k, ok := p.K.(cbor.Uint); ok && k == FieldID {
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return nil, ErrMalformed
			}
			claimedID = []byte(b)
			continue
		}
		withoutID = append(withoutID, p)
	}
	if claimedID == nil {
		return nil, ErrMalformed
	}
	recomputed, err := cbor.ContentID(withoutID)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(recomputed, claimedID) {
		return nil, ErrContentIDMismatch
	}

	o, err := objectFromMap(bodyMap)
	if err != nil {
		return nil, err
	}

	// field ranges (RangeError, §3.3 / R-3.3): channel 0..19, effect 0..3, profile 1..3.
	if o.Channel > 19 || o.Effect > 3 || o.Profile < 1 || o.Profile > 3 {
		return nil, ErrRangeError
	}

	// protected-header copies vs body (HeaderBodyMismatch, §2.1) + version.
	alg, hSigner, hProfile, hVersion, err := parseProtected(prot)
	if err != nil {
		return nil, err
	}
	if hVersion != NaalpVersion {
		return nil, ErrUnsupportedVersion
	}
	if !bytes.Equal(hSigner, o.Signer) || hProfile != o.Profile {
		return nil, ErrHeaderBodyMismatch
	}

	// critical extensions: any unrecognized key rejects (§2.5, R-2.5).
	if o.Cext != nil {
		for _, p := range o.Cext {
			k, ok := p.K.(cbor.Uint)
			if !ok || !knownCext[uint64(k)] {
				return nil, ErrUnknownCriticalExt
			}
		}
	}

	// kind/channel surface dispatch (UnknownKind, §2.6).
	if kindOK == nil || !kindOK(o.Channel, o.Kind) {
		return nil, ErrUnknownKind
	}

	// profile floor + COSE signature (reuse the C2 registry + verifier).
	level, known := cose.AlgLevel(alg)
	if !known {
		return nil, cose.ErrUnknownAlg
	}
	if level < cose.ProfileMinLevel(profile) {
		return nil, cose.ErrProfileDowngrade
	}
	if alg != v.Alg() {
		return nil, cose.ErrKeyAlgMismatch
	}
	tbs, err := cose.ToBeSignedRaw(prot, payload)
	if err != nil {
		return nil, err
	}
	if !v.VerifyRaw(tbs, sig) {
		return nil, cose.ErrBadSignature
	}
	return o, nil
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
			o.Ext = mm
		case FieldCext:
			mm, ok := p.V.(cbor.Map)
			if !ok {
				return nil, ErrMalformed
			}
			o.Cext = mm
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
