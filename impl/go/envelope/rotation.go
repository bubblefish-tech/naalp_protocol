// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package envelope

import (
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// A Rotation object (design.md §5.2) is the ONE object carried as a COSE_Sign (tag 98): a
// signed rotation statement co-signed by BOTH the old and the new key. Every other kind is a
// single COSE_Sign1 (tag 18). The single-Sign1 rotation gap (a rotation accepted on the new
// key alone) is closed by rejecting a tag-18 Rotation object in Verify (RotationUnauthorized)
// and requiring the old+new co-signature here. Reuses the existing RotationUnauthorized kind.

// ErrRotationUnauthorized reports a rotation that is not co-signed by the old key: a tag-18
// (single-signature) Rotation object, a tag-98 object without exactly the old-then-new legs, or
// a leg whose signature or key does not verify (§5.2, §5.5).
var ErrRotationUnauthorized = &cose.Error{Kind: "RotationUnauthorized", Msg: "rotation object not co-signed by the old key"}

// isRotationObject reports whether (channel, kind) selects the Identity-channel Rotation object
// (channel 0x0003, kind 0; vectors/registry/channels.csv, design.md §5.2), which MUST be a
// tag-98 COSE_Sign carrying the old+new co-signature — never a single-Sign1.
func isRotationObject(channel, kind uint64) bool { return channel == 3 && kind == 0 }

// isCompositeAlg reports whether alg is a composite (LAMPS) signature alg. Composite legs are
// undecided inside a rotation's old/new co-signature, so they are rejected fail-closed.
func isCompositeAlg(alg int) bool {
	return alg == cose.AlgComposite65Ed25519 || alg == cose.AlgComposite44Ed25519
}

// rotationOldLegFloorApplies is the OPEN-DECISION toggle (design.md §4.4 profile floor applied
// to a rotation): when a Sovereign/High verifier checks a rotation whose OLD (authorizing) key
// is below the profile's signature floor, does the floor gate the OLD leg too, or only the NEW
// (go-forward) leg? DEFAULT = FAIL-CLOSED: the floor applies to BOTH legs, so an old leg below
// the floor is a ProfileDowngrade. Set false to floor only the new (go-forward) leg. This is a
// single, clearly-marked compile-time toggle awaiting the maintainer's ruling.
const rotationOldLegFloorApplies = true

// SignRotation builds a Rotation object as a tag-98 COSE_Sign co-signed by the OLD then the NEW
// key in fixed order (design.md §5.2). Each leg signs the per-signer COSE_Signature ToBeSigned
// over the full object payload; the body protected header names the NEW (go-forward) key's alg
// plus the routing signer/profile/version copies, so a verifier reuses the same content-id,
// header/body, and version checks as a tag-18 object. It is permitted ONLY for the
// Identity-channel Rotation object (channel 3, kind 0); any other (channel, kind) is UnknownKind.
// A composite signer for either leg is rejected fail-closed (Malformed) — composite-inside-
// rotation is an undecided combination.
func SignRotation(o *Object, oldSigner, newSigner cose.Signer) ([]byte, error) {
	if !isRotationObject(o.Channel, o.Kind) {
		return nil, ErrUnknownKind
	}
	if isCompositeAlg(oldSigner.Alg()) || isCompositeAlg(newSigner.Alg()) {
		return nil, ErrMalformed
	}
	o.Suite = 0 // a rotation object is never composite
	id, err := o.ContentID()
	if err != nil {
		return nil, err
	}
	o.ID = id
	payload, err := cbor.Encode(o.bodyMap(true))
	if err != nil {
		return nil, err
	}
	bodyProt, err := protectedHeader(newSigner.Alg(), o.Signer, o.Profile)
	if err != nil {
		return nil, err
	}
	oldLeg, err := cose.SignatureLeg(bodyProt, oldSigner, payload)
	if err != nil {
		return nil, err
	}
	newLeg, err := cose.SignatureLeg(bodyProt, newSigner, payload)
	if err != nil {
		return nil, err
	}
	return cose.AssembleSignRaw(bodyProt, payload, []cose.CoseSignLeg{oldLeg, newLeg})
}

// VerifyRotationObject verifies a tag-98 Rotation object (design.md §5.2): the same object-body
// checks as Verify (content-id, ranges, header/body copies, version, critical extensions, kind
// dispatch), then EXACTLY two legs in fixed order (old-key then new-key) BOTH verifying over the
// object payload. Any missing/wrong/bad old leg is RotationUnauthorized — the old-key-mandatory
// semantics of identity.VerifyRotation. oldV is the verifier's trusted old key; newV is the
// object's go-forward key; both are supplied by the caller (the record-id<->key binding stays
// the identity layer's job, consistent with the pure Verify path). Permitted ONLY for (3, 0).
func VerifyRotationObject(profile int, oldV, newV cose.Verifier, kindOK KindValidator, knownCext map[uint64]bool, obj []byte) (*Object, error) {
	// Object octet-size bound (§3.4, R7): the tag-98 rotation object is a top-level
	// signed object too, so it is size-checked on raw bytes before any parse.
	if len(obj) > MaxObjectSize {
		return nil, ErrTooLarge
	}
	bodyProt, payload, legs, err := cose.ParseSignRaw(obj)
	if err != nil {
		return nil, ErrMalformed
	}
	o, alg, err := decodeAndCheck(bodyProt, payload, knownCext)
	if err != nil {
		return nil, err
	}
	// tag-98 is permitted ONLY for the Identity-channel Rotation object (channel 3, kind 0).
	if !isRotationObject(o.Channel, o.Kind) {
		return nil, ErrUnknownKind
	}
	if kindOK == nil || !kindOK(o.Channel, o.Kind) {
		return nil, ErrUnknownKind
	}
	// the body protected header names the NEW (go-forward) key (design.md §5.2).
	if isCompositeAlg(alg) {
		return nil, ErrMalformed // composite-inside-rotation is undecided; fail-closed
	}
	if alg != newV.Alg() {
		return nil, cose.ErrKeyAlgMismatch
	}

	// EXACTLY two legs, fixed order (old, new). A missing/lone leg IS "old leg dropped".
	if len(legs) != 2 {
		return nil, ErrRotationUnauthorized
	}
	oldAlg, err := cose.AlgFromProtected(legs[0].Protected)
	if err != nil {
		return nil, ErrMalformed
	}
	newAlg, err := cose.AlgFromProtected(legs[1].Protected)
	if err != nil {
		return nil, ErrMalformed
	}
	if isCompositeAlg(oldAlg) || isCompositeAlg(newAlg) {
		return nil, ErrMalformed
	}
	// legs MUST be in (old, new) order for the caller's trusted old key and the object's new key.
	if oldAlg != oldV.Alg() || newAlg != newV.Alg() {
		return nil, ErrRotationUnauthorized
	}

	// profile floor: the NEW (go-forward) leg always meets the floor; the OLD (authorizing) leg
	// iff the fail-closed toggle applies (the OPEN DECISION, rotationOldLegFloorApplies).
	newLevel, known := cose.AlgLevel(newAlg)
	if !known {
		return nil, cose.ErrUnknownAlg
	}
	if newLevel < cose.ProfileMinLevel(profile) {
		return nil, cose.ErrProfileDowngrade
	}
	if rotationOldLegFloorApplies {
		oldLevel, known := cose.AlgLevel(oldAlg)
		if !known {
			return nil, cose.ErrUnknownAlg
		}
		if oldLevel < cose.ProfileMinLevel(profile) {
			return nil, cose.ErrProfileDowngrade
		}
	}

	// both legs MUST verify over the per-signer ToBeSigned; any missing/wrong/bad leg is
	// RotationUnauthorized (the old-key-mandatory semantics of identity.VerifyRotation, §5.2/§5.5).
	oldTbs, err := cose.SignatureToBeSigned(bodyProt, oldAlg, payload)
	if err != nil {
		return nil, err
	}
	if !oldV.VerifyRaw(oldTbs, legs[0].Sig) {
		return nil, ErrRotationUnauthorized
	}
	newTbs, err := cose.SignatureToBeSigned(bodyProt, newAlg, payload)
	if err != nil {
		return nil, err
	}
	if !newV.VerifyRaw(newTbs, legs[1].Sig) {
		return nil, ErrRotationUnauthorized
	}
	return o, nil
}
