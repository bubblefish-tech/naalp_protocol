// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package identity implements N-AALP's C4 identity and key lifecycle (design.md §5): the
// self-certifying signer id (identical in form to the N-PAMP PeerHandle), key rotation
// (co-signed old+new), revocation (distinct from rotation), and foreign-identity linkage.
//
// The signer id is a pure function of the public signing key:
//
//	signer = multibase(base32, multihash(0x12, SHA-256(multicodec(mc, pubkey))))
//
// where mc is the multiformats multicodec key-type code (ed25519-pub 0xed, mldsa-65-pub
// 0x1211, mldsa-87-pub 0x1212). A verifier recomputes the id from the key and rejects a
// mismatch (R-5.1); no CA. The rotation/revocation/foreign-link records are signed with
// the C2 crypto primitives over deterministic-CBOR bodies; wrapping them as Identity-
// channel (0x0003) objects is the T12 surface's job. Every failure is fail-closed.
package identity

import (
	"crypto/sha256"
	"encoding/base32"

	"github.com/bubblefish-tech/n-aalp/impl/go/cbor"
	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
	"golang.org/x/text/unicode/norm"
)

// Multicodec key-type codes and the sha2-256 multihash code (multiformats registry).
const (
	codeEd25519 = 0xED
	codeMLDSA65 = 0x1211
	codeMLDSA87 = 0x1212
	mhSHA256    = 0x12
)

// multibaseBase32 is RFC 4648 base32, lowercase, no padding (multibase prefix 'b').
var multibaseBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var (
	ErrSignerMismatch       = &cose.Error{Kind: "SignerMismatch", Msg: "signer id does not equal the recomputed id"}
	ErrRotationUnauthorized = &cose.Error{Kind: "RotationUnauthorized", Msg: "rotation not co-signed by the old key"}
	ErrKeyRevoked           = &cose.Error{Kind: "KeyRevoked", Msg: "object position is after the key's revocation"}
	ErrNonNFC               = &cose.Error{Kind: "NonNFC", Msg: "identity/scope string is not Unicode NFC"}
	ErrUnknownAlg           = &cose.Error{Kind: "UnknownAlg", Msg: "no multicodec for the algorithm"}
)

// multicodecFor maps a COSE alg id to its multiformats multicodec key-type code.
func multicodecFor(alg int) (uint64, bool) {
	switch alg {
	case cose.AlgEd25519:
		return codeEd25519, true
	case cose.AlgMLDSA65:
		return codeMLDSA65, true
	case cose.AlgMLDSA87:
		return codeMLDSA87, true
	default:
		return 0, false
	}
}

// uvarint encodes n as an unsigned LEB128 varint (multiformats varint).
func uvarint(n uint64) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, b|0x80)
		} else {
			return append(out, b)
		}
	}
}

// SignerID derives the self-certifying signer id for a public key (design.md §5.1).
func SignerID(alg int, pubkey []byte) (string, error) {
	mc, ok := multicodecFor(alg)
	if !ok {
		return "", ErrUnknownAlg
	}
	tagged := append(uvarint(mc), pubkey...)
	digest := sha256.Sum256(tagged)
	mh := uvarint(mhSHA256)                    // sha2-256 multihash code (0x12)
	mh = append(mh, uvarint(uint64(len(digest)))...) // length (0x20 = 32)
	mh = append(mh, digest[:]...)
	return "b" + multibaseBase32.EncodeToString(mh), nil
}

// CheckSigner recomputes the id from the key and rejects a mismatch (R-5.1).
func CheckSigner(claimed string, alg int, pubkey []byte) error {
	got, err := SignerID(alg, pubkey)
	if err != nil {
		return err
	}
	if got != claimed {
		return ErrSignerMismatch
	}
	return nil
}

// RequireNFC rejects a text string that names an identity/resource/scope and is not in
// Unicode NFC form (design.md §3.1, R-3.3).
func RequireNFC(s string) error {
	if !norm.NFC.IsNormalString(s) {
		return ErrNonNFC
	}
	return nil
}

// ---- key lifecycle (design.md §5.2-§5.4) ---------------------------------------------

// RotationRecord links an old signer id to a new one from NotBefore (§5.2). Its signed
// bytes are the deterministic-CBOR map {1:old, 2:new, 3:not_before}.
type RotationRecord struct {
	Old       string
	New       string
	NotBefore uint64
}

func (r RotationRecord) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr(r.Old)},
		{K: cbor.Uint(2), V: cbor.Tstr(r.New)},
		{K: cbor.Uint(3), V: cbor.Uint(r.NotBefore)},
	})
	return b
}

// SignRotation co-signs a rotation with BOTH the old and new keys (§5.2).
func SignRotation(r RotationRecord, oldSigner, newSigner cose.Signer) (oldSig, newSig []byte, err error) {
	m := r.Bytes()
	oldSig, err = oldSigner.Sign(m)
	if err != nil {
		return nil, nil, err
	}
	newSig, err = newSigner.Sign(m)
	if err != nil {
		return nil, nil, err
	}
	return oldSig, newSig, nil
}

// VerifyRotation confirms a rotation is authorized: the old and new keys derive the ids
// in the record, and BOTH signatures verify. A substitution not co-signed by the old key
// is RotationUnauthorized (§5.2, §5.5).
func VerifyRotation(r RotationRecord, oldV, newV cose.Verifier, oldPub, newPub, oldSig, newSig []byte) error {
	if err := CheckSigner(r.Old, oldV.Alg(), oldPub); err != nil {
		return ErrRotationUnauthorized
	}
	if err := CheckSigner(r.New, newV.Alg(), newPub); err != nil {
		return ErrRotationUnauthorized
	}
	m := r.Bytes()
	if !oldV.VerifyRaw(m, oldSig) || !newV.VerifyRaw(m, newSig) {
		return ErrRotationUnauthorized
	}
	return nil
}

// RevocationRecord marks a key dead from NotAfter (§5.3). Signed bytes: {1:key, 2:not_after}.
type RevocationRecord struct {
	Key      string
	NotAfter uint64
}

func (r RevocationRecord) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr(r.Key)},
		{K: cbor.Uint(2), V: cbor.Uint(r.NotAfter)},
	})
	return b
}

// VerifyRevocation confirms the revocation is signed by the key it revokes (or a
// deployer recovery key, out of scope here).
func VerifyRevocation(r RevocationRecord, v cose.Verifier, pub, sig []byte) error {
	if err := CheckSigner(r.Key, v.Alg(), pub); err != nil {
		return err
	}
	if !v.VerifyRaw(r.Bytes(), sig) {
		return cose.ErrBadSignature
	}
	return nil
}

// RevokedAt reports whether an object fixed at authoritative position `posTime` is after
// the revocation (KeyRevoked); objects fixed at or before NotAfter stay valid (§5.3).
func RevokedAt(r RevocationRecord, posTime uint64) bool {
	return posTime > r.NotAfter
}

// ForeignLinkRecord cross-signs a foreign identity to a signer id (§5.4). Signed bytes:
// {1:controls, 2:foreign_id, 3:not_after}. It is signed by the FOREIGN identity's key.
type ForeignLinkRecord struct {
	Controls  string
	ForeignID string
	NotAfter  uint64
}

func (r ForeignLinkRecord) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr(r.Controls)},
		{K: cbor.Uint(2), V: cbor.Tstr(r.ForeignID)},
		{K: cbor.Uint(3), V: cbor.Uint(r.NotAfter)},
	})
	return b
}

// VerifyForeignLink reports whether a foreign-identity link confers linkage at time `now`.
// A non-NFC foreign_id is rejected (NonNFC). An expired link or a bad cross-signature
// confers NO linkage but is not itself an error — it simply does not link (the object
// remains valid on its own signature, §5.4/§5.5). It NEVER overrides the key-derived id.
func VerifyForeignLink(r ForeignLinkRecord, foreignV cose.Verifier, foreignPub, sig []byte, now uint64) (linked bool, err error) {
	if e := RequireNFC(r.ForeignID); e != nil {
		return false, e
	}
	if now > r.NotAfter {
		return false, nil // expired: confers no authority (ignored)
	}
	if !foreignV.VerifyRaw(r.Bytes(), sig) {
		return false, nil // bad/absent cross-signature: no linkage
	}
	return true, nil
}

// ---- durable identity thread (rotation-surviving attribution, R-1.4) -----------------

// Thread is a durable identity: a root signer id continued by a chain of rotations.
type Thread struct {
	Root    string   // the id the thread is named by (the first key)
	Current string   // the id after the latest rotation
	Chain   []string // root, then each rotated-to id in order
}

// RotationEvidence is one verified rotation step: the record plus the two keys and their
// co-signatures.
type RotationEvidence struct {
	Record         RotationRecord
	OldV, NewV     cose.Verifier
	OldPub, NewPub []byte
	OldSig, NewSig []byte
}

// ResolveThread verifies an ordered rotation chain and returns the durable identity
// thread. Each rotation must be authorized (co-signed) and link the previous `new` to the
// next `old`; a break yields RotationUnauthorized. A receipt signed under any id in Chain
// is attributable to Root, so it stays attributable after rotation (R-1.4).
func ResolveThread(evs []RotationEvidence) (*Thread, error) {
	if len(evs) == 0 {
		return nil, ErrRotationUnauthorized
	}
	t := &Thread{Root: evs[0].Record.Old, Chain: []string{evs[0].Record.Old}}
	prevNew := evs[0].Record.Old
	for _, e := range evs {
		if e.Record.Old != prevNew {
			return nil, ErrRotationUnauthorized // chain not contiguous
		}
		if err := VerifyRotation(e.Record, e.OldV, e.NewV, e.OldPub, e.NewPub, e.OldSig, e.NewSig); err != nil {
			return nil, err
		}
		t.Chain = append(t.Chain, e.Record.New)
		prevNew = e.Record.New
	}
	t.Current = prevNew
	return t, nil
}

// Attributable reports whether an object whose body signer id is `signer` belongs to this
// durable thread (any id in the chain, including a pre-rotation key, R-1.4).
func (t *Thread) Attributable(signer string) bool {
	for _, id := range t.Chain {
		if id == signer {
			return true
		}
	}
	return false
}
