// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package naalp is a thin, idiomatic convenience layer over the N-AALP reference SDK. It
// collapses the two common developer paths — sign an object, verify an object — to one
// well-named call each, and it delegates every cryptographic and encoding step to the
// underlying spine packages: key generation and signing to cose + Cloudflare CIRCL ML-DSA-65,
// the self-certifying signer id to identity, the deterministic object encoding + signature to
// envelope, and the (channel, kind) admission and declared-effect binding to channels. It
// introduces no new object encoding and no new signature construction; it composes the same
// primitives the graded conformance corpus covers.
//
// The layer fixes the two choices most callers do not want to make by hand:
//   - the signature suite is deterministic ML-DSA-65 (FIPS 204, rnd=0) at the Public profile;
//   - an object's effect (envelope field 7) is taken from the (channel, kind)'s declared
//     effect in the frozen channel registry, so a signed object is valid at the surface layer
//     as well as the spine layer.
//
// Verify is strictly stronger than a raw envelope.Verify: on success it additionally rebinds
// the object's self-certifying signer id to the public key the signature was actually checked
// against (closing the confused-deputy gap, design.md §21.4) and confirms the object's effect
// equals the kind's declared effect (R-11.2). Every failure is fail-closed with the spine's
// named error and no partial result.
package naalp

import (
	"crypto/rand"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// DefaultProfile is the crypto profile this layer signs at and verifies against: Public,
// whose floor is a post-quantum level-3 signature (design.md §4.4). ML-DSA-65 is level 3, so
// it satisfies Public and Enterprise; the Sovereign profile requires ML-DSA-87 and is reached
// through the cose/envelope packages directly.
const DefaultProfile = cose.ProfilePublic

// ErrSeedSize is returned when a caller-supplied seed is not exactly mldsa65.SeedSize bytes.
var ErrSeedSize = &cose.Error{Kind: "SeedSize", Msg: "ML-DSA-65 seed must be 32 bytes"}

// ErrKeyMalformed is returned by Verify when the supplied public key is not a valid packed
// ML-DSA-65 public key (wrong length or unparseable), rejected before any signature check.
var ErrKeyMalformed = &cose.Error{Kind: "KeyMalformed", Msg: "public key is not a valid ML-DSA-65 public key"}

// Signer holds a deterministic ML-DSA-65 signing key and its derived self-certifying signer
// id. It signs N-AALP objects at the Public profile.
type Signer struct {
	sk *mldsa65.PrivateKey
	pk *mldsa65.PublicKey
	id string
}

// NewSigner builds a Signer from a 32-byte ML-DSA-65 seed and derives its self-certifying
// signer id from the public key (identity.SignerID). A seed of the wrong length is rejected
// (ErrSeedSize) — no key is created.
func NewSigner(seed []byte) (*Signer, error) {
	if len(seed) != mldsa65.SeedSize {
		return nil, ErrSeedSize
	}
	var s [mldsa65.SeedSize]byte
	copy(s[:], seed)
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	id, err := identity.SignerID(cose.AlgMLDSA65, pk.Bytes())
	if err != nil {
		return nil, err
	}
	return &Signer{sk: sk, pk: pk, id: id}, nil
}

// GenerateSigner creates a fresh ML-DSA-65 identity from a cryptographically random 32-byte
// seed read from crypto/rand.
func GenerateSigner() (*Signer, error) {
	seed := make([]byte, mldsa65.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return NewSigner(seed)
}

// SignerID returns the signer's self-certifying id — a pure function of the public key
// (design.md §5.1). A verifier recomputes it from the key and rejects a mismatch.
func (s *Signer) SignerID() string { return s.id }

// PublicKey returns the raw packed ML-DSA-65 public-key bytes to hand to a verifier. This is
// the only key material a verifier needs; N-AALP verification is offline.
func (s *Signer) PublicKey() []byte { return s.pk.Bytes() }

// Sign builds, content-id-binds, and signs an N-AALP object on (channel, kind) carrying
// payload, timestamped with created (unix milliseconds). The object's effect is taken from the
// (channel, kind)'s declared effect in the frozen channel registry; an unregistered (channel,
// kind) is rejected (envelope.ErrUnknownKind) before any signing work. It returns the tagged
// COSE_Sign1 object bytes.
func (s *Signer) Sign(channel, kind, created uint64, payload cbor.Value) ([]byte, error) {
	spec, ok := channels.Lookup(channel, kind)
	if !ok {
		return nil, envelope.ErrUnknownKind
	}
	o := &envelope.Object{
		Kind:    kind,
		Channel: channel,
		Tier:    0,
		Signer:  []byte(s.id),
		Created: created,
		Effect:  uint64(spec.Effect),
		Profile: uint64(DefaultProfile),
		Body:    payload,
	}
	return envelope.Sign(o, cose.MLDSA65Signer{SK: s.sk})
}

// Verify checks a signed N-AALP object offline under an ML-DSA-65 public key, at the Public
// profile, and returns the decoded object or the first named failure (fail-closed). It runs,
// in order: the full envelope check (content id, field ranges, header/body copies, critical
// extensions, (channel, kind) admission against the frozen registry, profile floor, and the
// COSE signature); then it rebinds the object's self-certifying signer id to the key the
// signature was checked against (SignerMismatch on disagreement); then it confirms the
// object's effect equals the kind's declared effect (EffectDeclarationMismatch otherwise). A
// malformed public key is rejected before any of this (ErrKeyMalformed).
func Verify(pub, obj []byte) (*envelope.Object, error) {
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pub); err != nil {
		return nil, ErrKeyMalformed
	}
	v := cose.MLDSA65Verifier{PK: &pk}
	o, err := envelope.Verify(DefaultProfile, v, channels.KindValidator, nil, obj)
	if err != nil {
		return nil, err
	}
	if err := identity.CheckSigner(string(o.Signer), v.Alg(), v.PubKey()); err != nil {
		return nil, err
	}
	if err := channels.CheckEffect(o.Channel, o.Kind, o.Effect); err != nil {
		return nil, err
	}
	return o, nil
}
