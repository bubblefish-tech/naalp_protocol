// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"crypto/rand"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ProvenanceSigner signs a provenance Statement's canonical JSON bytes using N-AALP's C2
// signing layer directly (impl/go/cose.Sign1 + cose.MLDSA65Signer — the same construction
// naalp.Signer.Sign builds on, RFC 9052 COSE_Sign1, deterministic FIPS 204 rnd=0). It does
// NOT go through naalp.Signer / naalpcore.Sign, because those bind a signature to an
// N-AALP (channel, kind) wire object (design.md §5, the envelope's registered-kind
// admission check) — a supply-chain provenance statement is not an N-AALP wire object and
// has no (channel, kind); reusing naalp.Signer here would require either inventing a fake
// registry entry (a wire-format change, forbidden for this additive ecosystem layer) or
// silently mislabeling a generic attestation as an N-AALP protocol object. cose.Sign1 is
// the correct, already-generic seam: it signs arbitrary payload bytes into a tagged
// COSE_Sign1 object with no channel/kind coupling, exactly the shape naalpcore's own Sign
// function is a thin wrapper over (naalpcore.go: "Sign delegates to
// (*naalp.Signer).Sign — the canonical happy-path object-signing call").
//
// ProvenanceSigner derives its key the same way naalp.NewSigner does (a 32-byte ML-DSA-65
// seed via mldsa65.NewKeyFromSeed) because naalp.Signer's underlying private key field is
// unexported and therefore unavailable to a caller needing the raw cose.Signer this
// package's cose.Sign1 call requires.
type ProvenanceSigner struct {
	sk *mldsa65.PrivateKey
	pk *mldsa65.PublicKey
}

// NewProvenanceSigner derives a ProvenanceSigner from a 32-byte ML-DSA-65 seed. A seed of
// the wrong length is rejected (ErrSeedSize) before any key is created.
func NewProvenanceSigner(seed []byte) (*ProvenanceSigner, error) {
	if len(seed) != mldsa65.SeedSize {
		return nil, ErrSeedSize
	}
	var s [mldsa65.SeedSize]byte
	copy(s[:], seed)
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	return &ProvenanceSigner{sk: sk, pk: pk}, nil
}

// GenerateProvenanceSigner creates a fresh ML-DSA-65 identity from a cryptographically
// random 32-byte seed read from crypto/rand.
func GenerateProvenanceSigner() (*ProvenanceSigner, error) {
	seed := make([]byte, mldsa65.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return NewProvenanceSigner(seed)
}

// PublicKey returns the raw packed ML-DSA-65 public-key bytes to hand to a verifier.
func (s *ProvenanceSigner) PublicKey() []byte { return s.pk.Bytes() }

// SignStatement produces a tagged COSE_Sign1 object (cose.Sign1) over
// canonicalStatementJSON — deterministic ML-DSA-65 (FIPS 204, rnd=0), so signing the same
// bytes twice with the same signer always produces byte-identical output.
func (s *ProvenanceSigner) SignStatement(canonicalStatementJSON []byte) ([]byte, error) {
	return cose.Sign1(cose.MLDSA65Signer{SK: s.sk}, canonicalStatementJSON)
}

// VerifyStatementSignature checks that coseObj is a valid tagged COSE_Sign1 object under
// pub at the Public crypto profile (design.md §4.4, level-3 floor — ML-DSA-65 satisfies
// it), AND that its payload is byte-identical to expectedStatementJSON (ErrPayloadMismatch
// otherwise): a signature can be cryptographically valid over SOME payload while still not
// being a signature over the statement the caller actually cares about, so both checks are
// required, in that order (a structurally/cryptographically invalid object is rejected
// before the payload is even compared).
func VerifyStatementSignature(pub []byte, coseObj []byte, expectedStatementJSON []byte) error {
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pub); err != nil {
		return err
	}
	v := cose.MLDSA65Verifier{PK: &pk}
	if err := cose.Verify1(cose.ProfilePublic, v, coseObj); err != nil {
		return err
	}
	_, payload, _, err := cose.ParseSign1Raw(coseObj)
	if err != nil {
		return err
	}
	if string(payload) != string(expectedStatementJSON) {
		return ErrPayloadMismatch
	}
	return nil
}
