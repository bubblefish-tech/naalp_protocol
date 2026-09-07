// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpdid

import (
	"crypto/ed25519"
	"encoding/json"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// akpAlgName maps an N-AALP ML-DSA COSE algorithm id to its RFC 9964 JOSE "alg" name and
// FIPS 204 public-key size. Only the two ML-DSA parameter sets identity.go's
// multicodecFor recognizes are mapped — N-AALP has no ML-DSA-44 signer.
func akpAlgName(alg int) (name string, size int, ok bool) {
	switch alg {
	case cose.AlgMLDSA65:
		return "ML-DSA-65", mldsa65.PublicKeySize, true
	case cose.AlgMLDSA87:
		return "ML-DSA-87", mldsa87.PublicKeySize, true
	default:
		return "", 0, false
	}
}

// akpAlgID is the inverse of akpAlgName's alg half: an RFC 9964 JOSE "alg" string back
// to the COSE algorithm id.
func akpAlgID(name string) (alg int, ok bool) {
	switch name {
	case "ML-DSA-65":
		return cose.AlgMLDSA65, true
	case "ML-DSA-87":
		return cose.AlgMLDSA87, true
	default:
		return 0, false
	}
}

// ToDIDJWK builds a did:jwk identifier for an N-AALP signer's public key (design.md
// §5.4; grounded 2026-08-31, see doc.go). alg must be cose.AlgMLDSA65, cose.AlgMLDSA87,
// or cose.AlgEd25519 — the exact set impl/go/identity's multicodecFor recognizes; any
// other value is rejected (ErrUnknownAlg) before any encoding work, and a pubkey whose
// length disagrees with the algorithm's fixed FIPS 204 / RFC 8032 size is rejected
// (ErrKeySize) before any encoding work. Pure function of (alg, pubkey): no network
// access, no state, no side effect.
func ToDIDJWK(alg int, pubkey []byte) (string, error) {
	if alg == cose.AlgEd25519 {
		if len(pubkey) != ed25519.PublicKeySize {
			return "", ErrKeySize
		}
		return wrapDIDJWK(buildOKPJWK(pubkey)), nil
	}
	name, size, ok := akpAlgName(alg)
	if !ok {
		return "", ErrUnknownAlg
	}
	if len(pubkey) != size {
		return "", ErrKeySize
	}
	return wrapDIDJWK(buildAKPJWK(name, pubkey)), nil
}

// ktyProbe decodes ONLY the "kty" field, used to route FromDIDJWK's decode to the AKP or
// OKP parser without guessing from key length or any other heuristic.
type ktyProbe struct {
	Kty string `json:"kty"`
}

// FromDIDJWK is the inverse of ToDIDJWK: decode the did:jwk identifier, parse and
// validate the embedded JWK, and return the (alg, pubkey) it names. A malformed
// identifier, a private-key JWK, or a kty/alg/curve N-AALP does not recognize is
// rejected whole (fail-closed) with a named error before any key material is returned —
// there is no partial result.
func FromDIDJWK(didURI string) (alg int, pubkey []byte, err error) {
	raw, err := unwrapDIDJWK(didURI)
	if err != nil {
		return 0, nil, err
	}
	var kp ktyProbe
	if e := json.Unmarshal(raw, &kp); e != nil {
		return 0, nil, ErrMalformedJWK
	}
	switch kp.Kty {
	case "AKP":
		name, pub, e := parseAKPJWK(raw)
		if e != nil {
			return 0, nil, e
		}
		mappedAlg, ok := akpAlgID(name)
		if !ok {
			return 0, nil, ErrUnsupportedAlgString
		}
		_, size, _ := akpAlgName(mappedAlg)
		if len(pub) != size {
			return 0, nil, ErrKeySize
		}
		return mappedAlg, pub, nil
	case "OKP":
		pub, e := parseOKPJWK(raw)
		if e != nil {
			return 0, nil, e
		}
		if len(pub) != ed25519.PublicKeySize {
			return 0, nil, ErrKeySize
		}
		return cose.AlgEd25519, pub, nil
	default:
		return 0, nil, ErrUnsupportedKty
	}
}

// LinkSignerToDID builds and self-signs a ForeignLinkRecord binding an N-AALP signer id
// to its did:jwk representation (design.md §5.4; identity.ForeignLinkRecord /
// identity.VerifyForeignLink, impl/go/identity/identity.go:231-263 — an existing,
// already-tested linkage primitive this package does not modify). The "foreign" identity
// and the N-AALP identity are the same key here (a self-link asserting "this signer id
// IS also reachable at this did:jwk"), so VerifyForeignLink's "signed by the foreign
// identity's key" check is satisfied by `signer` alone. alg/pubkey/signer must all name
// the same key; passing a signer for a different key produces a record that will fail
// VerifyForeignLink, not a silently-wrong-but-accepted one.
func LinkSignerToDID(alg int, pubkey []byte, notAfter uint64, signer cose.Signer) (identity.ForeignLinkRecord, []byte, error) {
	signerID, err := identity.SignerID(alg, pubkey)
	if err != nil {
		return identity.ForeignLinkRecord{}, nil, err
	}
	did, err := ToDIDJWK(alg, pubkey)
	if err != nil {
		return identity.ForeignLinkRecord{}, nil, err
	}
	rec := identity.ForeignLinkRecord{Controls: signerID, ForeignID: did, NotAfter: notAfter}
	sig, err := signer.Sign(rec.Bytes())
	if err != nil {
		return identity.ForeignLinkRecord{}, nil, err
	}
	return rec, sig, nil
}
