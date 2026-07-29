// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package cose implements N-AALP's C2 signing layer: COSE_Sign1 (RFC 9052) over the
// deterministic-CBOR object body, crypto-agility by the COSE `alg` header parameter, the
// three-profile table with a Sovereign level-5 floor, and the optional Ed25519+ML-DSA
// hybrid (COSE_Sign, accepted only if both signatures verify). It reuses the C1 codec
// (impl/go/cbor); there is one signing construction and no second object encoding
// (R-2.1). Signing is deterministic (FIPS 204 rnd=0) so two implementations produce
// byte-identical signatures (R-2.2, R-16.2).
package cose

import (
	"crypto/ed25519"

	"github.com/bubblefish-tech/n-aalp/impl/go/cbor"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// COSE algorithm identifiers (design.md §4.1; ML-DSA from RFC 9964, Ed25519 from RFC 9864).
const (
	AlgMLDSA65 = -49
	AlgMLDSA87 = -50
	AlgEd25519 = -19
)

// COSE CBOR tags (RFC 9052): COSE_Sign1 is 18, the multi-signature COSE_Sign is 98.
const (
	TagSign1 = 18
	TagSign  = 98
)

// Crypto profiles (design.md §4.4).
const (
	ProfilePublic     = 1
	ProfileEnterprise = 2
	ProfileSovereign  = 3
)

// Error carries a stable Kind used by tests and callers (design.md §4.5).
type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string { return e.Kind + ": " + e.Msg }

var (
	ErrUnknownAlg       = &Error{"UnknownAlg", "algorithm id not in the N-AALP registry"}
	ErrProfileDowngrade = &Error{"ProfileDowngrade", "signature level below the profile minimum"}
	ErrHybridIncomplete = &Error{"HybridIncomplete", "hybrid requires both signatures to verify"}
	ErrBadSignature     = &Error{"BadSignature", "signature verification failed"}
	ErrKeyAlgMismatch   = &Error{"KeyAlgMismatch", "key algorithm does not match object header"}
	ErrMalformed        = &Error{"Malformed", "malformed COSE object"}
)

// algLevel returns the NIST security level for a registered algorithm and whether it is
// registered. Ed25519 is classical (level 0) and is only valid as a hybrid leg.
func algLevel(alg int) (level int, known bool) {
	switch alg {
	case AlgMLDSA87:
		return 5, true
	case AlgMLDSA65:
		return 3, true
	case AlgEd25519:
		return 0, true
	default:
		return 0, false
	}
}

// profileMinLevel is the minimum signature level a profile accepts (design.md §4.4).
// Sovereign refuses anything below level 5 (R-4.3, R-15.3); Public/Enterprise require
// a post-quantum level-3 signature (R-4.2 — no classical-only default at any profile).
func profileMinLevel(profile int) int {
	if profile == ProfileSovereign {
		return 5
	}
	return 3
}

// protectedHeader encodes the COSE protected header {1: alg} as deterministic CBOR.
func protectedHeader(alg int) ([]byte, error) {
	return cbor.Encode(cbor.Map{{K: cbor.Uint(1), V: cbor.Nint(int64(alg))}})
}

// ToBeSignedRaw builds the COSE_Sign1 signing input (RFC 9052 §4.4) over an
// already-serialized protected header:
// det-CBOR(["Signature1", protected(bstr), external_aad(bstr, empty), payload(bstr)]).
// This is the single COSE_Sign1 signing construction (R-2.1); ToBeSigned and the C3
// envelope both build on it.
func ToBeSignedRaw(protected, payload []byte) ([]byte, error) {
	ss := cbor.Arr{cbor.Tstr("Signature1"), cbor.Bstr(protected), cbor.Bstr(nil), cbor.Bstr(payload)}
	return cbor.Encode(ss)
}

// ToBeSigned builds the signing input for a bare {1: alg} protected header.
func ToBeSigned(alg int, payload []byte) ([]byte, error) {
	prot, err := protectedHeader(alg)
	if err != nil {
		return nil, err
	}
	return ToBeSignedRaw(prot, payload)
}

// AlgLevel returns the NIST security level for a registered algorithm and whether it is
// registered (exported for the C3 envelope's profile-floor check).
func AlgLevel(alg int) (level int, known bool) { return algLevel(alg) }

// ProfileMinLevel is the minimum signature level a profile accepts (exported for C3).
func ProfileMinLevel(profile int) int { return profileMinLevel(profile) }

// signatureToBeSigned builds the per-signer COSE_Signature signing input for a COSE_Sign
// (RFC 9052 §4.4): det-CBOR(["Signature", body_protected(bstr), sign_protected(bstr),
// external_aad(bstr), payload(bstr)]).
func signatureToBeSigned(bodyProt []byte, signerAlg int, payload []byte) ([]byte, error) {
	sprot, err := protectedHeader(signerAlg)
	if err != nil {
		return nil, err
	}
	ss := cbor.Arr{cbor.Tstr("Signature"), cbor.Bstr(bodyProt), cbor.Bstr(sprot), cbor.Bstr(nil), cbor.Bstr(payload)}
	return cbor.Encode(ss)
}

// Signer is a private key that signs the COSE ToBeSigned bytes; the ML-DSA signers use
// the FIPS 204 deterministic path so the output is reproducible byte-for-byte.
type Signer interface {
	Alg() int
	Sign(tbs []byte) ([]byte, error)
}

// Verifier is a public key that checks a raw signature over a message.
type Verifier interface {
	Alg() int
	VerifyRaw(msg, sig []byte) bool
}

// MLDSA65Signer / MLDSA87Signer sign deterministically (randomized=false => rnd=0).
type MLDSA65Signer struct{ SK *mldsa65.PrivateKey }

func (MLDSA65Signer) Alg() int { return AlgMLDSA65 }
func (s MLDSA65Signer) Sign(tbs []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.SK, tbs, nil, false, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

type MLDSA87Signer struct{ SK *mldsa87.PrivateKey }

func (MLDSA87Signer) Alg() int { return AlgMLDSA87 }
func (s MLDSA87Signer) Sign(tbs []byte) ([]byte, error) {
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(s.SK, tbs, nil, false, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// MLDSA65Verifier / MLDSA87Verifier / Ed25519Verifier implement Verifier.
type MLDSA65Verifier struct{ PK *mldsa65.PublicKey }

func (MLDSA65Verifier) Alg() int                        { return AlgMLDSA65 }
func (v MLDSA65Verifier) VerifyRaw(msg, sig []byte) bool { return mldsa65.Verify(v.PK, msg, nil, sig) }

type MLDSA87Verifier struct{ PK *mldsa87.PublicKey }

func (MLDSA87Verifier) Alg() int                        { return AlgMLDSA87 }
func (v MLDSA87Verifier) VerifyRaw(msg, sig []byte) bool { return mldsa87.Verify(v.PK, msg, nil, sig) }

type Ed25519Verifier struct{ PK ed25519.PublicKey }

func (Ed25519Verifier) Alg() int                        { return AlgEd25519 }
func (v Ed25519Verifier) VerifyRaw(msg, sig []byte) bool { return ed25519.Verify(v.PK, msg, sig) }

// AssembleSign1Raw builds the tagged COSE_Sign1 object bytes over an already-serialized
// protected header (the C3 envelope uses this with its enriched header).
func AssembleSign1Raw(protected, payload, sig []byte) ([]byte, error) {
	obj := cbor.Tag{Number: TagSign1, Content: cbor.Arr{
		cbor.Bstr(protected), // protected header, bstr-wrapped
		cbor.Map{},           // unprotected header (empty)
		cbor.Bstr(payload),   // payload
		cbor.Bstr(sig),       // signature
	}}
	return cbor.Encode(obj)
}

// assembleSign1 builds the tagged COSE_Sign1 object for a bare {1: alg} header.
func assembleSign1(alg int, payload, sig []byte) ([]byte, error) {
	prot, err := protectedHeader(alg)
	if err != nil {
		return nil, err
	}
	return AssembleSign1Raw(prot, payload, sig)
}

// Sign1 produces a tagged COSE_Sign1 object over payload.
func Sign1(s Signer, payload []byte) ([]byte, error) {
	tbs, err := ToBeSigned(s.Alg(), payload)
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(tbs)
	if err != nil {
		return nil, err
	}
	return assembleSign1(s.Alg(), payload, sig)
}

// ParseSign1Raw decodes a tagged COSE_Sign1 object into its raw (protected, payload,
// signature) byte strings; the C3 envelope decodes the protected header itself.
func ParseSign1Raw(obj []byte) (protected, payload, sig []byte, err error) {
	v, e := cbor.Decode(obj)
	if e != nil {
		return nil, nil, nil, ErrMalformed
	}
	tag, ok := v.(cbor.Tag)
	if !ok || tag.Number != TagSign1 {
		return nil, nil, nil, ErrMalformed
	}
	arr, ok := tag.Content.(cbor.Arr)
	if !ok || len(arr) != 4 {
		return nil, nil, nil, ErrMalformed
	}
	prot, ok1 := arr[0].(cbor.Bstr)
	pl, ok2 := arr[2].(cbor.Bstr)
	sg, ok3 := arr[3].(cbor.Bstr)
	if !ok1 || !ok2 || !ok3 {
		return nil, nil, nil, ErrMalformed
	}
	return []byte(prot), []byte(pl), []byte(sg), nil
}

// parseSign1 decodes a tagged COSE_Sign1 object into (alg, payload, signature).
func parseSign1(obj []byte) (alg int, payload, sig []byte, err error) {
	prot, pl, sg, err := ParseSign1Raw(obj)
	if err != nil {
		return 0, nil, nil, err
	}
	alg, err = algFromProtected(prot)
	if err != nil {
		return 0, nil, nil, err
	}
	return alg, pl, sg, nil
}

// algFromProtected extracts the `alg` (label 1) value from an encoded protected header.
func algFromProtected(prot []byte) (int, error) {
	pv, e := cbor.Decode(prot)
	if e != nil {
		return 0, ErrMalformed
	}
	m, ok := pv.(cbor.Map)
	if !ok {
		return 0, ErrMalformed
	}
	for _, p := range m {
		if p.K == cbor.Uint(1) {
			switch a := p.V.(type) {
			case cbor.Nint:
				return int(a), nil
			case cbor.Uint:
				return int(a), nil
			}
		}
	}
	return 0, ErrMalformed
}

// Verify1 verifies a tagged COSE_Sign1 object under a profile policy. Order of checks:
// UnknownAlg (registry) -> ProfileDowngrade (level floor) -> KeyAlgMismatch -> signature.
func Verify1(profile int, v Verifier, obj []byte) error {
	alg, payload, sig, err := parseSign1(obj)
	if err != nil {
		return err
	}
	level, known := algLevel(alg)
	if !known {
		return ErrUnknownAlg
	}
	if level < profileMinLevel(profile) {
		return ErrProfileDowngrade
	}
	if alg != v.Alg() {
		return ErrKeyAlgMismatch
	}
	tbs, err := ToBeSigned(alg, payload)
	if err != nil {
		return err
	}
	if !v.VerifyRaw(tbs, sig) {
		return ErrBadSignature
	}
	return nil
}

// SignHybrid produces a tagged COSE_Sign (multi-signature) object with an Ed25519 leg and
// an ML-DSA leg over the same payload; the body protected header is empty (design.md §4.2).
func SignHybrid(edSk ed25519.PrivateKey, ml Signer, payload []byte) ([]byte, error) {
	var bodyProt []byte // empty protected header -> zero-length bstr (RFC 9052 §3)

	edTbs, err := signatureToBeSigned(bodyProt, AlgEd25519, payload)
	if err != nil {
		return nil, err
	}
	edSig := ed25519.Sign(edSk, edTbs)
	edProt, err := protectedHeader(AlgEd25519)
	if err != nil {
		return nil, err
	}

	mlTbs, err := signatureToBeSigned(bodyProt, ml.Alg(), payload)
	if err != nil {
		return nil, err
	}
	mlSig, err := ml.Sign(mlTbs)
	if err != nil {
		return nil, err
	}
	mlProt, err := protectedHeader(ml.Alg())
	if err != nil {
		return nil, err
	}

	sigs := cbor.Arr{
		cbor.Arr{cbor.Bstr(edProt), cbor.Map{}, cbor.Bstr(edSig)},
		cbor.Arr{cbor.Bstr(mlProt), cbor.Map{}, cbor.Bstr(mlSig)},
	}
	obj := cbor.Tag{Number: TagSign, Content: cbor.Arr{
		cbor.Bstr(bodyProt), cbor.Map{}, cbor.Bstr(payload), sigs,
	}}
	return cbor.Encode(obj)
}

// VerifyHybrid verifies a tagged COSE_Sign hybrid object: it is accepted only if BOTH the
// Ed25519 leg and the ML-DSA leg verify (R-4.4). The ML-DSA leg must satisfy the profile
// level floor; the classical leg is an additional binding, never a standalone authority.
func VerifyHybrid(profile int, edV, mlV Verifier, obj []byte) error {
	v, e := cbor.Decode(obj)
	if e != nil {
		return ErrMalformed
	}
	tag, ok := v.(cbor.Tag)
	if !ok || tag.Number != TagSign {
		return ErrMalformed
	}
	arr, ok := tag.Content.(cbor.Arr)
	if !ok || len(arr) != 4 {
		return ErrMalformed
	}
	bodyProtV, ok1 := arr[0].(cbor.Bstr)
	payloadV, ok2 := arr[2].(cbor.Bstr)
	sigsV, ok3 := arr[3].(cbor.Arr)
	if !ok1 || !ok2 || !ok3 {
		return ErrMalformed
	}
	bodyProt := []byte(bodyProtV)
	payload := []byte(payloadV)

	edOK, mlOK := false, false
	for _, sv := range sigsV {
		entry, ok := sv.(cbor.Arr)
		if !ok || len(entry) != 3 {
			return ErrMalformed
		}
		sprot, ok1 := entry[0].(cbor.Bstr)
		sig, ok2 := entry[2].(cbor.Bstr)
		if !ok1 || !ok2 {
			return ErrMalformed
		}
		alg, err := algFromProtected([]byte(sprot))
		if err != nil {
			return err
		}
		tbs, err := signatureToBeSigned(bodyProt, alg, payload)
		if err != nil {
			return err
		}
		switch alg {
		case AlgEd25519:
			if edV.VerifyRaw(tbs, []byte(sig)) {
				edOK = true
			}
		case mlV.Alg():
			level, _ := algLevel(alg)
			if level < profileMinLevel(profile) {
				return ErrProfileDowngrade
			}
			if mlV.VerifyRaw(tbs, []byte(sig)) {
				mlOK = true
			}
		default:
			return ErrUnknownAlg
		}
	}
	if !edOK || !mlOK {
		return ErrHybridIncomplete
	}
	return nil
}
