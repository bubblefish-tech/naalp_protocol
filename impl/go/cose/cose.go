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
	"crypto/sha512"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
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
	ErrCompositeRefused = &Error{"CompositeRefused", "sovereign profile refuses a composite object"}
	ErrSuiteMismatch    = &Error{"SuiteMismatch", "signed suite declaration disagrees with the signature alg"}
)

// algLevel returns the NIST security level for a registered algorithm and whether it is
// registered. Ed25519 is classical (level 0) and is only valid as a hybrid leg.
func algLevel(alg int) (level int, known bool) {
	switch alg {
	case AlgMLDSA87:
		return 5, true
	case AlgMLDSA65:
		return 3, true
	case AlgComposite65Ed25519:
		return 3, true // composite PQ leg is ML-DSA-65 (level 3); Public/Enterprise only (§4.4)
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

// Verifier is a public key that checks a raw signature over a message. PubKey returns the raw
// public-key bytes of the verifying key, so a caller can bind an out-of-band signer-id derivation
// to the SAME key that actually verified — closing the confused-deputy gap where an id is derived
// from a public key different from the one the signature was checked against (design.md §21.4).
type Verifier interface {
	Alg() int
	VerifyRaw(msg, sig []byte) bool
	PubKey() []byte
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

func (MLDSA65Verifier) Alg() int                         { return AlgMLDSA65 }
func (v MLDSA65Verifier) VerifyRaw(msg, sig []byte) bool { return mldsa65.Verify(v.PK, msg, nil, sig) }
func (v MLDSA65Verifier) PubKey() []byte                 { return v.PK.Bytes() }

type MLDSA87Verifier struct{ PK *mldsa87.PublicKey }

func (MLDSA87Verifier) Alg() int                         { return AlgMLDSA87 }
func (v MLDSA87Verifier) VerifyRaw(msg, sig []byte) bool { return mldsa87.Verify(v.PK, msg, nil, sig) }
func (v MLDSA87Verifier) PubKey() []byte                 { return v.PK.Bytes() }

type Ed25519Verifier struct{ PK ed25519.PublicKey }

func (Ed25519Verifier) Alg() int                         { return AlgEd25519 }
func (v Ed25519Verifier) VerifyRaw(msg, sig []byte) bool { return ed25519.Verify(v.PK, msg, sig) }
func (v Ed25519Verifier) PubKey() []byte                 { return append([]byte(nil), v.PK...) }

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
	// §3.1.1 (R5): reject the redundant 0x41A0 encoding of an empty protected header (a bstr
	// wrapping an empty map; its unwrapped content is the single byte 0xA0) as NonCanonical,
	// before interpreting the header — the empty protected header is pinned to 0x40.
	if len(prot) == 1 && prot[0] == 0xA0 {
		return 0, &Error{Kind: "NonCanonical", Msg: "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)"}
	}
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
	// Sovereign refuses a composite object outright (§4.4/§4.5), a distinct verdict from the
	// generic level floor, so the layers agree with the envelope's CompositeRefused.
	if alg == AlgComposite65Ed25519 && profile == ProfileSovereign {
		return ErrCompositeRefused
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

// --- Opt-in LAMPS composite signature (design.md §4.2) --------------------------------

// Composite COSE algorithm ids (design.md §4.2/§4.4). N-AALP owns these provisional
// private-use identifiers (the COSE Algorithms range "integers less than -65536" is Private
// Use) until IANA assigns public composite code points, so adopting the eventual public ids
// is a registry swap, not a wire break. Only AlgComposite65Ed25519 is implemented this wave;
// AlgComposite44Ed25519 is RESERVED (registered, not implemented/graded).
const (
	AlgComposite65Ed25519 = -65537 // COMPSIG-MLDSA65-Ed25519-SHA512 (Public/Enterprise)
	AlgComposite44Ed25519 = -65538 // COMPSIG-MLDSA44-Ed25519-SHA512 (edge; RESERVED)
)

// The IETF LAMPS composite construction (draft-ietf-lamps-pq-composite-sigs rev-19).
// compositePrefix is the fixed ASCII domain string; compositeLabelMLDSA65Ed25519 is the
// suite's LAMPS algorithm label. Both are the ASCII octets of their strings (computed from
// the literals, never a hardcoded hex blob).
var (
	compositePrefix              = []byte("CompositeAlgorithmSignatures2025")
	compositeLabelMLDSA65Ed25519 = []byte("COMPSIG-MLDSA65-Ed25519-SHA512")
)

// ComputeMprime returns the LAMPS composite message representative M' for a suite label and
// composite context ctx over the COSE ToBeSigned bytes M (design.md §4.2):
//
//	M' = Prefix || Label || len(ctx) || ctx || PH(M)
//
// len(ctx) is a single length octet; PH is SHA-512; M is the object's COSE_Sign1 ToBeSigned.
// For N-AALP the composite context ctx is EMPTY (callers pass nil), so the octet is 0x00 and
// ctx contributes no bytes. Both the ML-DSA and Ed25519 legs sign this same M'. (The ctx
// parameter is general so the same construction reproduces the LAMPS WG reference vectors,
// which use a non-empty context.)
func ComputeMprime(label, ctx, m []byte) []byte {
	h := sha512.Sum512(m)
	out := make([]byte, 0, len(compositePrefix)+len(label)+1+len(ctx)+len(h))
	out = append(out, compositePrefix...)
	out = append(out, label...)
	out = append(out, byte(len(ctx))) // len(ctx) as a single length octet
	out = append(out, ctx...)
	out = append(out, h[:]...)
	return out
}

// CompositeSigner signs one COSE_Sign1 whose signature value is the IETF LAMPS composite of
// an ML-DSA-65 leg (pure ML-DSA, context = the suite Label octets) and an Ed25519 leg (no
// context), both over M' = ComputeMprime(Label, tbs); the value is mldsaSig || tradSig
// (ML-DSA first, raw concatenation, no length prefixes). It implements Signer with Alg()
// reporting the composite id, so the C3 envelope signs it through the same Sign path.
type CompositeSigner struct {
	ML65 *mldsa65.PrivateKey
	Ed   ed25519.PrivateKey
}

func (CompositeSigner) Alg() int { return AlgComposite65Ed25519 }

// Sign returns the composite signature value over the ToBeSigned bytes tbs. The ML-DSA leg
// is deterministic (randomized=false => rnd=0) with context = the Label octets; the Ed25519
// leg signs M' with no context.
func (s CompositeSigner) Sign(tbs []byte) ([]byte, error) {
	mprime := ComputeMprime(compositeLabelMLDSA65Ed25519, nil, tbs)
	mldsaSig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.ML65, mprime, compositeLabelMLDSA65Ed25519, false, mldsaSig); err != nil {
		return nil, err
	}
	tradSig := ed25519.Sign(s.Ed, mprime)
	out := make([]byte, 0, len(mldsaSig)+len(tradSig))
	out = append(out, mldsaSig...) // ML-DSA first (LAMPS order)
	out = append(out, tradSig...)
	return out, nil
}

// CompositeVerifier verifies a LAMPS composite signature: valid iff BOTH the ML-DSA-65 leg
// and the Ed25519 leg validate over M'. It implements Verifier; VerifyRaw reports the
// both-legs verdict, while the C3 envelope calls VerifyComposite to distinguish a single-leg
// failure (HybridIncomplete) from a structural one (Malformed).
type CompositeVerifier struct {
	ML65 *mldsa65.PublicKey
	Ed   ed25519.PublicKey
}

func (CompositeVerifier) Alg() int { return AlgComposite65Ed25519 }

// ML65Pub / EdPub return the raw component public keys; the self-certifying composite
// signer-id is derived from BOTH via identity.CompositeSignerID (design.md §5.1).
func (v CompositeVerifier) ML65Pub() []byte { return v.ML65.Bytes() }
func (v CompositeVerifier) EdPub() []byte   { return append([]byte(nil), v.Ed...) }

// PubKey returns the raw component keys concatenated (mldsaPub || ed25519Pub) so the generic
// Verifier interface is satisfied. A caller binding the signer-id to the verifying key uses
// ML65Pub / EdPub with identity.CompositeSignerID, which owns the one multicodec preimage
// construction (design.md §5.1, §21.4).
func (v CompositeVerifier) PubKey() []byte {
	ml := v.ML65.Bytes()
	out := make([]byte, 0, len(ml)+len(v.Ed))
	out = append(out, ml...)
	out = append(out, v.Ed...)
	return out
}

// VerifyRaw reports whether BOTH composite legs validate over M' = ComputeMprime(Label,
// msg). A value of the wrong length verifies as false.
func (v CompositeVerifier) VerifyRaw(msg, sig []byte) bool { return VerifyComposite(v, msg, sig) == nil }

// VerifyComposite validates a LAMPS composite signature value over the COSE ToBeSigned bytes
// M. It splits the value at the fixed ML-DSA-65 signature size (a value of the wrong length
// is Malformed — a structural fault), recomputes M', and verifies the ML-DSA leg (context =
// Label) and the Ed25519 leg (no context). Valid IFF both validate; any single-leg failure
// is HybridIncomplete. A stripped or re-interpreted lone leg has no valid composite because
// M' binds both components into one value (RFC 9955 Strong Non-Separability; §4.2/§4.5).
func VerifyComposite(v CompositeVerifier, m, sig []byte) error {
	if len(sig) != mldsa65.SignatureSize+ed25519.SignatureSize {
		return ErrMalformed
	}
	mprime := ComputeMprime(compositeLabelMLDSA65Ed25519, nil, m)
	mldsaOK := mldsa65.Verify(v.ML65, mprime, compositeLabelMLDSA65Ed25519, sig[:mldsa65.SignatureSize])
	edOK := ed25519.Verify(v.Ed, mprime, sig[mldsa65.SignatureSize:])
	if !mldsaOK || !edOK {
		return ErrHybridIncomplete
	}
	return nil
}

// --- COSE_Sign (tag 98) multi-signature support (used by the C4 Rotation object, §5.2) --

// CoseSignLeg is one COSE_Signature of a COSE_Sign object: its serialized protected header
// ({1: alg}) and signature value.
type CoseSignLeg struct {
	Protected []byte
	Sig       []byte
}

// SignatureToBeSigned is the exported per-signer COSE_Signature signing input (RFC 9052 §4.4)
// over an already-serialized body protected header: det-CBOR(["Signature", body_protected,
// sign_protected, external_aad(empty), payload]).
func SignatureToBeSigned(bodyProt []byte, signerAlg int, payload []byte) ([]byte, error) {
	return signatureToBeSigned(bodyProt, signerAlg, payload)
}

// AlgFromProtected extracts the alg (label 1) value from a serialized protected header.
func AlgFromProtected(prot []byte) (int, error) { return algFromProtected(prot) }

// SignatureLeg builds one COSE_Signature leg: it signs the per-signer ToBeSigned over the body
// protected header, and returns the leg's serialized {1: alg} protected header and signature.
func SignatureLeg(bodyProt []byte, signer Signer, payload []byte) (CoseSignLeg, error) {
	sprot, err := protectedHeader(signer.Alg())
	if err != nil {
		return CoseSignLeg{}, err
	}
	tbs, err := signatureToBeSigned(bodyProt, signer.Alg(), payload)
	if err != nil {
		return CoseSignLeg{}, err
	}
	sig, err := signer.Sign(tbs)
	if err != nil {
		return CoseSignLeg{}, err
	}
	return CoseSignLeg{Protected: sprot, Sig: sig}, nil
}

// AssembleSignRaw builds a tagged COSE_Sign (tag 98) object over an already-serialized body
// protected header, with the given signature legs in order (each carries an empty unprotected
// header). Empty body protected header is a zero-length bstr; here the caller passes the
// enriched header, matching the object's tag-18 protected header (RFC 9052 §4.1).
func AssembleSignRaw(bodyProt, payload []byte, legs []CoseSignLeg) ([]byte, error) {
	sigs := make(cbor.Arr, 0, len(legs))
	for _, l := range legs {
		sigs = append(sigs, cbor.Arr{cbor.Bstr(l.Protected), cbor.Map{}, cbor.Bstr(l.Sig)})
	}
	obj := cbor.Tag{Number: TagSign, Content: cbor.Arr{
		cbor.Bstr(bodyProt), cbor.Map{}, cbor.Bstr(payload), sigs,
	}}
	return cbor.Encode(obj)
}

// ParseSignRaw decodes a tagged COSE_Sign (tag 98) into its body protected header, payload, and
// ordered signature legs. A non-tag-98 object, wrong arity, or wrong types is Malformed.
func ParseSignRaw(obj []byte) (bodyProt, payload []byte, legs []CoseSignLeg, err error) {
	v, e := cbor.Decode(obj)
	if e != nil {
		return nil, nil, nil, ErrMalformed
	}
	tag, ok := v.(cbor.Tag)
	if !ok || tag.Number != TagSign {
		return nil, nil, nil, ErrMalformed
	}
	arr, ok := tag.Content.(cbor.Arr)
	if !ok || len(arr) != 4 {
		return nil, nil, nil, ErrMalformed
	}
	bp, ok1 := arr[0].(cbor.Bstr)
	pl, ok2 := arr[2].(cbor.Bstr)
	sigsV, ok3 := arr[3].(cbor.Arr)
	if !ok1 || !ok2 || !ok3 {
		return nil, nil, nil, ErrMalformed
	}
	for _, sv := range sigsV {
		entry, ok := sv.(cbor.Arr)
		if !ok || len(entry) != 3 {
			return nil, nil, nil, ErrMalformed
		}
		sp, ok1 := entry[0].(cbor.Bstr)
		sg, ok2 := entry[2].(cbor.Bstr)
		if !ok1 || !ok2 {
			return nil, nil, nil, ErrMalformed
		}
		legs = append(legs, CoseSignLeg{Protected: []byte(sp), Sig: []byte(sg)})
	}
	return []byte(bp), []byte(pl), legs, nil
}
