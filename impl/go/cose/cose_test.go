// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package cose

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

const vectorPath = "../../../vectors/cose/cases.json"

type coseCases struct {
	Sign1 []struct {
		Name          string `json:"name"`
		Alg           int    `json:"alg"`
		PayloadHex    string `json:"payload_hex"`
		ProtectedHex  string `json:"protected_hex"`
		ToBeSignedHex string `json:"tobesigned_hex"`
	} `json:"sign1"`
	Hybrid struct {
		PayloadHex       string `json:"payload_hex"`
		BodyProtectedHex string `json:"body_protected_hex"`
		Ed               struct {
			Alg           int    `json:"alg"`
			ProtectedHex  string `json:"protected_hex"`
			ToBeSignedHex string `json:"tobesigned_hex"`
		} `json:"ed"`
		Ml struct {
			Alg           int    `json:"alg"`
			ProtectedHex  string `json:"protected_hex"`
			ToBeSignedHex string `json:"tobesigned_hex"`
		} `json:"ml"`
	} `json:"hybrid"`
	MLDSAKeygen []struct {
		Param   string `json:"param"`
		Alg     int    `json:"alg"`
		SeedHex string `json:"seed_hex"`
		PkHex   string `json:"pk_hex"`
	} `json:"mldsa_keygen"`
	Ed25519 struct {
		SkHex  string `json:"sk_hex"`
		PkHex  string `json:"pk_hex"`
		MsgHex string `json:"msg_hex"`
		SigHex string `json:"sig_hex"`
	} `json:"ed25519_rfc8032_test1"`
}

func load(t *testing.T) coseCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c coseCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestToBeSignedMatchesOracle grades the COSE_Sign1 signing-input construction against
// the independent RFC 9052 §4.4 oracle (non-circular). Mutation guard: a constant
// ToBeSigned would fail the fixed hex.
func TestToBeSignedMatchesOracle(t *testing.T) {
	c := load(t)
	if len(c.Sign1) == 0 {
		t.Fatal("no sign1 cases")
	}
	for _, cse := range c.Sign1 {
		prot, err := protectedHeader(cse.Alg)
		if err != nil {
			t.Fatalf("%s: protected: %v", cse.Name, err)
		}
		if got := hex.EncodeToString(prot); got != cse.ProtectedHex {
			t.Errorf("%s: protected\n got %s\nwant %s", cse.Name, got, cse.ProtectedHex)
		}
		tbs, err := ToBeSigned(cse.Alg, mustHex(t, cse.PayloadHex))
		if err != nil {
			t.Fatalf("%s: tobesigned: %v", cse.Name, err)
		}
		if got := hex.EncodeToString(tbs); got != cse.ToBeSignedHex {
			t.Errorf("%s: tobesigned\n got %s\nwant %s", cse.Name, got, cse.ToBeSignedHex)
		}
	}
}

// TestHybridToBeSignedMatchesOracle grades the per-signer COSE_Signature signing input.
func TestHybridToBeSignedMatchesOracle(t *testing.T) {
	c := load(t)
	payload := mustHex(t, c.Hybrid.PayloadHex)
	var bodyProt []byte // empty
	edTbs, _ := signatureToBeSigned(bodyProt, c.Hybrid.Ed.Alg, payload)
	if got := hex.EncodeToString(edTbs); got != c.Hybrid.Ed.ToBeSignedHex {
		t.Errorf("hybrid ed tbs\n got %s\nwant %s", got, c.Hybrid.Ed.ToBeSignedHex)
	}
	mlTbs, _ := signatureToBeSigned(bodyProt, c.Hybrid.Ml.Alg, payload)
	if got := hex.EncodeToString(mlTbs); got != c.Hybrid.Ml.ToBeSignedHex {
		t.Errorf("hybrid ml tbs\n got %s\nwant %s", got, c.Hybrid.Ml.ToBeSignedHex)
	}
}

// TestMLDSAKeygenMatchesNIST reproduces each NIST ACVP keyGen vector (seed -> pk) with
// CIRCL. Independent authority = NIST (R-16.1); proves the ML-DSA primitive is genuine
// FIPS 204 and agrees with NIST byte-for-byte.
func TestMLDSAKeygenMatchesNIST(t *testing.T) {
	c := load(t)
	if len(c.MLDSAKeygen) == 0 {
		t.Fatal("no keygen vectors")
	}
	for _, kv := range c.MLDSAKeygen {
		seed := mustHex(t, kv.SeedHex)
		if len(seed) != 32 {
			t.Fatalf("%s: seed len %d", kv.Param, len(seed))
		}
		var seed32 [32]byte
		copy(seed32[:], seed)
		var got []byte
		switch kv.Param {
		case "ML-DSA-65":
			pk, _ := mldsa65.NewKeyFromSeed(&seed32)
			got = pk.Bytes()
		case "ML-DSA-87":
			pk, _ := mldsa87.NewKeyFromSeed(&seed32)
			got = pk.Bytes()
		default:
			t.Fatalf("unexpected param %s", kv.Param)
		}
		if hex.EncodeToString(got) != kv.PkHex {
			t.Errorf("%s: keygen pk mismatch vs NIST", kv.Param)
		}
	}
}

// TestEd25519RFC8032 reproduces RFC 8032 §7.1 TEST 1 with the Go standard library
// (independent authority = RFC 8032). This also cross-validates the fetched vector.
func TestEd25519RFC8032(t *testing.T) {
	c := load(t)
	seed := mustHex(t, c.Ed25519.SkHex)
	priv := ed25519.NewKeyFromSeed(seed)
	if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != c.Ed25519.PkHex {
		t.Errorf("ed25519 pubkey\n got %s\nwant %s", got, c.Ed25519.PkHex)
	}
	sig := ed25519.Sign(priv, mustHex(t, c.Ed25519.MsgHex))
	if got := hex.EncodeToString(sig); got != c.Ed25519.SigHex {
		t.Errorf("ed25519 signature\n got %s\nwant %s", got, c.Ed25519.SigHex)
	}
}

// keyFromNIST builds an ML-DSA-65 keypair from the NIST keyGen seed (a NIST-anchored key).
func mldsa65KeyFromNIST(t *testing.T, c coseCases) (*mldsa65.PublicKey, *mldsa65.PrivateKey) {
	t.Helper()
	for _, kv := range c.MLDSAKeygen {
		if kv.Param == "ML-DSA-65" {
			var s [32]byte
			copy(s[:], mustHex(t, kv.SeedHex))
			return mldsa65.NewKeyFromSeed(&s)
		}
	}
	t.Fatal("no ML-DSA-65 keygen vector")
	return nil, nil
}

func mldsa87KeyFromNIST(t *testing.T, c coseCases) (*mldsa87.PublicKey, *mldsa87.PrivateKey) {
	t.Helper()
	for _, kv := range c.MLDSAKeygen {
		if kv.Param == "ML-DSA-87" {
			var s [32]byte
			copy(s[:], mustHex(t, kv.SeedHex))
			return mldsa87.NewKeyFromSeed(&s)
		}
	}
	t.Fatal("no ML-DSA-87 keygen vector")
	return nil, nil
}

// TestSign1RoundTripAndTamper: a signed object verifies under a compatible profile; a
// one-byte tamper of the signature is rejected with BadSignature (fail-closed).
func TestSign1RoundTripAndTamper(t *testing.T) {
	c := load(t)
	pk, sk := mldsa65KeyFromNIST(t, c)
	payload := []byte{0xa1, 0x07, 0x00} // {7:0}
	obj, err := Sign1(MLDSA65Signer{SK: sk}, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify1(ProfilePublic, MLDSA65Verifier{PK: pk}, obj); err != nil {
		t.Fatalf("verify valid: %v", err)
	}
	tampered := append([]byte(nil), obj...)
	tampered[len(tampered)-1] ^= 0x01 // flip a bit inside the trailing signature bstr
	if err := Verify1(ProfilePublic, MLDSA65Verifier{PK: pk}, tampered); err == nil {
		t.Fatal("tampered signature accepted")
	} else if ce, ok := err.(*Error); !ok || ce.Kind != "BadSignature" {
		t.Fatalf("tamper: want BadSignature, got %v", err)
	}
}

// TestDeterministicSignature: signing the same object twice yields identical bytes
// (FIPS 204 deterministic path). This is the property that makes Go==Rust byte-parity
// possible (verified live across languages by scripts/verify.sh).
func TestDeterministicSignature(t *testing.T) {
	c := load(t)
	_, sk := mldsa65KeyFromNIST(t, c)
	payload := []byte{0xa1, 0x07, 0x00}
	a, err := Sign1(MLDSA65Signer{SK: sk}, payload)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign1(MLDSA65Signer{SK: sk}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Fatal("ML-DSA signing is not deterministic across calls")
	}
}

// TestProfileDowngrade: a Sovereign verifier refuses a level-3 (ML-DSA-65) object.
func TestProfileDowngrade(t *testing.T) {
	c := load(t)
	pk, sk := mldsa65KeyFromNIST(t, c)
	obj, _ := Sign1(MLDSA65Signer{SK: sk}, []byte{0xa1, 0x07, 0x00})
	err := Verify1(ProfileSovereign, MLDSA65Verifier{PK: pk}, obj)
	if ce, ok := err.(*Error); !ok || ce.Kind != "ProfileDowngrade" {
		t.Fatalf("want ProfileDowngrade, got %v", err)
	}
	// ML-DSA-87 is accepted at Sovereign.
	pk87, sk87 := mldsa87KeyFromNIST(t, c)
	obj87, _ := Sign1(MLDSA87Signer{SK: sk87}, []byte{0xa1, 0x07, 0x00})
	if err := Verify1(ProfileSovereign, MLDSA87Verifier{PK: pk87}, obj87); err != nil {
		t.Fatalf("sovereign should accept ML-DSA-87: %v", err)
	}
}

// TestUnknownAlg: an object whose header alg is not in the registry is rejected.
func TestUnknownAlg(t *testing.T) {
	c := load(t)
	pk, _ := mldsa65KeyFromNIST(t, c)
	obj, err := assembleSign1(-99, []byte{0xa1, 0x07, 0x00}, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	if e := Verify1(ProfilePublic, MLDSA65Verifier{PK: pk}, obj); e == nil {
		t.Fatal("unknown alg accepted")
	} else if ce, ok := e.(*Error); !ok || ce.Kind != "UnknownAlg" {
		t.Fatalf("want UnknownAlg, got %v", e)
	}
}

// TestHybridAcceptAndIncomplete: the hybrid verifies only when BOTH legs verify; a
// tampered ML-DSA leg yields HybridIncomplete.
func TestHybridAcceptAndIncomplete(t *testing.T) {
	c := load(t)
	pk, sk := mldsa65KeyFromNIST(t, c)
	edSeed := mustHex(t, c.Ed25519.SkHex)
	edPriv := ed25519.NewKeyFromSeed(edSeed)
	edPub := edPriv.Public().(ed25519.PublicKey)
	payload := []byte{0xa1, 0x07, 0x00}

	obj, err := SignHybrid(edPriv, MLDSA65Signer{SK: sk}, payload)
	if err != nil {
		t.Fatalf("sign hybrid: %v", err)
	}
	if err := VerifyHybrid(ProfilePublic, Ed25519Verifier{PK: edPub}, MLDSA65Verifier{PK: pk}, obj); err != nil {
		t.Fatalf("verify hybrid: %v", err)
	}
	tampered := append([]byte(nil), obj...)
	tampered[len(tampered)-1] ^= 0x01 // corrupt the last (ML-DSA) signature byte
	err = VerifyHybrid(ProfilePublic, Ed25519Verifier{PK: edPub}, MLDSA65Verifier{PK: pk}, tampered)
	if ce, ok := err.(*Error); !ok || ce.Kind != "HybridIncomplete" {
		t.Fatalf("want HybridIncomplete, got %v", err)
	}
}
