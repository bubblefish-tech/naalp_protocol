// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package identity

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/identity/cases.json"

type idCases struct {
	Signers []struct {
		Name      string `json:"name"`
		Alg       int    `json:"alg"`
		Multi     uint64 `json:"multicodec"`
		PubkeyHex string `json:"pubkey_hex"`
		SignerID  string `json:"signer_id"`
	} `json:"signers"`
	NFC struct {
		NFCHex string `json:"nfc_utf8_hex"`
		NFDHex string `json:"nfd_utf8_hex"`
	} `json:"nfc"`
}

func load(t *testing.T) idCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c idCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

func mh(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// TestSignerIDMatchesOracle grades the multiformats signer-id construction against the
// independent oracle (three-way: Go==oracle here, Rust==oracle in its suite, so Go==Rust).
func TestSignerIDMatchesOracle(t *testing.T) {
	c := load(t)
	if len(c.Signers) == 0 {
		t.Fatal("no signer cases")
	}
	for _, s := range c.Signers {
		got, err := SignerID(s.Alg, mh(t, s.PubkeyHex))
		if err != nil {
			t.Fatalf("%s: SignerID: %v", s.Name, err)
		}
		if got != s.SignerID {
			t.Errorf("%s: signer id\n got %s\nwant %s", s.Name, got, s.SignerID)
		}
	}
}

// TestSignerMismatch: recomputation rejects a claimed id that does not match the key.
func TestSignerMismatch(t *testing.T) {
	c := load(t)
	s := c.Signers[0]
	pub := mh(t, s.PubkeyHex)
	if err := CheckSigner(s.SignerID, s.Alg, pub); err != nil {
		t.Fatalf("correct id rejected: %v", err)
	}
	if err := CheckSigner("bwrongidwrongidwrongid", s.Alg, pub); err == nil {
		t.Fatal("mismatched id accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "SignerMismatch" {
		t.Fatalf("want SignerMismatch, got %v", err)
	}
}

// TestNFC: an NFC identity string is accepted, an NFD one rejected (NonNFC).
func TestNFC(t *testing.T) {
	c := load(t)
	if err := RequireNFC(string(mh(t, c.NFC.NFCHex))); err != nil {
		t.Errorf("NFC string rejected: %v", err)
	}
	if err := RequireNFC(string(mh(t, c.NFC.NFDHex))); err == nil {
		t.Fatal("NFD string accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "NonNFC" {
		t.Fatalf("want NonNFC, got %v", err)
	}
}

// keypair derives a distinct ML-DSA-65 keypair (and its signer id) from a seed byte.
func keypair(t *testing.T, seedByte byte) (*mldsa65.PublicKey, *mldsa65.PrivateKey, string) {
	t.Helper()
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = seedByte
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	id, err := SignerID(cose.AlgMLDSA65, pk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return pk, sk, id
}

// TestRotationVsSubstitution: a co-signed rotation verifies; a substitution not co-signed
// by the old key is RotationUnauthorized.
func TestRotationVsSubstitution(t *testing.T) {
	pk1, sk1, id1 := keypair(t, 1)
	pk2, sk2, id2 := keypair(t, 2)
	rec := RotationRecord{Old: id1, New: id2, NotBefore: 1000}
	oldSig, newSig, err := SignRotation(rec, cose.MLDSA65Signer{SK: sk1}, cose.MLDSA65Signer{SK: sk2})
	if err != nil {
		t.Fatal(err)
	}
	v1, v2 := cose.MLDSA65Verifier{PK: pk1}, cose.MLDSA65Verifier{PK: pk2}
	if err := VerifyRotation(rec, v1, v2, pk1.Bytes(), pk2.Bytes(), oldSig, newSig); err != nil {
		t.Fatalf("valid rotation rejected: %v", err)
	}
	// Substitution: corrupt the old-key signature.
	badOld := append([]byte(nil), oldSig...)
	badOld[len(badOld)-1] ^= 0x01
	if err := VerifyRotation(rec, v1, v2, pk1.Bytes(), pk2.Bytes(), badOld, newSig); err == nil {
		t.Fatal("substitution (bad old signature) accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "RotationUnauthorized" {
		t.Fatalf("want RotationUnauthorized, got %v", err)
	}
}

// TestRevocation: an object after not_after is revoked; before/at it stays valid.
func TestRevocation(t *testing.T) {
	pk, sk, id := keypair(t, 7)
	rec := RevocationRecord{Key: id, NotAfter: 100}
	sig, err := cose.MLDSA65Signer{SK: sk}.Sign(rec.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocation(rec, cose.MLDSA65Verifier{PK: pk}, pk.Bytes(), sig); err != nil {
		t.Fatalf("valid revocation rejected: %v", err)
	}
	if !RevokedAt(rec, 101) {
		t.Error("object after not_after should be revoked")
	}
	if RevokedAt(rec, 100) || RevokedAt(rec, 99) {
		t.Error("object at/before not_after should stay valid")
	}
}

// TestForeignLink: a valid link confers linkage; expired or wrong-key confers none
// (ignored, no error); a non-NFC foreign_id is rejected.
func TestForeignLink(t *testing.T) {
	c := load(t)
	pkF, skF, _ := keypair(t, 9) // the foreign identity's key
	_, _, controls := keypair(t, 1)
	rec := ForeignLinkRecord{Controls: controls, ForeignID: "did:example:abc", NotAfter: 100}
	sig, _ := cose.MLDSA65Signer{SK: skF}.Sign(rec.Bytes())
	vF := cose.MLDSA65Verifier{PK: pkF}

	if linked, err := VerifyForeignLink(rec, vF, pkF.Bytes(), sig, 50); err != nil || !linked {
		t.Fatalf("valid link: linked=%v err=%v", linked, err)
	}
	if linked, err := VerifyForeignLink(rec, vF, pkF.Bytes(), sig, 200); err != nil || linked {
		t.Fatalf("expired link must confer no authority: linked=%v err=%v", linked, err)
	}
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0x01
	if linked, err := VerifyForeignLink(rec, vF, pkF.Bytes(), bad, 50); err != nil || linked {
		t.Fatalf("bad cross-signature must confer no authority: linked=%v err=%v", linked, err)
	}
	// Non-NFC foreign_id: use the oracle's known-NFD bytes (a source literal's é could be
	// either normalization form, which would make this test unreliable).
	nfdID := string(mh(t, c.NFC.NFDHex))
	nfd := ForeignLinkRecord{Controls: controls, ForeignID: nfdID, NotAfter: 100}
	if _, err := VerifyForeignLink(nfd, vF, pkF.Bytes(), sig, 50); err == nil {
		t.Fatal("non-NFC foreign_id accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "NonNFC" {
		t.Fatalf("want NonNFC, got %v", err)
	}
}

// TestAttributionAcrossRotation: a receipt signed under K1 stays attributable to the
// durable identity thread after two rotations K1->K2->K3 (R-1.4).
func TestAttributionAcrossRotation(t *testing.T) {
	pk1, sk1, id1 := keypair(t, 1)
	pk2, sk2, id2 := keypair(t, 2)
	pk3, sk3, id3 := keypair(t, 3)

	rec12 := RotationRecord{Old: id1, New: id2, NotBefore: 1000}
	o12, n12, _ := SignRotation(rec12, cose.MLDSA65Signer{SK: sk1}, cose.MLDSA65Signer{SK: sk2})
	rec23 := RotationRecord{Old: id2, New: id3, NotBefore: 2000}
	o23, n23, _ := SignRotation(rec23, cose.MLDSA65Signer{SK: sk2}, cose.MLDSA65Signer{SK: sk3})

	evs := []RotationEvidence{
		{rec12, cose.MLDSA65Verifier{PK: pk1}, cose.MLDSA65Verifier{PK: pk2}, pk1.Bytes(), pk2.Bytes(), o12, n12},
		{rec23, cose.MLDSA65Verifier{PK: pk2}, cose.MLDSA65Verifier{PK: pk3}, pk2.Bytes(), pk3.Bytes(), o23, n23},
	}
	th, err := ResolveThread(evs)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}
	if th.Root != id1 || th.Current != id3 {
		t.Fatalf("thread root=%s current=%s, want %s / %s", th.Root, th.Current, id1, id3)
	}
	// A receipt signed under K1 (the pre-rotation key) is still attributable to the thread.
	if !th.Attributable(id1) {
		t.Error("pre-rotation id must stay attributable after rotation")
	}
	if !th.Attributable(id3) || th.Attributable("bstranger") {
		t.Error("attribution set wrong")
	}
}
