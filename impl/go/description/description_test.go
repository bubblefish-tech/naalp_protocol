// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package description_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/description"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/description/cases.json"

type opVec struct {
	Name             string `json:"name"`
	Effect           uint64 `json:"effect"`
	RequiresApproval uint64 `json:"requires_approval"`
	BodyHex          string `json:"body_hex"`
}

type vec struct {
	Description struct {
		ServiceHex string  `json:"service_hex"`
		Operations []opVec `json:"operations"`
		BodyHex    string  `json:"body_hex"`
		HeadHex    string  `json:"head_hex"`
		IDHex      string  `json:"id_hex"`
	} `json:"description"`
	Directory struct {
		DirectoryHex string   `json:"directory_hex"`
		Version      uint64   `json:"version"`
		MembersAHex  []string `json:"members_a_hex"`
		A            struct {
			BodyHex string `json:"body_hex"`
			HeadHex string `json:"head_hex"`
			IDHex   string `json:"id_hex"`
		} `json:"a"`
		Fork struct {
			MembersBHex []string `json:"members_b_hex"`
			B           struct {
				BodyHex string `json:"body_hex"`
				HeadHex string `json:"head_hex"`
				IDHex   string `json:"id_hex"`
			} `json:"b"`
			FirstDifferingPosition int `json:"first_differing_position"`
		} `json:"fork"`
		LengthFork struct {
			MembersShortHex        []string `json:"members_short_hex"`
			BodyHex                string   `json:"body_hex"`
			FirstDifferingPosition int      `json:"first_differing_position"`
		} `json:"length_fork"`
		DifferentVersion struct {
			Version uint64 `json:"version"`
			BodyHex string `json:"body_hex"`
		} `json:"different_version"`
		DuplicateFirstDifferingPosition int `json:"duplicate_first_differing_position"`
	} `json:"directory"`
	Import struct {
		ImporterHex             string  `json:"importer_hex"`
		Format                  uint64  `json:"format"`
		ForeignHex              string  `json:"foreign_hex"`
		ForeignIDHex            string  `json:"foreign_id_hex"`
		Operations              []opVec `json:"operations"`
		BodyHex                 string  `json:"body_hex"`
		HeadHex                 string  `json:"head_hex"`
		IDHex                   string  `json:"id_hex"`
		ForeignAssertedIdentity string  `json:"foreign_asserted_identity"`
		UnknownFormat           struct {
			Format  uint64 `json:"format"`
			BodyHex string `json:"body_hex"`
		} `json:"unknown_format"`
	} `json:"import"`
}

func hb(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func loadVec(t *testing.T) vec {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vec
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(v.Description.Operations) != 3 {
		t.Fatalf("expected 3 description operations in the corpus, got %d", len(v.Description.Operations))
	}
	return v
}

func opsFrom(vs []opVec) []description.Operation {
	out := make([]description.Operation, len(vs))
	for i, o := range vs {
		out[i] = description.Operation{Name: o.Name, Effect: o.Effect, RequiresApproval: o.RequiresApproval}
	}
	return out
}

func descFrom(t *testing.T, v vec) description.Description {
	return description.Description{Service: hb(t, v.Description.ServiceHex), Operations: opsFrom(v.Description.Operations)}
}

func membersFrom(t *testing.T, hexes []string) [][]byte {
	out := make([][]byte, len(hexes))
	for i, h := range hexes {
		out[i] = hb(t, h)
	}
	return out
}

func dirAFrom(t *testing.T, v vec) description.Directory {
	return description.Directory{
		Directory: hb(t, v.Directory.DirectoryHex),
		Version:   v.Directory.Version,
		Members:   membersFrom(t, v.Directory.MembersAHex),
	}
}

func importFrom(t *testing.T, v vec) description.Import {
	return description.Import{
		Importer:   hb(t, v.Import.ImporterHex),
		Format:     v.Import.Format,
		Foreign:    hb(t, v.Import.ForeignHex),
		Operations: opsFrom(v.Import.Operations),
	}
}

// key derives a real ML-DSA-65 keypair, its raw public-key bytes, and its self-certifying signer id.
func key(t *testing.T, seed byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier, []byte, string) {
	t.Helper()
	var s [mldsa65.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	pkb := pk.Bytes()
	id, err := identity.SignerID(cose.AlgMLDSA65, pkb)
	if err != nil {
		t.Fatalf("SignerID: %v", err)
	}
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}, pkb, id
}

// TestByteParityAgainstOracle: Go encoding == the non-circular Python oracle, byte-for-byte, for
// every object body, head, id, and each operation. Mutation: change any Bytes() field order/tag/key
// and a *_hex compare flips.
func TestByteParityAgainstOracle(t *testing.T) {
	v := loadVec(t)

	// Description body / head / id and each operation body.
	d := descFrom(t, v)
	if got := hex.EncodeToString(d.Bytes()); got != v.Description.BodyHex {
		t.Fatalf("Description.Bytes\n got %s\nwant %s", got, v.Description.BodyHex)
	}
	if got := hex.EncodeToString(d.Head()); got != v.Description.HeadHex {
		t.Fatalf("Description.Head got %s want %s", got, v.Description.HeadHex)
	}
	if got := hex.EncodeToString(d.ID()); got != v.Description.IDHex {
		t.Fatalf("Description.ID got %s want %s", got, v.Description.IDHex)
	}
	for i, o := range d.Operations {
		if got := hex.EncodeToString(o.Bytes()); got != v.Description.Operations[i].BodyHex {
			t.Fatalf("Operation[%d].Bytes got %s want %s", i, got, v.Description.Operations[i].BodyHex)
		}
	}

	// Directory A body / head / id.
	da := dirAFrom(t, v)
	if got := hex.EncodeToString(da.Bytes()); got != v.Directory.A.BodyHex {
		t.Fatalf("Directory.A.Bytes\n got %s\nwant %s", got, v.Directory.A.BodyHex)
	}
	if got := hex.EncodeToString(da.Head()); got != v.Directory.A.HeadHex {
		t.Fatalf("Directory.A.Head got %s want %s", got, v.Directory.A.HeadHex)
	}
	if got := hex.EncodeToString(da.ID()); got != v.Directory.A.IDHex {
		t.Fatalf("Directory.A.ID got %s want %s", got, v.Directory.A.IDHex)
	}
	// Directory B (the fork member list) body.
	db := description.Directory{Directory: hb(t, v.Directory.DirectoryHex), Version: v.Directory.Version, Members: membersFrom(t, v.Directory.Fork.MembersBHex)}
	if got := hex.EncodeToString(db.Bytes()); got != v.Directory.Fork.B.BodyHex {
		t.Fatalf("Directory.B.Bytes\n got %s\nwant %s", got, v.Directory.Fork.B.BodyHex)
	}

	// Import body / head / id and foreign_id.
	im := importFrom(t, v)
	if got := hex.EncodeToString(im.Bytes()); got != v.Import.BodyHex {
		t.Fatalf("Import.Bytes\n got %s\nwant %s", got, v.Import.BodyHex)
	}
	if got := hex.EncodeToString(im.Head()); got != v.Import.HeadHex {
		t.Fatalf("Import.Head got %s want %s", got, v.Import.HeadHex)
	}
	if got := hex.EncodeToString(im.ID()); got != v.Import.IDHex {
		t.Fatalf("Import.ID got %s want %s", got, v.Import.IDHex)
	}
	if got := hex.EncodeToString(im.ForeignID()); got != v.Import.ForeignIDHex {
		t.Fatalf("Import.ForeignID got %s want %s", got, v.Import.ForeignIDHex)
	}
}

// TestOperationEffectAndApprovalAccessors: the per-operation effect + approval-declaration accessor
// reflects the oracle exactly. Mutation: have EffectClass return a constant and the destructive/
// read_only rows flip; have RequiresApprovalFlag return a constant and the approval rows flip.
func TestOperationEffectAndApprovalAccessors(t *testing.T) {
	v := loadVec(t)
	d := descFrom(t, v)
	// The three operations carry distinct effects and approval declarations, so no constant accessor
	// passes: status (read_only, no approval), write_record (non_idempotent_write, approval),
	// purge (destructive, approval).
	var sawReadOnly, sawDestructive, sawApprovalTrue, sawApprovalFalse bool
	for i, o := range v.Description.Operations {
		op, ok := d.Operation(o.Name)
		if !ok {
			t.Fatalf("operation %q not found via accessor", o.Name)
		}
		if op.EffectClass() != policy.NormalizeEffect(o.Effect) {
			t.Fatalf("op[%d] %q EffectClass %d want %d", i, o.Name, op.EffectClass(), policy.NormalizeEffect(o.Effect))
		}
		if op.RequiresApprovalFlag() != (o.RequiresApproval == 1) {
			t.Fatalf("op[%d] %q RequiresApprovalFlag %v want %v", i, o.Name, op.RequiresApprovalFlag(), o.RequiresApproval == 1)
		}
		switch op.EffectClass() {
		case policy.ReadOnly:
			sawReadOnly = true
		case policy.Destructive:
			sawDestructive = true
		}
		if op.RequiresApprovalFlag() {
			sawApprovalTrue = true
		} else {
			sawApprovalFalse = true
		}
	}
	if !(sawReadOnly && sawDestructive && sawApprovalTrue && sawApprovalFalse) {
		t.Fatal("corpus must exercise both effect extremes and both approval states so no constant accessor passes")
	}
	// An unknown operation name is absent (fail-closed lookup).
	if _, ok := d.Operation("no-such-op"); ok {
		t.Fatal("unknown operation name unexpectedly resolved")
	}
}

// TestMalformedApprovalFlagRejected: a requires_approval value outside {0,1} is rejected
// MalformedApprovalFlag (no CBOR boolean on the spine). Mutation: drop the req>1 check in
// operationFromValue and this flips.
func TestMalformedApprovalFlagRejected(t *testing.T) {
	v := loadVec(t)
	bad := description.Description{Service: hb(t, v.Description.ServiceHex), Operations: []description.Operation{
		{Name: "x", Effect: 0, RequiresApproval: 2}, // 2 is not a boolean transcription
	}}
	if _, err := description.ParseDescription(bad.Bytes()); err != description.ErrApprovalFlag {
		t.Fatalf("malformed approval flag got %v, want MalformedApprovalFlag", err)
	}
	// A well-formed 0/1 flag parses.
	if _, err := description.ParseDescription(descFrom(t, v).Bytes()); err != nil {
		t.Fatalf("well-formed description parse: %v", err)
	}
}

// TestDescriptionOfflineReverifyWhenReserved is Checkpoint property #1: a signed Description
// re-verifies byte-identically when an UNRELATED host serves the identical bytes — the authority is
// the signature over the bytes, not the connection/fetch origin. The same signed object is verified
// under the SAME key twice (two hosts serving the same bearer bytes) and reconstructs an identical
// operation table; a foreign key is rejected. Mutation: make VerifyDescription consult anything but
// the signed bytes and the two reconstructions diverge.
func TestDescriptionOfflineReverifyWhenReserved(t *testing.T) {
	v := loadVec(t)
	d := descFrom(t, v)
	signer, verifier, _, _ := key(t, 0x11)
	_, foreign, _, _ := key(t, 0x22)

	obj, err := description.SignDescription(d, signer)
	if err != nil {
		t.Fatalf("SignDescription: %v", err)
	}

	// Host 1 serves obj.
	got1, err := description.VerifyDescription(obj, cose.ProfilePublic, verifier)
	if err != nil {
		t.Fatalf("VerifyDescription (host 1): %v", err)
	}
	// Host 2 (unrelated) serves the byte-identical obj: same reconstruction, same id.
	reserved := append([]byte(nil), obj...) // an unrelated host relays the exact bytes
	got2, err := description.VerifyDescription(reserved, cose.ProfilePublic, verifier)
	if err != nil {
		t.Fatalf("VerifyDescription (host 2, re-served): %v", err)
	}
	if !bytes.Equal(got1.ID(), got2.ID()) || !bytes.Equal(got1.Bytes(), got2.Bytes()) {
		t.Fatal("re-served Description did not re-verify byte-identically")
	}
	if !bytes.Equal(got1.ID(), d.ID()) {
		t.Fatalf("reconstructed id %x != original %x", got1.ID(), d.ID())
	}
	// The reconstructed operation table matches the original, from the bytes alone.
	for _, o := range d.Operations {
		ro, ok := got2.Operation(o.Name)
		if !ok || ro.EffectClass() != o.EffectClass() || ro.RequiresApprovalFlag() != o.RequiresApprovalFlag() {
			t.Fatalf("re-served operation %q did not reconstruct identically", o.Name)
		}
	}
	// A different key never authenticates the same bytes (the signature, not the host, is authority).
	if _, err := description.VerifyDescription(obj, cose.ProfilePublic, foreign); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key verify got %v, want BadSignature", err)
	}
}

// TestDirectoryForkDetectedWithPosition is Checkpoint property #2: two conflicting directory versions
// from ONE signer (same directory + version, different members) are detected as a fork at the
// FIRST-DIFFERING member position; a benign duplicate and a legitimate different version are not
// forks. Mutation: have DetectFork return a constant position and the honest/length cases diverge
// from the oracle; drop the id/version guard and the different-version case wrongly forks.
func TestDirectoryForkDetectedWithPosition(t *testing.T) {
	v := loadVec(t)
	da := dirAFrom(t, v)
	db := description.Directory{Directory: da.Directory, Version: da.Version, Members: membersFrom(t, v.Directory.Fork.MembersBHex)}

	pos, fork := description.DetectFork(da, db)
	if !fork || pos != v.Directory.Fork.FirstDifferingPosition {
		t.Fatalf("fork got (pos=%d fork=%v), want (pos=%d fork=true)", pos, fork, v.Directory.Fork.FirstDifferingPosition)
	}

	// A truncated member list forks at the length of the shorter list.
	short := description.Directory{Directory: da.Directory, Version: da.Version, Members: membersFrom(t, v.Directory.LengthFork.MembersShortHex)}
	lpos, lfork := description.DetectFork(da, short)
	if !lfork || lpos != v.Directory.LengthFork.FirstDifferingPosition {
		t.Fatalf("length fork got (pos=%d fork=%v), want (pos=%d fork=true)", lpos, lfork, v.Directory.LengthFork.FirstDifferingPosition)
	}

	// Identical members => benign duplicate, not a fork.
	if _, fork := description.DetectFork(da, da); fork {
		t.Fatal("identical members wrongly reported as a fork")
	}

	// A different version is a legitimate succession, not a fork.
	dv8 := description.Directory{Directory: da.Directory, Version: v.Directory.DifferentVersion.Version, Members: db.Members}
	if _, fork := description.DetectFork(da, dv8); fork {
		t.Fatal("a different version wrongly reported as a fork")
	}
	// A different directory id is not a conflicting pair.
	other := description.Directory{Directory: []byte("dir-other"), Version: da.Version, Members: db.Members}
	if _, fork := description.DetectFork(da, other); fork {
		t.Fatal("a different directory id wrongly reported as a fork")
	}
}

// TestDirectoryForkProofNonRepudiable: the signed fork proof carries the accused signer's OWN two
// signed directory objects; Verify returns the first-differing position iff BOTH verify under one key
// and they genuinely equivocate. A foreign key, an unnamed signer, identical members, or a different
// version is rejected. Mutation: drop the members-differ check and an identical-members "proof"
// wrongly verifies.
func TestDirectoryForkProofNonRepudiable(t *testing.T) {
	v := loadVec(t)
	signer, verifier, _, id := key(t, 0x11)
	_, foreign, _, _ := key(t, 0x22)

	da := dirAFrom(t, v)
	db := description.Directory{Directory: da.Directory, Version: da.Version, Members: membersFrom(t, v.Directory.Fork.MembersBHex)}
	signedA, err := description.SignDirectory(da, signer)
	if err != nil {
		t.Fatalf("SignDirectory A: %v", err)
	}
	signedB, err := description.SignDirectory(db, signer)
	if err != nil {
		t.Fatalf("SignDirectory B: %v", err)
	}

	fp := description.DirectoryForkProof{Signer: []byte(id), SignedA: signedA, SignedB: signedB}
	pos, err := fp.Verify(cose.ProfilePublic, verifier)
	if err != nil {
		t.Fatalf("ForkProof.Verify (honest): %v", err)
	}
	if pos != v.Directory.Fork.FirstDifferingPosition {
		t.Fatalf("fork proof position %d want %d", pos, v.Directory.Fork.FirstDifferingPosition)
	}

	// A foreign key does not verify the accused's signatures.
	if _, err := fp.Verify(cose.ProfilePublic, foreign); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key fork proof got %v, want BadSignature", err)
	}
	// An unnamed signer is not evidence.
	unnamed := description.DirectoryForkProof{Signer: nil, SignedA: signedA, SignedB: signedB}
	if _, err := unnamed.Verify(cose.ProfilePublic, verifier); err != description.ErrForkProofInvalid {
		t.Fatalf("unnamed fork proof got %v, want DirForkProofInvalid", err)
	}
	// Identical members are not equivocation (same signed object twice).
	dup := description.DirectoryForkProof{Signer: []byte(id), SignedA: signedA, SignedB: signedA}
	if _, err := dup.Verify(cose.ProfilePublic, verifier); err != description.ErrForkProofInvalid {
		t.Fatalf("identical-members fork proof got %v, want DirForkProofInvalid", err)
	}
	// A different version is a succession, not a fork.
	dv8 := description.Directory{Directory: da.Directory, Version: v.Directory.DifferentVersion.Version, Members: db.Members}
	signedV8, _ := description.SignDirectory(dv8, signer)
	succ := description.DirectoryForkProof{Signer: []byte(id), SignedA: signedA, SignedB: signedV8}
	if _, err := succ.Verify(cose.ProfilePublic, verifier); err != description.ErrForkProofInvalid {
		t.Fatalf("different-version fork proof got %v, want DirForkProofInvalid", err)
	}
}

// TestImportForeignIdentityNeverAuthorizes is Checkpoint property #3: an imported foreign card drives
// an N-AALP effect mapping, and the identity embedded in the foreign bytes NEVER becomes the
// authorization identity — the wrapping signer, recomputed self-certifyingly from the key, is the
// sole authority. Mutation: have VerifyImport return im.Importer verbatim (instead of the recomputed
// key id) or skip the match check and an attacker who writes a victim's id into the body is
// authorized as the victim.
func TestImportForeignIdentityNeverAuthorizes(t *testing.T) {
	v := loadVec(t)
	honestSigner, honestV, honestPK, honestID := key(t, 0x11)
	attackerSigner, attackerV, attackerPK, attackerID := key(t, 0x22)

	// The foreign bytes carry a FOREIGN identity claim (embedded in the opaque blob).
	foreign := hb(t, v.Import.ForeignHex)
	foreignIdentity := v.Import.ForeignAssertedIdentity
	if !strings.Contains(string(foreign), foreignIdentity) {
		t.Fatalf("test fixture: foreign identity %q not present in the foreign bytes", foreignIdentity)
	}

	// Honest import: importer = the honest signer's own id.
	im := description.Import{Importer: []byte(honestID), Format: v.Import.Format, Foreign: foreign, Operations: opsFrom(v.Import.Operations)}
	obj, err := description.SignImport(im, honestSigner)
	if err != nil {
		t.Fatalf("SignImport: %v", err)
	}
	r, err := description.VerifyImport(obj, cose.ProfilePublic, cose.AlgMLDSA65, honestPK, honestV)
	if err != nil {
		t.Fatalf("VerifyImport (honest): %v", err)
	}
	// The authority is the wrapping signer, NOT the foreign identity in the bytes.
	if r.AuthorityID != honestID {
		t.Fatalf("authority id %q, want the wrapping signer id %q", r.AuthorityID, honestID)
	}
	if r.AuthorityID == foreignIdentity {
		t.Fatal("foreign identity leaked into the authorization identity")
	}
	// The imported card drives the N-AALP effect mapping, and the foreign bytes are bound by id.
	if !bytes.Equal(r.ForeignID, im.ForeignID()) {
		t.Fatal("resolved foreign id does not bind the carried foreign bytes")
	}
	submit, ok := findResolvedOp(r.Operations, "submit")
	if !ok || submit.EffectClass() != policy.IdempotentWrite || !submit.RequiresApprovalFlag() {
		t.Fatal("imported card did not drive the attested effect mapping for 'submit'")
	}

	// Confused-deputy: an attacker forges the body's importer field to the VICTIM's id and signs with
	// their OWN key. VerifyImport recomputes the id from the attacker's key and rejects the mismatch —
	// a signer can only ever import AS ITSELF, never as an identity it merely names.
	forged := description.Import{Importer: []byte(honestID), Format: v.Import.Format, Foreign: foreign, Operations: opsFrom(v.Import.Operations)}
	forgedObj, _ := description.SignImport(forged, attackerSigner)
	if _, err := description.VerifyImport(forgedObj, cose.ProfilePublic, cose.AlgMLDSA65, attackerPK, attackerV); err != description.ErrImporterMismatch {
		t.Fatalf("forged-importer got %v, want ImporterMismatch", err)
	}
	// The attacker importing the SAME foreign bytes AS ITSELF is authorized only as the attacker — the
	// identical foreign identity in the bytes yields a DIFFERENT authority than the honest import,
	// proving the foreign id never determines authority.
	self := description.Import{Importer: []byte(attackerID), Format: v.Import.Format, Foreign: foreign, Operations: opsFrom(v.Import.Operations)}
	selfObj, _ := description.SignImport(self, attackerSigner)
	r2, err := description.VerifyImport(selfObj, cose.ProfilePublic, cose.AlgMLDSA65, attackerPK, attackerV)
	if err != nil {
		t.Fatalf("VerifyImport (attacker-as-self): %v", err)
	}
	if r2.AuthorityID != attackerID || r2.AuthorityID == honestID {
		t.Fatalf("same foreign bytes yielded authority %q; must be the wrapping signer %q, not the honest importer", r2.AuthorityID, attackerID)
	}
}

// TestUnknownImportFormatRejected is the C18 audit-fix 0d regression: field 2 (format) is the CLOSED
// naalp-description-format enum {1,2,3}. A code outside the set (99) is well-formed CBOR but not a
// registered format and MUST be rejected UnknownDescriptionFormat on decode. Mutation: drop the
// isKnownFormat check in ParseImport and the format=99 body wrongly decodes.
func TestUnknownImportFormatRejected(t *testing.T) {
	v := loadVec(t)
	// Byte parity: an Import carrying format=99 matches the oracle's forbidden body.
	bad := description.Import{
		Importer:   hb(t, v.Import.ImporterHex),
		Format:     v.Import.UnknownFormat.Format,
		Foreign:    hb(t, v.Import.ForeignHex),
		Operations: opsFrom(v.Import.Operations),
	}
	if got := hex.EncodeToString(bad.Bytes()); got != v.Import.UnknownFormat.BodyHex {
		t.Fatalf("format=99 Import body\n got %s\nwant %s", got, v.Import.UnknownFormat.BodyHex)
	}
	if _, err := description.ParseImport(hb(t, v.Import.UnknownFormat.BodyHex)); err != description.ErrUnknownFormat {
		t.Fatalf("ParseImport(format=99) got %v, want UnknownDescriptionFormat", err)
	}
	// A well-formed format still parses.
	if _, err := description.ParseImport(importFrom(t, v).Bytes()); err != nil {
		t.Fatalf("well-formed import parse: %v", err)
	}
}

// TestVerifierKeyMismatchRejected is the C18 audit-fix 0b regression: VerifyImport derives the
// authority id from (alg, pubkey) but checks the signature with v. If a caller passes v for key A and
// pubkey for key B, the signature verifies under A yet the authority id would be minted for B — the
// confused deputy. The fix binds (alg, pubkey) to the verifying key: alg == v.Alg() and pubkey ==
// v.PubKey(), else VerifierKeyMismatch. Mutation: remove that binding check and the v(A)+pubkey(B)
// call wrongly resolves an authority for B.
func TestVerifierKeyMismatchRejected(t *testing.T) {
	v := loadVec(t)
	signerA, vA, pkA, idA := key(t, 0x11)
	_, vB, pkB, _ := key(t, 0x22)

	// An honest import signed by A, whose importer field is A's own id.
	im := description.Import{Importer: []byte(idA), Format: v.Import.Format, Foreign: hb(t, v.Import.ForeignHex), Operations: opsFrom(v.Import.Operations)}
	obj, err := description.SignImport(im, signerA)
	if err != nil {
		t.Fatalf("SignImport: %v", err)
	}

	// Positive control: v(A) + pubkey(A) resolves the authority as A.
	r, err := description.VerifyImport(obj, cose.ProfilePublic, cose.AlgMLDSA65, pkA, vA)
	if err != nil || r.AuthorityID != idA {
		t.Fatalf("honest key-matched import got (%v, %q), want (nil, %q)", err, r.AuthorityID, idA)
	}
	// Confused deputy: the signature is checked with vA (key A), but pubkey is B's. The id would be
	// derived for B — REJECTED VerifierKeyMismatch before any authority is minted.
	if _, err := description.VerifyImport(obj, cose.ProfilePublic, cose.AlgMLDSA65, pkB, vA); err != description.ErrVerifierKeyMismatch {
		t.Fatalf("v(A)+pubkey(B) got %v, want VerifierKeyMismatch", err)
	}
	// A mismatched alg (with v for A) is likewise rejected before verification.
	if _, err := description.VerifyImport(obj, cose.ProfilePublic, cose.AlgMLDSA87, pkA, vA); err != description.ErrVerifierKeyMismatch {
		t.Fatalf("alg mismatch got %v, want VerifierKeyMismatch", err)
	}
	// Sanity: vB with pkB verifies its own signature-shape path (bad signature, not key mismatch) —
	// proving the mismatch guard is specifically about (alg,pubkey) vs v, not a blanket reject.
	if _, err := description.VerifyImport(obj, cose.ProfilePublic, cose.AlgMLDSA65, pkB, vB); err != cose.ErrBadSignature {
		t.Fatalf("v(B)+pubkey(B) on an A-signed object got %v, want BadSignature", err)
	}
}

func findResolvedOp(ops []description.Operation, name string) (description.Operation, bool) {
	for _, op := range ops {
		if op.Name == name {
			return op, true
		}
	}
	return description.Operation{}, false
}

// crossLangPinnedSignedDescriptionSHA384 is the pinned SHA-384 of the deterministic COSE_Sign1 object
// obtained by signing the Description body with the shared all-0x11 32-byte ML-DSA-65 seed. Go and
// Rust both pin this value, proving the two independent ML-DSA stacks emit a byte-identical signed
// Description for identical canonical CBOR + seed. Mutation: change the Description encoding or the
// signing input and the digest diverges from the pin.
const crossLangPinnedSignedDescriptionSHA384 = "c8aa348b49c469c7565a292b1ebe3e92af7763705bba728e8ef1b39379a30a0d213f6640ef997a26aaa0dd1550401a23"

// TestCrossLangSignedDescriptionPin proves Go and Rust produce a byte-identical signed Description for
// the same body + seed (deterministic ML-DSA-65 over identical canonical CBOR).
func TestCrossLangSignedDescriptionPin(t *testing.T) {
	v := loadVec(t)
	d := descFrom(t, v)
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 0x11
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	obj, err := description.SignDescription(d, cose.MLDSA65Signer{SK: sk})
	if err != nil {
		t.Fatalf("SignDescription: %v", err)
	}
	dg := sha512.Sum384(obj)
	got := hex.EncodeToString(dg[:])
	t.Logf("CROSS-LANG signed Description SHA-384 (seed=0x11*32): %s", got)
	if crossLangPinnedSignedDescriptionSHA384 != "PIN_ME" && got != crossLangPinnedSignedDescriptionSHA384 {
		t.Fatalf("cross-lang signed-description digest %s != pinned %s", got, crossLangPinnedSignedDescriptionSHA384)
	}
}
