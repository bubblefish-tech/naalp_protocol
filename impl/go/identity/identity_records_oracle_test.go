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

// TestIdentityRecordsAgainstOracle grades the eleven RECORD + THREAD surfaces that previously had
// NO independent oracle (tools/identity_records_oracle.py; F3): RevocationRecord, RevokedAt,
// VerifyRevocation, ForeignLinkRecord, VerifyForeignLink, RotationEvidence, Thread,
// Thread.Attributable, ResolveThread. See vectors/identity_records/cases.json for the full
// non-circular derivation notes, including VerifyRevocation's deployer-configured recovery-key
// authorization (§5.3), which the impl implements fail-closed.

const identityRecordsVectorPath = "../../../vectors/identity_records/cases.json"

type recordsCases struct {
	Revocation struct {
		RecordBytes []struct {
			Name     string `json:"name"`
			Key      string `json:"key"`
			NotAfter uint64 `json:"not_after"`
			BytesHex string `json:"bytes_hex"`
		} `json:"record_bytes"`
		RevokedAt []struct {
			Name        string `json:"name"`
			Revocations []struct {
				Key      string `json:"key"`
				NotAfter uint64 `json:"not_after"`
			} `json:"revocations"`
			QueryKey       string  `json:"query_key"`
			QueryPosition  uint64  `json:"query_position"`
			ExpectRevoked  bool    `json:"expect_revoked"`
			ExpectNotAfter *uint64 `json:"expect_not_after"`
		} `json:"revoked_at"`
		Verify []struct {
			Name   string `json:"name"`
			Record struct {
				Key      string `json:"key"`
				NotAfter uint64 `json:"not_after"`
			} `json:"record"`
			CandidateAlg          int      `json:"candidate_alg"`
			CandidatePubkeyHex    string   `json:"candidate_pubkey_hex"`
			SigHex                string   `json:"sig_hex"`
			AuthorizedRecoveryIDs []string `json:"authorized_recovery_ids"`
			ExpectValid           bool     `json:"expect_valid"`
			ExpectErrorKind       string   `json:"expect_error_kind"`
			Note                  string   `json:"note"`
		} `json:"verify"`
	} `json:"revocation"`

	ForeignLink struct {
		RecordBytes []struct {
			Name      string `json:"name"`
			Controls  string `json:"controls"`
			ForeignID string `json:"foreign_id"`
			NotAfter  uint64 `json:"not_after"`
			BytesHex  string `json:"bytes_hex"`
		} `json:"record_bytes"`
		Verify []struct {
			Name   string `json:"name"`
			Record struct {
				Controls  string `json:"controls"`
				ForeignID string `json:"foreign_id"`
				NotAfter  uint64 `json:"not_after"`
			} `json:"record"`
			CandidateAlg       int     `json:"candidate_alg"`
			CandidatePubkeyHex string  `json:"candidate_pubkey_hex"`
			SigHex             string  `json:"sig_hex"`
			Now                uint64  `json:"now"`
			ExpectLinked       bool    `json:"expect_linked"`
			ExpectErrorKind    string  `json:"expect_error_kind"`
			ExpectControls     *string `json:"expect_controls"`
			ExpectForeignID    *string `json:"expect_foreign_id"`
			Note               string  `json:"note"`
		} `json:"verify"`
	} `json:"foreign_link"`

	Thread struct {
		Resolve []struct {
			Name     string `json:"name"`
			Evidence []struct {
				Old            string `json:"old"`
				New            string `json:"new"`
				NotBefore      uint64 `json:"not_before"`
				OldAlg         int    `json:"old_alg"`
				OldPubkeyHex   string `json:"old_pubkey_hex"`
				OldSigHex      string `json:"old_sig_hex"`
				NewAlg         int    `json:"new_alg"`
				NewPubkeyHex   string `json:"new_pubkey_hex"`
				NewSigHex      string `json:"new_sig_hex"`
				RecordBytesHex string `json:"record_bytes_hex"`
			} `json:"evidence"`
			ExpectError  string `json:"expect_error"`
			ExpectThread *struct {
				Root    string   `json:"root"`
				Current string   `json:"current"`
				Chain   []string `json:"chain"`
			} `json:"expect_thread"`
			Note string `json:"note"`
		} `json:"resolve"`
		Attributable []struct {
			Name   string `json:"name"`
			Thread struct {
				Root    string   `json:"root"`
				Current string   `json:"current"`
				Chain   []string `json:"chain"`
			} `json:"thread"`
			Query  string `json:"query"`
			Expect bool   `json:"expect"`
		} `json:"attributable"`
	} `json:"thread"`
}

func loadRecordsCases(t *testing.T) recordsCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(identityRecordsVectorPath))
	if err != nil {
		t.Fatalf("read identity_records corpus: %v", err)
	}
	var c recordsCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse identity_records corpus: %v", err)
	}
	return c
}

func recHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// verifierFrom builds a cose.MLDSA65Verifier from a raw public-key hex string — never from a
// seed — matching how a real verifier only ever holds a candidate PUBLIC key.
func verifierFrom(t *testing.T, pubHex string) (cose.MLDSA65Verifier, []byte) {
	t.Helper()
	pub := recHex(t, pubHex)
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pub); err != nil {
		t.Fatalf("unmarshal pubkey: %v", err)
	}
	return cose.MLDSA65Verifier{PK: &pk}, pub
}

// ---- RevocationRecord.Bytes (§5.3) -------------------------------------------------------------

// TestRevocationRecordBytesMatchesOracle grades RevocationRecord.Bytes() byte-for-byte against the
// independent oracle over varying key strings and not_after magnitudes.
func TestRevocationRecordBytesMatchesOracle(t *testing.T) {
	c := loadRecordsCases(t)
	if len(c.Revocation.RecordBytes) == 0 {
		t.Fatal("no revocation record_bytes cases")
	}
	for _, tc := range c.Revocation.RecordBytes {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			r := RevocationRecord{Key: tc.Key, NotAfter: tc.NotAfter}
			if got := hex.EncodeToString(r.Bytes()); got != tc.BytesHex {
				t.Fatalf("RevocationRecord.Bytes()\n got %s\nwant %s", got, tc.BytesHex)
			}
		})
	}
}

// ---- RevokedAt (§5.3) — set-based scenarios graded via a thin selection loop --------------------

// TestRevokedAtMatchesOracle grades RevokedAt over the oracle's set-based scenarios: the impl's
// RevokedAt(record, position) is a pure per-record boolean, so the test performs the (key ->
// matching revocation) selection itself, then asserts the per-record verdict. The boundary case
// ("at_boundary_still_valid") is the MUTATION ANCHOR: flipping RevokedAt's `>` to `>=` flips it.
func TestRevokedAtMatchesOracle(t *testing.T) {
	c := loadRecordsCases(t)
	if len(c.Revocation.RevokedAt) == 0 {
		t.Fatal("no revoked_at scenarios")
	}
	for _, sc := range c.Revocation.RevokedAt {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			var revoked bool
			var notAfter uint64
			found := false
			for _, rv := range sc.Revocations {
				if rv.Key != sc.QueryKey {
					continue
				}
				found = true
				rec := RevocationRecord{Key: rv.Key, NotAfter: rv.NotAfter}
				if RevokedAt(rec, sc.QueryPosition) {
					revoked = true
					notAfter = rv.NotAfter
				}
			}
			if !found {
				revoked = false
			}
			if revoked != sc.ExpectRevoked {
				t.Fatalf("revoked: got %v want %v", revoked, sc.ExpectRevoked)
			}
			if sc.ExpectRevoked {
				if sc.ExpectNotAfter == nil || notAfter != *sc.ExpectNotAfter {
					t.Fatalf("not_after: got %d want %v", notAfter, sc.ExpectNotAfter)
				}
			}
		})
	}
}

// ---- VerifyRevocation (§5.3, §5.5) --------------------------------------------------------------

// TestVerifyRevocationMatchesOracle grades VerifyRevocation against the independent oracle across
// all seven authorization×signature cases. §5.3 permits a Revocation to be signed by the key it
// revokes OR by a deployer-configured recovery key; VerifyRevocation takes the deployer's
// authorized recovery-id set and accepts a signer iff its recomputed id equals record.Key or is a
// member of that set, then verifies the signature (membership BEFORE signature, fail-closed).
// MUTATION ANCHORS: "recovery_key_not_configured_reject" (a valid recovery-key signature with an
// EMPTY authorized set → SignerMismatch) and "wrong_key_reject" — dropping the membership guard
// flips both to accept. (Recovery-key authorization was approved 2026-08-21; the earlier
// recovery-key deferral is resolved.)
func TestVerifyRevocationMatchesOracle(t *testing.T) {
	c := loadRecordsCases(t)
	if len(c.Revocation.Verify) == 0 {
		t.Fatal("no revocation verify cases")
	}
	for _, tc := range c.Revocation.Verify {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			v, pub := verifierFrom(t, tc.CandidatePubkeyHex)
			rec := RevocationRecord{Key: tc.Record.Key, NotAfter: tc.Record.NotAfter}
			err := VerifyRevocation(rec, v, pub, recHex(t, tc.SigHex), tc.AuthorizedRecoveryIDs)
			if tc.ExpectValid {
				if err != nil {
					t.Fatalf("%s: expected valid, got %v — %s", tc.Name, err, tc.Note)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s: expected reject, got accept — %s", tc.Name, tc.Note)
			}
			if tc.ExpectErrorKind != "" {
				ce, ok := err.(*cose.Error)
				if !ok || ce.Kind != tc.ExpectErrorKind {
					t.Fatalf("%s: want error kind %s, got %v", tc.Name, tc.ExpectErrorKind, err)
				}
			}
		})
	}
}

// ---- ForeignLinkRecord.Bytes (§5.4) --------------------------------------------------------------

// TestForeignLinkRecordBytesMatchesOracle grades ForeignLinkRecord.Bytes() byte-for-byte, including
// the NFC-vs-NFD case proving Bytes() is a pure encoder (the NFC requirement lives in
// VerifyForeignLink, not in Bytes()). MUTATION ANCHOR: collapsing NFC/NFD to the same bytes (e.g.
// via a normalizing encoder) would flip nfd_form_different_bytes' byte-inequality assertion.
func TestForeignLinkRecordBytesMatchesOracle(t *testing.T) {
	c := loadRecordsCases(t)
	if len(c.ForeignLink.RecordBytes) < 2 {
		t.Fatal("expected >=2 foreign_link record_bytes cases")
	}
	seen := map[string]string{}
	for _, tc := range c.ForeignLink.RecordBytes {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			r := ForeignLinkRecord{Controls: tc.Controls, ForeignID: tc.ForeignID, NotAfter: tc.NotAfter}
			got := hex.EncodeToString(r.Bytes())
			if got != tc.BytesHex {
				t.Fatalf("ForeignLinkRecord.Bytes()\n got %s\nwant %s", got, tc.BytesHex)
			}
			seen[tc.Name] = got
		})
	}
	if seen["nfc_form"] == seen["nfd_form_different_bytes"] {
		t.Fatal("NFC and NFD foreign_id forms must encode to different bytes")
	}
}

// ---- VerifyForeignLink (§5.4, §5.5) --------------------------------------------------------------

// TestVerifyForeignLinkMatchesOracle grades VerifyForeignLink against the oracle: valid+unexpired
// links, the not_after boundary (MUTATION ANCHOR for `now > NotAfter`), expiry (ignored, no error),
// wrong-key (ignored, no error — the SAME bucket as expiry per §5.5), and non-NFC foreign_id
// (NonNFC, checked before expiry/signature).
func TestVerifyForeignLinkMatchesOracle(t *testing.T) {
	c := loadRecordsCases(t)
	if len(c.ForeignLink.Verify) == 0 {
		t.Fatal("no foreign_link verify cases")
	}
	for _, tc := range c.ForeignLink.Verify {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			v, pub := verifierFrom(t, tc.CandidatePubkeyHex)
			rec := ForeignLinkRecord{
				Controls: tc.Record.Controls, ForeignID: tc.Record.ForeignID, NotAfter: tc.Record.NotAfter,
			}
			linked, err := VerifyForeignLink(rec, v, pub, recHex(t, tc.SigHex), tc.Now)
			if tc.ExpectErrorKind != "" {
				if err == nil {
					t.Fatalf("%s: expected error kind %s, got nil (linked=%v)", tc.Name, tc.ExpectErrorKind, linked)
				}
				ce, ok := err.(*cose.Error)
				if !ok || ce.Kind != tc.ExpectErrorKind {
					t.Fatalf("%s: want error kind %s, got %v", tc.Name, tc.ExpectErrorKind, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: unexpected error %v — %s", tc.Name, err, tc.Note)
			}
			if linked != tc.ExpectLinked {
				t.Fatalf("%s: linked got %v want %v — %s", tc.Name, linked, tc.ExpectLinked, tc.Note)
			}
			if tc.ExpectLinked {
				if tc.ExpectControls == nil || tc.Record.Controls != *tc.ExpectControls {
					t.Fatalf("%s: controls got %s want %v", tc.Name, tc.Record.Controls, tc.ExpectControls)
				}
				if tc.ExpectForeignID == nil || tc.Record.ForeignID != *tc.ExpectForeignID {
					t.Fatalf("%s: foreign_id got %s want %v", tc.Name, tc.Record.ForeignID, tc.ExpectForeignID)
				}
			}
		})
	}
}

// ---- RotationEvidence / Thread / ResolveThread (§5.2, R-1.4) -------------------------------------

// buildEvidence constructs a []RotationEvidence from the oracle's per-link fixture: each
// RotationRecord is rebuilt from its logical fields (never trusted directly from record_bytes_hex),
// and RotationRecord.Bytes() is cross-checked against the oracle's record_bytes_hex so a
// constant/field-ignoring encoder would diverge before ResolveThread is ever reached.
func buildEvidence(t *testing.T, evs []struct {
	Old            string `json:"old"`
	New            string `json:"new"`
	NotBefore      uint64 `json:"not_before"`
	OldAlg         int    `json:"old_alg"`
	OldPubkeyHex   string `json:"old_pubkey_hex"`
	OldSigHex      string `json:"old_sig_hex"`
	NewAlg         int    `json:"new_alg"`
	NewPubkeyHex   string `json:"new_pubkey_hex"`
	NewSigHex      string `json:"new_sig_hex"`
	RecordBytesHex string `json:"record_bytes_hex"`
}) []RotationEvidence {
	t.Helper()
	out := make([]RotationEvidence, 0, len(evs))
	for _, e := range evs {
		rec := RotationRecord{Old: e.Old, New: e.New, NotBefore: e.NotBefore}
		if got := hex.EncodeToString(rec.Bytes()); got != e.RecordBytesHex {
			t.Fatalf("RotationRecord.Bytes() (RotationEvidence input)\n got %s\nwant %s", got, e.RecordBytesHex)
		}
		oldV, oldPub := verifierFrom(t, e.OldPubkeyHex)
		newV, newPub := verifierFrom(t, e.NewPubkeyHex)
		out = append(out, RotationEvidence{
			Record: rec, OldV: oldV, NewV: newV,
			OldPub: oldPub, NewPub: newPub,
			OldSig: recHex(t, e.OldSigHex), NewSig: recHex(t, e.NewSigHex),
		})
	}
	return out
}

// TestResolveThreadMatchesOracle grades ResolveThread against the oracle: empty chain, a single
// link, a 3-link contiguous chain, and TWO distinct broken-chain shapes that are each a MUTATION
// ANCHOR for a DIFFERENT guard inside ResolveThread — "broken_link_old_mismatch" pins the
// CONTIGUITY check (`e.Record.Old != prevNew`), and "broken_link_forged_old_signature" pins the
// per-link CO-SIGNATURE check (VerifyRotation), isolating one from the other.
func TestResolveThreadMatchesOracle(t *testing.T) {
	c := loadRecordsCases(t)
	if len(c.Thread.Resolve) == 0 {
		t.Fatal("no thread resolve cases")
	}
	for _, tc := range c.Thread.Resolve {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			evs := buildEvidence(t, tc.Evidence)
			th, err := ResolveThread(evs)
			if tc.ExpectError != "" {
				if err == nil {
					t.Fatalf("%s: expected error %s, got accept (thread=%+v) — %s", tc.Name, tc.ExpectError, th, tc.Note)
				}
				ce, ok := err.(*cose.Error)
				if !ok || ce.Kind != tc.ExpectError {
					t.Fatalf("%s: want error kind %s, got %v", tc.Name, tc.ExpectError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: unexpected error %v — %s", tc.Name, err, tc.Note)
			}
			if tc.ExpectThread == nil {
				t.Fatalf("%s: oracle declared no expected thread but impl accepted", tc.Name)
			}
			if th.Root != tc.ExpectThread.Root || th.Current != tc.ExpectThread.Current {
				t.Fatalf("%s: root/current got (%s,%s) want (%s,%s)",
					tc.Name, th.Root, th.Current, tc.ExpectThread.Root, tc.ExpectThread.Current)
			}
			if len(th.Chain) != len(tc.ExpectThread.Chain) {
				t.Fatalf("%s: chain length got %d want %d", tc.Name, len(th.Chain), len(tc.ExpectThread.Chain))
			}
			for i, id := range tc.ExpectThread.Chain {
				if th.Chain[i] != id {
					t.Fatalf("%s: chain[%d] got %s want %s", tc.Name, i, th.Chain[i], id)
				}
			}
		})
	}
}

// TestThreadAttributableMatchesOracle grades Thread.Attributable over the resolved 3-link thread:
// the root, every intermediate key, and the current key are all attributable; an unrelated key is
// not. "unrelated_key_not_attributable" is the MUTATION ANCHOR for the membership check itself
// (a stub that always returns true would flip it).
func TestThreadAttributableMatchesOracle(t *testing.T) {
	c := loadRecordsCases(t)
	if len(c.Thread.Attributable) == 0 {
		t.Fatal("no thread attributable cases")
	}
	for _, tc := range c.Thread.Attributable {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			th := &Thread{Root: tc.Thread.Root, Current: tc.Thread.Current, Chain: tc.Thread.Chain}
			if got := th.Attributable(tc.Query); got != tc.Expect {
				t.Fatalf("Attributable(%s): got %v want %v", tc.Query, got, tc.Expect)
			}
		})
	}
}
