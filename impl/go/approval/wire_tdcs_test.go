// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package approval_test

// Byte-parity + behavioral graders for the two R-TDCS wire additions (design.md §25, C22), graded
// against the independent oracle vectors/trust_decision/cases.json (built by tools/trust_decision_oracle.py,
// non-circular per F3). Go and Rust grade the SAME file, so Go == Rust == oracle bytes.
//   - R-TDCS-5 (audience): an approval that names an audience binds it under signature (distinct
//     bytes + id); one that names none encodes byte-identically to a 5-field approval; VerifyAudience
//     rejects a use context other than the named one, and passes any context when none is named.
//   - R-TDCS-3 (refusal): RefusalFromRecord carries the coarse outcome + the full record's content id
//     and NOTHING from inside the record (the reason never leaks); ParseRefusal rejects an unknown
//     outcome, an extra field, a missing/empty record id.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

const tdcsWirePath = "../../../vectors/trust_decision/cases.json"

type tdcsWireCases struct {
	Audience struct {
		Approver           string `json:"approver"`
		ApprovesHex        string `json:"approves_hex"`
		Grant              uint64 `json:"grant"`
		NonceHex           string `json:"nonce_hex"`
		NotAfter           uint64 `json:"not_after"`
		UseContextMatch    string `json:"use_context_match"`
		UseContextMismatch string `json:"use_context_mismatch"`
		Cases              []struct {
			Name          string `json:"name"`
			Audience      string `json:"audience"`
			RecordHex     string `json:"record_hex"`
			ApprovalIDHex string `json:"approval_id_hex"`
		} `json:"cases"`
	} `json:"audience"`
	Refusal struct {
		FullRecordHex   string `json:"full_record_hex"`
		FullRecordIDHex string `json:"full_record_id_hex"`
		LeakedReason    string `json:"leaked_reason"`
		Cases           []struct {
			Name      string `json:"name"`
			Outcome   uint64 `json:"outcome"`
			RecordHex string `json:"record_hex"`
		} `json:"cases"`
		Reject struct {
			UnknownOutcomeHex       string `json:"unknown_outcome_hex"`
			DetailLeakExtraFieldHex string `json:"detail_leak_extra_field_hex"`
			MissingRecordHex        string `json:"missing_record_hex"`
			EmptyRecordHex          string `json:"empty_record_hex"`
		} `json:"reject"`
	} `json:"refusal"`
}

func loadTDCSWire(t *testing.T) tdcsWireCases {
	t.Helper()
	b, err := os.ReadFile(tdcsWirePath)
	if err != nil {
		t.Fatalf("read %s: %v", tdcsWirePath, err)
	}
	var c tdcsWireCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return c
}

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestTDCS5AudienceByteParityAndCheck: R-TDCS-5. An approval carrying the OPTIONAL audience field
// encodes byte-identically to the oracle (Go == Rust == oracle), and a named audience is checked at
// use — a mismatched context is rejected, an absent audience passes any context, a matching one
// verifies.
func TestTDCS5AudienceByteParityAndCheck(t *testing.T) {
	c := loadTDCSWire(t)
	a := c.Audience
	for _, tc := range a.Cases {
		rec := approval.ApprovalRecord{
			Approves: hx(t, a.ApprovesHex),
			Approver: a.Approver,
			Grant:    a.Grant,
			Nonce:    hx(t, a.NonceHex),
			NotAfter: a.NotAfter,
			Audience: tc.Audience, // "" for audience_absent
		}
		if got := hex.EncodeToString(rec.Bytes()); got != tc.RecordHex {
			t.Fatalf("%s: approval bytes != oracle\n got %s\nwant %s", tc.Name, got, tc.RecordHex)
		}
		if got := hex.EncodeToString(rec.ID()); got != tc.ApprovalIDHex {
			t.Fatalf("%s: approval id != oracle\n got %s\nwant %s", tc.Name, got, tc.ApprovalIDHex)
		}
	}

	// A named audience must equal the absent-audience bytes iff the audience is empty — i.e. naming a
	// context changes the signed bytes, so a verdict cannot be silently moved to another context.
	present := approval.ApprovalRecord{Approves: hx(t, a.ApprovesHex), Approver: a.Approver, Grant: a.Grant, Nonce: hx(t, a.NonceHex), NotAfter: a.NotAfter, Audience: a.UseContextMatch}
	absent := approval.ApprovalRecord{Approves: hx(t, a.ApprovesHex), Approver: a.Approver, Grant: a.Grant, Nonce: hx(t, a.NonceHex), NotAfter: a.NotAfter}
	if bytes.Equal(present.Bytes(), absent.Bytes()) {
		t.Fatal("naming an audience must change the approval bytes")
	}

	// The check: named audience must match the use context; absent audience passes any context.
	if err := approval.VerifyAudience(present, a.UseContextMatch); err != nil {
		t.Fatalf("matching audience should verify, got %v", err)
	}
	if err := approval.VerifyAudience(present, a.UseContextMismatch); err == nil {
		t.Fatal("mismatched audience must be rejected, got nil")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "AudienceMismatch" {
		t.Fatalf("want AudienceMismatch, got %v", err)
	}
	if err := approval.VerifyAudience(absent, a.UseContextMismatch); err != nil {
		t.Fatalf("an approval that names no audience must pass any context, got %v", err)
	}
}

// TestTDCS3RefusalCoarseAndNoLeak: R-TDCS-3. RefusalFromRecord yields the exact oracle bytes for each
// closed-set outcome, carries the full record's content id, and NEVER carries the record's
// discriminating detail (the reason). ParseRefusal round-trips a conformant refusal and rejects every
// non-conformant shape: an unknown outcome, an extra field, a missing/empty record id.
func TestTDCS3RefusalCoarseAndNoLeak(t *testing.T) {
	c := loadTDCSWire(t)
	r := c.Refusal
	fullRecord := hx(t, r.FullRecordHex)
	recordID := hx(t, r.FullRecordIDHex)
	reason := []byte(r.LeakedReason)

	for _, tc := range r.Cases {
		ref := approval.RefusalFromRecord(tc.Outcome, fullRecord)
		b := ref.Bytes()
		if got := hex.EncodeToString(b); got != tc.RecordHex {
			t.Fatalf("%s: refusal bytes != oracle\n got %s\nwant %s", tc.Name, got, tc.RecordHex)
		}
		if bytes.Contains(b, reason) {
			t.Fatalf("%s: the record's reason LEAKED into the party-visible refusal", tc.Name)
		}
		if !bytes.Contains(b, recordID) {
			t.Fatalf("%s: refusal does not carry the full-record content id", tc.Name)
		}
		// Round-trip: a conformant refusal parses back to the same outcome + record id.
		got, err := approval.ParseRefusal(b)
		if err != nil {
			t.Fatalf("%s: conformant refusal rejected: %v", tc.Name, err)
		}
		if got.Outcome != tc.Outcome || !bytes.Equal(got.Record, recordID) {
			t.Fatalf("%s: round-trip mismatch: outcome=%d record=%x", tc.Name, got.Outcome, got.Record)
		}
	}

	// Non-conformant refusals a conformant parser MUST reject.
	if _, err := approval.ParseRefusal(hx(t, r.Reject.UnknownOutcomeHex)); err == nil {
		t.Fatal("unknown refusal outcome must be rejected")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "UnknownRefusalOutcome" {
		t.Fatalf("want UnknownRefusalOutcome, got %v", err)
	}
	for name, h := range map[string]string{
		"extra field (leaked detail)": r.Reject.DetailLeakExtraFieldHex,
		"missing record id":           r.Reject.MissingRecordHex,
		"empty record id":             r.Reject.EmptyRecordHex,
	} {
		if _, err := approval.ParseRefusal(hx(t, h)); err == nil {
			t.Fatalf("%s must be rejected", name)
		} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "RefusalDetailLeak" {
			t.Fatalf("%s: want RefusalDetailLeak, got %v", name, err)
		}
	}
}
