// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package agui_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/agui"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/agui/cases.json"

type eventVec struct {
	Kind      uint64 `json:"kind"`
	Seq       uint64 `json:"seq"`
	PrevHex   string `json:"prev_hex"`
	ActionHex string `json:"action_hex"`
	BodyHex   string `json:"body_hex"`
	HeadHex   string `json:"head_hex"`
	IDHex     string `json:"id_hex"`
}

type vec struct {
	GenesisHex     string `json:"genesis_hex"`
	KindVocabulary []struct {
		Name string `json:"name"`
		Code uint64 `json:"code"`
	} `json:"kind_vocabulary"`
	UnknownKind         uint64 `json:"unknown_kind"`
	SessionHex          string `json:"session_hex"`
	ActionBytesHex      string `json:"action_bytes_hex"`
	ActionCIDHex        string `json:"action_cid_hex"`
	SubstitutedBytesHex string `json:"substituted_bytes_hex"`
	SubstitutedCIDHex   string `json:"substituted_cid_hex"`
	Chain               struct {
		Events       []eventVec `json:"events"`
		FinalHeadHex string     `json:"final_head_hex"`
	} `json:"chain"`
	Hole struct {
		PresentIndices []string `json:"present_indices"`
		Position       int      `json:"position"`
	} `json:"hole"`
	BigSeq struct {
		SeqStr    string `json:"seq_str"`
		Kind      uint64 `json:"kind"`
		ActionHex string `json:"action_hex"`
		PrevHex   string `json:"prev_hex"`
		BodyHex   string `json:"body_hex"`
		HeadHex   string `json:"head_hex"`
		IDHex     string `json:"id_hex"`
	} `json:"big_seq"`
	Minimal struct {
		SessionHex string `json:"session_hex"`
		Kind       uint64 `json:"kind"`
		ActionHex  string `json:"action_hex"`
		Seq        uint64 `json:"seq"`
		PrevHex    string `json:"prev_hex"`
		BodyHex    string `json:"body_hex"`
		HeadHex    string `json:"head_hex"`
		IDHex      string `json:"id_hex"`
	} `json:"minimal"`
	EdgeCases struct {
		KeysOutOfOrder struct {
			ActionHex           string `json:"action_hex"`
			CanonicalBodyHex    string `json:"canonical_body_hex"`
			NoncanonicalBodyHex string `json:"noncanonical_body_hex"`
		} `json:"keys_out_of_order"`
		EmptyVsAbsent struct {
			EmptyAction struct {
				BodyHex string `json:"body_hex"`
				IDHex   string `json:"id_hex"`
			} `json:"empty_action"`
			PopulatedAction struct {
				ActionHex string `json:"action_hex"`
				BodyHex   string `json:"body_hex"`
				IDHex     string `json:"id_hex"`
			} `json:"populated_action"`
			AbsentField struct {
				BodyHex string `json:"body_hex"`
			} `json:"absent_field"`
		} `json:"empty_vs_absent"`
		LookAlike struct {
			BodyHex string `json:"body_hex"`
		} `json:"look_alike"`
	} `json:"edge_cases"`
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
	if len(v.Chain.Events) != 3 {
		t.Fatalf("expected 3 chain events, got %d", len(v.Chain.Events))
	}
	return v
}

func key(t *testing.T, seed byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier) {
	t.Helper()
	var s [mldsa65.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
}

func eventsFrom(t *testing.T, v vec) []agui.UIEvent {
	session := hb(t, v.SessionHex)
	out := make([]agui.UIEvent, len(v.Chain.Events))
	for i, ev := range v.Chain.Events {
		out[i] = agui.UIEvent{Session: session, Kind: ev.Kind, Action: hb(t, ev.ActionHex), Seq: ev.Seq, Prev: hb(t, ev.PrevHex)}
	}
	return out
}

// TestByteParityAgainstOracle: Go encoding == the non-circular Python oracle, byte-for-byte, for every
// UI event body/head/id, the chain heads, and the action content id. Mutation: change any Bytes()
// field order/tag/key and a *_hex compare flips.
func TestByteParityAgainstOracle(t *testing.T) {
	v := loadVec(t)
	events := eventsFrom(t, v)
	for i, ev := range events {
		want := v.Chain.Events[i]
		if got := hex.EncodeToString(ev.Bytes()); got != want.BodyHex {
			t.Fatalf("event[%d] Bytes\n got %s\nwant %s", i, got, want.BodyHex)
		}
		if got := hex.EncodeToString(ev.Head()); got != want.HeadHex {
			t.Fatalf("event[%d] Head got %s want %s", i, got, want.HeadHex)
		}
		if got := hex.EncodeToString(ev.ID()); got != want.IDHex {
			t.Fatalf("event[%d] ID got %s want %s", i, got, want.IDHex)
		}
	}
	// The action bytes hash to the action content id every event names.
	if got := hex.EncodeToString(agui.ContentID(hb(t, v.ActionBytesHex))); got != v.ActionCIDHex {
		t.Fatalf("action content id got %s want %s", got, v.ActionCIDHex)
	}
	if got := hex.EncodeToString(agui.ContentID(hb(t, v.SubstitutedBytesHex))); got != v.SubstitutedCIDHex {
		t.Fatalf("substituted content id got %s want %s", got, v.SubstitutedCIDHex)
	}
	// The kind vocabulary matches the oracle and the closed set is enforced.
	for _, e := range v.KindVocabulary {
		if !agui.IsKnownKind(e.Code) || agui.KindName(e.Code) != e.Name {
			t.Fatalf("kind %q (code %d) not registered as %q", e.Name, e.Code, agui.KindName(e.Code))
		}
	}
	if agui.IsKnownKind(v.UnknownKind) {
		t.Fatalf("unknown kind %d must not be known", v.UnknownKind)
	}
}

func mkApproval(t *testing.T, actionCID []byte, s cose.MLDSA65Signer, nonce byte, notAfter uint64) (approval.ApprovalRecord, []byte) {
	t.Helper()
	n := make([]byte, 16)
	for i := range n {
		n[i] = nonce
	}
	a := approval.ApprovalRecord{Approves: actionCID, Approver: "human-approver", Grant: uint64(policy.NonIdempotentWrite), Nonce: n, NotAfter: notAfter}
	sig, err := approval.SignApproval(a, s)
	if err != nil {
		t.Fatalf("SignApproval: %v", err)
	}
	return a, sig
}

// TestConsentBindsExactShownAction is the C21 UI checkpoint: a human approval verifies ONLY against
// the exact action shown; the shown chain is receipt-verifiable; and an omitted shown-event is a
// detectable hole with position.
func TestConsentBindsExactShownAction(t *testing.T) {
	v := loadVec(t)
	uiS, uiV := key(t, 0x31)       // the UI authority signs the shown events
	humanS, humanV := key(t, 0x32) // the human signs the approval
	_, foreignV := key(t, 0x42)

	events := eventsFrom(t, v)
	actionBytes := hb(t, v.ActionBytesHex)
	actionCID := agui.ContentID(actionBytes)
	notAfter := uint64(1785000000000)
	appr, apprSig := mkApproval(t, actionCID, humanS, 0x01, notAfter)

	// The shown chain verifies (signatures + contiguity), and its final head matches the oracle.
	objs := make([][]byte, len(events))
	for i, ev := range events {
		obj, err := agui.SignUIEvent(ev, uiS)
		if err != nil {
			t.Fatalf("SignUIEvent[%d]: %v", i, err)
		}
		objs[i] = obj
	}
	verified, err := agui.VerifyShownChain(objs, cose.ProfilePublic, uiV)
	if err != nil {
		t.Fatalf("VerifyShownChain: %v", err)
	}
	if len(verified) != 3 {
		t.Fatalf("verified %d events, want 3", len(verified))
	}
	shown, err := agui.WalkShown(events)
	if err != nil {
		t.Fatalf("WalkShown: %v", err)
	}
	if got := hex.EncodeToString(shown[len(shown)-1].Head); got != v.Chain.FinalHeadHex {
		t.Fatalf("final head %s != oracle %s", got, v.Chain.FinalHeadHex)
	}
	shownCID, ok := agui.ApprovedActionCID(shown)
	if !ok || !bytes.Equal(shownCID, actionCID) {
		t.Fatal("approved action content id is not the shown action")
	}

	// Honest consent: the exact shown-and-approved action verifies.
	if err := agui.VerifyConsent(events, actionBytes, appr, humanV, apprSig, notAfter); err != nil {
		t.Fatalf("VerifyConsent (honest): %v", err)
	}
	// A SUBSTITUTED action (different bytes, different content id) is rejected.
	substituted := hb(t, v.SubstitutedBytesHex)
	if err := agui.VerifyConsent(events, substituted, appr, humanV, apprSig, notAfter); err != agui.ErrActionSubstituted {
		t.Fatalf("substituted action got %v, want ActionSubstituted", err)
	}
	// A foreign key never authenticates the human approval.
	if err := agui.VerifyConsent(events, actionBytes, appr, foreignV, apprSig, notAfter); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key consent got %v, want BadSignature", err)
	}
	// After expiry the consent is dead.
	if err := agui.VerifyConsent(events, actionBytes, appr, humanV, apprSig, notAfter+1); err != approval.ErrApprovalExpired {
		t.Fatalf("expired consent got %v, want ApprovalExpired", err)
	}
	// A chain with no approved event has no consent to bind.
	shownOnly := events[:2] // shown, args-shown — no approved
	if err := agui.VerifyConsent(shownOnly, actionBytes, appr, humanV, apprSig, notAfter); err != agui.ErrNoConsent {
		t.Fatalf("no-approved consent got %v, want UINoConsent", err)
	}

	// A removed/omitted shown-event is detected with its POSITION (a chain hole).
	gappy := []agui.UIEvent{events[0], events[2]} // omit event 1 (args-shown)
	pos, hole := agui.DetectHole(gappy)
	if !hole || pos != v.Hole.Position {
		t.Fatalf("DetectHole got (pos=%d, hole=%v), want (pos=%d, true)", pos, hole, v.Hole.Position)
	}
	if _, err := agui.WalkShown(gappy); err != agui.ErrUIChainBroken {
		t.Fatalf("gappy WalkShown got %v, want UIChainBroken", err)
	}
	// Consent over the gappy chain is refused (the shown sequence is not provable).
	if err := agui.VerifyConsent(gappy, actionBytes, appr, humanV, apprSig, notAfter); err != agui.ErrUIChainBroken {
		t.Fatalf("gappy consent got %v, want UIChainBroken", err)
	}
}

// TestUISubstitutedActionMutation is REQUIRED checkpoint mutation (b): a UI profile that accepts an
// approval for a SUBSTITUTED action fails. The honest VerifyConsent ties the EXECUTED action bytes to
// the shown-and-approved content id (ErrActionSubstituted on a mismatch); a MUTANT profile that drops
// that tie — checking only that the human approved SOMETHING that was shown — wrongly accepts a
// substituted action. The test proves the executed-equals-shown check is load-bearing: remove it and
// the substitution is accepted.
func TestUISubstitutedActionMutation(t *testing.T) {
	v := loadVec(t)
	uiS, _ := key(t, 0x31)
	_ = uiS
	humanS, humanV := key(t, 0x32)

	events := eventsFrom(t, v)
	actionBytes := hb(t, v.ActionBytesHex)
	substituted := hb(t, v.SubstitutedBytesHex)
	actionCID := agui.ContentID(actionBytes)
	notAfter := uint64(1785000000000)
	appr, apprSig := mkApproval(t, actionCID, humanS, 0x01, notAfter)

	// HONEST profile: the substituted action is rejected.
	if err := agui.VerifyConsent(events, substituted, appr, humanV, apprSig, notAfter); err != agui.ErrActionSubstituted {
		t.Fatalf("honest profile got %v on substituted action, want ActionSubstituted", err)
	}

	// MUTANT profile: verifies the shown chain and that the human approved the SHOWN action, but omits
	// the executed-equals-shown tie — the confused-deputy bug. It wrongly accepts the substituted
	// action (whose bytes differ from what the human saw).
	mutantVerifyConsent := func(chain []agui.UIEvent, actionBytes []byte) error {
		shown, err := agui.WalkShown(chain)
		if err != nil {
			return err
		}
		shownCID, ok := agui.ApprovedActionCID(shown)
		if !ok {
			return agui.ErrNoConsent
		}
		// binds the approval to the SHOWN action (valid) but NEVER checks the executed action equals it.
		_ = actionBytes
		return approval.VerifyApproval(appr, humanV, apprSig, shownCID, notAfter)
	}
	if err := mutantVerifyConsent(events, substituted); err != nil {
		// The mutant does NOT reject the substituted action — proving the honest executed-equals-shown
		// check is what prevents the substitution. If this errored, the approval binding alone would be
		// catching it, which for a shown-action-bound approval it does not.
		t.Fatalf("mutant profile unexpectedly rejected the substitution (%v): the bug must reproduce", err)
	}
}

// crossLangPinnedSignedUIEventSHA384 is the pinned SHA-384 of the deterministic COSE_Sign1 object
// obtained by signing the approved UI event body with the shared all-0x11 32-byte ML-DSA-65 seed. Go
// and Rust both pin it, proving the two independent ML-DSA stacks emit byte-identical signed UI events.
const crossLangPinnedSignedUIEventSHA384 = "30dcd1991bb850c630293b32a99ece28806fa7e552176231716f13b16f3f9c89bb48b7fe64bb5edeaf447971e300ee84"

// TestCrossLangSignedUIEventPin proves Go and Rust produce a byte-identical signed UI event for the
// same body + seed (deterministic ML-DSA-65 over identical canonical CBOR).
func TestCrossLangSignedUIEventPin(t *testing.T) {
	v := loadVec(t)
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 0x11
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	s := cose.MLDSA65Signer{SK: sk}
	events := eventsFrom(t, v)
	approved := events[2] // the approved event
	obj, err := agui.SignUIEvent(approved, s)
	if err != nil {
		t.Fatalf("SignUIEvent: %v", err)
	}
	dg := sha512.Sum384(obj)
	got := hex.EncodeToString(dg[:])
	t.Logf("CROSS-LANG signed ui-event SHA-384 (seed=0x11*32): %s", got)
	if crossLangPinnedSignedUIEventSHA384 != "PIN_ME" && got != crossLangPinnedSignedUIEventSHA384 {
		t.Fatalf("cross-lang signed-ui-event digest %s != pinned %s", got, crossLangPinnedSignedUIEventSHA384)
	}
}

// TestAguiOversizedSeqRoundTrip is Phase 6 edge case #3 (the >2^53 discipline): a UI-event seq above
// 2^53 (0x0102030405060708 = 72623859790382856) MUST round-trip byte-exact (uint64 all the way, no
// float64). The oracle carries seq as a JSON STRING, parsed with a 64-bit integer parser. Mutation:
// truncate seq to a float64 and the body / recovered seq diverge.
func TestAguiOversizedSeqRoundTrip(t *testing.T) {
	v := loadVec(t)
	seq, err := strconv.ParseUint(v.BigSeq.SeqStr, 10, 64)
	if err != nil {
		t.Fatalf("parse seq_str: %v", err)
	}
	if seq <= 1<<53 {
		t.Fatalf("oracle big seq %d is not > 2^53", seq)
	}
	e := agui.UIEvent{Session: hb(t, v.SessionHex), Kind: v.BigSeq.Kind, Action: hb(t, v.BigSeq.ActionHex), Seq: seq, Prev: hb(t, v.BigSeq.PrevHex)}
	if got := hex.EncodeToString(e.Bytes()); got != v.BigSeq.BodyHex {
		t.Fatalf("big-seq ui-event body\n got %s\nwant %s", got, v.BigSeq.BodyHex)
	}
	got, err := agui.ParseUIEvent(e.Bytes())
	if err != nil {
		t.Fatalf("ParseUIEvent(big seq): %v", err)
	}
	if got.Seq != seq {
		t.Fatalf("recovered seq %d != %d (>2^53 corrupted)", got.Seq, seq)
	}
}

// TestAguiMinimal is Phase 6 edge case #4: the smallest valid ui-event (empty session, kind shown,
// empty action, seq 0, genesis prev) encodes, reconstructs, and has a stable content-id.
func TestAguiMinimal(t *testing.T) {
	v := loadVec(t)
	e := agui.UIEvent{Session: hb(t, v.Minimal.SessionHex), Kind: v.Minimal.Kind, Action: hb(t, v.Minimal.ActionHex), Seq: v.Minimal.Seq, Prev: hb(t, v.Minimal.PrevHex)}
	if got := hex.EncodeToString(e.Bytes()); got != v.Minimal.BodyHex {
		t.Fatalf("minimal ui-event body\n got %s\nwant %s", got, v.Minimal.BodyHex)
	}
	if got := hex.EncodeToString(e.ID()); got != v.Minimal.IDHex {
		t.Fatalf("minimal ui-event id got %s want %s", got, v.Minimal.IDHex)
	}
	if _, err := agui.ParseUIEvent(e.Bytes()); err != nil {
		t.Fatalf("ParseUIEvent(minimal): %v", err)
	}
}

// ---- standard wire-format edge cases (Part 1) --------------------------------------------

// TestAguiKeysOutOfOrderRejected is edge case #1: a ui-event body with top-level keys in DESCENDING
// order (5,4,3,2,1) is rejected NonCanonical by the strict shared decoder ParseUIEvent routes through
// (RFC 8949 §4.2.1). Mutation: relax the key-order check in the C1 codec and the descending body
// wrongly decodes.
func TestAguiKeysOutOfOrderRejected(t *testing.T) {
	v := loadVec(t)
	e := v.EdgeCases.KeysOutOfOrder
	ev := agui.UIEvent{Session: hb(t, v.SessionHex), Kind: agui.KindShown, Action: hb(t, e.ActionHex), Seq: 0, Prev: hb(t, v.GenesisHex)}
	if got := hex.EncodeToString(ev.Bytes()); got != e.CanonicalBodyHex {
		t.Fatalf("canonical ui-event body\n got %s\nwant %s", got, e.CanonicalBodyHex)
	}
	canon := hb(t, e.CanonicalBodyHex)
	noncanon := hb(t, e.NoncanonicalBodyHex)
	if _, err := cbor.Decode(canon); err != nil {
		t.Fatalf("canonical body should decode: %v", err)
	}
	if _, err := agui.ParseUIEvent(canon); err != nil {
		t.Fatalf("canonical body should parse: %v", err)
	}
	if _, err := cbor.Decode(noncanon); err == nil {
		t.Fatal("descending-key ui-event body decoded (want NonCanonical)")
	} else if ce, ok := err.(*cbor.Error); !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("descending-key body got %v, want NonCanonical", err)
	}
	if _, err := agui.ParseUIEvent(noncanon); err != agui.ErrMalformed {
		t.Fatalf("ParseUIEvent(noncanon) got %v, want UIMalformed", err)
	}
}

// TestAguiEmptyVsAbsentAction is edge case #2 for the action field (field 3, a bstr): an empty action
// is PRESENT and valid and DISTINCT by content-id from a populated one, and BOTH differ from a body
// whose action field is ABSENT — rejected UIMalformed (field 3 is mandatory). Mutation: drop the
// action-field presence requirement in ParseUIEvent and the absent body wrongly parses.
func TestAguiEmptyVsAbsentAction(t *testing.T) {
	v := loadVec(t)
	ea := v.EdgeCases.EmptyVsAbsent
	session := hb(t, v.SessionHex)
	prev := hb(t, v.GenesisHex)
	empty := agui.UIEvent{Session: session, Kind: agui.KindShown, Action: []byte{}, Seq: 0, Prev: prev}
	populated := agui.UIEvent{Session: session, Kind: agui.KindShown, Action: hb(t, ea.PopulatedAction.ActionHex), Seq: 0, Prev: prev}
	if got := hex.EncodeToString(empty.Bytes()); got != ea.EmptyAction.BodyHex {
		t.Fatalf("empty-action body\n got %s\nwant %s", got, ea.EmptyAction.BodyHex)
	}
	if got := hex.EncodeToString(populated.Bytes()); got != ea.PopulatedAction.BodyHex {
		t.Fatalf("populated-action body\n got %s\nwant %s", got, ea.PopulatedAction.BodyHex)
	}
	if bytes.Equal(empty.ID(), populated.ID()) {
		t.Fatal("empty and populated action events must have distinct content-ids")
	}
	if hex.EncodeToString(empty.ID()) != ea.EmptyAction.IDHex {
		t.Fatalf("empty-action id diverges from the oracle")
	}
	if _, err := agui.ParseUIEvent(empty.Bytes()); err != nil {
		t.Fatalf("ParseUIEvent(empty action): %v", err)
	}
	if _, err := agui.ParseUIEvent(populated.Bytes()); err != nil {
		t.Fatalf("ParseUIEvent(populated action): %v", err)
	}
	if _, err := agui.ParseUIEvent(hb(t, ea.AbsentField.BodyHex)); err != agui.ErrMalformed {
		t.Fatalf("absent action field got %v, want UIMalformed", err)
	}
}

// TestAguiLookAlikeRejected is edge case #5: NAALP-AGUI defines a single body kind, so the look-alike
// is a near-miss — a ui-event-shaped body lacking its field-5 chain back-pointer (prev), which a lax
// parser would admit as an unchained event. ParseUIEvent rejects it UIMalformed. Mutation: drop the
// prev-field presence requirement in ParseUIEvent and the near-miss wrongly parses.
func TestAguiLookAlikeRejected(t *testing.T) {
	v := loadVec(t)
	if _, err := agui.ParseUIEvent(hb(t, v.EdgeCases.LookAlike.BodyHex)); err != agui.ErrMalformed {
		t.Fatalf("look-alike (missing prev) got %v, want UIMalformed", err)
	}
}
