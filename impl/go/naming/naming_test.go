// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naming_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/description"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/naming"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/naming/cases.json"

type bindingVec struct {
	Seq       uint64 `json:"seq"`
	SignerHex string `json:"signer_hex"`
	PrevHex   string `json:"prev_hex"`
	BodyHex   string `json:"body_hex"`
	HeadHex   string `json:"head_hex"`
	IDHex     string `json:"id_hex"`
}

type walkVec struct {
	Seq       uint64 `json:"seq"`
	SignerHex string `json:"signer_hex"`
}

type transVec struct {
	Seq     uint64 `json:"seq"`
	From    uint64 `json:"from"`
	To      uint64 `json:"to"`
	PrevHex string `json:"prev_hex"`
	BodyHex string `json:"body_hex"`
	HeadHex string `json:"head_hex"`
	IDHex   string `json:"id_hex"`
}

type opVec struct {
	Name             string `json:"name"`
	Effect           uint64 `json:"effect"`
	RequiresApproval uint64 `json:"requires_approval"`
}

type vec struct {
	Name struct {
		NameUtf8       string       `json:"name_utf8"`
		GenesisPrevHex string       `json:"genesis_prev_hex"`
		Bindings       []bindingVec `json:"bindings"`
		Walk           []walkVec    `json:"walk"`
		Hole           struct {
			PresentSeqs       []int `json:"present_seqs"`
			FirstHolePosition int   `json:"first_hole_position"`
		} `json:"hole"`
		Fork struct {
			BPrime   bindingVec `json:"b_prime"`
			Position int        `json:"position"`
		} `json:"fork"`
		BigSeq struct {
			SeqStr    string `json:"seq_str"`
			SignerHex string `json:"signer_hex"`
			PrevHex   string `json:"prev_hex"`
			BodyHex   string `json:"body_hex"`
			HeadHex   string `json:"head_hex"`
			IDHex     string `json:"id_hex"`
		} `json:"big_seq"`
		Minimal struct {
			NameUtf8  string `json:"name_utf8"`
			SignerHex string `json:"signer_hex"`
			Seq       uint64 `json:"seq"`
			PrevHex   string `json:"prev_hex"`
			BodyHex   string `json:"body_hex"`
			HeadHex   string `json:"head_hex"`
			IDHex     string `json:"id_hex"`
		} `json:"minimal"`
		KeysOutOfOrder struct {
			CanonicalBindingBodyHex    string `json:"canonical_binding_body_hex"`
			NoncanonicalBindingBodyHex string `json:"noncanonical_binding_body_hex"`
		} `json:"keys_out_of_order"`
		LookAlike struct {
			BindingBodyHex    string `json:"binding_body_hex"`
			TransitionBodyHex string `json:"transition_body_hex"`
		} `json:"look_alike"`
	} `json:"name"`
	A2A struct {
		States struct {
			Submitted     uint64   `json:"submitted"`
			Working       uint64   `json:"working"`
			InputRequired uint64   `json:"input_required"`
			AuthRequired  uint64   `json:"auth_required"`
			Completed     uint64   `json:"completed"`
			Canceled      uint64   `json:"canceled"`
			Failed        uint64   `json:"failed"`
			Rejected      uint64   `json:"rejected"`
			Start         uint64   `json:"start"`
			Terminal      []uint64 `json:"terminal"`
			Interrupted   []uint64 `json:"interrupted"`
		} `json:"states"`
		LegalEdges   [][]uint64 `json:"legal_edges"`
		IllegalEdges [][]uint64 `json:"illegal_edges"`
		Card         struct {
			ImporterHex   string  `json:"importer_hex"`
			Format        uint64  `json:"format"`
			ForeignHex    string  `json:"foreign_hex"`
			Operations    []opVec `json:"operations"`
			ImportBodyHex string  `json:"import_body_hex"`
			CardIDHex     string  `json:"card_id_hex"`
		} `json:"card"`
		TaskUtf8       string     `json:"task_utf8"`
		GenesisPrevHex string     `json:"genesis_prev_hex"`
		Transitions    []transVec `json:"transitions"`
		Gap            struct {
			PresentSeqs      []int `json:"present_seqs"`
			FirstGapPosition int   `json:"first_gap_position"`
		} `json:"gap"`
		ForeignCardIDHex string `json:"foreign_card_id_hex"`
		BigSeq           struct {
			SeqStr  string `json:"seq_str"`
			From    uint64 `json:"from"`
			To      uint64 `json:"to"`
			PrevHex string `json:"prev_hex"`
			BodyHex string `json:"body_hex"`
			HeadHex string `json:"head_hex"`
			IDHex   string `json:"id_hex"`
		} `json:"big_seq"`
		Minimal struct {
			TaskHex string `json:"task_hex"`
			CardHex string `json:"card_hex"`
			From    uint64 `json:"from"`
			To      uint64 `json:"to"`
			Seq     uint64 `json:"seq"`
			PrevHex string `json:"prev_hex"`
			BodyHex string `json:"body_hex"`
			HeadHex string `json:"head_hex"`
			IDHex   string `json:"id_hex"`
		} `json:"minimal"`
	} `json:"a2a"`
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
	if len(v.Name.Bindings) != 3 {
		t.Fatalf("expected 3 name bindings in the corpus, got %d", len(v.Name.Bindings))
	}
	if len(v.A2A.Transitions) != 4 {
		t.Fatalf("expected 4 task transitions in the corpus, got %d", len(v.A2A.Transitions))
	}
	return v
}

func bindingsFrom(t *testing.T, v vec) []naming.NameBinding {
	out := make([]naming.NameBinding, len(v.Name.Bindings))
	for i, b := range v.Name.Bindings {
		out[i] = naming.NameBinding{Name: v.Name.NameUtf8, Signer: hb(t, b.SignerHex), Seq: b.Seq, Prev: hb(t, b.PrevHex)}
	}
	return out
}

func transitionsFrom(t *testing.T, v vec) []naming.Transition {
	task := []byte(v.A2A.TaskUtf8)
	card := hb(t, v.A2A.Card.CardIDHex)
	out := make([]naming.Transition, len(v.A2A.Transitions))
	for i, tr := range v.A2A.Transitions {
		out[i] = naming.Transition{
			Task: task, Card: card,
			From: naming.TaskState(tr.From), To: naming.TaskState(tr.To),
			Seq: tr.Seq, Prev: hb(t, tr.PrevHex),
		}
	}
	return out
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
// every name-binding body/head/id, every transition body/head/id, and the A2A Agent Card
// attestation's content-id. Mutation: reorder/retag any Bytes() field and a *_hex compare flips.
func TestByteParityAgainstOracle(t *testing.T) {
	v := loadVec(t)

	// Name bindings.
	for i, nb := range bindingsFrom(t, v) {
		bv := v.Name.Bindings[i]
		if got := hex.EncodeToString(nb.Bytes()); got != bv.BodyHex {
			t.Fatalf("binding[%d].Bytes\n got %s\nwant %s", i, got, bv.BodyHex)
		}
		if got := hex.EncodeToString(nb.Head()); got != bv.HeadHex {
			t.Fatalf("binding[%d].Head got %s want %s", i, got, bv.HeadHex)
		}
		if got := hex.EncodeToString(nb.ID()); got != bv.IDHex {
			t.Fatalf("binding[%d].ID got %s want %s", i, got, bv.IDHex)
		}
	}
	// The fork sibling (b' at seq 1) also encodes byte-identically to the oracle.
	bp := naming.NameBinding{Name: v.Name.NameUtf8, Signer: hb(t, v.Name.Fork.BPrime.SignerHex), Seq: v.Name.Fork.BPrime.Seq, Prev: hb(t, v.Name.Fork.BPrime.PrevHex)}
	if got := hex.EncodeToString(bp.Bytes()); got != v.Name.Fork.BPrime.BodyHex {
		t.Fatalf("fork b'.Bytes\n got %s\nwant %s", got, v.Name.Fork.BPrime.BodyHex)
	}

	// Task transitions.
	for i, tr := range transitionsFrom(t, v) {
		tv := v.A2A.Transitions[i]
		if got := hex.EncodeToString(tr.Bytes()); got != tv.BodyHex {
			t.Fatalf("transition[%d].Bytes\n got %s\nwant %s", i, got, tv.BodyHex)
		}
		if got := hex.EncodeToString(tr.Head()); got != tv.HeadHex {
			t.Fatalf("transition[%d].Head got %s want %s", i, got, tv.HeadHex)
		}
		if got := hex.EncodeToString(tr.ID()); got != tv.IDHex {
			t.Fatalf("transition[%d].ID got %s want %s", i, got, tv.IDHex)
		}
	}

	// The A2A Agent Card attestation content-id (a C18 import) that the profile binds.
	im := cardImport(t, v)
	if got := hex.EncodeToString(im.Bytes()); got != v.A2A.Card.ImportBodyHex {
		t.Fatalf("card import.Bytes\n got %s\nwant %s", got, v.A2A.Card.ImportBodyHex)
	}
	if got := hex.EncodeToString(im.ID()); got != v.A2A.Card.CardIDHex {
		t.Fatalf("card import.ID got %s want %s (card binding must be byte-identical to the oracle)", got, v.A2A.Card.CardIDHex)
	}
}

func cardImport(t *testing.T, v vec) description.Import {
	ops := make([]description.Operation, len(v.A2A.Card.Operations))
	for i, o := range v.A2A.Card.Operations {
		ops[i] = description.Operation{Name: o.Name, Effect: o.Effect, RequiresApproval: o.RequiresApproval}
	}
	return description.Import{
		Importer:   hb(t, v.A2A.Card.ImporterHex),
		Format:     v.A2A.Card.Format,
		Foreign:    hb(t, v.A2A.Card.ForeignHex),
		Operations: ops,
	}
}

// TestWalkHistoryMatchesOracle is a name-history walk: WalkHistory returns the signer succession
// (A -> B -> C) exactly as the oracle records it, and the CURRENT signer is the last event. Mutation:
// a constant-returning WalkHistory (always the same signer / a fixed slice) diverges from the corpus
// because the three signers differ.
func TestWalkHistoryMatchesOracle(t *testing.T) {
	v := loadVec(t)
	bindings := bindingsFrom(t, v)
	events, err := naming.WalkHistory(bindings)
	if err != nil {
		t.Fatalf("WalkHistory: %v", err)
	}
	if len(events) != len(v.Name.Walk) {
		t.Fatalf("walk length %d want %d", len(events), len(v.Name.Walk))
	}
	for i, e := range events {
		if e.Seq != v.Name.Walk[i].Seq {
			t.Fatalf("event[%d].Seq %d want %d", i, e.Seq, v.Name.Walk[i].Seq)
		}
		if got := hex.EncodeToString(e.Signer); got != v.Name.Walk[i].SignerHex {
			t.Fatalf("event[%d].Signer %s want %s", i, got, v.Name.Walk[i].SignerHex)
		}
	}
	// The current signer is the last event's signer (the most recent rotation).
	cur := events[len(events)-1].Signer
	if !bytes.Equal(cur, hb(t, v.Name.Bindings[len(v.Name.Bindings)-1].SignerHex)) {
		t.Fatalf("current signer %x is not the last binding's signer", cur)
	}
	// A name change mid-chain breaks the walk (a chain is for one name).
	bad := append([]naming.NameBinding(nil), bindings...)
	bad[1].Name = "other.name"
	if _, err := naming.WalkHistory([]naming.NameBinding{bad[0], bad[1]}); err != naming.ErrNameChainBroken {
		t.Fatalf("name-change walk got %v, want NameChainBroken", err)
	}
}

// TestNameHoleDetectedWithPosition: a deleted binding leaves a detected hole at the oracle position;
// a contiguous chain has no hole. Mutation: a constant DetectHole (always (0,false) or a fixed
// position) fails one of the two cases.
func TestNameHoleDetectedWithPosition(t *testing.T) {
	v := loadVec(t)
	bindings := bindingsFrom(t, v)

	// Contiguous: no hole.
	if pos, hole := naming.DetectHole(bindings); hole {
		t.Fatalf("contiguous chain wrongly reported a hole at %d", pos)
	}
	// Delete the binding at seq 1: the presented list [b0, b2] breaks at the oracle position.
	present := []naming.NameBinding{bindings[0], bindings[2]}
	pos, hole := naming.DetectHole(present)
	if !hole || pos != v.Name.Hole.FirstHolePosition {
		t.Fatalf("hole got (pos=%d hole=%v), want (pos=%d hole=true)", pos, hole, v.Name.Hole.FirstHolePosition)
	}
}

// TestNameForkDetectedWithPosition: two bindings by ONE authority at the same (name, seq) naming
// different signers are a fork at the oracle seq position; the signed NameForkProof is
// non-repudiable. Mutation: drop the body-differs check in DetectFork and a benign duplicate wrongly
// forks; return a constant position and the honest case diverges.
func TestNameForkDetectedWithPosition(t *testing.T) {
	v := loadVec(t)
	bindings := bindingsFrom(t, v)
	bp := naming.NameBinding{Name: v.Name.NameUtf8, Signer: hb(t, v.Name.Fork.BPrime.SignerHex), Seq: v.Name.Fork.BPrime.Seq, Prev: hb(t, v.Name.Fork.BPrime.PrevHex)}

	pos, fork := naming.DetectFork(bindings[1], bp)
	if !fork || pos != v.Name.Fork.Position {
		t.Fatalf("fork got (pos=%d fork=%v), want (pos=%d fork=true)", pos, fork, v.Name.Fork.Position)
	}
	// Identical bindings are a benign duplicate, not a fork.
	if _, fork := naming.DetectFork(bindings[1], bindings[1]); fork {
		t.Fatal("identical bindings wrongly reported as a fork")
	}
	// A different seq is a legitimate distinct binding, not a fork.
	if _, fork := naming.DetectFork(bindings[1], bindings[2]); fork {
		t.Fatal("different-seq bindings wrongly reported as a fork")
	}

	// Signed non-repudiable proof: one authority signs BOTH conflicting bindings.
	signer, verifier, _, id := key(t, 0x11)
	_, foreign, _, _ := key(t, 0x22)
	signedA, err := naming.SignBinding(bindings[1], signer)
	if err != nil {
		t.Fatalf("SignBinding A: %v", err)
	}
	signedB, err := naming.SignBinding(bp, signer)
	if err != nil {
		t.Fatalf("SignBinding B: %v", err)
	}
	fp := naming.NameForkProof{Signer: []byte(id), SignedA: signedA, SignedB: signedB}
	gotPos, err := fp.Verify(cose.ProfilePublic, verifier)
	if err != nil {
		t.Fatalf("NameForkProof.Verify (honest): %v", err)
	}
	if gotPos != v.Name.Fork.Position {
		t.Fatalf("fork proof position %d want %d", gotPos, v.Name.Fork.Position)
	}
	// A foreign key does not verify the accused's signatures.
	if _, err := fp.Verify(cose.ProfilePublic, foreign); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key fork proof got %v, want BadSignature", err)
	}
	// An unnamed accused is not evidence.
	unnamed := naming.NameForkProof{Signer: nil, SignedA: signedA, SignedB: signedB}
	if _, err := unnamed.Verify(cose.ProfilePublic, verifier); err != naming.ErrNameForkProofInvalid {
		t.Fatalf("unnamed fork proof got %v, want NameForkProofInvalid", err)
	}
	// Identical bodies (same signed object twice) are not equivocation.
	dup := naming.NameForkProof{Signer: []byte(id), SignedA: signedA, SignedB: signedA}
	if _, err := dup.Verify(cose.ProfilePublic, verifier); err != naming.ErrNameForkProofInvalid {
		t.Fatalf("identical fork proof got %v, want NameForkProofInvalid", err)
	}
}

// TestNameChainVerifyFailClosed: an honest signed chain verifies; a broken link, a bad signature, and
// a foreign key are each rejected with their named error. Also demonstrates the Registrar appender
// producing a walkable, verifiable chain. Mutation: drop the prev/seq guard and a reordered chain
// wrongly verifies.
func TestNameChainVerifyFailClosed(t *testing.T) {
	v := loadVec(t)
	signer, verifier, _, _ := key(t, 0x11)
	_, foreign, _, _ := key(t, 0x22)

	// Build a signed chain via the Registrar (a rotation A -> B -> C); each Append returns the tagged
	// COSE_Sign1 object for one binding (the on-wire signed form).
	reg := naming.NewRegistrar(v.Name.NameUtf8, signer)
	var bindings []naming.NameBinding
	var objs [][]byte
	for _, bv := range v.Name.Bindings {
		nb, obj, err := reg.Append(hb(t, bv.SignerHex))
		if err != nil {
			t.Fatalf("Registrar.Append: %v", err)
		}
		bindings = append(bindings, nb)
		objs = append(objs, obj)
	}
	// The Registrar dates each binding by chain position and reproduces the oracle bodies.
	for i, nb := range bindings {
		if got := hex.EncodeToString(nb.Bytes()); got != v.Name.Bindings[i].BodyHex {
			t.Fatalf("registrar binding[%d] %s != oracle %s", i, got, v.Name.Bindings[i].BodyHex)
		}
	}
	verified, err := naming.VerifyChain(objs, cose.ProfilePublic, verifier)
	if err != nil {
		t.Fatalf("VerifyChain (honest): %v", err)
	}
	// VerifyChain returns the verified bindings, which walk to the same succession.
	events, err := naming.WalkHistory(verified)
	if err != nil || len(events) != len(bindings) {
		t.Fatalf("WalkHistory over verified chain: %v (n=%d)", err, len(events))
	}
	// A reordered chain (swap objects 1 and 2) breaks the prev/seq linkage.
	reordered := [][]byte{objs[0], objs[2], objs[1]}
	if _, err := naming.VerifyChain(reordered, cose.ProfilePublic, verifier); err != naming.ErrNameChainBroken {
		t.Fatalf("reordered chain got %v, want NameChainBroken", err)
	}
	// A tampered object (flip a payload byte) fails its signature.
	tampered := append([][]byte(nil), objs...)
	corrupt := append([]byte(nil), objs[1]...)
	corrupt[len(corrupt)-1] ^= 0x01
	tampered[1] = corrupt
	if _, err := naming.VerifyChain(tampered, cose.ProfilePublic, verifier); err != cose.ErrBadSignature {
		t.Fatalf("tampered chain got %v, want BadSignature", err)
	}
	// A foreign verifier authenticates none of the accused's bindings.
	if _, err := naming.VerifyChain(objs, cose.ProfilePublic, foreign); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key chain got %v, want BadSignature", err)
	}
	// The single-object verify rejects a foreign key with BadSignature.
	if _, err := naming.VerifyBinding(objs[0], cose.ProfilePublic, foreign); err != cose.ErrBadSignature {
		t.Fatalf("VerifyBinding foreign got %v, want BadSignature", err)
	}
}

// TestTransitionTableMatchesOracle grades the explicit A2A transition table against the
// independently-listed oracle edge set: every legal edge is accepted, every illegal edge is rejected
// with IllegalTransition, and the start/terminal/interrupted categories match. Mutation: LegalEdge
// returning a constant true fails the illegal edges; a constant false fails the legal edges.
func TestTransitionTableMatchesOracle(t *testing.T) {
	v := loadVec(t)

	if len(naming.LegalEdges()) != len(v.A2A.LegalEdges) {
		t.Fatalf("legal-edge count %d != oracle %d", len(naming.LegalEdges()), len(v.A2A.LegalEdges))
	}
	for _, e := range v.A2A.LegalEdges {
		from, to := naming.TaskState(e[0]), naming.TaskState(e[1])
		if !naming.LegalEdge(from, to) {
			t.Fatalf("legal edge %s->%s rejected by the table", from.Name(), to.Name())
		}
		if err := naming.VerifyTransition(from, to); err != nil {
			t.Fatalf("VerifyTransition(%s->%s) got %v, want nil", from.Name(), to.Name(), err)
		}
	}
	for _, e := range v.A2A.IllegalEdges {
		from, to := naming.TaskState(e[0]), naming.TaskState(e[1])
		if naming.LegalEdge(from, to) {
			t.Fatalf("illegal edge %d->%d wrongly accepted by the table", e[0], e[1])
		}
		if err := naming.VerifyTransition(from, to); err != naming.ErrIllegalTransition {
			t.Fatalf("VerifyTransition(%d->%d) got %v, want IllegalTransition", e[0], e[1], err)
		}
	}
	// Categories match the oracle.
	if uint64(naming.StartState) != v.A2A.States.Start {
		t.Fatalf("start state %d != oracle %d", naming.StartState, v.A2A.States.Start)
	}
	for _, s := range v.A2A.States.Terminal {
		if !naming.TaskState(s).IsTerminal() {
			t.Fatalf("state %d should be terminal", s)
		}
	}
	for _, s := range v.A2A.States.Interrupted {
		if !naming.TaskState(s).IsInterrupted() {
			t.Fatalf("state %d should be interrupted", s)
		}
	}
	// A terminal state has no legal out-edge (cannot transition out).
	for _, s := range v.A2A.States.Terminal {
		for to := uint64(0); to < 8; to++ {
			if naming.LegalEdge(naming.TaskState(s), naming.TaskState(to)) {
				t.Fatalf("terminal state %d has an out-edge to %d", s, to)
			}
		}
	}
}

// TestStateNamesMatchA2AVocabulary grades TaskState.Name(), which until now was carried only in
// diagnostic strings and never asserted. For each of the eight A2A states it cross-checks the
// oracle's independent code assignment (vectors/naming/cases.json a2a.states) against the state
// constant it names, then asserts Name() returns the EXACT literal A2A spelling (naming.go:329-333
// stateName; the oracle's JSON keys use underscores where the wire name uses a hyphen, so the
// literal spelling is pinned here rather than read back out of the JSON). An out-of-range code
// names "unknown". Mutation: swap any two entries in stateName (or misspell one) and this fails.
func TestStateNamesMatchA2AVocabulary(t *testing.T) {
	v := loadVec(t)
	wantCode := map[naming.TaskState]uint64{
		naming.StateSubmitted:     v.A2A.States.Submitted,
		naming.StateWorking:       v.A2A.States.Working,
		naming.StateInputRequired: v.A2A.States.InputRequired,
		naming.StateAuthRequired:  v.A2A.States.AuthRequired,
		naming.StateCompleted:     v.A2A.States.Completed,
		naming.StateCanceled:      v.A2A.States.Canceled,
		naming.StateFailed:        v.A2A.States.Failed,
		naming.StateRejected:      v.A2A.States.Rejected,
	}
	wantName := map[naming.TaskState]string{
		naming.StateSubmitted:     "submitted",
		naming.StateWorking:       "working",
		naming.StateInputRequired: "input-required",
		naming.StateAuthRequired:  "auth-required",
		naming.StateCompleted:     "completed",
		naming.StateCanceled:      "canceled",
		naming.StateFailed:        "failed",
		naming.StateRejected:      "rejected",
	}
	if len(wantCode) != 8 {
		t.Fatalf("expected 8 A2A states, got %d", len(wantCode))
	}
	for state, oracleCode := range wantCode {
		if uint64(state) != oracleCode {
			t.Fatalf("state constant %d does not match the oracle's code %d for %q", state, oracleCode, wantName[state])
		}
		if got := state.Name(); got != wantName[state] {
			t.Errorf("TaskState(%d).Name() = %q, want %q", state, got, wantName[state])
		}
	}
	if got := naming.TaskState(255).Name(); got != "unknown" {
		t.Errorf("TaskState(255).Name() = %q, want \"unknown\"", got)
	}
}

// TestTaskChainLegalAndIllegal drives a task through its LEGAL ordered lifecycle (accepted) and then
// exercises every rejection: an illegal edge, a non-contiguous from, a bad start state, a foreign
// card, a gap, and a bad signature. Mutation: drop the edge check in VerifyTaskChain and the illegal
// chain wrongly verifies; drop the card check and the foreign card wrongly verifies.
func TestTaskChainLegalAndIllegal(t *testing.T) {
	v := loadVec(t)
	signer, verifier, _, _ := key(t, 0x11)
	card := hb(t, v.A2A.Card.CardIDHex)
	task := []byte(v.A2A.TaskUtf8)

	// LEGAL ordered lifecycle: submitted->working->input-required->working->completed.
	transitions := transitionsFrom(t, v)
	objs := signAll(t, transitions, signer)
	if _, err := naming.VerifyTaskChain(objs, card, cose.ProfilePublic, verifier); err != nil {
		t.Fatalf("VerifyTaskChain (legal): %v", err)
	}
	// The chain reproduces the oracle bodies.
	for i, tr := range transitions {
		if got := hex.EncodeToString(tr.Bytes()); got != v.A2A.Transitions[i].BodyHex {
			t.Fatalf("transition[%d] %s != oracle %s", i, got, v.A2A.Transitions[i].BodyHex)
		}
	}

	// ILLEGAL edge inside a chain: working -> submitted (rebuild a fresh 2-step chain).
	t0 := naming.Transition{Task: task, Card: card, From: naming.StateSubmitted, To: naming.StateWorking, Seq: 0, Prev: naming.Genesis()}
	illegal := naming.Transition{Task: task, Card: card, From: naming.StateWorking, To: naming.StateSubmitted, Seq: 1, Prev: t0.Head()}
	chain := []naming.Transition{t0, illegal}
	if _, err := naming.VerifyTaskChain(signAll(t, chain, signer), card, cose.ProfilePublic, verifier); err != naming.ErrIllegalTransition {
		t.Fatalf("illegal-edge chain got %v, want IllegalTransition", err)
	}

	// NON-CONTIGUOUS from: t1.From (input-required) != t0.To (working), though input-required->working
	// is itself a legal edge — so the failure is the contiguity check.
	nonContig := naming.Transition{Task: task, Card: card, From: naming.StateInputRequired, To: naming.StateWorking, Seq: 1, Prev: t0.Head()}
	chain = []naming.Transition{t0, nonContig}
	if _, err := naming.VerifyTaskChain(signAll(t, chain, signer), card, cose.ProfilePublic, verifier); err != naming.ErrIllegalTransition {
		t.Fatalf("non-contiguous chain got %v, want IllegalTransition", err)
	}

	// BAD START: the seq-0 transition does not leave the start state.
	badStart := naming.Transition{Task: task, Card: card, From: naming.StateWorking, To: naming.StateInputRequired, Seq: 0, Prev: naming.Genesis()}
	chain = []naming.Transition{badStart}
	if _, err := naming.VerifyTaskChain(signAll(t, chain, signer), card, cose.ProfilePublic, verifier); err != naming.ErrIllegalTransition {
		t.Fatalf("bad-start chain got %v, want IllegalTransition", err)
	}

	// FOREIGN CARD: a transition binding a different attestation than the profile's bound card.
	foreignCard := hb(t, v.A2A.ForeignCardIDHex)
	fc := naming.Transition{Task: task, Card: foreignCard, From: naming.StateSubmitted, To: naming.StateWorking, Seq: 0, Prev: naming.Genesis()}
	chain = []naming.Transition{fc}
	if _, err := naming.VerifyTaskChain(signAll(t, chain, signer), card, cose.ProfilePublic, verifier); err != naming.ErrForeignCard {
		t.Fatalf("foreign-card chain got %v, want ForeignCard", err)
	}

	// GAP: present [t0, t2] (t1 omitted) — the seq/prev linkage breaks.
	present := [][]byte{objs[0], objs[2]}
	if _, err := naming.VerifyTaskChain(present, card, cose.ProfilePublic, verifier); err != naming.ErrTaskChainBroken {
		t.Fatalf("gapped chain got %v, want TaskChainBroken", err)
	}

	// BAD SIGNATURE: an otherwise-legal chain with a tampered object at index 0.
	bad := append([][]byte(nil), objs...)
	corrupt := append([]byte(nil), objs[0]...)
	corrupt[len(corrupt)-1] ^= 0x01
	bad[0] = corrupt
	if _, err := naming.VerifyTaskChain(bad, card, cose.ProfilePublic, verifier); err != cose.ErrBadSignature {
		t.Fatalf("bad-signature chain got %v, want BadSignature", err)
	}
}

func signAll(t *testing.T, transitions []naming.Transition, s cose.MLDSA65Signer) [][]byte {
	t.Helper()
	out := make([][]byte, len(transitions))
	for i, tr := range transitions {
		obj, err := naming.SignTransition(tr, s)
		if err != nil {
			t.Fatalf("SignTransition[%d]: %v", i, err)
		}
		out[i] = obj
	}
	return out
}

// TestTaskGapDetectedWithPosition: a deleted transition leaves a detected gap at the oracle position;
// a contiguous chain has no gap. Mutation: a constant DetectTaskGap fails one of the two cases.
func TestTaskGapDetectedWithPosition(t *testing.T) {
	v := loadVec(t)
	transitions := transitionsFrom(t, v)
	if pos, gap := naming.DetectTaskGap(transitions); gap {
		t.Fatalf("contiguous chain wrongly reported a gap at %d", pos)
	}
	present := []naming.Transition{transitions[0], transitions[2]}
	pos, gap := naming.DetectTaskGap(present)
	if !gap || pos != v.A2A.Gap.FirstGapPosition {
		t.Fatalf("gap got (pos=%d gap=%v), want (pos=%d gap=true)", pos, gap, v.A2A.Gap.FirstGapPosition)
	}
}

// TestCardAttestationBindsProfile is the C18 -> C19 link: the A2A Agent Card attestation (a
// naalp-description-import) drives which agent/operation the task profile is bound to. The profile
// binds the card by content-id; the card attests the operation effect mapping; a foreign card is
// rejected. Mutation: have VerifyTaskChain ignore the card and the foreign-card chain wrongly passes.
func TestCardAttestationBindsProfile(t *testing.T) {
	v := loadVec(t)
	signer, verifier, _, _ := key(t, 0x11)
	im := cardImport(t, v)

	// The bound card is the attestation's own content-id.
	card := im.ID()
	if got := hex.EncodeToString(card); got != v.A2A.Card.CardIDHex {
		t.Fatalf("card id %s != oracle %s", got, v.A2A.Card.CardIDHex)
	}
	// The card attests the operation effect mapping (the A2A skill -> N-AALP effect).
	submit, ok := im.Operation("submit")
	if !ok || submit.EffectClass() != policy.IdempotentWrite || !submit.RequiresApprovalFlag() {
		t.Fatal("the A2A card did not attest the effect mapping for 'submit'")
	}

	// A chain bound to this card verifies.
	transitions := transitionsFrom(t, v)
	if _, err := naming.VerifyTaskChain(signAll(t, transitions, signer), card, cose.ProfilePublic, verifier); err != nil {
		t.Fatalf("VerifyTaskChain bound to the card: %v", err)
	}
	// A different card attestation (a different importer) yields a different bound id, and a chain
	// carrying it is refused against the profile's card.
	other := description.Import{Importer: []byte("IMPORTER_ID_B"), Format: im.Format, Foreign: im.Foreign, Operations: im.Operations}
	if bytes.Equal(other.ID(), card) {
		t.Fatal("a different importer must yield a different card id")
	}
	otherTransitions := []naming.Transition{{Task: []byte(v.A2A.TaskUtf8), Card: other.ID(), From: naming.StateSubmitted, To: naming.StateWorking, Seq: 0, Prev: naming.Genesis()}}
	if _, err := naming.VerifyTaskChain(signAll(t, otherTransitions, signer), card, cose.ProfilePublic, verifier); err != naming.ErrForeignCard {
		t.Fatalf("chain bound to a foreign card got %v, want ForeignCard", err)
	}
}

// TestMalformedRejected: a body that is not a well-formed binding/transition is NameMalformed
// (fail-closed). Mutation: skip the field checks in ParseNameBinding/ParseTransition and a garbage
// body wrongly parses.
func TestMalformedRejected(t *testing.T) {
	// A binding body missing field 4 (prev) is malformed.
	if _, err := naming.ParseNameBinding([]byte{0x80}); err != naming.ErrNameMalformed { // an empty CBOR array
		t.Fatalf("malformed binding got %v, want NameMalformed", err)
	}
	// A transition body that is not a map is malformed.
	if _, err := naming.ParseTransition([]byte{0x00}); err != naming.ErrNameMalformed { // a bare uint 0
		t.Fatalf("malformed transition got %v, want NameMalformed", err)
	}
}

// crossLangPinnedSignedBindingSHA384 is the pinned SHA-384 of the deterministic COSE_Sign1 object
// obtained by signing the seq-0 name binding with the shared all-0x11 32-byte ML-DSA-65 seed. Go and
// Rust both pin this value, proving the two independent ML-DSA stacks emit a byte-identical signed
// binding for identical canonical CBOR + seed. Mutation: change the binding encoding or the signing
// input and the digest diverges from the pin.
const crossLangPinnedSignedBindingSHA384 = "a9179b939fffb1bce6abb4cd594b20e08f9d855729047ce4cb287da191234c10fecc9b232f80be902f70a3da490bcb91"

// crossLangPinnedSignedTransitionSHA384 is the pinned SHA-384 of the deterministic COSE_Sign1 object
// obtained by signing the seq-0 task transition with the shared all-0x11 32-byte ML-DSA-65 seed.
const crossLangPinnedSignedTransitionSHA384 = "60a9902f51e3308149cf2ace5cb65cd4541b4cc7bd4ec5f9a120dd44f93560b6358dcb96cb04b0daedd4cbbdf31f5787"

// TestCrossLangSignedBindingPin proves Go and Rust produce a byte-identical signed name binding for
// the same body + seed (deterministic ML-DSA-65 over identical canonical CBOR).
func TestCrossLangSignedBindingPin(t *testing.T) {
	v := loadVec(t)
	nb := bindingsFrom(t, v)[0]
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 0x11
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	obj, err := naming.SignBinding(nb, cose.MLDSA65Signer{SK: sk})
	if err != nil {
		t.Fatalf("SignBinding: %v", err)
	}
	dg := sha512.Sum384(obj)
	got := hex.EncodeToString(dg[:])
	t.Logf("CROSS-LANG signed name-binding SHA-384 (seed=0x11*32): %s", got)
	if crossLangPinnedSignedBindingSHA384 != "PIN_ME" && got != crossLangPinnedSignedBindingSHA384 {
		t.Fatalf("cross-lang signed-binding digest %s != pinned %s", got, crossLangPinnedSignedBindingSHA384)
	}
}

// TestCrossLangSignedTransitionPin proves Go and Rust produce a byte-identical signed task transition
// for the same body + seed.
func TestCrossLangSignedTransitionPin(t *testing.T) {
	v := loadVec(t)
	tr := transitionsFrom(t, v)[0]
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 0x11
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	obj, err := naming.SignTransition(tr, cose.MLDSA65Signer{SK: sk})
	if err != nil {
		t.Fatalf("SignTransition: %v", err)
	}
	dg := sha512.Sum384(obj)
	got := hex.EncodeToString(dg[:])
	t.Logf("CROSS-LANG signed task-transition SHA-384 (seed=0x11*32): %s", got)
	if crossLangPinnedSignedTransitionSHA384 != "PIN_ME" && got != crossLangPinnedSignedTransitionSHA384 {
		t.Fatalf("cross-lang signed-transition digest %s != pinned %s", got, crossLangPinnedSignedTransitionSHA384)
	}
}

// TestNamingOversizedSeqRoundTrip is Phase 6 edge case #3 (the >2^53 discipline): a name-binding seq
// AND a task-transition seq above 2^53 (0x0102030405060708 = 72623859790382856) MUST round-trip
// byte-exact through the impl (uint64 all the way, no float64). Both are carried as JSON STRINGS and
// parsed with a 64-bit integer parser. Mutation: truncate seq to a float64 and the body / recovered
// seq diverge.
func TestNamingOversizedSeqRoundTrip(t *testing.T) {
	v := loadVec(t)

	bseq, err := strconv.ParseUint(v.Name.BigSeq.SeqStr, 10, 64)
	if err != nil {
		t.Fatalf("parse binding seq_str: %v", err)
	}
	if bseq <= 1<<53 {
		t.Fatalf("oracle binding seq %d is not > 2^53", bseq)
	}
	nb := naming.NameBinding{Name: v.Name.NameUtf8, Signer: hb(t, v.Name.BigSeq.SignerHex), Seq: bseq, Prev: hb(t, v.Name.BigSeq.PrevHex)}
	if got := hex.EncodeToString(nb.Bytes()); got != v.Name.BigSeq.BodyHex {
		t.Fatalf("big-seq binding body\n got %s\nwant %s", got, v.Name.BigSeq.BodyHex)
	}
	gotNB, err := naming.ParseNameBinding(nb.Bytes())
	if err != nil {
		t.Fatalf("ParseNameBinding(big seq): %v", err)
	}
	if gotNB.Seq != bseq {
		t.Fatalf("recovered binding seq %d != %d (>2^53 corrupted)", gotNB.Seq, bseq)
	}

	tseq, err := strconv.ParseUint(v.A2A.BigSeq.SeqStr, 10, 64)
	if err != nil {
		t.Fatalf("parse transition seq_str: %v", err)
	}
	tr := naming.Transition{Task: []byte(v.A2A.TaskUtf8), Card: hb(t, v.A2A.Card.CardIDHex), From: naming.TaskState(v.A2A.BigSeq.From), To: naming.TaskState(v.A2A.BigSeq.To), Seq: tseq, Prev: hb(t, v.A2A.BigSeq.PrevHex)}
	if got := hex.EncodeToString(tr.Bytes()); got != v.A2A.BigSeq.BodyHex {
		t.Fatalf("big-seq transition body\n got %s\nwant %s", got, v.A2A.BigSeq.BodyHex)
	}
	gotTR, err := naming.ParseTransition(tr.Bytes())
	if err != nil {
		t.Fatalf("ParseTransition(big seq): %v", err)
	}
	if gotTR.Seq != tseq {
		t.Fatalf("recovered transition seq %d != %d (>2^53 corrupted)", gotTR.Seq, tseq)
	}
}

// TestNamingMinimal is Phase 6 edge case #4: the smallest valid binding and transition encode, have
// stable content-ids, and reconstruct from their bytes alone.
func TestNamingMinimal(t *testing.T) {
	v := loadVec(t)
	nb := naming.NameBinding{Name: v.Name.Minimal.NameUtf8, Signer: hb(t, v.Name.Minimal.SignerHex), Seq: v.Name.Minimal.Seq, Prev: hb(t, v.Name.Minimal.PrevHex)}
	if got := hex.EncodeToString(nb.Bytes()); got != v.Name.Minimal.BodyHex {
		t.Fatalf("minimal binding body\n got %s\nwant %s", got, v.Name.Minimal.BodyHex)
	}
	if got := hex.EncodeToString(nb.ID()); got != v.Name.Minimal.IDHex {
		t.Fatalf("minimal binding id got %s want %s", got, v.Name.Minimal.IDHex)
	}
	if _, err := naming.ParseNameBinding(nb.Bytes()); err != nil {
		t.Fatalf("ParseNameBinding(minimal): %v", err)
	}
	tr := naming.Transition{Task: hb(t, v.A2A.Minimal.TaskHex), Card: hb(t, v.A2A.Minimal.CardHex), From: naming.TaskState(v.A2A.Minimal.From), To: naming.TaskState(v.A2A.Minimal.To), Seq: v.A2A.Minimal.Seq, Prev: hb(t, v.A2A.Minimal.PrevHex)}
	if got := hex.EncodeToString(tr.Bytes()); got != v.A2A.Minimal.BodyHex {
		t.Fatalf("minimal transition body\n got %s\nwant %s", got, v.A2A.Minimal.BodyHex)
	}
	if _, err := naming.ParseTransition(tr.Bytes()); err != nil {
		t.Fatalf("ParseTransition(minimal): %v", err)
	}
}

// TestNamingKeysOutOfOrderRejected is Phase 6 edge case #1: the canonical encoder emits ascending map
// keys; a hand-built binding body with keys in descending order (same content) is rejected
// NonCanonical by the strict shared decoder. Mutation: relax the key-order check and it decodes.
func TestNamingKeysOutOfOrderRejected(t *testing.T) {
	v := loadVec(t)
	// The canonical binding body matches a NameBinding's own Bytes() (ascending keys).
	canonWant := v.Name.KeysOutOfOrder.CanonicalBindingBodyHex
	b0 := v.Name.Bindings[0]
	nb := naming.NameBinding{Name: v.Name.NameUtf8, Signer: hb(t, b0.SignerHex), Seq: b0.Seq, Prev: hb(t, b0.PrevHex)}
	if got := hex.EncodeToString(nb.Bytes()); got != canonWant {
		t.Fatalf("canonical binding body\n got %s\nwant %s", got, canonWant)
	}
	if _, err := cbor.Decode(hb(t, canonWant)); err != nil {
		t.Fatalf("canonical binding body should decode: %v", err)
	}
	_, err := cbor.Decode(hb(t, v.Name.KeysOutOfOrder.NoncanonicalBindingBodyHex))
	ce, ok := err.(*cbor.Error)
	if !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("descending-key binding got %v, want NonCanonical", err)
	}
}

// TestNamingLookAlikeRejectedBySibling is Phase 6 edge case #5: a 4-field binding body and a 6-field
// transition body are each rejected by the OTHER's parser (different shapes). Mutation: make either
// parser tolerate the wrong field set and the look-alike parses.
func TestNamingLookAlikeRejectedBySibling(t *testing.T) {
	v := loadVec(t)
	bindingBody := hb(t, v.Name.LookAlike.BindingBodyHex)
	transitionBody := hb(t, v.Name.LookAlike.TransitionBodyHex)
	if _, err := naming.ParseTransition(bindingBody); err != naming.ErrNameMalformed {
		t.Fatalf("binding body parsed as Transition got %v, want NameMalformed", err)
	}
	if _, err := naming.ParseNameBinding(transitionBody); err != naming.ErrNameMalformed {
		t.Fatalf("transition body parsed as NameBinding got %v, want NameMalformed", err)
	}
}
