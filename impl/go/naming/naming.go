// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package naming implements C19 — name bindings and the signed A2A task-state profile (design.md
// §22; requirements R-NAME-1..6 and R-A2A-1..7).
//
// C19 is two receipt-CHAINED, signed, OFFLINE-WALKABLE surfaces carried on N-AALP's own signed
// object. Both reuse the C7 audit receipt-chain construction (§8.1) unchanged — head = SHA-384(body),
// genesis prev = 48 zero bytes, a monotonic seq, the prior head carried in the body so editing or
// omitting a record breaks the next record's linkage — and they add NO new envelope, encoding,
// signature, identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP body
// (COSE_Sign1, §4), reusing the T1 content-id framing (§2.3) and the C7 chain.
//
// Task 4.1 — name bindings:
//
//   - NameBinding {1: name, 2: signer, 3: seq, 4: prev} maps a name to a signer id and CHAINS onto
//     the prior binding for that name (prev = the prior binding's Head; genesis prev is zero). A key
//     ROTATION is a NEW binding at the next seq naming the new signer. A binding is DATED BY ITS
//     CHAIN POSITION (seq); the envelope's `created` field is advisory only (§2.4). A name's history
//     is WALKABLE offline (WalkHistory returns the signer succession), and a deleted/omitted binding
//     leaves a detectable HOLE at the first-broken position (DetectHole), gap-evident exactly as the
//     audit chain and the directory fork report position. Two bindings by ONE authority at the SAME
//     (name, seq) naming DIFFERENT signers are a FORK, reported at that seq (DetectFork /
//     NameForkProof), the same way the §8.5 audit fork proof reports an equivocation position.
//
// Task 4.2 — the signed A2A task-state profile:
//
//   - TaskState is the IMPORTED A2A (Agent2Agent) TaskState vocabulary (carriage, not adoption): the
//     eight states submitted, working, input-required, auth-required, completed, canceled, failed,
//     rejected. The A2A specification (§4.1.3) defines the state set and the terminal/interrupted
//     categories normatively (start = submitted; terminal = completed/canceled/failed/rejected;
//     interrupted = input-required/auth-required); the legal-edge table below is DERIVED from those
//     documented category rules. A Transition {1: task, 2: card, 3: from, 4: to, 5: seq, 6: prev} is
//     one receipt-CHAINED signed state transition. VerifyTransition rejects an illegal edge (an edge
//     not in the table, a self-loop, a from-terminal edge) with a named error; VerifyTaskChain walks
//     a task's transition chain enforcing the start state, contiguity (each from == the prior to),
//     the legal-edge table at every step, the terminal-cannot-continue rule, prev/seq linkage, the
//     card binding, and the signatures. `card` is the content-id of the A2A Agent Card attestation
//     (a C18 naalp-description-import) that binds the profile to an agent/operation; a transition
//     carrying a foreign card is rejected.
//
// Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
// causes no state change.
package naming

import (
	"bytes"
	"crypto/sha512"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// HeadSize is the width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit
// chain (audit.HeadSize). Genesis is zero.
const HeadSize = 48

// Named, fail-closed errors. A failing object is rejected whole and causes no state change (§15).
// They reuse the cose.Error type so every N-AALP error carries a stable Kind.
var (
	ErrNameMalformed        = &cose.Error{Kind: "NameMalformed", Msg: "object is not a well-formed N-AALP name-binding or task-transition body"}
	ErrNameChainBroken      = &cose.Error{Kind: "NameChainBroken", Msg: "name-binding prev/seq does not chain to the previous binding (a gap, reorder, or omitted binding)"}
	ErrNameForkProofInvalid = &cose.Error{Kind: "NameForkProofInvalid", Msg: "name fork proof does not prove equivocation (not one signer, not the same name+seq, or the same signer)"}
	ErrIllegalTransition    = &cose.Error{Kind: "IllegalTransition", Msg: "A2A task transition is not a legal edge (unknown edge, self-loop, from a terminal state, or a non-contiguous from)"}
	ErrTaskChainBroken      = &cose.Error{Kind: "TaskChainBroken", Msg: "task-transition prev/seq does not chain to the previous transition (a gap, reorder, or omitted transition)"}
	ErrForeignCard          = &cose.Error{Kind: "ForeignCard", Msg: "task transition binds a card attestation other than the profile's bound A2A Agent Card"}
)

// Genesis returns a fresh 48-octet zero prev — the empty-chain link (the C7 chain genesis).
func Genesis() []byte { return make([]byte, HeadSize) }

// head is SHA-384 over a body — a 48-octet digest (the same construction as audit.Receipt.Head).
func head(b []byte) []byte {
	d := sha512.Sum384(b)
	return d[:]
}

// contentID is the T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
func contentID(b []byte) []byte {
	h := head(b)
	return append([]byte{0x20, 0x30}, h...)
}

// ==== Task 4.1 — name bindings ================================================================

// NameBinding maps a name to a signer id at a chain position. It chains onto the prior binding for
// the same name: Prev is the prior binding's Head (Genesis for seq 0). A key rotation is a new
// binding at the next Seq naming the new Signer. The binding is DATED BY Seq; the envelope's
// `created` field is advisory only.
type NameBinding struct {
	Name   string // the name being bound (a durable, human-readable name)
	Signer []byte // the signer id this binding maps the name to (opaque bytes; §5.1 signer-id form)
	Seq    uint64 // monotonic per-name chain position; seq 0 is the genesis binding
	Prev   []byte // the prior binding's Head (HeadSize bytes; genesis is zero)
}

// Bytes is the deterministic-CBOR encoding {1: name, 2: signer, 3: seq, 4: prev}.
func (nb NameBinding) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr(nb.Name)},
		{K: cbor.Uint(2), V: cbor.Bstr(nb.Signer)},
		{K: cbor.Uint(3), V: cbor.Uint(nb.Seq)},
		{K: cbor.Uint(4), V: cbor.Bstr(nb.Prev)},
	})
	return b
}

// Head is the chain head after this binding: SHA-384 of the binding body (48 octets). Because the
// body carries Prev, editing any binding breaks the next binding's linkage.
func (nb NameBinding) Head() []byte { return head(nb.Bytes()) }

// ID is the binding's T1 content-id (50 octets).
func (nb NameBinding) ID() []byte { return contentID(nb.Bytes()) }

// ParseNameBinding reconstructs a NameBinding from its body bytes alone.
func ParseNameBinding(b []byte) (NameBinding, error) {
	m, ok := decodeMap(b)
	if !ok {
		return NameBinding{}, ErrNameMalformed
	}
	name, ok1 := tstrField(m, 1)
	signer, ok2 := bstrField(m, 2)
	seq, ok3 := uintField(m, 3)
	prev, ok4 := bstrField(m, 4)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return NameBinding{}, ErrNameMalformed
	}
	return NameBinding{Name: name, Signer: signer, Seq: seq, Prev: prev}, nil
}

// SignBinding produces the tagged COSE_Sign1 object over the binding body.
func SignBinding(nb NameBinding, s cose.Signer) ([]byte, error) { return cose.Sign1(s, nb.Bytes()) }

// VerifyBinding verifies the binding's full signature under the profile, then reconstructs it from
// the signed body bytes.
func VerifyBinding(obj []byte, profile int, v cose.Verifier) (NameBinding, error) {
	if err := cose.Verify1(profile, v, obj); err != nil {
		return NameBinding{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return NameBinding{}, err
	}
	return ParseNameBinding(payload)
}

// Registrar is a naming authority that appends monotonic signed bindings for ONE name (mirroring
// the C7 audit.Authority). Each Append records a name -> signer mapping at the next chain position;
// a rotation is simply an Append naming the new signer.
type Registrar struct {
	name   string
	signer cose.Signer
	head   []byte
	seq    uint64
}

// NewRegistrar starts a registrar for `name` with an empty (genesis) chain.
func NewRegistrar(name string, signer cose.Signer) *Registrar {
	return &Registrar{name: name, signer: signer, head: Genesis()}
}

// Append records a binding of the registrar's name to `subject` at the next chain position, returning
// the binding and its tagged COSE_Sign1 object. Seq increases by one per append (monotonic); the
// chain head advances to the new binding's Head.
func (r *Registrar) Append(subject []byte) (NameBinding, []byte, error) {
	nb := NameBinding{Name: r.name, Signer: append([]byte(nil), subject...), Seq: r.seq, Prev: append([]byte(nil), r.head...)}
	obj, err := SignBinding(nb, r.signer)
	if err != nil {
		return NameBinding{}, nil, err
	}
	r.head = nb.Head()
	r.seq++
	return nb, obj, nil
}

// NameEvent is one step of a walked name history: the chain position and the signer the name mapped
// to at that position, with the chain head after it.
type NameEvent struct {
	Seq    uint64
	Signer []byte
	Head   []byte
}

// WalkHistory verifies a name-binding chain's structural continuity OFFLINE (no signatures) and
// returns the ordered signer succession. It requires every binding to name the SAME name, seq i to
// equal its index, and prev to link to the previous binding's Head (genesis zero for seq 0). A gap,
// reorder, omitted binding, or a name change is NameChainBroken (fail-closed). The CURRENT signer is
// the last event's Signer.
func WalkHistory(bindings []NameBinding) ([]NameEvent, error) {
	events := make([]NameEvent, 0, len(bindings))
	h := Genesis()
	var name string
	for i, nb := range bindings {
		if i == 0 {
			name = nb.Name
		} else if nb.Name != name {
			return nil, ErrNameChainBroken // a chain is for exactly one name
		}
		if nb.Seq != uint64(i) || !bytes.Equal(nb.Prev, h) {
			return nil, ErrNameChainBroken
		}
		h = nb.Head()
		events = append(events, NameEvent{Seq: nb.Seq, Signer: append([]byte(nil), nb.Signer...), Head: append([]byte(nil), h...)})
	}
	return events, nil
}

// VerifyChain checks a name-binding chain offline against the authority's key. Each element is the
// tagged COSE_Sign1 object for one binding (the on-wire signed form); VerifyChain verifies every
// signature under the profile (VerifyBinding), then enforces structural continuity — every binding
// names the SAME name, seq i equals its index, and prev links to the previous binding's Head (genesis
// zero for seq 0) — returning the verified, ordered bindings. A bad signature propagates from
// cose.Verify1 (BadSignature); a broken link, a seq gap, or a name change is NameChainBroken. This
// detects any reorder, omission, or substitution (§8.1). Fail-closed.
func VerifyChain(objs [][]byte, profile int, v cose.Verifier) ([]NameBinding, error) {
	h := Genesis()
	var name string
	out := make([]NameBinding, 0, len(objs))
	for i, obj := range objs {
		nb, err := VerifyBinding(obj, profile, v)
		if err != nil {
			return nil, err // BadSignature (foreign/tampered) or NameMalformed
		}
		if i == 0 {
			name = nb.Name
		} else if nb.Name != name {
			return nil, ErrNameChainBroken // a chain is for exactly one name
		}
		if nb.Seq != uint64(i) || !bytes.Equal(nb.Prev, h) {
			return nil, ErrNameChainBroken
		}
		h = nb.Head()
		out = append(out, nb)
	}
	return out, nil
}

// DetectHole reports whether a presented (possibly gappy) binding list breaks contiguity — a
// deleted/omitted binding — and, if so, the FIRST-BROKEN POSITION: the index i where the i-th
// presented binding's Seq is not i or its Prev does not link to the previous binding's Head. A
// contiguous list returns (0, false). This is the gap-evident detector: a deleted binding leaves a
// detectable hole at the position where the missing binding should have been.
func DetectHole(bindings []NameBinding) (position int, hole bool) {
	h := Genesis()
	for i, nb := range bindings {
		if nb.Seq != uint64(i) || !bytes.Equal(nb.Prev, h) {
			return i, true
		}
		h = nb.Head()
	}
	return 0, false
}

// DetectFork compares two bindings for the SAME name and reports whether they equivocate — the SAME
// name and seq but DIFFERENT bodies (a different signer or a different prev) — and, if so, the seq
// POSITION at which they conflict. A different name or a different seq is a legitimate distinct
// binding, not a fork; byte-identical bindings are a benign duplicate. In both non-fork cases it
// returns (0, false). The "one authority" precondition is established by verifying both objects under
// the same key (NameForkProof.Verify).
func DetectFork(a, b NameBinding) (position int, fork bool) {
	if a.Name != b.Name || a.Seq != b.Seq {
		return 0, false // different name or seq — not a conflicting pair
	}
	if bytes.Equal(a.Bytes(), b.Bytes()) {
		return 0, false // byte-identical — a benign duplicate
	}
	return int(a.Seq), true // same (name, seq), different body => a fork at this seq
}

// NameForkProof is the non-repudiable evidence of a name fork: two validly-signed NameBinding objects
// by ONE authority at the SAME (name, seq) naming DIFFERENT signers, carried as the accused
// authority's OWN two signed objects (the tagged COSE_Sign1 bytes). It mirrors the directory /
// audit fork proof: because a single verifier checks BOTH signed objects, the proof is
// self-contained — any third party confirms both signatures against the accused key with no further
// evidence and no repudiation.
type NameForkProof struct {
	Signer  []byte // accused authority signer id (both signed objects verify under its key)
	SignedA []byte // the accused's first signed binding (tagged COSE_Sign1)
	SignedB []byte // the accused's second signed binding at the same (name, seq)
}

// Verify checks that fp is a genuine name fork by the authority whose key is v, and returns the seq
// POSITION at which it forks. It accepts iff ALL hold: (1) the signer id is present; (2) BOTH signed
// objects verify under v (which, because a single verifier checks both, proves one authority);
// (3) the two bindings share one name and seq; and (4) their bodies differ. Any failure rejects the
// whole proof (fail-closed) with a named error: an unnamed signer, a different name/seq, or identical
// bodies is NameForkProofInvalid, and a signature that does not verify propagates from cose.Verify1
// (BadSignature). v MUST be the verifier resolved for fp.Signer.
func (fp NameForkProof) Verify(profile int, v cose.Verifier) (position int, err error) {
	if len(fp.Signer) == 0 {
		return 0, ErrNameForkProofInvalid // an unnamed accused is not evidence
	}
	a, err := VerifyBinding(fp.SignedA, profile, v)
	if err != nil {
		return 0, err
	}
	b, err := VerifyBinding(fp.SignedB, profile, v)
	if err != nil {
		return 0, err
	}
	pos, fork := DetectFork(a, b)
	if !fork {
		return 0, ErrNameForkProofInvalid // same name+seq identical bodies, or not the same (name, seq)
	}
	return pos, nil
}

// ==== Task 4.2 — the signed A2A task-state profile ============================================

// TaskState is one of the imported A2A (Agent2Agent) TaskState values (carriage, not adoption). The
// codes are stable N-AALP wire codes for the A2A vocabulary; the state SET and the terminal/
// interrupted categories are from the A2A specification (§4.1.3).
type TaskState uint64

const (
	StateSubmitted     TaskState = 0 // A2A "submitted" — acknowledged, not yet started (the start state)
	StateWorking       TaskState = 1 // A2A "working" — actively processed
	StateInputRequired TaskState = 2 // A2A "input-required" — interrupted, awaiting client input
	StateAuthRequired  TaskState = 3 // A2A "auth-required" — interrupted, awaiting authentication
	StateCompleted     TaskState = 4 // A2A "completed" — terminal success
	StateCanceled      TaskState = 5 // A2A "canceled" — terminal, canceled before completion
	StateFailed        TaskState = 6 // A2A "failed" — terminal, finished with an error
	StateRejected      TaskState = 7 // A2A "rejected" — terminal, the agent declined the task
)

// StartState is the A2A lifecycle start state (submitted).
const StartState = StateSubmitted

// stateName maps a state code to its A2A name (for diagnostics). An unknown code returns "".
var stateName = map[TaskState]string{
	StateSubmitted: "submitted", StateWorking: "working", StateInputRequired: "input-required",
	StateAuthRequired: "auth-required", StateCompleted: "completed", StateCanceled: "canceled",
	StateFailed: "failed", StateRejected: "rejected",
}

// Name returns the A2A state name, or "unknown" for an out-of-range code.
func (s TaskState) Name() string {
	if n, ok := stateName[s]; ok {
		return n
	}
	return "unknown"
}

// IsState reports whether s is one of the eight defined A2A states.
func (s TaskState) IsState() bool { _, ok := stateName[s]; return ok }

// IsTerminal reports whether s is a terminal state (completed/canceled/failed/rejected): no
// transition may leave it.
func (s TaskState) IsTerminal() bool {
	switch s {
	case StateCompleted, StateCanceled, StateFailed, StateRejected:
		return true
	}
	return false
}

// IsInterrupted reports whether s is an interrupted state (input-required/auth-required): awaiting
// client action.
func (s TaskState) IsInterrupted() bool {
	return s == StateInputRequired || s == StateAuthRequired
}

// legalEdges is the explicit A2A transition table: the set of legal (from, to) edges derived from
// the A2A category rules (design §22.3). It is the authoritative source both the boolean LegalEdge
// check and VerifyTaskChain consult; the two-implementation parity grades it Go == Rust == oracle
// against the independently-listed edge set in vectors/naming/cases.json.
var legalEdges = func() map[[2]TaskState]bool {
	active := []TaskState{StateSubmitted, StateWorking}
	interrupted := []TaskState{StateInputRequired, StateAuthRequired}
	terminal := []TaskState{StateCompleted, StateCanceled, StateFailed, StateRejected}
	m := map[[2]TaskState]bool{}
	add := func(f, t TaskState) { m[[2]TaskState{f, t}] = true }
	add(StateSubmitted, StateWorking) // begin processing (the only active->active edge)
	for _, s := range active {        // active -> interrupted
		for _, t := range interrupted {
			add(s, t)
		}
	}
	for _, s := range active { // active -> terminal
		for _, t := range terminal {
			add(s, t)
		}
	}
	for _, s := range interrupted { // interrupted -> working (client acted)
		add(s, StateWorking)
	}
	for _, s := range interrupted { // interrupted -> terminal
		for _, t := range terminal {
			add(s, t)
		}
	}
	return m
}()

// LegalEdge reports whether (from -> to) is a legal A2A transition edge per the table. A self-loop,
// an edge out of a terminal state, an edge into or out of an undefined state, and any edge not in
// the table are all false.
func LegalEdge(from, to TaskState) bool {
	if !from.IsState() || !to.IsState() {
		return false
	}
	return legalEdges[[2]TaskState{from, to}]
}

// LegalEdges returns a copy of the legal transition table as a slice of [from, to] pairs (sorted),
// so a verifier or a test can enumerate the table.
func LegalEdges() [][2]TaskState {
	out := make([][2]TaskState, 0, len(legalEdges))
	for e := range legalEdges {
		out = append(out, e)
	}
	// deterministic order: by from then to
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && less(out[j], out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func less(a, b [2]TaskState) bool {
	if a[0] != b[0] {
		return a[0] < b[0]
	}
	return a[1] < b[1]
}

// VerifyTransition is the edge-legality gate (rejects illegal edges): it returns nil iff (from -> to)
// is a legal A2A transition edge, and ErrIllegalTransition otherwise (an unknown edge, a self-loop,
// an edge out of a terminal state, or an edge touching an undefined state). Fail-closed.
func VerifyTransition(from, to TaskState) error {
	if !LegalEdge(from, to) {
		return ErrIllegalTransition
	}
	return nil
}

// Transition is one signed, receipt-CHAINED A2A task state transition (design §22.4). It chains onto
// the prior transition of the same task: Prev is the prior transition's Head (Genesis for seq 0). It
// is DATED BY Seq. Card is the content-id of the A2A Agent Card attestation (a C18
// naalp-description-import) that binds this task profile to an agent/operation.
type Transition struct {
	Task []byte    // the task id (opaque bytes)
	Card []byte    // content-id of the bound A2A Agent Card attestation (the C18 import)
	From TaskState // the source state
	To   TaskState // the target state
	Seq  uint64    // monotonic per-task chain position; seq 0's From MUST be the start state
	Prev []byte    // the prior transition's Head (HeadSize bytes; genesis is zero)
}

// Bytes is the deterministic-CBOR encoding {1: task, 2: card, 3: from, 4: to, 5: seq, 6: prev}.
func (t Transition) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(t.Task)},
		{K: cbor.Uint(2), V: cbor.Bstr(t.Card)},
		{K: cbor.Uint(3), V: cbor.Uint(uint64(t.From))},
		{K: cbor.Uint(4), V: cbor.Uint(uint64(t.To))},
		{K: cbor.Uint(5), V: cbor.Uint(t.Seq)},
		{K: cbor.Uint(6), V: cbor.Bstr(t.Prev)},
	})
	return b
}

// Head is the chain head after this transition: SHA-384 of the transition body (48 octets).
func (t Transition) Head() []byte { return head(t.Bytes()) }

// ID is the transition's T1 content-id (50 octets).
func (t Transition) ID() []byte { return contentID(t.Bytes()) }

// ParseTransition reconstructs a Transition from its body bytes alone.
func ParseTransition(b []byte) (Transition, error) {
	m, ok := decodeMap(b)
	if !ok {
		return Transition{}, ErrNameMalformed
	}
	task, ok1 := bstrField(m, 1)
	card, ok2 := bstrField(m, 2)
	from, ok3 := uintField(m, 3)
	to, ok4 := uintField(m, 4)
	seq, ok5 := uintField(m, 5)
	prev, ok6 := bstrField(m, 6)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return Transition{}, ErrNameMalformed
	}
	return Transition{Task: task, Card: card, From: TaskState(from), To: TaskState(to), Seq: seq, Prev: prev}, nil
}

// SignTransition produces the tagged COSE_Sign1 object over the transition body.
func SignTransition(t Transition, s cose.Signer) ([]byte, error) { return cose.Sign1(s, t.Bytes()) }

// VerifyTransitionObject verifies a transition's full signature under the profile, then reconstructs
// it from the signed body bytes AND checks that its edge is legal (VerifyTransition). A bad signature
// propagates from cose.Verify1 (BadSignature); an illegal edge is ErrIllegalTransition. Fail-closed.
func VerifyTransitionObject(obj []byte, profile int, v cose.Verifier) (Transition, error) {
	if err := cose.Verify1(profile, v, obj); err != nil {
		return Transition{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return Transition{}, err
	}
	t, err := ParseTransition(payload)
	if err != nil {
		return Transition{}, err
	}
	if err := VerifyTransition(t.From, t.To); err != nil {
		return Transition{}, err
	}
	return t, nil
}

// VerifyTaskChain walks a task's transition chain offline against the authority's key and the bound
// card attestation. Each element is the tagged COSE_Sign1 object for one transition. It enforces, in
// order and fail-closed: (1) the SIGNATURE of every transition (cose.Verify1) — BadSignature
// otherwise; (2) prev/seq linkage (each Prev links to the prior Head, genesis zero for seq 0; seq i
// == index) — a gap/reorder is TaskChainBroken; (3) the CARD BINDING (every transition's Card equals
// `card`) — ForeignCard otherwise; and (4) the START STATE (the seq-0 transition's From is
// StartState), CONTIGUITY (each From == the prior To), and the LEGAL-EDGE TABLE at every step
// (including the terminal-cannot-continue rule, since a from-terminal edge is not in the table) —
// IllegalTransition otherwise. It returns the verified, ordered transitions. It never authorizes; it
// accepts or rejects.
func VerifyTaskChain(objs [][]byte, card []byte, profile int, v cose.Verifier) ([]Transition, error) {
	h := Genesis()
	var prevTo TaskState
	out := make([]Transition, 0, len(objs))
	for i, obj := range objs {
		if err := cose.Verify1(profile, v, obj); err != nil {
			return nil, err // BadSignature (foreign/tampered)
		}
		_, payload, _, err := cose.ParseSign1Raw(obj)
		if err != nil {
			return nil, err
		}
		t, err := ParseTransition(payload)
		if err != nil {
			return nil, err
		}
		if t.Seq != uint64(i) || !bytes.Equal(t.Prev, h) {
			return nil, ErrTaskChainBroken
		}
		if !bytes.Equal(t.Card, card) {
			return nil, ErrForeignCard
		}
		if i == 0 {
			if t.From != StartState {
				return nil, ErrIllegalTransition // the first transition MUST leave the start state
			}
		} else if t.From != prevTo {
			return nil, ErrIllegalTransition // non-contiguous: this From must equal the prior To
		}
		if err := VerifyTransition(t.From, t.To); err != nil {
			return nil, err // an illegal edge (incl. a from-terminal edge: terminal has no out-edge)
		}
		h = t.Head()
		prevTo = t.To
		out = append(out, t)
	}
	return out, nil
}

// DetectTaskGap reports whether a presented (possibly gappy) transition list breaks contiguity — a
// deleted/omitted or reordered transition — and, if so, the FIRST-BROKEN POSITION: the index i where
// the i-th presented transition's Seq is not i or its Prev does not link to the previous
// transition's Head. A contiguous list returns (0, false). (The gap-evident detector for the task
// chain, mirroring DetectHole for name bindings.)
func DetectTaskGap(transitions []Transition) (position int, gap bool) {
	h := Genesis()
	for i, t := range transitions {
		if t.Seq != uint64(i) || !bytes.Equal(t.Prev, h) {
			return i, true
		}
		h = t.Head()
	}
	return 0, false
}

// ---- small deterministic-CBOR field accessors ------------------------------------------------

func decodeMap(b []byte) (cbor.Map, bool) {
	v, err := cbor.Decode(b)
	if err != nil {
		return nil, false
	}
	m, ok := v.(cbor.Map)
	return m, ok
}

func field(m cbor.Map, k uint64) (cbor.Value, bool) {
	for _, p := range m {
		if p.K == cbor.Uint(k) {
			return p.V, true
		}
	}
	return nil, false
}

func bstrField(m cbor.Map, k uint64) ([]byte, bool) {
	v, ok := field(m, k)
	if !ok {
		return nil, false
	}
	bs, ok := v.(cbor.Bstr)
	return []byte(bs), ok
}

func tstrField(m cbor.Map, k uint64) (string, bool) {
	v, ok := field(m, k)
	if !ok {
		return "", false
	}
	ts, ok := v.(cbor.Tstr)
	return string(ts), ok
}

func uintField(m cbor.Map, k uint64) (uint64, bool) {
	v, ok := field(m, k)
	if !ok {
		return 0, false
	}
	u, ok := v.(cbor.Uint)
	return uint64(u), ok
}
