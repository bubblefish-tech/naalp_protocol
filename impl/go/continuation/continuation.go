// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package continuation implements C17 — N-AALP-CONT flow continuation (design.md §20;
// requirement R-CONT-1..7).
//
// N-AALP-CONT generalizes the C9 native-streaming pattern (one signed StreamOpen, cheap
// per-chunk data, one signed StreamCommit over a rolling digest) into a domain-agnostic *flow*:
//
//   - FlowOpen is the ONE full ML-DSA signature that fixes the flow's authority: its flow_id, its
//     effect ceiling, and the content-ids of the approvals that authorize it up to that ceiling.
//     The authority is reconstructable from the FlowOpen bytes ALONE (ParseFlowOpen) — no session
//     or server state is needed to know what a continuation is allowed to do.
//   - Continuation is a CHEAP object: no per-object signature, only a SHA-384 hash-chain link.
//     Each link's head is SHA-384(link body); its `prev` is the previous link's head; the chain's
//     genesis prev is the FlowOpen's head, which anchors every link to THIS FlowOpen. A link
//     carries its own effect, which MUST stay at or below the ceiling (AboveCeiling otherwise —
//     the cheap path can never escalate past the one full signature + approval).
//   - Checkpoint lets a verifier confirm a contiguous prefix and DETECT A GAP: a dropped or
//     reordered link breaks the recomputed chain (GapDetected).
//   - FlowCommit is a second full ML-DSA signature binding the whole ordered sequence with ONE
//     signature regardless of the number of continuations (the streaming StreamCommit property).
//
// A continuation replayed under a different FlowOpen fails: it carries the originating
// flow_open_id (WrongFlow) and its prev no longer chains to the other FlowOpen's head
// (ChainBroken). Domain separation is structural: FlowOpen (3 fields, an approvals array at 3),
// Continuation (5 fields), Checkpoint (3 fields, a bstr head at 3), and FlowCommit (2 fields) are
// each a distinct deterministic-CBOR shape, so a chain head — SHA-384 over the 5-field
// Continuation body — cannot collide with any other object's body hash.
package continuation

import (
	"bytes"
	"crypto/sha512"
	"math"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// HeadSize is the width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit
// chain (audit.HeadSize). A FlowOpen head anchors a flow's continuation chain.
const HeadSize = 48

// Named, fail-closed errors. A failing object is rejected whole and causes no state change (§15).
var (
	ErrWrongFlow      = &cose.Error{Kind: "WrongFlow", Msg: "object's flow_open_id does not match the FlowOpen"}
	ErrSeqGap         = &cose.Error{Kind: "SeqGap", Msg: "continuation seq is not the next expected value"}
	ErrAboveCeiling   = &cose.Error{Kind: "AboveCeiling", Msg: "continuation effect exceeds the FlowOpen effect ceiling"}
	ErrChainBroken    = &cose.Error{Kind: "ChainBroken", Msg: "continuation prev does not chain to the previous head"}
	ErrGapDetected    = &cose.Error{Kind: "GapDetected", Msg: "checkpoint reveals a dropped or reordered continuation"}
	ErrCommitMismatch = &cose.Error{Kind: "CommitMismatch", Msg: "flow commit final_head does not match the recomputed chain"}
	ErrMalformed      = &cose.Error{Kind: "ContMalformed", Msg: "object is not a well-formed N-AALP-CONT body"}
	ErrRange          = &cose.Error{Kind: "RangeError", Msg: "effect or effect_ceiling is outside the closed 0..3 lattice"}
)

// inLattice reports whether v is a value of the closed C5 effect lattice (0..3). The CDDL types both
// effect_ceiling (naalp-flow-open field 2) and a continuation effect (naalp-continuation field 3) as
// the closed `effect` enum, so an out-of-lattice value is rejected RangeError, NEVER normalized to
// destructive: normalizing a CEILING to destructive would silently make an out-of-range ceiling the
// MOST-permissive one (a fail-open), so a ceiling is range-checked, never NormalizeEffect'd.
func inLattice(v uint64) bool { return v <= uint64(policy.Destructive) }

// head is SHA-384 over a body — a 48-octet chain head (the same construction as audit.Receipt.Head).
func head(b []byte) []byte {
	d := sha512.Sum384(b)
	return d[:]
}

// contentID is the T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
func contentID(b []byte) []byte {
	h := head(b)
	return append([]byte{0x20, 0x30}, h...)
}

// ---- FlowOpen: the one full signature fixing the flow's authority (design.md §20.2) -----------

// FlowOpen fixes a flow's identity, effect ceiling, and approval bindings. It is signed with a
// full ML-DSA signature (SignFlowOpen); its authority is reconstructable from its bytes alone.
type FlowOpen struct {
	FlowID        []byte   // opaque, unique per flow (like a stream_id)
	EffectCeiling uint64   // the maximum effect any continuation on the cheap path may cause (C5 lattice)
	Approvals     [][]byte // content-ids of the approvals authorizing this flow up to the ceiling
}

// Bytes is the deterministic-CBOR encoding {1: flow_id, 2: effect_ceiling, 3: approvals[]}.
func (o FlowOpen) Bytes() []byte {
	arr := make(cbor.Arr, len(o.Approvals))
	for i, a := range o.Approvals {
		arr[i] = cbor.Bstr(a)
	}
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(o.FlowID)},
		{K: cbor.Uint(2), V: cbor.Uint(o.EffectCeiling)},
		{K: cbor.Uint(3), V: arr},
	})
	return b
}

// Head is the FlowOpen's SHA-384 head — the genesis prev that anchors the continuation chain.
func (o FlowOpen) Head() []byte { return head(o.Bytes()) }

// ID is the FlowOpen's content-id — carried by every child object (Continuation/Checkpoint/FlowCommit).
func (o FlowOpen) ID() []byte { return contentID(o.Bytes()) }

// ParseFlowOpen reconstructs a FlowOpen from its body bytes ALONE — the bearer-authority property:
// a verifier who holds the FlowOpen bytes (and has verified the signature) knows the ceiling and
// the approvals with no session state.
func ParseFlowOpen(b []byte) (FlowOpen, error) {
	m, ok := decodeMap(b)
	if !ok {
		return FlowOpen{}, ErrMalformed
	}
	fid, ok1 := bstrField(m, 1)
	ceil, ok2 := uintField(m, 2)
	appsV, ok3 := field(m, 3)
	if !ok1 || !ok2 || !ok3 {
		return FlowOpen{}, ErrMalformed
	}
	// The effect_ceiling is a CLOSED effect (0..3); an out-of-lattice ceiling is rejected on decode
	// (RangeError), never normalized — see inLattice.
	if !inLattice(ceil) {
		return FlowOpen{}, ErrRange
	}
	arr, ok := appsV.(cbor.Arr)
	if !ok {
		return FlowOpen{}, ErrMalformed
	}
	apps := make([][]byte, len(arr))
	for i, e := range arr {
		bs, ok := e.(cbor.Bstr)
		if !ok {
			return FlowOpen{}, ErrMalformed
		}
		apps[i] = []byte(bs)
	}
	return FlowOpen{FlowID: fid, EffectCeiling: ceil, Approvals: apps}, nil
}

// ---- Continuation: the cheap hash-chain link (design.md §20.3) --------------------------------

// Continuation is one cheap link in a flow's chain. It is NOT individually signed; its authenticity
// derives from the FlowOpen's signature plus the hash chain plus the FlowCommit's signature.
type Continuation struct {
	FlowOpenID []byte // the originating FlowOpen's content-id (WrongFlow if it does not match)
	Seq        uint64 // 0-based position in the chain
	Effect     uint64 // this step's effect; MUST be <= the FlowOpen ceiling (AboveCeiling otherwise)
	PayloadID  []byte // content-id of this step's payload
	Prev       []byte // the previous link's head (the FlowOpen head for seq 0)
}

// Bytes is the deterministic-CBOR encoding {1: flow_open_id, 2: seq, 3: effect, 4: payload_id, 5: prev}.
func (c Continuation) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(c.FlowOpenID)},
		{K: cbor.Uint(2), V: cbor.Uint(c.Seq)},
		{K: cbor.Uint(3), V: cbor.Uint(c.Effect)},
		{K: cbor.Uint(4), V: cbor.Bstr(c.PayloadID)},
		{K: cbor.Uint(5), V: cbor.Bstr(c.Prev)},
	})
	return b
}

// Head is this link's SHA-384 head — the prev of the next link.
func (c Continuation) Head() []byte { return head(c.Bytes()) }

// ParseContinuation is the single audited decode path for untrusted Continuation wire bytes. It
// reconstructs the 5-field body and range-checks the effect against the closed lattice (0..3):
// field 3 is typed `effect` (a closed enum) in the CDDL, so an out-of-lattice effect is rejected
// RangeError on decode, never carried as an unknown value into the cheap-path check. Fail-closed.
func ParseContinuation(b []byte) (Continuation, error) {
	m, ok := decodeMap(b)
	if !ok {
		return Continuation{}, ErrMalformed
	}
	fid, ok1 := bstrField(m, 1)
	seq, ok2 := uintField(m, 2)
	effect, ok3 := uintField(m, 3)
	pid, ok4 := bstrField(m, 4)
	prev, ok5 := bstrField(m, 5)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return Continuation{}, ErrMalformed
	}
	if !inLattice(effect) {
		return Continuation{}, ErrRange
	}
	return Continuation{FlowOpenID: fid, Seq: seq, Effect: effect, PayloadID: pid, Prev: prev}, nil
}

// VerifyContinuation is the CHEAP-path check of a single link against the flow's fixed authority:
// the same flow (WrongFlow), the next seq (SeqGap), effect within the ceiling (AboveCeiling), and
// prev chaining to the previous head (ChainBroken). It performs no signature verification — that
// is what makes it cheap; the measured cheap-vs-full ratio is in continuation_test.go.
func VerifyContinuation(c Continuation, flowOpenID, prevHead []byte, expectedSeq uint64, ceiling policy.Effect) error {
	// Both the ceiling and the link's effect are CLOSED effects (0..3). An out-of-lattice value is
	// RangeError — NOT NormalizeEffect'd — so neither an out-of-range ceiling silently becomes the
	// most-permissive class nor an out-of-range link effect is silently clamped below it (fail-closed).
	if !inLattice(uint64(ceiling)) {
		return ErrRange
	}
	if !inLattice(c.Effect) {
		return ErrRange
	}
	if !bytes.Equal(c.FlowOpenID, flowOpenID) {
		return ErrWrongFlow
	}
	if c.Seq != expectedSeq {
		return ErrSeqGap
	}
	if !ceiling.Authorizes(policy.Effect(c.Effect)) {
		return ErrAboveCeiling
	}
	if !bytes.Equal(c.Prev, prevHead) {
		return ErrChainBroken
	}
	return nil
}

// VerifyChain verifies a whole ordered continuation sequence starting from the FlowOpen and returns
// the final chain head. The ceiling comes from the FlowOpen (reconstructed from its bytes), so the
// cheap path can never exceed what the single full signature authorized.
func VerifyChain(open FlowOpen, conts []Continuation) ([]byte, error) {
	// The ceiling is a closed effect (0..3); an out-of-lattice ceiling is rejected RangeError, never
	// normalized to destructive (which would make it the most-permissive ceiling — a fail-open).
	if !inLattice(open.EffectCeiling) {
		return nil, ErrRange
	}
	id := open.ID()
	prev := open.Head()
	ceiling := policy.Effect(open.EffectCeiling)
	for i, c := range conts {
		if err := VerifyContinuation(c, id, prev, uint64(i), ceiling); err != nil {
			return nil, err
		}
		prev = c.Head()
	}
	return prev, nil
}

// ---- Checkpoint: confirm a prefix, detect a gap (design.md §20.4) -----------------------------

// Checkpoint asserts the chain head after a contiguous prefix of continuations (seq 0..ThroughSeq).
type Checkpoint struct {
	FlowOpenID []byte
	ThroughSeq uint64
	Head       []byte
}

// Bytes is the deterministic-CBOR encoding {1: flow_open_id, 2: through_seq, 3: head}.
func (c Checkpoint) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(c.FlowOpenID)},
		{K: cbor.Uint(2), V: cbor.Uint(c.ThroughSeq)},
		{K: cbor.Uint(3), V: cbor.Bstr(c.Head)},
	})
	return b
}

// ParseCheckpoint is the single audited decode path for untrusted Checkpoint wire bytes. It
// reconstructs the 3-field body (field 3 is a bstr head). It does not range-check through_seq (a
// full-range counter by the CDDL); the MaxUint64 overflow guard lives in VerifyCheckpoint, which is
// where the seq is used to size the prefix. Fail-closed on any malformed shape.
func ParseCheckpoint(b []byte) (Checkpoint, error) {
	m, ok := decodeMap(b)
	if !ok {
		return Checkpoint{}, ErrMalformed
	}
	fid, ok1 := bstrField(m, 1)
	through, ok2 := uintField(m, 2)
	h, ok3 := bstrField(m, 3)
	if !ok1 || !ok2 || !ok3 {
		return Checkpoint{}, ErrMalformed
	}
	return Checkpoint{FlowOpenID: fid, ThroughSeq: through, Head: h}, nil
}

// VerifyCheckpoint confirms the prefix is exactly the contiguous sequence seq 0..ThroughSeq and
// that its recomputed head matches the checkpoint. A dropped or reordered link — a missing seq, a
// broken prev, or the wrong count — is reported GapDetected.
func VerifyCheckpoint(cp Checkpoint, open FlowOpen, prefix []Continuation) error {
	if !bytes.Equal(cp.FlowOpenID, open.ID()) {
		return ErrWrongFlow
	}
	// through_seq is a 0-based index, so the prefix length is through_seq+1. At through_seq ==
	// MaxUint64 that addition would wrap to 0 and false-accept an EMPTY prefix as covering the whole
	// counter space — reject it as a gap instead (there can be no MaxUint64+1 contiguous links).
	if cp.ThroughSeq == math.MaxUint64 {
		return ErrGapDetected
	}
	if uint64(len(prefix)) != cp.ThroughSeq+1 {
		return ErrGapDetected // wrong count: a link is missing or extra
	}
	h, err := VerifyChain(open, prefix)
	if err != nil {
		return ErrGapDetected // a seq/prev break inside the prefix is a gap
	}
	if !bytes.Equal(cp.Head, h) {
		return ErrGapDetected
	}
	return nil
}

// ---- FlowCommit: the second full signature binding the whole sequence (design.md §20.5) --------

// FlowCommit binds a completed flow's final chain head under one full ML-DSA signature.
type FlowCommit struct {
	FlowOpenID []byte
	FinalHead  []byte
}

// Bytes is the deterministic-CBOR encoding {1: flow_open_id, 2: final_head} — the 2-field shape
// that distinguishes it from the 3-field Checkpoint.
func (c FlowCommit) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(c.FlowOpenID)},
		{K: cbor.Uint(2), V: cbor.Bstr(c.FinalHead)},
	})
	return b
}

// ---- Full-signature helpers (FlowOpen / FlowCommit) -------------------------------------------

// SignFlowOpen produces the tagged COSE_Sign1 object over the FlowOpen body (the one full signature
// that opens the flow).
func SignFlowOpen(o FlowOpen, s cose.Signer) ([]byte, error) { return cose.Sign1(s, o.Bytes()) }

// SignFlowCommit produces the tagged COSE_Sign1 object over the FlowCommit body.
func SignFlowCommit(c FlowCommit, s cose.Signer) ([]byte, error) { return cose.Sign1(s, c.Bytes()) }

// VerifyFlowOpen verifies the FlowOpen's full signature under the profile, then reconstructs the
// authority from the signed body bytes. This is the expensive path measured against the cheap one.
func VerifyFlowOpen(obj []byte, profile int, v cose.Verifier) (FlowOpen, error) {
	if err := cose.Verify1(profile, v, obj); err != nil {
		return FlowOpen{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return FlowOpen{}, err
	}
	return ParseFlowOpen(payload)
}

// VerifyFlowCommit verifies the FlowCommit's full signature, that it binds this FlowOpen, and that
// its final_head equals the chain recomputed over the delivered continuations. A missing or
// reordered continuation makes the recomputed head differ (CommitMismatch, or the chain error).
func VerifyFlowCommit(obj []byte, profile int, v cose.Verifier, open FlowOpen, conts []Continuation) (FlowCommit, error) {
	if err := cose.Verify1(profile, v, obj); err != nil {
		return FlowCommit{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return FlowCommit{}, err
	}
	m, ok := decodeMap(payload)
	if !ok {
		return FlowCommit{}, ErrMalformed
	}
	fid, ok1 := bstrField(m, 1)
	fh, ok2 := bstrField(m, 2)
	if !ok1 || !ok2 {
		return FlowCommit{}, ErrMalformed
	}
	fc := FlowCommit{FlowOpenID: fid, FinalHead: fh}
	if !bytes.Equal(fc.FlowOpenID, open.ID()) {
		return FlowCommit{}, ErrWrongFlow
	}
	finalHead, err := VerifyChain(open, conts)
	if err != nil {
		return FlowCommit{}, err
	}
	if !bytes.Equal(fc.FinalHead, finalHead) {
		return FlowCommit{}, ErrCommitMismatch
	}
	return fc, nil
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

func uintField(m cbor.Map, k uint64) (uint64, bool) {
	v, ok := field(m, k)
	if !ok {
		return 0, false
	}
	u, ok := v.(cbor.Uint)
	return uint64(u), ok
}
