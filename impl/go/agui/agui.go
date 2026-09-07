// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package agui implements C21 task 5B.2 — NAALP-AGUI UI-consent binding (design.md §24;
// requirements R-AGUI-1..6).
//
// NAALP-AGUI binds a human-in-the-loop approval, captured in a user-interface event stream (the AG-UI
// tool-lifecycle events an agent shows a user), to the EXACT action bytes by content id, and
// RECEIPT-CHAINS the shown events so the shown sequence is provable offline. It introduces NO new
// envelope, encoding, signature, identity, or audit mechanism (R-11.3): a UI event is an ordinary
// signed N-AALP body (COSE_Sign1, §4), and the surface reuses the C7 audit receipt-chain construction
// (§8.1) unchanged — head = SHA-384(body), genesis prev = 48 zero bytes, a monotonic seq, the prior
// head carried in `prev` so editing or omitting an event breaks the next event's linkage — and the §7
// approval binding (package approval) UNCHANGED.
//
//   - UIEvent {1: session, 2: kind, 3: action, 4: seq, 5: prev} is one shown tool-lifecycle event.
//     `kind` is a closed set (shown / args-shown / approved / rejected); `action` is the T1 content id
//     of the action bytes shown to the user at this step; the chain is receipt-chained by prev/seq.
//
// The load-bearing properties, graded by both implementations:
//
//   - A UI approval verifies ONLY against the EXACT action shown. VerifyConsent walks the shown chain,
//     takes the action content id from the shown-and-approved event, and requires the action actually
//     being executed to hash to THAT content id (ErrActionSubstituted otherwise) AND the human
//     approval to bind it (the §7 approval, ApprovalMismatch otherwise). A substituted action has a
//     different content id and is rejected.
//   - A removed/omitted shown-event is detected with its POSITION. WalkShown enforces contiguity and
//     returns UIChainBroken on a gap; DetectHole reports the first-broken position, the same way the
//     §8.5 audit fork proof and the §22 name-history hole report a position.
//
// Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
// causes no state change.
package agui

import (
	"bytes"
	"crypto/sha512"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// HeadSize is the width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain
// (audit.HeadSize). Genesis is zero.
const HeadSize = 48

// UI event kinds — the closed AG-UI tool-lifecycle set transcribed to the spine. A kind outside the
// set is rejected (UnknownUIEventKind).
const (
	KindShown     uint64 = 0 // the action / tool call was shown (rendered) to the user
	KindArgsShown uint64 = 1 // the arguments were shown to the user
	KindApproved  uint64 = 2 // the user approved the shown action
	KindRejected  uint64 = 3 // the user rejected the shown action
)

// kindName maps a UI-event kind code to its name (diagnostics); an unknown code returns "".
var kindName = map[uint64]string{
	KindShown: "shown", KindArgsShown: "args-shown", KindApproved: "approved", KindRejected: "rejected",
}

// IsKnownKind reports whether code is one of the closed UI-event kinds.
func IsKnownKind(code uint64) bool { _, ok := kindName[code]; return ok }

// KindName returns the kind name, or "unknown".
func KindName(code uint64) string {
	if n, ok := kindName[code]; ok {
		return n
	}
	return "unknown"
}

// Named, fail-closed errors. A failing object is rejected whole and causes no state change (§15).
// The approval binding, expiry, and signature errors are the EXISTING §7 errors reused unchanged
// (approval.ErrApprovalMismatch / ErrApprovalExpired, cose.ErrBadSignature).
var (
	ErrMalformed        = &cose.Error{Kind: "UIMalformed", Msg: "object is not a well-formed N-AALP ui-event body"}
	ErrUIChainBroken    = &cose.Error{Kind: "UIChainBroken", Msg: "ui-event prev/seq does not chain to the previous event (a gap, reorder, or omitted shown-event)"}
	ErrUnknownEventKind = &cose.Error{Kind: "UnknownUIEventKind", Msg: "ui-event kind is outside the closed set shown/args-shown/approved/rejected"}
	ErrActionSubstituted = &cose.Error{Kind: "ActionSubstituted", Msg: "the action being executed is not the exact action shown and approved in the UI stream"}
	ErrNoConsent        = &cose.Error{Kind: "UINoConsent", Msg: "the shown chain carries no approved event — there is no human consent to bind"}
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

// ContentID is the exported T1 content id of arbitrary bytes — the content id of an ACTION, which a
// UI event names in field 3 and a human approval binds. A relying party computes it over the exact
// action bytes it is about to execute.
func ContentID(b []byte) []byte { return contentID(b) }

// ---- UIEvent: one receipt-chained shown tool-lifecycle event (design.md §24) ------------------

// UIEvent is one shown tool-lifecycle event in a UI session's event stream. It chains onto the prior
// event: Prev is the prior event's Head (Genesis for seq 0). Action is the content id of the exact
// action bytes shown to the user at this step.
type UIEvent struct {
	Session []byte // UI session id (ties the stream together)
	Kind    uint64 // the event kind (closed set)
	Action  []byte // content id of the exact action bytes shown at this step
	Seq     uint64 // monotonic per-session chain position; seq 0 is the genesis event
	Prev    []byte // the prior event's Head (HeadSize bytes; genesis is zero)
}

// Bytes is the deterministic-CBOR encoding {1: session, 2: kind, 3: action, 4: seq, 5: prev}.
func (e UIEvent) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(e.Session)},
		{K: cbor.Uint(2), V: cbor.Uint(e.Kind)},
		{K: cbor.Uint(3), V: cbor.Bstr(e.Action)},
		{K: cbor.Uint(4), V: cbor.Uint(e.Seq)},
		{K: cbor.Uint(5), V: cbor.Bstr(e.Prev)},
	})
	return b
}

// Head is the chain head after this event: SHA-384 of the event body (48 octets). Because the body
// carries Prev, editing any event breaks the next event's linkage.
func (e UIEvent) Head() []byte { return head(e.Bytes()) }

// ID is the event's T1 content-id (50 octets).
func (e UIEvent) ID() []byte { return contentID(e.Bytes()) }

// ParseUIEvent reconstructs a UIEvent from its body bytes alone.
func ParseUIEvent(b []byte) (UIEvent, error) {
	m, ok := decodeMap(b)
	if !ok {
		return UIEvent{}, ErrMalformed
	}
	sess, ok1 := bstrField(m, 1)
	kind, ok2 := uintField(m, 2)
	action, ok3 := bstrField(m, 3)
	seq, ok4 := uintField(m, 4)
	prev, ok5 := bstrField(m, 5)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return UIEvent{}, ErrMalformed
	}
	return UIEvent{Session: sess, Kind: kind, Action: action, Seq: seq, Prev: prev}, nil
}

// SignUIEvent produces the tagged COSE_Sign1 object over the event body.
func SignUIEvent(e UIEvent, s cose.Signer) ([]byte, error) { return cose.Sign1(s, e.Bytes()) }

// VerifyUIEvent verifies the event's full signature under the profile, reconstructs it from the
// signed body bytes, and validates the kind against the closed set (UnknownUIEventKind). A bad
// signature propagates from cose.Verify1 (BadSignature). Fail-closed.
func VerifyUIEvent(obj []byte, profile int, v cose.Verifier) (UIEvent, error) {
	if err := cose.Verify1(profile, v, obj); err != nil {
		return UIEvent{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return UIEvent{}, err
	}
	e, err := ParseUIEvent(payload)
	if err != nil {
		return UIEvent{}, err
	}
	if !IsKnownKind(e.Kind) {
		return UIEvent{}, ErrUnknownEventKind
	}
	return e, nil
}

// ---- the shown chain: contiguity, walk, hole detection (mirrors the C7 chain) -----------------

// ShownEvent is one step of a walked shown chain: the chain position, the event kind, the action
// content id shown, and the chain head after it.
type ShownEvent struct {
	Seq    uint64
	Kind   uint64
	Action []byte
	Head   []byte
}

// WalkShown verifies a UI event chain's structural continuity OFFLINE (no signatures) and returns the
// ordered shown events. It requires every event to name the SAME session, seq i to equal its index,
// each kind to be in the closed set, and prev to link to the previous event's Head (genesis zero for
// seq 0). A gap, reorder, omitted event, or a session change is UIChainBroken (fail-closed); an
// unknown kind is UnknownUIEventKind.
func WalkShown(events []UIEvent) ([]ShownEvent, error) {
	out := make([]ShownEvent, 0, len(events))
	h := Genesis()
	var session []byte
	for i, e := range events {
		if i == 0 {
			session = e.Session
		} else if !bytes.Equal(e.Session, session) {
			return nil, ErrUIChainBroken // a chain is for exactly one session
		}
		if !IsKnownKind(e.Kind) {
			return nil, ErrUnknownEventKind
		}
		if e.Seq != uint64(i) || !bytes.Equal(e.Prev, h) {
			return nil, ErrUIChainBroken
		}
		h = e.Head()
		out = append(out, ShownEvent{Seq: e.Seq, Kind: e.Kind, Action: append([]byte(nil), e.Action...), Head: append([]byte(nil), h...)})
	}
	return out, nil
}

// VerifyShownChain checks a UI event chain offline against the UI authority's key. Each element is the
// tagged COSE_Sign1 object for one event; VerifyShownChain verifies every signature under the profile
// (VerifyUIEvent), then enforces the same structural continuity as WalkShown. A bad signature
// propagates from cose.Verify1 (BadSignature); a broken link, a seq gap, or a session change is
// UIChainBroken. This detects any reorder, omission, or substitution of a shown event (§8.1).
// Fail-closed.
func VerifyShownChain(objs [][]byte, profile int, v cose.Verifier) ([]UIEvent, error) {
	h := Genesis()
	var session []byte
	out := make([]UIEvent, 0, len(objs))
	for i, obj := range objs {
		e, err := VerifyUIEvent(obj, profile, v)
		if err != nil {
			return nil, err // BadSignature (foreign/tampered), UIMalformed, or UnknownUIEventKind
		}
		if i == 0 {
			session = e.Session
		} else if !bytes.Equal(e.Session, session) {
			return nil, ErrUIChainBroken
		}
		if e.Seq != uint64(i) || !bytes.Equal(e.Prev, h) {
			return nil, ErrUIChainBroken
		}
		h = e.Head()
		out = append(out, e)
	}
	return out, nil
}

// DetectHole reports whether a presented (possibly gappy) event list breaks contiguity — a
// deleted/omitted shown-event — and, if so, the FIRST-BROKEN POSITION: the index i where the i-th
// presented event's Seq is not i or its Prev does not link to the previous event's Head. A contiguous
// list returns (0, false). This is the gap-evident detector: a removed shown-event leaves a
// detectable hole at the position where the missing event should have been.
func DetectHole(events []UIEvent) (position int, hole bool) {
	h := Genesis()
	for i, e := range events {
		if e.Seq != uint64(i) || !bytes.Equal(e.Prev, h) {
			return i, true
		}
		h = e.Head()
	}
	return 0, false
}

// ---- the UI consent binding (reuses the §7 approval) ------------------------------------------

// ApprovedActionCID returns the content id of the action shown-and-approved in a walked chain, and
// whether an approved event is present. It is the content id a valid consent binds; a chain with no
// approved event has no consent to bind.
func ApprovedActionCID(shown []ShownEvent) ([]byte, bool) {
	for _, ev := range shown {
		if ev.Kind == KindApproved {
			return append([]byte(nil), ev.Action...), true
		}
	}
	return nil, false
}

// VerifyConsent binds a human-in-the-loop approval to the EXACT action shown in a UI event stream. It
// (1) walks the shown chain, rejecting any gap/reorder/omission (UIChainBroken); (2) takes the action
// content id from the shown-and-approved event (UINoConsent if there is none); (3) verifies the human
// §7 approval binds THAT shown content id and has not expired (ApprovalMismatch / ApprovalExpired /
// BadSignature, from packages approval and cose); and (4) requires the action actually being executed
// (`actionBytes`) to hash to the shown-and-approved content id — a SUBSTITUTED action has a different
// content id and is rejected (ErrActionSubstituted). Every failure returns its named error and
// authorizes nothing (fail-closed). On success the caller may execute exactly `actionBytes`.
func VerifyConsent(chain []UIEvent, actionBytes []byte, appr approval.ApprovalRecord, approverV cose.Verifier, apprSig []byte, now uint64) error {
	shown, err := WalkShown(chain)
	if err != nil {
		return err // UIChainBroken / UnknownUIEventKind — a hole in the shown sequence
	}
	shownCID, ok := ApprovedActionCID(shown)
	if !ok {
		return ErrNoConsent // no approved event: there is no human consent to bind
	}
	// The human approval must be a valid signature binding the shown-and-approved action content id.
	if err := approval.VerifyApproval(appr, approverV, apprSig, shownCID, now); err != nil {
		return err // ApprovalMismatch / ApprovalExpired / BadSignature
	}
	// The action actually being executed MUST be the exact one shown and approved: a substitution has
	// a different content id and is rejected. This is the seam a lax UI profile would drop.
	if !bytes.Equal(contentID(actionBytes), shownCID) {
		return ErrActionSubstituted
	}
	return nil
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
