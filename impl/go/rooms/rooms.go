// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package rooms implements the collaboration / rooms membership surface (feature #64): a
// Phase-3 ADDITIVE higher tier (tier 1) over the frozen draft-00 spine (design.md §2..§10;
// design-channels.md §21). It introduces NO new envelope, encoding, signature, identity, or
// audit mechanism — it reuses the spine unchanged (R-11.3, R-15A.2) — and adds only tier-1
// object kinds on the Governance channel (0x0004; membership ops) and the Identity channel
// (0x0003; the principal registry). A frozen baseline verifier that has not licensed the tier
// rejects a room kind as UnknownKind, fail-closed; that is honest, not a defect.
//
// It builds three recorded maintainer decisions:
//
//   - #4a Membership carriage — every membership change (create, add_member, remove_member,
//     change_role, add_owner) is a first-class SIGNED object (a normal N-AALP envelope object,
//     §2), CURSOR-OCCUPYING (it takes a real ordered position — the cursor — in the per-room
//     log), RECEIPT-CHAINED (the room log IS the append-only signed audit/receipt chain of §8.1,
//     one Receipt per accepted op over the op's content id), and EPOCH-BUMPING (each accepted op
//     increments the room's membership epoch; an op built against a superseded epoch is rejected
//     StaleEpoch — this serialises concurrent membership changes so a stale view cannot win).
//   - #4b O2 ownership — multi-owner, ADD-ONLY: a room may have many owners; add_owner adds one;
//     an owner is NEVER removed (remove_member refuses an owner) nor demoted (change_role refuses
//     to lower an owner). Create seeds exactly one owner, add_owner only grows the set, so the
//     owner count is monotonically >= 1 — a room can never become ownerless.
//   - #3  Delivery Model B — PrincipalRegistry maps a stable semantic principal id to a durable
//     Handle (the current signer id), resolved to the Handle at send time. The binding survives
//     key rotation (a rebind is authorised only by a verified rotation from the current handle,
//     R-1.4), so the semantic id is a durable layer above the connection-scoped N-PAMP PeerHandle
//     while a hijack to an unrelated key is refused (RebindUnauthorized).
//
// Every check is fail-closed: an op that fails any check is rejected whole, returns its named
// error, and causes no state change.
package rooms

import (
	"bytes"
	"crypto/sha512"
	"sort"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/audit"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// Channel bindings (R-1.2) and the tier for this higher-tier surface.
const (
	ChannelGovernance uint64 = 0x0004 // membership ops (who is authorised in the room)
	ChannelIdentity   uint64 = 0x0003 // the principal registry (durable naming, R-1.4)
	Tier              uint64 = 1       // a named higher tier over the frozen baseline (tier 0)
)

// Op is a room membership operation code (naalp-room-op field 2).
type Op uint64

const (
	OpCreate       Op = 0
	OpAddMember    Op = 1
	OpRemoveMember Op = 2
	OpChangeRole   Op = 3
	OpAddOwner     Op = 4
)

// Role is a member's role in a room (naalp-room-op field 5). It is NOT an effect and NOT a
// capability ceiling; it is the collaboration role that gates membership operations.
type Role uint64

const (
	RoleMember Role = 0
	RoleAdmin  Role = 1
	RoleOwner  Role = 2
)

// Tier-1 kind codes. Governance (0x0004) carries the five membership ops; Identity (0x0003)
// carries the principal binding. They start at 16 to sit clear of the frozen baseline kinds.
const (
	KindRoomCreate       uint64 = 16
	KindRoomAddMember    uint64 = 17
	KindRoomRemoveMember uint64 = 18
	KindRoomChangeRole   uint64 = 19
	KindRoomAddOwner     uint64 = 20
	KindPrincipalBind    uint64 = 16 // on the Identity channel
)

// Errors reuse the cose.Error type so every N-AALP error carries a stable Kind.
var (
	ErrStaleEpoch         = &cose.Error{Kind: "StaleEpoch", Msg: "op epoch does not match the room's current membership epoch"}
	ErrUnauthorized       = &cose.Error{Kind: "Unauthorized", Msg: "actor is not an owner of the room"}
	ErrOwnerImmutable     = &cose.Error{Kind: "OwnerImmutable", Msg: "an owner cannot be removed or demoted (ownership is add-only)"}
	ErrMemberExists       = &cose.Error{Kind: "MemberExists", Msg: "subject is already a member"}
	ErrMemberUnknown      = &cose.Error{Kind: "MemberUnknown", Msg: "subject is not a member of the room"}
	ErrOwnerExists        = &cose.Error{Kind: "OwnerExists", Msg: "subject is already an owner"}
	ErrRoleInvalid        = &cose.Error{Kind: "RoleInvalid", Msg: "role is not valid for this operation"}
	ErrRoomOpMismatch     = &cose.Error{Kind: "RoomOpMismatch", Msg: "op room id, kind, or op code does not match this room/operation"}
	ErrOpUnknown          = &cose.Error{Kind: "OpUnknown", Msg: "unknown room op code"}
	ErrNonNFC             = &cose.Error{Kind: "NonNFC", Msg: "subject/principal string is not Unicode NFC"}
	ErrPrincipalUnknown   = &cose.Error{Kind: "PrincipalUnknown", Msg: "no binding for the semantic principal id"}
	ErrPrincipalExists    = &cose.Error{Kind: "PrincipalExists", Msg: "principal already bound; use Rebind"}
	ErrRebindUnauthorized = &cose.Error{Kind: "RebindUnauthorized", Msg: "a rebind requires a verified rotation from the current handle to the new handle"}
)

// ---- the membership op (the first-class signed object's body) -------------------------

// RoomOp is one membership operation body carried in envelope field 10. Its content id
// (multihash(0x20, SHA-384(body))) is what the room log orders (the cursor position), so the
// op is content-addressed and its ordering is tamper-evident.
type RoomOp struct {
	Room    []byte // room id (bstr)
	Op      Op     // 0 create | 1 add_member | 2 remove_member | 3 change_role | 4 add_owner
	Epoch   uint64 // the membership epoch this op is built against (bumps on accept)
	Subject string // the affected member's signer id (the creator, for create); MUST be NFC
	Role    Role   // 0 member | 1 admin | 2 owner
}

func (o RoomOp) toMap() cbor.Map {
	return cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(o.Room)},
		{K: cbor.Uint(2), V: cbor.Uint(uint64(o.Op))},
		{K: cbor.Uint(3), V: cbor.Uint(o.Epoch)},
		{K: cbor.Uint(4), V: cbor.Tstr(o.Subject)},
		{K: cbor.Uint(5), V: cbor.Uint(uint64(o.Role))},
	}
}

// Bytes is the deterministic-CBOR encoding of the op body {1:room,2:op,3:epoch,4:subject,5:role}.
func (o RoomOp) Bytes() []byte {
	b, _ := cbor.Encode(o.toMap())
	return b
}

// ContentID is the op's content id in the T1 framing (design §2.3): multihash(0x20,
// SHA-384(body)). The room log orders this id.
func (o RoomOp) ContentID() []byte {
	d := sha512.Sum384(o.Bytes())
	out := make([]byte, 0, 2+len(d))
	out = append(out, 0x20, 0x30) // multihash: sha2-384 code 0x20, length 48 = 0x30
	return append(out, d[:]...)
}

// KindForOp maps an op code to its tier-1 Governance kind and its declared effect
// (design-channels.md §21). remove_member is destructive; the rest are non_idempotent_write.
func KindForOp(op Op) (kind uint64, effect policy.Effect, ok bool) {
	switch op {
	case OpCreate:
		return KindRoomCreate, policy.NonIdempotentWrite, true
	case OpAddMember:
		return KindRoomAddMember, policy.NonIdempotentWrite, true
	case OpRemoveMember:
		return KindRoomRemoveMember, policy.Destructive, true
	case OpChangeRole:
		return KindRoomChangeRole, policy.NonIdempotentWrite, true
	case OpAddOwner:
		return KindRoomAddOwner, policy.NonIdempotentWrite, true
	default:
		return 0, 0, false
	}
}

// EnvelopeObject builds the (unsigned) N-AALP envelope object that carries this op: tier 1,
// Governance channel, the op's kind and declared effect, the op body as field 10. The caller
// signs it with envelope.Sign to produce the first-class signed membership object.
func (o RoomOp) EnvelopeObject(signer []byte, created, profile uint64, causes [][]byte) (*envelope.Object, error) {
	kind, eff, ok := KindForOp(o.Op)
	if !ok {
		return nil, ErrOpUnknown
	}
	if err := identity.RequireNFC(o.Subject); err != nil {
		return nil, ErrNonNFC
	}
	return &envelope.Object{
		Kind: kind, Channel: ChannelGovernance, Tier: Tier,
		Signer: signer, Created: created, Effect: uint64(eff),
		Causes: causes, Profile: profile, Body: o.toMap(),
	}, nil
}

// RoomOpFromBody parses an envelope object body (field 10) back into a RoomOp. A body that is
// not exactly the {1,2,3,4,5} map with the right value types is RoomOpMismatch (fail-closed).
func RoomOpFromBody(v cbor.Value) (RoomOp, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return RoomOp{}, ErrRoomOpMismatch
	}
	var o RoomOp
	var seen [6]bool
	for _, p := range m {
		k, ok := p.K.(cbor.Uint)
		if !ok || uint64(k) < 1 || uint64(k) > 5 {
			return RoomOp{}, ErrRoomOpMismatch
		}
		switch uint64(k) {
		case 1:
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return RoomOp{}, ErrRoomOpMismatch
			}
			o.Room = []byte(b)
		case 2:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return RoomOp{}, ErrRoomOpMismatch
			}
			o.Op = Op(u)
		case 3:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return RoomOp{}, ErrRoomOpMismatch
			}
			o.Epoch = uint64(u)
		case 4:
			s, ok := p.V.(cbor.Tstr)
			if !ok {
				return RoomOp{}, ErrRoomOpMismatch
			}
			o.Subject = string(s)
		case 5:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return RoomOp{}, ErrRoomOpMismatch
			}
			o.Role = Role(u)
		}
		seen[k] = true
	}
	if !(seen[1] && seen[2] && seen[3] && seen[4] && seen[5]) {
		return RoomOp{}, ErrRoomOpMismatch
	}
	return o, nil
}

// ---- kind validation (composes with the frozen baseline) ------------------------------

// KindValidator accepts exactly this surface's tier-1 kinds: the five Governance membership
// kinds and the Identity principal-bind kind. It accepts nothing else.
func KindValidator(channel, kind uint64) bool {
	switch channel {
	case ChannelGovernance:
		return kind >= KindRoomCreate && kind <= KindRoomAddOwner
	case ChannelIdentity:
		return kind == KindPrincipalBind
	default:
		return false
	}
}

// ComposedKindValidator accepts the frozen baseline kinds (channels.KindValidator) OR this
// surface's tier-1 kinds — the validator a rooms-aware endpoint passes to envelope.Verify. It
// leaves the frozen baseline registry untouched (R-11.1); a baseline-only endpoint that uses
// channels.KindValidator alone correctly rejects a room kind as UnknownKind.
func ComposedKindValidator(channel, kind uint64) bool {
	return channels.KindValidator(channel, kind) || KindValidator(channel, kind)
}

// ---- the room state machine (per-room membership + the receipt-chained log) ------------

// Room is a collaboration room's live membership state and its signed, append-only log. The
// log is an audit.Authority receipt chain (§8.1): each accepted op is ordered at a cursor
// (the receipt seq) over the op's content id, weaving membership into the tamper-evident chain.
type Room struct {
	id       []byte
	epoch    uint64
	members  map[string]Role
	owners   map[string]bool
	auth     *audit.Authority
	receipts []audit.Receipt
	sigs     [][]byte
}

// CreateRoom builds a room from a verified create op signed by the creator. The creator (the
// op subject) becomes the first and, at creation, only owner+member. The create op occupies
// cursor 0 in the log; the room advances to epoch 1. `auth` is the room's ordering authority.
// A non-create op, a non-zero epoch, an empty/non-NFC subject, or an actor that is not the
// subject is rejected fail-closed.
func CreateRoom(op RoomOp, actor string, auth *audit.Authority, at uint64) (*Room, audit.Receipt, uint64, error) {
	if op.Op != OpCreate {
		return nil, audit.Receipt{}, 0, ErrRoomOpMismatch
	}
	if op.Epoch != 0 {
		return nil, audit.Receipt{}, 0, ErrStaleEpoch
	}
	if op.Subject == "" {
		return nil, audit.Receipt{}, 0, ErrRoomOpMismatch
	}
	if err := identity.RequireNFC(op.Subject); err != nil {
		return nil, audit.Receipt{}, 0, ErrNonNFC
	}
	if actor != op.Subject { // the creator seeds itself as the first owner
		return nil, audit.Receipt{}, 0, ErrUnauthorized
	}
	r := &Room{
		id:      append([]byte(nil), op.Room...),
		members: map[string]Role{op.Subject: RoleOwner},
		owners:  map[string]bool{op.Subject: true},
		auth:    auth,
	}
	rec, sig, err := auth.Append(op.ContentID(), at)
	if err != nil {
		return nil, audit.Receipt{}, 0, err
	}
	r.receipts = append(r.receipts, rec)
	r.sigs = append(r.sigs, sig)
	r.epoch = 1
	return r, rec, rec.Seq, nil
}

// Apply validates and applies one membership op (add_member, remove_member, change_role,
// add_owner) by an owner `actor`, orders it into the room log, and bumps the epoch. Check
// order is fail-closed throughout: room match -> epoch -> subject well-formed -> authorization
// -> per-op semantics -> order -> mutate -> bump. Any failure returns a named error and leaves
// the room unchanged. It returns the log receipt and the cursor (the op's ordered position).
func (r *Room) Apply(op RoomOp, actor string, at uint64) (audit.Receipt, uint64, error) {
	if !bytes.Equal(op.Room, r.id) || op.Op == OpCreate {
		return audit.Receipt{}, 0, ErrRoomOpMismatch
	}
	if op.Epoch != r.epoch {
		return audit.Receipt{}, 0, ErrStaleEpoch // stale (or future) membership view; fail-closed
	}
	if op.Subject == "" {
		return audit.Receipt{}, 0, ErrRoomOpMismatch
	}
	if err := identity.RequireNFC(op.Subject); err != nil {
		return audit.Receipt{}, 0, ErrNonNFC
	}
	if !r.owners[actor] { // only an owner may change membership (R-6.5: actor is the authenticated signer)
		return audit.Receipt{}, 0, ErrUnauthorized
	}
	// Per-op semantic validation — NO mutation yet (so a rejection is a true no-op).
	switch op.Op {
	case OpAddMember:
		if op.Role != RoleMember && op.Role != RoleAdmin {
			return audit.Receipt{}, 0, ErrRoleInvalid // owners are added via add_owner only
		}
		if _, ok := r.members[op.Subject]; ok {
			return audit.Receipt{}, 0, ErrMemberExists
		}
	case OpAddOwner:
		if op.Role != RoleOwner {
			return audit.Receipt{}, 0, ErrRoleInvalid
		}
		if r.owners[op.Subject] {
			return audit.Receipt{}, 0, ErrOwnerExists
		}
	case OpRemoveMember:
		if _, ok := r.members[op.Subject]; !ok {
			return audit.Receipt{}, 0, ErrMemberUnknown
		}
		if r.owners[op.Subject] {
			return audit.Receipt{}, 0, ErrOwnerImmutable // add-only ownership: no ownerless room
		}
	case OpChangeRole:
		cur, ok := r.members[op.Subject]
		if !ok {
			return audit.Receipt{}, 0, ErrMemberUnknown
		}
		if op.Role != RoleMember && op.Role != RoleAdmin {
			return audit.Receipt{}, 0, ErrRoleInvalid // promote to owner via add_owner only
		}
		if cur == RoleOwner {
			return audit.Receipt{}, 0, ErrOwnerImmutable // an owner cannot be demoted
		}
	default:
		return audit.Receipt{}, 0, ErrOpUnknown
	}
	// Order the op into the log first; if ordering fails there is no state change.
	rec, sig, err := r.auth.Append(op.ContentID(), at)
	if err != nil {
		return audit.Receipt{}, 0, err
	}
	switch op.Op {
	case OpAddMember:
		r.members[op.Subject] = op.Role
	case OpAddOwner:
		r.members[op.Subject] = RoleOwner
		r.owners[op.Subject] = true
	case OpRemoveMember:
		delete(r.members, op.Subject)
	case OpChangeRole:
		r.members[op.Subject] = op.Role
	}
	r.receipts = append(r.receipts, rec)
	r.sigs = append(r.sigs, sig)
	r.epoch++
	return rec, rec.Seq, nil
}

// ApplySigned is the behavioural end-to-end path: it verifies a signed membership object with
// real crypto (envelope.Verify against v, the composed rooms validator), binds the claimed
// signer id to the verifying key (identity.CheckSigner — a self-asserted id that does not
// derive from the authenticated key confers no authority, R-1.3/R-5.1), confirms the object is
// a tier-1 Governance room op whose kind and effect match its op code, then applies it with the
// authenticated signer id as the actor.
func (r *Room) ApplySigned(profile int, v cose.Verifier, pubkey, signedObj []byte, at uint64) (audit.Receipt, uint64, error) {
	o, err := envelope.Verify(profile, v, ComposedKindValidator, nil, signedObj)
	if err != nil {
		return audit.Receipt{}, 0, err
	}
	if o.Channel != ChannelGovernance || o.Tier != Tier {
		return audit.Receipt{}, 0, ErrRoomOpMismatch
	}
	actor, err := identity.SignerID(v.Alg(), pubkey)
	if err != nil {
		return audit.Receipt{}, 0, err
	}
	if string(o.Signer) != actor { // the object's signer field must be the authenticated id
		return audit.Receipt{}, 0, identity.ErrSignerMismatch
	}
	op, err := RoomOpFromBody(o.Body)
	if err != nil {
		return audit.Receipt{}, 0, err
	}
	wantKind, wantEff, ok := KindForOp(op.Op)
	if !ok || o.Kind != wantKind || o.Effect != uint64(wantEff) {
		return audit.Receipt{}, 0, ErrRoomOpMismatch
	}
	return r.Apply(op, actor, at)
}

// ID returns the room id.
func (r *Room) ID() []byte { return append([]byte(nil), r.id...) }

// Epoch returns the room's current membership epoch (the epoch the next op must carry).
func (r *Room) Epoch() uint64 { return r.epoch }

// RoleOf returns a subject's role and whether it is a member.
func (r *Room) RoleOf(subject string) (Role, bool) {
	role, ok := r.members[subject]
	return role, ok
}

// IsOwner reports whether a subject is an owner of the room.
func (r *Room) IsOwner(subject string) bool { return r.owners[subject] }

// OwnerCount returns the number of owners. The add-only ownership invariant guarantees this is
// always >= 1 after CreateRoom (a room can never become ownerless).
func (r *Room) OwnerCount() int { return len(r.owners) }

// Owners returns the owner ids in sorted order.
func (r *Room) Owners() []string {
	out := make([]string, 0, len(r.owners))
	for o := range r.owners {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// Members returns the members and their roles (a copy).
func (r *Room) Members() map[string]Role {
	out := make(map[string]Role, len(r.members))
	for k, v := range r.members {
		out[k] = v
	}
	return out
}

// Log returns the room log's receipts and their signatures (its persistent state). The chain
// verifies offline with audit.VerifyChain against the ordering authority's key.
func (r *Room) Log() ([]audit.Receipt, [][]byte) { return r.receipts, r.sigs }

// ---- Delivery Model B: the principal registry (semantic id -> durable Handle, R-1.4) ---

// Binding is one principal-registry record: a semantic principal id bound to a durable Handle
// at a monotonic per-principal epoch, chained to the prior binding's head. Signed as an
// Identity-channel (0x0003) tier-1 object; here it is the wire body (byte-graded) and the
// registry below is the policy (behaviour-graded).
type Binding struct {
	Principal string // the stable semantic principal id (MUST be NFC)
	Handle    string // the current durable Handle (a signer id) this principal resolves to
	Epoch     uint64 // monotonic per-principal binding epoch (0 for the first bind)
	Prev      []byte // prior binding chain head (48 bytes; genesis = zero)
}

func (b Binding) toMap() cbor.Map {
	return cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr(b.Principal)},
		{K: cbor.Uint(2), V: cbor.Tstr(b.Handle)},
		{K: cbor.Uint(3), V: cbor.Uint(b.Epoch)},
		{K: cbor.Uint(4), V: cbor.Bstr(b.Prev)},
	}
}

// Bytes is the deterministic-CBOR encoding {1:principal,2:handle,3:epoch,4:prev}.
func (b Binding) Bytes() []byte {
	out, _ := cbor.Encode(b.toMap())
	return out
}

// Head is the per-principal chain head after this binding: SHA-384(binding body). Because the
// body carries the prior head, editing any binding breaks the next binding's linkage.
func (b Binding) Head() []byte {
	d := sha512.Sum384(b.Bytes())
	return d[:]
}

// GenesisHead is the empty per-principal chain head (48 zero bytes).
func GenesisHead() []byte { return make([]byte, audit.HeadSize) }

// PrincipalRegistry is the durable semantic-naming layer of Delivery Model B: it maps each
// semantic principal id to its current durable Handle, keeping a per-principal signed binding
// chain. A delivery addresses a semantic id and Resolve returns the Handle at send time.
type PrincipalRegistry struct {
	chain   map[string][]Binding
	head    map[string][]byte
	current map[string]string
	epoch   map[string]uint64
}

// NewPrincipalRegistry makes an empty registry.
func NewPrincipalRegistry() *PrincipalRegistry {
	return &PrincipalRegistry{
		chain:   map[string][]Binding{},
		head:    map[string][]byte{},
		current: map[string]string{},
		epoch:   map[string]uint64{},
	}
}

// Bind creates the FIRST binding for a principal (epoch 0, prev = genesis). A principal already
// bound is PrincipalExists (use Rebind); an empty or non-NFC principal/handle is rejected.
func (pr *PrincipalRegistry) Bind(principal, handle string) (Binding, error) {
	if principal == "" || handle == "" {
		return Binding{}, ErrRoomOpMismatch
	}
	if err := identity.RequireNFC(principal); err != nil {
		return Binding{}, ErrNonNFC
	}
	if err := identity.RequireNFC(handle); err != nil {
		return Binding{}, ErrNonNFC
	}
	if _, ok := pr.current[principal]; ok {
		return Binding{}, ErrPrincipalExists
	}
	b := Binding{Principal: principal, Handle: handle, Epoch: 0, Prev: GenesisHead()}
	pr.chain[principal] = []Binding{b}
	pr.head[principal] = b.Head()
	pr.current[principal] = handle
	pr.epoch[principal] = 0
	return b, nil
}

// Rebind updates a principal to a new durable Handle, REQUIRING a verified rotation from the
// current handle to the new handle (R-1.4): the semantic id survives key rotation, but a rebind
// to a key not proven continuous with the current handle is refused (RebindUnauthorized). The
// binding epoch bumps and the chain links to the prior head. `rot` is the co-signed rotation
// record and the two keys' verifiers/pubkeys/signatures (identity.VerifyRotation).
func (pr *PrincipalRegistry) Rebind(principal, newHandle string, rot identity.RotationRecord,
	oldV, newV cose.Verifier, oldPub, newPub, oldSig, newSig []byte) (Binding, error) {
	cur, ok := pr.current[principal]
	if !ok {
		return Binding{}, ErrPrincipalUnknown
	}
	if newHandle == "" {
		return Binding{}, ErrRoomOpMismatch
	}
	if err := identity.RequireNFC(newHandle); err != nil {
		return Binding{}, ErrNonNFC
	}
	// The rotation MUST carry the current handle as old and the new handle as new, and it MUST
	// be a valid co-signed rotation (both keys derive their ids and both signatures verify).
	if rot.Old != cur || rot.New != newHandle {
		return Binding{}, ErrRebindUnauthorized
	}
	if err := identity.VerifyRotation(rot, oldV, newV, oldPub, newPub, oldSig, newSig); err != nil {
		return Binding{}, ErrRebindUnauthorized
	}
	ep := pr.epoch[principal] + 1
	b := Binding{Principal: principal, Handle: newHandle, Epoch: ep, Prev: append([]byte(nil), pr.head[principal]...)}
	pr.chain[principal] = append(pr.chain[principal], b)
	pr.head[principal] = b.Head()
	pr.current[principal] = newHandle
	pr.epoch[principal] = ep
	return b, nil
}

// Resolve returns the current durable Handle for a semantic principal id (Delivery Model B): a
// delivery addresses the semantic id, and this resolves it to the Handle at send time. An
// unknown principal is PrincipalUnknown (fail-closed — never a silent empty handle).
func (pr *PrincipalRegistry) Resolve(principal string) (string, error) {
	h, ok := pr.current[principal]
	if !ok {
		return "", ErrPrincipalUnknown
	}
	return h, nil
}

// Chain returns a principal's ordered binding chain (its persistent state) for offline audit.
func (pr *PrincipalRegistry) Chain(principal string) ([]Binding, bool) {
	c, ok := pr.chain[principal]
	return c, ok
}
