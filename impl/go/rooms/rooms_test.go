// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package rooms_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/audit"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/rooms"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/rooms/cases.json"

type opJSON struct {
	Seq           uint64 `json:"seq"`
	Op            uint64 `json:"op"`
	OpName        string `json:"op_name"`
	EpochAtBuild  uint64 `json:"epoch_at_build"`
	Subject       string `json:"subject"`
	Role          uint64 `json:"role"`
	BodyHex       string `json:"body_hex"`
	OpContentID   string `json:"op_content_id_hex"`
	EpochAfter    uint64 `json:"epoch_after"`
}

type receiptJSON struct {
	Seq          uint64 `json:"seq"`
	PrevHex      string `json:"prev_hex"`
	ObjHex       string `json:"obj_hex"`
	At           uint64 `json:"at"`
	BodyHex      string `json:"body_hex"`
	HeadAfterHex string `json:"head_after_hex"`
}

type bindingJSON struct {
	Principal    string `json:"principal"`
	Handle       string `json:"handle"`
	Epoch        uint64 `json:"epoch"`
	PrevHex      string `json:"prev_hex"`
	BodyHex      string `json:"body_hex"`
	HeadAfterHex string `json:"head_after_hex"`
}

type roomsCases struct {
	Rooms struct {
		RoomIDHex       string        `json:"room_id_hex"`
		GenesisPrevHex  string        `json:"genesis_prev_hex"`
		Ops             []opJSON      `json:"ops"`
		RoomLog         []receiptJSON `json:"room_log"`
		FinalLogHeadHex string        `json:"final_log_head_hex"`
		FinalEpoch      uint64        `json:"final_epoch"`
		FinalOwners     []string      `json:"final_owners"`
		FinalMembers    []struct {
			Subject string `json:"subject"`
			Role    uint64 `json:"role"`
		} `json:"final_members"`
	} `json:"rooms"`
	Registry struct {
		Bindings []bindingJSON     `json:"bindings"`
		Resolve  map[string]string `json:"resolve"`
	} `json:"registry"`
}

func load(t *testing.T) roomsCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c roomsCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func key(t *testing.T, seed byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier, []byte, string) {
	t.Helper()
	var s [mldsa65.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	id, err := identity.SignerID(cose.AlgMLDSA65, pk.Bytes())
	if err != nil {
		t.Fatalf("signer id: %v", err)
	}
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}, pk.Bytes(), id
}

// TestOpBodiesMatchOracle: every membership op body and its content id are byte-identical to the
// independent oracle (⟹ Go == Rust). Mutation: if RoomOp.Bytes ignored a field, the hex diverges.
func TestOpBodiesMatchOracle(t *testing.T) {
	c := load(t)
	room := hx(t, c.Rooms.RoomIDHex)
	for _, oj := range c.Rooms.Ops {
		op := rooms.RoomOp{Room: room, Op: rooms.Op(oj.Op), Epoch: oj.EpochAtBuild, Subject: oj.Subject, Role: rooms.Role(oj.Role)}
		if got := hex.EncodeToString(op.Bytes()); got != oj.BodyHex {
			t.Errorf("op %d (%s) body\n got %s\nwant %s", oj.Seq, oj.OpName, got, oj.BodyHex)
		}
		if got := hex.EncodeToString(op.ContentID()); got != oj.OpContentID {
			t.Errorf("op %d (%s) content-id\n got %s\nwant %s", oj.Seq, oj.OpName, got, oj.OpContentID)
		}
	}
}

// TestRoomRunMatchesOracle drives a real Room through the oracle's op sequence and asserts the
// resulting receipt-chained log (bodies + heads), the cursor positions, the epoch progression,
// and the final membership/ownership state are all byte/value-identical to the oracle. This
// grades the wire bytes AND the state machine at once (⟹ Go == Rust on the bytes).
func TestRoomRunMatchesOracle(t *testing.T) {
	c := load(t)
	room := hx(t, c.Rooms.RoomIDHex)
	authSigner, authVerifier, _, _ := key(t, 90) // the room's ordering authority
	auth := audit.NewAuthority(authSigner)

	// op 0 is create; the creator "alice" seeds itself as the first owner.
	create := c.Rooms.Ops[0]
	cop := rooms.RoomOp{Room: room, Op: rooms.Op(create.Op), Epoch: create.EpochAtBuild, Subject: create.Subject, Role: rooms.Role(create.Role)}
	rm, rec0, cursor0, err := rooms.CreateRoom(cop, create.Subject, auth, c.Rooms.RoomLog[0].At)
	if err != nil {
		t.Fatalf("create room: %v", err)
	}
	if cursor0 != 0 || rm.Epoch() != 1 {
		t.Fatalf("after create: cursor %d epoch %d (want 0, 1)", cursor0, rm.Epoch())
	}
	checkReceipt(t, rec0, c.Rooms.RoomLog[0])

	// The remaining ops are applied by "alice" (the owner).
	for i := 1; i < len(c.Rooms.Ops); i++ {
		oj := c.Rooms.Ops[i]
		op := rooms.RoomOp{Room: room, Op: rooms.Op(oj.Op), Epoch: oj.EpochAtBuild, Subject: oj.Subject, Role: rooms.Role(oj.Role)}
		if oj.EpochAtBuild != rm.Epoch() {
			t.Fatalf("op %d built epoch %d but room epoch %d", i, oj.EpochAtBuild, rm.Epoch())
		}
		rec, cursor, err := rm.Apply(op, create.Subject, c.Rooms.RoomLog[i].At)
		if err != nil {
			t.Fatalf("apply op %d (%s): %v", i, oj.OpName, err)
		}
		if cursor != oj.Seq {
			t.Errorf("op %d cursor %d want %d", i, cursor, oj.Seq)
		}
		if rm.Epoch() != oj.EpochAfter {
			t.Errorf("op %d epoch after %d want %d", i, rm.Epoch(), oj.EpochAfter)
		}
		checkReceipt(t, rec, c.Rooms.RoomLog[i])
	}

	// Final state matches the oracle.
	if rm.Epoch() != c.Rooms.FinalEpoch {
		t.Errorf("final epoch %d want %d", rm.Epoch(), c.Rooms.FinalEpoch)
	}
	gotOwners := rm.Owners()
	if len(gotOwners) != len(c.Rooms.FinalOwners) {
		t.Fatalf("owners %v want %v", gotOwners, c.Rooms.FinalOwners)
	}
	for i := range gotOwners {
		if gotOwners[i] != c.Rooms.FinalOwners[i] {
			t.Errorf("owner[%d] = %s want %s", i, gotOwners[i], c.Rooms.FinalOwners[i])
		}
	}
	for _, m := range c.Rooms.FinalMembers {
		role, ok := rm.RoleOf(m.Subject)
		if !ok || uint64(role) != m.Role {
			t.Errorf("member %s role %v (ok=%v) want %d", m.Subject, role, ok, m.Role)
		}
	}
	// Members() must equal the FULL membership set — no missing AND no extra members. RoleOf
	// alone (above) can only prove no member is missing; it cannot catch an extra one leaking in.
	// Mutation: if Members() also returned a stale/removed subject or aliased the internal map, the
	// length check or a set-equality check below would flip.
	gotMembers := rm.Members()
	if len(gotMembers) != len(c.Rooms.FinalMembers) {
		t.Fatalf("Members() has %d entries, oracle final_members has %d", len(gotMembers), len(c.Rooms.FinalMembers))
	}
	for _, m := range c.Rooms.FinalMembers {
		role, ok := gotMembers[m.Subject]
		if !ok || uint64(role) != m.Role {
			t.Errorf("Members()[%s] = %v (ok=%v) want %d", m.Subject, role, ok, m.Role)
		}
	}
	// The whole log verifies offline against the authority key, and the final head matches.
	receipts, sigs := rm.Log()
	if err := audit.VerifyChain(receipts, sigs, authVerifier); err != nil {
		t.Fatalf("room log chain does not verify: %v", err)
	}
	if got := hex.EncodeToString(receipts[len(receipts)-1].Head()); got != c.Rooms.FinalLogHeadHex {
		t.Errorf("final log head\n got %s\nwant %s", got, c.Rooms.FinalLogHeadHex)
	}
}

func checkReceipt(t *testing.T, rec audit.Receipt, want receiptJSON) {
	t.Helper()
	if got := hex.EncodeToString(rec.Bytes()); got != want.BodyHex {
		t.Errorf("log[%d] receipt body\n got %s\nwant %s", want.Seq, got, want.BodyHex)
	}
	if got := hex.EncodeToString(rec.Head()); got != want.HeadAfterHex {
		t.Errorf("log[%d] receipt head\n got %s\nwant %s", want.Seq, got, want.HeadAfterHex)
	}
	if got := hex.EncodeToString(rec.Obj); got != want.ObjHex {
		t.Errorf("log[%d] receipt obj\n got %s\nwant %s", want.Seq, got, want.ObjHex)
	}
}

// TestSignedMembershipEndToEnd: a membership op is a first-class SIGNED object — it verifies
// through the spine (tier-1 Governance, real ML-DSA), the authenticated signer is the actor,
// and the op is ordered into the room log. Uses REAL signer ids as subjects/actors.
func TestSignedMembershipEndToEnd(t *testing.T) {
	room := []byte{0x20, 0x30, 1, 2, 3, 4}
	ownerS, ownerV, ownerPub, ownerID := key(t, 50)
	_, _, _, bobID := key(t, 51)
	authSigner, _, _, _ := key(t, 91)
	auth := audit.NewAuthority(authSigner)

	// Signed create by the owner.
	createOp := rooms.RoomOp{Room: room, Op: rooms.OpCreate, Epoch: 0, Subject: ownerID, Role: rooms.RoleOwner}
	rm, _, _, err := rooms.CreateRoom(createOp, ownerID, auth, 1000)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Signed add_member(bob) by the owner, applied end-to-end with real crypto.
	addOp := rooms.RoomOp{Room: room, Op: rooms.OpAddMember, Epoch: rm.Epoch(), Subject: bobID, Role: rooms.RoleMember}
	obj, err := addOp.EnvelopeObject([]byte(ownerID), 1001, uint64(cose.ProfilePublic), nil)
	if err != nil {
		t.Fatalf("build object: %v", err)
	}
	signed, err := envelope.Sign(obj, ownerS)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, _, err := rm.ApplySigned(cose.ProfilePublic, ownerV, ownerPub, signed, 1001); err != nil {
		t.Fatalf("apply signed: %v", err)
	}
	if role, ok := rm.RoleOf(bobID); !ok || role != rooms.RoleMember {
		t.Fatalf("bob not added as member: role=%v ok=%v", role, ok)
	}
	// A baseline-only verifier (no tier licensed) rejects the room kind as UnknownKind.
	if _, err := envelope.Verify(cose.ProfilePublic, ownerV, channels.KindValidator, nil, signed); err == nil {
		t.Fatal("baseline verifier accepted a tier-1 room kind")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "UnknownKind" {
		t.Fatalf("want UnknownKind from baseline verifier, got %v", err)
	}
}

// TestStaleEpochRejected: EPOCH-BUMPING — two ops built against the same epoch cannot both
// apply; once the first is accepted (epoch bumps) the second is StaleEpoch. Mutation: if Apply
// ignored the epoch, the replay would succeed and this test would fail.
func TestStaleEpochRejected(t *testing.T) {
	room := []byte{9, 9, 9}
	_, _, _, ownerID := key(t, 52)
	_, _, _, bobID := key(t, 53)
	_, _, _, carolID := key(t, 54)
	auth := audit.NewAuthority(mustAuth(t, 92))
	rm, _, _, err := rooms.CreateRoom(rooms.RoomOp{Room: room, Op: rooms.OpCreate, Epoch: 0, Subject: ownerID, Role: rooms.RoleOwner}, ownerID, auth, 1)
	if err != nil {
		t.Fatal(err)
	}
	e := rm.Epoch() // both ops are built against this epoch
	if _, _, err := rm.Apply(rooms.RoomOp{Room: room, Op: rooms.OpAddMember, Epoch: e, Subject: bobID, Role: rooms.RoleMember}, ownerID, 2); err != nil {
		t.Fatalf("first add: %v", err)
	}
	_, _, err = rm.Apply(rooms.RoomOp{Room: room, Op: rooms.OpAddMember, Epoch: e, Subject: carolID, Role: rooms.RoleMember}, ownerID, 3)
	if err == nil {
		t.Fatal("stale-epoch op accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "StaleEpoch" {
		t.Fatalf("want StaleEpoch, got %v", err)
	}
	// carol was NOT added (no state change on the rejected op).
	if _, ok := rm.RoleOf(carolID); ok {
		t.Fatal("state changed on a rejected stale-epoch op")
	}
	// The same op rebuilt against the CURRENT epoch is accepted.
	if _, _, err := rm.Apply(rooms.RoomOp{Room: room, Op: rooms.OpAddMember, Epoch: rm.Epoch(), Subject: carolID, Role: rooms.RoleMember}, ownerID, 4); err != nil {
		t.Fatalf("current-epoch add rejected: %v", err)
	}
}

// TestUnauthorizedActorRejected: only an owner may change membership; a non-owner is refused
// (fail-closed) and no state changes. Mutation: if Apply skipped the owner check, this fails.
func TestUnauthorizedActorRejected(t *testing.T) {
	room := []byte{7, 7}
	_, _, _, ownerID := key(t, 55)
	_, _, _, bobID := key(t, 56)
	_, _, _, malloryID := key(t, 57)
	auth := audit.NewAuthority(mustAuth(t, 93))
	rm, _, _, _ := rooms.CreateRoom(rooms.RoomOp{Room: room, Op: rooms.OpCreate, Epoch: 0, Subject: ownerID, Role: rooms.RoleOwner}, ownerID, auth, 1)
	// bob is a plain member.
	if _, _, err := rm.Apply(rooms.RoomOp{Room: room, Op: rooms.OpAddMember, Epoch: rm.Epoch(), Subject: bobID, Role: rooms.RoleMember}, ownerID, 2); err != nil {
		t.Fatal(err)
	}
	// mallory (not even a member) tries to add themselves as owner.
	_, _, err := rm.Apply(rooms.RoomOp{Room: room, Op: rooms.OpAddOwner, Epoch: rm.Epoch(), Subject: malloryID, Role: rooms.RoleOwner}, malloryID, 3)
	if err == nil {
		t.Fatal("unauthorized actor accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "Unauthorized" {
		t.Fatalf("want Unauthorized, got %v", err)
	}
	// bob (a member but not an owner) also cannot add a member.
	if _, _, err := rm.Apply(rooms.RoomOp{Room: room, Op: rooms.OpAddMember, Epoch: rm.Epoch(), Subject: malloryID, Role: rooms.RoleMember}, bobID, 4); err == nil {
		t.Fatal("non-owner member accepted a membership change")
	}
	if rm.OwnerCount() != 1 {
		t.Fatalf("owner count changed to %d on rejected ops", rm.OwnerCount())
	}
}

// TestAddOnlyOwnershipNoOwnerless: O2 ownership is add-only. add_owner grows the owner set; an
// owner can be neither removed nor demoted; the owner count is monotonically >= 1, so the room
// can never become ownerless. Mutation: if remove/demote of an owner were allowed, this fails.
func TestAddOnlyOwnershipNoOwnerless(t *testing.T) {
	room := []byte{5}
	_, _, _, aliceID := key(t, 58)
	_, _, _, bobID := key(t, 59)
	auth := audit.NewAuthority(mustAuth(t, 94))
	rm, _, _, _ := rooms.CreateRoom(rooms.RoomOp{Room: room, Op: rooms.OpCreate, Epoch: 0, Subject: aliceID, Role: rooms.RoleOwner}, aliceID, auth, 1)
	if rm.OwnerCount() != 1 {
		t.Fatalf("fresh room owner count %d want 1", rm.OwnerCount())
	}
	// add_owner(bob): the owner set grows.
	if _, _, err := rm.Apply(rooms.RoomOp{Room: room, Op: rooms.OpAddOwner, Epoch: rm.Epoch(), Subject: bobID, Role: rooms.RoleOwner}, aliceID, 2); err != nil {
		t.Fatalf("add_owner: %v", err)
	}
	if rm.OwnerCount() != 2 || !rm.IsOwner(bobID) {
		t.Fatalf("after add_owner: count %d bobOwner %v", rm.OwnerCount(), rm.IsOwner(bobID))
	}
	// remove_member(alice) — an owner — is refused.
	if _, _, err := rm.Apply(rooms.RoomOp{Room: room, Op: rooms.OpRemoveMember, Epoch: rm.Epoch(), Subject: aliceID}, bobID, 3); err == nil {
		t.Fatal("removed an owner")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "OwnerImmutable" {
		t.Fatalf("want OwnerImmutable on remove, got %v", err)
	}
	// change_role(alice -> member) — demoting an owner — is refused.
	if _, _, err := rm.Apply(rooms.RoomOp{Room: room, Op: rooms.OpChangeRole, Epoch: rm.Epoch(), Subject: aliceID, Role: rooms.RoleMember}, bobID, 4); err == nil {
		t.Fatal("demoted an owner")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "OwnerImmutable" {
		t.Fatalf("want OwnerImmutable on demote, got %v", err)
	}
	// re-add of an existing owner is refused.
	if _, _, err := rm.Apply(rooms.RoomOp{Room: room, Op: rooms.OpAddOwner, Epoch: rm.Epoch(), Subject: bobID, Role: rooms.RoleOwner}, aliceID, 5); err == nil {
		t.Fatal("re-added an existing owner")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "OwnerExists" {
		t.Fatalf("want OwnerExists, got %v", err)
	}
	if rm.OwnerCount() < 1 {
		t.Fatal("owner count fell below 1")
	}
}

// TestBindingBytesMatchOracle: principal-binding wire bodies and per-principal chain heads are
// byte-identical to the oracle (⟹ Go == Rust).
func TestBindingBytesMatchOracle(t *testing.T) {
	c := load(t)
	for _, bj := range c.Registry.Bindings {
		b := rooms.Binding{Principal: bj.Principal, Handle: bj.Handle, Epoch: bj.Epoch, Prev: hx(t, bj.PrevHex)}
		if got := hex.EncodeToString(b.Bytes()); got != bj.BodyHex {
			t.Errorf("binding %s@%d body\n got %s\nwant %s", bj.Principal, bj.Epoch, got, bj.BodyHex)
		}
		if got := hex.EncodeToString(b.Head()); got != bj.HeadAfterHex {
			t.Errorf("binding %s@%d head\n got %s\nwant %s", bj.Principal, bj.Epoch, got, bj.HeadAfterHex)
		}
	}
}

// TestPrincipalRegistryRebindOnRotation: Delivery Model B — a semantic id resolves to a durable
// Handle; a rebind is authorised ONLY by a verified rotation from the current handle (R-1.4), so
// the semantic id survives rotation but a hijack to an unrelated key is refused. Mutation: if
// Rebind skipped the rotation check, the hijack would succeed and this fails.
func TestPrincipalRegistryRebindOnRotation(t *testing.T) {
	// alice's durable identity: key v1 rotates to key v2.
	v1S, v1V, v1Pub, v1ID := key(t, 60)
	v2S, v2V, v2Pub, v2ID := key(t, 61)
	_, _, _, evilID := key(t, 62)

	pr := rooms.NewPrincipalRegistry()
	if _, err := pr.Bind("agent:alice", v1ID); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if h, _ := pr.Resolve("agent:alice"); h != v1ID {
		t.Fatalf("resolve v1 = %s want %s", h, v1ID)
	}
	// A valid co-signed rotation v1 -> v2 authorises the rebind.
	rot := identity.RotationRecord{Old: v1ID, New: v2ID, NotBefore: 100}
	oldSig, newSig, err := identity.SignRotation(rot, v1S, v2S)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pr.Rebind("agent:alice", v2ID, rot, v1V, v2V, v1Pub, v2Pub, oldSig, newSig); err != nil {
		t.Fatalf("authorised rebind rejected: %v", err)
	}
	if h, _ := pr.Resolve("agent:alice"); h != v2ID {
		t.Fatalf("after rebind resolve = %s want %s (durable Handle should follow rotation)", h, v2ID)
	}
	// A hijack: rebind to an unrelated key with a rotation that does not name it is refused.
	badRot := identity.RotationRecord{Old: v2ID, New: evilID, NotBefore: 200}
	// Sign the bad rotation with the WRONG old key (v1, not the current v2) — not a valid
	// rotation from the current handle.
	bo, bn, _ := identity.SignRotation(badRot, v1S, v2S)
	if _, err := pr.Rebind("agent:alice", evilID, badRot, v1V, v2V, v1Pub, v2Pub, bo, bn); err == nil {
		t.Fatal("hijack rebind accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "RebindUnauthorized" {
		t.Fatalf("want RebindUnauthorized, got %v", err)
	}
	// The registry is unchanged after the refused hijack.
	if h, _ := pr.Resolve("agent:alice"); h != v2ID {
		t.Fatalf("hijack changed the binding to %s", h)
	}
	// An unknown principal resolves fail-closed.
	if _, err := pr.Resolve("agent:nobody"); err == nil {
		t.Fatal("unknown principal resolved")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "PrincipalUnknown" {
		t.Fatalf("want PrincipalUnknown, got %v", err)
	}
}

func mustAuth(t *testing.T, seed byte) cose.MLDSA65Signer {
	t.Helper()
	s, _, _, _ := key(t, seed)
	return s
}
