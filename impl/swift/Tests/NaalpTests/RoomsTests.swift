// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Collaboration / rooms membership (feature #64) higher-tier conformance for the Swift SDK — a
// Phase-3 ADDITIVE tier-1 surface over the frozen draft-00 spine (design.md §2..§10;
// design-channels.md §21). It introduces NO new envelope, encoding, signature, identity, or audit
// mechanism (R-11.3, R-15A.2): the per-room log IS the C7 audit receipt chain (§8.1) and a
// rotation-authorised rebind reuses the C4 identity rotation primitive. Graded against the shared
// independent corpus vectors/rooms/cases.json (values from the corpus, NEVER produced by this code).
//
// CORPUS-GRADED (pure, signature-independent): (1) every membership-op body + content id; (2) the
// full room run — receipt-chained log bodies/heads/objs, the cursor positions, the epoch progression,
// and the final membership/ownership state — matched byte/value-for-byte to the oracle (⟹ Go == Rust
// == Python); (3) the principal-binding wire bodies + per-principal chain heads; and (4) the
// state-machine verdicts (StaleEpoch epoch-bump serialisation, Unauthorized, add-only
// OwnerImmutable/OwnerExists, MemberExists/MemberUnknown/RoleInvalid).
//
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the room-log ordering authority signs each
// receipt with a real Ed25519 (RFC 8032) key (the pure-tier stand-in for the reference's ML-DSA
// authority) and the whole log verifies offline; the rotation that authorises a rebind is a real
// co-signed Ed25519 rotation (Identity.signRotation / Identity.verifyRotation). Swift is PURE-ONLY for
// ML-DSA (SwiftDilithium 3.6.0 has no deterministic-from-seed FIPS 204 path).
//
// SIGNED MEMBERSHIP OBJECT (honest F2/F4): the #4a first-class signed object composes on the spine
// Envelope.verify. PHP's applySigned reaches green because PHP's Envelope structurally accepts an
// ML-DSA-65 object; Swift's Envelope SKIP-TRACKS the ML-DSA signature (throws Unavailable, never a
// false green), so the positive envelope-verified apply cannot COMPLETE in the pure tier for an
// ML-DSA object. The post-verification authorization + apply logic (signer binding R-1.3/R-5.1,
// kind/effect match, owner-only apply) is exercised DIRECTLY via applyVerifiedObject with concrete
// input → correct output; the composition over the frozen baseline (R-11.1: composed validator admits
// the room kind and reaches the ML-DSA signature = Unavailable, while a baseline-only validator
// rejects the room kind = UnknownKind) is demonstrated on the real Envelope.verify. The ML-DSA
// signature bytes are the one un-exercised leg and are NOT fabricated (mirroring the PHP + Delegation
// ports).
//
// Written test-first: Naalp.Rooms / RoomOp / Room / PrincipalRegistry and Identity.RotationRecord are
// absent until Rooms.swift + the Identity additions land, so this fails RED with a compile error
// ("cannot find 'Rooms' in scope"). The load-bearing mutation: dropping the epoch-bump guard in
// Room.apply (so a stale-epoch op is not rejected) flips "stale-epoch op rejected (StaleEpoch)".
//
// Run:  swift test --filter RoomsTests

import XCTest
@testable import Naalp

final class RoomsTests: XCTestCase {

    static func hexToBytes(_ s: String) -> [UInt8] {
        var out = [UInt8](); out.reserveCapacity(s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    static func toHex(_ b: [UInt8]) -> String {
        let d = Array("0123456789abcdef")
        var s = ""
        for x in b { s.append(d[Int(x >> 4)]); s.append(d[Int(x & 0x0f)]) }
        return s
    }

    /// Cross-platform numeric read: corelibs-foundation deserializes JSON numbers as NSNumber.
    static func u64(_ v: Any?) throws -> UInt64 {
        return try XCTUnwrap(v as? NSNumber, "expected a JSON number").uint64Value
    }

    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/rooms/cases.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    static func loadVector() throws -> [String: Any] {
        guard let v = findVector() else {
            throw XCTSkip("vectors/rooms/cases.json not present (standalone build)")
        }
        return v
    }

    /// A deterministic 32-byte Ed25519 seed for a scenario label, derived through Naalp's public
    /// SHA-384 content-id (Cbor.contentId = [0x20,0x30] || SHA-384(label)); the first 32 octets of the
    /// SHA-384 digest are the seed. Distinct labels give distinct seeds; any 32 octets is a valid
    /// Ed25519 seed. Uses only Naalp's public API (no direct Crypto import), mirroring the sibling tests.
    static func seed(_ label: String) -> [UInt8] {
        return Array(Cbor.contentId(Array("naalp-rooms-key:\(label)".utf8)).dropFirst(2).prefix(32))
    }

    /// A deterministic Ed25519 keypair for a scenario label: (seed, raw pubkey, self-certifying signer
    /// id §5.1). The pure-tier stand-in for a durable identity.
    static func edKey(_ label: String) throws -> (seed: [UInt8], pk: [UInt8], id: String) {
        let s = seed(label)
        let pk = try Cose.ed25519PublicKey(s)
        let id = try Identity.signerId(Cose.ALG_ED25519, pk)
        return (s, pk, id)
    }

    static func edVerify(_ pk: [UInt8]) -> Audit.Verify {
        return { m, s in Cose.ed25519Verify(pk, m, s) }
    }

    static func rooms(_ c: [String: Any]) throws -> [String: Any] {
        return try XCTUnwrap(c["rooms"] as? [String: Any])
    }

    // 1. every membership-op body and its content id are byte-identical to the independent oracle
    //    (⟹ Go == Rust == Python). A field-ignoring / constant encoder diverges here.
    func testOpBodiesAndContentIdsMatchOracle() throws {
        let c = try Self.loadVector()
        let r = try Self.rooms(c)
        let roomId = Self.hexToBytes(try XCTUnwrap(r["room_id_hex"] as? String))
        let ops = try XCTUnwrap(r["ops"] as? [[String: Any]])
        XCTAssertFalse(ops.isEmpty, "corpus has ops")
        for oj in ops {
            let op = Rooms.RoomOp(room: roomId, op: try Self.u64(oj["op"]),
                                  epoch: try Self.u64(oj["epoch_at_build"]),
                                  subject: try XCTUnwrap(oj["subject"] as? String),
                                  role: try Self.u64(oj["role"]))
            XCTAssertEqual(Self.toHex(try op.bytes()), oj["body_hex"] as? String, "op body == oracle")
            XCTAssertEqual(Self.toHex(try op.contentId()), oj["op_content_id_hex"] as? String, "op content-id == oracle")
        }
    }

    // 2. drive a REAL Room through the oracle's op sequence; the resulting receipt-chained log (bodies +
    //    heads + objs), the cursor positions, the epoch progression, and the final membership/ownership
    //    are all byte/value-identical to the oracle. Grades the wire bytes AND the state machine at once.
    //    The room log is the C7 receipt chain; the ordering authority signs with a real Ed25519 key
    //    (pure-tier stand-in) and the whole log verifies offline against that key.
    func testRoomRunMatchesOracle() throws {
        let c = try Self.loadVector()
        let r = try Self.rooms(c)
        let roomId = Self.hexToBytes(try XCTUnwrap(r["room_id_hex"] as? String))
        let ops = try XCTUnwrap(r["ops"] as? [[String: Any]])
        let log = try XCTUnwrap(r["room_log"] as? [[String: Any]])

        let (authSeed, authPk, _) = try Self.edKey("room-authority")
        let auth = Audit.Authority(seed: authSeed)

        let create = ops[0]
        let creator = try XCTUnwrap(create["subject"] as? String)
        let cop = Rooms.RoomOp(room: roomId, op: try Self.u64(create["op"]),
                               epoch: try Self.u64(create["epoch_at_build"]),
                               subject: creator, role: try Self.u64(create["role"]))
        let (room, rec0, cursor0) = try Rooms.createRoom(cop, creator, auth, try Self.u64(log[0]["at"]))
        XCTAssertEqual(cursor0, 0, "create cursor == 0")
        XCTAssertEqual(room.epoch(), 1, "epoch after create == 1")
        try Self.checkReceipt(rec0, log[0])

        for i in 1..<ops.count {
            let oj = ops[i]
            XCTAssertEqual(try Self.u64(oj["epoch_at_build"]), room.epoch(), "op \(i) built epoch == room epoch")
            let op = Rooms.RoomOp(room: roomId, op: try Self.u64(oj["op"]),
                                  epoch: try Self.u64(oj["epoch_at_build"]),
                                  subject: try XCTUnwrap(oj["subject"] as? String), role: try Self.u64(oj["role"]))
            let (rec, cursor) = try room.apply(op, creator, try Self.u64(log[i]["at"]))
            XCTAssertEqual(cursor, try Self.u64(oj["seq"]), "op \(i) cursor == seq")
            XCTAssertEqual(room.epoch(), try Self.u64(oj["epoch_after"]), "op \(i) epoch_after == oracle")
            try Self.checkReceipt(rec, log[i])
        }

        XCTAssertEqual(room.epoch(), try Self.u64(r["final_epoch"]), "final epoch == oracle")
        XCTAssertEqual(room.owners(), try XCTUnwrap(r["final_owners"] as? [String]), "final owners == oracle")
        for m in try XCTUnwrap(r["final_members"] as? [[String: Any]]) {
            let subject = try XCTUnwrap(m["subject"] as? String)
            let (role, ok) = room.roleOf(subject)
            XCTAssertTrue(ok, "final member \(subject) present")
            XCTAssertEqual(role, try Self.u64(m["role"]), "final member \(subject) role == oracle")
        }

        let (receipts, sigs) = room.log()
        XCTAssertNoThrow(try Audit.verifyChain(receipts, sigs, Self.edVerify(authPk)), "room log verifies offline (Ed25519 authority)")
        XCTAssertEqual(Self.toHex(try receipts.last!.head()), r["final_log_head_hex"] as? String, "final log head == oracle")
    }

    static func checkReceipt(_ rec: Audit.Receipt, _ want: [String: Any]) throws {
        XCTAssertEqual(toHex(try rec.bytes()), want["body_hex"] as? String, "receipt body == oracle")
        XCTAssertEqual(toHex(try rec.head()), want["head_after_hex"] as? String, "receipt head == oracle")
        XCTAssertEqual(toHex(rec.obj), want["obj_hex"] as? String, "receipt obj == op content id")
    }

    // 3. EPOCH-BUMPING (#4a serialisation core) and THE LOAD-BEARING MUTATION TARGET: two ops built
    //    against the SAME epoch cannot both apply — once the first is accepted (epoch bumps) the second
    //    is StaleEpoch, fail-closed, with no state change; the same op rebuilt against the CURRENT epoch
    //    is accepted. Dropping the epoch guard in Room.apply flips "stale-epoch op rejected (StaleEpoch)".
    func testStaleEpochSerialisation() throws {
        let owner = try Self.edKey("epoch-owner").id
        let bob = try Self.edKey("epoch-bob").id
        let carol = try Self.edKey("epoch-carol").id
        let auth = Audit.Authority(seed: try Self.edKey("epoch-auth").seed)
        let rid: [UInt8] = [0x09, 0x09, 0x09]
        let (room, _, _) = try Rooms.createRoom(Rooms.RoomOp(room: rid, op: Rooms.OP_CREATE, epoch: 0, subject: owner, role: Rooms.ROLE_OWNER), owner, auth, 1)
        let e = room.epoch() // both ops are built against this epoch

        XCTAssertNoThrow(try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_ADD_MEMBER, epoch: e, subject: bob, role: Rooms.ROLE_MEMBER), owner, 2),
                         "first add at current epoch accepted")
        XCTAssertThrowsError(try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_ADD_MEMBER, epoch: e, subject: carol, role: Rooms.ROLE_MEMBER), owner, 3),
                             "stale-epoch op rejected (StaleEpoch)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "StaleEpoch", "stale op is StaleEpoch")
        }
        XCTAssertFalse(room.roleOf(carol).1, "state unchanged on the rejected stale op")
        XCTAssertNoThrow(try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_ADD_MEMBER, epoch: room.epoch(), subject: carol, role: Rooms.ROLE_MEMBER), owner, 4),
                         "same op at CURRENT epoch accepted")
    }

    // 4. only an owner may change membership; a non-owner actor is refused Unauthorized (fail-closed) and
    //    no state changes.
    func testOwnerAuthorization() throws {
        let owner = try Self.edKey("auth-owner").id
        let member = try Self.edKey("auth-member").id
        let mallory = try Self.edKey("auth-mallory").id
        let auth = Audit.Authority(seed: try Self.edKey("auth-auth").seed)
        let rid: [UInt8] = [0x07, 0x07]
        let (room, _, _) = try Rooms.createRoom(Rooms.RoomOp(room: rid, op: Rooms.OP_CREATE, epoch: 0, subject: owner, role: Rooms.ROLE_OWNER), owner, auth, 1)
        _ = try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_ADD_MEMBER, epoch: room.epoch(), subject: member, role: Rooms.ROLE_MEMBER), owner, 2)

        XCTAssertThrowsError(try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_ADD_OWNER, epoch: room.epoch(), subject: mallory, role: Rooms.ROLE_OWNER), mallory, 3),
                             "unauthorized actor refused (Unauthorized)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "Unauthorized")
        }
        XCTAssertThrowsError(try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_ADD_MEMBER, epoch: room.epoch(), subject: mallory, role: Rooms.ROLE_MEMBER), member, 4),
                             "non-owner member cannot change membership (Unauthorized)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "Unauthorized")
        }
        XCTAssertEqual(room.ownerCount(), 1, "owner count unchanged after refused ops")
    }

    // 5. O2 add-only ownership — add_owner grows the owner set; an owner can be neither removed nor
    //    demoted; a re-add is refused; the owner count is monotonically >= 1 (never ownerless).
    func testAddOnlyOwnership() throws {
        let alice = try Self.edKey("own-alice").id
        let bob = try Self.edKey("own-bob").id
        let auth = Audit.Authority(seed: try Self.edKey("own-auth").seed)
        let rid: [UInt8] = [0x05]
        let (room, _, _) = try Rooms.createRoom(Rooms.RoomOp(room: rid, op: Rooms.OP_CREATE, epoch: 0, subject: alice, role: Rooms.ROLE_OWNER), alice, auth, 1)
        XCTAssertEqual(room.ownerCount(), 1, "fresh room owner count == 1")
        _ = try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_ADD_OWNER, epoch: room.epoch(), subject: bob, role: Rooms.ROLE_OWNER), alice, 2)
        XCTAssertTrue(room.ownerCount() == 2 && room.isOwner(bob), "add_owner grows the owner set")
        XCTAssertThrowsError(try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_REMOVE_MEMBER, epoch: room.epoch(), subject: alice, role: Rooms.ROLE_MEMBER), bob, 3),
                             "remove of an owner refused (OwnerImmutable)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "OwnerImmutable")
        }
        XCTAssertThrowsError(try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_CHANGE_ROLE, epoch: room.epoch(), subject: alice, role: Rooms.ROLE_MEMBER), bob, 4),
                             "demote of an owner refused (OwnerImmutable)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "OwnerImmutable")
        }
        XCTAssertThrowsError(try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_ADD_OWNER, epoch: room.epoch(), subject: bob, role: Rooms.ROLE_OWNER), alice, 5),
                             "re-add of an existing owner refused (OwnerExists)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "OwnerExists")
        }
        XCTAssertGreaterThanOrEqual(room.ownerCount(), 1, "owner count still >= 1")
    }

    // 6. per-op semantic guards: a duplicate member (MemberExists), remove/change a non-member
    //    (MemberUnknown), add_member with the owner role (RoleInvalid).
    func testPerOpSemanticGuards() throws {
        let alice = try Self.edKey("guard-alice").id
        let bob = try Self.edKey("guard-bob").id
        let carol = try Self.edKey("guard-carol").id
        let auth = Audit.Authority(seed: try Self.edKey("guard-auth").seed)
        let rid: [UInt8] = [0x03]
        let (room, _, _) = try Rooms.createRoom(Rooms.RoomOp(room: rid, op: Rooms.OP_CREATE, epoch: 0, subject: alice, role: Rooms.ROLE_OWNER), alice, auth, 1)
        _ = try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_ADD_MEMBER, epoch: room.epoch(), subject: bob, role: Rooms.ROLE_MEMBER), alice, 2)
        XCTAssertThrowsError(try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_ADD_MEMBER, epoch: room.epoch(), subject: bob, role: Rooms.ROLE_MEMBER), alice, 3),
                             "duplicate add_member refused (MemberExists)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "MemberExists")
        }
        XCTAssertThrowsError(try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_REMOVE_MEMBER, epoch: room.epoch(), subject: carol, role: Rooms.ROLE_MEMBER), alice, 4),
                             "remove of a non-member refused (MemberUnknown)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "MemberUnknown")
        }
        XCTAssertThrowsError(try room.apply(Rooms.RoomOp(room: rid, op: Rooms.OP_ADD_MEMBER, epoch: room.epoch(), subject: carol, role: Rooms.ROLE_OWNER), alice, 5),
                             "add_member with owner role refused (RoleInvalid)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "RoleInvalid")
        }
    }

    // 7. a create op must be built against epoch 0, by the seeded owner, with an NFC subject.
    func testCreateGuards() throws {
        let auth = Audit.Authority(seed: try Self.edKey("create-auth").seed)
        let rid: [UInt8] = [0x01]
        XCTAssertThrowsError(try Rooms.createRoom(Rooms.RoomOp(room: rid, op: Rooms.OP_CREATE, epoch: 1, subject: "alice", role: Rooms.ROLE_OWNER), "alice", auth, 1),
                             "non-zero-epoch create refused (StaleEpoch)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "StaleEpoch")
        }
        XCTAssertThrowsError(try Rooms.createRoom(Rooms.RoomOp(room: rid, op: Rooms.OP_CREATE, epoch: 0, subject: "alice", role: Rooms.ROLE_OWNER), "mallory", auth, 1),
                             "create by a non-subject actor refused (Unauthorized)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "Unauthorized")
        }
        let nonNfc = "e\u{0301}" // "é" as e + combining acute (NFD, not NFC)
        XCTAssertThrowsError(try Rooms.createRoom(Rooms.RoomOp(room: rid, op: Rooms.OP_CREATE, epoch: 0, subject: nonNfc, role: Rooms.ROLE_OWNER), nonNfc, auth, 1),
                             "non-NFC create subject refused (NonNFC)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NonNFC")
        }
    }

    // 8. Delivery Model B — principal-binding wire bodies and per-principal chain heads are
    //    byte-identical to the oracle (⟹ Go == Rust == Python).
    func testBindingBodiesMatchOracle() throws {
        let c = try Self.loadVector()
        let reg = try XCTUnwrap(c["registry"] as? [String: Any])
        let bindings = try XCTUnwrap(reg["bindings"] as? [[String: Any]])
        XCTAssertFalse(bindings.isEmpty, "corpus has bindings")
        for bj in bindings {
            let b = Rooms.Binding(principal: try XCTUnwrap(bj["principal"] as? String),
                                  handle: try XCTUnwrap(bj["handle"] as? String),
                                  epoch: try Self.u64(bj["epoch"]),
                                  prev: Self.hexToBytes(try XCTUnwrap(bj["prev_hex"] as? String)))
            XCTAssertEqual(Self.toHex(try b.bytes()), bj["body_hex"] as? String, "binding body == oracle")
            XCTAssertEqual(Self.toHex(try b.head()), bj["head_after_hex"] as? String, "binding head == oracle")
        }
    }

    // 9. Delivery Model B behaviour — a semantic id resolves to a durable Handle; a rebind is authorised
    //    ONLY by a verified co-signed rotation from the CURRENT handle (R-1.4), so the semantic id
    //    survives rotation but a hijack to an unrelated key is refused RebindUnauthorized. The rotation
    //    is a real co-signed Ed25519 rotation (the C4 primitive added to Identity.swift). NOTE: rebind's
    //    authorization failure is RebindUnauthorized/RotationUnauthorized, NEVER StaleEpoch (the corpus
    //    stale_rebind_case descriptive field is not read as a byte vector here).
    func testDeliveryModelBRebind() throws {
        let v1 = try Self.edKey("dm-b-v1")
        let v2 = try Self.edKey("dm-b-v2")
        let ev = try Self.edKey("dm-b-evil")
        let pr = Rooms.PrincipalRegistry()
        _ = try pr.bind("agent:alice", v1.id)
        XCTAssertEqual(try pr.resolve("agent:alice"), v1.id, "resolve v1 handle")
        XCTAssertThrowsError(try pr.bind("agent:alice", v2.id), "re-bind of an existing principal refused (PrincipalExists)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "PrincipalExists")
        }
        // A valid co-signed rotation v1 -> v2 authorises the rebind.
        let rot = Identity.RotationRecord(old: v1.id, new: v2.id, notBefore: 100)
        let (oldSig, newSig) = try Identity.signRotation(rot, v1.seed, v2.seed)
        XCTAssertNoThrow(try pr.rebind("agent:alice", v2.id, rot, Cose.ALG_ED25519, v1.pk, Cose.ALG_ED25519, v2.pk, oldSig, newSig),
                         "authorised rebind on rotation accepted")
        XCTAssertEqual(try pr.resolve("agent:alice"), v2.id, "resolve follows rotation to v2")

        // A hijack: rebind to an unrelated key with a rotation NOT co-signed by the current (v2) key.
        let badRot = Identity.RotationRecord(old: v2.id, new: ev.id, notBefore: 200)
        let evNewSig = try Identity.signRotation(badRot, ev.seed, ev.seed).1 // "old" leg signed by evil, not v2
        let evOldSig = try Cose.ed25519Sign(ev.seed, try badRot.bytes())
        XCTAssertThrowsError(try pr.rebind("agent:alice", ev.id, badRot, Cose.ALG_ED25519, v2.pk, Cose.ALG_ED25519, ev.pk, evOldSig, evNewSig),
                             "hijack rebind refused (RebindUnauthorized)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "RebindUnauthorized")
        }
        XCTAssertEqual(try pr.resolve("agent:alice"), v2.id, "registry unchanged after refused hijack")
        XCTAssertThrowsError(try pr.resolve("agent:nobody"), "unknown principal resolves fail-closed (PrincipalUnknown)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "PrincipalUnknown")
        }
        // A rotation that names the wrong new handle is also refused.
        let mislabel = Identity.RotationRecord(old: v2.id, new: ev.id, notBefore: 300)
        let (mOld, mNew) = try Identity.signRotation(mislabel, v2.seed, ev.seed)
        XCTAssertThrowsError(try pr.rebind("agent:alice", "agent:someone-else", mislabel, Cose.ALG_ED25519, v2.pk, Cose.ALG_ED25519, ev.pk, mOld, mNew),
                             "rebind whose rotation names a different new handle refused (RebindUnauthorized)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "RebindUnauthorized")
        }
    }

    // 10. the rotation primitive itself (Identity.verifyRotation), Ed25519-demonstrated in isolation: a
    //     correct co-signed rotation verifies; a tampered old-leg signature is RotationUnauthorized; an
    //     old pubkey that does not derive the record's old id is RotationUnauthorized.
    func testRotationPrimitiveEd25519Demo() throws {
        let v1 = try Self.edKey("rot-v1")
        let v2 = try Self.edKey("rot-v2")
        let ev = try Self.edKey("rot-evil")
        let rot = Identity.RotationRecord(old: v1.id, new: v2.id, notBefore: 100)
        let (ro, rn) = try Identity.signRotation(rot, v1.seed, v2.seed)
        XCTAssertNoThrow(try Identity.verifyRotation(rot, Cose.ALG_ED25519, v1.pk, Cose.ALG_ED25519, v2.pk, ro, rn),
                         "valid co-signed rotation verifies")
        var tamper = ro; tamper[0] ^= 0x01
        XCTAssertThrowsError(try Identity.verifyRotation(rot, Cose.ALG_ED25519, v1.pk, Cose.ALG_ED25519, v2.pk, tamper, rn),
                             "tampered rotation signature refused (RotationUnauthorized)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "RotationUnauthorized")
        }
        XCTAssertThrowsError(try Identity.verifyRotation(rot, Cose.ALG_ED25519, ev.pk, Cose.ALG_ED25519, v2.pk, ro, rn),
                             "wrong old key refused (RotationUnauthorized)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "RotationUnauthorized")
        }
    }

    // 11. #4a a membership op is a FIRST-CLASS SIGNED object. PURE-ONLY Swift: Envelope.verify
    //     skip-tracks the ML-DSA signature (Unavailable), so the FULL applySigned cannot complete for an
    //     ML-DSA object; the post-verification authorization+apply logic is exercised DIRECTLY via
    //     applyVerifiedObject (concrete input → correct output). The composition over the frozen baseline
    //     (R-11.1) is demonstrated on the real Envelope.verify: the composed validator admits the room
    //     kind and reaches the ML-DSA signature (Unavailable), while a baseline-only validator rejects it
    //     (UnknownKind). Honest F2/F4: the ML-DSA signature bytes are the one un-exercised leg.
    func testSignedMembershipObjectComposition() throws {
        let ownerPub = [UInt8](repeating: 0xA1, count: 48) // ML-DSA-65 pubkey stand-in
        let bobPub = [UInt8](repeating: 0xB2, count: 48)
        let ownerMId = try Identity.signerId(Cose.ALG_MLDSA65, ownerPub)
        let bobMId = try Identity.signerId(Cose.ALG_MLDSA65, bobPub)
        let auth = Audit.Authority(seed: try Self.edKey("e2e-auth").seed)
        let sroom: [UInt8] = [0x20, 0x30, 0x01, 0x02, 0x03, 0x04]

        let (room, _, _) = try Rooms.createRoom(Rooms.RoomOp(room: sroom, op: Rooms.OP_CREATE, epoch: 0, subject: ownerMId, role: Rooms.ROLE_OWNER), ownerMId, auth, 1000)
        let addOp = Rooms.RoomOp(room: sroom, op: Rooms.OP_ADD_MEMBER, epoch: room.epoch(), subject: bobMId, role: Rooms.ROLE_MEMBER)

        // (a) the post-verification authorization+apply logic, exercised DIRECTLY (concrete → correct).
        let obj = try addOp.envelopeObject(Array(ownerMId.utf8), 1001, UInt64(Cose.PROFILE_PUBLIC), [])
        let (_, cursor) = try room.applyVerifiedObject(obj, Cose.ALG_MLDSA65, ownerPub, 1001)
        XCTAssertEqual(cursor, 1, "signed membership op ordered at cursor 1")
        XCTAssertTrue(room.roleOf(bobMId).1, "bob added as member via the verified-object path")
        XCTAssertEqual(room.roleOf(bobMId).0, Rooms.ROLE_MEMBER, "bob's role is member")

        // (b) a self-asserted signer that does not derive from the verifying key confers no authority.
        let (room2, _, _) = try Rooms.createRoom(Rooms.RoomOp(room: sroom, op: Rooms.OP_CREATE, epoch: 0, subject: ownerMId, role: Rooms.ROLE_OWNER), ownerMId, Audit.Authority(seed: try Self.edKey("e2e-auth2").seed), 1000)
        let forged = try Rooms.RoomOp(room: sroom, op: Rooms.OP_ADD_MEMBER, epoch: room2.epoch(), subject: bobMId, role: Rooms.ROLE_MEMBER).envelopeObject(Array(bobMId.utf8), 1001, UInt64(Cose.PROFILE_PUBLIC), [])
        XCTAssertThrowsError(try room2.applyVerifiedObject(forged, Cose.ALG_MLDSA65, ownerPub, 1001),
                             "self-asserted signer refused (SignerMismatch)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "SignerMismatch")
        }

        // (c) a kind/effect that does not match the op code is refused (RoomOpMismatch).
        var mismatchedKind = try addOp.envelopeObject(Array(ownerMId.utf8), 1001, UInt64(Cose.PROFILE_PUBLIC), [])
        mismatchedKind.kind = Rooms.KIND_ROOM_CREATE // 16 instead of add_member's 17
        XCTAssertThrowsError(try room2.applyVerifiedObject(mismatchedKind, Cose.ALG_MLDSA65, ownerPub, 1001),
                             "kind/effect mismatch refused (RoomOpMismatch)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "RoomOpMismatch")
        }

        // (d) an object on a non-Governance channel / wrong tier is refused (RoomOpMismatch).
        var wrongChannel = try addOp.envelopeObject(Array(ownerMId.utf8), 1001, UInt64(Cose.PROFILE_PUBLIC), [])
        wrongChannel.channel = 0x0005
        XCTAssertThrowsError(try room2.applyVerifiedObject(wrongChannel, Cose.ALG_MLDSA65, ownerPub, 1001),
                             "wrong-channel object refused (RoomOpMismatch)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "RoomOpMismatch")
        }

        // (e) the FULL applySigned path over a real (structurally assembled) ML-DSA-65 object: Swift's
        //     Envelope.verify skip-tracks the ML-DSA signature, so it surfaces Unavailable (the one
        //     un-exercised leg) — never a false green.
        var toSign = try addOp.envelopeObject(Array(ownerMId.utf8), 1001, UInt64(Cose.PROFILE_PUBLIC), [])
        let signed = try Envelope.assembleSigned(&toSign, Cose.ALG_MLDSA65, [UInt8](repeating: 0, count: 64))
        XCTAssertThrowsError(try room2.applySigned(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, ownerPub, signed, 1001),
                             "applySigned surfaces the un-exercised ML-DSA leg (Unavailable)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "Unavailable")
        }

        // (f) composition over the frozen baseline (R-11.1): the composed validator admits the room kind
        //     (reaching the ML-DSA signature = Unavailable), while a baseline-only validator rejects the
        //     tier-1 room kind (UnknownKind, reached BEFORE the signature). The DIFFERENCE is the
        //     composition — mutation-sensitive on composedKindValidator.
        XCTAssertThrowsError(try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, ownerPub, Rooms.composedKindValidator, signed),
                             "composed validator admits the room kind (reaches the ML-DSA signature)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "Unavailable")
        }
        let baseline: KindValidator = { ch, k in (try? Channels.lookup(Int(ch), Int(k))) != nil }
        XCTAssertThrowsError(try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, ownerPub, baseline, signed),
                             "baseline verifier rejects the tier-1 room kind (UnknownKind)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "UnknownKind")
        }
    }
}
