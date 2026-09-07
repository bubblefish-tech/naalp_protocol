// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// Collaboration / rooms membership (feature #64) for the C# SDK — a tier-1 ADDITIVE surface over
    /// the frozen draft-00 spine (design.md §2..§10; design-channels.md §21), ported from
    /// impl/go/rooms and cross-checked against impl/python/naalp/rooms.py. Graded against the shared
    /// independent corpus <c>vectors/rooms/cases.json</c> (NOT produced by this code):
    ///
    /// <para>BYTE surface (⟹ csharp == Go == Rust == oracle): every membership op body + content id;
    /// the whole receipt-chained room log (bodies + heads); the principal-binding wire bodies + chain
    /// heads. STATE MACHINE (behaviour, real ML-DSA-65): the create/apply epoch progression + cursor
    /// positions + final membership/ownership; epoch-bumping (StaleEpoch); owner authorization
    /// (Unauthorized); add-only ownership (OwnerImmutable/OwnerExists); the signed end-to-end path
    /// (tier-1 Governance object verified through the C3 envelope, with the baseline verifier rejecting
    /// the room kind UnknownKind); and Delivery-Model-B rebind-on-rotation (RebindUnauthorized), which
    /// composes on the ADDITIVE C4 identity-rotation primitive in <see cref="Identity"/>.</para>
    ///
    /// <para>Honest scope (F4), mirroring the Go/Python/Java/Kotlin ports: the corpus descriptive
    /// fields <c>stale_rebind_case</c> / <c>owner_immutable_case</c> are NOT read as byte vectors by
    /// any port's reference test — StaleEpoch / OwnerImmutable / rebind are covered by runtime
    /// state-machine scenarios, and Rebind's authorization failure is RebindUnauthorized (not
    /// StaleEpoch). This port mirrors that scoping and invents no property the reference lacks.</para>
    /// </summary>
    public sealed class RoomsTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "rooms", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/rooms/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        // A real ML-DSA-65 identity: the 32-byte seed, the raw public key, and the self-certifying id.
        private static (byte[] Seed, byte[] Pub, string Id) Key(byte seed)
        {
            byte[] s = new byte[32];
            for (int i = 0; i < 32; i++) s[i] = seed;
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", s);
            string id = Identity.SignerId(Alg, pk);
            return (s, pk, id);
        }

        // The baseline-only kind validator (no tier licensed): the frozen C10 registry alone.
        private static bool BaselineKindValidator(long channel, long kind)
        {
            try { Channels.Lookup(channel, kind); return true; }
            catch (NaalpException) { return false; }
        }

        private static Rooms.RoomOp OpOf(JsonElement o, byte[] room)
        {
            return new Rooms.RoomOp(
                room,
                o.GetProperty("op").GetInt64(),
                o.GetProperty("epoch_at_build").GetInt64(),
                o.GetProperty("subject").GetString()!,
                o.GetProperty("role").GetInt64());
        }

        // ---- byte surface: op bodies + content ids -------------------------------------------------
        // MUTATION ANCHOR family: if RoomOp.Bytes() dropped/retagged a field the hex diverges.

        [Fact]
        public void RoomOpBodiesMatchOracle()
        {
            JsonElement v = Vector();
            JsonElement rooms = v.GetProperty("rooms");
            byte[] room = Hb(rooms.GetProperty("room_id_hex").GetString()!);
            foreach (JsonElement o in rooms.GetProperty("ops").EnumerateArray())
            {
                Rooms.RoomOp op = OpOf(o, room);
                Assert.Equal(o.GetProperty("body_hex").GetString(), Hex(op.Bytes()));
                Assert.Equal(o.GetProperty("op_content_id_hex").GetString(), Hex(op.ContentId()));
            }
        }

        // ---- the whole room run: receipt-chained log + state machine, graded vs the oracle ---------

        [Fact]
        public void RoomRunMatchesOracle()
        {
            JsonElement v = Vector();
            JsonElement rooms = v.GetProperty("rooms");
            byte[] room = Hb(rooms.GetProperty("room_id_hex").GetString()!);
            JsonElement ops = rooms.GetProperty("ops");
            JsonElement log = rooms.GetProperty("room_log");

            (byte[] authSeed, byte[] authPub, _) = Key(90); // the room's ordering authority
            var auth = new Audit.Authority(Alg, authSeed);

            JsonElement create = ops[0];
            string creator = create.GetProperty("subject").GetString()!;
            (Rooms.Room rm, Audit.Receipt rec0, long cursor0) =
                Rooms.CreateRoom(OpOf(create, room), creator, auth, log[0].GetProperty("at").GetInt64());
            Assert.Equal(0, cursor0);
            Assert.Equal(1, rm.Epoch());
            CheckReceipt(rec0, log[0]);

            int n = ops.GetArrayLength();
            for (int i = 1; i < n; i++)
            {
                JsonElement oj = ops[i];
                Assert.Equal(oj.GetProperty("epoch_at_build").GetInt64(), rm.Epoch());
                (Audit.Receipt rec, long cursor) = rm.Apply(OpOf(oj, room), creator, log[i].GetProperty("at").GetInt64());
                Assert.Equal(oj.GetProperty("seq").GetInt64(), cursor);
                Assert.Equal(oj.GetProperty("epoch_after").GetInt64(), rm.Epoch());
                CheckReceipt(rec, log[i]);
            }

            // Final state matches the oracle.
            Assert.Equal(rooms.GetProperty("final_epoch").GetInt64(), rm.Epoch());
            var wantOwners = new List<string>();
            foreach (JsonElement ow in rooms.GetProperty("final_owners").EnumerateArray()) wantOwners.Add(ow.GetString()!);
            Assert.Equal(wantOwners, rm.Owners());
            foreach (JsonElement m in rooms.GetProperty("final_members").EnumerateArray())
            {
                (long role, bool ok) = rm.RoleOf(m.GetProperty("subject").GetString()!);
                Assert.True(ok);
                Assert.Equal(m.GetProperty("role").GetInt64(), role);
            }

            // The whole log verifies offline against the authority key, and the final head matches.
            (IReadOnlyList<Audit.Receipt> receipts, IReadOnlyList<byte[]> sigs) = rm.Log();
            Audit.VerifyChain(receipts, sigs, Alg, authPub);
            Assert.Equal(rooms.GetProperty("final_log_head_hex").GetString(), Hex(receipts[receipts.Count - 1].Head()));
        }

        private static void CheckReceipt(Audit.Receipt rec, JsonElement want)
        {
            Assert.Equal(want.GetProperty("body_hex").GetString(), Hex(rec.Bytes()));
            Assert.Equal(want.GetProperty("head_after_hex").GetString(), Hex(rec.Head()));
            Assert.Equal(want.GetProperty("obj_hex").GetString(), Hex(rec.Obj));
        }

        // ---- the signed end-to-end path (REAL ML-DSA) + baseline rejection -------------------------

        [Fact]
        public void SignedMembershipEndToEnd()
        {
            byte[] room = { 0x20, 0x30, 1, 2, 3, 4 };
            (byte[] ownerSeed, byte[] ownerPub, string ownerID) = Key(50);
            (_, _, string bobID) = Key(51);
            (byte[] authSeed, _, _) = Key(91);
            var auth = new Audit.Authority(Alg, authSeed);

            (Rooms.Room rm, _, _) = Rooms.CreateRoom(
                new Rooms.RoomOp(room, Rooms.OpCreate, 0, ownerID, Rooms.RoleOwner), ownerID, auth, 1000);

            // A signed add_member(bob) by the owner, applied end-to-end with real crypto.
            var addOp = new Rooms.RoomOp(room, Rooms.OpAddMember, rm.Epoch(), bobID, Rooms.RoleMember);
            Envelope.Object obj = addOp.EnvelopeObject(Encoding.UTF8.GetBytes(ownerID), 1001, Cose.PROFILE_PUBLIC, null);
            byte[] signed = Envelope.Sign(obj, Alg, ownerSeed);
            rm.ApplySigned(Cose.PROFILE_PUBLIC, Alg, ownerPub, signed, 1001);
            (long role, bool ok) = rm.RoleOf(bobID);
            Assert.True(ok);
            Assert.Equal(Rooms.RoleMember, role);

            // A baseline-only verifier (no tier licensed) rejects the room kind as UnknownKind.
            var ex = Assert.Throws<NaalpException>(() =>
                Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, ownerPub, BaselineKindValidator, signed));
            Assert.Equal("UnknownKind", ex.Kind);
        }

        // ---- epoch-bumping: a stale-epoch op is refused (fail-closed, no state change) -------------
        // MUTATION ANCHOR: dropping the epoch guard in Room.Apply lets the stale replay through, so
        // Assert.Throws below (Kind == StaleEpoch) no longer throws and this [Fact] fails on it.

        [Fact]
        public void StaleEpochRejected()
        {
            byte[] room = { 9, 9, 9 };
            (byte[] authSeed, _, _) = Key(92);
            (_, _, string ownerID) = Key(52);
            (_, _, string bobID) = Key(53);
            (_, _, string carolID) = Key(54);
            var auth = new Audit.Authority(Alg, authSeed);
            (Rooms.Room rm, _, _) = Rooms.CreateRoom(
                new Rooms.RoomOp(room, Rooms.OpCreate, 0, ownerID, Rooms.RoleOwner), ownerID, auth, 1);

            long e = rm.Epoch(); // both ops are built against this epoch
            rm.Apply(new Rooms.RoomOp(room, Rooms.OpAddMember, e, bobID, Rooms.RoleMember), ownerID, 2);

            var ex = Assert.Throws<NaalpException>(() =>
                rm.Apply(new Rooms.RoomOp(room, Rooms.OpAddMember, e, carolID, Rooms.RoleMember), ownerID, 3));
            Assert.Equal("StaleEpoch", ex.Kind);

            // carol was NOT added (no state change on the rejected op).
            (_, bool ok) = rm.RoleOf(carolID);
            Assert.False(ok);

            // The same op rebuilt against the CURRENT epoch is accepted.
            rm.Apply(new Rooms.RoomOp(room, Rooms.OpAddMember, rm.Epoch(), carolID, Rooms.RoleMember), ownerID, 4);
            (_, bool ok2) = rm.RoleOf(carolID);
            Assert.True(ok2);
        }

        // ---- authorization: only an owner may change membership ------------------------------------

        [Fact]
        public void UnauthorizedActorRejected()
        {
            byte[] room = { 7, 7 };
            (byte[] authSeed, _, _) = Key(93);
            (_, _, string ownerID) = Key(55);
            (_, _, string bobID) = Key(56);
            (_, _, string malloryID) = Key(57);
            var auth = new Audit.Authority(Alg, authSeed);
            (Rooms.Room rm, _, _) = Rooms.CreateRoom(
                new Rooms.RoomOp(room, Rooms.OpCreate, 0, ownerID, Rooms.RoleOwner), ownerID, auth, 1);

            // bob is a plain member.
            rm.Apply(new Rooms.RoomOp(room, Rooms.OpAddMember, rm.Epoch(), bobID, Rooms.RoleMember), ownerID, 2);

            // mallory (not even a member) tries to add themselves as owner.
            var ex = Assert.Throws<NaalpException>(() =>
                rm.Apply(new Rooms.RoomOp(room, Rooms.OpAddOwner, rm.Epoch(), malloryID, Rooms.RoleOwner), malloryID, 3));
            Assert.Equal("Unauthorized", ex.Kind);

            // bob (a member but not an owner) also cannot add a member.
            Assert.Throws<NaalpException>(() =>
                rm.Apply(new Rooms.RoomOp(room, Rooms.OpAddMember, rm.Epoch(), malloryID, Rooms.RoleMember), bobID, 4));

            Assert.Equal(1, rm.OwnerCount());
        }

        // ---- O2 add-only ownership: no room can ever become ownerless ------------------------------

        [Fact]
        public void AddOnlyOwnershipNoOwnerless()
        {
            byte[] room = { 5 };
            (byte[] authSeed, _, _) = Key(94);
            (_, _, string aliceID) = Key(58);
            (_, _, string bobID) = Key(59);
            var auth = new Audit.Authority(Alg, authSeed);
            (Rooms.Room rm, _, _) = Rooms.CreateRoom(
                new Rooms.RoomOp(room, Rooms.OpCreate, 0, aliceID, Rooms.RoleOwner), aliceID, auth, 1);
            Assert.Equal(1, rm.OwnerCount());

            // add_owner(bob): the owner set grows.
            rm.Apply(new Rooms.RoomOp(room, Rooms.OpAddOwner, rm.Epoch(), bobID, Rooms.RoleOwner), aliceID, 2);
            Assert.Equal(2, rm.OwnerCount());
            Assert.True(rm.IsOwner(bobID));

            // remove_member(alice) — an owner — is refused.
            var exRem = Assert.Throws<NaalpException>(() =>
                rm.Apply(new Rooms.RoomOp(room, Rooms.OpRemoveMember, rm.Epoch(), aliceID, Rooms.RoleMember), bobID, 3));
            Assert.Equal("OwnerImmutable", exRem.Kind);

            // change_role(alice -> member) — demoting an owner — is refused.
            var exDem = Assert.Throws<NaalpException>(() =>
                rm.Apply(new Rooms.RoomOp(room, Rooms.OpChangeRole, rm.Epoch(), aliceID, Rooms.RoleMember), bobID, 4));
            Assert.Equal("OwnerImmutable", exDem.Kind);

            // re-add of an existing owner is refused.
            var exExists = Assert.Throws<NaalpException>(() =>
                rm.Apply(new Rooms.RoomOp(room, Rooms.OpAddOwner, rm.Epoch(), bobID, Rooms.RoleOwner), aliceID, 5));
            Assert.Equal("OwnerExists", exExists.Kind);

            Assert.True(rm.OwnerCount() >= 1);
        }

        // ---- byte surface: principal-binding bodies + per-principal chain heads ---------------------

        [Fact]
        public void BindingBytesMatchOracle()
        {
            JsonElement v = Vector();
            foreach (JsonElement bj in v.GetProperty("registry").GetProperty("bindings").EnumerateArray())
            {
                var b = new Rooms.Binding(
                    bj.GetProperty("principal").GetString()!,
                    bj.GetProperty("handle").GetString()!,
                    bj.GetProperty("epoch").GetInt64(),
                    Hb(bj.GetProperty("prev_hex").GetString()!));
                Assert.Equal(bj.GetProperty("body_hex").GetString(), Hex(b.Bytes()));
                Assert.Equal(bj.GetProperty("head_after_hex").GetString(), Hex(b.Head()));
            }
        }

        // ---- Delivery Model B: a semantic id survives rotation; a hijack is refused ----------------
        // Composes on the ADDITIVE C4 identity-rotation primitive (Identity.RotationRecord/SignRotation/
        // VerifyRotation). MUTATION-adjacent: if Rebind skipped the rotation check, the hijack succeeds.

        [Fact]
        public void PrincipalRegistryRebindOnRotation()
        {
            (byte[] v1Seed, byte[] v1Pub, string v1ID) = Key(60);
            (byte[] v2Seed, byte[] v2Pub, string v2ID) = Key(61);
            (_, _, string evilID) = Key(62);

            var pr = new Rooms.PrincipalRegistry();
            pr.Bind("agent:alice", v1ID);
            Assert.Equal(v1ID, pr.Resolve("agent:alice"));

            // A valid co-signed rotation v1 -> v2 authorises the rebind.
            var rot = new Identity.RotationRecord(v1ID, v2ID, 100);
            (byte[] oldSig, byte[] newSig) = Identity.SignRotation(rot, Alg, v1Seed, v2Seed);
            pr.Rebind("agent:alice", v2ID, rot, Alg, v1Pub, Alg, v2Pub, oldSig, newSig);
            Assert.Equal(v2ID, pr.Resolve("agent:alice")); // the durable Handle followed the rotation

            // A hijack: rebind to an unrelated key with a rotation whose old key (v1) does not derive
            // the record's old id (v2) — not a valid rotation from the current handle.
            var badRot = new Identity.RotationRecord(v2ID, evilID, 200);
            (byte[] bo, byte[] bn) = Identity.SignRotation(badRot, Alg, v1Seed, v2Seed);
            var ex = Assert.Throws<NaalpException>(() =>
                pr.Rebind("agent:alice", evilID, badRot, Alg, v1Pub, Alg, v2Pub, bo, bn));
            Assert.Equal("RebindUnauthorized", ex.Kind);

            // The registry is unchanged after the refused hijack.
            Assert.Equal(v2ID, pr.Resolve("agent:alice"));

            // An unknown principal resolves fail-closed.
            var exUnknown = Assert.Throws<NaalpException>(() => pr.Resolve("agent:nobody"));
            Assert.Equal("PrincipalUnknown", exUnknown.Kind);
        }
    }
}
