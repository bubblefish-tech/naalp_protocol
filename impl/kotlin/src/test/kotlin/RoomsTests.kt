// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

//
// Rooms membership conformance (feature #64) for the Kotlin SDK, graded against the shared independent
// corpus vectors/rooms/cases.json (NOT produced by this code): the membership op body/content-id byte
// parity, the receipt-chained room log (bodies + heads via the C7 audit authority) with the epoch
// progression and the final membership/ownership state, the principal-binding wire bodies +
// per-principal chain heads, and the fail-closed behavioural surface (StaleEpoch, Unauthorized,
// OwnerImmutable, add-only ownership, RebindUnauthorized) exercised with REAL ML-DSA-65 signed objects
// and a REAL co-signed key rotation.
//
// CORPUS-GRADED (pure bytes / values): every op body + content id, every room-log receipt body + head,
// the final log head + epoch + members + owners, and every principal binding body + head - reproduced
// byte-for-byte or value-for-value from the corpus. SECURITY/BEHAVIOUR DEMONSTRATED IN ISOLATION with
// real crypto (the corpus carries no signature vector): the signed membership object verifies
// end-to-end through the spine (real ML-DSA-65 + signer-id binding) while a baseline verifier rejects
// the tier-1 kind UnknownKind; the rebind is a REAL co-signed identity rotation. Honest F4 scoping: the
// corpus stale_rebind_case / owner_immutable_case fields are descriptive, NOT read as byte vectors by
// any port's reference test; StaleEpoch / OwnerImmutable / rebind are exercised as runtime state-machine
// scenarios (all exercised + passing), and Rebind's authorization failure is RebindUnauthorized (never
// StaleEpoch) - mirroring the Go/Python/Java reference, not inventing a property the reference lacks.
//
// KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the "Tests"
// token the ten-language-parity gate indexes. Written test-first: [Rooms] is absent until Rooms.kt
// lands, so this fails RED with a kotlinc "unresolved reference: Rooms". The recorded mutation disables
// the stale-epoch comparison in Rooms.Room.apply, which flips the named
// "second op against a stale epoch rejected StaleEpoch" check on its assertion.
//

private var roFails = 0

private fun roCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        roFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- nesting-aware JSON access (Kotlin has no JSON library) ----

private fun roFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/rooms/cases.json not found")
        val p = File(File(cur, "vectors"), "rooms/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/rooms/cases.json not found from ${File(".").absolutePath}")
}

private fun roMatchClose(s: String, open: Int): Int {
    val oc = s[open]
    val cc = if (oc == '{') '}' else ']'
    var depth = 0
    var inStr = false
    var i = open
    while (i < s.length) {
        val ch = s[i]
        if (inStr) {
            when (ch) {
                '\\' -> i++
                '"' -> inStr = false
            }
        } else {
            when (ch) {
                '"' -> inStr = true
                oc -> depth++
                cc -> { depth--; if (depth == 0) return i + 1 }
            }
        }
        i++
    }
    throw AssertionError("unbalanced from $open")
}

private fun roAfterKey(s: String, key: String): Int {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:").find(s)
        ?: throw AssertionError("key not found: $key")
    return m.range.last + 1
}

private fun roObjBlock(s: String, key: String): String {
    val open = s.indexOf('{', roAfterKey(s, key))
    val close = roMatchClose(s, open)
    return s.substring(open + 1, close - 1)
}

private fun roArrayBlock(s: String, key: String): String {
    val open = s.indexOf('[', roAfterKey(s, key))
    val close = roMatchClose(s, open)
    return s.substring(open + 1, close - 1)
}

private fun roSplitObjects(arrayInner: String): List<String> {
    val out = ArrayList<String>()
    var i = 0
    while (true) {
        val open = arrayInner.indexOf('{', i)
        if (open < 0) return out
        val close = roMatchClose(arrayInner, open)
        out.add(arrayInner.substring(open + 1, close - 1))
        i = close
    }
}

private fun roTopStrings(arrayInner: String): List<String> =
    Regex("\"([^\"]*)\"").findAll(arrayInner).map { it.groupValues[1] }.toList()

private fun roField(scope: String, key: String): String {
    val m = Regex("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun roIntField(scope: String, key: String): Long {
    val m = Regex("\"" + key + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun roErrKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

private const val RO_ALG = Cose.ALG_MLDSA65
private const val RO_PROFILE = Cose.PROFILE_PUBLIC

private fun roSeed(b: Int): ByteArray = ByteArray(32) { b.toByte() }

private fun roSignerId(b: Int): String = Identity.signerId(RO_ALG, Cose.mldsaKeygen("ML-DSA-65", roSeed(b)))

private fun roCheckReceipt(rec: Audit.Receipt, want: String) {
    val sq = roIntField(want, "seq")
    roCheck("receipt body seq=$sq == oracle", Hex.encode(rec.bytes()), roField(want, "body_hex"))
    roCheck("receipt head seq=$sq == oracle", Hex.encode(rec.head()), roField(want, "head_after_hex"))
    roCheck("receipt obj seq=$sq == oracle", Hex.encode(rec.obj), roField(want, "obj_hex"))
}

private fun roomsRun() {
    val json = roFindVector().readText(Charsets.UTF_8)
    val rj = roObjBlock(json, "rooms")
    val reg = roObjBlock(json, "registry")
    val room = Hex.decode(roField(rj, "room_id_hex"))
    val ops = roSplitObjects(roArrayBlock(rj, "ops"))
    val log = roSplitObjects(roArrayBlock(rj, "room_log"))

    // 1. membership op body + content-id byte parity (design 2.3).
    for (oj in ops) {
        val op = Rooms.RoomOp(room, roIntField(oj, "op"), roIntField(oj, "epoch_at_build"), roField(oj, "subject"), roIntField(oj, "role"))
        val nm = roField(oj, "op_name")
        roCheck("op $nm body == oracle", Hex.encode(op.bytes()), roField(oj, "body_hex"))
        roCheck("op $nm content id == oracle", Hex.encode(op.contentId()), roField(oj, "op_content_id_hex"))
    }

    // 2. the full run: receipt-chained log + state machine (byte + value).
    val aseed = roSeed(90)
    val apk = Cose.mldsaKeygen("ML-DSA-65", aseed)
    val auth = Audit.Authority(RO_ALG, aseed)
    val create = ops[0]
    val cop = Rooms.RoomOp(room, roIntField(create, "op"), roIntField(create, "epoch_at_build"), roField(create, "subject"), roIntField(create, "role"))
    val creator = roField(create, "subject")
    val c0 = Rooms.createRoom(cop, creator, auth, roIntField(log[0], "at"))
    val rm = c0.room
    roCheck("create cursor == 0", c0.cursor.toString(), "0")
    roCheck("room epoch after create == 1", rm.epoch().toString(), "1")
    roCheckReceipt(c0.receipt, log[0])

    for (i in 1 until ops.size) {
        val oj = ops[i]
        val op = Rooms.RoomOp(room, roIntField(oj, "op"), roIntField(oj, "epoch_at_build"), roField(oj, "subject"), roIntField(oj, "role"))
        roCheck("built epoch tracks room epoch (seq ${roIntField(oj, "seq")})", roIntField(oj, "epoch_at_build").toString(), rm.epoch().toString())
        val ap = rm.apply(op, creator, roIntField(log[i], "at"))
        roCheck("cursor == oracle seq ${roIntField(oj, "seq")}", ap.cursor.toString(), roIntField(oj, "seq").toString())
        roCheck("epoch bumped to ${roIntField(oj, "epoch_after")}", rm.epoch().toString(), roIntField(oj, "epoch_after").toString())
        roCheckReceipt(ap.receipt, log[i])
    }

    roCheck("final epoch == oracle", rm.epoch().toString(), roIntField(rj, "final_epoch").toString())
    roCheck("final owners == oracle", rm.owners().joinToString(","), roTopStrings(roArrayBlock(rj, "final_owners")).joinToString(","))
    for (mj in roSplitObjects(roArrayBlock(rj, "final_members"))) {
        val rr = rm.roleOf(roField(mj, "subject"))
        roCheck("final member ${roField(mj, "subject")} is a member", rr.member.toString(), "true")
        roCheck("final member ${roField(mj, "subject")} role == oracle", rr.role.toString(), roIntField(mj, "role").toString())
    }
    roCheck("room log verifies offline", roErrKind { Audit.verifyChain(rm.receipts(), rm.sigs(), RO_ALG, apk) }, "no-error")
    roCheck("final log head == oracle", Hex.encode(rm.receipts().last().head()), roField(rj, "final_log_head_hex"))

    // 3. signed membership end-to-end (REAL ML-DSA-65 through the spine).
    roSignedMembershipEndToEnd()

    // 4. EPOCH-BUMPING: StaleEpoch (THIS is the mutation-target assertion).
    roStaleEpochRejected()

    // 5. only an owner may change membership (fail-closed).
    roUnauthorizedActorRejected()

    // 6. O2: add-only ownership, never ownerless.
    roAddOnlyOwnership()

    // 7. Delivery Model B: principal-binding wire bytes (byte parity).
    for (bj in roSplitObjects(roArrayBlock(reg, "bindings"))) {
        val b = Rooms.Binding(roField(bj, "principal"), roField(bj, "handle"), roIntField(bj, "epoch"), Hex.decode(roField(bj, "prev_hex")))
        roCheck("binding ${roField(bj, "principal")}@${roIntField(bj, "epoch")} body == oracle", Hex.encode(b.bytes()), roField(bj, "body_hex"))
        roCheck("binding ${roField(bj, "principal")}@${roIntField(bj, "epoch")} head == oracle", Hex.encode(b.head()), roField(bj, "head_after_hex"))
    }

    // 8. Delivery Model B: rebind-on-rotation (REAL co-signed rotation).
    roRebindOnRotation()

    // 9. double-bind refused; first binding is genesis (prev == zero).
    roBindDuplicateAndGenesis()
}

private fun roSignedMembershipEndToEnd() {
    val room = byteArrayOf(0x20, 0x30, 1, 2, 3, 4)
    val oseed = roSeed(50)
    val opk = Cose.mldsaKeygen("ML-DSA-65", oseed)
    val oid = Identity.signerId(RO_ALG, opk)
    val bobid = roSignerId(51)
    val auth = Audit.Authority(RO_ALG, roSeed(91))

    val c = Rooms.createRoom(Rooms.RoomOp(room, Rooms.OP_CREATE, 0, oid, Rooms.ROLE_OWNER), oid, auth, 1000)
    val rm = c.room

    val add = Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, rm.epoch(), bobid, Rooms.ROLE_MEMBER)
    val obj = add.envelopeObject(oid.toByteArray(Charsets.UTF_8), 1001, RO_PROFILE, emptyList())
    val signed = Envelope.sign(obj, RO_ALG, oseed)
    val ap = rm.applySigned(RO_PROFILE, RO_ALG, opk, signed, 1001)
    roCheck("signed add_member cursor == 1", ap.cursor.toString(), "1")
    val rr = rm.roleOf(bobid)
    roCheck("signed add_member: bob is a member", rr.member.toString(), "true")
    roCheck("signed add_member: bob role == member", rr.role.toString(), Rooms.ROLE_MEMBER.toString())

    // A baseline-only verifier (no tier licensed) rejects the tier-1 room kind as UnknownKind.
    val baseline = Envelope.KindValidator { ch, k ->
        try {
            Channels.lookup(ch, k); true
        } catch (e: NaalpException) {
            false
        }
    }
    roCheck("baseline verifier rejects the tier-1 kind UnknownKind", roErrKind { Envelope.verify(RO_PROFILE, RO_ALG, opk, baseline, signed) }, "UnknownKind")
}

private fun roStaleEpochRejected() {
    val room = byteArrayOf(9, 9, 9)
    val oid = roSignerId(52)
    val bobid = roSignerId(53)
    val carolid = roSignerId(54)
    val auth = Audit.Authority(RO_ALG, roSeed(92))
    val rm = Rooms.createRoom(Rooms.RoomOp(room, Rooms.OP_CREATE, 0, oid, Rooms.ROLE_OWNER), oid, auth, 1).room
    val e = rm.epoch() // both ops build against this epoch
    rm.apply(Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, e, bobid, Rooms.ROLE_MEMBER), oid, 2)
    roCheck("second op against a stale epoch rejected StaleEpoch",
        roErrKind { rm.apply(Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, e, carolid, Rooms.ROLE_MEMBER), oid, 3) }, "StaleEpoch")
    roCheck("no state change on a rejected stale-epoch op", rm.roleOf(carolid).member.toString(), "false")
    // The same op rebuilt against the CURRENT epoch is accepted (wrapped so a mutated run flips cleanly).
    roCheck("op rebuilt against the current epoch is accepted",
        roErrKind { rm.apply(Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, rm.epoch(), carolid, Rooms.ROLE_MEMBER), oid, 4) }, "no-error")
    roCheck("carol is a member after the accepted op", rm.roleOf(carolid).member.toString(), "true")
}

private fun roUnauthorizedActorRejected() {
    val room = byteArrayOf(7, 7)
    val oid = roSignerId(55)
    val bobid = roSignerId(56)
    val malloryid = roSignerId(57)
    val auth = Audit.Authority(RO_ALG, roSeed(93))
    val rm = Rooms.createRoom(Rooms.RoomOp(room, Rooms.OP_CREATE, 0, oid, Rooms.ROLE_OWNER), oid, auth, 1).room
    rm.apply(Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, rm.epoch(), bobid, Rooms.ROLE_MEMBER), oid, 2)
    // mallory (not even a member) tries to add themselves as owner.
    roCheck("non-owner actor rejected Unauthorized",
        roErrKind { rm.apply(Rooms.RoomOp(room, Rooms.OP_ADD_OWNER, rm.epoch(), malloryid, Rooms.ROLE_OWNER), malloryid, 3) }, "Unauthorized")
    // bob (a member, not an owner) also cannot add a member.
    roCheck("member (non-owner) actor rejected Unauthorized",
        roErrKind { rm.apply(Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, rm.epoch(), malloryid, Rooms.ROLE_MEMBER), bobid, 4) }, "Unauthorized")
    roCheck("owner count unchanged on rejected ops", rm.ownerCount().toString(), "1")
}

private fun roAddOnlyOwnership() {
    val room = byteArrayOf(5)
    val aliceid = roSignerId(58)
    val bobid = roSignerId(59)
    val auth = Audit.Authority(RO_ALG, roSeed(94))
    val rm = Rooms.createRoom(Rooms.RoomOp(room, Rooms.OP_CREATE, 0, aliceid, Rooms.ROLE_OWNER), aliceid, auth, 1).room
    roCheck("one owner after create", rm.ownerCount().toString(), "1")
    rm.apply(Rooms.RoomOp(room, Rooms.OP_ADD_OWNER, rm.epoch(), bobid, Rooms.ROLE_OWNER), aliceid, 2)
    roCheck("two owners after add_owner", rm.ownerCount().toString(), "2")
    roCheck("bob is an owner", rm.isOwner(bobid).toString(), "true")
    // remove_member(alice) - an owner - is refused OwnerImmutable.
    roCheck("remove of an owner refused OwnerImmutable",
        roErrKind { rm.apply(Rooms.RoomOp(room, Rooms.OP_REMOVE_MEMBER, rm.epoch(), aliceid, Rooms.ROLE_MEMBER), bobid, 3) }, "OwnerImmutable")
    // change_role(alice -> member) - demoting an owner - is refused OwnerImmutable.
    roCheck("demotion of an owner refused OwnerImmutable",
        roErrKind { rm.apply(Rooms.RoomOp(room, Rooms.OP_CHANGE_ROLE, rm.epoch(), aliceid, Rooms.ROLE_MEMBER), bobid, 4) }, "OwnerImmutable")
    // re-add of an existing owner is refused OwnerExists.
    roCheck("re-add of an existing owner refused OwnerExists",
        roErrKind { rm.apply(Rooms.RoomOp(room, Rooms.OP_ADD_OWNER, rm.epoch(), bobid, Rooms.ROLE_OWNER), aliceid, 5) }, "OwnerExists")
    roCheck("room is never ownerless (>= 1 owner)", (rm.ownerCount() >= 1).toString(), "true")
}

private fun roRebindOnRotation() {
    val v1seed = roSeed(60)
    val v1pk = Cose.mldsaKeygen("ML-DSA-65", v1seed)
    val v1id = Identity.signerId(RO_ALG, v1pk)
    val v2seed = roSeed(61)
    val v2pk = Cose.mldsaKeygen("ML-DSA-65", v2seed)
    val v2id = Identity.signerId(RO_ALG, v2pk)
    val evilid = roSignerId(62)

    val pr = Rooms.PrincipalRegistry()
    pr.bind("agent:alice", v1id)
    roCheck("resolve after first bind == v1", pr.resolve("agent:alice"), v1id)

    // A valid co-signed rotation v1 -> v2 authorises the rebind; the semantic id survives.
    val rot = Identity.RotationRecord(v1id, v2id, 100)
    val (oldSig, newSig) = Identity.signRotation(rot, RO_ALG, v1seed, v2seed)
    pr.rebind("agent:alice", v2id, rot, RO_ALG, v1pk, RO_ALG, v2pk, oldSig, newSig)
    roCheck("resolve after a valid rebind == v2", pr.resolve("agent:alice"), v2id)

    // A hijack: a rotation whose old leg is NOT signed by the current handle is refused, unchanged.
    val bad = Identity.RotationRecord(v2id, evilid, 200)
    val (bOldSig, bNewSig) = Identity.signRotation(bad, RO_ALG, v1seed, v2seed) // old leg signed by v1, not v2
    roCheck("hijack rebind refused RebindUnauthorized",
        roErrKind { pr.rebind("agent:alice", evilid, bad, RO_ALG, v1pk, RO_ALG, v2pk, bOldSig, bNewSig) }, "RebindUnauthorized")
    roCheck("registry unchanged after a refused rebind", pr.resolve("agent:alice"), v2id)

    // An unknown principal resolves fail-closed.
    roCheck("unknown principal resolves PrincipalUnknown", roErrKind { pr.resolve("agent:nobody") }, "PrincipalUnknown")
}

private fun roBindDuplicateAndGenesis() {
    val aid = roSignerId(63)
    val pr = Rooms.PrincipalRegistry()
    val b = pr.bind("agent:alice", aid)
    roCheck("first binding epoch == 0", b.epoch.toString(), "0")
    roCheck("first binding prev == genesis (all-zero)", Hex.encode(b.prev), Hex.encode(Rooms.genesisHead()))
    roCheck("double-bind refused PrincipalExists", roErrKind { pr.bind("agent:alice", aid) }, "PrincipalExists")
}

fun main() {
    println("rooms conformance (Kotlin) - graded vs vectors/rooms/cases.json")
    roomsRun()
    println(if (roFails == 0) "RoomsTests: PASS" else "RoomsTests: FAIL ($roFails)")
    exitProcess(if (roFails == 0) 0 else 1)
}
