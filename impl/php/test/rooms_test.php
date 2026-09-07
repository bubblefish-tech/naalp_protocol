<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C-rooms (feature #64) collaboration/rooms membership conformance for the PHP SDK (design.md
// §2..§10; design-channels.md §21), graded against the shared independent corpus
// vectors/rooms/cases.json (NOT produced by this code). Rooms is a Phase-3 ADDITIVE higher tier
// (tier 1) over the frozen draft-00 spine: it introduces NO new envelope, encoding, signature,
// identity, or audit mechanism (R-11.3, R-15A.2) and reuses the spine unchanged — the per-room log
// IS the C7 audit receipt chain (§8.1), and a rotation-authorised rebind reuses the C4 identity
// rotation primitive.
//
// CORPUS-GRADED (pure, signature-independent): (1) every membership-op body + content id; (2) the
// full room run — receipt-chained log bodies/heads/objs, the cursor positions, the epoch
// progression, and the final membership/ownership state — matched byte/value-for-byte to the
// oracle (⟹ Go == Rust == Python); (3) the principal-binding wire bodies + per-principal chain
// heads; and (4) the state-machine verdicts (StaleEpoch epoch-bump serialisation, Unauthorized,
// add-only OwnerImmutable/OwnerExists, MemberExists/MemberUnknown/RoleInvalid).
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the room-log ordering authority signs each
// receipt with a real Ed25519 (RFC 8032) key (the pure-tier stand-in for the reference's ML-DSA
// authority) and the whole log verifies offline; the rotation that authorises a rebind is a real
// co-signed Ed25519 rotation (Identity::signRotation/verifyRotation). PHP is PURE-ONLY for ML-DSA
// (FIPS 204 has no deterministic PHP signer), so those signatures are demonstrated with Ed25519 and
// the signed membership object below is verified STRUCTURALLY on the ML-DSA-65 path (level 3 clears
// the Public floor; the ML-DSA signature itself is the one un-exercised leg, exactly as the
// Delegation port documents).
//
// Written test-first: Naalp\Rooms / Naalp\RoomOp / Naalp\Room / Naalp\PrincipalRegistry are absent
// until Rooms.php lands, so this fails RED with a fatal "class not found". The load-bearing
// mutation: dropping the epoch-bump guard in Room::apply (so a stale-epoch op is not rejected) flips
// "stale-epoch op rejected (StaleEpoch)" and "state unchanged on the rejected stale op".
//
// Run:  php -d extension=sodium -d extension=intl test/rooms_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Rooms;
use Naalp\RoomOp;
use Naalp\Room;
use Naalp\Binding;
use Naalp\PrincipalRegistry;
use Naalp\Authority;
use Naalp\Audit;
use Naalp\Identity;
use Naalp\RotationRecord;
use Naalp\Cose;
use Naalp\Channels;
use Naalp\Policy;

$fails = 0;
function check(string $name, string $got, string $want): void
{
    global $fails;
    if ($got === $want) {
        echo "  ok   $name\n";
    } else {
        $fails++;
        echo "  FAIL $name\n       got  $got\n       want $want\n";
    }
}

/** Run $fn and return the caught error's ->kind (or "no-error" / the class name). */
function err_kind(callable $fn): string
{
    try {
        $fn();
        return "no-error";
    } catch (\Throwable $e) {
        return \property_exists($e, 'kind') ? $e->kind : \get_class($e);
    }
}

/** Walk up from this dir to the repository's shared corpus (the independent oracle). */
function rooms_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/rooms/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/rooms/cases.json not found");
}

/**
 * A deterministic Ed25519 keypair for a scenario label: the 32-byte seed, the raw public key, and
 * the self-certifying Ed25519 signer id (§5.1). Used for the durable-identity rotation demo.
 *
 * @return array{0:string,1:string,2:string} [seed, pubkey, signer-id]
 */
function ed_key(string $label): array
{
    static $cache = [];
    if (!isset($cache[$label])) {
        $seed = hash('sha256', "naalp-rooms-key:$label", true); // 32 bytes, deterministic per label
        $pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
        $cache[$label] = [$seed, $pk, Identity::signerId(Cose::ALG_ED25519, $pk)];
    }
    return $cache[$label];
}

/** An injected Ed25519 verify closure fn(msg,sig):bool (the pure-tier stand-in for ML-DSA verify). */
function ed_verify(string $pk): callable
{
    return static fn(string $msg, string $sig): bool => Cose::ed25519Verify($pk, $msg, $sig);
}

$C = rooms_vectors();
$R = $C["rooms"];
$roomId = hex2bin($R["room_id_hex"]);
echo "rooms conformance (PHP) — graded vs vectors/rooms/cases.json\n";

// 1. every membership-op body and its content id are byte-identical to the independent oracle
//    (⟹ Go == Rust == Python). A field-ignoring / constant encoder diverges here.
foreach ($R["ops"] as $oj) {
    $op = new RoomOp($roomId, $oj["op"], $oj["epoch_at_build"], $oj["subject"], $oj["role"]);
    check("op {$oj['seq']} ({$oj['op_name']}) body == oracle", bin2hex($op->bytes()), $oj["body_hex"]);
    check("op {$oj['seq']} ({$oj['op_name']}) content-id == oracle", bin2hex($op->contentId()), $oj["op_content_id_hex"]);
}

// 2. drive a REAL Room through the oracle's op sequence; the resulting receipt-chained log
//    (bodies + heads + objs), the cursor positions, the epoch progression, and the final
//    membership/ownership are all byte/value-identical to the oracle. Grades the wire bytes AND the
//    state machine at once. The room log is the C7 receipt chain; the ordering authority signs with
//    a real Ed25519 key (pure-tier stand-in) and the whole log verifies offline against that key.
[$authSeed, $authPk, ] = ed_key("room-authority");
$auth = new Authority($authSeed);
$create = $R["ops"][0]; // op 0 is create; creator "alice" seeds itself as the first owner.
$cop = new RoomOp($roomId, $create["op"], $create["epoch_at_build"], $create["subject"], $create["role"]);
[$room, $rec0, $cursor0] = Rooms::createRoom($cop, $create["subject"], $auth, $R["room_log"][0]["at"]);
check("create cursor == 0", (string) $cursor0, "0");
check("epoch after create == 1", (string) $room->epoch(), "1");
check_receipt("log[0]", $rec0, $R["room_log"][0]);
for ($i = 1; $i < count($R["ops"]); $i++) {
    $oj = $R["ops"][$i];
    check("op $i built epoch == room epoch", (string) $oj["epoch_at_build"], (string) $room->epoch());
    $op = new RoomOp($roomId, $oj["op"], $oj["epoch_at_build"], $oj["subject"], $oj["role"]);
    [$rec, $cursor] = $room->apply($op, $create["subject"], $R["room_log"][$i]["at"]);
    check("op $i cursor == seq", (string) $cursor, (string) $oj["seq"]);
    check("op $i epoch_after == oracle", (string) $room->epoch(), (string) $oj["epoch_after"]);
    check_receipt("log[$i]", $rec, $R["room_log"][$i]);
}
check("final epoch == oracle", (string) $room->epoch(), (string) $R["final_epoch"]);
check("final owners == oracle", implode(",", $room->owners()), implode(",", $R["final_owners"]));
foreach ($R["final_members"] as $m) {
    [$role, $ok] = $room->roleOf($m["subject"]);
    check("final member {$m['subject']} role == oracle", $ok ? (string) $role : "absent", (string) $m["role"]);
}
[$receipts, $sigs] = $room->log();
check("room log verifies offline (Ed25519 authority)", err_kind(fn() => Audit::verifyChain($receipts, $sigs, ed_verify($authPk))), "no-error");
$finalHead = end($receipts)->head();
check("final log head == oracle", bin2hex($finalHead), $R["final_log_head_hex"]);

function check_receipt(string $tag, $rec, array $want): void
{
    check("$tag receipt body == oracle", bin2hex($rec->bytes()), $want["body_hex"]);
    check("$tag receipt head == oracle", bin2hex($rec->head()), $want["head_after_hex"]);
    check("$tag receipt obj == op content id", bin2hex($rec->obj), $want["obj_hex"]);
}

// 3. EPOCH-BUMPING (#4a serialisation core) — two ops built against the SAME epoch cannot both
//    apply: once the first is accepted (epoch bumps) the second is StaleEpoch, fail-closed, with no
//    state change; the same op rebuilt against the CURRENT epoch is accepted. THE MUTATION TARGET:
//    dropping the epoch guard in Room::apply flips the two named checks below.
[, , $ownerId] = ed_key("epoch-owner");
[, , $bobId] = ed_key("epoch-bob");
[, , $carolId] = ed_key("epoch-carol");
[$sSeed, $sPk, ] = ed_key("epoch-auth");
$auth2 = new Authority($sSeed);
[$rm2, , ] = Rooms::createRoom(new RoomOp("\x09\x09\x09", Rooms::OP_CREATE, 0, $ownerId, Rooms::ROLE_OWNER), $ownerId, $auth2, 1);
$e = $rm2->epoch(); // both ops are built against this epoch
check("first add at current epoch accepted", err_kind(fn() => $rm2->apply(new RoomOp("\x09\x09\x09", Rooms::OP_ADD_MEMBER, $e, $bobId, Rooms::ROLE_MEMBER), $ownerId, 2)), "no-error");
check("stale-epoch op rejected (StaleEpoch)", err_kind(fn() => $rm2->apply(new RoomOp("\x09\x09\x09", Rooms::OP_ADD_MEMBER, $e, $carolId, Rooms::ROLE_MEMBER), $ownerId, 3)), "StaleEpoch");
check("state unchanged on the rejected stale op", $rm2->roleOf($carolId)[1] ? "changed" : "unchanged", "unchanged");
check("same op at CURRENT epoch accepted", err_kind(fn() => $rm2->apply(new RoomOp("\x09\x09\x09", Rooms::OP_ADD_MEMBER, $rm2->epoch(), $carolId, Rooms::ROLE_MEMBER), $ownerId, 4)), "no-error");

// 4. only an owner may change membership; a non-owner actor is refused Unauthorized (fail-closed)
//    and no state changes.
[, , $aOwner] = ed_key("auth-owner");
[, , $aMember] = ed_key("auth-member");
[, , $aMallory] = ed_key("auth-mallory");
[$aSeed, , ] = ed_key("auth-auth");
[$rm3, , ] = Rooms::createRoom(new RoomOp("\x07\x07", Rooms::OP_CREATE, 0, $aOwner, Rooms::ROLE_OWNER), $aOwner, new Authority($aSeed), 1);
$rm3->apply(new RoomOp("\x07\x07", Rooms::OP_ADD_MEMBER, $rm3->epoch(), $aMember, Rooms::ROLE_MEMBER), $aOwner, 2);
check("unauthorized actor refused (Unauthorized)", err_kind(fn() => $rm3->apply(new RoomOp("\x07\x07", Rooms::OP_ADD_OWNER, $rm3->epoch(), $aMallory, Rooms::ROLE_OWNER), $aMallory, 3)), "Unauthorized");
check("non-owner member cannot change membership (Unauthorized)", err_kind(fn() => $rm3->apply(new RoomOp("\x07\x07", Rooms::OP_ADD_MEMBER, $rm3->epoch(), $aMallory, Rooms::ROLE_MEMBER), $aMember, 4)), "Unauthorized");
check("owner count unchanged after refused ops", (string) $rm3->ownerCount(), "1");

// 5. O2 add-only ownership — add_owner grows the owner set; an owner can be neither removed nor
//    demoted; a re-add is refused; the owner count is monotonically >= 1 (never ownerless).
[, , $oAlice] = ed_key("own-alice");
[, , $oBob] = ed_key("own-bob");
[$oSeed, , ] = ed_key("own-auth");
[$rm4, , ] = Rooms::createRoom(new RoomOp("\x05", Rooms::OP_CREATE, 0, $oAlice, Rooms::ROLE_OWNER), $oAlice, new Authority($oSeed), 1);
check("fresh room owner count == 1", (string) $rm4->ownerCount(), "1");
$rm4->apply(new RoomOp("\x05", Rooms::OP_ADD_OWNER, $rm4->epoch(), $oBob, Rooms::ROLE_OWNER), $oAlice, 2);
check("add_owner grows the owner set", ($rm4->ownerCount() === 2 && $rm4->isOwner($oBob)) ? "grown" : "no", "grown");
check("remove of an owner refused (OwnerImmutable)", err_kind(fn() => $rm4->apply(new RoomOp("\x05", Rooms::OP_REMOVE_MEMBER, $rm4->epoch(), $oAlice, Rooms::ROLE_MEMBER), $oBob, 3)), "OwnerImmutable");
check("demote of an owner refused (OwnerImmutable)", err_kind(fn() => $rm4->apply(new RoomOp("\x05", Rooms::OP_CHANGE_ROLE, $rm4->epoch(), $oAlice, Rooms::ROLE_MEMBER), $oBob, 4)), "OwnerImmutable");
check("re-add of an existing owner refused (OwnerExists)", err_kind(fn() => $rm4->apply(new RoomOp("\x05", Rooms::OP_ADD_OWNER, $rm4->epoch(), $oBob, Rooms::ROLE_OWNER), $oAlice, 5)), "OwnerExists");
check("owner count still >= 1", ($rm4->ownerCount() >= 1) ? "yes" : "no", "yes");

// 6. per-op semantic guards: add a duplicate member (MemberExists), remove/change a non-member
//    (MemberUnknown), add_member with the owner role (RoleInvalid).
[, , $gAlice] = ed_key("guard-alice");
[, , $gBob] = ed_key("guard-bob");
[, , $gCarol] = ed_key("guard-carol");
[$gSeed, , ] = ed_key("guard-auth");
[$rm5, , ] = Rooms::createRoom(new RoomOp("\x03", Rooms::OP_CREATE, 0, $gAlice, Rooms::ROLE_OWNER), $gAlice, new Authority($gSeed), 1);
$rm5->apply(new RoomOp("\x03", Rooms::OP_ADD_MEMBER, $rm5->epoch(), $gBob, Rooms::ROLE_MEMBER), $gAlice, 2);
check("duplicate add_member refused (MemberExists)", err_kind(fn() => $rm5->apply(new RoomOp("\x03", Rooms::OP_ADD_MEMBER, $rm5->epoch(), $gBob, Rooms::ROLE_MEMBER), $gAlice, 3)), "MemberExists");
check("remove of a non-member refused (MemberUnknown)", err_kind(fn() => $rm5->apply(new RoomOp("\x03", Rooms::OP_REMOVE_MEMBER, $rm5->epoch(), $gCarol, Rooms::ROLE_MEMBER), $gAlice, 4)), "MemberUnknown");
check("add_member with owner role refused (RoleInvalid)", err_kind(fn() => $rm5->apply(new RoomOp("\x03", Rooms::OP_ADD_MEMBER, $rm5->epoch(), $gCarol, Rooms::ROLE_OWNER), $gAlice, 5)), "RoleInvalid");

// 7. a create op must be built against epoch 0, by the seeded owner, with an NFC subject.
[$cSeed, , ] = ed_key("create-auth");
check("non-zero-epoch create refused (StaleEpoch)", err_kind(fn() => Rooms::createRoom(new RoomOp("\x01", Rooms::OP_CREATE, 1, "alice", Rooms::ROLE_OWNER), "alice", new Authority($cSeed), 1)), "StaleEpoch");
check("create by a non-subject actor refused (Unauthorized)", err_kind(fn() => Rooms::createRoom(new RoomOp("\x01", Rooms::OP_CREATE, 0, "alice", Rooms::ROLE_OWNER), "mallory", new Authority($cSeed), 1)), "Unauthorized");
$nonNfc = "e\u{0301}"; // "é" as e + combining acute (NFD, not NFC)
check("non-NFC create subject refused (NonNFC)", err_kind(fn() => Rooms::createRoom(new RoomOp("\x01", Rooms::OP_CREATE, 0, $nonNfc, Rooms::ROLE_OWNER), $nonNfc, new Authority($cSeed), 1)), "NonNFC");

// 8. Delivery Model B — principal-binding wire bodies and per-principal chain heads are
//    byte-identical to the oracle (⟹ Go == Rust == Python).
foreach ($C["registry"]["bindings"] as $bj) {
    $b = new Binding($bj["principal"], $bj["handle"], $bj["epoch"], hex2bin($bj["prev_hex"]));
    check("binding {$bj['principal']}@{$bj['epoch']} body == oracle", bin2hex($b->bytes()), $bj["body_hex"]);
    check("binding {$bj['principal']}@{$bj['epoch']} head == oracle", bin2hex($b->head()), $bj["head_after_hex"]);
}

// 9. Delivery Model B behaviour — a semantic id resolves to a durable Handle; a rebind is authorised
//    ONLY by a verified co-signed rotation from the CURRENT handle (R-1.4), so the semantic id
//    survives rotation but a hijack to an unrelated key is refused RebindUnauthorized. The rotation
//    is a real co-signed Ed25519 rotation (the C4 primitive added to Identity.php). Mutation: if
//    Rebind skipped the rotation check, the hijack would succeed.
[$v1Seed, $v1Pk, $v1Id] = ed_key("dm-b-v1");
[$v2Seed, $v2Pk, $v2Id] = ed_key("dm-b-v2");
[$evSeed, $evPk, $evId] = ed_key("dm-b-evil");
$pr = new PrincipalRegistry();
$pr->bind("agent:alice", $v1Id);
check("resolve v1 handle", $pr->resolve("agent:alice"), $v1Id);
check("re-bind of an existing principal refused (PrincipalExists)", err_kind(fn() => $pr->bind("agent:alice", $v2Id)), "PrincipalExists");
// A valid co-signed rotation v1 -> v2 authorises the rebind.
$rot = new RotationRecord($v1Id, $v2Id, 100);
[$oldSig, $newSig] = Identity::signRotation($rot, $v1Seed, $v2Seed);
check("authorised rebind on rotation accepted", err_kind(fn() => $pr->rebind("agent:alice", $v2Id, $rot, Cose::ALG_ED25519, $v1Pk, Cose::ALG_ED25519, $v2Pk, $oldSig, $newSig)), "no-error");
check("resolve follows rotation to v2", $pr->resolve("agent:alice"), $v2Id);
// A hijack: rebind to an unrelated key with a rotation NOT co-signed by the current (v2) key.
$badRot = new RotationRecord($v2Id, $evId, 200);
[, $evNewSig] = Identity::signRotation($badRot, $evSeed, $evSeed); // "old" leg signed by evil, not v2
$evOldSig = Cose::ed25519Sign($evSeed, $badRot->bytes());
check("hijack rebind refused (RebindUnauthorized)", err_kind(fn() => $pr->rebind("agent:alice", $evId, $badRot, Cose::ALG_ED25519, $v2Pk, Cose::ALG_ED25519, $evPk, $evOldSig, $evNewSig)), "RebindUnauthorized");
check("registry unchanged after refused hijack", $pr->resolve("agent:alice"), $v2Id);
check("unknown principal resolves fail-closed (PrincipalUnknown)", err_kind(fn() => $pr->resolve("agent:nobody")), "PrincipalUnknown");
// A rotation that names the wrong new handle is also refused.
$mislabel = new RotationRecord($v2Id, $evId, 300);
[$mOld, $mNew] = Identity::signRotation($mislabel, $v2Seed, $evSeed);
check("rebind whose rotation names a different new handle refused (RebindUnauthorized)", err_kind(fn() => $pr->rebind("agent:alice", "agent:someone-else", $mislabel, Cose::ALG_ED25519, $v2Pk, Cose::ALG_ED25519, $evPk, $mOld, $mNew)), "RebindUnauthorized");

// 10. the rotation primitive itself (Identity::verifyRotation), Ed25519-demonstrated in isolation:
//     a correct co-signed rotation verifies; a tampered old-leg signature is RotationUnauthorized;
//     an old pubkey that does not derive the record's old id is RotationUnauthorized.
$rotOk = new RotationRecord($v1Id, $v2Id, 100);
[$ro, $rn] = Identity::signRotation($rotOk, $v1Seed, $v2Seed);
check("valid co-signed rotation verifies", err_kind(fn() => Identity::verifyRotation($rotOk, Cose::ALG_ED25519, $v1Pk, Cose::ALG_ED25519, $v2Pk, $ro, $rn)), "no-error");
$tamper = $ro;
$tamper[0] = $tamper[0] ^ "\x01";
check("tampered rotation signature refused (RotationUnauthorized)", err_kind(fn() => Identity::verifyRotation($rotOk, Cose::ALG_ED25519, $v1Pk, Cose::ALG_ED25519, $v2Pk, $tamper, $rn)), "RotationUnauthorized");
check("wrong old key refused (RotationUnauthorized)", err_kind(fn() => Identity::verifyRotation($rotOk, Cose::ALG_ED25519, $evPk, Cose::ALG_ED25519, $v2Pk, $ro, $rn)), "RotationUnauthorized");

// 11. #4a a membership op is a FIRST-CLASS SIGNED object — it verifies through the spine (tier-1
//     Governance), the authenticated signer is the actor, and the op is ordered into the room log.
//     Pure-tier: the object carries an ML-DSA-65 protected header verified STRUCTURALLY (level 3
//     clears the Public floor; the ML-DSA signature bytes are the one un-exercised leg, as in the
//     Delegation port). A baseline-only verifier (no tier licensed) rejects the room kind
//     UnknownKind, fail-closed — proving the tier composes over the frozen baseline (R-11.1).
$ownerPub = hash('sha384', "naalp-rooms-mldsa:owner", true);      // ML-DSA-65 pubkey stand-in
$ownerMId = Identity::signerId(Cose::ALG_MLDSA65, $ownerPub);
[, , $bobMId] = [null, null, Identity::signerId(Cose::ALG_MLDSA65, hash('sha384', "naalp-rooms-mldsa:bob", true))];
[$e2eSeed, , ] = ed_key("e2e-auth");
$e2eAuth = new Authority($e2eSeed);
$sroom = "\x20\x30\x01\x02\x03\x04";
[$rm6, , ] = Rooms::createRoom(new RoomOp($sroom, Rooms::OP_CREATE, 0, $ownerMId, Rooms::ROLE_OWNER), $ownerMId, $e2eAuth, 1000);
$addOp = new RoomOp($sroom, Rooms::OP_ADD_MEMBER, $rm6->epoch(), $bobMId, Rooms::ROLE_MEMBER);
$obj = $addOp->envelopeObject($ownerMId, 1001, Cose::PROFILE_PUBLIC, []);
$payload = \Naalp\Envelope::buildPayload($obj);
$prot = \Naalp\Envelope::protectedHeader(Cose::ALG_MLDSA65, $obj->signer, $obj->profile);
$signed = \Naalp\Envelope::assembleSigned($prot, $payload, str_repeat("\x00", 64)); // ML-DSA sig not verified in pure PHP
check("signed membership object applies end-to-end", err_kind(fn() => $rm6->applySigned(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $ownerPub, $signed, 1001)), "no-error");
check("bob added as member via the signed path", $rm6->roleOf($bobMId)[1] ? (string) $rm6->roleOf($bobMId)[0] : "absent", (string) Rooms::ROLE_MEMBER);
$baselineValidator = static function (int $ch, int $k): bool {
    try {
        Channels::lookup($ch, $k);
        return true;
    } catch (\Naalp\UnknownKind $e) {
        return false;
    }
};
check("baseline verifier rejects tier-1 room kind (UnknownKind)", err_kind(fn() => \Naalp\Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $ownerPub, $baselineValidator, $signed)), "UnknownKind");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
