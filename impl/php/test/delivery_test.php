<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C8 delivery conformance for the PHP SDK (design.md §9; R-9.1..9.4), graded against the shared
// independent corpus vectors/delivery/cases.json (NOT produced by this code). Delivery is four
// distinct, separately-observable signed stages (there is no single "sent" boolean): persisted_origin
// -> accepted_relay -> persisted_target -> presented; a stage advances only after the object is
// durably persisted (WAL fsync); observing an earlier stage than the one already reached is
// StageOutOfOrder; a content-free relay writes an audit trail over content ids while retaining no
// payload.
//
// CORPUS-GRADED (pure): the four stage names, the delivery.update body {1:obj,2:stage,3:at}
// byte-for-byte for every stage, and the T1 content-id framing.
// BEHAVIOURAL (isolation): the monotonic persist-before-ack Tracker (StageOutOfOrder on regression,
// idempotent no-op on the current stage, WAL replay recovery), the content-free relay (retains only
// a valid receipt chain, no payload), and the synchronous full-duplex switchboard.
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the delivery.update signature. PHP is
// PURE-ONLY for ML-DSA, so the reference's ML-DSA update signature is demonstrated with a real
// Ed25519 (RFC 8032) round-trip. PHP CLI is single-threaded (no pthreads), so the reference's two
// concurrent pump threads are expressed as a synchronous full-duplex relay that forwards both
// directions; the routing property (§9.3), not the OS-thread scheduling, is what is demonstrated.
//
// Written test-first: Naalp\Delivery is absent until Delivery.php lands, so this fails RED with a
// fatal "class not found"; dropping the monotonic guard in Tracker::advance flips
// "regression rejected (StageOutOfOrder)".
//
// Run:  php -d extension=sodium -d extension=intl test/delivery_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Delivery;
use Naalp\DeliveryUpdate;
use Naalp\ContentFreeRelay;
use Naalp\Switchboard;
use Naalp\Cose;
use Naalp\Audit;

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
function delivery_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/delivery/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/delivery/cases.json not found");
}

$C = delivery_vectors();
echo "delivery conformance (PHP) — graded vs vectors/delivery/cases.json\n";

// 1. the four stage names == the oracle; an out-of-range stage is "unknown".
foreach ($C["stages"] as $s) {
    check("stage name " . $s["value"], Delivery::stageName($s["value"]), $s["name"]);
}
check("unknown stage name", Delivery::stageName(99), "unknown");

// 2. the delivery.update body byte-for-byte vs the non-circular oracle, for every stage. A mutation
//    to bytes() (a key or value) flips a body_hex assertion.
$obj = hex2bin($C["obj_content_id_hex"]);
foreach ($C["updates"] as $u) {
    $du = new DeliveryUpdate($obj, $u["stage"], $u["at"]);
    check("update stage " . $u["stage"] . " body == oracle", bin2hex($du->bytes()), $u["body_hex"]);
    // round-trip: parseUpdate reconstructs the same body.
    $parsed = Delivery::parseUpdate($du->bytes());
    check("update stage " . $u["stage"] . " round-trip stage", (string) $parsed->stage, (string) $u["stage"]);
}

// 3. the T1 content-id framing is multihash(0x20 sha2-384, 0x30 len-48) || SHA-384(bytes) (§2.3),
//    checked against an independent recomputation (not the code under test).
$raw = "\x01\x02\x03\x04";
$cid = Delivery::contentId($raw);
check("content-id framing == independent multihash", bin2hex($cid), "2030" . hash('sha384', $raw));
check("content-id length", (string) strlen($cid), "50");

// 4. the monotonic persist-before-ack Tracker (the load-bearing §9.4 property; the mutation target).
$walPath = tempnam(sys_get_temp_dir(), 'naalp_del_');
$obj2 = Delivery::contentId("object-under-delivery");
$tr = Delivery::openTracker($walPath);
$tr->advance($obj2, Delivery::STAGE_PERSISTED_ORIGIN, 100);
$tr->advance($obj2, Delivery::STAGE_ACCEPTED_RELAY, 101);
$tr->advance($obj2, Delivery::STAGE_PERSISTED_TARGET, 102);
check("regression rejected (StageOutOfOrder)", err_kind(fn() => $tr->advance($obj2, Delivery::STAGE_ACCEPTED_RELAY, 103)), "StageOutOfOrder");
check("current stage is an idempotent no-op", err_kind(fn() => $tr->advance($obj2, Delivery::STAGE_PERSISTED_TARGET, 104)), "no-error");
$tr->advance($obj2, Delivery::STAGE_PRESENTED, 105); // a later stage is accepted
[$stg, $seen] = $tr->stage($obj2);
check("highest stage reached", (string) $stg . ($seen ? "/seen" : "/unseen"), "3/seen");
$tr->close();
// WAL replay recovers the last durable stage (persist-before-ack, §9.2).
$tr2 = Delivery::openTracker($walPath);
[$stg2, $seen2] = $tr2->stage($obj2);
check("WAL replay recovers stage", (string) $stg2 . ($seen2 ? "/seen" : "/unseen"), "3/seen");
$tr2->close();
@unlink($walPath);

// 5. the content-free relay retains only a valid receipt chain over content ids — never the payload
//    (§9.4). Ed25519-signed receipts; the retained trail verifies as a valid chain.
$relaySeed = str_repeat("\x33", 32);
$relay = new ContentFreeRelay($relaySeed);
$payloads = ["obj-alpha", "obj-bravo", "obj-charlie"];
foreach ($payloads as $i => $p) {
    $forwarded = $relay->route($p, 200 + $i);
    check("relay forwards payload $i unchanged", $forwarded, $p);
}
[$receipts, $relaySigs] = $relay->auditTrail();
check("relay retained receipt count", (string) count($receipts), (string) count($payloads));
check("relay trail links verify", err_kind(fn() => Audit::verifyChainLinks($receipts)), "no-error");
// each receipt names the object's content id, not the payload (content-free at rest).
check("relay receipt 0 names content-id not payload", bin2hex($receipts[0]->obj), bin2hex(Delivery::contentId($payloads[0])));

// 6. the synchronous full-duplex switchboard forwards objects in BOTH directions (§9.3 routing).
$sb = new Switchboard(4);
$sb->left()->send("l2r-1");
$sb->right()->send("r2l-1");
check("left->right delivered", $sb->right()->recv(), "l2r-1");
check("right->left delivered", $sb->left()->recv(), "r2l-1");
$sb->close();

// 7. ED25519-DEMONSTRATED (isolation): a delivery.update signature signs and verifies; a tampered
//    signature and a foreign key both fail. (The reference signs with ML-DSA; PURE-ONLY PHP here.)
$updSeed = str_repeat("\x44", 32);
$updPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($updSeed));
$foreignPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x45", 32)));
$du0 = new DeliveryUpdate($obj, 1, 101);
$usig = Delivery::signUpdate($du0, $updSeed);
check("update signature verifies", Delivery::verifyUpdate($du0, $updPk, $usig) ? "true" : "false", "true");
$utamp = $usig;
$utamp[strlen($utamp) - 1] = $utamp[strlen($utamp) - 1] ^ "\x01";
check("tampered update signature rejected", Delivery::verifyUpdate($du0, $updPk, $utamp) ? "true" : "false", "false");
check("foreign key rejected", Delivery::verifyUpdate($du0, $foreignPk, $usig) ? "true" : "false", "false");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
