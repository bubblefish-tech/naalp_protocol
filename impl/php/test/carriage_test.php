<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C12 foreign-carriage-by-class conformance for the PHP SDK (design.md §13; R-14.1..14.8, R-18.6),
// graded against the shared independent PER-CLASS corpus vectors/carriage/<class>/cases.json (NOT
// produced by this code). N-AALP carries a foreign agent protocol by wrapping its message,
// octet-for-octet, in a signed N-AALP carriage object whose effect/safety/identity/audit apply, and
// whose foreign body is interpreted by a carriage CLASS — not a bespoke per-protocol mapping (R-14.1).
// Five structured classes (JSONRPC, HTTP, MSG, STREAM, DOC) plus a universal OPAQUE class make any
// protocol carriable immediately on an experimental protocol id with no registration. The foreign field
// is carried VERBATIM and MUST NOT be re-serialized (R-14.4); the carriage object's signer remains the
// authority — a foreign principal never becomes an N-AALP authorization identity (R-14.6).
//
// CORPUS-GRADED (pure), per class subdir: the carriage body {1..6} byte-for-byte, and the round-trip
// identity — the foreign message recovers byte-identical (octet-exact) from the encoded body (R-14.7,
// R-14.4).
// BEHAVIOURAL (isolation): an unrepresentable class is a typed MappingError (never a silent drop,
// R-14.8); a below-foreign failure reports NotDelivered and never a false "delivered" (R-14.8); the
// protocol-id ranges classify per §13.4; an OPAQUE undefined protocol carries on an experimental id.
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): identity containment (R-14.6) — a real
// Ed25519-signed carriage object's authority is its N-AALP signer, NOT the foreign principal named
// inside the foreign bytes, which survive octet-exact through the full sign→serialize→decode cycle. PHP
// is PURE-ONLY for ML-DSA; the reference signs with ML-DSA on the Public floor, so the signature is
// demonstrated here with Ed25519 (envelope.signWithEd25519 + Cose signature verify).
//
// Written test-first: Naalp\Carriage is absent until Carriage.php lands, so this fails RED with a fatal
// "class not found"; truncating the recovered foreign in carriageFromValue flips the per-class
// "<class> foreign recovered octet-exact" round-trip checks.
//
// Run:  php -d extension=sodium -d extension=intl test/carriage_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Carriage;
use Naalp\CarriageBody;
use Naalp\NaalpObject;
use Naalp\Cbor;
use Naalp\Cose;
use Naalp\Envelope;
use Naalp\U;
use Naalp\B;

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

/** Walk up to the repository's shared PER-CLASS corpus (the independent oracle) for a class dir. */
function carriage_vectors(string $dir): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . "/vectors/carriage/$dir/cases.json";
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/carriage/$dir/cases.json not found");
}

echo "carriage conformance (PHP) — graded vs vectors/carriage/<class>/cases.json (per-class oracle)\n";

// 1. per-class byte parity + round-trip identity (octet-exact foreign) against each class's own oracle.
$classDirs = [
    "jsonrpc" => Carriage::CLASS_JSONRPC,
    "http" => Carriage::CLASS_HTTP,
    "msg" => Carriage::CLASS_MSG,
    "stream" => Carriage::CLASS_STREAM,
    "doc" => Carriage::CLASS_DOC,
    "opaque" => Carriage::CLASS_OPAQUE,
];
foreach ($classDirs as $dir => $wantClass) {
    $c = carriage_vectors($dir);
    check("$dir class code == oracle", (string) $c["class"], (string) $wantClass);
    $foreign = hex2bin($c["foreign_hex"]);
    $cb = Carriage::carry($c["protocol_id"], $c["class"], $c["content_type"], hex2bin($c["correlation_hex"]), $c["method"], $foreign);
    check("$dir carriage body == oracle", bin2hex($cb->bytes()), $c["body_hex"]);
    // round-trip: decode the carriage body and recover the foreign octets EXACTLY (R-14.7). This is the
    // load-bearing octet-for-octet property (R-14.4) — the mutation target.
    $rec = Carriage::carriageFromValue(Cbor::decode($cb->bytes()));
    check("$dir foreign recovered octet-exact", bin2hex($rec->foreign), $c["foreign_hex"]);
    check("$dir class recovered == oracle", (string) $rec->klass, (string) $c["class"]);
    check("$dir protocol_id recovered == oracle", (string) $rec->protocolId, (string) $c["protocol_id"]);
    check("$dir method recovered == oracle", $rec->method, $c["method"]);
}

// 2. R-18.6 — an OPAQUE undefined protocol carries on an EXPERIMENTAL protocol id (no registration),
//    byte-exact, and recovers an arbitrary binary blob unchanged.
$op = carriage_vectors("opaque");
check("opaque protocol id is experimental", Carriage::protocolRange($op["protocol_id"]), "experimental");
$blob = "\x00\x01\x02\xff\xfe\x7f\x80";
$cbOp = Carriage::carry($op["protocol_id"], Carriage::CLASS_OPAQUE, 1, "", "", $blob);
$recOp = Carriage::carriageFromValue(Cbor::decode($cbOp->bytes()));
check("opaque blob recovered octet-exact", bin2hex($recOp->foreign), bin2hex($blob));

// 3. §13.4 — the protocol-id ranges classify per the design boundaries.
$ranges = [0x00 => "reserved", 0x01 => "standards", 0x0F => "standards", 0x10 => "experimental", 0x7F => "experimental", 0x80 => "private", 0xFF => "private", 0x100 => "invalid"];
foreach ($ranges as $id => $want) {
    check("protocol range " . sprintf("0x%02x", $id), Carriage::protocolRange($id), $want);
}

// 4. R-14.8 — an unrepresentable class is a typed MappingError, never a silent drop.
check("unknown class rejected (MappingError)", err_kind(fn() => Carriage::carry(0x10, 99, 0, "", "x", "y")), "MappingError");
// and a body carrying an unknown class parses to a MappingError, not silently.
$badClassBody = (new CarriageBody(0x10, 99, 0, "", "x", "y"))->bytes();
check("unknown-class body rejected (MappingError)", err_kind(fn() => Carriage::carriageFromValue(Cbor::decode($badClassBody))), "MappingError");

// 5. R-14.8 — a below-foreign failure reports NotDelivered and never a false "delivered".
check("failed delivery reports NotDelivered", err_kind(fn() => Carriage::report(false)), "NotDelivered");
check("successful delivery reports delivered", Carriage::report(true)->delivered ? "true" : "false", "true");

// 6. the class-name vocabulary; an out-of-range code is "unknown".
foreach ($classDirs as $dir => $code) {
    check("class name of $code", strtolower(Carriage::className($code)), $dir);
}
check("unknown class name", Carriage::className(99), "unknown");

// 7. R-14.6 identity containment (ED25519-DEMONSTRATED, isolation): a real Ed25519-signed carriage
//    object's authority is its N-AALP SIGNER, never the foreign principal named inside the foreign
//    bytes, which survive octet-exact through the full sign→serialize→decode cycle.
$seed = str_repeat("\x50", 32);
$pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
$foreignPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x51", 32)));
$foreignMsg = '{"jsonrpc":"2.0","method":"tools/call","params":{"from":"attacker-principal"}}';
$cb = Carriage::carry(0x01, Carriage::CLASS_JSONRPC, 0, "\x01\x02\x03\x04", "tools/call", $foreignMsg);
$o = new NaalpObject(kind: 0, channel: 13, signer: $pk, created: 100, effect: 0, body: $cb->toValue(), profile: Cose::PROFILE_PUBLIC);
// the authority is the N-AALP signer, NOT the foreign principal.
check("carriage authority == N-AALP signer", bin2hex(Carriage::authority($o)), bin2hex($pk));
check("authority does not leak the foreign principal", str_contains(Carriage::authority($o), "attacker-principal") ? "leaked" : "clean", "clean");
// sign end-to-end with real Ed25519 and confirm the signature; a tampered signature and a foreign key fail.
$signed = Envelope::signWithEd25519($o, $seed);
[$prot, $payload, $sig] = Cose::parseSign1Raw($signed);
$tbs = Cose::toBeSignedRaw($prot, $payload);
check("signed carriage object verifies", Cose::ed25519Verify($pk, $tbs, $sig) ? "true" : "false", "true");
$badSig = $sig;
$badSig[0] = $badSig[0] ^ "\x01";
check("tampered carriage signature rejected", Cose::ed25519Verify($pk, $tbs, $badSig) ? "true" : "false", "false");
check("foreign key rejected", Cose::ed25519Verify($foreignPk, $tbs, $sig) ? "true" : "false", "false");
// recover the signer (field 5) and body (field 10) from the SIGNED bytes; the foreign survives octet-exact.
$bodyMap = Cbor::decode($payload);
$recSigner = null;
$recBody = null;
foreach ($bodyMap->pairs as [$k, $v]) {
    if ($k instanceof U && $k->v === Envelope::FIELD_SIGNER && $v instanceof B) {
        $recSigner = $v->v;
    }
    if ($k instanceof U && $k->v === Envelope::FIELD_BODY) {
        $recBody = $v;
    }
}
check("recovered signer is the authority (not the foreign principal)", bin2hex((string) $recSigner), bin2hex($pk));
$recCarriage = Carriage::carriageFromValue($recBody);
check("foreign survives octet-exact through the signed object", $recCarriage->foreign, $foreignMsg);
check("foreign still carries the (non-authoritative) principal", str_contains($recCarriage->foreign, "attacker-principal") ? "present" : "absent", "present");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
