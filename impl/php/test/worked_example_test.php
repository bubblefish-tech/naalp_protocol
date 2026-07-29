<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The full-object known-answer test for the PHP SDK. The reference worked object (fixed seed
// 0x2a*32, ML-DSA-65) has a fixed content id, payload, protected header, and ToBeSigned; PHP
// reproduces each of those PURE bytes and asserts them equal to the independent, committed vector
// (vectors/worked/example.json — produced by the Go/Rust reference oracle, NOT by PHP: non-circular
// per F3). PHP cannot produce the ML-DSA signature (PURE-ONLY), so the full signed_object_hex is not
// reproduced here; a real Ed25519 sign/verify round-trip is exercised instead.
//
// Dependency-free: run with `php -d extension=sodium -d extension=intl test/worked_example_test.php`
// from impl/php/. Exit code 0 = all checks passed; 1 = a mismatch (the KAT failed).
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Naalp;
use Naalp\Cose;
use Naalp\U;
use Naalp\T;
use Naalp\B;
use Naalp\M;

// short, self-contained KAT anchors (from vectors/worked/example.json)
const SIGNER_ID = "bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua";
const CONTENT_ID_HEX = "2030192922f9be80623bea1c689ddfe91dc15303abc851c8811b86cf9e53b837b5cc99d9c17e3acf95279f55e48203f79134";
const ARGS_ID_HEX = "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff";

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

/** Build the reference worked object (Governance Approval, channel 4 / kind 1). */
function worked_object(): \Naalp\NaalpObject
{
    $approval = new M([
        [new U(1), new B(hex2bin(ARGS_ID_HEX))],
        [new U(2), new T(SIGNER_ID)],
        [new U(3), new U(2)],
        [new U(4), new B("\x01\x02\x03\x04\x05\x06\x07\x08")],
        [new U(5), new U(1785000000000)],
    ]);
    return Naalp::object(
        kind: 1, channel: 4, signer: SIGNER_ID, created: 1785000000000, effect: 2,
        body: $approval, profile: Naalp::PROFILE_PUBLIC,
    );
}

/** Walk up from this dir to find the committed worked-example vector, if present. */
function find_vector(): ?string
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/worked/example.json';
        if (is_file($p)) {
            return $p;
        }
        $d = dirname($d);
    }
    return null;
}

echo "worked-example KAT (PHP)\n";

// 1. content id — the pure identity of the worked object.
$obj = worked_object();
check("content id", bin2hex(Naalp::contentId($obj)), CONTENT_ID_HEX);

// 2. byte-exact vs the committed independent vector (payload / protected header / ToBeSigned).
$vec = find_vector();
if ($vec !== null) {
    $want = json_decode(file_get_contents($vec), true);
    $obj2 = worked_object();
    $payload = Naalp::buildPayload($obj2);                  // sets $obj2->id
    $prot = Naalp::protectedHeader(Naalp::ALG_MLDSA65, SIGNER_ID, Naalp::PROFILE_PUBLIC);
    $tbs = Naalp::toBeSigned($prot, $payload);
    check("payload body", bin2hex($payload), $want["payload_body_hex"]);
    check("protected header", bin2hex($prot), $want["protected_hdr_hex"]);
    check("to-be-signed", bin2hex($tbs), $want["to_be_signed_hex"]);
    check("content id (vector)", bin2hex(Naalp::contentId($obj2)), $want["content_id_hex"]);
} else {
    echo "  skip byte-exact-vs-vector (committed vector not present — standalone install)\n";
}

// 3. a real Ed25519 sign/verify round-trip (crypto exercised in isolation).
$seed = str_repeat("\x2a", 32);
$pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
$sid = Naalp::signerId(Naalp::ALG_ED25519, $pk);
$eobj = Naalp::object(
    kind: 1, channel: 4, signer: $sid, created: 1785000000000, effect: 2,
    body: new M([[new U(1), new T("hi")]]), profile: Naalp::PROFILE_PUBLIC,
);
$signed = Naalp::signWithEd25519($eobj, $seed);
[$p2, $pl2, $s2] = Cose::parseSign1Raw($signed);
check("ed25519 round-trip", Cose::ed25519Verify($pk, Cose::toBeSignedRaw($p2, $pl2), $s2) ? "true" : "false", "true");

// tampering is rejected at the signature layer: flip the last byte of the signature.
$tsig = $s2;
$tsig[strlen($tsig) - 1] = $tsig[strlen($tsig) - 1] ^ "\x01";
check("ed25519 tamper rejected", Cose::ed25519Verify($pk, Cose::toBeSignedRaw($p2, $pl2), $tsig) ? "true" : "false", "false");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
