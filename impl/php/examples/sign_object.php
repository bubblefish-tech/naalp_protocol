<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// examples/sign_object.php — build, sign, and verify a full N-AALP object on the PHP pure surface.
//
// Two demonstrations, both real (no mocks):
//   1. Ed25519 (RFC 8032) via ext-sodium: build an object, sign it end-to-end, and check the
//      signature round-trips at the COSE layer (PHP's from-key signing leg; see Crypto scope).
//   2. The ML-DSA-65 worked object: build the exact Governance Approval object from the fixed
//      worked-example signer id and reproduce its content id byte-for-byte (the pure surface). PHP
//      cannot derive the ML-DSA signer from the seed, so the signer id is a fixed KAT anchor from
//      vectors/worked/example.json; the pure content id is identical to Go/Rust/Python.
//
// Run (from impl/php/):  php -d extension=sodium -d extension=intl examples/sign_object.php
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Naalp;
use Naalp\Cose;
use Naalp\U;
use Naalp\T;
use Naalp\B;
use Naalp\M;

// --- 1. Ed25519: a real from-key sign -> assemble -> COSE-layer verify round-trip ---
$seed = str_repeat("\x2a", 32);                       // a real 32-byte key seed in production
$pk   = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
$sid  = Naalp::signerId(Naalp::ALG_ED25519, $pk);
echo "ed25519 signer    $sid\n";

$obj = Naalp::object(
    kind: 1, channel: 4, signer: $sid, created: 1785000000000, effect: 2,
    body: new M([[new U(1), new T("hello, agent")]]), profile: Naalp::PROFILE_PUBLIC,
);
$signed = Naalp::signWithEd25519($obj, $seed);
[$prot, $payload, $sig] = Cose::parseSign1Raw($signed);
$ok = Cose::ed25519Verify($pk, Cose::toBeSignedRaw($prot, $payload), $sig);
echo "ed25519 signed    " . strlen($signed) . " bytes, cose-verify=" . ($ok ? "true" : "false") . "\n";
if (!$ok) {
    fwrite(STDERR, "FAIL: ed25519 signature did not verify\n");
    exit(1);
}

// --- 2. The ML-DSA-65 worked object: reproduce its content id (pure) ---
$signerId = "bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua";
$argsId = hex2bin("20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff");
$approval = new M([
    [new U(1), new B($argsId)],
    [new U(2), new T($signerId)],
    [new U(3), new U(2)],                                 // granted effect: non_idempotent_write
    [new U(4), new B("\x01\x02\x03\x04\x05\x06\x07\x08")], // nonce
    [new U(5), new U(1785000000000)],                     // not_after (epoch ms)
]);
$wobj = Naalp::object(
    kind: 1, channel: 4, signer: $signerId, created: 1785000000000, effect: 2,
    body: $approval, profile: Naalp::PROFILE_PUBLIC,
);
echo "mldsa   content-id " . bin2hex(Naalp::contentId($wobj)) . "\n";
echo "OK\n";
