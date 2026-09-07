<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Emit the worked-example N-AALP object's deterministic ToBeSigned bytes as one
// line of lowercase hex. PHP is PURE-ONLY: it has no ML-DSA-65 signer, so it cannot
// produce the full signed_object_hex. It CAN produce every pre-signature byte -- the
// COSE Sig_structure (protected header + payload) -- which is exactly what the
// cross-port object gate compares for a pure-only port, against the authority's
// to_be_signed_hex. Same construction as test/worked_example_test.php. Prints ONLY
// the hex so the recorder reads it unambiguously.
//
//   php -d extension=sodium -d extension=intl tools/naalp_worked_example.php   (from impl/php/)

require __DIR__ . '/../src/bootstrap.php';

use Naalp\Naalp;
use Naalp\U;
use Naalp\T;
use Naalp\B;
use Naalp\M;

// The signer id is a fixed KAT anchor (PHP cannot derive it from an ML-DSA pubkey).
const SIGNER_ID = "bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua";
const ARGS_ID_HEX = "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff";

$approval = new M([
    [new U(1), new B(hex2bin(ARGS_ID_HEX))],
    [new U(2), new T(SIGNER_ID)],
    [new U(3), new U(2)],
    [new U(4), new B("\x01\x02\x03\x04\x05\x06\x07\x08")],
    [new U(5), new U(1785000000000)],
]);
$obj = Naalp::object(
    kind: 1, channel: 4, signer: SIGNER_ID, created: 1785000000000, effect: 2,
    body: $approval, profile: Naalp::PROFILE_PUBLIC,
);
$payload = Naalp::buildPayload($obj);
$prot = Naalp::protectedHeader(Naalp::ALG_MLDSA65, SIGNER_ID, Naalp::PROFILE_PUBLIC);
$tbs = Naalp::toBeSigned($prot, $payload);
echo bin2hex($tbs) . "\n";
