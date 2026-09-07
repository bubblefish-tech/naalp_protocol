<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) known-answer + fail-closed tests
// for the PHP SDK.
//
// Mutation-surviving properties:
//   1. BYTE PARITY -- Envelope::signRotationObject over the fixed worked fixture reproduces the
//      Go/Rust/oracle bytes: the SHA-256 of the 6798-byte tag-98 object is pinned and equals the Go
//      rotation.sign reference (PHP == Go == Rust == Python == oracle on the whole two-leg object).
//      PHP's rotation legs are signed AND verified via MlDsa (PHP-FFI to OpenSSL >= 3.5), unlike
//      Envelope::verify()'s structural-only pure-ML-DSA path, so the full crypto round trip is real.
//   2. Round-trip -- Envelope::verifyRotationObject accepts a co-signed rotation (both legs, old
//      then new).
//   3. Fail-closed reject family -- a tag-18 single-signature rotation, a dropped old leg, a
//      wrong-key old leg, a tag-98 object on a non-rotation (channel,kind), and a Sovereign verifier
//      over a rotation whose OLD key is below the profile floor are ALL rejected with the named kind.
//
// Run: php -d extension=sodium -d extension=intl -d ffi.enable=1 -d extension=ffi
//          test/rotation_test.php   (from impl/php/). Exit code 0 = all checks passed.
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Naalp;
use Naalp\NaalpObject;
use Naalp\Envelope;
use Naalp\EnvelopeError;
use Naalp\Cose;
use Naalp\MlDsa;
use Naalp\U;
use Naalp\T;
use Naalp\M;

$OLD_SEED = str_repeat("\x0B", 32);       // old ML-DSA-65 key
$NEW_SEED = str_repeat("\x16", 32);       // new ML-DSA-65 key (go-forward)
$FLOOR_OLD_SEED = str_repeat("\x21", 32); // below-floor old ML-DSA-65 key (33)
$FLOOR_NEW_SEED = str_repeat("\x2C", 32); // go-forward ML-DSA-87 key (44)
// SHA-256 of the 6798-byte tag-98 rotation object for the fixed worked fixture; byte-identical to
// the Go rotation.sign reference and tools/rotation_oracle.py (a cross-language, non-circular
// anchor, not a PHP-only self-check).
const ROTATION_OBJECT_SHA256 = "298d5d5bac8a0bf556541784f3090ac7300897858e883dc3ab6e7625bc418194";
const ROTATION_SIGNER = "SIGNER_NEW";
const ROTATION_NOT_BEFORE = 1785000000000;

$fails = 0;
function check(string $name, bool $ok, string $detail = ""): void
{
    global $fails;
    if ($ok) {
        echo "  ok   $name\n";
    } else {
        $fails++;
        echo "  FAIL $name" . ($detail !== "" ? "  $detail" : "") . "\n";
    }
}

/** Reject $fn with EnvelopeError($expectedKind, ...); records a check() either way. */
function expectRejects(string $name, string $expectedKind, callable $fn): void
{
    try {
        $fn();
        check($name, false, "expected $expectedKind, no exception thrown");
    } catch (EnvelopeError $e) {
        check($name, $e->kind === $expectedKind, "got {$e->kind}, want $expectedKind");
    }
}

/** field-10 naalp-rotation body {1: old_id, 2: new_id, 3: not_before} */
function rotationRecord(): M
{
    return new M([
        [new U(1), new T("signer-old")],
        [new U(2), new T("signer-new")],
        [new U(3), new U(ROTATION_NOT_BEFORE)],
    ]);
}

function rotationWorkedObject(int $profile = Cose::PROFILE_PUBLIC): NaalpObject
{
    return Naalp::object(
        kind: 0, channel: 3, signer: ROTATION_SIGNER, created: ROTATION_NOT_BEFORE, effect: 2,
        body: rotationRecord(), profile: $profile,
    );
}

function rotationKindOk(int $ch, int $k): bool
{
    return $ch === 3 && $k === 0;
}

echo "rotation KAT (PHP)\n";

if (!MlDsa::available()) {
    echo "  SKIP all rotation checks: ML-DSA unavailable (" . MlDsa::unavailableReason() . ")\n";
    echo "PASS (skipped)\n";
    exit(0);
}

// 1. byte parity with the Go/Rust/oracle reference.
$obj = Envelope::signRotationObject(rotationWorkedObject(), Cose::ALG_MLDSA65, $OLD_SEED, Cose::ALG_MLDSA65, $NEW_SEED);
check("object length is 6798", \strlen($obj) === 6798, "got " . \strlen($obj));
check("object sha256 matches the reference", \hash("sha256", $obj) === ROTATION_OBJECT_SHA256,
    "rotation object diverged from the Go/Rust/oracle reference bytes");

// 2. round-trip accept.
$oldPk = MlDsa::keygenFromSeed($OLD_SEED, Cose::ALG_MLDSA65);
$newPk = MlDsa::keygenFromSeed($NEW_SEED, Cose::ALG_MLDSA65);
$obj2 = Envelope::signRotationObject(rotationWorkedObject(), Cose::ALG_MLDSA65, $OLD_SEED, Cose::ALG_MLDSA65, $NEW_SEED);
$o = Envelope::verifyRotationObject(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $oldPk, Cose::ALG_MLDSA65, $newPk,
    'rotationKindOk', $obj2);
check("roundtrip channel/kind", $o->channel === 3 && $o->kind === 0);

// 3. a channel-3/kind-0 object signed as a normal single-signature COSE_Sign1 (tag 18) is a
// rotation missing the old-key co-signature -> the general verify() rejects RotationUnauthorized.
expectRejects("tag-18 single-sig rejected", "RotationUnauthorized", function () use ($NEW_SEED, $newPk) {
    $o = rotationWorkedObject();
    $payload = Envelope::buildPayload($o); // sets id
    $prot = Envelope::protectedHeader(Cose::ALG_MLDSA65, $o->signer, $o->profile);
    $tbs = Cose::toBeSignedRaw($prot, $payload);
    $sig = MlDsa::sign($NEW_SEED, $tbs, Cose::ALG_MLDSA65);
    $signed = Cose::assembleSign1Raw($prot, $payload, $sig); // tag-18
    Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $newPk, 'rotationKindOk', $signed);
});

// 4. the mutation anchor: dropping the old leg (one leg) MUST be rejected RotationUnauthorized.
// Disabling the exactly-two-legs check in verifyRotationObject flips this test.
expectRejects("old leg dropped rejected", "RotationUnauthorized", function () use ($OLD_SEED, $NEW_SEED, $oldPk, $newPk) {
    $obj = Envelope::signRotationObject(rotationWorkedObject(), Cose::ALG_MLDSA65, $OLD_SEED, Cose::ALG_MLDSA65, $NEW_SEED);
    [$bodyProt, $payload, $legs] = Cose::parseSignRaw($obj);
    $oneLeg = Cose::assembleSignRaw($bodyProt, $payload, [$legs[1]]); // keep only the new leg
    Envelope::verifyRotationObject(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $oldPk, Cose::ALG_MLDSA65, $newPk,
        'rotationKindOk', $oneLeg);
});

// 5. both legs signed by the NEW key -> the trusted old key cannot verify slot 0.
expectRejects("old leg wrong key rejected", "RotationUnauthorized", function () use ($NEW_SEED, $oldPk, $newPk) {
    $obj = Envelope::signRotationObject(rotationWorkedObject(), Cose::ALG_MLDSA65, $NEW_SEED, Cose::ALG_MLDSA65, $NEW_SEED);
    Envelope::verifyRotationObject(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $oldPk, Cose::ALG_MLDSA65, $newPk,
        'rotationKindOk', $obj);
});

// 6. a tag-98 object built over a non-rotation (channel 4, kind 2) is UnknownKind.
expectRejects("non-rotation kind rejected", "UnknownKind", function () use ($OLD_SEED, $NEW_SEED, $oldPk, $newPk) {
    $o = new NaalpObject(kind: 2, channel: 4, signer: ROTATION_SIGNER, created: ROTATION_NOT_BEFORE,
        effect: 2, body: new T("hello"), profile: Cose::PROFILE_PUBLIC);
    $payload = Envelope::buildPayload($o); // sets id
    $bodyProt = Envelope::protectedHeader(Cose::ALG_MLDSA65, $o->signer, $o->profile);
    $oldLeg = Cose::signatureLeg($bodyProt, Cose::ALG_MLDSA65, $OLD_SEED, $payload);
    $newLeg = Cose::signatureLeg($bodyProt, Cose::ALG_MLDSA65, $NEW_SEED, $payload);
    $obj = Cose::assembleSignRaw($bodyProt, $payload, [$oldLeg, $newLeg]);
    Envelope::verifyRotationObject(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $oldPk, Cose::ALG_MLDSA65, $newPk,
        fn($c, $k) => true, $obj);
});

// 7. old=ML-DSA-65 (level 3), new=ML-DSA-87 (level 5), Sovereign floor 5 -> the sub-floor OLD leg
// yields ProfileDowngrade under the ratified fail-closed default.
expectRejects("sovereign old leg floor rejected", "ProfileDowngrade", function () use ($FLOOR_OLD_SEED, $FLOOR_NEW_SEED) {
    $oldPk = MlDsa::keygenFromSeed($FLOOR_OLD_SEED, Cose::ALG_MLDSA65);
    $newPk = MlDsa::keygenFromSeed($FLOOR_NEW_SEED, Cose::ALG_MLDSA87);
    $obj = Envelope::signRotationObject(rotationWorkedObject(Cose::PROFILE_SOVEREIGN), Cose::ALG_MLDSA65,
        $FLOOR_OLD_SEED, Cose::ALG_MLDSA87, $FLOOR_NEW_SEED);
    Envelope::verifyRotationObject(Cose::PROFILE_SOVEREIGN, Cose::ALG_MLDSA65, $oldPk, Cose::ALG_MLDSA87, $newPk,
        'rotationKindOk', $obj);
});

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
