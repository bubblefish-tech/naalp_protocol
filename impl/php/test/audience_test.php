<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The object-audience (field 13, §2.5.3) known-answer + gate tests for the PHP SDK.
//
// Three properties, all mutation-surviving:
//   1. BYTE MATCH -- an audience-bearing object reproduces the independent oracle's content id,
//      payload, protected header, and to-be-signed bytes (vectors/envelope/cases.json
//      object_with_audience), i.e. PHP == Go == Rust == Python == TS == Ruby == the oracle.
//      Pure encoding (no ML-DSA), so it runs everywhere.
//   2. checkAudience -- the three-branch point-of-use gate.
//   3. consumeObject -- the gate is enforced at the consume choke point BEFORE the compare-and-set:
//      a wrong/absent audience is rejected WrongAudience with NO ledger append; an unnamed ledger
//      refuses LedgerUnsigned; a correct audience consumes once (second -> AlreadyConsumed).
//
// Run:  php -d extension=sodium test/audience_test.php   (from impl/php/). Exit 0 = pass.
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Naalp;
use Naalp\Envelope;
use Naalp\Approval;
use Naalp\NaalpObject;
use Naalp\T;

const A_SIGNER_HEX = "5349474e45525f41";           // "SIGNER_A" (oracle's fixed synthetic signer)
const A_AUDIENCE = "consuming-authority-xyz";

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

/** Assert that $fn throws a Throwable whose ->kind === $wantKind. */
function expect_kind(string $name, callable $fn, string $wantKind): void
{
    global $fails;
    try {
        $fn();
        $fails++;
        echo "  FAIL $name (no exception; expected $wantKind)\n";
    } catch (\Throwable $e) {
        $got = $e->kind ?? get_class($e);
        if ($got === $wantKind) {
            echo "  ok   $name\n";
        } else {
            $fails++;
            echo "  FAIL $name\n       got kind  $got\n       want kind $wantKind\n";
        }
    }
}

function audience_object(): NaalpObject
{
    return Naalp::object(
        kind: 2, channel: 4, signer: hex2bin(A_SIGNER_HEX), created: 1785000000000, effect: 2,
        body: new T("hello"), profile: 1, audience: A_AUDIENCE,
    );
}

function gate_obj(string $aud): NaalpObject
{
    return Naalp::object(
        kind: 2, channel: 4, signer: hex2bin(A_SIGNER_HEX), created: 0, effect: 0,
        body: new T("x"), profile: 1, audience: $aud,
    );
}

function find_envelope_vector(): ?string
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/envelope/cases.json';
        if (is_file($p)) {
            return $p;
        }
        $d = dirname($d);
    }
    return null;
}

echo "object-audience KAT + gate (PHP)\n";

// 1. BYTE MATCH vs the independent oracle (object_with_audience).
$vec = find_envelope_vector();
if ($vec !== null) {
    $want = json_decode(file_get_contents($vec), true)["object_with_audience"];
    $obj = audience_object();
    $payload = Naalp::buildPayload($obj);   // sets $obj->id
    $prot = Naalp::protectedHeader(Naalp::ALG_MLDSA65, hex2bin(A_SIGNER_HEX), 1);
    $tbs = Naalp::toBeSigned($prot, $payload);
    check("content id", bin2hex(Naalp::contentId($obj)), $want["content_id_hex"]);
    check("payload", bin2hex($payload), $want["payload_hex"]);
    check("protected header", bin2hex($prot), $want["protected_hex"]);
    check("to-be-signed", bin2hex($tbs), $want["tobesigned_hex"]);
} else {
    echo "  skip byte-match (committed oracle vector not present — standalone install)\n";
}

// omit-when-empty is additive: a no-audience object carries no field 13 (0x0d)
$plain = Naalp::object(kind: 2, channel: 4, signer: hex2bin(A_SIGNER_HEX), created: 1785000000000,
    effect: 2, body: new T("hello"), profile: 1);
$plainBody = bin2hex(\Naalp\Cbor::encode($plain->bodyMap(false)));
check("omit-when-empty (no 0x0d tail)", substr($plainBody, -4) === "0d" ? "has0d" : "clean", "clean");

// 2. checkAudience -- the three branches.
Envelope::checkAudience(gate_obj("authority-A"), "authority-A", true);   // pass (no throw)
echo "  ok   checkAudience consume-once correct passes\n";
Envelope::checkAudience(gate_obj(""), "authority-A", false);             // pass (no throw)
echo "  ok   checkAudience unrestricted absent passes\n";
Envelope::checkAudience(gate_obj("authority-A"), "authority-A", false);  // pass (no throw)
echo "  ok   checkAudience unrestricted correct passes\n";
expect_kind("checkAudience consume-once foreign rejected", fn() => Envelope::checkAudience(gate_obj("authority-B"), "authority-A", true), "WrongAudience");
expect_kind("checkAudience consume-once absent rejected", fn() => Envelope::checkAudience(gate_obj(""), "authority-A", true), "WrongAudience");
expect_kind("checkAudience foreign rejected even unrestricted", fn() => Envelope::checkAudience(gate_obj("authority-B"), "authority-A", false), "WrongAudience");

// 3. consumeObject -- the choke point (a fresh WAL per case).
$aid = pack("C*", ...range(0, 49));

function with_ledger(string $authority, callable $fn): void
{
    $path = tempnam(sys_get_temp_dir(), "naalp-audience-");
    $led = Approval::openLedger($path, $authority);
    try {
        $fn($led);
    } finally {
        $led->close();
        @unlink($path);
    }
}

with_ledger("authority-A", function ($led) use ($aid) {
    expect_kind("consumeObject wrong audience rejected", fn() => $led->consumeObject(gate_obj("authority-B"), $aid, "consumer"), "WrongAudience");
    check("consumeObject wrong audience: no append", (string) $led->len(), "0");
});
with_ledger("authority-A", function ($led) use ($aid) {
    expect_kind("consumeObject absent audience rejected", fn() => $led->consumeObject(gate_obj(""), $aid, "consumer"), "WrongAudience");
    check("consumeObject absent audience: no append", (string) $led->len(), "0");
});
with_ledger("authority-A", function ($led) use ($aid) {
    $led->consumeObject(gate_obj("authority-A"), $aid, "consumer");
    check("consumeObject correct audience consumes once", (string) $led->len(), "1");
    expect_kind("consumeObject second consume rejected", fn() => $led->consumeObject(gate_obj("authority-A"), $aid, "consumer"), "AlreadyConsumed");
});
with_ledger("", function ($led) use ($aid) {
    expect_kind("consumeObject unnamed ledger refuses", fn() => $led->consumeObject(gate_obj("authority-A"), $aid, "consumer"), "LedgerUnsigned");
});

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
