<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP error object + numeric error-code registry conformance for the PHP SDK (design.md §3.5,
// R3.3/R3.4, T3.3), byte-parity-checked against the same known-answer bytes the Go/Rust reference
// implementations assert (impl/go/naalperror/naalperror.go, impl/rust/src/naalperror.rs) and the
// shared conformance corpus (vectors/conformance/corpus.json, ops error.name_for_code /
// error.encode / error.decode).
//
// Covers: the ordered 129-entry registry (index<->code, both directions), the KAT deterministic-CBOR
// encode() bytes, the two dual-carriage rules (a registered code + disagreeing name is rejected
// Malformed; an unregistered code is accepted opaque), and the closed-grammar structural rejects
// (non-map, non-integer key, wrong-typed field, unknown field key, missing code/name).
//
// Written test-first: Naalp\NaalpError is absent until NaalpError.php lands, so this fails RED with
// a fatal "class not found"; dropping the dual-carriage name-agreement check in decode() flips the
// mismatch case from Malformed to a false accept, and dropping the "default: throw Malformed" arm
// in the field switch flips the unknown-field-key case to a silent accept.
//
// Run: php -d extension=sodium -d extension=intl test/naalperror_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\A;
use Naalp\Cbor;
use Naalp\M;
use Naalp\NaalpError;
use Naalp\T;
use Naalp\U;

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

function err_kind(callable $fn): string
{
    try {
        $fn();
        return "no-error";
    } catch (\Throwable $e) {
        return \property_exists($e, 'kind') ? $e->kind : \get_class($e);
    }
}

echo "naalp-error conformance (PHP)\n";

// 1. registry size + full index<->code round trip in both directions (§3.5 fields-of-record order).
check("registry has 132 entries", (string) \count(NaalpError::NAMES), "132");
$indexOk = true;
foreach (NaalpError::NAMES as $i => $n) {
    if (NaalpError::codeForName($n) !== $i + 1) {
        $indexOk = false;
    }
    [$name, $reg] = NaalpError::nameForCode($i + 1);
    if (!$reg || $name !== $n) {
        $indexOk = false;
    }
}
check("every NAMES[i] round-trips codeForName/nameForCode to i+1", $indexOk ? "ok" : "mismatch", "ok");
check("nameForCode(1) == NonCanonical", NaalpError::nameForCode(1)[0], "NonCanonical");
check("nameForCode(119) == RebindUnauthorized", NaalpError::nameForCode(119)[0], "RebindUnauthorized");
check("code 0 is unregistered", NaalpError::nameForCode(0)[1] ? "registered" : "unregistered", "unregistered");
check("code 133 (one past last) is unregistered", NaalpError::nameForCode(133)[1] ? "registered" : "unregistered", "unregistered");
check("codeForName(unknown) is null", NaalpError::codeForName("NoSuchName") === null ? "null" : "non-null", "null");
check("STANDARDS_MAX == 0x7FFF", (string) NaalpError::STANDARDS_MAX, (string) 0x7FFF);

// 2. MANDATORY KATs (byte parity vs the Go/Rust reference and vectors/conformance/corpus.json
//    error.encode tcId 1 and 5).
check("encode(1, NonCanonical) KAT", \bin2hex(NaalpError::encode(1, "NonCanonical")), "a20101026c4e6f6e43616e6f6e6963616c");
check("encode(52, NotDelivered) KAT", \bin2hex(NaalpError::encode(52, "NotDelivered")), "a2011834026c4e6f7444656c697665726564");

// additional corpus KATs (error.encode tcId 2,3,4,6,7,8): the wire varint-length transitions
// (code 3 one-byte, code 22 one-byte-24..255, code 60/61/119 in the 0x18 range).
check("encode(3, Malformed) KAT", \bin2hex(NaalpError::encode(3, "Malformed")), "a2010302694d616c666f726d6564");
check("encode(11, WrongAudience) KAT", \bin2hex(NaalpError::encode(11, "WrongAudience")), "a2010b026d57726f6e6741756469656e6365");
check("encode(22, BadSignature) KAT", \bin2hex(NaalpError::encode(22, "BadSignature")), "a20116026c4261645369676e6174757265");
check("encode(60, ScopeOverlapConflict) KAT", \bin2hex(NaalpError::encode(60, "ScopeOverlapConflict")), "a201183c027453636f70654f7665726c6170436f6e666c696374");
check("encode(61, ReconcileMismatch) KAT", \bin2hex(NaalpError::encode(61, "ReconcileMismatch")), "a201183d02715265636f6e63696c654d69736d61746368");
check("encode(119, RebindUnauthorized) KAT", \bin2hex(NaalpError::encode(119, "RebindUnauthorized")), "a20118770272526562696e64556e617574686f72697a6564");

// full grammar (detail + subject present): corpus error.encode tcId 9.
$subj = \hex2bin("2030000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
check(
    "encode(22, BadSignature, detail, subject) KAT",
    \bin2hex(NaalpError::encode(22, "BadSignature", "verifier reason: see log", $subj)),
    "a40116026c4261645369676e6174757265037818766572696669657220726561736f6e3a20736565206c6f670458322030000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
);

// 3. decode round-trips the KAT bodies (corpus error.decode tcId 1..4).
$d1 = NaalpError::decode(\hex2bin("a20101026c4e6f6e43616e6f6e6963616c"));
check("decode KAT1 code", (string) $d1->code, "1");
check("decode KAT1 name", $d1->name, "NonCanonical");
$d2 = NaalpError::decode(\hex2bin("a2011834026c4e6f7444656c697665726564"));
check("decode KAT2 code", (string) $d2->code, "52");
check("decode KAT2 name", $d2->name, "NotDelivered");
$d3 = NaalpError::decode(\hex2bin("a20118770272526562696e64556e617574686f72697a6564"));
check("decode KAT3 code", (string) $d3->code, "119");
check("decode KAT3 name", $d3->name, "RebindUnauthorized");

// full-grammar round trip: detail + subject survive decode.
$fg = NaalpError::decode(NaalpError::encode(22, "BadSignature", "reason", \str_repeat("\x00", 50)));
check("full grammar decode detail", $fg->detail, "reason");
check("full grammar decode subject length", (string) \strlen((string) $fg->subject), "50");

// 4. dual-carriage rule (a): a registered code whose name disagrees with the registry is Malformed.
//    code 22 == BadSignature, but encoded with name "NotDelivered" -> Malformed. Mutation: dropping
//    the name-agreement check in decode() flips this to a false accept.
$mismatch = NaalpError::encode(22, "NotDelivered");
check("registered code + wrong name rejected (Malformed)", err_kind(fn() => NaalpError::decode($mismatch)), "Malformed");
// corpus error.decode tcId 5 exact body: code=22(BadSignature) encoded with name "NotDelivered".
check("corpus tcId5 body rejected (Malformed)", err_kind(fn() => NaalpError::decode(\hex2bin("a20116026c4e6f7444656c697665726564"))), "Malformed");

// 5. dual-carriage rule (b): an unregistered code is accepted opaque, name diagnostic only. Corpus
//    error.decode tcId 6 exact body (code=60000, name="SomeFutureError").
$opaque = NaalpError::decode(\hex2bin("a20119ea60026f536f6d654675747572654572726f72"));
check("unknown code accepted opaque, code", (string) $opaque->code, "60000");
check("unknown code accepted opaque, name", $opaque->name, "SomeFutureError");
// same, built via encode() rather than decoded from the fixed corpus bytes.
$opaque2 = NaalpError::decode(NaalpError::encode(60000, "SomeFutureError"));
check("unknown code (built) accepted opaque, code", (string) $opaque2->code, "60000");
check("unknown code (built) accepted opaque, name", $opaque2->name, "SomeFutureError");

// 6. closed-grammar structural rejects (all Malformed). Mutation: removing any of these individual
//    type/presence checks in decode() flips the corresponding case to a false accept or a PHP fatal.
check("not-a-map body rejected (Malformed)", err_kind(fn() => NaalpError::decode(Cbor::encode(new A([new U(1), new U(2)])))), "Malformed");
check("non-integer key rejected (Malformed)", err_kind(fn() => NaalpError::decode(Cbor::encode(new M([
    [new T("code"), new U(1)],
    [new U(2), new T("NonCanonical")],
])))), "Malformed");
check("wrong-typed field 1 (code as tstr) rejected (Malformed)", err_kind(fn() => NaalpError::decode(Cbor::encode(new M([
    [new U(1), new T("nope")],
    [new U(2), new T("NonCanonical")],
])))), "Malformed");
check("wrong-typed field 2 (name as uint) rejected (Malformed)", err_kind(fn() => NaalpError::decode(Cbor::encode(new M([
    [new U(1), new U(1)],
    [new U(2), new U(5)],
])))), "Malformed");
check("wrong-typed field 3 (detail as uint) rejected (Malformed)", err_kind(fn() => NaalpError::decode(Cbor::encode(new M([
    [new U(1), new U(1)],
    [new U(2), new T("NonCanonical")],
    [new U(3), new U(9)],
])))), "Malformed");
check("wrong-typed field 4 (subject as tstr) rejected (Malformed)", err_kind(fn() => NaalpError::decode(Cbor::encode(new M([
    [new U(1), new U(1)],
    [new U(2), new T("NonCanonical")],
    [new U(4), new T("not-bytes")],
])))), "Malformed");
check("unknown field key rejected (Malformed)", err_kind(fn() => NaalpError::decode(Cbor::encode(new M([
    [new U(1), new U(1)],
    [new U(2), new T("NonCanonical")],
    [new U(5), new U(9)],
])))), "Malformed");
check("missing code rejected (Malformed)", err_kind(fn() => NaalpError::decode(Cbor::encode(new M([
    [new U(2), new T("NonCanonical")],
])))), "Malformed");
check("missing name rejected (Malformed)", err_kind(fn() => NaalpError::decode(Cbor::encode(new M([
    [new U(1), new U(1)],
])))), "Malformed");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
