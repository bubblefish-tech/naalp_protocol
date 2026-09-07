<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// T1.3 recheck + T1.6 per-signer counter / duplication-detection known-answer tests for the PHP
// SDK, graded against the independent oracles (tools/recheck_oracle.py -> vectors/recheck/cases.json;
// tools/signer_counter_oracle.py -> vectors/signer_counter/cases.json), i.e. PHP == Go == Rust ==
// oracle. Mirrors impl/go/envelope/envelope_test.go (the T1.3 section) and
// impl/go/envelope/signer_counter_test.go.
//
// Properties covered:
//   1. Recheck MATCHES ORACLE -- byte parity + accept/reject verdict for every recheck case.
//   2. Recheck REJECT PATH IS REAL [MUTATION ANCHOR] -- critical unknown -> UnknownCriticalExt;
//      critical known -> accept; non-critical unknown -> ignored/accept.
//   3. Recheck READER ROUND TRIP -- Recheck()/SetRecheck() carry id+criticality; cext beats ext.
//   4. SignerCounter MATCHES ORACLE -- byte parity + accept/reject verdict for every counter case.
//   5. SignerCounter UNDER SIGNATURE -- the counter is folded into the signer's signed body.
//   6. SignerCounter READER ROUND TRIP -- present is keyed on the key, not the value.
//   7. SignerCounter ABSENT VALIDATES [MUTATION ANCHOR] -- the field is OPTIONAL.
//   8. DetectSignerDuplication MATCHES ORACLE -- every detection scenario.
//   9. DetectSignerDuplication ONE SEQUENCE NOT FLAGGED [MUTATION ANCHOR] -- detection requires two
//      conflicting sequences to physically meet.
//  10. DetectSignerDuplication TWO CONFLICTING FLAGGED -- surfaces both content ids.
//  11. DetectSignerDuplication FORWARD-ONLY CONSISTENT NOT FLAGGED -- different positions/signers.
//
// Run: php -d extension=sodium -d extension=intl -d ffi.enable=1 -d extension=ffi
//          test/envelope_test.php   (from impl/php/). Exit code 0 = all checks passed.
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Cbor;
use Naalp\Cose;
use Naalp\Envelope;
use Naalp\MlDsa;
use Naalp\NaalpObject;
use Naalp\U;
use Naalp\M;

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

/** Assert that $fn does NOT throw. */
function expect_ok(string $name, callable $fn): void
{
    global $fails;
    try {
        $fn();
        echo "  ok   $name\n";
    } catch (\Throwable $e) {
        $fails++;
        $k = $e->kind ?? get_class($e);
        echo "  FAIL $name (unexpected $k)\n";
    }
}

/** Assert that $fn throws SOME Throwable (kind unspecified). */
function expect_throws(string $name, callable $fn): void
{
    global $fails;
    try {
        $fn();
        $fails++;
        echo "  FAIL $name (no exception thrown)\n";
    } catch (\Throwable $e) {
        $got = $e->kind ?? get_class($e);
        echo "  ok   $name ($got)\n";
    }
}

function acceptKind(int $ch, int $k): bool
{
    return $ch === 4 && $k === 2;
}

function findVector(string $rel): ?string
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/' . $rel;
        if (is_file($p)) {
            return $p;
        }
        $d = dirname($d);
    }
    return null;
}

/** Decode a decimal string into the wrapped signed-64-bit PHP int Cbor's U type expects (the value
 * modulo 2^64, represented as a negative PHP int when >= 2^63). Uses bcmath so a uint64-max literal
 * decoded via JSON_BIGINT_AS_STRING loses no precision (a plain (int) cast on an overflowed float
 * would). */
function u64FromDecimalString(string $s): int
{
    $mod = \bcmod($s, '18446744073709551616'); // 2^64
    if (\bccomp($mod, '9223372036854775808') >= 0) { // >= 2^63
        $mod = \bcsub($mod, '18446744073709551616');
    }
    return (int) $mod;
}

/** Normalizes a JSON-decoded field that may be null, a plain PHP int (small values), or a decimal
 * string (values json_decode(..., JSON_BIGINT_AS_STRING) could not fit in a PHP int) into ?int. */
function toInt(mixed $raw): ?int
{
    if ($raw === null) {
        return null;
    }
    if (\is_int($raw)) {
        return $raw;
    }
    return u64FromDecimalString((string) $raw);
}

/** The inverse of the wrap: format a Cbor U-typed PHP int as its unsigned decimal value, for
 * readable FAIL messages on values >= 2^63 (which are carried as negative PHP ints). */
function fmtU64(int $v): string
{
    if ($v >= 0) {
        return (string) $v;
    }
    return \bcadd((string) $v, '18446744073709551616');
}

function loadJson(string $path): array
{
    $raw = \file_get_contents($path);
    $v = \json_decode($raw, true, 512, \JSON_BIGINT_AS_STRING);
    if (!\is_array($v)) {
        throw new \RuntimeException("bad vector JSON at $path");
    }
    return $v;
}

/** Sign a full object with a single deterministic ML-DSA-65 key, via the generic Envelope::sign(). */
function signPure(NaalpObject $o, string $seed): string
{
    return Envelope::sign($o, Cose::ALG_MLDSA65, $seed);
}

/** Sign a RAW payload (used for the negatives: a non-canonical body built by hand from the oracle's
 * payload_hex, not via Envelope::sign/buildPayload). */
function signRawPayload(NaalpObject $o, string $seed, string $payload): string
{
    $prot = Envelope::protectedHeader(Cose::ALG_MLDSA65, $o->signer, $o->profile);
    $tbs = Cose::toBeSignedRaw($prot, $payload);
    $sig = MlDsa::sign($seed, $tbs, Cose::ALG_MLDSA65);
    return Cose::assembleSign1Raw($prot, $payload, $sig);
}

echo "N-AALP T1.3/T1.6 envelope recheck + signer-counter + duplication KAT (PHP)\n";

if (!MlDsa::available()) {
    echo "  SKIP all checks: ML-DSA unavailable (" . MlDsa::unavailableReason() . ")\n";
    echo "PASS (skipped)\n";
    exit(0);
}

$recheckPath = findVector('recheck/cases.json');
$counterPath = findVector('signer_counter/cases.json');
if ($recheckPath === null || $counterPath === null) {
    echo "  SKIP all checks: committed vectors not present (standalone install)\n";
    echo "PASS (skipped)\n";
    exit(0);
}

$SEED = pack("C*", ...range(0, 31));
$pk = MlDsa::keygenFromSeed($SEED, Cose::ALG_MLDSA65);

// ==================================================================================
// T1.3 recheck
// ==================================================================================

$rc = loadJson($recheckPath);
check("recheck_key matches", (string) toInt($rc["recheck_key"]), (string) Envelope::RECHECK_KEY);

/** Build the shared base object (fields 2..10) from the corpus's LOGICAL fields -- never from the
 * oracle hex, so a constant encoder diverges from the pinned bytes. */
function baseRecheckObject(array $corpus): NaalpObject
{
    $base = $corpus["base_object"];
    $causes = [];
    foreach ($base["causes_hex"] as $h) {
        $causes[] = hex2bin($h);
    }
    return new NaalpObject(
        kind: $base["kind"],
        channel: $base["channel"],
        signer: hex2bin($base["signer_hex"]),
        created: $base["created"],
        effect: $base["effect"],
        body: new \Naalp\T($base["body_str"]),
        tier: $base["tier"],
        profile: $base["profile"],
        causes: $causes,
    );
}

/** Apply the case's recheck placement -- the ONLY variable per case. */
function applyRecheckPlacement(NaalpObject $o, string $placement, ?int $procId): void
{
    switch ($placement) {
        case "cext":
            Envelope::setRecheck($o, $procId, true);
            break;
        case "ext":
            Envelope::setRecheck($o, $procId, false);
            break;
        case "ext_empty":
            $o->ext = new M([]); // present but empty (no recheck) -- distinct bytes from absent
            break;
        case "absent":
            break;
        default:
            throw new \RuntimeException("unknown placement $placement");
    }
}

// 1. MATCHES ORACLE.
echo "\n1. Recheck MatchesOracle\n";
foreach ($rc["cases"] as $tc) {
    $name = $tc["name"];
    $procId = toInt($tc["procedure_id"]);

    // byte parity: body-without-id, content id, full body (all pre-signature).
    $o = baseRecheckObject($rc);
    applyRecheckPlacement($o, $tc["placement"], $procId);
    check("$name body-no-id", bin2hex(Cbor::encode($o->bodyMap(false))), $tc["body_no_id_hex"]);
    $cid = $o->contentId();
    check("$name content-id", bin2hex($cid), $tc["content_id_hex"]);
    $o->id = $cid;
    check("$name full-body", bin2hex(Cbor::encode($o->bodyMap(true))), $tc["full_hex"]);

    // verdict: sign for real and verify offline; assert accept vs the named error.
    $o2 = baseRecheckObject($rc);
    applyRecheckPlacement($o2, $tc["placement"], $procId);
    $signed = signPure($o2, $SEED);
    if ($tc["expect"] === "accept") {
        $got = Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $signed);
        [$rid, $present, $critical] = Envelope::recheck($got);
        check("$name present", $present ? "true" : "false", $tc["present"] ? "true" : "false");
        if ($present) {
            check("$name id", (string) $rid, (string) $procId);
            check("$name critical", $critical ? "true" : "false", $tc["critical"] ? "true" : "false");
        }
    } else {
        expect_kind("$name verdict", function () use ($pk, $signed) {
            Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $signed);
        }, $tc["expect"]);
    }
}

// non-canonical recheck bodies (cext keys out of order) are rejected at the CBOR layer.
foreach ($rc["negatives"] ?? [] as $neg) {
    $o = baseRecheckObject($rc);
    $payload = hex2bin($neg["payload_hex"]);
    $signed = signRawPayload($o, $SEED, $payload);
    expect_kind("negative_" . $neg["name"], function () use ($pk, $signed) {
        Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $signed);
    }, $neg["expect"]);
}

// 2. REJECT PATH IS REAL [MUTATION ANCHOR]: a CRITICAL recheck naming an UNKNOWN procedure id MUST
// be rejected with UnknownCriticalExt. If the isKnownRecheckProcedure/verify() reject branch is
// mutated to accept, this test flips pass->fail. A known critical procedure and a non-critical
// unknown procedure both verify, proving the reject is specific to unknown-under-critical.
echo "\n2. Recheck RejectPathIsReal [MUTATION ANCHOR]\n";
$criticalUnknown = baseRecheckObject($rc);
Envelope::setRecheck($criticalUnknown, 99, true); // unknown id, critical
$su = signPure($criticalUnknown, $SEED);
expect_kind("critical unknown recheck rejected", function () use ($pk, $su) {
    Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $su);
}, "UnknownCriticalExt");

$criticalKnown = baseRecheckObject($rc);
Envelope::setRecheck($criticalKnown, Envelope::RECHECK_WALK_CAUSES, true); // known id, critical
$sk = signPure($criticalKnown, $SEED);
expect_ok("known critical recheck verifies", function () use ($pk, $sk) {
    Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $sk);
});

$nonCritUnknown = baseRecheckObject($rc);
Envelope::setRecheck($nonCritUnknown, 99, false); // unknown id, non-critical -> ignored
$sn = signPure($nonCritUnknown, $SEED);
expect_ok("unknown non-critical recheck ignored", function () use ($pk, $sn) {
    Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $sn);
});

// 3. READER ROUND TRIP: Recheck()/SetRecheck() carry the id and criticality, and cext (critical)
// takes precedence over ext (non-critical) when both name the key.
echo "\n3. Recheck ReaderRoundTrip\n";
$o = baseRecheckObject($rc);
[$_id, $present, $_crit] = Envelope::recheck($o);
check("fresh object has no recheck", $present ? "present" : "absent", "absent");
Envelope::setRecheck($o, Envelope::RECHECK_VERIFY_COSE_SIGN1, false);
[$id, $present, $critical] = Envelope::recheck($o);
check("non-critical recheck present", $present ? "true" : "false", "true");
check("non-critical recheck id", (string) $id, (string) Envelope::RECHECK_VERIFY_COSE_SIGN1);
check("non-critical recheck critical", $critical ? "true" : "false", "false");
Envelope::setRecheck($o, Envelope::RECHECK_REPLAY_CONSUME_CHECK, true); // critical wins over the ext entry
[$id, $present, $critical] = Envelope::recheck($o);
check("critical recheck wins present", $present ? "true" : "false", "true");
check("critical recheck wins id", (string) $id, (string) Envelope::RECHECK_REPLAY_CONSUME_CHECK);
check("critical recheck wins critical", $critical ? "true" : "false", "true");

// ==================================================================================
// T1.6 per-signer forward-only counter + duplication detection
// ==================================================================================

$sc = loadJson($counterPath);
check("counter_key matches", (string) toInt($sc["counter_key"]), (string) Envelope::SIGNER_COUNTER_KEY);

/** Build the shared base object (fields 2..10), with an optional signer/body override -- never from
 * the oracle hex, so a constant encoder diverges. */
function baseCounterObject(array $corpus, string $signerHex, string $bodyStr): NaalpObject
{
    $base = $corpus["base_object"];
    $causes = [];
    foreach ($base["causes_hex"] as $h) {
        $causes[] = hex2bin($h);
    }
    $sh = $signerHex !== '' ? $signerHex : $base["signer_hex"];
    $bs = $bodyStr !== '' ? $bodyStr : $base["body_str"];
    return new NaalpObject(
        kind: $base["kind"],
        channel: $base["channel"],
        signer: hex2bin($sh),
        created: $base["created"],
        effect: $base["effect"],
        body: new \Naalp\T($bs),
        tier: $base["tier"],
        profile: $base["profile"],
        causes: $causes,
    );
}

/** Apply the case's counter placement -- the ONLY variable per case. */
function applyCounterPlacement(NaalpObject $o, string $placement, ?int $counter): void
{
    switch ($placement) {
        case "ext":
            Envelope::setSignerCounter($o, $counter);
            break;
        case "cext":
            // the counter placed in the CRITICAL map is an unrecognized critical extension.
            $o->cext = new M([[new U(Envelope::SIGNER_COUNTER_KEY), new U($counter)]]);
            break;
        case "ext_empty":
            $o->ext = new M([]); // present but empty (no counter) -- distinct bytes from absent
            break;
        case "absent":
            break;
        default:
            throw new \RuntimeException("unknown placement $placement");
    }
}

// 4. MATCHES ORACLE.
echo "\n4. SignerCounter MatchesOracle\n";
foreach ($sc["cases"] as $tc) {
    $name = $tc["name"];
    $counter = toInt($tc["counter"]);
    $signerHex = $tc["signer_hex"] ?? '';
    $bodyStr = $tc["body_str"] ?? '';

    $o = baseCounterObject($sc, $signerHex, $bodyStr);
    applyCounterPlacement($o, $tc["placement"], $counter);
    check("$name body-no-id", bin2hex(Cbor::encode($o->bodyMap(false))), $tc["body_no_id_hex"]);
    $cid = $o->contentId();
    check("$name content-id", bin2hex($cid), $tc["content_id_hex"]);
    $o->id = $cid;
    check("$name full-body", bin2hex(Cbor::encode($o->bodyMap(true))), $tc["full_hex"]);

    $o2 = baseCounterObject($sc, $signerHex, $bodyStr);
    applyCounterPlacement($o2, $tc["placement"], $counter);
    $signed = signPure($o2, $SEED);
    if ($tc["expect"] === "accept") {
        $got = Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $signed);
        [$seq, $present] = Envelope::signerCounter($got);
        check("$name present", $present ? "true" : "false", $tc["present"] ? "true" : "false");
        if ($present) {
            check("$name value", fmtU64($seq), fmtU64($counter));
        }
    } else {
        expect_kind("$name verdict", function () use ($pk, $signed) {
            Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $signed);
        }, $tc["expect"]);
    }
}

// non-canonical counter bodies (ext keys out of order) are rejected at the CBOR layer.
foreach ($sc["negatives"] ?? [] as $neg) {
    $o = baseCounterObject($sc, '', '');
    $payload = hex2bin($neg["payload_hex"]);
    $signed = signRawPayload($o, $SEED, $payload);
    expect_kind("negative_" . $neg["name"], function () use ($pk, $signed) {
        Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $signed);
    }, $neg["expect"]);
}

// 5. UNDER SIGNATURE: the counter is folded into the SIGNER's COSE_Sign1 signed input (ext, field
// 11, is part of the signed body): flipping the counter value in a signed object's payload breaks
// verification.
echo "\n5. SignerCounter UnderSignature\n";
$o = baseCounterObject($sc, '', '');
Envelope::setSignerCounter($o, 5);
$signed = signPure($o, $SEED);
$got = Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $signed);
[$seq, $present] = Envelope::signerCounter($got);
check("under-signature read-back", ($present && $seq === 5) ? "ok" : "fail", "ok");

// tamper: change the counter to 6 and re-encode WITHOUT re-signing; the object must be rejected (the
// content id no longer matches the signed body / the signature no longer covers it).
$tampered = baseCounterObject($sc, '', '');
Envelope::setSignerCounter($tampered, 6);
$tampered->id = $o->id; // keep the original (counter=5) content id -- a splice, not a re-sign
$payload = Cbor::encode($tampered->bodyMap(true));
[$prot, , $sig] = Cose::parseSign1Raw($signed);
$forged = Cose::assembleSign1Raw($prot, $payload, $sig);
expect_throws("under-signature tamper rejected", function () use ($pk, $forged) {
    Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $forged);
});

// 6. READER ROUND TRIP: SetSignerCounter/SignerCounter carry the value, the field is OPTIONAL, and a
// present counter of value 0 reads back present (present is keyed on the key, not the value).
echo "\n6. SignerCounter ReaderRoundTrip\n";
$o = baseCounterObject($sc, '', '');
[$_seq, $present] = Envelope::signerCounter($o);
check("fresh object has no counter", $present ? "present" : "absent", "absent");
Envelope::setSignerCounter($o, 42);
[$seq, $present] = Envelope::signerCounter($o);
check("counter round-trip present", $present ? "true" : "false", "true");
check("counter round-trip value", (string) $seq, "42");
Envelope::setSignerCounter($o, 0); // present with value zero
[$seq, $present] = Envelope::signerCounter($o);
check("present-zero counter present", $present ? "true" : "false", "true");
check("present-zero counter value", (string) $seq, "0");

// 7. ABSENT VALIDATES [MUTATION ANCHOR]: an object carrying NO counter Signs and Verifies. Making
// the field mandatory (e.g. adding a reject-if-absent check to verify()) flips this test pass->fail.
echo "\n7. SignerCounter AbsentValidates [MUTATION ANCHOR]\n";
$o = baseCounterObject($sc, '', '');
[$_seq, $present] = Envelope::signerCounter($o);
check("object built without a counter has none", $present ? "present" : "absent", "absent");
$signed = signPure($o, $SEED);
expect_ok("object with an absent counter verifies", function () use ($pk, $signed) {
    Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $signed);
});
$got = Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'acceptKind', $signed);
[$_seq, $present] = Envelope::signerCounter($got);
check("verified object reports no counter", $present ? "present" : "absent", "absent");

// 8. DETECTION MATCHES ORACLE: DetectSignerDuplication over every scenario in the independent
// oracle MUST reproduce the oracle's exact findings (signer, counter, and the SET of surfaced
// content ids).
echo "\n8. DetectSignerDuplication MatchesOracle\n";
foreach ($sc["detection"]["scenarios"] as $scenario) {
    $name = $scenario["name"];
    $objs = [];
    foreach ($scenario["objects"] as $ro) {
        $o = baseCounterObject($sc, $ro["signer_hex"], $ro["body_str"]);
        $counter = toInt($ro["counter"]);
        if ($counter !== null) {
            Envelope::setSignerCounter($o, $counter);
        }
        $cid = $o->contentId();
        check("$name scenario object content-id", bin2hex($cid), $ro["content_id_hex"]);
        $objs[] = $o;
    }
    $findings = Envelope::detectSignerDuplication($objs);
    check("$name findings count", (string) count($findings), (string) count($scenario["expect"]));
    foreach ($scenario["expect"] as $i => $want) {
        if (!isset($findings[$i])) {
            continue;
        }
        $f = $findings[$i];
        check("$name finding $i signer", bin2hex($f->signer), $want["signer_hex"]);
        check("$name finding $i counter", fmtU64($f->counter), fmtU64((int) toInt($want["counter"])));
        check("$name finding $i ids count", (string) count($f->ids), (string) count($want["ids_hex"]));
        foreach ($want["ids_hex"] as $j => $idHex) {
            if (!isset($f->ids[$j])) {
                continue;
            }
            check("$name finding $i id $j", bin2hex($f->ids[$j]), $idHex);
        }
    }
}

// 9. ONE SEQUENCE NOT FLAGGED [MUTATION ANCHOR]: a single sequence (one object per value) MUST NOT
// be flagged -- detection requires two conflicting sequences to physically meet. Relaxing the
// `count($idset) < 2` guard in Envelope::detectSignerDuplication to `< 1` flips this test
// pass->fail; that is the whole detection-not-prevention line.
echo "\n9. DetectSignerDuplication OneSequenceNotFlagged [MUTATION ANCHOR]\n";
$one = baseCounterObject($sc, '', 'holder');
Envelope::setSignerCounter($one, 5);
$f = Envelope::detectSignerDuplication([$one]);
check("one sequence alone must not be flagged", (string) count($f), "0");

$seqObjs = [];
foreach (["s1", "s2", "s3"] as $i => $body) {
    $o = baseCounterObject($sc, '', $body);
    Envelope::setSignerCounter($o, $i + 1);
    $seqObjs[] = $o;
}
$f = Envelope::detectSignerDuplication($seqObjs);
check("honest forward-only sequence must not be flagged", (string) count($f), "0");

// 10. TWO CONFLICTING FLAGGED: two DISTINCT objects, SAME signer id, SAME counter value, presented
// TOGETHER -> flagged once, surfacing BOTH content ids.
echo "\n10. DetectSignerDuplication TwoConflictingFlagged\n";
$holder = baseCounterObject($sc, '', 'holder');
Envelope::setSignerCounter($holder, 5);
$thief = baseCounterObject($sc, '', 'thief');
Envelope::setSignerCounter($thief, 5);
$f = Envelope::detectSignerDuplication([$holder, $thief]);
check("two conflicting sequences must be flagged once", (string) count($f), "1");
if (count($f) === 1) {
    check("finding counter", (string) $f[0]->counter, "5");
    check("finding ids count", (string) count($f[0]->ids), "2");
    $hid = $holder->contentId();
    $tid = $thief->contentId();
    $surfaced = \array_map('bin2hex', $f[0]->ids);
    \sort($surfaced);
    $wantSet = [\bin2hex($hid), \bin2hex($tid)];
    \sort($wantSet);
    check("finding surfaces both ids", \implode(',', $surfaced), \implode(',', $wantSet));
}

// 11. FORWARD-ONLY CONSISTENT NOT FLAGGED: two objects from one signer at DIFFERENT positions are
// not flagged; nor are two different signers at one position.
echo "\n11. DetectSignerDuplication ForwardOnlyConsistentNotFlagged\n";
$a5 = baseCounterObject($sc, '', 'holder');
Envelope::setSignerCounter($a5, 5);
$a6 = baseCounterObject($sc, '', 'next');
Envelope::setSignerCounter($a6, 6);
$f = Envelope::detectSignerDuplication([$a5, $a6]);
check("forward-only-consistent sequence must not be flagged", (string) count($f), "0");

$b5 = baseCounterObject($sc, '5349474e45525f42', 'other'); // SIGNER_B
Envelope::setSignerCounter($b5, 5);
$f = Envelope::detectSignerDuplication([$a5, $b5]);
check("different signers at one value must not be flagged", (string) count($f), "0");

echo "\n" . ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
