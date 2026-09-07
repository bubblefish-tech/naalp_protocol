<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// NA-IETF-1 producing-boundary disclosure (the OPTIONAL, self-asserted ext key 15, §2.5.4) known-answer
// tests for the PHP SDK, graded against the independent oracle (tools/producing_boundary_oracle.py ->
// vectors/producing_boundary/cases.json), i.e. PHP == Go == Rust == Python == oracle.
//
// Five properties, mirroring impl/go/envelope/producing_boundary_test.go and
// impl/python/tests/test_producing_boundary.py, all mutation-surviving:
//   1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body bytes;
//      a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; and the parsed
//      disclosure (present/kind/boundary/reporting) matches. Non-canonical sub-map bytes are rejected
//      NonCanonical at the codec.
//   2. UNDER SIGNATURE -- the disclosure is folded into the SIGNER's signed body: splicing a different
//      boundary into a signed object (keeping its id + signature) is rejected.
//   3. READER ROUND-TRIP -- set/get carries the value; the field is OPTIONAL; the setter DROPS a
//      reporting-boundary under observed (an observer relays from no one).
//   4. MALFORMED IGNORED [MUTATION ANCHOR] -- a well-formed object carrying a MALFORMED disclosure
//      (reporting under observed) in the non-critical ext map still verifies and is NOT surfaced.
//   5. CEXT REJECTED [MUTATION ANCHOR] -- the disclosure in the CRITICAL cext map is UnknownCriticalExt.
//
// Run: php -d extension=sodium -d extension=intl -d ffi.enable=1 -d extension=ffi
//          test/producing_boundary_test.php   (from impl/php/). Exit code 0 = all checks passed.
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Cbor;
use Naalp\Cose;
use Naalp\Envelope;
use Naalp\MlDsa;
use Naalp\NaalpObject;
use Naalp\ProducingBoundary;
use Naalp\U;
use Naalp\B;
use Naalp\T;
use Naalp\M;

// A LOCAL test signing seed -- the verdict is a sign+verify round-trip, not a reproduction of the
// oracle's signature (full_hex is the object BODY, not a signed COSE object, so byte-parity needs no
// signing).
$SEED = pack("C*", ...range(0, 31));

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

/** Assert that $fn throws SOME Throwable (kind unspecified -- a splice is rejected at whichever check
 * catches it first, mirroring the generic assertRaises(Exception)/verr==nil style the Python and Go
 * worked examples use for this property). */
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

function kindOk(int $ch, int $k): bool
{
    return true;
}

function findPbVector(): ?string
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/producing_boundary/cases.json';
        if (is_file($p)) {
            return $p;
        }
        $d = dirname($d);
    }
    return null;
}

/** Build the shared base object (fields 2..10) from the corpus's LOGICAL fields -- never from the
 * oracle hex, so a constant encoder diverges from the pinned bytes. */
function baseObject(array $corpus): NaalpObject
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
        body: new T($base["body_str"]),
        tier: $base["tier"],
        profile: $base["profile"],
        causes: $causes,
    );
}

/** Build the ext[15]/cext[15] sub-map DIRECTLY from the case's logical fields (the ONLY variable per
 * case) using the WIRE sub-keys 1/2/3, reproducing the oracle bytes for well-formed AND malformed
 * values -- the malformed cases cannot be built via Envelope::setProducingBoundary by design, so they
 * are constructed here. */
function applyPlacement(NaalpObject $o, array $tc): void
{
    if ($tc["placement"] === "absent") {
        return;
    }
    $sub = [];
    if (($tc["boundary_hex"] ?? null) !== null) {
        $sub[] = [new U(1), new B(hex2bin($tc["boundary_hex"]))];
    }
    if (($tc["kind"] ?? null) !== null) {
        $sub[] = [new U(2), new U($tc["kind"])];
    }
    if (($tc["reporting_hex"] ?? null) !== null) {
        $sub[] = [new U(3), new B(hex2bin($tc["reporting_hex"]))];
    }
    $ext = new M([[new U(Envelope::PRODUCING_BOUNDARY_KEY), new M($sub)]]);
    if ($tc["placement"] === "ext") {
        $o->ext = $ext;
    } elseif ($tc["placement"] === "cext") {
        $o->cext = $ext;
    } else {
        throw new \RuntimeException("unknown placement " . $tc["placement"]);
    }
}

/** Full end-to-end pure-ML-DSA-65 sign of an object (build -> protected header -> sign -> assemble),
 * mirroring the tag-18 pattern rotation_test.php uses inline (there is no generic Envelope::sign() for
 * a pure object; only signWithEd25519/signComposite/signRotationObject exist). */
function signPure(NaalpObject $o, string $seed): string
{
    $payload = Envelope::buildPayload($o); // sets id
    $prot = Envelope::protectedHeader(Cose::ALG_MLDSA65, $o->signer, $o->profile);
    $tbs = Cose::toBeSignedRaw($prot, $payload);
    $sig = MlDsa::sign($seed, $tbs, Cose::ALG_MLDSA65);
    return Cose::assembleSign1Raw($prot, $payload, $sig);
}

/** Sign a RAW payload (used for the negatives: a non-canonical sub-map inside an otherwise
 * well-formed body, built by hand from the oracle's payload_hex, not via buildPayload). */
function signRawPayload(NaalpObject $o, string $seed, string $payload): string
{
    $prot = Envelope::protectedHeader(Cose::ALG_MLDSA65, $o->signer, $o->profile);
    $tbs = Cose::toBeSignedRaw($prot, $payload);
    $sig = MlDsa::sign($seed, $tbs, Cose::ALG_MLDSA65);
    return Cose::assembleSign1Raw($prot, $payload, $sig);
}

echo "NA-IETF-1 producing-boundary disclosure KAT (PHP)\n";

if (!MlDsa::available()) {
    echo "  SKIP all producing-boundary checks: ML-DSA unavailable (" . MlDsa::unavailableReason() . ")\n";
    echo "PASS (skipped)\n";
    exit(0);
}

$vecPath = findPbVector();
if ($vecPath === null) {
    echo "  SKIP all producing-boundary checks: committed vector not present (standalone install)\n";
    echo "PASS (skipped)\n";
    exit(0);
}
$corpus = json_decode(file_get_contents($vecPath), true);
check("producing_boundary_key matches", (string) $corpus["producing_boundary_key"], (string) Envelope::PRODUCING_BOUNDARY_KEY);

$pk = MlDsa::keygenFromSeed($SEED, Cose::ALG_MLDSA65);

// 1. MATCHES ORACLE.
echo "\n1. MatchesOracle\n";
foreach ($corpus["cases"] as $tc) {
    $name = $tc["name"];

    // byte parity: body-without-id, content id, full body (all pre-signature).
    $o = baseObject($corpus);
    applyPlacement($o, $tc);
    check("$name body-no-id", bin2hex(Cbor::encode($o->bodyMap(false))), $tc["body_no_id_hex"]);
    $cid = $o->contentId();
    check("$name content-id", bin2hex($cid), $tc["content_id_hex"]);
    $o->id = $cid;
    check("$name full-body", bin2hex(Cbor::encode($o->bodyMap(true))), $tc["full_hex"]);

    // verdict: sign for real + verify offline; assert accept vs the named error.
    $o2 = baseObject($corpus);
    applyPlacement($o2, $tc);
    $signed = signPure($o2, $SEED);
    if ($tc["expect"] === "accept") {
        $got = Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'kindOk', $signed);
        [$pb, $present] = Envelope::producingBoundary($got);
        check("$name present", $present ? "true" : "false", $tc["present"] ? "true" : "false");
        if ($present && $tc["surfaced"] !== null) {
            $s = $tc["surfaced"];
            check("$name kind", (string) $pb->kind, (string) $s["kind"]);
            check("$name boundary", bin2hex($pb->boundary), $s["boundary_hex"]);
            $wantRep = $s["reporting_hex"] ?? "";
            check("$name reporting", bin2hex($pb->reporting ?? ""), $wantRep);
        }
    } else {
        expect_kind("$name verdict", function () use ($pk, $signed) {
            Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'kindOk', $signed);
        }, $tc["expect"]);
    }
}

// non-canonical disclosure bodies (sub-map keys out of order) are rejected at the CBOR layer.
foreach ($corpus["negatives"] ?? [] as $neg) {
    $o = baseObject($corpus);
    $payload = hex2bin($neg["payload_hex"]);
    $signed = signRawPayload($o, $SEED, $payload);
    expect_kind("negative_" . $neg["name"], function () use ($pk, $signed) {
        Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'kindOk', $signed);
    }, $neg["expect"]);
}

// 2. UNDER SIGNATURE.
echo "\n2. UnderSignature\n";
$o = baseObject($corpus);
Envelope::setProducingBoundary(
    $o,
    new ProducingBoundary(hex2bin("424f554e444152595f58"), Envelope::PRODUCING_BOUNDARY_OBSERVED)
);
$signed = signPure($o, $SEED);
$got = Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'kindOk', $signed);
[$pb, $present] = Envelope::producingBoundary($got);
check("under-signature read-back", ($present && $pb->kind === Envelope::PRODUCING_BOUNDARY_OBSERVED) ? "ok" : "fail", "ok");

// tamper: change boundary, keep the original id, reuse the original signature (a splice).
$tampered = baseObject($corpus);
Envelope::setProducingBoundary(
    $tampered,
    new ProducingBoundary(hex2bin("4f524947494e5f59"), Envelope::PRODUCING_BOUNDARY_OBSERVED)
);
$tampered->id = $o->id; // keep original content id -- a splice, not a re-sign
$payload = Cbor::encode($tampered->bodyMap(true));
[$prot, , $sig] = Cose::parseSign1Raw($signed);
$forged = Cose::assembleSign1Raw($prot, $payload, $sig);
expect_throws("under-signature tamper rejected", function () use ($pk, $forged) {
    Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'kindOk', $forged);
});

// 3. READER ROUND-TRIP.
echo "\n3. ReaderRoundTrip\n";
$o = baseObject($corpus);
[$_, $present] = Envelope::producingBoundary($o);
check("fresh object has no disclosure", $present ? "present" : "absent", "absent");
$x = hex2bin("424f554e444152595f58");
$y = hex2bin("4f524947494e5f59");

Envelope::setProducingBoundary($o, new ProducingBoundary($x, Envelope::PRODUCING_BOUNDARY_REPORTED, $y));
[$pb, $present] = Envelope::producingBoundary($o);
check("reported round-trip present", $present ? "true" : "false", "true");
check("reported round-trip kind", (string) $pb->kind, (string) Envelope::PRODUCING_BOUNDARY_REPORTED);
check("reported round-trip boundary", bin2hex($pb->boundary), bin2hex($x));
check("reported round-trip reporting", bin2hex($pb->reporting), bin2hex($y));

// the setter drops a reporting-boundary under observed: read-back has no reporting.
Envelope::setProducingBoundary($o, new ProducingBoundary($x, Envelope::PRODUCING_BOUNDARY_OBSERVED, $y));
[$pb, $present] = Envelope::producingBoundary($o);
check("observed round-trip present", $present ? "true" : "false", "true");
check("observed round-trip kind", (string) $pb->kind, (string) Envelope::PRODUCING_BOUNDARY_OBSERVED);
check("setter drops reporting under observed", $pb->reporting === null ? "null" : "notnull", "null");

// 4. MALFORMED IGNORED [MUTATION ANCHOR]: dropping the reporting-under-observed check in
// Envelope::producingBoundary() flips present false->true and this check ok->FAIL; that check is the
// observer-relays-from-no-one invariant.
echo "\n4. MalformedIgnored [MUTATION ANCHOR]\n";
$o = baseObject($corpus);
// malformed ext[15] = {1:X, 2:observed, 3:Y} built directly (the setter refuses to build it).
$o->ext = new M([[new U(Envelope::PRODUCING_BOUNDARY_KEY), new M([
    [new U(1), new B(hex2bin("424f554e444152595f58"))],
    [new U(2), new U(Envelope::PRODUCING_BOUNDARY_OBSERVED)],
    [new U(3), new B(hex2bin("4f524947494e5f59"))],
])]]);
$signed = signPure($o, $SEED);
$got = Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'kindOk', $signed); // must NOT throw (may-ignore)
echo "  ok   malformed disclosure still verifies (no exception)\n";
[$_, $present] = Envelope::producingBoundary($got);
check("malformed disclosure not surfaced", $present ? "present" : "absent", "absent");

// 5. CEXT REJECTED [MUTATION ANCHOR]: the disclosure in the CRITICAL cext map (field 12) is an
// unrecognized critical extension -> UnknownCriticalExt, fail-closed. A disclosure must never
// masquerade as a must-understand gate.
echo "\n5. CextRejected [MUTATION ANCHOR]\n";
$o = baseObject($corpus);
$o->cext = new M([[new U(Envelope::PRODUCING_BOUNDARY_KEY), new M([
    [new U(1), new B(hex2bin("424f554e444152595f58"))],
    [new U(2), new U(Envelope::PRODUCING_BOUNDARY_OBSERVED)],
])]]);
$signed = signPure($o, $SEED);
expect_kind("cext producing-boundary rejected", function () use ($pk, $signed) {
    Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk, 'kindOk', $signed);
}, "UnknownCriticalExt");

echo "\n" . ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
