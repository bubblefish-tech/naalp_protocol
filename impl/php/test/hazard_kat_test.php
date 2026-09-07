<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Manufacturing Add-ons Component F (naalp-hazard) known-answer test for the PHP SDK, graded
// against the independent, non-circular oracle vectors/hazard/cases.json (tools/hazard_oracle.py)
// -- mirroring impl/rust/naalp-hazard/src/lib.rs's test module and impl/csharp/test/HazardKatTest.cs
// / impl/java/.../HazardKatTest.java, i.e. PHP == Rust == oracle.
//
// Run: php -d extension=sodium -d extension=intl -d ffi.enable=1 -d memory_limit=-1
//          test/hazard_kat_test.php   (from impl/php/). Exit code 0 = all checks passed.

declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';

use Naalp\Hazard;
use Naalp\HazardAuthorization;
use Naalp\HazardClaim;
use Naalp\HazardEnvelope;
use Naalp\HazardWindow;
use Naalp\SpatialBounds;
use Naalp\Cbor;
use Naalp\U;

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

/** Walk up from this dir to the repository's shared corpus at $rel (the independent oracle). */
function shared_vectors(string $rel): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/' . $rel;
        if (\is_file($p)) {
            return \json_decode(\file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = \dirname($d);
    }
    throw new \RuntimeException("vectors/$rel not found");
}

/**
 * A `from_code` row's "code" cell is null, a JSON number, or (for the > 2^63-1 case) a decimal
 * string -- never a float64 decoder anywhere, so the exact wire value survives. Convert the
 * decimal string to the SAME two's-complement uint64 bit-pattern PHP int that Naalp\U::$v uses
 * (Cbor.php's own convention: a value >= 2^63 is a negative PHP int), via bcmath so no precision
 * is lost between "2^63" and "PHP_INT_MAX".
 */
function code_from_json(mixed $v): ?int
{
    if ($v === null) {
        return null;
    }
    if (\is_int($v)) {
        return $v;
    }
    // decimal string, in [0, 2^64-1]
    if (\bccomp($v, '9223372036854775807') <= 0) {
        return (int) $v;
    }
    return (int) \bcsub($v, '18446744073709551616'); // wrap into the signed 64-bit bit pattern
}

function axes_from(array $axesEl): array
{
    $out = [];
    foreach ($axesEl as $pair) {
        $out[] = [(int) $pair[0], (int) $pair[1]];
    }
    return $out;
}

function env_from(array $o): HazardEnvelope
{
    return new HazardEnvelope(
        new SpatialBounds((string) $o['frame'], axes_from($o['axes'])),
        (int) $o['speed_bound_mm_s'],
        new HazardWindow((int) $o['not_before'], (int) $o['not_after']),
    );
}

echo "naalp-hazard KAT (PHP, Manufacturing Add-ons Component F)\n";

$c = shared_vectors('hazard/cases.json');

// ---------------------------------------------------------------------------------------------
// F2: fail-closed class decode (mutation anchor: a constant CLASS_NONE return would pass none of
// the non-zero cases; a constant CLASS_MOTION_IN_SHARED_SPACE would fail the exact 0..3 cases).
// ---------------------------------------------------------------------------------------------
echo "\n1. from_code fail-closed decode\n";

foreach ($c['from_code'] as $row) {
    $input = code_from_json($row['code']);
    $want = (int) $row['class'];
    $got = Hazard::classFromCode($input);
    check("from_code(" . ($input === null ? "null" : $input) . ") == $want ({$row['class_name']})",
        $got === $want, "got $got");
}

// Explicit oracle-independent assertions of the two named fail-closed cases (F2).
check("absent must normalize to the highest class",
    Hazard::classFromCode(null) === Hazard::CLASS_MOTION_IN_SHARED_SPACE);
check("unknown code must normalize to the highest class",
    Hazard::classFromCode(9) === Hazard::CLASS_MOTION_IN_SHARED_SPACE);
check("an out-of-range code (PHP_INT_MAX bit pattern) must still normalize, not throw",
    Hazard::classFromCode(\PHP_INT_MAX) === Hazard::CLASS_MOTION_IN_SHARED_SPACE);

// The five in-range codes decode to themselves, never collapsing to the default.
for ($code = 0; $code <= 4; $code++) {
    check("from_code($code) round-trips to itself", Hazard::classFromCode($code) === $code);
}

// ---------------------------------------------------------------------------------------------
// byte-level: encode matches the independent oracle (=> PHP == Rust == C# == Java once graded).
// ---------------------------------------------------------------------------------------------
echo "\n2. claim/authorization bytes match oracle\n";

foreach ($c['bodies'] as $row) {
    $class = Hazard::classFromCode((int) $row['class']);
    $e = env_from($row);
    $claim = new HazardClaim($class, $e);
    $auth = new HazardAuthorization($class, $e);
    $name = $row['name'];
    $want = $row['body_hex'];
    check("claim $name body_hex", \bin2hex($claim->bytes()) === $want,
        "got " . \bin2hex($claim->bytes()));
    check("authorization $name body_hex (same shape as claim)", \bin2hex($auth->bytes()) === $want,
        "got " . \bin2hex($auth->bytes()));
    check("claim $name content_id_hex", \bin2hex($claim->contentId()) === $row['content_id_hex'],
        "got " . \bin2hex($claim->contentId()));
}

// ---------------------------------------------------------------------------------------------
// Round-trip: fromValue(toValue(x)) == x for every oracle body.
// ---------------------------------------------------------------------------------------------
echo "\n3. round-trip matches oracle\n";

foreach ($c['bodies'] as $row) {
    $class = Hazard::classFromCode((int) $row['class']);
    $e = env_from($row);
    $claim = new HazardClaim($class, $e);
    $got = HazardClaim::fromValue($claim->toValue());
    check("round-trip {$row['name']} class", $got->class === $claim->class);
    check("round-trip {$row['name']} bytes", \bin2hex($got->bytes()) === \bin2hex($claim->bytes()));
}

// ---------------------------------------------------------------------------------------------
// F3: coverage matrix (mutation anchor: a constant "always authorized" fails the deny rows; a
// constant "always denied" fails the allow rows).
// ---------------------------------------------------------------------------------------------
echo "\n4. coverage matches oracle\n";

$rows = $c['coverage'];
check("coverage matrix is non-empty", \count($rows) > 0);
$allows = 0;
$denies = 0;
foreach ($rows as $row) {
    $claim = new HazardClaim(
        Hazard::classFromCode(code_from_json($row['claim_class_code'])),
        env_from($row['claim_envelope']),
    );
    $grant = new HazardAuthorization(
        Hazard::classFromCode(code_from_json($row['grant_class_code'])),
        env_from($row['grant_envelope']),
    );
    $wantOk = (bool) $row['authorized'];
    $name = $row['name'];
    if ($wantOk) {
        $allows++;
        check("coverage $name -> authorized", err_kind(fn() => Hazard::hazardAuthorized($claim, $grant)) === "no-error");
    } else {
        $denies++;
        check("coverage $name -> HazardNotCovered",
            err_kind(fn() => Hazard::hazardAuthorized($claim, $grant)) === "HazardNotCovered");
    }
}
check("matrix needs both allows and denies", $allows > 0 && $denies > 0, "allows=$allows denies=$denies");

// ---------------------------------------------------------------------------------------------
// F2/F4's "absent hazard" behavioural vector, at the OBJECT level (no claim at all): distinct
// from an in-range-but-mismatched class, and distinct from an unrecognized class byte inside a
// present claim (covered by the coverage matrix's normalized rows).
// ---------------------------------------------------------------------------------------------
echo "\n5. absent claim denies with distinct error\n";

$grant = new HazardAuthorization(
    Hazard::CLASS_TOOL_ACTUATION,
    new HazardEnvelope(
        new SpatialBounds("cell-7/world", [[0, 1000], [0, 1000], [0, 500]]),
        500,
        new HazardWindow(0, 1000),
    ),
);
check("absent claim -> HazardUnknown",
    err_kind(fn() => Hazard::hazardAuthorizedOptional(null, $grant)) === "HazardUnknown");

$claim = new HazardClaim(
    Hazard::CLASS_TOOL_ACTUATION,
    new HazardEnvelope(
        new SpatialBounds("cell-7/world", [[100, 200], [100, 200], [0, 100]]),
        100,
        new HazardWindow(10, 900),
    ),
);
check("present, well-covered claim still authorizes through the same entry point",
    err_kind(fn() => Hazard::hazardAuthorizedOptional($claim, $grant)) === "no-error");

// ---------------------------------------------------------------------------------------------
// structural malformation (fail-closed, never partially valid).
// ---------------------------------------------------------------------------------------------
echo "\n6. malformed bodies rejected\n";

// empty axes
$bad = new SpatialBounds("f", []);
check("empty axes -> not well-formed", !$bad->isWellFormed());
check("empty axes -> HazardMalformed on decode",
    err_kind(fn() => SpatialBounds::fromValue($bad->toValue())) === "HazardMalformed");

// min > max
$bad2 = new SpatialBounds("f", [[10, -10]]);
check("min > max -> not well-formed", !$bad2->isWellFormed());

// non-NFC frame ('e' + combining acute, NFD not NFC)
$bad3 = new SpatialBounds("e\u{0301}", [[0, 1]]);
check("non-NFC frame -> not well-formed", !$bad3->isWellFormed());

// wrong shape entirely (not a map)
check("wrong shape -> HazardMalformed",
    err_kind(fn() => HazardClaim::fromValue(new U(0))) === "HazardMalformed");

// class present, envelope missing
$partial = new Naalp\M([[new U(1), new U(1)]]);
check("class present, envelope missing -> HazardMalformed",
    err_kind(fn() => HazardClaim::fromValue($partial)) === "HazardMalformed");

// an explicit out-of-range class ON THE WIRE (not "absent") is malformed, not silently
// normalized -- see Hazard::bodyFromValue's doc comment.
$goodEnv = (new HazardEnvelope(new SpatialBounds("f", [[0, 1]]), 1, new HazardWindow(0, 1)))->toValue();
$outOfRange = new Naalp\M([[new U(1), new U(99)], [new U(2), $goodEnv]]);
check("out-of-range class on the wire -> HazardMalformed",
    err_kind(fn() => HazardClaim::fromValue($outOfRange)) === "HazardMalformed");

// ---------------------------------------------------------------------------------------------
// containment truth table (independent of the oracle file, direct assertions).
// ---------------------------------------------------------------------------------------------
echo "\n7. spatial_contained truth table\n";

$grantSb = new SpatialBounds("f", [[0, 100], [0, 100]]);
$inside = new SpatialBounds("f", [[10, 90], [10, 90]]);
check("fully inside -> contained", Hazard::spatialContained($inside, $grantSb));
$equal = new SpatialBounds("f", [[0, 100], [0, 100]]);
check("equal bounds -> contained (closed interval)", Hazard::spatialContained($equal, $grantSb));
$outside = new SpatialBounds("f", [[10, 90], [10, 101]]);
check("one axis pokes outside -> not contained", !Hazard::spatialContained($outside, $grantSb));
$wrongFrame = new SpatialBounds("g", [[10, 90], [10, 90]]);
check("different frame -> never contained regardless of numeric bounds", !Hazard::spatialContained($wrongFrame, $grantSb));
$fewer = new SpatialBounds("f", [[10, 90]]);
check("fewer axes -> never contained", !Hazard::spatialContained($fewer, $grantSb));

echo "\n8. envelope_contained window and speed\n";

$mkEnv = fn(int $lo, int $hi, int $speed, int $nb, int $na) =>
    new HazardEnvelope(new SpatialBounds("f", [[$lo, $hi]]), $speed, new HazardWindow($nb, $na));

$envGrant = $mkEnv(0, 100, 500, 100, 900);
$ok = $mkEnv(0, 100, 500, 100, 900); // exact edges, closed interval
check("exact edges -> contained", Hazard::envelopeContained($ok, $envGrant));
$speedOver = $mkEnv(0, 100, 501, 100, 900);
check("speed over bound -> not contained", !Hazard::envelopeContained($speedOver, $envGrant));
$startsEarly = $mkEnv(0, 100, 500, 99, 900);
check("window starts before grant -> not contained", !Hazard::envelopeContained($startsEarly, $envGrant));
$endsLate = $mkEnv(0, 100, 500, 100, 901);
check("window ends after grant -> not contained", !Hazard::envelopeContained($endsLate, $envGrant));

echo "\n" . ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
