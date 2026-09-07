<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C5 §6 authorization conformance for the PHP SDK, graded against the shared independent corpus
// vectors/effect/cases.json (NOT produced by this code): the granted×effect authorization matrix
// (R-6.3), the signature-only authorization-principal rule (R-6.5), and the strict optional
// safety-label extraction (R-6.4). PolicyGrant (not Grant: Naalp\Grant already names the C15
// DelegationGrant body in this flat namespace) makes the effect an authorization input, fail-closed.
//
// Run:  php -d extension=sodium -d extension=intl test/policy_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Policy;
use Naalp\PolicyGrant;
use Naalp\Cbor;
use Naalp\U;
use Naalp\T;
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

function policy_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/effect/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/effect/cases.json not found");
}

$C = policy_vectors();
echo "policy (C5 §6) authorization conformance (PHP) — graded vs vectors/effect/cases.json\n";

$SRC = [
    "signature" => Policy::SOURCE_SIGNATURE,
    "transport_metadata" => Policy::SOURCE_TRANSPORT_METADATA,
    "foreign_header" => Policy::SOURCE_FOREIGN_HEADER,
    "client_name" => Policy::SOURCE_CLIENT_NAME,
];

// 1. R-6.3 — the granted×effect authorization matrix: a matched signature principal is authorized
//    iff the object effect is within the grant's ceiling, else EffectNotAuthorized. THE MUTATION
//    TARGET: making PolicyGrant::authorizeObject accept everything flips the denied rows below.
$matrix = $C["authorization_matrix"];
check("matrix has 16 cells", (string) count($matrix), "16");
$allows = 0;
$denies = 0;
foreach ($matrix as $r) {
    $g = new PolicyGrant("pA", (int) $r["granted"]);
    if ($r["allow"]) {
        $allows++;
        check(
            "granted={$r['granted']} effect={$r['effect']} allowed",
            err_kind(fn() => $g->authorizeObject(Policy::SOURCE_SIGNATURE, "pA", (int) $r["effect"])),
            "no-error"
        );
    } else {
        $denies++;
        check(
            "granted={$r['granted']} effect={$r['effect']} denied (EffectNotAuthorized)",
            err_kind(fn() => $g->authorizeObject(Policy::SOURCE_SIGNATURE, "pA", (int) $r["effect"])),
            "EffectNotAuthorized"
        );
    }
    // the raw lattice must agree with the matrix.
    check(
        "lattice authorizes(granted={$r['granted']}, norm(effect={$r['effect']}))",
        Policy::authorizes((int) $r["granted"], Policy::normalizeEffect((int) $r["effect"])) ? "yes" : "no",
        $r["allow"] ? "yes" : "no"
    );
}
check("matrix exercises both allow and deny", ($allows > 0 && $denies > 0) ? "yes" : "no", "yes");

// 2. R-6.5 — only a signature-derived identity is an authorization principal; a transport/foreign/
//    client source is refused UnauthenticatedPrincipal, and even a read_only object is denied from it.
$g = new PolicyGrant("pA", Policy::DESTRUCTIVE); // maximally permissive ceiling
foreach ($C["principal_sources"] as $ps) {
    $src = $SRC[$ps["source"]];
    if ($ps["accepted"]) {
        check("source {$ps['source']} accepted", err_kind(fn() => Policy::resolveAuthPrincipal($src, "pA")), "no-error");
        check("source {$ps['source']} authorizes read_only", err_kind(fn() => $g->authorizeObject($src, "pA", Policy::READ_ONLY)), "no-error");
    } else {
        check("source {$ps['source']} refused (UnauthenticatedPrincipal)", err_kind(fn() => Policy::resolveAuthPrincipal($src, "pA")), "UnauthenticatedPrincipal");
        check("source {$ps['source']} denies read_only (UnauthenticatedPrincipal)", err_kind(fn() => $g->authorizeObject($src, "pA", Policy::READ_ONLY)), "UnauthenticatedPrincipal");
    }
}

// 3. R-6.4 — safetyLabelFromExt extracts a well-formed {1:tstr,2:tstr} label (matching the
//    independently-hex-pinned oracle bytes), reports absence, and rejects a malformed/incomplete
//    label MalformedSafetyLabel — never silently accepting it.
$sl = $C["safety_label"];
$ext = new M([[new U((int) $sl["ext_key"]), new M([[new U(1), new T($sl["risk"])], [new U(2), new T($sl["scope"])]])]]);
[$label, $present] = Policy::safetyLabelFromExt($ext);
check("safety label present", $present ? "yes" : "no", "yes");
check("safety label risk == oracle", $label->risk, $sl["risk"]);
check("safety label scope == oracle", $label->scope, $sl["scope"]);
// the inner map matches the independently-pinned oracle bytes (non-circular).
check("safety label body == oracle hex", bin2hex(Policy::safetyLabelBytes($sl["risk"], $sl["scope"])), $sl["cbor_hex"]);

[$labelA, $presentA] = Policy::safetyLabelFromExt(new M([]));
check("absent ext -> not present", ($labelA === null && !$presentA) ? "yes" : "no", "yes");

$badNonMap = new M([[new U((int) $sl["ext_key"]), new U(9)]]);
check("malformed (non-map) rejected (MalformedSafetyLabel)", err_kind(fn() => Policy::safetyLabelFromExt($badNonMap)), "MalformedSafetyLabel");

$badIncomplete = new M([[new U((int) $sl["ext_key"]), new M([[new U(1), new T("x")]])]]);
check("incomplete (missing scope) rejected (MalformedSafetyLabel)", err_kind(fn() => Policy::safetyLabelFromExt($badIncomplete)), "MalformedSafetyLabel");

echo $fails === 0 ? "PASS\n" : "FAIL ($fails)\n";
exit($fails === 0 ? 0 : 1);
