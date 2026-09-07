<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Identity RECORD + THREAD surfaces (design.md §5.2-§5.5) known-answer tests for the PHP SDK: the
// eleven RevocationRecord/ForeignLinkRecord/RotationEvidence/Thread surfaces that previously had NO
// PHP port and NO independent oracle coverage in this SDK. Graded against the same independent
// oracle the Go and Rust reference implementations use (tools/identity_records_oracle.py ->
// vectors/identity_records/cases.json), i.e. PHP == Go == Rust == oracle -- mirroring
// impl/go/identity/identity_records_oracle_test.go and the identity_records tests appended to
// impl/rust/src/identity.rs.
//
// Groups (each MATCHES ORACLE, mutation-surviving):
//   1. RevocationRecord::bytes()      -- deterministic-CBOR body byte parity.
//   2. Identity::revokedAt()          -- position-vs-not_after set scenarios [MUTATION ANCHOR:
//                                         "at_boundary_still_valid" pins `>` vs `>=`].
//   3. Identity::verifyRevocation()   -- all seven authorization x signature cases, including the
//                                         fail-closed recovery-key-not-configured anchor [MUTATION
//                                         ANCHOR: "recovery_key_not_configured_reject" -- dropping the
//                                         membership guard flips it (and wrong_key_reject) to accept].
//   4. ForeignLinkRecord::bytes()     -- byte parity + the NFC/NFD not-equal assertion [MUTATION
//                                         ANCHOR: a normalizing encoder would collapse the two].
//   5. Identity::verifyForeignLink()  -- valid/boundary/expired/wrong-key/non-NFC.
//   6. Identity::resolveThread()      -- empty/single/3-link/two distinct broken-chain shapes
//                                         [MUTATION ANCHORS: "broken_link_old_mismatch" pins the
//                                         contiguity guard, "broken_link_forged_old_signature" pins
//                                         the per-link co-signature guard, isolating one from the
//                                         other].
//   7. Thread::attributable()         -- root/intermediate/current attributable, unrelated not
//                                         [MUTATION ANCHOR: "unrelated_key_not_attributable" -- an
//                                         always-true stub flips it].
//
// Run: php -d extension=sodium -d extension=intl -d ffi.enable=1 -d extension=ffi
//          test/identity_records_test.php   (from impl/php/). Exit code 0 = all checks passed.
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Identity;
use Naalp\RevocationRecord;
use Naalp\ForeignLinkRecord;
use Naalp\RotationRecord;
use Naalp\RotationEvidence;
use Naalp\Thread;
use Naalp\MlDsa;
use Naalp\Cose;
use Naalp\SignerMismatch;
use Naalp\NonNFC;
use Naalp\RotationUnauthorized;
use Naalp\BadSignature;

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

function findVector(string $rel): ?string
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/' . $rel;
        if (is_file($p)) {
            return $p;
        }
        $d = dirname($d);
    }
    return null;
}

echo "identity records (RECORD + THREAD) KAT (PHP)\n";

if (!MlDsa::available()) {
    echo "  SKIP all identity-records checks: ML-DSA unavailable (" . MlDsa::unavailableReason() . ")\n";
    echo "PASS (skipped)\n";
    exit(0);
}

$vecPath = findVector('vectors/identity_records/cases.json');
if ($vecPath === null) {
    echo "  SKIP all identity-records checks: committed vector not present (standalone install)\n";
    echo "PASS (skipped)\n";
    exit(0);
}
$c = json_decode(file_get_contents($vecPath), true);
check("oracle alg_mldsa65 matches Cose::ALG_MLDSA65", (int) $c["alg_mldsa65"] === Cose::ALG_MLDSA65);

// ---- 1. RevocationRecord::bytes (§5.3) ------------------------------------------------------------
echo "\n1. RevocationRecord::bytes matches oracle\n";
$recordBytesCases = $c["revocation"]["record_bytes"];
if (count($recordBytesCases) === 0) {
    check("revocation record_bytes cases present", false, "no cases in vector");
}
foreach ($recordBytesCases as $tc) {
    $r = new RevocationRecord($tc["key"], (int) $tc["not_after"]);
    check($tc["name"], bin2hex($r->bytes()) === $tc["bytes_hex"],
        "got " . bin2hex($r->bytes()) . " want " . $tc["bytes_hex"]);
}

// ---- 2. Identity::revokedAt (§5.3) -- set-based scenarios, selection loop mirrors the Go/Rust test -
// MUTATION ANCHOR: "at_boundary_still_valid" pins `>` vs `>=` in Identity::revokedAt.
echo "\n2. Identity::revokedAt matches oracle\n";
$revokedAtCases = $c["revocation"]["revoked_at"];
if (count($revokedAtCases) === 0) {
    check("revoked_at scenarios present", false, "no scenarios in vector");
}
foreach ($revokedAtCases as $sc) {
    $revoked = false;
    $notAfter = 0;
    foreach ($sc["revocations"] as $rv) {
        if ($rv["key"] !== $sc["query_key"]) {
            continue;
        }
        $rec = new RevocationRecord($rv["key"], (int) $rv["not_after"]);
        if (Identity::revokedAt($rec, (int) $sc["query_position"])) {
            $revoked = true;
            $notAfter = (int) $rv["not_after"];
        }
    }
    check($sc["name"] . " revoked", $revoked === $sc["expect_revoked"],
        "got " . ($revoked ? "true" : "false") . " want " . ($sc["expect_revoked"] ? "true" : "false"));
    if ($sc["expect_revoked"]) {
        check($sc["name"] . " not_after", $notAfter === (int) $sc["expect_not_after"],
            "got $notAfter want " . $sc["expect_not_after"]);
    }
}

// ---- 3. Identity::verifyRevocation (§5.3, §5.5) ----------------------------------------------------
// MUTATION ANCHORS: "recovery_key_not_configured_reject" (a valid recovery-key signature with an
// EMPTY authorized set -> SignerMismatch) and "wrong_key_reject" -- dropping the membership guard
// flips both to accept.
echo "\n3. Identity::verifyRevocation matches oracle\n";
$verifyCases = $c["revocation"]["verify"];
if (count($verifyCases) < 7) {
    check("revocation verify cases >= 7", false, "got " . count($verifyCases));
}
foreach ($verifyCases as $tc) {
    $name = $tc["name"];
    $pub = hex2bin($tc["candidate_pubkey_hex"]);
    $alg = (int) $tc["candidate_alg"];
    $rec = new RevocationRecord($tc["record"]["key"], (int) $tc["record"]["not_after"]);
    $sig = hex2bin($tc["sig_hex"]);
    $recoveryIds = $tc["authorized_recovery_ids"] ?? [];
    $expectValid = (bool) $tc["expect_valid"];
    $expectKind = $tc["expect_error_kind"] ?? "";
    if ($expectValid) {
        try {
            Identity::verifyRevocation($rec, $alg, $pub, $sig, $recoveryIds);
            check($name, true);
        } catch (\Throwable $e) {
            check($name, false, "expected valid, got " . ($e->kind ?? get_class($e)) . " -- " . ($tc["note"] ?? ""));
        }
        continue;
    }
    if ($expectKind !== "") {
        expect_kind($name, function () use ($rec, $alg, $pub, $sig, $recoveryIds) {
            Identity::verifyRevocation($rec, $alg, $pub, $sig, $recoveryIds);
        }, $expectKind);
    } else {
        expect_throws($name, function () use ($rec, $alg, $pub, $sig, $recoveryIds) {
            Identity::verifyRevocation($rec, $alg, $pub, $sig, $recoveryIds);
        });
    }
}

// ---- 4. ForeignLinkRecord::bytes (§5.4) -------------------------------------------------------------
// MUTATION ANCHOR: collapsing NFC/NFD to the same bytes (a normalizing encoder) flips the
// not-equal assertion below.
echo "\n4. ForeignLinkRecord::bytes matches oracle\n";
$flBytesCases = $c["foreign_link"]["record_bytes"];
if (count($flBytesCases) < 2) {
    check("foreign_link record_bytes cases >= 2", false, "got " . count($flBytesCases));
}
$seen = [];
foreach ($flBytesCases as $tc) {
    $r = new ForeignLinkRecord($tc["controls"], $tc["foreign_id"], (int) $tc["not_after"]);
    $got = bin2hex($r->bytes());
    check($tc["name"], $got === $tc["bytes_hex"], "got $got want " . $tc["bytes_hex"]);
    $seen[$tc["name"]] = $got;
}
check("NFC and NFD foreign_id forms encode to different bytes",
    ($seen["nfc_form"] ?? "") !== ($seen["nfd_form_different_bytes"] ?? ""));

// ---- 5. Identity::verifyForeignLink (§5.4, §5.5) -----------------------------------------------------
echo "\n5. Identity::verifyForeignLink matches oracle\n";
$flVerifyCases = $c["foreign_link"]["verify"];
if (count($flVerifyCases) === 0) {
    check("foreign_link verify cases present", false, "no cases in vector");
}
foreach ($flVerifyCases as $tc) {
    $name = $tc["name"];
    $pub = hex2bin($tc["candidate_pubkey_hex"]);
    $alg = (int) $tc["candidate_alg"];
    $rec = new ForeignLinkRecord($tc["record"]["controls"], $tc["record"]["foreign_id"], (int) $tc["record"]["not_after"]);
    $sig = hex2bin($tc["sig_hex"]);
    $now = (int) $tc["now"];
    $expectKind = $tc["expect_error_kind"] ?? "";
    if ($expectKind !== "") {
        expect_kind($name, function () use ($rec, $alg, $pub, $sig, $now) {
            Identity::verifyForeignLink($rec, $alg, $pub, $sig, $now);
        }, $expectKind);
        continue;
    }
    try {
        $linked = Identity::verifyForeignLink($rec, $alg, $pub, $sig, $now);
        check("$name linked", $linked === (bool) $tc["expect_linked"],
            "got " . ($linked ? "true" : "false") . " want " . ($tc["expect_linked"] ? "true" : "false"));
        if ($tc["expect_linked"]) {
            check("$name controls", $rec->controls === $tc["expect_controls"]);
            check("$name foreign_id", $rec->foreignId === $tc["expect_foreign_id"]);
        }
    } catch (\Throwable $e) {
        check($name, false, "unexpected error " . ($e->kind ?? get_class($e)) . " -- " . ($tc["note"] ?? ""));
    }
}

// ---- 6. RotationEvidence / Thread / Identity::resolveThread (§5.2, R-1.4) ----------------------------
echo "\n6. Identity::resolveThread matches oracle\n";

/** @return RotationEvidence[] */
function buildEvidence(array $evs): array
{
    $out = [];
    foreach ($evs as $e) {
        $rec = new RotationRecord($e["old"], $e["new"], (int) $e["not_before"]);
        check("  (evidence) " . $e["old"] . "->" . $e["new"] . " record bytes",
            bin2hex($rec->bytes()) === $e["record_bytes_hex"]);
        $out[] = new RotationEvidence(
            $rec,
            (int) $e["old_alg"],
            hex2bin($e["old_pubkey_hex"]),
            (int) $e["new_alg"],
            hex2bin($e["new_pubkey_hex"]),
            hex2bin($e["old_sig_hex"]),
            hex2bin($e["new_sig_hex"])
        );
    }
    return $out;
}

$resolveCases = $c["thread"]["resolve"];
if (count($resolveCases) === 0) {
    check("thread resolve cases present", false, "no cases in vector");
}
foreach ($resolveCases as $tc) {
    $name = $tc["name"];
    $evs = buildEvidence($tc["evidence"]);
    $expectError = $tc["expect_error"] ?? "";
    if ($expectError !== "") {
        expect_kind($name, function () use ($evs) {
            Identity::resolveThread($evs);
        }, $expectError);
        continue;
    }
    try {
        $th = Identity::resolveThread($evs);
        $want = $tc["expect_thread"];
        check("$name root/current", $th->root === $want["root"] && $th->current === $want["current"],
            "got ({$th->root},{$th->current}) want ({$want["root"]},{$want["current"]})");
        check("$name chain length", count($th->chain) === count($want["chain"]),
            "got " . count($th->chain) . " want " . count($want["chain"]));
        $chainOk = true;
        foreach ($want["chain"] as $i => $id) {
            if (($th->chain[$i] ?? null) !== $id) {
                $chainOk = false;
            }
        }
        check("$name chain contents", $chainOk);
    } catch (\Throwable $e) {
        check($name, false, "unexpected error " . ($e->kind ?? get_class($e)) . " -- " . ($tc["note"] ?? ""));
    }
}

// ---- 7. Thread::attributable (§5.2, R-1.4) ------------------------------------------------------------
// MUTATION ANCHOR: "unrelated_key_not_attributable" -- an always-true stub flips it.
echo "\n7. Thread::attributable matches oracle\n";
$attributableCases = $c["thread"]["attributable"];
if (count($attributableCases) === 0) {
    check("thread attributable cases present", false, "no cases in vector");
}
foreach ($attributableCases as $tc) {
    $th = new Thread($tc["thread"]["root"], $tc["thread"]["current"], $tc["thread"]["chain"]);
    $got = $th->attributable($tc["query"]);
    check($tc["name"], $got === (bool) $tc["expect"],
        "got " . ($got ? "true" : "false") . " want " . ($tc["expect"] ? "true" : "false"));
}

echo "\n" . ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
