<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// verifyReconcileOrder conformance for the PHP SDK — the verify-event choke point of the Reconcile
// state machine (ietf/draft-bubblefish-naalp-01.md "## Reconcile state machine", error code 61). An
// independent recomputation agrees with the record (verified), disagrees on a causally-valid but
// non-deterministic order (ReconcileMismatch), or rejects a node set that is not a valid partial
// order (CausalViolation). Mirrors impl/go/federation/verify_reconcile_test.go
// TestVerifyReconcileOrder. Self-contained (no shared corpus): two causally-INDEPENDENT byte-id
// nodes id_a=[0x01], id_b=[0x02] reconcile deterministically to [id_a, id_b] (content-id
// bytewise-ascending tie-break among concurrent objects).
//
// Written test-first: Naalp\Federation::verifyReconcileOrder is absent until Federation.php lands,
// so this fails RED with a fatal "call to undefined method"; a mutation that neuters the order
// comparison (short-circuits to "always verified") flips the "mismatch" and "mismatch-length"
// subtests from ReconcileMismatch to no-error.
//
// Run:  php -d extension=sodium -d extension=intl test/verify_reconcile_order_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Federation;
use Naalp\CausalNode;
use Naalp\ReconcileRecord;

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

echo "verifyReconcileOrder conformance (PHP) — self-contained (mirrors Go TestVerifyReconcileOrder)\n";

// Two causally-INDEPENDENT objects (no cause between them). Reconcile orders concurrent objects by
// content id bytewise-ascending, so idA < idB => the one deterministic order is [idA, idB].
$idA = "\x01";
$idB = "\x02";
$concurrent = [new CausalNode($idA, []), new CausalNode($idB, [])];

// 1. agrees: the claimed order IS the deterministic order -> verified (no throw).
$rec = new ReconcileRecord(["auth-1"], [$idA, $idB]);
check("agrees (verified, no throw)", err_kind(fn() => Federation::verifyReconcileOrder($rec, $concurrent)), "no-error");

// 2. mismatch: a causally-VALID-but-different order (the two objects are concurrent, so [idB, idA]
//    is causally valid) is not the deterministic order -> ReconcileMismatch. This is the mutation
//    target: neutering the order comparison flips this to no-error.
$recMismatch = new ReconcileRecord(["auth-1"], [$idB, $idA]);
check("mismatch (ReconcileMismatch)", err_kind(fn() => Federation::verifyReconcileOrder($recMismatch, $concurrent)), "ReconcileMismatch");

// 3. mismatch-length: a claim that drops an element -> ReconcileMismatch.
$recShort = new ReconcileRecord(["auth-1"], [$idA]);
check("mismatch-length (ReconcileMismatch)", err_kind(fn() => Federation::verifyReconcileOrder($recShort, $concurrent)), "ReconcileMismatch");

// 4. causal-violation: a cyclic node set is not a valid partial order; the recomputation rejects it
//    before any order comparison, so the record is rejected under the graph fault, fail-closed.
$idC = "\x03";
$idD = "\x04";
$cyclic = [new CausalNode($idC, [$idD]), new CausalNode($idD, [$idC])];
$recCyclic = new ReconcileRecord(["auth-1"], [$idC, $idD]);
check("causal-violation (CausalViolation)", err_kind(fn() => Federation::verifyReconcileOrder($recCyclic, $cyclic)), "CausalViolation");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
