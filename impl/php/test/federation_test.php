<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Federation higher-tier conformance for the PHP SDK (design.md §8.4; design-channels.md §7; R-8.6),
// graded against the shared independent corpus vectors/federation/cases.json (NOT produced by this
// code). Reconcile is the deterministic linearization of the union causal DAG, tie-broken among
// causally-concurrent objects by content id (bytewise ascending): it MUST equal the oracle order, be
// causally valid, and beat the naive content-id sort (which is NOT causally valid here). The tier-1
// Reconcile record MUST encode to the oracle bytes, and reconcile MUST be scope-independent (R-8.6).
//
// CORPUS-GRADED (pure): reconcile order, causal validity, naive-sort baseline, record bytes, scope
// independence, cycle rejection.
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the tier-1 authority's signature over the
// record. PHP is PURE-ONLY for ML-DSA (no deterministic PQ signer), so the reference's ML-DSA
// Reconcile signature is demonstrated here with a real Ed25519 sign/verify round-trip (sodium),
// exactly as worked_example_test.php demonstrates the object signature.
//
// Written test-first: Naalp\Federation is absent until Federation.php lands, so this fails RED with a
// fatal "class not found"; a mutation that ignores the causal graph flips "reconcile order == oracle".
//
// Run:  php -d extension=sodium -d extension=intl test/federation_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Federation;
use Naalp\CausalNode;
use Naalp\ReconcileRecord;
use Naalp\CausalViolation;
use Naalp\Cose;

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

/** Walk up from this dir to the repository's shared corpus (the independent oracle). */
function federation_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/federation/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/federation/cases.json not found");
}

$C = federation_vectors();
echo "federation conformance (PHP) — graded vs vectors/federation/cases.json\n";

/** Build the corpus nodes as CausalNode[] (binary ids/causes). @return CausalNode[] */
function corpus_nodes(array $C): array
{
    $out = [];
    foreach ($C["nodes"] as $n) {
        $out[] = new CausalNode(hex2bin($n["id_hex"]), array_map("hex2bin", $n["causes_hex"]));
    }
    return $out;
}

/** hex-join an ordered list of binary ids for a stable comparison string. */
function hexjoin(array $bins): string
{
    return implode(",", array_map("bin2hex", $bins));
}

// 1. reconcile == the independent oracle order (the load-bearing property; the mutation target).
$nodes = corpus_nodes($C);
$order = Federation::reconcile($nodes);
check("reconcile order == oracle", hexjoin($order), implode(",", $C["reconcile_order_hex"]));

// 2. the reconcile order is causally valid (every present cause precedes its effect).
check(
    "reconcile order causally valid",
    Federation::causallyValid($order, $nodes) ? "true" : "false",
    $C["reconcile_order_causally_valid"] ? "true" : "false",
);

// 3. the naive content-id sort's causal validity matches the oracle — and here it is NOT valid, so
//    it is the mutation baseline: a reconcile that degrades to the naive sort would be caught.
$naive = array_map("hex2bin", $C["naive_content_id_sort_hex"]);
check(
    "naive content-id sort causally valid == oracle",
    Federation::causallyValid($naive, $nodes) ? "true" : "false",
    $C["naive_causally_valid"] ? "true" : "false",
);

// 4. the tier-1 Reconcile record encodes to the oracle bytes {1:[authorities], 2:[order]}.
$rec = new ReconcileRecord($C["authorities"], $order);
check("reconcile record bytes == oracle", bin2hex($rec->bytes()), $C["record_hex"]);

// 5. R-8.6: reconcile depends only on the causal graph, not on input (scope) order — reversing the
//    input reconciles identically.
$reversed = Federation::reconcile(array_reverse($nodes));
check("scope independence (reversed input)", hexjoin($reversed), hexjoin($order));

// 6. an out-of-lattice cycle is rejected fail-closed (CausalViolation).
$a = hex2bin("2030" . str_repeat("aa", 48));
$b = hex2bin("2030" . str_repeat("bb", 48));
$cyclic = [new CausalNode($a, [$b]), new CausalNode($b, [$a])];
$got = "no-error";
try {
    Federation::reconcile($cyclic);
} catch (CausalViolation $e) {
    $got = $e->kind;
}
check("cycle rejected", $got, "CausalViolation");

// 7. Ed25519-DEMONSTRATED (isolation): a tier-1 authority signs the Reconcile record; the raw
//    signature verifies under its key, and a tampered record does NOT verify. This exercises the
//    signing binding in isolation; it is NOT the corpus-graded ML-DSA surface (PURE-ONLY PHP).
$seed = str_repeat("\x2a", 32);
$pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
$sig = Federation::signReconcile($rec, $seed);
check("ed25519 reconcile-record sign/verify", Federation::verifyReconcile($rec, $pk, $sig) ? "true" : "false", "true");
$tampered = new ReconcileRecord(["bauthority-z"], $rec->order);
check("ed25519 tampered record rejected", Federation::verifyReconcile($tampered, $pk, $sig) ? "true" : "false", "false");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
