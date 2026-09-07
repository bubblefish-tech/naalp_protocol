<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C7 audit conformance for the PHP SDK (design.md §8; R-8.1..8.6, R-12.2, R-12.3), graded against
// the shared independent corpus vectors/audit/cases.json (NOT produced by this code). An ordering
// authority appends a signed Receipt {1:prev, 2:obj, 3:seq, 4:at}; the chain is tamper-evident
// because a reorder/omission/substitution breaks a prev link or a seq. An auditor detects
// equivocation (two receipts at one seq naming different objects) from the signed receipts alone and
// mints a non-repudiable ForkProof (draft-01 §8.5). The causal graph is the authority-independent
// partial order checked offline.
//
// CORPUS-GRADED (pure, signature-independent): receipt body/head byte-parity, the chain final head,
// the ChainBroken linkage verdict, the two equivocation receipt bodies, the fork-proof framing
// witness (preimage, signatures elided), and the causal verdicts + topological order.
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the Authority/Auditor/ForkProof signature
// gates. PHP is PURE-ONLY for ML-DSA (FIPS 204 has no deterministic PHP signer), so the receipt and
// fork-proof signatures the reference makes with ML-DSA are demonstrated here with a real Ed25519
// (RFC 8032) round-trip via sodium. The full ForkProof body carrying real ML-DSA signatures is not
// reproducible in the pure tier; the corpus grades the signature-elided preimage, which is.
//
// Written test-first: Naalp\Audit is absent until Audit.php lands, so this fails RED with a fatal
// "class not found"; dropping the prev-link check in verifyChainLinks flips "chain_broken -> ChainBroken".
//
// Run:  php -d extension=sodium -d extension=intl test/audit_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Audit;
use Naalp\Receipt;
use Naalp\ForkProof;
use Naalp\Auditor;
use Naalp\Authority;
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

/** Walk up from this dir to the repository's shared corpus (the independent oracle). */
function audit_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/audit/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/audit/cases.json not found");
}

$C = audit_vectors();
echo "audit conformance (PHP) — graded vs vectors/audit/cases.json\n";

// An Ed25519 verify closure standing in for the reference's ML-DSA verifier (PURE-ONLY PHP).
function ed_verify(string $pk): callable
{
    return static fn(string $msg, string $sig): bool => Cose::ed25519Verify($pk, $msg, $sig);
}

// 1. genesis prev is 48 zero bytes.
check("genesis prev == oracle", bin2hex(str_repeat("\x00", Audit::HEAD_SIZE)), $C["chain"]["genesis_prev_hex"]);

// 2. the receipt chain: byte-for-byte body + head vs the non-circular oracle, built two independent
//    ways — reconstructed from the corpus fields, and produced by an Authority appending the same
//    objects (Ed25519-signed). A mutation to Bytes() flips a *_hex assertion; the chain also links.
$seed = str_repeat("\x14", 32);
$pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
$auth = new Authority($seed);
$receipts = [];
$sigs = [];
foreach ($C["chain"]["receipts"] as $i => $rj) {
    // reconstructed directly from the corpus (independent of the Authority):
    $r = new Receipt(hex2bin($rj["prev_hex"]), hex2bin($rj["obj_hex"]), $rj["seq"], $rj["at"]);
    check("receipt $i body == oracle", bin2hex($r->bytes()), $rj["body_hex"]);
    check("receipt $i head == oracle", bin2hex($r->head()), $rj["head_after_hex"]);
    // produced by the Authority (must equal the oracle body — the Authority builds the same bytes):
    [$ar, $asig] = $auth->append(hex2bin($rj["obj_hex"]), $rj["at"]);
    check("authority receipt $i body == oracle", bin2hex($ar->bytes()), $rj["body_hex"]);
    check("authority receipt $i seq", (string) $ar->seq, (string) $rj["seq"]);
    $receipts[] = $ar;
    $sigs[] = $asig;
}
check("chain final head == oracle", bin2hex(end($receipts)->head()), $C["chain"]["final_head_hex"]);
// the Ed25519-signed chain verifies offline (linkage + signature), and its links alone verify.
check("valid chain links verify", err_kind(fn() => Audit::verifyChainLinks($receipts)), "no-error");
check("valid signed chain verifies", err_kind(fn() => Audit::verifyChain($receipts, $sigs, ed_verify($pk))), "no-error");

// 3. a chain whose second receipt's prev does not link is ChainBroken (the tamper-evidence property;
//    the mutation target). The bodies still reconstruct byte-for-byte from the corpus.
$broken = [];
foreach ($C["chain_broken"]["receipts"] as $i => $rj) {
    $r = new Receipt(hex2bin($rj["prev_hex"]), hex2bin($rj["obj_hex"]), $rj["seq"], $rj["at"]);
    check("chain_broken receipt $i body == oracle", bin2hex($r->bytes()), $rj["body_hex"]);
    $broken[] = $r;
}
check("chain_broken rejected (ChainBroken)", err_kind(fn() => Audit::verifyChainLinks($broken)), $C["chain_broken"]["expect"]);
// a reordered valid chain (seq out of order) is also ChainBroken.
check("reordered chain rejected (ChainBroken)", err_kind(fn() => Audit::verifyChainLinks([$receipts[1], $receipts[0]])), "ChainBroken");
// a tampered receipt signature is ReceiptUnsigned (Ed25519-demonstrated).
$badSigs = $sigs;
$badSigs[0][strlen($badSigs[0]) - 1] = $badSigs[0][strlen($badSigs[0]) - 1] ^ "\x01";
check("tampered receipt sig rejected (ReceiptUnsigned)", err_kind(fn() => Audit::verifyChain($receipts, $badSigs, ed_verify($pk))), "ReceiptUnsigned");

// 4. equivocation: two receipts share seq 1 and prev = head(receipt 0) but name different objects.
//    The oracle bodies encode that prev/seq/at, so reconstructing with them byte-checks; the Auditor
//    (Ed25519-gated) then detects the fork.
$eqPrev = hex2bin($C["chain"]["receipts"][0]["head_after_hex"]);
$eqSeq = $C["equivocation"]["seq"];
$ra = new Receipt($eqPrev, hex2bin($C["equivocation"]["receipt_a"]["obj_hex"]), $eqSeq, 101);
$rb = new Receipt($eqPrev, hex2bin($C["equivocation"]["receipt_b"]["obj_hex"]), $eqSeq, 101);
check("equivocation receipt A body == oracle", bin2hex($ra->bytes()), $C["equivocation"]["receipt_a"]["body_hex"]);
check("equivocation receipt B body == oracle", bin2hex($rb->bytes()), $C["equivocation"]["receipt_b"]["body_hex"]);
$saEq = Cose::ed25519Sign($seed, $ra->bytes());
$sbEq = Cose::ed25519Sign($seed, $rb->bytes());
$aud = new Auditor(ed_verify($pk), "AUTH01");
check("first receipt not flagged", $aud->observe($ra, $saEq) === null ? "null" : "flagged", "null");
check("exact duplicate benign", $aud->observe($ra, $saEq) === null ? "null" : "flagged", "null");
$fpDetected = $aud->observe($rb, $sbEq);
check("equivocation detected (fork proof minted)", $fpDetected === null ? "null" : "proof", "proof");
if ($fpDetected !== null) {
    check("minted proof carries obj A", bin2hex($fpDetected->a->obj), $C["equivocation"]["receipt_a"]["obj_hex"]);
    check("minted proof carries obj B", bin2hex($fpDetected->b->obj), $C["equivocation"]["receipt_b"]["obj_hex"]);
    // the auditor-minted proof is non-repudiable: it verifies against the accused key (Ed25519).
    check("minted proof verifies", err_kind(fn() => $fpDetected->verify(ed_verify($pk))), "no-error");
}

// 5. the fork-proof framing witness (preimage: signer + ext_counter + the two receipt bodies, both
//    signatures elided) is byte-identical to the independent oracle — the corpus-graded surface. The
//    two embedded receipt bodies are the oracle's exact signed inputs.
$fpc = $C["fork_proof"];
$fpPrev = hex2bin($fpc["prev_hex"]);
$fa = new Receipt($fpPrev, hex2bin($fpc["obj_a_hex"]), $fpc["seq"], $fpc["at"]);
$fb = new Receipt($fpPrev, hex2bin($fpc["obj_b_hex"]), $fpc["seq"], $fpc["at"]);
check("fork-proof body A == oracle", bin2hex($fa->bytes()), $fpc["body_a_hex"]);
check("fork-proof body B == oracle", bin2hex($fb->bytes()), $fpc["body_b_hex"]);
$fpSigner = hex2bin($fpc["signer_hex"]);
$saFp = Cose::ed25519Sign($seed, $fa->bytes());
$sbFp = Cose::ed25519Sign($seed, $fb->bytes());
$fp = Audit::newForkProof($fpSigner, $fa, $saFp, $fb, $sbFp, $fpc["ext_counter"]);
check("fork-proof framing witness == oracle", bin2hex($fp->preimage()), $fpc["preimage_hex"]);
// the full body carries the (Ed25519, here) signatures, so it must differ from the elided witness.
check("full body differs from witness (sigs carried)", $fp->bytes() === $fp->preimage() ? "same" : "differs", "differs");

// 6. ForkProof.verify: the positive case and every fail-closed negative (Ed25519-demonstrated). A
//    verify that returned success unconditionally fails every negative below (mutation-surviving).
check("fork-proof verifies (positive)", err_kind(fn() => $fp->verify(ed_verify($pk))), "no-error");
$saTampered = $saFp;
$saTampered[strlen($saTampered) - 1] = $saTampered[strlen($saTampered) - 1] ^ "\x01";
$tamperA = Audit::newForkProof($fpSigner, $fa, $saTampered, $fb, $sbFp, $fpc["ext_counter"]);
check("tampered sig A rejected (ReceiptUnsigned)", err_kind(fn() => $tamperA->verify(ed_verify($pk))), "ReceiptUnsigned");
$foreignSeed = str_repeat("\x15", 32);
$foreignPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($foreignSeed));
check("wrong verifier rejected (ReceiptUnsigned)", err_kind(fn() => $fp->verify(ed_verify($foreignPk))), "ReceiptUnsigned");
$rSame = new Receipt($fpPrev, hex2bin($fpc["obj_a_hex"]), $fpc["seq"], $fpc["at"]);
$sSame = Cose::ed25519Sign($seed, $rSame->bytes());
$sameObj = Audit::newForkProof($fpSigner, $fa, $saFp, $rSame, $sSame, $fpc["ext_counter"]);
check("same object rejected (ForkProofInvalid)", err_kind(fn() => $sameObj->verify(ed_verify($pk))), "ForkProofInvalid");
$rSeq2 = new Receipt($fpPrev, hex2bin($fpc["obj_b_hex"]), $fpc["seq"] + 1, $fpc["at"]);
$sSeq2 = Cose::ed25519Sign($seed, $rSeq2->bytes());
$seqMismatch = Audit::newForkProof($fpSigner, $fa, $saFp, $rSeq2, $sSeq2, $fpc["ext_counter"]);
check("seq mismatch rejected (ForkProofInvalid)", err_kind(fn() => $seqMismatch->verify(ed_verify($pk))), "ForkProofInvalid");
$noSigner = Audit::newForkProof("", $fa, $saFp, $fb, $sbFp, $fpc["ext_counter"]);
check("empty signer rejected (ForkProofInvalid)", err_kind(fn() => $noSigner->verify(ed_verify($pk))), "ForkProofInvalid");

// 7. the causal graph: the valid DAG verifies with the oracle's topological order (tie-break by
//    POSITION, distinct from federation's content-id tie-break); a cycle and a future-cause each fire
//    CausalViolation. Nodes are [id, causes[], position] tuples (the shared Naalp\Graph contract).
function corpus_causal_nodes(array $nodesJson): array
{
    $out = [];
    foreach ($nodesJson as $n) {
        $out[] = [hex2bin($n["id_hex"]), array_map("hex2bin", $n["causes_hex"]), $n["position"]];
    }
    return $out;
}
$valid = corpus_causal_nodes($C["causal_valid"]["nodes"]);
check("valid causal graph verifies", err_kind(fn() => Audit::verifyCausal($valid)), "no-error");
$topo = Audit::topoOrder($valid);
check("topological order == oracle", implode(",", array_map("bin2hex", $topo)), implode(",", $C["causal_valid"]["topo_order_hex"]));
check("cycle rejected (CausalViolation)", err_kind(fn() => Audit::verifyCausal(corpus_causal_nodes($C["causal_cycle"]["nodes"]))), $C["causal_cycle"]["expect"]);
check("future cause rejected (CausalViolation)", err_kind(fn() => Audit::verifyCausal(corpus_causal_nodes($C["causal_future"]["nodes"]))), $C["causal_future"]["expect"]);

// 8. R-8.4 time anchor: an object's created time is consistent only if it does not exceed the
//    authority's independent time anchor.
check("created <= anchor consistent", Audit::consistentWithAnchor(100, 102) ? "true" : "false", "true");
check("created > anchor inconsistent", Audit::consistentWithAnchor(200, 102) ? "true" : "false", "false");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
