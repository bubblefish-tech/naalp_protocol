<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C19 name-binding + signed A2A task-state profile conformance for the PHP SDK (design.md §22;
// R-NAME-1..6, R-A2A-1..7), graded against the shared independent corpus vectors/naming/cases.json
// (NOT produced by this code). C19 is two receipt-CHAINED, offline-walkable surfaces carried on
// N-AALP's own signed object; both reuse the C7 audit receipt-chain construction (head=SHA-384(body),
// genesis prev=48 zero bytes, monotonic seq, prior head carried in the body) and add NO new
// mechanism (R-11.3).
//
// CORPUS-GRADED (pure, signature-independent): (1) every NameBinding body/head/id and every
// Transition body/head/id — including the >2^53 seq round-trip and the empty-field minimal — matched
// byte-for-byte to the oracle (⟹ Go == Rust == Python); (2) the offline walk verdicts —
// WalkHistory signer succession, DetectHole/DetectFork/DetectTaskGap first-broken positions, and the
// task-chain structural walk (start-state, contiguity, prev/seq linkage, card binding, legal-edge
// table); (3) the A2A legal/illegal edge table; (4) the strict-decoder NonCanonical rejection and the
// binding<->transition look-alike NameMalformed rejections; and (5) the A2A Agent Card import
// content-id (card_id == multihash(0x20, SHA-384(import_body)), both provided independently by the
// corpus — non-circular). ED25519-DEMONSTRATED (isolation, NOT corpus-graded): SignBinding/VerifyChain,
// NameForkProof.verify, and SignTransition/VerifyTaskChain over real Ed25519 (RFC 8032) signed objects.
//
// SIGNED-PIN NOTE (honest F2/F4): C19's cross-language SIGNED pins are real deterministic ML-DSA
// (FIPS 204) COSE_Sign1 objects. PHP is PURE-ONLY for ML-DSA (no deterministic PHP signer), so those
// signed pins are NOT reproducible here and are NOT faked. The corpus surfaces this port grades are
// the byte bodies/heads/ids and the walk/edge/decode verdicts — ALL signature-independent — and the
// signature BINDING itself is demonstrated in isolation with a real Ed25519 round-trip. The one
// un-exercised leg is the ML-DSA signature bytes, exactly as the Approval/Audit/Delegation ports note.
//
// Written test-first: Naalp\Naming / Naalp\NameBinding / Naalp\Transition are absent until Naming.php
// lands, so this fails RED with a fatal "class not found". The load-bearing mutation: making
// Naming::legalEdge return true unconditionally flips "illegal edge [4,1] rejected (IllegalTransition)"
// (and every other illegal-edge / from-terminal check) on its assertion.
//
// Run:  php -d extension=sodium -d extension=intl test/naming_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Naming;
use Naalp\NameBinding;
use Naalp\NameEvent;
use Naalp\Transition;
use Naalp\NameForkProof;
use Naalp\Registrar;
use Naalp\Cbor;
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

function naming_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/naming/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/naming/cases.json not found");
}

/** A deterministic Ed25519 keypair for a label: [seed, pubkey] (the pure-tier stand-in for ML-DSA). */
function nm_key(string $label): array
{
    $seed = hash('sha256', "naalp-naming-key:$label", true);
    $pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
    return [$seed, $pk];
}

function nm_verify(string $pk): callable
{
    return static fn(string $msg, string $sig): bool => Cose::ed25519Verify($pk, $msg, $sig);
}

$C = naming_vectors();
echo "naming (C19) conformance (PHP) — graded vs vectors/naming/cases.json\n";

// ===== Task 4.1 — name bindings =====
$NB = $C["name"];
$nm = $NB["name_utf8"];

// 1. every name-binding body, chain head, and content id are byte-identical to the oracle.
foreach ($NB["bindings"] as $bj) {
    $b = new NameBinding($nm, hex2bin($bj["signer_hex"]), $bj["seq"], hex2bin($bj["prev_hex"]));
    check("binding seq {$bj['seq']} body == oracle", bin2hex($b->bytes()), $bj["body_hex"]);
    check("binding seq {$bj['seq']} head == oracle", bin2hex($b->head()), $bj["head_hex"]);
    check("binding seq {$bj['seq']} id == oracle", bin2hex($b->id()), $bj["id_hex"]);
}

// 2. a seq > 2^53 (0x0102030405060708) round-trips byte-exact (carried as a string in the corpus).
$bs = $NB["big_seq"];
$bBig = new NameBinding($nm, hex2bin($bs["signer_hex"]), (int) $bs["seq_str"], hex2bin($bs["prev_hex"]));
check("big-seq binding body == oracle", bin2hex($bBig->bytes()), $bs["body_hex"]);
check("big-seq binding head == oracle", bin2hex($bBig->head()), $bs["head_hex"]);
check("big-seq binding id == oracle", bin2hex($bBig->id()), $bs["id_hex"]);

// 3. the all-empty minimal binding encodes exactly.
$mn = $NB["minimal"];
$bMin = new NameBinding($mn["name_utf8"], hex2bin($mn["signer_hex"]), $mn["seq"], hex2bin($mn["prev_hex"]));
check("minimal binding body == oracle", bin2hex($bMin->bytes()), $mn["body_hex"]);
check("minimal binding head == oracle", bin2hex($bMin->head()), $mn["head_hex"]);
check("minimal binding id == oracle", bin2hex($bMin->id()), $mn["id_hex"]);

// 4. WalkHistory verifies the chain offline and returns the signer succession == oracle.
$chain = [];
foreach ($NB["bindings"] as $bj) {
    $chain[] = new NameBinding($nm, hex2bin($bj["signer_hex"]), $bj["seq"], hex2bin($bj["prev_hex"]));
}
$events = Naming::walkHistory($chain);
check("walk length == oracle", (string) count($events), (string) count($NB["walk"]));
foreach ($NB["walk"] as $i => $w) {
    check("walk[$i] signer == oracle", bin2hex($events[$i]->signer), $w["signer_hex"]);
}
check("current signer == last walk signer", bin2hex(end($events)->signer), end($NB["walk"])["signer_hex"]);

// 5. DetectHole: a deleted binding at seq 1 (present [0,2]) breaks contiguity at position 1.
$b0 = $chain[0];
$b2 = $chain[2];
[$holePos, $hole] = Naming::detectHole([$b0, $b2]);
check("hole detected", $hole ? "yes" : "no", "yes");
check("hole position == oracle", (string) $holePos, (string) $NB["hole"]["first_hole_position"]);
// a contiguous full chain has no hole.
check("full chain has no hole", Naming::detectHole($chain)[1] ? "hole" : "none", "none");

// 6. DetectFork: two bindings at the SAME (name, seq 1) naming DIFFERENT signers => a fork at seq 1.
$b1 = $chain[1];
$fj = $NB["fork"]["b_prime"];
$bPrime = new NameBinding($nm, hex2bin($fj["signer_hex"]), $fj["seq"], hex2bin($fj["prev_hex"]));
check("b_prime body == oracle", bin2hex($bPrime->bytes()), $fj["body_hex"]);
[$forkPos, $fork] = Naming::detectFork($b1, $bPrime);
check("fork detected", $fork ? "yes" : "no", "yes");
check("fork position == oracle", (string) $forkPos, (string) $NB["fork"]["position"]);
check("byte-identical bindings are not a fork", Naming::detectFork($b1, $b1)[1] ? "fork" : "benign", "benign");
check("different-seq bindings are not a fork", Naming::detectFork($b0, $b1)[1] ? "fork" : "distinct", "distinct");

// 7. the strict decoder rejects a non-canonical (descending-key) binding body as NonCanonical, and
//    ParseNameBinding surfaces it as NameMalformed; the canonical form decodes.
$ko = $NB["keys_out_of_order"];
check("non-canonical body rejected by strict decoder (NonCanonical)", err_kind(fn() => Cbor::decode(hex2bin($ko["noncanonical_binding_body_hex"]))), $ko["reject"]);
check("canonical body decodes", err_kind(fn() => Cbor::decode(hex2bin($ko["canonical_binding_body_hex"]))), "no-error");
check("ParseNameBinding rejects non-canonical (NameMalformed)", err_kind(fn() => Naming::parseNameBinding(hex2bin($ko["noncanonical_binding_body_hex"]))), "NameMalformed");

// 8. look-alike: a 4-field binding fed to ParseTransition and a 6-field transition fed to
//    ParseNameBinding are both NameMalformed (the shapes do not cross).
$la = $NB["look_alike"];
check("binding body rejected by ParseTransition (NameMalformed)", err_kind(fn() => Naming::parseTransition(hex2bin($la["binding_body_hex"]))), "NameMalformed");
check("transition body rejected by ParseNameBinding (NameMalformed)", err_kind(fn() => Naming::parseNameBinding(hex2bin($la["transition_body_hex"]))), "NameMalformed");

// 9. VerifyChain over REAL Ed25519-signed bindings (isolation): a well-signed contiguous chain
//    verifies; a reordered chain is NameChainBroken; a tampered signature is BadSignature.
[$seed, $pk] = nm_key("registrar");
$signed = [];
foreach ($chain as $b) {
    $signed[] = Naming::signBinding($b, $seed);
}
check("Ed25519-signed chain verifies", err_kind(fn() => Naming::verifyChain($signed, nm_verify($pk))), "no-error");
$reordered = [$signed[0], $signed[2], $signed[1]];
check("reordered signed chain rejected (NameChainBroken)", err_kind(fn() => Naming::verifyChain($reordered, nm_verify($pk))), "NameChainBroken");
$badObj = $signed;
$t = $badObj[0];
$t[strlen($t) - 1] = $t[strlen($t) - 1] ^ "\x01";
$badObj[0] = $t;
check("tampered signed binding rejected (BadSignature)", err_kind(fn() => Naming::verifyChain($badObj, nm_verify($pk))), "BadSignature");

// 9.5 the Registrar appends the same monotonic chain the oracle records: appending each vector signer
//     as the subject at the next chain position yields a binding whose body == the oracle body_hex
//     (signature-independent). THE MUTATION TARGET: dropping the head advance (or the seq increment)
//     in Registrar::append flips "registrar reproduces oracle body[1]" (prev/seq stop matching).
$reg = new Registrar($nm, $seed);
foreach ($NB["bindings"] as $bj) {
    [$rb, $robj] = $reg->append(hex2bin($bj["signer_hex"]));
    check("registrar reproduces oracle body[{$bj['seq']}]", bin2hex($rb->bytes()), $bj["body_hex"]);
    check("registrar object verifies (seq {$bj['seq']})", err_kind(fn() => Naming::verifyBinding($robj, nm_verify($pk))), "no-error");
}

// 10. NameForkProof: two same-key Ed25519-signed bindings at (name, seq 1) naming different signers
//     is a non-repudiable fork proof reported at seq 1; an unnamed accused is not evidence.
$signedB1 = Naming::signBinding($b1, $seed);
$signedBPrime = Naming::signBinding($bPrime, $seed);
$fp = new NameForkProof(hex2bin($fj["signer_hex"]), $signedB1, $signedBPrime); // (accused id is opaque; both verify under $pk)
$fpPos = -1;
check("fork proof verifies", err_kind(function () use ($fp, $pk, &$fpPos) {
    $fpPos = $fp->verify(nm_verify($pk));
}), "no-error");
check("fork proof position == oracle", (string) $fpPos, (string) $NB["fork"]["position"]);
$fpUnnamed = new NameForkProof("", $signedB1, $signedBPrime);
check("unnamed accused rejected (NameForkProofInvalid)", err_kind(fn() => $fpUnnamed->verify(nm_verify($pk))), "NameForkProofInvalid");
$signedB1b = Naming::signBinding($b1, $seed);
$fpSame = new NameForkProof(hex2bin($fj["signer_hex"]), $signedB1, $signedB1b);
check("identical bindings are not a fork proof (NameForkProofInvalid)", err_kind(fn() => $fpSame->verify(nm_verify($pk))), "NameForkProofInvalid");

// ===== Task 4.2 — the signed A2A task-state profile =====
$A = $C["a2a"];
$states = $A["states"];

// 11. A2A state categories match the imported A2A vocabulary (§4.1.3).
check("start state == oracle", (string) Naming::START_STATE, (string) $states["start"]);
foreach ($states["terminal"] as $s) {
    check("state $s is terminal", Naming::isTerminal($s) ? "yes" : "no", "yes");
}
foreach ($states["interrupted"] as $s) {
    check("state $s is interrupted", Naming::isInterrupted($s) ? "yes" : "no", "yes");
}
for ($s = 0; $s <= 7; $s++) {
    check("state $s is a defined A2A state", Naming::isState($s) ? "yes" : "no", "yes");
}
check("state 8 is NOT a defined state", Naming::isState(8) ? "yes" : "no", "no");

// 12. the A2A legal-edge table == oracle, both ways: every listed legal edge is legal, every listed
//     illegal edge is refused (IllegalTransition), and the table has exactly the oracle's cardinality.
//     THE MUTATION TARGET: making legalEdge return true flips the illegal-edge checks below.
foreach ($A["legal_edges"] as $e) {
    check("legal edge [{$e[0]},{$e[1]}] accepted", Naming::legalEdge($e[0], $e[1]) ? "legal" : "illegal", "legal");
}
foreach ($A["illegal_edges"] as $e) {
    check("illegal edge [{$e[0]},{$e[1]}] rejected (IllegalTransition)", err_kind(fn() => Naming::verifyTransition($e[0], $e[1])), "IllegalTransition");
}
check("legal-edge table cardinality == oracle", (string) count(Naming::legalEdges()), (string) count($A["legal_edges"]));

// 13. the A2A Agent Card import content-id == multihash(0x20, SHA-384(import_body)) — non-circular
//     (the corpus provides both the import body and its content id independently).
$card = $A["card"];
$cardId = hex2bin($card["card_id_hex"]);
check("card content-id == multihash(SHA-384(import_body))", bin2hex(Cbor::contentId(hex2bin($card["import_body_hex"]))), $card["card_id_hex"]);

// 14. every task-transition body, chain head, and content id are byte-identical to the oracle.
$task = $A["task_utf8"];
$transitions = [];
foreach ($A["transitions"] as $tj) {
    $tr = new Transition($task, $cardId, $tj["from"], $tj["to"], $tj["seq"], hex2bin($tj["prev_hex"]));
    check("transition seq {$tj['seq']} ({$tj['from']}->{$tj['to']}) body == oracle", bin2hex($tr->bytes()), $tj["body_hex"]);
    check("transition seq {$tj['seq']} head == oracle", bin2hex($tr->head()), $tj["head_hex"]);
    check("transition seq {$tj['seq']} id == oracle", bin2hex($tr->id()), $tj["id_hex"]);
    $transitions[] = $tr;
}

// 15. big-seq + minimal transitions encode exactly.
$tbs = $A["big_seq"];
$trBig = new Transition($task, $cardId, $tbs["from"], $tbs["to"], (int) $tbs["seq_str"], hex2bin($tbs["prev_hex"]));
check("big-seq transition body == oracle", bin2hex($trBig->bytes()), $tbs["body_hex"]);
check("big-seq transition head == oracle", bin2hex($trBig->head()), $tbs["head_hex"]);
$tmn = $A["minimal"];
$trMin = new Transition(hex2bin($tmn["task_hex"]), hex2bin($tmn["card_hex"]), $tmn["from"], $tmn["to"], $tmn["seq"], hex2bin($tmn["prev_hex"]));
check("minimal transition body == oracle", bin2hex($trMin->bytes()), $tmn["body_hex"]);
check("minimal transition id == oracle", bin2hex($trMin->id()), $tmn["id_hex"]);

// 16. DetectTaskGap: a deleted transition at seq 1 (present [0,2]) breaks contiguity at position 1.
[$gapPos, $gap] = Naming::detectTaskGap([$transitions[0], $transitions[2]]);
check("task gap detected", $gap ? "yes" : "no", "yes");
check("task gap position == oracle", (string) $gapPos, (string) $A["gap"]["first_gap_position"]);
check("full transition chain has no gap", Naming::detectTaskGap($transitions)[1] ? "gap" : "none", "none");

// 17. the offline task-chain structural walk (start-state + contiguity + prev/seq linkage + card
//     binding + legal-edge table, all at once) accepts the oracle's chain and returns it ordered.
$walked = Naming::verifyTaskChainStructure($transitions, $cardId);
check("task-chain structural walk accepts the oracle chain", (string) count($walked), (string) count($transitions));

// 18. task-chain fail-closed verdicts: a foreign card is ForeignCard; a gap is TaskChainBroken; the
//     first transition must leave the start state; a from-terminal continuation is IllegalTransition.
$foreignCard = hex2bin($A["foreign_card_id_hex"]);
$foreignT0 = new Transition($task, $foreignCard, 0, 1, 0, Naming::genesis());
check("foreign-card transition rejected (ForeignCard)", err_kind(fn() => Naming::verifyTaskChainStructure([$foreignT0], $cardId)), "ForeignCard");
check("gappy chain rejected (TaskChainBroken)", err_kind(fn() => Naming::verifyTaskChainStructure([$transitions[0], $transitions[2]], $cardId)), "TaskChainBroken");
$notStart = new Transition($task, $cardId, 1, 2, 0, Naming::genesis()); // seq 0 but from != start
check("chain not leaving the start state rejected (IllegalTransition)", err_kind(fn() => Naming::verifyTaskChainStructure([$notStart], $cardId)), "IllegalTransition");
// build a legal-to-terminal step then a from-terminal continuation.
$toTerminal = new Transition($task, $cardId, 0, 4, 0, Naming::genesis());       // 0->4 completed (legal)
$fromTerminal = new Transition($task, $cardId, 4, 1, 1, $toTerminal->head());     // 4->1 (terminal cannot continue)
check("from-terminal continuation rejected (IllegalTransition)", err_kind(fn() => Naming::verifyTaskChainStructure([$toTerminal, $fromTerminal], $cardId)), "IllegalTransition");

// 19. VerifyTaskChain over REAL Ed25519-signed transitions (isolation): a well-signed chain verifies;
//     a tampered signature is BadSignature.
[$tSeed, $tPk] = nm_key("task-registrar");
$signedT = [];
foreach ($transitions as $tr) {
    $signedT[] = Naming::signTransition($tr, $tSeed);
}
check("Ed25519-signed task chain verifies", err_kind(fn() => Naming::verifyTaskChain($signedT, $cardId, nm_verify($tPk))), "no-error");
$badT = $signedT;
$x = $badT[1];
$x[strlen($x) - 1] = $x[strlen($x) - 1] ^ "\x01";
$badT[1] = $x;
check("tampered signed transition rejected (BadSignature)", err_kind(fn() => Naming::verifyTaskChain($badT, $cardId, nm_verify($tPk))), "BadSignature");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
