<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C17 N-AALP-CONT flow-continuation conformance for the PHP SDK (design.md §20; R-CONT-1..7), graded
// against the shared independent corpus vectors/continuation/cases.json (NOT produced by this code).
//
// N-AALP-CONT generalizes native streaming into a domain-agnostic flow: a FlowOpen is the ONE full
// signature fixing the flow's authority (flow_id, effect ceiling, approvals); a Continuation is a
// CHEAP hash-chain link (no per-object signature; head = SHA-384(body), prev chains to the previous
// head, genesis prev = FlowOpen head) carrying an effect that MUST stay at/below the ceiling
// (AboveCeiling otherwise); a Checkpoint confirms a contiguous prefix and DETECTS A GAP (GapDetected);
// a FlowCommit is a second full signature binding the whole ordered sequence.
//
// CORPUS-GRADED (pure, signature-independent): every object's deterministic-CBOR body + head + content
// id (FlowOpen/Continuation/Checkpoint/FlowCommit, incl. minimal, empty-vs-nonempty, big-seq >2^53,
// out-of-lattice range rejects, u64::MAX checkpoint overflow), the whole-chain final head, the cheap
// verify verdicts (WrongFlow/SeqGap/AboveCeiling/ChainBroken), the checkpoint gap verdicts, the
// replay-under-a-different-flow verdicts, the strict-decoder NonCanonical (keys out of order), and the
// look-alike sibling rejection (ContMalformed). ED25519-DEMONSTRATED (isolation, NOT corpus-graded):
// the FlowOpen/FlowCommit full-signature gates (SignFlowOpen/VerifyFlowOpen, SignFlowCommit/
// VerifyFlowCommit). PHP is PURE-ONLY for ML-DSA; the corpus carries no signed vector, so the full
// signature is demonstrated with a real Ed25519 (RFC 8032) COSE_Sign1 round-trip via sodium.
//
// PLATFORM NOTE (honest, F4): PHP models a u64 as a SIGNED 64-bit int. The big_seq case
// (0x0102030405060708 < 2^63) round-trips byte-exact. The checkpoint_overflow case (through_seq =
// u64::MAX = 2^64-1) exceeds PHP's representable positive range: it decodes from the corpus body_hex
// to a negative int (the wire's top bit set), which VerifyCheckpoint rejects GapDetected — the same
// fail-closed outcome as the reference's exact-MAX guard, reached for the whole unrepresentable
// >=2^63 range (no realizable contiguous prefix of that length exists). The u64::MAX checkpoint body
// cannot be BUILT from a native int (Cbor U rejects a negative), so that one body's byte-parity is
// graded by DECODING the corpus bytes, not re-encoding — stated plainly rather than faked.
//
// Written test-first: Naalp\Continuation etc. are absent until Continuation.php lands, so this fails
// RED with a fatal "class not found"; dropping the prev-chain check in VerifyContinuation flips the
// replay "ChainBroken" verdict, and dropping the u64::MAX guard flips the overflow "GapDetected".
//
// Run:  php -d extension=sodium -d extension=intl test/continuation_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Continuation;
use Naalp\FlowOpen;
use Naalp\Checkpoint;
use Naalp\FlowCommit;
use Naalp\Cbor;
use Naalp\Cose;
use Naalp\Policy;

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

function cont_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/continuation/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/continuation/cases.json not found");
}

/** Rebuild the FlowOpen struct from the oracle vector. */
function open_from(array $C): FlowOpen
{
    $apps = array_map("hex2bin", $C["flow_open"]["approvals_hex"]);
    return new FlowOpen(hex2bin($C["flow_open"]["flow_id_hex"]), $C["flow_open"]["effect_ceiling"], $apps);
}

/** Rebuild the full continuation chain from the oracle vector. */
function conts_from(array $C): array
{
    $id = hex2bin($C["flow_open"]["id_hex"]);
    $out = [];
    foreach ($C["continuations"] as $c) {
        $out[] = new Continuation($id, $c["seq"], $c["effect"], hex2bin($c["payload_id_hex"]), hex2bin($c["prev_hex"]));
    }
    return $out;
}

$C = cont_vectors();
echo "continuation conformance (PHP) — graded vs vectors/continuation/cases.json\n";

$open = open_from($C);

// 1. byte parity vs the non-circular oracle for every object (a field-ignoring/constant encoder
//    diverges here). FlowOpen body/head/id, the 3 continuations' body/head, the checkpoint + commit.
check("FlowOpen body == oracle", bin2hex($open->bytes()), $C["flow_open"]["body_hex"]);
check("FlowOpen head == oracle", bin2hex($open->head()), $C["flow_open"]["head_hex"]);
check("FlowOpen id == oracle", bin2hex($open->id()), $C["flow_open"]["id_hex"]);
$conts = conts_from($C);
foreach ($conts as $i => $c) {
    check("continuation $i body == oracle", bin2hex($c->bytes()), $C["continuations"][$i]["body_hex"]);
    check("continuation $i head == oracle", bin2hex($c->head()), $C["continuations"][$i]["head_hex"]);
}
$cp = new Checkpoint($open->id(), $C["checkpoint"]["through_seq"], hex2bin($C["checkpoint"]["head_hex"]));
check("Checkpoint body == oracle", bin2hex($cp->bytes()), $C["checkpoint"]["body_hex"]);
$fc = new FlowCommit($open->id(), hex2bin($C["flow_commit"]["final_head_hex"]));
check("FlowCommit body == oracle", bin2hex($fc->bytes()), $C["flow_commit"]["body_hex"]);

// 2. the whole cheap chain verifies and lands on the oracle's final head. Mutation: drop the
//    prev==prevHead check in VerifyContinuation and the returned head diverges from the oracle.
$final = null;
check("VerifyChain reaches a head", err_kind(function () use ($open, $conts, &$final) {
    $final = Continuation::verifyChain($open, $conts);
}), "no-error");
check("VerifyChain final head == oracle", $final === null ? "(none)" : bin2hex($final), $C["final_head_hex"]);

// 3. the bearer-authority property: the ceiling, flow_id, and approvals are reconstructed from the
//    FlowOpen bytes ALONE, and the reconstruction re-encodes to the same id (round-trip stable).
$parsed = Continuation::parseFlowOpen($open->bytes());
check("ParseFlowOpen ceiling == oracle", (string) $parsed->effectCeiling, (string) $C["flow_open"]["effect_ceiling"]);
check("ParseFlowOpen flow_id == oracle", bin2hex($parsed->flowId), $C["flow_open"]["flow_id_hex"]);
check("ParseFlowOpen approvals count", (string) count($parsed->approvals), (string) count($C["flow_open"]["approvals_hex"]));
check("ParseFlowOpen re-encodes to same id", bin2hex($parsed->id()), $C["flow_open"]["id_hex"]);
// ParseContinuation is the single audited decode path: each continuation round-trips byte-exact.
foreach ($conts as $i => $c) {
    $rt = Continuation::parseContinuation($c->bytes());
    check("ParseContinuation $i round-trips byte-exact", bin2hex($rt->bytes()), bin2hex($c->bytes()));
}

// 4. replay under a different FlowOpen fails: a continuation naming flow A does not verify under
//    FlowOpen B (WrongFlow); forging its id to B's makes prev (head of A) no longer chain to B's head
//    (ChainBroken). Positive control: it DOES verify under its own FlowOpen A. Mutation: drop the
//    flow_open_id check (WrongFlow flips) or the prev-chain check (the forged-id ChainBroken flips).
$openBID = hex2bin($C["replay"]["flow_open_b_id_hex"]);
$openBHead = hex2bin($C["replay"]["flow_open_b_head_hex"]);
$ceiling = $C["flow_open"]["effect_ceiling"];
check("replay as-is rejected (WrongFlow)", err_kind(fn() => Continuation::verifyContinuation($conts[0], $openBID, $openBHead, 0, $ceiling)), $C["replay"]["detect"]);
$forged = new Continuation($openBID, $conts[0]->seq, $conts[0]->effect, $conts[0]->payloadId, $conts[0]->prev);
check("replay forged-id rejected (ChainBroken)", err_kind(fn() => Continuation::verifyContinuation($forged, $openBID, $openBHead, 0, $ceiling)), "ChainBroken");
check("positive control under FlowOpen A verifies", err_kind(fn() => Continuation::verifyContinuation($conts[0], $open->id(), $open->head(), 0, $ceiling)), "no-error");

// 5. AboveCeiling: a continuation whose effect (3) exceeds the ceiling (2) is refused AboveCeiling;
//    the well-formed-but-forbidden body byte-matches the oracle. A within-ceiling effect is accepted.
$ac = $C["above_ceiling"];
$above = new Continuation($open->id(), $ac["seq"], $ac["effect"], hex2bin($ac["payload_id_hex"]), hex2bin($ac["prev_hex"]));
check("above-ceiling body == oracle", bin2hex($above->bytes()), $ac["body_hex"]);
check("above-ceiling rejected (AboveCeiling)", err_kind(fn() => Continuation::verifyContinuation($above, $open->id(), hex2bin($ac["prev_hex"]), $ac["seq"], $ac["ceiling"])), $ac["reject"]);
$okc = new Continuation($open->id(), $ac["seq"], Policy::NON_IDEMPOTENT_WRITE, hex2bin($ac["payload_id_hex"]), hex2bin($ac["prev_hex"]));
check("within-ceiling positive control verifies", err_kind(fn() => Continuation::verifyContinuation($okc, $open->id(), hex2bin($ac["prev_hex"]), $ac["seq"], $ac["ceiling"])), "no-error");
// SeqGap: the same link at the wrong expected seq is a gap.
check("wrong expected seq rejected (SeqGap)", err_kind(fn() => Continuation::verifyContinuation($conts[0], $open->id(), $open->head(), 5, $ceiling)), "SeqGap");

// 6. Checkpoint gap detection: an honest checkpoint verifies; a dropped link, a reorder, and a
//    tampered head are each GapDetected. Mutation: drop the contiguity/count/head checks.
check("honest checkpoint verifies", err_kind(fn() => Continuation::verifyCheckpoint($cp, $open, array_slice($conts, 0, $C["checkpoint"]["through_seq"] + 1))), "no-error");
$gapPrefix = [$conts[0], $conts[2]]; // claim through_seq 2 but deliver [seq0, seq2] (seq1 dropped)
$gapCp = new Checkpoint($open->id(), $C["gap"]["through_seq"], hex2bin($C["final_head_hex"]));
check("gap prefix rejected (GapDetected)", err_kind(fn() => Continuation::verifyCheckpoint($gapCp, $open, $gapPrefix)), $C["gap"]["detect"]);
$reordered = [$conts[1], $conts[0]];
$rcp = new Checkpoint($open->id(), 1, hex2bin($C["checkpoint"]["head_hex"]));
check("reordered prefix rejected (GapDetected)", err_kind(fn() => Continuation::verifyCheckpoint($rcp, $open, $reordered)), "GapDetected");
$badHead = hex2bin($C["checkpoint"]["head_hex"]);
$badHead[0] = $badHead[0] ^ "\x01";
$badCp = new Checkpoint($open->id(), $C["checkpoint"]["through_seq"], $badHead);
check("tampered-head checkpoint rejected (GapDetected)", err_kind(fn() => Continuation::verifyCheckpoint($badCp, $open, array_slice($conts, 0, $C["checkpoint"]["through_seq"] + 1))), "GapDetected");
// wrong-flow checkpoint (id != open.id) is WrongFlow, not GapDetected.
$wfCp = new Checkpoint($openBID, $C["checkpoint"]["through_seq"], hex2bin($C["checkpoint"]["head_hex"]));
check("wrong-flow checkpoint rejected (WrongFlow)", err_kind(fn() => Continuation::verifyCheckpoint($wfCp, $open, array_slice($conts, 0, $C["checkpoint"]["through_seq"] + 1))), "WrongFlow");

// 7. range reject (closed C5 lattice 0..3): a ceiling of 4 and an effect of 4 are well-formed CBOR
//    but not legal effects -> RangeError (NEVER normalized to destructive, which would make an
//    out-of-range CEILING the most-permissive one — a fail-open). Byte parity + Parse + Verify.
$rr = $C["range_reject"];
$badOpen = new FlowOpen(hex2bin($C["flow_open"]["flow_id_hex"]), $rr["out_of_lattice_value"], $open->approvals);
check("ceiling=4 FlowOpen body == oracle", bin2hex($badOpen->bytes()), $rr["flow_open_ceiling_body_hex"]);
check("ParseFlowOpen(ceiling=4) rejected (RangeError)", err_kind(fn() => Continuation::parseFlowOpen(hex2bin($rr["flow_open_ceiling_body_hex"]))), $rr["reject"]);
check("VerifyChain(ceiling=4) rejected (RangeError)", err_kind(fn() => Continuation::verifyChain($badOpen, [])), $rr["reject"]);
check("ParseContinuation(effect=4) rejected (RangeError)", err_kind(fn() => Continuation::parseContinuation(hex2bin($rr["continuation_effect_body_hex"]))), $rr["reject"]);
$badCont = new Continuation($open->id(), 0, $rr["out_of_lattice_value"], hex2bin($C["continuations"][0]["payload_id_hex"]), $open->head());
check("effect=4 Continuation body == oracle", bin2hex($badCont->bytes()), $rr["continuation_effect_body_hex"]);
check("VerifyContinuation(effect=4) rejected (RangeError)", err_kind(fn() => Continuation::verifyContinuation($badCont, $open->id(), $open->head(), 0, Policy::DESTRUCTIVE)), $rr["reject"]);
$okCont = new Continuation($open->id(), 0, 0, hex2bin($C["continuations"][0]["payload_id_hex"]), $open->head());
check("VerifyContinuation(ceiling=4) rejected (RangeError)", err_kind(fn() => Continuation::verifyContinuation($okCont, $open->id(), $open->head(), 0, $rr["out_of_lattice_value"])), $rr["reject"]);

// 8. big_seq (>2^53): a continuation seq above 2^53 (0x0102030405060708) round-trips byte-exact
//    (uint64 all the way, carried as a JSON STRING so no float64 rounding). Mutation: truncate to a
//    float anywhere and the body_hex / recovered seq diverge.
$bs = $C["big_seq"];
$bigSeq = (int) $bs["seq_str"]; // 72623859790382856 < PHP_INT_MAX, exact
if ($bigSeq <= (1 << 53)) {
    check("big_seq fixture is > 2^53", "in-lattice", "> 2^53"); // deliberately fail if the fixture drifts
} else {
    $bigC = new Continuation($open->id(), $bigSeq, $bs["effect"], hex2bin($bs["payload_id_hex"]), hex2bin($bs["prev_hex"]));
    check("big-seq body == oracle", bin2hex($bigC->bytes()), $bs["body_hex"]);
    check("big-seq head == oracle", bin2hex($bigC->head()), $bs["head_hex"]);
    $bigRt = Continuation::parseContinuation($bigC->bytes());
    check("big-seq round-trips seq byte-exact", (string) $bigRt->seq, (string) $bigSeq);
}

// 9. minimal FlowOpen (empty flow_id, ceiling read_only, no approvals): encodes, has a stable id,
//    reconstructs from its bytes alone.
$mn = $C["minimal"];
$minOpen = new FlowOpen(hex2bin($mn["flow_id_hex"]), $mn["effect_ceiling"], array_map("hex2bin", $mn["approvals_hex"]));
check("minimal FlowOpen body == oracle", bin2hex($minOpen->bytes()), $mn["body_hex"]);
check("minimal FlowOpen head == oracle", bin2hex($minOpen->head()), $mn["head_hex"]);
check("minimal FlowOpen id == oracle", bin2hex($minOpen->id()), $mn["id_hex"]);
check("minimal FlowOpen round-trips to same id", bin2hex(Continuation::parseFlowOpen($minOpen->bytes())->id()), $mn["id_hex"]);

// 10. empty-vs-nonempty approvals: an empty approvals[] is DISTINCT on the wire and by content-id
//     from a populated one (never conflated).
$ev = $C["empty_vs_nonempty"];
$emptyOpen = new FlowOpen(hex2bin($C["flow_open"]["flow_id_hex"]), $C["flow_open"]["effect_ceiling"], []);
$oneOpen = new FlowOpen(hex2bin($C["flow_open"]["flow_id_hex"]), $C["flow_open"]["effect_ceiling"], [hex2bin($C["flow_open"]["approvals_hex"][0])]);
check("empty-approvals body == oracle", bin2hex($emptyOpen->bytes()), $ev["empty_approvals"]["body_hex"]);
check("one-approval body == oracle", bin2hex($oneOpen->bytes()), $ev["one_approval"]["body_hex"]);
check("empty-approvals id == oracle", bin2hex($emptyOpen->id()), $ev["empty_approvals"]["id_hex"]);
check("empty and one-approval ids differ", bin2hex($emptyOpen->id()) === bin2hex($oneOpen->id()) ? "same" : "differ", "differ");

// 11. u64::MAX checkpoint overflow: through_seq = u64::MAX admits no realizable contiguous prefix,
//     so an empty prefix presented against it is rejected GapDetected (NO MAX+1 links). The corpus
//     body is decoded (PHP cannot build a u64::MAX uint from a native int — stated in the header).
//     Mutation: drop the overflow guard and the empty prefix false-verifies.
$co = $C["checkpoint_overflow"];
check("overflow fixture is u64::MAX", $co["through_seq_str"], "18446744073709551615");
$ovCp = Continuation::parseCheckpoint(hex2bin($co["body_hex"]));
check("overflow through_seq decoded (top bit set, unrepresentable positive)", $ovCp->throughSeq < 0 ? "negative" : "positive", "negative");
check("overflow checkpoint rejected (GapDetected)", err_kind(fn() => Continuation::verifyCheckpoint($ovCp, $open, [])), $co["reject"]);

// 12. keys out of order: the strict shared decoder rejects a descending-key body NonCanonical; the
//     canonical variant decodes cleanly. (The canonical encoder matches FlowCommit's own bytes.)
$ko = $C["keys_out_of_order"];
check("canonical FlowCommit body == oracle", bin2hex($fc->bytes()), $ko["canonical_commit_body_hex"]);
check("canonical body decodes", err_kind(fn() => Cbor::decode(hex2bin($ko["canonical_commit_body_hex"]))), "no-error");
check("descending-key body rejected (NonCanonical)", err_kind(fn() => Cbor::decode(hex2bin($ko["noncanonical_commit_body_hex"]))), $ko["reject"]);

// 13. look-alike: a 2-field FlowCommit body fed to the 3-field ParseCheckpoint or the 5-field
//     ParseContinuation is rejected ContMalformed (domain separation is structural).
$la = $C["look_alike"];
check("FlowCommit body as Checkpoint rejected (ContMalformed)", err_kind(fn() => Continuation::parseCheckpoint(hex2bin($la["flow_commit_body_hex"]))), "ContMalformed");
check("FlowCommit body as Continuation rejected (ContMalformed)", err_kind(fn() => Continuation::parseContinuation(hex2bin($la["flow_commit_body_hex"]))), "ContMalformed");

// 14. full-signature gates (Ed25519-DEMONSTRATED, NOT corpus-graded): SignFlowOpen verifies +
//     reconstructs the authority; a foreign key is rejected BadSignature. SignFlowCommit verifies;
//     a foreign key is BadSignature; a short/missing continuation makes the recomputed head diverge
//     (CommitMismatch); a tampered final_head is CommitMismatch.
$seed = str_repeat("\x11", 32);
$pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
$foreignPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x22", 32)));
$openObj = Continuation::signFlowOpen($open, $seed);
$recon = null;
check("VerifyFlowOpen (honest) verifies", err_kind(function () use ($openObj, $pk, &$recon) {
    $recon = Continuation::verifyFlowOpen($openObj, Cose::PROFILE_PUBLIC, $pk);
}), "no-error");
check("VerifyFlowOpen reconstructs the ceiling", $recon === null ? "(none)" : (string) $recon->effectCeiling, (string) $C["flow_open"]["effect_ceiling"]);
check("VerifyFlowOpen foreign key rejected (BadSignature)", err_kind(fn() => Continuation::verifyFlowOpen($openObj, Cose::PROFILE_PUBLIC, $foreignPk)), "BadSignature");
$commitObj = Continuation::signFlowCommit($fc, $seed);
check("VerifyFlowCommit (honest) verifies", err_kind(fn() => Continuation::verifyFlowCommit($commitObj, Cose::PROFILE_PUBLIC, $pk, $open, $conts)), "no-error");
check("VerifyFlowCommit foreign key rejected (BadSignature)", err_kind(fn() => Continuation::verifyFlowCommit($commitObj, Cose::PROFILE_PUBLIC, $foreignPk, $open, $conts)), "BadSignature");
check("VerifyFlowCommit short chain rejected (CommitMismatch)", err_kind(fn() => Continuation::verifyFlowCommit($commitObj, Cose::PROFILE_PUBLIC, $pk, $open, array_slice($conts, 0, 2))), "CommitMismatch");
$badFc = new FlowCommit($open->id(), hex2bin($C["final_head_hex"]));
$bfh = $badFc->finalHead;
$bfh[0] = $bfh[0] ^ "\x01";
$badFc2 = new FlowCommit($open->id(), $bfh);
$badCommitObj = Continuation::signFlowCommit($badFc2, $seed);
check("VerifyFlowCommit tampered final_head rejected (CommitMismatch)", err_kind(fn() => Continuation::verifyFlowCommit($badCommitObj, Cose::PROFILE_PUBLIC, $pk, $open, $conts)), "CommitMismatch");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
