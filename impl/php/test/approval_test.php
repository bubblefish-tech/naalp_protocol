<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C6 approval conformance for the PHP SDK (design.md §7; R-7.1..7.4), graded against the shared
// independent corpus vectors/approval/cases.json (NOT produced by this code). An Approval binds,
// under signature, the content id of the exact canonical args object it approves (§7.1); a changed
// argument changes the id and the approval no longer matches (ApprovalMismatch). The consume ledger
// is a durable, hash-chained compare-and-set set keyed by approval content id: the FIRST consumer of
// an id wins and every later consume of the same id is rejected AlreadyConsumed (§7.2) — the
// single-use replay guarantee, and the security core of this port.
//
// CORPUS-GRADED (pure, signature-independent): the approval body/head/content-id byte-parity, the
// consume-ledger genesis head, each entry's deterministic-CBOR bytes and head_after, the chain final
// head, and the AlreadyConsumed single-use replay verdict. ED25519-DEMONSTRATED (isolation, NOT
// corpus-graded): the approval SIGNATURE gate (SignApproval/VerifyApproval) and the HeldResult
// signature. PHP is PURE-ONLY for ML-DSA (FIPS 204 has no deterministic PHP signer), so the approval
// signature the reference makes with ML-DSA is demonstrated here with a real Ed25519 (RFC 8032)
// round-trip via sodium; the corpus carries no signed vector, so signing is isolation-only.
//
// NOT PORTED (out of scope, honest status F2/F4): the T1.5 §7.5 ledger-signed ConsumeReceipt /
// ConsumeFork / ReceiptSet double-spend-evidence surface (approval.go §7.5). It is graded by a
// SEPARATE corpus, vectors/consume_receipt/cases.json — not this port's grade target — and is tracked
// as its own deliverable (as the Python port defers it). The single-use replay guarantee this port
// DOES cover (AlreadyConsumed) is the core §7.2 property; the receipt surface is the additive
// ordering-authority evidence layer on top of it.
//
// Written test-first: Naalp\Approval / Naalp\Ledger are absent until Approval.php lands, so this
// fails RED with a fatal "class not found"; making consume() always-succeed (dropping the
// already-consumed compare-and-set guard) flips "replay of consumed id rejected (AlreadyConsumed)"
// and the "chain final head == oracle" assertion.
//
// Run:  php -d extension=sodium -d extension=intl test/approval_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Approval;
use Naalp\ApprovalRecord;
use Naalp\HeldResult;
use Naalp\LedgerEntry;
use Naalp\Cose;
use Naalp\ConsumeReceipt;
use Naalp\ConsumeForkEvidence;
use Naalp\ReceiptSet;
use Naalp\Refusal;
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
function approval_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/approval/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/approval/cases.json not found");
}

/** A fresh, unique WAL path in the OS temp dir (created at runtime, never a committed path). */
function fresh_wal(): string
{
    $p = tempnam(sys_get_temp_dir(), 'naalp_approval_wal_');
    // tempnam creates an empty file; the ledger opens it in place (genesis = empty log).
    return $p;
}

/** Walk up from this dir to the repository's shared corpus at $rel (the independent oracle). Decodes
 * with JSON_BIGINT_AS_STRING so a uint64-max literal (beyond PHP_INT_MAX) survives as a decimal
 * string instead of losing precision to a float — see u64FromDecimalString below. */
function shared_vectors(string $rel): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/' . $rel;
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/$rel not found");
}

/** Decode a decimal string into the wrapped signed-64-bit PHP int Cbor's U type expects (the value
 * modulo 2^64, represented as a negative PHP int when >= 2^63). Uses bcmath so a uint64-max literal
 * decoded via JSON_BIGINT_AS_STRING loses no precision (a plain (int) cast on an overflowed float
 * would). Mirrors envelope_test.php's u64FromDecimalString. */
function u64_from_decimal(string $s): int
{
    $mod = \bcmod($s, '18446744073709551616'); // 2^64
    if (\bccomp($mod, '9223372036854775808') >= 0) { // >= 2^63
        $mod = \bcsub($mod, '18446744073709551616');
    }
    return (int) $mod;
}

/** Normalizes a JSON-decoded position field (plain PHP int for small values, or a decimal string for
 * values JSON_BIGINT_AS_STRING could not fit in a PHP int) into the wrapped signed-64-bit PHP int. */
function u64_field(mixed $raw): int
{
    return \is_int($raw) ? $raw : u64_from_decimal((string) $raw);
}

/** An Ed25519 verify closure standing in for the reference's ML-DSA verifier (PURE-ONLY PHP). */
function appr_ed_verify(string $pk): callable
{
    return static fn(string $msg, string $sig): bool => Cose::ed25519Verify($pk, $msg, $sig);
}

$C = approval_vectors();
$wals = [];
echo "approval conformance (PHP) — graded vs vectors/approval/cases.json\n";

// 1. the approval body bytes and the approval content id equal the independent oracle (=> Go == Rust
//    == Python, which grade the same file). A field-ignoring / constant encoder diverges here.
foreach ($C["approvals"] as $aj) {
    $rec = new ApprovalRecord(
        hex2bin($aj["approves_hex"]),
        $aj["approver"],
        $aj["grant"],
        hex2bin($aj["nonce_hex"]),
        $aj["not_after"]
    );
    check("approval {$aj['name']} body == oracle", bin2hex($rec->bytes()), $aj["record_hex"]);
    check("approval {$aj['name']} id == oracle", bin2hex($rec->id()), $aj["approval_id_hex"]);
}

// 2. the durable consume ledger: running the oracle's consume scenario against a fresh WAL produces
//    byte-identical entries and chain heads, genesis is 48 zero bytes, and the SECOND consume of an
//    already-consumed approval is rejected AlreadyConsumed (the single-use security core, §7.2). The
//    mutation target: making consume() always-succeed flips the AlreadyConsumed + final-head checks.
$walPath = fresh_wal();
$wals[] = $walPath;
$led = Approval::openLedger($walPath);
check("genesis head == oracle", bin2hex($led->head()), $C["ledger"]["genesis_head_hex"]);
foreach ($C["ledger"]["consumes"] as $i => $cons) {
    $id = hex2bin($cons["approval_id_hex"]);
    if ($cons["expect"] === "ok") {
        $e = null;
        $k = err_kind(function () use ($led, $id, $cons, &$e) {
            $e = $led->consume($id, $cons["by"]);
        });
        check("consume $i accepted (no-error)", $k, "no-error");
        if ($e instanceof LedgerEntry) {
            check("consume $i seq == oracle", (string) $e->seq, (string) $cons["seq"]);
            check("consume $i entry bytes == oracle", bin2hex($e->bytes()), $cons["entry_hex"]);
            check("consume $i head_after == oracle", bin2hex($led->head()), $cons["head_after_hex"]);
        }
    } elseif ($cons["expect"] === "AlreadyConsumed") {
        // THE single-use replay proof: this id was already consumed at seq 0 above, so a second
        // consume (even by a DIFFERENT consumer) must be rejected fail-closed with no ledger append.
        check("replay of consumed id rejected (AlreadyConsumed)", err_kind(fn() => $led->consume($id, $cons["by"])), "AlreadyConsumed");
    }
}
check("chain final head == oracle", bin2hex($led->head()), $C["ledger"]["final_head_hex"]);
check("ledger length == 2 (exactly one entry per distinct id)", (string) $led->len(), "2");
$led->close();

// 3. single-use under repeated replay: after the winning consume, EVERY later consume of that id is
//    rejected (not just the first replay). A consume that always-succeeds would append here.
$walPath2 = fresh_wal();
$wals[] = $walPath2;
$led2 = Approval::openLedger($walPath2);
$idA = hex2bin($C["approvals"][0]["approval_id_hex"]);
check("first consume wins (no-error)", err_kind(fn() => $led2->consume($idA, "c1")), "no-error");
check("replay #1 rejected (AlreadyConsumed)", err_kind(fn() => $led2->consume($idA, "c2")), "AlreadyConsumed");
check("replay #2 rejected (AlreadyConsumed)", err_kind(fn() => $led2->consume($idA, "c3")), "AlreadyConsumed");
check("ledger still length 1 after replays", (string) $led2->len(), "1");
$headBefore = bin2hex($led2->head());
$led2->close();

// 4. durability across reopen (persist-before-ack, R-7.2): a consume that returned survives closing
//    and reopening the WAL, and the reopened ledger still rejects a re-consume (single-use is durable,
//    not just in-memory). A ledger that did not fsync/replay would forget the spend.
$led3 = Approval::openLedger($walPath2);
check("consumed id survives reopen", $led3->isConsumed($idA) ? "yes" : "no", "yes");
check("head preserved across reopen", bin2hex($led3->head()), $headBefore);
check("re-consume after reopen rejected (AlreadyConsumed)", err_kind(fn() => $led3->consume($idA, "c4")), "AlreadyConsumed");
$led3->close();

// 5. LedgerCorrupt: a WAL whose second entry's prev does not link to SHA-384(entry0) is rejected on
//    open (the tamper-evidence property; the chain-linkage mutation target). A replay that ignored
//    `prev` would accept it.
$corruptPath = fresh_wal();
$wals[] = $corruptPath;
$idB = hex2bin($C["approvals"][1]["approval_id_hex"]);
$genesis = str_repeat("\x00", Approval::HEAD_SIZE);
$e0 = new LedgerEntry(0, $genesis, $idA, "c1");
$e1bad = new LedgerEntry(1, $genesis, $idB, "c1"); // prev left at genesis instead of head(e0)
$fp = fopen($corruptPath, "wb");
foreach ([$e0->bytes(), $e1bad->bytes()] as $rec) {
    fwrite($fp, pack("N", strlen($rec)) . $rec);
}
fclose($fp);
check("corrupt (broken-link) ledger rejected (LedgerCorrupt)", err_kind(fn() => Approval::openLedger($corruptPath)), "LedgerCorrupt");

// 6. R-7.1/R-7.3 approval verify (Ed25519-demonstrated): a correct approval verifies; a mutated-args
//    content id is ApprovalMismatch; an expired approval (pos > not_after) is ApprovalExpired; a
//    tampered signature is BadSignature. A verify that returned success unconditionally fails the
//    three negatives below (mutation-surviving).
$seed = str_repeat("\x0b", 32);
$pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
$recA = new ApprovalRecord(
    hex2bin($C["approvals"][0]["approves_hex"]),
    $C["approvals"][0]["approver"],
    $C["approvals"][0]["grant"],
    hex2bin($C["approvals"][0]["nonce_hex"]),
    $C["approvals"][0]["not_after"]
);
$argsID = hex2bin($C["args"]["content_id_hex"]);
$sigA = Approval::signApproval($recA, $seed);
$validAt = $C["expiry"]["valid_at"];
$expiredAt = $C["expiry"]["expired_at"];
check("valid approval verifies", err_kind(fn() => Approval::verifyApproval($recA, appr_ed_verify($pk), $sigA, $argsID, $validAt)), "no-error");
$wrongArgs = hex2bin($C["mismatch"]["wrong_args_id_hex"]);
check("mismatched args rejected (ApprovalMismatch)", err_kind(fn() => Approval::verifyApproval($recA, appr_ed_verify($pk), $sigA, $wrongArgs, $validAt)), "ApprovalMismatch");
check("expired approval rejected (ApprovalExpired)", err_kind(fn() => Approval::verifyApproval($recA, appr_ed_verify($pk), $sigA, $argsID, $expiredAt)), "ApprovalExpired");
$badSig = $sigA;
$badSig[strlen($badSig) - 1] = $badSig[strlen($badSig) - 1] ^ "\x01";
check("tampered signature rejected (BadSignature)", err_kind(fn() => Approval::verifyApproval($recA, appr_ed_verify($pk), $badSig, $argsID, $validAt)), "BadSignature");

// 7. R-7.4 held outcome: the "not yet granted" result is a distinct signed object (never a silent
//    success/denial); its bytes are attributable via the signature (Ed25519-demonstrated).
$held = new HeldResult($argsID, "awaiting approver");
$hSig = Approval::signHeld($held, $seed);
check("held result verifies", Cose::ed25519Verify($pk, $held->bytes(), $hSig) ? "yes" : "no", "yes");
$hBad = $hSig;
$hBad[0] = $hBad[0] ^ "\x01";
check("tampered held-result signature rejected", Cose::ed25519Verify($pk, $held->bytes(), $hBad) ? "verified" : "rejected", "rejected");

// ---- T1.5 (NAALP-REQ-121): ledger-signed consume receipt with forward-only position -------------
// Graded against vectors/consume_receipt/cases.json (NOT produced by this code; Go/Rust grade the
// SAME file, so Go == Rust == PHP bytes). The anti-double-spend counter (position) rides under the
// LEDGER's own signature, never the requester's.

/** @param array{ledger_hex:string,approval_id_hex:string,position:mixed} $rj */
function cr_from_json(array $rj): ConsumeReceipt
{
    return new ConsumeReceipt(hex2bin($rj["ledger_hex"]), hex2bin($rj["approval_id_hex"]), u64_field($rj["position"]));
}

function cr_ed_seed(int $b): string
{
    return str_repeat(chr($b), 32);
}

/** ledgerId(raw) -> verify closure fn(msg,sig):bool, or null if unresolvable — the ReceiptSet/
 * ConsumeForkEvidence resolver shape. */
function cr_resolver(array $pairs): callable
{
    return static function (string $ledgerId) use ($pairs): ?callable {
        if (!\array_key_exists($ledgerId, $pairs)) {
            return null;
        }
        $pk = $pairs[$ledgerId];
        return static fn(string $msg, string $sig): bool => Cose::ed25519Verify($pk, $msg, $sig);
    };
}

$CR = shared_vectors('consume_receipt/cases.json');
echo "\nconsume-receipt conformance (PHP) — graded vs vectors/consume_receipt/cases.json\n";

// 8. every consume-receipt body is byte-identical to the independent oracle in this implementation
//    (=> Go == Rust == PHP). A field-ignoring or mis-framing encoder diverges here.
$crAll = [["name" => $CR["base"]["name"], "v" => $CR["base"]]];
foreach ($CR["sequence"] as $s) {
    $crAll[] = ["name" => $s["name"], "v" => $s];
}
foreach ($CR["forks"] as $f) {
    $crAll[] = ["name" => $f["name"] . ".a", "v" => $f["a"]];
    $crAll[] = ["name" => $f["name"] . ".b", "v" => $f["b"]];
}
foreach ($crAll as $item) {
    check("consume-receipt {$item['name']} body == oracle", bin2hex(cr_from_json($item["v"])->bytes()), $item["v"]["body_hex"]);
}

// 9. a ledger-signed receipt verifies under the ledger key (REQ-121); an unnamed ledger, a tampered
//    signature, and the wrong ledger key are each rejected fail-closed (ConsumeReceiptUnsigned).
$crLedgerSeed = cr_ed_seed(0x51);
$crLedgerPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($crLedgerSeed));
$crBase = cr_from_json($CR["base"]);
$crSig = Approval::signConsumeReceipt($crBase, $crLedgerSeed);
check("valid ledger-signed receipt verifies", err_kind(fn() => Approval::verifyConsumeReceipt($crBase, appr_ed_verify($crLedgerPk), $crSig)), "no-error");
$crUnnamed = new ConsumeReceipt("", $crBase->approvalId, $crBase->position);
check("unnamed-ledger receipt rejected (ConsumeReceiptUnsigned)", err_kind(fn() => Approval::verifyConsumeReceipt($crUnnamed, appr_ed_verify($crLedgerPk), $crSig)), "ConsumeReceiptUnsigned");
$crBadSig = $crSig;
$crBadSig[\strlen($crBadSig) - 1] = $crBadSig[\strlen($crBadSig) - 1] ^ "\x01";
check("tampered signature rejected (ConsumeReceiptUnsigned)", err_kind(fn() => Approval::verifyConsumeReceipt($crBase, appr_ed_verify($crLedgerPk), $crBadSig)), "ConsumeReceiptUnsigned");
$crOtherPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(cr_ed_seed(0x52)));
check("wrong ledger key rejected (ConsumeReceiptUnsigned)", err_kind(fn() => Approval::verifyConsumeReceipt($crBase, appr_ed_verify($crOtherPk), $crSig)), "ConsumeReceiptUnsigned");

// 10a. two ledger-signed receipts for the SAME approval id with DIFFERENT positions (one ledger signs
//      both, a partition) are detected as a fork; the surfaced evidence carries BOTH positions and
//      verifies as a non-repudiable double-spend proof. A byte-identical re-emission stays benign.
$fkSame = null;
foreach ($CR["forks"] as $f) {
    if ($f["name"] === "same_ledger_diff_position") {
        $fkSame = $f;
    }
}
if ($fkSame === null) {
    throw new RuntimeException("same_ledger_diff_position case missing from oracle");
}
check("same_ledger_diff_position oracle expects fork", $fkSame["expect"], "fork");
$fkSeed = cr_ed_seed(0x41);
$fkPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($fkSeed));
$fkA = cr_from_json($fkSame["a"]);
$fkB = cr_from_json($fkSame["b"]);
$fkSigA = Approval::signConsumeReceipt($fkA, $fkSeed);
$fkSigB = Approval::signConsumeReceipt($fkB, $fkSeed);
$fkResolve = cr_resolver([$fkA->ledger => $fkPk]);
$fkRs = new ReceiptSet($fkResolve);
$fkFirst = $fkRs->observe($fkA, $fkSigA);
check("first receipt of the pair not flagged", $fkFirst === null ? "null" : "flagged", "null");
$fkFe = $fkRs->observe($fkB, $fkSigB);
check("fork detected on same approval id / different positions", $fkFe instanceof ConsumeForkEvidence ? "fork" : "no-fork", "fork");
if ($fkFe instanceof ConsumeForkEvidence) {
    check("fork evidence surfaces distinct positions", $fkFe->a->position !== $fkFe->b->position ? "distinct" : "same", "distinct");
    check("fork evidence verifies (non-repudiable)", err_kind(fn() => $fkFe->verify($fkResolve)), "no-error");
}
$fkRs2 = new ReceiptSet($fkResolve);
$fkRs2->observe($fkA, $fkSigA);
$fkDup = $fkRs2->observe($fkA, $fkSigA);
check("benign byte-identical re-emission never flagged", $fkDup === null ? "null" : "flagged", "null");

// 10b. remaining oracle fork cases: cross-ledger same/different position (FORK) and distinct
//      approvals / an exact duplicate (benign, NOT a fork). Per-ledger keys are derived
//      deterministically from the ledger id so same-ledger cases naturally reuse one key.
function seed_for_ledger(string $ledgerRaw): string
{
    return \substr(\hash('sha256', 'consume-receipt-test-seed:' . $ledgerRaw, true), 0, 32);
}
foreach ($CR["forks"] as $f) {
    if ($f["name"] === "same_ledger_diff_position") {
        continue; // covered above
    }
    $rA = cr_from_json($f["a"]);
    $rB = cr_from_json($f["b"]);
    $seedA = seed_for_ledger($rA->ledger);
    $seedB = seed_for_ledger($rB->ledger);
    $pkA = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seedA));
    $pkB = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seedB));
    $sigA = Approval::signConsumeReceipt($rA, $seedA);
    $sigB = Approval::signConsumeReceipt($rB, $seedB);
    $pairs = [$rA->ledger => $pkA];
    if ($rB->ledger !== $rA->ledger) {
        $pairs[$rB->ledger] = $pkB;
    }
    $resolve = cr_resolver($pairs);
    $rs = new ReceiptSet($resolve);
    $rs->observe($rA, $sigA);
    $fe = $rs->observe($rB, $sigB);
    if ($f["expect"] === "fork") {
        check("{$f['name']}: fork detected", $fe instanceof ConsumeForkEvidence ? "fork" : "no-fork", "fork");
        if ($fe instanceof ConsumeForkEvidence) {
            check("{$f['name']}: fork evidence verifies", err_kind(fn() => $fe->verify($resolve)), "no-error");
            if ($rA->ledger !== $rB->ledger) {
                check("{$f['name']}: cross-ledger evidence names distinct ledgers", $fe->a->ledger !== $fe->b->ledger ? "distinct" : "same", "distinct");
            }
        }
    } else {
        check("{$f['name']}: not flagged (benign)", $fe === null ? "null" : "flagged", "null");
    }
}

// 10c. two INDEPENDENT real signed ledgers, each consuming the SAME approval id on its own ledger via
//      Ledger::consumeWithReceipt — the double spend is not prevented (they cannot see each other),
//      only made provable on comparison of the resulting receipts.
$ledgerAId = hex2bin($CR["ledgers"]["a_hex"]);
$ledgerBId = hex2bin($CR["ledgers"]["b_hex"]);
$approvalX = hex2bin($CR["approvals"]["x_hex"]);
$seedLA = cr_ed_seed(0x41);
$seedLB = cr_ed_seed(0x42);
$pkLA = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seedLA));
$pkLB = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seedLB));
$walLA = fresh_wal();
$wals[] = $walLA;
$walLB = fresh_wal();
$wals[] = $walLB;
$lA = Approval::openLedgerSigned($walLA, $ledgerAId, $seedLA);
$lB = Approval::openLedgerSigned($walLB, $ledgerBId, $seedLB);
[$eA, $rcA, $rcSigA] = $lA->consumeWithReceipt($approvalX, "requester");
[$eB, $rcB, $rcSigB] = $lB->consumeWithReceipt($approvalX, "requester");
$resolveAB = cr_resolver([$ledgerAId => $pkLA, $ledgerBId => $pkLB]);
$rsAB = new ReceiptSet($resolveAB);
$rsAB->observe($rcA, $rcSigA);
$feAB = $rsAB->observe($rcB, $rcSigB);
check("cross-ledger double spend detected (independent ledgers)", $feAB instanceof ConsumeForkEvidence ? "fork" : "no-fork", "fork");
if ($feAB instanceof ConsumeForkEvidence) {
    check("cross-ledger fork evidence names distinct ledgers", $feAB->a->ledger !== $feAB->b->ledger ? "distinct" : "same", "distinct");
    check("cross-ledger fork evidence verifies", err_kind(fn() => $feAB->verify($resolveAB)), "no-error");
}
$lA->close();
$lB->close();

// 11. TestConsumeFirstAppendWinsCAS anchor: on ONE honest signed ledger, consuming the same approval id
//     twice yields exactly ONE ledger-signed receipt (first-append-wins). The first consume returns a
//     receipt at position 0; the second returns AlreadyConsumed and mints nothing. Feeding the winning
//     receipt into a fork detector finds no fork. Mutating the CAS to always-succeed would mint a
//     SECOND receipt for the same approval id, flipping this AND the fork detector.
$walCAS = fresh_wal();
$wals[] = $walCAS;
$lCAS = Approval::openLedgerSigned($walCAS, $ledgerAId, $seedLA);
[$e1, $r1, $sig1] = $lCAS->consumeWithReceipt($approvalX, "requester");
check("first receipt position is the ledger's position 0", ($e1->seq === 0 && $r1->position === 0) ? "yes" : "no", "yes");
$rsCAS = new ReceiptSet(cr_resolver([$ledgerAId => $pkLA]));
$feCASFirst = $rsCAS->observe($r1, $sig1);
check("first receipt not flagged as a fork", $feCASFirst === null ? "null" : "flagged", "null");
check("second consume of same approval id rejected (AlreadyConsumed)", err_kind(function () use ($lCAS, $approvalX) {
    $lCAS->consumeWithReceipt($approvalX, "requester");
}), "AlreadyConsumed");
check("ledger has exactly 1 entry (first-append-wins, CAS mutation anchor)", (string) $lCAS->len(), "1");
$lCAS->close();

// 12. consume-receipt wire cases: keys out of order (NonCanonical at the CBOR layer, before any
//     receipt rule), a position too large for a normal int (64-bit uint round-trip), and empty-value
//     vs absent-value (empty != absent; empty ledger id is verify-rejected fail-closed).
check("non-canonical (keys 3,2,1) receipt body rejected (NonCanonical)", err_kind(function () use ($CR) {
    \Naalp\Cbor::decode(hex2bin($CR["wire"]["keys_out_of_order"]["payload_hex"]));
}), "NonCanonical");
check("canonical variant of the same receipt decodes cleanly", err_kind(function () use ($CR) {
    \Naalp\Cbor::decode(hex2bin($CR["wire"]["keys_out_of_order"]["canonical_payload_hex"]));
}), "no-error");

$ledgerXWire = hex2bin($CR["base"]["ledger_hex"]);
$approvalXWire = hex2bin($CR["base"]["approval_id_hex"]);
foreach ($CR["wire"]["position_too_large"] as $big) {
    $pos = u64_field($big["position"]);
    $r = new ConsumeReceipt($ledgerXWire, $approvalXWire, $pos);
    check("{$big['name']} encode == oracle", bin2hex($r->bytes()), $big["body_hex"]);
    $v = \Naalp\Cbor::decode(hex2bin($big["body_hex"]));
    $foundPos = null;
    foreach ($v->pairs as [$k, $val]) {
        if ($k instanceof \Naalp\U && $k->v === 3) {
            $foundPos = $val->v;
        }
    }
    check("{$big['name']} position round-trip", $foundPos === null ? "null" : (string) $foundPos, (string) $pos);
}

$emptyLedgerCase = $CR["wire"]["empty_ledger"];
$emptyR = new ConsumeReceipt("", hex2bin($emptyLedgerCase["approval_id_hex"]), u64_field($emptyLedgerCase["position"]));
check("empty-ledger body == oracle", bin2hex($emptyR->bytes()), $emptyLedgerCase["body_hex"]);
$junkSig = \str_repeat("\x00", 64);
check("empty-ledger receipt verify-rejected (ConsumeReceiptUnsigned)", err_kind(fn() => Approval::verifyConsumeReceipt($emptyR, fn($m, $s) => false, $junkSig)), $emptyLedgerCase["expect_verify"]);
$absentBodyHex = $CR["wire"]["absent_ledger"]["body_hex"];
check("empty-ledger and absent-ledger receipts encode to distinct bytes", $emptyLedgerCase["body_hex"] !== $absentBodyHex ? "distinct" : "same", "distinct");

// ---- R-TDCS wire additions (design.md §25, C22), graded against vectors/trust_decision/cases.json ---

$TD = shared_vectors('trust_decision/cases.json');
echo "\ntrust-decision conformance (PHP) — graded vs vectors/trust_decision/cases.json\n";

// 13. R-TDCS-5 (audience): an approval carrying the OPTIONAL audience field encodes byte-identically to
//     the oracle; a named audience is checked at use — a mismatched context is rejected, an absent
//     audience passes any context, a matching one verifies.
$aud = $TD["audience"];
foreach ($aud["cases"] as $tc) {
    $rec = new ApprovalRecord(
        hex2bin($aud["approves_hex"]),
        $aud["approver"],
        $aud["grant"],
        hex2bin($aud["nonce_hex"]),
        $aud["not_after"],
        $tc["audience"]
    );
    check("audience {$tc['name']} body == oracle", bin2hex($rec->bytes()), $tc["record_hex"]);
    check("audience {$tc['name']} id == oracle", bin2hex($rec->id()), $tc["approval_id_hex"]);
}
$audPresent = new ApprovalRecord(hex2bin($aud["approves_hex"]), $aud["approver"], $aud["grant"], hex2bin($aud["nonce_hex"]), $aud["not_after"], $aud["use_context_match"]);
$audAbsent = new ApprovalRecord(hex2bin($aud["approves_hex"]), $aud["approver"], $aud["grant"], hex2bin($aud["nonce_hex"]), $aud["not_after"]);
check("naming an audience changes the approval bytes", $audPresent->bytes() !== $audAbsent->bytes() ? "distinct" : "same", "distinct");
check("matching audience verifies", err_kind(fn() => Approval::verifyAudience($audPresent, $aud["use_context_match"])), "no-error");
check("mismatched audience rejected (AudienceMismatch)", err_kind(fn() => Approval::verifyAudience($audPresent, $aud["use_context_mismatch"])), "AudienceMismatch");
check("an approval naming no audience passes any context", err_kind(fn() => Approval::verifyAudience($audAbsent, $aud["use_context_mismatch"])), "no-error");

// 14. R-TDCS-3 (refusal): RefusalFromRecord yields the exact oracle bytes for each closed-set outcome,
//     carries the full record's content id, and NEVER carries the record's discriminating detail (the
//     reason). ParseRefusal round-trips a conformant refusal and rejects every non-conformant shape.
$ref = $TD["refusal"];
$fullRecordBytes = hex2bin($ref["full_record_hex"]);
$recordIdBytes = hex2bin($ref["full_record_id_hex"]);
$leakedReason = $ref["leaked_reason"];
foreach ($ref["cases"] as $tc) {
    $r = Approval::refusalFromRecord($tc["outcome"], $fullRecordBytes);
    $rb = $r->bytes();
    check("refusal {$tc['name']} bytes == oracle", bin2hex($rb), $tc["record_hex"]);
    check("refusal {$tc['name']} does not leak the reason", \str_contains($rb, $leakedReason) ? "leaked" : "clean", "clean");
    check("refusal {$tc['name']} carries the full-record content id", \str_contains($rb, $recordIdBytes) ? "present" : "absent", "present");
    $got = Approval::parseRefusal($rb);
    check("refusal {$tc['name']} round-trip outcome", (string) $got->outcome, (string) $tc["outcome"]);
    check("refusal {$tc['name']} round-trip record id", bin2hex($got->record), bin2hex($recordIdBytes));
}
check("unknown refusal outcome rejected (UnknownRefusalOutcome)", err_kind(fn() => Approval::parseRefusal(hex2bin($ref["reject"]["unknown_outcome_hex"]))), "UnknownRefusalOutcome");
check("extra-field (leaked detail) refusal rejected (RefusalDetailLeak)", err_kind(fn() => Approval::parseRefusal(hex2bin($ref["reject"]["detail_leak_extra_field_hex"]))), "RefusalDetailLeak");
check("missing-record refusal rejected (RefusalDetailLeak)", err_kind(fn() => Approval::parseRefusal(hex2bin($ref["reject"]["missing_record_hex"]))), "RefusalDetailLeak");
check("empty-record refusal rejected (RefusalDetailLeak)", err_kind(fn() => Approval::parseRefusal(hex2bin($ref["reject"]["empty_record_hex"]))), "RefusalDetailLeak");
check(
    "IsKnownRefusalOutcome is the closed set {0,1,2} only",
    (Approval::isKnownRefusalOutcome(0) && Approval::isKnownRefusalOutcome(1) && Approval::isKnownRefusalOutcome(2) && !Approval::isKnownRefusalOutcome(3)) ? "closed" : "open",
    "closed"
);

// 15. R-TDCS-4 (freshness independence): a credential's present-moment validity is judged against an
//     ordering authority STRUCTURALLY DISTINCT from the party being authenticated; a party stamping its
//     own freshness is rejected FreshnessSelfAsserted. Not corpus-graded (behavioral, ad hoc scenario
//     data, exactly as impl/go/approval/tdcs_test.go's freshScenario).
$freshApproverSeed = \str_repeat("\x11", 32);
$freshLedgerSeed = \str_repeat("\x22", 32);
$freshApproverPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($freshApproverSeed));
$freshLedgerPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($freshLedgerSeed));
$freshArgsId = "the-exact-canonical-args-content-id";
$freshApproverId = "approver-authenticated-party-id";
$freshLedgerId = "ordering-authority-ledger-id";
$freshApproval = new ApprovalRecord($freshArgsId, $freshApproverId, 1, "anti-replay-nonce", 1000);
$freshASig = Approval::signApproval($freshApproval, $freshApproverSeed);
$freshReceipt = new ConsumeReceipt($freshLedgerId, $freshApproval->id(), 7);
$freshRSig = Approval::signConsumeReceipt($freshReceipt, $freshLedgerSeed);
$freshApproverV = appr_ed_verify($freshApproverPk);
$freshLedgerV = appr_ed_verify($freshLedgerPk);

check(
    "distinct ordering authority verifies (fresh-independent)",
    err_kind(fn() => Approval::verifyFreshIndependent($freshApproval, $freshApproverV, $freshASig, $freshArgsId, 1000, $freshReceipt, $freshLedgerV, $freshRSig, $freshApproverId)),
    "no-error"
);
check(
    "self-asserted freshness rejected (FreshnessSelfAsserted)",
    err_kind(fn() => Approval::verifyFreshIndependent($freshApproval, $freshApproverV, $freshASig, $freshArgsId, 1000, $freshReceipt, $freshLedgerV, $freshRSig, $freshLedgerId)),
    "FreshnessSelfAsserted"
);
check(
    "expired approval still rejected under a distinct authority (ApprovalExpired)",
    err_kind(fn() => Approval::verifyFreshIndependent($freshApproval, $freshApproverV, $freshASig, $freshArgsId, 1001, $freshReceipt, $freshLedgerV, $freshRSig, $freshApproverId)),
    "ApprovalExpired"
);
$freshEmptyReceipt = new ConsumeReceipt("", $freshApproval->id(), 7);
$freshEmptySig = Approval::signConsumeReceipt($freshEmptyReceipt, \str_repeat("\x33", 32));
check(
    "unnamed ordering authority not accepted as freshness evidence (ConsumeReceiptUnsigned)",
    err_kind(fn() => Approval::verifyFreshIndependent($freshApproval, $freshApproverV, $freshASig, $freshArgsId, 1000, $freshEmptyReceipt, $freshLedgerV, $freshEmptySig, $freshApproverId)),
    "ConsumeReceiptUnsigned"
);

// 16. Approval::consumeApproval precedence (T20.1, approval.state): the composed choke point runs the
//     draft "## Approval state machine" precedence in ONE place. Exercises every reaction and both
//     precedence rules (mismatch over every cell; expiry over AlreadyConsumed), plus the
//     effect-ceiling / grant-range / bad-signature refusals, and asserts the ledger length so a mutant
//     that returns the right Kind but still appends is caught. MUTATION TARGET: dropping the
//     effect-ceiling check (Policy::authorizes) flips "insufficient grant rejected" below to no-error.
echo "\nconsumeApproval precedence (PHP) — approval.state choke point (T20.1)\n";
$caSeed = \str_repeat("\x07", 32);
$caPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($caSeed));
$caVerify = appr_ed_verify($caPk);
$caArgsCid = "args-content-id-A";
$caWrongCid = "args-content-id-B";
$caMk = function (int $grant, int $notAfter) use ($caArgsCid, $caSeed): array {
    $a = new ApprovalRecord($caArgsCid, "approver-1", $grant, "\x01\x02", $notAfter);
    return [$a, Approval::signApproval($a, $caSeed)];
};

// approved + consume -> consumed (len 1); a second consume of the same id -> AlreadyConsumed (len 1).
[$caA1, $caSig1] = $caMk(Policy::DESTRUCTIVE, 1000);
$caWal1 = fresh_wal();
$wals[] = $caWal1;
$caL1 = Approval::openLedger($caWal1);
check("consumeApproval: valid consume (no-error)", err_kind(fn() => Approval::consumeApproval($caA1, $caVerify, $caSig1, $caArgsCid, 500, Policy::READ_ONLY, $caL1, "by")), "no-error");
check("consumeApproval: len 1 after first consume", (string) $caL1->len(), "1");
check("consumeApproval: replay rejected (AlreadyConsumed)", err_kind(fn() => Approval::consumeApproval($caA1, $caVerify, $caSig1, $caArgsCid, 500, Policy::READ_ONLY, $caL1, "by")), "AlreadyConsumed");
check("consumeApproval: len stays 1 after replay", (string) $caL1->len(), "1");
$caL1->close();

// expired + consume -> ApprovalExpired; nothing appended.
[$caA2, $caSig2] = $caMk(Policy::DESTRUCTIVE, 1000);
$caWal2 = fresh_wal();
$wals[] = $caWal2;
$caL2 = Approval::openLedger($caWal2);
check("consumeApproval: expired rejected (ApprovalExpired)", err_kind(fn() => Approval::consumeApproval($caA2, $caVerify, $caSig2, $caArgsCid, 2000, Policy::READ_ONLY, $caL2, "by")), "ApprovalExpired");
check("consumeApproval: len 0 after expired refusal", (string) $caL2->len(), "0");
$caL2->close();

// expiry over consume: success, then a second past not_after -> ApprovalExpired (never AlreadyConsumed).
[$caA3, $caSig3] = $caMk(Policy::DESTRUCTIVE, 1000);
$caWal3 = fresh_wal();
$wals[] = $caWal3;
$caL3 = Approval::openLedger($caWal3);
check("consumeApproval: valid consume before expiry (no-error)", err_kind(fn() => Approval::consumeApproval($caA3, $caVerify, $caSig3, $caArgsCid, 500, Policy::READ_ONLY, $caL3, "by")), "no-error");
check("consumeApproval: expiry takes precedence over AlreadyConsumed", err_kind(fn() => Approval::consumeApproval($caA3, $caVerify, $caSig3, $caArgsCid, 2000, Policy::READ_ONLY, $caL3, "by")), "ApprovalExpired");
check("consumeApproval: len stays 1 (expiry-over-consume leaves ledger untouched)", (string) $caL3->len(), "1");
$caL3->close();

// mismatch takes precedence over every cell (fresh, and over an also-expired approval); no append.
[$caA4, $caSig4] = $caMk(Policy::DESTRUCTIVE, 1000);
$caWal4 = fresh_wal();
$wals[] = $caWal4;
$caL4 = Approval::openLedger($caWal4);
check("consumeApproval: mismatch rejected (ApprovalMismatch)", err_kind(fn() => Approval::consumeApproval($caA4, $caVerify, $caSig4, $caWrongCid, 500, Policy::READ_ONLY, $caL4, "by")), "ApprovalMismatch");
check("consumeApproval: mismatch precedes expiry (ApprovalMismatch)", err_kind(fn() => Approval::consumeApproval($caA4, $caVerify, $caSig4, $caWrongCid, 2000, Policy::READ_ONLY, $caL4, "by")), "ApprovalMismatch");
check("consumeApproval: len 0 after mismatches", (string) $caL4->len(), "0");
$caL4->close();

// a rejected mismatch leaves the ledger clean, so a later valid consume still succeeds.
[$caA5, $caSig5] = $caMk(Policy::DESTRUCTIVE, 1000);
$caWal5 = fresh_wal();
$wals[] = $caWal5;
$caL5 = Approval::openLedger($caWal5);
check("consumeApproval: rejected mismatch (ApprovalMismatch)", err_kind(fn() => Approval::consumeApproval($caA5, $caVerify, $caSig5, $caWrongCid, 500, Policy::READ_ONLY, $caL5, "by")), "ApprovalMismatch");
check("consumeApproval: len 0 after rejected mismatch", (string) $caL5->len(), "0");
check("consumeApproval: valid consume after rejected mismatch (no-error)", err_kind(fn() => Approval::consumeApproval($caA5, $caVerify, $caSig5, $caArgsCid, 500, Policy::READ_ONLY, $caL5, "by")), "no-error");
check("consumeApproval: len 1 after the valid consume", (string) $caL5->len(), "1");
$caL5->close();

// effect ceiling: granted effect below the action's required effect -> ApprovalRequired. THE mutation
// target: dropping this check (Policy::authorizes) makes an under-granted approval succeed instead.
[$caA6, $caSig6] = $caMk(Policy::READ_ONLY, 1000);
$caWal6 = fresh_wal();
$wals[] = $caWal6;
$caL6 = Approval::openLedger($caWal6);
check("consumeApproval: insufficient grant rejected (ApprovalRequired)", err_kind(fn() => Approval::consumeApproval($caA6, $caVerify, $caSig6, $caArgsCid, 500, Policy::DESTRUCTIVE, $caL6, "by")), "ApprovalRequired");
check("consumeApproval: len 0 after insufficient-grant refusal", (string) $caL6->len(), "0");
$caL6->close();

// grant-range guard: a grant outside the closed 0..3 vocabulary authorizes nothing.
[$caA7, $caSig7] = $caMk(7, 1000);
$caWal7 = fresh_wal();
$wals[] = $caWal7;
$caL7 = Approval::openLedger($caWal7);
check("consumeApproval: malformed grant rejected (ApprovalRequired)", err_kind(fn() => Approval::consumeApproval($caA7, $caVerify, $caSig7, $caArgsCid, 500, Policy::READ_ONLY, $caL7, "by")), "ApprovalRequired");
check("consumeApproval: len 0 after malformed-grant refusal", (string) $caL7->len(), "0");
$caL7->close();

// bad signature (checked first) -> BadSignature.
[$caA8, $caSig8] = $caMk(Policy::DESTRUCTIVE, 1000);
$caBadSig8 = $caSig8;
$caBadSig8[\strlen($caBadSig8) - 1] = $caBadSig8[\strlen($caBadSig8) - 1] ^ "\x01";
$caWal8 = fresh_wal();
$wals[] = $caWal8;
$caL8 = Approval::openLedger($caWal8);
check("consumeApproval: bad signature rejected (BadSignature)", err_kind(fn() => Approval::consumeApproval($caA8, $caVerify, $caBadSig8, $caArgsCid, 500, Policy::READ_ONLY, $caL8, "by")), "BadSignature");
check("consumeApproval: len 0 after bad-signature refusal", (string) $caL8->len(), "0");
$caL8->close();

// cleanup the transient WAL files (created at runtime in the OS temp dir).
foreach ($wals as $w) {
    @unlink($w);
}

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
