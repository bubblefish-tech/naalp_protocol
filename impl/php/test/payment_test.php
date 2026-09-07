<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C21 (5B.1) NAALP-PAY payment-import conformance for the PHP SDK (design.md §24; R-PAY-1..6),
// graded against the shared independent corpus vectors/payment/cases.json (NOT produced by this
// code). NAALP-PAY imports a foreign payment payload (AP2 mandate / Agentic Commerce Protocol
// delegated token / x402) octet-for-octet as OPAQUE foreign bytes (carriage, not adoption); the
// ChargeBinding {1:format,2:amount,3:currency,4:payee,5:not_after,6:foreign_id} names the exact value
// a §7 approval binds by content id, so a wrong amount/payee/currency or a substituted foreign payload
// yields a DIFFERENT charge content id (the structural binding guarantee). No fifth effect, no
// payment-specific ledger.
//
// CORPUS-GRADED (pure): the closed payment-format registry; the PaymentImport body/head/content-id
// byte-for-byte (incl. the oversized >2^53 amount and the minimal import); the foreign-payload content
// id (carriage binding); the ChargeBinding body/head/content-id; the parse round-trip; the fail-closed
// edges (non-canonical -> NonCanonical/PayMalformed, absent mandatory field -> PayMalformed, a
// bstr-currency look-alike -> PayMalformed, empty-vs-populated foreign distinct by content id); and the
// mismatch content-ids.
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the PaymentImport signature binding. PHP is
// PURE-ONLY for ML-DSA (FIPS 204), so the reference's ML-DSA signature is demonstrated with a real
// Ed25519 (RFC 8032) round-trip; the profile floor is level 3, so a pure-Ed25519 (level-0) object is
// correctly floored (ProfileDowngrade) by verifyPaymentImport, and an unregistered alg is UnknownAlg.
// AuthorizeCharge (Go impl/go/payment/payment.go:241) composes the EXISTING §7 approval + single-use
// consume ledger (Naalp\Approval / Naalp\Ledger, landed in the approval cluster) UNCHANGED: the approval
// MUST bind the EXACT charge binding content id (ApprovalMismatch on a wrong amount/payee/currency or a
// substituted foreign payload), its granted effect must cover CHARGE_EFFECT (a non_idempotent_write,
// ApprovalRequired otherwise), it must be unexpired (ApprovalExpired), the signature must verify
// (BadSignature), the format must be registered (UnknownPaymentFormat, checked first, no ledger append),
// and the single state change — the ledger consume — happens only when every check holds (AlreadyConsumed
// on replay, no double-spend). Ed25519-demonstrated (isolation, NOT corpus-graded): the payment corpus
// carries no approval/ledger vectors, so AuthorizeCharge is graded ad hoc exactly as
// impl/go/payment/payment_test.go's TestChargeSingleUseAndBinding does.
//
// Written test-first: Naalp\Payment is absent until Payment.php lands, so this fails RED with a fatal
// "class not found"; forcing the ChargeBinding amount field to a constant flips
// "ap2 charge_binding body == oracle". AuthorizeCharge is written test-first against
// Naalp\Payment::authorizeCharge, absent until this wave lands (fails RED "undefined method"); skipping
// the effect-coverage check flips "under-granting charge denied (ApprovalRequired)".
//
// Run:  php -d extension=sodium -d extension=intl test/payment_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Payment;
use Naalp\PaymentImport;
use Naalp\Cbor;
use Naalp\Cose;
use Naalp\Policy;
use Naalp\Approval;
use Naalp\ApprovalRecord;

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
function payment_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/payment/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/payment/cases.json not found");
}

$C = payment_vectors();
echo "payment conformance (PHP) — graded vs vectors/payment/cases.json\n";

/** Build a PaymentImport from a corpus import object (payee/foreign are hex, currency is text). */
function import_from(array $iv): PaymentImport
{
    return new PaymentImport(
        $iv["format"],
        $iv["amount"],
        $iv["currency"],
        hex2bin($iv["payee_hex"]),
        $iv["not_after"],
        hex2bin($iv["foreign_hex"]),
    );
}

// 1. the closed payment-format registry.
foreach ($C["format_vocabulary"] as $fv) {
    check("registered: " . $fv["name"], Payment::isRegisteredFormat($fv["code"]) ? "true" : "false", "true");
    check("name of code " . $fv["code"], Payment::formatName($fv["code"]), $fv["name"]);
}
check("unknown format not registered", Payment::isRegisteredFormat($C["unknown_format"]) ? "true" : "false", "false");
check("unknown format name", Payment::formatName($C["unknown_format"]), "unknown");

// 2. the charge effect is a non_idempotent_write (no fifth effect).
check("charge effect == oracle", (string) Payment::CHARGE_EFFECT, (string) $C["charge_effect"]);
check("charge effect == non_idempotent_write", (string) Payment::CHARGE_EFFECT, (string) Policy::NON_IDEMPOTENT_WRITE);

// 3. PaymentImport body/head/content-id + foreign-id byte parity vs the non-circular oracle.
foreach (["ap2", "acp", "x402"] as $name) {
    $iv = $C["imports"][$name];
    $p = import_from($iv);
    check("$name body == oracle", bin2hex($p->bytes()), $iv["body_hex"]);
    check("$name head == oracle", bin2hex($p->head()), $iv["head_hex"]);
    check("$name id == oracle", bin2hex($p->id()), $iv["id_hex"]);
    check("$name foreign-id == oracle", bin2hex($p->foreignId()), $iv["foreign_id_hex"]);
    // the exact value a §7 approval binds — the mutation-target assertion.
    $cb = $p->chargeBinding();
    check("$name charge_binding body == oracle", bin2hex($cb->bytes()), $iv["charge_binding"]["body_hex"]);
    check("$name charge_binding head == oracle", bin2hex($cb->head()), $iv["charge_binding"]["head_hex"]);
    check("$name charge_binding id == oracle", bin2hex($cb->contentId()), $iv["charge_binding"]["id_hex"]);
    // parse round-trip: the strict decoder reconstructs the same fields.
    $rp = Payment::parsePaymentImport($p->bytes());
    check("$name round-trip amount", (string) $rp->amount, (string) $iv["amount"]);
    check("$name round-trip currency", $rp->currency, $iv["currency"]);
    check("$name round-trip foreign", bin2hex($rp->foreign), $iv["foreign_hex"]);
}

// 4. the oversized amount (0x0102030405060708 > 2^53) round-trips byte-exact (carried as a JSON
//    string so it is not float-rounded before this code sees it).
$bv = $C["big_amount"];
$bigAmount = (int) $bv["amount_str"];
check("big amount parsed exactly", (string) $bigAmount, $bv["amount_str"]);
$bp = new PaymentImport($bv["format"], $bigAmount, $bv["currency"], hex2bin($bv["payee_hex"]), $bv["not_after"], hex2bin($bv["foreign_hex"]));
check("big-amount body == oracle", bin2hex($bp->bytes()), $bv["body_hex"]);
check("big-amount head == oracle", bin2hex($bp->head()), $bv["head_hex"]);
check("big-amount id == oracle", bin2hex($bp->id()), $bv["id_hex"]);
check("big-amount charge_binding id == oracle", bin2hex($bp->chargeBinding()->contentId()), $bv["charge_binding"]["id_hex"]);
$brp = Payment::parsePaymentImport(hex2bin($bv["body_hex"]));
check("big-amount round-trips through strict decoder", (string) $brp->amount, $bv["amount_str"]);

// 5. the minimal import.
$m = $C["minimal"];
$mp = new PaymentImport($m["format"], $m["amount"], $m["currency"], hex2bin($m["payee_hex"]), $m["not_after"], hex2bin($m["foreign_hex"]));
check("minimal body == oracle", bin2hex($mp->bytes()), $m["body_hex"]);
check("minimal head == oracle", bin2hex($mp->head()), $m["head_hex"]);
check("minimal id == oracle", bin2hex($mp->id()), $m["id_hex"]);

// 6. edge case: top-level keys DESCENDING are NonCanonical (strict decoder); the canonical form parses.
$ec = $C["edge_cases"]["keys_out_of_order"];
check("noncanonical decode rejected", err_kind(fn() => Cbor::decode(hex2bin($ec["noncanonical_body_hex"]))), "NonCanonical");
check("noncanonical parse rejected (PayMalformed)", err_kind(fn() => Payment::parsePaymentImport(hex2bin($ec["noncanonical_body_hex"]))), "PayMalformed");
check("canonical body parses", err_kind(fn() => Payment::parsePaymentImport(hex2bin($ec["canonical_body_hex"]))), "no-error");

// 7. edge case: an empty foreign payload is present and valid, distinct by content id from a populated
//    one; a body whose foreign field is absent is rejected (field 6 mandatory).
$ev = $C["edge_cases"]["empty_vs_absent"];
$empty = Payment::parsePaymentImport(hex2bin($ev["empty_foreign"]["body_hex"]));
check("empty foreign is empty", bin2hex($empty->foreign), "");
check("empty-foreign id == oracle", bin2hex($empty->id()), $ev["empty_foreign"]["id_hex"]);
check("empty-foreign foreign-id == oracle", bin2hex($empty->foreignId()), $ev["empty_foreign"]["foreign_id_hex"]);
$populated = Payment::parsePaymentImport(hex2bin($ev["populated_foreign"]["body_hex"]));
check("populated-foreign id == oracle", bin2hex($populated->id()), $ev["populated_foreign"]["id_hex"]);
check("empty != populated by id", $empty->id() === $populated->id() ? "same" : "distinct", "distinct");
check("empty != populated by foreign-id", $empty->foreignId() === $populated->foreignId() ? "same" : "distinct", "distinct");
check("absent foreign field rejected (PayMalformed)", err_kind(fn() => Payment::parsePaymentImport(hex2bin($ev["absent_field"]["body_hex"]))), $ev["absent_field"]["reject"]);

// 8. edge case: a sibling look-alike whose field 3 (currency) is a bstr where a tstr is required is
//    rejected PayMalformed.
$la = $C["edge_cases"]["look_alike"];
check("look-alike rejected (PayMalformed)", err_kind(fn() => Payment::parsePaymentImport(hex2bin($la["body_hex"]))), $la["reject"]);

// 9. the binding property: a wrong amount, wrong payee, or substituted foreign payload yields a
//    DIFFERENT charge content id — so a §7 approval bound to the original no longer matches
//    (ApprovalMismatch). Graded against the independent oracle's mismatch content-ids.
$base = import_from($C["imports"]["ap2"]);
$baseId = bin2hex($base->chargeBinding()->contentId());
$mm = $C["mismatch"];
$wrongAmount = new PaymentImport($base->format, $base->amount + 8000, $base->currency, $base->payee, $base->notAfter, $base->foreign);
check("wrong-amount charge id == oracle", bin2hex($wrongAmount->chargeBinding()->contentId()), $mm["wrong_amount_charge_id_hex"]);
$wrongPayee = new PaymentImport($base->format, $base->amount, $base->currency, "merchant:evil-store", $base->notAfter, $base->foreign);
check("wrong-payee charge id == oracle", bin2hex($wrongPayee->chargeBinding()->contentId()), $mm["wrong_payee_charge_id_hex"]);
$substituted = new PaymentImport($base->format, $base->amount, $base->currency, $base->payee, $base->notAfter, hex2bin($mm["substituted_foreign_hex"]));
check("substituted foreign-id == oracle", bin2hex($substituted->foreignId()), $mm["substituted_foreign_id_hex"]);
check("substituted charge id == oracle", bin2hex($substituted->chargeBinding()->contentId()), $mm["substituted_charge_id_hex"]);
foreach ([$mm["wrong_amount_charge_id_hex"], $mm["wrong_payee_charge_id_hex"], $mm["substituted_charge_id_hex"]] as $other) {
    check("changed charge != bound charge", $baseId === $other ? "same" : "distinct", "distinct");
}

// 10. ED25519-DEMONSTRATED (isolation): the PaymentImport signature signs and verifies raw; a tampered
//     signature and a foreign key fail; and verifyPaymentImport floors a pure-Ed25519 object
//     (ProfileDowngrade) and rejects an unregistered alg (UnknownAlg). The ML-DSA level-3 success path
//     is not reproducible in the pure tier (documented).
$paySeed = str_repeat("\x61", 32);
$payPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($paySeed));
$foreignPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x62", 32)));
$obj = Payment::signPaymentImport($base, Cose::ALG_ED25519, $paySeed);
[$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
$tbs = Cose::toBeSignedRaw($prot, $payload);
check("import signature verifies", Cose::ed25519Verify($payPk, $tbs, $sig) ? "true" : "false", "true");
check("reconstructed payload == body", bin2hex($payload), bin2hex($base->bytes()));
$tsig = $sig;
$tsig[strlen($tsig) - 1] = $tsig[strlen($tsig) - 1] ^ "\x01";
check("tampered import signature rejected", Cose::ed25519Verify($payPk, $tbs, $tsig) ? "true" : "false", "false");
check("foreign key rejected", Cose::ed25519Verify($foreignPk, $tbs, $sig) ? "true" : "false", "false");
check(
    "verifyPaymentImport floors Ed25519 (ProfileDowngrade)",
    err_kind(fn() => Payment::verifyPaymentImport($obj, Cose::PROFILE_PUBLIC, Cose::ALG_ED25519, $payPk)),
    "ProfileDowngrade",
);
$bogus = Payment::signPaymentImport($base, -99, $paySeed);
check(
    "verifyPaymentImport rejects unregistered alg (UnknownAlg)",
    err_kind(fn() => Payment::verifyPaymentImport($bogus, Cose::PROFILE_PUBLIC, -99, $payPk)),
    "UnknownAlg",
);

// 11. Payment::authorizeCharge (Go impl/go/payment/payment.go:241) — the C21 payment checkpoint: an
//     imported payment is spent SINGLE-USE through the §7 ledger (a replay is AlreadyConsumed) and is
//     bound to the exact charge (a wrong amount, wrong payee, wrong currency, substituted foreign
//     payload, foreign key, expired approval, under-granting approval, or unknown format each denies
//     fail-closed with no ledger append). Ed25519-demonstrated (isolation, NOT corpus-graded; the payment
//     corpus carries no approval/ledger vectors), mirroring impl/go/payment/payment_test.go's
//     TestChargeSingleUseAndBinding.

/** An Ed25519 verify closure standing in for the reference's ML-DSA verifier (PURE-ONLY PHP). */
function pay_ed_verify(string $pk): callable
{
    return static fn(string $msg, string $sig): bool => Cose::ed25519Verify($pk, $msg, $sig);
}

/** A fresh, unique WAL-backed ledger in the OS temp dir (each scenario gets its own so a deny in one
 * scenario cannot be confused with a replay from another). */
function pay_fresh_ledger(): \Naalp\Ledger
{
    $p = \tempnam(\sys_get_temp_dir(), 'naalp_payment_wal_');
    return Approval::openLedger($p);
}

/** Build and sign a §7 approval binding $chargeCid at $grant (real Ed25519, pure-tier stand-in). */
function pay_mk_approval(string $chargeCid, string $approver, int $grant, string $nonceByte, int $notAfter, string $signerSeed): array
{
    $nonce = \str_repeat($nonceByte, 16);
    $rec = new ApprovalRecord($chargeCid, $approver, $grant, $nonce, $notAfter);
    $sig = Approval::signApproval($rec, $signerSeed);
    return [$rec, $sig];
}

$chargeApproverSeed = \str_repeat("\x11", 32);
$chargeApproverPk = \sodium_crypto_sign_publickey(\sodium_crypto_sign_seed_keypair($chargeApproverSeed));
$chargeForeignPk = \sodium_crypto_sign_publickey(\sodium_crypto_sign_seed_keypair(\str_repeat("\x22", 32)));

$pi = import_from($C["imports"]["ap2"]);
$chargeCid = $pi->chargeBinding()->contentId();
[$appr, $apprSig] = pay_mk_approval($chargeCid, "approver-A", Payment::CHARGE_EFFECT, "\x01", $pi->notAfter, $chargeApproverSeed);

$chargeLedger = pay_fresh_ledger();
$entry = null;
check("first charge authorized (no-error)", err_kind(function () use ($pi, $appr, $chargeApproverPk, $apprSig, $chargeLedger, &$entry) {
    $entry = Payment::authorizeCharge($pi, $appr, pay_ed_verify($chargeApproverPk), $apprSig, "payer-1", $pi->notAfter, $chargeLedger);
}), "no-error");
check("first charge consumes at ledger seq 0", $entry !== null ? (string) $entry->seq : "null", "0");
check("replayed charge rejected (AlreadyConsumed)", err_kind(function () use ($pi, $appr, $chargeApproverPk, $apprSig, $chargeLedger) {
    Payment::authorizeCharge($pi, $appr, pay_ed_verify($chargeApproverPk), $apprSig, "payer-1", $pi->notAfter, $chargeLedger);
}), "AlreadyConsumed");
check("ledger has 1 entry after replay (no double-spend)", (string) $chargeLedger->len(), "1");

// A wrong-amount charge yields a different charge content-id, so the approval no longer matches.
$wrongAmountCharge = new PaymentImport($pi->format, $pi->amount + 8000, $pi->currency, $pi->payee, $pi->notAfter, $pi->foreign);
check("wrong-amount charge id == oracle", bin2hex($wrongAmountCharge->chargeBinding()->contentId()), $mm["wrong_amount_charge_id_hex"]);
check("wrong-amount charge denied (ApprovalMismatch)", err_kind(function () use ($wrongAmountCharge, $appr, $chargeApproverPk, $apprSig) {
    Payment::authorizeCharge($wrongAmountCharge, $appr, pay_ed_verify($chargeApproverPk), $apprSig, "payer-1", $wrongAmountCharge->notAfter, pay_fresh_ledger());
}), "ApprovalMismatch");

// A wrong-payee charge likewise fails the binding.
$wrongPayeeCharge = new PaymentImport($pi->format, $pi->amount, $pi->currency, "merchant:evil-store", $pi->notAfter, $pi->foreign);
check("wrong-payee charge id == oracle", bin2hex($wrongPayeeCharge->chargeBinding()->contentId()), $mm["wrong_payee_charge_id_hex"]);
check("wrong-payee charge denied (ApprovalMismatch)", err_kind(function () use ($wrongPayeeCharge, $appr, $chargeApproverPk, $apprSig) {
    Payment::authorizeCharge($wrongPayeeCharge, $appr, pay_ed_verify($chargeApproverPk), $apprSig, "payer-1", $wrongPayeeCharge->notAfter, pay_fresh_ledger());
}), "ApprovalMismatch");

// A substituted foreign payload changes the foreign content-id, hence the charge binding.
$substitutedCharge = new PaymentImport($pi->format, $pi->amount, $pi->currency, $pi->payee, $pi->notAfter, hex2bin($mm["substituted_foreign_hex"]));
check("substituted foreign-id == oracle", bin2hex($substitutedCharge->foreignId()), $mm["substituted_foreign_id_hex"]);
check("substituted charge id == oracle", bin2hex($substitutedCharge->chargeBinding()->contentId()), $mm["substituted_charge_id_hex"]);
check("substituted-payload charge denied (ApprovalMismatch)", err_kind(function () use ($substitutedCharge, $appr, $chargeApproverPk, $apprSig) {
    Payment::authorizeCharge($substitutedCharge, $appr, pay_ed_verify($chargeApproverPk), $apprSig, "payer-1", $substitutedCharge->notAfter, pay_fresh_ledger());
}), "ApprovalMismatch");

// A foreign key never authenticates the approval.
check("foreign-key charge denied (BadSignature)", err_kind(function () use ($pi, $appr, $chargeForeignPk, $apprSig) {
    Payment::authorizeCharge($pi, $appr, pay_ed_verify($chargeForeignPk), $apprSig, "payer-1", $pi->notAfter, pay_fresh_ledger());
}), "BadSignature");

// An expired charge is rejected.
check("expired charge denied (ApprovalExpired)", err_kind(function () use ($pi, $appr, $chargeApproverPk, $apprSig) {
    Payment::authorizeCharge($pi, $appr, pay_ed_verify($chargeApproverPk), $apprSig, "payer-1", $pi->notAfter + 1, pay_fresh_ledger());
}), "ApprovalExpired");

// THE mutation-surviving check: an under-granting approval (read_only cannot authorize a
// non_idempotent_write charge) is denied — the effect-coverage gate.
[$underAppr, $underSig] = pay_mk_approval($chargeCid, "approver-A", Policy::READ_ONLY, "\x03", $pi->notAfter, $chargeApproverSeed);
check("under-granting charge denied (ApprovalRequired)", err_kind(function () use ($pi, $underAppr, $chargeApproverPk, $underSig) {
    Payment::authorizeCharge($pi, $underAppr, pay_ed_verify($chargeApproverPk), $underSig, "payer-1", $pi->notAfter, pay_fresh_ledger());
}), "ApprovalRequired");

// An unknown imported format is not chargeable (checked FIRST, before the approval binding — no ledger
// append, matching the Go reference's check order).
$unkCharge = new PaymentImport($C["unknown_format"], $pi->amount, $pi->currency, $pi->payee, $pi->notAfter, $pi->foreign);
check("unknown-format charge denied (UnknownPaymentFormat)", err_kind(function () use ($unkCharge, $appr, $chargeApproverPk, $apprSig) {
    Payment::authorizeCharge($unkCharge, $appr, pay_ed_verify($chargeApproverPk), $apprSig, "payer-1", $unkCharge->notAfter, pay_fresh_ledger());
}), "UnknownPaymentFormat");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
