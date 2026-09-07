<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C21 NAALP-AGUI UI-consent conformance for the PHP SDK (design.md §24; R-AGUI-1..6), graded against
// the shared independent corpus vectors/agui/cases.json (NOT produced by this code). NAALP-AGUI binds a
// human-in-the-loop approval, captured in a UI event stream (the AG-UI tool-lifecycle events an agent
// shows a user), to the EXACT action bytes by content id, and RECEIPT-CHAINS the shown events so the
// shown sequence is provable offline. It introduces NO new envelope/encoding/signature/audit mechanism:
// a UIEvent {1:session,2:kind,3:action,4:seq,5:prev} is an ordinary signed N-AALP body and reuses the
// C7 audit receipt-chain (head=SHA-384(body), genesis prev=48 zero bytes, monotonic seq, prior head in
// field 5) and the §7 approval binding UNCHANGED.
//
// CORPUS-GRADED (pure, signature-independent): the kind vocabulary, every UI-event body/head/id
// byte-for-byte, the action + substituted content ids, the shown-chain final head, the >2^53 seq
// round-trip, the minimal event, and the wire-format rejections (NonCanonical descending keys, absent
// mandatory field, look-alike missing prev). BEHAVIOURAL (isolation): WalkShown contiguity,
// DetectHole position, VerifyConsent's exact-shown-action binding + ActionSubstituted tie.
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the UI-event signature and the signed
// shown-chain. PHP is PURE-ONLY for ML-DSA (FIPS 204 has no deterministic PHP signer), so the reference
// signs UI events with ML-DSA-65 while this port demonstrates a real Ed25519 (RFC 8032) round-trip; the
// corpus carries no signed vector, so signing is isolation-only. The §7 human approval binding reuses
// the just-landed Approval single-use module UNCHANGED (its verify takes an injected Ed25519 closure).
//
// Written test-first: Naalp\Agui / Naalp\UIEvent are absent until Agui.php lands, so this fails RED with
// a fatal "class not found"; dropping the executed-equals-shown tie in VerifyConsent (the confused-
// deputy mutation) flips "substituted action rejected (ActionSubstituted)".
//
// Run:  php -d extension=sodium -d extension=intl test/agui_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Agui;
use Naalp\UIEvent;
use Naalp\ApprovalRecord;
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
function agui_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/agui/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/agui/cases.json not found");
}

/** An Ed25519 verify closure standing in for the reference's ML-DSA verifier (PURE-ONLY PHP). */
function agui_ed_verify(string $pk): callable
{
    return static fn(string $msg, string $sig): bool => Cose::ed25519Verify($pk, $msg, $sig);
}

/** Build the chain of three UIEvents from the oracle (shared session), in order. */
function agui_events(array $C): array
{
    $session = hex2bin($C["session_hex"]);
    $out = [];
    foreach ($C["chain"]["events"] as $ev) {
        $out[] = new UIEvent($session, $ev["kind"], hex2bin($ev["action_hex"]), $ev["seq"], hex2bin($ev["prev_hex"]));
    }
    return $out;
}

$C = agui_vectors();
echo "agui conformance (PHP) — graded vs vectors/agui/cases.json\n";

// 1. the closed kind vocabulary == the oracle; the unknown kind is not known; genesis is 48 zero bytes.
foreach ($C["kind_vocabulary"] as $k) {
    check("kind {$k['name']} known", Agui::isKnownKind($k["code"]) ? "yes" : "no", "yes");
    check("kind {$k['name']} name", Agui::kindName($k["code"]), $k["name"]);
}
check("unknown kind not known", Agui::isKnownKind($C["unknown_kind"]) ? "yes" : "no", "no");
check("unknown kind name", Agui::kindName($C["unknown_kind"]), "unknown");
check("genesis == oracle", bin2hex(Agui::genesis()), $C["genesis_hex"]);

// 2. every UI-event body/head/id equals the independent oracle, byte-for-byte (=> Go == Python == Rust,
//    which grade the same file). A field-ignoring / constant encoder diverges here.
$events = agui_events($C);
foreach ($events as $i => $e) {
    $ev = $C["chain"]["events"][$i];
    check("event $i body == oracle", bin2hex($e->bytes()), $ev["body_hex"]);
    check("event $i head == oracle", bin2hex($e->head()), $ev["head_hex"]);
    check("event $i id == oracle", bin2hex($e->id()), $ev["id_hex"]);
}

// 3. the action bytes hash to the action content id every event names; a substituted action's bytes
//    hash to a DIFFERENT content id (the whole point of the binding).
check("action bytes -> action content id", bin2hex(Agui::contentId(hex2bin($C["action_bytes_hex"]))), $C["action_cid_hex"]);
check("substituted bytes -> substituted content id", bin2hex(Agui::contentId(hex2bin($C["substituted_bytes_hex"]))), $C["substituted_cid_hex"]);

// 4. WalkShown returns the ordered shown chain, final head == oracle, and ApprovedActionCID names the
//    action shown-and-approved. A gappy chain (omit event 1) is UIChainBroken and DetectHole reports
//    the FIRST-BROKEN POSITION (the §8.5 hole-with-position proof).
$shown = Agui::walkShown($events);
check("walk-shown final head == oracle", bin2hex($shown[count($shown) - 1]->head), $C["chain"]["final_head_hex"]);
[$shownCid, $ok] = Agui::approvedActionCid($shown);
check("approved action cid present", $ok ? "yes" : "no", "yes");
check("approved action cid == action content id", bin2hex($shownCid), $C["action_cid_hex"]);
$gappy = [$events[0], $events[2]]; // omit event 1 (args-shown)
[$pos, $hole] = Agui::detectHole($gappy);
check("gappy chain hole detected", $hole ? "yes" : "no", "yes");
check("gappy chain hole position == oracle", (string) $pos, (string) $C["hole"]["position"]);
check("gappy walk-shown rejected (UIChainBroken)", err_kind(fn() => Agui::walkShown($gappy)), "UIChainBroken");

// 5. VerifyConsent binds the human §7 approval to the EXACT shown action (Ed25519-demonstrated human
//    approval). THE C21 checkpoint + mutation target: the honest verify ties the EXECUTED action bytes
//    to the shown-and-approved content id; dropping that tie wrongly accepts a substituted action.
$humanSeed = str_repeat("\x32", 32);
$humanPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($humanSeed));
$foreignPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x42", 32)));
$actionBytes = hex2bin($C["action_bytes_hex"]);
$actionCid = Agui::contentId($actionBytes);
$notAfter = 1785000000000;
$appr = new ApprovalRecord($actionCid, "human-approver", Policy::NON_IDEMPOTENT_WRITE, str_repeat("\x01", 16), $notAfter);
$apprSig = Cose::ed25519Sign($humanSeed, $appr->bytes());
$hv = agui_ed_verify($humanPk);
$fv = agui_ed_verify($foreignPk);

check("honest consent verifies (exact shown action)", err_kind(fn() => Agui::verifyConsent($events, $actionBytes, $appr, $hv, $apprSig, $notAfter)), "no-error");
// THE mutation-surviving check: a SUBSTITUTED action (different bytes, different content id) is rejected.
$substituted = hex2bin($C["substituted_bytes_hex"]);
check("substituted action rejected (ActionSubstituted)", err_kind(fn() => Agui::verifyConsent($events, $substituted, $appr, $hv, $apprSig, $notAfter)), "ActionSubstituted");
// A foreign key never authenticates the human approval; an expired approval is dead; a chain with no
// approved event has no consent to bind; a gappy chain is not provable.
check("foreign-key consent rejected (BadSignature)", err_kind(fn() => Agui::verifyConsent($events, $actionBytes, $appr, $fv, $apprSig, $notAfter)), "BadSignature");
check("expired consent rejected (ApprovalExpired)", err_kind(fn() => Agui::verifyConsent($events, $actionBytes, $appr, $hv, $apprSig, $notAfter + 1)), "ApprovalExpired");
$shownOnly = [$events[0], $events[1]]; // shown, args-shown — no approved event
check("no-approved consent rejected (UINoConsent)", err_kind(fn() => Agui::verifyConsent($shownOnly, $actionBytes, $appr, $hv, $apprSig, $notAfter)), "UINoConsent");
check("gappy consent rejected (UIChainBroken)", err_kind(fn() => Agui::verifyConsent($gappy, $actionBytes, $appr, $hv, $apprSig, $notAfter)), "UIChainBroken");

// 6. the >2^53 seq discipline (edge case #3): a UI-event seq above 2^53 (0x0102030405060708) round-trips
//    byte-exact (uint64 all the way; the oracle carries seq as a STRING). Mutation: a float64 seq
//    corrupts the low octets and the body / recovered seq diverge.
$bs = $C["big_seq"];
$bigSeq = (int) $bs["seq_str"];
check("big seq > 2^53", $bigSeq > (1 << 53) ? "yes" : "no", "yes");
$eBig = new UIEvent(hex2bin($C["session_hex"]), $bs["kind"], hex2bin($bs["action_hex"]), $bigSeq, hex2bin($bs["prev_hex"]));
check("big-seq body == oracle", bin2hex($eBig->bytes()), $bs["body_hex"]);
check("big-seq id == oracle", bin2hex($eBig->id()), $bs["id_hex"]);
$eBigParsed = Agui::parseUIEvent($eBig->bytes());
check("big-seq round-trip seq (no float64 loss)", (string) $eBigParsed->seq, $bs["seq_str"]);

// 7. the minimal event (edge case #4): empty session, kind shown, empty action, seq 0, genesis prev.
$mn = $C["minimal"];
$eMin = new UIEvent(hex2bin($mn["session_hex"]), $mn["kind"], hex2bin($mn["action_hex"]), $mn["seq"], hex2bin($mn["prev_hex"]));
check("minimal body == oracle", bin2hex($eMin->bytes()), $mn["body_hex"]);
check("minimal id == oracle", bin2hex($eMin->id()), $mn["id_hex"]);
check("minimal round-trips (no error)", err_kind(fn() => Agui::parseUIEvent($eMin->bytes())), "no-error");

// 8. wire-format rejections. #1 descending top-level keys -> NonCanonical (strict decoder); the
//    canonical body parses. #2 an absent mandatory field (action) -> UIMalformed. #5 a look-alike body
//    missing its field-5 chain back-pointer (prev) -> UIMalformed.
$ec = $C["edge_cases"];
$canon = hex2bin($ec["keys_out_of_order"]["canonical_body_hex"]);
$noncanon = hex2bin($ec["keys_out_of_order"]["noncanonical_body_hex"]);
check("canonical body parses (no error)", err_kind(fn() => Agui::parseUIEvent($canon)), "no-error");
check("descending-key body rejected (UIMalformed)", err_kind(fn() => Agui::parseUIEvent($noncanon)), "UIMalformed");
$absent = hex2bin($ec["empty_vs_absent"]["absent_field"]["body_hex"]);
check("absent action field rejected (UIMalformed)", err_kind(fn() => Agui::parseUIEvent($absent)), "UIMalformed");
$emptyAction = hex2bin($ec["empty_vs_absent"]["empty_action"]["body_hex"]);
check("empty-action body parses (present, valid)", err_kind(fn() => Agui::parseUIEvent($emptyAction)), "no-error");
check("empty-action id == oracle (distinct from populated)", bin2hex(Agui::parseUIEvent($emptyAction)->id()), $ec["empty_vs_absent"]["empty_action"]["id_hex"]);
$lookAlike = hex2bin($ec["look_alike"]["body_hex"]);
check("look-alike (missing prev) rejected (UIMalformed)", err_kind(fn() => Agui::parseUIEvent($lookAlike)), "UIMalformed");

// 9. ED25519-DEMONSTRATED (isolation, NOT corpus-graded): a signed shown chain verifies (each event's
//    signature + contiguity); a tampered signature and a foreign key both fail. (The reference signs
//    with ML-DSA-65; PURE-ONLY PHP here.)
$uiSeed = str_repeat("\x31", 32);
$uiPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($uiSeed));
$sigs = [];
foreach ($events as $e) {
    $sigs[] = Agui::signUIEvent($e, $uiSeed);
}
check("signed shown chain verifies", err_kind(fn() => Agui::verifyShownChain($events, $sigs, agui_ed_verify($uiPk))), "no-error");
$tampered = $sigs;
$tampered[1][0] = $tampered[1][0] ^ "\x01";
check("tampered shown-chain signature rejected (BadSignature)", err_kind(fn() => Agui::verifyShownChain($events, $tampered, agui_ed_verify($uiPk))), "BadSignature");
check("foreign-key shown chain rejected (BadSignature)", err_kind(fn() => Agui::verifyShownChain($events, $sigs, agui_ed_verify($foreignPk))), "BadSignature");

// 10. verifyUIEvent (Go reference agui.go:158) — the SINGLE-event verify path pairing with signUIEvent +
//     parseUIEvent: verifies the Ed25519-demonstrated signature over the event body, reconstructs the
//     UIEvent from the signed bytes, and validates the kind against the closed set
//     (UnknownUIEventKind), exactly as VerifyUIEvent does for a full COSE_Sign1 object in the reference —
//     this pure-tier port verifies the RAW Ed25519 signature signUIEvent produces (as verifyShownChain
//     already does per-step), since there is no COSE_Sign1 wrapper in this port's sign convention.
foreach ($events as $i => $e) {
    $sig = Agui::signUIEvent($e, $uiSeed);
    $got = null;
    check("verifyUIEvent event $i verifies (no-error)", err_kind(function () use ($e, $sig, $uiPk, &$got) {
        $got = Agui::verifyUIEvent($e->bytes(), $sig, agui_ed_verify($uiPk));
    }), "no-error");
    if ($got instanceof UIEvent) {
        check("verifyUIEvent event $i reconstructs identical bytes", bin2hex($got->bytes()), bin2hex($e->bytes()));
    }
}
$tamperedSingle = Agui::signUIEvent($events[0], $uiSeed);
$tamperedSingle[0] = $tamperedSingle[0] ^ "\x01";
check("verifyUIEvent tampered signature rejected (BadSignature)", err_kind(fn() => Agui::verifyUIEvent($events[0]->bytes(), $tamperedSingle, agui_ed_verify($uiPk))), "BadSignature");
check("verifyUIEvent foreign key rejected (BadSignature)", err_kind(fn() => Agui::verifyUIEvent($events[0]->bytes(), Agui::signUIEvent($events[0], $uiSeed), agui_ed_verify($foreignPk))), "BadSignature");
// THE mutation-surviving check: an unknown kind (outside the closed set) is rejected even though its
// signature verifies and its wire shape parses cleanly.
$unknownKindEvent = new UIEvent(hex2bin($C["session_hex"]), $C["unknown_kind"], hex2bin($C["action_bytes_hex"]), 0, Agui::genesis());
$unknownKindSig = Agui::signUIEvent($unknownKindEvent, $uiSeed);
check("verifyUIEvent unknown kind rejected (UnknownUIEventKind)", err_kind(fn() => Agui::verifyUIEvent($unknownKindEvent->bytes(), $unknownKindSig, agui_ed_verify($uiPk))), "UnknownUIEventKind");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
