<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C20 governed negotiation, advisory risk labels, and trust references conformance for the PHP SDK
// (design.md §23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4), graded against the shared independent corpus
// vectors/negotiation/cases.json (NOT produced by this code). C20 adds three signed surfaces carried
// on N-AALP's own signed object; it introduces NO new envelope, encoding, signature, identity, or
// audit mechanism (R-11.3), reusing the closed C5 effect lattice, the T1 content-id framing, and the
// §8.2 causal partial order unchanged.
//
// CORPUS-GRADED (pure): every negotiation-message / risk-label / labeled-object / trust-ref
// body/head/content-id byte-for-byte; the closed role & profile vocabularies; the risk vocabulary and
// its gating/informing classes; the critical-extension rule (R-2.5) recognized-set and reject cases;
// the load-bearing effect invariant (a risk label NEVER changes an object's effect class); the descent
// DAG (an accept descends from its offer via a counter; a non-descended accept is rejected); the
// trust-ref content-id recompute (checkable, never weighed); and the strict-decoder edge cases
// (keys-out-of-order, empty-vs-absent, minimal, cross-kind look-alikes).
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the message / labeled-object / trust-ref
// signatures. PHP is PURE-ONLY for ML-DSA (FIPS 204), so the reference's ML-DSA COSE_Sign1 signatures
// are demonstrated with a real Ed25519 (RFC 8032) round-trip via ext-sodium; a foreign key is rejected
// (BadSignature). A cross-language real-ML-DSA signed pin cannot be reproduced in the pure tier, so it
// is documented, not faked (F2/F4).
//
// Written test-first: Naalp\Negotiation is absent until Negotiation.php lands, so this fails RED with a
// fatal "class not found"; escalating LabeledObject::effectClass() on a gating label flips
// "read_only + gating sensitive stays read_only".
//
// Run:  php -d extension=sodium -d extension=intl test/negotiation_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Negotiation;
use Naalp\Message;
use Naalp\RiskLabel;
use Naalp\LabeledObject;
use Naalp\TrustRef;
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
function negotiation_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/negotiation/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/negotiation/cases.json not found");
}

$C = negotiation_vectors();
echo "negotiation conformance (PHP) — graded vs vectors/negotiation/cases.json\n";

$neg = hex2bin($C["negotiation"]["negotiation_hex"]);

/** Build a Message from a corpus message vector (negotiation id from the top-level corpus). */
function msg_from(string $neg, array $mv): Message
{
    $causes = array_map('hex2bin', $mv["causes_hex"]);
    return new Message($neg, $mv["role"], $mv["profile"], $causes);
}

// 1. byte parity vs the non-circular oracle for every negotiation message body/head/id. A mutation to
//    Message::bytes() (key/tag/order) flips a *_hex assertion.
$msgVecs = [
    "offer" => $C["negotiation"]["offer"],
    "counter" => $C["negotiation"]["counter"],
    "accept" => $C["negotiation"]["accept"],
    "offer2" => $C["negotiation"]["offer2"],
    "accept_not_descended" => $C["negotiation"]["accept_not_descended"],
    "unknown_profile_offer" => $C["negotiation"]["unknown_profile_offer"],
    "unknown_role_message" => $C["negotiation"]["unknown_role_message"],
];
foreach ($msgVecs as $name => $mv) {
    $m = msg_from($neg, $mv);
    check("$name message body == oracle", bin2hex($m->bytes()), $mv["body_hex"]);
    check("$name message head == oracle", bin2hex($m->head()), $mv["head_hex"]);
    check("$name message id == oracle", bin2hex($m->id()), $mv["id_hex"]);
}

// 2. the closed role & profile vocabularies == the oracle; an out-of-set code is not known.
foreach ($C["negotiation"]["roles"] as $rname => $code) {
    check("role known: $rname", Negotiation::knownRole($code) ? "true" : "false", "true");
    check("role name of $code", Negotiation::roleName($code), $rname);
}
check("unknown role not known", Negotiation::knownRole(9) ? "true" : "false", "false");
check("unknown role name", Negotiation::roleName(9), "unknown");
foreach ($C["negotiation"]["profiles"] as $pname => $code) {
    check("profile registered: $pname", Negotiation::isRegisteredProfile($code) ? "true" : "false", "true");
    check("profile name of $code", Negotiation::profileName($code), $pname);
}
check("unknown profile not registered", Negotiation::isRegisteredProfile($C["negotiation"]["unknown_profile"]) ? "true" : "false", "false");

// 3. labeled-object byte parity with and without labels, for every effect (the corpus carries 4).
$carried = array_map(fn($c) => new RiskLabel($c["code"], $c["critical"]), $C["risk"]["carried_on_labeled_objects"]);
foreach ($C["risk"]["labeled_objects"] as $lo) {
    $with = new LabeledObject($lo["effect"], $carried);
    check("labeled effect {$lo['effect']} with-labels body == oracle", bin2hex($with->bytes()), $lo["with_labels"]["body_hex"]);
    check("labeled effect {$lo['effect']} with-labels head == oracle", bin2hex($with->head()), $lo["with_labels"]["head_hex"]);
    check("labeled effect {$lo['effect']} with-labels id == oracle", bin2hex($with->id()), $lo["with_labels"]["id_hex"]);
    $without = new LabeledObject($lo["effect"], []);
    check("labeled effect {$lo['effect']} without-labels body == oracle", bin2hex($without->bytes()), $lo["without_labels"]["body_hex"]);
}

// 4. trust-ref byte parity (two registries referencing the same external record).
$refA = new TrustRef(hex2bin($C["trust"]["registry_a_hex"]), hex2bin($C["trust"]["reference_hex"]), hex2bin($C["trust"]["subject_hex"]));
check("trust-ref A body == oracle", bin2hex($refA->bytes()), $C["trust"]["ref_a"]["body_hex"]);
check("trust-ref A head == oracle", bin2hex($refA->head()), $C["trust"]["ref_a"]["head_hex"]);
check("trust-ref A id == oracle", bin2hex($refA->id()), $C["trust"]["ref_a"]["id_hex"]);
$refB = new TrustRef(hex2bin($C["trust"]["registry_b_hex"]), hex2bin($C["trust"]["reference_hex"]), hex2bin($C["trust"]["subject_hex"]));
check("trust-ref B body == oracle", bin2hex($refB->bytes()), $C["trust"]["ref_b"]["body_hex"]);

// 5. governed negotiation: the accept descends from the offer along the causes DAG (via the counter)
//    and yields the agreed pre-registered profile; a non-descended accept is rejected NotDescended.
$offer = msg_from($neg, $C["negotiation"]["offer"]);
$counter = msg_from($neg, $C["negotiation"]["counter"]);
$accept = msg_from($neg, $C["negotiation"]["accept"]);
$offer2 = msg_from($neg, $C["negotiation"]["offer2"]);
$acceptBad = msg_from($neg, $C["negotiation"]["accept_not_descended"]);
// the causes wiring reproduces the oracle (counter->offer, accept->counter, acceptBad->offer2).
check("counter chains onto offer", bin2hex($counter->causes[0]), bin2hex($offer->id()));
check("accept chains onto counter", bin2hex($accept->causes[0]), bin2hex($counter->id()));
$byId = Negotiation::indexById([$offer, $counter, $accept, $offer2, $acceptBad]);
check("accept descends from offer", Negotiation::descends($accept, $offer->id(), $byId) ? "true" : "false", $C["negotiation"]["descends"]["accept_from_offer"] ? "true" : "false");
$agreed = Negotiation::verifyAccept($accept, $offer, $byId);
check("agreed profile == oracle", (string) $agreed, (string) $C["negotiation"]["agreed_profile"]);
check("acceptBad does NOT descend", Negotiation::descends($acceptBad, $offer->id(), $byId) ? "true" : "false", $C["negotiation"]["descends"]["accept_bad_from_offer"] ? "true" : "false");
check("non-descended accept rejected (NotDescended)", err_kind(fn() => Negotiation::verifyAccept($acceptBad, $offer, $byId)), "NotDescended");
check("non-offer-as-offer rejected (NotOffer)", err_kind(fn() => Negotiation::verifyAccept($accept, $counter, $byId)), "NotOffer");
check("non-accept-as-accept rejected (NotAccept)", err_kind(fn() => Negotiation::verifyAccept($counter, $offer, $byId)), "NotAccept");

// 6. ED25519-DEMONSTRATED (isolation): every message signs & verifies under the real key; a foreign
//    key is rejected (BadSignature); an unknown profile / unknown role is rejected at verify.
$seed = str_repeat("\x11", 32);
$pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
$foreignPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x22", 32)));
$offerObj = Negotiation::signMessage($offer, $seed);
check("signed message verifies under real key", err_kind(fn() => Negotiation::verifyMessage($offerObj, Cose::PROFILE_PUBLIC, $pk)), "no-error");
check("signed message rejected under foreign key (BadSignature)", err_kind(fn() => Negotiation::verifyMessage($offerObj, Cose::PROFILE_PUBLIC, $foreignPk)), "BadSignature");
$unkProfObj = Negotiation::signMessage(msg_from($neg, $C["negotiation"]["unknown_profile_offer"]), $seed);
check("unknown-profile message rejected (UnknownProfile)", err_kind(fn() => Negotiation::verifyMessage($unkProfObj, Cose::PROFILE_PUBLIC, $pk)), "UnknownProfile");
$unkRoleObj = Negotiation::signMessage(msg_from($neg, $C["negotiation"]["unknown_role_message"]), $seed);
check("unknown-role message rejected (UnknownRole)", err_kind(fn() => Negotiation::verifyMessage($unkRoleObj, Cose::PROFILE_PUBLIC, $pk)), "UnknownRole");

// 7. advisory risk labels: vocabulary/class == oracle; the critical-extension rule (R-2.5); the
//    LOAD-BEARING invariant that a risk label NEVER changes an object's effect class.
foreach ($C["risk"]["vocabulary"] as $e) {
    [$class, $ok] = Negotiation::riskClassOf($e["code"]);
    check("risk vocab {$e['name']} registered", $ok ? "true" : "false", "true");
    check("risk vocab {$e['name']} class == oracle", Negotiation::riskClassName($class), $e["class"]);
}
check("extensible range start == oracle", (string) Negotiation::EXTENSIBLE_RANGE_START, (string) $C["risk"]["extensible_range_start"]);
// recognized set: recognized-plus-unknown-noncritical validates; the unknown non-critical is dropped.
$recCarried = array_map(fn($c) => new RiskLabel($c["code"], $c["critical"]), $C["risk"]["validate"]["recognized_set"]["carried"]);
$recognized = Negotiation::validateLabels($recCarried);
$recCodes = array_map(fn($l) => $l->code, $recognized);
check("recognized codes == oracle", implode(",", $recCodes), implode(",", $C["risk"]["validate"]["recognized_set"]["recognized_codes"]));
// unknown CRITICAL label is rejected (R-2.5).
$critCarried = array_map(fn($c) => new RiskLabel($c["code"], $c["critical"]), $C["risk"]["validate"]["unknown_critical_rejected"]["carried"]);
check("unknown-critical label rejected (UnknownCriticalRisk)", err_kind(fn() => Negotiation::validateLabels($critCarried)), $C["risk"]["validate"]["unknown_critical_rejected"]["error"]);
// a critical flag outside {0,1} is rejected at parse time (no CBOR boolean).
$badFlag = (new LabeledObject(0, [new RiskLabel(Negotiation::RISK_SENSITIVE, 2)]))->bytes();
check("malformed critical flag rejected (MalformedCriticalFlag)", err_kind(fn() => Negotiation::parseLabeledObject($badFlag)), "MalformedCriticalFlag");
// THE load-bearing C20 invariant (the mutation target): carrying a risk label NEVER changes the effect
// class. For every effect, with-labels EffectClass == without == the oracle's normalized effect.
foreach ($C["risk"]["labeled_objects"] as $lo) {
    $with = new LabeledObject($lo["effect"], $carried);
    $without = new LabeledObject($lo["effect"], []);
    check("labeled {$lo['effect_name']} with-labels effect class == oracle", (string) $with->effectClass(), (string) $lo["effect_class"]);
    check("labeled {$lo['effect_name']} labels do not change effect class", (string) $with->effectClass(), (string) $without->effectClass());
}
// concretely: a read_only object carrying the gating "sensitive" label is STILL read_only.
$sensitive = new LabeledObject(Policy::READ_ONLY, [new RiskLabel(Negotiation::RISK_SENSITIVE, 1)]);
check("read_only + gating sensitive stays read_only", (string) $sensitive->effectClass(), (string) Policy::READ_ONLY);

// 8. trust references are CHECKABLE (content-id recompute) but NEVER weighed on the wire.
$record = hex2bin($C["trust"]["external_record_hex"]);
$tampered = hex2bin($C["trust"]["tampered_record_hex"]);
$reference = hex2bin($C["trust"]["reference_hex"]);
check("trust-ref binds its external record", $refA->bindsRecord($record) ? "true" : "false", "true");
check("trust-ref does NOT bind a tampered record", $refA->bindsRecord($tampered) ? "true" : "false", "false");
$refObj = Negotiation::signTrustRef($refA, $seed);
$resolved = Negotiation::verifyTrustRef($refObj, Cose::PROFILE_PUBLIC, $pk, $record);
check("verifyTrustRef honest resolves the reference", bin2hex($resolved->reference), bin2hex($reference));
check("verifyTrustRef rejects a tampered record (ReferenceMismatch)", err_kind(fn() => Negotiation::verifyTrustRef($refObj, Cose::PROFILE_PUBLIC, $pk, $tampered)), "ReferenceMismatch");
check("verifyTrustRef rejects a foreign key (BadSignature)", err_kind(fn() => Negotiation::verifyTrustRef($refObj, Cose::PROFILE_PUBLIC, $foreignPk, $record)), "BadSignature");
// two DIFFERENT registries referencing the SAME record both verify — the wire weighs neither.
$refBObj = Negotiation::signTrustRef($refB, $seed);
$resolvedB = Negotiation::verifyTrustRef($refBObj, Cose::PROFILE_PUBLIC, $pk, $record);
check("two registries, same record, symmetric references", bin2hex($resolved->reference), bin2hex($resolvedB->reference));
check("two registries actually differ (fixture)", $resolved->registry === $resolvedB->registry ? "same" : "distinct", "distinct");

// 9. wire-format edge cases (strict decoder).
$ekoo = $C["edge_cases"]["keys_out_of_order"];
check("canonical offer body decodes", err_kind(fn() => Cbor::decode(hex2bin($ekoo["canonical_offer_body_hex"]))), "no-error");
check("descending-keys offer body rejected (NonCanonical)", err_kind(fn() => Cbor::decode(hex2bin($ekoo["noncanonical_offer_body_hex"]))), "NonCanonical");
check("parseMessage rejects the descending-keys body (NegMalformed)", err_kind(fn() => Negotiation::parseMessage(hex2bin($ekoo["noncanonical_offer_body_hex"]))), "NegMalformed");
$eca = $C["edge_cases"]["empty_vs_absent"]["causes"];
$emptyCauses = new Message(strval("neg-0001"), 0, 0, []);
check("empty causes body == oracle", bin2hex($emptyCauses->bytes()), $eca["empty_present"]["body_hex"]);
$oneCause = new Message(strval("neg-0001"), 0, 0, [hex2bin($eca["one_cause"]["cause_hex"])]);
check("one-cause body == oracle", bin2hex($oneCause->bytes()), $eca["one_cause"]["body_hex"]);
check("empty != one-cause by id", $emptyCauses->id() === $oneCause->id() ? "same" : "distinct", "distinct");
check("absent causes field rejected (NegMalformed)", err_kind(fn() => Negotiation::parseMessage(hex2bin($eca["absent_field"]["body_hex"]))), "NegMalformed");
$elb = $C["edge_cases"]["empty_vs_absent"]["labels"];
$emptyLabels = new LabeledObject(0, []);
check("empty labels body == oracle", bin2hex($emptyLabels->bytes()), $elb["empty_present"]["body_hex"]);
$oneLabel = new LabeledObject(0, [new RiskLabel($elb["one_label"]["code"], $elb["one_label"]["critical"])]);
check("one-label body == oracle", bin2hex($oneLabel->bytes()), $elb["one_label"]["body_hex"]);
check("absent labels field rejected (NegMalformed)", err_kind(fn() => Negotiation::parseLabeledObject(hex2bin($elb["absent_field"]["body_hex"]))), "NegMalformed");
$em = $C["edge_cases"]["minimal"];
$minOffer = new Message(hex2bin($em["offer"]["negotiation_hex"]), $em["offer"]["role"], $em["offer"]["profile"], []);
check("minimal offer body == oracle", bin2hex($minOffer->bytes()), $em["offer"]["body_hex"]);
check("minimal offer id == oracle", bin2hex($minOffer->id()), $em["offer"]["id_hex"]);
check("minimal offer round-trips", err_kind(fn() => Negotiation::parseMessage($minOffer->bytes())), "no-error");
$minLo = new LabeledObject($em["labeled_object"]["effect"], []);
check("minimal labeled-object body == oracle", bin2hex($minLo->bytes()), $em["labeled_object"]["body_hex"]);
$minTr = new TrustRef("", "", "");
check("minimal trust-ref body == oracle", bin2hex($minTr->bytes()), $em["trust_ref"]["body_hex"]);
check("minimal trust-ref id == oracle", bin2hex($minTr->id()), $em["trust_ref"]["id_hex"]);
// cross-kind look-alikes: a trust-ref body fed to parseMessage, and a message body fed to parseTrustRef.
$la = $C["edge_cases"]["look_alike"];
check("trust-ref body rejected as a message (NegMalformed)", err_kind(fn() => Negotiation::parseMessage(hex2bin($la["trust_ref_as_message"]["body_hex"]))), "NegMalformed");
check("message body rejected as a trust-ref (NegMalformed)", err_kind(fn() => Negotiation::parseTrustRef(hex2bin($la["message_as_trust_ref"]["body_hex"]))), "NegMalformed");

// 10. remaining port-surface functions exercised in isolation (constructors reproduce the oracle
//     bodies; labeled-object sign/verify; the extensible-range predicate; the trust-ref reference
//     accessor; the LabeledObject instance validator).
check("newOffer builds the oracle offer body", bin2hex(Negotiation::newOffer($neg, Negotiation::PROFILE_BASELINE)->bytes()), $C["negotiation"]["offer"]["body_hex"]);
check("newCounter builds the oracle counter body", bin2hex(Negotiation::newCounter($neg, Negotiation::PROFILE_STREAMING, $offer->id())->bytes()), $C["negotiation"]["counter"]["body_hex"]);
check("newAccept builds the oracle accept body", bin2hex(Negotiation::newAccept($neg, Negotiation::PROFILE_STREAMING, $counter->id())->bytes()), $C["negotiation"]["accept"]["body_hex"]);
$lo0 = new LabeledObject($C["risk"]["labeled_objects"][0]["effect"], $carried);
$loObj = Negotiation::signLabeledObject($lo0, $seed);
[$vlo, $recog] = Negotiation::verifyLabeledObject($loObj, Cose::PROFILE_PUBLIC, $pk);
check("signed labeled-object verifies (effect class / recognized count)", (string) $vlo->effectClass() . "/" . count($recog), (string) $C["risk"]["labeled_objects"][0]["effect_class"] . "/" . count($carried));
check("labeled-object verify rejects foreign key (BadSignature)", err_kind(fn() => Negotiation::verifyLabeledObject($loObj, Cose::PROFILE_PUBLIC, $foreignPk)), "BadSignature");
check("inExtensibleRange on boundary code", Negotiation::inExtensibleRange(Negotiation::EXTENSIBLE_RANGE_START) ? "true" : "false", "true");
check("inExtensibleRange on standard code", Negotiation::inExtensibleRange(Negotiation::RISK_SENSITIVE) ? "true" : "false", "false");
check("trust-ref referenceId == carried reference", bin2hex($refA->referenceId()), bin2hex($reference));
check("LabeledObject::validateLabels drops unknown non-critical", (string) count((new LabeledObject(0, $recCarried))->validateLabels()), (string) count($C["risk"]["validate"]["recognized_set"]["recognized_codes"]));

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
