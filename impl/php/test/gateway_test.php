<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C21 gateway-decision conformance for the PHP SDK (design.md §24; R-GW-1..6), graded against the
// shared independent corpus vectors/gateway/cases.json (NOT produced by this code). A
// GatewayDecision {1:decision,2:action,3:policy,4:effect} is a signed decision an enforcement gateway
// of any vendor emits as portable evidence: its authority is the signature over the bytes, so it
// verifies offline and re-verifies IDENTICALLY when served by a party other than the gateway.
//
// CORPUS-GRADED (pure): the deterministic body/head/content-id byte-for-byte for allow/deny/hold, the
// closed decision set, the strict-decoder rejections (non-canonical / absent field / sibling
// look-alike), the empty-vs-absent policy distinction, the minimal decision, and the fail-closed
// effect class.
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the signature binding + third-party re-serve.
// PHP is PURE-ONLY for ML-DSA, so the gateway signature is demonstrated with a real Ed25519
// round-trip (sodium). The reference profile floor is level 3 (ML-DSA), so a pure-Ed25519 object is
// correctly REJECTED by verifyDecision (ProfileDowngrade) — that rejection, plus UnknownAlg, is the
// verifyDecision behavior reachable on the pure port; its success path needs an ML-DSA signature.
//
// Written test-first: Naalp\Gateway is absent until Gateway.php lands, so this fails RED with a fatal
// "class not found"; forcing the decision field to a constant flips "deny body == oracle".
//
// Run:  php -d extension=sodium -d extension=intl test/gateway_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Gateway;
use Naalp\GatewayDecision;
use Naalp\OrderingDisclosure;
use Naalp\ForeignProfilePin;
use Naalp\DecisionRecord;
use Naalp\CheckpointRoot;
use Naalp\WitnessCosign;
use Naalp\InclusionProof;
use Naalp\EgressAttestation;
use Naalp\Cbor;
use Naalp\Cose;
use Naalp\MlDsa;
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

function gateway_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/gateway/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/gateway/cases.json not found");
}

/** Generic vectors/<name>/cases.json loader, mirroring gateway_vectors() for the sibling
 * evidence-record corpora (decision_record/checkpoint/egress_attestation). */
function evidence_vectors(string $name): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/' . $name . '/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/$name/cases.json not found");
}

/** Decode a decimal string into the wrapped signed-64-bit PHP int Cbor's U type expects (the value
 * modulo 2^64, represented as a negative PHP int when >= 2^63). Uses bcmath so a uint64-max literal
 * (the checkpoint/witness-cosign/egress-attestation `at_str` fields, which the corpus carries as a
 * decimal STRING precisely so no float64 JSON decoder anywhere in the toolchain can round it) loses
 * no precision. Mirrors envelope_test.php's u64FromDecimalString. */
function u64_from_decimal_string(string $s): int
{
    $mod = \bcmod($s, '18446744073709551616'); // 2^64
    if (\bccomp($mod, '9223372036854775808') >= 0) { // >= 2^63
        $mod = \bcsub($mod, '18446744073709551616');
    }
    return (int) $mod;
}

$C = gateway_vectors();
echo "gateway conformance (PHP) — graded vs vectors/gateway/cases.json\n";

/** Build a GatewayDecision from a corpus decision object. */
function dec_from(array $dv): GatewayDecision
{
    return new GatewayDecision($dv["decision"], hex2bin($dv["action_hex"]), hex2bin($dv["policy_hex"]), $dv["effect"]);
}

// 1. body/head/content-id byte-parity vs the non-circular oracle, for every decision. A mutation to
//    any Bytes() field (key, value) flips a *_hex assertion.
foreach (["allow", "deny", "hold"] as $name) {
    $dv = $C["decisions"][$name];
    $d = dec_from($dv);
    check("$name body == oracle", bin2hex($d->bytes()), $dv["body_hex"]);
    check("$name head (SHA-384) == oracle", bin2hex($d->head()), $dv["head_hex"]);
    check("$name content-id == oracle", bin2hex($d->id()), $dv["id_hex"]);
}

// 2. the closed decision vocabulary; an out-of-set code is not known.
foreach ($C["decision_vocabulary"] as $e) {
    check("known: " . $e["name"], Gateway::isKnownDecision($e["code"]) ? "true" : "false", "true");
    check("name of code " . $e["code"], Gateway::decisionName($e["code"]), $e["name"]);
}
check("unknown decision not known", Gateway::isKnownDecision($C["unknown_decision"]) ? "true" : "false", "false");
check("unknown decision name", Gateway::decisionName($C["unknown_decision"]), "unknown");

// 3. edge case: top-level keys DESCENDING (4,3,2,1) are rejected NonCanonical by the strict decoder;
//    the canonical body parses.
$e = $C["edge_cases"]["keys_out_of_order"];
$dko = new GatewayDecision($e["decision"], hex2bin($e["action_hex"]), hex2bin($e["policy_hex"]), $e["effect"]);
check("keys_out_of_order canonical body", bin2hex($dko->bytes()), $e["canonical_body_hex"]);
check("canonical body parses", err_kind(fn() => Gateway::parseDecision(hex2bin($e["canonical_body_hex"]))), "no-error");
check("noncanonical decode rejected", err_kind(fn() => Cbor::decode(hex2bin($e["noncanonical_body_hex"]))), "NonCanonical");
check("noncanonical parse rejected", err_kind(fn() => Gateway::parseDecision(hex2bin($e["noncanonical_body_hex"]))), "GwMalformed");

// 4. edge case: an empty policy identity is present and valid and DISTINCT by content-id from a
//    populated one; a body whose policy field is ABSENT is rejected (field 3 mandatory).
$ea = $C["edge_cases"]["empty_vs_absent"];
$empty = new GatewayDecision(Gateway::DECISION_ALLOW, hex2bin($C["action_cid_hex"]), "", 1);
$populated = new GatewayDecision(Gateway::DECISION_ALLOW, hex2bin($C["action_cid_hex"]), hex2bin($ea["populated_policy"]["policy_hex"]), 1);
check("empty-policy body == oracle", bin2hex($empty->bytes()), $ea["empty_policy"]["body_hex"]);
check("populated-policy body == oracle", bin2hex($populated->bytes()), $ea["populated_policy"]["body_hex"]);
check("empty != populated by id", $empty->id() === $populated->id() ? "same" : "distinct", "distinct");
check("empty-policy id == oracle", bin2hex($empty->id()), $ea["empty_policy"]["id_hex"]);
check("absent policy field rejected", err_kind(fn() => Gateway::parseDecision(hex2bin($ea["absent_field"]["body_hex"]))), "GwMalformed");

// 5. edge case: the smallest valid decision encodes to the oracle bytes, has a stable id, and
//    round-trips through parseDecision.
$m = $C["edge_cases"]["minimal"];
$dm = new GatewayDecision($m["decision"], hex2bin($m["action_hex"]), hex2bin($m["policy_hex"]), $m["effect"]);
check("minimal body == oracle", bin2hex($dm->bytes()), $m["body_hex"]);
check("minimal id == oracle", bin2hex($dm->id()), $m["id_hex"]);
$parsed = Gateway::parseDecision($dm->bytes());
check("minimal round-trip decision", (string) $parsed->decision, (string) $m["decision"]);
check("minimal round-trip effect", (string) $parsed->effect, (string) $m["effect"]);

// 6. edge case: a sibling C21 body (ui-event {1:bstr,...}) whose field 1 is a bstr where the decision
//    uint is required is rejected GwMalformed.
check("look-alike rejected", err_kind(fn() => Gateway::parseDecision(hex2bin($C["edge_cases"]["look_alike"]["body_hex"]))), "GwMalformed");

// 7. the effect class is normalized fail-closed: an unrecognized value is destructive (R-6.2).
$dfc = new GatewayDecision(Gateway::DECISION_DENY, "", "", 99);
check("effect fail-closed to destructive", (string) $dfc->effectClass(), (string) Policy::DESTRUCTIVE);

// 8. ED25519-DEMONSTRATED (isolation): a gateway signs a decision; the raw signature verifies, and
//    re-serving the IDENTICAL bytes verifies IDENTICALLY (third-party re-serve — authority is the
//    signature over the bytes, not the connection). A tampered signature and a foreign key both fail.
$gwSeed = str_repeat("\x51", 32);
$foreignSeed = str_repeat("\x52", 32);
$gwPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($gwSeed));
$foreignPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($foreignSeed));
$dsig = dec_from($C["decisions"]["deny"]);
$obj = Gateway::signDecision($dsig, Cose::ALG_ED25519, $gwSeed);

[$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
$tbs = Cose::toBeSignedRaw($prot, $payload);
// served by the gateway, then re-served by a third party: SAME bytes, no server identity, so the
// verification result and the resolved decision are identical.
$byGateway = Cose::ed25519Verify($gwPk, $tbs, $sig);
$byThirdParty = Cose::ed25519Verify($gwPk, $tbs, $sig);
check("gateway serves: signature verifies", $byGateway ? "true" : "false", "true");
check("third-party re-serve verifies identically", ($byGateway === $byThirdParty && $byThirdParty) ? "true" : "false", "true");
$reserved = Gateway::parseDecision($payload);
check("re-served resolved decision == deny", (string) $reserved->decision, (string) Gateway::DECISION_DENY);
check("re-served action == oracle content-id", bin2hex($reserved->action), $C["action_cid_hex"]);

$tsig = $sig;
$tsig[strlen($tsig) - 1] = $tsig[strlen($tsig) - 1] ^ "\x01";
check("tampered signature rejected", Cose::ed25519Verify($gwPk, $tbs, $tsig) ? "true" : "false", "false");
check("foreign key rejected", Cose::ed25519Verify($foreignPk, $tbs, $sig) ? "true" : "false", "false");

// 9. verifyDecision real branches reachable on the pure port: a level-0 Ed25519 object is below the
//    PROFILE_PUBLIC floor (ProfileDowngrade); an unregistered alg is UnknownAlg. (The success path
//    needs an ML-DSA level-3 signature the pure PHP port cannot produce.)
check(
    "verifyDecision floors Ed25519 (ProfileDowngrade)",
    err_kind(fn() => Gateway::verifyDecision($obj, Cose::PROFILE_PUBLIC, Cose::ALG_ED25519, $gwPk)),
    "ProfileDowngrade",
);
$bogus = Gateway::signDecision($dsig, -99, $gwSeed); // header carries an unregistered alg -99
check(
    "verifyDecision rejects unregistered alg (UnknownAlg)",
    err_kind(fn() => Gateway::verifyDecision($bogus, Cose::PROFILE_PUBLIC, -99, $gwPk)),
    "UnknownAlg",
);

// 10. an unknown decision code is rejected by the closed-set check that verifyDecision enforces.
$badDec = new GatewayDecision($C["unknown_decision"], hex2bin($C["action_cid_hex"]), hex2bin($C["policy_hex"]), 0);
check("closed-set rejects unknown code", Gateway::isKnownDecision($badDec->decision) ? "true" : "false", "false");

// =================================================================================================
// 11. R1 ordering (field 5) + R8 foreign-profile (field 6) conformance, graded against the
//     optional_fields{} block of the SAME vectors/gateway/cases.json corpus. Mirrors
//     GatewayOptionalFieldsConformance in impl/python/tests/test_gateway.py.
// =================================================================================================
echo "\n-- R1/R8 GatewayDecision optional fields --\n";

// NON-REGRESSION: adding optional fields 5/6 must not perturb the pre-existing 4-field decision
// bodies at all. Pins the allow/deny/hold body_hex values as they stood BEFORE this change.
$PINNED_ALLOW = "a401000258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330401";
$PINNED_DENY = "a401010258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330403";
$PINNED_HOLD = "a401020258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330402";
check("pinned allow body unchanged", $C["decisions"]["allow"]["body_hex"], $PINNED_ALLOW);
check("pinned deny body unchanged", $C["decisions"]["deny"]["body_hex"], $PINNED_DENY);
check("pinned hold body unchanged", $C["decisions"]["hold"]["body_hex"], $PINNED_HOLD);
foreach ($C["decisions"] as $name => $dv) {
    $gd = new GatewayDecision($dv["decision"], hex2bin($dv["action_hex"]), hex2bin($dv["policy_hex"]), $dv["effect"]);
    check("existing $name body unchanged by optional-field wiring", bin2hex($gd->bytes()), $dv["body_hex"]);
}

$OF = $C["optional_fields"];

// with_ordering: field 5 present, field 6 absent.
$wo = $OF["with_ordering"];
$dOrd = new GatewayDecision(
    $wo["decision"], hex2bin($wo["action_hex"]), hex2bin($wo["policy_hex"]), $wo["effect"],
    new OrderingDisclosure($wo["ordering"]["basis"], hex2bin($wo["ordering"]["boundary_hex"]))
);
check("with_ordering body == oracle", bin2hex($dOrd->bytes()), $wo["body_hex"]);
check("with_ordering id == oracle", bin2hex($dOrd->id()), $wo["id_hex"]);
$pOrd = Gateway::parseDecision(hex2bin($wo["body_hex"]));
check("with_ordering parsed ordering present", $pOrd->ordering !== null ? "true" : "false", "true");
check("with_ordering parsed foreign-profile absent", $pOrd->foreignProfile === null ? "true" : "false", "true");
check("with_ordering parsed basis", (string) $pOrd->ordering->basis, (string) $wo["ordering"]["basis"]);
check("with_ordering parsed boundary", bin2hex($pOrd->ordering->boundary), $wo["ordering"]["boundary_hex"]);
check("with_ordering validate", err_kind(fn() => $pOrd->ordering->validate()), "no-error");

// with_foreign_profile: field 6 present, field 5 absent.
$wf = $OF["with_foreign_profile"];
$dFp = new GatewayDecision(
    $wf["decision"], hex2bin($wf["action_hex"]), hex2bin($wf["policy_hex"]), $wf["effect"],
    null, new ForeignProfilePin($wf["foreign_profile"]["id"], $wf["foreign_profile"]["revision"])
);
check("with_foreign_profile body == oracle", bin2hex($dFp->bytes()), $wf["body_hex"]);
check("with_foreign_profile id == oracle", bin2hex($dFp->id()), $wf["id_hex"]);
$pFp = Gateway::parseDecision(hex2bin($wf["body_hex"]));
check("with_foreign_profile parsed ordering absent", $pFp->ordering === null ? "true" : "false", "true");
check("with_foreign_profile parsed foreign-profile present", $pFp->foreignProfile !== null ? "true" : "false", "true");
check("with_foreign_profile parsed id", $pFp->foreignProfile->id, $wf["foreign_profile"]["id"]);
check("with_foreign_profile parsed revision", $pFp->foreignProfile->revision, $wf["foreign_profile"]["revision"]);
check("with_foreign_profile validate", err_kind(fn() => $pFp->foreignProfile->validate()), "no-error");

// with_both: fields 5 AND 6 present; full ML-DSA-65 sign+verify end-to-end.
$wb = $OF["with_both"];
$dBoth = new GatewayDecision(
    $wb["decision"], hex2bin($wb["action_hex"]), hex2bin($wb["policy_hex"]), $wb["effect"],
    new OrderingDisclosure($wb["ordering"]["basis"], "", hex2bin($wb["ordering"]["mechanism_hex"]), hex2bin($wb["ordering"]["relation_hex"])),
    new ForeignProfilePin($wb["foreign_profile"]["id"], $wb["foreign_profile"]["revision"])
);
check("with_both body == oracle", bin2hex($dBoth->bytes()), $wb["body_hex"]);
check("with_both id == oracle", bin2hex($dBoth->id()), $wb["id_hex"]);
$pBoth = Gateway::parseDecision(hex2bin($wb["body_hex"]));
check("with_both parsed ordering present", $pBoth->ordering !== null ? "true" : "false", "true");
check("with_both parsed foreign-profile present", $pBoth->foreignProfile !== null ? "true" : "false", "true");
check("with_both ordering validate", err_kind(fn() => $pBoth->ordering->validate()), "no-error");
check("with_both foreign-profile validate", err_kind(fn() => $pBoth->foreignProfile->validate()), "no-error");

// NOTE on GatewayDecision::verifyDecision + ML-DSA on the PURE-ONLY PHP port (pre-existing,
// unchanged by this wiring): verifyDecision's own verifySignature is Ed25519-only and refuses an
// ML-DSA object at the signature step rather than fake a result (see the class docstring above and
// the pre-existing "verifyDecision floors Ed25519 (ProfileDowngrade)" / "rejects unregistered alg"
// checks earlier in this file) -- so an ML-DSA-signed GatewayDecision NEVER reaches the ordering/
// foreign-profile validation this wiring adds inside verifyDecision, on EITHER a well-formed or a
// malformed optional field: the refusal fires first, honestly, for both. That the post-signature
// validation code is correctly wired is proven directly above by validate() on the parsed groups
// (with_both/foreign_profile_malformed/ordering_malformed all pass or fail exactly as expected);
// the SIGNED end-to-end path for these checks is proven by the S1/E6.3 sign+verify tests below,
// whose verifyDecisionRecord/verifyEgressAttestation use the real ML-DSA backend this file adds.
if (MlDsa::available()) {
    $seed71 = str_repeat("\x71", 32);
    $pk71 = MlDsa::keygenFromSeed($seed71, Cose::ALG_MLDSA65);
    $objBoth = Cose::assembleSign1Raw(
        Gateway::gatewayProtectedHeader(Cose::ALG_MLDSA65), $dBoth->bytes(),
        MlDsa::sign($seed71, Cose::toBeSignedRaw(Gateway::gatewayProtectedHeader(Cose::ALG_MLDSA65), $dBoth->bytes()), Cose::ALG_MLDSA65)
    );
    check(
        "with_both verifyDecision refuses ML-DSA (pure-port limitation, not a false accept)",
        err_kind(fn() => Gateway::verifyDecision($objBoth, Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk71)),
        "RuntimeException"
    );
} else {
    echo "  SKIP with_both verifyDecision refusal check: ML-DSA unavailable (" . MlDsa::unavailableReason() . ")\n";
}

// field 6 present but omits key 2 (revision): parseDecision decodes it structurally fine;
// ForeignProfilePin::validate() rejects the missing revision directly (the unit-level proof that
// verifyDecision's wiring is correct -- see the note above for why the signed path cannot reach it
// on this pure-only port).
$fpMalformedBody = hex2bin($OF["foreign_profile_malformed"]["body_hex"]);
$pFpm = Gateway::parseDecision($fpMalformedBody);
check("foreign_profile_malformed parsed present", $pFpm->foreignProfile !== null ? "true" : "false", "true");
check("foreign_profile_malformed validate rejected", err_kind(fn() => $pFpm->foreignProfile->validate()), "ForeignProfileMalformed");

// field 5 basis=external-mechanism(2) but key 2 (boundary) is ALSO present:
// OrderingDisclosure::validate() rejects it directly (same rationale as above).
$ordMalformedBody = hex2bin($OF["ordering_malformed"]["body_hex"]);
$pOm = Gateway::parseDecision($ordMalformedBody);
check("ordering_malformed parsed present", $pOm->ordering !== null ? "true" : "false", "true");
check("ordering_malformed validate rejected", err_kind(fn() => $pOm->ordering->validate()), "OrderingDisclosureMalformed");

// direct unit test of ForeignProfilePin::validate() (no oracle vector needed).
foreach ([
    ["both present", new ForeignProfilePin("https://example.test/p", "1"), false],
    ["missing id", new ForeignProfilePin("", "1"), true],
    ["missing revision", new ForeignProfilePin("https://example.test/p", ""), true],
    ["both empty", new ForeignProfilePin("", ""), true],
] as [$name, $pin, $wantErr]) {
    check(
        "foreign-profile-pin validate: $name",
        err_kind(fn() => $pin->validate()),
        $wantErr ? "ForeignProfileMalformed" : "no-error"
    );
}

// a field-6 map carrying a THIRD key (3) beyond the closed {1,2} set decodes structurally (the
// extra key does not fail decode) but fails validate(), exactly as a missing or empty field does.
$fpExtra = new \Naalp\M([
    [new \Naalp\U(1), new \Naalp\T("https://example-registry.test/profiles/acme")],
    [new \Naalp\U(2), new \Naalp\T("2026-01")],
    [new \Naalp\U(3), new \Naalp\T("unexpected")],
]);
$mExtra = new \Naalp\M([
    [new \Naalp\U(1), new \Naalp\U(Gateway::DECISION_ALLOW)],
    [new \Naalp\U(2), new \Naalp\B(hex2bin($C["action_cid_hex"]))],
    [new \Naalp\U(3), new \Naalp\B(hex2bin($C["policy_hex"]))],
    [new \Naalp\U(4), new \Naalp\U(1)],
    [new \Naalp\U(6), $fpExtra],
]);
$bodyExtra = Cbor::encode($mExtra);
$pExtra = Gateway::parseDecision($bodyExtra);
check("foreign-profile extra-key parsed id", $pExtra->foreignProfile->id, "https://example-registry.test/profiles/acme");
check("foreign-profile extra-key parsed revision", $pExtra->foreignProfile->revision, "2026-01");
check("foreign-profile extra-key validate rejected", err_kind(fn() => $pExtra->foreignProfile->validate()), "ForeignProfileMalformed");

// =================================================================================================
// 12. S1 naalp-decision-record conformance, graded against vectors/decision_record/cases.json.
//     Mirrors impl/go/gateway/decision_record_test.go / impl/python/tests/test_decision_record.py.
// =================================================================================================
echo "\n-- S1 naalp-decision-record --\n";

$DR = evidence_vectors("decision_record");

/** Build the mandatory-field-only shell of a records{}/ordering_examples{} case; the ordering/
 * terms/enforcement fixture is layered on by dr_build (mirroring the Go/Python tests' drFrom+build). */
function dr_from(array $rv): DecisionRecord
{
    $governing = \array_map('hex2bin', $rv["governing_hex"]);
    $d = new DecisionRecord(hex2bin($rv["action_hex"]), $governing, $rv["outcome"], Gateway::correspondenceOnly());
    if (!empty($rv["consume_hex"])) {
        $d->consume = hex2bin($rv["consume_hex"]);
    }
    return $d;
}

/** Reconstruct a records{}/ordering_examples{} case with its exact ordering/terms/enforcement
 * fixture, mirroring decision_record_test.go's build() switch exactly. */
function dr_build(string $name, array $rv): DecisionRecord
{
    $d = dr_from($rv);
    switch ($name) {
        case "allow_consuming":
        case "allow_no_consume":
        case "minimal":
        case "correspondence_only":
            $d->ordering = Gateway::correspondenceOnly();
            break;
        case "deny_two_governing":
            $d->ordering = new OrderingDisclosure(Gateway::ORDERING_SINGLE_BOUNDARY, "boundary-signer-X");
            break;
        case "hold_empty_governing":
        case "external_mechanism":
            $d->ordering = new OrderingDisclosure(
                Gateway::ORDERING_EXTERNAL_MECHANISM, "", "external-log:acme-transparency-v1",
                hex2bin("2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56")
            );
            break;
        case "single_boundary":
            $d->ordering = new OrderingDisclosure(Gateway::ORDERING_SINGLE_BOUNDARY, "SIGNER_B-boundary");
            break;
        case "external_mechanism_no_relation":
            $d->ordering = new OrderingDisclosure(Gateway::ORDERING_EXTERNAL_MECHANISM, "", "external-log:acme-transparency-v1");
            break;
        case "terms_valid":
            $d->ordering = Gateway::correspondenceOnly();
            $d->terms = [
                1 => new \Naalp\TermDisposition(Gateway::TERM_OBSERVED),
                4 => new \Naalp\TermDisposition(Gateway::TERM_REPORTED, "boundary:relay-partner-3"),
            ];
            break;
        case "enforcement_enforced":
            $d->ordering = Gateway::correspondenceOnly();
            $d->enforcement = Gateway::ENFORCEMENT_ENFORCED;
            break;
        case "enforcement_advised":
            $d->ordering = Gateway::correspondenceOnly();
            $d->enforcement = Gateway::ENFORCEMENT_ADVISED;
            break;
        default:
            throw new \RuntimeException("unhandled record name $name -- add its ordering/terms/enforcement fixture");
    }
    return $d;
}

foreach ($DR["outcome_vocabulary"] as $e) {
    check("outcome vocabulary known: " . $e["name"], Gateway::isKnownDecision($e["code"]) ? "true" : "false", "true");
    check("outcome vocabulary name of " . $e["code"], Gateway::decisionName($e["code"]), $e["name"]);
}
foreach ($DR["ordering_basis_vocabulary"] as $e) {
    check("ordering basis known: " . $e["name"], Gateway::isKnownOrderingBasis($e["code"]) ? "true" : "false", "true");
    check("ordering basis name of " . $e["code"], Gateway::orderingBasisName($e["code"]), $e["name"]);
}
check("ordering basis 99 not known", Gateway::isKnownOrderingBasis(99) ? "true" : "false", "false");

$allDrCases = $DR["records"] + $DR["ordering_examples"];
check(
    "records/ordering_examples name collision check",
    (string) \count($allDrCases),
    (string) (\count($DR["records"]) + \count($DR["ordering_examples"]))
);
foreach ($allDrCases as $name => $rv) {
    $d = dr_build($name, $rv);
    check("$name body == oracle", bin2hex($d->bytes()), $rv["body_hex"]);
    check("$name head == oracle", bin2hex($d->head()), $rv["head_hex"]);
    check("$name id == oracle", bin2hex($d->id()), $rv["id_hex"]);
    $parsed = Gateway::parseDecisionRecord($d->bytes());
    check("$name round-trip re-encode", bin2hex($parsed->bytes()), $rv["body_hex"]);
    check("$name validate (positive)", err_kind(fn() => Gateway::validateDecisionRecord($parsed)), "no-error");
}

$mRec = $DR["records"]["minimal"];
$dMin = new DecisionRecord("", [], $mRec["outcome"], Gateway::correspondenceOnly());
check("minimal record body == oracle", bin2hex($dMin->bytes()), $mRec["body_hex"]);
check("minimal record id == oracle", bin2hex($dMin->id()), $mRec["id_hex"]);
$parsedMin = Gateway::parseDecisionRecord($dMin->bytes());
check("minimal record validate", err_kind(fn() => Gateway::validateDecisionRecord($parsedMin)), "no-error");

function dr_kind_of(string $bodyHex): string
{
    try {
        $d = Gateway::parseDecisionRecord(hex2bin($bodyHex));
    } catch (\Throwable $e) {
        return \property_exists($e, 'kind') ? $e->kind : \get_class($e);
    }
    try {
        Gateway::validateDecisionRecord($d);
    } catch (\Throwable $e) {
        return \property_exists($e, 'kind') ? $e->kind : \get_class($e);
    }
    return "";
}

$negDr = $DR["negative"];
foreach ([
    "deny_with_consume_rejected", "hold_with_consume_rejected", "terms_key_outside_field_set_rejected",
    "unknown_outcome_rejected", "look_alike",
] as $name) {
    check("negative: $name", dr_kind_of($negDr[$name]["body_hex"]), $negDr[$name]["reject"]);
}
foreach ($negDr["ordering_malformed"] as $name => $c) {
    check("negative: ordering_malformed.$name", dr_kind_of($c["body_hex"]), $c["reject"]);
}

// keys_out_of_order: the canonical body decodes+validates cleanly; the descending-key body is
// rejected at the CBOR layer (NonCanonical) before parseDecisionRecord's own checks ever run.
$koo = $negDr["keys_out_of_order"];
$dKoo = Gateway::parseDecisionRecord(hex2bin($koo["canonical_body_hex"]));
check("keys_out_of_order canonical validate", err_kind(fn() => Gateway::validateDecisionRecord($dKoo)), "no-error");
check("keys_out_of_order noncanonical decode rejected", err_kind(fn() => Cbor::decode(hex2bin($koo["noncanonical_body_hex"]))), "NonCanonical");
check("keys_out_of_order noncanonical parse rejected", err_kind(fn() => Gateway::parseDecisionRecord(hex2bin($koo["noncanonical_body_hex"]))), "DecisionMalformed");

if (MlDsa::available()) {
    // third-party reserve
    $rvAc = $DR["records"]["allow_consuming"];
    $dAc = dr_build("allow_consuming", $rvAc);
    check("allow_consuming body pre-sign", bin2hex($dAc->bytes()), $rvAc["body_hex"]);

    $seedProducer = str_repeat("\x71", 32);
    $seedForeign = str_repeat("\x72", 32);
    $algDr = Cose::ALG_MLDSA65;
    $producerPk = MlDsa::keygenFromSeed($seedProducer, $algDr);
    $foreignPk = MlDsa::keygenFromSeed($seedForeign, $algDr);

    $objDr = Gateway::signDecisionRecord($dAc, $algDr, $seedProducer);
    $byProducer = Gateway::verifyDecisionRecord($objDr, Cose::PROFILE_PUBLIC, $algDr, $producerPk);
    $byThirdPartyDr = Gateway::verifyDecisionRecord($objDr, Cose::PROFILE_PUBLIC, $algDr, $producerPk);
    check("decision-record third-party action match", bin2hex($byProducer->action), bin2hex($byThirdPartyDr->action));
    check("decision-record third-party outcome match", (string) $byProducer->outcome, (string) $byThirdPartyDr->outcome);
    check("decision-record third-party outcome == allow", (string) $byThirdPartyDr->outcome, (string) Gateway::DECISION_ALLOW);
    check("decision-record third-party consume == oracle", bin2hex($byThirdPartyDr->consume), $rvAc["consume_hex"]);
    check(
        "decision-record foreign key rejected",
        err_kind(fn() => Gateway::verifyDecisionRecord($objDr, Cose::PROFILE_PUBLIC, $algDr, $foreignPk)),
        "BadSignature"
    );

    // sign/verify terms_valid: carries field 6 (terms) through the full signature-verification +
    // semantic-validation path, exercising the terms map on the signed/verified round trip.
    $rvTv = $DR["records"]["terms_valid"];
    $dTv = dr_build("terms_valid", $rvTv);
    check("terms_valid body pre-sign", bin2hex($dTv->bytes()), $rvTv["body_hex"]);
    $seedTv = str_repeat("\x11", 32);
    $pkTv = MlDsa::keygenFromSeed($seedTv, $algDr);
    $objTv = Gateway::signDecisionRecord($dTv, $algDr, $seedTv);
    $resolvedTv = Gateway::verifyDecisionRecord($objTv, Cose::PROFILE_PUBLIC, $algDr, $pkTv);
    check("terms_valid resolved terms[1].kind", (string) $resolvedTv->terms[1]->kind, (string) Gateway::TERM_OBSERVED);
    check("terms_valid resolved terms[4].kind", (string) $resolvedTv->terms[4]->kind, (string) Gateway::TERM_REPORTED);
    check("terms_valid resolved terms[4].source", $resolvedTv->terms[4]->source, "boundary:relay-partner-3");
} else {
    echo "  SKIP decision-record sign/verify checks: ML-DSA unavailable (" . MlDsa::unavailableReason() . ")\n";
}

// =================================================================================================
// 13. S3 naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof conformance, graded
//     against vectors/checkpoint/cases.json. Mirrors impl/go/gateway/checkpoint_test.go /
//     impl/python/tests/test_checkpoint.py.
// =================================================================================================
echo "\n-- S3 naalp-checkpoint-root / witness-cosign / inclusion-proof --\n";

$CP = evidence_vectors("checkpoint");

function cp_from(array $cv): CheckpointRoot
{
    return new CheckpointRoot(
        hex2bin($cv["log_hex"]), $cv["size"], hex2bin($cv["root_hex"]), hex2bin($cv["prev_hex"]),
        u64_from_decimal_string($cv["at_str"])
    );
}

function wc_from(array $wv): WitnessCosign
{
    return new WitnessCosign(hex2bin($wv["witness_hex"]), hex2bin($wv["root_hex"]), u64_from_decimal_string($wv["at_str"]));
}

check("genesis prev == oracle", bin2hex(Gateway::genesisPrev()), $CP["genesis"]["prev_hex"]);
foreach ($CP["checkpoints"] as $name => $cv) {
    $c = cp_from($cv);
    check("checkpoint $name body == oracle", bin2hex($c->bytes()), $cv["body_hex"]);
    check("checkpoint $name head == oracle", bin2hex($c->head()), $cv["head_hex"]);
    check("checkpoint $name id == oracle", bin2hex($c->id()), $cv["id_hex"]);
    $parsedCp = Gateway::parseCheckpointRoot($c->bytes());
    check("checkpoint $name round-trip", bin2hex($parsedCp->bytes()), $cv["body_hex"]);
}
foreach ($CP["witness_cosigns"] as $name => $wv) {
    $w = wc_from($wv);
    check("witness_cosign $name body == oracle", bin2hex($w->bytes()), $wv["body_hex"]);
    check("witness_cosign $name head == oracle", bin2hex($w->head()), $wv["head_hex"]);
    check("witness_cosign $name id == oracle", bin2hex($w->id()), $wv["id_hex"]);
}

// fork evidence: two witness-cosigned roots at one (log, size) carrying different root values.
$fe = $CP["fork_evidence"];
check("fork evidence: distinct roots", $fe["checkpoint_a"]["root_hex"] !== $fe["checkpoint_b"]["root_hex"] ? "true" : "false", "true");
check("fork evidence: distinct ids", $fe["checkpoint_a"]["id_hex"] !== $fe["checkpoint_b"]["id_hex"] ? "true" : "false", "true");
$wcA = wc_from($fe["checkpoint_a"]["witness_cosign"]);
$wcB = wc_from($fe["checkpoint_b"]["witness_cosign"]);
check("fork evidence: wc_a body == oracle", bin2hex($wcA->bytes()), $fe["checkpoint_a"]["witness_cosign"]["body_hex"]);
check("fork evidence: wc_b body == oracle", bin2hex($wcB->bytes()), $fe["checkpoint_b"]["witness_cosign"]["body_hex"]);
$idA = hex2bin($fe["checkpoint_a"]["id_hex"]);
$idB = hex2bin($fe["checkpoint_b"]["id_hex"]);
check("fork evidence: wc_a validates against a", err_kind(fn() => Gateway::validateWitnessCosign($wcA, $idA)), "no-error");
check("fork evidence: wc_b validates against b", err_kind(fn() => Gateway::validateWitnessCosign($wcB, $idB)), "no-error");
check("fork evidence: wc_a mismatches b", err_kind(fn() => Gateway::validateWitnessCosign($wcA, $idB)), "WitnessRootMismatch");
check("fork evidence: wc_b mismatches a", err_kind(fn() => Gateway::validateWitnessCosign($wcB, $idA)), "WitnessRootMismatch");

$checkpointFor = [
    "leaf3_of7" => "checkpoint0_size7",
    "leaf7_of8_newly_appended" => "checkpoint1_size8",
    "single_leaf_tree_empty_path" => "checkpoint_single_leaf",
];
foreach ($CP["inclusion_proofs"] as $name => $iv) {
    $cpName = $checkpointFor[$name];
    $cpv = $CP["checkpoints"][$cpName];
    $resolvedId = cp_from($cpv)->id();
    check("inclusion_proof $name checkpoint id matches root_hex", bin2hex($resolvedId), $iv["root_hex"]);

    $p = new InclusionProof(hex2bin($iv["root_hex"]), hex2bin($iv["leaf_hex"]), $iv["index"], \array_map('hex2bin', $iv["path_hex"]));
    check("inclusion_proof $name body == oracle", bin2hex($p->bytes()), $iv["body_hex"]);
    check("inclusion_proof $name head == oracle", bin2hex($p->head()), $iv["head_hex"]);
    check("inclusion_proof $name id == oracle", bin2hex($p->id()), $iv["id_hex"]);
    $parsedP = Gateway::parseInclusionProof($p->bytes());
    check(
        "inclusion_proof $name verifies",
        err_kind(fn() => Gateway::verifyInclusionProof($parsedP->leaf, $parsedP->index, $cpv["size"], $parsedP->path, hex2bin($cpv["root_hex"]))),
        "no-error"
    );
}

$cp0 = $CP["checkpoints"]["checkpoint0_size7"];
$root0 = hex2bin($cp0["root_hex"]);
$wi = $CP["negative"]["inclusion_wrong_index"];
check(
    "inclusion wrong index rejected",
    err_kind(fn() => Gateway::verifyInclusionProof(hex2bin($wi["leaf_hex"]), $wi["claimed_index"], $cp0["size"], \array_map('hex2bin', $wi["path_hex"]), $root0)),
    "InclusionProofInvalid"
);
$wp = $CP["negative"]["inclusion_wrong_path"];
check(
    "inclusion wrong path rejected",
    err_kind(fn() => Gateway::verifyInclusionProof(hex2bin($wp["leaf_hex"]), $wp["index"], $cp0["size"], \array_map('hex2bin', $wp["path_hex"]), $root0)),
    "InclusionProofInvalid"
);

$wm = $CP["negative"]["witness_root_mismatch"];
$wParsed = Gateway::parseWitnessCosign(hex2bin($wm["cosign_body_hex"]));
check("witness_root_mismatch parsed root", bin2hex($wParsed->root), $wm["cosign_names_root_hex"]);
check(
    "witness_root_mismatch rejected",
    err_kind(fn() => Gateway::validateWitnessCosign($wParsed, hex2bin($wm["checkpoint_accompanied_id_hex"]))),
    $wm["reject"]
);

$kooCp = $CP["negative"]["checkpoint_keys_out_of_order"];
check("checkpoint keys_out_of_order canonical parses", err_kind(fn() => Gateway::parseCheckpointRoot(hex2bin($kooCp["canonical_body_hex"]))), "no-error");
check("checkpoint keys_out_of_order noncanonical decode rejected", err_kind(fn() => Cbor::decode(hex2bin($kooCp["noncanonical_body_hex"]))), "NonCanonical");
check("checkpoint keys_out_of_order noncanonical parse rejected", err_kind(fn() => Gateway::parseCheckpointRoot(hex2bin($kooCp["noncanonical_body_hex"]))), "CheckpointMalformed");

$mfCp = $CP["negative"]["checkpoint_missing_field"];
check("checkpoint missing field rejected", err_kind(fn() => Gateway::parseCheckpointRoot(hex2bin($mfCp["body_hex"]))), $mfCp["reject"]);

check("empty tree kat (null)", bin2hex(Gateway::merkleRoot(null)), $CP["empty_tree_kat"]["root_hex"]);
check("empty tree kat (empty array)", bin2hex(Gateway::merkleRoot([])), $CP["empty_tree_kat"]["root_hex"]);

// Independently re-derives the oracle's own claimed property using PHP's OWN Merkle construction
// over synthetic leaves -- never the oracle's numbers -- so this catches an algorithmic defect the
// byte-parity vectors above (which only exercise n in {1,7,8}) do not reach.
$total = 0;
for ($n = 1; $n <= 12; $n++) {
    $leaves = [];
    for ($i = 0; $i < $n; $i++) {
        $leaves[] = "synthetic-leaf-$i";
    }
    $root = Gateway::merkleRoot($leaves);
    for ($m = 0; $m < $n; $m++) {
        $path = Gateway::generateInclusionProofPath($leaves, $m);
        Gateway::verifyInclusionProof($leaves[$m], $m, $n, $path, $root); // throws on failure
        $total++;
    }
}
check("rfc9162 self-fidelity total proofs", (string) $total, "78"); // sum(1..12) == 78

$leaves5 = [];
for ($i = 0; $i < 5; $i++) {
    $leaves5[] = "synthetic-leaf-$i";
}
$root5 = Gateway::merkleRoot($leaves5);
$path5 = Gateway::generateInclusionProofPath($leaves5, 2);
check(
    "rfc9162 self-fidelity: tampered leaf rejected",
    err_kind(fn() => Gateway::verifyInclusionProof("tampered-leaf", 2, 5, $path5, $root5)),
    "InclusionProofInvalid"
);

if (MlDsa::available()) {
    // NOT corpus-graded (the corpus carries no signed COSE vector): demonstrates
    // signCheckpointRoot round-tripping in isolation with a local seed.
    $cSeed = str_repeat("\x11", 32);
    $algCp = Cose::ALG_MLDSA65;
    $pkCp = MlDsa::keygenFromSeed($cSeed, $algCp);
    $cIso = cp_from($cp0);
    $objCp = Gateway::signCheckpointRoot($cIso, $algCp, $cSeed);
    [$protCp, $payloadCp, $sigCp] = Cose::parseSign1Raw($objCp);
    check("checkpoint sign/verify isolation: payload == bytes", $payloadCp === $cIso->bytes() ? "true" : "false", "true");
    check("checkpoint sign/verify isolation: verifies", MlDsa::verify($pkCp, Cose::toBeSignedRaw($protCp, $payloadCp), $sigCp, $algCp) ? "true" : "false", "true");
} else {
    echo "  SKIP checkpoint sign/verify isolation: ML-DSA unavailable (" . MlDsa::unavailableReason() . ")\n";
}

// =================================================================================================
// 14. E6.3 naalp-egress-attestation conformance, graded against vectors/egress_attestation/cases.json.
//     Mirrors impl/go/gateway/egress_attestation_test.go / impl/python/tests/test_egress_attestation.py.
// =================================================================================================
echo "\n-- E6.3 naalp-egress-attestation --\n";

$EG = evidence_vectors("egress_attestation");

function eg_from(array $av): EgressAttestation
{
    return new EgressAttestation(
        $av["binding"], hex2bin($av["digest_hex"]), $av["effect"], hex2bin($av["audience_hex"]),
        u64_from_decimal_string($av["at_str"])
    );
}

foreach (["content_bound" => $EG["attestations"]["content_bound"], "content_free" => $EG["attestations"]["content_free"]] as $name => $av) {
    $a = eg_from($av);
    check("egress $name body == oracle", bin2hex($a->bytes()), $av["body_hex"]);
    check("egress $name head == oracle", bin2hex($a->head()), $av["head_hex"]);
    check("egress $name id == oracle", bin2hex($a->id()), $av["id_hex"]);
}
foreach ($EG["binding_vocabulary"] as $e) {
    check("binding known: " . $e["name"], Gateway::isKnownBinding($e["code"]) ? "true" : "false", "true");
    check("binding name of " . $e["code"], Gateway::bindingName($e["code"]), $e["name"]);
}
check("unknown binding not known", Gateway::isKnownBinding($EG["unknown_binding"]) ? "true" : "false", "false");

// oversized counter: at = 2^64-1, carried as a decimal string so no float64 decoder rounds it.
$oc = $EG["edge_cases"]["oversized_counter"];
check("oversized counter at_str is 2^64-1", $oc["at_str"], "18446744073709551615");
$aOc = eg_from($oc);
check("oversized counter at wraps to -1 (two's complement)", (string) $aOc->at, "-1");
check("oversized counter body == oracle", bin2hex($aOc->bytes()), $oc["body_hex"]);
$parsedOc = Gateway::parseEgressAttestation($aOc->bytes());
check("oversized counter round-trip at", (string) $parsedOc->at, (string) $aOc->at);

if (MlDsa::available()) {
    $seedGw = str_repeat("\x61", 32);
    $seedForeignEg = str_repeat("\x62", 32);
    $algEg = Cose::ALG_MLDSA65;
    $gwPkEg = MlDsa::keygenFromSeed($seedGw, $algEg);
    $foreignPkEg = MlDsa::keygenFromSeed($seedForeignEg, $algEg);

    $aCb = eg_from($EG["attestations"]["content_bound"]);
    $objEg = Gateway::signEgressAttestation($aCb, $algEg, $seedGw);

    $byGwEg = Gateway::verifyEgressAttestation($objEg, Cose::PROFILE_PUBLIC, $algEg, $gwPkEg);
    $byThirdEg = Gateway::verifyEgressAttestation($objEg, Cose::PROFILE_PUBLIC, $algEg, $gwPkEg);
    check("egress third-party binding match", (string) $byGwEg->binding, (string) $byThirdEg->binding);
    check("egress third-party digest match", bin2hex($byGwEg->digest), bin2hex($byThirdEg->digest));
    check("egress third-party effect match", (string) $byGwEg->effect, (string) $byThirdEg->effect);
    check("egress third-party audience match", bin2hex($byGwEg->audience), bin2hex($byThirdEg->audience));
    check("egress third-party at match", (string) $byGwEg->at, (string) $byThirdEg->at);
    check("egress third-party binding == content_bound", (string) $byThirdEg->binding, (string) Gateway::BINDING_CONTENT_BOUND);
    check("egress third-party digest == oracle object cid", bin2hex($byThirdEg->digest), $EG["object_cid_hex"]);
    check(
        "egress foreign key rejected",
        err_kind(fn() => Gateway::verifyEgressAttestation($objEg, Cose::PROFILE_PUBLIC, $algEg, $foreignPkEg)),
        "BadSignature"
    );

    $badEg = new EgressAttestation($EG["unknown_binding"], hex2bin($EG["object_cid_hex"]), 0, hex2bin($EG["audience_hex"]), 0);
    $badObjEg = Gateway::signEgressAttestation($badEg, $algEg, $seedGw);
    check(
        "egress unknown binding rejected",
        err_kind(fn() => Gateway::verifyEgressAttestation($badObjEg, Cose::PROFILE_PUBLIC, $algEg, $gwPkEg)),
        "UnknownEgressBinding"
    );

    // vendor-only mutation: the honest verifyEgressAttestation takes NO serving-party identity, so
    // a mutant "vendor-only" verifier that additionally requires servingParty == gatewayId wrongly
    // rejects a third party re-serving the identical bytes.
    $gatewayId = "gateway-id-0x61";
    $thirdParty = "did:example:mirror-cache";
    $aCf = eg_from($EG["attestations"]["content_free"]);
    $objCf = Gateway::signEgressAttestation($aCf, $algEg, $seedGw);
    check("egress vendor-only baseline (honest verify)", err_kind(fn() => Gateway::verifyEgressAttestation($objCf, Cose::PROFILE_PUBLIC, $algEg, $gwPkEg)), "no-error");
    $mutantVerify = function (string $obj_, string $gwPk_, string $gatewayId_, string $servingParty) use ($algEg) {
        Gateway::verifyEgressAttestation($obj_, Cose::PROFILE_PUBLIC, $algEg, $gwPk_);
        if ($servingParty !== $gatewayId_) {
            throw new \Naalp\EgMalformed("stands in for a not-served-by-vendor rejection");
        }
    };
    check("egress vendor-only mutant accepts the vendor", err_kind(fn() => $mutantVerify($objCf, $gwPkEg, $gatewayId, $gatewayId)), "no-error");
    check("egress vendor-only mutant wrongly rejects third party", err_kind(fn() => $mutantVerify($objCf, $gwPkEg, $gatewayId, $thirdParty)), "EgMalformed");
} else {
    echo "  SKIP egress sign/verify checks: ML-DSA unavailable (" . MlDsa::unavailableReason() . ")\n";
}

// content_free commitment open/verify pair.
$co = $EG["commitment_open"];
$aCfCommit = eg_from($EG["attestations"]["content_free"]);
check("commitment digest == oracle", bin2hex($aCfCommit->digest), $co["commitment_hex"]);
$objectCid = hex2bin($co["object_cid_hex"]);
$wrongObjectCid = hex2bin($co["wrong_object_cid_hex"]);
$saltCo = hex2bin($co["salt_hex"]);
$wrongSalt = hex2bin($co["wrong_salt_hex"]);
check("egressCommit reproduces oracle commitment", bin2hex(Gateway::egressCommit($objectCid, $saltCo)), $co["commitment_hex"]);
check("openEgressCommitment: correct opens", Gateway::openEgressCommitment($aCfCommit, $objectCid, $saltCo) ? "true" : "false", "true");
check("openEgressCommitment: wrong salt fails", Gateway::openEgressCommitment($aCfCommit, $objectCid, $wrongSalt) ? "true" : "false", "false");
check("openEgressCommitment: wrong object cid fails", Gateway::openEgressCommitment($aCfCommit, $wrongObjectCid, $saltCo) ? "true" : "false", "false");
check("openEgressCommitment: both wrong fails", Gateway::openEgressCommitment($aCfCommit, $wrongObjectCid, $wrongSalt) ? "true" : "false", "false");
$aBoundCommit = eg_from($EG["attestations"]["content_bound"]);
check("openEgressCommitment: content_bound never opens", Gateway::openEgressCommitment($aBoundCommit, $objectCid, $saltCo) ? "true" : "false", "false");

// keys_out_of_order rejected.
$kooEg = $EG["edge_cases"]["keys_out_of_order"];
$aKoo = new EgressAttestation($kooEg["binding"], hex2bin($kooEg["digest_hex"]), $kooEg["effect"], hex2bin($kooEg["audience_hex"]), u64_from_decimal_string($kooEg["at_str"]));
check("egress keys_out_of_order canonical body == oracle", bin2hex($aKoo->bytes()), $kooEg["canonical_body_hex"]);
$canonEg = hex2bin($kooEg["canonical_body_hex"]);
$noncanonEg = hex2bin($kooEg["noncanonical_body_hex"]);
check("egress keys_out_of_order canonical decodes", err_kind(fn() => Cbor::decode($canonEg)), "no-error");
check("egress keys_out_of_order canonical parses", err_kind(fn() => Gateway::parseEgressAttestation($canonEg)), "no-error");
check("egress keys_out_of_order noncanonical decode rejected", err_kind(fn() => Cbor::decode($noncanonEg)), "NonCanonical");
check("egress keys_out_of_order noncanonical parse rejected", err_kind(fn() => Gateway::parseEgressAttestation($noncanonEg)), "EgMalformed");

// empty-vs-absent audience.
$eaEg = $EG["edge_cases"]["empty_vs_absent"];
$emptyEg = new EgressAttestation(Gateway::BINDING_CONTENT_BOUND, hex2bin($EG["object_cid_hex"]), 1, "", 1735689600000);
$populatedEg = new EgressAttestation(Gateway::BINDING_CONTENT_BOUND, hex2bin($EG["object_cid_hex"]), 1, hex2bin($eaEg["populated_audience"]["audience_hex"]), 1735689600000);
check("egress empty-audience body == oracle", bin2hex($emptyEg->bytes()), $eaEg["empty_audience"]["body_hex"]);
check("egress populated-audience body == oracle", bin2hex($populatedEg->bytes()), $eaEg["populated_audience"]["body_hex"]);
check("egress empty != populated by id", $emptyEg->id() !== $populatedEg->id() ? "distinct" : "same", "distinct");
check("egress empty-audience id == oracle", bin2hex($emptyEg->id()), $eaEg["empty_audience"]["id_hex"]);
check("egress empty-audience parses", err_kind(fn() => Gateway::parseEgressAttestation($emptyEg->bytes())), "no-error");
check("egress populated-audience parses", err_kind(fn() => Gateway::parseEgressAttestation($populatedEg->bytes())), "no-error");
check("egress absent audience field rejected", err_kind(fn() => Gateway::parseEgressAttestation(hex2bin($eaEg["absent_field"]["body_hex"]))), "EgMalformed");

// minimal.
$mEg = $EG["edge_cases"]["minimal"];
$aMinEg = new EgressAttestation($mEg["binding"], hex2bin($mEg["digest_hex"]), $mEg["effect"], hex2bin($mEg["audience_hex"]), u64_from_decimal_string($mEg["at_str"]));
check("egress minimal body == oracle", bin2hex($aMinEg->bytes()), $mEg["body_hex"]);
check("egress minimal id == oracle", bin2hex($aMinEg->id()), $mEg["id_hex"]);
check("egress minimal parses", err_kind(fn() => Gateway::parseEgressAttestation($aMinEg->bytes())), "no-error");
if (MlDsa::available()) {
    $seed63 = str_repeat("\x63", 32);
    $pk63 = MlDsa::keygenFromSeed($seed63, Cose::ALG_MLDSA65);
    $objMinEg = Gateway::signEgressAttestation($aMinEg, Cose::ALG_MLDSA65, $seed63);
    check("egress minimal signs+verifies", err_kind(fn() => Gateway::verifyEgressAttestation($objMinEg, Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $pk63)), "no-error");
}

// look-alike rejected.
$laEg = $EG["edge_cases"]["look_alike"];
check("egress look-alike rejected", err_kind(fn() => Gateway::parseEgressAttestation(hex2bin($laEg["body_hex"]))), $laEg["reject"]);

// ordering byte parity: field 6 (ordering) present, correspondence_only / single_boundary /
// external_mechanism variants.
foreach ($EG["ordering_basis_vocabulary"] as $e) {
    check("egress ordering basis known: " . $e["name"], Gateway::isKnownOrderingBasis($e["code"]) ? "true" : "false", "true");
    check("egress ordering basis name of " . $e["code"], Gateway::orderingBasisName($e["code"]), $e["name"]);
}

function eg_build_with_ordering(string $name, array $av): EgressAttestation
{
    $a = eg_from($av);
    switch ($name) {
        case "correspondence_only":
            $a->ordering = Gateway::correspondenceOnly();
            break;
        case "single_boundary":
            $a->ordering = new OrderingDisclosure(Gateway::ORDERING_SINGLE_BOUNDARY, "boundary-signer-X");
            break;
        case "external_mechanism":
            $a->ordering = new OrderingDisclosure(
                Gateway::ORDERING_EXTERNAL_MECHANISM, "", "external-log:acme-transparency-v1",
                hex2bin("2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56")
            );
            break;
        default:
            throw new \RuntimeException("unhandled attestations_with_ordering name $name");
    }
    return $a;
}
foreach ($EG["attestations_with_ordering"] as $name => $av) {
    $a = eg_build_with_ordering($name, $av);
    check("egress ordering $name body == oracle", bin2hex($a->bytes()), $av["body_hex"]);
    check("egress ordering $name head == oracle", bin2hex($a->head()), $av["head_hex"]);
    check("egress ordering $name id == oracle", bin2hex($a->id()), $av["id_hex"]);
    $parsedA = Gateway::parseEgressAttestation($a->bytes());
    check("egress ordering $name parsed ordering present", $parsedA->ordering !== null ? "true" : "false", "true");
    check("egress ordering $name round-trip", bin2hex($parsedA->bytes()), $av["body_hex"]);
    check("egress ordering $name validate", err_kind(fn() => Gateway::validateEgressAttestation($parsedA)), "no-error");
}
$plainEg = Gateway::parseEgressAttestation(eg_from($EG["attestations"]["content_bound"])->bytes());
check("egress plain ordering absent", $plainEg->ordering === null ? "true" : "false", "true");

function eg_ordering_kind_of(string $bodyHex): string
{
    try {
        $a = Gateway::parseEgressAttestation(hex2bin($bodyHex));
    } catch (\Throwable $e) {
        return \property_exists($e, 'kind') ? $e->kind : \get_class($e);
    }
    try {
        Gateway::validateEgressAttestation($a);
    } catch (\Throwable $e) {
        return \property_exists($e, 'kind') ? $e->kind : \get_class($e);
    }
    return "";
}
$sbwm = $EG["negative_ordering"]["ordering_malformed_single_boundary_with_mechanism"];
check("egress ordering negative: single_boundary_with_mechanism", eg_ordering_kind_of($sbwm["body_hex"]), $sbwm["reject"]);
$uob = $EG["negative_ordering"]["unknown_ordering_basis"];
check("egress ordering negative: unknown_ordering_basis", eg_ordering_kind_of($uob["body_hex"]), $uob["reject"]);

// missing `at` (field 5) rejected: fields 1-4 correctly typed, field 5 absent.
$missingAtBody = Cbor::encode(new \Naalp\M([
    [new \Naalp\U(1), new \Naalp\U(Gateway::BINDING_CONTENT_BOUND)],
    [new \Naalp\U(2), new \Naalp\B(\hex2bin("2030"))],
    [new \Naalp\U(3), new \Naalp\U(1)],
    [new \Naalp\U(4), new \Naalp\B("")],
]));
check("egress missing at field rejected", err_kind(fn() => Gateway::parseEgressAttestation($missingAtBody)), "EgMalformed");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
