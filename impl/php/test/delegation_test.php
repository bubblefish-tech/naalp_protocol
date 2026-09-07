<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C15 multi-hop agent-delegation conformance for the PHP SDK (design.md §18; R-DEL-1..8), graded
// against the shared independent corpus vectors/delegation/cases.json (NOT produced by this code).
//
// Agent-delegation answers WHO may act on whose behalf, across multiple hops, with a chain that
// terminates at a trust anchor. A DelegationGrant is a normal N-AALP envelope object (a tier-1
// Capability surface, kind 4); its body carries exactly what delegation adds over a single-hop
// capability — the delegatee `subject`, the `effect_cap` ceiling, the `max_depth` onward bound, and
// the validity window (plus an optional `scope`). The ISSUER is NOT a body field — it is the verified
// envelope signer (R-DEL-3); the delegation PARENT is named by content id in the envelope `causes`.
//
// CORPUS-GRADED (pure, signature-independent): (1) every DelegationGrant body + content id (incl.
// unicode NFC subject/scope, omitted-vs-present scope), (2) the D2 scope-containment truth table, and
// (3) the 12-step leaf->root chain verifier's verdict for every scenario (both `authorized` and every
// named deny). The chain scenarios are driven through the REAL VerifyGrantObject path (envelope
// structural verify + tier/kind/effect checks + the R-DEL-3 issuer->key binding + grant-body parse)
// over grant objects wired by real envelope content ids — the same wiring the Go/Rust/Python ports
// use, minus the ML-DSA signature bytes.
//
// CRYPTO SCOPE (PURE-ONLY, honest F4): PHP has no deterministic ML-DSA (FIPS 204) signer/verifier, so
// the grant objects here carry an ML-DSA-65 protected header with a PLACEHOLDER signature that PHP's
// envelope does NOT verify (documented PURE-ONLY behaviour of Naalp\Envelope::verify for ML-DSA). The
// STRUCTURAL surface — content-id binding, field ranges, header/body copies, version, kind dispatch,
// the profile floor (ML-DSA-65 is level 3, so it clears the Public floor), the issuer->signer-id
// binding, and the whole D3 chain walk — is fully exercised and corpus-graded. The ML-DSA SIGNATURE
// itself is the only un-exercised leg, and it is not what the corpus grades. The Ed25519 leg is not
// usable for grants (classical level 0 < the profile floor 3), so grants use the ML-DSA structural
// path exactly as the reference does.
//
// Written test-first: Naalp\Delegation / Naalp\Grant are absent until Delegation.php lands, so this
// fails RED with a fatal "class not found"; making ScopeContained always-return-true flips the
// scope-not-contained denies, and dropping the leaf effect_cap attenuation flips the CapExceedsParent
// verdicts.
//
// Run:  php -d extension=sodium -d extension=intl test/delegation_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Delegation;
use Naalp\Grant;
use Naalp\Resolved;
use Naalp\Action;
use Naalp\NaalpObject;
use Naalp\Envelope;
use Naalp\Identity;
use Naalp\Cose;
use Naalp\T;

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

function del_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/delegation/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/delegation/cases.json not found");
}

/**
 * A deterministic ML-DSA-65 key stand-in for a scenario label: a distinct "public key" (any bytes;
 * the signature is never verified in the pure tier) and its self-certifying signer id (§5.1). The
 * signer id is a real hash of multicodec(mldsa-65)||pubkey, so the R-DEL-3 issuer->key binding is
 * genuinely exercised.
 *
 * @return array{0:string,1:string} [pubkey, signer-id]
 */
function del_key(string $label): array
{
    static $cache = [];
    if (!isset($cache[$label])) {
        $pub = hash('sha384', "naalp-del-key:$label", true); // deterministic, distinct per label
        $cache[$label] = [$pub, Identity::signerId(Cose::ALG_MLDSA65, $pub)];
    }
    return $cache[$label];
}

/** Assemble a STRUCTURAL ML-DSA-65 COSE_Sign1 for an object (placeholder sig, not verified in pure PHP). */
function del_assemble(NaalpObject $o): string
{
    $payload = Envelope::buildPayload($o); // sets $o->id to the envelope content id
    $prot = Envelope::protectedHeader(Cose::ALG_MLDSA65, $o->signer, $o->profile);
    $sig = str_repeat("\x00", 64); // placeholder: ML-DSA is not verified in the pure tier
    return Envelope::assembleSigned($prot, $payload, $sig);
}

$C = del_vectors();
echo "delegation conformance (PHP) — graded vs vectors/delegation/cases.json\n";

// 1. every DelegationGrant body and its content id are byte-identical to the independent oracle
//    (=> Go == Rust == Python on the wire). Mutation: a constant/field-ignoring encoder diverges,
//    and an omitted-vs-present scope field flips the content id. Covers unicode NFC subject/scope.
foreach ($C["grants"] as $gj) {
    $g = new Grant($gj["subject"], $gj["effect_cap"], $gj["max_depth"], $gj["not_before"], $gj["not_after"], $gj["scope"]);
    check("grant {$gj['name']} body == oracle", bin2hex($g->bytes()), $gj["body_hex"]);
    check("grant {$gj['name']} content-id == oracle", bin2hex($g->contentId()), $gj["content_id_hex"]);
}

// 2. the D2 path-prefix scope-containment rule, graded directly against the independent truth table
//    (both allows and denies, so a constant predicate fails). Mutation: return a constant and a row flips.
foreach ($C["scope_containment"] as $i => $r) {
    check("scope_containment[$i] ({$r['child']} in {$r['parent']})", Delegation::scopeContained($r["child"], $r["parent"]) ? "true" : "false", $r["contained"] ? "true" : "false");
}

// 3. the 12-step chain verifier's verdict == the oracle for every scenario, driven through the REAL
//    VerifyGrantObject path over structural ML-DSA grant objects wired by real envelope content ids.
//    The scenario set contains both `authorized` and every named deny, so a constant-authorize
//    verifier fails the denies and a constant-error verifier fails the allows (mutation-surviving).
foreach ($C["scenarios"] as $sc) {
    $name = $sc["name"];
    // Build + structurally verify each grant, wiring real envelope content ids into `causes`.
    $grantCID = [];
    $set = [];
    $ok = true;
    foreach ($sc["grants"] as $i => $gj) {
        [$ipub, $iid] = del_key($gj["issuer"]);
        [, $sid] = del_key($gj["subject"]);
        $g = new Grant($sid, $gj["effect_cap"], $gj["max_depth"], $gj["not_before"], $gj["not_after"], $gj["scope"]);
        $causes = [];
        foreach ($gj["causes"] as $ci) {
            $causes[] = $grantCID[$ci];
        }
        $obj = $g->envelopeObject($iid, 1, Cose::PROFILE_PUBLIC, $causes);
        $signed = del_assemble($obj);
        try {
            $res = Delegation::verifyGrantObject(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $ipub, $signed);
        } catch (\Throwable $e) {
            check("scenario $name grant $i verifies (D3 step 3)", $e->kind ?? get_class($e), "no-error");
            $ok = false;
            break;
        }
        $grantCID[$i] = $res->contentId;
        $set[$res->contentId] = $res;
    }
    if (!$ok) {
        continue;
    }
    // Build + structurally verify the action object (D3 step 1: its signer is the verified signer).
    [$apub, $aid] = del_key($sc["action"]["signer"]);
    $aCauses = [];
    foreach ($sc["action"]["causes"] as $ci) {
        $aCauses[] = $grantCID[$ci];
    }
    $aobj = new NaalpObject(
        kind: 2,
        channel: 0x0001,
        signer: $aid,
        created: 1,
        effect: $sc["action"]["effect"],
        body: new T("action"),
        tier: 0,
        profile: Cose::PROFILE_PUBLIC,
        causes: $aCauses
    );
    $aSigned = del_assemble($aobj);
    $averified = Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $apub, [Delegation::class, 'composedKindValidator'], $aSigned);
    $action = new Action($averified->signer, $averified->effect, $sc["action"]["scope"], $averified->causes);

    $anchors = [];
    foreach ($sc["anchors"] as $a) {
        [, $anId] = del_key($a);
        $anchors[$anId] = true;
    }
    $revoked = [];
    foreach ($sc["revoked"] as $rv) {
        $revoked[$grantCID[$rv["grant"]]] = $rv["pos"];
    }

    $verdict = err_kind(fn() => Delegation::verifyChain($action, $set, $anchors, $revoked, $sc["now"]));
    $want = $sc["expect"] === "authorized" ? "no-error" : $sc["expect"];
    check("scenario $name verdict == oracle", $verdict, $want);
}

// 4. dedicated fail-closed integrity paths (structural, real). A forged issuer (envelope signer field
//    claims an id NOT derived from the key passed to VerifyGrantObject) is SignerMismatch (R-DEL-3); a
//    baseline-only verifier rejects the tier-1 grant kind UnknownKind; a non-NFC subject is rejected at
//    build. These prove the port binds identity and dispatches kinds, not just the walk logic.
[$realPub, $realId] = del_key("real-issuer");
[, $victimId] = del_key("victim");
[, $subjId] = del_key("subj");
$gForge = new Grant($subjId, 2, 1, 0, 1000000, "");
$forgeObj = $gForge->envelopeObject($victimId, 1, Cose::PROFILE_PUBLIC, []); // claims VICTIM as issuer
$forgeSigned = del_assemble($forgeObj);
check("forged issuer rejected (SignerMismatch)", err_kind(fn() => Delegation::verifyGrantObject(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $realPub, $forgeSigned)), "SignerMismatch");

$gOk = new Grant($subjId, 2, 1, 0, 1000000, "");
$okObj = $gOk->envelopeObject($realId, 1, Cose::PROFILE_PUBLIC, []);
$okSigned = del_assemble($okObj);
// A frozen baseline verifier licenses no tier-1 surface: it recognizes only registered baseline kinds.
$baselineValidator = static function (int $ch, int $k): bool {
    try {
        \Naalp\Channels::lookup($ch, $k);
        return true;
    } catch (\Naalp\UnknownKind $e) {
        return false;
    }
};
check("baseline verifier rejects tier-1 grant kind (UnknownKind)", err_kind(fn() => Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $realPub, $baselineValidator, $okSigned)), "UnknownKind");

$nonNfc = "e\u{0301}"; // "é" as e + combining acute (NFD, not NFC)
$gBad = new Grant($nonNfc, 0, 0, 0, 1, "");
check("non-NFC subject rejected at build (NonNFC)", err_kind(fn() => $gBad->envelopeObject($realId, 1, Cose::PROFILE_PUBLIC, [])), "NonNFC");

// 5. D4 composition (design §18.3, R-DEL-8): a destructive action needs BOTH a valid chain AND a
//    valid, unconsumed, exact-bytes approval, consumed single-use. Precedence: the chain is checked
//    first (a broken chain wins even with an approval); a valid chain with no matching approval denies
//    ApprovalRequired; a replayed approval denies AlreadyConsumed; the approval is consumed only when
//    both gates hold. Reuses the real Approval consume ledger (not a stub).
$D = del_setup_destructive($C);
check("D4 both gates authorize", err_kind(fn() => Delegation::authorizeDestructive(
    $D["action"], $D["set"], $D["anchors"], [], 500,
    $D["appr"], $D["verify"], $D["apprSig"], $D["argsCID"], $D["ledger"]
)), "no-error");
check("D4 approval consumed after authorization", $D["ledger"]->isConsumed($D["appr"]->id()) ? "yes" : "no", "yes");
check("D4 replay denied (AlreadyConsumed)", err_kind(fn() => Delegation::authorizeDestructive(
    $D["action"], $D["set"], $D["anchors"], [], 500,
    $D["appr"], $D["verify"], $D["apprSig"], $D["argsCID"], $D["ledger"]
)), "AlreadyConsumed");
$D2 = del_setup_destructive($C);
$otherArgs = "\x20\x30" . hash('sha384', "some other args the approval does not bind", true);
check("D4 no matching approval denies (ApprovalRequired)", err_kind(fn() => Delegation::authorizeDestructive(
    $D2["action"], $D2["set"], $D2["anchors"], [], 500,
    $D2["appr"], $D2["verify"], $D2["apprSig"], $otherArgs, $D2["ledger"]
)), "ApprovalRequired");
check("D4 no ledger append on rejected action", (string) $D2["ledger"]->len(), "0");
$D3 = del_setup_destructive($C);
check("D4 broken chain wins over approval (UntrustedChainRoot)", err_kind(fn() => Delegation::authorizeDestructive(
    $D3["action"], $D3["set"], [], [], 500, // no anchors => untrusted root
    $D3["appr"], $D3["verify"], $D3["apprSig"], $D3["argsCID"], $D3["ledger"]
)), "UntrustedChainRoot");
check("D4 no ledger append when chain gate fails", (string) $D3["ledger"]->len(), "0");
$D["ledger"]->close();
$D2["ledger"]->close();
$D3["ledger"]->close();

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);

/**
 * Build a valid A->M->B destructive chain (leaf effect_cap admits destructive), a fresh consume
 * ledger, and a valid Ed25519-signed approval over the action's args (granted effect destructive,
 * consumed by B). Returns the pieces so each composition check perturbs one variable.
 */
function del_setup_destructive(array $C): array
{
    [$apub, $aid] = del_key("D4-A"); // trust anchor / root issuer
    [$mpub, $mid] = del_key("D4-M"); // middle
    [$bpub, $bid] = del_key("D4-B"); // actor

    $rootG = new Grant($mid, \Naalp\Policy::DESTRUCTIVE, 2, 0, 1000000, "");
    $rootObj = $rootG->envelopeObject($aid, 1, Cose::PROFILE_PUBLIC, []);
    $rootRes = Delegation::verifyGrantObject(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $apub, del_assemble($rootObj));

    $leafG = new Grant($bid, \Naalp\Policy::DESTRUCTIVE, 1, 0, 1000000, "");
    $leafObj = $leafG->envelopeObject($mid, 1, Cose::PROFILE_PUBLIC, [$rootRes->contentId]);
    $leafRes = Delegation::verifyGrantObject(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $mpub, del_assemble($leafObj));

    $set = [$rootRes->contentId => $rootRes, $leafRes->contentId => $leafRes];
    $anchors = [$aid => true];

    $action = new Action($bid, \Naalp\Policy::DESTRUCTIVE, "", [$leafRes->contentId]);

    // args content id the approval binds (a stand-in T1 content id over "action args").
    $argsCID = "\x20\x30" . hash('sha384', "the exact canonical action args", true);
    $seed = str_repeat("\x32", 32);
    $pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
    [, $approverId] = del_key("D4-approver");
    $appr = new \Naalp\ApprovalRecord($argsCID, $approverId, \Naalp\Policy::DESTRUCTIVE, "\x01\x02\x03\x04", 1000000);
    $apprSig = \Naalp\Approval::signApproval($appr, $seed);
    $verify = static fn(string $msg, string $sig): bool => Cose::ed25519Verify($pk, $msg, $sig);

    $walPath = tempnam(sys_get_temp_dir(), 'naalp_del_wal_');
    $ledger = \Naalp\Approval::openLedger($walPath);

    return compact('action', 'set', 'anchors', 'appr', 'apprSig', 'argsCID', 'ledger', 'verify');
}
