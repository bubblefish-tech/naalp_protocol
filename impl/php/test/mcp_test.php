<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// NAALP-MCP binding-profile conformance for the PHP SDK (design.md §19; Companion-Spec Requirement
// 6.1), graded against the shared independent corpus vectors/mcp/cases.json (NOT produced by this
// code). NAALP-MCP is a draft-01 ADDITIVE tier-1 surface that turns MCP's anonymous, untrusted tool
// annotations into a SIGNED effect claim by a named key. It introduces NO new envelope/encoding/
// signature/identity/audit mechanism: an MCP tool call is a normal N-AALP object on the Bridge channel,
// reusing the closed effect lattice (Policy), the §7 approval + single-use consume ledger, and the T1
// content-id framing unchanged.
//
// CORPUS-GRADED (pure, signature-independent): the annotation-set encoding, the published annotation->
// effect mapping table, the malformed-annotation rejections (MalformedAnnotation), every tool-call
// body/content-id/tool-id/args-id/call-binding/call-content-id, the resolution verdicts (accept ->
// enforced+mismatch; under-declaration -> EffectUnderDeclared), the approval-binding content ids
// (a changed tool description OR changed arguments yields a different call content id), and the
// wire-format edge cases (NonCanonical descending keys, empty-vs-absent annotations, minimal,
// look-alike 2-field call-binding).
// BEHAVIOURAL (isolation): the more-severe ResolveEnforcedEffect attenuator, the tier-1 dispatch.
// STRUCTURAL-ML-DSA + REAL-LEDGER (isolation, NOT corpus-graded): verifyToolCall over a structural
// ML-DSA-65 envelope object (bare header + placeholder sig, clearing the level-3 floor; the ML-DSA
// signature is not cryptographically verified in PHP — the delegation port's idiom) and authorizeCall
// against a REAL §7 Approval consume ledger with an Ed25519-demonstrated human approval. The corpus
// carries no signed vector, so all signed paths are isolation-only.
//
// Written test-first: Naalp\Mcp / Naalp\ToolCall are absent until Mcp.php lands, so this fails RED with
// a fatal "class not found"; dropping the declared<annotation-mapped guard in resolveEnforcedEffect
// (the good-regulator collapse-up) flips "resolution under_declare_severe_annotation_benign_signer
// verdict == oracle".
//
// Run:  php -d extension=sodium -d extension=intl test/mcp_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Mcp;
use Naalp\Annotations;
use Naalp\ToolCall;
use Naalp\ApprovalRecord;
use Naalp\Approval;
use Naalp\Envelope;
use Naalp\NaalpObject;
use Naalp\Cbor;
use Naalp\Cose;
use Naalp\Identity;
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
function mcp_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/mcp/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/mcp/cases.json not found");
}

/** Build an Annotations value from a hints dict {"1":1,"2":0,...} (absent key => null hint). */
function mcp_annotations_from_hints(array $hints): Annotations
{
    $a = new Annotations();
    foreach ($hints as $k => $v) {
        $flag = ((int) $v) === 1;
        switch ((int) $k) {
            case 1: $a->readOnly = $flag; break;
            case 2: $a->destructive = $flag; break;
            case 3: $a->idempotent = $flag; break;
            case 4: $a->openWorld = $flag; break;
        }
    }
    return $a;
}

/** Assemble a STRUCTURAL ML-DSA-65 signed envelope object (placeholder sig, not verified in pure PHP —
 * the delegation port's del_assemble idiom). */
function mcp_assemble(NaalpObject $o): string
{
    $payload = Envelope::buildPayload($o); // sets $o->id
    $prot = Envelope::protectedHeader(Cose::ALG_MLDSA65, $o->signer, $o->profile);
    $sig = str_repeat("\x00", 64); // placeholder: ML-DSA is not verified in the pure tier
    return Envelope::assembleSigned($prot, $payload, $sig);
}

$C = mcp_vectors();
$wals = [];
echo "mcp conformance (PHP) — graded vs vectors/mcp/cases.json\n";

// 1. the annotation set encoding + the published annotation->effect mapping table, byte/verdict-for
//    every set vs the non-circular oracle. Both directions: build-from-hints encodes to annotations_hex,
//    and parse-from-hex maps to mapped_effect. A field-ignoring encoder or a constant map diverges.
foreach ($C["annotations"] as $aj) {
    $a = mcp_annotations_from_hints($aj["hints"]);
    check("annotations {$aj['name']} encode == oracle", bin2hex($a->encode()), $aj["annotations_hex"]);
    $parsed = Mcp::annotationsFromValue(Cbor::decode(hex2bin($aj["annotations_hex"])));
    check("annotations {$aj['name']} round-trip encode", bin2hex($parsed->encode()), $aj["annotations_hex"]);
    check("annotations {$aj['name']} mapped effect == oracle", (string) Mcp::mapAnnotationsToEffect($parsed), (string) $aj["mapped_effect"]);
}

// 2. the malformed annotation sets: a hint value outside {0,1} or a key outside {1,2,3,4} maps outside
//    the closed lattice and is rejected MalformedAnnotation — never defaulted to benign (AC-6.1.2).
foreach ($C["malformed_annotations"] as $mj) {
    check("malformed annotations {$mj['name']} rejected (MalformedAnnotation)", err_kind(fn() => Mcp::annotationsFromValue(Cbor::decode(hex2bin($mj["annotations_hex"])))), "MalformedAnnotation");
}

// 3. every tool-call: body, content id, tool-id, args-id, call-binding body, call content id, and the
//    annotation-mapped effect, byte/verdict-for vs the oracle. Round-trip: toolCallFromBody reconstructs.
foreach ($C["tool_calls"] as $tj) {
    $tc = new ToolCall(hex2bin($tj["tool_hex"]), hex2bin($tj["args_hex"]), mcp_annotations_from_hints($tj["hints"]));
    check("tool-call {$tj['name']} body == oracle", bin2hex($tc->bytes()), $tj["body_hex"]);
    check("tool-call {$tj['name']} content id == oracle", bin2hex($tc->contentId()), $tj["content_id_hex"]);
    $cb = $tc->callBinding();
    check("tool-call {$tj['name']} tool-id == oracle", bin2hex($cb->toolId), $tj["tool_id_hex"]);
    check("tool-call {$tj['name']} args-id == oracle", bin2hex($cb->argsId), $tj["args_id_hex"]);
    check("tool-call {$tj['name']} call-binding body == oracle", bin2hex($cb->bytes()), $tj["call_binding_hex"]);
    check("tool-call {$tj['name']} call content id == oracle", bin2hex($cb->contentId()), $tj["call_content_id_hex"]);
    check("tool-call {$tj['name']} annotation-mapped effect == oracle", (string) Mcp::mapAnnotationsToEffect($tc->annotations), (string) $tj["annotation_mapped_effect"]);
    $rt = Mcp::toolCallFromBody(Cbor::decode(hex2bin($tj["body_hex"])));
    check("tool-call {$tj['name']} round-trips (body)", bin2hex($rt->bytes()), $tj["body_hex"]);
}

// 4. the more-severe resolution: for every (annotation_mapped, declared) pair the oracle's verdict and,
//    on accept, its enforced effect + mismatch flag. THE mutation target: dropping the declared <
//    annotation-mapped guard flips every under_declare_* verdict from EffectUnderDeclared to accept.
foreach ($C["resolution"] as $r) {
    $name = $r["name"];
    if ($r["verdict"] === "accept") {
        [$enf, $mis] = Mcp::resolveEnforcedEffect($r["annotation_mapped"], $r["declared"]);
        check("resolution $name enforced == oracle", (string) $enf, (string) $r["enforced"]);
        check("resolution $name mismatch == oracle", $mis ? "true" : "false", $r["mismatch"] ? "true" : "false");
    } else {
        check("resolution $name verdict == oracle", err_kind(fn() => Mcp::resolveEnforcedEffect($r["annotation_mapped"], $r["declared"])), $r["verdict"]);
    }
}
// a declared effect outside the closed lattice is rejected EffectOutsideLattice, never defaulted benign.
check("declared effect > destructive rejected (EffectOutsideLattice)", err_kind(fn() => Mcp::resolveEnforcedEffect(0, 4)), "EffectOutsideLattice");

// 5. the approval binding: a changed tool DESCRIPTION or changed ARGUMENTS yields a DIFFERENT call
//    content id (so a prior approval no longer binds it — Requirement 6.1 / AC-6.1.2, AC-6.1.3).
$callCids = [];
foreach ($C["approval_binding"] as $bj) {
    $cb = Mcp::newCallBinding(hex2bin($bj["tool_hex"]), hex2bin($bj["args_hex"]));
    check("approval-binding {$bj['name']} tool-id == oracle", bin2hex($cb->toolId), $bj["tool_id_hex"]);
    check("approval-binding {$bj['name']} args-id == oracle", bin2hex($cb->argsId), $bj["args_id_hex"]);
    check("approval-binding {$bj['name']} call-binding body == oracle", bin2hex($cb->bytes()), $bj["call_binding_hex"]);
    check("approval-binding {$bj['name']} call content id == oracle", bin2hex($cb->contentId()), $bj["call_content_id_hex"]);
    $callCids[$bj["name"]] = bin2hex($cb->contentId());
}
check("changed args yields a different call content id", $callCids["base_T_A"] === $callCids["changed_args_T_B"] ? "same" : "different", "different");
check("changed tool description yields a different call content id", $callCids["base_T_A"] === $callCids["changed_tool_desc_T2_A"] ? "same" : "different", "different");

// 6. wire-format edge cases. keys-out-of-order -> the strict decoder rejects NonCanonical (the canonical
//    body parses). empty-vs-absent: an empty annotations map is present+valid (all MCP defaults ->
//    destructive); an absent annotations field is ToolCallMalformed. minimal: smallest valid tool-call.
//    look-alike: a 2-field call-binding fed to the tool-call parser is ToolCallMalformed.
$ec = $C["edge_cases"];
$kv = $ec["keys_out_of_order"];
check("canonical tool-call body parses (no error)", err_kind(fn() => Mcp::toolCallFromBody(Cbor::decode(hex2bin($kv["canonical_body_hex"])))), "no-error");
check("descending-key tool-call body rejected (NonCanonical)", err_kind(fn() => Cbor::decode(hex2bin($kv["noncanonical_body_hex"]))), "NonCanonical");
$ea = $ec["empty_vs_absent"];
$emptyAnn = Mcp::toolCallFromBody(Cbor::decode(hex2bin($ea["empty_annotations"]["body_hex"])));
check("empty-annotations tool-call content id == oracle", bin2hex($emptyAnn->contentId()), $ea["empty_annotations"]["content_id_hex"]);
check("empty-annotations maps to destructive default", (string) Mcp::mapAnnotationsToEffect($emptyAnn->annotations), (string) $ea["empty_annotations"]["mapped_effect"]);
check("absent-annotations tool-call rejected (ToolCallMalformed)", err_kind(fn() => Mcp::toolCallFromBody(Cbor::decode(hex2bin($ea["absent_annotations"]["body_hex"])))), "ToolCallMalformed");
$mn = $ec["minimal"];
$minTc = new ToolCall(hex2bin($mn["tool_hex"]), hex2bin($mn["args_hex"]), new Annotations());
check("minimal tool-call body == oracle", bin2hex($minTc->bytes()), $mn["body_hex"]);
check("minimal tool-call content id == oracle", bin2hex($minTc->contentId()), $mn["content_id_hex"]);
check("minimal tool-call maps to destructive default", (string) Mcp::mapAnnotationsToEffect($minTc->annotations), (string) $mn["mapped_effect"]);
$la = $ec["look_alike"];
check("look-alike (2-field call-binding) rejected (ToolCallMalformed)", err_kind(fn() => Mcp::toolCallFromBody(Cbor::decode(hex2bin($la["call_binding_body_hex"])))), "ToolCallMalformed");

// 7. STRUCTURAL-ML-DSA (isolation): verifyToolCall over a signed envelope object. A lying benign
//    annotation (read_only) under a signer who DECLARES destructive resolves to destructive (the more
//    severe), mismatch attributable to the signer; a signer under-declaring below its own carried
//    annotations is rejected EffectUnderDeclared at the enforcement point. A baseline-only kind
//    dispatch would reject the tier-1 McpToolCall.
$signerKey = hash('sha384', "naalp-mcp-signer", true); // structural ML-DSA-65 pubkey
$signerId = Identity::signerId(Cose::ALG_MLDSA65, $signerKey);
// lying tool: annotations {ro=1} (=> read_only), signer declares destructive.
$lyingTc = new ToolCall("tool-lie", "args-lie", mcp_annotations_from_hints(["1" => 1]));
$lyingObj = $lyingTc->envelopeObject($signerId, 1, Cose::PROFILE_PUBLIC, Policy::DESTRUCTIVE, []);
$lyingSigned = mcp_assemble($lyingObj);
$rLying = null;
check("verify lying-tool wrapper (no error)", err_kind(function () use ($lyingSigned, $signerKey, &$rLying) {
    $rLying = Mcp::verifyToolCall(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $signerKey, $lyingSigned);
}), "no-error");
if ($rLying !== null) {
    check("lying-tool annotation-mapped == read_only", (string) $rLying->annotationMapped, (string) Policy::READ_ONLY);
    check("lying-tool enforced == declared destructive (more severe)", (string) $rLying->enforced, (string) Policy::DESTRUCTIVE);
    check("lying-tool mismatch flag set (attributable to signer)", $rLying->mismatch ? "true" : "false", "true");
}
// under-declared: annotations {} (=> destructive), signer declares read_only -> EffectUnderDeclared.
$underTc = new ToolCall("tool-under", "args-under", new Annotations());
$underObj = $underTc->envelopeObject($signerId, 1, Cose::PROFILE_PUBLIC, Policy::READ_ONLY, []);
$underSigned = mcp_assemble($underObj);
check("verify under-declared wrapper rejected (EffectUnderDeclared)", err_kind(fn() => Mcp::verifyToolCall(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $signerKey, $underSigned)), "EffectUnderDeclared");

// 8. REAL-LEDGER (isolation): the per-call approval gate reuses the §7 approval + single-use consume
//    ledger. An approval binding the EXACT call binding content id, granting >= the enforced effect and
//    unexpired, authorizes ONCE and is consumed; a replay is AlreadyConsumed; an approval bound to a
//    DIFFERENT call (changed args) does not bind (ApprovalRequired); an under-granting approval is
//    ApprovalRequired. Ed25519-demonstrated human approval (the reference uses ML-DSA).
$humanSeed = str_repeat("\x37", 32);
$humanPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($humanSeed));
$hv = static fn(string $msg, string $sig): bool => Cose::ed25519Verify($humanPk, $msg, $sig);
// the approved call: annotations {ro=0,de=0,idem=0} (=> non_idempotent_write 2), signer declares 2.
$callTc = new ToolCall("tool-pay", "args-A", mcp_annotations_from_hints(["1" => 0, "2" => 0, "3" => 0]));
$callObj = $callTc->envelopeObject($signerId, 1, Cose::PROFILE_PUBLIC, Policy::NON_IDEMPOTENT_WRITE, []);
$rCall = Mcp::verifyToolCall(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $signerKey, mcp_assemble($callObj));
$callCid = $rCall->toolCall->callBinding()->contentId();
$apprOk = new ApprovalRecord($callCid, "human-approver", Policy::NON_IDEMPOTENT_WRITE, str_repeat("\x01", 16), 1785000000000);
$apprOkSig = Cose::ed25519Sign($humanSeed, $apprOk->bytes());
$walA = tempnam(sys_get_temp_dir(), 'naalp_mcp_wal_');
$wals[] = $walA;
$ledA = Approval::openLedger($walA);
check("authorize exact call (no error)", err_kind(fn() => Mcp::authorizeCall($rCall, $apprOk, $hv, $apprOkSig, "caller-1", 1785000000000 - 1000, $ledA)), "no-error");
check("replay of consumed approval rejected (AlreadyConsumed)", err_kind(fn() => Mcp::authorizeCall($rCall, $apprOk, $hv, $apprOkSig, "caller-2", 1785000000000 - 1000, $ledA)), "AlreadyConsumed");
$ledA->close();
// changed args (a different call) — the approval bound to the original call does NOT bind it.
$callTcB = new ToolCall("tool-pay", "args-B", mcp_annotations_from_hints(["1" => 0, "2" => 0, "3" => 0]));
$rCallB = Mcp::verifyToolCall(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $signerKey, mcp_assemble($callTcB->envelopeObject($signerId, 1, Cose::PROFILE_PUBLIC, Policy::NON_IDEMPOTENT_WRITE, [])));
$walB = tempnam(sys_get_temp_dir(), 'naalp_mcp_wal_');
$wals[] = $walB;
$ledB = Approval::openLedger($walB);
check("approval for changed-args call does not bind (ApprovalRequired)", err_kind(fn() => Mcp::authorizeCall($rCallB, $apprOk, $hv, $apprOkSig, "caller-3", 1785000000000 - 1000, $ledB)), "ApprovalRequired");
// an approval that binds the call but grants BELOW the enforced effect is ApprovalRequired.
$apprWeak = new ApprovalRecord($callCid, "human-approver", Policy::IDEMPOTENT_WRITE, str_repeat("\x02", 16), 1785000000000);
$apprWeakSig = Cose::ed25519Sign($humanSeed, $apprWeak->bytes());
check("under-granting approval rejected (ApprovalRequired)", err_kind(fn() => Mcp::authorizeCall($rCall, $apprWeak, $hv, $apprWeakSig, "caller-4", 1785000000000 - 1000, $ledB)), "ApprovalRequired");
$ledB->close();

foreach ($wals as $w) {
    @unlink($w);
}

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
