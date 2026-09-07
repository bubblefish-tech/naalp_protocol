<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C18 signed-description / directory / import conformance for the PHP SDK (design.md §21; R-DESC-1..8),
// graded against the shared independent corpus vectors/description/cases.json (NOT produced by this
// code). C18 is a signed, OFFLINE-VERIFIABLE description + discovery layer whose authority lives in the
// SIGNED BYTES, never in the connection or the host that served them. Three wire objects:
//   - Description {1:service,2:operations[]} — each Operation {1:name,2:effect,3:requires_approval}.
//   - Directory {1:directory,2:version,3:members[]} — two conflicting versions from ONE signer (same
//     directory+version, differing members) are a FORK, detected at the first-differing member POSITION.
//   - Import {1:importer,2:format,3:foreign,4:operations[]} — carries a foreign description format
//     octet-for-octet (carriage, not adoption); the IMPORTER (the wrapping signer, recomputed from the
//     verifying key) is the SOLE authorization identity, a foreign identity never authorizes (R-14.6).
//
// CORPUS-GRADED (pure, signature-independent): every Description/Directory/Import body/head/id
// byte-for-byte, each Operation body, the foreign-id binding, the fork first-differing POSITION (fork,
// length-fork, different-version=no-fork, duplicate=no-fork), and the closed-format rejection
// (UnknownDescriptionFormat). BEHAVIOURAL (isolation): the offline re-serve identity, the confused-
// deputy ImporterMismatch (THE §21.4 security core), the DirectoryForkProof position, and the
// MalformedApprovalFlag rejection.
// STRUCTURAL-ML-DSA (isolation, NOT corpus-graded): the signed-object verify paths. PHP is PURE-ONLY
// for ML-DSA (FIPS 204 has no deterministic PHP signer), so — exactly as the delegation port — a signed
// object carries an ML-DSA-65 header + placeholder signature and clears the level-3 profile floor
// structurally (the ML-DSA signature itself is not cryptographically verified in PHP); the signer id
// the confused-deputy check binds is a REAL identity.signerId(ML-DSA-65, pubkey), so the R-14.6 binding
// is genuinely exercised. A pure Ed25519 (level-0) object is correctly rejected ProfileDowngrade. The
// corpus carries no signed vector, so all signed paths are isolation-only.
//
// DEVIATION (honest F4, as the Python port documents): Go's VerifyImport carries a VerifierKeyMismatch
// guard because it takes BOTH an (alg,pubkey) pair AND a separate verifier v and must bind them before
// deriving the authority id. This port (like gateway/delegation) verifies with a SINGLE (alg,pubkey),
// so the authority id is ALWAYS derived from exactly the verifying key — the mismatch that guard
// prevents is structurally impossible, so there is no VerifierKeyMismatch surface. Absent, not dropped.
//
// Written test-first: Naalp\Desc / Naalp\Description are absent until Description.php lands, so this
// fails RED with a fatal "class not found"; dropping the confused-deputy importer==signer-id check in
// verifyImport flips "foreign importer rejected (ImporterMismatch)".
//
// Run:  php -d extension=sodium -d extension=intl test/description_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Desc;
use Naalp\Description;
use Naalp\Directory;
use Naalp\DirectoryForkProof;
use Naalp\Import;
use Naalp\Operation;
use Naalp\Cbor;
use Naalp\Cose;
use Naalp\Identity;
use Naalp\U;
use Naalp\N;
use Naalp\B;
use Naalp\T;
use Naalp\A;
use Naalp\M;

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
function description_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/description/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/description/cases.json not found");
}

/** Assemble a STRUCTURAL ML-DSA-65 COSE_Sign1 for a body (placeholder sig, not verified in pure PHP —
 * exactly the delegation port's del_assemble idiom). */
function desc_assemble(string $body): string
{
    $prot = Cbor::encode(new M([[new U(1), new N(Cose::ALG_MLDSA65)]])); // bare {1: alg} header
    $sig = str_repeat("\x00", 64); // placeholder: ML-DSA is not verified in the pure tier
    return Cose::assembleSign1Raw($prot, $body, $sig);
}

$C = description_vectors();
echo "description conformance (PHP) — graded vs vectors/description/cases.json\n";

// 1. the Description: each Operation body, and the whole Description body/head/id, byte-for-byte vs the
//    non-circular oracle (=> Go == Python == Rust). A field-ignoring encoder diverges here.
$dv = $C["description"];
$ops = [];
foreach ($dv["operations"] as $oj) {
    $op = new Operation($oj["name"], $oj["effect"], $oj["requires_approval"]);
    check("operation {$oj['name']} body == oracle", bin2hex($op->bytes()), $oj["body_hex"]);
    $ops[] = $op;
}
$desc = new Description(hex2bin($dv["service_hex"]), $ops);
check("description body == oracle", bin2hex($desc->bytes()), $dv["body_hex"]);
check("description head == oracle", bin2hex($desc->head()), $dv["head_hex"]);
check("description id == oracle", bin2hex($desc->id()), $dv["id_hex"]);
// ParseDescription reconstructs the operation table from the bytes ALONE (offline-verifiable), and the
// per-operation effect + approval-declaration accessors resolve.
$reparsed = Desc::parseDescription($desc->bytes());
[$wr, $found] = $reparsed->operation("write_record");
check("parsed operation found", $found ? "yes" : "no", "yes");
check("parsed operation effect class (fail-closed)", (string) $wr->effectClass(), "2");
check("parsed operation requires-approval flag", $wr->requiresApprovalFlag() ? "yes" : "no", "yes");

// 2. the Directory: version a body/head/id, the fork b, the length-fork, and the different-version
//    body, all byte-for-byte vs the oracle.
$dirV = $C["directory"];
$dirId = hex2bin($dirV["directory_hex"]);
$membersA = array_map('hex2bin', $dirV["members_a_hex"]);
$membersB = array_map('hex2bin', $dirV["fork"]["members_b_hex"]);
$membersShort = array_map('hex2bin', $dirV["length_fork"]["members_short_hex"]);
$dirA = new Directory($dirId, $dirV["version"], $membersA);
$dirB = new Directory($dirId, $dirV["version"], $membersB);
$dirShort = new Directory($dirId, $dirV["version"], $membersShort);
$dirDiffVer = new Directory($dirId, $dirV["different_version"]["version"], $membersB);
check("directory-a body == oracle", bin2hex($dirA->bytes()), $dirV["a"]["body_hex"]);
check("directory-a head == oracle", bin2hex($dirA->head()), $dirV["a"]["head_hex"]);
check("directory-a id == oracle", bin2hex($dirA->id()), $dirV["a"]["id_hex"]);
check("directory-b (fork) body == oracle", bin2hex($dirB->bytes()), $dirV["fork"]["b"]["body_hex"]);
check("directory-b (fork) head == oracle", bin2hex($dirB->head()), $dirV["fork"]["b"]["head_hex"]);
check("length-fork body == oracle", bin2hex($dirShort->bytes()), $dirV["length_fork"]["body_hex"]);
check("different-version body == oracle", bin2hex($dirDiffVer->bytes()), $dirV["different_version"]["body_hex"]);

// 3. fork detection at the FIRST-DIFFERING member POSITION (§8.5 equivocation position). Same
//    directory+version, differing members => fork at position 1; a truncated list forks at the length
//    of the shorter; a different version is a legitimate succession (no fork); identical members are a
//    benign duplicate (no fork). Represent "no fork" as -1 to match the oracle. A constant predicate
//    fails at least one row.
[$posFork, $isFork] = Desc::detectFork($dirA, $dirB);
check("fork detected", $isFork ? "yes" : "no", "yes");
check("fork first-differing position == oracle", (string) $posFork, (string) $dirV["fork"]["first_differing_position"]);
[$posLen, $isLenFork] = Desc::detectFork($dirA, $dirShort);
check("length-fork position == oracle", $isLenFork ? (string) $posLen : "-1", (string) $dirV["length_fork"]["first_differing_position"]);
[, $isVerFork] = Desc::detectFork($dirA, $dirDiffVer);
check("different-version is not a fork", $isVerFork ? "yes" : "no", "no");
[$posDup, $isDupFork] = Desc::detectFork($dirA, $dirA);
check("identical-members duplicate is not a fork", $isDupFork ? (string) $posDup : "-1", (string) $dirV["duplicate_first_differing_position"]);

// 4. the Import: body/head/id, and the foreign-id binding (the content id of the carried foreign bytes)
//    byte-for-byte vs the oracle. A closed-format code outside {1,2,3} is rejected on parse.
$iv = $C["import"];
$importOps = [];
foreach ($iv["operations"] as $oj) {
    $importOps[] = new Operation($oj["name"], $oj["effect"], $oj["requires_approval"]);
}
$im = new Import(hex2bin($iv["importer_hex"]), $iv["format"], hex2bin($iv["foreign_hex"]), $importOps);
check("import body == oracle", bin2hex($im->bytes()), $iv["body_hex"]);
check("import head == oracle", bin2hex($im->head()), $iv["head_hex"]);
check("import id == oracle", bin2hex($im->id()), $iv["id_hex"]);
check("import foreign-id == oracle (binds the exact foreign bytes)", bin2hex($im->foreignId()), $iv["foreign_id_hex"]);
$unknownFmtBody = hex2bin($iv["unknown_format"]["body_hex"]);
check("unknown format rejected on parse (UnknownDescriptionFormat)", err_kind(fn() => Desc::parseImport($unknownFmtBody)), "UnknownDescriptionFormat");

// 5. MalformedApprovalFlag (isolation): requires_approval is uint 1/0 — the spine carries no CBOR bool,
//    so a value outside {0,1} is rejected, never defaulted. Build a description body whose one operation
//    has requires_approval=2 and confirm parse rejects it (fail-closed, never silently coerced).
$badFlagBody = Cbor::encode(new M([
    [new U(1), new B("svc")],
    [new U(2), new A([new M([[new U(1), new T("op")], [new U(2), new U(1)], [new U(3), new U(2)]])])],
]));
check("requires_approval=2 rejected (MalformedApprovalFlag)", err_kind(fn() => Desc::parseDescription($badFlagBody)), "MalformedApprovalFlag");

// 6. STRUCTURAL-ML-DSA (isolation): the OFFLINE re-serve property (R-DESC-1) — a signed Description
//    verifies to the IDENTICAL operation table regardless of who serves the bytes; and a pure Ed25519
//    (level-0) object is correctly rejected ProfileDowngrade (below the level-3 Public floor).
$descKey = hash('sha384', "naalp-desc-key", true); // structural ML-DSA-65 pubkey (any distinct bytes)
$signedDesc = desc_assemble($desc->bytes());
$v1 = Desc::verifyDescription($signedDesc, Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $descKey);
$v2 = Desc::verifyDescription($signedDesc, Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $descKey); // a "different host" serving the same bytes
check("offline re-serve verifies to identical bytes", bin2hex($v1->bytes()), bin2hex($v2->bytes()));
check("offline re-serve == the signed description", bin2hex($v1->bytes()), $dv["body_hex"]);
// a level-0 Ed25519 object is below the level-3 floor.
$edProt = Cbor::encode(new M([[new U(1), new N(Cose::ALG_ED25519)]]));
$edSeed = str_repeat("\x51", 32);
$edSig = Cose::ed25519Sign($edSeed, Cose::toBeSignedRaw($edProt, $desc->bytes()));
$edPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($edSeed));
$edObj = Cose::assembleSign1Raw($edProt, $desc->bytes(), $edSig);
check("ed25519 (level-0) object rejected (ProfileDowngrade)", err_kind(fn() => Desc::verifyDescription($edObj, Cose::PROFILE_PUBLIC, Cose::ALG_ED25519, $edPk)), "ProfileDowngrade");

// 7. STRUCTURAL-ML-DSA (isolation): the DirectoryForkProof — two validly-signed Directory objects by
//    ONE signer at the same (directory,version) with DIFFERENT members prove equivocation and report
//    the first-differing POSITION; a proof over identical members is DirForkProofInvalid; an unnamed
//    accused is DirForkProofInvalid.
$forkSignerKey = hash('sha384', "naalp-dir-fork-signer", true);
$forkSignerId = Identity::signerId(Cose::ALG_MLDSA65, $forkSignerKey);
$signedDirA = desc_assemble($dirA->bytes());
$signedDirB = desc_assemble($dirB->bytes());
$fp = new DirectoryForkProof($forkSignerId, $signedDirA, $signedDirB);
$fpPos = null;
check("directory fork proof accepted", err_kind(function () use ($fp, $forkSignerKey, &$fpPos) {
    $fpPos = $fp->verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $forkSignerKey);
}), "no-error");
check("directory fork proof position == oracle", (string) $fpPos, (string) $dirV["fork"]["first_differing_position"]);
$fpDup = new DirectoryForkProof($forkSignerId, $signedDirA, desc_assemble($dirA->bytes()));
check("identical-members fork proof rejected (DirForkProofInvalid)", err_kind(fn() => $fpDup->verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $forkSignerKey)), "DirForkProofInvalid");
$fpUnnamed = new DirectoryForkProof("", $signedDirA, $signedDirB);
check("unnamed-accused fork proof rejected (DirForkProofInvalid)", err_kind(fn() => $fpUnnamed->verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $forkSignerKey)), "DirForkProofInvalid");

// 8. STRUCTURAL-ML-DSA (isolation): THE §21.4 confused-deputy security core + mutation target. The
//    wrapping signer (recomputed from the verifying key) is the SOLE authorization identity; the
//    attested `importer` MUST equal it. An honest import (importer == the key's signer id) verifies and
//    resolves that key id as the authority; a FOREIGN importer (a self-asserted id not derived from the
//    key) is rejected ImporterMismatch — a foreign identity never becomes an N-AALP authorization
//    identity (R-14.6). Dropping the importer==signer-id tie wrongly accepts the foreign importer.
$importKey = hash('sha384', "naalp-import-key", true); // structural ML-DSA-65 pubkey
$importKeyId = Identity::signerId(Cose::ALG_MLDSA65, $importKey);
$foreignBytes = hex2bin($iv["foreign_hex"]);
$honestImport = new Import($importKeyId, $iv["format"], $foreignBytes, $importOps);
$signedHonest = desc_assemble($honestImport->bytes());
$resolved = null;
check("honest import verifies (importer == key signer-id)", err_kind(function () use ($signedHonest, $importKey, &$resolved) {
    $resolved = Desc::verifyImport($signedHonest, Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $importKey);
}), "no-error");
if ($resolved !== null) {
    check("resolved authority id is the WRAPPING key id (not the foreign identity)", $resolved->authorityId, $importKeyId);
    check("resolved foreign id binds the exact foreign bytes", bin2hex($resolved->foreignId), $iv["foreign_id_hex"]);
}
// THE mutation-surviving check: a foreign importer (the foreign identity asserted inside `foreign`, or
// any id not derived from the verifying key) never authorizes.
$foreignImport = new Import($iv["foreign_asserted_identity"], $iv["format"], $foreignBytes, $importOps);
$signedForeign = desc_assemble($foreignImport->bytes());
check("foreign importer rejected (ImporterMismatch)", err_kind(fn() => Desc::verifyImport($signedForeign, Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $importKey)), "ImporterMismatch");

// 9. signDescription / signDirectory / signImport pair with the EXISTING verify path (round-trip),
//    mirroring the established php sign pattern (Negotiation::signMessage, Payment::signPaymentImport):
//    a structural ML-DSA-65 signed object (as desc_assemble builds by hand above) verifies to the
//    IDENTICAL body through verifyDescription/verifyDirectory/verifyImport, and a real Ed25519 signature
//    round-trips its raw signature (though it is below the level-3 profile floor verifyX enforces, so a
//    level-0 Ed25519 object built by signX is, correctly, ProfileDowngrade through verifyX). THE
//    mutation-surviving check: signX must sign the ACTUAL body bytes, not a constant — a signer that
//    ignores its payload flips the round-trip-equals-original assertions below.
$signKey = hash('sha384', "naalp-sign-key", true); // structural ML-DSA-65 pubkey (any distinct bytes)

// -- Description --
$signedDescMldsa = Desc::signDescription($desc, Cose::ALG_MLDSA65, $signKey);
$rtDesc = Desc::verifyDescription($signedDescMldsa, Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $signKey);
check("signDescription/verifyDescription round-trip == original body", bin2hex($rtDesc->bytes()), bin2hex($desc->bytes()));
$descEdSeed = str_repeat("\x73", 32);
$descEdPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($descEdSeed));
$signedDescEd = Desc::signDescription($desc, Cose::ALG_ED25519, $descEdSeed);
[$descEdProt, $descEdPayload, $descEdSig] = Cose::parseSign1Raw($signedDescEd);
check("signDescription(Ed25519) payload == original body", bin2hex($descEdPayload), bin2hex($desc->bytes()));
check("signDescription(Ed25519) signature verifies (raw)", Cose::ed25519Verify($descEdPk, Cose::toBeSignedRaw($descEdProt, $descEdPayload), $descEdSig) ? "true" : "false", "true");
check("signDescription(Ed25519) object rejected by verifyDescription (ProfileDowngrade, below level-3 floor)", err_kind(fn() => Desc::verifyDescription($signedDescEd, Cose::PROFILE_PUBLIC, Cose::ALG_ED25519, $descEdPk)), "ProfileDowngrade");

// -- Directory --
$signedDirMldsa = Desc::signDirectory($dirA, Cose::ALG_MLDSA65, $signKey);
$rtDir = Desc::verifyDirectory($signedDirMldsa, Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $signKey);
check("signDirectory/verifyDirectory round-trip == original body", bin2hex($rtDir->bytes()), bin2hex($dirA->bytes()));

// -- Import -- signed/verified under $importKey (whose signer id IS $honestImport's importer field).
$signedImportMldsa = Desc::signImport($honestImport, Cose::ALG_MLDSA65, $importKey);
$rtResolved = null;
check("signImport/verifyImport round-trip (honest importer) verifies", err_kind(function () use ($signedImportMldsa, $importKey, &$rtResolved) {
    $rtResolved = Desc::verifyImport($signedImportMldsa, Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, $importKey);
}), "no-error");
if ($rtResolved !== null) {
    check("signImport round-trip resolved authority id == wrapping key id", $rtResolved->authorityId, $importKeyId);
    check("signImport round-trip foreign-id == oracle", bin2hex($rtResolved->foreignId), $iv["foreign_id_hex"]);
}

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
