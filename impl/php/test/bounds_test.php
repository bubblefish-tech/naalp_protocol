<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Decoder resource bounds (design.md §3.4, R7) known-answer + fail-closed tests for the PHP SDK,
// mirroring impl/go/cbor/bounds_test.go, impl/go/envelope/bounds_test.go, and
// impl/go/streaming/bounds_test.go (impl/rust/src/{cbor,envelope,streaming}.rs carry the same
// shapes). These bounds are MUST-level wire limits (a memory/verification-cost DoS guard) and are
// projected once into WireConstants so all ten ports agree on the numbers.
//
// Each bound is proven by a BOUNDARY PAIR: an otherwise-valid input exactly AT the limit is
// accepted, and an otherwise-valid input one past the limit is rejected with its named error.
// "Otherwise valid" is load-bearing for mutation survival: because the only defect is the bound,
// deleting the bound check makes the over-limit input verify, so a constant-return mutation is
// caught.
//
// Properties covered:
//   1. Cbor::decodeBounded nesting-depth bound -- the outermost item is depth 1; an item at
//      depth==maxDepth decodes; an item at depth==maxDepth+1 is rejected DepthExceeded, BEFORE it is
//      materialized; the unbounded Cbor::decode accepts the same over-depth structure (the bound,
//      not another check, is what rejects it).
//   2. Envelope::verify causes[] cardinality bound -- MAX_CAUSES accepted, MAX_CAUSES+1 rejected
//      TooManyCauses.
//   3. Envelope::verify ext cardinality bound -- MAX_EXT accepted, MAX_EXT+1 rejected
//      TooManyExtensions.
//   4. Envelope::verify cext cardinality bound -- MAX_CEXT+1 rejected TooManyExtensions (the same
//      cardinality check in objectFromMap fires before the critical-extension recognition check).
//   5. Envelope::verify CBOR nesting-depth bound (via decodeBounded) -- a body nested to exactly
//      MAX_NESTING_DEPTH verifies; one level deeper is rejected DepthExceeded.
//   6. Envelope::verify / verifyRotationObject object octet-size bound -- an under-limit signed
//      object verifies; an over-limit one is rejected TooLarge on the raw bytes, before any parse.
//   7. Streaming::verifyCommit / verifyCheckpoint chunk-count bound -- MAX_STREAM_CHUNKS chunks
//      verify; MAX_STREAM_CHUNKS+1 is rejected TooManyChunks BEFORE the digest/contiguity check (both
//      commits carry a MATCHING rolling digest, so the count is the only reason to reject).
//
// Run: php -d extension=sodium -d extension=intl -d ffi.enable=1 -d memory_limit=-1
//          test/bounds_test.php   (from impl/php/). Exit code 0 = all checks passed.
require __DIR__ . '/../src/bootstrap.php';

use Naalp\A;
use Naalp\B;
use Naalp\Cbor;
use Naalp\Chunk;
use Naalp\Cose;
use Naalp\Envelope;
use Naalp\M;
use Naalp\NaalpObject;
use Naalp\StreamCheckpoint;
use Naalp\StreamCommit;
use Naalp\Streaming;
use Naalp\U;
use Naalp\WireConstants;

$fails = 0;
function check(string $name, bool $ok, string $detail = ""): void
{
    global $fails;
    if ($ok) {
        echo "  ok   $name\n";
    } else {
        $fails++;
        echo "  FAIL $name" . ($detail !== "" ? "  $detail" : "") . "\n";
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

echo "decoder resource bounds KAT (PHP, design.md §3.4, R7)\n";

// ---------------------------------------------------------------------------------------------
// 1. Cbor::decodeBounded nesting-depth bound (mirrors impl/go/cbor/bounds_test.go).
// ---------------------------------------------------------------------------------------------
echo "\n1. Cbor::decodeBounded depth bound\n";

/**
 * Returns canonical CBOR for k single-element arrays wrapping a zero scalar: 0x81 (array of one)
 * repeated k times, then 0x00. Decoding it, the outermost array is at depth 1 and the innermost
 * scalar is at depth k+1.
 */
function nestedArraysCbor(int $k): string
{
    return \str_repeat("\x81", $k) . "\x00";
}

$d = 3;
$atLimit = nestedArraysCbor($d - 1); // deepest scalar at depth d
check("deepest item at depth $d decodes at maxDepth=$d", err_kind(function () use ($atLimit, $d) {
    Cbor::decodeBounded($atLimit, $d);
}) === "no-error");

$over = nestedArraysCbor($d); // deepest scalar at depth d+1
check("deepest item at depth " . ($d + 1) . " is DepthExceeded at maxDepth=$d",
    err_kind(fn() => Cbor::decodeBounded($over, $d)) === "DepthExceeded");

// The unbounded path accepts the same over-depth structure: the bound, not another check, is what
// rejected it above.
check("unbounded Cbor::decode accepts the depth-" . ($d + 1) . " structure",
    err_kind(fn() => Cbor::decode($over)) === "no-error");

// ---------------------------------------------------------------------------------------------
// Envelope helpers (mirrors impl/go/envelope/bounds_test.go / impl/csharp/test/EnvelopeBoundsTests).
//
// These assemble a structural ML-DSA-65 (level 3, meets the Public-profile floor of 3; Ed25519 is
// level 0 and would fail EVERY profile floor via ProfileDowngrade, so it cannot reach the final
// accept for a boundary-pair) COSE_Sign1 object with a PLACEHOLDER signature, bypassing
// Envelope::sign()/MlDsa::sign(). This is not a shortcut: Envelope::verify()'s pure path NEVER
// cryptographically checks an ML-DSA signature -- "for an ML-DSA object the structural checks
// above are complete and the signature is NOT verified here (PHP has no deterministic ML-DSA
// verify)" (Envelope.php's own documented crypto scope; $pubkey is unused for this alg). So every
// ML-DSA object this port's own production verify() ever accepts is accepted on exactly this
// structural basis, and the six §3.4 bounds under test run identically regardless of the
// signature bytes -- this needs no ML-DSA/OpenSSL >= 3.5 floor and so runs everywhere.
// ---------------------------------------------------------------------------------------------
$boundsSigner = \str_repeat("\x42", 20); // an arbitrary fixed synthetic signer-id byte string
$boundsPlaceholderSig = \str_repeat("\x00", 64);

/** A fresh, otherwise-valid object with the given body and the fixed synthetic signer above. */
function buildBoundsObject(mixed $body): NaalpObject
{
    global $boundsSigner;
    return new NaalpObject(
        kind: 1, channel: 4, signer: $boundsSigner, created: 1785000000000, effect: 2, body: $body,
        profile: Cose::PROFILE_PUBLIC,
    );
}

function acceptAllKind(int $ch, int $k): bool
{
    return true;
}

/** n content-id-shaped bstrs (multihash sha2-384 = 0x20 0x30 + 48 bytes), so causes[] is otherwise valid at any cardinality. */
function makeCauses(int $n): array
{
    $out = [];
    for ($i = 0; $i < $n; $i++) {
        $b = "\x20\x30" . \str_repeat("\x00", 48);
        $out[] = $b;
    }
    return $out;
}

/** n distinct non-critical extension entries (unknown keys, which the may-ignore rule accepts). */
function makeExtMap(int $n): M
{
    $pairs = [];
    for ($i = 0; $i < $n; $i++) {
        $pairs[] = [new U(100 + $i), new U(0)];
    }
    return new M($pairs);
}

/** k single-element arrays wrapping a zero scalar. As a body value it sits at depth 2 (the object
 * body map is depth 1), so the scalar is at depth 2+k. */
function nestArrays(int $k): mixed
{
    $v = new U(0);
    for ($i = 0; $i < $k; $i++) {
        $v = new A([$v]);
    }
    return $v;
}

/** Assembles $o as a structural ML-DSA-65 COSE_Sign1 object; see the header comment above. */
function signBoundsObject(NaalpObject $o): string
{
    global $boundsPlaceholderSig;
    $payload = Envelope::buildPayload($o); // sets id = contentId()
    $prot = Envelope::protectedHeader(Cose::ALG_MLDSA65, $o->signer, $o->profile);
    return Envelope::assembleSigned($prot, $payload, $boundsPlaceholderSig);
}

function verifyBoundsObject(string $obj): NaalpObject
{
    return Envelope::verify(Cose::PROFILE_PUBLIC, Cose::ALG_MLDSA65, "", 'acceptAllKind', $obj);
}

// ---------------------------------------------------------------------------------------------
// 2/3. Envelope::verify causes[] / ext cardinality bounds -- accept AT the limit.
// ---------------------------------------------------------------------------------------------
echo "\n2. Envelope::verify BoundsAcceptAtLimit\n";

$oc = buildBoundsObject(new U(0));
$oc->causes = makeCauses(WireConstants::MAX_CAUSES);
check("causes==MAX_CAUSES verifies", err_kind(fn() => verifyBoundsObject(signBoundsObject($oc))) === "no-error");

$oe = buildBoundsObject(new U(0));
$oe->ext = makeExtMap(WireConstants::MAX_EXT);
check("ext==MAX_EXT verifies", err_kind(fn() => verifyBoundsObject(signBoundsObject($oe))) === "no-error");

// body nested so the deepest scalar sits at exactly MAX_NESTING_DEPTH (2 + (MAX_NESTING_DEPTH-2)).
$od = buildBoundsObject(nestArrays(WireConstants::MAX_NESTING_DEPTH - 2));
check("depth==MAX_NESTING_DEPTH verifies", err_kind(fn() => verifyBoundsObject(signBoundsObject($od))) === "no-error");

// ---------------------------------------------------------------------------------------------
// 3. Envelope::verify -- reject one past each bound, with its named error (fail-closed).
// ---------------------------------------------------------------------------------------------
echo "\n3. Envelope::verify BoundsRejectOverLimit\n";

$oc2 = buildBoundsObject(new U(0));
$oc2->causes = makeCauses(WireConstants::MAX_CAUSES + 1);
check("causes==MAX_CAUSES+1 rejected TooManyCauses",
    err_kind(fn() => verifyBoundsObject(signBoundsObject($oc2))) === "TooManyCauses");

$oe2 = buildBoundsObject(new U(0));
$oe2->ext = makeExtMap(WireConstants::MAX_EXT + 1);
check("ext==MAX_EXT+1 rejected TooManyExtensions",
    err_kind(fn() => verifyBoundsObject(signBoundsObject($oe2))) === "TooManyExtensions");

// cext over the limit also yields TooManyExtensions: the cardinality check in objectFromMap fires
// before the critical-extension recognition check.
$ox = buildBoundsObject(new U(0));
$ox->cext = makeExtMap(WireConstants::MAX_CEXT + 1);
check("cext==MAX_CEXT+1 rejected TooManyExtensions",
    err_kind(fn() => verifyBoundsObject(signBoundsObject($ox))) === "TooManyExtensions");

// body nested so the deepest scalar sits at MAX_NESTING_DEPTH+1.
$od2 = buildBoundsObject(nestArrays(WireConstants::MAX_NESTING_DEPTH - 1));
check("depth==MAX_NESTING_DEPTH+1 rejected DepthExceeded",
    err_kind(fn() => verifyBoundsObject(signBoundsObject($od2))) === "DepthExceeded");

// ---------------------------------------------------------------------------------------------
// 4. Envelope::verify object octet-size bound (TooLarge), raw bytes, before any parse.
// ---------------------------------------------------------------------------------------------
echo "\n4. Envelope::verify BoundTooLarge\n";

$under = buildBoundsObject(new B(\str_repeat("\x00", WireConstants::MAX_OBJECT_SIZE - 16384)));
$uobj = signBoundsObject($under);
check("under-limit object is <= MAX_OBJECT_SIZE bytes", \strlen($uobj) <= WireConstants::MAX_OBJECT_SIZE,
    "got " . \strlen($uobj) . " bytes");
check("under-limit object verifies", err_kind(fn() => verifyBoundsObject($uobj)) === "no-error");

$over2 = buildBoundsObject(new B(\str_repeat("\x00", WireConstants::MAX_OBJECT_SIZE)));
$bobj = signBoundsObject($over2);
check("over-limit object is > MAX_OBJECT_SIZE bytes", \strlen($bobj) > WireConstants::MAX_OBJECT_SIZE,
    "got " . \strlen($bobj) . " bytes");
check("over-limit object rejected TooLarge", err_kind(fn() => verifyBoundsObject($bobj)) === "TooLarge");

// ---------------------------------------------------------------------------------------------
// 5. Streaming::verifyCommit / verifyCheckpoint chunk-count bound (mirrors
//    impl/go/streaming/bounds_test.go). Both commits carry a MATCHING rolling digest, so the count
//    is the only reason to reject; the chunks share one backing Chunk instance to bound test memory
//    (all offsets are 0/empty, so the digest is trivial to compute over a million-plus entries).
// ---------------------------------------------------------------------------------------------
echo "\n5. Streaming::verifyCommit/verifyCheckpoint BoundTooManyChunks\n";

$sharedChunk = new Chunk(0, "");
$atLimitChunks = \array_fill(0, WireConstants::MAX_STREAM_CHUNKS, $sharedChunk);
$overChunks = $atLimitChunks;
$overChunks[] = $sharedChunk; // MAX_STREAM_CHUNKS + 1

$okCommit = new StreamCommit("", Streaming::commitDigest($atLimitChunks));
check("commit at MAX_STREAM_CHUNKS verifies",
    err_kind(fn() => Streaming::verifyCommit($okCommit, $atLimitChunks)) === "no-error");

$overCommit = new StreamCommit("", Streaming::commitDigest($overChunks));
check("commit at MAX_STREAM_CHUNKS+1 rejected TooManyChunks",
    err_kind(fn() => Streaming::verifyCommit($overCommit, $overChunks)) === "TooManyChunks");

// VerifyCheckpoint enforces the same bound, and the count check fires before the
// contiguity/digest checks, so the diagnosis is TooManyChunks (not a digest error).
$overCp = new StreamCheckpoint("", 0, "");
check("checkpoint at MAX_STREAM_CHUNKS+1 rejected TooManyChunks",
    err_kind(fn() => Streaming::verifyCheckpoint($overCp, $overChunks)) === "TooManyChunks");

echo "\n" . ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
