<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C9 native-streaming conformance for the PHP SDK (design.md §10; R-10.1..10.6), graded against the
// shared independent corpus vectors/stream/cases.json (NOT produced by this code; note the oracle
// directory is `stream`, while the module is Streaming — the name mismatch is intentional and matches
// the Go/Python layout). A native stream is three signed objects plus unsigned chunks: StreamOpen
// establishes identity/effect/approval and refuses an unauthorized effect BEFORE any chunk (R-10.3);
// the chunks are raw frames the transport AEAD already authenticates (N-AALP does not sign them
// individually, R-10.2); StreamCommit carries a rolling SHA-384 over the chunks in absolute-offset
// order, making the whole stream non-repudiable with ONE signature, not N (§10.2); optional
// StreamCheckpoints confirm a prefix without the end. Altering any delivered byte invalidates the
// commitment (StreamDigestMismatch).
//
// CORPUS-GRADED (pure): the rolling commitment digest, the mid-stream checkpoint digests, the
// StreamOpen/StreamCommit/StreamCheckpoint bodies byte-for-byte, and the independent tampered digest.
// BEHAVIOURAL (isolation): verifyCommit accepts the true stream and rejects a tampered one
// (StreamDigestMismatch); verifyCheckpoint confirms a prefix and rejects a wrong-length prefix;
// openStream refuses an over-ceiling / unknown effect before any chunk (EffectNotAuthorized); the
// commitment is over ABSOLUTE-OFFSET order (input order is irrelevant, but swapping which bytes sit at
// which offset changes the digest).
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the StreamCommit signature — the ONE
// end-commitment signature that covers the whole stream. PHP is PURE-ONLY for ML-DSA (FIPS 204), so the
// reference's ML-DSA signature is demonstrated with a real Ed25519 (RFC 8032) round-trip; a tampered
// signature and a foreign key both fail.
//
// Written test-first: Naalp\Streaming is absent until Streaming.php lands, so this fails RED with a
// fatal "class not found"; dropping the digest comparison in verifyCommit flips
// "tampered stream rejected (StreamDigestMismatch)".
//
// Run:  php -d extension=sodium -d extension=intl test/streaming_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Streaming;
use Naalp\Chunk;
use Naalp\StreamOpen;
use Naalp\StreamCommit;
use Naalp\StreamCheckpoint;
use Naalp\Cose;
use Naalp\Policy;
use Naalp\Guard;
use Naalp\State;

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

/** Walk up to the repository's shared corpus (the independent oracle; dir is `stream`, not `streaming`). */
function stream_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/stream/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/stream/cases.json not found");
}

$C = stream_vectors();
echo "streaming conformance (PHP) — graded vs vectors/stream/cases.json\n";

$streamId = hex2bin($C["stream_id_hex"]);
/** Fresh Chunk objects from the corpus (a fresh set each call so a tamper mutates no shared object). */
function chunks_of(array $C): array
{
    return array_map(fn($c) => new Chunk($c["offset"], hex2bin($c["data_hex"])), $C["chunks"]);
}
$chunks = chunks_of($C);

// 1. the rolling commitment digest == the independent oracle; the mid-stream checkpoints match the
//    running digest after each chunk; the final rolling digest == the oracle's final.
check("commit digest == oracle", bin2hex(Streaming::commitDigest($chunks)), $C["final_digest_hex"]);
$sd = Streaming::newStreamDigest();
foreach ($chunks as $i => $ch) {
    $sd->update($ch->data);
    if ($i < count($C["checkpoints"])) {
        check("rolling digest after chunk $i == checkpoint $i", bin2hex($sd->digestSoFar()), $C["checkpoints"][$i]["digest_so_far_hex"]);
    }
}
check("rolling final == oracle final", bin2hex($sd->digestSoFar()), $C["final_digest_hex"]);

// 2. the StreamOpen (approval present), StreamCommit, StreamCheckpoint bodies byte-for-byte vs oracle.
$open = new StreamOpen($streamId, $C["effect"], hex2bin($C["approval_hex"]), $C["substream"]);
check("StreamOpen body == oracle", bin2hex($open->bytes()), $C["open_body_hex"]);
$commit = new StreamCommit($streamId, hex2bin($C["final_digest_hex"]));
check("StreamCommit body == oracle", bin2hex($commit->bytes()), $C["commit_body_hex"]);
$cp0 = new StreamCheckpoint($streamId, $C["checkpoints"][0]["through_offset"], hex2bin($C["checkpoints"][0]["digest_so_far_hex"]));
check("StreamCheckpoint body == oracle", bin2hex($cp0->bytes()), $C["checkpoint_body_hex"]);

// 3. the TRUE stream verifies; altering one delivered byte invalidates the commitment. The tampered
//    digest is itself pinned to the independent oracle. (This is the load-bearing R-10.2 property.)
check("valid stream verifies", err_kind(fn() => Streaming::verifyCommit($commit, $chunks)), "no-error");
$tampered = chunks_of($C);
$tampered[$C["tamper"]["chunk_index"]]->data = hex2bin($C["tamper"]["flipped_data_hex"]);
check("tampered digest == oracle", bin2hex(Streaming::commitDigest($tampered)), $C["tamper"]["digest_hex"]);
check("tampered stream rejected (StreamDigestMismatch)", err_kind(fn() => Streaming::verifyCommit($commit, $tampered)), "StreamDigestMismatch");

// 4. a checkpoint confirms a prefix WITHOUT the end; a checkpoint given the full stream (wrong length)
//    is rejected.
foreach ($C["checkpoints"] as $i => $cpj) {
    $cp = new StreamCheckpoint($streamId, $cpj["through_offset"], hex2bin($cpj["digest_so_far_hex"]));
    $prefix = array_slice($chunks, 0, $i + 1); // chunks through this checkpoint, WITHOUT the end
    check("checkpoint $i confirms its prefix", err_kind(fn() => Streaming::verifyCheckpoint($cp, $prefix)), "no-error");
}
check("checkpoint rejects a wrong-length prefix", err_kind(fn() => Streaming::verifyCheckpoint($cp0, $chunks)), "StreamDigestMismatch");

// 5. R-10.3 — an effect over the granted ceiling (or an unknown effect, fail-closed to destructive) is
//    refused BEFORE any chunk; the corpus stream (idempotent_write) under an idempotent_write grant is
//    authorized.
$destructive = new StreamOpen($streamId, Policy::DESTRUCTIVE, null, 1);
check("destructive stream refused under read-only (EffectNotAuthorized)", err_kind(fn() => Streaming::openStream($destructive, Policy::READ_ONLY)), "EffectNotAuthorized");
check("corpus stream authorized under idempotent_write", err_kind(fn() => Streaming::openStream($open, Policy::IDEMPOTENT_WRITE)), "no-error");
$unknownEff = new StreamOpen($streamId, 99, null, 1);
check("unknown effect refused below destructive (EffectNotAuthorized)", err_kind(fn() => Streaming::openStream($unknownEff, Policy::NON_IDEMPOTENT_WRITE)), "EffectNotAuthorized");

// 6. the commitment is over ABSOLUTE-OFFSET order: input order is irrelevant, but swapping which bytes
//    sit at which offset changes the digest.
$reversed = array_reverse(chunks_of($C));
check("digest is offset-ordered (reversed input, same digest)", bin2hex(Streaming::commitDigest($reversed)), $C["final_digest_hex"]);
$swapped = chunks_of($C);
$tmp = $swapped[0]->data;
$swapped[0]->data = $swapped[1]->data;
$swapped[1]->data = $tmp;
check("swapping bytes across offsets changes the digest", bin2hex(Streaming::commitDigest($swapped)) === $C["final_digest_hex"] ? "same" : "different", "different");

// 7. ED25519-DEMONSTRATED (isolation): the ONE end-commitment signature covers the whole stream; a
//    tampered signature and a foreign key both fail. (The reference signs with ML-DSA; PURE-ONLY PHP.)
$seed = str_repeat("\x3c", 32);
$pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
$foreignPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x3d", 32)));
$sig = Streaming::signCommit($commit, $seed);
check("commit signature verifies", Streaming::verifyCommitSig($commit, $pk, $sig) ? "true" : "false", "true");
$bad = $sig;
$bad[0] = $bad[0] ^ "\x01";
check("tampered commit signature rejected", Streaming::verifyCommitSig($commit, $pk, $bad) ? "true" : "false", "false");
check("foreign key rejected", Streaming::verifyCommitSig($commit, $foreignPk, $sig) ? "true" : "false", "false");
// the StreamOpen and StreamCheckpoint are also signed objects (§10.2); their signatures round-trip too.
$sigOpen = Streaming::signOpen($open, $seed);
check("open signature verifies", Streaming::verifyOpenSig($open, $pk, $sigOpen) ? "true" : "false", "true");
check("open signature rejects a foreign key", Streaming::verifyOpenSig($open, $foreignPk, $sigOpen) ? "true" : "false", "false");
$sigCp = Streaming::signCheckpoint($cp0, $seed);
check("checkpoint signature verifies", Streaming::verifyCheckpointSig($cp0, $pk, $sigCp) ? "true" : "false", "true");
$badCp = $sigCp;
$badCp[0] = $badCp[0] ^ "\x01";
check("checkpoint tampered signature rejected", Streaming::verifyCheckpointSig($cp0, $pk, $badCp) ? "true" : "false", "false");

// 8. Stream state Guard (design.md §10 state table; § Timers) — mirrors
//    impl/go/streaming/state_guard_test.go's 7 mutation-surviving tests. Independent of the corpus
//    above: each guard test builds its own StreamOpen/StreamCommit values and never touches the
//    corpus stream id.

// (a) TestGuardRejectsForbiddenTransitions: forbidden (state, event) pairs are rejected
//     StreamStateError, and a rejected event never changes state.
$sidForbidden = "stream-forbidden";
$gChunkBeforeOpen = new Guard();
check("chunk before open rejected (StreamStateError)", err_kind(fn() => $gChunkBeforeOpen->chunk($sidForbidden)), "StreamStateError");
check("chunk before open leaves state idle", State::name($gChunkBeforeOpen->state($sidForbidden)), "idle");

$gCheckpointBeforeOpen = new Guard();
check("checkpoint before open rejected (StreamStateError)", err_kind(fn() => $gCheckpointBeforeOpen->checkpoint($sidForbidden)), "StreamStateError");
check("checkpoint before open leaves state idle", State::name($gCheckpointBeforeOpen->state($sidForbidden)), "idle");

$gCommitBeforeOpen = new Guard();
check("commit before open rejected (StreamStateError)", err_kind(fn() => $gCommitBeforeOpen->commit(new StreamCommit($sidForbidden, ""), [])), "StreamStateError");
check("commit before open leaves state idle", State::name($gCommitBeforeOpen->state($sidForbidden)), "idle");

$sidDoubleOpen = "stream-double-open";
$gDoubleOpen = new Guard();
$openDouble = new StreamOpen($sidDoubleOpen, Policy::IDEMPOTENT_WRITE, null, 0);
check("double_open: first open succeeds", err_kind(fn() => $gDoubleOpen->open($openDouble, Policy::IDEMPOTENT_WRITE)), "no-error");
check("double_open: re-open rejected (StreamStateError)", err_kind(fn() => $gDoubleOpen->open($openDouble, Policy::IDEMPOTENT_WRITE)), "StreamStateError");
check("double_open: a rejected re-open leaves state open", State::name($gDoubleOpen->state($sidDoubleOpen)), "open");

$sidAfterCommit = "stream-after-commit";
$gAfterCommit = new Guard();
$openAfterCommit = new StreamOpen($sidAfterCommit, Policy::IDEMPOTENT_WRITE, null, 0);
check("events_after_commit: open succeeds", err_kind(fn() => $gAfterCommit->open($openAfterCommit, Policy::IDEMPOTENT_WRITE)), "no-error");
$chunksAfterCommit = [new Chunk(0, "payload")];
$commitAfterCommit = new StreamCommit($sidAfterCommit, Streaming::commitDigest($chunksAfterCommit));
check("events_after_commit: commit succeeds", err_kind(fn() => $gAfterCommit->commit($commitAfterCommit, $chunksAfterCommit)), "no-error");
check("events_after_commit: stream is committed", State::name($gAfterCommit->state($sidAfterCommit)), "committed");
check("events_after_commit: chunk after commit rejected (StreamStateError)", err_kind(fn() => $gAfterCommit->chunk($sidAfterCommit)), "StreamStateError");
check("events_after_commit: checkpoint after commit rejected (StreamStateError)", err_kind(fn() => $gAfterCommit->checkpoint($sidAfterCommit)), "StreamStateError");
check("events_after_commit: commit after commit rejected (StreamStateError)", err_kind(fn() => $gAfterCommit->commit($commitAfterCommit, $chunksAfterCommit)), "StreamStateError");
check("events_after_commit: open after commit rejected (StreamStateError)", err_kind(fn() => $gAfterCommit->open($openAfterCommit, Policy::IDEMPOTENT_WRITE)), "StreamStateError");
check("events_after_commit: rejected post-commit events leave state committed", State::name($gAfterCommit->state($sidAfterCommit)), "committed");

// (b) TestGuardValidSequenceSucceeds: the false-positive check — an ordered open -> chunk ->
//     checkpoint -> commit sequence must succeed and drive the state idle -> open -> committed.
$sidValid = "stream-valid";
$gValid = new Guard();
check("valid sequence: unopened stream is idle", State::name($gValid->state($sidValid)), "idle");
$openValid = new StreamOpen($sidValid, Policy::IDEMPOTENT_WRITE, null, 0);
check("valid sequence: open succeeds", err_kind(fn() => $gValid->open($openValid, Policy::IDEMPOTENT_WRITE)), "no-error");
check("valid sequence: after open, state is open", State::name($gValid->state($sidValid)), "open");
$chunksValid = [new Chunk(0, "hello "), new Chunk(6, "world")];
foreach ($chunksValid as $i => $ch) {
    check("valid sequence: chunk $i succeeds", err_kind(fn() => $gValid->chunk($sidValid)), "no-error");
}
check("valid sequence: checkpoint succeeds", err_kind(fn() => $gValid->checkpoint($sidValid)), "no-error");
check("valid sequence: chunks/checkpoint keep the stream open", State::name($gValid->state($sidValid)), "open");
$commitValid = new StreamCommit($sidValid, Streaming::commitDigest($chunksValid));
check("valid sequence: commit succeeds", err_kind(fn() => $gValid->commit($commitValid, $chunksValid)), "no-error");
check("valid sequence: after commit, state is committed", State::name($gValid->state($sidValid)), "committed");

// (c) TestGuardDigestMismatchIsNotStateError: distinguishes the guard's ordering check from the
//     digest check — a digest mismatch surfaces StreamDigestMismatch, NOT StreamStateError, and
//     leaves the stream open (the row rejects without advancing) so a corrected commit still lands.
$sidBadDigest = "stream-bad-digest";
$gBadDigest = new Guard();
$openBadDigest = new StreamOpen($sidBadDigest, Policy::IDEMPOTENT_WRITE, null, 0);
check("digest mismatch: open succeeds", err_kind(fn() => $gBadDigest->open($openBadDigest, Policy::IDEMPOTENT_WRITE)), "no-error");
$chunksBadDigest = [new Chunk(0, "payload")];
$badCommit = new StreamCommit($sidBadDigest, "not-the-real-digest-not-the-real-digest");
check("digest mismatch: commit rejected (StreamDigestMismatch, not StreamStateError)", err_kind(fn() => $gBadDigest->commit($badCommit, $chunksBadDigest)), "StreamDigestMismatch");
check("digest mismatch: a digest-mismatched commit leaves the stream open", State::name($gBadDigest->state($sidBadDigest)), "open");
$goodCommit = new StreamCommit($sidBadDigest, Streaming::commitDigest($chunksBadDigest));
check("digest mismatch: the corrected commit still succeeds", err_kind(fn() => $gBadDigest->commit($goodCommit, $chunksBadDigest)), "no-error");
check("digest mismatch: after the corrected commit, state is committed", State::name($gBadDigest->state($sidBadDigest)), "committed");

// (d) TestGuardEffectNotAuthorizedLeavesIdle: an unauthorized open surfaces EffectNotAuthorized,
//     NOT StreamStateError, and leaves the stream idle so a properly authorized open on the same
//     stream id still succeeds (R-10.3).
$sidUnauthorized = "stream-unauthorized";
$gUnauthorized = new Guard();
$destructiveOpen = new StreamOpen($sidUnauthorized, Policy::DESTRUCTIVE, null, 0);
check("effect not authorized: rejected (EffectNotAuthorized)", err_kind(fn() => $gUnauthorized->open($destructiveOpen, Policy::READ_ONLY)), "EffectNotAuthorized");
check("effect not authorized: an unauthorized open leaves the stream idle", State::name($gUnauthorized->state($sidUnauthorized)), "idle");
$authorizedOpen = new StreamOpen($sidUnauthorized, Policy::IDEMPOTENT_WRITE, null, 0);
check("effect not authorized: the authorized open still succeeds", err_kind(fn() => $gUnauthorized->open($authorizedOpen, Policy::IDEMPOTENT_WRITE)), "no-error");
check("effect not authorized: after the authorized open, state is open", State::name($gUnauthorized->state($sidUnauthorized)), "open");

// (e) TestGuardIndependentStreamsDoNotInterfere: the guard is keyed by stream id, so one stream's
//     state never leaks into another's.
$gIndependent = new Guard();
$sidA = "stream-a";
$sidB = "stream-b";
$openA = new StreamOpen($sidA, Policy::IDEMPOTENT_WRITE, null, 0);
check("independent streams: open a succeeds", err_kind(fn() => $gIndependent->open($openA, Policy::IDEMPOTENT_WRITE)), "no-error");
check("independent streams: b was never opened, still rejected (StreamStateError)", err_kind(fn() => $gIndependent->chunk($sidB)), "StreamStateError");
check("independent streams: chunk on the open stream a succeeds", err_kind(fn() => $gIndependent->chunk($sidA)), "no-error");

// (f) TestGuardExpireAbandonsOpenStream: expire on an open stream transitions it open -> abandoned,
//     a terminal state that then rejects every event with StreamStateError — including a
//     StreamOpen reusing the id, so an abandoned stream is never re-admitted.
$sidAbandoned = "stream-abandoned";
$gAbandoned = new Guard();
$openAbandoned = new StreamOpen($sidAbandoned, Policy::IDEMPOTENT_WRITE, null, 0);
check("expire abandons: open succeeds", err_kind(fn() => $gAbandoned->open($openAbandoned, Policy::IDEMPOTENT_WRITE)), "no-error");
check("expire abandons: expiring an open stream succeeds", err_kind(fn() => $gAbandoned->expire($sidAbandoned)), "no-error");
check("expire abandons: after expiry, state is abandoned", State::name($gAbandoned->state($sidAbandoned)), "abandoned");
$chunksAbandoned = [new Chunk(0, "payload")];
$commitAbandoned = new StreamCommit($sidAbandoned, Streaming::commitDigest($chunksAbandoned));
check("expire abandons: chunk on abandoned rejected (StreamStateError)", err_kind(fn() => $gAbandoned->chunk($sidAbandoned)), "StreamStateError");
check("expire abandons: checkpoint on abandoned rejected (StreamStateError)", err_kind(fn() => $gAbandoned->checkpoint($sidAbandoned)), "StreamStateError");
check("expire abandons: commit on abandoned rejected (StreamStateError)", err_kind(fn() => $gAbandoned->commit($commitAbandoned, $chunksAbandoned)), "StreamStateError");
check("expire abandons: reopen (StreamOpen) on abandoned rejected (StreamStateError)", err_kind(fn() => $gAbandoned->open($openAbandoned, Policy::IDEMPOTENT_WRITE)), "StreamStateError");
check("expire abandons: rejected post-abandon events leave state abandoned", State::name($gAbandoned->state($sidAbandoned)), "abandoned");

// (g) TestGuardExpireOnNonOpenIsStateError: the idle/commit timer clears when a StreamCommit
//     transitions the stream to committed, so a correct caller fires expire() only while the
//     stream is open. Expire on idle, committed, or already-abandoned is rejected StreamStateError
//     and leaves the state unchanged (fail-closed).
$sidExpireIdle = "stream-expire-idle";
$gExpireIdle = new Guard();
check("expire on idle: rejected (StreamStateError)", err_kind(fn() => $gExpireIdle->expire($sidExpireIdle)), "StreamStateError");
check("expire on idle: state unchanged", State::name($gExpireIdle->state($sidExpireIdle)), "idle");

$sidExpireCommitted = "stream-expire-committed";
$gExpireCommitted = new Guard();
$openExpireCommitted = new StreamOpen($sidExpireCommitted, Policy::IDEMPOTENT_WRITE, null, 0);
check("expire on committed: open succeeds", err_kind(fn() => $gExpireCommitted->open($openExpireCommitted, Policy::IDEMPOTENT_WRITE)), "no-error");
$chunksExpireCommitted = [new Chunk(0, "payload")];
$commitExpireCommitted = new StreamCommit($sidExpireCommitted, Streaming::commitDigest($chunksExpireCommitted));
check("expire on committed: commit succeeds", err_kind(fn() => $gExpireCommitted->commit($commitExpireCommitted, $chunksExpireCommitted)), "no-error");
check("expire on committed: rejected (StreamStateError)", err_kind(fn() => $gExpireCommitted->expire($sidExpireCommitted)), "StreamStateError");
check("expire on committed: a spurious expire must not turn a committed stream into abandoned", State::name($gExpireCommitted->state($sidExpireCommitted)), "committed");

$sidExpireTwice = "stream-expire-twice";
$gExpireTwice = new Guard();
$openExpireTwice = new StreamOpen($sidExpireTwice, Policy::IDEMPOTENT_WRITE, null, 0);
check("expire twice: open succeeds", err_kind(fn() => $gExpireTwice->open($openExpireTwice, Policy::IDEMPOTENT_WRITE)), "no-error");
check("expire twice: first expire succeeds", err_kind(fn() => $gExpireTwice->expire($sidExpireTwice)), "no-error");
check("expire twice: second expire rejected (StreamStateError)", err_kind(fn() => $gExpireTwice->expire($sidExpireTwice)), "StreamStateError");
check("expire twice: a second expire must not change state", State::name($gExpireTwice->state($sidExpireTwice)), "abandoned");

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
