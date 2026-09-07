// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C9 native-streaming conformance for the TypeScript SDK, graded against the shared independent corpus
// vectors/stream/cases.json (NOT produced by this code -- note the oracle directory is `stream`, while
// this module is naalp/streaming.mjs). The corpus grades: the rolling SHA-384 commitment over chunks
// in absolute-offset order (the single per-stream signature covers the whole stream, not N), the
// byte-exact StreamOpen/StreamCommit/StreamCheckpoint bodies, the mid-stream checkpoint prefix
// confirmation, and that altering a delivered byte invalidates the commitment (the tamper vector).
//
// The StreamOpen/Commit/Checkpoint signatures (real deterministic ML-DSA-65, a raw signature over the
// body) are demonstrated in isolation only: the corpus carries no signature vector or key, so they are
// NOT corpus-graded (stated honestly). What the corpus grades is the commitment and the object bytes.
//
// Written test-first; the streaming module is absent until ported, so this fails RED on import
// (ERR_MODULE_NOT_FOUND) until impl/typescript/naalp/streaming.mjs lands, and a mutation forcing the
// rolling digest to a constant flips 'streaming rolling commitment digest matches the oracle
// byte-for-byte'.
//
// Run:  node --test test/streaming.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as policy from '../naalp/policy.mjs';
import * as streaming from '../naalp/streaming.mjs';

function vectors() {
  // NAME MISMATCH: the module is `streaming` but its oracle directory is `stream`.
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'stream', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/stream/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');
const mkChunks = () => C.chunks.map((c) => new streaming.Chunk(c.offset, hexToBytes(c.data_hex)));

test('streaming rolling commitment digest matches the oracle byte-for-byte', () => {
  // THIS is the mutation-target assertion: the single rolling SHA-384 over absolute-offset order IS
  // the C9 commitment; forcing it to a constant flips this assertion against the independent oracle.
  const chunks = mkChunks();
  assert.equal(bytesToHex(streaming.commitDigest(chunks)), C.final_digest_hex);
  // order-independent: a reordered delivery of the same frames yields the same commitment (the chunks
  // are folded in offset order, not arrival order).
  const reordered = [chunks[2], chunks[0], chunks[1]];
  assert.equal(bytesToHex(streaming.commitDigest(reordered)), C.final_digest_hex);
});

test('streaming open/commit/checkpoint bodies match the oracle byte-for-byte', () => {
  const open = new streaming.StreamOpen(hexToBytes(C.stream_id_hex), C.effect, hexToBytes(C.approval_hex), C.substream);
  assert.equal(bytesToHex(open.bytes()), C.open_body_hex);
  const commit = new streaming.StreamCommit(hexToBytes(C.stream_id_hex), hexToBytes(C.final_digest_hex));
  assert.equal(bytesToHex(commit.bytes()), C.commit_body_hex);
  const cp0 = C.checkpoints[0];
  const cp = new streaming.StreamCheckpoint(hexToBytes(C.stream_id_hex), cp0.through_offset, hexToBytes(cp0.digest_so_far_hex));
  assert.equal(bytesToHex(cp.bytes()), C.checkpoint_body_hex);
});

test('streaming StreamOpen omits the approval field when there is no binding', () => {
  // field 3 (approval) is present only when a binding exists; the two encodings differ, and the
  // no-binding body carries keys {1,2,4} only.
  const withA = new streaming.StreamOpen(hexToBytes(C.stream_id_hex), C.effect, hexToBytes(C.approval_hex), C.substream);
  const withoutA = new streaming.StreamOpen(hexToBytes(C.stream_id_hex), C.effect, null, C.substream);
  assert.notEqual(bytesToHex(withA.bytes()), bytesToHex(withoutA.bytes()));
  const keys = cbor.decode(withoutA.bytes()).pairs.map(([k]) => Number(k.v)).sort((a, b) => a - b);
  assert.deepEqual(keys, [1, 2, 4]);
});

test('streaming checkpoints confirm a prefix without the end', () => {
  const chunks = mkChunks();
  const prefixThrough = (through) => chunks.filter((c) => Number(c.offset) < through);
  for (const cpv of C.checkpoints) {
    const prefix = prefixThrough(cpv.through_offset);
    // the rolling digest over the prefix equals the checkpoint's digest_so_far (SHA-384 does not
    // finalize, so streaming continues after a checkpoint).
    assert.equal(bytesToHex(streaming.commitDigest(prefix)), cpv.digest_so_far_hex, `through ${cpv.through_offset}`);
    const cp = new streaming.StreamCheckpoint(hexToBytes(C.stream_id_hex), cpv.through_offset, hexToBytes(cpv.digest_so_far_hex));
    assert.equal(streaming.verifyCheckpoint(cp, prefix), null, `verify through ${cpv.through_offset}`);
  }
});

test('streaming verifyCommit accepts the valid stream and rejects a tampered chunk', () => {
  const chunks = mkChunks();
  const commit = new streaming.StreamCommit(hexToBytes(C.stream_id_hex), hexToBytes(C.final_digest_hex));
  assert.equal(streaming.verifyCommit(commit, chunks), null);
  // flip the corpus-identified chunk to the corpus flipped bytes -> the recomputed digest differs and
  // equals the oracle's tampered digest; verifyCommit rejects it fail-closed.
  const tampered = chunks.map((c) => new streaming.Chunk(c.offset, c.data));
  tampered[C.tamper.chunk_index] = new streaming.Chunk(chunks[C.tamper.chunk_index].offset, hexToBytes(C.tamper.flipped_data_hex));
  assert.equal(bytesToHex(streaming.commitDigest(tampered)), C.tamper.digest_hex);
  assert.throws(() => streaming.verifyCommit(commit, tampered), (e) => e.kind === 'StreamDigestMismatch');
});

test('streaming openStream refuses an effect above the granted ceiling before any chunk', () => {
  const open = new streaming.StreamOpen(hexToBytes(C.stream_id_hex), C.effect, hexToBytes(C.approval_hex), C.substream);
  // the corpus effect is idempotent_write (1): a ceiling >= 1 authorizes, a read_only ceiling refuses.
  assert.equal(streaming.openStream(open, policy.NON_IDEMPOTENT_WRITE), null);
  assert.equal(streaming.openStream(open, policy.IDEMPOTENT_WRITE), null);
  assert.throws(() => streaming.openStream(open, policy.READ_ONLY), (e) => e.kind === 'EffectNotAuthorized');
  // an unrecognized effect fails closed to destructive -> refused under any non-destructive ceiling.
  const wild = new streaming.StreamOpen(hexToBytes(C.stream_id_hex), 99, null, 0);
  assert.throws(() => streaming.openStream(wild, policy.NON_IDEMPOTENT_WRITE), (e) => e.kind === 'EffectNotAuthorized');
});

// ---- stream state guard (design.md §10 state table + § Timers; naalp-error code 49) ------------
//
// Mirrors impl/go/streaming/state_guard_test.go's 7 mutation-surviving guard tests, translated to
// the TypeScript Guard/StreamOpen/StreamCommit/Chunk port in impl/typescript/naalp/streaming.mjs
// (with impl/python/tests/test_streaming_guard.py as a second reference for the flattened-subcase
// idiom this port's test file already uses -- see the sibling `*.test.mjs` files in this
// directory, which favor plain per-case assertions over nested subtests).
//
// Mutation target: flipping the state check in Guard.open (or any of chunk/checkpoint/commit/
// expire) so a forbidden transition is admitted flips 'streaming Guard rejects forbidden
// transitions' (and several siblings) RED; flipping Guard.expire to leave the state OPEN instead
// of ABANDONED flips 'streaming Guard expire abandons an open stream' RED.

const openObj = (sid, effect = policy.IDEMPOTENT_WRITE) => new streaming.StreamOpen(sid, effect, null, 0);
const enc = new TextEncoder();

test('streaming Guard rejects forbidden transitions', () => {
  // idle + chunk / checkpoint / commit -> unlisted pair, default StreamStateError.
  const cases = [
    ['chunk_before_open', (g, sid) => g.chunk(sid)],
    ['checkpoint_before_open', (g, sid) => g.checkpoint(sid)],
    ['commit_before_open', (g, sid) => g.commit(new streaming.StreamCommit(sid, new Uint8Array(0)), [])],
  ];
  for (const [name, run] of cases) {
    const g = new streaming.Guard();
    const sid = enc.encode('stream-forbidden');
    assert.throws(() => run(g, sid), (e) => e.kind === 'StreamStateError', name);
    assert.equal(g.state(sid), streaming.STATE_IDLE, `${name}: a rejected event must not change state`);
  }

  // open + StreamOpen -> reject (StreamStateError) -- explicit table row.
  {
    const sid = enc.encode('stream-double-open');
    const g = new streaming.Guard();
    const o = openObj(sid);
    g.open(o, policy.IDEMPOTENT_WRITE); // first open should succeed
    assert.throws(() => g.open(o, policy.IDEMPOTENT_WRITE), (e) => e.kind === 'StreamStateError');
    assert.equal(g.state(sid), streaming.STATE_OPEN, 'a rejected re-open must not change state');
  }

  // committed + {chunk, StreamCheckpoint, StreamCommit, StreamOpen} -- the first three are explicit
  // table rows ("reject (StreamStateError)"); StreamOpen-after-committed is the unlisted-pair
  // default.
  {
    const sid = enc.encode('stream-after-commit');
    const g = new streaming.Guard();
    const o = openObj(sid);
    g.open(o, policy.IDEMPOTENT_WRITE);
    const chunks = [new streaming.Chunk(0, enc.encode('payload'))];
    const commit = new streaming.StreamCommit(sid, streaming.commitDigest(chunks));
    g.commit(commit, chunks);
    assert.equal(g.state(sid), streaming.STATE_COMMITTED);

    assert.throws(() => g.chunk(sid), (e) => e.kind === 'StreamStateError');
    assert.throws(() => g.checkpoint(sid), (e) => e.kind === 'StreamStateError');
    assert.throws(() => g.commit(commit, chunks), (e) => e.kind === 'StreamStateError');
    assert.throws(() => g.open(o, policy.IDEMPOTENT_WRITE), (e) => e.kind === 'StreamStateError');
    assert.equal(g.state(sid), streaming.STATE_COMMITTED, 'rejected post-commit events must not change state');
  }
});

test('streaming Guard valid sequence succeeds', () => {
  // the false-positive check: an ordered open -> chunk -> checkpoint -> commit sequence must
  // succeed and drive the state idle -> open -> committed -- the guard must not reject events the
  // stream state table actually admits.
  const sid = enc.encode('stream-valid');
  const g = new streaming.Guard();
  assert.equal(g.state(sid), streaming.STATE_IDLE, 'an unopened stream should be idle');

  const o = openObj(sid);
  g.open(o, policy.IDEMPOTENT_WRITE);
  assert.equal(g.state(sid), streaming.STATE_OPEN, 'after open, state should be open');

  const chunks = [new streaming.Chunk(0, enc.encode('hello ')), new streaming.Chunk(6, enc.encode('world'))];
  for (const _c of chunks) g.chunk(sid);
  g.checkpoint(sid);
  assert.equal(g.state(sid), streaming.STATE_OPEN, 'chunks/checkpoint must keep the stream open');

  const commit = new streaming.StreamCommit(sid, streaming.commitDigest(chunks));
  g.commit(commit, chunks);
  assert.equal(g.state(sid), streaming.STATE_COMMITTED, 'after commit, state should be committed');
});

test('streaming Guard digest mismatch is not a state error', () => {
  // distinguishes the guard's ordering check from the existing digest check: "open | StreamCommit
  // (digest mismatch) | reject (StreamDigestMismatch)" must surface StreamDigestMismatch, not
  // StreamStateError, and must leave the stream open (the row rejects without advancing) so a
  // corrected commit still lands.
  const sid = enc.encode('stream-bad-digest');
  const g = new streaming.Guard();
  g.open(openObj(sid), policy.IDEMPOTENT_WRITE);
  const chunks = [new streaming.Chunk(0, enc.encode('payload'))];

  const bad = new streaming.StreamCommit(sid, enc.encode('not-the-real-digest-not-the-real-digest'));
  assert.throws(() => g.commit(bad, chunks), (e) => e.kind === 'StreamDigestMismatch');
  assert.equal(g.state(sid), streaming.STATE_OPEN, 'a digest-mismatched commit must leave the stream open');

  const good = new streaming.StreamCommit(sid, streaming.commitDigest(chunks));
  g.commit(good, chunks); // the corrected commit should still succeed
  assert.equal(g.state(sid), streaming.STATE_COMMITTED, 'after the corrected commit, state should be committed');
});

test('streaming Guard effect-not-authorized leaves the stream idle', () => {
  // "idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)" must surface
  // EffectNotAuthorized, not StreamStateError, and must leave the stream idle so a properly
  // authorized open on the same stream id still succeeds (R-10.3).
  const sid = enc.encode('stream-unauthorized');
  const g = new streaming.Guard();

  const destructive = new streaming.StreamOpen(sid, policy.DESTRUCTIVE, null, 0);
  assert.throws(() => g.open(destructive, policy.READ_ONLY), (e) => e.kind === 'EffectNotAuthorized');
  assert.equal(g.state(sid), streaming.STATE_IDLE, 'an unauthorized open must leave the stream idle');

  const authorized = openObj(sid);
  g.open(authorized, policy.IDEMPOTENT_WRITE); // the authorized open should still succeed
  assert.equal(g.state(sid), streaming.STATE_OPEN, 'after the authorized open, state should be open');
});

test('streaming Guard independent streams do not interfere', () => {
  // the guard is keyed by stream id, so one stream's state never leaks into another's.
  const g = new streaming.Guard();
  const a = enc.encode('stream-a');
  const b = enc.encode('stream-b');

  g.open(openObj(a), policy.IDEMPOTENT_WRITE);
  // b was never opened; any event on b is still rejected StreamStateError even though a is open.
  assert.throws(() => g.chunk(b), (e) => e.kind === 'StreamStateError');
  g.chunk(a); // chunk on the open stream a should succeed
});

test('streaming Guard expire abandons an open stream', () => {
  // drives the idle/commit timer's expiry (§ Timers): expire() on an open stream transitions it
  // "open -> abandoned", a terminal state that then rejects every event with StreamStateError --
  // including a StreamOpen reusing the id, so an abandoned stream is never re-admitted. This is
  // the fail-closed retention that stops a replayed signed StreamOpen from re-opening an abandoned
  // id.
  const sid = enc.encode('stream-abandoned');
  const g = new streaming.Guard();
  const o = openObj(sid);
  g.open(o, policy.IDEMPOTENT_WRITE);

  g.expire(sid); // expiring an open stream should succeed
  assert.equal(g.state(sid), streaming.STATE_ABANDONED, 'after expiry, state should be abandoned');

  // An abandoned stream admits nothing -- chunk, checkpoint, commit, and a StreamOpen reusing the
  // id are all rejected StreamStateError (the id is never re-admitted).
  const chunks = [new streaming.Chunk(0, enc.encode('payload'))];
  const commit = new streaming.StreamCommit(sid, streaming.commitDigest(chunks));
  assert.throws(() => g.chunk(sid), (e) => e.kind === 'StreamStateError');
  assert.throws(() => g.checkpoint(sid), (e) => e.kind === 'StreamStateError');
  assert.throws(() => g.commit(commit, chunks), (e) => e.kind === 'StreamStateError');
  assert.throws(() => g.open(o, policy.IDEMPOTENT_WRITE), (e) => e.kind === 'StreamStateError');
  assert.equal(g.state(sid), streaming.STATE_ABANDONED, 'rejected post-abandon events must not change state');
});

test('streaming Guard expire on a non-open stream is a state error', () => {
  // the idle/commit timer clears when a StreamCommit transitions the stream to committed
  // (§ Timers), so a correct caller fires expire() only while the stream is open. Expire on an
  // idle, committed, or already-abandoned stream is therefore rejected StreamStateError and leaves
  // the state unchanged (fail-closed).

  // idle: nothing has been opened.
  {
    const sid = enc.encode('stream-expire-idle');
    const g = new streaming.Guard();
    assert.throws(() => g.expire(sid), (e) => e.kind === 'StreamStateError');
    assert.equal(g.state(sid), streaming.STATE_IDLE, 'expiring an idle stream must not change state');
  }

  // committed: the timer should have cleared on commit; a spurious expire is a state error and
  // must not turn a committed (non-repudiable) stream into an abandoned one.
  {
    const sid = enc.encode('stream-expire-committed');
    const g = new streaming.Guard();
    g.open(openObj(sid), policy.IDEMPOTENT_WRITE);
    const chunks = [new streaming.Chunk(0, enc.encode('payload'))];
    const commit = new streaming.StreamCommit(sid, streaming.commitDigest(chunks));
    g.commit(commit, chunks);
    assert.throws(() => g.expire(sid), (e) => e.kind === 'StreamStateError');
    assert.equal(g.state(sid), streaming.STATE_COMMITTED, 'expiring a committed stream must not change state');
  }

  // already abandoned: a second expire is a state error and a no-op.
  {
    const sid = enc.encode('stream-expire-twice');
    const g = new streaming.Guard();
    g.open(openObj(sid), policy.IDEMPOTENT_WRITE);
    g.expire(sid); // first expire
    assert.throws(() => g.expire(sid), (e) => e.kind === 'StreamStateError');
    assert.equal(g.state(sid), streaming.STATE_ABANDONED, 'a second expire must not change state');
  }
});

test('streaming sign/verify the commitment in isolation (real ML-DSA-65, not corpus-graded)', () => {
  const seed = new Uint8Array(32);
  const alg = cose.ALG_MLDSA65;
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  const commit = new streaming.StreamCommit(hexToBytes(C.stream_id_hex), hexToBytes(C.final_digest_hex));
  const sig = streaming.signCommit(commit, alg, seed);
  assert.equal(streaming.verifyCommitSig(commit, alg, pk, sig), true);
  const open = new streaming.StreamOpen(hexToBytes(C.stream_id_hex), C.effect, hexToBytes(C.approval_hex), C.substream);
  assert.equal(streaming.verifyOpenSig(open, alg, pk, streaming.signOpen(open, alg, seed)), true);
  const cp0 = C.checkpoints[0];
  const cp = new streaming.StreamCheckpoint(hexToBytes(C.stream_id_hex), cp0.through_offset, hexToBytes(cp0.digest_so_far_hex));
  assert.equal(streaming.verifyCheckpointSig(cp, alg, pk, streaming.signCheckpoint(cp, alg, seed)), true);
  // a tampered signature does not verify.
  const bad = Uint8Array.from(sig); bad[bad.length - 1] ^= 1;
  assert.equal(streaming.verifyCommitSig(commit, alg, pk, bad), false);
});
