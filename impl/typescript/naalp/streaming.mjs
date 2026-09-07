// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C9 native streaming with a single signed per-stream commitment for the TypeScript SDK
// (design.md §10; R-10.1..10.6).
//
// A native stream is three signed objects plus unsigned chunks: StreamOpen establishes the stream's
// identity, effect, and (where it causes an effect) its approval binding, refusing a stream whose
// effect is not authorized BEFORE any chunk (§10.2, R-10.3); the chunks are raw data frames the
// transport AEAD already authenticates, so N-AALP does NOT sign them individually (R-10.2); StreamCommit
// carries a rolling SHA-384 over the chunks in absolute-offset order, making the whole stream
// non-repudiable with ONE signature, not N (§10.2). Optional signed StreamCheckpoints let a verifier
// confirm a prefix without the end. Altering any delivered byte invalidates the commitment
// (StreamDigestMismatch).
//
// Native streaming is channel 0x000C and is kept distinct from foreign streamed carriage (§13, 0x000D);
// this module never carries a foreign protocol (R-10.6). Ported from impl/go/streaming (with
// impl/python/naalp/streaming as a second reference); graded against vectors/stream/cases.json (the
// oracle directory is `stream`, not `streaming`). The StreamOpen/StreamCommit/StreamCheckpoint
// signatures are real deterministic ML-DSA-65 (a raw signature over the body) but not corpus-graded.

import { sha384 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, B, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import * as policy from './policy.mjs';
import { MAX_STREAM_CHUNKS } from './wire_constants_gen.mjs';

// The N-PAMP Stream channel native streams run on; foreign streamed carriage uses the distinct Bridge
// channel 0x000D (R-10.6).
export const STREAM_CHANNEL = 0x000C;

// A named, fail-closed streaming error; .kind is the stable error kind (§15) -- StreamDigestMismatch
// or EffectNotAuthorized, mirroring the Go/Rust/Python/Ruby kinds.
export class StreamError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// One absolute-offset-positioned data frame of a stream (unsigned; the transport authenticates it).
export class Chunk {
  constructor(offset, data) {
    this.offset = offset;
    this.data = Uint8Array.from(data);
  }
}

// The rolling SHA-384 commitment accumulator (design.md §10.2). update() feeds chunks in absolute-
// offset order; digestSoFar() returns the SHA-384 of everything fed so far WITHOUT ending the stream,
// which is exactly a checkpoint's digest_so_far (the hash is cloned to read, so streaming continues
// after a checkpoint).
export class StreamDigest {
  constructor() {
    this._h = sha384.create();
  }

  // Feed the next chunk's data into the rolling digest.
  update(data) {
    this._h.update(Uint8Array.from(data));
    return this;
  }

  // The SHA-384 of all data fed so far; the underlying state is unchanged (clone-and-finalize), so
  // streaming continues after a checkpoint.
  digestSoFar() {
    return this._h.clone().digest();
  }
}

// Compute the rolling SHA-384 over chunks in absolute-offset order. Input order is irrelevant -- the
// chunks are sorted by offset before folding -- so a delivered stream and a reordered delivery of the
// same frames yield the same commitment, while swapping which bytes sit at which offset does not.
export function commitDigest(chunks) {
  const sorted = Array.from(chunks).sort((a, b) => (Number(a.offset) - Number(b.offset)));
  const sd = new StreamDigest();
  for (const c of sorted) sd.update(c.data);
  return sd.digestSoFar();
}

// Establishes a stream's identity, effect, optional approval binding, and sub-stream id (design.md
// §10.2). It is signed.
export class StreamOpen {
  constructor(streamId, effect, approval, substream) {
    this.streamId = Uint8Array.from(streamId);
    this.effect = effect;
    this.approval = approval === null || approval === undefined ? null : Uint8Array.from(approval);
    this.substream = substream;
  }

  // Deterministic-CBOR encoding {1: stream_id, 2: effect, 3: approval?, 4: substream}; field 3 is
  // present only when an approval binding exists (encode emits canonical key order regardless of
  // insertion order).
  bytes() {
    const pairs = [
      [new U(1), new B(this.streamId)],
      [new U(2), new U(this.effect)],
      [new U(4), new U(this.substream)],
    ];
    if (this.approval !== null) pairs.push([new U(3), new B(this.approval)]);
    return cbor.encode(new M(pairs));
  }
}

// Carries the completed stream's rolling-SHA-384 commitment (design.md §10.2).
export class StreamCommit {
  constructor(streamId, digest) {
    this.streamId = Uint8Array.from(streamId);
    this.digest = Uint8Array.from(digest);
  }

  // Deterministic-CBOR encoding {1: stream_id, 2: digest}.
  bytes() {
    return cbor.encode(new M([[new U(1), new B(this.streamId)], [new U(2), new B(this.digest)]]));
  }
}

// Carries a mid-stream commitment over the prefix through throughOffset (design.md §10.2).
export class StreamCheckpoint {
  constructor(streamId, throughOffset, digestSoFar) {
    this.streamId = Uint8Array.from(streamId);
    this.throughOffset = throughOffset;
    this.digestSoFar = Uint8Array.from(digestSoFar);
  }

  // Deterministic-CBOR encoding {1: stream_id, 2: through_offset, 3: digest_so_far}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.streamId)],
      [new U(2), new U(this.throughOffset)],
      [new U(3), new B(this.digestSoFar)],
    ]));
  }
}

// Authorize a StreamOpen against the granted effect ceiling, refusing a stream whose effect exceeds it
// BEFORE any chunk (R-10.3). An unrecognized effect is treated as destructive (fail-closed, via the C5
// policy). Returns null when the stream may proceed, else throws EffectNotAuthorized.
export function openStream(o, grantedMax) {
  if (!policy.authorizes(grantedMax, policy.normalizeEffect(o.effect))) {
    throw new StreamError('EffectNotAuthorized', 'stream effect exceeds the granted capability ceiling');
  }
  return null;
}

const digestEq = (a, b) => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

// Recompute the rolling digest over the delivered chunks and compare it to the signed commitment; any
// altered or reordered byte yields StreamDigestMismatch (R-10.2). Returns null on a match.
export function verifyCommit(commit, chunks) {
  if (chunks.length > MAX_STREAM_CHUNKS) { // stream chunk-count bound (§3.4, R7)
    throw new StreamError('TooManyChunks', 'stream chunk count exceeds the maximum (§3.4, R7)');
  }
  if (!digestEq(commit.digest, commitDigest(chunks))) {
    throw new StreamError('StreamDigestMismatch', 'stream commitment digest does not match the recomputed digest');
  }
  return null;
}

// Confirm a prefix without the end (design.md §10.2): the prefix chunks must be contiguous from offset
// 0 and total exactly throughOffset bytes, and their rolling digest must equal the checkpoint's
// digest_so_far. Otherwise StreamDigestMismatch. Returns null on a clean confirmation.
export function verifyCheckpoint(cp, prefix) {
  if (prefix.length > MAX_STREAM_CHUNKS) { // stream chunk-count bound (§3.4, R7)
    throw new StreamError('TooManyChunks', 'stream chunk count exceeds the maximum (§3.4, R7)');
  }
  const sorted = Array.from(prefix).sort((a, b) => (Number(a.offset) - Number(b.offset)));
  let total = 0;
  for (const c of sorted) {
    if (Number(c.offset) !== total) throw new StreamError('StreamDigestMismatch', 'non-contiguous prefix');
    total += c.data.length;
  }
  if (total !== Number(cp.throughOffset)) throw new StreamError('StreamDigestMismatch', 'prefix length does not match through_offset');
  if (!digestEq(cp.digestSoFar, commitDigest(prefix))) throw new StreamError('StreamDigestMismatch', 'prefix digest does not match the checkpoint');
  return null;
}

// ---- signatures (real deterministic ML-DSA over the body, demonstrated in isolation) ----------

// A raw deterministic ML-DSA signature over the StreamOpen body (matches impl/go/streaming).
export function signOpen(o, alg, seed) { return cose.mldsaSign(alg, seed, o.bytes()); }

// A raw deterministic ML-DSA signature over the StreamCommit body -- the ONE end-commitment signature
// that covers the whole stream (R-10.2).
export function signCommit(c, alg, seed) { return cose.mldsaSign(alg, seed, c.bytes()); }

// A raw deterministic ML-DSA signature over the StreamCheckpoint body.
export function signCheckpoint(c, alg, seed) { return cose.mldsaSign(alg, seed, c.bytes()); }

// Verify a raw StreamOpen signature under the stream owner's public key.
export function verifyOpenSig(o, alg, pubkey, sig) { return cose.mldsaVerify(alg, pubkey, o.bytes(), sig); }

// Verify a raw StreamCommit signature under the stream owner's public key.
export function verifyCommitSig(c, alg, pubkey, sig) { return cose.mldsaVerify(alg, pubkey, c.bytes(), sig); }

// Verify a raw StreamCheckpoint signature under the stream owner's public key.
export function verifyCheckpointSig(c, alg, pubkey, sig) { return cose.mldsaVerify(alg, pubkey, c.bytes(), sig); }

// ---- stream state guard (design.md §10 state table + § Timers; naalp-error code 49) ------------

// Stream lifecycle state (design.md §10, the stream state table): idle (no stream open for this
// id), open, committed, or abandoned (the terminal state an open stream enters when its
// idle/commit timer expires, § Timers -- like committed, it admits no further event and its
// stream id is never re-admitted). Mirrors impl/go/streaming's State enum, following the same
// closed-int-constant idiom this SDK already uses for policy.mjs's effect vocabulary.
export const STATE_IDLE = 0;
export const STATE_OPEN = 1;
export const STATE_COMMITTED = 2;
export const STATE_ABANDONED = 3;

const STATE_NAMES = ['idle', 'open', 'committed', 'abandoned'];

// stateName names a State (Go State.String): "idle", "open", "committed", "abandoned", or
// "unknown".
export function stateName(s) {
  return (Number.isInteger(s) && s >= 0 && s < STATE_NAMES.length) ? STATE_NAMES[s] : 'unknown';
}

const hexOf = (bytes) => Buffer.from(bytes).toString('hex');

// Guard enforces the stream state machine across concurrently open streams, keyed by stream id
// (design.md §10, the stream state table; mirrors impl/go/streaming's Guard). It tracks only the
// current lifecycle state (idle/open/committed/abandoned), never chunk data, and rejects an event
// the state table does not admit for the stream's current state BEFORE any state change -- a
// rejected event leaves the state exactly as it was (fail-closed, no partial transition). It holds
// no clock: the idle/commit timer (§ Timers) lives in the caller, which calls expire() when a
// stream's interval elapses; the numeric interval is a deployment policy, not a protocol constant.
// No lock is needed: every method below is fully synchronous (no await between the state read and
// the state write), so two events on the same Guard can never interleave under Node's single-
// threaded event loop.
//
// A Guard is per-connection: the caller discards it when the connection closes, so the states map
// is freed with the connection. There is NO eviction of terminal (committed/abandoned) entries --
// evicting one would re-admit a replayed signed StreamOpen reusing that id as a fresh idle -> open,
// the exact replay the terminal states exist to refuse. Retained entries are therefore bounded by
// the number of streams the connection actually opened, each of which cost the peer a full
// StreamOpen signature to create.
export class Guard {
  constructor() {
    this._states = new Map();
  }

  // The current lifecycle state of streamId (for callers and tests); an id never seen is
  // STATE_IDLE (design.md §10: "idle (no stream open for this stream id)").
  state(streamId) {
    const k = hexOf(streamId);
    return this._states.has(k) ? this._states.get(k) : STATE_IDLE;
  }

  // Validate a StreamOpen against the state table: only idle admits StreamOpen, and then only when
  // the effect is authorized (R-10.3) -- "idle | StreamOpen (effect authorized) -> open" and "idle
  // | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)". A stream already open,
  // committed, or abandoned rejects StreamStateError (committed+StreamOpen and abandoned+
  // StreamOpen fall under the table's unlisted-pair default -- an abandoned or committed stream id
  // is never re-admitted). On EffectNotAuthorized the stream stays idle, since the open never took
  // effect; on StreamStateError the existing state is untouched; only a successful open advances
  // to open.
  open(o, grantedMax) {
    if (this.state(o.streamId) !== STATE_IDLE) {
      throw new StreamError('StreamStateError', 'stream event is illegal for the current stream state (§10 state table)');
    }
    openStream(o, grantedMax); // throws EffectNotAuthorized; state stays idle on failure
    this._states.set(hexOf(o.streamId), STATE_OPEN);
    return null;
  }

  // Validate a data chunk's arrival against the state table: only open admits a chunk ("open |
  // chunk -> open"); idle, committed, or abandoned reject it StreamStateError (committed+chunk is
  // listed explicitly; idle+chunk and abandoned+chunk fall under the unlisted-pair default). A
  // chunk never changes the stream's state -- it stays open.
  chunk(streamId) {
    if (this.state(streamId) !== STATE_OPEN) {
      throw new StreamError('StreamStateError', 'stream event is illegal for the current stream state (§10 state table)');
    }
    return null;
  }

  // Validate a StreamCheckpoint's arrival against the state table: only open admits it ("open |
  // StreamCheckpoint -> open"); idle, committed, or abandoned reject it StreamStateError
  // (committed+StreamCheckpoint is listed explicitly; the others fall under the unlisted-pair
  // default). A checkpoint never changes the stream's state -- it stays open.
  checkpoint(streamId) {
    if (this.state(streamId) !== STATE_OPEN) {
      throw new StreamError('StreamStateError', 'stream event is illegal for the current stream state (§10 state table)');
    }
    return null;
  }

  // Validate a StreamCommit against the state table: only open admits it -- idle, committed, or
  // abandoned reject it StreamStateError before the digest is even inspected (committed+
  // StreamCommit is listed explicitly; the others fall under the unlisted-pair default). When
  // open, the commitment is verified against the delivered chunks (R-10.2): a digest mismatch
  // (StreamDigestMismatch) leaves the stream open (this table row rejects without advancing, so a
  // corrected commit may still follow), and a digest match advances the stream to committed.
  commit(c, chunks) {
    if (this.state(c.streamId) !== STATE_OPEN) {
      throw new StreamError('StreamStateError', 'stream event is illegal for the current stream state (§10 state table)');
    }
    verifyCommit(c, chunks); // throws StreamDigestMismatch/TooManyChunks; stays open on failure
    this._states.set(hexOf(c.streamId), STATE_COMMITTED);
    return null;
  }

  // Fire the idle/commit timer's expiry for streamId (§ Timers): an open stream that has not
  // committed within its interval transitions "open -> abandoned", a terminal state that rejects
  // every subsequent event with StreamStateError -- including a StreamOpen reusing the id, so an
  // abandoned stream is never re-admitted and nothing it delivered without a StreamCommit is
  // non-repudiable. Only an open stream can be abandoned: the timer clears when a StreamCommit
  // transitions the stream to committed (§ Timers), so a correct caller fires expire() only while
  // the stream is open; expire() on an idle, committed, or already-abandoned stream is rejected
  // StreamStateError with no state change (fail-closed). The Guard holds no clock -- the caller
  // decides when the interval has elapsed; the interval itself is a deployment policy.
  expire(streamId) {
    if (this.state(streamId) !== STATE_OPEN) {
      throw new StreamError('StreamStateError', 'stream event is illegal for the current stream state (§10 state table)');
    }
    this._states.set(hexOf(streamId), STATE_ABANDONED);
    return null;
  }
}
