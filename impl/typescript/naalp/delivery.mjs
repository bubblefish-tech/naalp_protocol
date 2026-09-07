// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C8 delivery for the TypeScript SDK -- delivery as four signed monotonic stages, the
// persist-before-acknowledge discipline, the live full-duplex switchboard, and the content-free
// relay (design.md §9; R-9.1..9.4).
//
// Delivery is four distinct, separately-observable stages, each a signed delivery.update naming the
// target object's content id and the stage reached -- there is no single "sent" boolean (§9.1):
// persisted_origin -> accepted_relay -> persisted_target -> presented. A stage is advanced only after
// the object is durably persisted (WAL fsync), so a crash right after an acknowledgment loses nothing
// (§9.2). Observing a stage earlier than the one already reached is StageOutOfOrder (§9.4). The
// switchboard holds two connections open and passes objects through both directions concurrently
// (§9.3); a relay that holds objects only in transit writes an audit trail over content ids while
// retaining no payload (§9.4, R-9.4).
//
// Ported from impl/go/delivery (with impl/python/naalp/delivery.py as a second reference). The
// delivery.update SIGNATURE is a RAW deterministic ML-DSA signature over the update body
// (cose.mldsaSign / cose.mldsaVerify). The content-id framing and the relay's retained trail reuse
// the shared naalp/cbor and naalp/audit. Graded against the shared vectors/delivery/cases.json.

import { openSync, existsSync, readSync, writeSync, fsyncSync, closeSync } from 'node:fs';
import * as cbor from './cbor.mjs';
import { U, B, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import * as audit from './audit.mjs';

// Delivery stages (design §9.1), monotonic in this order.
export const STAGE_PERSISTED_ORIGIN = 0;
export const STAGE_ACCEPTED_RELAY = 1;
export const STAGE_PERSISTED_TARGET = 2;
export const STAGE_PRESENTED = 3;

const STAGE_NAMES = ['persisted_origin', 'accepted_relay', 'persisted_target', 'presented'];

// The name of a stage value (0..3), or 'unknown'.
export function stageName(stage) {
  const s = Number(stage);
  return (s >= 0 && s < STAGE_NAMES.length) ? STAGE_NAMES[s] : 'unknown';
}

// A named, fail-closed delivery error; .kind is the stable error kind.
export class DeliveryError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// T1 content-id framing multihash(0x20, SHA-384(b)) = 0x20 0x30 || SHA-384(b) (50 octets), identical
// to the spine framing (naalp/cbor contentId over raw bytes).
export function contentId(b) {
  return cbor.contentId(Uint8Array.from(b));
}

function hexOf(b) { return Buffer.from(b).toString('hex'); }

// One signed delivery-stage notification (design §9.1).
export class DeliveryUpdate {
  constructor(obj, stage, at) {
    this.obj = Uint8Array.from(obj); // content id of the object whose delivery this reports
    this.stage = stage;              // the stage reached (0..3)
    this.at = at;                    // observer time, epoch ms
  }

  // Deterministic-CBOR encoding {1: obj, 2: stage, 3: at}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.obj)],
      [new U(2), new U(this.stage)],
      [new U(3), new U(this.at)],
    ]));
  }
}

// Sign a delivery.update with the observer's key: a RAW deterministic signature over the update body.
export function signUpdate(update, alg, seed) {
  return cose.mldsaSign(alg, seed, update.bytes());
}

// Verify a raw delivery.update signature under the observer's public key.
export function verifyUpdate(update, alg, pubkey, sig) {
  return cose.mldsaVerify(alg, pubkey, update.bytes(), sig);
}

// Reconstruct a DeliveryUpdate from a WAL record body; fail-closed on a malformed shape.
function parseUpdate(rec) {
  let v;
  try {
    v = cbor.decode(rec);
  } catch (e) {
    if (e instanceof cbor.NonCanonical) {
      throw new DeliveryError('Malformed', 'delivery update is not canonical: ' + e.message);
    }
    throw e;
  }
  if (!(v instanceof M)) throw new DeliveryError('Malformed', 'delivery update is not a map');
  let obj = null;
  let stage = null;
  let at = null;
  for (const [k, val] of v.pairs) {
    if (!(k instanceof U)) throw new DeliveryError('Malformed', 'non-uint key');
    if (k.v === 1n && val instanceof B) obj = val.v;
    else if (k.v === 2n && val instanceof U) stage = val.v;
    else if (k.v === 3n && val instanceof U) at = val.v;
    else throw new DeliveryError('Malformed', 'unknown or mistyped delivery-update field ' + k.v);
  }
  if (obj === null || stage === null || at === null) {
    throw new DeliveryError('Malformed', 'delivery update missing a mandatory field');
  }
  return new DeliveryUpdate(obj, stage, at);
}

// A durable, per-object delivery-stage tracker enforcing monotonic stages and
// persist-before-acknowledge. Each advance persists to the write-ahead log and fsyncs before
// returning the acknowledging update, so a crash after the ack loses nothing (§9.2). WAL records are
// length-prefixed (4-byte big-endian) deterministic-CBOR update bodies.
export class Tracker {
  constructor(fd) {
    this._fd = fd;
    this._current = new Map(); // object-id (hex) -> highest stage reached (Number)
    this._pos = 0;
    this._replay();
  }

  _replay() {
    let pos = 0;
    for (;;) {
      const lenBuf = Buffer.alloc(4);
      const n = readSync(this._fd, lenBuf, 0, 4, pos);
      if (n === 0) break;
      if (n !== 4) throw new DeliveryError('Malformed', 'truncated WAL length prefix');
      pos += 4;
      const reclen = lenBuf.readUInt32BE(0);
      const rec = Buffer.alloc(reclen);
      const m = readSync(this._fd, rec, 0, reclen, pos);
      if (m !== reclen) throw new DeliveryError('Malformed', 'truncated WAL record');
      pos += reclen;
      const u = parseUpdate(Uint8Array.from(rec));
      this._current.set(hexOf(u.obj), Number(u.stage)); // last durable stage wins (monotonic on write)
    }
    this._pos = pos;
  }

  // Record that obj reached stage at time at, returning the acknowledging update. A stage earlier than
  // the one already reached is StageOutOfOrder (no state change); re-reporting the current stage is an
  // idempotent no-op; a later stage is persisted (WAL fsync) before the update is returned. Skipping
  // ahead is permitted; only regression is an error.
  advance(obj, stage, at) {
    const key = hexOf(obj);
    const cur = this._current.get(key);
    if (cur !== undefined) {
      if (Number(stage) < cur) {
        throw new DeliveryError('StageOutOfOrder', 'a delivery stage regressed to an earlier stage');
      }
      if (Number(stage) === cur) {
        return new DeliveryUpdate(obj, stage, at);
      }
    }
    const u = new DeliveryUpdate(obj, stage, at);
    const rec = Buffer.from(u.bytes());
    const lenPrefix = Buffer.alloc(4);
    lenPrefix.writeUInt32BE(rec.length, 0);
    const frame = Buffer.concat([lenPrefix, rec]);
    writeSync(this._fd, frame, 0, frame.length, this._pos);
    this._pos += frame.length;
    fsyncSync(this._fd); // persist-before-ack (R-9.2)
    this._current.set(key, Number(stage));
    return u;
  }

  // The highest stage reached for obj and whether it has been seen: [stage, seen].
  stage(obj) {
    const s = this._current.get(hexOf(obj));
    return s !== undefined ? [s, true] : [0, false];
  }

  // Flush and close the WAL file.
  close() {
    closeSync(this._fd);
  }
}

// Open (creating if needed) a WAL-backed tracker and replay it to recover the last durable stage for
// every object.
export function openTracker(path) {
  const fd = existsSync(path) ? openSync(path, 'r+') : openSync(path, 'w+');
  return new Tracker(fd);
}

// An asynchronous single-consumer FIFO: put() enqueues, get() returns a promise that resolves with
// the next item (immediately if one is buffered, otherwise when the next put arrives). It is the
// concurrency primitive the switchboard pumps forward objects through.
class AsyncQueue {
  constructor() {
    this._items = [];
    this._waiters = [];
  }

  put(x) {
    const w = this._waiters.shift();
    if (w) w(x);
    else this._items.push(x);
  }

  get() {
    if (this._items.length) return Promise.resolve(this._items.shift());
    return new Promise((res) => this._waiters.push(res));
  }
}

// One side of a switchboard connection: objects written to send are relayed to the peer's recv,
// concurrently with the reverse direction.
export class Endpoint {
  constructor(sendQ, recvQ) {
    this._send = sendQ;
    this._recv = recvQ;
  }

  // Submit an object into the switchboard toward the peer.
  send(obj) {
    this._send.put(Uint8Array.from(obj));
  }

  // Receive the next object relayed from the peer (resolves when one arrives).
  recv() {
    return this._recv.get();
  }
}

const SENTINEL = Symbol('switchboard-close');

// Holds two connections open and relays objects through in both directions concurrently (design §9.3)
// -- a live full-duplex relay, not a one-object mailbox. Two async pumps forward left->right and
// right->left simultaneously; a pump retains nothing (content-free in transit).
export class Switchboard {
  constructor(capacity) {
    // capacity is accepted for parity with the reference (the async queues are unbounded); it bounds
    // the reference's channel buffering, which the event-loop model does not need to preallocate.
    this._capacity = capacity;
    this._lSend = new AsyncQueue();
    this._lRecv = new AsyncQueue();
    this._rSend = new AsyncQueue();
    this._rRecv = new AsyncQueue();
    this._left = new Endpoint(this._lSend, this._lRecv);
    this._right = new Endpoint(this._rSend, this._rRecv);
    // left.send -> right.recv, and right.send -> left.recv, concurrently.
    this._p1 = this._pump(this._lSend, this._rRecv);
    this._p2 = this._pump(this._rSend, this._lRecv);
  }

  async _pump(inQ, outQ) {
    for (;;) {
      const obj = await inQ.get();
      if (obj === SENTINEL) return;
      outQ.put(obj); // forwarded in transit; the pump retains nothing
    }
  }

  left() { return this._left; }

  right() { return this._right; }

  // Stop both pumps and wait for them to exit.
  async close() {
    this._lSend.put(SENTINEL);
    this._rSend.put(SENTINEL);
    await Promise.all([this._p1, this._p2]);
  }
}

// Routes objects while retaining no payload at rest: for each routed object it appends a C7 audit
// receipt over the object's content id and returns the object for immediate forwarding, keeping only
// the receipt chain (content ids), never the payload (§9.4, R-9.4). The retained audit trail alone
// verifies as a valid chain.
export class ContentFreeRelay {
  constructor(alg, seed) {
    this._auth = new audit.Authority(alg, seed);
    this._receipts = [];
    this._sigs = [];
  }

  // Record an audit receipt over obj's content id and return obj for forwarding. The relay keeps the
  // receipt only; it does not store obj.
  route(obj, at) {
    const [rec, sig] = this._auth.append(contentId(obj), at);
    this._receipts.push(rec);
    this._sigs.push(sig);
    return Uint8Array.from(obj);
  }

  // The receipts and signatures the relay retained (its only persistent state), for offline chain
  // verification.
  auditTrail() {
    return [this._receipts.slice(), this._sigs.slice()];
  }
}
