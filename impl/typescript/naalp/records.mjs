// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP body builders for the TypeScript SDK — the deterministic-CBOR bodies of the spine records:
// approval + consume ledger (C6, §7), audit receipt (C7, §8), delivery update (C8, §9), stream
// open/commit/checkpoint + rolling commitment (C9, §10), foreign carriage (C12, §13), and the
// transport confidentiality boundary (C11, §12). Each body is exactly what the Go, Rust and Python
// reference implementations encode, so the bytes are byte-identical.

import { sha384 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, B, T, M } from './cbor.mjs';

// --- C6 approval + consume ledger (§7) ---

export function approvalBody(approves, approver, grant, nonce, notAfter) {
  return cbor.encode(new M([
    [new U(1), new B(approves)], [new U(2), new T(approver)], [new U(3), new U(grant)],
    [new U(4), new B(nonce)], [new U(5), new U(notAfter)],
  ]));
}

export function approvalId(approves, approver, grant, nonce, notAfter) {
  return cbor.contentId(approvalBody(approves, approver, grant, nonce, notAfter));
}

export function ledgerEntry(seq, prev, approvalIdBytes, by) {
  return cbor.encode(new M([
    [new U(1), new U(seq)], [new U(2), new B(prev)], [new U(3), new B(approvalIdBytes)], [new U(4), new T(by)],
  ]));
}

// --- C7 audit receipt (§8) ---

export function receiptBody(prev, obj, seq, at) {
  return cbor.encode(new M([
    [new U(1), new B(prev)], [new U(2), new B(obj)], [new U(3), new U(seq)], [new U(4), new U(at)],
  ]));
}

export function receiptHead(body) {
  return sha384(Uint8Array.from(body));
}

// --- C8 delivery (§9) ---

export function deliveryUpdate(obj, stage, at) {
  return cbor.encode(new M([[new U(1), new B(obj)], [new U(2), new U(stage)], [new U(3), new U(at)]]));
}

// --- C9 streaming (§10) ---

export function streamDigest(chunks) {
  // Rolling SHA-384 over the chunk data in absolute-offset order (R-10.2).
  const ordered = chunks.slice().sort((a, b) => {
    const ao = BigInt(a[0]), bo = BigInt(b[0]);
    return ao < bo ? -1 : (ao > bo ? 1 : 0);
  });
  const h = sha384.create();
  for (const [, data] of ordered) h.update(Uint8Array.from(data));
  return h.digest();
}

export function streamOpenBody(streamId, effect, approval, substream) {
  const pairs = [[new U(1), new B(streamId)], [new U(2), new U(effect)], [new U(4), new U(substream)]];
  if (approval && approval.length) pairs.push([new U(3), new B(approval)]); // field 3 present only when an approval binding exists
  return cbor.encode(new M(pairs));
}

export function streamCommitBody(streamId, digest) {
  return cbor.encode(new M([[new U(1), new B(streamId)], [new U(2), new B(digest)]]));
}

export function streamCheckpointBody(streamId, throughOffset, digestSoFar) {
  return cbor.encode(new M([
    [new U(1), new B(streamId)], [new U(2), new U(throughOffset)], [new U(3), new B(digestSoFar)],
  ]));
}

// --- C12 foreign carriage (§13) ---

export const CLASS_JSONRPC = 0, CLASS_HTTP = 1, CLASS_MSG = 2, CLASS_STREAM = 3, CLASS_DOC = 4, CLASS_OPAQUE = 5;

export class MappingError extends Error { constructor(m) { super(m); this.kind = 'MappingError'; } }

export function carriageBody(protocolId, cls, contentType, correlation, method, foreign) {
  if (Number(cls) > CLASS_OPAQUE) throw new MappingError('carriage class ' + cls + ' is not defined');
  return cbor.encode(new M([
    [new U(1), new U(protocolId)], [new U(2), new U(cls)], [new U(3), new U(contentType)],
    [new U(4), new B(correlation)], [new U(5), new T(method)], [new U(6), new B(foreign)],
  ]));
}

// --- C11 transport confidentiality boundary (§12) ---

const TRANSPORTS = new Map([
  ['npamp', [true, true]],
  ['quic', [true, true]],
  ['websocket+wss', [true, false]],
  ['websocket+ws', [false, false]],
  ['https', [true, false]],
  ['http', [false, false]],
]);

export class UnknownTransport extends Error { constructor(m) { super(m); this.kind = 'UnknownTransport'; } }

export function transportEmit(name, sensitive, requirePeerAuth) {
  // Apply the §12.3 confidentiality boundary + §12.4 peer-auth rule; returns the result label.
  const t = TRANSPORTS.get(name);
  if (t === undefined) throw new UnknownTransport('unknown transport ' + name);
  const [confidential, peerAuthenticated] = t;
  if (sensitive && !confidential) return 'ConfidentialTransportRequired';
  if (requirePeerAuth && !peerAuthenticated) return 'PeerUnauthenticated';
  return 'ok';
}
