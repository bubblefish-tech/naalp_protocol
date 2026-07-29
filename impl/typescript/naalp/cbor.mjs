// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Deterministic CBOR (RFC 8949 §4.2.1) for N-AALP — the C1 codec.
//
// An independent TypeScript/ESM implementation of the same deterministic profile the Go, Rust
// and Python reference implementations produce: shortest-form integer heads, no indefinite
// lengths, canonical (bytewise-ascending, by encoded key) map ordering, no duplicate keys. The
// content id is multihash(0x20, 0x30, SHA-384(body)) over the deterministic body bytes (§2.3).

import { sha384 } from '@noble/hashes/sha2.js';

export class NonCanonical extends Error {
  constructor(msg) { super(msg); this.kind = 'NonCanonical'; }
}

// --- value model (mirrors the Go/Rust/Python cbor.Value variants) ---

export class U { constructor(v) { this.v = BigInt(v); } }       // unsigned integer (major 0)
export class N { constructor(v) { this.v = BigInt(v); } }       // negative integer (major 1); v is the negative value itself
export class B { constructor(v) { this.v = Uint8Array.from(v); } } // byte string (major 2)
export class T { constructor(v) { this.v = String(v); } }        // text string (major 3)
export class A { constructor(items) { this.items = Array.from(items); } } // array (major 4)
export class M { constructor(pairs) { this.pairs = Array.from(pairs); } } // map (major 5); pairs = [[keyVal, val], ...]
export class Tag { constructor(n, content) { this.n = BigInt(n); this.content = content; } } // tag (major 6)

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

function concat(chunks) {
  let len = 0;
  for (const c of chunks) len += c.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

function beBytes(n, width) {
  const out = new Uint8Array(width);
  let v = n;
  for (let i = width - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

function head(major, n) {
  const mj = major << 5;
  n = BigInt(n);
  if (n < 24n) return Uint8Array.of(mj | Number(n));
  if (n < 256n) return Uint8Array.of(mj | 24, Number(n));
  if (n < 65536n) return concat([Uint8Array.of(mj | 25), beBytes(n, 2)]);
  if (n < 4294967296n) return concat([Uint8Array.of(mj | 26), beBytes(n, 4)]);
  return concat([Uint8Array.of(mj | 27), beBytes(n, 8)]);
}

function cmpBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

export function encode(v) {
  if (v instanceof U) {
    if (v.v < 0n) throw new NonCanonical('uint is negative');
    return head(0, v.v);
  }
  if (v instanceof N) return head(1, -1n - v.v);
  if (v instanceof B) return concat([head(2, v.v.length), v.v]);
  if (v instanceof T) {
    const b = enc.encode(v.v);
    return concat([head(3, b.length), b]);
  }
  if (v instanceof A) return concat([head(4, v.items.length), ...v.items.map(encode)]);
  if (v instanceof M) {
    const encPairs = v.pairs.map(([k, val]) => [encode(k), encode(val)]);
    encPairs.sort((x, y) => cmpBytes(x[0], y[0]));
    for (let i = 1; i < encPairs.length; i++) {
      if (cmpBytes(encPairs[i - 1][0], encPairs[i][0]) === 0) throw new NonCanonical('duplicate map key');
    }
    const body = [];
    for (const [k, val] of encPairs) { body.push(k, val); }
    return concat([head(5, encPairs.length), ...body]);
  }
  if (v instanceof Tag) return concat([head(6, v.n), encode(v.content)]);
  throw new TypeError('not a cbor value');
}

function dec1(data) {
  if (data.length < 1) throw new NonCanonical('truncated');
  const ib = data[0];
  const major = ib >> 5;
  const ai = ib & 0x1f;
  let arg, rest;
  if (ai === 31) throw new NonCanonical('indefinite length');
  if (ai < 24) { arg = BigInt(ai); rest = data.subarray(1); }
  else if (ai === 24) {
    if (data.length < 2) throw new NonCanonical('truncated head');
    arg = BigInt(data[1]); rest = data.subarray(2);
    if (arg < 24n) throw new NonCanonical('non-shortest integer');
  } else if (ai === 25) {
    if (data.length < 3) throw new NonCanonical('truncated head');
    arg = (BigInt(data[1]) << 8n) | BigInt(data[2]); rest = data.subarray(3);
    if (arg < 256n) throw new NonCanonical('non-shortest integer');
  } else if (ai === 26) {
    if (data.length < 5) throw new NonCanonical('truncated head');
    arg = 0n; for (let i = 1; i <= 4; i++) arg = (arg << 8n) | BigInt(data[i]); rest = data.subarray(5);
    if (arg < 65536n) throw new NonCanonical('non-shortest integer');
  } else if (ai === 27) {
    if (data.length < 9) throw new NonCanonical('truncated head');
    arg = 0n; for (let i = 1; i <= 8; i++) arg = (arg << 8n) | BigInt(data[i]); rest = data.subarray(9);
    if (arg < 4294967296n) throw new NonCanonical('non-shortest integer');
  } else {
    throw new NonCanonical('reserved additional-info');
  }

  const argN = Number(arg);
  if (major === 0) return [new U(arg), rest];
  if (major === 1) return [new N(-1n - arg), rest];
  if (major === 2) {
    if (rest.length < argN) throw new NonCanonical('truncated byte string');
    return [new B(rest.subarray(0, argN)), rest.subarray(argN)];
  }
  if (major === 3) {
    if (rest.length < argN) throw new NonCanonical('truncated text string');
    let s;
    try { s = dec.decode(rest.subarray(0, argN)); }
    catch (e) { throw new NonCanonical('invalid utf-8 text string'); }
    return [new T(s), rest.subarray(argN)];
  }
  if (major === 4) {
    const items = []; let cur = rest;
    for (let i = 0; i < argN; i++) { const [it, nx] = dec1(cur); items.push(it); cur = nx; }
    return [new A(items), cur];
  }
  if (major === 5) {
    const pairs = []; let cur = rest; let prev = null;
    for (let i = 0; i < argN; i++) {
      const before = cur;
      const [k, afterK] = dec1(cur);
      const kbytes = before.subarray(0, before.length - afterK.length);
      const [val, afterV] = dec1(afterK);
      cur = afterV;
      if (prev !== null && cmpBytes(kbytes, prev) <= 0) throw new NonCanonical('map keys out of order or duplicate');
      prev = kbytes;
      pairs.push([k, val]);
    }
    return [new M(pairs), cur];
  }
  if (major === 6) {
    const [content, rest2] = dec1(rest);
    return [new Tag(arg, content), rest2];
  }
  throw new NonCanonical('unsupported major type ' + major);
}

export function decode(data) {
  const buf = Uint8Array.from(data);
  const [v, rest] = dec1(buf);
  if (rest.length) throw new NonCanonical('trailing bytes after top-level item');
  return v;
}

export function contentId(body) {
  let bytes;
  if (body instanceof Uint8Array) bytes = body;
  else bytes = encode(body);
  return concat([Uint8Array.of(0x20, 0x30), sha384(bytes)]);
}
