// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C4 identity for the TypeScript SDK: the self-certifying signer id (§5.1) and the NFC rule.
//
// signer id = multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))),
// identical in form to the N-PAMP PeerHandle. Multicodec codes are from the multiformats registry:
// ed25519-pub 0xed, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212; multihash sha2-256 0x12.

import { sha256 } from '@noble/hashes/sha2.js';
import { ALG_ED25519, ALG_MLDSA65, ALG_MLDSA87 } from './cose.mjs';

const MULTICODEC = new Map([
  [ALG_ED25519, 0xed],
  [ALG_MLDSA65, 0x1211],
  [ALG_MLDSA87, 0x1212],
]);
const MH_SHA256 = 0x12;

// RFC 4648 base32 lowercase alphabet (no padding).
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

export class UnknownAlg extends Error { constructor(m) { super(m); this.kind = 'UnknownAlg'; } }
export class SignerMismatch extends Error { constructor(m) { super(m); this.kind = 'SignerMismatch'; } }
export class NonNFC extends Error { constructor(m) { super(m); this.kind = 'NonNFC'; } }

function uvarint(n) {
  const out = [];
  for (;;) {
    let b = n & 0x7f;
    n >>>= 7;
    if (n) { out.push(b | 0x80); } else { out.push(b); return Uint8Array.from(out); }
  }
}

function base32NoPad(data) {
  let bits = 0, value = 0, out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}

export function signerId(alg, pubkey) {
  const mc = MULTICODEC.get(alg);
  if (mc === undefined) throw new UnknownAlg('no multicodec for alg ' + alg);
  const tagged = concat(uvarint(mc), Uint8Array.from(pubkey));
  const digest = sha256(tagged);
  const mh = concat(concat(uvarint(MH_SHA256), uvarint(digest.length)), digest);
  return 'b' + base32NoPad(mh);
}

export function checkSigner(claimed, alg, pubkey) {
  if (signerId(alg, pubkey) !== claimed) throw new SignerMismatch('signer id does not recompute from the key');
}

export function requireNFC(s) {
  // Reject an identity/scope string that is not Unicode NFC (§3.1, R-3.3).
  if (s.normalize('NFC') !== s) throw new NonNFC('string is not Unicode NFC');
}
