// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C7 audit for the TypeScript SDK -- the signed hash-chained receipt (the baseline single-authority
// ordering tier), the equivocation auditor and its non-repudiable fork proof, and the
// offline-checkable causal graph (design.md §8; R-8.1..8.6, R-12.2, R-12.3).
//
// An ordering authority records each accepted object by appending a signed Receipt
// {1: prev, 2: obj, 3: seq, 4: at}; the chain is tamper-evident because reordering, omission, or
// substitution breaks a `prev` link or a `seq`. The authority never mutates the origin object to
// order it -- ordering is an outer signed layer. The causal graph is the authority-independent
// foundation: an edge "A causes B" is proven by B's signature over A's content id and is checkable
// offline; a total order is a policy layered over this partial order. An auditor detects
// equivocation -- two receipts by one authority at one seq naming different objects -- from the
// signed receipts alone, and mints a non-repudiable ForkProof carrying BOTH of the accused's
// signatures and an external monotonic counter (draft-01 finding #70).
//
// Ported from impl/go/audit (with impl/python/naalp/audit.py as a second reference). Receipt /
// fork-proof signatures are a RAW deterministic ML-DSA signature over the record body
// (cose.mldsaSign / cose.mldsaVerify), exactly as the reference's cose.Signer/Verifier sign the
// receipt body directly. The causal partial order is checked by the shared naalp/graph (the same
// foundation the reference reuses). Graded against the shared vectors/audit/cases.json.

import { sha384 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, B, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import { verifyCausal as graphVerifyCausal, CausalViolation } from './graph.mjs';

// The width of a chain head / prev link (SHA-384 = 48 bytes); genesis is zero.
export const HEAD_SIZE = 48;

// A named, fail-closed audit error; .kind is the stable error kind (design §8.6).
export class AuditError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// One signed append to an ordering authority's chain (design §8.1).
export class Receipt {
  constructor(prev, obj, seq, at) {
    this.prev = Uint8Array.from(prev); // hash of the previous receipt body (HEAD_SIZE bytes; genesis is zero)
    this.obj = Uint8Array.from(obj);   // content id of the accepted object (never the object itself -- §8.2)
    this.seq = seq;                    // monotonic sequence position within this authority's chain
    this.at = at;                      // the authority's time anchor, epoch ms (independent of the signer's clock)
  }

  // Deterministic-CBOR encoding of the receipt body {1: prev, 2: obj, 3: seq, 4: at}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.prev)],
      [new U(2), new B(this.obj)],
      [new U(3), new U(this.seq)],
      [new U(4), new U(this.at)],
    ]));
  }

  // The chain head after this receipt: SHA-384 of the receipt body. Because the body carries prev,
  // editing any receipt breaks the next receipt's linkage.
  head() {
    return sha384(this.bytes());
  }
}

// A baseline single ordering authority (§8.4). It appends monotonic signed receipts over object
// content ids; it holds no object bodies and mutates none. Signs with a real deterministic ML-DSA
// key derived from `seed` (a RAW signature over each receipt body).
export class Authority {
  constructor(alg, seed) {
    this._alg = alg;
    this._seed = Uint8Array.from(seed);
    this._head = new Uint8Array(HEAD_SIZE);
    this._seq = 0;
  }

  // Record acceptance of the object named by content id obj at time at, returning [receipt,
  // signature]. Seq increases by one per append (monotonic).
  append(obj, at) {
    const r = new Receipt(this._head, obj, this._seq, at);
    const sig = cose.mldsaSign(this._alg, this._seed, r.bytes());
    this._head = r.head();
    this._seq += 1;
    return [r, sig];
  }
}

// Check a receipt chain offline against the authority's key: each receipt's seq is the next expected
// value, its prev links to the previous receipt's head (genesis is zero), and its raw signature
// verifies. A broken link or a seq gap is ChainBroken; a bad signature is ReceiptUnsigned. Detects
// any reorder, omission, or substitution (§8.1). Returns null on success (fail-closed).
export function verifyChain(receipts, sigs, alg, pubkey) {
  if (receipts.length !== sigs.length) {
    throw new AuditError('ChainBroken', 'receipt/signature count mismatch');
  }
  let head = new Uint8Array(HEAD_SIZE);
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    if (Number(r.seq) !== i || !bytesEqual(r.prev, head)) {
      throw new AuditError('ChainBroken', 'receipt prev/seq does not chain to the previous receipt');
    }
    if (!cose.mldsaVerify(alg, pubkey, r.bytes(), sigs[i])) {
      throw new AuditError('ReceiptUnsigned', 'receipt signature does not verify');
    }
    head = r.head();
  }
  return null;
}

// An object cannot be created after the authority ordered it, so created MUST NOT exceed at (R-8.4).
// The receipt's `at` is signed and chained, so it is evidence a verifier checks independently of the
// signer's clock.
export function consistentWithAnchor(created, at) {
  return Number(created) <= Number(at);
}

// Non-repudiable evidence of equivocation (draft-01 §8.5, R-8.3): two validly-signed receipts by ONE
// authority at the SAME seq naming DIFFERENT objects, with the accused's OWN two signatures and an
// external monotonic counter -- self-contained, so any third party verifies both signatures against
// the accused key with no further evidence and no repudiation.
export class ForkProof {
  constructor(signer, extCounter, a, sigA, b, sigB) {
    this.signer = Uint8Array.from(signer); // accused authority signer id; both sigs verify under its key
    this.extCounter = extCounter;          // external monotonic counter bound into the proof
    this.a = a;                            // first receipt (a.bytes() is the signed input for sigA)
    this.sigA = Uint8Array.from(sigA);     // the accused authority's signature over a.bytes()
    this.b = b;                            // second receipt at the same seq naming a different object
    this.sigB = Uint8Array.from(sigB);     // the accused authority's signature over b.bytes()
  }

  // Deterministic-CBOR fork-proof body {1: signer, 2: ext_counter, 3: body_a, 4: sig_a, 5: body_b,
  // 6: sig_b}. The two receipt bodies are embedded as the exact bytes each signature covers.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.signer)],
      [new U(2), new U(this.extCounter)],
      [new U(3), new B(this.a.bytes())],
      [new U(4), new B(this.sigA)],
      [new U(5), new B(this.b.bytes())],
      [new U(6), new B(this.sigB)],
    ]));
  }

  // The deterministic-CBOR framing witness: the fork-proof body with the two signature byte-strings
  // elided to empty. It is the structural authority the independent oracle reproduces byte-for-byte;
  // the two ML-DSA signatures are graded by cross-implementation byte-parity elsewhere. This is not a
  // wire object; it exists only to grade the framing.
  preimage() {
    return cbor.encode(new M([
      [new U(1), new B(this.signer)],
      [new U(2), new U(this.extCounter)],
      [new U(3), new B(this.a.bytes())],
      [new U(4), new B(new Uint8Array(0))],
      [new U(5), new B(this.b.bytes())],
      [new U(6), new B(new Uint8Array(0))],
    ]));
  }

  // Accept iff ALL hold: (1) the signer id is present; (2) the two receipts share one seq; (3) they
  // name DIFFERENT objects; and (4) BOTH signatures verify under the accused key. Any failure rejects
  // the whole proof (fail-closed): a same-object / seq-mismatch / unnamed-signer proof is
  // ForkProofInvalid, and a signature that does not verify is ReceiptUnsigned. Returns null on a
  // valid, non-repudiable proof of Equivocation.
  verify(alg, pubkey) {
    if (this.signer.length === 0) {
      throw new AuditError('ForkProofInvalid', 'an unnamed accused is not evidence');
    }
    if (Number(this.a.seq) !== Number(this.b.seq)) {
      throw new AuditError('ForkProofInvalid', 'receipts at different sequence positions');
    }
    if (bytesEqual(this.a.obj, this.b.obj)) {
      throw new AuditError('ForkProofInvalid', 'same object named twice -- no equivocation');
    }
    if (!cose.mldsaVerify(alg, pubkey, this.a.bytes(), this.sigA) ||
        !cose.mldsaVerify(alg, pubkey, this.b.bytes(), this.sigB)) {
      throw new AuditError('ReceiptUnsigned', 'a signature does not verify under the accused key');
    }
    return null;
  }
}

// Assemble a fork proof from two conflicting signed receipts, the accused signer id, and an external
// monotonic counter. Performs no checks -- verify is the fail-closed gate; this is the pure
// constructor (A9). Copies the byte slices so the proof owns its evidence.
export function newForkProof(signer, a, sigA, b, sigB, extCounter) {
  return new ForkProof(signer, extCounter, a, sigA, b, sigB);
}

// Observes an authority's receipts and detects equivocation from the signed receipts alone (§8.5).
// On a conflict it mints a non-repudiable ForkProof carrying the accused signer id, both conflicting
// signatures, and an external monotonic counter.
export class Auditor {
  constructor(alg, pubkey, signer, extBase = 0) {
    this._alg = alg;
    this._pk = Uint8Array.from(pubkey);
    this._signer = Uint8Array.from(signer);
    this._ext = extBase;
    this._seen = new Map(); // seq -> {r: Receipt, sig: Uint8Array}
  }

  // Record a signed receipt. Throws AuditError(ReceiptUnsigned) on a bad signature. Returns a
  // ForkProof (Equivocation) if a previously-seen receipt at the same seq named a different object --
  // the proof carries the accused signer id, both signatures, and the auditor's current external
  // counter, which then advances. Returns null otherwise (including a benign exact duplicate).
  observe(r, sig) {
    if (!cose.mldsaVerify(this._alg, this._pk, r.bytes(), sig)) {
      throw new AuditError('ReceiptUnsigned', 'receipt signature does not verify');
    }
    const key = Number(r.seq);
    const prev = this._seen.get(key);
    if (prev !== undefined) {
      if (!bytesEqual(prev.r.obj, r.obj)) {
        const fp = newForkProof(this._signer, prev.r, prev.sig, r, sig, this._ext);
        this._ext += 1;
        return fp;
      }
      return null;
    }
    this._seen.set(key, { r, sig: Uint8Array.from(sig) });
    return null;
  }
}

// An object's place in the causal graph: its content id, the content ids of its causes (envelope
// field 8), and its ordering position (authority seq, or `created` absent a receipt).
export class CausalNode {
  constructor(id, causes, position) {
    this.id = Uint8Array.from(id);
    this.causes = causes.map((c) => Uint8Array.from(c));
    this.position = position;
  }
}

// Check the signed partial order (§8.2, §8.3): no object names a present cause whose position exceeds
// its own (a future cause it could not have seen), and the graph is acyclic. Either fault is
// CausalViolation. Edges to causes not present in the set are ignored (external references). Runs with
// no ordering authority present (R-8.5). Delegates to the shared naalp/graph, which implements exactly
// this partial order. Returns null on success.
export function verifyCausal(nodes) {
  graphVerifyCausal(nodes.map((n) => [n.id, n.causes, n.position]));
  return null;
}

function hexOf(b) { return Buffer.from(b).toString('hex'); }

// Return the causal nodes' content ids in a deterministic topological order (a cause before its
// effects). Ties among ready nodes break by (position, input index), so the order is reproducible.
// Throws CausalViolation if the graph does not verify. NOTE: the audit tie-break is by POSITION --
// distinct from the federation reconcile, whose tie-break is the content id (naalp/graph reconcile).
export function topoOrder(nodes) {
  verifyCausal(nodes);
  const idx = new Map();
  nodes.forEach((n, i) => idx.set(hexOf(n.id), i));
  const indeg = new Array(nodes.length).fill(0);
  const effects = nodes.map(() => []); // cause index -> effect indices
  nodes.forEach((n, i) => {
    for (const c of n.causes) {
      const j = idx.get(hexOf(c));
      if (j !== undefined) {
        effects[j].push(i);
        indeg[i] += 1;
      }
    }
  });
  const done = new Array(nodes.length).fill(false);
  const order = [];
  while (order.length < nodes.length) {
    let pick = -1;
    for (let i = 0; i < nodes.length; i++) {
      if (done[i] || indeg[i] !== 0) continue;
      if (pick === -1 || Number(nodes[i].position) < Number(nodes[pick].position)) {
        pick = i; // lowest position wins; equal positions keep the lower index (first seen)
      }
    }
    if (pick === -1) throw new CausalViolation('no ready node (unreachable after verifyCausal)');
    done[pick] = true;
    order.push(nodes[pick].id);
    for (const e of effects[pick]) indeg[e] -= 1;
  }
  return order;
}
