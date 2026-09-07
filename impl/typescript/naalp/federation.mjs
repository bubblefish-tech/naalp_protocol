// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP Federation higher tier (tier 1) for the TypeScript SDK -- federated ordering by a
// deterministic reconcile-merge over the shared causal graph (design.md §8.4; design-channels.md §7;
// R-8.6, R-15A.2, R-15A.3).
//
// The baseline tier is a single ordering authority's monotonic receipt chain (C7). The higher tier
// lets multiple independent authorities each order their own scope and reconcile over the shared
// causal graph -- the partial order every authority already signs over (§8.2). Reconcile is a
// DETERMINISTIC linearization of the union causal DAG: a topological sort whose tie-break among
// causally-concurrent objects is the object content id (bytewise ascending). Because it depends only
// on the causal graph (not on how scopes are split), any split of the same objects reconciles to the
// same order -- so moving from single-authority to federated ordering requires no envelope or object
// change (R-8.6).
//
// Ported from impl/go/federation; the causal partial order is checked by the shared naalp/graph.mjs
// (the C7/audit foundation), exactly as the reference reuses the audit layer. Graded against the
// shared vectors/federation/cases.json.

import * as cbor from './cbor.mjs';
import { U, B, T, A, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import { verifyCausal, CausalViolation } from './graph.mjs';

function hexOf(bytes) { return Buffer.from(bytes).toString('hex'); }

function cmpBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

// A named, fail-closed federation error; .kind is the stable error kind (naalp-error registry code
// 61). Emitted by verifyReconcileOrder.
export class FederationError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// A node's place in the shared causal graph: its content id and the content ids of its causes
// (envelope field 8). The federated tier reconciles by these causal edges and the content-id
// tie-break.
export class CausalNode {
  constructor(id, causes) {
    this.id = Uint8Array.from(id);
    this.causes = causes.map((c) => Uint8Array.from(c));
  }
}

// Reconcile deterministically merges the objects of a shared causal graph into one total order
// (design.md §8.4). It first verifies the graph is a valid partial order (acyclic, no future-cause)
// via the shared naalp/graph, then linearizes it with Kahn's algorithm, breaking ties among ready
// nodes by content id (bytewise ascending). The result is causally consistent and deterministic. A
// duplicate object id (scope overlap) is ordered once (resolved).
export function reconcile(nodes) {
  verifyCausal(nodes.map((n) => [n.id, n.causes, 0]));
  const ids = nodes.map((n) => n.id);
  const present = new Set(ids.map(hexOf));
  const causes = nodes.map((n) => n.causes.filter((c) => present.has(hexOf(c))));
  const indeg = causes.map((cs) => cs.length);
  const done = new Array(nodes.length).fill(false);
  const order = [];
  while (order.length < nodes.length) {
    let pick = -1;
    for (let i = 0; i < nodes.length; i++) {
      if (done[i] || indeg[i] !== 0) continue;
      if (pick === -1 || cmpBytes(ids[i], ids[pick]) < 0) pick = i;
    }
    // unreachable after verifyCausal, but fail-closed rather than loop forever
    if (pick === -1) throw new CausalViolation('no ready node');
    done[pick] = true;
    order.push(ids[pick]);
    for (let j = 0; j < nodes.length; j++) {
      if (!done[j] && causes[j].some((c) => cmpBytes(c, ids[pick]) === 0)) indeg[j] -= 1;
    }
  }
  return order;
}

// Reports whether an order places every object's (present) causes before it.
export function causallyValid(order, nodes) {
  const pos = new Map();
  order.forEach((id, k) => pos.set(hexOf(id), k));
  for (const n of nodes) {
    const np = pos.get(hexOf(n.id));
    if (np === undefined) continue;
    for (const c of n.causes) {
      const cp = pos.get(hexOf(c));
      if (cp !== undefined && cp > np) return false;
    }
  }
  return true;
}

// The tier-1 Reconcile object body (design-channels.md §7): the authorities reconciled and the
// resulting deterministic total order (object content ids). Signed with the C2 crypto over its
// deterministic-CBOR bytes; it orders the identical signed objects the baseline already produced
// (no envelope change).
export class ReconcileRecord {
  constructor(authorities, order) {
    this.authorities = authorities;
    this.order = order;
  }

  // Deterministic-CBOR encoding {1: [authorities], 2: [order content-ids]}.
  bytes() {
    const auth = new A(this.authorities.map((a) => new T(a)));
    const ordr = new A(this.order.map((o) => new B(o)));
    return cbor.encode(new M([[new U(1), auth], [new U(2), ordr]]));
  }
}

// Sign a Reconcile record with a tier-1 ordering authority's ML-DSA key: a raw deterministic
// signature over the record's deterministic-CBOR bytes.
export function signReconcile(record, alg, seed) {
  return cose.mldsaSign(alg, seed, record.bytes());
}

// Verify a raw Reconcile-record signature under the authority's public key.
export function verifyReconcile(record, alg, pubkey, sig) {
  return cose.mldsaVerify(alg, pubkey, record.bytes(), sig);
}

// verifyReconcileOrder is the verify-event choke point of the Reconcile state machine (draft "##
// Reconcile state machine"). A verifier independently re-runs the deterministic linearization over
// the identical causal graph and rejects the record whole (ReconcileMismatch) if the recomputed
// total order differs from the one the record claims. It MUST recompute via reconcile() -- the
// content-id tie-break -- and NEVER a position/index tie-break, whose ordering would spuriously
// disagree on causally-concurrent objects. A node set that is not a valid partial order is rejected
// under that fault (CausalViolation, thrown by reconcile -> verifyCausal), fail-closed. Returns null
// only when the record's claimed order is byte-for-byte the deterministic order (verified).
//
// This is distinct from the per-port signature-verify verifyReconcile(record, alg, pubkey, sig),
// which checks the COSE signature over the record bytes; verifyReconcileOrder verifies the ORDER,
// not the signature. Named ...Order uniformly across all ten ports so one parity token cannot
// collide with the signature-verify name.
export function verifyReconcileOrder(record, nodes) {
  const recomputed = reconcile(nodes); // throws CausalViolation fail-closed
  if (recomputed.length !== record.order.length) {
    throw new FederationError('ReconcileMismatch',
      "independent linearization disagrees with the reconcile record's claimed order");
  }
  for (let i = 0; i < recomputed.length; i++) {
    if (cmpBytes(recomputed[i], record.order[i]) !== 0) {
      throw new FederationError('ReconcileMismatch',
        "independent linearization disagrees with the reconcile record's claimed order");
    }
  }
  return null;
}
