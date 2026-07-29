// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP causal graph (C7, §8.2-§8.3) and federation reconcile (T13, §8.6) for the TypeScript SDK.
//
// verifyCausal enforces no-future-cause (a present cause may not sit at a later position than its
// effect) and acyclicity. reconcile is the deterministic merge: a topological linearization of the
// union causal DAG, ties broken by content id (bytewise), scope-independent (R-8.6).

import * as cbor from './cbor.mjs';
import { U, B, T, A, M } from './cbor.mjs';

export class CausalViolation extends Error { constructor(m) { super(m); this.kind = 'CausalViolation'; } }

function hexOf(bytes) { return Buffer.from(bytes).toString('hex'); }

function cmpBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

// nodes: array of [id: Uint8Array, causes: Uint8Array[], position: number]
export function verifyCausal(nodes) {
  const idx = new Map();
  nodes.forEach(([nid], i) => idx.set(hexOf(nid), i));
  // no future cause
  for (const [, causes, pos] of nodes) {
    for (const c of causes) {
      const j = idx.get(hexOf(c));
      if (j !== undefined && nodes[j][2] > pos) throw new CausalViolation('cause at a later position than its effect');
    }
  }
  // acyclic (3-colour DFS over effect -> cause edges)
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Array(nodes.length).fill(WHITE);

  function hasCycle(i) {
    color[i] = GRAY;
    for (const c of nodes[i][1]) {
      const j = idx.get(hexOf(c));
      if (j === undefined) continue;
      if (color[j] === GRAY) return true;
      if (color[j] === WHITE && hasCycle(j)) return true;
    }
    color[i] = BLACK;
    return false;
  }

  for (let i = 0; i < nodes.length; i++) {
    if (color[i] === WHITE && hasCycle(i)) throw new CausalViolation('causal graph contains a cycle');
  }
}

export function reconcile(nodes) {
  // Deterministic topological merge over the union causal DAG; ties break by content id.
  verifyCausal(nodes);
  const ids = nodes.map(([nid]) => nid);
  const present = new Set(ids.map(hexOf));
  const causes = nodes.map(([, cs]) => cs.filter((c) => present.has(hexOf(c))));
  const indeg = causes.map((cs) => cs.length);
  const done = new Array(nodes.length).fill(false);
  const order = [];
  while (order.length < nodes.length) {
    let pick = -1;
    for (let i = 0; i < nodes.length; i++) {
      if (done[i] || indeg[i] !== 0) continue;
      if (pick === -1 || cmpBytes(ids[i], ids[pick]) < 0) pick = i;
    }
    if (pick === -1) throw new CausalViolation('no ready node (unreachable after verifyCausal)');
    done[pick] = true;
    order.push(ids[pick]);
    for (let j = 0; j < nodes.length; j++) {
      if (!done[j] && causes[j].some((c) => cmpBytes(c, ids[pick]) === 0)) indeg[j] -= 1;
    }
  }
  return order;
}

export function reconcileRecord(authorities, order) {
  // The tier-1 Reconcile body {1: [authorities], 2: [order content-ids]}.
  const auth = new A(authorities.map((a) => new T(a)));
  const ordr = new A(order.map((o) => new B(o)));
  return cbor.encode(new M([[new U(1), auth], [new U(2), ordr]]));
}
