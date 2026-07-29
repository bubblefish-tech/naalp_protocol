// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C5 effect vocabulary and authorization for the TypeScript SDK (§6).
//
// The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an unrecognized
// value fails closed to destructive (R-6.2); authorization is the §6.1 lattice (action <= ceiling).
// The optional signed safety label is a CBOR map {1:risk, 2:scope}.

import * as cbor from './cbor.mjs';
import { U, T, M } from './cbor.mjs';

export const READ_ONLY = 0;
export const IDEMPOTENT_WRITE = 1;
export const NON_IDEMPOTENT_WRITE = 2;
export const DESTRUCTIVE = 3;

const NAMES = ['read_only', 'idempotent_write', 'non_idempotent_write', 'destructive'];

export function normalizeEffect(v) {
  // Map a raw effect value to the closed set; anything outside 0..3 is destructive (R-6.2).
  v = Number(v);
  return (v >= 0 && v <= 3) ? v : DESTRUCTIVE;
}

export function safetyLabelName(e) {
  return NAMES[normalizeEffect(e)];
}

export function authorizes(ceiling, action) {
  // The §6.1 lattice: an action of class `action` is permitted under ceiling iff action <= ceiling.
  return Number(action) <= Number(ceiling);
}

export function safetyLabelBytes(risk, scope) {
  // The signed safety-label body {1: risk, 2: scope} (R-6.4).
  return cbor.encode(new M([[new U(1), new T(risk)], [new U(2), new T(scope)]]));
}
