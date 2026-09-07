// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C5 effect vocabulary and authorization for the TypeScript SDK (§6).
//
// The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an unrecognized
// value fails closed to destructive (R-6.2); authorization is the §6.1 lattice (action <= ceiling).
// The optional signed safety label is a CBOR map {1:risk, 2:scope}.
//
// Authorization principal resolution (R-6.5) and the Grant.authorizeObject capability check (R-6.3)
// are ported from impl/go/policy/policy.go: only a signature-derived identity is ever an
// authorization principal, and an endpoint grant's maxEffect is the ceiling an object's declared
// effect must not exceed. Every check is fail-closed and performs no side effect.

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

// ---- authorization principal + Grant.authorizeObject (design §6.3, §6.5; R-6.3, R-6.5) ----------

// A named, fail-closed policy/authorization error; .kind is the stable error kind, mirroring the
// Go/Rust/Python/Ruby/PHP kinds (UnauthenticatedPrincipal, EffectNotAuthorized, MalformedSafetyLabel).
export class PolicyError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// PrincipalSource is where a claimed identity came from. Only a signature-derived identity is an
// authorization principal (R-6.5).
export const SOURCE_SIGNATURE = 0;          // the verified COSE signature's signer id
export const SOURCE_TRANSPORT_METADATA = 1; // e.g. a TLS peer name / connection tag
export const SOURCE_FOREIGN_HEADER = 2;     // e.g. an X-Agent-ID or a carried foreign header
export const SOURCE_CLIENT_NAME = 3;        // e.g. a self-asserted clientInfo.name

// resolveAuthPrincipal returns the authorization principal id iff it is signature-derived and
// non-empty (R-6.5). A transport-metadata, foreign-header, or client-supplied name is refused with
// UnauthenticatedPrincipal -- it is never treated as an authorization identity.
export function resolveAuthPrincipal(src, id) {
  if (Number(src) !== SOURCE_SIGNATURE || id === '') {
    throw new PolicyError('UnauthenticatedPrincipal',
      'an authorization identity must be signature-derived, not transport/foreign/client-asserted');
  }
  return id;
}

// Grant is a capability an endpoint issues to an authenticated signer id: the most dangerous effect
// that principal is permitted to carry. The default maxEffect (READ_ONLY) is the least-privilege
// default, so a Grant constructed with no ceiling authorizes only read_only.
export class Grant {
  constructor(principal, maxEffect = READ_ONLY) {
    this.principal = String(principal);
    this.maxEffect = Number(maxEffect);
  }

  // authorizeObject is the endpoint policy check that makes the effect an authorization input, not a
  // hint (R-6.3). It (1) resolves the presenter's identity, refusing any non-signature source
  // (R-6.5, propagating UnauthenticatedPrincipal); (2) requires that identity to match the grant's
  // principal -- no matching grant means no authority; (3) normalizes the object's effect fail-closed
  // (R-6.2) and denies it if it exceeds the grant's ceiling. No side effect; throws a named error on
  // any failure (fail-closed).
  authorizeObject(src, presented, objectEffect) {
    const who = resolveAuthPrincipal(src, presented);
    if (who !== this.principal) {
      throw new PolicyError('EffectNotAuthorized', 'object effect exceeds the granted capability');
    }
    if (!authorizes(this.maxEffect, normalizeEffect(objectEffect))) {
      throw new PolicyError('EffectNotAuthorized', 'object effect exceeds the granted capability');
    }
  }
}

// SafetyLabelExtKey is the non-critical ext key under which the optional safety label is carried
// (ext[1], design.md §6.4).
export const SAFETY_LABEL_EXT_KEY = 1;

// SafetyLabel is the OPTIONAL signed safety annotation (R-6.4). It is attributable to the object's
// signer and auditable -- an ACCOUNTABLE CLAIM, not a guarantee the content is safe.
export class SafetyLabel {
  constructor(risk, scope) {
    this.risk = String(risk);
    this.scope = String(scope);
  }
}

// safetyLabelFromExt extracts the optional safety label from an object's ext map (a cbor.M). Returns
// {label, present}: {label: SafetyLabel, present:true} when a well-formed label is present at key 1,
// {label:null, present:false} when key 1 is absent (no error). Throws PolicyError('MalformedSafetyLabel')
// when the ext[1] entry is present but is not exactly {1:tstr, 2:tstr} -- every key must be a uint and
// every value a text string, and both risk (1) and scope (2) must be present. A malformed label is
// REJECTED, never silently accepted.
export function safetyLabelFromExt(ext) {
  const pairs = (ext instanceof M) ? ext.pairs : Array.from(ext);
  for (const [k, v] of pairs) {
    if (!(k instanceof U) || Number(k.v) !== SAFETY_LABEL_EXT_KEY) continue;
    if (!(v instanceof M)) {
      throw new PolicyError('MalformedSafetyLabel', 'safety label is not {1:tstr risk, 2:tstr scope}');
    }
    let risk = null;
    let scope = null;
    for (const [kk, vv] of v.pairs) {
      if (!(kk instanceof U)) {
        throw new PolicyError('MalformedSafetyLabel', 'safety label is not {1:tstr risk, 2:tstr scope}');
      }
      if (!(vv instanceof T)) {
        throw new PolicyError('MalformedSafetyLabel', 'safety label is not {1:tstr risk, 2:tstr scope}');
      }
      const kn = Number(kk.v);
      if (kn === 1) risk = vv.v;
      else if (kn === 2) scope = vv.v;
      else throw new PolicyError('MalformedSafetyLabel', 'safety label is not {1:tstr risk, 2:tstr scope}');
    }
    if (risk === null || scope === null) {
      throw new PolicyError('MalformedSafetyLabel', 'safety label is not {1:tstr risk, 2:tstr scope}');
    }
    return { label: new SafetyLabel(risk, scope), present: true };
  }
  return { label: null, present: false };
}
