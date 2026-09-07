// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C15 multi-hop agent delegation for the TypeScript SDK (design.md §18; R-DEL-1..8), a Phase-3
// draft-01 ADDITIVE tier-1 surface over the frozen spine. It introduces NO new envelope, encoding,
// signature, identity, or audit mechanism (R-11.3): a DelegationGrant is a normal N-AALP envelope
// object (a tier-1 Capability surface, kind 4), and the mechanism REUSES the -00 CapDelegate substrate
// -- parent-by-content-id in `causes` (§8.2) and the CapExceedsParent attenuation (§6.1 lattice). The
// only additions over CapDelegate are the body's `subject`, `max_depth`, and validity window.
//
// Agent-delegation answers WHO may act on whose behalf, across multiple hops, with a chain that
// terminates at a trust anchor. The two graded surfaces: the DelegationGrant wire body (byte-graded ==
// oracle: Grant.bytes/contentId), and the 12-step leaf->root chain verifier (verdict-graded == oracle,
// over REAL ML-DSA-65 signed chains). Every check is fail-closed (§15): an action that fails any step
// is rejected whole, throws its named error, and causes no state change. There is no partial credit
// and no fail-open path. Ported from impl/go/delegation (with impl/python/naalp/delegation.py as a
// second reference); graded against vectors/delegation/cases.json. The D4 composition
// (authorizeDestructive) reuses the new approval module's single-use consume ledger for the per-action
// approval gate -- a real wiring of delegation onto approval, not a stub.

import { U, T, M } from './cbor.mjs';
import * as cbor from './cbor.mjs';
import * as policy from './policy.mjs';
import * as channels from './channels.mjs';
import * as envelope from './envelope.mjs';
import * as identity from './identity.mjs';
import * as approval from './approval.mjs';

// Channel binding, the tier-1 kind code, and the tier for agent-delegation (design.md §18.1).
export const CHANNEL_CAPABILITY = 0x0002; // Capability channel (reuses the CapDelegate substrate)
export const KIND_DELEGATION_GRANT = 4;   // tier-1 kind code, the next free code after Cap{Issue,Delegate,Revoke,Lookup}
export const TIER = 1;                     // a named escalation adding multi-hop capability

// A grant's OWN envelope effect (field 7): issuing a grant is a non_idempotent_write. This is separate
// from the body's effect_cap, which is the ceiling the grant CONFERS on its subject.
export const GRANT_EFFECT = policy.NON_IDEMPOTENT_WRITE;

// A named, fail-closed delegation error; .kind is the stable error kind (§18.6, §15). Kinds reused from
// other layers (CapExceedsParent, EffectNotAuthorized, ApprovalRequired, SignerMismatch, AlreadyConsumed)
// carry those exact kind strings so a verifier's verdict is identical to the Go/Python reference.
export class DelegationError extends Error {
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

function hexOf(b) { return Buffer.from(b).toString('hex'); }

// ---- the DelegationGrant object body (design.md §18.1, §18.5) --------------------------------

// The signed body of a DelegationGrant. `subject` is the delegatee agent id (signer-id form, MUST be
// NFC); `effectCap` is the max effect this grant conveys; `maxDepth` the max FURTHER delegation hops
// below it; `notBefore`/`notAfter` the validity window; `scope` an OPTIONAL NFC resource scope
// ("" = absent/unconstrained, field 6 omitted). The ISSUER is NOT a body field -- it is the verified
// envelope signer (R-DEL-3); the delegation PARENT is named by content id in the envelope `causes`.
export class Grant {
  constructor(subject, effectCap, maxDepth, notBefore, notAfter, scope = '') {
    this.subject = String(subject);
    this.effectCap = Number(effectCap);
    this.maxDepth = maxDepth;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.scope = String(scope);
  }

  toMap() {
    const pairs = [
      [new U(1), new T(this.subject)],
      [new U(2), new U(this.effectCap)],
      [new U(3), new U(this.maxDepth)],
      [new U(4), new U(this.notBefore)],
      [new U(5), new U(this.notAfter)],
    ];
    if (this.scope !== '') { // "" == absent (field 6 omitted); an empty scope is not a distinct value
      pairs.push([new U(6), new T(this.scope)]);
    }
    return new M(pairs);
  }

  // Deterministic-CBOR encoding {1:subject,2:effect_cap,3:max_depth,4:not_before,5:not_after,?6:scope}.
  bytes() {
    return cbor.encode(this.toMap());
  }

  // The grant body's content id: multihash(0x20, SHA-384(body)). This is the body's self-address; the
  // ENVELOPE content id (from envelope.sign) is what a delegation chain wires into `causes`.
  contentId() {
    return cbor.contentId(this.bytes());
  }

  // Build the (unsigned) N-AALP envelope object carrying this grant: tier 1, Capability channel, kind
  // DelegationGrant, the grant's own effect non_idempotent_write, the grant body as the object body,
  // and `causes` naming the delegation parent by content id (empty for a root grant). A non-NFC
  // subject/scope or an out-of-range effect_cap is rejected fail-closed.
  envelopeObject(issuer, created, profile, causes) {
    try {
      identity.requireNFC(this.subject);
    } catch (e) {
      throw new DelegationError('NonNFC', 'subject is not Unicode NFC');
    }
    if (this.scope !== '') {
      try {
        identity.requireNFC(this.scope);
      } catch (e) {
        throw new DelegationError('NonNFC', 'scope is not Unicode NFC');
      }
    }
    if (this.effectCap > policy.DESTRUCTIVE) {
      throw new DelegationError('GrantMalformed', 'effect_cap outside the closed lattice');
    }
    return new envelope.Object({
      kind: KIND_DELEGATION_GRANT, channel: CHANNEL_CAPABILITY, tier: TIER,
      signer: issuer, created, effect: GRANT_EFFECT, causes, profile, body: this.toMap(),
    });
  }
}

// Sign a DelegationGrant envelope object with a real deterministic ML-DSA key; the signer BECOMES the
// grant's issuer (R-DEL-3).
export function signGrant(obj, alg, seed) {
  return envelope.sign(obj, alg, seed);
}

// Parse an envelope object body back into a Grant. A body that is not exactly the {1,2,3,4,5,?6} map
// with the right value types and an in-range effect_cap is an unverifiable/malformed grant link and is
// rejected ChainBroken (fail-closed). An out-of-range effect_cap is NEVER normalized up (that would
// widen a ceiling -- fail-open); it is rejected.
export function grantFromBody(v) {
  if (!(v instanceof M)) throw new DelegationError('ChainBroken', 'grant body is not a map');
  const g = new Grant('', 0, 0, 0, 0, '');
  const seen = new Set();
  for (const [k, val] of v.pairs) {
    if (!(k instanceof U) || k.v < 1n || k.v > 6n) {
      throw new DelegationError('ChainBroken', 'grant body has an out-of-range field');
    }
    const kv = Number(k.v);
    if (kv === 1) {
      if (!(val instanceof T)) throw new DelegationError('ChainBroken', 'subject is not a tstr');
      g.subject = val.v;
    } else if (kv === 2) {
      if (!(val instanceof U) || val.v > BigInt(policy.DESTRUCTIVE)) {
        throw new DelegationError('ChainBroken', 'effect_cap absent or out of range');
      }
      g.effectCap = Number(val.v);
    } else if (kv === 3) {
      if (!(val instanceof U)) throw new DelegationError('ChainBroken', 'max_depth is not a uint');
      g.maxDepth = val.v;
    } else if (kv === 4) {
      if (!(val instanceof U)) throw new DelegationError('ChainBroken', 'not_before is not a uint');
      g.notBefore = val.v;
    } else if (kv === 5) {
      if (!(val instanceof U)) throw new DelegationError('ChainBroken', 'not_after is not a uint');
      g.notAfter = val.v;
    } else if (kv === 6) {
      if (!(val instanceof T)) throw new DelegationError('ChainBroken', 'scope is not a tstr');
      g.scope = val.v;
    }
    seen.add(kv);
  }
  if (!(seen.has(1) && seen.has(2) && seen.has(3) && seen.has(4) && seen.has(5))) { // scope (6) optional
    throw new DelegationError('ChainBroken', 'grant body is missing a mandatory field');
  }
  return g;
}

// ---- kind validation (composes with the frozen baseline) -------------------------------------

// Accepts exactly this surface's tier-1 kind (Capability channel, DelegationGrant).
export function kindValidator(channel, kind) {
  return Number(channel) === CHANNEL_CAPABILITY && Number(kind) === KIND_DELEGATION_GRANT;
}

function baselineKindValidator(channel, kind) {
  try {
    channels.lookup(channel, kind);
    return true;
  } catch (e) {
    return false;
  }
}

// Accepts the frozen baseline kinds OR the tier-1 DelegationGrant -- the validator a delegation-aware
// endpoint passes to envelope.verify. A baseline-only endpoint using the baseline validator alone
// correctly rejects a DelegationGrant as UnknownKind (fail-closed).
export function composedKindValidator(channel, kind) {
  return baselineKindValidator(channel, kind) || kindValidator(channel, kind);
}

// ---- verified grants + the trust/revocation inputs -------------------------------------------

// A DelegationGrant that has passed envelope verification and integrity binding: its ENVELOPE content
// id (what `causes` point to), its verified issuer id (the envelope signer -- NOT a body field,
// R-DEL-3), the parsed grant body, and the grant's own `causes`.
export class Resolved {
  constructor(contentId, issuer, grant, causes) {
    this.contentId = Uint8Array.from(contentId);
    this.issuer = issuer;
    this.grant = grant;
    this.causes = causes.map((c) => Uint8Array.from(c));
  }
}

// Verify a signed DelegationGrant end-to-end with real crypto (envelope.verify against the composed
// validator), confirm it is a tier-1 Capability DelegationGrant whose own effect is non_idempotent_write,
// bind the claimed issuer id to the verifying key (a self-asserted issuer that does not derive from the
// authenticated key confers nothing, R-DEL-3), and parse the grant body. Any failure is an unverifiable
// link (ChainBroken / SignerMismatch / the envelope's named error), fail-closed.
export function verifyGrantObject(profile, alg, pubkey, signedObj) {
  const o = envelope.verify(profile, alg, pubkey, composedKindValidator, signedObj);
  if (Number(o.channel) !== CHANNEL_CAPABILITY || Number(o.kind) !== KIND_DELEGATION_GRANT || Number(o.tier) !== TIER) {
    throw new DelegationError('ChainBroken', 'not a tier-1 Capability DelegationGrant');
  }
  if (Number(o.effect) !== GRANT_EFFECT) {
    throw new DelegationError('ChainBroken', "a DelegationGrant's own effect must be non_idempotent_write");
  }
  const issuer = identity.signerId(alg, pubkey);
  if (new TextDecoder().decode(o.signer) !== issuer) { // the envelope signer field MUST be the authenticated id
    throw new DelegationError('SignerMismatch', 'issuer id does not derive from the verifying key');
  }
  const g = grantFromBody(o.body);
  return new Resolved(o.id, issuer, g, o.causes);
}

// Whether the grant named by content id `cid` is revoked as of `now` (a revoke ordered at or before
// `now`). `revocations` is a Map (content-id hex -> revoke position), or null.
export function revokedAt(revocations, cid, now) {
  if (!revocations) return false;
  const p = revocations.get(hexOf(cid));
  return p !== undefined && Number(p) <= Number(now);
}

// The verified action whose delegated authority is being checked: the acting agent (verified signer of
// the action object), the action's own effect and resource scope (the running child at the leaf hop),
// and the action's `causes` (from which the leaf grant is located).
export class Action {
  constructor(signer, effect, scope, causes) {
    this.signer = signer;
    this.effect = Number(effect);
    this.scope = String(scope);
    this.causes = causes.map((c) => Uint8Array.from(c));
  }
}

// ---- D2 scope containment (design.md §18.1) --------------------------------------------------

// Whether `child` is contained in `parent` under the D2 path-prefix rule: an absent parent scope ("")
// is unconstrained; otherwise the child must equal the parent or begin with parent + "/". A missing
// child scope ("") under a scoped parent WIDENS authority and is NOT contained.
export function scopeContained(child, parent) {
  if (parent === '') return true;   // unconstrained parent
  if (child === '') return false;   // missing child scope under a scoped parent widens authority
  if (child === parent) return true;
  return child.startsWith(parent + '/');
}

// The distinct verified grants named in `causes` whose subject equals `subject` (the parent/leaf
// resolution predicate). Duplicate content ids are counted once.
function matchingCauses(causes, subject, grants) {
  const seen = new Set();
  const out = [];
  for (const c of causes) {
    const key = hexOf(c);
    if (seen.has(key)) continue;
    const r = grants.get(key);
    if (r !== undefined && r.grant.subject === subject) {
      seen.add(key);
      out.push(r);
    }
  }
  return out;
}

// ---- D3 chain verification (design.md §18.2) -------------------------------------------------

// The 12-step leaf->root delegation-chain walk, fail-closed with no partial credit. `grants` is a Map
// (content-id hex -> Resolved); `anchors` is a Set of trust-anchor issuer-id strings; `revoked` is a Map
// (content-id hex -> revoke position) or null; `now` is the action's authoritative ordering position.
// Returns null iff the chain terminates at a trusted root with every hop holding; otherwise throws the
// specific named error and authorizes nothing.
export function verifyChain(action, grants, anchors, revoked, now) {
  // step 2 -- locate the unique leaf grant among the action's causes whose subject == the actor.
  const leaves = matchingCauses(action.causes, action.signer, grants);
  if (leaves.length === 0) {
    throw new DelegationError('EffectNotAuthorized', 'no delegation authorizes this action');
  }
  if (leaves.length > 1) {
    throw new DelegationError('ChainBroken', 'more than one authorizing grant is ambiguous');
  }
  let g = leaves[0];
  let childEffect = action.effect;
  let childScope = action.scope;
  let pos = 0; // realized delegation hops beneath the current grant
  const visited = new Set();

  for (;;) {
    const key = hexOf(g.contentId);
    if (visited.has(key)) { // a content-id cycle (infeasible for a real hash chain) -- fail-closed
      throw new DelegationError('ChainBroken', 'content-id cycle in the delegation chain');
    }
    visited.add(key);

    // step 4 -- validity window at `now`.
    if (Number(now) < Number(g.grant.notBefore)) {
      throw new DelegationError('GrantNotYetValid', 'grant is before its not_before at this position');
    }
    if (Number(now) > Number(g.grant.notAfter)) {
      throw new DelegationError('GrantExpired', 'grant is past its not_after at this position');
    }
    // step 5 -- revocation at `now`.
    if (revokedAt(revoked, g.contentId, now)) {
      throw new DelegationError('GrantRevoked', 'grant is revoked at or before this position');
    }
    // step 6 -- attenuation (CapExceedsParent): effect ceiling AND scope containment.
    if (!policy.authorizes(g.grant.effectCap, childEffect)) {
      throw new DelegationError('CapExceedsParent', "child effect exceeds this grant's effect_cap");
    }
    if (!scopeContained(childScope, g.grant.scope)) {
      throw new DelegationError('CapExceedsParent', "child scope is not contained in this grant's scope");
    }
    // step 9 -- realized-depth bound: `pos` grants sit beneath g, so pos must not exceed max_depth.
    if (Number(pos) > Number(g.grant.maxDepth)) {
      throw new DelegationError('DelegationDepthExceeded', 'realized delegation depth exceeds max_depth');
    }
    // step 7 -- resolve g's delegation parent (the unique cause whose subject == g's issuer).
    const parents = matchingCauses(g.causes, g.issuer, grants);
    if (parents.length > 1) {
      throw new DelegationError('ChainBroken', 'ambiguous delegation parent');
    }
    if (parents.length === 0) {
      // steps 10 / 11 -- root test: g has no delegation parent.
      if (anchors.has(g.issuer)) return null; // terminated at a trusted root: authorized
      throw new DelegationError('UntrustedChainRoot', "the chain root's issuer is not a trust anchor");
    }
    const p = parents[0];
    // step 8 -- declared-depth attenuation: g.max_depth <= p.max_depth - 1 (no unsigned underflow; a
    // parent with max_depth 0 admits no child grant).
    if (Number(p.grant.maxDepth) === 0 || Number(g.grant.maxDepth) >= Number(p.grant.maxDepth)) {
      throw new DelegationError('DelegationDepthExceeded', 'declared delegation depth exceeds parent');
    }
    childEffect = g.grant.effectCap;
    childScope = g.grant.scope;
    g = p;
    pos += 1;
  }
}

// ---- D4 composition with per-action approval (design.md §18.3, R-DEL-8) ------------------------

// The D4 two-gate composition: a destructive-effect action requires BOTH a valid delegation chain (D3)
// terminating at a trusted root AND a valid, unconsumed, exact-bytes §7 approval whose granted effect
// covers the action, CONSUMED single-use by the acting agent (accountability binds to it). Precedence:
// the chain is checked first, so a broken chain denies with its D3 error even when an approval is
// present; a valid chain with no valid approval denies ApprovalRequired; a valid-but-already-consumed
// approval denies AlreadyConsumed. The approval is CONSUMED (the single state change) only when both
// gates hold; a rejected action makes no ledger append. Returns null on authorization.
export function authorizeDestructive(action, grants, anchors, revoked, now, appr, approverAlg, approverPubkey, apprSig, argsContentId, ledger) {
  // Gate 1 -- the delegation chain (D3). A broken chain denies with its named D3 error (thrown).
  verifyChain(action, grants, anchors, revoked, now);
  // Gate 2 -- a valid, unconsumed, exact-bytes approval over the action's args, consumed by the actor.
  try {
    approval.verifyApproval(appr, approverAlg, approverPubkey, apprSig, argsContentId, now);
  } catch (e) {
    throw new DelegationError('ApprovalRequired', 'no valid approval on a destructive action (held §7.3)');
  }
  if (!policy.authorizes(appr.grant, action.effect)) {
    throw new DelegationError('ApprovalRequired', "the approval's granted effect does not cover the action");
  }
  // Consume single-use. The ledger's named error (AlreadyConsumed) is surfaced uniformly as a
  // DelegationError so the composition's whole deny contract is one error type. Fail-closed: a spent
  // approval is not fresh authority.
  try {
    ledger.consume(appr.id(), action.signer);
  } catch (e) {
    throw new DelegationError(e.kind || 'LedgerError', String(e.message || e));
  }
  return null;
}
