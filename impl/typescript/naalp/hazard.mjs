// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP Manufacturing Add-ons Component F -- the physical-hazard authorization extension
// (design.md addendum; requirements F1-F5; wire authority `spec/naalp-draft-01.cddl`),
// TypeScript/ESM port of
// impl/rust/naalp-hazard/src/lib.rs (mirroring impl/csharp/Hazard.cs, impl/java/.../Hazard.java,
// impl/php/src/Hazard.php and impl/ruby/lib/naalp/hazard.rb).
//
// `effect` (envelope field 7, naalp::policy) describes DATA reversibility. `hazard` is a new,
// ORTHOGONAL dimension describing PHYSICAL danger: a data-reversible action may still be a high
// physical hazard. The two dimensions are never merged and neither derives the other.
//
// This module adds no new cryptography and no new CBOR codec of its own: every encode call
// delegates to cbor.encode / cbor.contentId, exactly as the Rust reference crate adds no
// crypto/encoding of its own over the graded naalp core.
//
// The fail-closed rules (F2, F3):
//   - classFromCode is the ONE fail-closed decode entry point: any missing or out-of-range raw
//     value normalizes to CLASS_MOTION_IN_SHARED_SPACE -- the highest class -- never to "absent"
//     or any weaker class.
//   - hazardAuthorized requires an EXACT class match (not a <= ceiling the way the effect
//     lattice's policy.authorizes works) AND full containment of the claim's envelope inside the
//     grant's on every axis, the speed bound, and the time window. Any single failing dimension
//     denies the WHOLE claim -- there is no partial authorization.
//   - hazardAuthorizedOptional additionally covers the case where an action carries NO hazard
//     claim at all: there is no envelope to check containment against, so it denies immediately
//     with a distinct error (HazardUnknown) rather than fabricating a sentinel envelope and
//     running the ordinary coverage check.

import * as cbor from './cbor.mjs';
import { U, N, T, A, M } from './cbor.mjs';
import { requireNFC } from './identity.mjs';

export class HazardMalformed extends Error {
  constructor(msg = 'hazard body is not the spec/naalp-draft-01.cddl shape, or an axis/frame is invalid') {
    super(msg);
    this.kind = 'HazardMalformed';
  }
}

export class HazardNotCovered extends Error {
  constructor(msg = 'declared hazard class or envelope is not fully covered by the authorization') {
    super(msg);
    this.kind = 'HazardNotCovered';
  }
}

export class HazardUnknown extends Error {
  constructor(msg = 'hazard value unrecognized or absent; no claim to check coverage against') {
    super(msg);
    this.kind = 'HazardUnknown';
  }
}

// ---- hazard-class (F2: closed, fail-closed to the highest class) -----------------------------

// The closed five-value hazard-class vocabulary (spec/naalp-draft-01.cddl). CLASS_MOTION_IN_
// SHARED_SPACE is BOTH a named class (4) and the fail-closed default for an unrecognized or
// absent raw value (F2) -- the assumption that "the producer did not tell us" is at least as
// dangerous as the worst named class.
export const CLASS_NONE = 0;
export const CLASS_TOOL_ACTUATION = 1;
export const CLASS_THERMAL = 2;
export const CLASS_ENERGY_RELEASE = 3;
export const CLASS_MOTION_IN_SHARED_SPACE = 4;

// Fail-closed decode (F2). `code` may be a BigInt, a JS safe-integer number, a decimal string, or
// null/undefined (absent). Absent, or any value outside 0..4 (unrecognized), normalizes to
// CLASS_MOTION_IN_SHARED_SPACE -- never to a weaker class, and never a decode failure (there is
// no "invalid hazard" outcome; there is only "the worst case we must assume"). Converted through
// BigInt() so a wire value far outside the float64-safe range (up to 2^64-1 and beyond, including
// a >2^63-1 decimal string) still normalizes correctly rather than losing precision to float64
// rounding or throwing.
export function classFromCode(code) {
  if (code === null || code === undefined) return CLASS_MOTION_IN_SHARED_SPACE;
  let c;
  try {
    c = typeof code === 'bigint' ? code : BigInt(code);
  } catch {
    return CLASS_MOTION_IN_SHARED_SPACE; // an unparsable/non-integer raw value still normalizes
  }
  if (c >= 0n && c <= 4n) return Number(c);
  return CLASS_MOTION_IN_SHARED_SPACE; // F2: unknown/absent -> highest class
}

function classToValue(cls) {
  return new U(cls);
}

// ---- shared int<->CBOR-value helpers for SpatialBounds -----------------------------------------

function intValue(v) {
  return v >= 0 ? new U(v) : new N(v);
}

function intFromValue(v) {
  if (v instanceof U) return Number(v.v);
  if (v instanceof N) return Number(v.v);
  throw new HazardMalformed();
}

// ---- spatial-bounds ----------------------------------------------------------------------

// A named coordinate frame plus a signed axis-aligned bounding region in that frame, integer
// millimeters (spec/naalp-draft-01.cddl `spatial-bounds`). `axes` is a list of [min, max] pairs,
// millimeters, signed. MUST be non-empty; every entry MUST satisfy min <= max.
export class SpatialBounds {
  constructor(frame, axes) {
    this.frame = String(frame);
    this.axes = Array.from(axes, ([min, max]) => [min, max]);
  }

  // Structural validity (spec/naalp-draft-01.cddl): non-empty axes, every min <= max, frame
  // non-empty and Unicode NFC.
  isWellFormed() {
    if (this.axes.length === 0) return false;
    for (const [min, max] of this.axes) {
      if (min > max) return false;
    }
    if (this.frame === '') return false;
    try {
      requireNFC(this.frame);
    } catch {
      return false;
    }
    return true;
  }

  toValue() {
    const axes = this.axes.map(([min, max]) => new A([intValue(min), intValue(max)]));
    return new M([
      [new U(1), new T(this.frame)],
      [new U(2), new A(axes)],
    ]);
  }

  // Deterministic-CBOR encoding of {1:frame,2:axes}. Malformed input still encodes (encoding is
  // not the validity gate); callers MUST check isWellFormed() before treating a SpatialBounds as
  // authoritative, exactly as fromValue() does on decode.
  bytes() {
    return cbor.encode(this.toValue());
  }

  // Parse a `spatial-bounds` map. Rejects a non-map, an out-of-range/wrong-typed key or value, a
  // missing key, empty axes, an axis with min > max, or a non-NFC/empty frame -- fail-closed
  // (HazardMalformed), never a partially-valid result.
  static fromValue(v) {
    if (!(v instanceof M)) throw new HazardMalformed();
    let frame = null;
    let axes = null;
    for (const [k, val] of v.pairs) {
      if (!(k instanceof U)) throw new HazardMalformed();
      const key = Number(k.v);
      if (key === 1) {
        if (!(val instanceof T)) throw new HazardMalformed();
        frame = val.v;
      } else if (key === 2) {
        if (!(val instanceof A) || val.items.length === 0) throw new HazardMalformed();
        const out = [];
        for (const it of val.items) {
          if (!(it instanceof A) || it.items.length !== 2) throw new HazardMalformed();
          const min = intFromValue(it.items[0]);
          const max = intFromValue(it.items[1]);
          if (min > max) throw new HazardMalformed();
          out.push([min, max]);
        }
        axes = out;
      } else {
        throw new HazardMalformed();
      }
    }
    if (frame === null || axes === null) throw new HazardMalformed();
    const sb = new SpatialBounds(frame, axes);
    if (!sb.isWellFormed()) throw new HazardMalformed();
    return sb;
  }
}

// Full containment (F3): same frame id (a bound in one frame says nothing about a bound in a
// different, unrelated frame), the SAME axis count in the SAME order, and every claim axis's
// [min,max] a subset of the matching grant axis's [min,max].
export function spatialContained(claim, grant) {
  if (claim.frame !== grant.frame) return false;
  if (claim.axes.length !== grant.axes.length) return false;
  for (let i = 0; i < claim.axes.length; i++) {
    const [cmin, cmax] = claim.axes[i];
    const [gmin, gmax] = grant.axes[i];
    if (!(cmin >= gmin && cmax <= gmax)) return false;
  }
  return true;
}

// ---- hazard-window -------------------------------------------------------------------------

// A validity window, epoch ms, the same convention as `naalp-object` field 6 (created) and
// `naalp-delegation-grant` fields 4/5.
export class HazardWindow {
  constructor(notBefore, notAfter) {
    this.notBefore = notBefore;
    this.notAfter = notAfter;
  }

  toValue() {
    return new M([
      [new U(1), new U(this.notBefore)],
      [new U(2), new U(this.notAfter)],
    ]);
  }

  static fromValue(v) {
    if (!(v instanceof M)) throw new HazardMalformed();
    let notBefore = null;
    let notAfter = null;
    for (const [k, val] of v.pairs) {
      if (!(k instanceof U) || !(val instanceof U)) throw new HazardMalformed();
      const key = Number(k.v);
      if (key === 1) notBefore = Number(val.v);
      else if (key === 2) notAfter = Number(val.v);
      else throw new HazardMalformed();
    }
    if (notBefore === null || notAfter === null) throw new HazardMalformed();
    return new HazardWindow(notBefore, notAfter);
  }
}

// ---- hazard-envelope -----------------------------------------------------------------------

// The full physical envelope a claim or an authorization bounds itself by. All three fields are
// MANDATORY on the wire (spec/naalp-draft-01.cddl) -- a silently-absent axis would be fail-OPEN
// in a physical-safety context, so an issuer that means "unbounded" states so explicitly with
// wide numeric bounds; the wire never infers permissiveness from silence here (deliberate
// contrast with `naalp-delegation-grant`'s optional scope).
export class HazardEnvelope {
  constructor(spatial, speedBoundMmS, window) {
    this.spatial = spatial;
    // Max instantaneous speed, millimeters per second.
    this.speedBoundMmS = speedBoundMmS;
    this.window = window;
  }

  toValue() {
    return new M([
      [new U(1), this.spatial.toValue()],
      [new U(2), new U(this.speedBoundMmS)],
      [new U(3), this.window.toValue()],
    ]);
  }

  // Deterministic-CBOR encoding of {1:spatial,2:speed_bound,3:window}.
  bytes() {
    return cbor.encode(this.toValue());
  }

  // The envelope's content id (T1 framing): a pure function of the bytes above.
  contentId() {
    return cbor.contentId(this.toValue());
  }

  // Parse a `hazard-envelope` map; fail-closed on any missing/malformed field.
  static fromValue(v) {
    if (!(v instanceof M)) throw new HazardMalformed();
    let spatial = null;
    let speed = null;
    let window = null;
    for (const [k, val] of v.pairs) {
      if (!(k instanceof U)) throw new HazardMalformed();
      const key = Number(k.v);
      if (key === 1) {
        spatial = SpatialBounds.fromValue(val);
      } else if (key === 2) {
        if (!(val instanceof U)) throw new HazardMalformed();
        speed = Number(val.v);
      } else if (key === 3) {
        window = HazardWindow.fromValue(val);
      } else {
        throw new HazardMalformed();
      }
    }
    if (spatial === null || speed === null || window === null) throw new HazardMalformed();
    return new HazardEnvelope(spatial, speed, window);
  }
}

// Full containment (F3): spatialContained() AND claim.speedBoundMmS <= grant.speedBoundMmS AND
// the claim's window is a sub-interval of the grant's (grant.notBefore <= claim.notBefore and
// claim.notAfter <= grant.notAfter).
export function envelopeContained(claim, grant) {
  return spatialContained(claim.spatial, grant.spatial)
    && claim.speedBoundMmS <= grant.speedBoundMmS
    && grant.window.notBefore <= claim.window.notBefore
    && claim.window.notAfter <= grant.window.notAfter;
}

// ---- naalp-hazard-claim / naalp-hazard-authorization ----------------------------------------

function bodyToValue(cls, envelope) {
  return new M([
    [new U(1), classToValue(cls)],
    [new U(2), envelope.toValue()],
  ]);
}

function bodyFromValue(v) {
  if (!(v instanceof M)) throw new HazardMalformed();
  let classCode = null;
  let envelope = null;
  for (const [k, val] of v.pairs) {
    if (!(k instanceof U)) throw new HazardMalformed();
    const key = Number(k.v);
    if (key === 1) {
      // An out-of-range class ON THE WIRE (not merely "absent") is a malformed body, not a
      // normalize-to-4 input: F2's fail-closed normalization is for the DECODE step that
      // produces a class from a less-structured source (classFromCode), not for a CDDL-invalid
      // hazard-class value already claiming to be well-formed.
      if (!(val instanceof U) || val.v > 4n) throw new HazardMalformed();
      classCode = val.v;
    } else if (key === 2) {
      envelope = HazardEnvelope.fromValue(val);
    } else {
      throw new HazardMalformed();
    }
  }
  if (classCode === null || envelope === null) throw new HazardMalformed();
  return [classFromCode(classCode), envelope];
}

// A signed physical-hazard claim (spec/naalp-draft-01.cddl `naalp-hazard-claim`). Carriage (the
// object it accompanies and how) is a wire-impact decision, not this module's concern.
export class HazardClaim {
  constructor(cls, envelope) {
    this.class = cls;
    this.envelope = envelope;
  }

  toValue() {
    return bodyToValue(this.class, this.envelope);
  }

  // Deterministic-CBOR encoding of {1:class,2:envelope}.
  bytes() {
    return cbor.encode(this.toValue());
  }

  // The claim's content id (T1 framing).
  contentId() {
    return cbor.contentId(this.toValue());
  }

  // Parse a `naalp-hazard-claim` body. Both class and envelope are mandatory -- a claim
  // declaring one and omitting the other is HazardMalformed, not partially valid.
  static fromValue(v) {
    const [cls, envelope] = bodyFromValue(v);
    return new HazardClaim(cls, envelope);
  }
}

// A signed physical-hazard authorization ("a grant" in requirements F3's language;
// spec/naalp-draft-01.cddl `naalp-hazard-authorization`). Same shape as HazardClaim deliberately:
// one envelope shape for both sides keeps the containment check symmetric.
export class HazardAuthorization {
  constructor(cls, envelope) {
    this.class = cls;
    this.envelope = envelope;
  }

  toValue() {
    return bodyToValue(this.class, this.envelope);
  }

  // Deterministic-CBOR encoding of {1:class,2:envelope}.
  bytes() {
    return cbor.encode(this.toValue());
  }

  // The authorization's content id (T1 framing).
  contentId() {
    return cbor.contentId(this.toValue());
  }

  // Parse a `naalp-hazard-authorization` body.
  static fromValue(v) {
    const [cls, envelope] = bodyFromValue(v);
    return new HazardAuthorization(cls, envelope);
  }
}

// ---- F3: grant-coverage authorization -------------------------------------------------------

// Authorize a well-formed, present claim against an authorization (F3): EXACT class match (not a
// <= ceiling -- see the module doc) AND envelopeContained(). Any single failing dimension denies
// the WHOLE claim (HazardNotCovered) -- there is no partial authorization and no fail-open
// branch.
export function hazardAuthorized(claim, grant) {
  if (claim.class !== grant.class) throw new HazardNotCovered();
  if (!envelopeContained(claim.envelope, grant.envelope)) throw new HazardNotCovered();
}

// Authorize an OPTIONAL claim (F2's "absent" case at the object level, distinct from a
// present-but-unrecognized class byte inside a claim). null/undefined -- no hazard-claim object
// exists at all for an action that requires one -- denies immediately (HazardUnknown) rather than
// fabricating a sentinel envelope and running the ordinary coverage check: there is no envelope
// to check containment against, so the honest outcome is a distinct error, not a coverage denial
// that implies an envelope was compared.
export function hazardAuthorizedOptional(claim, grant) {
  if (claim === null || claim === undefined) throw new HazardUnknown();
  hazardAuthorized(claim, grant);
}
