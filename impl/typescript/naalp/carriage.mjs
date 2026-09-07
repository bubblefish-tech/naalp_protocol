// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C12 foreign carriage by class for the TypeScript SDK (design.md §13; R-14.1..14.8, R-18.6).
//
// N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a signed N-AALP
// carriage object whose effect, safety, identity, and audit apply, and whose foreign body is
// interpreted by a carriage CLASS -- not a bespoke per-protocol mapping (R-14.1). There are five
// structured classes (JSONRPC, HTTP, MSG, STREAM, DOC) plus a universal OPAQUE class that makes any
// protocol -- including one nobody has defined -- carriable immediately on an experimental protocol id
// with no registration (R-14.1, R-18.6). The foreign field is carried VERBATIM and MUST NOT be
// re-serialized, canonicalized, summarized, or rewritten (R-14.4); N-AALP metadata is carried around
// it, never inside it. The carriage object's signer remains the authority -- a foreign identity never
// becomes an N-AALP authorization identity (R-14.6).
//
// Ported from impl/go/carriage (with impl/python/naalp/carriage as a second reference); each carriage
// class is graded against its own per-class oracle at vectors/carriage/<class>/cases.json.

import * as cbor from './cbor.mjs';
import { U, B, T, M } from './cbor.mjs';

// Carriage classes (design.md §13.2).
export const CLASS_JSONRPC = 0;
export const CLASS_HTTP = 1;
export const CLASS_MSG = 2;
export const CLASS_STREAM = 3;
export const CLASS_DOC = 4;
export const CLASS_OPAQUE = 5;

const CLASS_NAMES = ['JSONRPC', 'HTTP', 'MSG', 'STREAM', 'DOC', 'OPAQUE'];

// The name of a class code (0..5), or 'unknown'.
export function className(c) {
  const n = Number(c);
  return (n >= 0 && n < CLASS_NAMES.length) ? CLASS_NAMES[n] : 'unknown';
}

// A named, fail-closed carriage error; .kind is the stable error kind (design §13.6) -- MappingError,
// Malformed, or NotDelivered, mirroring the Go/Rust/Python/Ruby kinds.
export class CarriageError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// The body of a carriage object (design.md §13.2). `klass` is the carriage class (named `klass` rather
// than `class`, a reserved word); `foreign` is the foreign message carried octet-for-octet (R-14.4).
export class CarriageBody {
  constructor(protocolId, klass, contentType, correlation, method, foreign) {
    this.protocolId = protocolId;
    this.klass = klass;
    this.contentType = contentType;
    this.correlation = Uint8Array.from(correlation);
    this.method = String(method);
    this.foreign = Uint8Array.from(foreign);
  }

  // The carriage body as a CBOR map {1: protocol_id, 2: class, 3: content_type, 4: correlation,
  // 5: method, 6: foreign}.
  toValue() {
    return new M([
      [new U(1), new U(this.protocolId)],
      [new U(2), new U(this.klass)],
      [new U(3), new U(this.contentType)],
      [new U(4), new B(this.correlation)],
      [new U(5), new T(this.method)],
      [new U(6), new B(this.foreign)],
    ]);
  }

  // The deterministic-CBOR encoding of the carriage body.
  bytes() {
    return cbor.encode(this.toValue());
  }
}

// Reject a class code outside the defined set with a typed mapping error, never a silent drop (R-14.8).
// Returns null when the class is representable.
export function validateClass(klass) {
  const k = Number(klass);
  if (k > CLASS_OPAQUE || k < 0) {
    throw new CarriageError('MappingError', 'an N-AALP semantic cannot be represented by this carriage class');
  }
  return null;
}

// Wrap a foreign message octet-for-octet in a carriage body (R-14.1, R-14.4). It does not parse,
// canonicalize, or rewrite the foreign bytes. An undefined protocol carries under OPAQUE with an
// experimental protocol id and zero new specification (R-18.6).
export function carry(protocolId, klass, contentType, correlation, method, foreign) {
  validateClass(klass);
  return new CarriageBody(protocolId, klass, contentType, correlation, method, foreign);
}

// Parse a carriage body from a CBOR value, recovering the foreign field octet-for-octet. A structurally
// invalid body is Malformed; an unknown class is a MappingError. The mandatory foreign field (key 6)
// must be present.
export function carriageFromValue(v) {
  if (!(v instanceof M)) throw new CarriageError('Malformed', 'carriage body is not a map');
  let protocolId = 0;
  let klass = 0;
  let contentType = 0;
  let correlation = new Uint8Array(0);
  let method = '';
  let foreign = new Uint8Array(0);
  let haveForeign = false;
  for (const [k, val] of v.pairs) {
    if (!(k instanceof U)) throw new CarriageError('Malformed', 'non-uint carriage key');
    switch (Number(k.v)) {
      case 1:
        if (!(val instanceof U)) throw new CarriageError('Malformed', 'protocol_id not a uint');
        protocolId = val.v;
        break;
      case 2:
        if (!(val instanceof U)) throw new CarriageError('Malformed', 'class not a uint');
        klass = val.v;
        break;
      case 3:
        if (!(val instanceof U)) throw new CarriageError('Malformed', 'content_type not a uint');
        contentType = val.v;
        break;
      case 4:
        if (!(val instanceof B)) throw new CarriageError('Malformed', 'correlation not a bstr');
        correlation = val.v;
        break;
      case 5:
        if (!(val instanceof T)) throw new CarriageError('Malformed', 'method not a tstr');
        method = val.v;
        break;
      case 6:
        if (!(val instanceof B)) throw new CarriageError('Malformed', 'foreign not a bstr');
        foreign = val.v;
        haveForeign = true;
        break;
      default:
        throw new CarriageError('Malformed', 'unknown carriage field ' + k.v);
    }
  }
  if (!haveForeign) throw new CarriageError('Malformed', 'carriage body missing the mandatory foreign field');
  validateClass(klass);
  return new CarriageBody(protocolId, klass, contentType, correlation, method, foreign);
}

// The protocol-id range (design.md §13.4): reserved 0x00, standards 0x01-0x0F,
// experimental 0x10-0x7F (no registration), private 0x80-0xFF. protocol_id is one octet; anything wider
// is invalid.
export function protocolRange(id) {
  const n = Number(id);
  if (n === 0x00) return 'reserved';
  if (n <= 0x0F) return 'standards';
  if (n <= 0x7F) return 'experimental';
  if (n <= 0xFF) return 'private';
  return 'invalid';
}

// Records whether a carried message was actually delivered. A report never claims delivery it did not
// achieve (R-14.8).
export class DeliveryReport {
  constructor(delivered) {
    this.delivered = Boolean(delivered);
  }
}

// Produce a delivery report from the below-foreign outcome: a failed delivery throws NotDelivered
// (never a false 'delivered'); a success returns DeliveryReport(delivered=true) (R-14.8).
export function report(deliveredBelow) {
  if (!deliveredBelow) throw new CarriageError('NotDelivered', 'a below-foreign failure; the message was not delivered');
  return new DeliveryReport(true);
}

// The authorizing principal of a carriage object: the N-AALP signer of the object (envelope field 5),
// never any foreign principal named inside the foreign bytes (R-14.6). It reads only the signed
// envelope, never the carried foreign message.
export function carriageAuthority(obj) {
  return obj.signer;
}
