// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The N-AALP error object and the numeric error-code registry for the TypeScript SDK (design.md
// §3.5, R3.3/R3.4, T3.3). The naalp-error object is the Control/Error body (channel 0x0000, kind 3,
// effect read_only) that carries one fail-closed rejection reason as
// {1:code, 2:name, ?3:detail, ?4:subject}. The registry is the ordered 129-entry name<->code table
// below (the code for NAMES[i] is i+1; 0 is reserved). NAMES is the single source the machine-
// readable registry (vectors/registry/error-codes.csv) and the CDDL naalp-error-code enum are
// generated to match, and scripts/registry_drift.py asserts the three agree; the table itself is
// graded against the non-circular oracle by the error.name_for_code conformance op.
//
// Two dual-carriage rules keep the code/name pair unambiguous and forward-compatible: a registered
// code whose name disagrees with the registry is rejected Malformed (the code is authoritative — the
// strengthening direction); a code outside the registry is opaque and non-fatal (the name is
// diagnostic only), so a receiver interoperates with a peer emitting a later-registered code.
//
// Ported from impl/go/naalperror (with impl/rust/src/naalperror.rs as a byte-identical second
// reference).

import * as cbor from './cbor.mjs';
import { U, B, T, M } from './cbor.mjs';

// STANDARDS_MAX is the top of the RFC-Required standards range; codes >= 0x8000 are private-use.
export const STANDARDS_MAX = 0x7FFF;

// NAMES is the ordered error-code registry: the code for NAMES[i] is i+1 (0 is reserved and MUST
// NOT appear on the wire). Order is the fields-of-record authority for every code (§3.5). Copied
// verbatim from impl/go/naalperror/naalperror.go Names.
export const NAMES = [
  'NonCanonical', 'DepthExceeded', 'Malformed', 'ContentIdMismatch', 'HeaderBodyMismatch',
  'UnsupportedVersion', 'UnknownCriticalExt', 'UnknownKind', 'RangeError', 'NonNFC',
  'WrongAudience', 'TooLarge', 'TooManyCauses', 'TooManyExtensions', 'TooManyChunks',
  'UnknownAlg', 'KeyAlgMismatch', 'ProfileDowngrade', 'HybridIncomplete', 'SuiteMismatch',
  'CompositeRefused', 'BadSignature', 'SignerMismatch', 'RotationUnauthorized', 'KeyRevoked',
  'EffectNotAuthorized', 'UnauthenticatedPrincipal', 'MalformedSafetyLabel', 'ApprovalRequired',
  'ApprovalMismatch', 'ApprovalExpired', 'AlreadyConsumed', 'ConsumeFork', 'ConsumeForkInvalid',
  'ConsumeReceiptUnsigned', 'LedgerCorrupt', 'LedgerUnsigned', 'AudienceMismatch',
  'FreshnessSelfAsserted', 'UnknownRefusalOutcome', 'RefusalDetailLeak', 'ChainBroken',
  'Equivocation', 'CausalViolation', 'ReceiptUnsigned', 'ForkProofInvalid', 'StageOutOfOrder',
  'StreamDigestMismatch', 'StreamStateError', 'ConfidentialTransportRequired', 'PeerUnauthenticated',
  'NotDelivered', 'MappingError', 'EffectDeclarationMismatch', 'StateTransitionError',
  'CapExceedsParent', 'TransformCycle', 'InputGateBypass', 'TaskStateError', 'ScopeOverlapConflict',
  'ReconcileMismatch', 'WrongFlow', 'SeqGap', 'AboveCeiling', 'GapDetected', 'CommitMismatch',
  'ContMalformed', 'GrantExpired', 'GrantNotYetValid', 'GrantRevoked', 'UntrustedChainRoot',
  'DelegationDepthExceeded', 'GrantMalformed', 'NameMalformed', 'NameChainBroken',
  'NameForkProofInvalid', 'IllegalTransition', 'TaskChainBroken', 'ForeignCard', 'DescMalformed',
  'MalformedApprovalFlag', 'DirForkProofInvalid', 'ImporterMismatch', 'UnknownDescriptionFormat',
  'VerifierKeyMismatch', 'NegMalformed', 'UnknownRole', 'UnknownProfile', 'NotDescended',
  'NotOffer', 'NotAccept', 'MalformedCriticalFlag', 'UnknownCriticalRisk', 'ReferenceMismatch',
  'MalformedAnnotation', 'EffectUnderDeclared', 'EffectOutsideLattice', 'ToolCallMalformed',
  'PayMalformed', 'UnknownPaymentFormat', 'GwMalformed', 'UnknownGatewayDecision', 'UIMalformed',
  'UIChainBroken', 'UnknownUIEventKind', 'ActionSubstituted', 'UINoConsent', 'StaleEpoch',
  'Unauthorized', 'OwnerImmutable', 'MemberExists', 'MemberUnknown', 'OwnerExists', 'RoleInvalid',
  'RoomOpMismatch', 'OpUnknown', 'PrincipalUnknown', 'PrincipalExists', 'RebindUnauthorized',
  // Evidence-record family (E6.3 egress + S1 decision-record + S3 checkpoint + R1/R8), codes 120-129.
  'EgMalformed', 'UnknownEgressBinding', 'DecisionMalformed', 'UnknownOrderingBasis', 'OrderingDisclosureMalformed',
  'TermDispositionMalformed', 'CheckpointMalformed', 'WitnessRootMismatch', 'InclusionProofInvalid', 'ForeignProfileMalformed', 'HazardMalformed', 'HazardNotCovered', 'HazardUnknown',
];

const CODE_BY_NAME = new Map(NAMES.map((n, i) => [n, i + 1]));

// A named, fail-closed naalp-error decode error; .kind is the stable error kind. Decode has exactly
// one reject kind (Malformed), mirroring impl/go (which reuses cose.ErrMalformed) and impl/rust
// (which reuses cose::Error{kind:"Malformed"}).
export class NaalperrorError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// nameForCode returns {name, registered} for a code: registered=true with the registered name for
// 1 <= code <= 129, else registered=false with name=''. A code of 0, or any value past the
// registered range, is unregistered (opaque per the open-registry rule).
export function nameForCode(code) {
  const c = Number(code);
  if (c >= 1 && c <= NAMES.length) return { name: NAMES[c - 1], registered: true };
  return { name: '', registered: false };
}

// codeForName returns {code, registered} for a name: registered=true with the registered code when
// the name is in the registry, else registered=false with code=0.
export function codeForName(name) {
  const c = CODE_BY_NAME.get(name);
  if (c === undefined) return { code: 0, registered: false };
  return { code: c, registered: true };
}

// A decoded naalp-error body.
export class ErrorObject {
  constructor(code, name, detail, subject) {
    this.code = code;
    this.name = name;
    this.detail = detail;     // '' if field 3 absent
    this.subject = subject;   // null if field 4 absent
  }
}

// encode returns the deterministic CBOR (RFC 8949 §4.2.1) of a naalp-error body
// {1:code, 2:name, ?3:detail, ?4:subject}. detail=='' omits field 3; subject==null/undefined omits
// field 4. The integer keys 1..4 are already in canonical ascending order.
export function encode(code, name, detail = '', subject = null) {
  const pairs = [
    [new U(1), new U(code)],
    [new U(2), new T(String(name))],
  ];
  if (detail !== '' && detail !== undefined && detail !== null) {
    pairs.push([new U(3), new T(String(detail))]);
  }
  if (subject !== null && subject !== undefined) {
    pairs.push([new U(4), new B(subject)]);
  }
  return cbor.encode(new M(pairs));
}

// decode parses a naalp-error body and enforces the dual-carriage rules. A structurally malformed
// body (not a map, a non-integer key, a wrong-typed or unknown field, or a missing code/name) is
// rejected Malformed. A registered code whose name disagrees with the registry is rejected Malformed
// (the code is authoritative). An unregistered code is accepted opaque (name diagnostic only).
export function decode(data) {
  let v;
  try {
    v = cbor.decode(data);
  } catch (e) {
    throw new NaalperrorError('Malformed', 'naalp-error body is not well-formed deterministic CBOR');
  }
  if (!(v instanceof M)) throw new NaalperrorError('Malformed', 'naalp-error body is not a map');

  let code = null;
  let name = null;
  let detail = '';
  let subject = null;
  let haveCode = false;
  let haveName = false;

  for (const [k, val] of v.pairs) {
    if (!(k instanceof U)) throw new NaalperrorError('Malformed', 'non-uint naalp-error key');
    switch (Number(k.v)) {
      case 1:
        if (!(val instanceof U)) throw new NaalperrorError('Malformed', 'code not a uint');
        code = Number(val.v);
        haveCode = true;
        break;
      case 2:
        if (!(val instanceof T)) throw new NaalperrorError('Malformed', 'name not a tstr');
        name = val.v;
        haveName = true;
        break;
      case 3:
        if (!(val instanceof T)) throw new NaalperrorError('Malformed', 'detail not a tstr');
        detail = val.v;
        break;
      case 4:
        if (!(val instanceof B)) throw new NaalperrorError('Malformed', 'subject not a bstr');
        subject = val.v;
        break;
      default:
        throw new NaalperrorError('Malformed', 'unknown naalp-error field ' + k.v); // closed grammar
    }
  }

  if (!haveCode || !haveName) throw new NaalperrorError('Malformed', 'naalp-error body missing code or name');

  const reg = nameForCode(code);
  if (reg.registered && reg.name !== name) {
    throw new NaalperrorError('Malformed', 'registered code disagrees with the registry name');
  }

  return new ErrorObject(code, name, detail, subject);
}
