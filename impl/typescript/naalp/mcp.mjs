// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// NAALP-MCP binding profile for the TypeScript SDK (design.md §19; Companion-Spec Requirement 6.1) --
// a draft-01 ADDITIVE tier-1 surface over the frozen spine. It introduces NO new envelope, encoding,
// signature, identity, or audit mechanism (R-11.3): an MCP tool call is a normal N-AALP object
// (envelope §2) on the Bridge channel, and it REUSES the closed effect lattice (policy), the approval +
// single-use consume ledger (approval), and the T1 content-id framing (§2.3) unchanged.
//
// What the profile adds is the governance MCP itself lacks. The MCP specification states plainly that a
// tool's annotations are unenforced hints a malicious server can lie about -- "clients MUST consider
// tool annotations to be untrusted unless they come from trusted servers". This profile turns that
// anonymous, untrusted hint into a SIGNED effect claim by a named key:
//
//   - CARRIAGE, NOT ADOPTION. The MCP tool-definition bytes and the tool-call argument bytes are carried
//     OCTET-FOR-OCTET; a foreign identity inside them never becomes an N-AALP authorization identity --
//     the wrapping signer is the authority (R-14.6).
//   - PUBLISHED MAPPING TABLE. The tool's annotations map to the closed four-effect lattice
//     (read_only < idempotent_write < non_idempotent_write < destructive). Because the spine carries no
//     CBOR boolean (design §3.1), each JSON hint is transcribed as the uint 1/0; an ABSENT hint takes
//     its MCP default. destructiveHint's default of TRUE is why an un-annotated write maps to destructive
//     -- the fail-closed rule.
//   - THE WRAPPING SIGNER IS ACCOUNTABLE. The wrapper's envelope effect (field 7) is the signer's
//     DECLARED effect, under its ML-DSA signature. A verifier independently recomputes the
//     annotation-derived effect and enforces the MORE SEVERE of the two (resolveEnforcedEffect -- the
//     good-regulator attenuator: a disagreeing input collapses UP, never down). A signer that DECLARES
//     BELOW its own carried annotations is rejected fail-closed (EffectUnderDeclared); an annotation set
//     mapping outside the lattice is rejected (MalformedAnnotation), never defaulted to benign.
//   - THE APPROVAL BINDS THE EXACT CALL. An approval binds the content id of the call binding
//     (tool_id + args_id). A changed tool description or changed arguments yields a new content id and
//     invalidates a prior approval (Requirement 6.1), reusing the §7 approval + consume ledger.
//
// Every check is fail-closed (§15). Ported from impl/go/mcp (with impl/python/naalp/mcp.py as a second
// reference); the byte surface (annotation encoding, the mapping table, tool-call bodies/content-ids,
// call bindings, the resolution verdicts) is graded against the shared vectors/mcp/cases.json; the
// signed governance path (verifyToolCall / authorizeCall) uses real deterministic ML-DSA-65 and is
// demonstrated in isolation only (the corpus carries no signed vector).

import * as cbor from './cbor.mjs';
import { U, B, M } from './cbor.mjs';
import * as channels from './channels.mjs';
import * as policy from './policy.mjs';
import * as envelope from './envelope.mjs';
import * as approval from './approval.mjs';

// Channel binding, the tier-1 kind code, and the tier for the MCP wrapper (design §6.1). McpToolCall is
// kind 1 on the Bridge channel -- a named escalation over the frozen baseline Carriage kind (0), which
// stays untouched (R-15A.2).
export const CHANNEL_BRIDGE = 0x000D;   // Bridge channel (foreign carriage lives here)
export const KIND_MCP_TOOL_CALL = 1;    // tier-1 kind code (baseline Carriage is kind 0)
export const TIER = 1;                   // a named escalation adding the governed MCP wrapper (R-15A.2)

// Annotation CBOR keys inside a naalp-mcp-annotations map. Each value is the uint 1 (true) / 0 (false)
// -- the spine carries no CBOR boolean (design §3.1).
export const KEY_READ_ONLY = 1;    // MCP readOnlyHint
export const KEY_DESTRUCTIVE = 2;  // MCP destructiveHint
export const KEY_IDEMPOTENT = 3;   // MCP idempotentHint
export const KEY_OPEN_WORLD = 4;   // MCP openWorldHint (ADVISORY -- not an effect determinant)

// MCP documented defaults for an ABSENT hint. destructiveHint defaults to TRUE, so an un-annotated
// write maps to destructive -- the fail-closed default.
export const DEFAULT_READ_ONLY = false;
export const DEFAULT_DESTRUCTIVE = true;
export const DEFAULT_IDEMPOTENT = false;

// A named, fail-closed MCP-profile error; .kind is the stable error kind (mirroring the Go/Rust/Python
// kinds MalformedAnnotation, EffectUnderDeclared, EffectOutsideLattice, ToolCallMalformed, and the
// reused §7 ApprovalRequired).
export class McpError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// T1 content-id framing multihash(0x20, SHA-384(b)) = 0x20 0x30 || SHA-384(b) (50 octets), identical to
// the spine framing over raw bytes.
export function contentId(b) {
  return cbor.contentId(Uint8Array.from(b));
}

// ---- the transcribed MCP annotation set (naalp-mcp-annotations) -------------------------------

// The wrapping signer's transcription of a tool's MCP ToolAnnotations. Each hint is OPTIONAL: an
// undefined/null field means the hint was absent (the MCP default applies in the mapping), so an absent
// hint and a present false are distinct on the wire though they may resolve to the same effect.
// openWorld is carried for accountability but never enters the effect mapping (design §5).
export class Annotations {
  constructor(readOnly, destructive, idempotent, openWorld) {
    this.readOnly = readOnly;       // MCP readOnlyHint (undefined => absent)
    this.destructive = destructive; // MCP destructiveHint
    this.idempotent = idempotent;   // MCP idempotentHint
    this.openWorld = openWorld;     // MCP openWorldHint (advisory only)
  }

  // Encode the annotation set as its CBOR map: present hints only, uint keys -> uint 0/1.
  toValue() {
    const pairs = [];
    if (this.readOnly != null) pairs.push([new U(KEY_READ_ONLY), new U(this.readOnly ? 1 : 0)]);
    if (this.destructive != null) pairs.push([new U(KEY_DESTRUCTIVE), new U(this.destructive ? 1 : 0)]);
    if (this.idempotent != null) pairs.push([new U(KEY_IDEMPOTENT), new U(this.idempotent ? 1 : 0)]);
    if (this.openWorld != null) pairs.push([new U(KEY_OPEN_WORLD), new U(this.openWorld ? 1 : 0)]);
    return new M(pairs);
  }

  // The deterministic-CBOR bytes of the annotation map (keys sorted by encode).
  encode() {
    return cbor.encode(this.toValue());
  }
}

// Parse a naalp-mcp-annotations map. Rejects (MalformedAnnotation, fail-closed): a non-map, a non-uint
// key, a non-uint value, a hint value outside {0,1} (it transcribes no boolean), a duplicate key, or an
// annotation key outside the closed mapping {1,2,3,4}. Such a set would map outside the closed lattice,
// so it is rejected, never defaulted to benign (AC-6.1.2).
export function annotationsFromValue(v) {
  if (!(v instanceof M)) throw new McpError('MalformedAnnotation', 'annotation set is not a map');
  const a = new Annotations();
  const seen = new Set();
  for (const [k, val] of v.pairs) {
    if (!(k instanceof U)) throw new McpError('MalformedAnnotation', 'non-uint annotation key');
    if (!(val instanceof U) || val.v > 1n) {
      throw new McpError('MalformedAnnotation', 'annotation hint value is outside {0,1}');
    }
    if (seen.has(k.v)) throw new McpError('MalformedAnnotation', 'duplicate annotation key');
    seen.add(k.v);
    const flag = val.v === 1n;
    switch (Number(k.v)) {
      case KEY_READ_ONLY: a.readOnly = flag; break;
      case KEY_DESTRUCTIVE: a.destructive = flag; break;
      case KEY_IDEMPOTENT: a.idempotent = flag; break;
      case KEY_OPEN_WORLD: a.openWorld = flag; break;
      default: throw new McpError('MalformedAnnotation', 'annotation key outside the closed mapping');
    }
  }
  return a;
}

// ---- the published annotation -> effect mapping table (design §6.1) ---------------------------

// Map a tool's transcribed annotations to the closed four-effect lattice by the published table,
// applying the MCP default for each absent hint:
//
//   readOnlyHint true                                  -> read_only
//   readOnlyHint false, destructiveHint true           -> destructive
//   readOnlyHint false, destructiveHint false, idem T  -> idempotent_write
//   readOnlyHint false, destructiveHint false, idem F  -> non_idempotent_write
//
// An absent readOnlyHint defaults false (a write); an absent destructiveHint defaults TRUE (destructive)
// -- so a tool with no annotations maps to destructive, the fail-closed collapse to the most-severe.
// openWorldHint is never consulted (design §5).
export function mapAnnotationsToEffect(a) {
  const ro = a.readOnly == null ? DEFAULT_READ_ONLY : a.readOnly;
  const de = a.destructive == null ? DEFAULT_DESTRUCTIVE : a.destructive;
  const idem = a.idempotent == null ? DEFAULT_IDEMPOTENT : a.idempotent;
  if (ro) return policy.READ_ONLY;
  if (de) return policy.DESTRUCTIVE;
  if (idem) return policy.IDEMPOTENT_WRITE;
  return policy.NON_IDEMPOTENT_WRITE;
}

// The more-severe resolution (the good-regulator attenuator). Given the annotation-derived effect and
// the wrapping signer's declared effect, return [enforced, mismatch] -- the enforced effect being the
// MORE SEVERE (equal to `declared` on success), and mismatch whether the two disagreed (attributable to
// the wrapping signer). A declared value outside the closed lattice is EffectOutsideLattice; a declared
// value BELOW the annotation-derived effect is EffectUnderDeclared (a wrapper's declared effect can
// never sit under its own carried annotations' mapping).
export function resolveEnforcedEffect(annotationMapped, declared) {
  const am = Number(annotationMapped);
  const d = Number(declared);
  if (d > policy.DESTRUCTIVE) {
    throw new McpError('EffectOutsideLattice', 'declared effect outside the closed four-effect lattice');
  }
  if (d < am) {
    throw new McpError('EffectUnderDeclared', 'declared effect is below the annotation-mapped effect');
  }
  return [d, d !== am];
}

// ---- the wrapper body (naalp-mcp-tool-call) ---------------------------------------------------

// The wrapper body (envelope field 10). `tool` and `args` are the foreign MCP bytes, carried
// octet-for-octet (carriage, not adoption); `annotations` is the wrapping signer's transcription of the
// tool's hints, on which the mapping operates. The wrapper's OWN effect is envelope field 7, not a body
// field.
export class ToolCall {
  constructor(tool, args, annotations) {
    this.tool = Uint8Array.from(tool);
    this.args = Uint8Array.from(args);
    this.annotations = annotations;
  }

  toMap() {
    return new M([
      [new U(1), new B(this.tool)],
      [new U(2), new B(this.args)],
      [new U(3), this.annotations.toValue()],
    ]);
  }

  // Deterministic-CBOR encoding of the tool-call body {1:tool,2:args,3:annotations}.
  bytes() {
    return cbor.encode(this.toMap());
  }

  // The tool-call body's content id (T1 framing).
  contentId() {
    return contentId(this.bytes());
  }

  // The (tool_id, args_id) binding whose content id an approval binds for this call.
  callBinding() {
    return newCallBinding(this.tool, this.args);
  }

  // Build the (unsigned) N-AALP envelope object carrying this tool call: tier 1, Bridge channel, kind
  // McpToolCall, the wrapping signer's DECLARED effect as field 7, the tool-call body as field 10, and
  // `causes`. The caller signs it; the signer BECOMES accountable for the declared effect and the
  // annotation transcription. A declared effect outside the closed lattice is rejected fail-closed.
  // Under-declaration is NOT rejected here -- it is a signed, attributable claim whose inconsistency
  // verifyToolCall surfaces as EffectUnderDeclared at the enforcement point.
  envelopeObject(signer, created, profile, declared, causes) {
    if (Number(declared) > policy.DESTRUCTIVE) {
      throw new McpError('EffectOutsideLattice', 'declared effect outside the closed lattice');
    }
    return new envelope.Object({
      kind: KIND_MCP_TOOL_CALL, channel: CHANNEL_BRIDGE, tier: TIER,
      signer, created, effect: declared, causes: causes || [], profile, body: this.toMap(),
    });
  }
}

// Sign an McpToolCall envelope object with a real deterministic ML-DSA key; the signer becomes
// accountable for the declared effect and the carried annotations.
export function signToolCall(obj, alg, seed) {
  return envelope.sign(obj, alg, seed);
}

// Parse an envelope object body (a decoded cbor Value) into a ToolCall. A body that is not exactly
// {1:tool bstr, 2:args bstr, 3:annotations map} with those value types is ToolCallMalformed; a malformed
// annotation set is MalformedAnnotation. Fail-closed.
export function toolCallFromBody(v) {
  if (!(v instanceof M)) throw new McpError('ToolCallMalformed', 'tool-call body is not a map');
  let tool = null;
  let args = null;
  let ann = null;
  let haveAnn = false;
  for (const [k, val] of v.pairs) {
    if (!(k instanceof U)) throw new McpError('ToolCallMalformed', 'non-uint tool-call body key');
    switch (Number(k.v)) {
      case 1:
        if (!(val instanceof B)) throw new McpError('ToolCallMalformed', 'tool is not a bstr');
        tool = val.v;
        break;
      case 2:
        if (!(val instanceof B)) throw new McpError('ToolCallMalformed', 'args is not a bstr');
        args = val.v;
        break;
      case 3:
        ann = annotationsFromValue(val); // throws MalformedAnnotation
        haveAnn = true;
        break;
      default:
        throw new McpError('ToolCallMalformed', 'unknown tool-call body field ' + k.v);
    }
  }
  if (tool === null || args === null || !haveAnn) {
    throw new McpError('ToolCallMalformed', 'tool-call body missing a mandatory field');
  }
  return new ToolCall(tool, args, ann);
}

// ---- the call binding an approval binds (naalp-mcp-call-binding) ------------------------------

// Names the exact tool call by content id: the tool bytes' content id AND the args bytes' content id. An
// approval binds the content id of THIS binding, so a changed tool description (new toolId) OR changed
// arguments (new argsId) yields a new call content id and invalidates a prior approval bound to the old
// one (Requirement 6.1 / AC-6.1.2, AC-6.1.3).
export class CallBinding {
  constructor(toolId, argsId) {
    this.toolId = Uint8Array.from(toolId);
    this.argsId = Uint8Array.from(argsId);
  }

  toMap() {
    return new M([[new U(1), new B(this.toolId)], [new U(2), new B(this.argsId)]]);
  }

  // Deterministic-CBOR encoding of the call binding {1:tool_id, 2:args_id}.
  bytes() {
    return cbor.encode(this.toMap());
  }

  // The call content id an approval binds.
  contentId() {
    return contentId(this.bytes());
  }
}

// Compute the binding from the raw tool and args bytes.
export function newCallBinding(tool, args) {
  return new CallBinding(contentId(tool), contentId(args));
}

// ---- kind validation (composes with the frozen baseline) --------------------------------------

// Accepts exactly this surface's tier-1 kind (Bridge channel, McpToolCall).
export function kindValidator(channel, kind) {
  return Number(channel) === CHANNEL_BRIDGE && Number(kind) === KIND_MCP_TOOL_CALL;
}

function baselineKindValidator(channel, kind) {
  try {
    channels.lookup(channel, kind);
    return true;
  } catch (e) {
    if (e instanceof channels.UnknownKind) return false;
    throw e;
  }
}

// Accepts the frozen baseline kinds OR the tier-1 McpToolCall -- the validator an MCP-aware endpoint
// passes to envelope.verify. A baseline-only endpoint using the baseline validator alone correctly
// rejects an McpToolCall as UnknownKind (fail-closed).
export function composedKindValidator(channel, kind) {
  return baselineKindValidator(channel, kind) || kindValidator(channel, kind);
}

// ---- verified tool call -----------------------------------------------------------------------

// An MCP tool call that has passed envelope verification and effect resolution. It carries the enforced
// effect (the more-severe value C5 authorizes on), whether the annotation and declared effect disagreed
// (mismatch -- attributable to signer), and the parsed tool call.
export class Resolved {
  constructor(contentId, signer, toolCall, annotationMapped, declared, enforced, mismatch) {
    this.contentId = Uint8Array.from(contentId);
    this.signer = signer;
    this.toolCall = toolCall;
    this.annotationMapped = annotationMapped;
    this.declared = declared;
    this.enforced = enforced;
    this.mismatch = mismatch;
  }
}

// Verify a signed MCP wrapper end-to-end and resolve its enforced effect. It (1) verifies the signed
// object with real crypto (envelope.verify against the composed validator -- content id, ranges,
// header/body, kind dispatch, signature); (2) confirms it is a tier-1 Bridge McpToolCall; (3) parses the
// tool-call body (rejecting a malformed annotation set); (4) recomputes the annotation-derived effect
// from the CARRIED annotations, independent of the declared effect; (5) resolves the enforced effect to
// the MORE SEVERE, rejecting under-declaration. The enforced effect equals the declared envelope effect
// on success, so the object's field 7 is the correct C5 authorization input. Any failure returns its
// named error and authorizes nothing (fail-closed).
export function verifyToolCall(profile, alg, pubkey, signedObj) {
  const o = envelope.verify(profile, alg, pubkey, composedKindValidator, signedObj);
  if (Number(o.channel) !== CHANNEL_BRIDGE || Number(o.kind) !== KIND_MCP_TOOL_CALL || Number(o.tier) !== TIER) {
    throw new McpError('ToolCallMalformed', 'not a tier-1 Bridge McpToolCall');
  }
  const tc = toolCallFromBody(o.body);
  const mapped = mapAnnotationsToEffect(tc.annotations);
  const declared = Number(o.effect); // envelope.verify already range-checked field 7 to 0..3
  const [enforced, mismatch] = resolveEnforcedEffect(mapped, declared);
  return new Resolved(o.id, o.signer, tc, mapped, declared, enforced, mismatch);
}

// ---- the per-call approval gate (reuses §7 approval + consume ledger) --------------------------

// Enforce the profile's per-call approval gate for a verified tool call. The approval MUST bind the
// EXACT call binding content id (tool_id + args_id) -- so it satisfies neither a call with different
// arguments nor a call whose tool description changed (Requirement 6.1) -- its granted effect must cover
// the call's ENFORCED (more-severe) effect, it must be unexpired at `now`, and it is consumed single-use
// by `by` through the §7 ledger. Precedence and fail-closed behaviour mirror the spine: a non-matching
// or under-granting approval denies ApprovalRequired with no ledger append; an already-spent approval
// denies AlreadyConsumed; the consume (the single state change) happens only when every check holds.
// Returns null on authorization.
export function authorizeCall(r, appr, approverAlg, approverPubkey, apprSig, by, now, ledger) {
  const callCID = r.toolCall.callBinding().contentId();
  try {
    approval.verifyApproval(appr, approverAlg, approverPubkey, apprSig, callCID, now);
  } catch (e) {
    // A mismatch on the exact call bytes is a held outcome, not a silent pass (§7.3/§7.4).
    if (e instanceof approval.ApprovalError && e.kind === 'ApprovalMismatch') {
      throw new McpError('ApprovalRequired', 'approval does not bind this exact call');
    }
    throw e;
  }
  if (!policy.authorizes(appr.grant, r.enforced)) {
    throw new McpError('ApprovalRequired', 'the approval\'s granted effect does not cover the call');
  }
  ledger.consume(appr.id(), by); // AlreadyConsumed on replay (fail-closed, no double-spend)
  return null;
}
