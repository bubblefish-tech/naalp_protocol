// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C17 N-AALP-CONT flow continuation for the TypeScript SDK (design.md §20; R-CONT-1..7).
//
// N-AALP-CONT generalizes native streaming (one signed StreamOpen, cheap per-chunk data, one signed
// StreamCommit over a rolling digest) into a domain-agnostic flow:
//
//   - FlowOpen is the ONE full ML-DSA signature that fixes the flow's authority: its flow_id, its
//     effect ceiling, and the content-ids of the approvals that authorize it up to that ceiling. The
//     authority is reconstructable from the FlowOpen bytes ALONE (parseFlowOpen) -- no session state.
//   - Continuation is a CHEAP object: no per-object signature, only a SHA-384 hash-chain link. Each
//     link's head is SHA-384(link body); its `prev` is the previous link's head; the genesis prev is
//     the FlowOpen's head. A link carries its own effect, which MUST stay at or below the ceiling
//     (AboveCeiling otherwise -- the cheap path can never escalate past the one full signature).
//   - Checkpoint confirms a contiguous prefix and DETECTS A GAP (GapDetected).
//   - FlowCommit is a second full ML-DSA signature binding the whole ordered sequence with ONE
//     signature regardless of the number of continuations.
//
// A continuation replayed under a different FlowOpen fails: it carries the originating flow_open_id
// (WrongFlow) and its prev no longer chains to the other FlowOpen's head (ChainBroken). Domain
// separation is structural: FlowOpen (3 fields), Continuation (5 fields), Checkpoint (3 fields, a bstr
// head at 3), and FlowCommit (2 fields) are each a distinct deterministic-CBOR shape. Every check is
// fail-closed. Ported from impl/go/continuation (with impl/python/naalp/continuation.py as a second
// reference); graded against vectors/continuation/cases.json. The FlowOpen / FlowCommit signatures are
// real deterministic ML-DSA-65 (a bare tagged COSE_Sign1 over the flow body), not corpus-graded.

import { sha384 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, N, B, A, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import * as policy from './policy.mjs';

// HeadSize is the width of a chain head / prev link (SHA-384 = 48 bytes). A FlowOpen head anchors a
// flow's continuation chain.
export const HEAD_SIZE = 48;

const MAX_U64 = (2n ** 64n) - 1n;

// A named, fail-closed N-AALP-CONT error; .kind is the stable error kind (§15).
export class ContError extends Error {
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

// Whether v is a value of the closed C5 effect lattice (0..3). An out-of-lattice value is rejected
// RangeError, NEVER normalized to destructive -- normalizing a CEILING to destructive would silently
// make an out-of-range ceiling the MOST-permissive one (a fail-open).
function inLattice(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 && n <= policy.DESTRUCTIVE;
}

// SHA-384 over a body -- a 48-octet chain head.
function head(b) {
  return sha384(b);
}

// The T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
function contentId(b) {
  return cbor.contentId(Uint8Array.from(b));
}

// ---- FlowOpen: the one full signature fixing the flow's authority (design.md §20.2) -----------

// Fixes a flow's identity, effect ceiling, and approval bindings. Signed with a full ML-DSA signature
// (signFlowOpen); its authority is reconstructable from its bytes alone.
export class FlowOpen {
  constructor(flowId, effectCeiling, approvals) {
    this.flowId = Uint8Array.from(flowId);
    this.effectCeiling = effectCeiling;
    this.approvals = approvals.map((a) => Uint8Array.from(a));
  }

  // Deterministic-CBOR encoding {1: flow_id, 2: effect_ceiling, 3: approvals[]}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.flowId)],
      [new U(2), new U(this.effectCeiling)],
      [new U(3), new A(this.approvals.map((a) => new B(a)))],
    ]));
  }

  // The FlowOpen's SHA-384 head -- the genesis prev that anchors the continuation chain.
  head() {
    return head(this.bytes());
  }

  // The FlowOpen's content-id -- carried by every child object.
  id() {
    return contentId(this.bytes());
  }
}

// Reconstruct a FlowOpen from its body bytes ALONE (the bearer-authority property). An out-of-lattice
// effect_ceiling is rejected RangeError on decode, never normalized. Fail-closed (ContMalformed) on any
// malformed shape.
export function parseFlowOpen(b) {
  const m = decodeMap(b);
  const fid = bstrField(m, 1);
  const ceil = uintField(m, 2);
  const appsV = field(m, 3);
  if (fid === null || ceil === null || appsV === null || !(appsV instanceof A)) {
    throw new ContError('ContMalformed', 'object is not a well-formed FlowOpen body');
  }
  if (!inLattice(ceil)) {
    throw new ContError('RangeError', 'effect_ceiling is outside the closed 0..3 lattice');
  }
  const apps = [];
  for (const e of appsV.items) {
    if (!(e instanceof B)) throw new ContError('ContMalformed', 'approval is not a bstr');
    apps.push(e.v);
  }
  return new FlowOpen(fid, ceil, apps);
}

// ---- Continuation: the cheap hash-chain link (design.md §20.3) --------------------------------

// One cheap link in a flow's chain. NOT individually signed; its authenticity derives from the FlowOpen
// signature plus the hash chain plus the FlowCommit signature.
export class Continuation {
  constructor(flowOpenId, seq, effect, payloadId, prev) {
    this.flowOpenId = Uint8Array.from(flowOpenId);
    this.seq = BigInt(seq); // 64-bit; kept as BigInt so a seq > 2^53 never rounds through float64
    this.effect = effect;
    this.payloadId = Uint8Array.from(payloadId);
    this.prev = Uint8Array.from(prev);
  }

  // Deterministic-CBOR encoding {1: flow_open_id, 2: seq, 3: effect, 4: payload_id, 5: prev}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.flowOpenId)],
      [new U(2), new U(this.seq)],
      [new U(3), new U(this.effect)],
      [new U(4), new B(this.payloadId)],
      [new U(5), new B(this.prev)],
    ]));
  }

  // This link's SHA-384 head -- the prev of the next link.
  head() {
    return head(this.bytes());
  }
}

// The single audited decode path for untrusted Continuation wire bytes. Reconstructs the 5-field body
// and range-checks the effect against the closed lattice (0..3): an out-of-lattice effect is rejected
// RangeError, never carried as an unknown value. Fail-closed (ContMalformed).
export function parseContinuation(b) {
  const m = decodeMap(b);
  const fid = bstrField(m, 1);
  const seq = uintField(m, 2);
  const effect = uintField(m, 3);
  const pid = bstrField(m, 4);
  const prev = bstrField(m, 5);
  if (fid === null || seq === null || effect === null || pid === null || prev === null) {
    throw new ContError('ContMalformed', 'object is not a well-formed Continuation body');
  }
  if (!inLattice(effect)) {
    throw new ContError('RangeError', 'effect is outside the closed 0..3 lattice');
  }
  return new Continuation(fid, seq, effect, pid, prev);
}

// The CHEAP-path check of a single link against the flow's fixed authority: same flow (WrongFlow), next
// seq (SeqGap), effect within the ceiling (AboveCeiling), and prev chaining to the previous head
// (ChainBroken). Performs no signature verification -- that is what makes it cheap. Both the ceiling and
// the link effect are closed effects; an out-of-lattice value is RangeError, never normalized
// (fail-closed). Returns null on success.
export function verifyContinuation(c, flowOpenId, prevHead, expectedSeq, ceiling) {
  if (!inLattice(ceiling)) {
    throw new ContError('RangeError', 'ceiling is outside the closed 0..3 lattice');
  }
  if (!inLattice(c.effect)) {
    throw new ContError('RangeError', 'effect is outside the closed 0..3 lattice');
  }
  if (!bytesEqual(c.flowOpenId, Uint8Array.from(flowOpenId))) {
    throw new ContError('WrongFlow', "object's flow_open_id does not match the FlowOpen");
  }
  if (BigInt(c.seq) !== BigInt(expectedSeq)) {
    throw new ContError('SeqGap', 'continuation seq is not the next expected value');
  }
  if (!policy.authorizes(ceiling, c.effect)) {
    throw new ContError('AboveCeiling', 'continuation effect exceeds the FlowOpen effect ceiling');
  }
  if (!bytesEqual(c.prev, Uint8Array.from(prevHead))) {
    throw new ContError('ChainBroken', 'continuation prev does not chain to the previous head');
  }
  return null;
}

// Verify a whole ordered continuation sequence starting from the FlowOpen and return the final chain
// head. The ceiling comes from the FlowOpen, so the cheap path can never exceed what the one full
// signature authorized.
export function verifyChain(open, conts) {
  if (!inLattice(open.effectCeiling)) {
    throw new ContError('RangeError', 'effect_ceiling is outside the closed 0..3 lattice');
  }
  const id = open.id();
  let prev = open.head();
  const ceiling = open.effectCeiling;
  for (let i = 0; i < conts.length; i++) {
    verifyContinuation(conts[i], id, prev, BigInt(i), ceiling);
    prev = conts[i].head();
  }
  return prev;
}

// ---- Checkpoint: confirm a prefix, detect a gap (design.md §20.4) -----------------------------

// Asserts the chain head after a contiguous prefix of continuations (seq 0..through_seq).
export class Checkpoint {
  constructor(flowOpenId, throughSeq, headBytes) {
    this.flowOpenId = Uint8Array.from(flowOpenId);
    this.throughSeq = BigInt(throughSeq);
    this.head = Uint8Array.from(headBytes);
  }

  // Deterministic-CBOR encoding {1: flow_open_id, 2: through_seq, 3: head}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.flowOpenId)],
      [new U(2), new U(this.throughSeq)],
      [new U(3), new B(this.head)],
    ]));
  }
}

// The single audited decode path for untrusted Checkpoint wire bytes: the 3-field body (field 3 a bstr
// head). A 2-field FlowCommit look-alike is rejected here (missing field 3). Fail-closed (ContMalformed).
export function parseCheckpoint(b) {
  const m = decodeMap(b);
  const fid = bstrField(m, 1);
  const through = uintField(m, 2);
  const h = bstrField(m, 3);
  if (fid === null || through === null || h === null) {
    throw new ContError('ContMalformed', 'object is not a well-formed Checkpoint body');
  }
  return new Checkpoint(fid, through, h);
}

// Confirm the prefix is exactly the contiguous sequence seq 0..through_seq and that its recomputed head
// matches the checkpoint. A dropped or reordered link -- a missing seq, a broken prev, or the wrong
// count -- is reported GapDetected. Returns null on a clean confirmation.
export function verifyCheckpoint(cp, open, prefix) {
  if (!bytesEqual(cp.flowOpenId, open.id())) {
    throw new ContError('WrongFlow', 'checkpoint flow_open_id does not match the FlowOpen');
  }
  // through_seq is a 0-based index, so the prefix length is through_seq+1. At through_seq == u64::MAX
  // that addition would wrap and false-accept an EMPTY prefix as covering the whole counter space --
  // reject it as a gap instead (there can be no MAX+1 contiguous links).
  if (cp.throughSeq === MAX_U64) {
    throw new ContError('GapDetected', 'through_seq at u64::MAX admits no contiguous prefix');
  }
  if (BigInt(prefix.length) !== cp.throughSeq + 1n) {
    throw new ContError('GapDetected', 'wrong count: a link is missing or extra');
  }
  let h;
  try {
    h = verifyChain(open, prefix);
  } catch (e) {
    if (e instanceof ContError) throw new ContError('GapDetected', 'a seq/prev break inside the prefix is a gap');
    throw e;
  }
  if (!bytesEqual(cp.head, h)) {
    throw new ContError('GapDetected', 'recomputed prefix head does not match the checkpoint');
  }
  return null;
}

// ---- FlowCommit: the second full signature binding the whole sequence (design.md §20.5) --------

// Binds a completed flow's final chain head under one full ML-DSA signature.
export class FlowCommit {
  constructor(flowOpenId, finalHead) {
    this.flowOpenId = Uint8Array.from(flowOpenId);
    this.finalHead = Uint8Array.from(finalHead);
  }

  // Deterministic-CBOR encoding {1: flow_open_id, 2: final_head} -- the 2-field shape that distinguishes
  // it from the 3-field Checkpoint.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.flowOpenId)],
      [new U(2), new B(this.finalHead)],
    ]));
  }
}

// ---- full-signature helpers (FlowOpen / FlowCommit) -- real ML-DSA, isolation -----------------

// The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int).
function protectedHeader(alg) {
  return cbor.encode(new M([[new U(1), new N(alg)]]));
}

// The tagged COSE_Sign1 over the FlowOpen body (the one full signature that opens the flow).
export function signFlowOpen(o, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), o.bytes());
}

// The tagged COSE_Sign1 over the FlowCommit body.
export function signFlowCommit(c, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), c.bytes());
}

// Verify the FlowOpen's full signature, then reconstruct the authority from the signed body bytes
// (fail-closed BadSignature). `profile` is accepted for API parity; the bearer COSE_Sign1 carries no
// envelope profile floor (that gate is envelope.verify's, for full N-AALP objects).
export function verifyFlowOpen(obj, profile, alg, pubkey) {
  const [prot, payload, sig] = cose.parseSign1Raw(obj);
  const tbs = cose.toBeSignedRaw(prot, payload);
  if (!cose.coseVerify1Raw(alg, pubkey, tbs, sig)) {
    throw new ContError('BadSignature', 'flow-open signature does not verify');
  }
  return parseFlowOpen(payload);
}

// Verify the FlowCommit's full signature, that it binds this FlowOpen, and that its final_head equals
// the chain recomputed over the delivered continuations (CommitMismatch otherwise).
export function verifyFlowCommit(obj, profile, alg, pubkey, open, conts) {
  const [prot, payload, sig] = cose.parseSign1Raw(obj);
  const tbs = cose.toBeSignedRaw(prot, payload);
  if (!cose.coseVerify1Raw(alg, pubkey, tbs, sig)) {
    throw new ContError('BadSignature', 'flow-commit signature does not verify');
  }
  const m = decodeMap(payload);
  const fid = bstrField(m, 1);
  const fh = bstrField(m, 2);
  if (fid === null || fh === null) {
    throw new ContError('ContMalformed', 'object is not a well-formed FlowCommit body');
  }
  const fc = new FlowCommit(fid, fh);
  if (!bytesEqual(fc.flowOpenId, open.id())) {
    throw new ContError('WrongFlow', 'flow-commit does not bind this FlowOpen');
  }
  const final = verifyChain(open, conts);
  if (!bytesEqual(fc.finalHead, final)) {
    throw new ContError('CommitMismatch', 'flow commit final_head does not match the recomputed chain');
  }
  return fc;
}

// ---- small deterministic-CBOR field accessors -------------------------------------------------

function decodeMap(b) {
  let v;
  try {
    v = cbor.decode(Uint8Array.from(b)); // strict decoder: throws NonCanonical on a non-canonical body
  } catch (e) {
    throw new ContError('ContMalformed', 'object is not well-formed deterministic CBOR: ' + e.message);
  }
  if (!(v instanceof M)) throw new ContError('ContMalformed', 'object is not a map');
  return v;
}

function field(m, k) {
  for (const [key, val] of m.pairs) {
    if (key instanceof U && key.v === BigInt(k)) return val;
  }
  return null;
}

function bstrField(m, k) {
  const v = field(m, k);
  return v instanceof B ? v.v : null;
}

function uintField(m, k) {
  const v = field(m, k);
  return v instanceof U ? v.v : null;
}
