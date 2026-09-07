// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C6 approval for the TypeScript SDK -- the §7.1 approval object that binds exact canonical
// arguments by content id, the §7.2 durable, hash-chained, single-use consume ledger, the R-TDCS-3
// party-visible coarse refusal, the R-TDCS-5 optional audience binding, and the T1.5 (NAALP-REQ-121)
// ledger-signed consume receipt / fork-evidence double-spend proof (design.md §7, §25/C22; requirements
// R-7.1..7.4, R-TDCS-2..5).
//
// An ApprovalRecord binds, under signature, the content id of the exact canonical argument object it
// approves (§7.1); because the args are named by content id, mutating any argument changes the id and
// the approval no longer matches (ApprovalMismatch). The consume ledger is a durable compare-and-set
// set keyed by approval content id: the FIRST consumer of an id wins and every later consume of the
// same id is rejected AlreadyConsumed (§7.2) -- an approval consumable twice is a replay skeleton key,
// the bug this cap prevents. Atomicity is honest, not decorative: the membership check AND the append
// run in ONE synchronous critical section with no intervening await (JS is single-threaded), the
// single-writer analogue of the Go reference's single mutex, so there is no read-then-write TOCTOU
// window and a race spends an approval exactly once. Each winning consume is written and fsynced to
// the write-ahead log before it returns (persist-before-ack, R-7.2 durability), and a log that does
// not hash-chain cleanly on replay is refused LedgerCorrupt rather than trusted. A held outcome is a
// distinct signed non-success result (HeldResult, §7.4). Every rejection is fail-closed and causes no
// ledger append.
//
// T1.5 (NAALP-REQ-121): a ledger opened with openLedgerSigned() (a named ordering-authority identity +
// signing key) offers consumeWithReceipt(), which mints a ConsumeReceipt binding the approval id to the
// entry's forward-only position, signed under the LEDGER's key (never the requester's). ReceiptSet
// observes receipts and mints a non-repudiable ConsumeForkEvidence the instant one approval id carries
// two conflicting ledger-signed receipts -- a double spend made provable on comparison, mirroring
// naalp/audit's Auditor equivocation detector. Graded against vectors/consume_receipt/cases.json (a
// SEPARATE corpus from vectors/approval/cases.json).
//
// Ported from impl/go/approval (with impl/rust/src/approval.rs as a second reference, and
// impl/python/naalp/approval.py for prior TypeScript-adjacent conventions); the WAL framing follows the
// sibling naalp/delivery Tracker (length-prefixed deterministic-CBOR records, fsync per append). The
// approval and consume-receipt SIGNATURES are real deterministic ML-DSA-65 over the body bytes DIRECTLY
// (as the reference cose.Signer.Sign -- a raw message, NOT a COSE Sig_structure).

import { openSync, existsSync, readSync, writeSync, fsyncSync, closeSync } from 'node:fs';
import { sha384 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, B, T, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import * as envelope from './envelope.mjs';
import * as policy from './policy.mjs';

// HeadSize is the width of a chain head (SHA-384 = 48 bytes). Genesis is all-zero.
export const HEAD_SIZE = 48;

// A named, fail-closed approval error; .kind is the stable error kind (design §7, §15).
export class ApprovalError extends Error {
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

// The chain head after an entry: SHA-384 over the entry's deterministic-CBOR bytes (48 octets).
// Because the entry body carries prev, editing any entry breaks the next entry's linkage.
function chainNext(entryBytes) {
  return sha384(entryBytes);
}

// ---- §7.1 the approval object body ----------------------------------------------------

// The body of an Approval object (§7.1). Signed over its deterministic-CBOR bytes; `approves` is the
// content id of the exact canonical args object, so a changed argument changes the id and the approval
// no longer matches (ApprovalMismatch). `audience` is the OPTIONAL R-TDCS-5 valid-context (design.md
// §25, C22): "" means absent (field 6 omitted, unrestricted) -- an empty string is not a distinct
// value, so an approval that names no audience encodes byte-identically to a 5-field approval
// (additive by design).
export class ApprovalRecord {
  constructor(approves, approver, grant, nonce, notAfter, audience = '') {
    this.approves = Uint8Array.from(approves); // content id of the exact canonical args object (§7.1)
    this.approver = String(approver);          // approver signer id
    this.grant = grant;                        // granted effect class (0..3), the C5 effect
    this.nonce = Uint8Array.from(nonce);       // anti-replay nonce (§7.3)
    this.notAfter = notAfter;                  // expiry, epoch ms (§7.3)
    this.audience = String(audience);          // OPTIONAL valid-context (R-TDCS-5); "" == absent
  }

  // Deterministic-CBOR encoding of the approval body {1:approves,2:approver,3:grant,4:nonce,5:not_after,
  // ?6:audience}. Field 6 is OMITTED when audience is "" (R-TDCS-5, additive by design).
  bytes() {
    const pairs = [
      [new U(1), new B(this.approves)],
      [new U(2), new T(this.approver)],
      [new U(3), new U(this.grant)],
      [new U(4), new B(this.nonce)],
      [new U(5), new U(this.notAfter)],
    ];
    if (this.audience !== '') pairs.push([new U(6), new T(this.audience)]);
    return cbor.encode(new M(pairs));
  }

  // The approval content id (the ledger key): multihash(0x20, SHA-384(body)) (50 octets).
  id() {
    return cbor.contentId(this.bytes());
  }
}

// ErrAudienceMismatch (R-TDCS-5) -- an approval that names an audience is valid only in that context;
// presenting it at a different use context is rejected fail-closed, authorizing nothing.

// VerifyAudience (R-TDCS-5) enforces the OPTIONAL audience binding. An approval that NAMES an audience
// (a.audience !== '') is valid only in that context: a relying party checks it at use and rejects
// AudienceMismatch on a mismatch. An approval that names NO audience is unrestricted by the issuer's
// explicit choice and passes for any use context -- a deployment MAY require an audience by local
// policy above this check. The check is mandatory WHEN a context is present, never mandatory-presence
// (the JWT `aud` present-optional / check-mandatory shape). Returns null on success; throws otherwise.
export function verifyAudience(a, useContext) {
  if (a.audience !== '' && a.audience !== useContext) {
    throw new ApprovalError('AudienceMismatch', 'approval names an audience other than the use context');
  }
  return null;
}

// Sign the approval body with a real deterministic ML-DSA key derived from seed. The signed input is
// the approval body bytes DIRECTLY (matching the reference cose.Signer.Sign: raw message, rnd=0 -- no
// COSE Sig_structure wrapping).
export function signApproval(a, alg, seed) {
  return cose.mldsaSign(alg, seed, a.bytes());
}

// Verify an approval: (1) signed by the approver's key over its body bytes, (2) binds the exact args by
// content id, (3) not expired at posTime. Returns null only if all three hold; otherwise throws the
// specific named error and authorizes nothing. Check order is fail-closed: BadSignature ->
// ApprovalMismatch -> ApprovalExpired. It does NOT consume -- consumption is the separate atomic ledger
// step (§7.2).
export function verifyApproval(a, alg, pubkey, sig, argsContentId, posTime) {
  if (!cose.coseVerify1Raw(alg, pubkey, a.bytes(), sig)) {
    throw new ApprovalError('BadSignature', 'approval signature does not verify');
  }
  if (!bytesEqual(a.approves, Uint8Array.from(argsContentId))) {
    throw new ApprovalError('ApprovalMismatch', "approval does not bind these arguments' content id");
  }
  if (Number(posTime) > Number(a.notAfter)) {
    throw new ApprovalError('ApprovalExpired', 'approval is past its not_after');
  }
  return null;
}

// The composed, single-call consume choke point for the approval state machine (draft "## Approval
// state machine"). It runs the table's precedence in ONE impl-owned place -- the exact sequence that
// payment.authorizeCharge and the mcp/agui/delegation callers each hand-assemble -- so a caller (and
// the conformance suite) drives one realization of the reactions rather than re-deriving the ordering
// at each call site:
//
//  1. verifyApproval checks the signature, then the args-content-id binding (ApprovalMismatch, which
//     the draft says "takes precedence over every cell"), then expiry (ApprovalExpired) -- all BEFORE
//     the ledger is consulted. So a request both past notAfter AND already in the ledger is refused
//     ApprovalExpired, never AlreadyConsumed (the draft's expiry-over-consume rule), and the ledger is
//     left untouched by the rejected request.
//  2. The granted effect must be a valid class (0..3) and must cover the action's required effect; a
//     grant outside the closed vocabulary, or one below the required effect, authorizes nothing and is
//     refused ApprovalRequired (fail-closed; the grant-range guard is stricter than the raw callers).
//  3. The atomic single-use consume through the §7 ledger: the first consumer of the id wins, a second
//     returns AlreadyConsumed, and neither a rejected earlier step nor a losing race appends.
//
// Every rejection is fail-closed and appends nothing; it consumes only when every check holds,
// returning the ledger entry. It does NOT enforce object audience -- that is consumeObject's binding
// (design.md §2.5.3); consumeApproval is the args-content-id/effect/single-use choke point.
export function consumeApproval(a, alg, pubkey, aSig, argsContentId, posTime, requiredEffect, ledger, by) {
  verifyApproval(a, alg, pubkey, aSig, argsContentId, posTime); // BadSignature / ApprovalMismatch / ApprovalExpired -- all before the ledger
  if (Number(a.grant) > policy.DESTRUCTIVE) {
    throw new ApprovalError('ApprovalRequired', 'action requires an approval that is not present'); // a grant outside the closed 0..3 effect vocabulary authorizes nothing
  }
  if (!policy.authorizes(a.grant, requiredEffect)) {
    throw new ApprovalError('ApprovalRequired', 'action requires an approval that is not present'); // the approval's granted effect does not cover this action
  }
  return ledger.consume(a.id(), by);
}

// ---- §7.4 the held (not-yet-granted) outcome ------------------------------------------

// The distinct, signed, non-success result returned when an action requires an approval that has not
// been granted (§7.4). It is never a silent success or a silent denial.
export class HeldResult {
  constructor(approves, reason) {
    this.approves = Uint8Array.from(approves); // content id of the args whose approval is pending
    this.reason = String(reason);
  }

  // Deterministic-CBOR encoding {1: approves, 2: reason}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.approves)],
      [new U(2), new T(this.reason)],
    ]));
  }
}

// Sign a held result so the "not yet granted" outcome is itself attributable (real ML-DSA).
export function signHeld(h, alg, seed) {
  return cose.mldsaSign(alg, seed, h.bytes());
}

// ---- R-TDCS-3 the party-visible coarse refusal object (design.md §25, C22) ------------

// A refusal returned to the authenticated party carries ONLY a single value from a closed vocabulary
// and the content id of the full signed record that carries the discriminating detail -- a reference,
// not the reason. The detail exists, is signed, and is auditor-resolvable through the record channel,
// but never reaches the adversary-facing surface, so repeated refusals cannot serve an adaptive party
// as an oracle. A party-visible refusal that carries discriminating detail, or omits the record content
// id, is RefusalDetailLeak; an outcome outside the closed set is UnknownRefusalOutcome.

// The closed refusal-outcome set.
export const REFUSAL_DENIED = 0n;       // the action is refused
export const REFUSAL_HELD = 1n;         // the action requires a further step not yet taken
export const REFUSAL_UNVERIFIABLE = 2n; // required evidence did not verify

const REFUSAL_OUTCOME_NAME = new Map([[0n, 'denied'], [1n, 'held'], [2n, 'unverifiable']]);

// isKnownRefusalOutcome reports whether code is in the closed refusal-outcome set.
export function isKnownRefusalOutcome(code) {
  return REFUSAL_OUTCOME_NAME.has(BigInt(code));
}

// The party-visible coarse refusal body {1: outcome, 2: record}. outcome is the closed-set coarse
// outcome; record is the T1 content id of the full signed record carrying the detail.
export class Refusal {
  constructor(outcome, record) {
    this.outcome = BigInt(outcome); // denied / held / unverifiable (closed set)
    this.record = Uint8Array.from(record); // content id of the full signed record carrying the detail
  }

  // Deterministic-CBOR encoding {1: outcome, 2: record}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new U(this.outcome)],
      [new U(2), new B(this.record)],
    ]));
  }
}

// Build the party-visible refusal for a full signed record: it carries the coarse outcome and the
// content id of fullRecord, and NOTHING drawn from inside fullRecord -- the discriminating detail stays
// in the record, referenced only by its id. This is the coarse-to-party split the closure property
// requires (R-TDCS-3).
export function refusalFromRecord(outcome, fullRecord) {
  return new Refusal(outcome, cbor.contentId(Uint8Array.from(fullRecord)));
}

// Reconstruct a Refusal from its body bytes, enforcing that a party-visible refusal carries ONLY
// {outcome, record} and nothing more (R-TDCS-3). Rejects, fail-closed: a malformed body, any key other
// than 1 and 2, a missing or empty record id (RefusalDetailLeak -- discriminating detail leaked, or the
// auditor reference dropped), and an outcome outside the closed set (UnknownRefusalOutcome). Authorizes
// nothing.
export function parseRefusal(b) {
  let v;
  try {
    v = cbor.decode(b);
  } catch (e) {
    throw new ApprovalError('RefusalDetailLeak', 'malformed refusal body: ' + e.message);
  }
  if (!(v instanceof M)) throw new ApprovalError('RefusalDetailLeak', 'refusal body is not a map');
  let outcome = null;
  let record = null;
  for (const [k, val] of v.pairs) {
    if (!(k instanceof U)) throw new ApprovalError('RefusalDetailLeak', 'non-uint refusal key');
    if (k.v === 1n && val instanceof U) outcome = val.v;
    else if (k.v === 2n && val instanceof B) record = val.v;
    else throw new ApprovalError('RefusalDetailLeak', 'refusal carries a field beyond {1,2}'); // leaked detail
  }
  if (outcome === null || record === null || record.length === 0) {
    throw new ApprovalError('RefusalDetailLeak', 'refusal must carry the full-record content id');
  }
  if (!isKnownRefusalOutcome(outcome)) {
    throw new ApprovalError('UnknownRefusalOutcome', 'refusal outcome is outside the closed set denied/held/unverifiable');
  }
  return new Refusal(outcome, record);
}

// ---- §7.2 the consume ledger entry ----------------------------------------------------

// One append to the consume ledger (§7.2).
export class LedgerEntry {
  constructor(seq, prev, approvalId, by) {
    this.seq = seq;                              // ledger sequence position
    this.prev = Uint8Array.from(prev);           // prior chain head (HEAD_SIZE bytes; genesis is all-zero)
    this.approvalId = Uint8Array.from(approvalId); // the approval content id being consumed
    this.by = String(by);                        // consumer signer id
  }

  // Deterministic-CBOR encoding {1: seq, 2: prev, 3: approval-id, 4: by}. The head after this entry is
  // SHA-384(bytes()); because bytes carries prev, editing any entry breaks the next entry's linkage.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new U(this.seq)],
      [new U(2), new B(this.prev)],
      [new U(3), new B(this.approvalId)],
      [new U(4), new T(this.by)],
    ]));
  }

  // This entry's chain head -- the prev of the next entry.
  head() {
    return chainNext(this.bytes());
  }
}

// Decode a ledger entry from its deterministic-CBOR bytes. A malformed shape, a non-uint key, a
// mistyped field, an unknown field, or a missing field is a corrupt log (LedgerCorrupt).
function parseEntry(rec) {
  let v;
  try {
    v = cbor.decode(rec); // strict decoder: throws NonCanonical on a non-canonical body
  } catch (e) {
    throw new ApprovalError('LedgerCorrupt', 'ledger entry is not canonical: ' + e.message);
  }
  if (!(v instanceof M)) throw new ApprovalError('LedgerCorrupt', 'ledger entry is not a map');
  let seq = null;
  let prev = null;
  let aid = null;
  let by = null;
  for (const [k, val] of v.pairs) {
    if (!(k instanceof U)) throw new ApprovalError('LedgerCorrupt', 'non-uint ledger entry key');
    if (k.v === 1n && val instanceof U) seq = val.v;
    else if (k.v === 2n && val instanceof B) prev = val.v;
    else if (k.v === 3n && val instanceof B) aid = val.v;
    else if (k.v === 4n && val instanceof T) by = val.v;
    else throw new ApprovalError('LedgerCorrupt', 'unknown or mistyped ledger entry field ' + k.v);
  }
  if (seq === null || prev === null || aid === null || by === null) {
    throw new ApprovalError('LedgerCorrupt', 'ledger entry missing a mandatory field');
  }
  return new LedgerEntry(seq, prev, aid, by);
}

// ---- §7.5 T1.5 (NAALP-REQ-121): the ledger-signed consume receipt with forward-only position ------

// The draft-01 (T1.5, NAALP-REQ-121) ledger-signed evidence that a consuming ledger -- the ORDERING
// AUTHORITY -- bound an approval content id to its own forward-only position. The anti-double-spend
// counter (position) rides under the LEDGER's signature, never the requester's: the requester cannot
// forge the ledger's position or its signature. A partition that spends one approval twice therefore
// leaves two ledger-signed receipts against one approval id, each carrying a position drawn from forked
// state -- a contradiction authored by neither the requester nor a thief, provable the instant the two
// receipts are compared (see ConsumeForkEvidence). It does not PREVENT the second spend; it makes the
// double-spend detectable in bytes neither party could repudiate.
export class ConsumeReceipt {
  constructor(ledger, approvalId, position) {
    this.ledger = Uint8Array.from(ledger);         // the consuming ledger's signer id (the ordering authority; REQ-121)
    this.approvalId = Uint8Array.from(approvalId); // the approval content id consumed (the CAS key)
    this.position = BigInt(position);              // the ledger's forward-only position bound to this consume
  }

  // Deterministic-CBOR encoding of the receipt body {1: ledger, 2: approval_id, 3: position} -- the
  // exact bytes the ledger signs (T1.5).
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.ledger)],
      [new U(2), new B(this.approvalId)],
      [new U(3), new U(this.position)],
    ]));
  }
}

// Sign a consume receipt with the LEDGER's key (REQ-121: the anti-double-spend counter is under the
// ordering authority's signature). The signed input is the receipt bytes() (real deterministic ML-DSA).
export function signConsumeReceipt(r, alg, seed) {
  return cose.mldsaSign(alg, seed, r.bytes());
}

// Check that a consume receipt is a valid ledger-signed statement: the ledger id is present (an
// unnamed ordering authority is not evidence) and the signature verifies under the ledger's key.
// Fail-closed: either fault throws ConsumeReceiptUnsigned and authorizes nothing. (ledgerAlg, ledgerPk)
// MUST be the verifier resolved for r.ledger. Returns null on success.
export function verifyConsumeReceipt(r, ledgerAlg, ledgerPk, sig) {
  if (r.ledger.length === 0) {
    throw new ApprovalError('ConsumeReceiptUnsigned', 'an unnamed ordering authority is not evidence');
  }
  if (!cose.coseVerify1Raw(ledgerAlg, ledgerPk, r.bytes(), sig)) {
    throw new ApprovalError('ConsumeReceiptUnsigned', 'consume receipt signature does not verify');
  }
  return null;
}

// (R-TDCS-4) judges an approval's present-moment validity using time drawn from an ordering authority
// STRUCTURALLY DISTINCT from the party being authenticated. It is the named realization of the §18.2
// seam -- "validity judged on the ordering position, never the signer's clock" -- composing the
// existing verifiers and adding the distinctness check a relying party runs so a party can never be the
// source of the time against which its own credential's expiry is judged. It (1) verifies the approval
// binds argsContentId, is signed by the approver, and is unexpired at posTime, where posTime is the
// ORDERING AUTHORITY's forward-only position (never a clock the approver supplies); (2) verifies the
// consume receipt is ledger-signed (the position rides under the ordering authority's key, never the
// requester's); and (3) throws FreshnessSelfAsserted when the ordering authority r.ledger IS the
// authenticated party partyId. Fail-closed: any fault throws its named error and authorizes nothing.
export function verifyFreshIndependent(
  a, approverAlg, approverPk, aSig, argsContentId, posTime,
  r, ledgerAlg, ledgerPk, rSig, partyId,
) {
  verifyApproval(a, approverAlg, approverPk, aSig, argsContentId, posTime);
  verifyConsumeReceipt(r, ledgerAlg, ledgerPk, rSig);
  if (bytesEqual(r.ledger, Uint8Array.from(partyId))) {
    throw new ApprovalError('FreshnessSelfAsserted', 'the ordering authority that stamps freshness is the authenticated party itself');
  }
  return null;
}

// The non-repudiable evidence (T1.5, NAALP-REQ-121) that ONE approval content id received TWO
// conflicting ledger-signed consume receipts -- a double spend made provable on comparison. It carries
// both receipts and both ledger signatures; because a verifier checks each signature under the key its
// receipt names, the contradiction is authored by neither the requester nor a thief. Both positions
// (and, cross-ledger, both ledger ids) are surfaced so the contradiction is legible to a human and to
// tooling.
export class ConsumeForkEvidence {
  constructor(approvalId, a, sigA, b, sigB) {
    this.approvalId = Uint8Array.from(approvalId); // the one approval content id spent twice
    this.a = a;                                    // first receipt
    this.sigA = Uint8Array.from(sigA);              // ledger A's signature over a.bytes()
    this.b = b;                                     // second receipt (same approval id; different position and/or ledger)
    this.sigB = Uint8Array.from(sigB);              // ledger B's signature over b.bytes()
  }

  // Checks that this is a genuine fork: (1) the disputed approval id is present and BOTH receipts name
  // it; (2) the two receipts actually conflict -- they are NOT byte-identical (a byte-identical
  // re-emission is a benign duplicate, not a fork); and (3) BOTH ledger signatures verify under the
  // keys their receipts name, resolved through `resolve` -- a function (ledgerId) => [alg, pk] or a
  // falsy value if unknown. Any failure rejects the whole thing (fail-closed): a mismatched/absent
  // approval id or a byte-identical pair is ConsumeForkInvalid, and an unnamed/unresolvable ledger or a
  // signature that does not verify is ConsumeReceiptUnsigned. On a clean pass the double spend is
  // proven and non-repudiable. Returns null on success.
  verify(resolve) {
    if (this.approvalId.length === 0) {
      throw new ApprovalError('ConsumeForkInvalid', 'fork evidence names no disputed approval id');
    }
    if (!bytesEqual(this.a.approvalId, this.approvalId) || !bytesEqual(this.b.approvalId, this.approvalId)) {
      throw new ApprovalError('ConsumeForkInvalid', 'both receipts must name the one disputed approval id');
    }
    if (bytesEqual(this.a.bytes(), this.b.bytes())) {
      throw new ApprovalError('ConsumeForkInvalid', 'byte-identical receipts are a benign duplicate, not a fork');
    }
    const va = resolve(this.a.ledger);
    if (!va || this.a.ledger.length === 0) {
      throw new ApprovalError('ConsumeReceiptUnsigned', 'ledger A is unnamed or unresolvable');
    }
    const vb = resolve(this.b.ledger);
    if (!vb || this.b.ledger.length === 0) {
      throw new ApprovalError('ConsumeReceiptUnsigned', 'ledger B is unnamed or unresolvable');
    }
    const [algA, pkA] = va;
    const [algB, pkB] = vb;
    if (!cose.coseVerify1Raw(algA, pkA, this.a.bytes(), this.sigA) ||
        !cose.coseVerify1Raw(algB, pkB, this.b.bytes(), this.sigB)) {
      throw new ApprovalError('ConsumeReceiptUnsigned', 'a ledger signature does not verify');
    }
    return null; // a valid, non-repudiable double-spend proof
  }
}

// Observes ledger-signed consume receipts, keyed by approval content id, and detects a fork (a double
// spend) from the signed receipts alone (T1.5, NAALP-REQ-121) -- the consume-layer analogue of the
// audit Auditor's equivocation detection (naalp/audit.mjs). It resolves each receipt's ledger verifier
// through `resolve`, rejects any receipt whose ledger signature does not verify, and on a conflicting
// second receipt for one approval id mints a non-repudiable ConsumeForkEvidence. Mirrors the Auditor
// idiom: observe() returns the evidence directly (not thrown) on a fork, and throws only on a bad
// signature/unresolvable ledger.
export class ReceiptSet {
  constructor(resolve) {
    this._resolve = resolve; // (ledgerId: Uint8Array) => [alg, pk] | falsy
    this._seen = new Map();  // approval-id hex -> {r: ConsumeReceipt, sig: Uint8Array}
  }

  // Records a ledger-signed consume receipt. Throws ConsumeReceiptUnsigned if the ledger is
  // unnamed/unresolvable or the signature does not verify. Returns a ConsumeForkEvidence when a
  // previously-seen receipt for the same approval id conflicts (different position and/or ledger); and
  // null otherwise (including a benign byte-identical duplicate).
  observe(r, sig) {
    if (r.ledger.length === 0) {
      throw new ApprovalError('ConsumeReceiptUnsigned', 'an unnamed ordering authority is not evidence');
    }
    const resolved = this._resolve(r.ledger);
    if (!resolved) {
      throw new ApprovalError('ConsumeReceiptUnsigned', 'ledger id does not resolve to a known verifier');
    }
    const [alg, pk] = resolved;
    if (!cose.coseVerify1Raw(alg, pk, r.bytes(), sig)) {
      throw new ApprovalError('ConsumeReceiptUnsigned', 'consume receipt signature does not verify');
    }
    const key = hexOf(r.approvalId);
    const prev = this._seen.get(key);
    if (prev !== undefined) {
      if (bytesEqual(prev.r.bytes(), r.bytes())) return null; // benign byte-identical duplicate
      return new ConsumeForkEvidence(r.approvalId, prev.r, prev.sig, r, Uint8Array.from(sig));
    }
    this._seen.set(key, { r, sig: Uint8Array.from(sig) });
    return null;
  }
}

// Makes a fork detector that resolves a ledger id to its (alg, pk) verifier via resolve (which returns
// a falsy value for an unknown ledger id).
export function newReceiptSet(resolve) {
  return new ReceiptSet(resolve);
}

// The durable, hash-chained, single-use consume set (§7.2). All state mutation goes through consume()
// in one synchronous critical section (the single-writer discipline), and each winning consume is
// written and fsynced to the WAL before it returns. Use openLedger() to construct one. WAL records are
// length-prefixed (4-byte big-endian) deterministic-CBOR entry bodies, as the sibling delivery Tracker.
export class Ledger {
  constructor(fd, authority = '') {
    this._fd = fd;
    this._consumed = new Map(); // approval-id hex -> seq (BigInt)
    this._head = new Uint8Array(HEAD_SIZE); // current chain head (genesis is all-zero)
    this._seq = 0n;             // next sequence number
    this._pos = 0;              // append offset in the WAL
    this._ledgerId = authority; // consuming-authority NAME (§2.5.3 audience target); identity only, NOT a signed-ledger id
    // T1.5 (NAALP-REQ-121): the ledger's own signing key, set only by openLedgerSigned. A plain
    // openLedger() ledger has _signAlg/_signSeed null and offers consume(), not consumeWithReceipt().
    this._signAlg = null;
    this._signSeed = null;
    this._replay();
  }

  // Read the WAL from the start, rebuilding state and verifying the chain. Each record is
  // length-prefixed (uint32 big-endian) so the log is self-framing. An out-of-order seq or a broken
  // prev linkage is refused LedgerCorrupt.
  _replay() {
    let pos = 0;
    let head = new Uint8Array(HEAD_SIZE);
    let seq = 0n;
    for (;;) {
      const lenBuf = Buffer.alloc(4);
      const n = readSync(this._fd, lenBuf, 0, 4, pos);
      if (n === 0) break;
      if (n !== 4) throw new ApprovalError('LedgerCorrupt', 'truncated WAL length prefix');
      pos += 4;
      const reclen = lenBuf.readUInt32BE(0);
      const rec = Buffer.alloc(reclen);
      const m = readSync(this._fd, rec, 0, reclen, pos);
      if (m !== reclen) throw new ApprovalError('LedgerCorrupt', 'truncated WAL record');
      pos += reclen;
      const recBytes = Uint8Array.from(rec);
      const e = parseEntry(recBytes);
      if (e.seq !== seq || !bytesEqual(e.prev, head)) {
        throw new ApprovalError('LedgerCorrupt', 'out-of-order seq or broken chain linkage');
      }
      this._consumed.set(hexOf(e.approvalId), e.seq);
      head = chainNext(recBytes);
      seq += 1n;
    }
    this._head = head;
    this._seq = seq;
    this._pos = pos;
  }

  // Atomically consume an approval id exactly once (§7.2). The first caller for a given id appends a
  // ledger entry (written and fsynced before returning) and returns it; every later caller for the same
  // id throws AlreadyConsumed with no append. The membership check and the append are one synchronous
  // critical section (no await between them), so under contention exactly one caller wins.
  consume(approvalId, by) {
    const aid = Uint8Array.from(approvalId);
    const key = hexOf(aid);
    if (this._consumed.has(key)) {
      throw new ApprovalError('AlreadyConsumed', 'approval already consumed');
    }
    const e = new LedgerEntry(this._seq, this._head, aid, by);
    const rec = Buffer.from(e.bytes());
    const lenPrefix = Buffer.alloc(4);
    lenPrefix.writeUInt32BE(rec.length, 0);
    const frame = Buffer.concat([lenPrefix, rec]);
    writeSync(this._fd, frame, 0, frame.length, this._pos);
    this._pos += frame.length;
    fsyncSync(this._fd); // persist-before-ack (R-7.2 durability)
    this._consumed.set(key, e.seq);
    this._head = chainNext(Uint8Array.from(rec));
    this._seq += 1n;
    return e;
  }

  // Consume the approval for a consume-once OBJECT, enforcing the §2.5.3 audience binding at the
  // choke point BEFORE the compare-and-set: the object's audience MUST name this ledger's consuming
  // authority, or the object is rejected WrongAudience with no ledger append. An unnamed ledger (no
  // authority) refuses LedgerUnsigned -- it cannot be the audience of any object. The audience check
  // is NEVER inside envelope.verify() (a relay/auditor legitimately verifies objects addressed to
  // others). Mirrors Go/Rust Ledger.ConsumeObject -- the authority is this port's ledger NAME.
  consumeObject(o, approvalId, by) {
    if (!this._ledgerId) throw new ApprovalError('LedgerUnsigned', 'ledger has no consuming authority');
    // fail-closed, before the CAS: throws envelope EnvelopeError('WrongAudience') and appends nothing
    envelope.checkAudience(o, this._ledgerId, true);
    return this.consume(approvalId, by);
  }

  // Performs the first-append-wins compare-and-set (exactly as consume()) AND, on the winning append,
  // returns a ledger-signed ConsumeReceipt binding the approval id to the entry's forward-only position
  // (its ledger seq) (design.md §7.5; T1.5, NAALP-REQ-121). The ledger must have been opened with
  // openLedgerSigned(); a plain ledger throws LedgerUnsigned (fail-closed). A second consume of the same
  // approval id throws AlreadyConsumed and signs nothing -- the first receipt stands (first-append-
  // wins). The receipt is signed BEFORE the WAL write, so a signing failure records nothing. JS's
  // single-threaded synchronous critical section (as consume()) gives the same exactly-once guarantee as
  // the Go reference's single mutex. Returns { entry, receipt, sig }.
  consumeWithReceipt(approvalId, by) {
    if (this._signSeed === null || !this._ledgerId) {
      throw new ApprovalError('LedgerUnsigned', 'ledger was not opened with a signing key');
    }
    const aid = Uint8Array.from(approvalId);
    const key = hexOf(aid);
    if (this._consumed.has(key)) {
      throw new ApprovalError('AlreadyConsumed', 'approval already consumed'); // first-append-wins: no second receipt
    }
    const e = new LedgerEntry(this._seq, this._head, aid, by);
    // The receipt binds the approval id to THIS consume's forward-only position (the entry seq), signed
    // by the ledger key. Sign before touching the WAL so a signing failure records nothing.
    const ledgerIdBytes = new TextEncoder().encode(this._ledgerId);
    const receipt = new ConsumeReceipt(ledgerIdBytes, aid, e.seq);
    const sig = cose.mldsaSign(this._signAlg, this._signSeed, receipt.bytes());
    const rec = Buffer.from(e.bytes());
    const lenPrefix = Buffer.alloc(4);
    lenPrefix.writeUInt32BE(rec.length, 0);
    const frame = Buffer.concat([lenPrefix, rec]);
    writeSync(this._fd, frame, 0, frame.length, this._pos);
    this._pos += frame.length;
    fsyncSync(this._fd); // persist-before-ack (R-7.2 durability)
    this._consumed.set(key, e.seq);
    this._head = chainNext(Uint8Array.from(rec));
    this._seq += 1n;
    return { entry: e, receipt, sig };
  }

  // Whether an approval id has been consumed.
  isConsumed(approvalId) {
    return this._consumed.has(hexOf(Uint8Array.from(approvalId)));
  }

  // The current chain head (a copy).
  head() {
    return Uint8Array.from(this._head);
  }

  // The number of consumed approvals.
  len() {
    return this._consumed.size;
  }

  // Flush and close the WAL file.
  close() {
    closeSync(this._fd);
  }
}

// Open (creating if needed) a WAL-backed consume ledger at path and replay any existing log to rebuild
// the consumed set and chain head. A log that does not hash-chain cleanly is refused LedgerCorrupt
// rather than trusted.
export function openLedger(path, authority = '') {
  const fd = existsSync(path) ? openSync(path, 'r+') : openSync(path, 'w+');
  try {
    return new Ledger(fd, authority);
  } catch (e) {
    closeSync(fd); // a corrupt log leaves no open descriptor behind
    throw e;
  }
}

// Opens a WAL-backed ledger (as openLedger) and binds it to its own ordering-authority identity
// (ledgerId, the NAME form of the ledger key, matching the openLedger authority convention) and signing
// key (alg, seed), so it can produce ledger-signed consume receipts (design.md §7.5; T1.5,
// NAALP-REQ-121). An empty ledgerId or a missing seed is refused fail-closed LedgerUnsigned: an unnamed
// or keyless ordering authority cannot sign the anti-double-spend position, so consumeWithReceipt would
// have nothing accountable to emit.
export function openLedgerSigned(path, ledgerId, alg, seed) {
  if (!ledgerId || !seed) {
    throw new ApprovalError('LedgerUnsigned', 'an unnamed or keyless ordering authority cannot sign consume receipts');
  }
  const fd = existsSync(path) ? openSync(path, 'r+') : openSync(path, 'w+');
  try {
    const l = new Ledger(fd, ledgerId);
    l._signAlg = alg;
    l._signSeed = Uint8Array.from(seed);
    return l;
  } catch (e) {
    closeSync(fd); // a corrupt log leaves no open descriptor behind
    throw e;
  }
}
