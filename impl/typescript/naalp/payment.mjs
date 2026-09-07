// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C21 (task 5B.1) NAALP-PAY payment import for the TypeScript SDK (design.md §24; R-PAY-1..6).
//
// NAALP-PAY imports a foreign payment payload -- an AP2 mandate, an Agentic Commerce Protocol
// delegated token, an x402 payload -- octet-for-octet as OPAQUE foreign bytes (carriage, not
// adoption): the foreign bytes are never re-serialized, canonicalized, or rewritten (R-14.4), and a
// foreign identity inside them never becomes an N-AALP authorization identity (R-14.6). It introduces
// NO new envelope, encoding, signature, identity, effect, or ledger mechanism (R-11.3): the imported
// payload becomes a value-bearing charge that N-AALP governs with its OWN added guarantees, reusing
// the closed C5 effect lattice (naalp/policy). There is NO fifth effect and NO payment-specific ledger.
//
// The added guarantees over the imported formats:
//
//   - PaymentImport {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign} is the
//     wrapper body. `format` selects the imported FORMAT from the closed payment-format registry;
//     `foreign` carries the imported payload octet-for-octet. An unknown format is rejected
//     (UnknownPaymentFormat).
//   - THE CHARGE IS BOUND. ChargeBinding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
//     6: foreign_id} names the exact value a §7 approval binds by content id -- including the foreign
//     payload's content id (the carriage binding). A wrong-amount, wrong-payee, wrong-currency, or
//     substituted-payload charge yields a different content id and no longer matches the approval.
//
//   - THE CHARGE IS SPENT SINGLE-USE. A payment spend is a non_idempotent_write (CHARGE_EFFECT); the
//     approval's granted effect must cover it, and authorizeCharge consumes the approval single-use
//     through the §7 ledger (naalp/approval), so a replayed charge is rejected (AlreadyConsumed) with
//     no state change.
//
// Every check is fail-closed (§15): a failing charge is rejected whole and returns its named error.
//
// Ported from impl/go/payment (with impl/rust/src/payment.rs as a second reference). The PaymentImport
// SIGNATURE is a bare-{1:alg} COSE_Sign1 (as the reference's cose.Sign1) with real deterministic
// ML-DSA. Graded against vectors/payment/cases.json.
//
// authorizeCharge reuses naalp/approval's ApprovalRecord / verifyApproval / Ledger.consume and
// naalp/policy's authorizes UNCHANGED -- there is no payment-specific ledger or effect.

import { sha384 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, N, B, T, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import * as policy from './policy.mjs';
import * as approval from './approval.mjs';

// The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
export const HEAD_SIZE = 48;

// The C5 effect a payment spend carries: a non_idempotent_write. A charge is value-bearing and not
// safely repeatable, which is why it is spent single-use through the §7 ledger.
export const CHARGE_EFFECT = policy.NON_IDEMPOTENT_WRITE;

// Payment format codes (design §24; the closed payment-format registry). A code outside the closed set
// is rejected (UnknownPaymentFormat).
export const FORMAT_AP2_MANDATE = 1; // AP2 mandate
export const FORMAT_ACP_TOKEN = 2;   // Agentic Commerce Protocol delegated token
export const FORMAT_X402 = 3;        // x402 payload

const FORMAT_NAMES = new Map([
  [FORMAT_AP2_MANDATE, 'ap2-mandate'],
  [FORMAT_ACP_TOKEN, 'acp-delegated-token'],
  [FORMAT_X402, 'x402-payload'],
]);

// Whether code is one of the closed payment formats.
export function isRegisteredFormat(code) {
  return FORMAT_NAMES.has(Number(code));
}

// The registry name of a format code, or 'unknown'.
export function formatName(code) {
  return FORMAT_NAMES.get(Number(code)) ?? 'unknown';
}

// A named, fail-closed payment error; .kind is the stable error kind (§15).
export class PayError extends Error {
  constructor(kind, msg = '') {
    super(msg ? `${kind}: ${msg}` : kind);
    this.kind = kind;
  }
}

// SHA-384 over a body -- a 48-octet digest.
function headOf(b) {
  return sha384(b);
}

// Wraps a foreign payment payload as a value-bearing charge. Format selects the imported format
// (closed registry); Amount/Currency/Payee/NotAfter are the bound charge terms; Foreign is the
// imported payload carried octet-for-octet (carriage, not adoption).
export class PaymentImport {
  constructor(format, amount, currency, payee, notAfter, foreign) {
    this.format = format;
    this.amount = amount;            // may exceed 2^53 -- carried through BigInt at encode time
    this.currency = currency;
    this.payee = Uint8Array.from(payee);
    this.not_after = notAfter;
    this.foreign = Uint8Array.from(foreign);
  }

  // Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new U(this.format)],
      [new U(2), new U(this.amount)],
      [new U(3), new T(this.currency)],
      [new U(4), new B(this.payee)],
      [new U(5), new U(this.not_after)],
      [new U(6), new B(this.foreign)],
    ]));
  }

  // The SHA-384 head (48 octets).
  head() {
    return headOf(this.bytes());
  }

  // The T1 content-id (50 octets): multihash(0x20, SHA-384(body)).
  id() {
    return cbor.contentId(this.bytes());
  }

  // The T1 content-id of the carried foreign payload -- the hash the charge binding binds (the
  // carriage binding). A substituted payload yields a different foreignId.
  foreignId() {
    return cbor.contentId(this.foreign);
  }

  // The exact charge value an approval binds for this import (amount + currency + payee + expiry + the
  // foreign payload's content id). A change to any bound term -- including the foreign payload --
  // changes the binding's content id.
  chargeBinding() {
    return new ChargeBinding(this.format, this.amount, this.currency, this.payee, this.not_after, this.foreignId());
  }
}

// Names the exact charge by value: format, amount, currency, payee, expiry, and the foreign payload's
// content id. A §7 approval binds THIS binding's content id, so a change to any bound term invalidates
// a prior approval (ApprovalMismatch).
export class ChargeBinding {
  constructor(format, amount, currency, payee, notAfter, foreignId) {
    this.format = format;
    this.amount = amount;
    this.currency = currency;
    this.payee = Uint8Array.from(payee);
    this.not_after = notAfter;
    this.foreignId = Uint8Array.from(foreignId); // content-id of the foreign payload
  }

  // Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
  // 6: foreign_id}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new U(this.format)],
      [new U(2), new U(this.amount)],
      [new U(3), new T(this.currency)],
      [new U(4), new B(this.payee)],
      [new U(5), new U(this.not_after)],
      [new U(6), new B(this.foreignId)],
    ]));
  }

  // The SHA-384 head (48 octets).
  head() {
    return headOf(this.bytes());
  }

  // The charge content id an approval binds: multihash(0x20, SHA-384(binding)).
  contentId() {
    return cbor.contentId(this.bytes());
  }
}

// Return the value of map key k if it is present with type typ, else null.
function fieldOf(m, k, typ) {
  for (const [key, val] of m.pairs) {
    if (key instanceof U && key.v === BigInt(k)) {
      return val instanceof typ ? val : null;
    }
  }
  return null;
}

// Reconstruct a PaymentImport from its body bytes alone. Does NOT validate the format against the
// closed set (that is verifyPaymentImport's job), so an import carrying an unknown format can be
// represented (then rejected). Fail-closed on a malformed shape or a non-canonical encoding.
export function parsePaymentImport(b) {
  let v;
  try {
    v = cbor.decode(b); // the strict decoder rejects a non-canonical body (NonCanonical)
  } catch (e) {
    if (e instanceof cbor.NonCanonical) {
      throw new PayError('PayMalformed', 'non-canonical payment-import body: ' + e.message);
    }
    throw e;
  }
  if (!(v instanceof M)) throw new PayError('PayMalformed', 'payment import is not a map');
  const fmt = fieldOf(v, 1, U);
  const amt = fieldOf(v, 2, U);
  const cur = fieldOf(v, 3, T);
  const payee = fieldOf(v, 4, B);
  const na = fieldOf(v, 5, U);
  const foreign = fieldOf(v, 6, B);
  if (fmt === null || amt === null || cur === null || payee === null || na === null || foreign === null) {
    throw new PayError('PayMalformed', 'object is not a well-formed N-AALP payment-import body');
  }
  return new PaymentImport(fmt.v, amt.v, cur.v, payee.v, na.v, foreign.v);
}

// ---- signed import (bare {1:alg} COSE_Sign1, as the reference's cose.Sign1) --------------------

// The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int).
function protectedHeader(alg) {
  return cbor.encode(new M([[new U(1), new N(alg)]]));
}

function algFromProtected(prot) {
  const v = cbor.decode(prot);
  if (!(v instanceof M)) throw new PayError('PayMalformed', 'protected header is not a map');
  for (const [k, val] of v.pairs) {
    if (k instanceof U && k.v === 1n && (val instanceof N || val instanceof U)) return Number(val.v);
  }
  throw new PayError('PayMalformed', 'protected header has no alg');
}

// Produce the tagged COSE_Sign1 object over the PaymentImport body with a real deterministic ML-DSA
// key derived from seed.
export function signPaymentImport(p, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), p.bytes());
}

// Verify the import's full signature under the profile, reconstruct it from the signed body bytes, and
// validate the format against the closed registry. Check order (fail-closed): PayMalformed ->
// UnknownAlg -> ProfileDowngrade -> KeyAlgMismatch -> BadSignature -> parse -> UnknownPaymentFormat.
// Returns the PaymentImport on success.
export function verifyPaymentImport(obj, profile, alg, pubkey) {
  let prot;
  let payload;
  let sig;
  try {
    [prot, payload, sig] = cose.parseSign1Raw(obj);
  } catch (e) {
    throw new PayError('PayMalformed', 'not a tagged COSE_Sign1: ' + e.message);
  }
  const halg = algFromProtected(prot);
  const [level, known] = cose.algLevel(halg);
  if (!known) throw new PayError('UnknownAlg', 'algorithm id not in the N-AALP registry');
  if (level < cose.profileMinLevel(profile)) {
    throw new PayError('ProfileDowngrade', 'signature level below the profile minimum');
  }
  if (halg !== Number(alg)) {
    throw new PayError('KeyAlgMismatch', 'key algorithm does not match object header');
  }
  const tbs = cose.toBeSignedRaw(prot, payload);
  if (!cose.coseVerify1Raw(halg, pubkey, tbs, sig)) {
    throw new PayError('BadSignature', 'signature verification failed');
  }
  const p = parsePaymentImport(payload);
  if (!isRegisteredFormat(p.format)) {
    throw new PayError('UnknownPaymentFormat', 'payment import selects a format outside the closed payment-format registry');
  }
  return p;
}

// ---- authorizeCharge: the per-charge approval gate (reuses §7 approval + consume ledger) -------

// Enforces the value-bearing rule for an imported payment, reusing naalp/approval's ApprovalRecord,
// verifyApproval, and the single-use consume Ledger UNCHANGED (impl/go/payment.go:241 is the authority;
// impl/rust/src/payment.rs::authorize_charge is the second cross-check). The approval MUST bind the
// EXACT charge binding content id (format + amount + currency + payee + expiry + foreign_id) -- so it
// satisfies neither a different amount/payee/currency nor a substituted foreign payload
// (ApprovalMismatch, from naalp/approval) -- its granted effect must cover this charge's CHARGE_EFFECT
// (a non_idempotent_write), it must be unexpired at `now`, and it is consumed single-use by `by`
// through the §7 ledger. Precedence and fail-closed behaviour mirror the reference: an unknown format
// denies first (no ledger append); a non-matching/expired/badly-signed approval denies next
// (ApprovalMismatch / ApprovalExpired / BadSignature, propagated from approval.verifyApproval); an
// under-granting approval denies ApprovalRequired; an already-spent approval denies AlreadyConsumed
// (propagated from Ledger.consume); the consume is the ONLY state change and happens only when every
// prior check holds. Returns the ledger entry (approval.LedgerEntry) on success.
//
//   p          - the PaymentImport being charged.
//   appr       - the approval.ApprovalRecord presented for this charge.
//   approverAlg, approverPk - the approver's verifier (matching approval.verifyApproval's signature).
//   apprSig    - the approval's signature bytes.
//   by         - the consuming signer id (the ledger entry's `by`).
//   now        - the ordering-authority time/position the approval's expiry is judged against.
//   ledger     - the approval.Ledger (or a signed ledger) the charge is consumed through.
export function authorizeCharge(p, appr, approverAlg, approverPk, apprSig, by, now, ledger) {
  if (!isRegisteredFormat(p.format)) {
    // an unknown imported format is not chargeable, fail-closed -- no ledger append
    throw new PayError('UnknownPaymentFormat', 'payment import selects a format outside the closed payment-format registry');
  }
  const chargeCID = p.chargeBinding().contentId();
  // ApprovalMismatch (wrong amount/payee/currency/payload) / ApprovalExpired / BadSignature
  approval.verifyApproval(appr, approverAlg, approverPk, apprSig, chargeCID, now);
  if (!policy.authorizes(appr.grant, CHARGE_EFFECT)) {
    // the approval's granted effect does not cover the charge
    throw new PayError('ApprovalRequired', 'action requires an approval that is not present');
  }
  // AlreadyConsumed on replay (single-use, no double-spend) -- the ONLY state change
  return ledger.consume(appr.id(), by);
}
