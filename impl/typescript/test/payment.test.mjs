// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C21 (5B.1) NAALP-PAY payment-import conformance for the TypeScript SDK, graded against the shared
// independent corpus vectors/payment/cases.json (NOT produced by this code): the closed payment-format
// registry, the byte-exact PaymentImport body/head/content-id (incl. the oversized >2^53 amount and
// the minimal import), the foreign-payload content id (carriage binding), the byte-exact ChargeBinding
// body/head/content-id, the parse round-trip, the fail-closed edge cases (non-canonical -> NonCanonical
// / PayMalformed, absent mandatory field -> PayMalformed, a bstr-currency look-alike -> PayMalformed,
// empty vs populated foreign distinct by content-id), and the mismatch content-ids (a wrong amount,
// wrong payee, or substituted foreign payload yields a DIFFERENT charge content-id).
//
// The PaymentImport SIGNATURE is real deterministic ML-DSA-65 via a bare-{1:alg} COSE_Sign1 (as the
// reference's cose.Sign1); the corpus carries no signed vector for this channel, so sign/verify is
// demonstrated in isolation only -- stated honestly, not corpus-graded.
//
// authorizeCharge (STEP-2 parity wave) composes naalp/approval's ApprovalRecord / verifyApproval /
// Ledger.consume and naalp/policy's authorizes, ported from impl/go/payment.go:241 AuthorizeCharge
// (impl/rust/src/payment.rs::authorize_charge as the second cross-check). It is corpus-graded for the
// charge-binding content ids (the mismatch cases below) and isolation-graded (real ML-DSA + a real WAL
// ledger, not corpus-vectored) for the single-use/replay and approval-verification behaviour, mirroring
// impl/go/payment/payment_test.go::TestChargeSingleUseAndBinding /
// TestPaymentImportMultiUseMutation.
//
// Written test-first; the payment module is absent until ported, so this fails RED on import until
// impl/typescript/naalp/payment.mjs lands, and a mutation forcing the ChargeBinding amount field to a
// constant flips 'payment charge-binding ids match the oracle'.
//
// Run:  node --test test/payment.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as policy from '../naalp/policy.mjs';
import * as approval from '../naalp/approval.mjs';
import * as payment from '../naalp/payment.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'payment', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/payment/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

const ALG = cose.ALG_MLDSA65;
const SEED = new Uint8Array(32);
const PK = cose.mldsaKeygen('ML-DSA-65', SEED);

function importFrom(iv) {
  return new payment.PaymentImport(
    iv.format, iv.amount, iv.currency, hexToBytes(iv.payee_hex), iv.not_after, hexToBytes(iv.foreign_hex));
}

// ---- closed payment-format registry (design §24) --------------------------------------

test('payment format vocabulary', () => {
  for (const fv of C.format_vocabulary) {
    assert.equal(payment.isRegisteredFormat(fv.code), true, fv.name);
    assert.equal(payment.formatName(fv.code), fv.name);
  }
  assert.equal(payment.isRegisteredFormat(C.unknown_format), false);
  assert.equal(payment.formatName(C.unknown_format), 'unknown');
});

test('payment charge effect', () => {
  // A payment spend is a non_idempotent_write (the value-bearing rule).
  assert.equal(payment.CHARGE_EFFECT, C.charge_effect);
  assert.equal(payment.CHARGE_EFFECT, policy.NON_IDEMPOTENT_WRITE);
});

// ---- PaymentImport byte parity (design §24) -------------------------------------------

test('payment import bodies match the oracle', () => {
  for (const name of ['ap2', 'acp', 'x402']) {
    const iv = C.imports[name];
    const p = importFrom(iv);
    assert.equal(bytesToHex(p.bytes()), iv.body_hex, name);
    assert.equal(bytesToHex(p.head()), iv.head_hex, name);
    assert.equal(bytesToHex(p.id()), iv.id_hex, name);
    assert.equal(bytesToHex(p.foreignId()), iv.foreign_id_hex, name);
  }
});

test('payment charge-binding ids match the oracle', () => {
  // THIS is the mutation-target assertion: the exact charge value a §7 approval binds.
  for (const name of ['ap2', 'acp', 'x402']) {
    const iv = C.imports[name];
    const cb = importFrom(iv).chargeBinding();
    assert.equal(bytesToHex(cb.bytes()), iv.charge_binding.body_hex, name);
    assert.equal(bytesToHex(cb.head()), iv.charge_binding.head_hex, name);
    assert.equal(bytesToHex(cb.contentId()), iv.charge_binding.id_hex, name);
  }
});

test('payment big amount over 2^53 round-trips', () => {
  const bv = C.big_amount;
  const amount = BigInt(bv.amount_str); // 72623859790382856 > 2^53, exact (BigInt)
  assert.equal(amount > 2n ** 53n, true);
  const p = new payment.PaymentImport(bv.format, amount, bv.currency, hexToBytes(bv.payee_hex), bv.not_after, hexToBytes(bv.foreign_hex));
  assert.equal(bytesToHex(p.bytes()), bv.body_hex);
  assert.equal(bytesToHex(p.head()), bv.head_hex);
  assert.equal(bytesToHex(p.id()), bv.id_hex);
  const cb = p.chargeBinding();
  assert.equal(bytesToHex(cb.contentId()), bv.charge_binding.id_hex);
  // and the parsed amount round-trips byte-exact through the strict decoder
  const rp = payment.parsePaymentImport(hexToBytes(bv.body_hex));
  assert.equal(BigInt(rp.amount), amount);
});

test('payment minimal import', () => {
  const m = C.minimal;
  const p = new payment.PaymentImport(m.format, m.amount, m.currency, hexToBytes(m.payee_hex), m.not_after, hexToBytes(m.foreign_hex));
  assert.equal(bytesToHex(p.bytes()), m.body_hex);
  assert.equal(bytesToHex(p.head()), m.head_hex);
  assert.equal(bytesToHex(p.id()), m.id_hex);
});

// ---- parse round-trip + fail-closed edges (design §24, §15) ---------------------------

test('payment parse round-trips', () => {
  for (const name of ['ap2', 'acp', 'x402']) {
    const iv = C.imports[name];
    const p = payment.parsePaymentImport(hexToBytes(iv.body_hex));
    assert.equal(Number(p.format), iv.format, name);
    assert.equal(Number(p.amount), iv.amount, name);
    assert.equal(p.currency, iv.currency, name);
    assert.equal(bytesToHex(p.payee), iv.payee_hex, name);
    assert.equal(Number(p.not_after), iv.not_after, name);
    assert.equal(bytesToHex(p.foreign), iv.foreign_hex, name);
  }
});

test('payment rejects a non-canonical body', () => {
  const ec = C.edge_cases.keys_out_of_order;
  assert.throws(() => cbor.decode(hexToBytes(ec.noncanonical_body_hex)), (e) => e.kind === 'NonCanonical');
  assert.throws(() => payment.parsePaymentImport(hexToBytes(ec.noncanonical_body_hex)), (e) => e.kind === 'PayMalformed');
  // the canonical form of the same content parses
  const p = payment.parsePaymentImport(hexToBytes(ec.canonical_body_hex));
  assert.equal(Number(p.format), ec.format);
});

test('payment distinguishes empty from absent foreign', () => {
  const ev = C.edge_cases.empty_vs_absent;
  const empty = payment.parsePaymentImport(hexToBytes(ev.empty_foreign.body_hex));
  assert.equal(bytesToHex(empty.foreign), '');
  assert.equal(bytesToHex(empty.id()), ev.empty_foreign.id_hex);
  assert.equal(bytesToHex(empty.foreignId()), ev.empty_foreign.foreign_id_hex);
  const populated = payment.parsePaymentImport(hexToBytes(ev.populated_foreign.body_hex));
  assert.equal(bytesToHex(populated.id()), ev.populated_foreign.id_hex);
  assert.equal(bytesToHex(populated.foreignId()), ev.populated_foreign.foreign_id_hex);
  // an empty foreign payload is present and valid, distinct by content-id from a populated one
  assert.notEqual(bytesToHex(empty.id()), bytesToHex(populated.id()));
  assert.notEqual(bytesToHex(empty.foreignId()), bytesToHex(populated.foreignId()));
  // field 6 (foreign) is mandatory: a body missing it is rejected fail-closed
  assert.throws(() => payment.parsePaymentImport(hexToBytes(ev.absent_field.body_hex)), (e) => e.kind === ev.absent_field.reject);
});

test('payment rejects a look-alike', () => {
  const la = C.edge_cases.look_alike;
  assert.throws(() => payment.parsePaymentImport(hexToBytes(la.body_hex)), (e) => e.kind === la.reject);
});

// ---- the binding property: a changed charge is a different content-id -----------------

test('payment charge-binding mismatch ids', () => {
  const baseIv = C.imports.ap2;
  const base = importFrom(baseIv);
  const baseId = bytesToHex(base.chargeBinding().contentId());
  assert.equal(baseId, baseIv.charge_binding.id_hex);
  const mm = C.mismatch;

  const wrongAmount = new payment.PaymentImport(base.format, Number(base.amount) + 8000, base.currency, base.payee, base.not_after, base.foreign);
  assert.equal(bytesToHex(wrongAmount.chargeBinding().contentId()), mm.wrong_amount_charge_id_hex);

  const wrongPayee = new payment.PaymentImport(base.format, base.amount, base.currency, Uint8Array.from(Buffer.from('merchant:evil-store')), base.not_after, base.foreign);
  assert.equal(bytesToHex(wrongPayee.chargeBinding().contentId()), mm.wrong_payee_charge_id_hex);

  const substituted = new payment.PaymentImport(base.format, base.amount, base.currency, base.payee, base.not_after, hexToBytes(mm.substituted_foreign_hex));
  assert.equal(bytesToHex(substituted.foreignId()), mm.substituted_foreign_id_hex);
  assert.equal(bytesToHex(substituted.chargeBinding().contentId()), mm.substituted_charge_id_hex);

  for (const other of [mm.wrong_amount_charge_id_hex, mm.wrong_payee_charge_id_hex, mm.substituted_charge_id_hex]) {
    assert.notEqual(baseId, other, 'a changed charge must not match the bound one');
  }
});

// ---- signed import round-trip in isolation (design §24) -------------------------------

test('payment sign/verify import in isolation', () => {
  // NOT corpus-graded (no signed vector). Real deterministic ML-DSA-65 via a bare COSE_Sign1.
  const iv = C.imports.ap2;
  const p = importFrom(iv);
  const obj = payment.signPaymentImport(p, ALG, SEED);
  const got = payment.verifyPaymentImport(obj, cose.PROFILE_PUBLIC, ALG, PK);
  assert.equal(Number(got.format), Number(p.format));
  assert.equal(Number(got.amount), Number(p.amount));
  assert.equal(got.currency, p.currency);
  assert.equal(bytesToHex(got.payee), bytesToHex(p.payee));
  assert.equal(Number(got.not_after), Number(p.not_after));
  assert.equal(bytesToHex(got.foreign), bytesToHex(p.foreign));
  // tampered signature -> BadSignature
  const bad = Uint8Array.from(obj);
  bad[bad.length - 1] ^= 1;
  assert.throws(() => payment.verifyPaymentImport(bad, cose.PROFILE_PUBLIC, ALG, PK), (e) => e.kind === 'BadSignature');
  // an unknown imported format is not chargeable -> UnknownPaymentFormat
  const badFmt = new payment.PaymentImport(C.unknown_format, 1, 'USD', Uint8Array.from(Buffer.from('x')), 1, new Uint8Array(0));
  const badObj = payment.signPaymentImport(badFmt, ALG, SEED);
  assert.throws(() => payment.verifyPaymentImport(badObj, cose.PROFILE_PUBLIC, ALG, PK), (e) => e.kind === 'UnknownPaymentFormat');
});

// ---- authorizeCharge: single-use spend + exact binding (design §24; impl/go/payment.go:241) ------
//
// Mirrors impl/go/payment/payment_test.go::TestChargeSingleUseAndBinding / mkApproval / freshLedger.
// Isolation-graded (real deterministic ML-DSA-65 + a real WAL-backed approval.Ledger), not corpus-
// vectored for the approval/consume flow itself; the charge-binding content ids it exercises ARE
// corpus-graded (vectors/payment/cases.json `mismatch`).

const APPROVER_SEED = new Uint8Array(32).fill(0x11);
const APPROVER_PK = cose.mldsaKeygen('ML-DSA-65', APPROVER_SEED);
const FOREIGN_SEED = new Uint8Array(32).fill(0x22);
const FOREIGN_PK = cose.mldsaKeygen('ML-DSA-65', FOREIGN_SEED);

// Runs fn(ledgerPath) against a fresh temp-directory WAL, cleaning up afterward (mirrors approval.test.mjs).
function withTempLedger(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'naalp-payment-'));
  const path = join(dir, 'charge.wal');
  try {
    return fn(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Builds and signs a §7 approval binding chargeCID at grant `grant` (mirrors Go's mkApproval).
function mkApproval(chargeCID, approver, grant, nonceByte, notAfter, alg, seed) {
  const nonce = new Uint8Array(16).fill(nonceByte);
  const a = new approval.ApprovalRecord(chargeCID, approver, grant, nonce, notAfter);
  const sig = approval.signApproval(a, alg, seed);
  return [a, sig];
}

test('authorizeCharge: honest charge is authorized and consumed exactly once at seq 0', () => {
  const pi = importFrom(C.imports.ap2);
  const chargeCID = pi.chargeBinding().contentId();
  const [appr, apprSig] = mkApproval(chargeCID, 'approver-A', payment.CHARGE_EFFECT, 0x01, pi.not_after, ALG, APPROVER_SEED);
  withTempLedger((path) => {
    const ledger = approval.openLedger(path);
    try {
      const entry = payment.authorizeCharge(pi, appr, ALG, APPROVER_PK, apprSig, 'payer-1', pi.not_after, ledger);
      assert.notEqual(entry, null, 'AuthorizeCharge (honest) must return a ledger entry');
      assert.equal(Number(entry.seq), 0, 'first charge did not consume at seq 0');
      assert.equal(ledger.len(), 1);
    } finally {
      ledger.close();
    }
  });
});

test('authorizeCharge: a replayed charge is AlreadyConsumed with no double-spend [MUTATION ANCHOR]', () => {
  // The single-use security property: the FIRST charge consumes; every later charge for the SAME
  // approval is rejected AlreadyConsumed with NO second ledger append. Red-evidence mutation target:
  // neutering ledger.Consume() (skipping the AlreadyConsumed guard, or dropping the consume call
  // entirely) makes this flip GREEN wrongly (the replay would be silently authorized) -- see the
  // mutation-anchor test below for the load-bearing proof in isolation.
  const pi = importFrom(C.imports.ap2);
  const chargeCID = pi.chargeBinding().contentId();
  const [appr, apprSig] = mkApproval(chargeCID, 'approver-A', payment.CHARGE_EFFECT, 0x01, pi.not_after, ALG, APPROVER_SEED);
  withTempLedger((path) => {
    const ledger = approval.openLedger(path);
    try {
      payment.authorizeCharge(pi, appr, ALG, APPROVER_PK, apprSig, 'payer-1', pi.not_after, ledger);
      assert.throws(
        () => payment.authorizeCharge(pi, appr, ALG, APPROVER_PK, apprSig, 'payer-1', pi.not_after, ledger),
        (e) => e.kind === 'AlreadyConsumed', 'replayed charge must be AlreadyConsumed');
      assert.equal(ledger.len(), 1, 'ledger has more than 1 entry after a rejected replay (double-spend)');
    } finally {
      ledger.close();
    }
  });
});

test('authorizeCharge denies ApprovalMismatch: wrong amount, wrong payee, and a substituted foreign payload', () => {
  const pi = importFrom(C.imports.ap2);
  const chargeCID = pi.chargeBinding().contentId();
  const [appr, apprSig] = mkApproval(chargeCID, 'approver-A', payment.CHARGE_EFFECT, 0x01, pi.not_after, ALG, APPROVER_SEED);
  const mm = C.mismatch;

  // A wrong-amount charge yields a different charge content-id, so the approval no longer matches.
  const wrongAmount = new payment.PaymentImport(pi.format, Number(pi.amount) + 8000, pi.currency, pi.payee, pi.not_after, pi.foreign);
  assert.equal(bytesToHex(wrongAmount.chargeBinding().contentId()), mm.wrong_amount_charge_id_hex);
  withTempLedger((path) => {
    const ledger = approval.openLedger(path);
    try {
      assert.throws(
        () => payment.authorizeCharge(wrongAmount, appr, ALG, APPROVER_PK, apprSig, 'payer-1', pi.not_after, ledger),
        (e) => e.kind === 'ApprovalMismatch', 'wrong-amount charge must be ApprovalMismatch');
      assert.equal(ledger.len(), 0, 'no ledger append on a denied charge');
    } finally {
      ledger.close();
    }
  });

  // A wrong-payee charge likewise fails the binding.
  const wrongPayee = new payment.PaymentImport(
    pi.format, pi.amount, pi.currency, Uint8Array.from(Buffer.from('merchant:evil-store')), pi.not_after, pi.foreign);
  assert.equal(bytesToHex(wrongPayee.chargeBinding().contentId()), mm.wrong_payee_charge_id_hex);
  withTempLedger((path) => {
    const ledger = approval.openLedger(path);
    try {
      assert.throws(
        () => payment.authorizeCharge(wrongPayee, appr, ALG, APPROVER_PK, apprSig, 'payer-1', pi.not_after, ledger),
        (e) => e.kind === 'ApprovalMismatch', 'wrong-payee charge must be ApprovalMismatch');
    } finally {
      ledger.close();
    }
  });

  // A substituted foreign payload changes the foreign content-id, hence the charge binding.
  const substituted = new payment.PaymentImport(
    pi.format, pi.amount, pi.currency, pi.payee, pi.not_after, hexToBytes(mm.substituted_foreign_hex));
  assert.equal(bytesToHex(substituted.foreignId()), mm.substituted_foreign_id_hex);
  assert.equal(bytesToHex(substituted.chargeBinding().contentId()), mm.substituted_charge_id_hex);
  withTempLedger((path) => {
    const ledger = approval.openLedger(path);
    try {
      assert.throws(
        () => payment.authorizeCharge(substituted, appr, ALG, APPROVER_PK, apprSig, 'payer-1', pi.not_after, ledger),
        (e) => e.kind === 'ApprovalMismatch', 'substituted-payload charge must be ApprovalMismatch');
    } finally {
      ledger.close();
    }
  });
});

test('authorizeCharge denies BadSignature: a foreign key never authenticates the approval', () => {
  const pi = importFrom(C.imports.ap2);
  const chargeCID = pi.chargeBinding().contentId();
  const [appr, apprSig] = mkApproval(chargeCID, 'approver-A', payment.CHARGE_EFFECT, 0x01, pi.not_after, ALG, APPROVER_SEED);
  withTempLedger((path) => {
    const ledger = approval.openLedger(path);
    try {
      assert.throws(
        () => payment.authorizeCharge(pi, appr, ALG, FOREIGN_PK, apprSig, 'payer-1', pi.not_after, ledger),
        (e) => e.kind === 'BadSignature', 'foreign-key charge must be BadSignature');
      assert.equal(ledger.len(), 0);
    } finally {
      ledger.close();
    }
  });
});

test('authorizeCharge denies ApprovalExpired at posTime past not_after', () => {
  const pi = importFrom(C.imports.ap2);
  const chargeCID = pi.chargeBinding().contentId();
  const [appr, apprSig] = mkApproval(chargeCID, 'approver-A', payment.CHARGE_EFFECT, 0x01, pi.not_after, ALG, APPROVER_SEED);
  withTempLedger((path) => {
    const ledger = approval.openLedger(path);
    try {
      assert.throws(
        () => payment.authorizeCharge(pi, appr, ALG, APPROVER_PK, apprSig, 'payer-1', Number(pi.not_after) + 1, ledger),
        (e) => e.kind === 'ApprovalExpired', 'expired charge must be ApprovalExpired');
      assert.equal(ledger.len(), 0);
    } finally {
      ledger.close();
    }
  });
});

test('authorizeCharge denies ApprovalRequired: an under-granting approval cannot authorize a non_idempotent_write charge [MUTATION ANCHOR]', () => {
  // read_only (0) does not cover CHARGE_EFFECT (non_idempotent_write, 2) under the §6.1 lattice
  // (action <= ceiling). Red-evidence mutation target: neutering this effect-coverage check (e.g.
  // always treating the effect as authorized) flips this test GREEN-to-RED-then-back wrongly.
  const pi = importFrom(C.imports.ap2);
  const underCID = pi.chargeBinding().contentId();
  const [underAppr, underSig] = mkApproval(underCID, 'approver-A', policy.READ_ONLY, 0x03, pi.not_after, ALG, APPROVER_SEED);
  withTempLedger((path) => {
    const ledger = approval.openLedger(path);
    try {
      assert.throws(
        () => payment.authorizeCharge(pi, underAppr, ALG, APPROVER_PK, underSig, 'payer-1', pi.not_after, ledger),
        (e) => e.kind === 'ApprovalRequired', 'under-granting charge must be ApprovalRequired');
      assert.equal(ledger.len(), 0, 'no ledger append on a denied charge');
    } finally {
      ledger.close();
    }
  });
});

test('authorizeCharge denies UnknownPaymentFormat for an unregistered format (no ledger append)', () => {
  const pi = importFrom(C.imports.ap2);
  const chargeCID = pi.chargeBinding().contentId();
  const [appr, apprSig] = mkApproval(chargeCID, 'approver-A', payment.CHARGE_EFFECT, 0x01, pi.not_after, ALG, APPROVER_SEED);
  const unk = new payment.PaymentImport(C.unknown_format, pi.amount, pi.currency, pi.payee, pi.not_after, pi.foreign);
  withTempLedger((path) => {
    const ledger = approval.openLedger(path);
    try {
      assert.throws(
        () => payment.authorizeCharge(unk, appr, ALG, APPROVER_PK, apprSig, 'payer-1', pi.not_after, ledger),
        (e) => e.kind === 'UnknownPaymentFormat', 'unknown-format charge must be UnknownPaymentFormat');
      assert.equal(ledger.len(), 0, 'no ledger append on an unknown format');
    } finally {
      ledger.close();
    }
  });
});

test('authorizeCharge single-use is load-bearing: a mutant importer without ledger.consume treats the charge as multi-use', () => {
  // Mirrors impl/go/payment/payment_test.go::TestPaymentImportMultiUseMutation: proves in isolation
  // that ledger.consume() (used by the honest authorizeCharge) is the load-bearing single-use
  // guarantee, by constructing a mutant path that verifies the binding but never consumes -- and
  // showing IT wrongly authorizes the replay a second time, unlike the honest path above.
  const pi = importFrom(C.imports.ap2);
  const chargeCID = pi.chargeBinding().contentId();
  const [appr, apprSig] = mkApproval(chargeCID, 'approver-A', payment.CHARGE_EFFECT, 0x01, pi.not_after, ALG, APPROVER_SEED);

  // HONEST path: single-use through the ledger -- the replay is rejected.
  withTempLedger((path) => {
    const ledger = approval.openLedger(path);
    try {
      payment.authorizeCharge(pi, appr, ALG, APPROVER_PK, apprSig, 'payer-1', pi.not_after, ledger);
      assert.throws(
        () => payment.authorizeCharge(pi, appr, ALG, APPROVER_PK, apprSig, 'payer-1', pi.not_after, ledger),
        (e) => e.kind === 'AlreadyConsumed');
    } finally {
      ledger.close();
    }
  });

  // MUTANT importer: verifies the binding but treats the token as MULTI-USE (no ledger.consume call).
  // This is the bug the ledger prevents; the mutant wrongly authorizes the replay a second time.
  const mutantAuthorize = () => {
    approval.verifyApproval(appr, ALG, APPROVER_PK, apprSig, pi.chargeBinding().contentId(), pi.not_after);
    // no ledger.consume() -- multi-use bug
  };
  assert.doesNotThrow(() => mutantAuthorize(), 'mutant first charge must succeed');
  assert.doesNotThrow(() => mutantAuthorize(),
    'mutant replay unexpectedly rejected: the multi-use bug must reproduce, proving ledger.consume is the single-use guarantee');
});
