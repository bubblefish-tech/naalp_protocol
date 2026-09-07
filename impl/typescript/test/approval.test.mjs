// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C6 approval conformance for the TypeScript SDK, graded against the shared independent corpus
// vectors/approval/cases.json (NOT produced by this code): the §7.1 approval object body + content
// id (byte-for-byte), the §7.2 durable hash-chained consume ledger (genesis + per-entry body +
// head_after + final head), the single-use ATOMIC consume (AlreadyConsumed replay guard, exactly
// once), ApprovalMismatch / ApprovalExpired, and fail-closed ledger-chain integrity (LedgerCorrupt).
//
// The approval SIGNATURE is real deterministic ML-DSA-65 (@noble/post-quantum, rnd=0) over the body
// bytes directly, but the corpus carries no signature vector for this channel, so sign/verify is
// demonstrated in isolation with a fixed local seed -- stated honestly, not corpus-graded. Every
// byte-exact assertion (record/entry/head) and every ledger verdict IS corpus-graded.
//
// Written test-first; the approval module is absent until ported, so this fails RED on import until
// impl/typescript/naalp/approval.mjs lands, and the mutation "consume always-succeeds (drop the
// AlreadyConsumed guard)" flips 'approval consume rejects a replay (single-use skeleton-key guard)'.
//
// Run:  node --test test/approval.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as approval from '../naalp/approval.mjs';
import * as policy from '../naalp/policy.mjs';

function findVectorFile(name) {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', name, 'cases.json');
    if (existsSync(p)) return p;
    d = dirname(d);
  }
  throw new Error(`vectors/${name}/cases.json not found`);
}

function vectors() {
  return JSON.parse(readFileSync(findVectorFile('approval'), 'utf-8'));
}

// The R-TDCS wire additions (audience §25/R-TDCS-5, refusal §25/R-TDCS-3) graded against the shared
// independent oracle vectors/trust_decision/cases.json (built by tools/trust_decision_oracle.py).
function loadTDCS() {
  return JSON.parse(readFileSync(findVectorFile('trust_decision'), 'utf-8'));
}

// T1.5 (NAALP-REQ-121) ledger-signed consume receipt vectors. Quote every bare `"position": <int>`
// literal before JSON.parse so a 64-bit forward-only ledger position (up to 2^64-1, beyond
// Number.MAX_SAFE_INTEGER = 2^53-1) round-trips EXACTLY as a string -> BigInt, never a
// precision-losing float64 (JS's JSON.parse always converts bare numbers to float64).
function loadConsumeReceipt() {
  const text = readFileSync(findVectorFile('consume_receipt'), 'utf-8');
  const patched = text.replace(/"position":\s*(-?\d+)/g, '"position":"$1"');
  return JSON.parse(patched);
}

// A deterministic ML-DSA-65 key derived from a fixed seed byte, for ledger/party identities in the
// R-TDCS-4 and T1.5 isolation tests (the corpus carries no signed vector for these real keys).
function ledgerKey(seedByte) {
  const seed = new Uint8Array(32).fill(seedByte);
  const pk = cose.mldsaKeygen('ML-DSA-65', seed);
  return { alg: ALG, seed, pk };
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

const ALG = cose.ALG_MLDSA65;
const SEED = new Uint8Array(32);                 // the approver's deterministic ML-DSA seed
const PK = cose.mldsaKeygen('ML-DSA-65', SEED);  // the approver's public key
const ARGS_CID = hexToBytes(C.args.content_id_hex);

function recordOf(av) {
  return new approval.ApprovalRecord(
    hexToBytes(av.approves_hex), av.approver, av.grant, hexToBytes(av.nonce_hex), av.not_after);
}

function withTempLedger(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'naalp-approval-'));
  const path = join(dir, 'consume.wal');
  try {
    return fn(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ---- §7.1 the approval object body (byte-graded) --------------------------------------

test('approval record body + content id match the oracle byte-for-byte', () => {
  // THIS is a mutation-target assertion: the encoder must emit {1:approves,2:approver,3:grant,
  // 4:nonce,5:not_after} exactly; a constant/field-ignoring encoder diverges from the pinned hex,
  // and the content id (multihash over the body) flips with it.
  assert.ok(C.approvals.length >= 2, 'need at least two approval vectors');
  for (const av of C.approvals) {
    const rec = recordOf(av);
    assert.equal(bytesToHex(rec.bytes()), av.record_hex, `approval ${av.name} body`);
    assert.equal(bytesToHex(rec.id()), av.approval_id_hex, `approval ${av.name} id`);
  }
});

// ---- §7.2 the durable hash-chained consume ledger (byte-graded) -----------------------

test('approval consume ledger reproduces the oracle chain byte-for-byte', () => {
  withTempLedger((path) => {
    const led = approval.openLedger(path);
    try {
      assert.equal(bytesToHex(led.head()), C.ledger.genesis_head_hex, 'genesis head is 48 zero bytes');
      for (const cv of C.ledger.consumes) {
        const aid = hexToBytes(cv.approval_id_hex);
        if (cv.expect === 'ok') {
          const e = led.consume(aid, cv.by);
          assert.equal(bytesToHex(e.bytes()), cv.entry_hex, `entry body seq=${cv.seq}`);
          assert.equal(Number(e.seq), cv.seq, `entry seq=${cv.seq}`);
          assert.equal(bytesToHex(e.head()), cv.head_after_hex, `entry head_after seq=${cv.seq}`);
          assert.equal(bytesToHex(led.head()), cv.head_after_hex, `ledger head after seq=${cv.seq}`);
        } else {
          assert.throws(() => led.consume(aid, cv.by), (er) => er.kind === cv.expect,
            `consume expected ${cv.expect}`);
        }
      }
      assert.equal(bytesToHex(led.head()), C.ledger.final_head_hex, 'final head matches the oracle');
      assert.equal(led.len(), 2, 'exactly two distinct approvals consumed');
    } finally {
      led.close();
    }
  });
});

// ---- the single-use security property (the skeleton-key guard) ------------------------

test('approval consume rejects a replay (single-use skeleton-key guard)', () => {
  // The bug this cap prevents: an approval consumable twice is a replay skeleton key. The FIRST
  // consume of an id wins; every later consume of the SAME id is rejected AlreadyConsumed with NO
  // ledger append and NO head change. MUTATION: making consume always-succeed (dropping the
  // AlreadyConsumed guard) flips this test on its assertion.
  withTempLedger((path) => {
    const led = approval.openLedger(path);
    try {
      const aid = hexToBytes(C.approvals[0].approval_id_hex);
      const first = led.consume(aid, C.approvals[0].approver);
      assert.notEqual(first, null, 'first consume wins');
      assert.equal(led.len(), 1);
      const headAfterFirst = bytesToHex(led.head());
      for (let i = 0; i < 5; i++) {
        assert.throws(() => led.consume(aid, 'thief:' + i), (e) => e.kind === 'AlreadyConsumed',
          'a second consume of the same approval id must be rejected AlreadyConsumed');
      }
      assert.equal(led.len(), 1, 'no ledger append on a rejected replay');
      assert.equal(bytesToHex(led.head()), headAfterFirst, 'ledger head unchanged after rejected replays');
      assert.equal(led.isConsumed(aid), true);
    } finally {
      led.close();
    }
  });
});

test('approval consume is exactly-once under many callers (single-writer, no TOCTOU)', () => {
  // JS is single-threaded and consume() performs its membership check AND its append in one
  // synchronous critical section with no intervening await, so there is no interleaving point --
  // the honest analogue of the Go reference's single-mutex atomicity. Among N contending callers
  // for one approval id, exactly ONE wins and the rest are AlreadyConsumed.
  withTempLedger((path) => {
    const led = approval.openLedger(path);
    try {
      const aid = hexToBytes(C.approvals[1].approval_id_hex);
      const N = 32;
      let won = 0;
      let rejected = 0;
      for (let i = 0; i < N; i++) {
        try {
          led.consume(aid, 'caller:' + i);
          won += 1;
        } catch (e) {
          assert.equal(e.kind, 'AlreadyConsumed');
          rejected += 1;
        }
      }
      assert.equal(won, 1, 'exactly one caller wins the compare-and-set');
      assert.equal(rejected, N - 1);
      assert.equal(led.len(), 1);
    } finally {
      led.close();
    }
  });
});

// ---- §7 verify: bind args by content id, fail closed (real ML-DSA, isolation) ---------

test('approval verifyApproval accepts a valid, in-window, matching approval (isolation)', () => {
  const av = C.approvals[0];
  const rec = recordOf(av);
  assert.equal(bytesToHex(rec.bytes()), av.record_hex); // sign the exact corpus bytes
  const sig = approval.signApproval(rec, ALG, SEED);
  // approves == the args content id, and valid_at (1000) == not_after (1000) is in-window.
  assert.equal(approval.verifyApproval(rec, ALG, PK, sig, ARGS_CID, C.expiry.valid_at), null);
});

test('approval verifyApproval fails closed: mismatch, expired, bad signature', () => {
  const av = C.approvals[0];
  const rec = recordOf(av);
  const sig = approval.signApproval(rec, ALG, SEED);

  // (1) ApprovalMismatch: a good signature but the approval does not bind THESE args' content id.
  assert.throws(
    () => approval.verifyApproval(rec, ALG, PK, sig, hexToBytes(C.mismatch.wrong_args_id_hex), C.expiry.valid_at),
    (e) => e.kind === 'ApprovalMismatch');

  // (2) ApprovalExpired: posTime 1001 is past not_after 1000.
  assert.throws(
    () => approval.verifyApproval(rec, ALG, PK, sig, ARGS_CID, C.expiry.expired_at),
    (e) => e.kind === 'ApprovalExpired');

  // (3) BadSignature: a tampered signature is rejected first, before any binding check.
  const bad = Uint8Array.from(sig);
  bad[bad.length - 1] ^= 1;
  assert.throws(
    () => approval.verifyApproval(rec, ALG, PK, bad, ARGS_CID, C.expiry.valid_at),
    (e) => e.kind === 'BadSignature');
});

// ---- §7.4 the held (not-yet-granted) outcome (isolation, not corpus-graded) -----------

test('approval held result body round-trips and is signable (isolation)', () => {
  // The corpus carries no held vector; this proves the §7.4 held outcome is a distinct, attributable,
  // deterministically-encoded signed object (never a silent success/denial), demonstrated in isolation.
  const h = new approval.HeldResult(ARGS_CID, 'awaiting human approval');
  const body = h.bytes();
  assert.ok(body.length > 0);
  const sig = approval.signHeld(h, ALG, SEED);
  assert.equal(cose.mldsaVerify(ALG, PK, body, sig), true);
  // A different reason yields distinct bytes (the body is parameter-sensitive, not a stub).
  const h2 = new approval.HeldResult(ARGS_CID, 'awaiting human approval!');
  assert.notEqual(bytesToHex(h2.bytes()), bytesToHex(body));
});

// ---- §7.2 fail-closed durable-chain integrity on replay (LedgerCorrupt) ---------------

test('approval ledger replay rejects a non-chaining log (LedgerCorrupt)', () => {
  // A durable log whose hash chain does not verify is refused rather than trusted: a second entry
  // whose `prev` does not link to the first entry's head is a broken chain. This proves the ledger
  // fails closed on a tampered/forked WAL (the durability half of §7.2), not merely on live replay.
  withTempLedger((path) => {
    const genesis = new Uint8Array(approval.HEAD_SIZE);
    const aidA = hexToBytes(C.approvals[0].approval_id_hex);
    const aidB = hexToBytes(C.approvals[1].approval_id_hex);
    const e0 = new approval.LedgerEntry(0, genesis, aidA, C.approvals[0].approver);
    // e1.prev is left at genesis (WRONG -- it must be head(e0)); seq is otherwise correct.
    const e1bad = new approval.LedgerEntry(1, genesis, aidB, C.approvals[1].approver);
    const frame = (rec) => {
      const lp = Buffer.alloc(4);
      lp.writeUInt32BE(rec.length, 0);
      return Buffer.concat([lp, Buffer.from(rec)]);
    };
    writeFileSync(path, Buffer.concat([frame(e0.bytes()), frame(e1bad.bytes())]));
    assert.throws(() => approval.openLedger(path), (e) => e.kind === 'LedgerCorrupt');
  });
});

// ---- R-TDCS-5 the optional audience binding (byte-graded) -----------------------------

test('approval audience byte-parity: present vs absent, and verifyAudience checks match/mismatch/absent', () => {
  const TD = loadTDCS();
  const a = TD.audience;
  for (const tc of a.cases) {
    const rec = new approval.ApprovalRecord(
      hexToBytes(a.approves_hex), a.approver, a.grant, hexToBytes(a.nonce_hex), a.not_after, tc.audience);
    assert.equal(bytesToHex(rec.bytes()), tc.record_hex, `${tc.name}: approval bytes != oracle`);
    assert.equal(bytesToHex(rec.id()), tc.approval_id_hex, `${tc.name}: approval id != oracle`);
  }

  // A named audience must change the signed bytes -- naming a context cannot be silently ignored.
  const present = new approval.ApprovalRecord(
    hexToBytes(a.approves_hex), a.approver, a.grant, hexToBytes(a.nonce_hex), a.not_after, a.use_context_match);
  const absent = new approval.ApprovalRecord(
    hexToBytes(a.approves_hex), a.approver, a.grant, hexToBytes(a.nonce_hex), a.not_after);
  assert.notEqual(bytesToHex(present.bytes()), bytesToHex(absent.bytes()), 'naming an audience must change the approval bytes');

  // The check: named audience must match the use context; absent audience passes any context.
  assert.equal(approval.verifyAudience(present, a.use_context_match), null);
  assert.throws(() => approval.verifyAudience(present, a.use_context_mismatch), (e) => e.kind === 'AudienceMismatch');
  assert.equal(approval.verifyAudience(absent, a.use_context_mismatch), null,
    'an approval that names no audience must pass any context');
});

// ---- R-TDCS-3 the party-visible coarse refusal (byte-graded, no-leak) -----------------

test('isKnownRefusalOutcome: closed set accepts denied/held/unverifiable and rejects everything else [MUTATION ANCHOR]', () => {
  assert.equal(approval.isKnownRefusalOutcome(approval.REFUSAL_DENIED), true);
  assert.equal(approval.isKnownRefusalOutcome(approval.REFUSAL_HELD), true);
  assert.equal(approval.isKnownRefusalOutcome(approval.REFUSAL_UNVERIFIABLE), true);
  assert.equal(approval.isKnownRefusalOutcome(3), false);
  assert.equal(approval.isKnownRefusalOutcome(999n), false);
});

test('refusalFromRecord matches the oracle bytes, never leaks the reason, and parseRefusal round-trips / rejects non-conformant shapes', () => {
  const TD = loadTDCS();
  const r = TD.refusal;
  const fullRecord = hexToBytes(r.full_record_hex);
  const recordID = hexToBytes(r.full_record_id_hex);
  const reasonBytes = Buffer.from(r.leaked_reason, 'utf-8');

  for (const tc of r.cases) {
    const ref = approval.refusalFromRecord(tc.outcome, fullRecord);
    const b = Buffer.from(ref.bytes());
    assert.equal(b.toString('hex'), tc.record_hex, `${tc.name}: refusal bytes != oracle`);
    assert.ok(!b.includes(reasonBytes), `${tc.name}: the record's reason LEAKED into the party-visible refusal`);
    assert.ok(b.includes(Buffer.from(recordID)), `${tc.name}: refusal does not carry the full-record content id`);

    // Round-trip: a conformant refusal parses back to the same outcome + record id.
    const got = approval.parseRefusal(b);
    assert.equal(got.outcome, BigInt(tc.outcome), `${tc.name}: round-trip outcome`);
    assert.equal(bytesToHex(got.record), bytesToHex(recordID), `${tc.name}: round-trip record id`);
  }

  // Non-conformant refusals a conformant parser MUST reject.
  assert.throws(() => approval.parseRefusal(hexToBytes(r.reject.unknown_outcome_hex)),
    (e) => e.kind === 'UnknownRefusalOutcome', 'unknown refusal outcome must be rejected');
  const rejects = {
    'extra field (leaked detail)': r.reject.detail_leak_extra_field_hex,
    'missing record id': r.reject.missing_record_hex,
    'empty record id': r.reject.empty_record_hex,
  };
  for (const [name, h] of Object.entries(rejects)) {
    assert.throws(() => approval.parseRefusal(hexToBytes(h)),
      (e) => e.kind === 'RefusalDetailLeak', `${name} must be rejected`);
  }
});

// ---- T1.5 (NAALP-REQ-121): ledger-signed consume receipt with forward-only position ----

function recFromJSON(rj) {
  return new approval.ConsumeReceipt(hexToBytes(rj.ledger_hex), hexToBytes(rj.approval_id_hex), BigInt(rj.position));
}

test('consume receipt body bytes match the oracle byte-for-byte (T1.5)', () => {
  const CR = loadConsumeReceipt();
  const all = [CR.base, ...CR.sequence];
  for (const f of CR.forks) all.push(f.a, f.b);
  assert.ok(all.length > 0, 'need consume-receipt cases');
  for (const rj of all) {
    assert.equal(bytesToHex(recFromJSON(rj).bytes()), rj.body_hex, `receipt body ${rj.name || ''}`);
  }
});

test('consume receipt sign/verify: valid, unnamed ledger, tampered signature, and wrong key are each rejected fail-closed', () => {
  const CR = loadConsumeReceipt();
  const k1 = ledgerKey(0x51);
  const r = recFromJSON(CR.base);

  const sig = approval.signConsumeReceipt(r, k1.alg, k1.seed);
  assert.equal(approval.verifyConsumeReceipt(r, k1.alg, k1.pk, sig), null, 'valid ledger-signed receipt rejected');

  // unnamed ordering authority (empty ledger id) is not evidence.
  const unnamed = new approval.ConsumeReceipt(new Uint8Array(0), r.approvalId, r.position);
  assert.throws(() => approval.verifyConsumeReceipt(unnamed, k1.alg, k1.pk, sig),
    (e) => e.kind === 'ConsumeReceiptUnsigned', 'unnamed-ledger receipt accepted');

  // tampered signature.
  const bad = Uint8Array.from(sig);
  bad[bad.length - 1] ^= 1;
  assert.throws(() => approval.verifyConsumeReceipt(r, k1.alg, k1.pk, bad),
    (e) => e.kind === 'ConsumeReceiptUnsigned', 'tampered signature accepted');

  // wrong ledger key.
  const k2 = ledgerKey(0x52);
  assert.throws(() => approval.verifyConsumeReceipt(r, k2.alg, k2.pk, sig),
    (e) => e.kind === 'ConsumeReceiptUnsigned', 'wrong ledger key accepted');
});

test('ReceiptSet detects a fork: same ledger, same approval id, different positions', () => {
  const CR = loadConsumeReceipt();
  const fk = CR.forks.find((f) => f.name === 'same_ledger_diff_position');
  assert.ok(fk, 'same_ledger_diff_position case missing from oracle');
  assert.equal(fk.expect, 'fork');

  const k = ledgerKey(0x41); // one ledger signs both conflicting positions (a partition)
  const rA = recFromJSON(fk.a);
  const rB = recFromJSON(fk.b);
  const sigA = approval.signConsumeReceipt(rA, k.alg, k.seed);
  const sigB = approval.signConsumeReceipt(rB, k.alg, k.seed);

  const resolve = (id) => (bytesToHex(id) === bytesToHex(rA.ledger) ? [k.alg, k.pk] : null);
  const rs = approval.newReceiptSet(resolve);
  assert.equal(rs.observe(rA, sigA), null, 'first receipt flagged');
  const fe = rs.observe(rB, sigB);
  assert.ok(fe instanceof approval.ConsumeForkEvidence, 'fork not detected on same approval id / different positions');
  // the two positions are surfaced (the contradiction is legible).
  assert.notEqual(fe.a.position, fe.b.position, 'fork evidence hides the position conflict');
  // the evidence is non-repudiable: both ledger signatures verify under the named key.
  assert.equal(fe.verify(resolve), null, 'fork evidence failed to verify');

  // a byte-identical re-emission is a benign duplicate, never flagged.
  const rs2 = approval.newReceiptSet(resolve);
  rs2.observe(rA, sigA);
  assert.equal(rs2.observe(rA, sigA), null, 'benign duplicate flagged');
});

test('ReceiptSet detects a cross-ledger fork: two independent ledgers spend one approval id', () => {
  const CR = loadConsumeReceipt();
  const approvalX = hexToBytes(CR.approvals.x_hex);
  const kA = ledgerKey(0x41);
  const kB = ledgerKey(0x42);

  withTempLedger((pathA) => {
    withTempLedger((pathB) => {
      const lA = approval.openLedgerSigned(pathA, 'LEDGER01', kA.alg, kA.seed); // "LEDGER01" == ledgers.a_hex
      const lB = approval.openLedgerSigned(pathB, 'LEDGER02', kB.alg, kB.seed); // "LEDGER02" == ledgers.b_hex
      try {
        assert.equal(bytesToHex(hexToBytes(CR.ledgers.a_hex)), bytesToHex(Buffer.from('LEDGER01', 'utf-8')));
        assert.equal(bytesToHex(hexToBytes(CR.ledgers.b_hex)), bytesToHex(Buffer.from('LEDGER02', 'utf-8')));

        // Two independent ordering authorities each consuming approval X on its own signed ledger.
        // Each SUCCEEDS locally (they cannot see each other) -- the double spend is not prevented,
        // only made provable on comparison.
        const { receipt: rA, sig: sigA } = lA.consumeWithReceipt(approvalX, 'requester');
        const { receipt: rB, sig: sigB } = lB.consumeWithReceipt(approvalX, 'requester');

        const resolve = (id) => {
          const h = bytesToHex(id);
          if (h === bytesToHex(rA.ledger)) return [kA.alg, kA.pk];
          if (h === bytesToHex(rB.ledger)) return [kB.alg, kB.pk];
          return null;
        };
        const rs = approval.newReceiptSet(resolve);
        assert.equal(rs.observe(rA, sigA), null, 'first receipt flagged');
        const fe = rs.observe(rB, sigB);
        assert.ok(fe instanceof approval.ConsumeForkEvidence, 'cross-ledger double spend not detected');
        assert.notEqual(bytesToHex(fe.a.ledger), bytesToHex(fe.b.ledger), 'cross-ledger fork evidence names the same ledger twice');
        assert.equal(fe.verify(resolve), null, 'cross-ledger fork evidence failed to verify');
      } finally {
        lA.close();
        lB.close();
      }
    });
  });
});

test('consumeWithReceipt is first-append-wins: a second consume of the same id mints NO second receipt [MUTATION ANCHOR]', () => {
  // This is the compare-and-set MUTATION anchor. On ONE honest signed ledger, consuming the same
  // approval id twice must yield exactly ONE ledger-signed receipt: the first consume returns a
  // receipt at position 0; the second throws AlreadyConsumed and signs nothing. If the CAS is mutated
  // to always-succeed, the second consume mints a SECOND receipt at position 1 for the same approval
  // id, so (1) this assertion flips and (2) the fork detector would fire on a single honest ledger.
  const CR = loadConsumeReceipt();
  const approvalX = hexToBytes(CR.approvals.x_hex);
  const k = ledgerKey(0x41);

  withTempLedger((path) => {
    const l = approval.openLedgerSigned(path, 'LEDGER01', k.alg, k.seed);
    try {
      const resolve = () => [k.alg, k.pk];
      const rs = approval.newReceiptSet(resolve);

      // first consume wins with a receipt at the ledger's forward-only position 0.
      const first = l.consumeWithReceipt(approvalX, 'requester');
      assert.equal(Number(first.entry.seq), 0);
      assert.equal(Number(first.receipt.position), 0);
      assert.equal(rs.observe(first.receipt, first.sig), null, 'first receipt flagged');

      // second consume of the same id: AlreadyConsumed, signs nothing (first-append-wins).
      assert.throws(() => l.consumeWithReceipt(approvalX, 'requester'),
        (e) => e.kind === 'AlreadyConsumed',
        'second consume of the same approval id succeeded (CAS is not first-append-wins)');
      assert.equal(l.len(), 1, 'ledger has more than one entry, want exactly 1');
    } finally {
      l.close();
    }
  });
});

test('consumeWithReceipt is exactly-once under many callers: exactly one wins and mints exactly one receipt', () => {
  const CR = loadConsumeReceipt();
  const approvalX = hexToBytes(CR.approvals.x_hex);
  const k = ledgerKey(0x41);

  withTempLedger((path) => {
    const l = approval.openLedgerSigned(path, 'LEDGER01', k.alg, k.seed);
    try {
      const N = 32;
      let won = 0;
      let rejected = 0;
      let winnerReceipt = null;
      let winnerSig = null;
      for (let i = 0; i < N; i++) {
        try {
          const { receipt, sig } = l.consumeWithReceipt(approvalX, 'caller:' + i);
          won += 1;
          winnerReceipt = receipt;
          winnerSig = sig;
        } catch (e) {
          assert.equal(e.kind, 'AlreadyConsumed');
          rejected += 1;
        }
      }
      assert.equal(won, 1, 'exactly-once violated');
      assert.equal(rejected, N - 1);
      // the single minted receipt is not a fork with itself.
      const rs = approval.newReceiptSet(() => [k.alg, k.pk]);
      assert.equal(rs.observe(winnerReceipt, winnerSig), null, 'sole winning receipt flagged');
    } finally {
      l.close();
    }
  });
});

test('consume receipt wire cases: non-canonical keys, 64-bit position round-trip, empty != absent ledger', () => {
  const CR = loadConsumeReceipt();

  // keys out of order -> the strict decoder rejects NonCanonical, before any receipt rule.
  assert.throws(() => cbor.decode(hexToBytes(CR.wire.keys_out_of_order.payload_hex)),
    (e) => e.kind === 'NonCanonical', 'non-canonical (keys 3,2,1) receipt body accepted by decoder');
  // the canonical variant of the same logical receipt decodes cleanly.
  cbor.decode(hexToBytes(CR.wire.keys_out_of_order.canonical_payload_hex));

  // position too large: a 64-bit uint position round-trips (encode == oracle, decode == value).
  const ledgerX = hexToBytes(CR.base.ledger_hex);
  const approvalX = hexToBytes(CR.base.approval_id_hex);
  for (const big of CR.wire.position_too_large) {
    const r = new approval.ConsumeReceipt(ledgerX, approvalX, BigInt(big.position));
    assert.equal(bytesToHex(r.bytes()), big.body_hex, `${big.name} encode`);
    const v = cbor.decode(hexToBytes(big.body_hex));
    let pos = null;
    for (const [k, val] of v.pairs) {
      if (k instanceof cbor.U && k.v === 3n) pos = val.v;
    }
    assert.equal(pos, BigInt(big.position), `${big.name} position round-trip`);
  }

  // empty-ledger receipt: well-formed bytes (match oracle) but verify-rejected fail-closed, and its
  // bytes differ from the absent-ledger variant (empty != absent).
  const empty = new approval.ConsumeReceipt(
    new Uint8Array(0), hexToBytes(CR.wire.empty_ledger.approval_id_hex), BigInt(CR.wire.empty_ledger.position));
  assert.equal(bytesToHex(empty.bytes()), CR.wire.empty_ledger.body_hex);
  const k = ledgerKey(0x41);
  assert.throws(() => approval.verifyConsumeReceipt(empty, k.alg, k.pk, new Uint8Array(3309)),
    (e) => e.kind === 'ConsumeReceiptUnsigned', 'empty-ledger receipt verified');
  assert.notEqual(CR.wire.empty_ledger.body_hex, CR.wire.absent_ledger.body_hex,
    'empty-ledger and absent-ledger receipts must encode to distinct bytes (empty != absent)');
});

// ---- R-TDCS-4 freshness independence ---------------------------------------------------

test('verifyFreshIndependent (R-TDCS-4): distinct ordering authority verifies; self-asserted freshness is rejected fail-closed', () => {
  const approverK = ledgerKey(0x11); // the approver's key (the authenticated party)
  const ledgerK = ledgerKey(0x22);   // the ordering authority (ledger) -- a DISTINCT key
  const argsID = Buffer.from('the-exact-canonical-args-content-id', 'utf-8');
  const approverID = Buffer.from('approver-authenticated-party-id', 'utf-8');
  const ledgerID = Buffer.from('ordering-authority-ledger-id', 'utf-8');

  const a = new approval.ApprovalRecord(
    argsID, 'approver-authenticated-party-id', 1, Buffer.from('anti-replay-nonce', 'utf-8'), 1000n);
  const aSig = approval.signApproval(a, approverK.alg, approverK.seed);
  const r = new approval.ConsumeReceipt(ledgerID, a.id(), 7n);
  const rSig = approval.signConsumeReceipt(r, ledgerK.alg, ledgerK.seed);

  // Distinct ordering authority (party != ledger): an unexpired, correctly-signed approval with a
  // valid ledger receipt verifies.
  assert.equal(
    approval.verifyFreshIndependent(
      a, approverK.alg, approverK.pk, aSig, argsID, 1000n, r, ledgerK.alg, ledgerK.pk, rSig, approverID),
    null, 'distinct ordering authority should verify');

  // Self-asserted freshness (party == ledger): the party is the source of its own time -- rejected.
  assert.throws(
    () => approval.verifyFreshIndependent(
      a, approverK.alg, approverK.pk, aSig, argsID, 1000n, r, ledgerK.alg, ledgerK.pk, rSig, ledgerID),
    (e) => e.kind === 'FreshnessSelfAsserted',
    'self-asserted freshness (party == ordering authority) must be rejected');

  // The distinctness check does not weaken the underlying checks: an expired approval still fails
  // closed (posTime past not_after), and a distinct authority does not rescue it.
  assert.throws(
    () => approval.verifyFreshIndependent(
      a, approverK.alg, approverK.pk, aSig, argsID, 1001n, r, ledgerK.alg, ledgerK.pk, rSig, approverID),
    (e) => e.kind === 'ApprovalExpired', 'expired approval must still be rejected under a distinct authority');

  // A receipt with no named ordering authority is not evidence (unnamed authority), even when the
  // party id supplied is distinct.
  const emptyR = new approval.ConsumeReceipt(new Uint8Array(0), a.id(), 7n);
  const thirdK = ledgerKey(0x33);
  const emptySig = approval.signConsumeReceipt(emptyR, thirdK.alg, thirdK.seed);
  assert.throws(
    () => approval.verifyFreshIndependent(
      a, approverK.alg, approverK.pk, aSig, argsID, 1000n, emptyR, ledgerK.alg, ledgerK.pk, emptySig, approverID),
    (e) => e.kind === 'ConsumeReceiptUnsigned', 'unnamed ordering authority must not be accepted as freshness evidence');
});

// ---- draft "## Approval state machine": consumeApproval, the composed choke point -----

test('consumeApproval runs the draft "## Approval state machine" precedence [MUTATION ANCHOR]', () => {
  // consumeApproval runs the table's precedence in ONE impl-owned place: verifyApproval
  // (sig -> mismatch -> expiry) BEFORE the ledger, then the grant-range guard, then the
  // effect-ceiling authorization, then the atomic single-use consume. This test exercises every
  // reaction and the two precedence rules (mismatch over every cell; expiry over AlreadyConsumed),
  // plus the effect-ceiling / grant-range / bad-signature refusals, and asserts the ledger length
  // so a mutant that returns the right kind but still appends is caught. Reactions are the draft's,
  // not read off the implementation.
  const k = ledgerKey(0x07);
  const argsCidA = new TextEncoder().encode('args-content-id-A');
  const argsCidB = new TextEncoder().encode('args-content-id-B');
  const mk = (grant, notAfter) => {
    const a = new approval.ApprovalRecord(argsCidA, 'approver-1', grant, Uint8Array.from([0x01, 0x02]), notAfter);
    const sig = approval.signApproval(a, k.alg, k.seed);
    return { a, sig };
  };

  // approved + consume -> consumed (len 1); a second consume of the SAME id -> AlreadyConsumed (len
  // stays 1).
  withTempLedger((path) => {
    const led = approval.openLedger(path);
    try {
      const { a, sig } = mk(policy.DESTRUCTIVE, 1000n);
      approval.consumeApproval(a, k.alg, k.pk, sig, argsCidA, 500n, policy.READ_ONLY, led, 'by');
      assert.equal(led.len(), 1, 'valid consume must append');
      assert.throws(
        () => approval.consumeApproval(a, k.alg, k.pk, sig, argsCidA, 500n, policy.READ_ONLY, led, 'by'),
        (e) => e.kind === 'AlreadyConsumed', 'a second consume of the same id must be rejected');
      assert.equal(led.len(), 1, 'a rejected replay must not append');
    } finally { led.close(); }
  });

  // expired + consume -> ApprovalExpired; nothing appended.
  withTempLedger((path) => {
    const led = approval.openLedger(path);
    try {
      const { a, sig } = mk(policy.DESTRUCTIVE, 1000n);
      assert.throws(
        () => approval.consumeApproval(a, k.alg, k.pk, sig, argsCidA, 2000n, policy.READ_ONLY, led, 'by'),
        (e) => e.kind === 'ApprovalExpired');
      assert.equal(led.len(), 0);
    } finally { led.close(); }
  });

  // expiry over consume: success, then a second past not_after -> ApprovalExpired (never
  // AlreadyConsumed), ledger untouched (len stays 1).
  withTempLedger((path) => {
    const led = approval.openLedger(path);
    try {
      const { a, sig } = mk(policy.DESTRUCTIVE, 1000n);
      approval.consumeApproval(a, k.alg, k.pk, sig, argsCidA, 500n, policy.READ_ONLY, led, 'by');
      assert.throws(
        () => approval.consumeApproval(a, k.alg, k.pk, sig, argsCidA, 2000n, policy.READ_ONLY, led, 'by'),
        (e) => e.kind === 'ApprovalExpired', 'expiry must take precedence over AlreadyConsumed');
      assert.equal(led.len(), 1, 'the expired-second-attempt must not append');
    } finally { led.close(); }
  });

  // mismatch over every cell (fresh, and over an also-expired approval); no append either time.
  withTempLedger((path) => {
    const led = approval.openLedger(path);
    try {
      const { a, sig } = mk(policy.DESTRUCTIVE, 1000n);
      assert.throws(
        () => approval.consumeApproval(a, k.alg, k.pk, sig, argsCidB, 500n, policy.READ_ONLY, led, 'by'),
        (e) => e.kind === 'ApprovalMismatch');
      assert.throws(
        () => approval.consumeApproval(a, k.alg, k.pk, sig, argsCidB, 2000n, policy.READ_ONLY, led, 'by'),
        (e) => e.kind === 'ApprovalMismatch', 'mismatch must take precedence over expiry');
      assert.equal(led.len(), 0);
    } finally { led.close(); }
  });

  // a rejected mismatch leaves the ledger clean, so a later valid consume still succeeds.
  withTempLedger((path) => {
    const led = approval.openLedger(path);
    try {
      const { a, sig } = mk(policy.DESTRUCTIVE, 1000n);
      assert.throws(
        () => approval.consumeApproval(a, k.alg, k.pk, sig, argsCidB, 500n, policy.READ_ONLY, led, 'by'),
        (e) => e.kind === 'ApprovalMismatch');
      assert.equal(led.len(), 0);
      approval.consumeApproval(a, k.alg, k.pk, sig, argsCidA, 500n, policy.READ_ONLY, led, 'by');
      assert.equal(led.len(), 1, 'a valid consume after a rejected mismatch must still succeed');
    } finally { led.close(); }
  });

  // effect ceiling: granted effect below the action's required effect -> ApprovalRequired.
  // [MUTATION ANCHOR] a mutant that drops or short-circuits this check would let this consume
  // succeed and append -- both the thrown kind AND len==0 must hold.
  withTempLedger((path) => {
    const led = approval.openLedger(path);
    try {
      const { a, sig } = mk(policy.READ_ONLY, 1000n);
      assert.throws(
        () => approval.consumeApproval(a, k.alg, k.pk, sig, argsCidA, 500n, policy.DESTRUCTIVE, led, 'by'),
        (e) => e.kind === 'ApprovalRequired', 'insufficient grant must be refused ApprovalRequired');
      assert.equal(led.len(), 0, 'a refused insufficient-grant consume must not append');
    } finally { led.close(); }
  });

  // grant-range guard: a grant outside the closed 0..3 vocabulary authorizes nothing.
  withTempLedger((path) => {
    const led = approval.openLedger(path);
    try {
      const { a, sig } = mk(7, 1000n);
      assert.throws(
        () => approval.consumeApproval(a, k.alg, k.pk, sig, argsCidA, 500n, policy.READ_ONLY, led, 'by'),
        (e) => e.kind === 'ApprovalRequired', 'a malformed grant (outside 0..3) must be refused');
      assert.equal(led.len(), 0);
    } finally { led.close(); }
  });

  // bad signature (checked first) -> BadSignature.
  withTempLedger((path) => {
    const led = approval.openLedger(path);
    try {
      const { a, sig } = mk(policy.DESTRUCTIVE, 1000n);
      const bad = Uint8Array.from(sig);
      bad[bad.length - 1] ^= 0x01;
      assert.throws(
        () => approval.consumeApproval(a, k.alg, k.pk, bad, argsCidA, 500n, policy.READ_ONLY, led, 'by'),
        (e) => e.kind === 'BadSignature');
      assert.equal(led.len(), 0);
    } finally { led.close(); }
  });
});
