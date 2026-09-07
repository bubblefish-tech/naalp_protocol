// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C4 identity RECORD + THREAD surfaces (design.md §5.2/§5.3/§5.4/§5.5, R-1.4) known-answer
// tests for the TypeScript SDK, graded against the independent oracle
// (tools/identity_records_oracle.py -> vectors/identity_records/cases.json), i.e.
// TypeScript == Go == Rust == oracle on every *_hex byte and every
// expect_valid/expect_linked/expect_error/expect verdict.
//
// Ported from impl/go/identity/identity.go (identity_records_oracle_test.go) and
// impl/rust/src/identity.rs's `mod tests` RECORD + THREAD block: RevocationRecord, RevokedAt,
// VerifyRevocation, ForeignLinkRecord, VerifyForeignLink, RotationEvidence, Thread,
// Thread.attributable, ResolveThread.
//
// SECURITY-CRITICAL: verifyRevocation is fail-closed (§5.3/§5.5) -- the signer id is recomputed and
// checked for membership in {r.key} u recoveryIds BEFORE the signature is verified. The
// "recovery_key_not_configured_reject" case is the MUTATION ANCHOR: the SAME valid recovery-key
// signature that is accepted when the recovery id is configured (recovery_key_valid_per_design) MUST
// be rejected SignerMismatch when the authorized set is empty. Dropping the membership guard
// (authorized = id === r.key || member -> authorized = true) flips this case from reject to accept.
//
// Run:  node --test test/identity.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as identity from '../naalp/identity.mjs';

const bytesToHex = (b) => Buffer.from(b).toString('hex');
const hexToBytes = (h) => Uint8Array.from(Buffer.from(h, 'hex'));

function findVector() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'identity_records', 'cases.json');
    if (existsSync(p)) return p;
    d = dirname(d);
  }
  return null;
}

function loadCorpus() {
  const p = findVector();
  if (!p) return null;
  return JSON.parse(readFileSync(p, 'utf8'));
}

// ---- RevocationRecord.bytes (§5.3) ---------------------------------------------------------------

test('RevocationRecord.bytes matches the independent oracle', () => {
  const c = loadCorpus();
  if (!c) return; // committed oracle vector not present (standalone install)
  const cases = c.revocation.record_bytes;
  assert.ok(cases.length > 0);
  for (const tc of cases) {
    const r = new identity.RevocationRecord(tc.key, tc.not_after);
    assert.equal(bytesToHex(r.bytes()), tc.bytes_hex, tc.name);
  }
});

// ---- RevokedAt (§5.3) -- set-based scenarios graded via a thin selection loop, since the impl's
//      revokedAt(record, position) is a pure per-record boolean. MUTATION ANCHOR:
//      "at_boundary_still_valid" pins `>` vs `>=`. --------------------------------------------------

test('revokedAt matches the independent oracle', () => {
  const c = loadCorpus();
  if (!c) return;
  const scenarios = c.revocation.revoked_at;
  assert.ok(scenarios.length > 0);
  for (const sc of scenarios) {
    let revoked = false;
    let notAfter = 0;
    for (const rv of sc.revocations) {
      if (rv.key !== sc.query_key) continue;
      const rec = new identity.RevocationRecord(rv.key, rv.not_after);
      if (identity.revokedAt(rec, sc.query_position)) {
        revoked = true;
        notAfter = rv.not_after;
      }
    }
    assert.equal(revoked, sc.expect_revoked, sc.name);
    if (sc.expect_revoked) {
      assert.equal(notAfter, sc.expect_not_after, sc.name);
    }
  }
});

// ---- VerifyRevocation (§5.3, §5.5) ----------------------------------------------------------------
// §5.3 permits a Revocation to be signed by the key it revokes OR by a deployer-configured recovery
// key. verifyRevocation takes the deployer's authorized recovery-id set and accepts a signer iff its
// recomputed id equals record.key or is a member of that set, then verifies the signature (membership
// BEFORE signature, fail-closed). MUTATION ANCHORS: "recovery_key_not_configured_reject" (a valid
// recovery-key signature with an EMPTY authorized set -> SignerMismatch) and "wrong_key_reject" --
// dropping the membership guard flips both to accept.

test('verifyRevocation matches the independent oracle [MUTATION ANCHOR: fail-closed membership]', () => {
  const c = loadCorpus();
  if (!c) return;
  const cases = c.revocation.verify;
  assert.ok(cases.length >= 7);
  for (const tc of cases) {
    const rec = new identity.RevocationRecord(tc.record.key, tc.record.not_after);
    const pub = hexToBytes(tc.candidate_pubkey_hex);
    const sig = hexToBytes(tc.sig_hex);
    const recoveryIds = tc.authorized_recovery_ids || [];
    if (tc.expect_valid) {
      assert.doesNotThrow(
        () => identity.verifyRevocation(rec, tc.candidate_alg, pub, sig, recoveryIds),
        `${tc.name}: expected valid`,
      );
    } else if (tc.expect_error_kind) {
      assert.throws(
        () => identity.verifyRevocation(rec, tc.candidate_alg, pub, sig, recoveryIds),
        (e) => e && e.kind === tc.expect_error_kind,
        `${tc.name}: expected ${tc.expect_error_kind}`,
      );
    } else {
      assert.throws(
        () => identity.verifyRevocation(rec, tc.candidate_alg, pub, sig, recoveryIds),
        undefined,
        `${tc.name}: expected reject`,
      );
    }
  }
});

// ---- ForeignLinkRecord.bytes (§5.4) --------------------------------------------------------------
// MUTATION ANCHOR: collapsing NFC/NFD to the same bytes would flip the not-equal assertion.

test('ForeignLinkRecord.bytes matches the independent oracle [MUTATION ANCHOR: NFC != NFD bytes]', () => {
  const c = loadCorpus();
  if (!c) return;
  const cases = c.foreign_link.record_bytes;
  assert.ok(cases.length >= 2);
  const seen = new Map();
  for (const tc of cases) {
    const r = new identity.ForeignLinkRecord(tc.controls, tc.foreign_id, tc.not_after);
    const got = bytesToHex(r.bytes());
    assert.equal(got, tc.bytes_hex, tc.name);
    seen.set(tc.name, got);
  }
  assert.notEqual(
    seen.get('nfc_form'), seen.get('nfd_form_different_bytes'),
    'NFC and NFD foreign_id forms must encode to different bytes',
  );
});

// ---- VerifyForeignLink (§5.4, §5.5) ---------------------------------------------------------------
// Valid+unexpired, the not_after boundary (MUTATION ANCHOR for `now > NotAfter`), expiry (ignored, no
// error), wrong-key (ignored, no error -- the SAME bucket as expiry per §5.5), and non-NFC foreign_id
// (NonNFC, checked before expiry/signature).

test('verifyForeignLink matches the independent oracle', () => {
  const c = loadCorpus();
  if (!c) return;
  const cases = c.foreign_link.verify;
  assert.ok(cases.length > 0);
  for (const tc of cases) {
    const rec = new identity.ForeignLinkRecord(tc.record.controls, tc.record.foreign_id, tc.record.not_after);
    const pub = hexToBytes(tc.candidate_pubkey_hex);
    const sig = hexToBytes(tc.sig_hex);
    if (tc.expect_error_kind) {
      assert.throws(
        () => identity.verifyForeignLink(rec, tc.candidate_alg, pub, sig, tc.now),
        (e) => e && e.kind === tc.expect_error_kind,
        `${tc.name}: expected ${tc.expect_error_kind}`,
      );
      continue;
    }
    const linked = identity.verifyForeignLink(rec, tc.candidate_alg, pub, sig, tc.now);
    assert.equal(linked, tc.expect_linked, tc.name);
    if (tc.expect_linked) {
      assert.equal(rec.controls, tc.expect_controls, tc.name);
      assert.equal(rec.foreignId, tc.expect_foreign_id, tc.name);
    }
  }
});

// ---- RotationEvidence / Thread / ResolveThread (§5.2, R-1.4) --------------------------------------

function buildEvidence(evsJson) {
  return evsJson.map((e) => {
    const rec = new identity.RotationRecord(e.old, e.new, e.not_before);
    assert.equal(bytesToHex(rec.bytes()), e.record_bytes_hex, 'RotationRecord.bytes() (RotationEvidence input)');
    return new identity.RotationEvidence(
      rec, e.old_alg, hexToBytes(e.old_pubkey_hex), e.new_alg, hexToBytes(e.new_pubkey_hex),
      hexToBytes(e.old_sig_hex), hexToBytes(e.new_sig_hex),
    );
  });
}

// resolveThread: empty chain, single link, a 3-link contiguous chain, and TWO distinct broken-chain
// shapes -- "broken_link_old_mismatch" pins the CONTIGUITY guard (e.record.old !== prevNew), and
// "broken_link_forged_old_signature" pins the per-link CO-SIGNATURE guard (verifyRotation), isolating
// one guard from the other. MUTATION ANCHORS.

test('resolveThread matches the independent oracle [MUTATION ANCHORS: contiguity + co-signature guards]', () => {
  const c = loadCorpus();
  if (!c) return;
  const cases = c.thread.resolve;
  assert.ok(cases.length > 0);
  for (const tc of cases) {
    const evs = buildEvidence(tc.evidence);
    if (tc.expect_error) {
      assert.throws(
        () => identity.resolveThread(evs),
        (e) => e && e.kind === tc.expect_error,
        `${tc.name}: expected ${tc.expect_error}`,
      );
      continue;
    }
    const th = identity.resolveThread(evs);
    assert.equal(th.root, tc.expect_thread.root, tc.name);
    assert.equal(th.current, tc.expect_thread.current, tc.name);
    assert.deepEqual(th.chain, tc.expect_thread.chain, tc.name);
  }
});

// Thread.attributable: root/intermediate/current keys are attributable; an unrelated key is not.
// "unrelated_key_not_attributable" is the MUTATION ANCHOR (an always-true stub flips it).

test('Thread.attributable matches the independent oracle [MUTATION ANCHOR: unrelated key]', () => {
  const c = loadCorpus();
  if (!c) return;
  const cases = c.thread.attributable;
  assert.ok(cases.length > 0);
  for (const tc of cases) {
    const th = new identity.Thread(tc.thread.root, tc.thread.current, tc.thread.chain);
    assert.equal(th.attributable(tc.query), tc.expect, tc.name);
  }
});
