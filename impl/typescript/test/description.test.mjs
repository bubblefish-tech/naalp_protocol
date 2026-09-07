// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C18 signed description / directory conformance for the TypeScript SDK, graded against the shared
// independent corpus vectors/description/cases.json (NOT produced by this code): the Description body +
// head + content id, each Operation body, the Directory body/head/id and its fork detection (the
// first-differing member position, incl. a length fork and a legitimate version succession), and the
// Import body/head/id + foreign-id binding + closed-format rejection (UnknownDescriptionFormat).
//
// The offline-verification, directory fork-proof, and confused-deputy (import) paths use real
// deterministic ML-DSA-65 and are demonstrated in isolation (the corpus carries no signed vector) --
// stated honestly, not corpus-graded.
//
// Written test-first; the description module is absent until ported, so this fails RED on import until
// impl/typescript/naalp/description.mjs lands, and the mutation "firstMemberDifference never reports a
// difference" flips 'description directory fork detection reports the first-differing position'.
//
// Run:  node --test test/description.test.mjs      (from impl/typescript/)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as cbor from '../naalp/cbor.mjs';
import * as cose from '../naalp/cose.mjs';
import * as identity from '../naalp/identity.mjs';
import * as description from '../naalp/description.mjs';

function vectors() {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(d, 'vectors', 'description', 'cases.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'));
    d = dirname(d);
  }
  throw new Error('vectors/description/cases.json not found');
}

const C = vectors();
const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

const ALG = cose.ALG_MLDSA65;
const SEED = new Uint8Array(32);
const PK = cose.mldsaKeygen('ML-DSA-65', SEED);

function opOf(o) {
  return new description.Operation(o.name, o.effect, o.requires_approval);
}

// ---- Description: the signed operation table (byte-graded) -----------------------------

test('description body + head + content id match the oracle byte-for-byte', () => {
  const d = C.description;
  const ops = d.operations.map(opOf);
  // each operation encodes to its pinned body
  for (const o of d.operations) {
    assert.equal(bytesToHex(opOf(o).bytes()), o.body_hex, `operation ${o.name} body`);
  }
  const desc = new description.Description(hexToBytes(d.service_hex), ops);
  assert.equal(bytesToHex(desc.bytes()), d.body_hex, 'description body');
  assert.equal(bytesToHex(desc.head()), d.head_hex, 'description head');
  assert.equal(bytesToHex(desc.id()), d.id_hex, 'description id');

  // ParseDescription reconstructs the whole operation table from the bytes ALONE (offline property).
  const parsed = description.parseDescription(hexToBytes(d.body_hex));
  assert.equal(bytesToHex(parsed.bytes()), d.body_hex, 'round-trip body');
  const purge = parsed.operation('purge');
  assert.ok(purge[1], 'purge is listed');
  assert.equal(purge[0].effectClass(), 3, 'purge is destructive');
  assert.equal(purge[0].requiresApprovalFlag(), true, 'purge requires approval');
  const status = parsed.operation('status');
  assert.equal(status[0].requiresApprovalFlag(), false, 'status requires no approval');
});

// ---- Directory: signed content-id collection + fork detection (byte/verdict-graded) ----

test('description directory body + head + content id match the oracle byte-for-byte', () => {
  const dir = C.directory;
  const a = new description.Directory(hexToBytes(dir.directory_hex), dir.version, dir.members_a_hex.map(hexToBytes));
  assert.equal(bytesToHex(a.bytes()), dir.a.body_hex, 'directory A body');
  assert.equal(bytesToHex(a.head()), dir.a.head_hex, 'directory A head');
  assert.equal(bytesToHex(a.id()), dir.a.id_hex, 'directory A id');

  const b = new description.Directory(hexToBytes(dir.directory_hex), dir.version, dir.fork.members_b_hex.map(hexToBytes));
  assert.equal(bytesToHex(b.bytes()), dir.fork.b.body_hex, 'directory B body');
  assert.equal(bytesToHex(b.head()), dir.fork.b.head_hex, 'directory B head');
  assert.equal(bytesToHex(b.id()), dir.fork.b.id_hex, 'directory B id');

  // the length-fork and version-succession bodies also reproduce byte-for-byte.
  const short = new description.Directory(hexToBytes(dir.directory_hex), dir.version, dir.length_fork.members_short_hex.map(hexToBytes));
  assert.equal(bytesToHex(short.bytes()), dir.length_fork.body_hex, 'length-fork body');
  const v8 = new description.Directory(hexToBytes(dir.directory_hex), dir.different_version.version, dir.fork.members_b_hex.map(hexToBytes));
  assert.equal(bytesToHex(v8.bytes()), dir.different_version.body_hex, 'different-version body');
});

test('description directory fork detection reports the first-differing position', () => {
  // THIS is the mutation-target assertion. A fork is the SAME directory+version with DIFFERENT members,
  // reported at the first-differing member position (as the audit fork-proof reports an equivocation).
  // MUTATION: making firstMemberDifference never report a difference collapses detectFork to (0,false),
  // so the [1,true] assertions below fail.
  const dir = C.directory;
  const a = new description.Directory(hexToBytes(dir.directory_hex), dir.version, dir.members_a_hex.map(hexToBytes));
  const b = new description.Directory(hexToBytes(dir.directory_hex), dir.version, dir.fork.members_b_hex.map(hexToBytes));
  const short = new description.Directory(hexToBytes(dir.directory_hex), dir.version, dir.length_fork.members_short_hex.map(hexToBytes));
  const v8 = new description.Directory(hexToBytes(dir.directory_hex), dir.different_version.version, dir.fork.members_b_hex.map(hexToBytes));

  // member[1] differs (desc-B -> desc-X) => fork at position 1.
  assert.deepEqual(description.detectFork(a, b), [dir.fork.first_differing_position, true]);
  // a truncated member list forks at the length of the shorter list (position 1).
  assert.deepEqual(description.detectFork(a, short), [dir.length_fork.first_differing_position, true]);
  // a different version is a legitimate succession, not a fork.
  assert.deepEqual(description.detectFork(a, v8), [0, false]);
  // an identical directory is a benign duplicate, not a fork (corpus duplicate_first_differing_position = -1).
  assert.deepEqual(description.detectFork(a, a), [0, false]);
  assert.equal(dir.duplicate_first_differing_position, -1);
});

// ---- Import: foreign description carried as a signed attestation (byte-graded) ---------

test('description import body + head + id + foreign-id match the oracle byte-for-byte', () => {
  const im = C.import;
  const ops = im.operations.map(opOf);
  const imp = new description.Import(hexToBytes(im.importer_hex), im.format, hexToBytes(im.foreign_hex), ops);
  assert.equal(bytesToHex(imp.bytes()), im.body_hex, 'import body');
  assert.equal(bytesToHex(imp.head()), im.head_hex, 'import head');
  assert.equal(bytesToHex(imp.id()), im.id_hex, 'import id');
  assert.equal(bytesToHex(imp.foreignId()), im.foreign_id_hex, 'foreign id binds the exact foreign bytes');

  // ParseImport reconstructs from the bytes alone.
  const parsed = description.parseImport(hexToBytes(im.body_hex));
  assert.equal(bytesToHex(parsed.bytes()), im.body_hex, 'round-trip import body');

  // a format code outside the closed set {1,2,3} is rejected on decode (UnknownDescriptionFormat).
  assert.throws(() => description.parseImport(hexToBytes(im.unknown_format.body_hex)),
    (e) => e.kind === im.unknown_format.reject);
});

// ---- fail-closed field guards (isolation, not corpus-graded) ---------------------------

test('description rejects a requires_approval flag outside {0,1} (MalformedApprovalFlag)', () => {
  // The spine carries no CBOR boolean, so requires_approval is the uint 1/0; a value >1 is rejected,
  // never defaulted. This grades the fail-closed guard in operationFromValue in isolation.
  const badOp = new cbor.M([
    [new cbor.U(1), new cbor.T('bad')],
    [new cbor.U(2), new cbor.U(0)],
    [new cbor.U(3), new cbor.U(2)], // requires_approval = 2, outside {0,1}
  ]);
  const body = cbor.encode(new cbor.M([
    [new cbor.U(1), new cbor.B(new Uint8Array([1]))],
    [new cbor.U(2), new cbor.A([badOp])],
  ]));
  assert.throws(() => description.parseDescription(body), (e) => e.kind === 'MalformedApprovalFlag');
});

// ---- offline verification: authority in the signed bytes, not the host (real ML-DSA, isolation) ----

test('description offline verify: same signed bytes re-verify regardless of the serving host', () => {
  const ops = C.description.operations.map(opOf);
  const desc = new description.Description(hexToBytes(C.description.service_hex), ops);
  const signed = description.signDescription(desc, ALG, SEED);
  // an unrelated party re-serving the identical bytes yields an identical verification.
  const v1 = description.verifyDescription(signed, cose.PROFILE_PUBLIC, ALG, PK);
  const v2 = description.verifyDescription(Uint8Array.from(signed), cose.PROFILE_PUBLIC, ALG, PK);
  assert.equal(bytesToHex(v1.bytes()), bytesToHex(v2.bytes()));
  assert.equal(bytesToHex(v1.id()), C.description.id_hex);
  // a tampered signature is rejected fail-closed (BadSignature).
  const bad = Uint8Array.from(signed);
  bad[bad.length - 1] ^= 1;
  assert.throws(() => description.verifyDescription(bad, cose.PROFILE_PUBLIC, ALG, PK), (e) => e.kind === 'BadSignature');
});

test('description directory fork proof is self-contained non-repudiable evidence (real ML-DSA, isolation)', () => {
  const dir = C.directory;
  const a = new description.Directory(hexToBytes(dir.directory_hex), dir.version, dir.members_a_hex.map(hexToBytes));
  const b = new description.Directory(hexToBytes(dir.directory_hex), dir.version, dir.fork.members_b_hex.map(hexToBytes));
  const signedA = description.signDirectory(a, ALG, SEED);
  const signedB = description.signDirectory(b, ALG, SEED);
  const signerBytes = new TextEncoder().encode(identity.signerId(ALG, PK));

  const proof = new description.DirectoryForkProof(signerBytes, signedA, signedB);
  assert.equal(proof.verify(cose.PROFILE_PUBLIC, ALG, PK), dir.fork.first_differing_position);

  // two identical signed directories are NOT a fork (DirForkProofInvalid).
  const benign = new description.DirectoryForkProof(signerBytes, signedA, description.signDirectory(a, ALG, SEED));
  assert.throws(() => benign.verify(cose.PROFILE_PUBLIC, ALG, PK), (e) => e.kind === 'DirForkProofInvalid');
  // an unnamed accused is not evidence.
  const unnamed = new description.DirectoryForkProof(new Uint8Array(0), signedA, signedB);
  assert.throws(() => unnamed.verify(cose.PROFILE_PUBLIC, ALG, PK), (e) => e.kind === 'DirForkProofInvalid');
});

test('description import confused-deputy: the wrapping signer is the sole authority (real ML-DSA, isolation)', () => {
  // The importer field MUST equal the verifying key's self-certifying id: a signer imports AS ITSELF,
  // never as a foreign identity embedded in the carried bytes (R-14.6).
  const keyId = identity.signerId(ALG, PK);
  const foreign = hexToBytes(C.import.foreign_hex);
  const ops = C.import.operations.map(opOf);
  const im = new description.Import(new TextEncoder().encode(keyId), C.import.format, foreign, ops);
  const signed = description.signImport(im, ALG, SEED);
  const resolved = description.verifyImport(signed, cose.PROFILE_PUBLIC, ALG, PK);
  assert.equal(resolved.authorityId, keyId, 'the authority is the wrapping key, not a foreign identity');
  assert.equal(bytesToHex(resolved.foreignId), bytesToHex(description.contentId(foreign)));

  // an attestation whose importer is NOT the verifying key's id is rejected ImporterMismatch: a foreign
  // identity named inside the object can never become the authorization identity.
  const imWrong = new description.Import(new TextEncoder().encode('did:wba:foreign.example:agent'), C.import.format, foreign, ops);
  const signedWrong = description.signImport(imWrong, ALG, SEED);
  assert.throws(() => description.verifyImport(signedWrong, cose.PROFILE_PUBLIC, ALG, PK), (e) => e.kind === 'ImporterMismatch');
});
