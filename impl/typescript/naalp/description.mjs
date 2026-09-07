// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C18 -- the signed description / directory primitive for the TypeScript SDK (design.md §21;
// R-DESC-1..8).
//
// C18 is a signed, OFFLINE-VERIFIABLE description and discovery layer carried on N-AALP's own signed
// object. Its load-bearing property is that authority lives in the SIGNED BYTES, never in the connection
// or the host that served them: the same signed Description re-verifies byte-identically when an
// unrelated host serves it, because the signature (not a TLS-fetch origin) is the authority. It
// introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3): each object is
// an ordinary signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice (policy) and the
// T1 content-id framing (§2.3) unchanged.
//
// Three wire objects:
//
//   - Description {1: service, 2: operations[]} lists a service's operations, each Operation
//     {1: name, 2: effect, 3: requires_approval} carrying its C5 effect and an approval declaration.
//     parseDescription reconstructs the whole operation table from the bytes ALONE.
//   - Directory {1: directory, 2: version, 3: members[]} is a signed collection whose members are
//     content ids. Two conflicting versions from ONE signer -- same directory and version, different
//     members -- are a FORK, detected at the FIRST-DIFFERING member POSITION (as the §8.5 audit
//     fork-proof reports the position of an equivocation).
//   - Import {1: importer, 2: format, 3: foreign, 4: operations[]} carries a foreign description format
//     (an A2A Agent Card, an ANP Agent Description, an AGNTCY Agent Badge) octet-for-octet (carriage,
//     not adoption) as a signed N-AALP attestation binding the foreign bytes' content id AND an N-AALP
//     effect mapping. The IMPORTER (the wrapping signer, recomputed self-certifyingly from the verifying
//     key) is the SOLE authorization identity; a foreign identity embedded in `foreign` never becomes an
//     N-AALP authorization identity -- the confused-deputy rule, enforced normatively here (R-14.6).
//
// Every check is fail-closed (§15). Ported from impl/go/description (with impl/python/naalp/description.py
// as a second reference); the byte surface (bodies, heads, content ids, foreign-id binding, fork
// position, closed foreign-format rejection) is graded against vectors/description/cases.json; the
// offline-verification, fork-proof, and confused-deputy paths use real deterministic ML-DSA-65 and are
// demonstrated in isolation (the corpus carries no signed vector).
//
// Deviation from the Go reference, honest F4 note: Go's VerifyImport carries an ErrVerifierKeyMismatch
// guard because it takes BOTH an (alg, pubkey) pair AND a separate cose.Verifier, and must bind them
// before deriving the authority id. The TypeScript idiom (as gateway.verifyDecision) verifies with a
// single (alg, pubkey) pair, so the authority id is ALWAYS derived from exactly the key that verified
// the signature -- the mismatch the Go guard prevents is structurally impossible here, so there is no
// VerifierKeyMismatch surface to port. It is not silently dropped; it is absent because the vulnerability
// it guards cannot arise in this signature.

import { sha384 } from '@noble/hashes/sha2.js';
import * as cbor from './cbor.mjs';
import { U, N, B, T, A, M } from './cbor.mjs';
import * as cose from './cose.mjs';
import * as policy from './policy.mjs';
import * as identity from './identity.mjs';

// The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
export const HEAD_SIZE = 48;

// Foreign description format codes (design §21; the closed naalp-description-format registry).
export const FORMAT_A2A_CARD = 1;         // A2A Agent Card
export const FORMAT_ANP_DESCRIPTION = 2;  // ANP Agent Description
export const FORMAT_AGNTCY_BADGE = 3;     // AGNTCY Agent Badge

const KNOWN_FORMATS = new Set([FORMAT_A2A_CARD, FORMAT_ANP_DESCRIPTION, FORMAT_AGNTCY_BADGE]);

// A named, fail-closed C18 error; .kind is the stable error kind (mirroring the Go/Rust/Python kinds
// DescMalformed, MalformedApprovalFlag, DirForkProofInvalid, ImporterMismatch, UnknownDescriptionFormat,
// plus the reused cose kinds BadSignature/UnknownAlg/ProfileDowngrade/KeyAlgMismatch).
export class DescriptionError extends Error {
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

// SHA-384 over a body -- a 48-octet digest (the same construction as the C7 receipt head).
export function head(b) {
  return sha384(Uint8Array.from(b));
}

// T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
export function contentId(b) {
  return cbor.contentId(Uint8Array.from(b));
}

function isKnownFormat(fmt) {
  return KNOWN_FORMATS.has(Number(fmt));
}

// ---- Operation: one listed operation with its effect + approval declaration (design §21.2) -----

// One entry of a Description or Import mapping: a named operation, its C5 effect class, and whether it
// requires an approval. requiresApproval is the uint 1 (yes) / 0 (no) -- no CBOR boolean (design §3.1).
export class Operation {
  constructor(name, effect, requiresApproval) {
    this.name = String(name);
    this.effect = Number(effect);
    this.requiresApproval = Number(requiresApproval);
  }

  toMap() {
    return new M([
      [new U(1), new T(this.name)],
      [new U(2), new U(this.effect)],
      [new U(3), new U(this.requiresApproval)],
    ]);
  }

  // Deterministic-CBOR encoding of the operation body {1:name,2:effect,3:requires_approval}.
  bytes() {
    return cbor.encode(this.toMap());
  }

  // The per-operation effect, normalized fail-closed: an unrecognized value is destructive.
  effectClass() {
    return policy.normalizeEffect(this.effect);
  }

  // True iff the operation declares that it requires an approval.
  requiresApprovalFlag() {
    return this.requiresApproval === 1;
  }
}

// Parse one operation map, rejecting a malformed shape (DescMalformed) or an approval flag outside {0,1}
// (MalformedApprovalFlag). Fail-closed.
export function operationFromValue(v) {
  if (!(v instanceof M)) throw new DescriptionError('DescMalformed', 'operation is not a map');
  let name = null;
  let effect = null;
  let req = null;
  for (const [k, val] of v.pairs) {
    if (!(k instanceof U)) throw new DescriptionError('DescMalformed', 'non-uint operation key');
    if (k.v === 1n && val instanceof T) name = val.v;
    else if (k.v === 2n && val instanceof U) effect = val.v;
    else if (k.v === 3n && val instanceof U) req = val.v;
  }
  if (name === null || effect === null || req === null) {
    throw new DescriptionError('DescMalformed', 'operation missing a mandatory field');
  }
  if (req > 1n) throw new DescriptionError('MalformedApprovalFlag', 'requires_approval is outside {0,1}');
  return new Operation(name, effect, req);
}

function operationsFromValue(v) {
  if (!(v instanceof A)) throw new DescriptionError('DescMalformed', 'operations is not an array');
  return v.items.map(operationFromValue);
}

function operationsValue(ops) {
  return new A(ops.map((op) => op.toMap()));
}

function findOperation(ops, name) {
  for (const op of ops) {
    if (op.name === name) return [op, true];
  }
  return [null, false];
}

// ---- Description: a service's signed operation table (design §21.2) ----------------------------

// A signed N-AALP object listing a service's operations. Its authority is in the signed bytes:
// parseDescription reconstructs the whole operation table (each operation's effect and approval
// declaration) from the bytes alone, so an unrelated host serving the same bytes yields a byte-identical
// verification (offline-verifiable, not fetch-authenticated).
export class Description {
  constructor(service, operations) {
    this.service = Uint8Array.from(service);
    this.operations = Array.from(operations);
  }

  // Deterministic-CBOR encoding {1: service, 2: operations[]}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.service)],
      [new U(2), operationsValue(this.operations)],
    ]));
  }

  head() {
    return head(this.bytes());
  }

  id() {
    return contentId(this.bytes());
  }

  // The named operation and whether it is listed.
  operation(name) {
    return findOperation(this.operations, name);
  }
}

// Reconstruct a Description from its body bytes ALONE -- the offline-verifiable property.
export function parseDescription(b) {
  const m = decodeMap(b);
  const svc = bstrField(m, 1);
  const opsV = field(m, 2);
  if (svc === null || opsV === null) throw new DescriptionError('DescMalformed', 'description missing service or operations');
  return new Description(svc, operationsFromValue(opsV));
}

// Produce the tagged COSE_Sign1 object over the Description body.
export function signDescription(d, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), d.bytes());
}

// Verify the Description's full signature under the profile, then reconstruct the operation table from
// the signed body bytes. Because the authority is the signature over the bytes, this returns the
// identical Description regardless of which host served `obj` (R-DESC-1). Fail-closed.
export function verifyDescription(obj, profile, alg, pubkey) {
  const payload = verifySign1(obj, profile, alg, pubkey);
  return parseDescription(payload);
}

// ---- Directory: a signed collection of content ids, with fork detection (design §21.3) ----------

// A signed collection object whose members are content ids. It carries a monotonic per-signer version so
// two versions can be compared for equivocation.
export class Directory {
  constructor(directory, version, members) {
    this.directory = Uint8Array.from(directory);
    this.version = Number(version);
    this.members = Array.from(members, (m) => Uint8Array.from(m));
  }

  // Deterministic-CBOR encoding {1: directory, 2: version, 3: members[]}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.directory)],
      [new U(2), new U(this.version)],
      [new U(3), new A(this.members.map((m) => new B(m)))],
    ]));
  }

  head() {
    return head(this.bytes());
  }

  id() {
    return contentId(this.bytes());
  }
}

// Reconstruct a Directory from its body bytes alone.
export function parseDirectory(b) {
  const m = decodeMap(b);
  const did = bstrField(m, 1);
  const ver = uintField(m, 2);
  const memV = field(m, 3);
  if (did === null || ver === null || memV === null || !(memV instanceof A)) {
    throw new DescriptionError('DescMalformed', 'directory missing or malformed field');
  }
  const members = [];
  for (const e of memV.items) {
    if (!(e instanceof B)) throw new DescriptionError('DescMalformed', 'member is not a bstr');
    members.push(e.v);
  }
  return new Directory(did, ver, members);
}

// Produce the tagged COSE_Sign1 object over the Directory body.
export function signDirectory(d, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), d.bytes());
}

// Verify the Directory's full signature under the profile, then reconstruct it from the signed body
// bytes. Fail-closed.
export function verifyDirectory(obj, profile, alg, pubkey) {
  const payload = verifySign1(obj, profile, alg, pubkey);
  return parseDirectory(payload);
}

// The first index at which two member lists differ, and whether they differ at all. If the lists share a
// common prefix and one is longer, the difference is reported at the length of the shorter list.
// Identical lists return [0, false].
export function firstMemberDifference(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (!bytesEqual(Uint8Array.from(a[i]), Uint8Array.from(b[i]))) return [i, true];
  }
  if (a.length !== b.length) return [n, true];
  return [0, false];
}

// Compare two directory versions from ONE signer and report whether they equivocate -- the SAME
// directory id and version but DIFFERENT members -- and, if so, the FIRST-DIFFERING member POSITION. A
// different directory id or version is a legitimate distinct object/succession, not a fork; identical
// members are a benign duplicate. In both non-fork cases returns [0, false]. The caller establishes the
// 'one signer' precondition by verifying both objects under the same key.
export function detectFork(a, b) {
  if (!bytesEqual(a.directory, b.directory) || a.version !== b.version) return [0, false];
  return firstMemberDifference(a.members, b.members);
}

// Non-repudiable evidence of a directory fork: two validly-signed Directory objects by ONE signer at the
// SAME (directory, version) listing DIFFERENT members, carried as the accused signer's OWN two signed
// objects. Because a single verifier checks BOTH signed objects, the proof is self-contained.
export class DirectoryForkProof {
  constructor(signer, signedA, signedB) {
    this.signer = Uint8Array.from(signer);
    this.signedA = Uint8Array.from(signedA);
    this.signedB = Uint8Array.from(signedB);
  }

  // Check that this is a genuine directory fork by the signer whose key is (alg, pubkey), and return the
  // FIRST-DIFFERING member POSITION. Accepts iff ALL hold: (1) the signer id is present; (2) BOTH signed
  // objects verify under the key (which, because a single verifier checks both, proves one signer);
  // (3) the two directories share one directory id and version; and (4) their member lists differ. Any
  // failure rejects the whole proof (fail-closed): an unnamed signer, a different directory/version, or
  // identical members is DirForkProofInvalid; a signature that does not verify propagates BadSignature.
  verify(profile, alg, pubkey) {
    if (this.signer.length === 0) throw new DescriptionError('DirForkProofInvalid', 'an unnamed accused is not evidence');
    const a = verifyDirectory(this.signedA, profile, alg, pubkey);
    const b = verifyDirectory(this.signedB, profile, alg, pubkey);
    const [pos, fork] = detectFork(a, b);
    if (!fork) {
      throw new DescriptionError('DirForkProofInvalid',
        'same directory+version identical members, or not the same versioned directory');
    }
    return pos;
  }
}

// ---- Import: foreign description carried as a signed attestation (design §21.4) -----------------

// Carries a foreign description format octet-for-octet (carriage, not adoption) as a signed N-AALP
// attestation. `importer` is the wrapping signer id (the sole authorization identity); `foreign` is the
// foreign bytes verbatim; `operations` is the N-AALP effect mapping the importer attests. The foreign
// bytes' content id is bound by foreignId.
export class Import {
  constructor(importer, format, foreign, operations) {
    this.importer = Uint8Array.from(importer);
    this.format = Number(format);
    this.foreign = Uint8Array.from(foreign);
    this.operations = Array.from(operations);
  }

  // Deterministic-CBOR encoding {1: importer, 2: format, 3: foreign, 4: operations[]}.
  bytes() {
    return cbor.encode(new M([
      [new U(1), new B(this.importer)],
      [new U(2), new U(this.format)],
      [new U(3), new B(this.foreign)],
      [new U(4), operationsValue(this.operations)],
    ]));
  }

  head() {
    return head(this.bytes());
  }

  id() {
    return contentId(this.bytes());
  }

  // The T1 content id of the carried foreign bytes -- the hash the attestation binds. A changed foreign
  // document yields a different foreignId, so an attestation binds the exact bytes.
  foreignId() {
    return contentId(this.foreign);
  }

  operation(name) {
    return findOperation(this.operations, name);
  }
}

// Reconstruct an Import from its body bytes alone. A format code outside the closed
// naalp-description-format set {1,2,3} is rejected on decode (UnknownDescriptionFormat), never carried as
// an unknown format. Fail-closed.
export function parseImport(b) {
  const m = decodeMap(b);
  const imp = bstrField(m, 1);
  const fmt = uintField(m, 2);
  const foreign = bstrField(m, 3);
  const opsV = field(m, 4);
  if (imp === null || fmt === null || foreign === null || opsV === null) {
    throw new DescriptionError('DescMalformed', 'import missing a mandatory field');
  }
  if (!isKnownFormat(fmt)) {
    throw new DescriptionError('UnknownDescriptionFormat', 'import format ' + fmt + ' is outside the closed set {1,2,3}');
  }
  return new Import(imp, fmt, foreign, operationsFromValue(opsV));
}

// Produce the tagged COSE_Sign1 object over the Import body.
export function signImport(im, alg, seed) {
  return cose.coseSign1(alg, seed, protectedHeader(alg), im.bytes());
}

// An Import that has passed signature verification and the confused-deputy check. authorityId is the
// self-certifying signer id RECOMPUTED from the verifying key -- the wrapping signer, and the only
// authorization identity. It is never any identity parsed from the foreign bytes.
export class ResolvedImport {
  constructor(authorityId, format, foreignId, operations) {
    this.authorityId = authorityId;
    this.format = format;
    this.foreignId = Uint8Array.from(foreignId);
    this.operations = Array.from(operations);
  }
}

// Verify a foreign-description import end-to-end and enforce the confused-deputy rule normatively. It (1)
// verifies the signed object under the profile with real crypto; (2) recomputes the wrapping signer's
// SELF-CERTIFYING id from the verifying key (identity.signerId); and (3) requires the attestation's
// `importer` field to equal that recomputed id (ImporterMismatch otherwise). The returned authorityId is
// that recomputed key id -- the wrapping signer -- so no field inside the carried foreign bytes,
// including any foreign identity claim, can ever become the N-AALP authorization identity (R-14.6). Any
// failure returns its named error and authorizes nothing (fail-closed).
export function verifyImport(obj, profile, alg, pubkey) {
  const payload = verifySign1(obj, profile, alg, pubkey);
  const im = parseImport(payload);
  const keyId = identity.signerId(alg, pubkey);
  // The authorization identity is the wrapping key's own id. The attestation's declared importer MUST
  // match it: a signer can only ever import AS ITSELF, never as a foreign identity it names.
  if (new TextDecoder('utf-8', { fatal: false }).decode(im.importer) !== keyId) {
    throw new DescriptionError('ImporterMismatch', 'the attested importer is not the verifying key\'s signer id');
  }
  return new ResolvedImport(keyId, im.format, im.foreignId(), im.operations);
}

// ---- signing / verification helpers (COSE_Sign1 with the bare {1: alg} header) ------------------

// The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits (matching
// gateway.gatewayProtectedHeader).
function protectedHeader(alg) {
  return cbor.encode(new M([[new U(1), new N(alg)]]));
}

// Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the payload.
// Mirrors gateway.verifyDecision's checks: alg registry, profile floor, key-alg match, signature.
// Fail-closed with a named DescriptionError.
function verifySign1(obj, profile, alg, pubkey) {
  const [prot, payload, sig] = cose.parseSign1Raw(obj);
  const halg = algFromProtected(prot);
  const [level, known] = cose.algLevel(halg);
  if (!known) throw new DescriptionError('UnknownAlg', 'unregistered alg ' + halg);
  if (level < cose.profileMinLevel(profile)) {
    throw new DescriptionError('ProfileDowngrade', 'signature level below the profile minimum');
  }
  if (halg !== Number(alg)) {
    throw new DescriptionError('KeyAlgMismatch', 'alg ' + halg + ' does not match the verifier key alg ' + alg);
  }
  const tbs = cose.toBeSignedRaw(prot, payload);
  if (!cose.coseVerify1Raw(halg, pubkey, tbs, sig)) {
    throw new DescriptionError('BadSignature', 'signature does not verify');
  }
  return payload;
}

function algFromProtected(prot) {
  const v = cbor.decode(prot);
  if (v instanceof M) {
    for (const [k, val] of v.pairs) {
      if (k instanceof U && k.v === 1n && (val instanceof N || val instanceof U)) return Number(val.v);
    }
  }
  throw new DescriptionError('DescMalformed', 'protected header has no alg');
}

// ---- small deterministic-CBOR field accessors -------------------------------------------------

function decodeMap(b) {
  let v;
  try {
    v = cbor.decode(Uint8Array.from(b));
  } catch (e) {
    if (e instanceof cbor.NonCanonical) throw new DescriptionError('DescMalformed', 'body is not well-formed deterministic CBOR');
    throw e;
  }
  if (!(v instanceof M)) throw new DescriptionError('DescMalformed', 'body is not a map');
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
