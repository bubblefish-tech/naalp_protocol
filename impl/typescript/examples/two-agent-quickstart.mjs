// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// examples/two-agent-quickstart.mjs — the N-AALP core loop, end-to-end, between two agents.
//
// Agent A generates an identity, builds and signs a real N-AALP object (a message on the Interaction
// surface), and hands agent B *only* the object bytes and A's public key. Agent B verifies the
// object offline — no shared connection, no shared secret — reads it, and rejects a tampered copy
// fail-closed. Every cryptographic and encoding step is the real SDK; nothing here is hand-rolled.
//
// Run:  node examples/two-agent-quickstart.mjs      (from impl/typescript/)

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { Signer, quick } from '../naalp/index.mjs';
import { cose, channels } from '../naalp/index.mjs';
import { U, T, M } from '../naalp/cbor.mjs';

// The Interaction surface (design-channels.md §16). Kind 0 (Elicit) is a read_only message an agent
// posts to another — "agent A posts a message on the interaction surface".
const INTERACTION = 0x000F;
const ELICIT = 0;

function line(label, value) {
  console.log(`  ${label.padEnd(16)} ${value}`);
}

function main() {
  console.log('N-AALP two-agent quickstart (TypeScript SDK)\n');

  // ---- Agent A: generate an identity -------------------------------------------------------------
  console.log('[1] Agent A generates a signing identity');
  const seedA = randomBytes(32);                       // a real random 32-byte ML-DSA seed
  const agentA = new Signer(seedA);                    // derives the public key + signer id (§5.1)
  line('alg', 'ML-DSA-65 (COSE ' + cose.ALG_MLDSA65 + ', FIPS 204)');
  line('signer id', agentA.signerId);
  line('public key', agentA.publicKey.length + ' bytes');

  // ---- Agent A: build and sign a message --------------------------------------------------------
  console.log('\n[2] Agent A builds and signs a message');
  const [kindName, effect] = channels.lookup(INTERACTION, ELICIT);
  const body = new M([
    [new U(1), new T('Hello, agent B — this is agent A.')],
    [new U(2), new T('Please confirm you can verify this object offline.')],
  ]);
  const signed = agentA.sign(INTERACTION, ELICIT, body, { created: Date.now() });
  line('channel/kind', `0x${INTERACTION.toString(16).padStart(4, '0')} ${channels.channelName(INTERACTION)} / ${ELICIT} ${kindName}`);
  line('effect', `${effect} (from the channel registry)`);
  line('signed object', signed.length + ' bytes (a single, self-describing COSE_Sign1)');

  // ---- The wire: agent B receives ONLY the bytes and A's public key -----------------------------
  console.log('\n[3] Over the wire, agent B receives only:');
  line('object bytes', signed.length + ' bytes');
  line("A's public key", agentA.publicKey.length + ' bytes');
  const wireBytes = Uint8Array.from(signed);
  const publicKeyOfA = Uint8Array.from(agentA.publicKey);

  // ---- Agent B: verify and read -----------------------------------------------------------------
  console.log('\n[4] Agent B verifies the object offline and reads it');
  const obj = quick.verify(publicKeyOfA, wireBytes);   // throws (fail-closed) on any failure
  const d = quick.describe(obj);
  line('verified', 'true');
  line('channel', d.channel);
  line('kind', d.kind);
  line('effect', String(d.effect));
  line('signer', d.signer);
  line('content id', d.contentId);
  const readBack = obj.body.pairs.map(([, v]) => v.v).join(' | ');
  line('message', readBack);

  // The signer id is self-certifying: it must recompute from the key B was given.
  assert.equal(quick.describe(obj).signer, agentA.signerId, 'signer id must recompute from the key');

  // ---- Fail-closed: a tampered object is rejected -----------------------------------------------
  console.log('\n[5] Agent B rejects a tampered object (fail-closed)');
  const tampered = Uint8Array.from(wireBytes);
  tampered[tampered.length - 1] ^= 0x01;               // flip one bit of the signature
  let rejected = false;
  let rejectionKind = '';
  try {
    quick.verify(publicKeyOfA, tampered);
  } catch (e) {
    rejected = true;
    rejectionKind = e.kind || e.constructor.name;
  }
  line('tampered', 'rejected: ' + rejectionKind);

  // This assertion makes the example mutation-surviving: if verify were bypassed or made a no-op,
  // the tampered object would be accepted, `rejected` would stay false, and the script would exit
  // non-zero here rather than printing success.
  assert.equal(rejected, true, 'a tampered object MUST be rejected');
  assert.equal(rejectionKind, 'BadSignature', 'tamper must fail with BadSignature');

  console.log('\nDone: A signed, B verified and read the message, and the tampered copy was rejected.');
}

main();
