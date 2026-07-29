// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// naalp-adapter-typescript — the TypeScript/ESM N-AALP conformance adapter.
//
// Wraps the impl/typescript `naalp` SDK behind the length-prefixed JSON op protocol the
// naalp-conform runner drives (harness/INSTRUCTIONS.md): a 4-byte little-endian length + UTF-8 JSON
// {"op","in"} request on stdin, and a {"out"|"error"|"skipped"} response in the same framing on
// stdout, flushed after each. Node has a deterministic ML-DSA library (@noble/post-quantum) and
// Ed25519 (@noble/curves), so it implements every op including the crypto leg.

import { sha384 } from '@noble/hashes/sha2.js';

import * as cbor from '../../../impl/typescript/naalp/cbor.mjs';
import * as cose from '../../../impl/typescript/naalp/cose.mjs';
import * as identity from '../../../impl/typescript/naalp/identity.mjs';
import * as policy from '../../../impl/typescript/naalp/policy.mjs';
import * as records from '../../../impl/typescript/naalp/records.mjs';
import * as graph from '../../../impl/typescript/naalp/graph.mjs';
import * as channels from '../../../impl/typescript/naalp/channels.mjs';

const hexToBytes = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');

function tagged(v) {
  // Convert a language-neutral tagged value into a cbor.Value.
  if (!Array.isArray(v) || v.length !== 2) throw new Error('tagged value must be [tag, payload]');
  const [tag, p] = v;
  if (tag === 'u') return new cbor.U(typeof p === 'string' ? BigInt(p) : BigInt(p));
  if (tag === 'b') return new cbor.B(hexToBytes(p));
  if (tag === 's') return new cbor.T(String(p));
  if (tag === 'arr') return new cbor.A(p.map(tagged));
  if (tag === 'map') return new cbor.M(p.map(([k, val]) => [tagged(k), tagged(val)]));
  throw new Error('unknown tag ' + JSON.stringify(tag));
}

// u accepts a JSON number or a decimal string (64-bit counters travel as strings when they exceed
// 2^53); returns a BigInt so large values keep full precision through the CBOR encoder.
function u(inp, k) {
  const v = inp[k];
  if (typeof v === 'string') return BigInt(v);
  if (v === undefined || v === null) return 0n;
  return BigInt(v);
}

const hx = (inp, k) => hexToBytes(inp[k]);

function errKind(e, fallback) {
  const kind = (e && e.kind) ? e.kind : fallback;
  return { error: kind + ': ' + (e && e.message ? e.message : String(e)) };
}

function handle(op, inp) {
  switch (op) {
    case 'sha384':
      return { out: { digest_hex: bytesToHex(sha384(hx(inp, 'msg_hex'))) } };

    case 'cbor.encode':
      return { out: { bytes_hex: bytesToHex(cbor.encode(tagged(inp.value))) } };

    case 'cbor.decode':
      try { cbor.decode(hx(inp, 'bytes_hex')); return { out: { ok: true } }; }
      catch (e) { return errKind(e, 'Malformed'); }

    case 'content.id': {
      const v = cbor.decode(hx(inp, 'body_hex'));
      return { out: { id_hex: bytesToHex(cbor.contentId(v)) } };
    }

    case 'cose.tbs':
      return { out: { tobesigned_hex: bytesToHex(cose.toBeSignedRaw(hx(inp, 'protected_hex'), hx(inp, 'payload_hex'))) } };

    case 'mldsa.keygen':
      return { out: { pk_hex: bytesToHex(cose.mldsaKeygen(inp.param || 'ML-DSA-65', hx(inp, 'seed_hex'))) } };

    case 'ed25519.sign':
      return { out: { sig_hex: bytesToHex(cose.ed25519Sign(hx(inp, 'sk_hex'), hx(inp, 'msg_hex'))) } };

    case 'cose.sign1': {
      const obj = cose.coseSign1(Number(inp.alg), hx(inp, 'seed_hex'), hx(inp, 'protected_hex'), hx(inp, 'payload_hex'));
      return { out: { obj_hex: bytesToHex(obj) } };
    }

    case 'cose.verify1':
      return { out: { valid: cose.coseVerify1(Number(inp.alg), hx(inp, 'pubkey_hex'), hx(inp, 'obj_hex')) } };

    case 'signerid':
      try { return { out: { signer_id: identity.signerId(Number(inp.alg), hx(inp, 'pubkey_hex')) } }; }
      catch (e) { return errKind(e, 'UnknownAlg'); }

    case 'nfc.check': {
      const s = Buffer.from(hx(inp, 'utf8_hex')).toString('utf-8');
      try { identity.requireNFC(s); return { out: { ok: true } }; }
      catch (e) { return errKind(e, 'NonNFC'); }
    }

    case 'effect.normalize':
      return { out: { effect: policy.normalizeEffect(u(inp, 'value')) } };

    case 'effect.authorize':
      return { out: { allow: policy.authorizes(policy.normalizeEffect(u(inp, 'granted')), Number(u(inp, 'effect'))) } };

    case 'effect.safety_label':
      return { out: { cbor_hex: bytesToHex(policy.safetyLabelBytes(inp.risk || '', inp.scope || '')) } };

    case 'approval.body':
    case 'approval.id': {
      const args = [hx(inp, 'approves_hex'), inp.approver || '', u(inp, 'grant'), hx(inp, 'nonce_hex'), u(inp, 'not_after')];
      if (op === 'approval.id') return { out: { id_hex: bytesToHex(records.approvalId(...args)) } };
      return { out: { body_hex: bytesToHex(records.approvalBody(...args)) } };
    }

    case 'ledger.entry':
      return { out: { body_hex: bytesToHex(records.ledgerEntry(u(inp, 'seq'), hx(inp, 'prev_hex'), hx(inp, 'approval_id_hex'), inp.by || '')) } };

    case 'receipt.body':
      return { out: { body_hex: bytesToHex(records.receiptBody(hx(inp, 'prev_hex'), hx(inp, 'obj_hex'), u(inp, 'seq'), u(inp, 'at'))) } };

    case 'receipt.head':
      return { out: { head_hex: bytesToHex(records.receiptHead(hx(inp, 'body_hex'))) } };

    case 'causal.verify': {
      const nodes = inp.nodes.map((n) => [
        hexToBytes(n.id_hex),
        (n.causes_hex || []).map(hexToBytes),
        Number(n.position || 0),
      ]);
      try { graph.verifyCausal(nodes); return { out: { valid: true } }; }
      catch (e) { return errKind(e, 'CausalViolation'); }
    }

    case 'delivery.update':
      return { out: { body_hex: bytesToHex(records.deliveryUpdate(hx(inp, 'obj_hex'), u(inp, 'stage'), u(inp, 'at'))) } };

    case 'stream.digest': {
      const chunks = inp.chunks.map((c) => [BigInt(c.offset), hexToBytes(c.data_hex)]);
      return { out: { digest_hex: bytesToHex(records.streamDigest(chunks)) } };
    }

    case 'stream.open': {
      const approval = inp.approval_hex ? hexToBytes(inp.approval_hex) : new Uint8Array(0);
      return { out: { body_hex: bytesToHex(records.streamOpenBody(hx(inp, 'stream_id_hex'), u(inp, 'effect'), approval, u(inp, 'substream'))) } };
    }

    case 'stream.commit':
      return { out: { body_hex: bytesToHex(records.streamCommitBody(hx(inp, 'stream_id_hex'), hx(inp, 'digest_hex'))) } };

    case 'stream.checkpoint':
      return { out: { body_hex: bytesToHex(records.streamCheckpointBody(hx(inp, 'stream_id_hex'), u(inp, 'through_offset'), hx(inp, 'digest_so_far_hex'))) } };

    case 'transport.emit':
      try { return { out: { result: records.transportEmit(inp.transport || '', Boolean(inp.sensitive), Boolean(inp.require_peer_auth)) } }; }
      catch (e) { return { error: String(e && e.message ? e.message : e) }; }

    case 'carriage.body':
      try {
        const body = records.carriageBody(u(inp, 'protocol_id'), u(inp, 'class'), u(inp, 'content_type'),
          hx(inp, 'correlation_hex'), inp.method || '', hx(inp, 'foreign_hex'));
        return { out: { body_hex: bytesToHex(body) } };
      } catch (e) { return errKind(e, 'MappingError'); }

    case 'channels.lookup':
      try {
        const [name, effect, variable] = channels.lookup(u(inp, 'channel'), u(inp, 'kind'));
        return { out: { name, effect, variable } };
      } catch (e) { return errKind(e, 'UnknownKind'); }

    case 'channels.effect_check':
      try { channels.checkEffect(u(inp, 'channel'), u(inp, 'kind'), u(inp, 'effect')); return { out: { ok: true } }; }
      catch (e) { return errKind(e, 'EffectDeclarationMismatch'); }

    case 'federation.reconcile': {
      const nodes = inp.nodes.map((n) => [
        hexToBytes(n.id_hex),
        (n.causes_hex || []).map(hexToBytes),
        Number(n.position || 0),
      ]);
      try { const order = graph.reconcile(nodes); return { out: { order: order.map(bytesToHex) } }; }
      catch (e) { return errKind(e, 'CausalViolation'); }
    }

    case 'federation.record': {
      const order = (inp.order || []).map(hexToBytes);
      return { out: { body_hex: bytesToHex(graph.reconcileRecord(inp.authorities || [], order)) } };
    }

    default:
      return { skipped: 'op not implemented: ' + op };
  }
}

// ---- framing loop: 4-byte LE length + UTF-8 JSON ----

let buf = Buffer.alloc(0);

function process_(body) {
  let req, resp;
  try {
    req = JSON.parse(body.toString('utf-8'));
    resp = handle(req.op || '', req.in || {});
  } catch (e) {
    resp = { error: 'adapter exception: ' + (e && e.message ? e.message : String(e)) };
  }
  const ob = Buffer.from(JSON.stringify(resp), 'utf-8');
  const len4 = Buffer.alloc(4);
  len4.writeUInt32LE(ob.length, 0);
  process.stdout.write(Buffer.concat([len4, ob]));
}

process.stdin.on('data', (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  for (;;) {
    if (buf.length < 4) return;
    const n = buf.readUInt32LE(0);
    if (buf.length < 4 + n) return;
    const body = buf.subarray(4, 4 + n);
    buf = buf.subarray(4 + n);
    process_(body);
  }
});

process.stdin.on('end', () => process.exit(0));
