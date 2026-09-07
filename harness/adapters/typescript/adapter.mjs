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
import { ed25519 } from '@noble/curves/ed25519.js';
import { tmpdir } from 'node:os';
import { unlinkSync } from 'node:fs';
import { join as pathJoin } from 'node:path';
import { randomUUID } from 'node:crypto';

import * as cbor from '../../../impl/typescript/naalp/cbor.mjs';
import * as cose from '../../../impl/typescript/naalp/cose.mjs';
import * as envelope from '../../../impl/typescript/naalp/envelope.mjs';
import * as approval from '../../../impl/typescript/naalp/approval.mjs';
import * as identity from '../../../impl/typescript/naalp/identity.mjs';
import * as policy from '../../../impl/typescript/naalp/policy.mjs';
import * as records from '../../../impl/typescript/naalp/records.mjs';
import * as graph from '../../../impl/typescript/naalp/graph.mjs';
import * as audit from '../../../impl/typescript/naalp/audit.mjs';
import * as federation from '../../../impl/typescript/naalp/federation.mjs';
import * as channels from '../../../impl/typescript/naalp/channels.mjs';
import * as streaming from '../../../impl/typescript/naalp/streaming.mjs';
import * as delivery from '../../../impl/typescript/naalp/delivery.mjs';
import * as naalperror from '../../../impl/typescript/naalp/naalperror.mjs';

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

    case 'rotation.leg_tbs':
      return { out: { tbs_hex: bytesToHex(cose.signatureToBeSigned(hx(inp, 'body_protected_hex'), Number(inp.leg_alg), hx(inp, 'payload_hex'))) } };

    case 'rotation.sign': {
      const prot = hx(inp, 'protected_hex');
      const payload = hx(inp, 'payload_hex');
      const oldLeg = cose.signatureLeg(prot, Number(inp.old_alg), hx(inp, 'old_seed_hex'), payload);
      const newLeg = cose.signatureLeg(prot, Number(inp.new_alg), hx(inp, 'new_seed_hex'), payload);
      return { out: { obj_hex: bytesToHex(cose.assembleSignRaw(prot, payload, [oldLeg, newLeg])) } };
    }

    case 'rotation.verify': {
      const obj = hx(inp, 'obj_hex');
      const oldAlg = Number(inp.old_alg);
      const newAlg = Number(inp.new_alg);
      const profile = Number(inp.profile);
      const oldPk = hx(inp, 'old_pubkey_hex');
      const newPk = hx(inp, 'new_pubkey_hex');
      const kindOk = (ch, k) => Number(ch) === 3 && Number(k) === 0;
      // dispatch by COSE tag: tag-98 (0xd8 0x62) -> two-leg verifyRotationObject; a tag-18
      // single-sig object -> the general verify, which rejects a (3,0) single-sig rotation.
      try {
        if (obj.length >= 2 && obj[0] === 0xd8 && obj[1] === 0x62) {
          envelope.verifyRotationObject(profile, oldAlg, oldPk, newAlg, newPk, kindOk, obj);
        } else {
          envelope.verify(profile, newAlg, newPk, kindOk, obj);
        }
        return { out: { valid: true, error: '' } };
      } catch (e) {
        return { out: { valid: false, error: e.kind || 'Malformed' } };
      }
    }

    case 'object.decode': {
      // R7 decoder resource bounds: decode + bound-enforce an untrusted object; all four object-
      // level bounds fire BEFORE the COSE signature is checked, so a permissive kind validator and
      // an unused (dummy) alg/pubkey are safe -- never reached for a reject. over_size materializes
      // the octet-size bound (rejected on raw length before any parse).
      const obj = Object.prototype.hasOwnProperty.call(inp, 'over_size')
        ? new Uint8Array(Number(inp.over_size))
        : hx(inp, 'obj_hex');
      const kindOk = () => true;
      try {
        envelope.verify(1, 0, new Uint8Array(0), kindOk, obj);
        return { out: { valid: true, error: '' } };
      } catch (e) {
        return { out: { valid: false, error: e.kind || 'Malformed' } };
      }
    }

    case 'stream.state': {
      // design.md §10 state table + § Timers (stream idle/commit timer): drive ONE stream through
      // an ordered `events` list on a fresh Guard; report the LAST event's outcome plus the
      // stream's final state. Graded against the independent, non-circular tools/streamstate_oracle.py
      // (F3).
      const rawEvents = Array.isArray(inp.events) ? inp.events : [];
      const g = new streaming.Guard();
      let lastErr = null;
      let lastStream = new Uint8Array(0);
      for (const em of rawEvents) {
        if (typeof em !== 'object' || em === null) return { error: 'stream.state: event is not an object' };
        const sid = hx(em, 'stream_hex');
        lastStream = sid;
        lastErr = null;
        try {
          switch (em.ev) {
            case 'open': {
              const o = new streaming.StreamOpen(sid, u(em, 'effect'), null, 0n);
              g.open(o, Number(u(em, 'granted')));
              break;
            }
            case 'chunk':
              g.chunk(sid);
              break;
            case 'checkpoint':
              g.checkpoint(sid);
              break;
            case 'commit': {
              const rawChunks = Array.isArray(em.chunks) ? em.chunks : [];
              const chunks = rawChunks.map((cm) => new streaming.Chunk(u(cm, 'offset'), hexToBytes(cm.data_hex || '')));
              const digest = hx(em, 'digest_hex');
              g.commit(new streaming.StreamCommit(sid, digest), chunks);
              break;
            }
            case 'expire':
              g.expire(sid);
              break;
            default:
              return { error: 'stream.state: unknown event ' + JSON.stringify(em.ev) };
          }
        } catch (e) {
          lastErr = e;
        }
      }
      return {
        out: {
          valid: lastErr === null,
          error: lastErr ? (lastErr.kind || '') : '',
          state: streaming.stateName(g.state(lastStream)),
        },
      };
    }

    case 'stream.verify_commit': {
      const n = Number(inp.chunk_count);
      const chunks = new Array(n);
      for (let i = 0; i < n; i++) chunks[i] = new streaming.Chunk(0, new Uint8Array(0));
      const commit = new streaming.StreamCommit(new Uint8Array(0), new Uint8Array(0));
      try {
        streaming.verifyCommit(commit, chunks);
        return { out: { valid: true, error: '' } };
      } catch (e) {
        return { out: { valid: false, error: e.kind || 'Malformed' } };
      }
    }

    case 'delivery.state': {
      // ietf draft "## Delivery state machine" (# Object State Machines): drive ONE object through
      // an ordered `events` list of signed delivery updates on a fresh WAL-backed Tracker; report
      // the LAST event's outcome plus the object's final stage name. A rejected event (regress ->
      // StageOutOfOrder) leaves the recorded stage unchanged. Graded against the independent,
      // non-circular tools/delivery_state_oracle.py (F3).
      const rawEvents = Array.isArray(inp.events) ? inp.events : [];
      const walPath = pathJoin(tmpdir(), `naalp-delivery-state-${randomUUID()}.wal`);
      const tr = delivery.openTracker(walPath);
      let lastErr = null;
      let lastObj = new Uint8Array(0);
      try {
        for (const em of rawEvents) {
          if (typeof em !== 'object' || em === null) return { error: 'delivery.state: event is not an object' };
          const obj = hx(em, 'obj_hex');
          lastObj = obj;
          lastErr = null;
          switch (em.ev) {
            case 'update':
              try {
                tr.advance(obj, u(em, 'stage'), 0n);
              } catch (e) {
                lastErr = e;
              }
              break;
            default:
              return { error: 'delivery.state: unknown event ' + JSON.stringify(em.ev) };
          }
        }
        const [st] = tr.stage(lastObj);
        return {
          out: {
            valid: lastErr === null,
            error: lastErr ? (lastErr.kind || '') : '',
            state: delivery.stageName(st),
          },
        };
      } finally {
        tr.close();
        try { unlinkSync(walPath); } catch { /* best-effort cleanup */ }
      }
    }

    case 'approval.state': {
      // ietf draft "## Approval state machine" (# Object State Machines): build ONE signed approval,
      // then drive it through an ordered `events` list of consume attempts through the REAL composed
      // choke point approval.consumeApproval on a fresh single-use ledger; report the LAST event's
      // {valid, error} plus the ledger length after it (the draft's "ledger left untouched by a
      // rejected request", observable via Ledger.len()). Graded against the independent, non-circular
      // tools/approval_state_oracle.py (F3). The approver key is a deterministic Ed25519 test key --
      // the signature is verified, not graded (bytes are not compared across ports for this op).
      const am = inp.approval;
      if (typeof am !== 'object' || am === null) return { error: 'approval.state: missing approval object' };
      const a = new approval.ApprovalRecord(
        hx(am, 'approves_hex'), am.approver || '', u(am, 'grant'), hx(am, 'nonce_hex'), u(am, 'not_after'));
      const seed = new Uint8Array(32); // deterministic all-zero test approver seed
      const pubkey = ed25519.getPublicKey(seed);
      const sig = cose.ed25519Sign(seed, a.bytes());

      const walPath = pathJoin(tmpdir(), `naalp-approval-state-${randomUUID()}.wal`);
      const ledger = approval.openLedger(walPath);
      try {
        const rawEvents = Array.isArray(inp.events) ? inp.events : [];
        let lastErr = null;
        for (const em of rawEvents) {
          if (typeof em !== 'object' || em === null) return { error: 'approval.state: event is not an object' };
          lastErr = null;
          switch (em.ev) {
            case 'consume':
              try {
                approval.consumeApproval(
                  a, cose.ALG_ED25519, pubkey, sig, hx(em, 'present_cid_hex'),
                  u(em, 'pos_time'), u(em, 'required_effect'), ledger, em.by || '');
              } catch (e) {
                lastErr = e;
              }
              break;
            default:
              return { error: 'approval.state: unknown event ' + JSON.stringify(em.ev) };
          }
        }
        return {
          out: {
            valid: lastErr === null,
            error: lastErr ? (lastErr.kind || '') : '',
            ledger_len: ledger.len(),
          },
        };
      } finally {
        ledger.close();
        try { unlinkSync(walPath); } catch { /* best-effort cleanup */ }
      }
    }

    // ---- T3.3 naalp-error object + numeric error-code registry (design.md §3.5) ----
    case 'error.name_for_code': {
      // Grades the port's embedded 119-entry name<->code table per-code, plus the unknown-code
      // (opaque) contract.
      const { name, registered } = naalperror.nameForCode(u(inp, 'code'));
      return { out: { name, registered } };
    }

    case 'error.encode': {
      // Deterministic CBOR of a naalp-error body {1:code, 2:name, ?3:detail, ?4:subject}.
      const subject = Object.prototype.hasOwnProperty.call(inp, 'subject_hex') ? hx(inp, 'subject_hex') : null;
      const detail = typeof inp.detail === 'string' ? inp.detail : '';
      const name = typeof inp.name === 'string' ? inp.name : '';
      const body = naalperror.encode(u(inp, 'code'), name, detail, subject);
      return { out: { body_hex: bytesToHex(body) } };
    }

    case 'error.decode': {
      // Parse + dual-carriage validate a naalp-error body (registered code + wrong name ->
      // Malformed; unknown code -> opaque accept).
      try {
        const o = naalperror.decode(hx(inp, 'body_hex'));
        return { out: { valid: true, code: o.code, name: o.name } };
      } catch (e) {
        return { out: { valid: false, error: e.kind || 'Malformed' } };
      }
    }

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

    case 'reconcile.state': {
      // ietf draft "## Reconcile state machine" (# Object State Machines): drive the machine
      // through ONE event (add-chain | linearize | verify) on fresh state and report
      // {valid, error}. add-chain runs the draft's fixed verifyChain-then-observe pipeline (a
      // `chain` that must independently pass verifyChain, plus an optional `extra` receipt fed
      // only to observe -- a chain array cannot itself carry a duplicate seq without independently
      // tripping ChainBroken, so equivocation is exercised via the separate `extra` observation);
      // linearize runs federation.reconcile (which calls graph.verifyCausal internally); verify
      // runs federation.verifyReconcileOrder, which MUST recompute via reconcile() (content-id
      // tie-break), never a position/index tie-break. Graded against the independent, non-circular
      // tools/reconcile_state_oracle.py (F3). The authority key is a deterministic all-zero
      // ML-DSA-65 test seed -- the signature is verified, not graded (bytes are not compared
      // across ports for this op).
      const ALG = cose.ALG_MLDSA65;
      const SEED = new Uint8Array(32); // deterministic all-zero test authority seed
      const PK = cose.mldsaKeygen('ML-DSA-65', SEED);

      const buildReceipt = (rm) => new audit.Receipt(hx(rm, 'prev_hex'), hx(rm, 'obj_hex'), u(rm, 'seq'), u(rm, 'at'));
      const nodesFrom = (i2) => (i2.nodes || []).map((n) =>
        new federation.CausalNode(hx(n, 'id_hex'), (n.causes_hex || []).map(hexToBytes)));

      switch (inp.event) {
        case 'add-chain': {
          const rawChain = Array.isArray(inp.chain) ? inp.chain : [];
          const receipts = [];
          const sigs = [];
          for (const rm of rawChain) {
            const r = buildReceipt(rm);
            receipts.push(r);
            sigs.push(cose.mldsaSign(ALG, SEED, r.bytes()));
          }
          if (typeof inp.corrupt_sig_at === 'number') {
            const corrupted = Uint8Array.from(sigs[inp.corrupt_sig_at]);
            corrupted[0] ^= 0xFF;
            sigs[inp.corrupt_sig_at] = corrupted;
          }
          let lastErr = null;
          try {
            audit.verifyChain(receipts, sigs, ALG, PK);
            const auditor = new audit.Auditor(ALG, PK, PK, 0);
            for (let i = 0; i < receipts.length && lastErr === null; i++) {
              const fp = auditor.observe(receipts[i], sigs[i]);
              if (fp !== null) lastErr = new audit.AuditError('Equivocation');
            }
            if (lastErr === null && inp.extra && typeof inp.extra === 'object') {
              const er = buildReceipt(inp.extra);
              const esig = cose.mldsaSign(ALG, SEED, er.bytes());
              const fp = auditor.observe(er, esig);
              if (fp !== null) lastErr = new audit.AuditError('Equivocation');
            }
          } catch (e) {
            lastErr = e;
          }
          return { out: { valid: lastErr === null, error: lastErr ? (lastErr.kind || '') : '' } };
        }

        case 'linearize': {
          try {
            federation.reconcile(nodesFrom(inp));
            return { out: { valid: true, error: '' } };
          } catch (e) {
            return { out: { valid: false, error: e.kind || '' } };
          }
        }

        case 'verify': {
          try {
            const nodes = nodesFrom(inp);
            const order = (inp.claimed_order_hex || []).map(hexToBytes);
            const rec = new federation.ReconcileRecord([], order);
            federation.verifyReconcileOrder(rec, nodes);
            return { out: { valid: true, error: '' } };
          } catch (e) {
            return { out: { valid: false, error: e.kind || '' } };
          }
        }

        default:
          return { error: 'reconcile.state: unknown event ' + JSON.stringify(inp.event) };
      }
    }

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

    // ---- opt-in LAMPS composite signature (alg -65537, design.md §4.2) ----
    case 'composite.mprime':
      return { out: { mprime_hex: bytesToHex(cose.computeMprime(
        new TextEncoder().encode('COMPSIG-MLDSA65-Ed25519-SHA512'), new Uint8Array(0), hx(inp, 'm_hex'))) } };

    case 'composite.signerid':
      try {
        return { out: { signer_id: identity.compositeSignerId(Number(inp.mldsa_alg), hx(inp, 'mldsa_pubkey_hex'), hx(inp, 'ed_pubkey_hex')) } };
      } catch (e) { return errKind(e, 'UnknownAlg'); }

    case 'composite.sign':
      return { out: { value_hex: bytesToHex(cose.compositeSign(hx(inp, 'mldsa_seed_hex'), hx(inp, 'ed_seed_hex'), hx(inp, 'tbs_hex'))) } };

    case 'composite.verify':
      return { out: { valid: cose.compositeVerify(hx(inp, 'mldsa_pubkey_hex'), hx(inp, 'ed_pubkey_hex'), hx(inp, 'm_hex'), hx(inp, 'sig_hex')) } };

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
