# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
naalp-adapter-python — the Python N-AALP conformance adapter.

Wraps the impl/python `naalp` SDK behind the length-prefixed JSON op protocol the naalp-conform
runner drives (harness/INSTRUCTIONS.md): a 4-byte little-endian length + UTF-8 JSON {"op","in"}
request on stdin, and a {"out"|"error"|"skipped"} response in the same framing on stdout, flushed
after each. Python has a deterministic ML-DSA library (dilithium-py), so it implements every op
including the crypto leg.
"""
import json
import os
import struct
import sys
import tempfile

# make the impl/python package importable regardless of cwd
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "..", "impl", "python"))

from naalp import approval as approval_mod  # noqa: E402 (aliased: `approval` is also a local var name in the stream.open op below)
from naalp import audit, cbor, channels, cose, delivery, envelope, federation, graph, identity, naalperror, policy, records, streaming  # noqa: E402


def _tagged(v):
    """Convert a language-neutral tagged value into a cbor.Value."""
    if not isinstance(v, list) or len(v) != 2:
        raise ValueError("tagged value must be [tag, payload]")
    tag, p = v
    if tag == "u":
        return cbor.U(int(p))
    if tag == "b":
        return cbor.B(bytes.fromhex(p))
    if tag == "s":
        return cbor.T(str(p))
    if tag == "arr":
        return cbor.A([_tagged(i) for i in p])
    if tag == "map":
        return cbor.M([(_tagged(k), _tagged(val)) for k, val in p])
    raise ValueError("unknown tag %r" % tag)


def _u(inp, k):
    v = inp.get(k)
    if isinstance(v, str):
        return int(v)
    return int(v) if v is not None else 0


def _hx(inp, k):
    return bytes.fromhex(inp[k])


def handle(op, inp):
    if op == "sha384":
        import hashlib
        return {"out": {"digest_hex": hashlib.sha384(_hx(inp, "msg_hex")).hexdigest()}}
    if op == "cbor.encode":
        return {"out": {"bytes_hex": cbor.encode(_tagged(inp["value"])).hex()}}
    if op == "cbor.decode":
        try:
            cbor.decode(_hx(inp, "bytes_hex"))
            return {"out": {"ok": True}}
        except Exception as e:
            return {"error": "%s: %s" % (getattr(e, "kind", "Malformed"), e)}
    if op == "content.id":
        v = cbor.decode(_hx(inp, "body_hex"))
        return {"out": {"id_hex": cbor.content_id(v).hex()}}
    if op == "cose.tbs":
        return {"out": {"tobesigned_hex": cose.to_be_signed_raw(_hx(inp, "protected_hex"), _hx(inp, "payload_hex")).hex()}}
    if op == "mldsa.keygen":
        return {"out": {"pk_hex": cose.mldsa_keygen(inp.get("param", "ML-DSA-65"), _hx(inp, "seed_hex")).hex()}}
    if op == "ed25519.sign":
        return {"out": {"sig_hex": cose.ed25519_sign(_hx(inp, "sk_hex"), _hx(inp, "msg_hex")).hex()}}
    if op == "cose.sign1":
        obj = cose.cose_sign1(int(inp["alg"]), _hx(inp, "seed_hex"), _hx(inp, "protected_hex"), _hx(inp, "payload_hex"))
        return {"out": {"obj_hex": obj.hex()}}
    if op == "cose.verify1":
        return {"out": {"valid": cose.cose_verify1(int(inp["alg"]), _hx(inp, "pubkey_hex"), _hx(inp, "obj_hex"))}}
    if op == "rotation.leg_tbs":
        return {"out": {"tbs_hex": cose.signature_to_be_signed(_hx(inp, "body_protected_hex"), int(inp["leg_alg"]), _hx(inp, "payload_hex")).hex()}}
    if op == "rotation.sign":
        prot, payload = _hx(inp, "protected_hex"), _hx(inp, "payload_hex")
        old_leg = cose.signature_leg(prot, int(inp["old_alg"]), _hx(inp, "old_seed_hex"), payload)
        new_leg = cose.signature_leg(prot, int(inp["new_alg"]), _hx(inp, "new_seed_hex"), payload)
        return {"out": {"obj_hex": cose.assemble_sign_raw(prot, payload, [old_leg, new_leg]).hex()}}
    if op == "rotation.verify":
        obj = _hx(inp, "obj_hex")
        old_alg, new_alg, profile = int(inp["old_alg"]), int(inp["new_alg"]), int(inp["profile"])
        old_pk, new_pk = _hx(inp, "old_pubkey_hex"), _hx(inp, "new_pubkey_hex")
        # dispatch by COSE tag: tag-98 (0xd8 0x62) -> two-leg verify_rotation_object; a tag-18
        # single-sig object -> the general verify, which rejects a (3,0) single-sig rotation.
        try:
            if len(obj) >= 2 and obj[0] == 0xd8 and obj[1] == 0x62:
                envelope.verify_rotation_object(profile, old_alg, old_pk, new_alg, new_pk,
                                                lambda ch, k: ch == 3 and k == 0, obj)
            else:
                envelope.verify(profile, new_alg, new_pk, lambda ch, k: ch == 3 and k == 0, obj)
            return {"out": {"valid": True, "error": ""}}
        except Exception as e:
            return {"out": {"valid": False, "error": getattr(e, "kind", "Malformed")}}
    if op == "object.decode":
        # R7 decoder resource bounds: decode + bound-enforce an untrusted object; all four
        # object-level bounds fire BEFORE the COSE signature is checked, so no verifier is
        # ever consulted -- pubkey=None is safe. over_size materializes the octet-size bound
        # (rejected on raw length before any parse).
        if "over_size" in inp:
            obj = bytes(int(_u(inp, "over_size")))
        else:
            obj = _hx(inp, "obj_hex")
        try:
            envelope.verify(cose.PROFILE_PUBLIC, 0, None, lambda ch, k: True, obj)
            return {"out": {"valid": True, "error": ""}}
        except Exception as e:
            return {"out": {"valid": False, "error": getattr(e, "kind", "Malformed")}}
    if op == "stream.verify_commit":
        n = int(_u(inp, "chunk_count"))
        chunks = [streaming.Chunk(0, b"") for _ in range(n)]
        try:
            streaming.verify_commit(streaming.StreamCommit(b"", b""), chunks)
            return {"out": {"valid": True, "error": ""}}
        except Exception as e:
            return {"out": {"valid": False, "error": getattr(e, "kind", "Malformed")}}
    if op == "signerid":
        try:
            return {"out": {"signer_id": identity.signer_id(int(inp["alg"]), _hx(inp, "pubkey_hex"))}}
        except Exception as e:
            return {"error": "%s: %s" % (getattr(e, "kind", "UnknownAlg"), e)}
    if op == "nfc.check":
        s = _hx(inp, "utf8_hex").decode("utf-8")
        try:
            identity.require_nfc(s)
            return {"out": {"ok": True}}
        except Exception as e:
            return {"error": "%s: %s" % (getattr(e, "kind", "NonNFC"), e)}
    if op == "effect.normalize":
        return {"out": {"effect": policy.normalize_effect(_u(inp, "value"))}}
    if op == "effect.authorize":
        return {"out": {"allow": policy.authorizes(policy.normalize_effect(_u(inp, "granted")), _u(inp, "effect"))}}
    if op == "effect.safety_label":
        return {"out": {"cbor_hex": policy.safety_label_bytes(inp.get("risk", ""), inp.get("scope", "")).hex()}}
    if op in ("approval.body", "approval.id"):
        args = (_hx(inp, "approves_hex"), inp.get("approver", ""), _u(inp, "grant"), _hx(inp, "nonce_hex"), _u(inp, "not_after"))
        if op == "approval.id":
            return {"out": {"id_hex": records.approval_id(*args).hex()}}
        return {"out": {"body_hex": records.approval_body(*args).hex()}}
    if op == "ledger.entry":
        return {"out": {"body_hex": records.ledger_entry(_u(inp, "seq"), _hx(inp, "prev_hex"), _hx(inp, "approval_id_hex"), inp.get("by", "")).hex()}}
    if op == "receipt.body":
        return {"out": {"body_hex": records.receipt_body(_hx(inp, "prev_hex"), _hx(inp, "obj_hex"), _u(inp, "seq"), _u(inp, "at")).hex()}}
    if op == "receipt.head":
        return {"out": {"head_hex": records.receipt_head(_hx(inp, "body_hex")).hex()}}
    if op == "approval.state":
        # ietf draft "## Approval state machine" (# Object State Machines): build ONE signed approval,
        # then drive it through an ordered `events` list of consume attempts through the REAL composed
        # choke point approval.consume_approval on a fresh single-use ledger; report the LAST event's
        # {valid, error} plus the ledger length after it (the draft's "ledger left untouched by a
        # rejected request", observable via len(ledger)). Graded against the independent, non-circular
        # tools/approval_state_oracle.py (F3). The approver key is a deterministic Ed25519 test key --
        # the signature is verified, not graded (bytes are not compared across ports for this op).
        # Mirrors harness/adapters/go/main.go's approval.state case.
        am = inp.get("approval")
        if not isinstance(am, dict):
            return {"error": "approval.state: missing approval object"}
        a = approval_mod.ApprovalRecord(
            _hx(am, "approves_hex"), am.get("approver", ""), _u(am, "grant"),
            _hx(am, "nonce_hex"), _u(am, "not_after"))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        seed = bytes(32)  # deterministic all-zero test approver seed
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        sig = cose.ed25519_sign(seed, a.bytes())

        fd, path = tempfile.mkstemp(prefix="naalp-approval-state-", suffix=".wal")
        os.close(fd)
        try:
            ledger = approval_mod.open_ledger(path)
            try:
                last_err = None
                for em in inp.get("events") or []:
                    ev = em.get("ev")
                    if ev != "consume":
                        return {"error": "approval.state: unknown event %r" % (ev,)}
                    last_err = None
                    try:
                        approval_mod.consume_approval(
                            a, cose.ALG_ED25519, pub, sig, _hx(em, "present_cid_hex"),
                            _u(em, "pos_time"), _u(em, "required_effect"), ledger, em.get("by", ""))
                    except Exception as e:
                        last_err = e
                return {"out": {
                    "valid": last_err is None,
                    "error": "" if last_err is None else getattr(last_err, "kind", "Malformed"),
                    "ledger_len": len(ledger),
                }}
            finally:
                ledger.close()
        finally:
            os.remove(path)
    if op == "causal.verify":
        nodes = [(bytes.fromhex(n["id_hex"]), [bytes.fromhex(c) for c in n.get("causes_hex", [])], int(n.get("position", 0)))
                 for n in inp["nodes"]]
        try:
            graph.verify_causal(nodes)
            return {"out": {"valid": True}}
        except Exception as e:
            return {"error": "%s: %s" % (getattr(e, "kind", "CausalViolation"), e)}
    if op == "delivery.update":
        return {"out": {"body_hex": records.delivery_update(_hx(inp, "obj_hex"), _u(inp, "stage"), _u(inp, "at")).hex()}}
    if op == "delivery.state":
        # ietf draft "## Delivery state machine" (# Object State Machines): drive ONE object
        # through an ordered `events` list of signed delivery updates on a fresh WAL-backed
        # Tracker; report the LAST event's outcome plus the object's final stage name. A
        # rejected event (regress -> StageOutOfOrder) leaves the recorded stage unchanged.
        # Graded against the independent, non-circular tools/delivery_state_oracle.py (F3).
        # Mirrors harness/adapters/go/main.go's delivery.state case.
        raw_events = inp.get("events") or []
        fd, path = tempfile.mkstemp(prefix="naalp-delivery-state-", suffix=".wal")
        os.close(fd)
        try:
            tr = delivery.open_tracker(path)
            try:
                last_err = None
                last_obj = b""
                for em in raw_events:
                    obj = _hx(em, "obj_hex")
                    last_obj = obj
                    ev = em.get("ev")
                    if ev != "update":
                        return {"error": "delivery.state: unknown event %r" % (ev,)}
                    last_err = None
                    try:
                        tr.advance(obj, _u(em, "stage"), 0)
                    except Exception as e:
                        last_err = e
                st, _seen = tr.stage(last_obj)
                return {"out": {
                    "valid": last_err is None,
                    "error": "" if last_err is None else getattr(last_err, "kind", "Malformed"),
                    "state": delivery.stage_name(st),
                }}
            finally:
                tr.close()
        finally:
            os.remove(path)
    if op == "stream.digest":
        chunks = [(int(c["offset"]), bytes.fromhex(c["data_hex"])) for c in inp["chunks"]]
        return {"out": {"digest_hex": records.stream_digest(chunks).hex()}}
    if op == "stream.open":
        approval = bytes.fromhex(inp["approval_hex"]) if inp.get("approval_hex") else b""
        return {"out": {"body_hex": records.stream_open_body(_hx(inp, "stream_id_hex"), _u(inp, "effect"), approval, _u(inp, "substream")).hex()}}
    if op == "stream.commit":
        return {"out": {"body_hex": records.stream_commit_body(_hx(inp, "stream_id_hex"), _hx(inp, "digest_hex")).hex()}}
    if op == "stream.checkpoint":
        return {"out": {"body_hex": records.stream_checkpoint_body(_hx(inp, "stream_id_hex"), _u(inp, "through_offset"), _hx(inp, "digest_so_far_hex")).hex()}}
    if op == "stream.state":
        # design.md §10 state table + § Timers (stream idle/commit timer): drive ONE stream through
        # an ordered `events` list on a fresh Guard; report the LAST event's outcome plus the
        # stream's final state. Graded against the independent, non-circular
        # tools/streamstate_oracle.py (F3). Mirrors harness/adapters/go/main.go's stream.state case.
        raw_events = inp.get("events") or []
        g = streaming.Guard()
        last_err = None
        last_stream = b""
        for em in raw_events:
            sid = _hx(em, "stream_hex")
            last_stream = sid
            ev = em.get("ev")
            last_err = None
            try:
                if ev == "open":
                    o = streaming.StreamOpen(sid, _u(em, "effect"), None, 0)
                    g.open(o, _u(em, "granted"))
                elif ev == "chunk":
                    g.chunk(sid)
                elif ev == "checkpoint":
                    g.checkpoint(sid)
                elif ev == "commit":
                    chunks = [streaming.Chunk(_u(cm, "offset"), bytes.fromhex(cm["data_hex"]))
                              for cm in em.get("chunks") or []]
                    commit_obj = streaming.StreamCommit(sid, _hx(em, "digest_hex"))
                    g.commit(commit_obj, chunks)
                elif ev == "expire":
                    g.expire(sid)
                else:
                    return {"error": "stream.state: unknown event %r" % (ev,)}
            except Exception as e:
                last_err = e
        return {"out": {
            "valid": last_err is None,
            "error": "" if last_err is None else getattr(last_err, "kind", "Malformed"),
            "state": streaming.state_name(g.state(last_stream)),
        }}
    if op == "transport.emit":
        try:
            return {"out": {"result": records.transport_emit(inp.get("transport", ""), bool(inp.get("sensitive")), bool(inp.get("require_peer_auth")))}}
        except Exception as e:
            return {"error": str(e)}
    if op == "carriage.body":
        try:
            body = records.carriage_body(_u(inp, "protocol_id"), _u(inp, "class"), _u(inp, "content_type"),
                                         _hx(inp, "correlation_hex"), inp.get("method", ""), _hx(inp, "foreign_hex"))
            return {"out": {"body_hex": body.hex()}}
        except Exception as e:
            return {"error": "%s: %s" % (getattr(e, "kind", "MappingError"), e)}
    if op == "channels.lookup":
        try:
            name, effect, variable = channels.lookup(_u(inp, "channel"), _u(inp, "kind"))
            return {"out": {"name": name, "effect": effect, "variable": variable}}
        except Exception as e:
            return {"error": "%s: %s" % (getattr(e, "kind", "UnknownKind"), e)}
    if op == "channels.effect_check":
        try:
            channels.check_effect(_u(inp, "channel"), _u(inp, "kind"), _u(inp, "effect"))
            return {"out": {"ok": True}}
        except Exception as e:
            return {"error": "%s: %s" % (getattr(e, "kind", "EffectDeclarationMismatch"), e)}
    if op == "federation.reconcile":
        nodes = [(bytes.fromhex(n["id_hex"]), [bytes.fromhex(c) for c in n.get("causes_hex", [])], int(n.get("position", 0)))
                 for n in inp["nodes"]]
        try:
            order = graph.reconcile(nodes)
            return {"out": {"order": [o.hex() for o in order]}}
        except Exception as e:
            return {"error": "%s: %s" % (getattr(e, "kind", "CausalViolation"), e)}
    if op == "federation.record":
        order = [bytes.fromhex(o) for o in inp.get("order", [])]
        return {"out": {"body_hex": graph.reconcile_record(inp.get("authorities", []), order).hex()}}
    if op == "reconcile.state":
        # ietf draft "## Reconcile state machine" (# Object State Machines): drive the machine
        # through ONE event (add-chain | linearize | verify) on fresh state and report
        # {valid, error}. add-chain runs the draft's fixed VerifyChain-then-Observe pipeline (a
        # `chain` that must independently pass verify_chain, plus an optional `extra` receipt fed
        # only to Auditor.observe -- a chain array cannot itself carry a duplicate seq without
        # independently tripping ChainBroken, so equivocation is exercised via the separate `extra`
        # observation); linearize runs federation.reconcile (which calls graph.verify_causal
        # internally); verify runs federation.verify_reconcile_order, which MUST recompute via
        # reconcile() (content-id tie-break), never a position/index tie-break. Graded against the
        # independent, non-circular tools/reconcile_state_oracle.py (F3). The authority key is a
        # deterministic all-zero-seed ML-DSA-65 test key (the same pattern impl/python's own
        # test_audit.py uses) -- the signature is verified, not graded (bytes are not compared
        # across ports for this op). Mirrors harness/adapters/go/main.go's reconcile.state case.
        _ALG = cose.ALG_MLDSA65
        _SEED = bytes(32)  # deterministic all-zero test authority seed
        _PK = cose.mldsa_keygen("ML-DSA-65", _SEED)

        def _build_receipt(rm):
            return audit.Receipt(_hx(rm, "prev_hex"), _hx(rm, "obj_hex"), _u(rm, "seq"), _u(rm, "at"))

        def _nodes_from(inp):
            raw = inp.get("nodes") or []
            return [federation.CausalNode(_hx(nm, "id_hex"),
                                          [bytes.fromhex(c) for c in nm.get("causes_hex") or []])
                    for nm in raw]

        event = inp.get("event")
        if event == "add-chain":
            raw_chain = inp.get("chain") or []
            receipts = []
            sigs = []
            for rm in raw_chain:
                r = _build_receipt(rm)
                receipts.append(r)
                sigs.append(cose.mldsa_sign(_ALG, _SEED, r.bytes()))
            ci = inp.get("corrupt_sig_at")
            if ci is not None:
                idx = int(ci)
                corrupted = bytearray(sigs[idx])
                corrupted[0] ^= 0xFF
                sigs[idx] = bytes(corrupted)
            last_err = None
            try:
                audit.verify_chain(receipts, sigs, _ALG, _PK)
            except Exception as e:
                last_err = e
            if last_err is None:
                auditor = audit.Auditor(_ALG, _PK, _PK)
                for i, r in enumerate(receipts):
                    try:
                        fp = auditor.observe(r, sigs[i])
                    except Exception as e:
                        last_err = e
                        break
                    if fp is not None:
                        last_err = audit.AuditError("Equivocation", "two receipts at one seq name different objects")
                        break
                if last_err is None:
                    em = inp.get("extra")
                    if isinstance(em, dict):
                        er = _build_receipt(em)
                        esig = cose.mldsa_sign(_ALG, _SEED, er.bytes())
                        try:
                            fp = auditor.observe(er, esig)
                        except Exception as e:
                            last_err = e
                        else:
                            if fp is not None:
                                last_err = audit.AuditError("Equivocation", "two receipts at one seq name different objects")
            return {"out": {"valid": last_err is None, "error": "" if last_err is None else getattr(last_err, "kind", "Malformed")}}
        if event == "linearize":
            nodes = _nodes_from(inp)
            try:
                federation.reconcile(nodes)
                last_err = None
            except Exception as e:
                last_err = e
            return {"out": {"valid": last_err is None, "error": "" if last_err is None else getattr(last_err, "kind", "Malformed")}}
        if event == "verify":
            nodes = _nodes_from(inp)
            order = [bytes.fromhex(o) for o in inp.get("claimed_order_hex") or []]
            rec = federation.ReconcileRecord([], order)
            try:
                federation.verify_reconcile_order(rec, nodes)
                last_err = None
            except Exception as e:
                last_err = e
            return {"out": {"valid": last_err is None, "error": "" if last_err is None else getattr(last_err, "kind", "Malformed")}}
        return {"error": "reconcile.state: unknown event %r" % (event,)}
    # ---- opt-in LAMPS composite signature (alg -65537, design.md §4.2) ----
    if op == "composite.mprime":
        # M' = Prefix || Label || len(ctx)=0x00 || SHA-512(M); the committed non-circular KAT.
        mp = cose.compute_mprime(cose._COMPOSITE_LABEL_MLDSA65_ED25519, b"", _hx(inp, "m_hex"))
        return {"out": {"mprime_hex": mp.hex()}}
    if op == "composite.signerid":
        try:
            sid = identity.composite_signer_id(int(inp["mldsa_alg"]), _hx(inp, "mldsa_pubkey_hex"),
                                               _hx(inp, "ed_pubkey_hex"))
            return {"out": {"signer_id": sid}}
        except Exception as e:
            return {"error": "%s: %s" % (getattr(e, "kind", "UnknownAlg"), e)}
    if op == "composite.sign":
        # deterministic two-leg value mldsaSig || edSig over the ToBeSigned; consensus-graded.
        val = cose.composite_sign(_hx(inp, "mldsa_seed_hex"), _hx(inp, "ed_seed_hex"), _hx(inp, "tbs_hex"))
        return {"out": {"value_hex": val.hex()}}
    if op == "composite.verify":
        ok = cose.composite_verify(_hx(inp, "mldsa_pubkey_hex"), _hx(inp, "ed_pubkey_hex"),
                                   _hx(inp, "m_hex"), _hx(inp, "sig_hex"))
        return {"out": {"valid": ok}}
    # ---- T3.3 naalp-error object + numeric error-code registry (design.md §3.5) ----
    if op == "error.name_for_code":
        name, registered = naalperror.name_for_code(_u(inp, "code"))
        return {"out": {"name": name, "registered": registered}}
    if op == "error.encode":
        subject = _hx(inp, "subject_hex") if "subject_hex" in inp else None
        body = naalperror.encode(_u(inp, "code"), inp.get("name", ""), inp.get("detail", ""), subject)
        return {"out": {"body_hex": body.hex()}}
    if op == "error.decode":
        try:
            o = naalperror.decode(_hx(inp, "body_hex"))
            return {"out": {"valid": True, "code": o.code, "name": o.name}}
        except Exception as e:
            return {"out": {"valid": False, "error": getattr(e, "kind", "Malformed")}}
    return {"skipped": "op not implemented: " + op}


def main():
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        lp = stdin.read(4)
        if len(lp) < 4:
            return
        n = struct.unpack("<I", lp)[0]
        body = stdin.read(n)
        try:
            req = json.loads(body)
            resp = handle(req.get("op", ""), req.get("in", {}) or {})
        except Exception as e:
            resp = {"error": "adapter exception: %s" % e}
        ob = json.dumps(resp).encode("utf-8")
        stdout.write(struct.pack("<I", len(ob)))
        stdout.write(ob)
        stdout.flush()


if __name__ == "__main__":
    main()
