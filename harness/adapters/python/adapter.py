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

# make the impl/python package importable regardless of cwd
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "..", "impl", "python"))

from naalp import cbor, channels, cose, graph, identity, policy, records  # noqa: E402


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
