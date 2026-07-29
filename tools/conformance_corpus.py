# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
conformance_corpus.py — assemble the cross-language conformance corpus for N-AALP.

This does NOT compute any expected value itself. It RESHAPES the per-family oracle
outputs in vectors/<family>/cases.json (each emitted by an independent, non-circular
oracle in tools/<name>_oracle.py, anchored to an RFC / FIPS / NIST vector or a
from-scratch constructor) into the language-agnostic op-replay corpus that the
`naalp-conform` runner drives through every SDK adapter.

Because every expected byte here traces back to a per-family oracle (F3 non-circular),
grading an adapter against this corpus is grading it against an independent authority,
never against another implementation.

Output: vectors/conformance/corpus.json in the schema
  { algorithm, schemaVersion, specRevision, testGroups: [
      { op, profile, tests: [ { tcId, requirement, comment, in, expected, result, flags } ] } ] }
with result in {"valid","invalid","acceptable"} exactly as the runner's grader expects.

Run:  python tools/conformance_corpus.py     (writes the corpus; LF line endings)
"""
import hashlib
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VEC = os.path.join(ROOT, "vectors")


def load(fam, sub=None):
    p = os.path.join(VEC, fam, sub, "cases.json") if sub else os.path.join(VEC, fam, "cases.json")
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def sha384_hex(body_hex):
    return hashlib.sha384(bytes.fromhex(body_hex)).hexdigest()


def tagged_map_from_obj(obj):
    """The cbor oracle's obj_without_id is {str(uintkey): taggedvalue}; rebuild it as a
    tagged CBOR map ["map", [[["u",k], v], ...]] so the encoder-under-test produces bytes."""
    pairs = [[["u", int(k)], v] for k, v in obj.items()]
    return ["map", pairs]


def group(op, tests, profile="any"):
    return {"op": op, "profile": profile, "tests": tests}


def t(tc, req, in_, expected=None, result="valid", flags=None, comment=""):
    d = {"tcId": tc, "requirement": req, "comment": comment, "in": in_, "result": result}
    if expected is not None:
        d["expected"] = expected
    if flags:
        d["flags"] = flags
    return d


def build():
    groups = []

    # ---- C1: SHA-384 KAT, deterministic CBOR encode, content-id, canonical-reject ----
    cbor = load("cbor")
    kat = cbor["sha384_kat"]
    groups.append(group("sha384", [
        t(1, "R-16.1/sha384-kat", {"msg_hex": kat["input_utf8"].encode("utf-8").hex()},
          {"digest_hex": kat["digest_hex"]}, comment="FIPS 180-4 SHA-384('abc')"),
    ]))

    enc_tests, cid_tests = [], []
    for i, pos in enumerate(cbor["positives"], 1):
        enc_tests.append(t(i, "R-3.1/deterministic-cbor", {"value": tagged_map_from_obj(pos["obj_without_id"])},
                           {"bytes_hex": pos["body_no1_hex"]}, comment=f"encode '{pos['name']}' body"))
        cid_tests.append(t(i, "R-2.3/content-id", {"body_hex": pos["body_no1_hex"]},
                          {"id_hex": pos["id_hex"]}, comment=f"content-id of '{pos['name']}'"))
    groups.append(group("cbor.encode", enc_tests))
    groups.append(group("content.id", cid_tests))

    dec_tests = []
    for i, neg in enumerate(cbor["negatives"], 1):
        dec_tests.append(t(i, "R-3.4/reject-non-canonical", {"bytes_hex": neg["bytes_hex"]},
                           result="invalid", flags=["MustReject", neg["expect"]],
                           comment=f"{neg['name']} -> {neg['expect']}"))
    groups.append(group("cbor.decode", dec_tests))

    # ---- C2: COSE ToBeSigned (RFC 9052), ML-DSA keyGen (NIST ACVP), Ed25519 (RFC 8032) ----
    cose = load("cose")
    tbs_tests = []
    for i, s in enumerate(cose["sign1"], 1):
        tbs_tests.append(t(i, "R-4.1/cose-tobesigned",
                           {"protected_hex": s["protected_hex"], "payload_hex": s["payload_hex"]},
                           {"tobesigned_hex": s["tobesigned_hex"]}, comment=s["name"]))
    groups.append(group("cose.tbs", tbs_tests))

    kg_tests = []
    for i, kv in enumerate(cose["mldsa_keygen"], 1):
        kg_tests.append(t(i, "R-4.3/mldsa-keygen-nist", {"param": kv["param"], "seed_hex": kv["seed_hex"]},
                         {"pk_hex": kv["pk_hex"]}, comment=f"{kv['param']} NIST ACVP seed->pk"))
    groups.append(group("mldsa.keygen", kg_tests))

    ed = cose["ed25519_rfc8032_test1"]
    groups.append(group("ed25519.sign", [
        t(1, "R-4.6/ed25519-rfc8032", {"sk_hex": ed["sk_hex"], "msg_hex": ed["msg_hex"]},
          {"sig_hex": ed["sig_hex"]}, comment="RFC 8032 §7.1 test 1"),
    ]))

    # cose.sign1 / cose.verify1 are graded by the crypto-consensus gate (harness/crypto-consensus.sh),
    # not by this corpus: the deterministic ML-DSA signature has no clean non-circular committed KAT
    # (the ACVP sigGen vectors are an internal interface). The corpus carries the inputs as
    # `acceptable` so an adapter that implements them is exercised; byte-parity across languages is
    # asserted by the consensus gate (Go==Rust==... over the same seed+payload), and each impl's
    # ML-DSA correctness is anchored here by mldsa.keygen (NIST) + cose.tbs (RFC 9052).
    # only ML-DSA sign1 cases (deterministic, byte-reproducible); Ed25519 signing is the
    # ed25519.sign op above (RFC 8032 KAT).
    sign1_tests = []
    tc = 1
    for s in cose["sign1"]:
        seed = next((kv["seed_hex"] for kv in cose["mldsa_keygen"] if kv["alg"] == s["alg"]), None)
        if seed is None:
            continue
        sign1_tests.append(t(tc, "R-4.1/cose-sign1-deterministic",
                             {"alg": s["alg"], "seed_hex": seed,
                              "protected_hex": s["protected_hex"], "payload_hex": s["payload_hex"]},
                             result="acceptable", flags=["crypto", "consensus-graded"],
                             comment=f"{s['name']} deterministic COSE_Sign1"))
        tc += 1
    groups.append(group("cose.sign1", sign1_tests))

    # ---- C4: signer id (multiformats PeerHandle), NFC ----
    ident = load("identity")
    sid_tests = []
    for i, sg in enumerate(ident["signers"], 1):
        sid_tests.append(t(i, "R-5.1/signer-id", {"alg": sg["alg"], "pubkey_hex": sg["pubkey_hex"]},
                          {"signer_id": sg["signer_id"]}, comment=sg["name"]))
    groups.append(group("signerid", sid_tests))

    nfc = ident["nfc"]
    groups.append(group("nfc.check", [
        t(1, "R-3.3/nfc-accept", {"utf8_hex": nfc["nfc_utf8_hex"]}, {"ok": True}, comment="NFC 'café' accepted"),
        t(2, "R-3.3/nfc-reject", {"utf8_hex": nfc["nfd_utf8_hex"]}, result="invalid",
          flags=["MustReject", "NonNFC"], comment="NFD 'café' rejected"),
    ]))

    # ---- C5: effect normalize / authorize / safety-label ----
    eff = load("effect")
    norm_tests = []
    for i, e in enumerate(eff["effects"], 1):
        norm_tests.append(t(i, "R-6.1/effect-normalize", {"value": e["value"]}, {"effect": e["value"]},
                           comment=e["safety_label"]))
    for j, u in enumerate(eff["unknown_normalization"], len(norm_tests) + 1):
        norm_tests.append(t(j, "R-6.2/unknown-fails-closed", {"value": u["input"]}, {"effect": u["effect"]},
                           comment=f"unknown {u['input']} -> {u['effect']} (destructive)"))
    groups.append(group("effect.normalize", norm_tests))

    auth_tests = []
    for i, m in enumerate(eff["authorization_matrix"], 1):
        auth_tests.append(t(i, "R-6.1/effect-authorize", {"granted": m["granted"], "effect": m["effect"]},
                           {"allow": m["allow"]}, comment=f"grant {m['granted']} vs effect {m['effect']}"))
    groups.append(group("effect.authorize", auth_tests))

    sl = eff["safety_label"]
    groups.append(group("effect.safety_label", [
        t(1, "R-6.4/safety-label-cbor", {"risk": sl["risk"], "scope": sl["scope"]},
          {"cbor_hex": sl["cbor_hex"]}, comment="signed safety label bytes"),
    ]))

    # ---- C6: approval body + id, ledger entry ----
    appr = load("approval")
    ab_tests, ai_tests = [], []
    for i, a in enumerate(appr["approvals"], 1):
        in_ = {"approves_hex": a["approves_hex"], "approver": a["approver"], "grant": a["grant"],
               "nonce_hex": a["nonce_hex"], "not_after": a["not_after"]}
        ab_tests.append(t(i, "R-7.1/approval-body", in_, {"body_hex": a["record_hex"]}, comment=a["name"]))
        ai_tests.append(t(i, "R-7.1/approval-id", in_, {"id_hex": a["approval_id_hex"]}, comment=a["name"]))
    groups.append(group("approval.body", ab_tests))
    groups.append(group("approval.id", ai_tests))

    led = appr["ledger"]
    le_tests = []
    prev = led["genesis_head_hex"]  # prev of entry n is the head after entry n-1 (genesis for seq 0)
    tcl = 1
    for c in led["consumes"]:
        if "entry_hex" not in c:  # a rejected double-consume appends no entry (expect=AlreadyConsumed)
            continue
        le_tests.append(t(tcl, "R-7.2/ledger-entry",
                          {"seq": c["seq"], "prev_hex": prev,
                           "approval_id_hex": c["approval_id_hex"], "by": c["by"]},
                          {"body_hex": c["entry_hex"]}, comment=f"consume seq {c['seq']}"))
        prev = c["head_after_hex"]
        tcl += 1
    groups.append(group("ledger.entry", le_tests))

    # ---- C7: receipt body + head, causal verify ----
    aud = load("audit")
    rb_tests, rh_tests = [], []
    for i, r in enumerate(aud["chain"]["receipts"], 1):
        rb_tests.append(t(i, "R-8.1/receipt-body",
                          {"prev_hex": r["prev_hex"], "obj_hex": r["obj_hex"], "seq": r["seq"], "at": r["at"]},
                          {"body_hex": r["body_hex"]}, comment=f"receipt seq {r['seq']}"))
        rh_tests.append(t(i, "R-8.1/receipt-head", {"body_hex": r["body_hex"]},
                         {"head_hex": sha384_hex(r["body_hex"])}, comment=f"head after seq {r['seq']}"))
    groups.append(group("receipt.body", rb_tests))
    groups.append(group("receipt.head", rh_tests))

    def nodes_in(v):
        # carry position where the oracle supplies it — the future-cause check compares positions
        return {"nodes": [
            {"id_hex": n["id_hex"], "causes_hex": n["causes_hex"],
             **({"position": n["position"]} if "position" in n else {})}
            for n in v["nodes"]]}

    cv_tests = [
        t(1, "R-8.5/causal-valid", nodes_in(aud["causal_valid"]), {"valid": True}, comment="acyclic DAG"),
        t(2, "R-8.5/causal-cycle", nodes_in(aud["causal_cycle"]), result="invalid",
          flags=["MustReject", "CausalViolation"], comment="cycle rejected"),
        t(3, "R-8.5/causal-future", nodes_in(aud["causal_future"]), result="invalid",
          flags=["MustReject", "CausalViolation"], comment="future-cause rejected"),
    ]
    groups.append(group("causal.verify", cv_tests))

    # ---- C8: delivery.update ----
    dlv = load("delivery")
    du_tests = []
    for i, u in enumerate(dlv["updates"], 1):
        du_tests.append(t(i, "R-9.1/delivery-update",
                          {"obj_hex": dlv["obj_content_id_hex"], "stage": u["stage"], "at": u["at"]},
                          {"body_hex": u["body_hex"]}, comment=f"stage {u['stage']}"))
    groups.append(group("delivery.update", du_tests))

    # ---- C9: stream digest + open/commit/checkpoint bodies ----
    st = load("stream")
    groups.append(group("stream.digest", [
        t(1, "R-10.2/stream-commitment",
          {"chunks": [{"offset": c["offset"], "data_hex": c["data_hex"]} for c in st["chunks"]]},
          {"digest_hex": st["final_digest_hex"]}, comment="rolling SHA-384 over offset-ordered chunks"),
    ]))
    open_in = {"stream_id_hex": st["stream_id_hex"], "effect": st["effect"], "substream": st["substream"]}
    if st.get("approval_hex"):
        open_in["approval_hex"] = st["approval_hex"]
    groups.append(group("stream.open", [
        t(1, "R-10.2/stream-open", open_in, {"body_hex": st["open_body_hex"]}, comment="StreamOpen body"),
    ]))
    groups.append(group("stream.commit", [
        t(1, "R-10.2/stream-commit", {"stream_id_hex": st["stream_id_hex"], "digest_hex": st["final_digest_hex"]},
          {"body_hex": st["commit_body_hex"]}, comment="StreamCommit body"),
    ]))
    # the committed checkpoint_body_hex is the first checkpoint (through_offset in field 2)
    cp_off = st["checkpoint_body_hex"][2 * (1 + 1 + 16 + 1):2 * (1 + 1 + 16 + 1) + 2]
    cp = next((c for c in st["checkpoints"] if c["through_offset"] == int(cp_off, 16)), st["checkpoints"][0])
    groups.append(group("stream.checkpoint", [
        t(1, "R-10.2/stream-checkpoint",
          {"stream_id_hex": st["stream_id_hex"], "through_offset": cp["through_offset"],
           "digest_so_far_hex": cp["digest_so_far_hex"]},
          {"body_hex": st["checkpoint_body_hex"]}, comment="StreamCheckpoint body"),
    ]))

    # ---- C11: transport emit matrix ----
    tr = load("transport")
    em_tests = []
    for i, m in enumerate(tr["emit_matrix"], 1):
        em_tests.append(t(i, "R-13.4/transport-emit",
                          {"transport": m["transport"], "sensitive": m["sensitive"],
                           "require_peer_auth": m["require_peer_auth"]},
                          {"result": m["result"]},
                          comment=f"{m['transport']} sensitive={m['sensitive']} peer_auth={m['require_peer_auth']}"))
    groups.append(group("transport.emit", em_tests))

    # ---- C12: carriage body per class ----
    car_tests = []
    classes = sorted(os.listdir(os.path.join(VEC, "carriage")))
    for i, cls in enumerate([c for c in classes if os.path.isdir(os.path.join(VEC, "carriage", c))], 1):
        c = load("carriage", cls)
        car_tests.append(t(i, "R-14.4/carriage-body",
                           {"protocol_id": c["protocol_id"], "class": c["class"], "content_type": c["content_type"],
                            "correlation_hex": c["correlation_hex"], "method": c["method"], "foreign_hex": c["foreign_hex"]},
                           {"body_hex": c["body_hex"]}, comment=f"carriage class {cls}"))
    groups.append(group("carriage.body", car_tests))

    # ---- C10: channel registry lookup + effect check ----
    chan_dir = os.path.join(VEC, "channels")
    ch_lookup, ch_effect = [], []
    tc = 1
    for cname in sorted(os.listdir(chan_dir)):
        cpath = os.path.join(chan_dir, cname, "cases.json")
        if not os.path.isfile(cpath):
            continue
        d = json.load(open(cpath, encoding="utf-8"))
        cid = d["channel_id"]
        for k in d["kinds"]:
            ch_lookup.append(t(tc, "R-11.1/channel-lookup", {"channel": cid, "kind": k["code"]},
                               {"name": k["name"], "effect": k["effect"], "variable": k["variable"]},
                               comment=f"{d['name']}.{k['name']}"))
            # effect_check: the kind's declared effect is accepted; a non-variable kind rejects a wrong effect
            ch_effect.append(t(tc, "R-11.3/effect-declaration",
                               {"channel": cid, "kind": k["code"], "effect": k["effect"]},
                               {"ok": True}, comment=f"{d['name']}.{k['name']} declared effect ok"))
            tc += 1
    # one unknown-kind negative
    ch_lookup.append(t(tc, "R-11.1/unknown-kind", {"channel": 0, "kind": 9999}, result="invalid",
                       flags=["MustReject", "UnknownKind"], comment="unregistered kind rejected"))
    groups.append(group("channels.lookup", ch_lookup))
    groups.append(group("channels.effect_check", ch_effect))

    # ---- T13: federation reconcile order + record ----
    fed = load("federation")
    fn = {"nodes": [{"id_hex": n["id_hex"], "causes_hex": n["causes_hex"]} for n in fed["nodes"]]}
    groups.append(group("federation.reconcile", [
        t(1, "R-8.6/reconcile-order", fn, {"order": fed["reconcile_order_hex"]},
          comment="deterministic causal-merge order"),
    ]))
    groups.append(group("federation.record", [
        t(1, "R-8.6/reconcile-record",
          {"authorities": fed["authorities"], "order": fed["reconcile_order_hex"]},
          {"body_hex": fed["record_hex"]}, comment="Reconcile record body"),
    ]))

    corpus = {
        "algorithm": "N-AALP",
        "schemaVersion": 1,
        "specRevision": "draft-bubblefish-naalp-00",
        "note": ("Op-replay conformance corpus assembled from the per-family non-circular oracles "
                 "(tools/*_oracle.py). Every expected value traces to an RFC/FIPS/NIST vector or a "
                 "from-scratch constructor, never to an implementation under test (F3). Driven through "
                 "each SDK adapter by harness/runner (naalp-conform). cose.sign1 is graded by the "
                 "crypto-consensus gate, not here."),
        "testGroups": groups,
    }
    return corpus


def main():
    corpus = build()
    outdir = os.path.join(VEC, "conformance")
    os.makedirs(outdir, exist_ok=True)
    outp = os.path.join(outdir, "corpus.json")
    with open(outp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(corpus, f, indent=2, ensure_ascii=True)
        f.write("\n")
    ng = len(corpus["testGroups"])
    nt = sum(len(g["tests"]) for g in corpus["testGroups"])
    nvalid = sum(1 for g in corpus["testGroups"] for x in g["tests"] if x["result"] == "valid")
    ninval = sum(1 for g in corpus["testGroups"] for x in g["tests"] if x["result"] == "invalid")
    naccept = sum(1 for g in corpus["testGroups"] for x in g["tests"] if x["result"] == "acceptable")
    print(f"wrote {outp}")
    print(f"  {ng} op groups, {nt} cases ({nvalid} valid / {ninval} invalid / {naccept} acceptable)")
    print("  ops: " + ", ".join(g["op"] for g in corpus["testGroups"]))


if __name__ == "__main__":
    main()
