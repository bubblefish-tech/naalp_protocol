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
    # ---- C16: NAALP-MCP (design.md §19) wire byte-production folded via the universal content.id op.
    # The mapping / more-severe resolution / malformed-annotation-reject SEMANTICS are graded by the
    # Go+Rust unit tests against tools/mcp_oracle.py (the design §14 pattern: the corpus grades wire
    # byte-production, semantics are unit-graded). Here every SDK adapter must compute the same
    # content id over the MCP tool-call body and the call binding — so a mutated MCP body (a dropped
    # or changed annotation, changed tool/args) changes the bytes -> changes the content id -> the
    # case fails (mutation-surviving). The eight non-Go/Rust SDKs grade this universal op today; the
    # full MCP-specific port is a later wave (Policy P6.3).
    mcp = load("mcp")
    for tcv in mcp["tool_calls"]:
        cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": tcv["body_hex"]},
                           {"id_hex": tcv["content_id_hex"]}, comment="mcp tool-call body '%s'" % tcv["name"]))
        cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": tcv["call_binding_hex"]},
                           {"id_hex": tcv["call_content_id_hex"]}, comment="mcp call-binding '%s'" % tcv["name"]))
    for ab in mcp["approval_binding"]:
        cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": ab["call_binding_hex"]},
                           {"id_hex": ab["call_content_id_hex"]}, comment="mcp approval call-binding '%s'" % ab["name"]))
    # ---- C17: N-AALP-CONT (design.md §20) wire byte-production folded via the universal content.id op.
    # Go+Rust unit tests grade CONT against tools/continuation_oracle.py; here the corpus grades that
    # any SDK computes the same content-id over the FlowOpen body and each continuation body — so a
    # mutated CONT body (a changed ceiling, seq, effect, payload_id, or prev) changes the bytes ->
    # changes the content id -> the case fails. (A continuation head is SHA-384(body); its content-id
    # is the T1 framing 0x20 0x30 || head, so id_hex = "2030" + head_hex.)
    cont = load("continuation")
    fo = cont["flow_open"]
    cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": fo["body_hex"]},
                       {"id_hex": fo["id_hex"]}, comment="cont flow-open body"))
    for cc in cont["continuations"]:
        cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": cc["body_hex"]},
                           {"id_hex": "2030" + cc["head_hex"]}, comment="cont continuation seq %d body" % cc["seq"]))
    # ---- C18: N-AALP signed description primitive (design.md §21) folded via the content.id op.
    # Go+Rust unit tests grade C18 against tools/description_oracle.py; here the corpus grades that
    # any SDK computes the same content-id over the Description, Directory, and description-import
    # bodies — so a mutated body (a changed operation/effect, member, or foreign hash) changes the
    # bytes -> changes the content id -> the case fails.
    desc = load("description")
    cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": desc["description"]["body_hex"]},
                       {"id_hex": desc["description"]["id_hex"]}, comment="description body"))
    cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": desc["directory"]["a"]["body_hex"]},
                       {"id_hex": desc["directory"]["a"]["id_hex"]}, comment="directory body"))
    cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": desc["import"]["body_hex"]},
                       {"id_hex": desc["import"]["id_hex"]}, comment="description-import body"))
    # ---- C19: name bindings + A2A task transitions (design.md §22) folded via the content.id op.
    # Grades that any SDK computes the same content-id over a name-binding body and a task-transition
    # body — a mutated binding (changed signer/prev) or transition (changed from/to/seq) changes the
    # bytes -> changes the content id -> the case fails.
    nm = load("naming")
    for i, b in enumerate(nm["name"]["bindings"]):
        cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": b["body_hex"]},
                           {"id_hex": b["id_hex"]}, comment="name binding seq %d body" % i))
    for i, tr in enumerate(nm["a2a"]["transitions"]):
        cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": tr["body_hex"]},
                           {"id_hex": tr["id_hex"]}, comment="a2a task transition seq %d body" % i))
    # ---- C20: negotiation + risk labels + trust refs (design.md §23) folded via the content.id op.
    neg = load("negotiation")
    for label, obj in [("negotiation offer", neg["negotiation"]["offer"]),
                       ("negotiation counter", neg["negotiation"]["counter"]),
                       ("negotiation accept", neg["negotiation"]["accept"]),
                       ("risk labeled-object", neg["risk"]["labeled_objects"][0]["with_labels"]),
                       ("trust ref", neg["trust"]["ref_a"])]:
        cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": obj["body_hex"]},
                           {"id_hex": obj["id_hex"]}, comment=label + " body"))
    # ---- C21: payment import + UI consent + gateway decision (design.md §24) folded via content.id.
    pay = load("payment")
    for k in ("ap2", "acp", "x402"):
        cb = pay["imports"][k]["charge_binding"]
        cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": cb["body_hex"]},
                           {"id_hex": cb["id_hex"]}, comment="payment %s charge-binding" % k))
    ag = load("agui")
    for i, ev in enumerate(ag["chain"]["events"]):
        cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": ev["body_hex"]},
                           {"id_hex": ev["id_hex"]}, comment="agui shown-event %d" % i))
    gw = load("gateway")
    for k in ("allow", "deny", "hold"):
        dd = gw["decisions"][k]
        cid_tests.append(t(len(cid_tests) + 1, "R-2.3/content-id", {"body_hex": dd["body_hex"]},
                           {"id_hex": dd["id_hex"]}, comment="gateway %s decision" % k))
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

    # ---- C2b: opt-in LAMPS composite signature (alg -65537, design.md §4.2) ----
    # Committed non-circular KATs for the DETERMINISTIC parts (M' construction §4.2 + composite
    # signer id §5.1), from tools/composite_oracle.py (a from-scratch constructor, no impl code).
    # These grade cross-ALL-ports; the seven composite-less ports auto-skip via the adapter
    # fallthrough. The two-leg signature VALUE has no committed KAT (like cose.sign1 — deterministic
    # ML-DSA sigGen is an internal ACVP interface), so composite.sign is carried "acceptable" and its
    # cross-language byte-parity is graded by the crypto-consensus gate (tools/crypto_consensus.py).
    comp = load("composite")
    groups.append(group("composite.mprime", [
        t(1, "R-4.2/composite-mprime", {"m_hex": comp["mprime"]["raw_tbs"]["m_hex"]},
          {"mprime_hex": comp["mprime"]["raw_tbs"]["mprime_hex"]},
          comment="M' = Prefix||Label||0x00||SHA-512(M) over the raw parity tbs"),
        t(2, "R-4.2/composite-mprime", {"m_hex": comp["mprime"]["object_tbs"]["m_hex"]},
          {"mprime_hex": comp["mprime"]["object_tbs"]["mprime_hex"]},
          comment="M' over the worked composite object ToBeSigned"),
    ]))
    groups.append(group("composite.signerid", [
        t(1, "R-5.1/composite-signer-id",
          {"mldsa_alg": comp["mldsa_alg"], "mldsa_pubkey_hex": comp["mldsa_pubkey_hex"],
           "ed_pubkey_hex": comp["ed_pubkey_hex"]},
          {"signer_id": comp["signer_id"]},
          comment="composite signer id = multihash(sha256, tagged(mldsaPub)||tagged(edPub))"),
    ]))
    groups.append(group("composite.sign", [
        t(1, "R-16.2/composite-byte-parity",
          {"mldsa_seed_hex": comp["mldsa_seed_hex"], "ed_seed_hex": comp["ed_seed_hex"],
           "tbs_hex": comp["value"]["m_hex"]},
          result="acceptable", flags=["crypto", "consensus-graded"],
          comment="deterministic composite value mldsaSig||edSig; Go==Rust==Python byte-parity (consensus)"),
    ]))

    # ---- C4b: §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature, #143) ----
    # From tools/rotation_oracle.py (a from-scratch constructor, no impl code). The leg "Signature"
    # Sig_structure is a committed non-circular KAT (rotation.leg_tbs) — the pure-CBOR anchor for the
    # multi-leg structure that distinguishes a COSE_Sign leg from a COSE_Sign1. The verify verdicts
    # (accept + the reject family: tag-18 single-sig, dropped/reordered/wrong-key old leg, non-rotation
    # kind, and the Sovereign below-floor ProfileDowngrade) are committed (spec-derived, deterministic).
    # The full two-leg object carries two DETERMINISTIC ML-DSA signatures with no clean committed KAT
    # (like cose.sign1), so rotation.sign is carried "acceptable" and its cross-language byte-parity is
    # graded by the crypto-consensus gate; the eight composite/rotation-less ports auto-skip.
    rot = load("rotation")
    groups.append(group("rotation.leg_tbs", [
        t(i, "R-5.2/rotation-leg-tbs",
          {"body_protected_hex": lt["body_protected_hex"], "leg_alg": lt["leg_alg"],
           "payload_hex": lt["payload_hex"]},
          {"tbs_hex": lt["tbs_hex"]},
          comment="rotation leg Signature Sig_structure (alg %d)" % lt["leg_alg"])
        for i, lt in enumerate(rot["leg_tbs"], 1)
    ]))
    rs = rot["sign"]
    groups.append(group("rotation.sign", [
        t(1, "R-5.2/rotation-object-byte-parity",
          {"old_alg": rs["old_alg"], "old_seed_hex": rs["old_seed_hex"],
           "new_alg": rs["new_alg"], "new_seed_hex": rs["new_seed_hex"],
           "protected_hex": rs["protected_hex"], "payload_hex": rs["payload_hex"]},
          result="acceptable", flags=["crypto", "consensus-graded"],
          comment="deterministic tag-98 rotation object (old+new legs); Go==Rust==... byte-parity (consensus)"),
    ]))
    groups.append(group("rotation.verify", [
        t(i, "R-5.2/rotation-verify",
          {"obj_hex": vc["obj_hex"], "old_alg": vc["old_alg"], "old_pubkey_hex": vc["old_pubkey_hex"],
           "new_alg": vc["new_alg"], "new_pubkey_hex": vc["new_pubkey_hex"], "profile": vc["profile"]},
          {"valid": vc["expect_valid"], "error": vc["expect_error"]},
          comment="rotation verify %s -> %s" % (vc["name"], vc["expect_error"] or "valid"))
        for i, vc in enumerate(rot["verify"], 1)
    ]))

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

    # ---- C7: draft-01 ForkProof (finding #70) ----
    # The non-repudiable equivocation proof (§8.5). The framing witness (signer id + external
    # counter + the two conflicting receipt bodies, signatures elided) is graded byte-for-byte
    # against the non-circular oracle across every implementing adapter (Go, Rust; others skip).
    fp = aud["fork_proof"]
    fp_in = {
        "signer_hex": fp["signer_hex"], "ext_counter": fp["ext_counter"],
        "prev_hex": fp["prev_hex"], "at": fp["at"], "seq": fp["seq"],
        "obj_a_hex": fp["obj_a_hex"], "obj_b_hex": fp["obj_b_hex"],
    }
    groups.append(group("forkproof.preimage", [
        t(1, "R-8.3/forkproof-framing", fp_in, {"preimage_hex": fp["preimage_hex"]},
          comment="draft-01 fork-proof framing witness (signatures elided) == oracle"),
    ]))
    # The full fork-proof body carries the accused's two DETERMINISTIC ML-DSA signatures over the
    # two receipt bodies. Like cose.sign1 the signature bytes have no committed KAT, so the corpus
    # marks this "acceptable" and the complete-body byte-parity is graded by the two-implementation
    # consensus (tools/crypto_consensus.py); its framing is graded above. Seed 0x14*32 is the audit
    # authority key.
    fp_body_in = dict(fp_in, seed_hex="14" * 32)
    groups.append(group("forkproof.body", [
        t(1, "R-8.3/forkproof-body", fp_body_in, result="acceptable",
          comment="full fork-proof body with both real signatures (Go==Rust byte-parity)"),
    ]))

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

    # ---- stream.state: streaming Guard state-machine conformance (design.md §10 state table +
    # § Timers stream idle/commit timer; ietf/draft-bubblefish-naalp-01.md "## Stream state
    # machine"). Each test drives ONE stream through an ordered `events` list on a fresh Guard;
    # the graded outcome is the LAST event's {valid, error} plus the stream's final state.
    # Expected outcomes are hardcoded in the independent tools/streamstate_oracle.py, read off
    # the draft's normative table — the oracle never imports or calls Guard code (F3 non-circular).
    ss = load("streamstate")
    ss_tests = []
    for c in ss["cases"]:
        ss_tests.append(t(c["tcId"], "R-10/stream-state", {"events": c["events"]}, c["expected"],
                          comment=c["name"] + " -- " + c["table_row"]))
    groups.append(group("stream.state", ss_tests))

    # ---- delivery.state: delivery Tracker state-machine conformance (ietf/draft-bubblefish-naalp-01.md
    # "## Delivery state machine" under "# Object State Machines"). Each test drives ONE object through
    # an ordered `events` list of signed delivery updates on a fresh tracker; the graded outcome is the
    # LAST event's {valid, error} plus the object's final stage name. Expected outcomes are hardcoded in
    # the independent tools/delivery_state_oracle.py, read off the draft's normative table — the oracle
    # never imports or calls delivery.Tracker (F3 non-circular).
    dls = load("delivery_state")
    dls_tests = []
    for c in dls["cases"]:
        dls_tests.append(t(c["tcId"], "R-9/delivery-state", {"events": c["events"]}, c["expected"],
                           comment=c["name"] + " -- " + c["table_row"]))
    groups.append(group("delivery.state", dls_tests))

    # ---- approval.state: approval consume state-machine conformance (ietf/draft-bubblefish-naalp-01.md
    # "## Approval state machine" under "# Object State Machines"). Each test builds ONE signed approval
    # and drives it through an ordered `events` list of consume attempts through the composed choke point
    # approval.ConsumeApproval on a fresh single-use ledger; the graded outcome is the LAST event's
    # {valid, error} plus the ledger length after it (the draft's "the ledger is left untouched by the
    # rejected request", observable as the consume count). Expected outcomes are hardcoded in the
    # independent tools/approval_state_oracle.py, read off the draft's normative table and its
    # mismatch-over-every-cell + expiry-over-consume precedence rules — the oracle never imports or calls
    # the approval package (F3 non-circular). The effect-ceiling cell is deliberately not graded (the
    # draft is silent on its error code); see the oracle docstring.
    aps = load("approval_state")
    aps_tests = []
    for c in aps["cases"]:
        aps_tests.append(t(c["tcId"], "R-7/approval-state",
                           {"approval": c["approval"], "events": c["events"]}, c["expected"],
                           comment=c["name"] + " -- " + c["table_row"]))
    groups.append(group("approval.state", aps_tests))

    # ---- R7: decoder resource bounds (design.md §3.4) — reject vectors ----
    # object.decode grades each object-level bound by its exact named error (rotation.verify-style:
    # result="valid" + expected {valid:false, error:Kind}); the object octet-size bound rides a
    # size-parameterized case the adapter materializes. Bytes and bound values come from the
    # independent tools/envelope_bounds_oracle.py (F3 non-circular; no impl code involved).
    eb = load("envelope_bounds")
    od_tests = []
    for i, r in enumerate(eb["object_decode_reject"], 1):
        od_tests.append(t(i, "R-7/decoder-bound", {"obj_hex": r["obj_hex"]},
                          {"valid": False, "error": r["error"]},
                          comment=r["name"] + ": " + r["note"]))
    for r in eb["size_parameterized"]:
        od_tests.append(t(len(od_tests) + 1, "R-7/object-size", {"over_size": r["over_size"]},
                          {"valid": False, "error": r["error"]}, comment=r["name"] + ": " + r["note"]))
    # §3.1.1 determinism dispositions (R5): a CBOR float in body/ext/cext, a duplicate map key, and
    # the 0x41A0 (bstr-wrapped empty map) protected-header form instead of the pinned 0x40 — each an
    # otherwise-valid object with exactly one violation, rejected NonCanonical at the parse/decode
    # stage. Bytes from the independent tools/determinism_oracle.py (F3 non-circular; no impl code).
    det = load("determinism")
    for r in det["object_decode_reject"]:
        od_tests.append(t(len(od_tests) + 1, "R-5/determinism", {"obj_hex": r["obj_hex"]},
                          {"valid": False, "error": r["error"]}, comment=r["name"] + ": " + r["note"]))
    groups.append(group("object.decode", od_tests))

    # stream.verify_commit: the stream chunk-count bound (streaming layer, not object.decode).
    # Count-parameterized — the adapter materializes MAX_STREAM_CHUNKS+1 empty chunks; the count
    # check fires before the digest check, so the reject is TooManyChunks (design.md §3.4, R7).
    sv_tests = []
    for i, r in enumerate(eb["chunk_parameterized"], 1):
        sv_tests.append(t(i, "R-7/stream-chunks", {"chunk_count": r["chunk_count"]},
                          {"valid": False, "error": r["error"]}, comment=r["name"] + ": " + r["note"]))
    groups.append(group("stream.verify_commit", sv_tests))

    # ---- T3.3: naalp-error object + numeric error-code registry (design.md §3.5, R3.3/3.4) ----
    # The naalp-error object (Control/Error, channel 0/kind 3) carries a fail-closed rejection reason
    # as {1:code, 2:name, ?3:detail, ?4:subject}. Three ops grade it across all ten adapters from the
    # non-circular tools/error_codes_oracle.py: error.name_for_code grades each port's embedded
    # 119-entry name<->code table (per-code, so a port that dropped or mis-mapped an entry fails);
    # error.encode grades the body bytes; error.decode grades the structural parse + the two
    # dual-carriage rules (registered code + wrong name -> Malformed; unknown code -> opaque).
    ec = load("error_codes")
    nf_tests = []
    for i, e in enumerate(ec["errors"], 1):
        nf_tests.append(t(i, "R-3.3/error-code", {"code": e["code"]},
                          {"name": e["name"], "registered": True}, comment=e["name"]))
    for uc in (0, ec["unknown_code_example"]):
        nf_tests.append(t(len(nf_tests) + 1, "R-3.4/unknown-code", {"code": uc},
                          {"name": "", "registered": False}, comment="unknown code %d is opaque" % uc))
    groups.append(group("error.name_for_code", nf_tests))
    enc_tests = []
    for c in ec["encode_cases"]:
        inp = {"code": c["code"], "name": c["name"]}
        if c.get("detail") is not None:
            inp["detail"] = c["detail"]
        if c.get("subject_hex") is not None:
            inp["subject_hex"] = c["subject_hex"]
        enc_tests.append(t(c["tcId"], "R-3.3/error-encode", inp, {"body_hex": c["want_hex"]},
                           comment="encode %d %s" % (c["code"], c["name"])))
    groups.append(group("error.encode", enc_tests))
    dec_tests = []
    for c in ec["decode_cases"]:
        if c["reject"] is not None:
            exp = {"valid": False, "error": c["reject"]}
        else:
            exp = {"valid": True, "code": c["want"]["code"], "name": c["want"]["name"]}
        dec_tests.append(t(c["tcId"], "R-3.4/error-decode", {"body_hex": c["in_hex"]}, exp,
                           comment=c["note"]))
    groups.append(group("error.decode", dec_tests))

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

    # ---- reconcile.state: Reconcile state-machine conformance (ietf/draft-bubblefish-naalp-01.md
    # "## Reconcile state machine" under "# Object State Machines"). Each add-chain test builds
    # receipt(s) from hardcoded, byte-correct bodies and drives them through a fixed
    # VerifyChain-then-Observe pipeline with exactly one injected fault; each linearize test drives
    # a causal node set through Reconcile/VerifyCausal; each verify test compares a claimed total
    # order against the federation.VerifyReconcileOrder choke point. Expected outcomes are hardcoded in
    # the independent tools/reconcile_state_oracle.py, read off the draft's normative table — the
    # oracle never imports or calls the federation/audit packages (F3 non-circular).
    rcs = load("reconcile_state")
    rcs_tests = []
    for c in rcs["cases"]:
        in_ = {"event": c["event"]}
        if c["event"] == "add-chain":
            in_["chain"] = c["chain"]
            in_["extra"] = c["extra"]
            in_["corrupt_sig_at"] = c["corrupt_sig_at"]
        elif c["event"] == "linearize":
            in_["nodes"] = c["nodes"]
        elif c["event"] == "verify":
            in_["nodes"] = c["nodes"]
            in_["claimed_order_hex"] = c["claimed_order_hex"]
        rcs_tests.append(t(c["tcId"], "R-8/reconcile-state", in_, c["expected"],
                           comment=c["name"] + " -- " + c["table_row"]))
    groups.append(group("reconcile.state", rcs_tests))

    # ---- draft-01 Wave B/C/D field coverage (coding-instructions §4): the recheck field,
    # the consume-receipt position, and the per-signer counter. Each is graded through the
    # UNIVERSAL ops every SDK adapter implements — content.id, cbor.encode, cbor.decode — so
    # the new fields' byte production grades byte-identical across ALL language ports (not just
    # the Go/Rust parity pair). Every expected value comes from the per-family non-circular
    # oracle (F3), never from an implementation under test. The §4 required wire-format cases
    # are all present: minimal-object-with-the-field, keys-out-of-order, unknown-critical
    # procedure id, empty-value-vs-absent-value, and a position too large for a 53-bit int.

    # T1.3 recheck (NAALP-REQ-110/111): content-id over each recheck-carrying object body
    # (the body encodes the procedure id in the correct ext/cext slot). Distinct absent vs
    # present-empty ids prove empty != absent; the unknown-critical bodies prove the wire
    # encoding of an out-of-registry procedure id.
    rck = load("recheck")
    groups.append(group("content.id", [
        t(i, "NAALP-REQ-111/recheck-body-id", {"body_hex": c["body_no_id_hex"]},
          {"id_hex": c["content_id_hex"]}, comment=f"recheck {c['name']} (expect {c['expect']})")
        for i, c in enumerate(rck["cases"], 1)
    ]))
    groups.append(group("cbor.decode", [
        t(i, "R-3.4/recheck-noncanonical", {"bytes_hex": n["payload_hex"]},
          result="invalid", flags=["MustReject", n["expect"]], comment=f"recheck {n['name']}")
        for i, n in enumerate(rck["negatives"], 1)
    ]))

    # T1.6 per-signer forward-only counter (NAALP-REQ-120): content-id over each counter
    # body, incl. the present-zero, present-empty vs absent, and 2^53 / uint64-max positions.
    sc = load("signer_counter")
    groups.append(group("content.id", [
        t(i, "NAALP-REQ-120/signer-counter-body-id", {"body_hex": c["body_no_id_hex"]},
          {"id_hex": c["content_id_hex"]}, comment=f"signer-counter {c['name']} (expect {c['expect']})")
        for i, c in enumerate(sc["cases"], 1)
    ]))
    groups.append(group("cbor.decode", [
        t(i, "R-3.4/signer-counter-noncanonical", {"bytes_hex": n["payload_hex"]},
          result="invalid", flags=["MustReject", n["expect"]], comment=f"signer-counter {n['name']}")
        for i, n in enumerate(sc["negatives"], 1)
    ]))

    # T1.5 ledger-signed consume-receipt position (NAALP-REQ-121): the receipt body
    # {1: ledger, 2: approval-id, 3: position} is a NEW byte production. Grade it by having
    # each adapter's own CBOR encoder emit the bytes from the structured fields; the position
    # travels as a decimal STRING so a 2^53 / uint64-max value is not float64-rounded before
    # the encoder runs. Distinct empty-ledger vs absent-ledger bodies prove empty != absent.
    cr = load("consume_receipt")

    def receipt_value(ledger_hex, approval_hex, position, with_ledger=True):
        pairs = []
        if with_ledger:
            pairs.append([["u", 1], ["b", ledger_hex]])
        pairs.append([["u", 2], ["b", approval_hex]])
        pairs.append([["u", 3], ["u", str(position)]])  # 64-bit-safe: decimal string
        return ["map", pairs]

    base_led, base_appr = cr["base"]["ledger_hex"], cr["base"]["approval_id_hex"]
    seen, cr_rows = set(), []

    def add_receipt(name, led, appr, pos, body_hex, with_ledger=True):
        if body_hex in seen:
            return
        seen.add(body_hex)
        cr_rows.append((name, led, appr, pos, body_hex, with_ledger))

    add_receipt(cr["base"]["name"], base_led, base_appr, cr["base"]["position"], cr["base"]["body_hex"])
    for s in cr["sequence"]:
        add_receipt(s["name"], s["ledger_hex"], s["approval_id_hex"], s["position"], s["body_hex"])
    for fk in cr["forks"]:
        for side in ("a", "b"):
            r = fk[side]
            add_receipt(f"{fk['name']}.{side}", r["ledger_hex"], r["approval_id_hex"], r["position"], r["body_hex"])
    for p in cr["wire"]["position_too_large"]:
        add_receipt(p["name"], base_led, base_appr, p["position"], p["body_hex"])
    el = cr["wire"]["empty_ledger"]
    add_receipt("empty_ledger", el["ledger_hex"], el["approval_id_hex"], el["position"], el["body_hex"])
    al = cr["wire"]["absent_ledger"]
    add_receipt("absent_ledger", None, al["approval_id_hex"], al["position"], al["body_hex"], with_ledger=False)

    groups.append(group("cbor.encode", [
        t(i, "NAALP-REQ-121/consume-receipt-body",
          {"value": receipt_value(led, appr, pos, wl)},
          {"bytes_hex": body_hex}, comment=f"consume receipt {name} (position {pos})")
        for i, (name, led, appr, pos, body_hex, wl) in enumerate(cr_rows, 1)
    ]))
    cro = cr["wire"]["keys_out_of_order"]
    groups.append(group("cbor.decode", [
        t(1, "R-3.4/consume-receipt-noncanonical", {"bytes_hex": cro["payload_hex"]},
          result="invalid", flags=["MustReject", cro["expect"]], comment="consume receipt keys_out_of_order"),
    ]))

    corpus = {
        "algorithm": "N-AALP",
        "schemaVersion": 1,
        "specRevision": "draft-bubblefish-naalp-01",
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
