# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Registry drift gate (T14): the machine-readable registries under vectors/registry/*.csv are the
source the prose/CDDL is generated from, so they MUST stay consistent with the graded conformance
vectors the two implementations are tested against. This checks, with no drift permitted:

  * signatures.csv  <-> the COSE algorithm code points the crypto vectors use (name, alg, level).
  * multicodec.csv  <-> the signer-id key multicodec codes the identity vectors use.
  * channels.csv    <-> the 20 per-channel vectors (every channel/kind/effect, both directions).
  * protocols.csv   <-> the carriage protocol-id assignments (standards range) the vectors use.

Exit non-zero on any drift. Pure standard library.
"""
import csv
import glob
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
EFFECT_NAME = {0: "read_only", 1: "idempotent_write", 2: "non_idempotent_write", 3: "destructive"}
fails = []


def check(cond, msg):
    if cond:
        print("  PASS ", msg)
    else:
        print("  FAIL ", msg)
        fails.append(msg)


def load_csv(path):
    with open(os.path.join(ROOT, path), newline="") as f:
        return list(csv.DictReader(f))


def load_json(path):
    with open(os.path.join(ROOT, path)) as f:
        return json.load(f)


def check_signatures():
    print("== signatures.csv <-> COSE algorithm vectors ==")
    rows = {r["name"]: r for r in load_csv("vectors/registry/signatures.csv")}
    algs = load_json("vectors/cose/cases.json")["algs"]
    for a in algs:
        r = rows.get(a["name"])
        check(r is not None, "%s present in signatures.csv" % a["name"])
        if r:
            check(int(r["cose_alg"]) == a["alg"], "%s cose_alg %s == vector %d" % (a["name"], r["cose_alg"], a["alg"]))
            check(int(r["nist_level"]) == a["level"], "%s nist_level matches" % a["name"])
            check(r["reference"] == a["ref"], "%s reference %s == vector %s" % (a["name"], r["reference"], a["ref"]))
    # SLH-DSA is reserved (no code point, not an active alg vector).
    check(rows.get("SLH-DSA", {}).get("status") == "reserved", "SLH-DSA is reserved (no code point)")


def check_multicodec():
    print("== multicodec.csv <-> signer-id key codes (identity vectors) ==")
    rows = {r["name"]: int(r["code"], 16) for r in load_csv("vectors/registry/multicodec.csv")}
    want = {"ML-DSA-65": "mldsa-65-pub", "ML-DSA-87": "mldsa-87-pub", "Ed25519": "ed25519-pub"}
    for s in load_json("vectors/identity/cases.json")["signers"]:
        key = want[s["name"]]
        check(key in rows, "%s key multicodec %s present" % (s["name"], key))
        if key in rows:
            check(rows[key] == s["multicodec"], "%s multicodec 0x%x == vector %d" % (s["name"], rows[key], s["multicodec"]))
    # A6: every multihash HASH code point the CDDL mandates MUST be registered as a
    # multihash-hash row, or a verifier cannot resolve the self-describing content-id/signer-id
    # hash. The CDDL (spec/naalp-draft-01.cddl) is the authority: multihash(0x20, SHA-384(...))
    # names the content id (§2.3) and multihash(0x12, SHA-256(...)) the signer id (§5.1). Scan
    # those codes out of the CDDL and assert coverage, so a hash added to the wire cannot ship
    # without a registry row. (0x20 = sha2-384, 0x12 = sha2-256 per the multiformats table.)
    all_rows = load_csv("vectors/registry/multicodec.csv")
    hash_codes = {int(r["code"], 16) for r in all_rows if r["role"] == "multihash-hash"}
    cddl = open(os.path.join(ROOT, "spec/naalp-draft-01.cddl")).read()
    cddl_hash_codes = sorted({int(m, 16) for m in re.findall(r"multihash\(0x([0-9a-fA-F]+)", cddl)})
    check(len(cddl_hash_codes) > 0, "CDDL names at least one multihash hash code point")
    for code in cddl_hash_codes:
        check(code in hash_codes,
              "CDDL multihash 0x%02x registered as multihash-hash in multicodec.csv" % code)


def check_channels():
    print("== channels.csv <-> 20 per-channel vectors (both directions) ==")
    csv_rows = load_csv("vectors/registry/channels.csv")
    csv_set = set()
    for r in csv_rows:
        cid = int(r["channel_id"], 16)
        csv_set.add((cid, int(r["kind_code"]), r["kind_name"], r["effect"]))
    vec_set = set()
    nchan = 0
    for f in glob.glob(os.path.join(ROOT, "vectors/channels/*/cases.json")):
        c = json.load(open(f))
        nchan += 1
        for k in c["kinds"]:
            eff = "variable" if k["variable"] else EFFECT_NAME[k["effect"]]
            vec_set.add((c["channel_id"], k["code"], k["name"], eff))
    check(nchan == 20, "20 channel vector files present (found %d)" % nchan)
    check(csv_set == vec_set, "channels.csv kind set == vector kind set (%d rows)" % len(csv_set))
    if csv_set != vec_set:
        only_csv = csv_set - vec_set
        only_vec = vec_set - csv_set
        if only_csv:
            print("    only in csv:", sorted(only_csv)[:5])
        if only_vec:
            print("    only in vectors:", sorted(only_vec)[:5])


def check_protocols():
    print("== protocols.csv <-> carriage protocol-id assignments ==")
    rows = {int(r["protocol_id"], 16): r for r in load_csv("vectors/registry/protocols.csv")}
    valid_classes = {"JSONRPC", "HTTP", "MSG", "STREAM", "DOC", "OPAQUE"}
    for pid, r in rows.items():
        check(0x01 <= pid <= 0x0F, "%s in standards range 0x01-0x0F" % r["protocol_id"])
        check(r["class"] in valid_classes, "%s class %s is a valid carriage class" % (r["protocol_id"], r["class"]))
        check(r["range"] == "standards", "%s range=standards" % r["protocol_id"])
    # A standards-range carriage vector's protocol id must be registered.
    j = load_json("vectors/carriage/jsonrpc/cases.json")
    check(j["protocol_id"] in rows, "JSONRPC vector protocol_id 0x%02x is registered" % j["protocol_id"])


def check_carriage_content_types():
    # T11.1 / R11: content_type (naalp-carriage-body field 3, design §13.7) is an OPEN registry-backed
    # uint -- the "N-AALP Carriage Content Types" registry -- NOT a closed enum, because the OPAQUE
    # class carries any (including undefined) foreign encoding, so a new encoding registers without a
    # wire change. Like protocols.csv the value is a label with no independently-computable bytes, so
    # the honest, non-circular check is CSV <-> the content_type values the graded carriage vectors
    # ACTUALLY use: every value on the wire MUST be registered, and every registered standards value
    # MUST sit in the standards range (0x00-0x0F, RFC Required / FCFS per the ISE constraint).
    print("== carriage-content-types.csv <-> carriage vector content_type values ==")
    rows = {int(r["content_type"]): r for r in load_csv("vectors/registry/carriage-content-types.csv")}
    valid_ranges = {"standards", "experimental", "private"}
    for ct, r in rows.items():
        check(r["range"] in valid_ranges, "content_type %d range %s is valid" % (ct, r["range"]))
        if r["range"] == "standards":
            check(0x00 <= ct <= 0x0F, "content_type %d in standards range 0x00-0x0F" % ct)
    used = set()
    for f in glob.glob(os.path.join(ROOT, "vectors/carriage/*/cases.json")):
        used.add(json.load(open(f))["content_type"])
    check(len(used) > 0, "carriage vectors present (found %d content_type values)" % len(used))
    for ct in sorted(used):
        check(ct in rows, "carriage vector content_type %d is registered" % ct)


def check_extension_keys():
    # T4.1 / R4: the ext (field 11) and cext (field 12) extension-KEY namespace is a single registry
    # (vectors/registry/extension-keys.csv) so two implementers assigning keys cannot collide -- a
    # critical-ext collision is a denial. The non-circular check: every key is UNIQUE, and each key the
    # graded per-capability registries (signer_counter.csv key 14, producing_boundary.csv key 15) and
    # the CDDL wire authority actually name is registered here under the same name. (RFC Required / FCFS
    # per the ISE constraint; design.md documents the collision-free guarantee this gate enforces.)
    print("== extension-keys.csv <-> per-capability ext-key registries + CDDL ==")
    rows = load_csv("vectors/registry/extension-keys.csv")
    keys = [int(r["ext_key"]) for r in rows]
    check(len(keys) == len(set(keys)), "extension-keys.csv keys are unique (no collision): %s" % sorted(keys))
    reg = {int(r["ext_key"]): r["name"] for r in rows}
    for r in rows:
        check(r["maps"] in {"ext", "cext", "ext|cext"}, "%s maps %s is ext/cext/ext|cext" % (r["name"], r["maps"]))
    sc = load_csv("vectors/registry/signer_counter.csv")[0]
    check(reg.get(int(sc["ext_key"])) == sc["name"],
          "signer_counter ext_key %s registered as %s" % (sc["ext_key"], sc["name"]))
    pb = load_csv("vectors/registry/producing_boundary.csv")[0]
    check(reg.get(int(pb["ext_key"])) == pb["name"],
          "producing_boundary ext_key %s registered as %s" % (pb["ext_key"], pb["name"]))
    cddl = open(os.path.join(ROOT, "spec/naalp-draft-01.cddl")).read()
    for k in reg:
        check(("ext key %d" % k) in cddl or ("ext/cext key %d" % k) in cddl,
              "CDDL names extension key %d" % k)


def check_recheck():
    # T1.3: the closed re-check procedure registry MUST agree across its three independent
    # sources — vectors/registry/recheck.csv, the CDDL `recheck-procedure` production, and the
    # non-circular oracle's vectors/recheck/cases.json — so a procedure added on the wire cannot
    # ship without its registry row and CDDL point (F3; mirrors the signatures/channels gates).
    print("== recheck.csv <-> CDDL recheck-procedure <-> recheck oracle vectors ==")
    csv_rows = load_csv("vectors/registry/recheck.csv")
    csv_set = {(int(r["procedure_id"]), r["procedure_name"]) for r in csv_rows}

    cddl = open(os.path.join(ROOT, "spec/naalp-draft-01.cddl")).read()
    # Capture the enum body up to the closing ")" at the start of a line (comments contain
    # parentheses like "(§2.3)", so a non-greedy match to the first ")" would stop too early).
    m = re.search(r"recheck-procedure\s*=\s*&\(\n(.*?)\n\)", cddl, re.DOTALL)
    check(m is not None, "CDDL defines the recheck-procedure production")
    cddl_set = set()
    if m:
        # each value line is "  name: N,  ; comment" — take the name:int before any ";" comment.
        for line in m.group(1).splitlines():
            code = line.split(";", 1)[0]
            pm = re.match(r"\s*([a-z0-9-]+)\s*:\s*(\d+)", code)
            if pm:
                cddl_set.add((int(pm.group(2)), pm.group(1)))

    oracle = load_json("vectors/recheck/cases.json")["procedures"]
    oracle_set = {(p["id"], p["name"]) for p in oracle}

    check(csv_set == cddl_set, "recheck.csv procedure set == CDDL recheck-procedure enum (%d)" % len(csv_set))
    check(csv_set == oracle_set, "recheck.csv procedure set == oracle procedures (%d)" % len(oracle_set))
    if not (csv_set == cddl_set == oracle_set):
        print("    csv   :", sorted(csv_set))
        print("    cddl  :", sorted(cddl_set))
        print("    oracle:", sorted(oracle_set))


def check_signer_counter():
    # T1.6: the ext-key assignment for the OPTIONAL per-signer counter MUST agree across its three
    # independent sources — vectors/registry/signer_counter.csv, the CDDL (the signer-counter
    # production + the naalp-object "ext key 14 = signer-counter" comment), and the non-circular
    # oracle's vectors/signer_counter/cases.json counter_key — so key 14 cannot be reassigned
    # inconsistently on the wire (F3; mirrors the recheck gate). The counter carries no value enum
    # (any 64-bit uint is a valid position), so this gate cross-checks the KEY assignment, not a set.
    print("== signer_counter.csv <-> CDDL signer-counter <-> counter oracle vectors ==")
    rows = load_csv("vectors/registry/signer_counter.csv")
    check(len(rows) == 1, "signer_counter.csv has exactly one ext-key assignment")
    if not rows:
        return
    r = rows[0]
    csv_key = int(r["ext_key"])
    check(r["name"] == "signer-counter", "signer_counter.csv name is signer-counter")
    check(r["placement"] == "ext", "signer_counter.csv placement is ext (non-critical)")

    cddl = open(os.path.join(ROOT, "spec/naalp-draft-01.cddl")).read()
    check(re.search(r"^signer-counter\s*=\s*uint\b", cddl, re.MULTILINE) is not None,
          "CDDL defines the signer-counter production (= uint)")
    m = re.search(r"ext key (\d+)\s*=\s*signer-counter", cddl)
    check(m is not None, "CDDL naalp-object names 'ext key N = signer-counter'")
    cddl_key = int(m.group(1)) if m else -1

    oracle = load_json("vectors/signer_counter/cases.json")
    oracle_key = oracle["counter_key"]
    check(csv_key == cddl_key == oracle_key == 14,
          "signer-counter ext key agrees across csv/CDDL/oracle (== 14): csv=%d cddl=%d oracle=%d"
          % (csv_key, cddl_key, oracle_key))


def check_mcp():
    # Companion Requirement 6.1: the published NAALP-MCP annotation->effect mapping table
    # (vectors/registry/mcp.csv) MUST equal the non-circular oracle's mapping_table
    # (vectors/mcp/cases.json), which the two impls (impl/go/mcp, impl/rust/src/mcp.rs) are graded
    # against — so a mapping row cannot drift from the graded table without failing this gate (F3;
    # mirrors the recheck/signer-counter gates). design.md §19.3.
    print("== mcp.csv <-> NAALP-MCP oracle mapping_table (annotation->effect) ==")
    rows = load_csv("vectors/registry/mcp.csv")
    csv_set = {(r["read_only_hint"], r["destructive_hint"], r["idempotent_hint"],
                r["effect"], int(r["effect_value"])) for r in rows}
    oracle = load_json("vectors/mcp/cases.json")["mapping_table"]
    oracle_set = {(m["read_only_hint"], m["destructive_hint"], m["idempotent_hint"],
                   m["effect"], int(m["effect_value"])) for m in oracle}
    check(len(rows) == 4, "mcp.csv has the 4 canonical mapping rows (found %d)" % len(rows))
    check(csv_set == oracle_set, "mcp.csv mapping == oracle mapping_table (%d rows)" % len(csv_set))
    if csv_set != oracle_set:
        print("    csv   :", sorted(csv_set))
        print("    oracle:", sorted(oracle_set))


def cddl_enum(rule):
    """Extract a CDDL `<rule> = &( name: code, ... )` enum as {name: code}. The CDDL is the
    authority (cddl_check validates it); the .csv registry must not drift from it."""
    with open(os.path.join(ROOT, "spec/naalp-draft-01.cddl")) as f:
        txt = f.read()
    # Capture the enum body from `&(` to the closing `)` at the start of a line — comments may
    # themselves contain `)`, so a non-greedy match up to a line-initial `)` is used, not [^)]*.
    m = re.search(re.escape(rule) + r"\s*=\s*&\(\s*(.*?)\n\)", txt, re.DOTALL)
    out = {}
    if m:
        for line in m.group(1).splitlines():
            mm = re.match(r"\s*([A-Za-z0-9_-]+)\s*:\s*(\d+)", line)
            if mm:
                out[mm.group(1)] = int(mm.group(2))
    return out


def check_a2a_task_state():
    # C19: the A2A TaskState registry (vectors/registry/a2a-task-state.csv) MUST equal the CDDL
    # task-state enum the naming vectors + two impls are graded against. design.md §22.4.
    print("== a2a-task-state.csv <-> CDDL task-state enum ==")
    enum = cddl_enum("task-state")
    rows = {r["state_name"]: int(r["state_code"]) for r in load_csv("vectors/registry/a2a-task-state.csv")}
    check(len(enum) == 8, "CDDL task-state has 8 states (found %d)" % len(enum))
    check(rows == enum, "a2a-task-state.csv (%d rows) == CDDL task-state enum" % len(rows))
    if rows != enum:
        print("    csv :", sorted(rows.items()))
        print("    cddl:", sorted(enum.items()))


def check_risk_labels():
    # C20: the advisory risk-label vocabulary (vectors/registry/risk-labels.csv) MUST equal the
    # non-circular oracle's risk vocabulary (vectors/negotiation/cases.json), which the two impls
    # (impl/go/negotiation, impl/rust/src/negotiation.rs) are graded against — so a label row cannot
    # drift from the graded vocabulary without failing this gate (F3; mirrors the mcp/recheck gates).
    # Each row is (label_name, label_code, class in {gating, informing}). design.md §23.
    print("== risk-labels.csv <-> negotiation oracle risk vocabulary (label->gating/informing) ==")
    rows = load_csv("vectors/registry/risk-labels.csv")
    valid_classes = {"gating", "informing"}
    csv_set = set()
    for r in rows:
        check(r["class"] in valid_classes, "%s class %s is gating|informing" % (r["label_name"], r["class"]))
        csv_set.add((r["label_name"], int(r["label_code"]), r["class"]))
    oracle = load_json("vectors/negotiation/cases.json")["risk"]["vocabulary"]
    oracle_set = {(v["name"], int(v["code"]), v["class"]) for v in oracle}
    check(len(rows) == 3, "risk-labels.csv has the 3 standard-vocabulary rows (found %d)" % len(rows))
    check(csv_set == oracle_set, "risk-labels.csv vocabulary == oracle risk vocabulary (%d rows)" % len(csv_set))
    if csv_set != oracle_set:
        print("    csv   :", sorted(csv_set))
        print("    oracle:", sorted(oracle_set))


def check_payment_format():
    # C21: the payment-format registry (vectors/registry/payment-format.csv) MUST equal the CDDL
    # naalp-payment-format enum AND the non-circular payment oracle's format vocabulary
    # (vectors/payment/cases.json), which the two impls (impl/go/payment, impl/rust/src/payment.rs)
    # are graded against — so a format row cannot drift from the graded vocabulary without failing this
    # gate (F3; mirrors the description-format/risk-labels gates). design.md §24.
    print("== payment-format.csv <-> CDDL naalp-payment-format enum <-> payment oracle vocabulary ==")
    enum = cddl_enum("naalp-payment-format")
    rows = {r["format_name"]: int(r["format_code"]) for r in load_csv("vectors/registry/payment-format.csv")}
    oracle_map = {v["name"]: int(v["code"]) for v in load_json("vectors/payment/cases.json")["format_vocabulary"]}
    check(len(enum) == 3, "CDDL naalp-payment-format has 3 formats (found %d)" % len(enum))
    check(rows == enum, "payment-format.csv (%d rows) == CDDL enum" % len(rows))
    check(rows == oracle_map, "payment-format.csv == payment oracle vocabulary (%d)" % len(oracle_map))
    if rows != enum:
        print("    csv :", sorted(rows.items()))
        print("    cddl:", sorted(enum.items()))


def check_description_format():
    # C18: the foreign-description-format registry (vectors/registry/description-format.csv) MUST
    # equal the CDDL naalp-description-format enum. design.md §21.
    print("== description-format.csv <-> CDDL naalp-description-format enum ==")
    enum = cddl_enum("naalp-description-format")
    rows = {r["format_name"]: int(r["format_code"]) for r in load_csv("vectors/registry/description-format.csv")}
    check(len(enum) == 3, "CDDL naalp-description-format has 3 formats (found %d)" % len(enum))
    check(rows == enum, "description-format.csv (%d rows) == CDDL enum" % len(rows))
    if rows != enum:
        print("    csv :", sorted(rows.items()))
        print("    cddl:", sorted(enum.items()))


def check_trust_decision_input_classes():
    # R-TDCS-1: the open, Specification-Required registry of trust-decision input classes (design.md
    # §25.4) MUST agree between its machine-readable CSV and the CDDL `trust-decision-input-class` enum,
    # and every row's safe_shape MUST be one of the three closed shapes. It is a TAXONOMY, not a wire
    # encoding — the classes have no independently-computable expected bytes — so there is no oracle
    # third source (an oracle that echoed the CSV would be circular); CSV <-> CDDL is the honest check.
    print("== trust-decision-input-classes.csv <-> CDDL trust-decision-input-class ==")
    rows = load_csv("vectors/registry/trust-decision-input-classes.csv")
    csv_set = {(int(r["class_id"]), r["class_name"]) for r in rows}
    cddl = cddl_enum("trust-decision-input-class")
    check(bool(cddl), "CDDL defines the trust-decision-input-class production")
    cddl_set = {(code, name) for name, code in cddl.items()}
    check(csv_set == cddl_set, "input-class CSV set == CDDL enum (%d)" % len(csv_set))
    if csv_set != cddl_set:
        print("    csv :", sorted(csv_set))
        print("    cddl:", sorted(cddl_set))
    shapes = {"verifiable", "attenuating", "committed"}
    bad = [r["class_name"] for r in rows if r["safe_shape"] not in shapes]
    check(not bad, "every safe_shape is verifiable/attenuating/committed" + (" (bad: %s)" % bad if bad else ""))


def check_error_codes():
    # T3.3 / R3.3-3.4: the "N-AALP Error Codes" registry (vectors/registry/error-codes.csv) is the
    # name<->code taxonomy the naalp-error object (Control/Error surface, channel 0/kind 3) carries.
    # It MUST agree across its three independent sources — the CSV, the CDDL naalp-error-code enum,
    # and the non-circular oracle's mapping (vectors/error_codes/cases.json "errors"), which the ten
    # ports are graded against — so a code cannot drift on the wire without failing this gate (F3;
    # mirrors the recheck/description-format gates). design.md §3.5. Codes are the standards range
    # 1..0x7FFF; 0 is reserved.
    print("== error-codes.csv <-> CDDL naalp-error-code enum <-> error_codes oracle mapping ==")
    csv_rows = load_csv("vectors/registry/error-codes.csv")
    csv_map = {r["name"]: int(r["code"]) for r in csv_rows}
    cddl = cddl_enum("naalp-error-code")
    oracle = {e["name"]: int(e["code"]) for e in load_json("vectors/error_codes/cases.json")["errors"]}
    check(bool(cddl), "CDDL defines the naalp-error-code production")
    check(len(csv_map) == len(csv_rows), "error-codes.csv names are unique (%d rows)" % len(csv_rows))
    check(csv_map == cddl, "error-codes.csv (%d) == CDDL naalp-error-code enum (%d)" % (len(csv_map), len(cddl)))
    check(csv_map == oracle, "error-codes.csv == error_codes oracle mapping (%d)" % len(oracle))
    if not (csv_map == cddl == oracle):
        print("    csv-only :", sorted(set(csv_map.items()) - set(cddl.items()))[:5])
        print("    cddl-only:", sorted(set(cddl.items()) - set(csv_map.items()))[:5])
    # every standards code in range, 0 reserved (not assigned), and the sequential-from-1 scheme is
    # intact (a gap or duplicate would break the fields-of-record ordering the oracle documents).
    codes = sorted(csv_map.values())
    check(all(1 <= c <= 0x7FFF for c in codes), "every code is in the standards range 1..0x7FFF")
    check(codes == list(range(1, len(codes) + 1)), "codes are sequential 1..%d with no gap/dup" % len(codes))
    # retryable + subsystem must equal the oracle's (both derive from the oracle CANON; a hand-edit
    # of the generated CSV that diverges is caught here).
    ocanon = {e["name"]: (e["retryable"], e["subsystem"]) for e in load_json("vectors/error_codes/cases.json")["errors"]}
    bad = [r["name"] for r in csv_rows
           if (r["retryable"] == "yes") != ocanon.get(r["name"], (False, ""))[0]
           or r["subsystem"] != ocanon.get(r["name"], (False, ""))[1]]
    check(not bad, "CSV retryable/subsystem == oracle" + (" (bad: %s)" % bad[:5] if bad else ""))


def main():
    check_signatures()
    check_multicodec()
    check_channels()
    check_protocols()
    check_recheck()
    check_signer_counter()
    check_mcp()
    check_description_format()
    check_a2a_task_state()
    check_risk_labels()
    check_payment_format()
    check_trust_decision_input_classes()
    check_error_codes()
    print()
    if fails:
        print("REGISTRY DRIFT: FAILED (%d)" % len(fails))
        sys.exit(1)
    print("REGISTRY DRIFT: ALL GREEN (no drift)")


if __name__ == "__main__":
    main()
