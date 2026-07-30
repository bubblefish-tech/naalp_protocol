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
    # hash. The CDDL (spec/naalp-draft-00.cddl) is the authority: multihash(0x20, SHA-384(...))
    # names the content id (§2.3) and multihash(0x12, SHA-256(...)) the signer id (§5.1). Scan
    # those codes out of the CDDL and assert coverage, so a hash added to the wire cannot ship
    # without a registry row. (0x20 = sha2-384, 0x12 = sha2-256 per the multiformats table.)
    all_rows = load_csv("vectors/registry/multicodec.csv")
    hash_codes = {int(r["code"], 16) for r in all_rows if r["role"] == "multihash-hash"}
    cddl = open(os.path.join(ROOT, "spec/naalp-draft-00.cddl")).read()
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


def main():
    check_signatures()
    check_multicodec()
    check_channels()
    check_protocols()
    print()
    if fails:
        print("REGISTRY DRIFT: FAILED (%d)" % len(fails))
        sys.exit(1)
    print("REGISTRY DRIFT: ALL GREEN (no drift)")


if __name__ == "__main__":
    main()
