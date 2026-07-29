# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP C2 independent oracle: COSE_Sign1 / COSE_Sign signing inputs (RFC 9052 §4.4),
the crypto-profile table, and the algorithm registry — plus pass-through of the
independent NIST/RFC key-material known-answer vectors used to grade the primitives.

Non-circular authorities (R-16.1 / CLAUDE.md):
  - RFC 9052 §4.4  Sig_structure / ToBeSigned. Constructed here from scratch (this file
    shares no code with impl/go or impl/rust) over the shared deterministic-CBOR encoder
    in cbor_oracle.py (RFC 8949). This is the byte-authority for the COSE construction.
  - RFC 9964        ML-DSA COSE algorithm code points (-49 ML-DSA-65, -50 ML-DSA-87).
  - RFC 9864 §2.2   Ed25519 COSE code point (-19).
  - NIST ACVP FIPS 204 keyGen KATs (vectors/cose/nist_acvp_mldsa.json) — seed->pk, the
    independent authority for ML-DSA key generation (both impls reproduce pk byte-exact).
  - RFC 8032 §7.1   Ed25519 TEST 1 (sk/pk/msg/sig), the independent authority for the
    hybrid classical leg.

The ML-DSA *signature* bytes are not emitted here (a from-scratch Python ML-DSA is out of
scope); the signature path is graded by two-implementation deterministic byte-parity plus
mutual verification in the impl test suites, both anchored to NIST via the keyGen KAT. A
direct in-repo NIST sigGen byte-match needs NIST external-interface vectors and is tracked
for T14 (see nist_acvp_mldsa.json._note).
"""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # so `import cbor_oracle` resolves to tools/cbor_oracle.py
import cbor_oracle  # shared deterministic-CBOR encoder (RFC 8949), extended with Nint/Tag


# ---- COSE algorithm registry (design.md §4.1) -----------------------------------------
ALGS = [
    {"name": "ML-DSA-65", "alg": -49, "level": 3, "ref": "RFC9964"},
    {"name": "ML-DSA-87", "alg": -50, "level": 5, "ref": "RFC9964"},
    {"name": "Ed25519",   "alg": -19, "level": 0, "ref": "RFC9864"},  # classical, hybrid leg only
]

# ---- crypto-profile table (design.md §4.4) --------------------------------------------
PROFILES = [
    {"profile": 1, "name": "public",     "default_alg": -49, "min_level": 3},
    {"profile": 2, "name": "enterprise", "default_alg": -49, "min_level": 3},
    {"profile": 3, "name": "sovereign",  "default_alg": -50, "min_level": 5},
]


def enc(v):
    return cbor_oracle.encode(v)


def protected_bytes(header_pairs):
    """Serialize a COSE protected header. RFC 9052 §3: an EMPTY protected header is a
    zero-length byte string, not the encoding of an empty map."""
    if not header_pairs:
        return b""
    return enc(("map", header_pairs))


def sign1_tobesigned(alg, payload):
    """COSE_Sign1 ToBeSigned (RFC 9052 §4.4): det-CBOR of
    ["Signature1", body_protected(bstr), external_aad(bstr, empty), payload(bstr)]."""
    prot = protected_bytes([(1, alg)])              # protected header {1: alg}
    sig_structure = ["Signature1", prot, b"", payload]
    return enc(sig_structure), prot


def signature_tobesigned(body_prot, signer_alg, payload):
    """COSE_Signature ToBeSigned inside a COSE_Sign (hybrid, RFC 9052 §4.4): det-CBOR of
    ["Signature", body_protected(bstr), sign_protected(bstr), external_aad(bstr), payload]."""
    signer_prot = protected_bytes([(1, signer_alg)])
    sig_structure = ["Signature", body_prot, signer_prot, b"", payload]
    return enc(sig_structure), signer_prot


def hx(b):
    return b.hex()


def build():
    nist = json.load(open(os.path.join(HERE, "..", "vectors", "cose", "nist_acvp_mldsa.json")))

    # A representative object-body payload (an object body is CBOR; here {7:0} = effect read_only).
    payload = bytes.fromhex("a10700")

    sign1 = []
    for a in (-49, -50, -19):
        tbs, prot = sign1_tobesigned(a, payload)
        sign1.append({
            "name": f"sign1_alg{a}",
            "alg": a,
            "payload_hex": hx(payload),
            "protected_hex": hx(prot),
            "tobesigned_hex": hx(tbs),
        })

    # Hybrid (COSE_Sign, tag 98): empty body protected header, one Ed25519 (-19) and one
    # ML-DSA (-49) signer, each with its own per-signer ToBeSigned.
    body_prot = protected_bytes([])  # empty -> h''
    ed_tbs, ed_prot = signature_tobesigned(body_prot, -19, payload)
    ml_tbs, ml_prot = signature_tobesigned(body_prot, -49, payload)
    hybrid = {
        "payload_hex": hx(payload),
        "body_protected_hex": hx(body_prot),          # "" (empty protected)
        "ed": {"alg": -19, "protected_hex": hx(ed_prot), "tobesigned_hex": hx(ed_tbs)},
        "ml": {"alg": -49, "protected_hex": hx(ml_prot), "tobesigned_hex": hx(ml_tbs)},
    }

    mldsa_keygen = []
    for name, alg in (("ML-DSA-65", -49), ("ML-DSA-87", -50)):
        kv = nist["keygen"][name]
        # NIST ACVP hex is uppercase; normalize to lowercase so the graded corpus is
        # uniform and matches Go hex.EncodeToString / Rust hex::encode output. Case is
        # not semantically meaningful; the byte values are unchanged.
        mldsa_keygen.append({"param": name, "alg": alg,
                             "seed_hex": kv["seed"].lower(), "pk_hex": kv["pk"].lower()})

    # RFC 8032 §7.1 Ed25519 TEST 1 (independent authority for the hybrid classical leg).
    ed25519 = {
        "_source": "RFC 8032 Section 7.1, TEST 1",
        "sk_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "pk_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "msg_hex": "",
        "sig_hex": ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33"
                    "bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    }

    return {
        "note": "Independent oracle output for N-AALP C2 (COSE_Sign1 signing input + profiles + "
                "registry). Go and Rust MUST reproduce every protected_hex/tobesigned_hex, reproduce "
                "each mldsa_keygen pk_hex from its seed, and reproduce the RFC 8032 Ed25519 signature. "
                "Generated by tools/cose_oracle.py; do not hand-edit.",
        "algs": ALGS,
        "profiles": PROFILES,
        "sign1": sign1,
        "hybrid": hybrid,
        "mldsa_keygen": mldsa_keygen,
        "ed25519_rfc8032_test1": ed25519,
    }


def main():
    out_dir = os.path.normpath(os.path.join(HERE, "..", "vectors", "cose"))
    os.makedirs(out_dir, exist_ok=True)
    data = build()
    path = os.path.join(out_dir, "cases.json")
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    for c in data["sign1"]:
        print(c["name"], "protected", c["protected_hex"], "tbs", len(c["tobesigned_hex"]) // 2, "bytes")
    print("hybrid ed tbs", len(data["hybrid"]["ed"]["tobesigned_hex"]) // 2, "bytes;",
          "ml tbs", len(data["hybrid"]["ml"]["tobesigned_hex"]) // 2, "bytes")
    for k in data["mldsa_keygen"]:
        print("keygen", k["param"], "pk", len(k["pk_hex"]) // 2, "bytes")
    print("wrote", path)


if __name__ == "__main__":
    main()
