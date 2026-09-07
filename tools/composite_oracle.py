# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP independent oracle for the opt-in LAMPS composite signature (alg -65537, design.md
§4.2). Constructs, FROM SCRATCH, the byte authority for the composite message representative
M' and the deterministic non-signature framing of a composite object, and reproduces the
composite value + full signed object for the worked fixture as a non-circular anchor.

WHAT THIS ORACLE GRADES, AND HOW (house convention, mirrors cose_oracle/envelope_oracle):
  - M' construction  = Prefix || Label || len(ctx) || ctx || SHA-512(M)  (§4.2). Pure hashing,
    fully independent of any implementation -> a COMMITTED, cross-all-ports KAT.
  - composite object ToBeSigned (the deterministic COSE_Sign1 signing input over the composite
    body: field 14 present, protected-header alg -65537) -> a COMMITTED, cross-all-ports KAT,
    built over the shared deterministic-CBOR encoder (cbor_oracle, RFC 8949 §4.2.1), the same
    way envelope_oracle builds the pure object's ToBeSigned.
  - composite signer id (§5.1) for the worked fixture's OWN keys -> a COMMITTED KAT (multihash
    of the multicodec-tagged ML-DSA-65 pubkey concatenated with the tagged Ed25519 pubkey; only
    existing official multicodecs, no minted code). Independent of any implementation.
  - the full deterministic composite VALUE (mldsaSig || edSig) and the full signed OBJECT are
    reproduced here as a REFERENCE and a non-circular anchor, but -- exactly like cose.sign1 --
    the deterministic ML-DSA signature has no clean non-circular committed KAT (the NIST ACVP
    sigGen vectors are an internal interface), so their cross-language byte-parity is graded by
    the crypto-consensus gate (tools/crypto_consensus.py: Go==Rust==Python==... agreement +
    verify-accepts-consensus + verify-rejects-tamper), NEVER as a pinned KAT.

NON-CIRCULARITY (R-16.1 / F3): this constructor shares NO code with impl/{go,rust,python}. It
uses only the shared deterministic-CBOR encoder (cbor_oracle) and the ML-DSA / Ed25519 crypto
libraries directly (dilithium_py, pyca cryptography) -- the same independence posture as
cose_oracle and envelope_oracle. The three DURABLE self-asserts below tie this from-scratch
construction to the Go-verified pinned constants (value 424ccd9a.., object d0768cfc.., signer
id bciqpryn..): if the from-scratch path ever drifts from Go's independently-produced bytes,
verify.sh step [1/5] fails loud. That is the anchor, not a self-agreement.

Fixture (the SAME one test_composite.py and Go cmd/naalp-composite / Rust example/naalp_composite
pin, so there is ONE coherent composite fixture): ML-DSA-65 seed = bytes(0..31), Ed25519 seed =
"naalp-composite-ed25519-seed-32b", worked object {kind 2, channel 4, tier 0, signer "SIGNER_A",
created 1785000000000, effect 2, profile 1, body "hello", suite 1}.

RELATIONSHIP TO THE OTHER COMPOSITE ORACLE BLOCKS (distinct consumers, no conflict): cose_oracle.py
emits a minimal composite block in vectors/cose/cases.json (M' + ToBeSigned only, no seeds/value)
that the impl/{go,rust} cose UNIT tests grade; signerid_oracle.py emits the composite signer id
(NIST keys) in vectors/identity/cases.json for the identity unit test. This oracle is the
composite-FAMILY oracle for the CROSS-PORT HARNESS: it additionally emits the deterministic seeds,
the verifying-key split, and the coherent worked-object fixture the corpus (composite.mprime /
composite.signerid) and the crypto-consensus gate (composite.sign) drive through every adapter.
Each block is independently anchored (this one by the self-asserts below; the unit-test blocks by
their own tests), so they cannot silently drift.
"""
import base64
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared deterministic-CBOR encoder (RFC 8949 §4.2.1); NOT an impl SDK

enc = cbor_oracle.encode

# ---- composite construction constants (design.md §4.2) --------------------------------------
COMPOSITE_PREFIX = b"CompositeAlgorithmSignatures2025"
COMPOSITE_LABEL = b"COMPSIG-MLDSA65-Ed25519-SHA512"
ALG_COMPOSITE_65_ED25519 = -65537           # COMPSIG-MLDSA65-Ed25519-SHA512 (Public/Enterprise)
MLDSA65_SIG_SIZE = 3309                     # FIPS 204 ML-DSA-65 signature size
MLDSA65_PUB_SIZE = 1952                     # FIPS 204 ML-DSA-65 public-key size (split point)

# object wire constants (spec/wire-constants.csv -> _wire_constants_gen.py in the impl); the
# oracle hard-codes them independently and the object-SHA self-assert catches any drift.
FIELD_SUITE = 14
SUITE_MLDSA65_ED25519 = 1
NAALP_VERSION = 2
HEADER_LABEL = "naalp"

# multiformats codes (multicodec registry) for the composite signer id (§5.1).
CODE_ED25519 = 0xED
CODE_MLDSA65 = 0x1211
MH_SHA256 = 0x12

# the worked composite fixture (identical to test_composite.py / Go cmd / Rust example).
MLDSA_SEED = bytes(range(32))
ED_SEED = b"naalp-composite-ed25519-seed-32b"
RAW_TBS = b"parity-tbs-fixed"              # the value-level KAT message (test_composite parity tbs)

# Go-verified pinned constants (the non-circular anchor; test_composite.py pins these against the
# Go reference: value == impl/go/cose CompositeSigner, object == cmd/naalp-composite, id == Go
# identity.CompositeSignerID).
PIN_VALUE_SHA256 = "424ccd9ac5c96024f2c5a780705749b927b5f1cede4460cd099ebdfbb2b8d9d1"
PIN_OBJECT_SHA256 = "d0768cfc7948c189cee5ecf2336fa2f2b62a35ad4def84c801da86a0f6133181"
PIN_SIGNER_ID = "bciqprynbbhjimvhoque4zvkhftcwubtjahyw5ybwoqxxit5desygivi"


# ---- from-scratch crypto core (no impl import) ----------------------------------------------

def compute_mprime(label, ctx, m):
    """M' = Prefix || Label || len(ctx) || ctx || SHA-512(M) (design.md §4.2). len(ctx) is a
    single length octet; PH is SHA-512; ctx is empty for N-AALP (octet 0x00, no ctx bytes)."""
    if len(ctx) > 255:
        raise ValueError("composite context exceeds one length octet")
    return COMPOSITE_PREFIX + label + bytes([len(ctx)]) + ctx + hashlib.sha512(bytes(m)).digest()


def composite_keys(mldsa_seed, ed_seed):
    """Derive the ML-DSA-65 and Ed25519 public keys for the composite keypair."""
    from dilithium_py.ml_dsa import ML_DSA_65
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    ml_pk, _sk = ML_DSA_65.key_derive(bytes(mldsa_seed))
    ed_pk = Ed25519PrivateKey.from_private_bytes(bytes(ed_seed)).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    return bytes(ml_pk), bytes(ed_pk)


def composite_value(mldsa_seed, ed_seed, m):
    """The LAMPS composite signature value over message m: mldsaSig(M') || edSig(M') (ML-DSA
    first, raw concat, §4.2). ML-DSA-65 leg is deterministic (rnd=0) with context = the suite
    Label octets; the Ed25519 leg signs M' with no context."""
    from dilithium_py.ml_dsa import ML_DSA_65
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    mprime = compute_mprime(COMPOSITE_LABEL, b"", m)
    _pk, sk = ML_DSA_65.key_derive(bytes(mldsa_seed))
    mldsa_sig = ML_DSA_65.sign(sk, mprime, COMPOSITE_LABEL, deterministic=True)
    ed_sig = Ed25519PrivateKey.from_private_bytes(bytes(ed_seed)).sign(mprime)
    return bytes(mldsa_sig) + bytes(ed_sig)


# ---- from-scratch composite signer id (§5.1), independent of impl/identity ------------------

def _uvarint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def composite_signer_id(ml_pk, ed_pk):
    """multibase(base32, multihash(0x12, SHA-256(multicodec(0x1211, mldsaPub) ||
    multicodec(0xed, edPub)))) (§5.1). Substituting either leg changes the id."""
    preimage = _uvarint(CODE_MLDSA65) + ml_pk + _uvarint(CODE_ED25519) + ed_pk
    digest = hashlib.sha256(preimage).digest()
    mh = _uvarint(MH_SHA256) + _uvarint(len(digest)) + digest
    return "b" + base64.b32encode(mh).decode("ascii").lower().rstrip("=")


# ---- from-scratch composite object framing (over cbor_oracle, like envelope_oracle) ---------

def _content_id(body_no_id_pairs):
    digest = hashlib.sha384(enc(("map", body_no_id_pairs))).digest()  # 48 bytes
    return b"\x20\x30" + digest


def build_object(mldsa_seed, ed_seed):
    """Assemble the worked composite object from scratch: body (field 14 present) -> content id ->
    payload -> protected (alg -65537) -> ToBeSigned -> composite value -> tagged COSE_Sign1."""
    signer = bytes.fromhex("5349474e45525f41")  # "SIGNER_A"
    kind, channel, tier, created, effect, profile = 2, 4, 0, 1785000000000, 2, 1
    body_str = "hello"

    # body without field 1 (id), composite => field 14 (suite) present. The encoder sorts by the
    # encoded key, so the literal order here does not matter; the fields present do.
    body_no_id = [
        (2, kind), (3, channel), (4, tier), (5, signer), (6, created),
        (7, effect), (8, []), (9, profile), (10, body_str),
        (FIELD_SUITE, SUITE_MLDSA65_ED25519),
    ]
    cid = _content_id(body_no_id)
    payload = enc(("map", [(1, cid)] + body_no_id))

    naalp = ("map", [(1, signer), (2, profile), (3, NAALP_VERSION)])
    protected = enc(("map", [(1, ALG_COMPOSITE_65_ED25519), (HEADER_LABEL, naalp)]))

    tbs = enc(["Signature1", protected, b"", payload])
    value = composite_value(mldsa_seed, ed_seed, tbs)
    obj = enc(("tag", 18, [protected, ("map", []), payload, value]))
    return {
        "signer_hex": signer.hex(), "kind": kind, "channel": channel, "tier": tier,
        "created": created, "effect": effect, "profile": profile, "body_str": body_str,
        "suite": SUITE_MLDSA65_ED25519, "alg": ALG_COMPOSITE_65_ED25519, "version": NAALP_VERSION,
        "content_id_hex": cid.hex(),
        "payload_hex": payload.hex(),
        "protected_hex": protected.hex(),
        "tobesigned_hex": tbs.hex(),
        "value_hex": value.hex(),
        "object_hex": obj.hex(),
    }


def build():
    ml_pk, ed_pk = composite_keys(MLDSA_SEED, ED_SEED)

    # M' KATs (committed, non-circular): the raw-tbs value message, and the object's ToBeSigned.
    raw_mprime = compute_mprime(COMPOSITE_LABEL, b"", RAW_TBS)

    # value-level KAT over the raw parity tbs (the crypto-core anchor; consensus-graded).
    raw_value = composite_value(MLDSA_SEED, ED_SEED, RAW_TBS)

    obj = build_object(MLDSA_SEED, ED_SEED)
    obj_mprime = compute_mprime(COMPOSITE_LABEL, b"", bytes.fromhex(obj["tobesigned_hex"]))
    sid = composite_signer_id(ml_pk, ed_pk)

    # ---- DURABLE non-circular self-asserts (advisor linchpin): the from-scratch construction
    # MUST reproduce the Go-verified pinned constants. A mismatch is a FINDING, surfaced loud.
    assert hashlib.sha256(raw_value).hexdigest() == PIN_VALUE_SHA256, (
        "composite value drifted from the Go reference: %s != %s"
        % (hashlib.sha256(raw_value).hexdigest(), PIN_VALUE_SHA256))
    assert hashlib.sha256(bytes.fromhex(obj["object_hex"])).hexdigest() == PIN_OBJECT_SHA256, (
        "composite object drifted from the Go cmd/naalp-composite reference: %s != %s"
        % (hashlib.sha256(bytes.fromhex(obj["object_hex"])).hexdigest(), PIN_OBJECT_SHA256))
    assert sid == PIN_SIGNER_ID, "composite signer id drifted from Go: %s != %s" % (sid, PIN_SIGNER_ID)
    assert len(raw_value) == MLDSA65_SIG_SIZE + 64, "composite value must be mldsaSig(3309) || edSig(64)"

    return {
        "note": "Independent oracle output for the N-AALP opt-in LAMPS composite signature "
                "(alg -65537, design.md §4.2). Go, Rust, and Python MUST reproduce mprime.mprime_hex "
                "and the object tobesigned_hex (committed, non-circular), reproduce the composite "
                "signer id from both leg keys, and produce a composite value/object that agrees "
                "byte-for-byte across implementations (crypto-consensus, like cose.sign1) and verifies "
                "fail-closed. Generated by tools/composite_oracle.py; do not hand-edit.",
        "label_ascii": COMPOSITE_LABEL.decode("ascii"),
        "prefix_ascii": COMPOSITE_PREFIX.decode("ascii"),
        "alg": ALG_COMPOSITE_65_ED25519,
        "mldsa_alg": -49,  # COSE ML-DSA-65 alg id; selects multicodec 0x1211 for the signer id (§5.1)
        "mldsa_seed_hex": MLDSA_SEED.hex(),
        "ed_seed_hex": ED_SEED.hex(),
        "mldsa_pubkey_hex": ml_pk.hex(),
        "ed_pubkey_hex": ed_pk.hex(),
        "composite_pubkey_hex": (ml_pk + ed_pk).hex(),  # verifying key = mldsaPub || edPub
        "signer_id": sid,
        "mprime": {
            # committed KATs: len(M') = 32 + 30 + 1 + 0 + 64 = 127 bytes.
            "raw_tbs": {"m_hex": RAW_TBS.hex(), "mprime_hex": raw_mprime.hex()},
            "object_tbs": {"m_hex": obj["tobesigned_hex"], "mprime_hex": obj_mprime.hex()},
        },
        "value": {
            # crypto-core reference over the raw parity tbs (consensus-graded, == Go pin).
            "m_hex": RAW_TBS.hex(), "value_hex": raw_value.hex(),
            "mldsa_sig_size": MLDSA65_SIG_SIZE, "ed_sig_size": 64,
        },
        "object": obj,
    }


def main():
    out_dir = os.path.normpath(os.path.join(HERE, "..", "vectors", "composite"))
    os.makedirs(out_dir, exist_ok=True)
    data = build()
    path = os.path.join(out_dir, "cases.json")
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("composite label   :", data["label_ascii"])
    print("M' (raw tbs)       :", data["mprime"]["raw_tbs"]["mprime_hex"][:24], "...",
          len(data["mprime"]["raw_tbs"]["mprime_hex"]) // 2, "bytes")
    print("value (raw tbs)    :", data["value"]["value_hex"][:20], "...",
          len(data["value"]["value_hex"]) // 2, "bytes  [pin OK]")
    print("object (worked)    :", data["object"]["object_hex"][:20], "...",
          len(data["object"]["object_hex"]) // 2, "bytes  [pin OK]")
    print("composite signer id:", data["signer_id"], " [pin OK]")
    print("wrote", path)


if __name__ == "__main__":
    main()
