# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP independent oracle for the §5.2 Rotation object — the ONE object carried as a tagged
COSE_Sign (tag 98, RFC 9052 §4.4) with EXACTLY two COSE_Signature legs in fixed order
(old key then new key), each leg signing the per-signer "Signature" ToBeSigned over the full
object payload. Constructs, FROM SCRATCH over the shared deterministic-CBOR encoder
(cbor_oracle.py, RFC 8949 §4.2.1), the byte authority for the worked rotation object and the
family of reject cases the cross-port harness grades.

WHAT THIS ORACLE GRADES, AND HOW (house convention, mirrors composite_oracle / envelope_oracle):
  - leg ToBeSigned (the "Signature" Sig_structure, RFC 9052 §4.4): det-CBOR(["Signature",
    body_protected, sign_protected, external_aad(empty), payload]) -> a COMMITTED, cross-all-ports
    KAT (rotation.leg_tbs). This is the pure-CBOR anchor for the multi-leg structure and is what
    distinguishes a COSE_Sign leg ("Signature", 5 elements, per-leg sign_protected) from a
    COSE_Sign1 ("Signature1", 4 elements, no per-signer header). A port that copies its Sign1 path
    diverges HERE, before any signature, and this committed KAT catches it non-circularly.
  - the full two-leg tag-98 object (rotation.sign): reproduced here as the byte reference. Like
    cose.sign1 / composite.sign, the deterministic ML-DSA signatures have no clean non-circular
    committed KAT (the NIST ACVP sigGen vectors are an internal interface), so the full object's
    cross-language byte-parity is graded by CONSENSUS (Go==Rust==...==this oracle) + the DURABLE
    self-assert below that pins the SHA-256 of the Go-produced object; NEVER as a standalone KAT.
  - the verify verdicts (rotation.verify): the worked object ACCEPTS; a tag-18 single-signature
    rotation, a dropped old leg, reordered legs, and a wrong-key old leg are each
    RotationUnauthorized; a tag-98 object on a non-rotation (channel,kind) is UnknownKind; and a
    Sovereign verifier over a rotation whose OLD key is below the profile signature floor is
    ProfileDowngrade (the ratified fail-closed default, rotationOldLegFloorApplies=true). These
    verdicts are committed (the object bytes are pinned/consensus-graded; the expected verdict is
    derived from design.md §5.2/§5.5, independent of any implementation).

NON-CIRCULARITY (R-16.1 / F3): this constructor shares NO code with impl/{go,rust,python,...}. It
uses only the shared deterministic-CBOR encoder (cbor_oracle) and the ML-DSA crypto library
directly (dilithium_py), the same independence posture as cose_oracle / envelope_oracle /
composite_oracle. The DURABLE self-assert (PIN_ROTATION_OBJECT_SHA256) ties this from-scratch
construction to the Go-produced object bytes: if the from-scratch path ever drifts from Go's
independently-produced bytes, the oracle fails loud. That pin is the anchor, not a self-agreement.

Fixture: old ML-DSA-65 seed = 0x0b*32, new ML-DSA-65 seed = 0x16*32; below-floor variant uses
old ML-DSA-65 seed = 0x21*32 and new ML-DSA-87 seed = 0x2c*32 (the 33/44 seeds the Go
TestRotationSovereignOldLegFloor uses). Worked object: channel 3, kind 0, effect 2
(non_idempotent_write, per channels.csv), tier 0, signer "SIGNER_NEW", created 1785000000000,
profile 1 (Public), field-10 rotation record {1:"signer-old", 2:"signer-new", 3:1785000000000}.
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

# ---- wire constants (independent of the impl; the object-SHA pin catches any drift) ----------
ALG_MLDSA65 = -49
ALG_MLDSA87 = -50
PROFILE_PUBLIC = 1
PROFILE_SOVEREIGN = 3
NAALP_VERSION = 2                 # draft-01 wire revision (design.md §2.5.3)
HEADER_LABEL = "naalp"
TAG_SIGN = 98                     # COSE_Sign (RFC 9052 §4)
TAG_SIGN1 = 18                    # COSE_Sign1 (RFC 9052 §4)

# alg -> NIST level, profile -> minimum signature level (cose.go algLevel / profileMinLevel).
_ALG_LEVEL = {ALG_MLDSA65: 3, ALG_MLDSA87: 5}
_PROFILE_FLOOR = {PROFILE_PUBLIC: 3, PROFILE_SOVEREIGN: 5}

# ---- worked rotation fixture ----------------------------------------------------------------
OLD_SEED = bytes([0x0B]) * 32     # old ML-DSA-65 key
NEW_SEED = bytes([0x16]) * 32     # new ML-DSA-65 key (go-forward)
FLOOR_OLD_SEED = bytes([0x21]) * 32   # 33: below-floor old ML-DSA-65 key
FLOOR_NEW_SEED = bytes([0x2C]) * 32   # 44: go-forward ML-DSA-87 key
SIGNER = b"SIGNER_NEW"            # object field-5 signer copy (opaque bstr; the go-forward id)
KIND, CHANNEL, TIER, EFFECT = 0, 3, 0, 2   # Identity Rotation object (channel 3, kind 0, effect 2)
CREATED = 1785000000000
NOT_BEFORE = 1785000000000
ROT_RECORD = ("map", [(1, "signer-old"), (2, "signer-new"), (3, NOT_BEFORE)])  # naalp-rotation body

# non-rotation (channel,kind) used for the UnknownKind reject case (a valid worked object relabel).
NONROT_CHANNEL, NONROT_KIND, NONROT_EFFECT = 4, 2, 2

# Go-produced pin (the non-circular anchor): the Go adapter's rotation.sign reproduced this
# from-scratch object byte-for-byte at the anchor step (#143b). If the from-scratch path ever
# drifts from Go's independently-produced bytes, build() fails loud (like composite's PIN_OBJECT).
PIN_ROTATION_OBJECT_SHA256 = "298d5d5bac8a0bf556541784f3090ac7300897858e883dc3ab6e7625bc418194"


# ---- from-scratch ML-DSA crypto (deterministic rnd=0, empty context; == cose.MLDSA*Signer) ---

def _mldsa(alg):
    from dilithium_py.ml_dsa import ML_DSA_65, ML_DSA_87
    return {ALG_MLDSA65: ML_DSA_65, ALG_MLDSA87: ML_DSA_87}[alg]


def mldsa_pub(alg, seed):
    pk, _sk = _mldsa(alg).key_derive(bytes(seed))
    return bytes(pk)


def mldsa_sign(alg, seed, msg):
    """Deterministic ML-DSA signature (rnd=0) over msg with EMPTY context — byte-identical to
    cose.MLDSA65Signer/MLDSA87Signer (mldsa.SignTo(sk, tbs, nil, false, sig))."""
    _pk, sk = _mldsa(alg).key_derive(bytes(seed))
    return bytes(_mldsa(alg).sign(sk, bytes(msg), b"", deterministic=True))


# ---- from-scratch object framing (over cbor_oracle, like envelope_oracle) --------------------

def content_id(body_no_id_pairs):
    digest = hashlib.sha384(enc(("map", body_no_id_pairs))).digest()  # 48 bytes
    return b"\x20\x30" + digest


def rotation_body_no_id(channel, kind, effect, profile, body):
    """Object body without field 1 (id); the encoder sorts by encoded key, so literal order is
    immaterial. Field 10 is the rotation record for the worked object."""
    return [
        (2, kind), (3, channel), (4, TIER), (5, SIGNER), (6, CREATED),
        (7, effect), (8, []), (9, profile), (10, body),
    ]


def object_payload(channel, kind, effect, profile, body):
    body_no_id = rotation_body_no_id(channel, kind, effect, profile, body)
    cid = content_id(body_no_id)
    payload = enc(("map", [(1, cid)] + body_no_id))
    return cid, payload


def body_protected(new_alg, profile):
    """The body protected header names the NEW (go-forward) key's alg plus the routing copies
    {1:signer, 2:profile, 3:version} (design.md §2.1/§2.5, §5.2)."""
    naalp = ("map", [(1, SIGNER), (2, profile), (3, NAALP_VERSION)])
    return enc(("map", [(1, new_alg), (HEADER_LABEL, naalp)]))


def leg_protected(alg):
    """One COSE_Signature protected header: {1: alg}."""
    return enc(("map", [(1, alg)]))


def leg_tbs(body_prot, alg, payload):
    """The per-signer COSE_Signature ToBeSigned (RFC 9052 §4.4):
    det-CBOR(["Signature", body_protected, sign_protected, external_aad(empty), payload])."""
    return enc(["Signature", body_prot, leg_protected(alg), b"", payload])


def sign_leg(body_prot, alg, seed, payload):
    """Return (sign_protected_bytes, signature_bytes) for one leg."""
    return leg_protected(alg), mldsa_sign(alg, seed, leg_tbs(body_prot, alg, payload))


def assemble_sign(body_prot, payload, legs):
    """Assemble a tagged COSE_Sign (tag 98) over the body protected header, payload, and ordered
    legs (each carries an empty unprotected header): 98([bp, {}, pl, [[sp,{},sig], ...]])."""
    sig_arr = [[sprot, ("map", []), sig] for (sprot, sig) in legs]
    return enc(("tag", TAG_SIGN, [body_prot, ("map", []), payload, sig_arr]))


def assemble_sign1(prot, alg, seed, payload):
    """A tag-18 single-signature COSE_Sign1 of the same object (the rejected single-sig rotation)."""
    tbs = enc(["Signature1", prot, b"", payload])
    sig = mldsa_sign(alg, seed, tbs)
    return enc(("tag", TAG_SIGN1, [prot, ("map", []), payload, sig]))


# ---- build the worked object + the reject family --------------------------------------------

def build():
    # ---- the worked (happy-path) rotation object: old=new=ML-DSA-65, profile Public ----------
    body_prot = body_protected(ALG_MLDSA65, PROFILE_PUBLIC)
    cid, payload = object_payload(CHANNEL, KIND, EFFECT, PROFILE_PUBLIC, ROT_RECORD)
    old_sprot, old_sig = sign_leg(body_prot, ALG_MLDSA65, OLD_SEED, payload)
    new_sprot, new_sig = sign_leg(body_prot, ALG_MLDSA65, NEW_SEED, payload)
    good_obj = assemble_sign(body_prot, payload, [(old_sprot, old_sig), (new_sprot, new_sig)])

    old_pub = mldsa_pub(ALG_MLDSA65, OLD_SEED)
    new_pub = mldsa_pub(ALG_MLDSA65, NEW_SEED)

    # committed leg-tbs KATs (pure CBOR, non-circular): the "Signature" Sig_structure per leg.
    old_tbs = leg_tbs(body_prot, ALG_MLDSA65, payload)
    new_tbs = leg_tbs(body_prot, ALG_MLDSA65, payload)  # same alg => same tbs; graded once per alg

    # ---- reject family (same worked keys unless noted) ---------------------------------------
    # tag-18 single-signature rotation (valid new-key Sign1) -> RotationUnauthorized.
    tag18_obj = assemble_sign1(body_prot, ALG_MLDSA65, NEW_SEED, payload)
    # dropped old leg (one leg, the new leg) -> RotationUnauthorized.
    oneleg_obj = assemble_sign(body_prot, payload, [(new_sprot, new_sig)])
    # reordered legs [new, old]: old key cannot verify the new-key sig in slot 0 -> RotationUnauthorized.
    reordered_obj = assemble_sign(body_prot, payload, [(new_sprot, new_sig), (old_sprot, old_sig)])
    # wrong old-key leg: both legs the NEW key -> old key cannot verify slot 0 -> RotationUnauthorized.
    wrong_sprot, wrong_sig = sign_leg(body_prot, ALG_MLDSA65, NEW_SEED, payload)
    wrongkey_obj = assemble_sign(body_prot, payload, [(wrong_sprot, wrong_sig), (new_sprot, new_sig)])
    # tag-98 on a non-rotation (channel 4, kind 2) -> UnknownKind.
    nr_cid, nr_payload = object_payload(NONROT_CHANNEL, NONROT_KIND, NONROT_EFFECT, PROFILE_PUBLIC, "hello")
    nr_old = sign_leg(body_prot, ALG_MLDSA65, OLD_SEED, nr_payload)
    nr_new = sign_leg(body_prot, ALG_MLDSA65, NEW_SEED, nr_payload)
    nonrot_obj = assemble_sign(body_prot, nr_payload, [nr_old, nr_new])

    # ---- below-floor Sovereign case: old=ML-DSA-65 (level 3), new=ML-DSA-87 (level 5),
    #      profile Sovereign (floor 5) -> ProfileDowngrade (old leg sub-floor, ratified default). --
    floor_prot = body_protected(ALG_MLDSA87, PROFILE_SOVEREIGN)
    floor_cid, floor_payload = object_payload(CHANNEL, KIND, EFFECT, PROFILE_SOVEREIGN, ROT_RECORD)
    floor_old = sign_leg(floor_prot, ALG_MLDSA65, FLOOR_OLD_SEED, floor_payload)
    floor_new = sign_leg(floor_prot, ALG_MLDSA87, FLOOR_NEW_SEED, floor_payload)
    floor_obj = assemble_sign(floor_prot, floor_payload, [floor_old, floor_new])
    floor_old_pub = mldsa_pub(ALG_MLDSA65, FLOOR_OLD_SEED)
    floor_new_pub = mldsa_pub(ALG_MLDSA87, FLOOR_NEW_SEED)

    # ---- structural self-asserts (the Go SHA pin is added at the anchor step #143b) ----------
    assert _ALG_LEVEL[ALG_MLDSA65] < _PROFILE_FLOOR[PROFILE_SOVEREIGN], "below-floor case must be sub-floor"
    assert _ALG_LEVEL[ALG_MLDSA87] >= _PROFILE_FLOOR[PROFILE_SOVEREIGN], "new leg must meet the floor"
    if PIN_ROTATION_OBJECT_SHA256 is not None:
        got = hashlib.sha256(bytes.fromhex(good_obj.hex())).hexdigest()
        assert got == PIN_ROTATION_OBJECT_SHA256, (
            "rotation object drifted from the Go reference: %s != %s" % (got, PIN_ROTATION_OBJECT_SHA256))

    def vcase(name, obj_hex, old_alg, old_pubkey, new_alg, new_pubkey, profile, valid, error):
        return {
            "name": name, "obj_hex": obj_hex,
            "old_alg": old_alg, "old_pubkey_hex": old_pubkey.hex(),
            "new_alg": new_alg, "new_pubkey_hex": new_pubkey.hex(),
            "profile": profile, "expect_valid": valid, "expect_error": error,
        }

    return {
        "note": "Independent oracle output for the N-AALP §5.2 Rotation object (tag-98 COSE_Sign, "
                "old+new co-signature). Go, Rust, and every port MUST reproduce leg_tbs (committed, "
                "non-circular), produce a rotation object that agrees byte-for-byte across "
                "implementations (consensus, like cose.sign1) and == the pinned Go object, and return "
                "the listed verify verdict for every case. Generated by tools/rotation_oracle.py; do "
                "not hand-edit.",
        "fixture": {
            "old_alg": ALG_MLDSA65, "old_seed_hex": OLD_SEED.hex(),
            "new_alg": ALG_MLDSA65, "new_seed_hex": NEW_SEED.hex(),
            "old_pubkey_hex": old_pub.hex(), "new_pubkey_hex": new_pub.hex(),
            "profile": PROFILE_PUBLIC, "channel": CHANNEL, "kind": KIND, "effect": EFFECT,
            "content_id_hex": cid.hex(),
            "protected_hex": body_prot.hex(),
            "payload_hex": payload.hex(),
        },
        # committed leg-tbs KATs (rotation.leg_tbs): the "Signature" Sig_structure per alg.
        "leg_tbs": [
            {"body_protected_hex": body_prot.hex(), "leg_alg": ALG_MLDSA65,
             "payload_hex": payload.hex(), "tbs_hex": old_tbs.hex()},
        ],
        # rotation.sign consensus input+expected (the worked object).
        "sign": {
            "old_alg": ALG_MLDSA65, "old_seed_hex": OLD_SEED.hex(),
            "new_alg": ALG_MLDSA65, "new_seed_hex": NEW_SEED.hex(),
            "protected_hex": body_prot.hex(), "payload_hex": payload.hex(),
            "obj_hex": good_obj.hex(),
            "obj_sha256": hashlib.sha256(good_obj).hexdigest(),
        },
        # rotation.verify verdict cases (accept + the reject family).
        "verify": [
            vcase("good", good_obj.hex(), ALG_MLDSA65, old_pub, ALG_MLDSA65, new_pub, PROFILE_PUBLIC, True, ""),
            vcase("tag18_single_sig", tag18_obj.hex(), ALG_MLDSA65, old_pub, ALG_MLDSA65, new_pub, PROFILE_PUBLIC, False, "RotationUnauthorized"),
            vcase("old_leg_dropped", oneleg_obj.hex(), ALG_MLDSA65, old_pub, ALG_MLDSA65, new_pub, PROFILE_PUBLIC, False, "RotationUnauthorized"),
            vcase("reordered_legs", reordered_obj.hex(), ALG_MLDSA65, old_pub, ALG_MLDSA65, new_pub, PROFILE_PUBLIC, False, "RotationUnauthorized"),
            vcase("old_leg_wrong_key", wrongkey_obj.hex(), ALG_MLDSA65, old_pub, ALG_MLDSA65, new_pub, PROFILE_PUBLIC, False, "RotationUnauthorized"),
            vcase("non_rotation_kind", nonrot_obj.hex(), ALG_MLDSA65, old_pub, ALG_MLDSA65, new_pub, PROFILE_PUBLIC, False, "UnknownKind"),
            vcase("sovereign_old_leg_floor", floor_obj.hex(), ALG_MLDSA65, floor_old_pub, ALG_MLDSA87, floor_new_pub, PROFILE_SOVEREIGN, False, "ProfileDowngrade"),
        ],
    }


def main():
    out_dir = os.path.normpath(os.path.join(HERE, "..", "vectors", "rotation"))
    os.makedirs(out_dir, exist_ok=True)
    data = build()
    path = os.path.join(out_dir, "cases.json")
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("leg tbs (ML-DSA-65):", data["leg_tbs"][0]["tbs_hex"][:24], "...",
          len(data["leg_tbs"][0]["tbs_hex"]) // 2, "bytes")
    print("worked object      :", data["sign"]["obj_hex"][:20], "...",
          len(data["sign"]["obj_hex"]) // 2, "bytes  sha256", data["sign"]["obj_sha256"][:16],
          "[pin OK]" if PIN_ROTATION_OBJECT_SHA256 else "[pin PENDING #143b]")
    print("verify cases       :", ", ".join(c["name"] for c in data["verify"]))
    print("wrote", path)


if __name__ == "__main__":
    main()
