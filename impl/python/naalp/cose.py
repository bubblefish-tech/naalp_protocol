# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP C2 signing layer for the Python SDK: the COSE_Sign1 (RFC 9052) signing-input and
object assembly, plus deterministic ML-DSA (FIPS 204, rnd=0) and Ed25519 (RFC 8032).

The deterministic ML-DSA path (dilithium-py sign(..., deterministic=True), which sets the
FIPS 204 rnd to 32 zero bytes) produces signatures byte-identical to the Go (CIRCL) and Rust
(fips204) reference implementations — verified against the shared conformance corpus and the
NIST ACVP keyGen vectors.
"""
from . import cbor
from .cbor import U, B, T, A, M, Tag

ALG_MLDSA65 = -49
ALG_MLDSA87 = -50
ALG_ED25519 = -19

PROFILE_PUBLIC = 1
PROFILE_ENTERPRISE = 2
PROFILE_SOVEREIGN = 3

TAG_SIGN1 = 18


def alg_level(alg: int):
    """NIST security level of a registered alg, and whether it is registered. Ed25519 is
    classical (level 0), valid only as a hybrid leg."""
    return {ALG_MLDSA87: 5, ALG_MLDSA65: 3, ALG_ED25519: 0}.get(alg, 0), alg in (ALG_MLDSA87, ALG_MLDSA65, ALG_ED25519)


def profile_min_level(profile: int) -> int:
    """Minimum signature level a profile accepts (Sovereign floors at level 5; else 3)."""
    return 5 if profile == PROFILE_SOVEREIGN else 3


def to_be_signed_raw(protected: bytes, payload: bytes) -> bytes:
    """The RFC 9052 §4.4 Sig_structure for a COSE_Sign1 over an already-serialized header."""
    return cbor.encode(A([T("Signature1"), B(protected), B(b""), B(payload)]))


def assemble_sign1_raw(protected: bytes, payload: bytes, sig: bytes) -> bytes:
    """The tagged COSE_Sign1 object: 18([protected, {}, payload, signature])."""
    return cbor.encode(Tag(TAG_SIGN1, A([B(protected), M([]), B(payload), B(sig)])))


def parse_sign1_raw(obj: bytes):
    """Recover (protected, payload, sig) from a tagged COSE_Sign1 object."""
    v = cbor.decode(obj)
    if not isinstance(v, Tag) or v.n != TAG_SIGN1 or not isinstance(v.content, A):
        raise ValueError("not a tagged COSE_Sign1")
    arr = v.content.items
    if len(arr) != 4 or not isinstance(arr[0], B) or not isinstance(arr[2], B) or not isinstance(arr[3], B):
        raise ValueError("malformed COSE_Sign1 array")
    return arr[0].v, arr[2].v, arr[3].v


# --- ML-DSA (FIPS 204) via dilithium-py ---

def _mldsa(alg):
    from dilithium_py.ml_dsa import ML_DSA_65, ML_DSA_87
    if alg == ALG_MLDSA65:
        return ML_DSA_65
    if alg == ALG_MLDSA87:
        return ML_DSA_87
    raise ValueError("alg %d is not an ML-DSA algorithm" % alg)


def mldsa_keygen(param: str, seed: bytes) -> bytes:
    """Derive the public key from a 32-byte seed (NIST ACVP keyGen); returns pk bytes."""
    from dilithium_py.ml_dsa import ML_DSA_65, ML_DSA_87
    M_ = ML_DSA_87 if param == "ML-DSA-87" else ML_DSA_65
    pk, _sk = M_.key_derive(bytes(seed))
    return pk


def mldsa_sign(alg: int, seed: bytes, tbs: bytes) -> bytes:
    """Deterministic (rnd=0) ML-DSA signature over tbs with the key derived from seed."""
    M_ = _mldsa(alg)
    _pk, sk = M_.key_derive(bytes(seed))
    return M_.sign(sk, bytes(tbs), b"", deterministic=True)


def mldsa_verify(alg: int, pk: bytes, tbs: bytes, sig: bytes) -> bool:
    M_ = _mldsa(alg)
    return bool(M_.verify(bytes(pk), bytes(tbs), bytes(sig), b""))


# --- Ed25519 (RFC 8032) via pyca/cryptography ---

def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if len(seed) != 32:
        raise ValueError("ed25519 secret key must be a 32-byte seed")
    return Ed25519PrivateKey.from_private_bytes(bytes(seed)).sign(bytes(msg))


def ed25519_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(bytes(pk)).verify(bytes(sig), bytes(msg))
        return True
    except InvalidSignature:
        return False


def cose_sign1(alg: int, seed: bytes, protected: bytes, payload: bytes) -> bytes:
    """Produce a deterministic tagged COSE_Sign1 object over (protected, payload)."""
    tbs = to_be_signed_raw(protected, payload)
    sig = mldsa_sign(alg, seed, tbs)
    return assemble_sign1_raw(protected, payload, sig)


def cose_verify1_raw(alg: int, pk: bytes, tbs: bytes, sig: bytes) -> bool:
    """Verify a raw signature over already-assembled ToBeSigned bytes, dispatching by alg."""
    if alg in (ALG_MLDSA65, ALG_MLDSA87):
        return mldsa_verify(alg, pk, tbs, sig)
    if alg == ALG_ED25519:
        return ed25519_verify(pk, tbs, sig)
    raise ValueError("unknown alg %d" % alg)


def cose_verify1(alg: int, pk: bytes, obj: bytes) -> bool:
    protected, payload, sig = parse_sign1_raw(obj)
    tbs = to_be_signed_raw(protected, payload)
    return cose_verify1_raw(alg, pk, tbs, sig)
