# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP C2 signing layer for the Python SDK: the COSE_Sign1 (RFC 9052) signing-input and
object assembly, plus deterministic ML-DSA (FIPS 204, rnd=0) and Ed25519 (RFC 8032).

The deterministic ML-DSA path (dilithium-py sign(..., deterministic=True), which sets the
FIPS 204 rnd to 32 zero bytes) produces signatures byte-identical to the Go (CIRCL) and Rust
(fips204) reference implementations — verified against the shared conformance corpus and the
NIST ACVP keyGen vectors.
"""
import hashlib

from . import cbor
from . import _dilithium_thread_safety  # noqa: F401  (D10/#241: thread-safe SHAKE before any ML-DSA op)
from .cbor import U, N, B, T, A, M, Tag

ALG_MLDSA65 = -49
ALG_MLDSA87 = -50
ALG_ED25519 = -19

PROFILE_PUBLIC = 1
PROFILE_ENTERPRISE = 2
PROFILE_SOVEREIGN = 3

TAG_SIGN1 = 18
TAG_SIGN = 98  # COSE_Sign (multiple signatures) — the §5.2 Rotation object co-signature


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


# --- COSE_Sign (tag 98) multi-signature support: the §5.2 Rotation object co-signature ---

def leg_protected(alg: int) -> bytes:
    """One COSE_Signature protected header: {1: alg} (RFC 9052 §4)."""
    return cbor.encode(M([(U(1), N(alg))]))


def signature_to_be_signed(body_prot: bytes, signer_alg: int, payload: bytes) -> bytes:
    """The per-signer COSE_Signature signing input for a COSE_Sign (RFC 9052 §4.4):
    det-CBOR(["Signature", body_protected, sign_protected, external_aad(empty), payload]). Note the
    five-element "Signature" structure (with the per-leg sign_protected) vs the four-element
    "Signature1" of a COSE_Sign1."""
    return cbor.encode(A([T("Signature"), B(body_prot), B(leg_protected(signer_alg)), B(b""), B(payload)]))


def signature_leg(body_prot: bytes, alg: int, seed: bytes, payload: bytes):
    """Build one COSE_Signature leg: sign the per-signer ToBeSigned with the deterministic ML-DSA
    key derived from `seed`; return (leg_protected_bytes, signature_bytes)."""
    sprot = leg_protected(alg)
    sig = mldsa_sign(alg, seed, signature_to_be_signed(body_prot, alg, payload))
    return sprot, sig


def assemble_sign_raw(body_prot: bytes, payload: bytes, legs) -> bytes:
    """The tagged COSE_Sign object: 98([body_prot, {}, payload, [[sprot, {}, sig], ...]]). Each
    leg is (sprot, sig); each carries an empty unprotected header."""
    sig_arr = A([A([B(sprot), M([]), B(sig)]) for (sprot, sig) in legs])
    return cbor.encode(Tag(TAG_SIGN, A([B(body_prot), M([]), B(payload), sig_arr])))


def parse_sign_raw(obj: bytes):
    """Recover (body_prot, payload, [(sprot, sig), ...]) from a tagged COSE_Sign object."""
    v = cbor.decode(obj)
    if not isinstance(v, Tag) or v.n != TAG_SIGN or not isinstance(v.content, A):
        raise ValueError("not a tagged COSE_Sign")
    arr = v.content.items
    if len(arr) != 4 or not isinstance(arr[0], B) or not isinstance(arr[2], B) or not isinstance(arr[3], A):
        raise ValueError("malformed COSE_Sign array")
    legs = []
    for e in arr[3].items:
        if not isinstance(e, A) or len(e.items) != 3 or not isinstance(e.items[0], B) or not isinstance(e.items[2], B):
            raise ValueError("malformed COSE_Signature leg")
        legs.append((e.items[0].v, e.items[2].v))
    return arr[0].v, arr[2].v, legs


def alg_from_protected(prot: bytes) -> int:
    """Extract the alg (label 1) value from a serialized leg protected header {1: alg}."""
    # §3.1.1 (R5): reject the redundant 0x41A0 encoding of an empty protected header (a bstr
    # wrapping an empty map; its unwrapped content is the single byte 0xA0) as NonCanonical,
    # before interpreting the header -- the empty protected header is pinned to 0x40.
    if len(prot) == 1 and prot[0] == 0xA0:
        raise cbor.NonCanonical("empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)")
    v = cbor.decode(prot)
    if not isinstance(v, M):
        raise ValueError("protected header not a map")
    for k, val in v.pairs:
        if isinstance(k, U) and k.v == 1 and isinstance(val, N):
            return val.v
    raise ValueError("no alg in protected header")


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


# --- LAMPS opt-in composite signature (alg -65537, design.md §4.2) ---

ALG_COMPOSITE_65_ED25519 = -65537  # COMPSIG-MLDSA65-Ed25519-SHA512 (Public/Enterprise)
ALG_COMPOSITE_44_ED25519 = -65538  # COMPSIG-MLDSA44-Ed25519-SHA512 (edge; RESERVED, not implemented)
_COMPOSITE_PREFIX = b"CompositeAlgorithmSignatures2025"
_COMPOSITE_LABEL_MLDSA65_ED25519 = b"COMPSIG-MLDSA65-Ed25519-SHA512"
_MLDSA65_SIG_SIZE = 3309  # FIPS 204 ML-DSA-65 signature size; asserted by the round-trip test
MLDSA65_PUB_SIZE = 1952   # FIPS 204 ML-DSA-65 public-key size; the composite pubkey split point


def compute_mprime(label: bytes, ctx: bytes, m: bytes) -> bytes:
    """LAMPS composite message representative (design.md §4.2):

        M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)

    len(ctx) is a single length octet; PH is SHA-512; M is the object's COSE_Sign1 ToBeSigned.
    For N-AALP the composite context ctx is empty, so the octet is 0x00 and ctx adds no bytes.
    Both the ML-DSA and Ed25519 legs sign this same M'."""
    if len(ctx) > 255:
        raise ValueError("composite context exceeds one length octet")
    return _COMPOSITE_PREFIX + label + bytes([len(ctx)]) + ctx + hashlib.sha512(bytes(m)).digest()


def composite_sign(mldsa_seed: bytes, ed_seed: bytes, tbs: bytes) -> bytes:
    """LAMPS composite signature value over the COSE ToBeSigned bytes tbs: mldsaSig || tradSig
    (ML-DSA-65 first, raw concatenation, no length prefixes; design.md §4.2). The ML-DSA leg is
    deterministic (rnd=0) with context = the suite Label octets; the Ed25519 leg signs M' with no
    context."""
    from dilithium_py.ml_dsa import ML_DSA_65
    mprime = compute_mprime(_COMPOSITE_LABEL_MLDSA65_ED25519, b"", tbs)
    _pk, sk = ML_DSA_65.key_derive(bytes(mldsa_seed))
    mldsa_sig = ML_DSA_65.sign(sk, mprime, _COMPOSITE_LABEL_MLDSA65_ED25519, deterministic=True)
    trad_sig = ed25519_sign(ed_seed, mprime)
    return bytes(mldsa_sig) + bytes(trad_sig)  # ML-DSA first (LAMPS order)


def composite_verify(mldsa_pk: bytes, ed_pk: bytes, m: bytes, sig: bytes) -> bool:
    """Valid IFF BOTH the ML-DSA-65 leg (context = Label) and the Ed25519 leg (no context)
    validate over M'. A value of the wrong length is malformed and rejected. A stripped or
    re-interpreted lone leg has no valid composite because M' binds both components into one
    value (RFC 9955 Strong Non-Separability; design.md §4.2/§4.5)."""
    from dilithium_py.ml_dsa import ML_DSA_65
    if len(sig) != _MLDSA65_SIG_SIZE + 64:
        return False
    mprime = compute_mprime(_COMPOSITE_LABEL_MLDSA65_ED25519, b"", m)
    mldsa_ok = bool(ML_DSA_65.verify(
        bytes(mldsa_pk), mprime, bytes(sig[:_MLDSA65_SIG_SIZE]), _COMPOSITE_LABEL_MLDSA65_ED25519))
    ed_ok = ed25519_verify(ed_pk, mprime, sig[_MLDSA65_SIG_SIZE:])
    return mldsa_ok and ed_ok


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
