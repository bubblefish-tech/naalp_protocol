# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP C4 identity for the Python SDK: the self-certifying signer id (§5.1) and the NFC rule.

signer id = multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))),
identical in form to the N-PAMP PeerHandle. Multicodec codes are from the multiformats
registry: ed25519-pub 0xed, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212; multihash sha2-256 0x12.
"""
import base64
import hashlib
import unicodedata

from .cose import ALG_ED25519, ALG_MLDSA65, ALG_MLDSA87

_MULTICODEC = {
    ALG_ED25519: 0xED,
    ALG_MLDSA65: 0x1211,
    ALG_MLDSA87: 0x1212,
}
_MH_SHA256 = 0x12


class UnknownAlg(ValueError):
    kind = "UnknownAlg"


class SignerMismatch(ValueError):
    kind = "SignerMismatch"


class NonNFC(ValueError):
    kind = "NonNFC"


def _uvarint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def signer_id(alg: int, pubkey: bytes) -> str:
    mc = _MULTICODEC.get(alg)
    if mc is None:
        raise UnknownAlg("no multicodec for alg %d" % alg)
    tagged = _uvarint(mc) + bytes(pubkey)
    digest = hashlib.sha256(tagged).digest()
    mh = _uvarint(_MH_SHA256) + _uvarint(len(digest)) + digest
    return "b" + base64.b32encode(mh).decode("ascii").lower().rstrip("=")


def check_signer(claimed: str, alg: int, pubkey: bytes) -> None:
    if signer_id(alg, pubkey) != claimed:
        raise SignerMismatch("signer id does not recompute from the key")


def require_nfc(s: str) -> None:
    """Reject an identity/scope string that is not Unicode NFC (§3.1, R-3.3)."""
    if unicodedata.normalize("NFC", s) != s:
        raise NonNFC("string is not Unicode NFC")
