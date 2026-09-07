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


def composite_signer_id(mldsa_alg: int, mldsa_pub: bytes, ed_pub: bytes) -> str:
    """Self-certifying signer id for a composite key pair (§5.1). The SHA-256 preimage is the
    multicodec-tagged ML-DSA public key concatenated with the multicodec-tagged Ed25519 public
    key -- using only existing official multicodecs (no minted composite code) -- so stripping or
    substituting either leg changes the id (=> SignerMismatch before verify). Downgrade-resistant.
    mldsa_alg selects the ML-DSA multicodec (0x1211 for ML-DSA-65, 0x1212 for ML-DSA-87); the
    classical leg is always Ed25519 (0xed)."""
    if mldsa_alg not in (ALG_MLDSA65, ALG_MLDSA87):
        raise UnknownAlg("composite signer id requires an ML-DSA alg, got %d" % mldsa_alg)
    preimage = (_uvarint(_MULTICODEC[mldsa_alg]) + bytes(mldsa_pub)
                + _uvarint(_MULTICODEC[ALG_ED25519]) + bytes(ed_pub))
    digest = hashlib.sha256(preimage).digest()
    mh = _uvarint(_MH_SHA256) + _uvarint(len(digest)) + digest
    return "b" + base64.b32encode(mh).decode("ascii").lower().rstrip("=")


def check_signer(claimed: str, alg: int, pubkey: bytes) -> None:
    if signer_id(alg, pubkey) != claimed:
        raise SignerMismatch("signer id does not recompute from the key")


def require_nfc(s: str) -> None:
    """Reject an identity/scope string that is not Unicode NFC (§3.1, R-3.3)."""
    if unicodedata.normalize("NFC", s) != s:
        raise NonNFC("string is not Unicode NFC")


# ---- key rotation (design §5.2): the co-signed old->new link ---------------------------------
# The self-certifying signer id survives a key rotation: a RotationRecord binds the old id to the
# new id from a not_before position, co-signed by BOTH keys, so attribution to the durable identity
# is preserved across rotation (R-1.4). This is the C4 primitive the Delivery-Model-B principal
# registry (naalp.rooms) composes on for a rotation-authorised rebind.


class RotationUnauthorized(ValueError):
    kind = "RotationUnauthorized"


class RotationRecord:
    """Links an old signer id to a new one from `not_before` (§5.2). Its signed bytes are the
    deterministic-CBOR map {1: old, 2: new, 3: not_before}."""

    __slots__ = ("old", "new", "not_before")

    def __init__(self, old: str, new: str, not_before: int):
        self.old = old
        self.new = new
        self.not_before = int(not_before)

    def bytes(self) -> bytes:
        from . import cbor
        from .cbor import U, T, M
        return cbor.encode(M([(U(1), T(self.old)), (U(2), T(self.new)), (U(3), U(self.not_before))]))


def sign_rotation(r: RotationRecord, alg: int, old_seed: bytes, new_seed: bytes):
    """Co-sign a rotation with BOTH the old and new keys (§5.2): each leg is a raw deterministic
    ML-DSA signature over the rotation body. Returns (old_sig, new_sig)."""
    from . import cose
    m = r.bytes()
    return cose.mldsa_sign(alg, old_seed, m), cose.mldsa_sign(alg, new_seed, m)


def verify_rotation(r: RotationRecord, old_alg: int, old_pub: bytes,
                    new_alg: int, new_pub: bytes, old_sig: bytes, new_sig: bytes) -> None:
    """Confirm a rotation is authorized (§5.2, §5.5): the old and new keys derive the ids in the
    record AND both signatures verify. Any failure -- an id that does not recompute from its key or
    a signature that does not verify -- is RotationUnauthorized (fail-closed). A substitution not
    co-signed by the old key cannot pass, so the durable id cannot be hijacked to an unrelated key."""
    from . import cose
    try:
        if signer_id(old_alg, old_pub) != r.old:
            raise RotationUnauthorized("old key does not derive the record's old id")
        if signer_id(new_alg, new_pub) != r.new:
            raise RotationUnauthorized("new key does not derive the record's new id")
    except UnknownAlg:
        raise RotationUnauthorized("rotation names an unregistered algorithm")
    m = r.bytes()
    if not cose.cose_verify1_raw(old_alg, old_pub, m, old_sig) or \
            not cose.cose_verify1_raw(new_alg, new_pub, m, new_sig):
        raise RotationUnauthorized("a rotation signature does not verify under its key")
    return None


# ---- revocation (design §5.3): distinct from rotation -----------------------------------------


class BadSignature(ValueError):
    kind = "BadSignature"


class RevocationRecord:
    """Marks a key dead from `not_after` (§5.3). Signed bytes: the deterministic-CBOR map
    {1: key, 2: not_after}."""

    __slots__ = ("key", "not_after")

    def __init__(self, key: str, not_after: int):
        self.key = key
        self.not_after = int(not_after)

    def bytes(self) -> bytes:
        from . import cbor
        from .cbor import U, T, M
        return cbor.encode(M([(U(1), T(self.key)), (U(2), U(self.not_after))]))


def verify_revocation(r: RevocationRecord, alg: int, pub: bytes, sig: bytes, recovery_ids) -> None:
    """Confirm a revocation is validly signed (§5.3): by the key it revokes, or by a
    deployer-configured recovery key. recovery_ids is the deployer's set of authorized recovery-key
    signer ids; a revocation whose signer is neither r.key nor a member of recovery_ids is rejected
    SignerMismatch (§5.5), fail-closed -- an empty recovery_ids admits only the revoked key itself.
    The signer id is recomputed from the presented key and checked BEFORE the signature (membership
    guard first, fail-closed)."""
    from . import cose
    id_ = signer_id(alg, pub)  # UnknownAlg propagates unchanged
    authorized = id_ == r.key
    for rid in (recovery_ids or ()):
        if rid == id_:
            authorized = True
            break
    if not authorized:
        raise SignerMismatch("signer is neither the revoked key nor an authorized recovery key")
    if not cose.cose_verify1_raw(alg, pub, r.bytes(), sig):
        raise BadSignature("revocation signature does not verify")


def revoked_at(r: RevocationRecord, pos_time: int) -> bool:
    """Reports whether an object fixed at authoritative position `pos_time` is after the
    revocation (KeyRevoked); objects fixed at or before not_after stay valid (§5.3)."""
    return pos_time > r.not_after


# ---- foreign-identity linkage (design §5.4) ----------------------------------------------------


class ForeignLinkRecord:
    """Cross-signs a foreign identity to a signer id (§5.4). Signed bytes: the deterministic-CBOR
    map {1: controls, 2: foreign_id, 3: not_after}. It is signed by the FOREIGN identity's key."""

    __slots__ = ("controls", "foreign_id", "not_after")

    def __init__(self, controls: str, foreign_id: str, not_after: int):
        self.controls = controls
        self.foreign_id = foreign_id
        self.not_after = int(not_after)

    def bytes(self) -> bytes:
        from . import cbor
        from .cbor import U, T, M
        return cbor.encode(M([(U(1), T(self.controls)), (U(2), T(self.foreign_id)),
                               (U(3), U(self.not_after))]))


def verify_foreign_link(r: ForeignLinkRecord, alg: int, foreign_pub: bytes, sig: bytes,
                        now: int) -> bool:
    """Reports whether a foreign-identity link confers linkage at time `now`. A non-NFC
    foreign_id is rejected (NonNFC). An expired link or a bad cross-signature confers NO linkage
    but is not itself an error -- it simply does not link (the object remains valid on its own
    signature, §5.4/§5.5). It NEVER overrides the key-derived id."""
    from . import cose
    require_nfc(r.foreign_id)
    if now > r.not_after:
        return False  # expired: confers no authority (ignored)
    if not cose.cose_verify1_raw(alg, foreign_pub, r.bytes(), sig):
        return False  # bad/absent cross-signature: no linkage
    return True


# ---- durable identity thread (rotation-surviving attribution, R-1.4) ---------------------------


class RotationEvidence:
    """One verified rotation step: the record plus the two keys and their co-signatures."""

    __slots__ = ("record", "old_alg", "new_alg", "old_pub", "new_pub", "old_sig", "new_sig")

    def __init__(self, record: RotationRecord, old_alg: int, new_alg: int,
                 old_pub: bytes, new_pub: bytes, old_sig: bytes, new_sig: bytes):
        self.record = record
        self.old_alg = old_alg
        self.new_alg = new_alg
        self.old_pub = old_pub
        self.new_pub = new_pub
        self.old_sig = old_sig
        self.new_sig = new_sig


class Thread:
    """A durable identity: a root signer id continued by a chain of rotations."""

    __slots__ = ("root", "current", "chain")

    def __init__(self, root: str, current: str, chain):
        self.root = root
        self.current = current
        self.chain = list(chain)

    def attributable(self, signer: str) -> bool:
        """Reports whether an object whose body signer id is `signer` belongs to this durable
        thread (any id in the chain, including a pre-rotation key, R-1.4)."""
        return signer in self.chain


def resolve_thread(evs) -> Thread:
    """Verify an ordered rotation chain and return the durable identity thread. Each rotation must
    be authorized (co-signed) and link the previous `new` to the next `old`; a break yields
    RotationUnauthorized. A receipt signed under any id in Chain is attributable to Root, so it
    stays attributable after rotation (R-1.4)."""
    evs = list(evs)
    if not evs:
        raise RotationUnauthorized("empty rotation chain")
    root = evs[0].record.old
    chain = [root]
    prev_new = root
    for e in evs:
        if e.record.old != prev_new:
            raise RotationUnauthorized("chain not contiguous")
        verify_rotation(e.record, e.old_alg, e.old_pub, e.new_alg, e.new_pub, e.old_sig, e.new_sig)
        chain.append(e.record.new)
        prev_new = e.record.new
    return Thread(root=root, current=prev_new, chain=chain)
