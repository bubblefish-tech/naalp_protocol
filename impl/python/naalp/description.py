# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C18 -- the signed description / directory primitive for the Python SDK (design.md §21; R-DESC-1..8).

C18 is a signed, OFFLINE-VERIFIABLE description and discovery layer carried on N-AALP's own signed
object. Its load-bearing property is that authority lives in the SIGNED BYTES, never in the connection
or the host that served them: the same signed Description re-verifies byte-identically when an
unrelated host serves it, because the signature (not a TLS-fetch origin) is the authority. It
introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3): each object is
an ordinary signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice (policy) and the
T1 content-id framing (§2.3) unchanged.

Three wire objects:

  - Description {1: service, 2: operations[]} lists a service's operations, each Operation
    {1: name, 2: effect, 3: requires_approval} carrying its C5 effect and an approval declaration.
    parse_description reconstructs the whole operation table from the bytes ALONE.
  - Directory {1: directory, 2: version, 3: members[]} is a signed collection whose members are
    content ids. Two conflicting versions from ONE signer -- same directory and version, different
    members -- are a FORK, detected at the FIRST-DIFFERING member POSITION (as the §8.5 audit
    fork-proof reports the position of an equivocation).
  - Import {1: importer, 2: format, 3: foreign, 4: operations[]} carries a foreign description format
    (an A2A Agent Card, an ANP Agent Description, an AGNTCY Agent Badge) octet-for-octet (carriage,
    not adoption) as a signed N-AALP attestation binding the foreign bytes' content id AND an N-AALP
    effect mapping. The IMPORTER (the wrapping signer, recomputed self-certifyingly from the verifying
    key) is the SOLE authorization identity; a foreign identity embedded in `foreign` never becomes an
    N-AALP authorization identity -- the confused-deputy rule, enforced normatively here (R-14.6).

Every check is fail-closed (§15). Ported from impl/go/description; the byte surface (bodies, heads,
content ids, foreign-id binding, fork position, closed foreign-format rejection) is graded against
vectors/description/cases.json; the offline-verification, fork-proof, and confused-deputy paths use
real deterministic ML-DSA-65 and are demonstrated in isolation (the corpus carries no signed vector).

Deviation from the Go reference, honest F4 note: Go's VerifyImport carries a ErrVerifierKeyMismatch
guard because it takes BOTH an (alg, pubkey) pair AND a separate cose.Verifier `v`, and must bind
them before deriving the authority id. The Python idiom (as gateway.verify_decision / delegation.
verify_grant_object) verifies with a single (alg, pubkey) pair, so the authority id is ALWAYS derived
from exactly the key that verified the signature -- the mismatch the Go guard prevents is structurally
impossible here, so there is no VerifierKeyMismatch surface to port. It is not silently dropped; it is
absent because the vulnerability it guards cannot arise in this signature.
"""
import hashlib

from . import cbor, cose, identity, policy
from .cbor import U, N, B, T, A, M

# The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
HEAD_SIZE = 48

# Foreign description format codes (design §21; the closed naalp-description-format registry).
FORMAT_A2A_CARD = 1          # A2A Agent Card
FORMAT_ANP_DESCRIPTION = 2   # ANP Agent Description
FORMAT_AGNTCY_BADGE = 3      # AGNTCY Agent Badge

_KNOWN_FORMATS = (FORMAT_A2A_CARD, FORMAT_ANP_DESCRIPTION, FORMAT_AGNTCY_BADGE)


class DescriptionError(ValueError):
    """A named, fail-closed C18 error; .kind is the stable error kind (mirroring the Go/Rust kinds
    DescMalformed, MalformedApprovalFlag, DirForkProofInvalid, ImporterMismatch,
    UnknownDescriptionFormat, plus the reused cose kinds BadSignature/UnknownAlg/ProfileDowngrade/
    KeyAlgMismatch)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def head(b):
    """SHA-384 over a body -- a 48-octet digest (the same construction as the C7 receipt head)."""
    return hashlib.sha384(bytes(b)).digest()


def content_id(b):
    """T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets)."""
    return cbor.content_id(bytes(b))


def _is_known_format(fmt):
    return fmt in _KNOWN_FORMATS


# ---- Operation: one listed operation with its effect + approval declaration (design §21.2) -----

class Operation:
    """One entry of a Description or Import mapping: a named operation, its C5 effect class, and
    whether it requires an approval. requires_approval is the uint 1 (yes) / 0 (no) -- no CBOR
    boolean (design §3.1)."""

    __slots__ = ("name", "effect", "requires_approval")

    def __init__(self, name, effect, requires_approval):
        self.name = name
        self.effect = int(effect)
        self.requires_approval = int(requires_approval)

    def to_map(self):
        return M([(U(1), T(self.name)), (U(2), U(self.effect)), (U(3), U(self.requires_approval))])

    def bytes(self):
        """Deterministic-CBOR encoding of the operation body {1:name,2:effect,3:requires_approval}."""
        return cbor.encode(self.to_map())

    def effect_class(self):
        """The per-operation effect, normalized fail-closed: an unrecognized value is destructive."""
        return policy.normalize_effect(self.effect)

    def requires_approval_flag(self):
        """True iff the operation declares that it requires an approval."""
        return self.requires_approval == 1


def operation_from_value(v):
    """Parse one operation map, rejecting a malformed shape (DescMalformed) or an approval flag
    outside {0,1} (MalformedApprovalFlag). Fail-closed."""
    if not isinstance(v, M):
        raise DescriptionError("DescMalformed", "operation is not a map")
    name = effect = req = None
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise DescriptionError("DescMalformed", "non-uint operation key")
        if k.v == 1 and isinstance(val, T):
            name = val.v
        elif k.v == 2 and isinstance(val, U):
            effect = val.v
        elif k.v == 3 and isinstance(val, U):
            req = val.v
    if name is None or effect is None or req is None:
        raise DescriptionError("DescMalformed", "operation missing a mandatory field")
    if req > 1:
        raise DescriptionError("MalformedApprovalFlag", "requires_approval is outside {0,1}")
    return Operation(name, effect, req)


def _operations_from_value(v):
    if not isinstance(v, A):
        raise DescriptionError("DescMalformed", "operations is not an array")
    return [operation_from_value(e) for e in v.items]


def _operations_value(ops):
    return A([op.to_map() for op in ops])


def _find_operation(ops, name):
    for op in ops:
        if op.name == name:
            return op, True
    return None, False


# ---- Description: a service's signed operation table (design §21.2) ----------------------------

class Description:
    """A signed N-AALP object listing a service's operations. Its authority is in the signed bytes:
    parse_description reconstructs the whole operation table (each operation's effect and approval
    declaration) from the bytes alone, so an unrelated host serving the same bytes yields a
    byte-identical verification (offline-verifiable, not fetch-authenticated)."""

    __slots__ = ("service", "operations")

    def __init__(self, service, operations):
        self.service = bytes(service)
        self.operations = list(operations)

    def bytes(self):
        """Deterministic-CBOR encoding {1: service, 2: operations[]}."""
        return cbor.encode(M([(U(1), B(self.service)), (U(2), _operations_value(self.operations))]))

    def head(self):
        return head(self.bytes())

    def id(self):
        return content_id(self.bytes())

    def operation(self, name):
        """The named operation and whether it is listed."""
        return _find_operation(self.operations, name)


def parse_description(b):
    """Reconstruct a Description from its body bytes ALONE -- the offline-verifiable property."""
    m = _decode_map(b)
    svc = _bstr_field(m, 1)
    ops_v = _field(m, 2)
    if svc is None or ops_v is None:
        raise DescriptionError("DescMalformed", "description missing service or operations")
    return Description(svc, _operations_from_value(ops_v))


def sign_description(d, alg, seed):
    """Produce the tagged COSE_Sign1 object over the Description body."""
    return cose.cose_sign1(alg, seed, _protected_header(alg), d.bytes())


def verify_description(obj, profile, alg, pubkey):
    """Verify the Description's full signature under the profile, then reconstruct the operation table
    from the signed body bytes. Because the authority is the signature over the bytes, this returns
    the identical Description regardless of which host served `obj` (R-DESC-1). Fail-closed."""
    payload = _verify_sign1(obj, profile, alg, pubkey)
    return parse_description(payload)


# ---- Directory: a signed collection of content ids, with fork detection (design §21.3) ----------

class Directory:
    """A signed collection object whose members are content ids. It carries a monotonic per-signer
    version so two versions can be compared for equivocation."""

    __slots__ = ("directory", "version", "members")

    def __init__(self, directory, version, members):
        self.directory = bytes(directory)
        self.version = int(version)
        self.members = [bytes(m) for m in members]

    def bytes(self):
        """Deterministic-CBOR encoding {1: directory, 2: version, 3: members[]}."""
        return cbor.encode(M([
            (U(1), B(self.directory)),
            (U(2), U(self.version)),
            (U(3), A([B(m) for m in self.members])),
        ]))

    def head(self):
        return head(self.bytes())

    def id(self):
        return content_id(self.bytes())


def parse_directory(b):
    """Reconstruct a Directory from its body bytes alone."""
    m = _decode_map(b)
    did = _bstr_field(m, 1)
    ver = _uint_field(m, 2)
    mem_v = _field(m, 3)
    if did is None or ver is None or mem_v is None or not isinstance(mem_v, A):
        raise DescriptionError("DescMalformed", "directory missing or malformed field")
    members = []
    for e in mem_v.items:
        if not isinstance(e, B):
            raise DescriptionError("DescMalformed", "member is not a bstr")
        members.append(e.v)
    return Directory(did, ver, members)


def sign_directory(d, alg, seed):
    """Produce the tagged COSE_Sign1 object over the Directory body."""
    return cose.cose_sign1(alg, seed, _protected_header(alg), d.bytes())


def verify_directory(obj, profile, alg, pubkey):
    """Verify the Directory's full signature under the profile, then reconstruct it from the signed
    body bytes. Fail-closed."""
    payload = _verify_sign1(obj, profile, alg, pubkey)
    return parse_directory(payload)


def first_member_difference(a, b):
    """The first index at which two member lists differ, and whether they differ at all. If the lists
    share a common prefix and one is longer, the difference is reported at the length of the shorter
    list. Identical lists return (0, False)."""
    n = min(len(a), len(b))
    for i in range(n):
        if bytes(a[i]) != bytes(b[i]):
            return i, True
    if len(a) != len(b):
        return n, True
    return 0, False


def detect_fork(a, b):
    """Compare two directory versions from ONE signer and report whether they equivocate -- the SAME
    directory id and version but DIFFERENT members -- and, if so, the FIRST-DIFFERING member POSITION.
    A different directory id or version is a legitimate distinct object/succession, not a fork;
    identical members are a benign duplicate. In both non-fork cases returns (0, False). The caller
    establishes the 'one signer' precondition by verifying both objects under the same key."""
    if a.directory != b.directory or a.version != b.version:
        return 0, False
    return first_member_difference(a.members, b.members)


class DirectoryForkProof:
    """Non-repudiable evidence of a directory fork: two validly-signed Directory objects by ONE signer
    at the SAME (directory, version) listing DIFFERENT members, carried as the accused signer's OWN
    two signed objects. Because a single verifier checks BOTH signed objects, the proof is
    self-contained."""

    __slots__ = ("signer", "signed_a", "signed_b")

    def __init__(self, signer, signed_a, signed_b):
        self.signer = bytes(signer)
        self.signed_a = bytes(signed_a)
        self.signed_b = bytes(signed_b)

    def verify(self, profile, alg, pubkey):
        """Check that this is a genuine directory fork by the signer whose key is (alg, pubkey), and
        return the FIRST-DIFFERING member POSITION. Accepts iff ALL hold: (1) the signer id is
        present; (2) BOTH signed objects verify under the key (which, because a single verifier checks
        both, proves one signer); (3) the two directories share one directory id and version; and (4)
        their member lists differ. Any failure rejects the whole proof (fail-closed): an unnamed
        signer, a different directory/version, or identical members is DirForkProofInvalid; a signature
        that does not verify propagates BadSignature."""
        if len(self.signer) == 0:
            raise DescriptionError("DirForkProofInvalid", "an unnamed accused is not evidence")
        a = verify_directory(self.signed_a, profile, alg, pubkey)
        b = verify_directory(self.signed_b, profile, alg, pubkey)
        pos, fork = detect_fork(a, b)
        if not fork:
            raise DescriptionError("DirForkProofInvalid",
                                   "same directory+version identical members, or not the same versioned directory")
        return pos


# ---- Import: foreign description carried as a signed attestation (design §21.4) -----------------

class Import:
    """Carries a foreign description format octet-for-octet (carriage, not adoption) as a signed
    N-AALP attestation. `importer` is the wrapping signer id (the sole authorization identity);
    `foreign` is the foreign bytes verbatim; `operations` is the N-AALP effect mapping the importer
    attests. The foreign bytes' content id is bound by foreign_id."""

    __slots__ = ("importer", "format", "foreign", "operations")

    def __init__(self, importer, format, foreign, operations):
        self.importer = bytes(importer)
        self.format = int(format)
        self.foreign = bytes(foreign)
        self.operations = list(operations)

    def bytes(self):
        """Deterministic-CBOR encoding {1: importer, 2: format, 3: foreign, 4: operations[]}."""
        return cbor.encode(M([
            (U(1), B(self.importer)),
            (U(2), U(self.format)),
            (U(3), B(self.foreign)),
            (U(4), _operations_value(self.operations)),
        ]))

    def head(self):
        return head(self.bytes())

    def id(self):
        return content_id(self.bytes())

    def foreign_id(self):
        """The T1 content id of the carried foreign bytes -- the hash the attestation binds. A changed
        foreign document yields a different foreign_id, so an attestation binds the exact bytes."""
        return content_id(self.foreign)

    def operation(self, name):
        return _find_operation(self.operations, name)


def parse_import(b):
    """Reconstruct an Import from its body bytes alone. A format code outside the closed
    naalp-description-format set {1,2,3} is rejected on decode (UnknownDescriptionFormat), never
    carried as an unknown format. Fail-closed."""
    m = _decode_map(b)
    imp = _bstr_field(m, 1)
    fmt = _uint_field(m, 2)
    foreign = _bstr_field(m, 3)
    ops_v = _field(m, 4)
    if imp is None or fmt is None or foreign is None or ops_v is None:
        raise DescriptionError("DescMalformed", "import missing a mandatory field")
    if not _is_known_format(fmt):
        raise DescriptionError("UnknownDescriptionFormat",
                               "import format %d is outside the closed set {1,2,3}" % fmt)
    return Import(imp, fmt, foreign, _operations_from_value(ops_v))


def sign_import(im, alg, seed):
    """Produce the tagged COSE_Sign1 object over the Import body."""
    return cose.cose_sign1(alg, seed, _protected_header(alg), im.bytes())


class ResolvedImport:
    """An Import that has passed signature verification and the confused-deputy check. authority_id is
    the self-certifying signer id RECOMPUTED from the verifying key -- the wrapping signer, and the
    only authorization identity. It is never any identity parsed from the foreign bytes."""

    __slots__ = ("authority_id", "format", "foreign_id", "operations")

    def __init__(self, authority_id, format, foreign_id, operations):
        self.authority_id = authority_id
        self.format = format
        self.foreign_id = bytes(foreign_id)
        self.operations = list(operations)


def verify_import(obj, profile, alg, pubkey):
    """Verify a foreign-description import end-to-end and enforce the confused-deputy rule normatively.
    It (1) verifies the signed object under the profile with real crypto; (2) recomputes the wrapping
    signer's SELF-CERTIFYING id from the verifying key (identity.signer_id); and (3) requires the
    attestation's `importer` field to equal that recomputed id (ImporterMismatch otherwise). The
    returned authority_id is that recomputed key id -- the wrapping signer -- so no field inside the
    carried foreign bytes, including any foreign identity claim, can ever become the N-AALP
    authorization identity (R-14.6). Any failure returns its named error and authorizes nothing."""
    payload = _verify_sign1(obj, profile, alg, pubkey)
    im = parse_import(payload)
    key_id = identity.signer_id(alg, pubkey)
    # The authorization identity is the wrapping key's own id. The attestation's declared importer MUST
    # match it: a signer can only ever import AS ITSELF, never as a foreign identity it names.
    if im.importer.decode("utf-8", "replace") != key_id:
        raise DescriptionError("ImporterMismatch",
                               "the attested importer is not the verifying key's signer id")
    return ResolvedImport(key_id, im.format, im.foreign_id(), im.operations)


# ---- signing / verification helpers (COSE_Sign1 with the bare {1: alg} header) ------------------

def _protected_header(alg):
    """The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits (matching
    gateway.gateway_protected_header)."""
    return cbor.encode(M([(U(1), N(alg))]))


def _verify_sign1(obj, profile, alg, pubkey):
    """Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the
    payload. Mirrors gateway.verify_decision's checks: alg registry, profile floor, key-alg match,
    signature. Fail-closed with a named DescriptionError."""
    prot, payload, sig = cose.parse_sign1_raw(obj)
    halg = _alg_from_protected(prot)
    level, known = cose.alg_level(halg)
    if not known:
        raise DescriptionError("UnknownAlg", "unregistered alg %d" % halg)
    if level < cose.profile_min_level(profile):
        raise DescriptionError("ProfileDowngrade", "signature level below the profile minimum")
    if halg != alg:
        raise DescriptionError("KeyAlgMismatch", "alg %d does not match the verifier key alg %d" % (halg, alg))
    tbs = cose.to_be_signed_raw(prot, payload)
    if not cose.cose_verify1_raw(halg, pubkey, tbs, sig):
        raise DescriptionError("BadSignature", "signature does not verify")
    return payload


def _alg_from_protected(prot):
    v = cbor.decode(prot)
    if isinstance(v, M):
        for k, val in v.pairs:
            if isinstance(k, U) and k.v == 1 and isinstance(val, (N, U)):
                return val.v
    raise DescriptionError("DescMalformed", "protected header has no alg")


# ---- small deterministic-CBOR field accessors -------------------------------------------------

def _decode_map(b):
    try:
        v = cbor.decode(bytes(b))
    except cbor.NonCanonical:
        raise DescriptionError("DescMalformed", "body is not well-formed deterministic CBOR")
    if not isinstance(v, M):
        raise DescriptionError("DescMalformed", "body is not a map")
    return v


def _field(m, k):
    for key, val in m.pairs:
        if isinstance(key, U) and key.v == k:
            return val
    return None


def _bstr_field(m, k):
    v = _field(m, k)
    return v.v if isinstance(v, B) else None


def _uint_field(m, k):
    v = _field(m, k)
    return v.v if isinstance(v, U) else None
