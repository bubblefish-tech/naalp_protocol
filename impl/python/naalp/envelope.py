# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP C3 object envelope for the Python SDK — the full signed object and its offline verify.

This is the ergonomic surface a developer uses: build an Object (its channel/kind/effect/body
and the rest), sign it with a signer, and get a single self-describing, offline-verifiable
byte string; verify one from the object + key + spec alone. The bytes are byte-identical to the
Go and Rust reference implementations (the worked example in vectors/worked/example.json is the
byte-level known-answer for this module).
"""
from . import cbor, cose
from .cbor import U, N, B, T, A, M, Tag

# object body field numbers (§2.1)
FIELD_ID = 1
FIELD_KIND = 2
FIELD_CHANNEL = 3
FIELD_TIER = 4
FIELD_SIGNER = 5
FIELD_CREATED = 6
FIELD_EFFECT = 7
FIELD_CAUSES = 8
FIELD_PROFILE = 9
FIELD_BODY = 10
FIELD_EXT = 11
FIELD_CEXT = 12

NAALP_VERSION = 1
_HEADER_LABEL = "naalp"


class EnvelopeError(ValueError):
    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg))
        self.kind = kind


class Object:
    """A decoded N-AALP object body. `id` is set by sign() (content id §2.3)."""

    def __init__(self, kind, channel, signer, created, effect, body,
                 tier=0, profile=cose.PROFILE_PUBLIC, causes=None, ext=None, cext=None):
        self.id = None
        self.kind = kind
        self.channel = channel
        self.tier = tier
        self.signer = bytes(signer)
        self.created = created
        self.effect = effect
        self.causes = list(causes or [])
        self.profile = profile
        self.body = body           # a cbor Value (e.g. cbor.M([...]))
        self.ext = ext             # cbor.M or None (field 11, non-critical)
        self.cext = cext           # cbor.M or None (field 12, critical)

    def _body_map(self, include_id):
        pairs = []
        if include_id:
            pairs.append((U(FIELD_ID), B(self.id)))
        pairs += [
            (U(FIELD_KIND), U(self.kind)),
            (U(FIELD_CHANNEL), U(self.channel)),
            (U(FIELD_TIER), U(self.tier)),
            (U(FIELD_SIGNER), B(self.signer)),
            (U(FIELD_CREATED), U(self.created)),
            (U(FIELD_EFFECT), U(self.effect)),
            (U(FIELD_CAUSES), A([B(c) for c in self.causes])),
            (U(FIELD_PROFILE), U(self.profile)),
            (U(FIELD_BODY), self.body),
        ]
        if self.ext is not None:
            pairs.append((U(FIELD_EXT), self.ext))
        if self.cext is not None:
            pairs.append((U(FIELD_CEXT), self.cext))
        return M(pairs)

    def content_id(self):
        """The object content id over the body without field 1 (§2.3)."""
        return cbor.content_id(self._body_map(False))


def _protected_header(alg, signer, profile):
    naalp = M([(U(1), B(signer)), (U(2), U(profile)), (U(3), U(NAALP_VERSION))])
    return cbor.encode(M([(U(1), N(alg)), (T(_HEADER_LABEL), naalp)]))


def sign(obj: Object, alg: int, seed: bytes) -> bytes:
    """Assemble, content-id-bind, and deterministically sign a full N-AALP object with an
    ML-DSA key derived from `seed`. Returns the tagged COSE_Sign1 object bytes."""
    obj.id = obj.content_id()
    payload = cbor.encode(obj._body_map(True))
    prot = _protected_header(alg, obj.signer, obj.profile)
    tbs = cose.to_be_signed_raw(prot, payload)
    sig = cose.mldsa_sign(alg, seed, tbs)
    return cose.assemble_sign1_raw(prot, payload, sig)


def _parse_protected(prot):
    v = cbor.decode(prot)
    if not isinstance(v, M):
        raise EnvelopeError("Malformed", "protected header not a map")
    alg = signer = profile = version = None
    for k, val in v.pairs:
        if isinstance(k, N) and k.v < 0:  # {1: nint alg}
            pass
        if isinstance(k, U) and k.v == 1 and isinstance(val, N):
            alg = val.v
        elif isinstance(k, T) and k.v == _HEADER_LABEL and isinstance(val, M):
            for kk, vv in val.pairs:
                if isinstance(kk, U) and kk.v == 1 and isinstance(vv, B):
                    signer = vv.v
                elif isinstance(kk, U) and kk.v == 2 and isinstance(vv, U):
                    profile = vv.v
                elif isinstance(kk, U) and kk.v == 3 and isinstance(vv, U):
                    version = vv.v
    if alg is None or signer is None or profile is None or version is None:
        raise EnvelopeError("Malformed", "protected header missing routing fields")
    return alg, signer, profile, version


def _object_from_map(m):
    fields = {}
    for k, v in m.pairs:
        if not isinstance(k, U):
            raise EnvelopeError("Malformed", "non-uint body key")
        fields[k.v] = v

    def need(fnum, typ):
        v = fields.get(fnum)
        if not isinstance(v, typ):
            raise EnvelopeError("Malformed", "field %d wrong type/absent" % fnum)
        return v

    signer = need(FIELD_SIGNER, B).v
    causes_v = need(FIELD_CAUSES, A)
    causes = []
    for c in causes_v.items:
        if not isinstance(c, B):
            raise EnvelopeError("Malformed", "cause not a bstr")
        causes.append(c.v)
    ext = fields.get(FIELD_EXT)
    cext = fields.get(FIELD_CEXT)
    if ext is not None and not isinstance(ext, M):
        raise EnvelopeError("Malformed", "ext not a map")
    if cext is not None and not isinstance(cext, M):
        raise EnvelopeError("Malformed", "cext not a map")
    o = Object(
        kind=need(FIELD_KIND, U).v, channel=need(FIELD_CHANNEL, U).v, signer=signer,
        created=need(FIELD_CREATED, U).v, effect=need(FIELD_EFFECT, U).v,
        body=need(FIELD_BODY, (U, N, B, T, A, M, Tag)), tier=need(FIELD_TIER, U).v,
        profile=need(FIELD_PROFILE, U).v, causes=causes, ext=ext, cext=cext,
    )
    o.id = fields.get(FIELD_ID).v if isinstance(fields.get(FIELD_ID), B) else None
    return o


def verify(profile, alg, pubkey, kind_validator, obj_bytes, known_cext=None):
    """Verify a signed N-AALP object end-to-end, offline (R-2.4). Returns the Object on
    success; raises EnvelopeError (or a cose/cbor error) with a stable .kind on the first
    named failure. Check order (fail-closed): decode -> content-id -> field ranges ->
    header/body copies + version -> critical extensions -> kind dispatch -> profile floor ->
    signature."""
    known_cext = known_cext or {}
    prot, payload, sig = cose.parse_sign1_raw(obj_bytes)
    bv = cbor.decode(payload)  # raises NonCanonical on a non-canonical body
    if not isinstance(bv, M):
        raise EnvelopeError("Malformed", "body not a map")

    # content-id: recompute over the body without field 1, compare to the claimed id
    claimed = None
    without = []
    for k, v in bv.pairs:
        if isinstance(k, U) and k.v == FIELD_ID:
            if not isinstance(v, B):
                raise EnvelopeError("Malformed", "id not a bstr")
            claimed = v.v
            continue
        without.append((k, v))
    if claimed is None:
        raise EnvelopeError("Malformed", "no content id")
    if cbor.content_id(M(without)) != claimed:
        raise EnvelopeError("ContentIdMismatch", "recomputed id differs")

    o = _object_from_map(bv)

    # field ranges (§3.3): channel 0..19, effect 0..3, profile 1..3
    if o.channel > 19 or o.effect > 3 or o.profile < 1 or o.profile > 3:
        raise EnvelopeError("RangeError", "field out of range")

    halg, hsigner, hprofile, hversion = _parse_protected(prot)
    if hversion != NAALP_VERSION:
        raise EnvelopeError("UnsupportedVersion", "bad naalp-version")
    if hsigner != o.signer or hprofile != o.profile:
        raise EnvelopeError("HeaderBodyMismatch", "protected header disagrees with body")

    if o.cext is not None:
        for k, _v in o.cext.pairs:
            if not (isinstance(k, U) and k.v in known_cext):
                raise EnvelopeError("UnknownCriticalExt", "unrecognized critical extension")

    if kind_validator is None or not kind_validator(o.channel, o.kind):
        raise EnvelopeError("UnknownKind", "kind/channel not a registered surface")

    level, known = cose.alg_level(halg)
    if not known:
        raise EnvelopeError("UnknownAlg", "unregistered alg")
    if level < cose.profile_min_level(profile):
        raise EnvelopeError("ProfileDowngrade", "signature level below the profile minimum")
    tbs = cose.to_be_signed_raw(prot, payload)
    if not cose.cose_verify1_raw(halg, pubkey, tbs, sig):
        raise EnvelopeError("BadSignature", "signature does not verify")
    return o
