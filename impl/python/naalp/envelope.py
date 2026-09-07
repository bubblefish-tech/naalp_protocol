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

# The object body field numbers, the protected-header NAALP_VERSION, and _HEADER_LABEL are
# GENERATED from spec/wire-constants.csv into _wire_constants_gen.py so the ten ports cannot
# drift on the wire. Change the CSV and run scripts/gen_wire_constants.py; never edit here.
from ._wire_constants_gen import (  # noqa: F401,E402  (re-exported as part of this module's surface)
    FIELD_ID, FIELD_KIND, FIELD_CHANNEL, FIELD_TIER, FIELD_SIGNER, FIELD_CREATED,
    FIELD_EFFECT, FIELD_CAUSES, FIELD_PROFILE, FIELD_BODY, FIELD_EXT, FIELD_CEXT,
    FIELD_AUDIENCE, FIELD_SUITE, NAALP_VERSION, _HEADER_LABEL,
    MAX_OBJECT_SIZE, MAX_CAUSES, MAX_EXT, MAX_CEXT, MAX_NESTING_DEPTH,
)

# The signed suite id carried in field 14 for the opt-in ML-DSA-65 + Ed25519 composite
# signature (§4.2); a small-uint provisional assignment. Field 14 is present iff the object is
# signed by a composite alg, so a pure object encodes byte-identically to a draft-00 object.
SUITE_MLDSA65_ED25519 = 1


def _composite_suite_for_alg(alg: int):
    """(suite id, True) for a composite alg; (0, False) for any non-composite alg -- so field 14
    is absent for a pure object."""
    if alg == cose.ALG_COMPOSITE_65_ED25519:
        return SUITE_MLDSA65_ED25519, True
    return 0, False


# --- T1.3 recheck (the checkable-minimum field, NAALP-REQ-110/111, design.md §2.5) -----------
#
# RECHECK_KEY is the ext/cext extension key under which an object NAMES the re-check procedure
# for the claim in its body. The value is a procedure id into the CLOSED registry below. In the
# non-critical ext map (field 11) it is may-ignore; in the critical cext map (field 12) it is
# must-understand and an unknown procedure id is rejected fail-closed (UnknownCriticalExt), the
# same C3 critical-extension rule reaching the procedure it names. 13 does not collide with the
# safety-label ext key 1 (§6.4). Byte-identical to impl/go and impl/rust.
RECHECK_KEY = 13

# The closed re-check procedure registry (design.md §2.5; T1.3); mirrors the spec
# recheck-procedure production and vectors/registry/recheck.csv.
RECHECK_RECOMPUTE_CONTENT_ID = 1  # recompute the content id from the body and compare (§2.3)
RECHECK_VERIFY_COSE_SIGN1 = 2     # verify the COSE_Sign1 signature under the signer key (§4)
RECHECK_WALK_CAUSES = 3           # walk the signed causal partial order offline (§8.2)
RECHECK_REPLAY_CONSUME_CHECK = 4  # replay the single-use consume ledger for the approval (§7.2)


def is_known_recheck_procedure(id_):
    """Report whether id_ is a recognized re-check procedure. The registry is CLOSED: an id
    outside it is unknown, and an unknown id under the critical map is rejected (§2.5)."""
    return RECHECK_RECOMPUTE_CONTENT_ID <= id_ <= RECHECK_REPLAY_CONSUME_CHECK


# --- T1.6 per-signer forward-only counter (the OPTIONAL detection field, NAALP-REQ-120) -------
#
# SIGNER_COUNTER_KEY is the ext extension key under which an object OPTIONALLY carries a
# forward-only per-signer counter (design.md §2.5.2). The value is a forward-only position (a
# uint) the signer increments on each object. It lives in the NON-CRITICAL ext map (field 11): a
# verifier that does not perform duplication-detection ignores it and the object still verifies
# (may-ignore). Because ext (field 11) is part of the signed body/payload, the counter is
# covered by the SIGNER's own COSE_Sign1 signature -- the deliberate contrast with the T1.5
# consume-receipt position, which is signed by the LEDGER key. 14 does not collide with the
# safety-label ext key 1 (§6.4) or the recheck ext/cext key 13 (T1.3). Byte-identical to impl/go
# and impl/rust.
#
# The counter is DETECTION, not prevention (NAALP-REQ-120; Security Considerations): a single
# self-authored sequence proves nothing. It is a NON-CRITICAL field only -- placing it in the
# critical cext map (field 12) is an unrecognized critical extension and is rejected fail-closed
# (UnknownCriticalExt, the existing §2.5 rule), because a detection aid is never a
# must-understand verification gate.
SIGNER_COUNTER_KEY = 14


def _cext_get_uint(m, key):
    """Return (value, True) for the uint value under key in a CBOR map (ext or cext), reporting
    present only when the key exists AND its value is a uint. m may be None (absent carrier)."""
    if m is None:
        return 0, False
    for k, v in m.pairs:
        if isinstance(k, U) and k.v == key:
            if isinstance(v, U):
                return v.v, True
            return 0, False
    return 0, False


class EnvelopeError(ValueError):
    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg))
        self.kind = kind


class Object:
    """A decoded N-AALP object body. `id` is set by sign() (content id §2.3)."""

    def __init__(self, kind, channel, signer, created, effect, body,
                 tier=0, profile=cose.PROFILE_PUBLIC, causes=None, ext=None, cext=None,
                 audience="", suite=0):
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
        # field 13 (§2.5.3): the single-use consume binding. Omit-when-empty -- a no-audience
        # object encodes byte-identically to a draft-00 object (additivity). Anchors version 2.
        self.audience = audience
        # field 14 (§4.2): the signed suite declaration, present (value 1) iff a composite alg
        # signs this object; 0 = absent, so a pure object stays byte-identical to draft-00.
        self.suite = suite

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
        if self.audience:
            pairs.append((U(FIELD_AUDIENCE), T(self.audience)))
        if self.suite:
            pairs.append((U(FIELD_SUITE), U(self.suite)))
        return M(pairs)

    def content_id(self):
        """The object content id over the body without field 1 (§2.3)."""
        return cbor.content_id(self._body_map(False))

    def recheck(self):
        """Return (id, present, critical): the re-check procedure named in RECHECK_KEY (§2.5).
        present is True iff a procedure is named; critical is True iff it is named in the cext
        map (field 12, must-understand) rather than the ext map (field 11, may-ignore). cext
        takes precedence when both carry the key. When no procedure is named the claim is
        attributable-only (NAALP-REQ-111)."""
        v, ok = _cext_get_uint(self.cext, RECHECK_KEY)
        if ok:
            return v, True, True
        v, ok = _cext_get_uint(self.ext, RECHECK_KEY)
        if ok:
            return v, True, False
        return 0, False, False

    def set_recheck(self, proc_id, critical):
        """Name proc_id as the body claim's re-check procedure. critical places it in the cext
        map (field 12, must-understand); otherwise the ext map (field 11, may-ignore). Creates
        the carrier if absent, replaces an existing RECHECK_KEY entry in place, and leaves any
        other extension entries intact."""
        entry = (U(RECHECK_KEY), U(proc_id))
        attr = "cext" if critical else "ext"
        current = getattr(self, attr)
        if current is None:
            setattr(self, attr, M([entry]))
            return
        new_pairs = []
        replaced = False
        for k, v in current.pairs:
            if isinstance(k, U) and k.v == RECHECK_KEY:
                new_pairs.append(entry)
                replaced = True
            else:
                new_pairs.append((k, v))
        if not replaced:
            new_pairs.append(entry)
        setattr(self, attr, M(new_pairs))

    def signer_counter(self):
        """Return (seq, present): the forward-only per-signer position named in SIGNER_COUNTER_KEY
        (§2.5.2), read from the non-critical ext map (field 11) only. The field is OPTIONAL --
        absent (present == False) is valid. present is keyed on the KEY being present, not on the
        value: a present counter of value 0 returns (0, True)."""
        return _cext_get_uint(self.ext, SIGNER_COUNTER_KEY)

    def set_signer_counter(self, seq):
        """Name seq as this object's forward-only per-signer position in the NON-CRITICAL ext map
        (field 11), covered by the signer's COSE_Sign1 signature. Creates the ext carrier if
        absent, replaces an existing SIGNER_COUNTER_KEY entry in place, and leaves any other
        extension entries intact. The counter is deliberately never placed in the critical cext
        map (it is detection, not a verification gate)."""
        entry = (U(SIGNER_COUNTER_KEY), U(seq))
        if self.ext is None:
            self.ext = M([entry])
            return
        new_pairs = []
        replaced = False
        for k, v in self.ext.pairs:
            if isinstance(k, U) and k.v == SIGNER_COUNTER_KEY:
                new_pairs.append(entry)
                replaced = True
            else:
                new_pairs.append((k, v))
        if not replaced:
            new_pairs.append(entry)
        self.ext = M(new_pairs)


class DuplicationFinding:
    """Surfaces one detected per-signer counter conflict: two or more DISTINCT objects (distinct
    content ids) from the SAME signer id that carry the SAME forward-only counter value (§2.5.2,
    NAALP-REQ-120). A forward-only counter binds each value to at most one object, so a value
    bound to >= 2 distinct objects is the observable fingerprint of the key incrementing in two
    places (key duplication). The finding surfaces BOTH sides of the contradiction: the reused
    counter value and every conflicting content id (ids, ascending by bytes) -- never a single
    flag with the evidence hidden."""

    def __init__(self, signer, counter, ids):
        self.signer = bytes(signer)      # the signer id whose forward-only counter was reused
        self.counter = counter           # the reused forward-only counter value
        self.ids = list(ids)             # content ids of the >= 2 conflicting objects, ascending

    def __eq__(self, other):
        return (isinstance(other, DuplicationFinding) and self.signer == other.signer
                and self.counter == other.counter and self.ids == other.ids)

    def __repr__(self):
        return "DuplicationFinding(signer=%r, counter=%r, ids=%r)" % (
            self.signer, self.counter, self.ids)


def detect_signer_duplication(objs):
    """Scan a SET of PRESENTED objects for per-signer counter reuse. This is the whole point of
    the field, and it is DETECTION, not prevention (NAALP-REQ-120): it flags a signer id ONLY
    when two conflicting sequences from that signer physically MEET in the presented set -- a
    counter value bound to >= 2 distinct content ids by one signer. Given only ONE object per
    value (one sequence) it returns no findings; the second conflicting object must be present,
    unsuppressed, for the duplication to become provable. Objects with no counter do not
    participate. Output is deterministic (findings ordered by signer id then counter; ids within
    a finding ascending).

    It operates over the SET, never per object: a per-object boolean could never express "these
    two distinct objects reuse one position," and a single self-authored counter proves nothing
    on its own."""
    # signer bytes -> counter -> {content-id bytes: True}, a set that de-dups a byte-identical
    # re-presentation (one content id twice) so it is NOT a conflict.
    groups = {}
    for o in objs:
        seq, present = o.signer_counter()
        if not present:
            continue  # a counter-less object does not participate in detection
        try:
            cid = o.content_id()
        except (cbor.NonCanonical, TypeError):
            continue  # a body that cannot be canonically encoded cannot be a presented object
        by_counter = groups.setdefault(o.signer, {})
        idset = by_counter.setdefault(seq, {})
        idset[cid] = True

    findings = []
    for signer in sorted(groups.keys()):
        by_counter = groups[signer]
        for counter in sorted(by_counter.keys()):
            idset = by_counter[counter]
            # A (signer, counter) that binds two-or-more DISTINCT content ids is a detected
            # duplication. The >= 2 requirement is the detection-requires-both invariant: relax
            # it to >= 1 and a single sequence would flag (prevention theatre) -- the mutation
            # the "one sequence alone -> not flagged" test is built to catch.
            if len(idset) < 2:
                continue
            findings.append(DuplicationFinding(signer, counter, sorted(idset.keys())))
    return findings


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


def sign_composite(obj: Object, mldsa_seed: bytes, ed_seed: bytes) -> bytes:
    """Assemble, content-id-bind, and sign a full N-AALP object with the opt-in LAMPS composite
    signature (alg -65537, §4.2). Sets the signed suite field (14) present (value 1) BEFORE the
    content id so the id covers it; the composite value is deterministic in both legs (ML-DSA-65
    with ctx=Label, Ed25519 with no ctx). Returns the tagged COSE_Sign1 object bytes."""
    obj.suite = SUITE_MLDSA65_ED25519
    obj.id = obj.content_id()
    payload = cbor.encode(obj._body_map(True))
    prot = _protected_header(cose.ALG_COMPOSITE_65_ED25519, obj.signer, obj.profile)
    tbs = cose.to_be_signed_raw(prot, payload)
    sig = cose.composite_sign(mldsa_seed, ed_seed, tbs)
    return cose.assemble_sign1_raw(prot, payload, sig)


def _parse_protected(prot):
    # §3.1.1 (R5): the empty protected header is pinned to 0x40; a byte string wrapping an
    # empty CBOR map (the 0x41A0 form -- its unwrapped content is the single byte 0xA0) is the
    # one redundant encoding RFC 9052 §3 otherwise permits, and MUST be rejected as
    # NonCanonical before the header is interpreted (otherwise it dies downstream as a generic
    # Malformed / no-alg, losing the determinism verdict).
    if len(prot) == 1 and prot[0] == 0xA0:
        raise cbor.NonCanonical("empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)")
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
    if len(causes_v.items) > MAX_CAUSES:  # causal fan-in bound (§3.4, R7)
        raise EnvelopeError("TooManyCauses", "causes[] exceeds the maximum count (§3.4, R7)")
    causes = []
    for c in causes_v.items:
        if not isinstance(c, B):
            raise EnvelopeError("Malformed", "cause not a bstr")
        causes.append(c.v)
    ext = fields.get(FIELD_EXT)
    cext = fields.get(FIELD_CEXT)
    if ext is not None and not isinstance(ext, M):
        raise EnvelopeError("Malformed", "ext not a map")
    if ext is not None and len(ext.pairs) > MAX_EXT:  # ext cardinality bound (§3.4, R7)
        raise EnvelopeError("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)")
    if cext is not None and not isinstance(cext, M):
        raise EnvelopeError("Malformed", "cext not a map")
    if cext is not None and len(cext.pairs) > MAX_CEXT:  # cext cardinality bound (§3.4, R7)
        raise EnvelopeError("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)")
    aud = fields.get(FIELD_AUDIENCE)
    if aud is not None and not isinstance(aud, T):
        raise EnvelopeError("Malformed", "audience not a tstr")
    suite_v = fields.get(FIELD_SUITE)
    if suite_v is not None and not isinstance(suite_v, U):
        raise EnvelopeError("Malformed", "suite not a uint")
    o = Object(
        kind=need(FIELD_KIND, U).v, channel=need(FIELD_CHANNEL, U).v, signer=signer,
        created=need(FIELD_CREATED, U).v, effect=need(FIELD_EFFECT, U).v,
        body=need(FIELD_BODY, (U, N, B, T, A, M, Tag)), tier=need(FIELD_TIER, U).v,
        profile=need(FIELD_PROFILE, U).v, causes=causes, ext=ext, cext=cext,
        audience=(aud.v if aud is not None else ""),
        suite=(suite_v.v if suite_v is not None else 0),
    )
    o.id = fields.get(FIELD_ID).v if isinstance(fields.get(FIELD_ID), B) else None
    return o


def check_audience(o, self_authority, consume_once):
    """The single-use consume binding gate (§2.5.3), checked at the point of use -- before the
    consume logic (the CAS append) -- NEVER inside verify(). An in-transit relay, ordering
    authority, or auditor legitimately verifies objects addressed to some OTHER authority; only
    the authority about to CONSUME an object enforces that the object is addressed to it.

    Three branches: (a) absent audience on a consume-once object -> WrongAudience; (b) an audience
    present but not this authority -> WrongAudience; (c) a non-consume-once object with no audience
    -> pass. Raises EnvelopeError('WrongAudience') on rejection; returns None on pass."""
    if not o.audience:
        if consume_once:
            raise EnvelopeError("WrongAudience", "consume-once object has no audience")
        return None
    if o.audience != self_authority:
        raise EnvelopeError("WrongAudience", "object audience is not this consuming authority")
    return None


def verify(profile, alg, pubkey, kind_validator, obj_bytes, known_cext=None):
    """Verify a signed N-AALP object end-to-end, offline (R-2.4). Returns the Object on
    success; raises EnvelopeError (or a cose/cbor error) with a stable .kind on the first
    named failure. Check order (fail-closed): decode -> content-id -> field ranges ->
    header/body copies + version -> critical extensions -> kind dispatch -> profile floor ->
    signature."""
    # Object octet-size bound (§3.4, R7): reject an oversized signed object on the raw bytes,
    # before any parse (RFC 8949 §10 decoder-memory guard).
    if len(obj_bytes) > MAX_OBJECT_SIZE:
        raise EnvelopeError("TooLarge", "object exceeds the maximum octet size (§3.4, R7)")
    known_cext = known_cext or {}
    prot, payload, sig = cose.parse_sign1_raw(obj_bytes)
    # non-canonical -> NonCanonical (§2.6); over-nested -> DepthExceeded (§3.4, R7)
    bv = cbor.decode_bounded(payload, MAX_NESTING_DEPTH)
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

    # A (channel 3, kind 0) Rotation object MUST be a tag-98 COSE_Sign co-signed by the old AND
    # new key (§5.2); a single-signature (tag-18) rotation is missing the old-key co-signature and
    # is rejected RotationUnauthorized (the single-Sign1 rotation-gap fix).
    if _is_rotation_object(o.channel, o.kind):
        raise EnvelopeError("RotationUnauthorized", "single-signature rotation missing the old-key co-signature")

    # field ranges (§3.3): channel 0..19, effect 0..3, profile 1..3
    if o.channel > 19 or o.effect > 3 or o.profile < 1 or o.profile > 3:
        raise EnvelopeError("RangeError", "field out of range")

    halg, hsigner, hprofile, hversion = _parse_protected(prot)
    if hversion != NAALP_VERSION:
        raise EnvelopeError("UnsupportedVersion", "bad naalp-version")
    if hsigner != o.signer or hprofile != o.profile:
        raise EnvelopeError("HeaderBodyMismatch", "protected header disagrees with body")

    # critical extensions: any unrecognized key rejects (§2.5, R-2.5). RECHECK_KEY (13) is an
    # envelope-recognized critical key: a critical recheck naming an UNKNOWN procedure id is
    # rejected fail-closed (the critical-extension rule reaching the procedure it names, T1.3);
    # a known procedure id is recognized. A NON-critical recheck (ext, field 11) is never
    # rejected here -- an unknown non-critical procedure is ignored per the may-ignore rule.
    if o.cext is not None:
        for k, v in o.cext.pairs:
            if not isinstance(k, U):
                raise EnvelopeError("UnknownCriticalExt", "unrecognized critical extension")
            if k.v == RECHECK_KEY:
                if not isinstance(v, U):
                    raise EnvelopeError("Malformed", "recheck procedure id not a uint")
                if not is_known_recheck_procedure(v.v):
                    raise EnvelopeError("UnknownCriticalExt", "unrecognized critical extension")
                continue
            if k.v not in known_cext:
                raise EnvelopeError("UnknownCriticalExt", "unrecognized critical extension")

    if kind_validator is None or not kind_validator(o.channel, o.kind):
        raise EnvelopeError("UnknownKind", "kind/channel not a registered surface")

    tbs = cose.to_be_signed_raw(prot, payload)
    if halg == cose.ALG_COMPOSITE_65_ED25519:
        # Opt-in composite path (§4.2/§4.4/§4.5). Check order: CompositeRefused (Sovereign floors
        # at level 5 and the composite's ML-DSA-65 leg is level 3) -> SuiteMismatch (field 14 must
        # declare the matching suite) -> both-legs signature. The verifying key is the raw
        # component keys concatenated (mldsaPub || ed25519Pub).
        if profile == cose.PROFILE_SOVEREIGN:
            raise EnvelopeError("CompositeRefused", "composite refused on the Sovereign profile")
        if o.suite != SUITE_MLDSA65_ED25519:
            raise EnvelopeError("SuiteMismatch", "field 14 does not declare the composite suite")
        mldsa_pub, ed_pub = pubkey[:cose.MLDSA65_PUB_SIZE], pubkey[cose.MLDSA65_PUB_SIZE:]
        if len(ed_pub) != 32 or not cose.composite_verify(mldsa_pub, ed_pub, tbs, sig):
            raise EnvelopeError("BadSignature", "composite signature does not verify")
        return o
    # pure path: a non-composite alg MUST NOT carry the signed suite field (§4.2).
    if o.suite != 0:
        raise EnvelopeError("SuiteMismatch", "pure object carries a composite suite field")
    level, known = cose.alg_level(halg)
    if not known:
        raise EnvelopeError("UnknownAlg", "unregistered alg")
    if level < cose.profile_min_level(profile):
        raise EnvelopeError("ProfileDowngrade", "signature level below the profile minimum")
    if not cose.cose_verify1_raw(halg, pubkey, tbs, sig):
        raise EnvelopeError("BadSignature", "signature does not verify")
    return o


# --- §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) --------------------------

# The OPEN-DECISION toggle (design.md §4.4 profile floor applied to a rotation): when a
# Sovereign/High verifier checks a rotation whose OLD (authorizing) key is below the profile's
# signature floor, the floor gates the OLD leg too (DEFAULT, fail-closed) rather than only the NEW
# (go-forward) leg. Ratified default = True (matches impl/go rotationOldLegFloorApplies).
_ROTATION_OLD_LEG_FLOOR_APPLIES = True


def _is_rotation_object(channel, kind):
    """The Identity-channel Rotation object selector (channel 3, kind 0; design.md §5.2)."""
    return channel == 3 and kind == 0


def _is_composite_alg(alg):
    """Composite (LAMPS) legs are undecided inside a rotation co-signature -> rejected fail-closed."""
    return alg in (cose.ALG_COMPOSITE_65_ED25519, cose.ALG_COMPOSITE_44_ED25519)


def sign_rotation_object(o: Object, old_alg: int, old_seed: bytes, new_alg: int, new_seed: bytes) -> bytes:
    """Build a §5.2 Rotation object as a tag-98 COSE_Sign co-signed by the OLD then the NEW key in
    fixed order. The body protected header names the NEW (go-forward) key's alg. Permitted ONLY for
    the Identity Rotation object (channel 3, kind 0); a composite leg is rejected fail-closed. Bytes
    are byte-identical to the Go and Rust reference implementations."""
    if not _is_rotation_object(o.channel, o.kind):
        raise EnvelopeError("UnknownKind", "tag-98 permitted only for the Identity Rotation object")
    if _is_composite_alg(old_alg) or _is_composite_alg(new_alg):
        raise EnvelopeError("Malformed", "composite-inside-rotation is undecided")
    o.suite = 0  # a rotation object is never composite
    o.id = o.content_id()
    payload = cbor.encode(o._body_map(True))
    body_prot = _protected_header(new_alg, o.signer, o.profile)
    old_leg = cose.signature_leg(body_prot, old_alg, old_seed, payload)
    new_leg = cose.signature_leg(body_prot, new_alg, new_seed, payload)
    return cose.assemble_sign_raw(body_prot, payload, [old_leg, new_leg])


def verify_rotation_object(profile, old_alg, old_pk, new_alg, new_pk, kind_validator, obj_bytes, known_cext=None):
    """Verify a tag-98 Rotation object (§5.2): the same object-body checks as verify(), then EXACTLY
    two legs in fixed order (old-key then new-key) BOTH verifying over the object payload. Any
    missing/wrong/bad old leg is RotationUnauthorized. `old_pk` is the verifier's trusted old key;
    `new_pk` is the object's go-forward key. Permitted ONLY for (channel 3, kind 0)."""
    # Object octet-size bound (§3.4, R7): the tag-98 rotation object is a top-level signed object
    # too, so it is size-checked on raw bytes before any parse.
    if len(obj_bytes) > MAX_OBJECT_SIZE:
        raise EnvelopeError("TooLarge", "object exceeds the maximum octet size (§3.4, R7)")
    known_cext = known_cext or {}
    body_prot, payload, legs = cose.parse_sign_raw(obj_bytes)
    bv = cbor.decode_bounded(payload, MAX_NESTING_DEPTH)
    if not isinstance(bv, M):
        raise EnvelopeError("Malformed", "body not a map")

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
    if o.channel > 19 or o.effect > 3 or o.profile < 1 or o.profile > 3:
        raise EnvelopeError("RangeError", "field out of range")

    halg, hsigner, hprofile, hversion = _parse_protected(body_prot)
    if hversion != NAALP_VERSION:
        raise EnvelopeError("UnsupportedVersion", "bad naalp-version")
    if hsigner != o.signer or hprofile != o.profile:
        raise EnvelopeError("HeaderBodyMismatch", "protected header disagrees with body")
    if o.cext is not None:
        for k, v in o.cext.pairs:
            if not isinstance(k, U):
                raise EnvelopeError("UnknownCriticalExt", "unrecognized critical extension")
            if k.v == RECHECK_KEY:
                if not isinstance(v, U):
                    raise EnvelopeError("Malformed", "recheck procedure id not a uint")
                if not is_known_recheck_procedure(v.v):
                    raise EnvelopeError("UnknownCriticalExt", "unrecognized critical extension")
                continue
            if k.v not in known_cext:
                raise EnvelopeError("UnknownCriticalExt", "unrecognized critical extension")

    # tag-98 is permitted ONLY for the Identity-channel Rotation object (channel 3, kind 0).
    if not _is_rotation_object(o.channel, o.kind):
        raise EnvelopeError("UnknownKind", "tag-98 permitted only for the Identity Rotation object")
    if kind_validator is None or not kind_validator(o.channel, o.kind):
        raise EnvelopeError("UnknownKind", "kind/channel not a registered surface")
    if _is_composite_alg(halg):
        raise EnvelopeError("Malformed", "composite-inside-rotation is undecided")
    if halg != new_alg:
        raise EnvelopeError("KeyAlgMismatch", "body header alg is not the new key alg")

    # EXACTLY two legs, fixed order (old, new). A missing/lone leg IS "old leg dropped".
    if len(legs) != 2:
        raise EnvelopeError("RotationUnauthorized", "rotation must carry exactly two legs")
    old_leg_alg = cose.alg_from_protected(legs[0][0])
    new_leg_alg = cose.alg_from_protected(legs[1][0])
    if _is_composite_alg(old_leg_alg) or _is_composite_alg(new_leg_alg):
        raise EnvelopeError("Malformed", "composite leg in a rotation")
    if old_leg_alg != old_alg or new_leg_alg != new_alg:
        raise EnvelopeError("RotationUnauthorized", "legs not in (old, new) order")

    # profile floor: the NEW (go-forward) leg always; the OLD leg iff the fail-closed toggle applies.
    new_level, nknown = cose.alg_level(new_leg_alg)
    if not nknown:
        raise EnvelopeError("UnknownAlg", "unregistered alg")
    if new_level < cose.profile_min_level(profile):
        raise EnvelopeError("ProfileDowngrade", "new-leg level below the profile minimum")
    if _ROTATION_OLD_LEG_FLOOR_APPLIES:
        old_level, oknown = cose.alg_level(old_leg_alg)
        if not oknown:
            raise EnvelopeError("UnknownAlg", "unregistered alg")
        if old_level < cose.profile_min_level(profile):
            raise EnvelopeError("ProfileDowngrade", "old-leg level below the profile minimum")

    # both legs MUST verify over their per-signer ToBeSigned.
    old_tbs = cose.signature_to_be_signed(body_prot, old_leg_alg, payload)
    if not cose.cose_verify1_raw(old_leg_alg, old_pk, old_tbs, legs[0][1]):
        raise EnvelopeError("RotationUnauthorized", "old leg does not verify")
    new_tbs = cose.signature_to_be_signed(body_prot, new_leg_alg, payload)
    if not cose.cose_verify1_raw(new_leg_alg, new_pk, new_tbs, legs[1][1]):
        raise EnvelopeError("RotationUnauthorized", "new leg does not verify")
    return o


# --- NA-IETF-1 producing-boundary disclosure (OPTIONAL, self-asserted ext key 15, §2.5.4) -------

# The ext extension key under which an object OPTIONALLY carries a per-object producing-boundary
# disclosure (design.md §2.5.4, NA-IETF-1): the trust boundary that emitted the object and whether
# that boundary OBSERVED the event it describes first-hand or is RELAYING a report of it. It rides
# the NON-CRITICAL ext map (field 11): a verifier that does not understand it, or that reads a
# malformed value, IGNORES the entry and the object still verifies (may-ignore). Because ext is part
# of the signed body/payload, the disclosure is covered by the SIGNER's own COSE_Sign1 signature --
# a SELF-ASSERTED claim. 15 collides with neither the safety-label ext key 1 (§6.4), the recheck
# ext/cext key 13 (§2.5.1), nor the signer-counter ext key 14 (§2.5.2). Byte-identical to impl/go
# and impl/rust.
PRODUCING_BOUNDARY_KEY = 15

# The producing-boundary kind (§2.5.4): a closed enum naming whether the emitting boundary witnessed
# the event directly or is relaying a report of it.
PRODUCING_BOUNDARY_OBSERVED = 1   # this boundary witnessed the event directly (first-hand)
PRODUCING_BOUNDARY_REPORTED = 2   # this boundary is relaying a report it did not witness

# The producing-boundary value sub-map keys (§2.5.4).
_PB_FIELD_BOUNDARY = 1    # bstr -- the emitting trust boundary (party id)
_PB_FIELD_KIND = 2        # 1 observed / 2 reported
_PB_FIELD_REPORTING = 3   # bstr -- report origin; present iff kind == reported


class ProducingBoundary:
    """A decoded producing-boundary disclosure (PRODUCING_BOUNDARY_KEY, §2.5.4). `boundary` is the
    emitting trust boundary (the same bstr party-id form as Object.signer). `kind` is
    PRODUCING_BOUNDARY_OBSERVED or PRODUCING_BOUNDARY_REPORTED. `reporting` names the report origin
    and is non-None ONLY when kind is PRODUCING_BOUNDARY_REPORTED (an observer relays from no one)."""

    def __init__(self, boundary, kind, reporting=None):
        self.boundary = bytes(boundary)
        self.kind = kind
        self.reporting = None if reporting is None else bytes(reporting)

    def __eq__(self, other):
        return (isinstance(other, ProducingBoundary) and self.boundary == other.boundary
                and self.kind == other.kind and self.reporting == other.reporting)

    def __repr__(self):
        return "ProducingBoundary(boundary=%r, kind=%r, reporting=%r)" % (
            self.boundary, self.kind, self.reporting)


def producing_boundary(o):
    """Return (ProducingBoundary, True) iff `o` carries a WELL-FORMED producing-boundary disclosure
    in the non-critical ext map (field 11, PRODUCING_BOUNDARY_KEY): a non-empty boundary (key 1), a
    kind (key 2) in {observed, reported}, and a reporting-boundary (key 3) absent unless the kind is
    reported. A malformed value is IGNORED -- returns (None, False), NEVER raising (may-ignore). An
    absent disclosure returns (None, False). An unrecognized sub-key is ignored and does not by
    itself make an otherwise well-formed value malformed."""
    if o.ext is None:
        return None, False
    val = None
    found = False
    for k, v in o.ext.pairs:
        if isinstance(k, U) and k.v == PRODUCING_BOUNDARY_KEY:
            val = v
            found = True
            break
    if not found or not isinstance(val, M):
        return None, False
    boundary = None
    kind = None
    reporting = None
    have_reporting = False
    for k, v in val.pairs:
        if not isinstance(k, U):
            return None, False
        if k.v == _PB_FIELD_BOUNDARY:
            if not isinstance(v, B):
                return None, False
            boundary = v.v
        elif k.v == _PB_FIELD_KIND:
            if not isinstance(v, U):
                return None, False
            kind = v.v
        elif k.v == _PB_FIELD_REPORTING:
            if not isinstance(v, B):
                return None, False
            reporting = v.v
            have_reporting = True
        # else: an unrecognized sub-key -- may-ignore.
    # well-formedness (§2.5.4). Any failure returns (None, False) (may-ignore), never an error.
    if boundary is None or len(boundary) == 0:
        return None, False
    if kind != PRODUCING_BOUNDARY_OBSERVED and kind != PRODUCING_BOUNDARY_REPORTED:
        return None, False
    if have_reporting and kind != PRODUCING_BOUNDARY_REPORTED:
        return None, False  # a reporting-boundary under observed: an observer relays from no one
    return ProducingBoundary(boundary, kind, reporting if have_reporting else None), True


def set_producing_boundary(o, pb):
    """Name `pb` as `o`'s producing-boundary disclosure in the NON-CRITICAL ext map (field 11),
    covered by the signer's COSE_Sign1 signature. Creates the ext carrier if absent and leaves any
    other extension entries intact. The reporting-boundary is emitted ONLY when non-None AND the kind
    is reported, so a caller cannot accidentally emit a malformed observed-with-reporting disclosure
    (an observer relays from no one). Sub-map keys are appended in ascending order; encode emits
    canonical CBOR regardless, so the object stays deterministic."""
    sub = [(U(_PB_FIELD_BOUNDARY), B(pb.boundary)), (U(_PB_FIELD_KIND), U(pb.kind))]
    if pb.reporting is not None and pb.kind == PRODUCING_BOUNDARY_REPORTED:
        sub.append((U(_PB_FIELD_REPORTING), B(pb.reporting)))
    entry = (U(PRODUCING_BOUNDARY_KEY), M(sub))
    if o.ext is None:
        o.ext = M([entry])
        return
    new_pairs = []
    replaced = False
    for k, v in o.ext.pairs:
        if isinstance(k, U) and k.v == PRODUCING_BOUNDARY_KEY:
            new_pairs.append(entry)
            replaced = True
        else:
            new_pairs.append((k, v))
    if not replaced:
        new_pairs.append(entry)
    o.ext = M(new_pairs)
