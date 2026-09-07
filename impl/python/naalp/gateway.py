# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""N-AALP C21 portable gateway-decision object for the Python SDK (design.md §24; R-GW-1..6).

A GatewayDecision is a SIGNED decision object an enforcement gateway of ANY vendor emits as
PORTABLE EVIDENCE that it decided about an action. Its load-bearing property, exactly as the C18
signed description, is that authority lives in the SIGNED BYTES, never in the connection or the
host that served them: verify_decision takes NO serving-party/connection identity, so the same
signed decision RE-VERIFIES IDENTICALLY when a party OTHER than the gateway serves it (the
third-party re-serve property). It introduces NO new envelope, encoding, signature, identity, or
audit mechanism: the object is an ordinary signed N-AALP body (COSE_Sign1), reusing the closed C5
effect lattice and the T1 content-id framing unchanged. This is the EVIDENCE FORMAT ONLY -- never a
policy language. Every check is fail-closed: a failing object is rejected whole, returns its named
error, and causes no state change.

Ported from impl/go/gateway; graded against the shared vectors/gateway/cases.json.
"""
import hashlib
import hmac

from . import cbor, cose, policy
from .cbor import U, N, B, T, A, M

# The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
HEAD_SIZE = 48

# The closed set a gateway may emit; a code outside the set is rejected (UnknownGatewayDecision).
DECISION_ALLOW = 0  # the gateway allows the action
DECISION_DENY = 1   # the gateway denies the action
DECISION_HOLD = 2   # the gateway holds the action pending a further step

# decision code -> name (diagnostics); an unknown code has no entry.
DECISION_NAMES = {DECISION_ALLOW: "allow", DECISION_DENY: "deny", DECISION_HOLD: "hold"}


class GatewayError(ValueError):
    """A named, fail-closed gateway error; .kind is a stable string mirroring the Go/Rust/Ruby
    error kinds (GwMalformed, UnknownGatewayDecision, BadSignature, UnknownAlg, ProfileDowngrade,
    KeyAlgMismatch)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def is_known_decision(code):
    """Reports whether code is one of the closed decision codes."""
    return code in DECISION_NAMES


def decision_name(code):
    """The decision name, or 'unknown'."""
    return DECISION_NAMES.get(code, "unknown")


def _mfield(pairs, k):
    """Return the CBOR value for integer key k in a decoded map's pairs list, or None if absent.
    Mirrors the Go embedded-field accessor field(m, k): a key that is not the matching cbor.Uint
    simply does not match -- it never causes the whole map to be rejected."""
    for key, val in pairs:
        if isinstance(key, U) and key.v == k:
            return val
    return None


class GatewayDecision:
    """A signed decision an enforcement gateway emits as portable evidence. `decision` is the
    closed-set outcome; `action` is the content id of the action decided about; `policy` is the
    opaque deciding-policy identity (a name, not a program); `effect` is the action's C5 class.
    `ordering` (field 5, R1) and `foreign_profile` (field 6, R8) are OPTIONAL: None reads exactly
    as an absent field (correspondence-only ordering / no foreign-profile pin) -- never a stronger
    claim inferred from silence."""

    __slots__ = ("decision", "action", "policy", "effect", "ordering", "foreign_profile")

    def __init__(self, decision, action, policy, effect, ordering=None, foreign_profile=None):
        self.decision = decision
        self.action = bytes(action)
        self.policy = bytes(policy)
        self.effect = effect
        self.ordering = ordering
        self.foreign_profile = foreign_profile

    def bytes(self):
        """Deterministic-CBOR encoding {1: decision, 2: action, 3: policy, 4: effect,
        ?5: ordering, ?6: foreign-profile}. Fields 5/6 are OMITTED entirely when None (the same
        omit-when-absent precedent as naalp-decision-record's optional fields 3/6/7)."""
        pairs = [
            (U(1), U(self.decision)),
            (U(2), B(self.action)),
            (U(3), B(self.policy)),
            (U(4), U(self.effect)),
        ]
        if self.ordering is not None:
            pairs.append((U(5), self.ordering.to_cbor()))
        if self.foreign_profile is not None:
            pairs.append((U(6), self.foreign_profile.to_cbor()))
        return cbor.encode(M(pairs))

    def head(self):
        """The decision's SHA-384 head (48 octets)."""
        return hashlib.sha384(self.bytes()).digest()

    def id(self):
        """The decision's T1 content-id: multihash(0x20, 0x30 [48]) || SHA-384(body) (50 octets)."""
        return cbor.content_id(self.bytes())

    def effect_class(self):
        """The C5 effect class, normalized fail-closed: an unrecognized value is destructive."""
        return policy.normalize_effect(self.effect)


class ResolvedDecision:
    """A GatewayDecision that has passed signature verification. It carries NOTHING about who served
    the bytes -- the authority is the signature, so the resolved evidence is identical regardless of
    the serving party (the third-party re-serve property)."""

    __slots__ = ("decision", "action", "policy", "effect")

    def __init__(self, decision, action, policy, effect):
        self.decision = decision
        self.action = bytes(action)
        self.policy = bytes(policy)
        self.effect = effect


def parse_decision(b):
    """Reconstruct a GatewayDecision from its body bytes alone. It does NOT validate the decision
    code against the closed set, the ordering-disclosure's basis-conditioned well-formedness, or
    the foreign-profile-pin's field well-formedness -- those are verify_decision's job (mirroring
    the decision-record parse/validate split), so a decision carrying an unknown code, or an
    ordering/foreign-profile that is structurally decodable but semantically malformed, can be
    represented (and then rejected). It DOES enforce field-1-4 presence/type and, when field 5/6
    is PRESENT, that it decodes to the expected CBOR shape: present-with-wrong-type fails here
    (GwMalformed), never silently treated as absent. Fail-closed on any malformed shape: a
    non-canonical body, a non-map, or an absent/wrong-typed field 1-4 is GwMalformed."""
    try:
        v = cbor.decode(b)
    except cbor.NonCanonical:
        raise GatewayError("GwMalformed", "decision body is not well-formed deterministic CBOR")
    if not isinstance(v, M):
        raise GatewayError("GwMalformed", "decision body is not a map")
    dec = _mfield(v.pairs, 1)
    action = _mfield(v.pairs, 2)
    pol = _mfield(v.pairs, 3)
    eff = _mfield(v.pairs, 4)
    if not (isinstance(dec, U) and isinstance(action, B) and isinstance(pol, B)
            and isinstance(eff, U)):
        raise GatewayError("GwMalformed", "decision body missing or wrong-typed field 1-4")
    gd = GatewayDecision(dec.v, action.v, pol.v, eff.v)
    ord_v = _mfield(v.pairs, 5)
    if ord_v is not None:
        ordering = _ordering_from_cbor(ord_v)
        if ordering is None:
            raise GatewayError("GwMalformed", "field 5 (ordering) is present but malformed")
        gd.ordering = ordering
    fp_v = _mfield(v.pairs, 6)
    if fp_v is not None:
        fp = _foreign_profile_from_cbor(fp_v)
        if fp is None:
            raise GatewayError("GwMalformed", "field 6 (foreign-profile) is present but malformed")
        gd.foreign_profile = fp
    return gd


def gateway_protected_header(alg):
    """The bare {1: alg} COSE_Sign1 protected header (§4), as the reference's cose.Sign1 emits."""
    return cbor.encode(M([(U(1), N(alg))]))


def sign_decision(d, alg, seed):
    """Produce the tagged COSE_Sign1 object over the decision body, signed by the gateway."""
    return cose.cose_sign1(alg, seed, gateway_protected_header(alg), d.bytes())


def alg_from_protected(prot):
    """Read the alg (label 1) value from an encoded protected header."""
    v = cbor.decode(prot)
    if not isinstance(v, M):
        raise GatewayError("GwMalformed", "protected header is not a map")
    for k, val in v.pairs:
        if isinstance(k, U) and k.v == 1 and isinstance(val, (N, U)):
            return val.v
    raise GatewayError("GwMalformed", "protected header has no alg")


def verify_decision(obj, profile, alg, pubkey):
    """Verify a gateway decision end-to-end and return the resolved evidence. It (1) verifies the
    signed object under the profile with real crypto (signature, alg registry, profile floor)
    against the gateway's key; (2) reconstructs it from the signed bytes (parse_decision --
    structural only); (3) validates the decision code against the closed set
    (UnknownGatewayDecision); (4) if field 5 (ordering) is present, its basis-conditioned
    well-formedness (UnknownOrderingBasis / OrderingDisclosureMalformed); and (5) if field 6
    (foreign-profile) is present, its own well-formedness (ForeignProfileMalformed). Mandatory
    fields 1-4 are validated FIRST via parse_decision: a body failing a mandatory-field check is
    GwMalformed regardless of any optional 5/6. It takes NO serving-party or connection identity:
    the authority is the signature over the bytes, so the same obj yields an identical
    ResolvedDecision whether the gateway or an unrelated third party served it. Any failure raises
    its named error and resolves nothing (fail-closed)."""
    prot, payload, sig = cose.parse_sign1_raw(obj)
    halg = alg_from_protected(prot)
    level, known = cose.alg_level(halg)
    if not known:
        raise GatewayError("UnknownAlg", "unregistered alg %d" % halg)
    if level < cose.profile_min_level(profile):
        raise GatewayError("ProfileDowngrade", "signature level below the profile minimum")
    if halg != alg:
        raise GatewayError("KeyAlgMismatch", "alg %d does not match the verifier key alg %d" % (halg, alg))
    tbs = cose.to_be_signed_raw(prot, payload)
    if not cose.cose_verify1_raw(halg, pubkey, tbs, sig):
        raise GatewayError("BadSignature", "signature does not verify")
    d = parse_decision(payload)
    if not is_known_decision(d.decision):
        raise GatewayError("UnknownGatewayDecision", "decision code %d outside the closed set" % d.decision)
    if d.ordering is not None:
        d.ordering.validate()
    if d.foreign_profile is not None:
        d.foreign_profile.validate()
    return ResolvedDecision(d.decision, d.action, d.policy, policy.normalize_effect(d.effect))


# =================================================================================================
# Evidence-record family (E6.3 egress-attestation + S1 decision-record + S3 checkpoint + R1/R8
# ordering-disclosure / foreign-profile-pin), ported from impl/go/gateway/{ordering,decision_record,
# checkpoint,egress_attestation}.go; graded against the shared vectors/{decision_record,checkpoint,
# egress_attestation}/cases.json plus gateway/cases.json's optional_fields{} block.
# =================================================================================================

# ---- ordering-disclosure embeddable group (design.md section 26.3) ----------------------------
#
# `ordering-disclosure` states what, if anything, establishes decision->effect / record->event
# ORDER, and from which observational domain, rather than leaving the reader to assume more than
# the bytes support. It is carried as a field inside naalp-decision-record (mandatory, field 5),
# naalp-egress-attestation (optional, field 6), and naalp-gateway-decision (optional, field 5) --
# never as a top-level object of its own, so it has no head()/id() of its own; it is embedded
# directly as a nested CBOR map value inside its carrying record.
#
# correspondence-only (0) is the weakest claim and the value a verifier MUST read when the field is
# ABSENT on an optional carrier -- never a stronger claim inferred from silence. single-boundary (1)
# names one covering boundary. external-mechanism (2) names an external sequencing mechanism and,
# optionally, the log relation binding the record under it.
#
# Well-formedness is fail-closed and NATIVE: correspondence-only requires keys 2/3/4 absent;
# single-boundary requires key 2 present and 3/4 absent; external-mechanism requires key 3 present
# (4 optional) and key 2 absent. Any violation rejects the WHOLE carrying record
# (OrderingDisclosureMalformed).

ORDERING_CORRESPONDENCE_ONLY = 0  # the record orders only its own two-party construction (the weakest claim)
ORDERING_SINGLE_BOUNDARY = 1      # one boundary observed both terms and is named
ORDERING_EXTERNAL_MECHANISM = 2   # an external sequencing mechanism is named

_ORDERING_BASIS_NAMES = {
    ORDERING_CORRESPONDENCE_ONLY: "correspondence-only",
    ORDERING_SINGLE_BOUNDARY: "single-boundary",
    ORDERING_EXTERNAL_MECHANISM: "external-mechanism",
}


def is_known_ordering_basis(code):
    """Reports whether code is one of the closed ordering-basis codes."""
    return code in _ORDERING_BASIS_NAMES


def ordering_basis_name(code):
    """The ordering-basis name, or 'unknown'."""
    return _ORDERING_BASIS_NAMES.get(code, "unknown")


# Enforcement-disposition codes -- the closed set (design.md section 26.4).
ENFORCEMENT_ENFORCED = 1  # the producer states it actually enforces this outcome
ENFORCEMENT_ADVISED = 2   # the producer's own unverifiable self-account that it only advises

# Term-disposition kind codes -- reused unchanged from the section 2.5.4 producing-boundary kind
# vocabulary.
TERM_OBSERVED = 1  # the term was observed first-hand
TERM_REPORTED = 2  # the term was reported, relayed from a named source


class OrderingDisclosure:
    """The embeddable group {1: basis, ?2: boundary, ?3: mechanism, ?4: relation} (design.md
    section 26.3). It is never a top-level signed object; it is always a field inside another
    record. The zero value (basis=correspondence-only, no boundary/mechanism/relation) is the
    weakest claim and is exactly what an ABSENT optional ordering-disclosure field reads as."""

    __slots__ = ("basis", "boundary", "mechanism", "relation")

    def __init__(self, basis, boundary=b"", mechanism=b"", relation=b""):
        self.basis = basis
        self.boundary = bytes(boundary)
        self.mechanism = bytes(mechanism)
        self.relation = bytes(relation)

    def to_cbor(self):
        """Return self as a nested CBOR map VALUE (never top-level bytes -- self is always
        embedded as a field inside its carrying record)."""
        pairs = [(U(1), U(self.basis))]
        if self.boundary:
            pairs.append((U(2), B(self.boundary)))
        if self.mechanism:
            pairs.append((U(3), B(self.mechanism)))
        if self.relation:
            pairs.append((U(4), B(self.relation)))
        return M(pairs)

    def validate(self):
        """Checks (a) basis is in the closed set (UnknownOrderingBasis) and (b) the
        basis-conditioned field well-formedness rule (design.md section 26.3, native and
        fail-closed -- any violation rejects the whole carrying record,
        OrderingDisclosureMalformed). UnknownOrderingBasis is checked and raised FIRST: an
        out-of-set basis is never additionally reported as malformed."""
        if not is_known_ordering_basis(self.basis):
            raise GatewayError("UnknownOrderingBasis",
                                "ordering-disclosure basis is outside the closed set "
                                "correspondence-only/single-boundary/external-mechanism")
        if self.basis == ORDERING_CORRESPONDENCE_ONLY:
            if self.boundary or self.mechanism or self.relation:
                raise GatewayError("OrderingDisclosureMalformed",
                                    "correspondence-only requires keys 2/3/4 absent")
        elif self.basis == ORDERING_SINGLE_BOUNDARY:
            if not self.boundary or self.mechanism or self.relation:
                raise GatewayError("OrderingDisclosureMalformed",
                                    "single-boundary requires key 2 present, keys 3/4 absent")
        elif self.basis == ORDERING_EXTERNAL_MECHANISM:
            if self.boundary or not self.mechanism:
                raise GatewayError("OrderingDisclosureMalformed",
                                    "external-mechanism requires key 2 absent, key 3 present")


def correspondence_only():
    """The weakest ordering-disclosure claim, exactly what a verifier reads for an absent optional
    ordering-disclosure field."""
    return OrderingDisclosure(ORDERING_CORRESPONDENCE_ONLY)


def _ordering_from_cbor(v):
    """Decode a nested ordering-disclosure map value. Returns None on any wrong shape, including an
    optional key present under the WRONG CBOR type (never silently treated as absent)."""
    if not isinstance(v, M):
        return None
    basis_v = _mfield(v.pairs, 1)
    if not isinstance(basis_v, U):
        return None
    boundary = mechanism = relation = b""
    v2 = _mfield(v.pairs, 2)
    if v2 is not None:
        if not isinstance(v2, B):
            return None
        boundary = v2.v
    v3 = _mfield(v.pairs, 3)
    if v3 is not None:
        if not isinstance(v3, B):
            return None
        mechanism = v3.v
    v4 = _mfield(v.pairs, 4)
    if v4 is not None:
        if not isinstance(v4, B):
            return None
        relation = v4.v
    return OrderingDisclosure(basis_v.v, boundary, mechanism, relation)


class TermDisposition:
    """The embeddable group {1: kind, ?2: source} (design.md section 26.4). `kind` is carried as a
    plain uint on the wire (the CDDL does not close its value set the way ordering-basis does), so
    TermDisposition itself validates no closed set -- only naalp-decision-record's own field-6 key
    set (the record's own field numbers) is fail-closed (TermDispositionMalformed)."""

    __slots__ = ("kind", "source")

    def __init__(self, kind, source=b""):
        self.kind = kind
        self.source = bytes(source)

    def to_cbor(self):
        pairs = [(U(1), U(self.kind))]
        if self.source:
            pairs.append((U(2), B(self.source)))
        return M(pairs)


def _term_disposition_from_cbor(v):
    """Decode a nested term-disposition map value. Returns None on any wrong shape."""
    if not isinstance(v, M):
        return None
    kind_v = _mfield(v.pairs, 1)
    if not isinstance(kind_v, U):
        return None
    source = b""
    v2 = _mfield(v.pairs, 2)
    if v2 is not None:
        if not isinstance(v2, B):
            return None
        source = v2.v
    return TermDisposition(kind_v.v, source)


# ---- ForeignProfilePin: GatewayDecision field 6, R8 --------------------------------------------

class ForeignProfilePin:
    """The embeddable group {1: id, 2: revision} (naalp-foreign-profile-pin, R8). Present on
    GatewayDecision field 6 iff the decision was over foreign-protocol evidence: it pins the
    foreign evidence profile's identifier (an absolute URI) AND the revision pinned at decision
    time -- binding the reference, not just the class. Both fields are mandatory tstr; the group
    carries no other keys. It is never a top-level signed object -- always embedded as field 6 of
    its carrying naalp-gateway-decision, so it has no head()/id() of its own (mirroring
    OrderingDisclosure)."""

    __slots__ = ("id", "revision", "_unknown_field")

    def __init__(self, id="", revision="", _unknown_field=False):
        self.id = id
        self.revision = revision
        self._unknown_field = _unknown_field

    def to_cbor(self):
        """Return self as a nested CBOR map VALUE {1: tstr(id), 2: tstr(revision)}."""
        return M([(U(1), T(self.id)), (U(2), T(self.revision))])

    def validate(self):
        """Checks the foreign-profile-pin's own well-formedness (R8): both id and revision are
        mandatory non-empty tstr, and no key besides 1/2 may be present. A missing, empty, or
        extra field rejects the WHOLE carrying naalp-gateway-decision (ForeignProfileMalformed)."""
        if not self.id or not self.revision or self._unknown_field:
            raise GatewayError("ForeignProfileMalformed",
                                "foreign-profile-pin is not well-formed (id and revision are "
                                "mandatory tstr, no other keys)")


def _foreign_profile_from_cbor(v):
    """Decode a nested foreign-profile-pin map value. Decode is STRUCTURAL only, mirroring
    _ordering_from_cbor: a key present under the WRONG CBOR type fails decode (returns None, never
    silently treated as absent); a key that is simply ABSENT decodes to the empty string, leaving
    the mandatory-presence check to validate() (mirroring OrderingDisclosure's own decode/validate
    split). A key besides 1/2 marks the group's unknown-field flag, also caught by validate() --
    the closed 2-key set is enforced semantically, not by refusing to decode a map that merely
    carries an extra key."""
    if not isinstance(v, M):
        return None
    id_ = ""
    v1 = _mfield(v.pairs, 1)
    if v1 is not None:
        if not isinstance(v1, T):
            return None
        id_ = v1.v
    revision = ""
    v2 = _mfield(v.pairs, 2)
    if v2 is not None:
        if not isinstance(v2, T):
            return None
        revision = v2.v
    unknown = False
    for k, _val in v.pairs:
        if not (isinstance(k, U) and k.v in (1, 2)):
            unknown = True
            break
    return ForeignProfilePin(id_, revision, unknown)


# ---- naalp-decision-record: S1, the full governed-decision accountability record --------------
#
# A DecisionRecord is the SIGNED record a governed decision point emits that it decided about an
# action under a CLOSED, uniquely-selected condition set. It carries the T/T+n accountability
# triple (section 26.1): UNIQUE SELECTION (field 2, the governing set in the clear as content ids);
# GOVERNED-AT-T (field 3, the naalp-consume-receipt spent at decision time); BINDING-FIXED-BY-T
# (established off-record by inclusion under a witnessed naalp-checkpoint-root). The record is
# deliberately CLOCK-FREE: it carries no claimed timestamp anywhere in its own body; both time
# properties are POSITIONAL, never a self-asserted timestamp. It introduces no new envelope,
# encoding, signature, or identity mechanism: an ordinary N-AALP signed body (COSE_Sign1), reusing
# the closed gw-decision outcome vocabulary unchanged.
#
# Following parse_decision/verify_decision's split: parse_decision_record reconstructs the record
# from its body bytes ALONE and performs only STRUCTURAL checks (field presence and CBOR type); it
# does NOT validate the outcome against the closed gw-decision set, the ordering disclosure's
# well-formedness, the deny/hold-with-consume rule, or the terms key set -- those are
# validate_decision_record's job.

class DecisionRecord:
    """The governed-decision accountability record (design.md section 26.4). `action` is the
    content id of the action decided about; `governing` is the closed governing condition set,
    content ids, in the clear (may be empty); `consume` is OPTIONAL field 3 (content id of the
    consume-receipt spent at decision time; b"" == absent); `outcome` is field 4 (allow/deny/hold,
    reuses the closed gw-decision set); `ordering` is field 5, MANDATORY (no silent default --
    every record states its ordering basis); `terms` is OPTIONAL field 6 (per-term
    observed/reported, keyed by this record's OWN field numbers 1..5; empty/None == absent);
    `enforcement` is OPTIONAL field 7 (enforced(1)/advised(2); 0 == absent)."""

    __slots__ = ("action", "governing", "consume", "outcome", "ordering", "terms", "enforcement")

    def __init__(self, action, governing, outcome, ordering, consume=b"", terms=None, enforcement=0):
        self.action = bytes(action)
        self.governing = [bytes(g) for g in governing]
        self.consume = bytes(consume)
        self.outcome = outcome
        self.ordering = ordering
        self.terms = dict(terms) if terms else {}
        self.enforcement = enforcement

    def bytes(self):
        """Deterministic-CBOR encoding {1:action, 2:governing[], ?3:consume, 4:outcome, 5:ordering,
        ?6:terms, ?7:enforcement}. Fields 3/6/7 are OMITTED when absent (consume empty, terms
        empty, enforcement zero) -- the omit-when-absent precedent (naalp-approval ?6:audience)."""
        pairs = [
            (U(1), B(self.action)),
            (U(2), A([B(g) for g in self.governing])),
        ]
        if self.consume:
            pairs.append((U(3), B(self.consume)))
        pairs.append((U(4), U(self.outcome)))
        pairs.append((U(5), self.ordering.to_cbor()))
        if self.terms:
            pairs.append((U(6), M([(U(k), td.to_cbor()) for k, td in self.terms.items()])))
        if self.enforcement:
            pairs.append((U(7), U(self.enforcement)))
        return cbor.encode(M(pairs))

    def head(self):
        """The record's SHA-384 head (48 octets)."""
        return hashlib.sha384(self.bytes()).digest()

    def id(self):
        """The record's T1 content-id (50 octets)."""
        return cbor.content_id(self.bytes())


def parse_decision_record(b):
    """Reconstruct a DecisionRecord from its body bytes alone. It performs ONLY structural checks
    (mandatory-field presence and CBOR type); it does NOT validate the outcome against the closed
    gw-decision set, the ordering disclosure's basis-conditioned well-formedness, the
    deny/hold-with-consume rule, or the terms key set -- see validate_decision_record. Fail-closed
    on any malformed shape (DecisionMalformed)."""
    try:
        v = cbor.decode(b)
    except cbor.NonCanonical:
        raise GatewayError("DecisionMalformed", "decision-record body is not well-formed deterministic CBOR")
    if not isinstance(v, M):
        raise GatewayError("DecisionMalformed", "decision-record body is not a map")
    action = _mfield(v.pairs, 1)
    gov_v = _mfield(v.pairs, 2)
    if not isinstance(action, B) or not isinstance(gov_v, A):
        raise GatewayError("DecisionMalformed", "missing or wrong-typed field 1/2")
    governing = []
    for e in gov_v.items:
        if not isinstance(e, B):
            raise GatewayError("DecisionMalformed", "governing array element not a bstr")
        governing.append(e.v)
    consume = b""
    consume_v = _mfield(v.pairs, 3)
    if consume_v is not None:
        if not isinstance(consume_v, B):
            raise GatewayError("DecisionMalformed", "field 3 (consume) wrong type")
        consume = consume_v.v
    outcome_v = _mfield(v.pairs, 4)
    if not isinstance(outcome_v, U):
        raise GatewayError("DecisionMalformed", "missing or wrong-typed field 4 (outcome)")
    ord_v = _mfield(v.pairs, 5)
    if ord_v is None:
        raise GatewayError("DecisionMalformed", "missing mandatory field 5 (ordering)")
    ordering = _ordering_from_cbor(ord_v)
    if ordering is None:
        raise GatewayError("DecisionMalformed", "field 5 (ordering) malformed")
    terms = {}
    terms_v = _mfield(v.pairs, 6)
    if terms_v is not None:
        if not isinstance(terms_v, M):
            raise GatewayError("DecisionMalformed", "field 6 (terms) wrong type")
        for k, val in terms_v.pairs:
            if not isinstance(k, U):
                raise GatewayError("DecisionMalformed", "terms map key not a uint")
            td = _term_disposition_from_cbor(val)
            if td is None:
                raise GatewayError("DecisionMalformed", "terms map value malformed")
            terms[k.v] = td
    enforcement = 0
    enf_v = _mfield(v.pairs, 7)
    if enf_v is not None:
        if not isinstance(enf_v, U):
            raise GatewayError("DecisionMalformed", "field 7 (enforcement) wrong type")
        enforcement = enf_v.v
    return DecisionRecord(action.v, governing, outcome_v.v, ordering, consume, terms, enforcement)


def _valid_decision_record_term_key(k):
    """Reports whether k is one of the record's own field numbers 1..5 -- the only valid keys for
    the field-6 terms map (design.md section 26.4; TermDispositionMalformed otherwise)."""
    return 1 <= k <= 5


def validate_decision_record(d):
    """Performs the semantic, closed-set, and native well-formedness checks parse_decision_record
    deliberately does not (mirroring verify_decision's parse/validate split):

    1. Outcome must be in the closed gw-decision set (UnknownGatewayDecision).
    2. Ordering must satisfy its basis-conditioned well-formedness rule (UnknownOrderingBasis /
       OrderingDisclosureMalformed) -- checked BEFORE the deny/hold-consume rule so a record whose
       ordering is itself malformed is never additionally reported as a consume violation.
    3. A deny/hold outcome carrying a field-3 consume reference is rejected in full
       (DecisionMalformed) -- nothing was consumed, so a value here would assert authority spent
       for an action the record's own outcome says was not taken.
    4. Every terms map key must be one of the record's own field numbers 1..5
       (TermDispositionMalformed)."""
    if not is_known_decision(d.outcome):
        raise GatewayError("UnknownGatewayDecision", "decision-record outcome %d outside the closed set" % d.outcome)
    d.ordering.validate()
    if d.outcome != DECISION_ALLOW and d.consume:
        raise GatewayError("DecisionMalformed",
                            "a deny/hold outcome must not carry a field-3 consume reference")
    for k in d.terms:
        if not _valid_decision_record_term_key(k):
            raise GatewayError("TermDispositionMalformed",
                                "a terms map key is outside the record's own field set 1..5")


def sign_decision_record(d, alg, seed):
    """Produce the tagged COSE_Sign1 object over the record body, signed by the governed decision
    point."""
    return cose.cose_sign1(alg, seed, gateway_protected_header(alg), d.bytes())


class ResolvedDecisionRecord:
    """A DecisionRecord that has passed signature verification and full semantic validation."""

    __slots__ = ("action", "governing", "consume", "outcome", "ordering", "terms", "enforcement")

    def __init__(self, action, governing, consume, outcome, ordering, terms, enforcement):
        self.action = bytes(action)
        self.governing = [bytes(g) for g in governing]
        self.consume = bytes(consume)
        self.outcome = outcome
        self.ordering = ordering
        self.terms = dict(terms)
        self.enforcement = enforcement


def verify_decision_record(obj, profile, alg, pubkey):
    """Verify a decision record end-to-end: (1) the signed object under the profile with real
    crypto; (2) structural reconstruction (parse_decision_record); and (3) full semantic
    validation (validate_decision_record). It takes no serving-party or connection identity -- the
    authority is the signature over the bytes, mirroring verify_decision. Any failure raises its
    named error and resolves nothing (fail-closed)."""
    prot, payload, sig = cose.parse_sign1_raw(obj)
    halg = alg_from_protected(prot)
    level, known = cose.alg_level(halg)
    if not known:
        raise GatewayError("UnknownAlg", "unregistered alg %d" % halg)
    if level < cose.profile_min_level(profile):
        raise GatewayError("ProfileDowngrade", "signature level below the profile minimum")
    if halg != alg:
        raise GatewayError("KeyAlgMismatch", "alg %d does not match the verifier key alg %d" % (halg, alg))
    tbs = cose.to_be_signed_raw(prot, payload)
    if not cose.cose_verify1_raw(halg, pubkey, tbs, sig):
        raise GatewayError("BadSignature", "signature does not verify")
    d = parse_decision_record(payload)
    validate_decision_record(d)
    return ResolvedDecisionRecord(d.action, d.governing, d.consume, d.outcome, d.ordering, d.terms, d.enforcement)


# ---- naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof: S3 -------------------
#
# S3 is the neither-party anchor for the BINDING-FIXED-BY-T leg of the accountability triple
# (design.md section 26.5). Tree construction follows RFC 9162
# (https://www.rfc-editor.org/rfc/rfc9162.html) section 2.1 EXACTLY, SHA-384-profiled: leaf hash =
# HASH(0x00 || leaf); interior node hash = HASH(0x01 || left || right); MTH({}) = HASH() (the empty
# hash); MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the largest
# power of two k < n. Section 2.1.2's PATH(m, D[n]) recursion (leaf-to-root sibling order) generates
# the audit path; section 2.1.3.1's inverse recursion recomputes the root from (leaf, index, size,
# path) and compares against the named root (InclusionProofInvalid on mismatch, fail-closed).
#
# naalp-checkpoint-root is a log operator's signed Merkle tree head over a leaf set of record
# content ids, chaining by `prev` (genesis = HEAD_SIZE zero bytes). naalp-witness-cosign carries the
# wire hook for an independent countersignature over one exact checkpoint by content id;
# naalp-inclusion-proof proves one record's content id was a leaf under a named checkpoint. Two
# witness-cosigned roots at one (log, size) carrying different root values are fork evidence.

class CheckpointRoot:
    """A log operator's signed Merkle tree head over a leaf set of record content ids (design.md
    section 26.5)."""

    __slots__ = ("log", "size", "root", "prev", "at")

    def __init__(self, log, size, root, prev, at):
        self.log = bytes(log)
        self.size = size
        self.root = bytes(root)
        self.prev = bytes(prev)
        self.at = at

    def bytes(self):
        """Deterministic-CBOR encoding {1:log, 2:size, 3:root, 4:prev, 5:at}."""
        return cbor.encode(M([
            (U(1), B(self.log)),
            (U(2), U(self.size)),
            (U(3), B(self.root)),
            (U(4), B(self.prev)),
            (U(5), U(self.at)),
        ]))

    def head(self):
        """The checkpoint's SHA-384 head (48 octets) -- the `prev` the NEXT checkpoint chains from."""
        return hashlib.sha384(self.bytes()).digest()

    def id(self):
        """The checkpoint's T1 content-id (50 octets) -- what an inclusion proof's `root` field and
        a witness-cosign's `root` field both name."""
        return cbor.content_id(self.bytes())


def genesis_prev():
    """The HEAD_SIZE all-zero prev value a log's first checkpoint chains from."""
    return bytes(HEAD_SIZE)


def parse_checkpoint_root(b):
    """Reconstruct a CheckpointRoot from its body bytes alone. Fail-closed on any malformed shape
    (CheckpointMalformed): every one of the five fields is mandatory."""
    try:
        v = cbor.decode(b)
    except cbor.NonCanonical:
        raise GatewayError("CheckpointMalformed", "checkpoint-root body is not well-formed deterministic CBOR")
    if not isinstance(v, M):
        raise GatewayError("CheckpointMalformed", "checkpoint-root body is not a map")
    log = _mfield(v.pairs, 1)
    size = _mfield(v.pairs, 2)
    root = _mfield(v.pairs, 3)
    prev = _mfield(v.pairs, 4)
    at = _mfield(v.pairs, 5)
    if not (isinstance(log, B) and isinstance(size, U) and isinstance(root, B)
            and isinstance(prev, B) and isinstance(at, U)):
        raise GatewayError("CheckpointMalformed", "missing or wrong-typed field 1-5")
    return CheckpointRoot(log.v, size.v, root.v, prev.v, at.v)


def sign_checkpoint_root(c, alg, seed):
    """Produce the tagged COSE_Sign1 object over the checkpoint body, signed by the log operator."""
    return cose.cose_sign1(alg, seed, gateway_protected_header(alg), c.bytes())


class WitnessCosign:
    """A witness's countersignature over one exact checkpoint by content id (design.md section
    26.5). Whether the witness's observational domain is genuinely distinct from both parties to
    the decisions the checkpoint covers is a structural deployment fact checkable in substance at
    T+n -- the wire supplies the hook; it does not manufacture the independence itself."""

    __slots__ = ("witness", "root", "at")

    def __init__(self, witness, root, at):
        self.witness = bytes(witness)
        self.root = bytes(root)
        self.at = at

    def bytes(self):
        """Deterministic-CBOR encoding {1:witness, 2:root, 3:at}."""
        return cbor.encode(M([
            (U(1), B(self.witness)),
            (U(2), B(self.root)),
            (U(3), U(self.at)),
        ]))

    def head(self):
        """The cosign's SHA-384 head (48 octets)."""
        return hashlib.sha384(self.bytes()).digest()

    def id(self):
        """The cosign's T1 content-id (50 octets)."""
        return cbor.content_id(self.bytes())


def parse_witness_cosign(b):
    """Reconstruct a WitnessCosign from its body bytes alone. Fail-closed on any malformed shape:
    every one of the three fields is mandatory."""
    try:
        v = cbor.decode(b)
    except cbor.NonCanonical:
        raise GatewayError("CheckpointMalformed", "witness-cosign body is not well-formed deterministic CBOR")
    if not isinstance(v, M):
        raise GatewayError("CheckpointMalformed", "witness-cosign body is not a map")
    witness = _mfield(v.pairs, 1)
    root = _mfield(v.pairs, 2)
    at = _mfield(v.pairs, 3)
    if not (isinstance(witness, B) and isinstance(root, B) and isinstance(at, U)):
        raise GatewayError("CheckpointMalformed", "missing or wrong-typed field 1-3")
    return WitnessCosign(witness.v, root.v, at.v)


def sign_witness_cosign(w, alg, seed):
    """Produce the tagged COSE_Sign1 object over the cosign body, signed by the witness."""
    return cose.cose_sign1(alg, seed, gateway_protected_header(alg), w.bytes())


def validate_witness_cosign(w, accompanied_checkpoint_id):
    """Checks that w names the EXACT checkpoint it accompanies (WitnessRootMismatch, design.md
    section 26.5): w.root must equal accompanied_checkpoint_id, the content id of the
    naalp-checkpoint-root object w claims to cosign. Fail-closed."""
    if bytes(w.root) != bytes(accompanied_checkpoint_id):
        raise GatewayError("WitnessRootMismatch",
                            "witness-cosign names a root content id that does not match the checkpoint it accompanies")


class InclusionProof:
    """Proves one record's content id existed as a leaf under a named checkpoint (design.md
    section 26.5, RFC 9162 section 2.1.3.1)."""

    __slots__ = ("root", "leaf", "index", "path")

    def __init__(self, root, leaf, index, path):
        self.root = bytes(root)
        self.leaf = bytes(leaf)
        self.index = index
        self.path = [bytes(p) for p in path]

    def bytes(self):
        """Deterministic-CBOR encoding {1:root, 2:leaf, 3:index, 4:path[]}."""
        return cbor.encode(M([
            (U(1), B(self.root)),
            (U(2), B(self.leaf)),
            (U(3), U(self.index)),
            (U(4), A([B(p) for p in self.path])),
        ]))

    def head(self):
        """The proof's SHA-384 head (48 octets)."""
        return hashlib.sha384(self.bytes()).digest()

    def id(self):
        """The proof's T1 content-id (50 octets)."""
        return cbor.content_id(self.bytes())


def parse_inclusion_proof(b):
    """Reconstruct an InclusionProof from its body bytes alone. Fail-closed on any malformed shape:
    every one of the four fields is mandatory."""
    try:
        v = cbor.decode(b)
    except cbor.NonCanonical:
        raise GatewayError("CheckpointMalformed", "inclusion-proof body is not well-formed deterministic CBOR")
    if not isinstance(v, M):
        raise GatewayError("CheckpointMalformed", "inclusion-proof body is not a map")
    root = _mfield(v.pairs, 1)
    leaf = _mfield(v.pairs, 2)
    index = _mfield(v.pairs, 3)
    path_v = _mfield(v.pairs, 4)
    if not (isinstance(root, B) and isinstance(leaf, B) and isinstance(index, U) and isinstance(path_v, A)):
        raise GatewayError("CheckpointMalformed", "missing or wrong-typed field 1-4")
    path = []
    for e in path_v.items:
        if not isinstance(e, B):
            raise GatewayError("CheckpointMalformed", "path array element not a bstr")
        path.append(e.v)
    return InclusionProof(root.v, leaf.v, index.v, path)


# ---- RFC 9162 section 2.1 Merkle tree math (SHA-384-profiled) ----------------------------------

def _leaf_hash(leaf):
    """leaf_hash = HASH(0x00 || leaf) (RFC 9162 section 2.1's LEAF_HASH, leaf/interior domain
    separation)."""
    return hashlib.sha384(b"\x00" + bytes(leaf)).digest()


def _node_hash(l, r):
    """node_hash = HASH(0x01 || left || right) (RFC 9162 section 2.1's NODE_HASH)."""
    return hashlib.sha384(b"\x01" + bytes(l) + bytes(r)).digest()


def _largest_power_of_two_less_than(n):
    """The largest power of two strictly less than n (n > 1), per RFC 9162 section 2.1's k =
    "the largest power of two smaller than n"."""
    k = 1
    while 2 * k < n:
        k *= 2
    return k


def merkle_root(leaves):
    """Computes MTH(leaves) per RFC 9162 section 2.1: MTH({}) = HASH() (SHA-384 of the empty
    string); MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the
    largest power of two k < n. leaves are raw leaf VALUES (record content ids); LEAF_HASH is
    applied internally -- callers never hash a leaf before calling merkle_root. `leaves=None` is
    accepted as the empty list (mirroring Go's nil-slice-len-0 semantics for MerkleRoot(nil))."""
    n = 0 if leaves is None else len(leaves)
    if n == 0:
        return hashlib.sha384(b"").digest()  # MTH({}) = HASH(""), the empty-list base case
    if n == 1:
        return _leaf_hash(leaves[0])
    k = _largest_power_of_two_less_than(n)
    return _node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


class _PathLengthMismatch(Exception):
    """Internal sentinel: the recursive root recomputation ran out of path entries (or had entries
    left over) before reaching the single-leaf base case. Always surfaced to callers as
    InclusionProofInvalid -- never exported."""


def generate_inclusion_proof_path(leaves, index):
    """Computes the RFC 9162 section 2.1.2 PATH(index, leaves) audit path (leaf-to-root sibling
    order -- the list's FIRST entry is the leaf's immediate sibling, the LAST is closest to the
    root, exactly the order naalp-inclusion-proof's `path` field carries)."""
    if index < 0 or index >= len(leaves):
        raise GatewayError("InclusionProofInvalid", "leaf index out of range")
    return _gen_path(leaves, index)


def _gen_path(leaves, index):
    n = len(leaves)
    if n <= 1:
        return []  # PATH(0, {d0}) = {} -- the single-leaf base case
    k = _largest_power_of_two_less_than(n)
    if index < k:
        sub = _gen_path(leaves[:k], index)
        return sub + [merkle_root(leaves[k:])]
    sub = _gen_path(leaves[k:], index - k)
    return sub + [merkle_root(leaves[:k])]


def _recompute_root(leaf_h, index, size, path):
    """The exact structural inverse of _gen_path: at each level it consumes the LAST remaining
    path entry (closest to the root) as this level's sibling and recurses into the appropriate
    half with the entries that remain."""
    if size == 1:
        if len(path) != 0:
            raise _PathLengthMismatch()
        return leaf_h
    if len(path) == 0:
        raise _PathLengthMismatch()
    k = _largest_power_of_two_less_than(size)
    last = path[-1]
    rest = path[:-1]
    if index < k:
        left = _recompute_root(leaf_h, index, k, rest)
        return _node_hash(left, last)
    right = _recompute_root(leaf_h, index - k, size - k, rest)
    return _node_hash(last, right)


def verify_inclusion_proof(leaf, index, size, path, root):
    """Recomputes the audit path bottom-up (RFC 9162 section 2.1.3.1, the inverse of PATH()) from
    (leaf, index, size, path) and compares the result against root. `size` is the tree size the
    proof is checked against -- the resolved naalp-checkpoint-root's own `size` field, NOT carried
    inside naalp-inclusion-proof itself (the proof names the checkpoint by content id; the verifier
    is expected to already hold the resolved checkpoint to learn its size). Fail-closed: any
    mismatch, out-of-range index, or path-length mismatch is InclusionProofInvalid."""
    if size == 0 or index >= size:
        raise GatewayError("InclusionProofInvalid", "index out of range for the claimed tree size")
    try:
        got = _recompute_root(_leaf_hash(leaf), index, size, list(path))
    except _PathLengthMismatch:
        raise GatewayError("InclusionProofInvalid", "inclusion path length does not match the claimed tree size")
    if got != bytes(root):
        raise GatewayError("InclusionProofInvalid", "inclusion audit path does not recompute to the named root")


# ---- naalp-egress-attestation: E6.3 --------------------------------------------------------------
#
# A naalp-egress-attestation is a SIGNED attestation a gateway/sidecar emits that an object of a
# given effect class, bound to a given audience, crossed an egress boundary at a given time --
# third-party verifiable WITHOUT the payload. It is a near-clone of GatewayDecision: the gateway is
# the SIGNER, and verify_egress_attestation takes NO serving-party or connection identity -- the
# authority is the signature over the bytes, so the identical attested evidence re-verifies whether
# the gateway or an unrelated third party serves it. `binding` is a closed set
# (content_bound/content_free); `digest` is either the T1 content-id of the crossed object
# (content_bound) or a hiding commitment SHA-384(content_id||salt) (content_free) -- never both;
# `effect` is the C5 effect class of the crossed object; `audience` is the bound destination
# (empty-permitted); `at` is the crossing time in epoch milliseconds. Field 6 (`ordering`) is
# OPTIONAL: ABSENT reads correspondence-only, never a stronger claim inferred from silence.
#
# The content_free binding lets a gateway attest an egress crossing WITHOUT disclosing which object
# crossed. egress_commit/open_egress_commitment is the open/verify pair: the gateway (or anyone it
# later discloses content-id+salt to) can PROVE which object a content_free attestation names,
# without the attestation bytes themselves ever carrying the content-id.

BINDING_CONTENT_BOUND = 0  # digest is the crossed object's T1 content-id
BINDING_CONTENT_FREE = 1   # digest is a hiding commitment SHA-384(content_id||salt)

_BINDING_NAMES = {BINDING_CONTENT_BOUND: "content_bound", BINDING_CONTENT_FREE: "content_free"}


def is_known_binding(code):
    """Reports whether code is one of the closed binding codes."""
    return code in _BINDING_NAMES


def binding_name(code):
    """The binding name, or 'unknown'."""
    return _BINDING_NAMES.get(code, "unknown")


class EgressAttestation:
    """A signed attestation a gateway/sidecar emits that an object crossed an egress boundary.
    `binding` selects how `digest` is interpreted (content_bound: the crossed object's T1
    content-id; content_free: a hiding commitment). `effect` is the crossed object's C5 effect
    class. `audience` is the bound destination (empty-permitted). `at` is the crossing time, epoch
    ms. `ordering` is the OPTIONAL field 6: None == ABSENT (reads correspondence-only)."""

    __slots__ = ("binding", "digest", "effect", "audience", "at", "ordering")

    def __init__(self, binding, digest, effect, audience, at, ordering=None):
        self.binding = binding
        self.digest = bytes(digest)
        self.effect = effect
        self.audience = bytes(audience)
        self.at = at
        self.ordering = ordering

    def bytes(self):
        """Deterministic-CBOR encoding {1:binding, 2:digest, 3:effect, 4:audience, 5:at,
        ?6:ordering}. Field 6 is OMITTED when `ordering` is None."""
        pairs = [
            (U(1), U(self.binding)),
            (U(2), B(self.digest)),
            (U(3), U(self.effect)),
            (U(4), B(self.audience)),
            (U(5), U(self.at)),
        ]
        if self.ordering is not None:
            pairs.append((U(6), self.ordering.to_cbor()))
        return cbor.encode(M(pairs))

    def head(self):
        """The attestation's SHA-384 head (48 octets)."""
        return hashlib.sha384(self.bytes()).digest()

    def id(self):
        """The attestation's T1 content-id (50 octets)."""
        return cbor.content_id(self.bytes())

    def effect_class(self):
        """The attestation's C5 effect class, normalized fail-closed: a value the evaluator does
        not recognize is treated as destructive, never as a weaker class."""
        return policy.normalize_effect(self.effect)


def parse_egress_attestation(b):
    """Reconstruct an EgressAttestation from its body bytes alone. It does NOT validate the binding
    code against the closed set -- that is verify_egress_attestation's job -- so an attestation
    carrying an unknown binding can be represented (and then rejected). Fail-closed on a malformed
    shape: every one of the five mandatory fields is required, and a present-but-wrong-typed field
    6 fails here too."""
    try:
        v = cbor.decode(b)
    except cbor.NonCanonical:
        raise GatewayError("EgMalformed", "egress-attestation body is not well-formed deterministic CBOR")
    if not isinstance(v, M):
        raise GatewayError("EgMalformed", "egress-attestation body is not a map")
    binding = _mfield(v.pairs, 1)
    digest = _mfield(v.pairs, 2)
    effect = _mfield(v.pairs, 3)
    audience = _mfield(v.pairs, 4)
    at = _mfield(v.pairs, 5)
    if not (isinstance(binding, U) and isinstance(digest, B) and isinstance(effect, U)
            and isinstance(audience, B) and isinstance(at, U)):
        raise GatewayError("EgMalformed", "missing or wrong-typed field 1-5")
    ordering = None
    ord_v = _mfield(v.pairs, 6)
    if ord_v is not None:
        ordering = _ordering_from_cbor(ord_v)
        if ordering is None:
            raise GatewayError("EgMalformed", "field 6 (ordering) is present but malformed")
    return EgressAttestation(binding.v, digest.v, effect.v, audience.v, at.v, ordering)


def sign_egress_attestation(a, alg, seed):
    """Produce the tagged COSE_Sign1 object over the attestation body, signed by the gateway."""
    return cose.cose_sign1(alg, seed, gateway_protected_header(alg), a.bytes())


class ResolvedEgressAttestation:
    """An EgressAttestation that has passed signature verification. It carries NOTHING about WHO
    served the bytes -- the authority is the signature, so the resolved evidence is identical
    regardless of the serving party (the third-party re-serve property)."""

    __slots__ = ("binding", "digest", "effect", "audience", "at", "ordering")

    def __init__(self, binding, digest, effect, audience, at, ordering):
        self.binding = binding
        self.digest = bytes(digest)
        self.effect = effect
        self.audience = bytes(audience)
        self.at = at
        self.ordering = ordering


def validate_egress_attestation(a):
    """Performs the semantic, closed-set checks parse_egress_attestation deliberately does not: the
    binding must be in the closed set (UnknownEgressBinding), and -- if present -- the field-6
    ordering disclosure must satisfy its basis-conditioned well-formedness rule
    (UnknownOrderingBasis/OrderingDisclosureMalformed)."""
    if not is_known_binding(a.binding):
        raise GatewayError("UnknownEgressBinding",
                            "egress attestation binding code is outside the closed set content_bound/content_free")
    if a.ordering is not None:
        a.ordering.validate()


def verify_egress_attestation(obj, profile, alg, pubkey):
    """Verifies an egress attestation end-to-end and returns the resolved evidence. It (1) verifies
    the signed object under the profile with real crypto against the GATEWAY's key; (2)
    reconstructs it from the signed bytes; and (3) validates the binding code against the closed
    set (UnknownEgressBinding), and the ordering disclosure if present. It takes NO serving-party
    or connection identity: the authority is the signature over the bytes, so the same `obj` yields
    an identical ResolvedEgressAttestation whether the gateway or an unrelated third party served
    it (the third-party re-serve property). Any failure raises its named error and resolves
    nothing (fail-closed)."""
    prot, payload, sig = cose.parse_sign1_raw(obj)
    halg = alg_from_protected(prot)
    level, known = cose.alg_level(halg)
    if not known:
        raise GatewayError("UnknownAlg", "unregistered alg %d" % halg)
    if level < cose.profile_min_level(profile):
        raise GatewayError("ProfileDowngrade", "signature level below the profile minimum")
    if halg != alg:
        raise GatewayError("KeyAlgMismatch", "alg %d does not match the verifier key alg %d" % (halg, alg))
    tbs = cose.to_be_signed_raw(prot, payload)
    if not cose.cose_verify1_raw(halg, pubkey, tbs, sig):
        raise GatewayError("BadSignature", "signature does not verify")
    a = parse_egress_attestation(payload)
    validate_egress_attestation(a)
    return ResolvedEgressAttestation(a.binding, a.digest, policy.normalize_effect(a.effect), a.audience, a.at, a.ordering)


# ---- content_free commitment open/verify pair --------------------------------------------------

def egress_commit(object_cid, salt):
    """The content_free hiding commitment over an object's T1 content-id and a salt:
    SHA-384(object_cid || salt) (48 octets). The commitment reveals nothing about object_cid
    without the salt; a gateway builds it once to populate a content_free attestation's `digest`
    field, and retains object_cid+salt to later prove which object crossed via
    open_egress_commitment."""
    return hashlib.sha384(bytes(object_cid) + bytes(salt)).digest()


def open_egress_commitment(a, object_cid, salt):
    """Proves which object crossed under a content_free attestation. It recomputes
    egress_commit(object_cid, salt) and compares it, in constant time, against `a.digest`. Returns
    True iff `a` is a content_free attestation AND the recomputed commitment matches: a wrong salt
    or a wrong object_cid both fail to open (return False), and a content_bound attestation never
    opens (its digest is not a commitment)."""
    if a.binding != BINDING_CONTENT_FREE:
        return False
    want = egress_commit(object_cid, salt)
    if len(want) != len(a.digest):
        return False
    return hmac.compare_digest(want, a.digest)
