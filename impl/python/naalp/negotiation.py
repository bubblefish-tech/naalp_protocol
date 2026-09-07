# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C20 governed negotiation, advisory risk labels, and trust references for the Python SDK
(design.md §23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4).

C20 adds three signed surfaces carried on N-AALP's own signed object; it introduces NO new
envelope, encoding, signature, identity, or audit mechanism (R-11.3). Each object is an ordinary
signed N-AALP body reusing the closed C5 effect lattice (policy), the T1 content-id framing (§2.3),
and the §8.2 causal partial order (`causes`) UNCHANGED.

  - Task 5.1 governed negotiation: a Message {1:negotiation, 2:role, 3:profile, 4:causes[]} is one
    signed step -- an OFFER, a COUNTER, or an ACCEPT -- causally linked to its predecessor(s) by
    content-id, selecting a profile from a CLOSED pre-registered set (no free-form/runtime
    capability). An ACCEPT MUST DESCEND from its offer by walking the `causes` DAG (verify_accept),
    else it is rejected (NotDescended). An unknown profile/role is rejected.
  - Task 5.2 advisory risk labels: a RiskLabel {1:code, 2:critical} + a LabeledObject
    {1:effect, 2:labels[]}. The R-2.5 critical-extension rule applies (an unknown CRITICAL label is
    rejected, an unknown non-critical one is ignored). LOAD-BEARING invariant: carrying a risk label
    NEVER changes an object's effect class -- effect_class derives from field 1 (the effect) ALONE.
  - Task 5.3 trust references: a TrustRef {1:registry, 2:reference, 3:subject} carries a third-party
    trust statement as a CHECKABLE signed object -- verify_trust_ref recomputes the referenced
    content-id over the external record. NO wire field weighs it: there is no score/rank/ordering and
    no scoring function, by design.

Every check is fail-closed (§15). Ported from impl/go/negotiation; graded against
vectors/negotiation/cases.json. The Message/LabeledObject/TrustRef signatures are real deterministic
ML-DSA-65 (COSE_Sign1) but not corpus-graded.
"""
import hashlib

from . import cbor, cose, policy
from .cbor import U, B, A, M

# HeadSize is the width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 chain.
HEAD_SIZE = 48


class NegotiationError(ValueError):
    """A named, fail-closed C20 error; .kind is the stable error kind (§15)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def _head(b):
    """SHA-384 over a body -- a 48-octet digest (the same construction as audit head)."""
    return hashlib.sha384(bytes(b)).digest()


def _content_id(b):
    """T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets)."""
    return cbor.content_id(bytes(b))


# ==== Task 5.1 -- governed negotiation =========================================================

ROLE_OFFER = 0    # the initiating offer (root of a negotiation; no causes)
ROLE_COUNTER = 1  # a counter-offer chaining onto the offer or a prior counter
ROLE_ACCEPT = 2   # the accept; it MUST descend from its offer

_ROLE_NAMES = {ROLE_OFFER: "offer", ROLE_COUNTER: "counter", ROLE_ACCEPT: "accept"}


def known_role(r):
    """Whether r is one of the three defined negotiation roles."""
    return r in _ROLE_NAMES


def role_name(r):
    """The role name, or 'unknown' for an out-of-range code."""
    return _ROLE_NAMES.get(r, "unknown")


PROFILE_BASELINE = 0   # the baseline capability profile
PROFILE_STREAMING = 1  # the native-streaming capability profile (C9)
PROFILE_BATCH = 2      # the batched-delivery capability profile

_PROFILE_NAMES = {PROFILE_BASELINE: "baseline", PROFILE_STREAMING: "streaming", PROFILE_BATCH: "batch"}


def is_registered_profile(p):
    """Whether p is one of the pre-registered profiles (the closed set)."""
    return p in _PROFILE_NAMES


def profile_name(p):
    """The profile name, or 'unknown' for an unregistered code."""
    return _PROFILE_NAMES.get(p, "unknown")


class Message:
    """One signed step of a governed negotiation: an offer, a counter, or an accept. It is causally
    linked to its predecessor(s) by content-id in `causes` (empty for an offer) and SELECTS a
    pre-registered profile."""

    __slots__ = ("negotiation", "role", "profile", "causes")

    def __init__(self, negotiation, role, profile, causes=None):
        self.negotiation = bytes(negotiation)
        self.role = int(role)
        self.profile = int(profile)
        self.causes = [bytes(c) for c in (causes or [])]

    def bytes(self):
        """Deterministic-CBOR encoding {1: negotiation, 2: role, 3: profile, 4: causes[]}."""
        return cbor.encode(M([
            (U(1), B(self.negotiation)),
            (U(2), U(self.role)),
            (U(3), U(self.profile)),
            (U(4), A([B(c) for c in self.causes])),
        ]))

    def head(self):
        """The Message's SHA-384 head (48 octets)."""
        return _head(self.bytes())

    def id(self):
        """The Message's T1 content-id (50 octets) -- the id a successor names in its causes."""
        return _content_id(self.bytes())


def new_offer(negotiation, profile):
    """Build an offer (the root of a negotiation): role offer, no causes."""
    return Message(negotiation, ROLE_OFFER, profile, [])


def new_counter(negotiation, profile, predecessor_id):
    """Build a counter chaining onto the predecessor named by predecessor_id."""
    return Message(negotiation, ROLE_COUNTER, profile, [predecessor_id])


def new_accept(negotiation, profile, predecessor_id):
    """Build an accept chaining onto the predecessor named by predecessor_id."""
    return Message(negotiation, ROLE_ACCEPT, profile, [predecessor_id])


def parse_message(b):
    """Reconstruct a Message from its body bytes alone. It does NOT validate the role or profile
    against the closed sets (that is verify_message's job), so a message carrying an unknown role or
    profile can be represented and then rejected. Fail-closed (NegMalformed) on any malformed shape,
    a non-canonical body, or a mistyped field."""
    m = _decode_map(b)
    if m is None:
        raise NegotiationError("NegMalformed", "object is not a well-formed negotiation body")
    neg = _bstr_field(m, 1)
    role = _uint_field(m, 2)
    prof = _uint_field(m, 3)
    causes_v = _field(m, 4)
    if neg is None or role is None or prof is None or causes_v is None or not isinstance(causes_v, A):
        raise NegotiationError("NegMalformed", "object is not a well-formed negotiation body")
    causes = []
    for e in causes_v.items:
        if not isinstance(e, B):
            raise NegotiationError("NegMalformed", "cause is not a bstr")
        causes.append(e.v)
    return Message(neg, role, prof, causes)


def sign_message(m, alg, seed):
    """The tagged COSE_Sign1 over the Message body (real deterministic ML-DSA)."""
    return cose.cose_sign1(alg, seed, _protected_header(alg), m.bytes())


def verify_message(obj, profile, alg, pubkey):
    """Verify the Message's full signature, reconstruct it from the signed body bytes, and validate
    it against the closed sets: the role MUST be offer/counter/accept (UnknownRole) and the selected
    profile MUST be pre-registered (UnknownProfile). Fail-closed."""
    m = _verify_body(obj, alg, pubkey)
    msg = parse_message(m)
    if not known_role(msg.role):
        raise NegotiationError("UnknownRole", "negotiation message role is not offer/counter/accept")
    if not is_registered_profile(msg.profile):
        raise NegotiationError("UnknownProfile", "negotiation selects a profile outside the closed set")
    return msg


def index_by_id(msgs):
    """Build the content-id -> Message index the descent walk resolves predecessors through."""
    return {m.id(): m for m in msgs}


def descends(from_msg, target_id, by_id):
    """Whether `from_msg` reaches target_id by following causes edges resolved through by_id: a real
    reachability walk over the causal DAG. A cause that cannot be resolved through by_id cannot extend
    the chain, so a forged causes pointer to an id the verifier never saw does not manufacture descent.
    Fail-closed."""
    target = bytes(target_id)
    seen = set()
    stack = list(from_msg.causes)
    while stack:
        cid = stack.pop()
        if cid == target:
            return True
        if cid in seen:
            continue
        seen.add(cid)
        pred = by_id.get(cid)
        if pred is None:
            continue  # an unresolved cause: the chain cannot be walked through it
        stack.extend(pred.causes)
    return False


def descends_msg(accept, offer, by_id):
    """Whether `accept` descends from `offer` by walking the causes DAG through by_id (a counter or a
    chain of counters between them is traversed). Performs no signature check."""
    return descends(accept, offer.id(), by_id)


def verify_accept(accept, offer, by_id):
    """Check an accept against its offer over a set of verified messages, fail-closed. It requires
    `offer` to be a genuine offer selecting a pre-registered profile (NotOffer / UnknownProfile),
    `accept` to be an accept selecting a pre-registered profile (NotAccept / UnknownProfile), and the
    accept to DESCEND from the offer (NotDescended otherwise). Returns the AGREED profile. It
    authorizes nothing; it accepts or rejects."""
    if offer.role != ROLE_OFFER:
        raise NegotiationError("NotOffer", "the object presented as the offer is not an offer role")
    if not is_registered_profile(offer.profile):
        raise NegotiationError("UnknownProfile", "offer selects a profile outside the closed set")
    if accept.role != ROLE_ACCEPT:
        raise NegotiationError("NotAccept", "the object presented as the accept is not an accept role")
    if not is_registered_profile(accept.profile):
        raise NegotiationError("UnknownProfile", "accept selects a profile outside the closed set")
    if not descends_msg(accept, offer, by_id):
        raise NegotiationError("NotDescended", "accept does not descend from its offer along the causes chain")
    return accept.profile


# ==== Task 5.2 -- advisory risk labels =========================================================

CLASS_INFORMING = 0  # purely informational
CLASS_GATING = 1     # a policy MAY require an additional gate when this label is present

_RISK_CLASS_NAMES = {CLASS_INFORMING: "informing", CLASS_GATING: "gating"}


def risk_class_name(c):
    """The class name ('gating'/'informing'), or '' for an out-of-range value."""
    return _RISK_CLASS_NAMES.get(c, "")


RISK_SENSITIVE = 1   # gating: the object touches sensitive material
RISK_EGRESS = 2      # gating: the object causes data egress
RISK_REVERSIBLE = 3  # informing: the object's effect is reversible

# ExtensibleRangeStart is the first code of the private/experimental extensible range. A code at or
# above it is unknown to a verifier that lacks it: carried critical it is rejected (R-2.5), carried
# non-critical it is ignored.
EXTENSIBLE_RANGE_START = 0x1000

# The closed standard risk-label vocabulary: code -> class.
_RISK_VOCAB = {
    RISK_SENSITIVE: CLASS_GATING,
    RISK_EGRESS: CLASS_GATING,
    RISK_REVERSIBLE: CLASS_INFORMING,
}


def risk_class_of(code):
    """A code's vocabulary class and whether the code is a registered standard label."""
    if code in _RISK_VOCAB:
        return _RISK_VOCAB[code], True
    return CLASS_INFORMING, False


def is_registered_risk(code):
    """Whether code is in the closed standard vocabulary."""
    return code in _RISK_VOCAB


def in_extensible_range(code):
    """Whether code lies in the private/experimental extensible range."""
    return code >= EXTENSIBLE_RANGE_START


class RiskLabel:
    """One advisory risk label carried on an object. `code` is the label code; `critical` is the
    per-carriage must-understand flag (1 = critical, 0 = advisory) -- the uint 1/0, no CBOR boolean."""

    __slots__ = ("code", "critical")

    def __init__(self, code, critical):
        self.code = int(code)
        self.critical = int(critical)

    def is_critical(self):
        """Whether the label is carried critical (must-understand)."""
        return self.critical == 1

    def to_map(self):
        """The label's CBOR map {1: code, 2: critical}."""
        return M([(U(1), U(self.code)), (U(2), U(self.critical))])

    def bytes(self):
        """Deterministic-CBOR encoding of the risk-label body."""
        return cbor.encode(self.to_map())


def _risk_label_from_value(v):
    """Parse one risk-label map, rejecting a malformed shape (NegMalformed) or a critical flag outside
    {0,1} (MalformedCriticalFlag). Fail-closed."""
    if not isinstance(v, M):
        raise NegotiationError("NegMalformed", "risk label is not a map")
    code = _uint_field(v, 1)
    crit = _uint_field(v, 2)
    if code is None or crit is None:
        raise NegotiationError("NegMalformed", "risk label missing a field")
    if crit > 1:
        raise NegotiationError("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}")
    return RiskLabel(code, crit)


def validate_labels(labels):
    """Apply the critical-extension rule (R-2.5) to a set of carried risk labels: return the RECOGNIZED
    (standard-vocabulary) labels, DROP unknown non-critical labels, and REJECT an unknown CRITICAL
    label (UnknownCriticalRisk). A critical flag outside {0,1} is MalformedCriticalFlag. It NEVER
    inspects or returns an effect -- risk labels are an advisory dimension, never a fifth effect.
    Fail-closed."""
    recognized = []
    for l in labels:
        if l.critical > 1:
            raise NegotiationError("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}")
        if is_registered_risk(l.code):
            recognized.append(l)
            continue
        if l.is_critical():
            raise NegotiationError("UnknownCriticalRisk", "an unknown critical risk label is rejected (R-2.5)")
        # unknown non-critical: ignored (dropped from the recognized set)
    return recognized


class LabeledObject:
    """A minimal N-AALP object carrying an effect (field 1, C5) and a set of advisory risk labels. It
    exists to demonstrate -- provably, in isolation -- the load-bearing invariant that carrying a risk
    label NEVER changes the object's effect class."""

    __slots__ = ("effect", "labels")

    def __init__(self, effect, labels=None):
        self.effect = int(effect)
        self.labels = list(labels or [])

    def bytes(self):
        """Deterministic-CBOR encoding {1: effect, 2: labels[]}."""
        return cbor.encode(M([
            (U(1), U(self.effect)),
            (U(2), A([l.to_map() for l in self.labels])),
        ]))

    def head(self):
        """The LabeledObject's SHA-384 head (48 octets)."""
        return _head(self.bytes())

    def id(self):
        """The LabeledObject's T1 content-id (50 octets)."""
        return _content_id(self.bytes())

    def effect_class(self):
        """The object's C5 effect class, derived from the effect field (field 1) ALONE and normalized
        fail-closed (unknown -> destructive, R-6.2). It DELIBERATELY does not consult the risk labels:
        a risk label is an advisory dimension, never a fifth effect, so the closed lattice is untouched
        by any label the object carries. This is the load-bearing C20 invariant."""
        return policy.normalize_effect(self.effect)

    def validate_labels(self):
        """Apply the critical-extension rule to the object's carried labels."""
        return validate_labels(self.labels)


def parse_labeled_object(b):
    """Reconstruct a LabeledObject from its body bytes alone. Fail-closed (NegMalformed) on a malformed
    shape; a critical flag outside {0,1} is MalformedCriticalFlag."""
    m = _decode_map(b)
    if m is None:
        raise NegotiationError("NegMalformed", "object is not a well-formed labeled-object body")
    eff = _uint_field(m, 1)
    labels_v = _field(m, 2)
    if eff is None or labels_v is None or not isinstance(labels_v, A):
        raise NegotiationError("NegMalformed", "object is not a well-formed labeled-object body")
    labels = [_risk_label_from_value(e) for e in labels_v.items]
    return LabeledObject(eff, labels)


def sign_labeled_object(o, alg, seed):
    """The tagged COSE_Sign1 over the LabeledObject body (real deterministic ML-DSA)."""
    return cose.cose_sign1(alg, seed, _protected_header(alg), o.bytes())


def verify_labeled_object(obj, profile, alg, pubkey):
    """Verify the signature, reconstruct the object, and apply the critical-extension rule to its labels
    (an unknown critical label is rejected). Returns (object, recognized_labels). The returned object's
    effect_class is unchanged by any label. Fail-closed."""
    payload = _verify_body(obj, alg, pubkey)
    o = parse_labeled_object(payload)
    recognized = validate_labels(o.labels)
    return o, recognized


# ==== Task 5.3 -- trust references (checkable, never weighed) ==================================

class TrustRef:
    """A third-party trust statement carried as a CHECKABLE signed object. `registry` is an opaque
    external-registry identifier (an ERC-8004-style reputation/identity registry -- a name, not a URL
    the wire resolves); `reference` is the T1 content-id of the referenced external record; `subject`
    is the opaque id the statement is about. The wire CARRIES the reference; NO field here weighs it --
    there is no score, rank, or ordering."""

    __slots__ = ("registry", "reference", "subject")

    def __init__(self, registry, reference, subject):
        self.registry = bytes(registry)
        self.reference = bytes(reference)
        self.subject = bytes(subject)

    def bytes(self):
        """Deterministic-CBOR encoding {1: registry, 2: reference, 3: subject}."""
        return cbor.encode(M([
            (U(1), B(self.registry)),
            (U(2), B(self.reference)),
            (U(3), B(self.subject)),
        ]))

    def head(self):
        """The TrustRef's SHA-384 head (48 octets)."""
        return _head(self.bytes())

    def id(self):
        """The TrustRef's own T1 content-id (50 octets)."""
        return _content_id(self.bytes())

    def reference_id(self):
        """The content-id the trust ref binds (the carried external-record reference)."""
        return bytes(self.reference)

    def binds_record(self, record):
        """Whether the carried reference is the T1 content-id of `record` -- i.e. the reference
        recomputes over the presented external bytes. This is the CHECK a relying party runs to confirm
        the reference names those exact external bytes; it computes NO score. A changed record yields a
        different content-id, so binds_record returns False."""
        return self.reference == _content_id(record)


def parse_trust_ref(b):
    """Reconstruct a TrustRef from its body bytes alone. Fail-closed (NegMalformed)."""
    m = _decode_map(b)
    if m is None:
        raise NegotiationError("NegMalformed", "object is not a well-formed trust-ref body")
    reg = _bstr_field(m, 1)
    ref = _bstr_field(m, 2)
    subj = _bstr_field(m, 3)
    if reg is None or ref is None or subj is None:
        raise NegotiationError("NegMalformed", "object is not a well-formed trust-ref body")
    return TrustRef(reg, ref, subj)


def sign_trust_ref(r, alg, seed):
    """The tagged COSE_Sign1 over the TrustRef body (real deterministic ML-DSA)."""
    return cose.cose_sign1(alg, seed, _protected_header(alg), r.bytes())


class ResolvedTrustRef:
    """A TrustRef that has passed signature verification and (given the external record) the content-id
    recompute. It carries NO score, rank, or trust weight -- the protocol does not weigh trust; which
    statement to believe is left to the relying party."""

    __slots__ = ("registry", "reference", "subject")

    def __init__(self, registry, reference, subject):
        self.registry = bytes(registry)
        self.reference = bytes(reference)
        self.subject = bytes(subject)


def verify_trust_ref(obj, profile, alg, pubkey, external_record):
    """Verify a trust reference end-to-end: (1) verify the signed object with real crypto
    (BadSignature); (2) reconstruct it from the signed bytes; and (3) confirm the reference by
    RECOMPUTING the external record's content-id and requiring it to equal the carried reference
    (ReferenceMismatch otherwise). Returns the resolved reference -- and NOTHING that scores it: this
    module has no trust-weighting function, by design. Fail-closed."""
    payload = _verify_body(obj, alg, pubkey)
    r = parse_trust_ref(payload)
    if not r.binds_record(external_record):
        raise NegotiationError("ReferenceMismatch", "trust-ref reference does not recompute over the record")
    return ResolvedTrustRef(r.registry, r.reference, r.subject)


# ---- full-signature helpers (real ML-DSA COSE_Sign1, demonstrated in isolation) ---------------

def _protected_header(alg):
    """The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int)."""
    from .cbor import N
    return cbor.encode(M([(U(1), N(alg))]))


def _verify_body(obj, alg, pubkey):
    """Verify a tagged COSE_Sign1 object's full signature and return its signed payload bytes.
    Fail-closed (BadSignature)."""
    prot, payload, sig = cose.parse_sign1_raw(obj)
    tbs = cose.to_be_signed_raw(prot, payload)
    if not cose.cose_verify1_raw(alg, pubkey, tbs, sig):
        raise NegotiationError("BadSignature", "signature does not verify")
    return payload


# ---- small deterministic-CBOR field accessors ------------------------------------------------

def _decode_map(b):
    """Strict-canonical decode to a CBOR map, or None on any decode error / non-map (mirrors the Go
    decodeMap ok=false path; a non-canonical body decodes to None -> NegMalformed at the call site)."""
    try:
        v = cbor.decode(bytes(b))
    except cbor.NonCanonical:
        return None
    return v if isinstance(v, M) else None


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
