# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP C5 effect vocabulary and authorization for the Python SDK (§6).

The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an
unrecognized value fails closed to destructive (R-6.2); authorization is the §6.1 lattice
(action <= ceiling). The optional signed safety label is a CBOR map {1:risk, 2:scope}.
"""
from . import cbor
from .cbor import U, T, M

READ_ONLY = 0
IDEMPOTENT_WRITE = 1
NON_IDEMPOTENT_WRITE = 2
DESTRUCTIVE = 3

_NAMES = ["read_only", "idempotent_write", "non_idempotent_write", "destructive"]


def normalize_effect(v: int) -> int:
    """Map a raw effect value to the closed set; anything outside 0..3 is destructive (R-6.2)."""
    return v if 0 <= v <= 3 else DESTRUCTIVE


def safety_label_name(e: int) -> str:
    return _NAMES[normalize_effect(e)]


def authorizes(ceiling: int, action: int) -> bool:
    """The §6.1 lattice: an action of class `action` is permitted under ceiling iff action <= ceiling."""
    return action <= ceiling


def safety_label_bytes(risk: str, scope: str) -> bytes:
    """The signed safety-label body {1: risk, 2: scope} (R-6.4)."""
    return cbor.encode(M([(U(1), T(risk)), (U(2), T(scope))]))


class PolicyError(ValueError):
    """A named, fail-closed C5 policy error; .kind is the stable error kind (§15)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


# PrincipalSource: where a claimed identity came from. Only a signature-derived identity is
# an authorization principal (R-6.5).
SOURCE_SIGNATURE = 0            # the verified COSE signature's signer id
SOURCE_TRANSPORT_METADATA = 1   # e.g. a TLS peer name / connection tag
SOURCE_FOREIGN_HEADER = 2       # e.g. an X-Agent-ID or a carried foreign header
SOURCE_CLIENT_NAME = 3          # e.g. a self-asserted clientInfo.name


def resolve_auth_principal(src: int, presented: str) -> str:
    """Return the authorization principal id iff it is signature-derived and non-empty
    (R-6.5). A transport-metadata, foreign-header, or client-supplied name is refused with
    UnauthenticatedPrincipal -- it is never treated as an authorization identity."""
    if src != SOURCE_SIGNATURE or not presented:
        raise PolicyError(
            "UnauthenticatedPrincipal",
            "an authorization identity must be signature-derived, not transport/foreign/client-asserted",
        )
    return presented


class Grant:
    """A capability an endpoint issues to an authenticated signer id: the most dangerous
    effect that principal is permitted to carry. The default max_effect (READ_ONLY) is the
    least-privilege default, so a bare Grant(principal) authorizes only read_only."""

    __slots__ = ("principal", "max_effect")

    def __init__(self, principal: str, max_effect: int = READ_ONLY):
        self.principal = principal
        self.max_effect = max_effect

    def authorize_object(self, src: int, presented: str, object_effect: int) -> None:
        """The endpoint policy check that makes the effect an authorization input, not a
        hint (R-6.3). It (1) resolves the presenter's identity, refusing any non-signature
        source (R-6.5); (2) requires that identity to match the grant's principal -- no
        matching grant means no authority; (3) normalizes the object's effect fail-closed
        (R-6.2) and denies it if it exceeds the grant's ceiling. It performs no side effect
        and raises a named PolicyError on any failure (fail-closed)."""
        who = resolve_auth_principal(src, presented)
        if who != self.principal:
            raise PolicyError("EffectNotAuthorized", "object effect exceeds the granted capability")
        if not authorizes(self.max_effect, normalize_effect(object_effect)):
            raise PolicyError("EffectNotAuthorized", "object effect exceeds the granted capability")
        return None


# SAFETY_LABEL_EXT_KEY is the non-critical ext key under which the optional safety label is
# carried (ext[1], design.md §6.4). Recorded in vectors/registry (T14).
SAFETY_LABEL_EXT_KEY = 1


class SafetyLabel:
    """The OPTIONAL signed safety annotation (R-6.4). It is attributable to the object's
    signer and auditable. It is an ACCOUNTABLE CLAIM, not a guarantee the content is safe
    (design.md §6.4; stated in the security considerations, T15)."""

    __slots__ = ("risk", "scope")

    def __init__(self, risk: str, scope: str):
        self.risk = str(risk)    # an accountable risk claim, e.g. "elevated"
        self.scope = str(scope)  # what the object affects, e.g. "billing-records"

    def __eq__(self, other):
        return isinstance(other, SafetyLabel) and self.risk == other.risk and self.scope == other.scope

    def __repr__(self):
        return "SafetyLabel(risk=%r, scope=%r)" % (self.risk, self.scope)

    def to_value(self) -> M:
        """The safety label's CBOR map {1: risk, 2: scope}."""
        return M([(U(1), T(self.risk)), (U(2), T(self.scope))])

    def encode(self) -> bytes:
        """The deterministic-CBOR bytes of the safety-label map."""
        return cbor.encode(self.to_value())

    def ext(self) -> M:
        """An ext map carrying only this safety label, ready to place in an object's field 11
        (or merge into an existing ext map)."""
        return M([(U(SAFETY_LABEL_EXT_KEY), self.to_value())])


def safety_label_from_ext(ext):
    """Extract the optional safety label from an object's ext map (a cbor.M, or None when the
    object carries no ext). Returns (label, True) when a well-formed label is present,
    (None, False) when absent, and raises PolicyError('MalformedSafetyLabel') when the
    ext[1] entry is present but not exactly {1:tstr, 2:tstr} -- a malformed label is
    rejected, never silently accepted."""
    if ext is None:
        return None, False
    for k, v in ext.pairs:
        if not (isinstance(k, U) and k.v == SAFETY_LABEL_EXT_KEY):
            continue
        if not isinstance(v, M):
            raise PolicyError("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
        risk, scope = None, None
        have_risk, have_scope = False, False
        for kk, vv in v.pairs:
            if not isinstance(kk, U):
                raise PolicyError("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
            if not isinstance(vv, T):
                raise PolicyError("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
            if kk.v == 1:
                risk, have_risk = vv.v, True
            elif kk.v == 2:
                scope, have_scope = vv.v, True
            else:
                raise PolicyError("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
        if not have_risk or not have_scope:
            raise PolicyError("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
        return SafetyLabel(risk, scope), True
    return None, False
