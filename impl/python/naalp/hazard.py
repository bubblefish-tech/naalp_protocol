# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Manufacturing Add-ons Component F, the physical-hazard authorization extension (design.md
addendum; requirements F1-F5; wire authority `spec/naalp-draft-01.cddl`), Python port of
impl/rust/naalp-hazard/src/lib.rs
(mirroring impl/csharp/Hazard.cs, impl/java/.../Hazard.java, impl/php/src/Hazard.php, and
impl/ruby/lib/naalp/hazard.rb).

STATUS: FROZEN 2026-09-01 (Shawn-approved wire bytes). The `naalp-hazard-claim` (critical
`cext` key 16) and `naalp-hazard-authorization` (Governance `0x0004` kind 7) productions are
merged into the normative `spec/naalp-draft-01.cddl` `naalp-artifact` reachability root; the
channel kind is registered in `vectors/registry/channels.csv`, the ext key in
`extension-keys.csv`, and the three error codes (130/131/132) in `error-codes.csv`. This
module is the Python port of the byte-authority Rust reference, graded in isolation against
the frozen `vectors/hazard` corpus.

`effect` (Envelope field 7, `naalp.policy`) describes DATA reversibility. `hazard` is a new,
ORTHOGONAL dimension describing PHYSICAL danger: a data-reversible action may still be a high
physical hazard. The two dimensions are never merged and neither derives the other.

This module adds no new cryptography and no new CBOR codec of its own: every encode call
delegates to `naalp.cbor.encode` / `naalp.cbor.content_id`, exactly as the Rust reference crate
adds no crypto/encoding of its own over the graded `naalp` core.

The fail-closed rules (F2, F3):
  - `from_code` is the ONE fail-closed decode entry point: any missing or out-of-range raw
    value normalizes to MOTION_IN_SHARED_SPACE -- the highest class -- never to "absent" or
    any weaker class.
  - `hazard_authorized` requires an EXACT class match (not a <= ceiling the way the effect
    lattice's `naalp.policy.authorizes` works) AND full containment of the claim's envelope
    inside the grant's on every axis, the speed bound, and the time window. Any single failing
    dimension denies the WHOLE claim -- there is no partial authorization.
  - `hazard_authorized_optional` additionally covers the case where an action carries NO
    hazard claim at all: there is no envelope to check containment against, so it denies
    immediately with a distinct error (HazardUnknown) rather than fabricating a sentinel
    envelope and running the ordinary coverage check.
"""
from . import cbor, identity
from .cbor import A, M, N, T, U


class HazardError(ValueError):
    """Base class for the three named, fail-closed Component F errors; .kind is the stable
    error kind (matches the CDDL error-codes registry entries 130/131/132)."""

    kind = "HazardError"

    def __init__(self, msg=""):
        super().__init__("%s: %s" % (self.kind, msg) if msg else self.kind)


class HazardMalformed(HazardError):
    """(130) a hazard-claim/hazard-authorization/envelope body is not the
    spec/naalp-draft-01.cddl shape, a spatial-bounds axis has min > max, axes is empty, or
    frame is not Unicode NFC."""

    kind = "HazardMalformed"

    def __init__(self, msg="hazard body is not the spec/naalp-draft-01.cddl shape, or an axis/frame is invalid"):
        super().__init__(msg)


class HazardNotCovered(HazardError):
    """(131, design's E_HAZARD_UNCOV) a well-formed claim's class or envelope is not fully
    covered by the presented authorization."""

    kind = "HazardNotCovered"

    def __init__(self, msg="declared hazard class or envelope is not fully covered by the authorization"):
        super().__init__(msg)


class HazardUnknown(HazardError):
    """(132, design's E_HAZARD_UNKNOWN) the hazard value for an action requiring one is
    unrecognized or absent, and -- for the fully-absent case -- no envelope exists to check
    coverage against at all."""

    kind = "HazardUnknown"

    def __init__(self, msg="hazard value unrecognized or absent; no claim to check coverage against"):
        super().__init__(msg)


# ---- hazard-class (F2: closed, fail-closed to the highest class) --------------------------

# The closed five-value hazard-class vocabulary (`spec/naalp-draft-01.cddl`).
# MOTION_IN_SHARED_SPACE is BOTH a named class (4) and the fail-closed default for an
# unrecognized or absent raw value (F2) -- the assumption that "the producer did not tell us"
# is at least as dangerous as the worst named class.
NONE = 0
TOOL_ACTUATION = 1
THERMAL = 2
ENERGY_RELEASE = 3
MOTION_IN_SHARED_SPACE = 4

_CLASS_NAMES = {
    NONE: "none",
    TOOL_ACTUATION: "tool_actuation",
    THERMAL: "thermal",
    ENERGY_RELEASE: "energy_release",
    MOTION_IN_SHARED_SPACE: "motion_in_shared_space",
}


def from_code(code):
    """Fail-closed decode (F2). `None` (the raw value was absent) or any value outside 0..4
    (unrecognized) normalizes to MOTION_IN_SHARED_SPACE -- never to a weaker class, and never a
    decode failure (there is no "invalid hazard" outcome; there is only "the worst case we must
    assume"). `code` carries the raw wire integer as a plain Python int -- Python ints are
    arbitrary-precision, so a malformed wire value far beyond even a u64 still normalizes
    correctly rather than raising or wrapping."""
    if code is not None and NONE <= code <= MOTION_IN_SHARED_SPACE:
        return code
    return MOTION_IN_SHARED_SPACE  # F2: unknown/absent -> highest class


def class_name(hazard_class):
    """The CDDL-registered name for a closed hazard-class value (KeyError on an out-of-range
    input -- callers pass a value already normalized by from_code)."""
    return _CLASS_NAMES[hazard_class]


def _class_to_value(hazard_class):
    return U(hazard_class)


# ---- spatial-bounds ----------------------------------------------------------------------

def _int_value(v):
    return U(v) if v >= 0 else N(v)


def _int_from_value(v):
    if isinstance(v, U):
        return v.v
    if isinstance(v, N):
        return v.v
    raise HazardMalformed()


class SpatialBounds:
    """A named coordinate frame plus a signed axis-aligned bounding region in that frame,
    integer millimeters (`spec/naalp-draft-01.cddl` `spatial-bounds`).

    `axes` is a list of `(min, max)` int pairs, millimeters, signed. MUST be non-empty; every
    entry MUST satisfy `min <= max`."""

    __slots__ = ("frame", "axes")

    def __init__(self, frame, axes):
        self.frame = frame
        self.axes = [tuple(a) for a in axes]

    def is_well_formed(self):
        """Structural validity (`spec/naalp-draft-01.cddl`): non-empty axes, every min <= max,
        frame non-empty and Unicode NFC."""
        if not self.axes:
            return False
        if any(mn > mx for mn, mx in self.axes):
            return False
        if not self.frame:
            return False
        try:
            identity.require_nfc(self.frame)
        except identity.NonNFC:
            return False
        return True

    def to_value(self):
        axes = A([A([_int_value(mn), _int_value(mx)]) for mn, mx in self.axes])
        return M([(U(1), T(self.frame)), (U(2), axes)])

    def bytes(self):
        """Deterministic-CBOR encoding of {1:frame,2:axes}. Malformed input still encodes
        (encoding is not the validity gate); callers MUST check is_well_formed() before
        treating a SpatialBounds as authoritative, exactly as from_value() does on decode."""
        return cbor.encode(self.to_value())

    @staticmethod
    def from_value(v):
        """Parse a `spatial-bounds` map. Rejects a non-map, an out-of-range/wrong-typed key or
        value, a missing key, empty axes, an axis with min > max, or a non-NFC/empty frame --
        fail-closed (HazardMalformed), never a partially-valid result."""
        if not isinstance(v, M):
            raise HazardMalformed()
        frame = None
        axes = None
        for k, val in v.pairs:
            if not isinstance(k, U):
                raise HazardMalformed()
            if k.v == 1:
                if not isinstance(val, T):
                    raise HazardMalformed()
                frame = val.v
            elif k.v == 2:
                if not isinstance(val, A) or not val.items:
                    raise HazardMalformed()
                out = []
                for it in val.items:
                    if not isinstance(it, A) or len(it.items) != 2:
                        raise HazardMalformed()
                    mn = _int_from_value(it.items[0])
                    mx = _int_from_value(it.items[1])
                    if mn > mx:
                        raise HazardMalformed()
                    out.append((mn, mx))
                axes = out
            else:
                raise HazardMalformed()
        if frame is None or axes is None:
            raise HazardMalformed()
        sb = SpatialBounds(frame, axes)
        if not sb.is_well_formed():
            raise HazardMalformed()
        return sb


def spatial_contained(claim, grant):
    """Full containment (F3): same frame id (a bound in one frame says nothing about a bound
    in a different, unrelated frame), the SAME axis count in the SAME order, and every claim
    axis's [min,max] a subset of the matching grant axis's [min,max]."""
    if claim.frame != grant.frame:
        return False
    if len(claim.axes) != len(grant.axes):
        return False
    for (cmin, cmax), (gmin, gmax) in zip(claim.axes, grant.axes):
        if not (cmin >= gmin and cmax <= gmax):
            return False
    return True


# ---- hazard-window -------------------------------------------------------------------------

class HazardWindow:
    """A validity window, epoch ms, the same convention as `naalp-object` field 6 (created)
    and `naalp-delegation-grant` fields 4/5."""

    __slots__ = ("not_before", "not_after")

    def __init__(self, not_before, not_after):
        self.not_before = not_before
        self.not_after = not_after

    def to_value(self):
        return M([(U(1), U(self.not_before)), (U(2), U(self.not_after))])

    @staticmethod
    def from_value(v):
        if not isinstance(v, M):
            raise HazardMalformed()
        not_before = None
        not_after = None
        for k, val in v.pairs:
            if not isinstance(k, U) or not isinstance(val, U):
                raise HazardMalformed()
            if k.v == 1:
                not_before = val.v
            elif k.v == 2:
                not_after = val.v
            else:
                raise HazardMalformed()
        if not_before is None or not_after is None:
            raise HazardMalformed()
        return HazardWindow(not_before, not_after)


# ---- hazard-envelope -----------------------------------------------------------------------

class HazardEnvelope:
    """The full physical envelope a claim or an authorization bounds itself by. All three
    fields are MANDATORY on the wire (`spec/naalp-draft-01.cddl`) -- a silently-absent axis
    would be fail-OPEN in a physical-safety context, so an issuer that means "unbounded" states
    so explicitly with wide numeric bounds; the wire never infers permissiveness from silence
    here (deliberate contrast with `naalp-delegation-grant`'s optional scope)."""

    __slots__ = ("spatial", "speed_bound_mm_s", "window")

    def __init__(self, spatial, speed_bound_mm_s, window):
        self.spatial = spatial
        self.speed_bound_mm_s = speed_bound_mm_s
        self.window = window

    def to_value(self):
        return M([
            (U(1), self.spatial.to_value()),
            (U(2), U(self.speed_bound_mm_s)),
            (U(3), self.window.to_value()),
        ])

    def bytes(self):
        """Deterministic-CBOR encoding of {1:spatial,2:speed_bound,3:window}."""
        return cbor.encode(self.to_value())

    def content_id(self):
        """The envelope's content id (T1 framing): a pure function of the bytes above."""
        return cbor.content_id(self.to_value())

    @staticmethod
    def from_value(v):
        """Parse a `hazard-envelope` map; fail-closed on any missing/malformed field."""
        if not isinstance(v, M):
            raise HazardMalformed()
        spatial = None
        speed = None
        window = None
        for k, val in v.pairs:
            if not isinstance(k, U):
                raise HazardMalformed()
            if k.v == 1:
                spatial = SpatialBounds.from_value(val)
            elif k.v == 2:
                if not isinstance(val, U):
                    raise HazardMalformed()
                speed = val.v
            elif k.v == 3:
                window = HazardWindow.from_value(val)
            else:
                raise HazardMalformed()
        if spatial is None or speed is None or window is None:
            raise HazardMalformed()
        return HazardEnvelope(spatial, speed, window)


def envelope_contained(claim, grant):
    """Full containment (F3): spatial_contained() AND claim.speed_bound_mm_s <=
    grant.speed_bound_mm_s AND the claim's window is a sub-interval of the grant's
    (grant.not_before <= claim.not_before and claim.not_after <= grant.not_after)."""
    return (
        spatial_contained(claim.spatial, grant.spatial)
        and claim.speed_bound_mm_s <= grant.speed_bound_mm_s
        and grant.window.not_before <= claim.window.not_before
        and claim.window.not_after <= grant.window.not_after
    )


# ---- naalp-hazard-claim / naalp-hazard-authorization ----------------------------------------

def _body_to_value(hazard_class, envelope):
    return M([(U(1), _class_to_value(hazard_class)), (U(2), envelope.to_value())])


def _body_from_value(v):
    if not isinstance(v, M):
        raise HazardMalformed()
    class_code = None
    envelope = None
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise HazardMalformed()
        if k.v == 1:
            # An out-of-range class ON THE WIRE (not merely "absent") is a malformed body, not
            # a normalize-to-4 input: F2's fail-closed normalization is for the DECODE step
            # that produces a class from a less-structured source (see from_code), not for a
            # CDDL-invalid hazard-class value already claiming to be well-formed.
            if not isinstance(val, U) or not (NONE <= val.v <= MOTION_IN_SHARED_SPACE):
                raise HazardMalformed()
            class_code = val.v
        elif k.v == 2:
            envelope = HazardEnvelope.from_value(val)
        else:
            raise HazardMalformed()
    if class_code is None or envelope is None:
        raise HazardMalformed()
    return from_code(class_code), envelope


class HazardClaim:
    """A signed physical-hazard claim (`spec/naalp-draft-01.cddl` `naalp-hazard-claim`).
    Carriage (the object it accompanies and how) is a wire-impact decision, not this module's
    concern."""

    __slots__ = ("hazard_class", "envelope")

    def __init__(self, hazard_class, envelope):
        self.hazard_class = hazard_class
        self.envelope = envelope

    def to_value(self):
        return _body_to_value(self.hazard_class, self.envelope)

    def bytes(self):
        """Deterministic-CBOR encoding of {1:class,2:envelope}."""
        return cbor.encode(self.to_value())

    def content_id(self):
        """The claim's content id (T1 framing)."""
        return cbor.content_id(self.to_value())

    @staticmethod
    def from_value(v):
        """Parse a `naalp-hazard-claim` body. Both class and envelope are mandatory -- a claim
        declaring one and omitting the other is HazardMalformed, not partially valid."""
        hazard_class, envelope = _body_from_value(v)
        return HazardClaim(hazard_class, envelope)


class HazardAuthorization:
    """A signed physical-hazard authorization ("a grant" in requirements F3's language;
    `spec/naalp-draft-01.cddl` `naalp-hazard-authorization`). Same shape as HazardClaim
    deliberately: one envelope shape for both sides keeps the containment check symmetric."""

    __slots__ = ("hazard_class", "envelope")

    def __init__(self, hazard_class, envelope):
        self.hazard_class = hazard_class
        self.envelope = envelope

    def to_value(self):
        return _body_to_value(self.hazard_class, self.envelope)

    def bytes(self):
        """Deterministic-CBOR encoding of {1:class,2:envelope}."""
        return cbor.encode(self.to_value())

    def content_id(self):
        """The authorization's content id (T1 framing)."""
        return cbor.content_id(self.to_value())

    @staticmethod
    def from_value(v):
        """Parse a `naalp-hazard-authorization` body."""
        hazard_class, envelope = _body_from_value(v)
        return HazardAuthorization(hazard_class, envelope)


# ---- F3: grant-coverage authorization -------------------------------------------------------

def hazard_authorized(claim, grant):
    """Authorize a well-formed, present claim against an authorization (F3): EXACT class match
    (not a <= ceiling -- see the module doc) AND envelope_contained(). Any single failing
    dimension denies the WHOLE claim (HazardNotCovered) -- there is no partial authorization
    and no fail-open branch."""
    if claim.hazard_class != grant.hazard_class:
        raise HazardNotCovered()
    if not envelope_contained(claim.envelope, grant.envelope):
        raise HazardNotCovered()


def hazard_authorized_optional(claim, grant):
    """Authorize an OPTIONAL claim (F2's "absent" case at the object level, distinct from a
    present-but-unrecognized class byte inside a claim). `None` -- no hazard-claim object
    exists at all for an action that requires one -- denies immediately (HazardUnknown) rather
    than fabricating a sentinel envelope and running the ordinary coverage check: there is no
    envelope to check containment against, so the honest outcome is a distinct error, not a
    coverage denial that implies an envelope was compared."""
    if claim is None:
        raise HazardUnknown()
    hazard_authorized(claim, grant)
