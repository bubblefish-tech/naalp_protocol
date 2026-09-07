# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP semantic-intent validator (Part-2 ecosystem task E0.2, requirement R3).

Checks a CANDIDATE object -- a `naalp.envelope.Object` that has not been signed yet --
against the inlined CDDL structure, the effect-class / kind registry
(`vectors/registry/channels.csv`, ported to `naalp.channels`), and the Part-1 R7 decoder
bounds, BEFORE it is signed and transmitted (design.md's P-PRESIGN property: "a malformed/
out-of-bounds/unknown-kind object is rejected locally before signing; nothing invalid
reaches the wire").

This module performs NO cryptography and defines NO second CBOR codec: every byte-level
operation (canonical encoding, content-id, bounded decode) is the Part-1 reference
implementation's own `naalp.cbor` / `naalp.envelope` code, imported and called directly.
Reimplementing the codec here would violate the two-implementations/ten-port wire-truth
discipline for a validator whose entire job is to agree with that wire truth.

Design choice -- COLLECT, don't fail-fast: `naalp.envelope.verify()` (the wire verifier)
raises on the FIRST failure, which is correct for a network-input rejection function. This
PRE-SIGN validator instead collects every applicable violation into one ValidationResult,
because its consumer is a developer (or an LLM-driven agent) who benefits from seeing every
problem in a hallucinated candidate at once, not one problem per round-trip.

Grounded correction of the audience rule (recorded per the "verify-relay" / conformance-fix-
direction discipline): the task brief that requested this component paraphrased the audience
rule as "an effecting kind MUST carry an audience". That paraphrase is broader than the wire
spec. design.md Sec.2.5.3 and the naalp-object CDDL comment (`spec/naalp-draft-01.cddl` field 13)
both state the rule precisely: the audience is mandatory for *consume-once* kinds -- "a kind
whose acceptance spends a single-use ledger resource" -- not for every kind whose effect is
non-read-only. design-channels.md Sec.5 names exactly one baseline kind that IS a consume-once
kind: Governance/Consume (channel 0x0004, kind 3), "the single-use ledger append, spine Sec.7.2".
This module enforces the audience rule against that grounded, narrower definition
(CONSUME_ONCE_KINDS below), not the broader paraphrase, so it never rejects a perfectly valid
non-consume-once effecting object (e.g. a Workflow TaskCreate, a Commerce Order) that the wire
itself accepts without an audience.
"""
from . import _bootstrap  # noqa: F401  (side-effecting import: puts impl/python on sys.path)

from naalp import cbor, channels, cose, envelope
from naalp.envelope import MAX_CAUSES, MAX_CEXT, MAX_EXT, MAX_NESTING_DEPTH, MAX_OBJECT_SIZE
from naalp._wire_constants_gen import MAX_STREAM_CHUNKS

__all__ = [
    "Violation", "ValidationResult", "validate", "validate_stream_chunk_count",
    "is_consume_once_kind", "CONSUME_ONCE_KINDS",
    "MAX_CAUSES", "MAX_CEXT", "MAX_EXT", "MAX_NESTING_DEPTH", "MAX_OBJECT_SIZE",
    "MAX_STREAM_CHUNKS",
]

# The baseline consume-once kind set (design.md Sec.2.5.3 + design-channels.md Sec.5): the
# ONLY (channel, kind) pair whose acceptance spends the Sec.7 single-use consume ledger at the
# frozen baseline tier is Governance/Consume. This is a closed, grounded set -- not derived
# from "effect != read_only" -- because consume-once-ness is a property of the LEDGER
# OPERATION a kind represents, not of its effect class (Governance/Approval, for example, is
# also non_idempotent_write but is NOT itself the ledger-spending object).
CONSUME_ONCE_KINDS = frozenset({(0x0004, 3)})


def is_consume_once_kind(channel, kind):
    """Whether (channel, kind) is a baseline consume-once kind (design.md Sec.2.5.3)."""
    return (channel, kind) in CONSUME_ONCE_KINDS


class Violation:
    """One rejected aspect of a candidate object. `error` is always an exact, registered
    N-AALP error NAME (`naalp.naalperror.NAMES` / vectors/registry/error-codes.csv) -- never
    an invented string -- so a caller (or the firewall hook) can dispatch on it exactly as it
    would dispatch on a wire rejection. `field` names the offending field when applicable
    (None for whole-object violations)."""
    __slots__ = ("error", "detail", "field")

    def __init__(self, error, detail="", field=None):
        self.error = error
        self.detail = detail
        self.field = field

    def __eq__(self, other):
        return (isinstance(other, Violation) and self.error == other.error
                and self.field == other.field)

    def __hash__(self):
        return hash((self.error, self.field))

    def __repr__(self):
        return "Violation(error=%r, field=%r, detail=%r)" % (self.error, self.field, self.detail)


class ValidationResult:
    """The outcome of validate(): `valid` is computed (True iff `violations` is empty), never
    stored independently -- so there is exactly one place a mutation could break the verdict,
    and it is the property below, not a second flag that could drift from the list."""
    __slots__ = ("violations",)

    def __init__(self, violations):
        self.violations = list(violations)

    @property
    def valid(self):
        return len(self.violations) == 0

    def __bool__(self):
        return self.valid

    def errors(self):
        """The set of distinct error NAMES present (order-preserving first-seen)."""
        seen = []
        for v in self.violations:
            if v.error not in seen:
                seen.append(v.error)
        return seen

    def __repr__(self):
        return "ValidationResult(valid=%r, violations=%r)" % (self.valid, self.violations)


def _uint_field(violations, name, value):
    """True iff value is a well-formed uint (CDDL `uint`): a non-negative int, and explicitly
    NOT a bool (Python's bool is an int subclass; the wire has no boolean type at all -- see
    naalp.cbor's value model, which defines only U/N/B/T/A/M/Tag)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        violations.append(Violation("Malformed", "%s must be a non-negative integer (uint)" % name, field=name))
        return False
    return True


def _pair_count(m):
    """Return the entry count of an ext/cext carrier, or None if it is not a well-formed
    `{ * uint => any }` map (CDDL): accepts either a naalp.cbor.M (keys must be cbor.U) or a
    plain dict (keys must be non-negative, non-bool ints) -- the latter so a candidate built
    from a plain dict does not need to hand-wrap the ext/cext KEYS in cbor.U just to be
    measured for the R7 cardinality bound. This wraps keys only, never values: a dict
    VALUE must already be a Part-1 CBOR value object (U/N/B/T/A/M/Tag), because encoding a
    raw Python value would require this module to invent its own type-coercion rules --
    exactly the "second codec" the module docstring forbids. See `_as_cbor_map` below for
    the corresponding key-wrapping step applied before the real encode."""
    if isinstance(m, cbor.M):
        for k, _ in m.pairs:
            if not isinstance(k, cbor.U):
                return None
        return len(m.pairs)
    if isinstance(m, dict):
        for k in m.keys():
            if isinstance(k, bool) or not isinstance(k, int) or k < 0:
                return None
        return len(m)
    return None


def _as_cbor_map(m):
    """Return `m` as a `cbor.M`, ready for `cbor.encode`. If `m` is already a `cbor.M`,
    return it unchanged. If `m` is a plain dict, wrap each (already-int-validated, by
    `_pair_count`) key in `cbor.U` and pass the value through untouched -- this is exactly
    the `M([(U(k), v), ...])` a caller would write by hand, not a new encoding rule, so it
    does not reintroduce the second-codec the module docstring forbids. A value that is not
    itself a valid CBOR value object (e.g. a raw Python int/str an LLM emitted unwrapped)
    still fails at the real `cbor.encode` call below with a Malformed violation -- correctly,
    because this module reuses the Part-1 codec rather than inventing value coercion for it.
    Caller must only call this after `_pair_count(m) is not None`."""
    if isinstance(m, cbor.M):
        return m
    return cbor.M([(cbor.U(k), v) for k, v in m.items()])


def validate(candidate, *, self_authority=None):
    """Validate `candidate` -- a `naalp.envelope.Object`, or a plain dict keyed exactly like
    `Object.__init__`'s parameters (kind, channel, signer, created, effect, body, tier,
    profile, causes, ext, cext, audience, suite) -- against:

      1. CDDL structure (required-field types; naalp-object, spec/naalp-draft-01.cddl).
      2. The kind registry (channel, kind) must be a registered baseline surface.
      3. The effect-class invariant: a fixed-effect kind's object must carry its declared
         effect; a variable-effect kind (Stream/StreamOpen, Bridge/Carriage) accepts 0..3.
      4. The Part-1 R7 decoder bounds: object octet size, |causes|, |ext|+|cext| cardinality,
         CBOR nesting depth.
      5. The consume-once audience rule (design.md Sec.2.5.3; CONSUME_ONCE_KINDS above).

    `self_authority`, if given, is the identity of the authority that WOULD consume this
    object (the point-of-use check design.md Sec.2.5.3 performs at the consume ledger, not
    inside signature verification): when provided, a present-but-foreign audience is also
    flagged WrongAudience. Pre-sign, this is usually unknown, so it defaults to None and only
    the "consume-once kind with no audience at all" branch is checked -- exactly the part of
    the rule that IS knowable before the consuming authority exists.

    Returns a ValidationResult that collects every applicable violation (see the module
    docstring for why this collects rather than fails fast)."""
    violations = []

    if isinstance(candidate, envelope.Object):
        obj = candidate
    elif isinstance(candidate, dict):
        try:
            obj = envelope.Object(**candidate)
        except (TypeError, ValueError) as e:
            return ValidationResult([Violation(
                "Malformed", "candidate dict does not match the naalp-object field shape: %s" % e)])
    else:
        return ValidationResult([Violation(
            "Malformed", "candidate must be a naalp.envelope.Object or a field-keyed dict, "
                         "got %s" % type(candidate).__name__)])

    # --- 1. scalar field types (CDDL: fields 2,4,6,7,9,14 uint; field 13 tstr; field 8 list of bstr)
    kind_ok = _uint_field(violations, "kind", obj.kind)
    channel_ok = _uint_field(violations, "channel", obj.channel)
    tier_ok = _uint_field(violations, "tier", obj.tier)
    created_ok = _uint_field(violations, "created", obj.created)
    effect_ok = _uint_field(violations, "effect", obj.effect)
    profile_ok = _uint_field(violations, "profile", obj.profile)
    suite_ok = _uint_field(violations, "suite", obj.suite)

    if not isinstance(obj.audience, str):
        violations.append(Violation("Malformed", "audience must be a text string (tstr)", field="audience"))
        audience_ok = False
    else:
        audience_ok = True

    if not isinstance(obj.causes, list) or not all(isinstance(c, (bytes, bytearray)) for c in obj.causes):
        violations.append(Violation("Malformed", "causes must be a list of byte strings (bstr)", field="causes"))
        causes_ok = False
    else:
        causes_ok = True

    ext_ok = True
    cext_ok = True
    ext_count = cext_count = None
    if obj.ext is not None:
        ext_count = _pair_count(obj.ext)
        if ext_count is None:
            violations.append(Violation("Malformed", "ext must be a uint-keyed map ({ * uint => any })", field="ext"))
            ext_ok = False
    if obj.cext is not None:
        cext_count = _pair_count(obj.cext)
        if cext_count is None:
            violations.append(Violation("Malformed", "cext must be a uint-keyed map ({ * uint => any })", field="cext"))
            cext_ok = False

    # --- 2. field ranges (Sec.3.3; envelope.verify's own precedence -- RangeError precedes
    #     kind dispatch and the effect-class check, so a channel/effect/profile that is not
    #     even a legal enum member is reported as RangeError, never re-reported as
    #     UnknownKind/EffectDeclarationMismatch too).
    channel_in_range = channel_ok
    if channel_ok and obj.channel > 19:
        violations.append(Violation("RangeError", "channel exceeds the registered range 0..19 (channel-id)", field="channel"))
        channel_in_range = False

    effect_in_range = effect_ok
    if effect_ok and obj.effect > channels.DE:
        violations.append(Violation("RangeError", "effect exceeds the closed effect enum 0..3", field="effect"))
        effect_in_range = False

    if profile_ok and not (cose.PROFILE_PUBLIC <= obj.profile <= cose.PROFILE_SOVEREIGN):
        violations.append(Violation("RangeError", "profile is not a registered crypto profile (1..3)", field="profile"))

    # --- 3. R7 count bounds
    if causes_ok and len(obj.causes) > MAX_CAUSES:
        violations.append(Violation(
            "TooManyCauses", "causes[] exceeds the maximum count (%d)" % MAX_CAUSES, field="causes"))
    if ext_ok and ext_count is not None and ext_count > MAX_EXT:
        violations.append(Violation(
            "TooManyExtensions", "ext exceeds the maximum cardinality (%d)" % MAX_EXT, field="ext"))
    if cext_ok and cext_count is not None and cext_count > MAX_CEXT:
        violations.append(Violation(
            "TooManyExtensions", "cext exceeds the maximum cardinality (%d)" % MAX_CEXT, field="cext"))

    # --- 4. kind registry + effect-class invariant (channels.csv, ported to naalp.channels)
    if channel_in_range and kind_ok:
        try:
            _name, _declared, _variable = channels.lookup(obj.channel, obj.kind)
        except channels.UnknownKind as e:
            violations.append(Violation("UnknownKind", str(e), field="kind"))
        else:
            if effect_in_range:
                try:
                    channels.check_effect(obj.channel, obj.kind, obj.effect)
                except channels.EffectDeclarationMismatch as e:
                    violations.append(Violation("EffectDeclarationMismatch", str(e), field="effect"))

    # --- 5. consume-once audience rule (design.md Sec.2.5.3; grounded correction, see module docstring)
    if audience_ok and channel_in_range and kind_ok:
        if is_consume_once_kind(obj.channel, obj.kind) and not obj.audience:
            violations.append(Violation(
                "WrongAudience", "consume-once kind requires an audience naming its consuming "
                                 "authority (Sec.2.5.3, R1)", field="audience"))
        elif self_authority is not None and obj.audience and obj.audience != self_authority:
            violations.append(Violation(
                "WrongAudience", "audience names a different consuming authority", field="audience"))

    # --- 6. octet-size + nesting-depth bounds, via the REAL Part-1 codec (no reimplementation):
    #     only attempted once every scalar field is at least well-typed, so a type error already
    #     reported above is never re-reported a second time as an opaque encode failure.
    can_attempt_encode = (
        kind_ok and channel_ok and tier_ok and created_ok and effect_ok and profile_ok
        and suite_ok and audience_ok and causes_ok and ext_ok and cext_ok
    )
    if can_attempt_encode:
        prev_id = obj.id
        prev_ext = obj.ext
        prev_cext = obj.cext
        payload = None
        try:
            # A plain-dict ext/cext (accepted above by _pair_count) must reach the real
            # Part-1 encoder in the SAME shape a hand-built cbor.M candidate would -- else a
            # perfectly valid dict-shaped candidate would be rejected here with a leaked
            # "not a cbor value" implementation detail instead of being measured correctly.
            # _as_cbor_map only wraps already-validated int keys; it never touches values.
            if obj.ext is not None:
                obj.ext = _as_cbor_map(obj.ext)
            if obj.cext is not None:
                obj.cext = _as_cbor_map(obj.cext)
            obj.id = obj.content_id()
            payload = cbor.encode(obj._body_map(True))
        except cbor.NonCanonical as e:
            violations.append(Violation("NonCanonical", str(e)))
        except (TypeError, ValueError, AttributeError) as e:
            violations.append(Violation("Malformed", "object body cannot be canonically encoded: %s" % e))
        finally:
            obj.id = prev_id      # validate() is side-effect-free on the candidate
            obj.ext = prev_ext
            obj.cext = prev_cext

        if payload is not None:
            if len(payload) > MAX_OBJECT_SIZE:
                violations.append(Violation(
                    "TooLarge", "object exceeds the maximum octet size (%d bytes)" % MAX_OBJECT_SIZE))
            try:
                cbor.decode_bounded(payload, MAX_NESTING_DEPTH)
            except cbor.DepthExceeded as e:
                violations.append(Violation("DepthExceeded", str(e)))
            except cbor.NonCanonical:
                # Our own encoder is canonical by construction; this branch is unreachable for
                # any payload this function itself produced. Never silently swallow a real
                # decode disagreement, though: surface it rather than assume it away.
                violations.append(Violation(
                    "NonCanonical", "encoded candidate failed its own canonical re-decode"))

    return ValidationResult(violations)


def validate_stream_chunk_count(count):
    """The one R7 bound that does not apply to a signed object at all: a native stream's
    DELIVERED CHUNK COUNT (design.md Sec.10.2; the chunks are unsigned raw frames the
    transport AEAD protects, never part of a naalp-object body), bounded at 2**20
    (MAX_STREAM_CHUNKS, mirroring `naalp.streaming.verify_commit`/`verify_prefix`'s own
    TooManyChunks check). Exposed separately from validate() because chunks are not a
    field of any single candidate object -- there is nothing for validate() to inspect
    without a chunk list in hand."""
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return ValidationResult([Violation("Malformed", "chunk count must be a non-negative integer")])
    if count > MAX_STREAM_CHUNKS:
        return ValidationResult([Violation(
            "TooManyChunks", "stream chunk count exceeds the maximum (%d)" % MAX_STREAM_CHUNKS)])
    return ValidationResult([])
